"""
tests/test_credentials_plain.py — Regression tests for modules/credentials_plain.py.

Uses synthetic packet stubs (no real pcap needed).
Run with: pytest tests/test_credentials_plain.py -v
"""

import pytest
from unittest.mock import MagicMock, PropertyMock
from modules.credentials_plain import (
    _decode_hex_payload,
    _extract_http_form_fields,
    detect_cleartext_creds,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hex_encode(text: str) -> str:
    """Encode a UTF-8 string as a colon-separated hex string (pyshark format)."""
    return ":".join(f"{b:02x}" for b in text.encode("utf-8"))


def _make_base_pkt(src="10.0.0.1", dst="10.0.0.2") -> MagicMock:
    """Return a minimal packet stub with ip.src/dst set."""
    pkt = MagicMock()
    pkt.ip.src = src
    pkt.ip.dst = dst
    return pkt


def _make_http_post_pkt(body: str, src="10.0.0.1", dst="10.0.0.2") -> MagicMock:
    """Return a packet stub that looks like an HTTP POST with a form body.

    pyshark exposes the body as a colon-hex string in http.file_data.
    We also add a fake urlencoded-form layer as a fallback.
    """
    pkt = _make_base_pkt(src, dst)

    # Simulate http layer with file_data as colon-hex
    pkt.http.file_data = _hex_encode(body)
    pkt.http.authorization = ""     # no Basic Auth on this packet

    # Make `hasattr(pkt, 'http')` True
    # (MagicMock already does this, but be explicit)
    type(pkt).http = PropertyMock(return_value=pkt.http)

    # urlencoded-form layer (also contains body text)
    form_layer = MagicMock()
    form_layer.__str__ = lambda self: body
    setattr(pkt, "urlencoded-form", form_layer)

    return pkt


def _make_telnet_sequence(
    client_ip="10.0.0.100",
    server_ip="10.0.0.1",
    username="root",
    password="s3cr3t",
) -> list:
    """Return a minimal Telnet login sequence as packet stubs.

    Sequence:
      server → client : "login: "
      client → server : username + "\r\n"
      server → client : "Password: "
      client → server : password + "\r\n"
    """
    events = [
        # server sends login prompt
        (server_ip, client_ip, "23", "12345", "login: "),
        # client sends username
        (client_ip, server_ip, "12345", "23", username + "\r\n"),
        # server sends password prompt
        (server_ip, client_ip, "23", "12345", "Password: "),
        # client sends password
        (client_ip, server_ip, "12345", "23", password + "\r\n"),
    ]
    pkts = []
    for src, dst, sport, dport, data in events:
        pkt = _make_base_pkt(src, dst)
        pkt.ip.src = src
        pkt.ip.dst = dst
        pkt.tcp.srcport = sport
        pkt.tcp.dstport = dport
        pkt.telnet.data = data
        pkts.append(pkt)
    return pkts


# ── Unit tests ────────────────────────────────────────────────────────────────

class TestDecodeHexPayload:
    """Verify the colon-hex decoder works correctly."""

    def test_basic_form_body(self):
        body = "username=jefe&password=secret123&submit=Login"
        hex_str = _hex_encode(body)
        assert _decode_hex_payload(hex_str) == body

    def test_empty_string(self):
        assert _decode_hex_payload("") == ""

    def test_invalid_hex_returns_empty(self):
        assert _decode_hex_payload("ZZ:ZZ:ZZ") == ""


class TestExtractHttpFormFields:
    """Verify that form body text is extracted regardless of which layer is present."""

    def test_reads_file_data_hex(self):
        body = "password=hunter2&user=alice"
        pkt = _make_http_post_pkt(body)
        text = _extract_http_form_fields(pkt)
        assert "password=hunter2" in text

    def test_reads_urlencoded_form_layer(self):
        """Even without file_data, the urlencoded-form layer must be read."""
        pkt = _make_base_pkt()
        pkt.http = MagicMock()
        # No file_data attribute — simulate missing
        del pkt.http.file_data
        body = "passwd=mypassword&login=admin"
        form_layer = MagicMock()
        form_layer.__str__ = lambda self: body
        setattr(pkt, "urlencoded-form", form_layer)
        text = _extract_http_form_fields(pkt)
        assert "passwd=mypassword" in text


class TestHttpPostCredentialDetection:
    """
    BUG REGRESSION: HTTP POST credential detection was effectively dead code
    because http.file_data (a truthy colon-hex string) always short-circuited
    the `if not payload` check, so the urlencoded-form branch was never reached.

    After the fix, a POST with a body containing password= must produce a finding.
    """

    def test_post_with_password_field_produces_finding(self):
        body = "username=jefe&password=s3cr3tP%40ss&submit=Login"
        pkt = _make_http_post_pkt(body)
        findings = detect_cleartext_creds([pkt])
        post_findings = [f for f in findings if "HTTP POST" in f.titulo]
        assert len(post_findings) >= 1, (
            "Expected at least one finding for HTTP POST with password field, "
            f"but got none. All findings: {[f.titulo for f in findings]}"
        )

    def test_post_with_passwd_variant_produces_finding(self):
        """Field name 'passwd' (not 'password') must also be detected."""
        body = "user=alice&passwd=mypass123"
        pkt = _make_http_post_pkt(body)
        findings = detect_cleartext_creds([pkt])
        post_findings = [f for f in findings if "HTTP POST" in f.titulo]
        assert len(post_findings) >= 1

    def test_post_with_pwd_variant_produces_finding(self):
        """Field name 'pwd' must also be detected."""
        body = "login=bob&pwd=abc123"
        pkt = _make_http_post_pkt(body)
        findings = detect_cleartext_creds([pkt])
        post_findings = [f for f in findings if "HTTP POST" in f.titulo]
        assert len(post_findings) >= 1

    def test_post_without_credential_fields_no_finding(self):
        """An ordinary POST body without credential fields must NOT fire."""
        body = "search=sharks&category=fish"
        pkt = _make_http_post_pkt(body)
        findings = detect_cleartext_creds([pkt])
        post_findings = [f for f in findings if "HTTP POST" in f.titulo]
        assert post_findings == []

    def test_case_insensitive_field_detection(self):
        """Field names are case-insensitive: PASSWORD= must be caught."""
        body = "USERNAME=admin&PASSWORD=secret"
        pkt = _make_http_post_pkt(body)
        findings = detect_cleartext_creds([pkt])
        post_findings = [f for f in findings if "HTTP POST" in f.titulo]
        assert len(post_findings) >= 1


class TestTelnetCredentialExtraction:
    """
    NEW FEATURE: Telnet credential extraction by tracking per-stream
    login/password prompt sequences.
    """

    def test_telnet_login_sequence_produces_finding(self):
        pkts = _make_telnet_sequence(username="root", password="topsecret")
        findings = detect_cleartext_creds(pkts)
        telnet_findings = [f for f in findings if "Telnet" in f.titulo]
        assert len(telnet_findings) >= 1, (
            "Expected a Telnet credential finding but got none. "
            f"All findings: {[f.titulo for f in findings]}"
        )

    def test_telnet_finding_is_critical(self):
        pkts = _make_telnet_sequence()
        findings = detect_cleartext_creds(pkts)
        telnet_findings = [f for f in findings if "Telnet" in f.titulo]
        assert telnet_findings, "No Telnet finding produced."
        assert telnet_findings[0].severidad == "critico"

    def test_telnet_password_is_masked(self):
        """The actual password must NOT appear in the finding description."""
        pkts = _make_telnet_sequence(username="root", password="s3cr3tP@ss")
        findings = detect_cleartext_creds(pkts)
        telnet_findings = [f for f in findings if "Telnet" in f.titulo]
        assert telnet_findings, "No Telnet finding produced."
        desc = telnet_findings[0].descripcion
        assert "s3cr3tP@ss" not in desc, (
            f"Password was exposed in finding description: {desc}"
        )
        assert "***" in desc, f"Expected '***' mask in description but got: {desc}"

    def test_telnet_username_captured(self):
        """The username should appear (unmasked) in the finding description."""
        pkts = _make_telnet_sequence(username="admin", password="pass")
        findings = detect_cleartext_creds(pkts)
        telnet_findings = [f for f in findings if "Telnet" in f.titulo]
        assert telnet_findings
        desc = telnet_findings[0].descripcion
        assert "admin" in desc, f"Username not found in description: {desc}"

    def test_no_false_positive_on_normal_telnet_data(self):
        """Telnet packets with no login prompt must NOT fire."""
        pkt = _make_base_pkt("10.0.0.1", "10.0.0.2")
        pkt.ip.src = "10.0.0.1"
        pkt.ip.dst = "10.0.0.2"
        pkt.tcp.srcport = "23"
        pkt.tcp.dstport = "54321"
        pkt.telnet.data = "Welcome to the server!\r\n"
        findings = detect_cleartext_creds([pkt])
        telnet_findings = [f for f in findings if "Telnet" in f.titulo]
        assert telnet_findings == [], (
            f"False positive on non-credential Telnet data: {[f.titulo for f in telnet_findings]}"
        )
