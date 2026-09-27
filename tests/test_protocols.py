"""
tests/test_protocols.py — Regression tests for modules/protocols.py.

Uses synthetic packet stubs (no real pcap needed).
Run with: pytest tests/test_protocols.py -v
"""

import pytest
from unittest.mock import MagicMock
from modules.protocols import (
    _confirmed_by_dissector,
    detect_uncommon_protocols,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_tcp_pkt(
    dstport: int,
    has_layer: str = None,   # e.g. "telnet", "ftp"
    highest_layer: str = "DATA",
) -> MagicMock:
    """Return a minimal TCP packet stub with the given destination port.

    Args:
        dstport:       TCP destination port number.
        has_layer:     If set, the packet will have an attribute with this name
                       (simulating pyshark finding a protocol layer).
        highest_layer: Value returned by pkt.highest_layer.
    """
    pkt = MagicMock()
    pkt.tcp.dstport = str(dstport)
    pkt.highest_layer = highest_layer

    # Make hasattr(pkt, 'tcp') True and hasattr(pkt, 'udp') False
    # MagicMock auto-creates attrs, so we have to be careful
    del pkt.udp  # prevent accidental UDP match

    if has_layer:
        # e.g. pkt.telnet exists — creates a truthy MagicMock attr
        setattr(pkt, has_layer, MagicMock())
    else:
        # Remove common deprecated protocol layers so hasattr returns False
        for layer in ("telnet", "ftp", "tftp", "snmp", "http", "pop", "nntp"):
            # Deleting forces AttributeError → hasattr returns False
            try:
                delattr(pkt, layer)
            except AttributeError:
                pass

    return pkt


# ── Unit tests for _confirmed_by_dissector ────────────────────────────────────

class TestConfirmedByDissector:
    """Verify cross-check against actual dissected protocol layer."""

    def test_telnet_layer_present(self):
        pkt = _make_tcp_pkt(23, has_layer="telnet", highest_layer="TELNET")
        assert _confirmed_by_dissector(pkt, "telnet") is True

    def test_ftp_layer_present(self):
        pkt = _make_tcp_pkt(21, has_layer="ftp", highest_layer="FTP")
        assert _confirmed_by_dissector(pkt, "ftp") is True

    def test_telnet_port_but_no_layer(self):
        """Port 23 traffic without a telnet dissector layer → must return False."""
        pkt = _make_tcp_pkt(23, has_layer=None, highest_layer="DATA")
        assert _confirmed_by_dissector(pkt, "telnet") is False

    def test_http_highest_layer(self):
        """highest_layer == 'HTTP' is sufficient even without hasattr check."""
        pkt = _make_tcp_pkt(80, has_layer=None, highest_layer="HTTP")
        assert _confirmed_by_dissector(pkt, "http") is True

    def test_unknown_proto_returns_false(self):
        pkt = _make_tcp_pkt(9999)
        assert _confirmed_by_dissector(pkt, "someunknownproto") is False


# ── Integration tests for detect_uncommon_protocols ──────────────────────────

class TestDetectUncommonProtocols:
    """
    BUG REGRESSION: Previously, any traffic to port 23 was flagged as Telnet,
    even if tshark/pyshark never identified a Telnet protocol layer.

    After the fix, a finding is only produced when the dissector confirms it.
    """

    def test_no_finding_for_port_only_match(self):
        """
        A packet to port 23 with no telnet dissector layer must NOT produce
        a finding (port-only false positive).
        """
        pkt = _make_tcp_pkt(23, has_layer=None, highest_layer="DATA")
        findings = detect_uncommon_protocols([pkt])
        telnet_findings = [f for f in findings if "TELNET" in f.titulo]
        assert telnet_findings == [], (
            "False positive: port-23 packet without telnet layer was flagged as TELNET. "
            f"Findings: {[f.titulo for f in telnet_findings]}"
        )

    def test_finding_produced_when_dissector_confirms(self):
        """When tshark dissects the packet as Telnet, a finding MUST be produced."""
        pkt = _make_tcp_pkt(23, has_layer="telnet", highest_layer="TELNET")
        findings = detect_uncommon_protocols([pkt])
        telnet_findings = [f for f in findings if "TELNET" in f.titulo]
        assert len(telnet_findings) == 1, (
            "Expected exactly one TELNET finding when dissector confirms the protocol, "
            f"but got: {[f.titulo for f in findings]}"
        )

    def test_ftp_port_without_layer_no_finding(self):
        """Port 21 without FTP dissector layer → no finding."""
        pkt = _make_tcp_pkt(21, has_layer=None, highest_layer="TCP")
        findings = detect_uncommon_protocols([pkt])
        ftp_findings = [f for f in findings if "FTP" in f.titulo]
        assert ftp_findings == []

    def test_ftp_with_layer_produces_finding(self):
        pkt = _make_tcp_pkt(21, has_layer="ftp", highest_layer="FTP")
        findings = detect_uncommon_protocols([pkt])
        ftp_findings = [f for f in findings if "FTP" in f.titulo]
        assert len(ftp_findings) == 1

    def test_http_port_without_layer_no_finding(self):
        """Port 80 without HTTP layer (e.g. scan SYN) → no finding."""
        pkt = _make_tcp_pkt(80, has_layer=None, highest_layer="TCP")
        findings = detect_uncommon_protocols([pkt])
        http_findings = [f for f in findings if "HTTP" in f.titulo]
        assert http_findings == []

    def test_http_with_layer_produces_finding(self):
        pkt = _make_tcp_pkt(80, has_layer="http", highest_layer="HTTP")
        findings = detect_uncommon_protocols([pkt])
        http_findings = [f for f in findings if "HTTP" in f.titulo]
        assert len(http_findings) == 1

    def test_baseline_whitelists_known_protocol(self):
        """Protocols listed in baseline expected_protocols must be suppressed."""
        pkt = _make_tcp_pkt(21, has_layer="ftp", highest_layer="FTP")
        baseline = {"expected_protocols": ["ftp"]}
        findings = detect_uncommon_protocols([pkt], baseline_profile=baseline)
        assert findings == []

    def test_deduplication_one_finding_per_port(self):
        """Multiple packets to the same deprecated port → only one finding."""
        pkts = [
            _make_tcp_pkt(23, has_layer="telnet", highest_layer="TELNET")
            for _ in range(5)
        ]
        findings = detect_uncommon_protocols(pkts)
        assert len(findings) == 1
