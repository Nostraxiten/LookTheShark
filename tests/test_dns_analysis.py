"""
tests/test_dns_analysis.py — Regression tests for modules/dns_analysis.py.

Uses synthetic pyshark-like packet stubs so no real .pcap file is needed.
Run with: pytest tests/test_dns_analysis.py -v
"""

import pytest
from unittest.mock import MagicMock
from modules.dns_analysis import (
    _is_dns_response,
    extract_dns_queries,
    detect_tunneling,
    TUNNEL_QPS_THRESHOLD,
    TUNNEL_MIN_SPAN_S,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

class MockLayer:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class MockPacket:
    def __init__(self, dns=None, ip=None, sniff_time="2024-01-01 00:00:00"):
        if dns is not None:
            self.dns = dns
        if ip is not None:
            self.ip = ip
        self.sniff_time = sniff_time


def _make_dns_pkt(
    qry_name: str,
    flags_response,   # raw value as pyshark would return it
    src: str = "192.0.2.100",
    dst: str = "192.0.2.2",
    sniff_time: str = "2024-01-01 00:00:00",
) -> MockPacket:
    """Create a minimal pyshark-packet stub with a dns layer."""
    ip_layer = MockLayer(src=src, dst=dst)
    dns_layer = MockLayer(
        flags_response=str(flags_response),
        qry_name=qry_name,
        qry_type="A",
    )
    return MockPacket(dns=dns_layer, ip=ip_layer, sniff_time=sniff_time)


def _make_pkt_list(
    count: int,
    *,
    qry_name: str,
    flags_response,
    src: str = "192.0.2.100",
    dst: str = "192.0.2.2",
    start_offset_s: float = 0.0,
    spacing_s: float = 0.1,
) -> list:
    """Return a list of *count* DNS packet stubs at evenly-spaced times."""
    from datetime import datetime, timedelta
    base = datetime(2024, 1, 1, 0, 0, 0)
    pkts = []
    for i in range(count):
        ts = (base + timedelta(seconds=start_offset_s + i * spacing_s)).isoformat()
        pkts.append(
            _make_dns_pkt(qry_name, flags_response, src=src, dst=dst, sniff_time=ts)
        )
    return pkts


# ── Unit tests for _is_dns_response ──────────────────────────────────────────

class TestIsDnsResponse:
    """Verify the fixed response-detection helper covers all pyshark variants."""

    def test_string_true(self):
        assert _is_dns_response("True") is True

    def test_string_true_lowercase(self):
        assert _is_dns_response("true") is True

    def test_string_true_mixed(self):
        assert _is_dns_response("TRUE") is True

    def test_string_one(self):
        assert _is_dns_response("1") is True

    def test_string_false(self):
        assert _is_dns_response("False") is False

    def test_string_false_lowercase(self):
        assert _is_dns_response("false") is False

    def test_string_zero(self):
        assert _is_dns_response("0") is False

    def test_empty_string(self):
        assert _is_dns_response("") is False

    def test_whitespace_true(self):
        assert _is_dns_response("  True  ") is True


# ── Integration test: response count via extract_dns_queries ──────────────────

class TestExtractDnsQueries:
    """
    BUG REGRESSION: DNS responses were always counted as queries because
    str(qr) == "1" was always False when pyshark returned "True"/"False".

    After the fix, is_response must be True for packets where pyshark sets
    flags_response to "True" (or "1").
    """

    def _build_packets(self):
        """Return 7 query stubs and 13 response stubs."""
        queries = _make_pkt_list(
            7,
            qry_name="example.com",
            flags_response="False",
            src="192.0.2.100",
            dst="8.8.8.8",
        )
        responses = _make_pkt_list(
            13,
            qry_name="example.com",
            flags_response="True",
            src="8.8.8.8",
            dst="192.0.2.100",
        )
        return queries + responses

    def test_response_count_is_correct(self):
        """Must report 13 responses, not 0."""
        packets = self._build_packets()
        extracted = extract_dns_queries(packets)
        response_count = sum(1 for q in extracted if q["is_response"])
        assert response_count == 13, (
            f"Expected 13 DNS responses but got {response_count}. "
            "The is_response flag is likely still broken."
        )

    def test_query_count_is_correct(self):
        packets = self._build_packets()
        extracted = extract_dns_queries(packets)
        query_count = sum(1 for q in extracted if not q["is_response"])
        assert query_count == 7

    def test_responses_excluded_from_queries_per_dst(self):
        """
        BUG REGRESSION: when is_response was always False, response packets
        were included in queries_per_dst, causing a false-positive high-rate
        finding towards the *client* IP (destination of the responses).

        After the fix, detect_tunneling() must NOT flag the client IP as a
        suspicious destination for DNS queries.
        """
        # 20 response packets from 8.8.8.8 → 192.0.2.100 spread over 2 s
        # (was enough to trigger the old false positive because they all had
        # dst=192.0.2.100 and is_response=False under the old broken logic)
        responses = _make_pkt_list(
            20,
            qry_name="example.com",
            flags_response="True",
            src="8.8.8.8",
            dst="192.0.2.100",
            spacing_s=0.1,   # 20 × 0.1 s = 2 s span → 10 qps if counted
        )
        extracted = extract_dns_queries(responses)
        findings = detect_tunneling(extracted, threshold=5.0, min_span=1.0)
        # The only destination in these packets is 192.0.2.100 (the client).
        # It must NOT appear as a tunneling target.
        client_findings = [
            f for f in findings if "192.0.2.100" in f.titulo
        ]
        assert client_findings == [], (
            "False-positive: response packets are being counted as queries "
            f"towards the client IP. Findings: {[f.titulo for f in client_findings]}"
        )


# ── Tunneling threshold / min-span tests ─────────────────────────────────────

class TestDetectTunneling:
    """Verify the configurable QPS threshold and minimum span requirement."""

    def _make_query_events(
        self, count: int, span_s: float, dst: str = "8.8.8.8"
    ) -> list:
        """Return query event dicts (not full packets) spread over span_s seconds."""
        from datetime import datetime, timedelta
        base = datetime(2024, 1, 1)
        spacing = span_s / (count - 1) if count > 1 else 1.0
        return [
            {
                "name": "example.com",
                "type": "A",
                "src": "192.0.2.100",
                "dst": dst,
                "answers": [],
                "is_response": False,
                "timestamp": (base + timedelta(seconds=i * spacing)).isoformat(),
            }
            for i in range(count)
        ]

    def test_high_rate_sustained_fires(self):
        """20 queries over 2 s to the same resolver → should fire (10 qps > 5.0)."""
        events = self._make_query_events(20, span_s=2.0)
        findings = detect_tunneling(events, threshold=5.0, min_span=1.0)
        assert any("High DNS query rate" in f.titulo for f in findings)

    def test_high_rate_short_burst_does_not_fire(self):
        """10 queries in 0.5 s (20 qps) but span < min_span → must NOT fire."""
        events = self._make_query_events(10, span_s=0.5)
        findings = detect_tunneling(events, threshold=5.0, min_span=2.0)
        rate_findings = [f for f in findings if "High DNS query rate" in f.titulo]
        assert rate_findings == [], (
            "Short burst false-positive: queries over a window shorter than "
            f"min_span should be suppressed. Findings: {rate_findings}"
        )

    def test_low_rate_does_not_fire(self):
        """20 queries over 10 s (2 qps < threshold=5.0) → must NOT fire."""
        events = self._make_query_events(20, span_s=10.0)
        findings = detect_tunneling(events, threshold=5.0, min_span=2.0)
        rate_findings = [f for f in findings if "High DNS query rate" in f.titulo]
        assert rate_findings == []

    def test_fewer_than_10_queries_does_not_fire(self):
        """8 queries regardless of rate → below minimum count, must NOT fire."""
        events = self._make_query_events(8, span_s=1.0)
        findings = detect_tunneling(events, threshold=5.0, min_span=0.5)
        rate_findings = [f for f in findings if "High DNS query rate" in f.titulo]
        assert rate_findings == []
