"""
tests/test_layer2_anomalies.py — Regression tests for modules/layer2_anomalies.py.

Uses synthetic packet stubs (no real pcap needed).
Run with: pytest tests/test_layer2_anomalies.py -v
"""

import pytest
from modules.layer2_anomalies import detect_arp_anomalies, detect_dhcp_rogue


class MockLayer:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class MockPacket:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


# ── ARP Spoofing Tests ────────────────────────────────────────────────────────

class TestArpAnomalies:
    def test_single_mac_per_ip_no_finding(self):
        pkts = [
            MockPacket(arp=MockLayer(src_hw_mac="00:11:22:33:44:55", src_proto_ipv4="192.168.1.1")),
            MockPacket(arp=MockLayer(src_hw_mac="00:11:22:33:44:55", src_proto_ipv4="192.168.1.1")),
        ]
        findings = detect_arp_anomalies(pkts)
        assert len(findings) == 0

    def test_multiple_macs_same_ip_produces_finding(self):
        pkts = [
            MockPacket(arp=MockLayer(src_hw_mac="00:11:22:33:44:55", src_proto_ipv4="192.168.1.1")),
            MockPacket(arp=MockLayer(src_hw_mac="aa:bb:cc:dd:ee:ff", src_proto_ipv4="192.168.1.1")),
        ]
        findings = detect_arp_anomalies(pkts)
        assert len(findings) == 1
        assert "192.168.1.1" in findings[0].titulo
        assert findings[0].severidad == "critico"


# ── DHCP Rogue Tests ──────────────────────────────────────────────────────────

class TestDhcpRogue:
    def test_single_dhcp_server_offer_no_finding(self):
        pkts = [
            MockPacket(
                dhcp=MockLayer(id="0xdeadbeef", option_dhcp="2"),
                eth=MockLayer(src="00:11:22:33:44:55")
            ),
        ]
        findings = detect_dhcp_rogue(pkts)
        assert len(findings) == 0

    def test_two_dhcp_servers_same_txid_produces_finding(self):
        """
        Scenario: Two distinct DHCP servers (different MACs) answer the same
        transaction ID (0xdeadbeef) with DHCP Offer (type 2) or ACK (type 5).
        """
        pkts = [
            MockPacket(
                dhcp=MockLayer(id="0xdeadbeef", option_dhcp="2"),
                eth=MockLayer(src="00:11:22:33:44:55")
            ),
            MockPacket(
                dhcp=MockLayer(id="0xdeadbeef", option_dhcp="2"),
                eth=MockLayer(src="aa:bb:cc:dd:ee:ff")
            ),
        ]
        findings = detect_dhcp_rogue(pkts)
        assert len(findings) == 1
        assert findings[0].patron == "dhcp_rogue"
        assert "0xdeadbeef" in findings[0].descripcion
        assert "00:11:22:33:44:55" in findings[0].evidencia
        assert "aa:bb:cc:dd:ee:ff" in findings[0].evidencia
        assert findings[0].severidad == "alto"

    def test_bootp_layer_fallback(self):
        """Verify fallback when layer is named bootp instead of dhcp."""
        pkts = [
            MockPacket(
                bootp=MockLayer(id="0xdeadbeef", option_dhcp="2"),
                eth=MockLayer(src="00:11:22:33:44:55")
            ),
            MockPacket(
                bootp=MockLayer(id="0xdeadbeef", option_dhcp="2"),
                eth=MockLayer(src="aa:bb:cc:dd:ee:ff")
            ),
        ]
        findings = detect_dhcp_rogue(pkts)
        assert len(findings) == 1
        assert findings[0].patron == "dhcp_rogue"
