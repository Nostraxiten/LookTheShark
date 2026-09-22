"""
modules/layer2_anomalies.py — Layer 2 / Local Network Module.

Detects LAN anomalies: ARP storms, multiple MACs for one IP, rogue DHCP servers.
"""

from collections import defaultdict
from typing import List

from rich.console import Console

from modules import Finding, Confianza, safe_get_attr
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 8
MODULE_NAME = "Layer 2 / Local Network"
MODULE_ID   = "layer2"


def detect_arp_anomalies(packets) -> List[Finding]:
    """Detects multiple MAC addresses claiming the same IP (possible ARP spoofing)."""
    findings = []
    
    # ip -> set(macs)
    ip_mac_map = defaultdict(set)
    
    for pkt in packets:
        if hasattr(pkt, "arp"):
            sender_mac = safe_get_attr(pkt, "arp", "src_hw_mac")
            sender_ip = safe_get_attr(pkt, "arp", "src_proto_ipv4")
            
            if sender_mac and sender_ip and sender_ip != "0.0.0.0":
                ip_mac_map[sender_ip].add(sender_mac)
                
    for ip, macs in ip_mac_map.items():
        if len(macs) > 1:
            findings.append(Finding(
                titulo=f"Possible ARP Spoofing detected for IP {ip}",
                descripcion=(
                    f"Multiple MAC addresses ({len(macs)}) claim IP {ip}. "
                    f"Strong indicator of ARP cache poisoning or severe network conflict. "
                    f"Review manually."
                ),
                severidad="critico",
                confianza=Confianza.ALTA,
                modulo=MODULE_ID,
                evidencia=f"MACs observed: {', '.join(macs)}",
                patron="arp_spoof",
                interpretacion=(
                    "ARP Cache Poisoning / Man-in-the-Middle | "
                    "Multiple MAC addresses claiming ownership of a single IP address | "
                    "IP address conflict, virtual machine migration, VRRP/HSRP router failover, or network interface bonding/teaming"
                )
            ))
            
    return findings


def detect_dhcp_rogue(packets) -> List[Finding]:
    """Detects multiple DHCP servers offering IP addresses."""
    findings = []
    
    # txid -> set(server_macs)
    dhcp_offers = defaultdict(set)
    
    for pkt in packets:
        if hasattr(pkt, "dhcp"):
            msg_type = safe_get_attr(pkt, "dhcp", "option.dhcp")
            if msg_type in ("2", "5"):
                server_mac = safe_get_attr(pkt, "eth", "src")
                txid = safe_get_attr(pkt, "bootp", "id")
                if server_mac and txid:
                    dhcp_offers[txid].add(server_mac)
                    
    for txid, macs in dhcp_offers.items():
        if len(macs) > 1:
            findings.append(Finding(
                titulo="Rogue DHCP Server detected",
                descripcion=(
                    f"For DHCP transaction {txid}, multiple servers responded "
                    f"({len(macs)} distinct MACs). Possible rogue DHCP server assigning "
                    f"malicious gateway or DNS configurations (Man-in-the-Middle)."
                ),
                severidad="alto",
                confianza=Confianza.ALTA,
                modulo=MODULE_ID,
                evidencia=f"DHCP server MACs: {', '.join(macs)}",
                patron="dhcp_rogue",
                interpretacion=(
                    "DHCP Rogue Server / Spoofing | "
                    "Multiple distinct MAC addresses answering the same DHCP transaction ID | "
                    "Dual redundant DHCP servers in high-availability setup, misconfigured switch relay agent, or home router connected to enterprise LAN"
                )
            ))
            break
            
    return findings


def run(packets, config: dict, console: Console) -> List[Finding]:
    findings = []
    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    arp_anomalies = detect_arp_anomalies(packets)
    dhcp_rogue = detect_dhcp_rogue(packets)
    
    findings.extend(arp_anomalies)
    findings.extend(dhcp_rogue)

    if findings:
        for f in findings:
            console.print(f"  {estilo_severidad(f.severidad)}  {f.titulo}")
            console.print(f"      [dim]{f.descripcion}[/]")
            console.print(f"      [dim]-> {f.evidencia}[/]")
        console.print()
    else:
        console.print("  [bold bright_green][OK][/] [dim]No Layer 2 anomalies (ARP, DHCP) detected.[/]")
        console.print()

    console.print(pie_modulo())
    return findings
