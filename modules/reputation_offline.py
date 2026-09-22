"""
modules/reputation_offline.py — Offline Reputation Module.

Matches IPs and domains in the capture against local threat intelligence feeds.
Never performs live queries to external APIs.
"""

import os
from collections import defaultdict
from typing import List

from rich.console import Console

from modules import Finding, Confianza, safe_get_attr, es_ip_privada
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 9
MODULE_NAME = "Offline Reputation"
MODULE_ID   = "reputation"

_FEEDS = {"ips": set(), "domains": set()}
_FEEDS_LOADED = False

def _load_feeds():
    global _FEEDS_LOADED
    if _FEEDS_LOADED:
        return
        
    feeds_dir = os.path.join(os.path.dirname(__file__), "..", "data", "reputation_feeds")
    if not os.path.isdir(feeds_dir):
        _FEEDS_LOADED = True
        return
        
    for fname in os.listdir(feeds_dir):
        if not fname.endswith(".txt"):
            continue
            
        fpath = os.path.join(feeds_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                        
                    if any(c.isalpha() for c in line):
                        _FEEDS["domains"].add(line.lower())
                    else:
                        _FEEDS["ips"].add(line)
        except Exception:
            pass
            
    _FEEDS_LOADED = True


def extract_entities(packets) -> tuple:
    """Extracts all unique public IPs and domains from capture."""
    ips = set()
    domains = set()
    
    for pkt in packets:
        src = safe_get_attr(pkt, "ip", "src")
        dst = safe_get_attr(pkt, "ip", "dst")
        if src and not es_ip_privada(src): ips.add(src)
        if dst and not es_ip_privada(dst): ips.add(dst)
        
        if hasattr(pkt, "dns"):
            query_name = safe_get_attr(pkt, "dns", "qry_name", "")
            if query_name:
                domains.add(query_name.lower().rstrip("."))
                
        if hasattr(pkt, "http"):
            host = safe_get_attr(pkt, "http", "host", "")
            if host: domains.add(host.lower().split(":")[0])
        if hasattr(pkt, "tls"):
            try:
                sni = pkt.tls.handshake_extensions_server_name
                if sni: domains.add(sni.lower())
            except AttributeError:
                pass
                
    return ips, domains


def run(packets, config: dict, console: Console) -> List[Finding]:
    findings = []
    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    _load_feeds()
    
    if not _FEEDS["ips"] and not _FEEDS["domains"]:
        console.print("  [dim]No local reputation feeds found in data/reputation_feeds/.[/]")
        console.print("  [dim]Offline cross-check will not report findings.[/]")
        console.print(pie_modulo())
        return findings
        
    ips_vistas, dominios_vistos = extract_entities(packets)
    
    ips_maliciosas = ips_vistas.intersection(_FEEDS["ips"])
    dominios_maliciosos = dominios_vistos.intersection(_FEEDS["domains"])
    
    console.print(f"  Feeds loaded: [bold white]{len(_FEEDS['ips']):,}[/] IPs, [bold white]{len(_FEEDS['domains']):,}[/] domains.")
    console.print(f"  Entities in capture: {len(ips_vistas):,} IPs, {len(dominios_vistos):,} domains.")
    console.print()

    # Generate findings
    for ip in ips_maliciosas:
        findings.append(Finding(
            titulo=f"Malicious IP contacted: {ip}",
            descripcion="This IP matches entries in local reputation feeds. Could indicate C2, malware, or scanners.",
            severidad="alto",
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"Destination/Source IP: {ip}",
        ))
        
    for dom in dominios_maliciosos:
        findings.append(Finding(
            titulo=f"Malicious domain contacted: {dom}",
            descripcion="This domain matches entries in local reputation feeds. Could indicate phishing, C2, or malware.",
            severidad="alto",
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"Queried domain / SNI: {dom}",
        ))

    if findings:
        console.print(f"  [bold bright_red][!] Matches found in local reputation feeds![/]")
        console.print()
        for f in findings[:10]:
            console.print(f"  {estilo_severidad(f.severidad)}  {f.titulo}")
            console.print(f"      [dim]{f.descripcion}[/]")
        if len(findings) > 10:
            console.print(f"  [dim]... and {len(findings)-10} more matches.[/]")
        console.print()
    else:
        console.print("  [bold bright_green][OK][/] [dim]No captured IP or domain matched local reputation feeds.[/]")
        console.print()

    console.print(pie_modulo())
    return findings
