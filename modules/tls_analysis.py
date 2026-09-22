"""
modules/tls_analysis.py — TLS / Certificates Module.

Detection of obsolete TLS versions, SNI inspection, and JA3 fingerprinting.
"""

import os
import json
import hashlib
from typing import List

from rich.console import Console
from rich.table import Table
from rich import box

from modules import Finding, Confianza, safe_get_attr
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 6
MODULE_NAME = "TLS / Certificates"
MODULE_ID   = "tls"


_JA3_DB = {}

def _load_ja3_db():
    global _JA3_DB
    if _JA3_DB: return
    db_path = os.path.join(os.path.dirname(__file__), "..", "data", "ja3_fingerprints.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            _JA3_DB = data.get("fingerprints", {})
    except Exception:
        pass


def _calc_ja3(pkt) -> str:
    """Calculates or extracts JA3 hash if available from tshark/pyshark."""
    try:
        return pkt.tls.handshake_ja3
    except AttributeError:
        pass
    return ""


def analyze_tls(packets) -> tuple:
    """Analyzes TLS looking for JA3 fingerprints, SNIs, and obsolete versions."""
    _load_ja3_db()
    
    snis = set()
    ja3_hashes = {}  # hash -> {'ip': ip, 'count': int, 'match': str}
    obsolete = []
    
    for pkt in packets:
        if not hasattr(pkt, "tls"):
            continue
            
        # 1. Extract SNI (Server Name Indication)
        try:
            sni = pkt.tls.handshake_extensions_server_name
            if sni and sni not in snis:
                snis.add(sni)
        except AttributeError:
            pass
            
        # 2. JA3 fingerprint
        ja3_hash = _calc_ja3(pkt)
        if ja3_hash:
            src = safe_get_attr(pkt, "ip", "src")
            if ja3_hash not in ja3_hashes:
                match = _JA3_DB.get(ja3_hash, {"client": "Unknown", "risk": "none"})
                ja3_hashes[ja3_hash] = {"ip": src, "count": 0, "match": match}
            ja3_hashes[ja3_hash]["count"] += 1
            
        # 3. Obsolete TLS versions
        try:
            ver_hex = pkt.tls.handshake_version
            if ver_hex in ("0x0300", "0x0301", "0x0302"):
                src = safe_get_attr(pkt, "ip", "src")
                dst = safe_get_attr(pkt, "ip", "dst")
                ver_name = {"0x0300": "SSLv3", "0x0301": "TLS 1.0", "0x0302": "TLS 1.1"}[ver_hex]
                key = (src, dst, ver_name)
                if key not in obsolete:
                    obsolete.append(key)
        except AttributeError:
            pass
            
    return snis, ja3_hashes, obsolete


def run(packets, config: dict, console: Console) -> List[Finding]:
    findings = []
    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    snis, ja3_hashes, obsolete = analyze_tls(packets)
    
    console.print(f"  SNIs observed:                  [bold white]{len(snis)}[/]")
    console.print(f"  Obsolete connections detected:  [bold white]{len(obsolete)}[/]")
    console.print()

    # ── SNI List ───────────────────────────────────────
    if snis:
        console.print("  [dim]Top SNI:[/]")
        for sni in list(snis)[:10]:
            console.print(f"    - {sni}")
        console.print()
        
    # ── Obsolete versions ──────────────────────────────
    for src, dst, ver in obsolete:
        findings.append(Finding(
            titulo=f"Use of obsolete protocol: {ver}",
            descripcion=f"Detected TLS negotiation using {ver}, which is considered insecure.",
            severidad="medio",
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"{src} -> {dst}",
            patron="tls_downgrade",
            interpretacion=(
                "Downgrade Attack / Insecure TLS Version Negotiation | "
                "Negotiation of legacy SSLv3/TLS 1.0/TLS 1.1 cipher suites vulnerable to POODLE/BEAST | "
                "Legacy embedded devices, unupdated operating systems, or internal compatibility constraints"
            )
        ))
        
    # ── JA3 Fingerprints ───────────────────────────────
    if ja3_hashes:
        console.print("  [bold white]JA3 Fingerprints detected:[/]")
        for h, data in list(ja3_hashes.items())[:10]:
            match = data["match"]
            client = match.get("client", "Unknown")
            risk = match.get("risk", "none")
            
            color = "white"
            if risk == "high": color = "bright_red"
            elif risk == "medium": color = "yellow"
            
            console.print(f"    [dim]{h[:16]}...[/] -> [{color}]{client}[/] [dim]({data['ip']})[/]")
            
            if risk in ("high", "medium"):
                findings.append(Finding(
                    titulo=f"Suspicious JA3 fingerprint: {client}",
                    descripcion=(
                        f"Detected TLS client matching known pentest frameworks, "
                        f"C2 tooling, or malware ({client}). Review manually."
                    ),
                    severidad="alto" if risk == "high" else "medio",
                    confianza=Confianza.MEDIA,
                    modulo=MODULE_ID,
                    evidencia=f"IP: {data['ip']}, JA3: {h}",
                    patron="unusual_ja3",
                    interpretacion=(
                        "Non-Standard / Malicious TLS Client Fingerprint (JA3) | "
                        "JA3 hash matching known penetration testing frameworks, malware C2, or custom automation tooling | "
                        "Custom Python/Go network utilities, automation scrapers, or development testing tools"
                    )
                ))
        console.print()

    # ── Display findings ───────────────────────────────
    if findings:
        for f in findings:
            console.print(f"  {estilo_severidad(f.severidad)}  {f.titulo}")
            console.print(f"      [dim]{f.descripcion}[/]")
        console.print()
    else:
        console.print("  [bold bright_green][OK][/] [dim]No TLS anomalies (downgrades or suspicious JA3) detected.[/]")
        console.print()

    console.print(pie_modulo())
    return findings
