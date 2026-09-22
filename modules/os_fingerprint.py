"""
modules/os_fingerprint.py — OS Fingerprint Module.

OS estimation via packet behavior (initial TTL, TCP window size, TCP options).
HTTP User-Agents extraction and service banners.
"""

import os
import json
from collections import defaultdict
from typing import List

from rich.console import Console
from rich.table import Table
from rich import box

from modules import Finding, Confianza, safe_get_attr, safe_int
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 5
MODULE_NAME = "OS Fingerprint"
MODULE_ID   = "os_fp"

# ──────────────────────────────────────────────────────
# Signatures database
# ──────────────────────────────────────────────────────
_SIGNATURES = []

def _load_signatures():
    global _SIGNATURES
    if _SIGNATURES:
        return
    db_path = os.path.join(os.path.dirname(__file__), "..", "data", "os_signatures.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            _SIGNATURES = json.load(f)
    except Exception:
        _SIGNATURES = []


def _estimate_initial_ttl(observed_ttl: int) -> int:
    """Estimates original TTL (commonly 64, 128, or 255)."""
    if observed_ttl <= 64:
        return 64
    elif observed_ttl <= 128:
        return 128
    else:
        return 255


def _match_signature(initial_ttl: int, window: int, tcp_options_str: str) -> dict:
    """Matches TCP parameters against signatures database."""
    _load_signatures()
    best_match = None
    
    # 1. Exact match (TTL + Window + Options)
    if tcp_options_str:
        for sig in _SIGNATURES:
            if sig.get("ttl") == initial_ttl and sig.get("window") == window and sig.get("options") == tcp_options_str:
                return sig
    
    # 2. Partial match (TTL + Window)
    for sig in _SIGNATURES:
        if sig.get("ttl") == initial_ttl and sig.get("window") == window:
            best_match = sig
            break
            
    # 3. Fallback to TTL
    if not best_match:
        if initial_ttl == 128:
            return {"os": "Windows (generic)", "family": "Windows", "confidence": "baja"}
        elif initial_ttl == 64:
            return {"os": "Linux/macOS (generic)", "family": "Unix-like", "confidence": "baja"}
        elif initial_ttl == 255:
            return {"os": "Network Device (Cisco/etc)", "family": "Network", "confidence": "baja"}
            
    return best_match


def extract_user_agents(packets) -> dict:
    """Extracts HTTP User-Agents and counts per source IP."""
    uas = defaultdict(lambda: defaultdict(int))
    for pkt in packets:
        if hasattr(pkt, "http"):
            ua = safe_get_attr(pkt, "http", "user_agent")
            src = safe_get_attr(pkt, "ip", "src")
            if ua and src:
                uas[src][ua] += 1
    return uas


def extract_banners(packets) -> list:
    """Extracts common service banners (SSH, FTP, SMTP)."""
    banners = []
    for pkt in packets:
        if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
            try:
                payload = bytes.fromhex(pkt.tcp.payload.replace(":", "")).decode("utf-8", errors="ignore")
                src = safe_get_attr(pkt, "ip", "src")
                dst_port = safe_get_attr(pkt, "tcp", "dstport")
                src_port = safe_get_attr(pkt, "tcp", "srcport")
                
                if payload.startswith("SSH-"):
                    banners.append({"ip": src, "port": src_port, "service": "SSH", "banner": payload.strip()})
                elif payload.startswith("220 "):
                    service = "FTP" if src_port == "21" else ("SMTP" if src_port in ("25", "587") else "Unknown")
                    banners.append({"ip": src, "port": src_port, "service": service, "banner": payload.strip()})
            except Exception:
                pass
                
    unique_banners = []
    seen = set()
    for b in banners:
        key = (b["ip"], b["port"], b["banner"])
        if key not in seen:
            seen.add(key)
            unique_banners.append(b)
            
    return unique_banners


def passive_fingerprint(packets) -> dict:
    """Performs passive TCP fingerprinting based on SYN packets."""
    fingerprints = {}
    
    for pkt in packets:
        if hasattr(pkt, "tcp") and hasattr(pkt, "ip"):
            flags = safe_get_attr(pkt, "tcp", "flags")
            try:
                flags_int = int(flags, 16)
            except ValueError:
                continue
                
            if flags_int == 2:  # SYN only
                src = safe_get_attr(pkt, "ip", "src")
                if src in fingerprints:
                    continue
                    
                ttl = safe_int(safe_get_attr(pkt, "ip", "ttl"))
                window = safe_int(safe_get_attr(pkt, "tcp", "window_size_value"))
                
                options = []
                if hasattr(pkt.tcp, "options"):
                    if hasattr(pkt.tcp, "options_mss"): options.append("mss")
                    if hasattr(pkt.tcp, "options_nop"): options.append("nop")
                    if hasattr(pkt.tcp, "options_wscale"): options.append("ws")
                    if hasattr(pkt.tcp, "options_sack_perm"): options.append("sack")
                    if hasattr(pkt.tcp, "options_timestamp"): options.append("ts")
                
                options_str = ",".join(options)
                
                if ttl > 0:
                    init_ttl = _estimate_initial_ttl(ttl)
                    match = _match_signature(init_ttl, window, options_str)
                    
                    fingerprints[src] = {
                        "observed_ttl": ttl,
                        "initial_ttl": init_ttl,
                        "window": window,
                        "options": options_str,
                        "match": match
                    }
                    
    return fingerprints


def run(packets, config: dict, console: Console) -> List[Finding]:
    """Executes OS fingerprint analysis."""
    findings = []
    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    fps = passive_fingerprint(packets)
    uas = extract_user_agents(packets)
    banners = extract_banners(packets)
    
    # ── Passive TCP Fingerprints ───────────────────────
    if fps:
        console.print("  [bold white]Passive TCP Fingerprinting (SYN packets):[/]")
        tabla = Table(
            show_header=True, header_style="tabla_header",
            box=box.SIMPLE_HEAVY, border_style="tabla_border", padding=(0, 1)
        )
        tabla.add_column("Source IP", style="bold cyan", width=16)
        tabla.add_column("Probable OS", width=25)
        tabla.add_column("TTL (obs/est)", justify="right", width=15)
        tabla.add_column("Window", justify="right", width=10)
        
        for ip, fp in list(fps.items())[:15]:
            match = fp["match"]
            os_name = match["os"] if match else "Unknown"
            tabla.add_row(
                ip, os_name,
                f"{fp['observed_ttl']} / {fp['initial_ttl']}",
                str(fp['window'])
            )
        console.print(tabla)
        console.print()
    else:
        console.print("  [dim]No TCP SYN packets detected for fingerprinting.[/]")
        console.print()
        
    # ── User-Agents ────────────────────────────────────
    if uas:
        console.print("  [bold white]HTTP User-Agents detected:[/]")
        for ip, ua_dict in list(uas.items())[:10]:
            for ua, count in list(ua_dict.items())[:3]:
                console.print(f"    [bold cyan]{ip}[/] -> {ua[:80]}{'...' if len(ua)>80 else ''} [dim]({count} times)[/]")
        console.print()
        
    # ── Banners ────────────────────────────────────────
    if banners:
        console.print("  [bold white]Service banners detected:[/]")
        for b in banners[:10]:
            console.print(f"    [bold cyan]{b['ip']}:{b['port']}[/] ({b['service']}) -> [white]{b['banner'][:60]}[/]")
        console.print()

    console.print(pie_modulo())
    return findings
