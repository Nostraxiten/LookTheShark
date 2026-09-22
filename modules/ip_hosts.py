"""
modules/ip_hosts.py — IP / Hosts Module.

Extracts and classifies source/destination IPs, traffic volume, top talkers,
conversation pairs, and optional geolocation.
"""

import os
import json
from collections import defaultdict
from typing import List

from rich.console import Console
from rich.table import Table
from rich import box

from modules import Finding, Confianza, es_ip_privada, formatear_bytes, safe_get_attr, safe_int
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 1
MODULE_NAME = "IP / Hosts"
MODULE_ID   = "ip_hosts"

_geoip_reader = None

def _init_geoip():
    global _geoip_reader
    if _geoip_reader is not None:
        return
    try:
        import geoip2.database
        db_paths = [
            os.path.join(os.path.dirname(__file__), "..", "data", "geoip", "GeoLite2-City.mmdb"),
            os.path.join(os.path.dirname(__file__), "..", "data", "GeoLite2-City.mmdb"),
        ]
        for p in db_paths:
            if os.path.isfile(p):
                _geoip_reader = geoip2.database.Reader(p)
                return
    except ImportError:
        pass


def _geolocate(ip: str) -> str:
    """Geolocates an IP. Returns 'City, Country' or '—'."""
    _init_geoip()
    if _geoip_reader is None:
        return "—"
    if es_ip_privada(ip):
        return "LAN"
    try:
        resp = _geoip_reader.city(ip)
        parts = []
        if resp.city.name:
            parts.append(resp.city.name)
        if resp.country.name:
            parts.append(resp.country.name)
        return ", ".join(parts) if parts else "—"
    except Exception:
        return "—"


def get_unique_ips(packets) -> dict:
    """Extracts unique IPs with traffic statistics."""
    stats = defaultdict(lambda: {"pkts_src": 0, "pkts_dst": 0, "bytes_src": 0, "bytes_dst": 0})

    for pkt in packets:
        src = safe_get_attr(pkt, "ip", "src")
        dst = safe_get_attr(pkt, "ip", "dst")
        length = safe_int(safe_get_attr(pkt, "ip", "len"), 0)

        if src:
            stats[src]["pkts_src"] += 1
            stats[src]["bytes_src"] += length
        if dst:
            stats[dst]["pkts_dst"] += 1
            stats[dst]["bytes_dst"] += length

    return dict(stats)


def get_top_talkers(ip_stats: dict, n: int = 10) -> list:
    """Top N IPs by total traffic volume."""
    ranked = []
    for ip, s in ip_stats.items():
        total_bytes = s["bytes_src"] + s["bytes_dst"]
        total_pkts = s["pkts_src"] + s["pkts_dst"]
        ranked.append({
            "ip": ip,
            "total_bytes": total_bytes,
            "total_pkts": total_pkts,
            "private": es_ip_privada(ip),
            "geo": _geolocate(ip),
        })
    ranked.sort(key=lambda x: x["total_bytes"], reverse=True)
    return ranked[:n]


def get_conversation_pairs(packets) -> list:
    """IP <-> IP conversation pairs with counts."""
    pairs = defaultdict(lambda: {"pkts": 0, "bytes": 0})

    for pkt in packets:
        src = safe_get_attr(pkt, "ip", "src")
        dst = safe_get_attr(pkt, "ip", "dst")
        length = safe_int(safe_get_attr(pkt, "ip", "len"), 0)

        if src and dst:
            key = tuple(sorted([src, dst]))
            pairs[key]["pkts"] += 1
            pairs[key]["bytes"] += length

    result = [
        {"pair": f"{k[0]} <-> {k[1]}", "pkts": v["pkts"], "bytes": v["bytes"]}
        for k, v in pairs.items()
    ]
    result.sort(key=lambda x: x["bytes"], reverse=True)
    return result[:20]


def run(packets, config: dict, console: Console) -> List[Finding]:
    """Executes IP/Hosts analysis and displays results."""
    findings = []

    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    ip_stats = get_unique_ips(packets)
    top_talkers = get_top_talkers(ip_stats, n=15)
    conversations = get_conversation_pairs(packets)

    # ── Summary ────────────────────────────────────────
    total_ips = len(ip_stats)
    ips_publicas = [ip for ip in ip_stats if not es_ip_privada(ip)]
    ips_privadas = [ip for ip in ip_stats if es_ip_privada(ip)]

    console.print(f"  Unique IPs:      [bold white]{total_ips}[/]")
    console.print(f"  Private IPs:     [bold white]{len(ips_privadas)}[/]")
    console.print(f"  Public IPs:      [bold white]{len(ips_publicas)}[/]")
    console.print()

    # ── Top Talkers ────────────────────────────────────
    if top_talkers:
        tabla = Table(
            show_header=True,
            header_style="tabla_header",
            box=box.SIMPLE_HEAVY,
            border_style="tabla_border",
            padding=(0, 1),
            title="Top Talkers",
            title_style="bold white",
        )
        tabla.add_column("IP", style="bold cyan", width=18)
        tabla.add_column("Type", width=8)
        tabla.add_column("Packets", justify="right", width=10)
        tabla.add_column("Bytes", justify="right", width=12)
        tabla.add_column("Geo", style="dim", width=25)

        for t in top_talkers[:10]:
            tipo = "[dim]LAN[/]" if t["private"] else "[bold white]WAN[/]"
            tabla.add_row(
                t["ip"], tipo,
                f"{t['total_pkts']:,}",
                formatear_bytes(t["total_bytes"]),
                t["geo"],
            )
        console.print(tabla)
        console.print()

    # ── Top Conversations ──────────────────────────────
    if conversations:
        console.print("  [bold white]Top Conversations:[/]")
        for c in conversations[:8]:
            console.print(
                f"    {c['pair']}  [dim]({c['pkts']:,} pkts, "
                f"{formatear_bytes(c['bytes'])})[/]"
            )
        console.print()

    # ── Whitelist check ────────────────────────────────
    whitelist = set(config.get("whitelist_ips", []))
    if whitelist:
        ips_no_whitelist = [ip for ip in ips_publicas if ip not in whitelist]
        console.print(f"  [dim]Public IPs outside whitelist: {len(ips_no_whitelist)}[/]")

    console.print(pie_modulo())

    return findings
