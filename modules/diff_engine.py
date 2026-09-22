"""
modules/diff_engine.py — §3.13 Capture Diff / Comparison Module.

Compares two captures (before/after an incident or rule change)
and displays only what changed. This module operates independently
of the standard single-pcap analysis flow.
"""

from collections import Counter

from rich.console import Console
from rich.table import Table

from modules import safe_get_attr, safe_int
from ui.theme import cabecera_modulo, pie_modulo


MODULE_NUM  = 12
MODULE_NAME = "Capture Diff"
MODULE_ID   = "diff"


# ─────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────

def _extract_profile(packets) -> dict:
    """Build a quick network profile from a capture (IPs, ports, protocols, flows).

    Returns a dict with:
        ips       - set of all unique IP addresses (src + dst)
        ports     - set of all unique destination ports (TCP/UDP)
        protocols - set of highest-layer protocol names
        flows     - set of (src_ip, dst_ip, dst_port) tuples
        proto_counts - Counter of protocols for volume comparison
        port_counts  - Counter of dst ports for volume comparison
    """
    profile: dict = {
        "ips":          set(),
        "ports":        set(),
        "protocols":    set(),
        "flows":        set(),
        "proto_counts": Counter(),
        "port_counts":  Counter(),
        "total":        0,
    }

    for pkt in packets:
        profile["total"] += 1

        src = safe_get_attr(pkt, "ip", "src")
        dst = safe_get_attr(pkt, "ip", "dst")

        if src:
            profile["ips"].add(src)
        if dst:
            profile["ips"].add(dst)

        try:
            layer = pkt.highest_layer
            profile["protocols"].add(layer)
            profile["proto_counts"][layer] += 1
        except Exception:
            pass

        dport = None
        if hasattr(pkt, "tcp"):
            dport = safe_int(safe_get_attr(pkt, "tcp", "dstport")) or None
        elif hasattr(pkt, "udp"):
            dport = safe_int(safe_get_attr(pkt, "udp", "dstport")) or None

        if dport:
            profile["ports"].add(dport)
            profile["port_counts"][dport] += 1
            if src and dst:
                profile["flows"].add((src, dst, dport))

    return profile


def _pct_change(a: int, b: int) -> str:
    """Return a formatted percentage change string from a to b."""
    if a == 0:
        return "+inf%" if b > 0 else "0%"
    delta = ((b - a) / a) * 100
    sign  = "+" if delta >= 0 else ""
    return f"{sign}{delta:.0f}%"


def _print_set_diff(
    console: Console,
    label_new: str,
    label_gone: str,
    new_items,
    gone_items,
    limit: int = 12,
    fmt=None,
) -> None:
    """Print added and removed items from two sets."""
    if new_items:
        console.print(f"  [bold bright_green]  + {label_new} ({len(new_items)}):[/]")
        items = list(new_items)[:limit]
        for item in items:
            display = fmt(item) if fmt else str(item)
            console.print(f"      {display}")
        if len(new_items) > limit:
            console.print(f"      [dim]... and {len(new_items) - limit} more[/]")
        console.print()

    if gone_items:
        console.print(f"  [bold red]  - {label_gone} ({len(gone_items)}):[/]")
        items = list(gone_items)[:limit]
        for item in items:
            display = fmt(item) if fmt else str(item)
            console.print(f"      {display}")
        if len(gone_items) > limit:
            console.print(f"      [dim]... and {len(gone_items) - limit} more[/]")
        console.print()


# ─────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────

def run(packets1, packets2, config: dict, console: Console) -> None:
    """Perform a diff between two parsed captures and report what changed."""
    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    if not packets1 or not packets2:
        console.print("  [bold red]ERROR: Missing data — both captures are required for comparison.[/]")
        console.print(pie_modulo())
        return

    console.print("  [dim]Building network profiles for both captures...[/]")
    console.print()

    p1 = _extract_profile(packets1)
    p2 = _extract_profile(packets2)

    # ── Summary table ──────────────────────────────────────
    console.print("  [bold white]CAPTURE SUMMARY[/]")
    console.print()

    tbl = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 2))
    tbl.add_column("Metric",     style="dim")
    tbl.add_column("Capture 1",  justify="right")
    tbl.add_column("Capture 2",  justify="right")
    tbl.add_column("Change",     justify="right")

    rows = [
        ("Total packets",     p1["total"],           p2["total"]),
        ("Unique IPs",        len(p1["ips"]),         len(p2["ips"])),
        ("Unique dst ports",  len(p1["ports"]),       len(p2["ports"])),
        ("Unique protocols",  len(p1["protocols"]),   len(p2["protocols"])),
        ("Unique flows",      len(p1["flows"]),       len(p2["flows"])),
    ]
    for label, v1, v2 in rows:
        change = _pct_change(v1, v2)
        color  = "bright_green" if v2 > v1 else ("red" if v2 < v1 else "dim")
        tbl.add_row(label, str(v1), str(v2), f"[{color}]{change}[/]")

    console.print(tbl)
    console.print()

    # ── Additions (in capture 2, not in capture 1) ─────────
    console.print("  [bold white]ADDITIONS IN CAPTURE 2:[/]")
    console.print()

    new_protos = p2["protocols"] - p1["protocols"]
    new_ports  = p2["ports"]     - p1["ports"]
    new_ips    = p2["ips"]       - p1["ips"]
    new_flows  = p2["flows"]     - p1["flows"]

    _print_set_diff(console, "New protocols",      "",             new_protos, set())
    _print_set_diff(console, "New dst ports",      "",             new_ports,  set())
    _print_set_diff(console, "New IPs observed",   "",             new_ips,    set())
    _print_set_diff(
        console,
        "New communication flows", "",
        new_flows, set(),
        fmt=lambda f: f"{f[0]} -> {f[1]}:{f[2]}",
    )

    if not (new_protos or new_ports or new_ips or new_flows):
        console.print(
            "  [dim]No additions found — capture 2 is a subset of or identical in profile to capture 1.[/]"
        )
        console.print()

    # ── Removals (in capture 1, gone in capture 2) ─────────
    console.print("  [bold white]REMOVALS FROM CAPTURE 2:[/]")
    console.print()

    gone_protos = p1["protocols"] - p2["protocols"]
    gone_ports  = p1["ports"]     - p2["ports"]
    gone_ips    = p1["ips"]       - p2["ips"]
    gone_flows  = p1["flows"]     - p2["flows"]

    _print_set_diff(console, "", "Protocols no longer seen",  set(), gone_protos)
    _print_set_diff(console, "", "Dst ports no longer seen",  set(), gone_ports)
    _print_set_diff(console, "", "IPs no longer transmitting", set(), gone_ips)
    _print_set_diff(
        console,
        "", "Flows cut / inactive",
        set(), gone_flows,
        fmt=lambda f: f"{f[0]} -> {f[1]}:{f[2]}",
    )

    if not (gone_protos or gone_ports or gone_ips or gone_flows):
        console.print(
            "  [dim]No removals — every flow and IP from capture 1 is still present in capture 2.[/]"
        )
        console.print()

    # ── Top-protocol volume shift ───────────────────────────
    shared_protos = p1["protocols"] & p2["protocols"]
    if shared_protos:
        console.print("  [bold white]PROTOCOL VOLUME SHIFT (shared protocols):[/]")
        console.print()
        vol_tbl = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 2))
        vol_tbl.add_column("Protocol", style="dim")
        vol_tbl.add_column("Cap 1 pkts", justify="right")
        vol_tbl.add_column("Cap 2 pkts", justify="right")
        vol_tbl.add_column("Change",     justify="right")

        for proto in sorted(shared_protos):
            c1 = p1["proto_counts"][proto]
            c2 = p2["proto_counts"][proto]
            change = _pct_change(c1, c2)
            color  = "bright_green" if c2 > c1 else ("red" if c2 < c1 else "dim")
            vol_tbl.add_row(proto, str(c1), str(c2), f"[{color}]{change}[/]")

        console.print(vol_tbl)
        console.print()

    console.print(pie_modulo())
