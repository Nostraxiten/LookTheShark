"""
modules/dns_analysis.py — DNS Analysis Module.

Extracts DNS queries/responses, calculates domain entropy to detect
DGA/tunneling, and analyzes suspicious query patterns.
"""

import math
from collections import defaultdict, Counter
from typing import List

from rich.console import Console
from rich.table import Table
from rich import box

from modules import Finding, Confianza, safe_get_attr
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 3
MODULE_NAME = "DNS"
MODULE_ID   = "dns"

ENTROPY_THRESHOLD = 3.8
TUNNEL_LABEL_LEN = 50
TUNNEL_QPS_THRESHOLD = 5.0


def entropy_score(domain: str) -> float:
    """Calculates Shannon entropy of domain name without TLD."""
    parts = domain.rstrip(".").split(".")
    if len(parts) > 1:
        label = ".".join(parts[:-1])
    else:
        label = domain

    if not label:
        return 0.0

    freq = Counter(label.lower())
    total = len(label)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def extract_dns_queries(packets) -> list:
    """Extracts all DNS queries from the capture."""
    queries = []

    for pkt in packets:
        if not hasattr(pkt, "dns"):
            continue

        dns_layer = pkt.dns

        qr = safe_get_attr(pkt, "dns", "flags_response", "")
        query_name = safe_get_attr(pkt, "dns", "qry_name", "")
        query_type = safe_get_attr(pkt, "dns", "qry_type", "")

        if not query_name:
            continue

        src = safe_get_attr(pkt, "ip", "src", "")
        dst = safe_get_attr(pkt, "ip", "dst", "")

        answers = []
        try:
            if hasattr(dns_layer, "a"):
                answers.append(str(dns_layer.a))
            if hasattr(dns_layer, "aaaa"):
                answers.append(str(dns_layer.aaaa))
            if hasattr(dns_layer, "cname"):
                answers.append(str(dns_layer.cname))
        except Exception:
            pass

        timestamp = ""
        try:
            timestamp = str(pkt.sniff_time)
        except Exception:
            pass

        queries.append({
            "name": query_name,
            "type": query_type,
            "src": src,
            "dst": dst,
            "answers": answers,
            "is_response": str(qr) == "1",
            "timestamp": timestamp,
        })

    return queries


def detect_dga(queries: list) -> List[Finding]:
    """Detects domains with high entropy (possible DGA)."""
    findings = []
    checked = set()

    for q in queries:
        domain = q["name"].lower().rstrip(".")
        if domain in checked:
            continue
        checked.add(domain)

        ent = entropy_score(domain)
        if ent >= ENTROPY_THRESHOLD:
            parts = domain.split(".")
            if len(parts) >= 2 and len(parts[-2]) <= 3:
                continue

            findings.append(Finding(
                titulo=f"High entropy domain: {domain}",
                descripcion=(
                    f"Shannon entropy: {ent:.2f} (threshold: {ENTROPY_THRESHOLD}). "
                    f"Could indicate an algorithmically generated domain (DGA). "
                    f"Review manually."
                ),
                severidad="medio",
                confianza=Confianza.MEDIA,
                modulo=MODULE_ID,
                evidencia=f"Query from {q['src']} -> {q['dst']}",
                patron="dga",
                timestamp=q.get("timestamp", ""),
                interpretacion=(
                    "Domain Generation Algorithms (DGA) / C2 Communication | "
                    "High Shannon entropy (>3.8) in query domain label | "
                    "Legitimate content delivery networks (CDNs), cloud load balancers, anti-spam lookups, or UUID-based API endpoints"
                )
            ))

    return findings


def detect_tunneling(queries: list, threshold: float = TUNNEL_QPS_THRESHOLD) -> List[Finding]:
    """Detects potential DNS tunneling via query rate or long subdomains."""
    findings = []

    # 1. Long subdomains
    checked_long = set()
    for q in queries:
        domain = q["name"].lower().rstrip(".")
        parts = domain.split(".")

        for part in parts:
            if len(part) > TUNNEL_LABEL_LEN and domain not in checked_long:
                checked_long.add(domain)
                findings.append(Finding(
                    titulo=f"Unusually long subdomain: {domain[:60]}...",
                    descripcion=(
                        f"Label with {len(part)} characters detected. "
                        f"Long subdomains are typical of DNS tunneling (encoded payloads). "
                        f"Review manually."
                    ),
                    severidad="alto",
                    confianza=Confianza.MEDIA,
                    modulo=MODULE_ID,
                    evidencia=f"Query from {q['src']}",
                    patron="dns_tunneling",
                    timestamp=q.get("timestamp", ""),
                    interpretacion=(
                        "DNS Tunneling / Data Exfiltration | "
                        "Unusually long DNS label (>50 chars) containing encoded data payload | "
                        "Legitimate antivirus update queries, DKIM/SPF DNS records, or cryptographic handshake identifiers"
                    )
                ))

    # 2. Query rate per DNS destination
    queries_per_dst = defaultdict(list)
    for q in queries:
        if not q["is_response"]:
            queries_per_dst[q["dst"]].append(q)

    for dst, qs in queries_per_dst.items():
        if len(qs) < 10:
            continue

        timestamps = []
        for q in qs:
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(q["timestamp"].replace("Z", "+00:00") if q["timestamp"] else "")
                timestamps.append(ts)
            except Exception:
                continue

        if len(timestamps) >= 2:
            timestamps.sort()
            span = (timestamps[-1] - timestamps[0]).total_seconds()
            if span > 0:
                qps = len(timestamps) / span
                if qps >= threshold:
                    findings.append(Finding(
                        titulo=f"High DNS query rate towards {dst}",
                        descripcion=(
                            f"{qps:.1f} queries/second (threshold: {threshold}). "
                            f"Could indicate DNS tunneling or high-rate exfiltration. "
                            f"Review manually."
                        ),
                        severidad="alto",
                        confianza=Confianza.MEDIA,
                        modulo=MODULE_ID,
                        evidencia=f"{len(qs)} queries in {span:.0f}s",
                        patron="dns_tunneling",
                        interpretacion=(
                            "DNS Tunneling / Exfiltration Rate Anomaly | "
                            "DNS query rate exceeding 5.0 queries/second to a single resolver destination | "
                            "Legitimate high-volume recursive resolver traffic, intense web browser prefetching, or local DNS cache misses"
                        )
                    ))

    return findings


def run(packets, config: dict, console: Console) -> List[Finding]:
    """Executes DNS analysis."""
    findings = []

    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    queries = extract_dns_queries(packets)

    if not queries:
        console.print("  [dim]No DNS packets found in capture.[/]")
        console.print(pie_modulo())
        return findings

    # ── Summary ────────────────────────────────────────
    unique_domains = set(q["name"].lower().rstrip(".") for q in queries)
    query_only = [q for q in queries if not q["is_response"]]
    response_only = [q for q in queries if q["is_response"]]

    console.print(f"  DNS Queries:       [bold white]{len(query_only)}[/]")
    console.print(f"  DNS Responses:     [bold white]{len(response_only)}[/]")
    console.print(f"  Unique Domains:    [bold white]{len(unique_domains)}[/]")
    console.print()

    # ── Most queried domains ───────────────────────────
    domain_counts = Counter(q["name"].lower().rstrip(".") for q in query_only)

    tabla = Table(
        show_header=True,
        header_style="tabla_header",
        box=box.SIMPLE_HEAVY,
        border_style="tabla_border",
        padding=(0, 1),
        title="Most Queried Domains",
        title_style="bold white",
    )
    tabla.add_column("Domain", style="bold cyan", width=40)
    tabla.add_column("Queries", justify="right", width=10)
    tabla.add_column("Entropy", justify="right", width=10)

    for domain, count in domain_counts.most_common(15):
        ent = entropy_score(domain)
        ent_style = "bold yellow" if ent >= ENTROPY_THRESHOLD else "dim"
        tabla.add_row(
            domain[:40],
            f"{count:,}",
            f"[{ent_style}]{ent:.2f}[/]",
        )
    console.print(tabla)
    console.print()

    # ── Detection ──────────────────────────────────────
    dga_findings = detect_dga(queries)
    findings.extend(dga_findings)

    tunnel_findings = detect_tunneling(queries)
    findings.extend(tunnel_findings)

    if findings:
        console.print()
        for f in findings:
            console.print(f"  {estilo_severidad(f.severidad)}  {f.titulo}")
            console.print(f"      [dim]{f.descripcion}[/]")
            console.print(f"      [dim]-> {f.evidencia}[/]")
            console.print(f"      [dim]Review manually.[/]")
        console.print()
    else:
        console.print("  [bold bright_green][OK][/] [dim]No DNS anomalies detected.[/]")
        console.print()

    console.print(pie_modulo())
    return findings
