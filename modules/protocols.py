"""
modules/protocols.py — Protocols Module.

Breakdown of observed protocols, most frequent destination ports and services,
and detection of deprecated/insecure protocols on the network.
"""

from collections import defaultdict
from typing import List

from rich.console import Console
from rich.table import Table
from rich import box

from modules import Finding, Confianza, safe_get_attr, safe_int
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 2
MODULE_NAME = "Protocols"
MODULE_ID   = "protocols"

# ──────────────────────────────────────────────────────
# Ports -> known service
# ──────────────────────────────────────────────────────
SERVICIOS_CONOCIDOS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-S", 68: "DHCP-C", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "SMTP-Sub",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9200: "Elasticsearch",
    27017: "MongoDB",
}

# Protocols considered deprecated or risky
PROTOCOLOS_DEPRECADOS = {
    "telnet": {"severidad": "alto", "razon": "Plaintext protocol, replaced by SSH"},
    "ftp": {"severidad": "medio", "razon": "Plaintext credentials, prefer SFTP/SCP"},
    "tftp": {"severidad": "medio", "razon": "No authentication or encryption"},
    "snmp": {"severidad": "medio", "razon": "SNMPv1/v2c transmits community strings in cleartext"},
    "http": {"severidad": "bajo", "razon": "Unencrypted traffic, prefer HTTPS"},
    "pop3": {"severidad": "medio", "razon": "Plaintext credentials without TLS"},
    "nntp": {"severidad": "bajo", "razon": "Obsolete protocol"},
}

# Ports mapped to deprecated protocols
PUERTOS_DEPRECADOS = {
    23: "telnet", 21: "ftp", 69: "tftp", 161: "snmp",
    80: "http", 110: "pop3", 119: "nntp",
}


def protocol_breakdown(packets) -> dict:
    """Counts packets by highest layer protocol."""
    conteo = defaultdict(int)
    for pkt in packets:
        try:
            highest = pkt.highest_layer
            conteo[highest] += 1
        except Exception:
            conteo["UNKNOWN"] += 1
    return dict(sorted(conteo.items(), key=lambda x: x[1], reverse=True))


def port_breakdown(packets) -> dict:
    """Counts packets by destination TCP/UDP port."""
    conteo = defaultdict(int)

    for pkt in packets:
        dst_port = None
        if hasattr(pkt, "tcp"):
            dst_port = safe_int(safe_get_attr(pkt, "tcp", "dstport"), None)
        elif hasattr(pkt, "udp"):
            dst_port = safe_int(safe_get_attr(pkt, "udp", "dstport"), None)

        if dst_port is not None:
            conteo[dst_port] += 1

    return dict(sorted(conteo.items(), key=lambda x: x[1], reverse=True))


def detect_uncommon_protocols(packets, baseline_profile: dict = None) -> List[Finding]:
    """Detects deprecated or insecure protocols."""
    findings = []
    ports_seen = set()

    for pkt in packets:
        dst_port = None
        if hasattr(pkt, "tcp"):
            dst_port = safe_int(safe_get_attr(pkt, "tcp", "dstport"), None)
        elif hasattr(pkt, "udp"):
            dst_port = safe_int(safe_get_attr(pkt, "udp", "dstport"), None)

        if dst_port is not None and dst_port in PUERTOS_DEPRECADOS:
            if dst_port not in ports_seen:
                ports_seen.add(dst_port)
                proto = PUERTOS_DEPRECADOS[dst_port]
                info = PROTOCOLOS_DEPRECADOS.get(proto, {})

                if baseline_profile:
                    expected = baseline_profile.get("expected_protocols", [])
                    if proto.lower() in [p.lower() for p in expected]:
                        continue

                findings.append(Finding(
                    titulo=f"Deprecated protocol detected: {proto.upper()} (port {dst_port})",
                    descripcion=info.get("razon", "Potentially insecure protocol"),
                    severidad=info.get("severidad", "bajo"),
                    confianza=Confianza.MEDIA,
                    modulo=MODULE_ID,
                    evidencia=f"Destination port {dst_port} observed in capture",
                    patron="cleartext_protocol",
                    interpretacion=(
                        "Insecure / Cleartext Protocol Usage (Network Sniffing) | "
                        "Unencrypted or deprecated protocol communication observed on standard port | "
                        "Legacy network management, embedded systems, local debugging, or lab test environment"
                    )
                ))

    return findings


def run(packets, config: dict, console: Console) -> List[Finding]:
    """Executes protocol analysis."""
    findings = []

    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    proto_stats = protocol_breakdown(packets)
    port_stats = port_breakdown(packets)

    # ── Protocol Breakdown Table ───────────────────────
    console.print("  [bold white]Protocol Breakdown:[/]")
    console.print()

    tabla = Table(
        show_header=True,
        header_style="tabla_header",
        box=box.SIMPLE_HEAVY,
        border_style="tabla_border",
        padding=(0, 1),
    )
    tabla.add_column("Protocol", style="bold cyan", width=20)
    tabla.add_column("Packets", justify="right", width=12)
    tabla.add_column("% of Total", justify="right", width=12)

    total_pkts = sum(proto_stats.values())
    for proto, count in list(proto_stats.items())[:15]:
        pct = (count / total_pkts * 100) if total_pkts > 0 else 0
        tabla.add_row(proto, f"{count:,}", f"{pct:.1f}%")
    console.print(tabla)
    console.print()

    # ── Port Table ─────────────────────────────────────
    if port_stats:
        console.print("  [bold white]Most Frequent Ports:[/]")
        console.print()

        tabla_p = Table(
            show_header=True,
            header_style="tabla_header",
            box=box.SIMPLE_HEAVY,
            border_style="tabla_border",
            padding=(0, 1),
        )
        tabla_p.add_column("Port", style="bold cyan", width=10)
        tabla_p.add_column("Service", width=18)
        tabla_p.add_column("Packets", justify="right", width=12)

        for port, count in list(port_stats.items())[:12]:
            svc = SERVICIOS_CONOCIDOS.get(port, f"port/{port}")
            tabla_p.add_row(str(port), svc, f"{count:,}")
        console.print(tabla_p)
        console.print()

    # ── Deprecated Protocols ───────────────────────────
    baseline = config.get("baseline_profile")
    deprecados = detect_uncommon_protocols(packets, baseline)
    findings.extend(deprecados)

    if deprecados:
        console.print("  [bold yellow]Deprecated/Insecure protocols detected:[/]")
        for f in deprecados:
            console.print(f"  {estilo_severidad(f.severidad)}  {f.titulo}")
            console.print(f"      [dim]{f.descripcion}[/]")
            console.print(f"      [dim]Review manually.[/]")
        console.print()
    else:
        console.print("  [bold bright_green][OK][/] [dim]No deprecated protocols detected.[/]")
        console.print()

    console.print(pie_modulo())

    return findings
