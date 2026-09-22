"""
modules/behavior_heuristics.py — §3.6 Módulo Heurísticas (--deep).

Detecta escaneo de puertos, beaconing, transferencias masivas y anomalías de comportamiento.
"""

from collections import defaultdict
from typing import List
from datetime import datetime

from rich.console import Console

from modules import Finding, Confianza, safe_get_attr, safe_int, formatear_bytes
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 10
MODULE_NAME = "Heuristics (--deep)"
MODULE_ID   = "heuristics"


def _parse_time(sniff_time):
    """Converts sniff_time to datetime or returns None."""
    try:
        return datetime.fromisoformat(str(sniff_time).replace("Z", "+00:00"))
    except Exception:
        return None


def detect_portscan(packets, window_seconds: float = 2.0, port_threshold: int = 15) -> List[Finding]:
    """Detects port scanning: multiple distinct destination IP:port from one source in short time."""
    findings = []
    
    # src_ip -> { dst_ip -> set(dst_ports) }
    scans = defaultdict(lambda: {"ports": set(), "first": None, "last": None, "targets": set()})
    
    for pkt in packets:
        src = safe_get_attr(pkt, "ip", "src")
        dst = safe_get_attr(pkt, "ip", "dst")
        if not src or not dst:
            continue
            
        dst_port = None
        if hasattr(pkt, "tcp"):
            dst_port = safe_int(safe_get_attr(pkt, "tcp", "dstport"))
        elif hasattr(pkt, "udp"):
            dst_port = safe_int(safe_get_attr(pkt, "udp", "dstport"))
            
        if dst_port is not None:
            ts = _parse_time(getattr(pkt, "sniff_time", ""))
            
            s = scans[src]
            s["ports"].add(dst_port)
            s["targets"].add(dst)
            if ts:
                if not s["first"] or ts < s["first"]: s["first"] = ts
                if not s["last"] or ts > s["last"]: s["last"] = ts

    for src, data in scans.items():
        if len(data["ports"]) >= port_threshold:
            duration = (data["last"] - data["first"]).total_seconds() if data["last"] and data["first"] else 0.0
            if duration <= window_seconds or (duration > 0 and window_seconds > 0 and len(data["ports"]) / (duration or 1.0) > (port_threshold / (window_seconds or 1.0))):
                findings.append(Finding(
                    titulo=f"Possible port scan from {src}",
                    descripcion=(
                        f"Detected connections to {len(data['ports'])} distinct ports "
                        f"across {len(data['targets'])} destination host(s) in {duration:.1f} seconds. "
                        f"Review manually."
                    ),
                    severidad="alto",
                    confianza=Confianza.MEDIA if duration > 5 else Confianza.ALTA,
                    modulo=MODULE_ID,
                    evidencia=f"Source: {src}, {len(data['ports'])} ports",
                    patron="portscan",
                    interpretacion=(
                        "Network Service Discovery / Port Scanning | "
                        "Rapid SYN/UDP connection attempts to multiple distinct destination ports from a single source host | "
                        "Legitimate vulnerability scanning tools, network inventory discovery, or monitoring services"
                    )
                ))
                
    return findings


def detect_beaconing(packets, max_variance: float = 0.1, min_connections: int = 10) -> List[Finding]:
    """Detects beaconing (C2): connections to same destination at regular intervals."""
    findings = []
    
    # pair (src, dst, dstport) -> list(timestamps)
    conns = defaultdict(list)
    
    for pkt in packets:
        if not hasattr(pkt, "tcp"): continue
        
        # Only SYN flags
        flags = safe_get_attr(pkt, "tcp", "flags")
        try:
            if int(flags, 16) != 2: continue
        except Exception:
            continue
            
        src = safe_get_attr(pkt, "ip", "src")
        dst = safe_get_attr(pkt, "ip", "dst")
        dport = safe_get_attr(pkt, "tcp", "dstport")
        ts = _parse_time(getattr(pkt, "sniff_time", ""))
        
        if src and dst and ts:
            conns[(src, dst, dport)].append(ts)
            
    for (src, dst, dport), times in conns.items():
        if len(times) < min_connections:
            continue
            
        times.sort()
        intervals = [(times[i] - times[i-1]).total_seconds() for i in range(1, len(times))]
        
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval > 0:
                # Check variance
                regular_count = sum(1 for i in intervals if abs(i - avg_interval) / avg_interval <= max_variance)
                
                if regular_count / len(intervals) > 0.8:
                    findings.append(Finding(
                        titulo=f"Beaconing pattern detected towards {dst}:{dport}",
                        descripcion=(
                            f"Detected {len(times)} regular connections "
                            f"every ~{avg_interval:.1f} seconds. Typical Command and Control (C2) behavior. "
                            f"Review manually."
                        ),
                        severidad="critico",
                        confianza=Confianza.ALTA,
                        modulo=MODULE_ID,
                        evidencia=f"{src} -> {dst}:{dport} ({len(times)} times)",
                        patron="beaconing",
                        interpretacion=(
                            "Command and Control (C2) Beaconing | "
                            "Periodic heartbeat connections with low time variance to a fixed destination IP and port | "
                            "Legitimate NTP synchronization, cloud telemetry, software update checks, or monitoring agents"
                        )
                    ))
                    
    return findings


def detect_exfiltration(packets, bytes_threshold: int = 10 * 1024 * 1024) -> List[Finding]:
    """Detects exfiltration or massive transfers (>10MB)."""
    findings = []
    
    # pair (src, dst) -> bytes_sent
    flows = defaultdict(int)
    
    for pkt in packets:
        src = safe_get_attr(pkt, "ip", "src")
        dst = safe_get_attr(pkt, "ip", "dst")
        length = safe_int(safe_get_attr(pkt, "ip", "len"))
        if src and dst:
            flows[(src, dst)] += length
            
    for (src, dst), total_bytes in flows.items():
        if total_bytes > bytes_threshold:
            findings.append(Finding(
                titulo=f"Massive data transfer: {src} -> {dst}",
                descripcion=(
                    f"Transferred {formatear_bytes(total_bytes)} between these hosts. "
                    f"If the destination is external or unexpected, this could indicate data exfiltration. "
                    f"Review manually."
                ),
                severidad="medio",
                confianza=Confianza.ALTA,
                modulo=MODULE_ID,
                evidencia=f"{formatear_bytes(total_bytes)} sent",
                patron="exfiltration",
                interpretacion=(
                    "Data Exfiltration Over Alternative Protocol | "
                    "Outbound data volume exceeding 10MB threshold between two endpoints | "
                    "Legitimate file backups, OS updates, media streaming, or large software downloads"
                )
            ))
            
    return findings


def run(packets, config: dict, console: Console) -> List[Finding]:
    """Executes behavioral heuristics."""
    findings = []
    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    if not config.get("deep_mode", False):
        console.print("  [dim]Advanced heuristics are disabled.[/]")
        console.print("  [dim]Run with --deep to enable them.[/]")
        console.print(pie_modulo())
        return findings

    # Whitelist
    whitelist = set(config.get("whitelist_ips", []))
    
    heuristic_packets = []
    for pkt in packets:
        src = safe_get_attr(pkt, "ip", "src")
        if src not in whitelist:
            heuristic_packets.append(pkt)

    console.print("  [dim]Analyzing network behavior...[/]")
    
    portscan = detect_portscan(heuristic_packets)
    beaconing = detect_beaconing(heuristic_packets)
    exfil = detect_exfiltration(heuristic_packets)
    
    findings.extend(portscan)
    findings.extend(beaconing)
    findings.extend(exfil)
    
    if findings:
        for f in findings:
            console.print(f"  {estilo_severidad(f.severidad)}  {f.titulo}")
            console.print(f"      [dim]{f.descripcion}[/]")
        console.print()
    else:
        console.print("  [bold bright_green][OK][/] [dim]No anomalous behaviors detected (scans, beaconing, exfil).[/]")
        console.print()

    console.print(pie_modulo())
    return findings
