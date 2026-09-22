#!/usr/bin/env python3
"""
lookingtheshark.py — Punto de entrada de LookingTheShark.

Traductor forense de capturas de red.
Flujo: Banner → Parseo (pyshark) → Ejecución de módulos → Reporte.
"""

import os
import sys
import argparse
import time
import json
import asyncio
from typing import List, Optional

try:
    import pyshark
except ImportError:
    print("[ERROR] pyshark no instalado. Ejecuta: pip install -r requirements.txt")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
except ImportError:
    print("[ERROR] rich no instalado. Ejecuta: pip install -r requirements.txt")
    sys.exit(1)

from ui.theme import SHARK_THEME, SEPARADOR
from ui.banner import mostrar_banner
from ui.menu import solicitar_archivo, seleccionar_modulos, solicitar_exportacion, MENU_ITEMS

# ── Importar módulos ───────────────────────────────────
from modules import Finding
import modules.ip_hosts
import modules.protocols
import modules.file_extraction
import modules.os_fingerprint
import modules.dns_analysis
import modules.behavior_heuristics
import modules.tls_analysis
import modules.credentials_plain
import modules.layer2_anomalies
import modules.reputation_offline
import modules.mitre_mapping
import modules.diff_engine
import modules.report_builder

# ──────────────────────────────────────────────────────
# Tool registry
# ──────────────────────────────────────────────────────
TOOLS = {
    "ip_hosts":   {"name": "IP / Hosts",            "fn": modules.ip_hosts.run},
    "protocols":  {"name": "Protocols",             "fn": modules.protocols.run},
    "dns":        {"name": "DNS",                   "fn": modules.dns_analysis.run},
    "files":      {"name": "Files / Objects",       "fn": modules.file_extraction.run},
    "os_fp":      {"name": "OS Fingerprint",        "fn": modules.os_fingerprint.run},
    "tls":        {"name": "TLS / Certificates",    "fn": modules.tls_analysis.run},
    "creds":      {"name": "Cleartext Credentials", "fn": modules.credentials_plain.run},
    "layer2":     {"name": "Layer 2 / Local Network","fn": modules.layer2_anomalies.run},
    "reputation": {"name": "Offline Reputation",    "fn": modules.reputation_offline.run},
    "heuristics": {"name": "Heuristics (--deep)",   "fn": modules.behavior_heuristics.run},
    "mitre":      {"name": "MITRE ATT&CK Mapping",  "fn": None}, # Executed at the end
    "diff":       {"name": "Diff Between Captures", "fn": None}, # Special execution
}

def load_capture(filepath: str, console: Console, progress=None, task_id=None) -> list:
    """Loads and parses the pcap using pyshark."""
    if progress is None:
        console.print(f"  [dim]Parsing capture {filepath}... (this may take a while)[/]")
    try:
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

        # keep_packets=True to iterate multiple times
        cap = pyshark.FileCapture(filepath, keep_packets=True)
        cap.load_packets() 
        if progress is not None and task_id is not None:
            progress.update(task_id, completed=1, description="[green]Capture parsed[/]")
        return cap
    except Exception as e:
        console.print(f"  [bold red][FAIL] Error reading capture:[/] {e}")
        return []

def load_json(filepath: str, console: Console) -> dict:
    if not filepath: return {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        console.print(f"  [bold red][!] Error loading {filepath}:[/] {e}")
        return {}


def run_analysis(
    pcap_path: str,
    selected_modules: List[str],
    config: dict,
    console: Console
) -> List[Finding]:
    
    all_findings = []
    capture_info = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        
        parse_task = progress.add_task(f"[cyan]Parsing capture {os.path.basename(pcap_path)}...", total=1)
        
        packets = load_capture(pcap_path, console, progress, parse_task)
        if not packets:
            return [], {}
            
        duracion = "Unknown"
        try:
            if len(packets) > 0:
                t1 = float(packets[0].sniff_timestamp)
                t2 = float(packets[-1].sniff_timestamp)
                from modules import formatear_duracion
                duracion = formatear_duracion(t2 - t1)
        except Exception:
            pass
            
        capture_info = {
            "nombre": os.path.basename(pcap_path),
            "paquetes": len(packets),
            "duracion": duracion,
            "path": pcap_path
        }
        
        config["pcap_path"] = pcap_path # For extraction
        config["capture_info"] = capture_info
        
        progress.print(f"  [bold cyan][~] Capture loaded:[/] {capture_info['nombre']} ({len(packets)} pkts, {duracion})")
        progress.print(SEPARADOR)
        
        modules_to_run = [m for m in selected_modules if m not in ("mitre", "diff")]
        
        if modules_to_run:
            mod_task = progress.add_task("[cyan]Analyzing modules...", total=len(modules_to_run))
            
            for mod_id in modules_to_run:
                tool = TOOLS.get(mod_id)
                if tool and tool["fn"]:
                    progress.update(mod_task, description=f"[cyan]Running {tool['name']}...")
                    try:
                        findings = tool["fn"](packets, config, console)
                        if findings:
                            all_findings.extend(findings)
                    except Exception as e:
                        progress.print(f"  [bold red][FAIL] Error in {tool['name']}:[/] {e}")
                progress.advance(mod_task)
                
            progress.update(mod_task, description="[green]Module analysis completed[/]")
                
        # MITRE Mapping at the end
        if "mitre" in selected_modules or config.get("mitre_mode"):
            mitre_task = progress.add_task("[cyan]Mapping to MITRE ATT&CK...", total=1)
            config["mitre_mode"] = True
            modules.mitre_mapping.run(all_findings, config, console)
            progress.update(mitre_task, completed=1, description="[green]MITRE mapping completed[/]")
            
    return all_findings, capture_info


def main():
    parser = argparse.ArgumentParser(description="LookingTheShark — Forensic translator for network captures")
    parser.add_argument("--file", help=".pcap/.pcapng file to analyze")
    parser.add_argument("--modules", help="Modules to execute (comma-separated)")
    parser.add_argument("--deep", action="store_true", help="Enable behavioral heuristics")
    parser.add_argument("--baseline", help="Normal network baseline profile in JSON")
    parser.add_argument("--whitelist-ips", help="Text file of IPs to exclude (one per line)")
    parser.add_argument("--time-range", help="Time window HH:MM-HH:MM (not implemented in this demo)")
    parser.add_argument("--confidence-threshold", choices=["bajo","medio","alto"], default="bajo", help="Minimum confidence threshold (bajo, medio, alto)")
    parser.add_argument("--anonymize", action="store_true", help="Replace IPs with host-A, host-B in the report")
    parser.add_argument("--format", default="md", help="md,json,html (comma-combinable)")
    parser.add_argument("--mitre", action="store_true", help="Enable MITRE ATT&CK mapping")
    parser.add_argument("--diff", nargs=2, help="Compare two captures (pcap_before pcap_after)")
    parser.add_argument("--output", help="Base path for generated report (without extension)")
    parser.add_argument("--color", action="store_true", help="Force ANSI colors")
    parser.add_argument("--menu", action="store_true", help="Interactive menu mode")
    
    args = parser.parse_args()
    
    console = Console(theme=SHARK_THEME, force_terminal=args.color if args.color else None)
    
    mostrar_banner(console)
    
    # ── Global configuration ───────────────────────────
    whitelist = []
    if args.whitelist_ips and os.path.isfile(args.whitelist_ips):
        with open(args.whitelist_ips, "r") as f:
            whitelist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            
    config = {
        "deep_mode": args.deep,
        "mitre_mode": args.mitre,
        "baseline_profile": load_json(args.baseline, console),
        "whitelist_ips": whitelist,
        "confidence_threshold": args.confidence_threshold,
        "anonymize": args.anonymize,
        "format": args.format,
        "output_base": args.output or "report_capture",
    }
    
    # ── DIFF MODE ──────────────────────────────────────
    if args.diff:
        cap1, cap2 = args.diff
        console.print(f"  [bold white]Diff Mode:[/] {cap1} vs {cap2}")
        packets1 = load_capture(cap1, console)
        packets2 = load_capture(cap2, console)
        modules.diff_engine.run(packets1, packets2, config, console)
        sys.exit(0)
        
    # ── MENU MODE ──────────────────────────────────────
    if args.menu or (not args.file and not args.diff):
        pcap_path = solicitar_archivo(console)
        if not pcap_path:
            console.print("\n  [dim]Exiting...[/]\n")
            sys.exit(0)
            
        mods = seleccionar_modulos(console)
        if not mods:
            console.print("\n  [dim]Exiting...[/]\n")
            sys.exit(0)
            
        # If heuristics or mitre explicitly selected, activate flags
        if "heuristics" in mods: config["deep_mode"] = True
        if "mitre" in mods: config["mitre_mode"] = True
            
        export_fmt = solicitar_exportacion(console)
        if export_fmt:
            config["format"] = export_fmt
            # In interactive mode, ask for report name
            from ui.menu import solicitar_ruta_salida
            config["output_base"] = solicitar_ruta_salida(console, export_fmt, os.path.splitext(os.path.basename(pcap_path))[0])
        else:
            config["format"] = ""
            
    # ── CLI MODE ───────────────────────────────────────
    else:
        pcap_path = args.file
        if args.modules:
            mods = [m.strip() for m in args.modules.split(",")]
        else:
            # Default: read-only modules
            mods = ["ip_hosts", "protocols", "dns", "files", "os_fp", "tls", "creds", "layer2", "reputation"]
            if args.deep: mods.append("heuristics")
            if args.mitre: mods.append("mitre")
            
    console.print()
    console.print(SEPARADOR)
    
    # ── EXECUTION ──────────────────────────────────────
    inicio_total = time.perf_counter()
    
    findings, cap_info = run_analysis(pcap_path, mods, config, console)
    
    # ── EXPORT ─────────────────────────────────────────
    if config.get("format"):
        console.print(SEPARADOR)
        console.print("  [bold white]Generating reports...[/]")
        modules.report_builder.build_reports(findings, config, cap_info)
        
    tiempo_total = time.perf_counter() - inicio_total
    console.print(SEPARADOR)
    console.print(f"  [dim]Analysis completed in {tiempo_total:.1f} seconds.[/]")
    console.print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        from rich import print as rprint
        rprint("\n\n  [bold yellow][!] Interrupted by user.[/]\n")
        sys.exit(0)
