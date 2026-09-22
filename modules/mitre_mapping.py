"""
modules/mitre_mapping.py — §3.12 Módulo MITRE ATT&CK.

Mapea los hallazgos de todos los módulos anteriores a técnicas del 
framework MITRE ATT&CK usando data/mitre_map.json.
Este módulo no genera findings nuevos, muta los existentes.
"""

import os
import json
from typing import List

from rich.console import Console

from modules import Finding
from ui.theme import cabecera_modulo, pie_modulo


MODULE_NUM  = 11
MODULE_NAME = "MITRE ATT&CK Mapping"
MODULE_ID   = "mitre"

_MITRE_MAP = {}

def _load_mitre_map():
    global _MITRE_MAP
    if _MITRE_MAP: return
    db_path = os.path.join(os.path.dirname(__file__), "..", "data", "mitre_map.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            _MITRE_MAP = json.load(f)
    except Exception:
        pass


def run(findings: List[Finding], config: dict, console: Console) -> None:
    """Enriches findings with MITRE ATT&CK information."""
    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    if not config.get("mitre_mode", False):
        console.print("  [dim]MITRE mapping disabled. Use --mitre to enable.[/]")
        console.print(pie_modulo())
        return

    _load_mitre_map()
    if not _MITRE_MAP:
        console.print("  [bold red][FAIL] Could not load data/mitre_map.json[/]")
        console.print(pie_modulo())
        return

    mapped_count = 0
    mapped_techniques = set()

    for f in findings:
        if f.patron and f.patron in _MITRE_MAP:
            t = _MITRE_MAP[f.patron]
            f.mitre_id = t["id"]
            f.mitre_name = f"{t['id']} {t['name']}"
            mapped_count += 1
            mapped_techniques.add(f.mitre_name)

    if mapped_count > 0:
        console.print(f"  {mapped_count} finding(s) mapped to {len(mapped_techniques)} MITRE techniques:")
        console.print()
        for t in sorted(mapped_techniques):
            console.print(f"    [bold cyan]*[/] {t}")
        console.print()
        
        # Display attack explanations if present
        explanations = [f for f in findings if f.mitre_name and f.interpretacion]
        if explanations:
            console.print("  [bold white]Attack Explanations & Context:[/]")
            console.print()
            for f in explanations:
                parts = [p.strip() for p in f.interpretacion.split("|")]
                if len(parts) == 3:
                    attack_type, pattern_ev, legit_alt = parts
                    console.print(f"    [bold color(81)]* {f.mitre_name}[/] - [bold white]{attack_type}[/]")
                    console.print(f"      [dim]Evidence/Pattern:[/] {pattern_ev}")
                    console.print(f"      [dim]Legitimate Context:[/] {legit_alt}")
                else:
                    console.print(f"    [bold color(81)]* {f.mitre_name}[/]: {f.interpretacion}")
                console.print()
    else:
        console.print("  [dim]No findings with patterns mappable to MITRE in this capture.[/]")
        console.print()

    console.print(pie_modulo())
