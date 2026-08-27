"""
modules/mitre_mapping.py — Traduccion a MITRE ATT&CK.

No genera hallazgos: enriquece los que ya hay con la tecnica de ATT&CK
correspondiente. Sirve para dos cosas concretas: hablar el mismo idioma que el
resto del sector en un informe, y ver de un vistazo en que fase del ataque
estamos (reconocimiento, acceso, movimiento lateral, exfiltracion).
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Dict, List

from rich.console import Console

from modules import Finding, plural, truncar
from ui import theme

MODULE_NUM = 14
MODULE_NAME = "MITRE ATT&CK"
MODULE_ID = "mitre"
MODULE_DESC = "En que fase de un ataque encaja cada hallazgo"

# Orden de la cadena de ataque, para presentar las tacticas como se desarrollan.
ORDEN_TACTICAS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

TACTICA_ES = {
    "Reconnaissance": "Reconocimiento",
    "Resource Development": "Preparacion de recursos",
    "Initial Access": "Acceso inicial",
    "Execution": "Ejecucion",
    "Persistence": "Persistencia",
    "Privilege Escalation": "Escalada de privilegios",
    "Defense Evasion": "Evasion de defensas",
    "Credential Access": "Acceso a credenciales",
    "Discovery": "Descubrimiento",
    "Lateral Movement": "Movimiento lateral",
    "Collection": "Recoleccion",
    "Command and Control": "Mando y control",
    "Exfiltration": "Exfiltracion",
    "Impact": "Impacto",
}

_MAPA: Dict[str, dict] = {}
_CARGADO = False


def _cargar_mapa() -> Dict[str, dict]:
    global _MAPA, _CARGADO
    if _CARGADO:
        return _MAPA
    _CARGADO = True
    ruta = os.path.join(os.path.dirname(__file__), "..", "data", "mitre_map.json")
    try:
        with open(ruta, "r", encoding="utf-8") as fh:
            crudo = json.load(fh)
        # El fichero lleva claves de documentacion ("_comment") cuyo valor es
        # texto, no una tecnica: se descartan al cargar.
        _MAPA = {k: v for k, v in crudo.items()
                 if isinstance(v, dict) and "id" in v}
    except (OSError, ValueError, AttributeError):
        _MAPA = {}
    return _MAPA


def enriquecer(hallazgos: List[Finding]) -> int:
    """Rellena mitre_id / mitre_name / mitre_tactica. Devuelve cuantos mapeo."""
    mapa = _cargar_mapa()
    if not mapa:
        return 0

    mapeados = 0
    for f in hallazgos:
        if not f.patron or f.mitre_id:
            continue
        tecnica = mapa.get(f.patron)
        if not tecnica:
            continue
        f.mitre_id = tecnica["id"]
        f.mitre_name = f"{tecnica['id']} · {tecnica['name']}"
        f.mitre_tactica = tecnica.get("tactic", "")
        mapeados += 1
    return mapeados


def run(hallazgos: List[Finding], config: dict, console: Console) -> None:
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    if not config.get("mitre_mode", False):
        console.print("  [dim_text]Mapeo desactivado. Anade [/][dato]--mitre[/]"
                      "[dim_text] para activarlo.[/]")
        console.print(theme.pie_modulo())
        return

    mapa = _cargar_mapa()
    if not mapa:
        console.print("  [error]✘ No se pudo leer data/mitre_map.json[/]")
        console.print(theme.pie_modulo())
        return

    mapeados = enriquecer(hallazgos)
    if not mapeados:
        console.print("  [dim_text]Ningun hallazgo de esta captura corresponde a "
                      "una tecnica catalogada.[/]")
        console.print(theme.pie_modulo())
        return

    # ── Agrupar por tactica ───────────────────────────
    por_tactica = defaultdict(list)
    for f in hallazgos:
        if f.mitre_id:
            for tactica in (f.mitre_tactica or "Sin clasificar").split(","):
                por_tactica[tactica.strip()].append(f)

    console.print(f"  {mapeados} de {len(hallazgos)} hallazgos encajan en "
                  f"{plural(len({f.mitre_id for f in hallazgos if f.mitre_id}), 'tecnica', 'tecnicas')} "
                  f"de ATT&CK")
    console.print()

    # ── Cadena de ataque ──────────────────────────────
    presentes = [t for t in ORDEN_TACTICAS if t in por_tactica]
    otras = [t for t in por_tactica if t not in ORDEN_TACTICAS]

    console.print("  [titulo]Fases cubiertas por lo observado[/]")
    console.print()
    for tactica in ORDEN_TACTICAS:
        nombre = TACTICA_ES.get(tactica, tactica)
        if tactica in por_tactica:
            cantidad = len(por_tactica[tactica])
            marca = "[sev_alto]███[/]"
            console.print(f"    {marca} [titulo]{nombre:<28}[/] "
                          f"[valor]{cantidad}[/] [dim_text]hallazgo(s)[/]")
        else:
            console.print(f"    [separador]░░░[/] [dim_text]{nombre}[/]")
    console.print()

    if len(presentes) >= 4:
        console.print("  [sev_alto]⚠ Se observan fases encadenadas de un ataque, "
                      "no hechos sueltos.[/]")
        console.print(f"  [dim_text]Secuencia detectada: "
                      f"{' → '.join(TACTICA_ES.get(t, t) for t in presentes)}[/]")
        console.print()

    # ── Detalle de tecnicas ───────────────────────────
    t = theme.tabla("Tecnicas identificadas")
    t.add_column("ID", style="bold bright_cyan", width=11)
    t.add_column("Tecnica", max_width=34)
    t.add_column("Tactica", max_width=22)
    t.add_column("Hallazgos", justify="right", width=10)

    por_tecnica = defaultdict(list)
    for f in hallazgos:
        if f.mitre_id:
            por_tecnica[f.mitre_id].append(f)

    for tecnica_id, lista in sorted(por_tecnica.items()):
        info = next((v for v in mapa.values() if v.get("id") == tecnica_id), {})
        tacticas = ", ".join(TACTICA_ES.get(x.strip(), x.strip())
                             for x in info.get("tactic", "").split(","))
        t.add_row(tecnica_id, truncar(info.get("name", ""), 32),
                  truncar(tacticas, 20), str(len(lista)))
    console.print(t)
    console.print()

    for tecnica_id, lista in sorted(por_tecnica.items())[:8]:
        info = next((v for v in mapa.values() if v.get("id") == tecnica_id), {})
        if not info.get("description"):
            continue
        console.print(f"  [bold bright_cyan]{tecnica_id}[/] [titulo]{info.get('name','')}[/]")
        console.print(f"      [dim_text]{truncar(info['description'], 150)}[/]")
        console.print(f"      [etiqueta]En esta captura:[/] "
                      f"{truncar('; '.join(f.titulo for f in lista[:2]), 110)}")
        console.print(f"      [etiqueta]Referencia:[/] "
                      f"[dim]https://attack.mitre.org/techniques/"
                      f"{tecnica_id.replace('.', '/')}/[/]")
        console.print()

    console.print(theme.pie_modulo())
