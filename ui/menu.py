"""
ui/menu.py — Menú interactivo y configuración de LookingTheShark.

Gestiona la selección de herramientas, la carga del archivo pcap,
y las opciones de exportación en modo interactivo (--menu).
"""

import os
import sys
from typing import Optional

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box

from ui.theme import SHARK_THEME, ICONOS, SEPARADOR


# ──────────────────────────────────────────────────────
# Registro de herramientas (espejo de TOOLS en main)
# ──────────────────────────────────────────────────────
MENU_ITEMS = [
    {"num": "1",  "id": "ip_hosts",     "name": "IP / Hosts"},
    {"num": "2",  "id": "protocols",    "name": "Protocols"},
    {"num": "3",  "id": "dns",          "name": "DNS"},
    {"num": "4",  "id": "files",        "name": "Files / Objects"},
    {"num": "5",  "id": "os_fp",        "name": "OS Fingerprint"},
    {"num": "6",  "id": "tls",          "name": "TLS / Certificates"},
    {"num": "7",  "id": "creds",        "name": "Cleartext Credentials"},
    {"num": "8",  "id": "layer2",       "name": "Layer 2 / Local Network"},
    {"num": "9",  "id": "reputation",   "name": "Offline Reputation"},
    {"num": "10", "id": "heuristics",   "name": "Heuristics (--deep)"},
    {"num": "11", "id": "mitre",        "name": "MITRE ATT&CK Mapping"},
    {"num": "12", "id": "diff",         "name": "Diff Between Captures"},
]


def solicitar_archivo(console: Console) -> Optional[str]:
    """Requests the pcap file path from the user."""
    console.print(f"  {ICONOS['file']} [bold white]Capture file path (.pcap / .pcapng):[/]")
    console.print()

    while True:
        try:
            ruta = Prompt.ask("  [bold cyan]File[/]", console=console)
        except (KeyboardInterrupt, EOFError):
            return None

        ruta = ruta.strip().strip('"').strip("'")

        if not ruta:
            console.print(f"  {ICONOS['warn']} [bold yellow]Empty path. Please try again.[/]")
            continue

        if not os.path.isfile(ruta):
            console.print(f"  {ICONOS['error']} [bold red]File not found: {ruta}[/]")
            continue

        ext = os.path.splitext(ruta)[1].lower()
        if ext not in (".pcap", ".pcapng"):
            console.print(f"  {ICONOS['warn']} [bold yellow]Unrecognized extension '{ext}'. Expected .pcap or .pcapng.[/]")
            try:
                continuar = Confirm.ask("  [dim]Continue anyway?[/]", console=console, default=False)
            except (KeyboardInterrupt, EOFError):
                return None
            if not continuar:
                continue

        console.print(f"  {ICONOS['ok']} File: [bold white]{os.path.basename(ruta)}[/] [dim]({os.path.getsize(ruta):,} bytes)[/]")
        return ruta


def solicitar_archivo_diff(console: Console) -> Optional[tuple]:
    """Requests two capture paths for comparison."""
    console.print(f"  {ICONOS['file']} [bold white]Comparison between two captures:[/]")
    console.print()

    rutas = []
    for label in ["Capture BEFORE", "Capture AFTER"]:
        try:
            ruta = Prompt.ask(f"  [bold cyan]{label}[/]", console=console)
        except (KeyboardInterrupt, EOFError):
            return None

        ruta = ruta.strip().strip('"').strip("'")
        if not os.path.isfile(ruta):
            console.print(f"  {ICONOS['error']} [bold red]File not found: {ruta}[/]")
            return None
        rutas.append(ruta)

    return tuple(rutas)


def seleccionar_modulos(console: Console) -> Optional[list]:
    """
    Shows tool menu and returns list of selected IDs.
    """
    console.print(f"  [bold white]Select tool:[/]")
    console.print()

    for item in MENU_ITEMS:
        pad = " " if len(item["num"]) < 2 else ""
        console.print(f"  [bold cyan] [{item['num']}]{pad}[/] {item['name']}")

    console.print(f"  [bold cyan] [A] [/] Run all")
    console.print(f"  [bold cyan] [0] [/] Exit and generate report")
    console.print()

    try:
        seleccion = Prompt.ask("  [bold cyan]>[/]", console=console)
    except (KeyboardInterrupt, EOFError):
        return None

    seleccion = seleccion.strip().upper()

    if seleccion == "0":
        return None

    if seleccion == "A":
        return [item["id"] for item in MENU_ITEMS]

    # Parse multi-selection (e.g. "1,3,5" or "1 3 5")
    nums = seleccion.replace(",", " ").split()
    ids = []
    valid_nums = {item["num"]: item["id"] for item in MENU_ITEMS}

    for n in nums:
        if n in valid_nums:
            ids.append(valid_nums[n])
        else:
            console.print(f"  {ICONOS['warn']} [bold yellow]Option '{n}' not recognized, ignored.[/]")

    if not ids:
        console.print(f"  {ICONOS['error']} [bold red]No module selected.[/]")
        return None

    return ids


def solicitar_exportacion(console: Console) -> Optional[str]:
    """Asks for the report export format."""
    console.print()
    console.print(f"  [bold white]Export format:[/]")
    console.print(f"   [bold cyan][1][/] Markdown (.md)")
    console.print(f"   [bold cyan][2][/] JSON (.json)")
    console.print(f"   [bold cyan][3][/] HTML (.html)")
    console.print(f"   [bold cyan][4][/] All")
    console.print(f"   [bold cyan][0][/] Do not export")
    console.print()

    try:
        opcion = Prompt.ask("  [bold cyan]>[/]", console=console, default="1")
    except (KeyboardInterrupt, EOFError):
        return None

    mapa = {
        "1": "md",
        "2": "json",
        "3": "html",
        "4": "md,json,html",
        "0": None,
    }
    return mapa.get(opcion.strip(), "md")


def solicitar_ruta_salida(console: Console, formatos: str, nombre_base: str) -> str:
    """Suggests an output path and allows the user to change it."""
    default = f"report_{nombre_base}"
    console.print(f"  [dim]Report base name (without extension):[/]")

    try:
        nombre = Prompt.ask("  [bold cyan]Report[/]", console=console, default=default)
    except (KeyboardInterrupt, EOFError):
        nombre = default

    return nombre.strip()


def mostrar_resumen_captura(console: Console, info: dict) -> None:
    """Displays loaded capture information."""
    console.print(
        f"  {ICONOS['shark']} Loaded capture: [bold white]{info.get('nombre', '?')}[/] "
        f"[dim]({info.get('paquetes', '?')} packets, {info.get('duracion', '?')})[/]"
    )
    console.print()
