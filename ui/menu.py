"""
ui/menu.py — Interactive menu and configuration for LookingTheShark.

Manages tool selection, pcap file loading, and export options
in interactive mode (--menu).
"""

import os
import sys
from typing import Optional

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box

from ui.theme import SHARK_THEME, ICONS, SEPARATOR


# ──────────────────────────────────────────────────────
# Tool registry (mirrors TOOLS in main)
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


def prompt_file(console: Console) -> Optional[str]:
    """Requests the pcap file path from the user."""
    console.print(f"  {ICONS['file']} [bold white]Capture file path (.pcap / .pcapng):[/]")
    console.print()

    while True:
        try:
            path = Prompt.ask("  [bold cyan]File[/]", console=console)
        except (KeyboardInterrupt, EOFError):
            return None

        path = path.strip().strip('"').strip("'")

        if not path:
            console.print(f"  {ICONS['warn']} [bold yellow]Empty path. Please try again.[/]")
            continue

        if not os.path.isfile(path):
            console.print(f"  {ICONS['error']} [bold red]File not found: {path}[/]")
            continue

        ext = os.path.splitext(path)[1].lower()
        if ext not in (".pcap", ".pcapng"):
            console.print(f"  {ICONS['warn']} [bold yellow]Unrecognized extension '{ext}'. Expected .pcap or .pcapng.[/]")
            try:
                proceed = Confirm.ask("  [dim]Continue anyway?[/]", console=console, default=False)
            except (KeyboardInterrupt, EOFError):
                return None
            if not proceed:
                continue

        console.print(f"  {ICONS['ok']} File: [bold white]{os.path.basename(path)}[/] [dim]({os.path.getsize(path):,} bytes)[/]")
        return path


def prompt_diff_files(console: Console) -> Optional[tuple]:
    """Requests two capture paths for comparison."""
    console.print(f"  {ICONS['file']} [bold white]Comparison between two captures:[/]")
    console.print()

    paths = []
    for label in ["Capture BEFORE", "Capture AFTER"]:
        try:
            path = Prompt.ask(f"  [bold cyan]{label}[/]", console=console)
        except (KeyboardInterrupt, EOFError):
            return None

        path = path.strip().strip('"').strip("'")
        if not os.path.isfile(path):
            console.print(f"  {ICONS['error']} [bold red]File not found: {path}[/]")
            return None
        paths.append(path)

    return tuple(paths)


def select_modules(console: Console) -> Optional[list]:
    """Shows the tool menu and returns the list of selected module IDs."""
    console.print(f"  [bold white]Select tool:[/]")
    console.print()

    for item in MENU_ITEMS:
        pad = " " if len(item["num"]) < 2 else ""
        console.print(f"  [bold cyan] [{item['num']}]{pad}[/] {item['name']}")

    console.print(f"  [bold cyan] [A] [/] Run all")
    console.print(f"  [bold cyan] [0] [/] Exit and generate report")
    console.print()

    try:
        selection = Prompt.ask("  [bold cyan]>[/]", console=console)
    except (KeyboardInterrupt, EOFError):
        return None

    selection = selection.strip().upper()

    if selection == "0":
        return None

    if selection == "A":
        return [item["id"] for item in MENU_ITEMS]

    # Parse multi-selection (e.g. "1,3,5" or "1 3 5")
    nums = selection.replace(",", " ").split()
    ids = []
    valid_nums = {item["num"]: item["id"] for item in MENU_ITEMS}

    for n in nums:
        if n in valid_nums:
            ids.append(valid_nums[n])
        else:
            console.print(f"  {ICONS['warn']} [bold yellow]Option '{n}' not recognized, ignored.[/]")

    if not ids:
        console.print(f"  {ICONS['error']} [bold red]No module selected.[/]")
        return None

    return ids


def prompt_export_format(console: Console) -> Optional[str]:
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
        option = Prompt.ask("  [bold cyan]>[/]", console=console, default="1")
    except (KeyboardInterrupt, EOFError):
        return None

    mapping = {
        "1": "md",
        "2": "json",
        "3": "html",
        "4": "md,json,html",
        "0": None,
    }
    return mapping.get(option.strip(), "md")


def prompt_output_path(console: Console, formats: str, base_name: str) -> str:
    """Suggests an output path and allows the user to change it."""
    default = f"report_{base_name}"
    console.print(f"  [dim]Report base name (without extension):[/]")

    try:
        name = Prompt.ask("  [bold cyan]Report[/]", console=console, default=default)
    except (KeyboardInterrupt, EOFError):
        name = default

    return name.strip()


def show_capture_summary(console: Console, info: dict) -> None:
    """Displays loaded capture information."""
    console.print(
        f"  {ICONS['shark']} Loaded capture: [bold white]{info.get('name', '?')}[/] "
        f"[dim]({info.get('packets', '?')} packets, {info.get('duration', '?')})[/]"
    )
    console.print()
