"""
ui/theme.py — Consistent colour palette and styles for LookingTheShark.

Each severity/confidence level has an assigned colour:
  - Green     → Info / safe / low
  - Yellow    → Medium
  - Orange    → High (colour 208)
  - Red       → Critical / maximum alert
  - Grey      → Descriptive info / dim
  - Cyan      → Framework branding / objective data
  - White     → Titles / main data
"""

from rich.theme import Theme


# ──────────────────────────────────────────────────────
# Main LookingTheShark theme
# ──────────────────────────────────────────────────────
SHARK_THEME = Theme({
    # ── Severity ───────────────────────────────────────
    "sev_info":      "bold bright_green",
    "sev_low":       "bold bright_green",
    "sev_medium":    "bold yellow",
    "sev_high":      "bold color(208)",
    "sev_critical":  "bold bright_red",
    # ── Confidence ─────────────────────────────────────
    "conf_high":     "bold bright_green",
    "conf_medium":   "bold color(208)",
    "conf_low":      "bold yellow",
    # ── System / UI ────────────────────────────────────
    "system":        "bold cyan",
    "progress":      "cyan",
    "brand":         "bold cyan",
    "subbrand":      "color(75)",
    "separator":     "color(240)",
    # ── Base text ──────────────────────────────────────
    "title":         "bold white",
    "subtitle":      "bold color(252)",
    "error":         "bold red",
    "success":       "bold green",
    "warning":       "bold yellow",
    "dim_text":      "dim color(245)",
    # ── Table headers ──────────────────────────────────
    "table_header":  "bold color(81)",
    "table_border":  "color(240)",
})


# ──────────────────────────────────────────────────────
# Status icons — ASCII only
# ──────────────────────────────────────────────────────
ICONS = {
    "ok":       "[bold bright_green][OK][/]",
    "warn":     "[bold yellow][!][/]",
    "error":    "[bold bright_red][FAIL][/]",
    "info":     "[bold cyan][i][/]",
    "critical": "[bold bright_red][!!][/]",
    "high":     "[bold color(208)][!][/]",
    "medium":   "[bold yellow][!][/]",
    "low":      "[bold bright_green][i][/]",
    "safe":     "[bold bright_green][OK][/]",
    "arrow":    "[bold cyan]->[/]",
    "bullet":   "[bold cyan]*[/]",
    "module":   "[bold color(75)][M][/]",
    "shark":    "[bold cyan][~][/]",
    "file":     "[bold white][F][/]",
    "lock":     "[bold yellow][L][/]",
    "key":      "[bold bright_red][K][/]",
    "network":  "[bold cyan][N][/]",
    "shield":   "[bold bright_green][S][/]",
    "danger":   "[bold bright_red][!][/]",
}


# ──────────────────────────────────────────────────────
# Severity tags — [i] LOW, [!] MEDIUM, [!!] HIGH
# ──────────────────────────────────────────────────────
SEVERITY_LABEL = {
    "info":     {"tag": "[i]",  "style": "bold bright_green",  "label": "INFO"},
    "low":      {"tag": "[i]",  "style": "bold bright_green",  "label": "LOW"},
    "medium":   {"tag": "[!]",  "style": "bold yellow",        "label": "MEDIUM"},
    "high":     {"tag": "[!!]", "style": "bold color(208)",     "label": "HIGH"},
    "critical": {"tag": "[!!]", "style": "bold bright_red",     "label": "CRITICAL"},
}


def severity_style(severity: str) -> str:
    """Returns rich markup for a severity level: '[!] MEDIUM'."""
    s = SEVERITY_LABEL.get(severity, SEVERITY_LABEL["low"])
    return f"[{s['style']}]{s['tag']} {s['label']}[/]"


def confidence_style(level: str) -> str:
    """Returns rich markup for a confidence level."""
    mapping = {
        "high":   "[bold bright_green][OK] HIGH[/]",
        "medium": "[bold color(208)][!] MEDIUM[/]",
        "low":    "[bold yellow][!] LOW[/]",
    }
    return mapping.get(level, f"[dim]{level.upper()}[/]")


# ──────────────────────────────────────────────────────
# Module separators — ==== opens, ---- closes
# ──────────────────────────────────────────────────────
SEP_MODULE_OPEN  = "=" * 64
SEP_MODULE_CLOSE = "-" * 64
SEPARATOR        = "[color(240)]" + "═" * 55 + "[/]"
SEPARATOR_THIN   = "[color(240)]" + "─" * 55 + "[/]"


def module_header(num: int, name: str) -> str:
    """
    Generates the module header:
    ================================================================
      [06] TLS / CERTIFICATES
    ================================================================
    """
    lines = [
        SEP_MODULE_OPEN,
        f"  [{num:02d}] {name.upper()}",
        SEP_MODULE_OPEN,
    ]
    return "\n".join(lines)


def module_footer() -> str:
    """Module closing separator."""
    return SEP_MODULE_CLOSE
