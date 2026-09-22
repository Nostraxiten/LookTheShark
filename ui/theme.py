"""
ui/theme.py — Paleta de colores y estilos consistentes de LookingTheShark.

Cada nivel de severidad/confianza tiene un color asignado:
  - Verde     → Información / seguro / bajo
  - Amarillo  → Medio
  - Naranja   → Alto (color 208)
  - Rojo      → Crítico / alerta máxima
  - Gris      → Info descriptiva / dim
  - Cyan      → Branding del framework / datos objetivos
  - Blanco    → Títulos / datos principales
"""

from rich.theme import Theme


# ──────────────────────────────────────────────────────
# Tema principal de LookingTheShark
# ──────────────────────────────────────────────────────
SHARK_THEME = Theme({
    # ── Severidad ──────────────────────────────────────
    "sev_info":      "bold bright_green",
    "sev_bajo":      "bold bright_green",
    "sev_medio":     "bold yellow",
    "sev_alto":      "bold color(208)",
    "sev_critico":   "bold bright_red",
    # ── Confianza ──────────────────────────────────────
    "conf_alta":     "bold bright_green",
    "conf_media":    "bold color(208)",
    "conf_baja":     "bold yellow",
    # ── Sistema / UI ──────────────────────────────────
    "sistema":       "bold cyan",
    "progreso":      "cyan",
    "marca":         "bold cyan",
    "submarca":      "color(75)",
    "separador":     "color(240)",
    # ── Texto base ────────────────────────────────────
    "titulo":        "bold white",
    "subtitulo":     "bold color(252)",
    "error":         "bold red",
    "exito":         "bold green",
    "advertencia":   "bold yellow",
    "dim_text":      "dim color(245)",
    # ── Cabeceras de tabla ────────────────────────────
    "tabla_header":  "bold color(81)",
    "tabla_border":  "color(240)",
})


# ──────────────────────────────────────────────────────
# Status icons — ASCII only
# ──────────────────────────────────────────────────────
ICONOS = {
    "ok":        "[bold bright_green][OK][/]",
    "warn":      "[bold yellow][!][/]",
    "error":     "[bold bright_red][FAIL][/]",
    "info":      "[bold cyan][i][/]",
    "critico":   "[bold bright_red][!!][/]",
    "alto":      "[bold color(208)][!][/]",
    "medio":     "[bold yellow][!][/]",
    "bajo":      "[bold bright_green][i][/]",
    "seguro":    "[bold bright_green][OK][/]",
    "flecha":    "[bold cyan]->[/]",
    "punto":     "[bold cyan]*[/]",
    "modulo":    "[bold color(75)][M][/]",
    "shark":     "[bold cyan][~][/]",
    "file":      "[bold white][F][/]",
    "lock":      "[bold yellow][L][/]",
    "key":       "[bold bright_red][K][/]",
    "network":   "[bold cyan][N][/]",
    "shield":    "[bold bright_green][S][/]",
    "danger":    "[bold bright_red][!][/]",
}


# ──────────────────────────────────────────────────────
# Severity tags — [i] LOW, [!] MEDIUM, [!!] HIGH
# ──────────────────────────────────────────────────────
SEVERIDAD_ETIQUETA = {
    "info":     {"tag": "[i]",  "estilo": "bold bright_green",  "nombre": "INFO"},
    "bajo":     {"tag": "[i]",  "estilo": "bold bright_green",  "nombre": "LOW"},
    "medio":    {"tag": "[!]",  "estilo": "bold yellow",        "nombre": "MEDIUM"},
    "alto":     {"tag": "[!!]", "estilo": "bold color(208)",     "nombre": "HIGH"},
    "critico":  {"tag": "[!!]", "estilo": "bold bright_red",     "nombre": "CRITICAL"},
}


def estilo_severidad(severidad: str) -> str:
    """Returns rich markup for a severity level: '[!] MEDIUM'."""
    s = SEVERIDAD_ETIQUETA.get(severidad, SEVERIDAD_ETIQUETA["bajo"])
    return f"[{s['estilo']}]{s['tag']} {s['nombre']}[/]"


def estilo_confianza(nivel: str) -> str:
    """Returns rich markup for a confidence level."""
    mapa = {
        "alta":  "[bold bright_green][OK] HIGH[/]",
        "media": "[bold color(208)][!] MEDIUM[/]",
        "baja":  "[bold yellow][!] LOW[/]",
    }
    return mapa.get(nivel, f"[dim]{nivel.upper()}[/]")


# ──────────────────────────────────────────────────────
# Separadores §9.3 — ==== abre, ---- cierra
# ──────────────────────────────────────────────────────
SEP_MODULO_OPEN  = "=" * 64
SEP_MODULO_CLOSE = "-" * 64
SEPARADOR        = "[color(240)]" + "═" * 55 + "[/]"
SEPARADOR_FINO   = "[color(240)]" + "─" * 55 + "[/]"


def cabecera_modulo(num: int, nombre: str) -> str:
    """
    Genera la cabecera de un módulo según §9.3:
    ================================================================
      [06] TLS / CERTIFICADOS
    ================================================================
    """
    lineas = [
        SEP_MODULO_OPEN,
        f"  [{num:02d}] {nombre.upper()}",
        SEP_MODULO_OPEN,
    ]
    return "\n".join(lineas)


def pie_modulo() -> str:
    """Separador de cierre de módulo."""
    return SEP_MODULO_CLOSE
