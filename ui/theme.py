"""
ui/theme.py — Paleta, iconos y componentes de lectura de LookingTheShark.

La idea de fondo: mirar paquetes es aburrido y no dice nada. Lo que se lee
aqui son frases, no campos. Cada componente de este fichero existe para
convertir un dato tecnico en algo que se entienda de un vistazo:

  severidad()      convierte 'critico' en una etiqueta que se ve venir
  barra()          compara magnitudes sin tener que leer numeros
  sparkline()      ensena la forma del trafico en el tiempo en 40 caracteres
  panel_hallazgo() presenta un hallazgo con que es, que significa y que hacer
  bloque_http()    ensena una peticion HTTP como se lee, no como se captura
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from rich import box
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.markup import escape
from rich.text import Text
from rich.theme import Theme


# ──────────────────────────────────────────────────────
# Tema
# ──────────────────────────────────────────────────────
SHARK_THEME = Theme({
    # Severidad
    "sev_info":     "bold bright_cyan",
    "sev_bajo":     "bold bright_green",
    "sev_medio":    "bold yellow",
    "sev_alto":     "bold color(208)",
    "sev_critico":  "bold white on red",
    # Confianza
    "conf_alta":    "bold bright_green",
    "conf_media":   "bold yellow",
    "conf_baja":    "dim yellow",
    # Marca y estructura
    "marca":        "bold cyan",
    "submarca":     "color(75)",
    "separador":    "color(238)",
    "titulo":       "bold white",
    "subtitulo":    "bold color(252)",
    "etiqueta":     "color(245)",
    "valor":        "bold white",
    "dato":         "bright_cyan",
    # Estados
    "error":        "bold red",
    "exito":        "bold bright_green",
    "advertencia":  "bold yellow",
    "dim_text":     "dim color(245)",
    # Tablas
    "tabla_header": "bold color(81)",
    "tabla_border": "color(238)",
    # Roles de red
    "lan":          "color(114)",
    "wan":          "color(215)",
    "atacante":     "bold red",
    "victima":      "bold yellow",
})

# Caja de tabla por defecto: limpia y sin ruido visual.
CAJA = box.SIMPLE_HEAD


def esc(valor) -> str:
    """Escapa datos que vienen de la captura antes de imprimirlos.

    Una URL, un User-Agent o un banner pueden contener corchetes, y rich los
    interpretaria como etiquetas de estilo: el texto se rompe o desaparece.
    Todo dato que salga del pcap pasa por aqui antes de entrar en un f-string
    con markup o en una celda de tabla.
    """
    return escape(str(valor)) if valor is not None else ""


# ──────────────────────────────────────────────────────
# Iconos
# ──────────────────────────────────────────────────────
ICONOS = {
    "ok": "✔", "warn": "⚠", "error": "✘", "info": "ℹ",
    "critico": "🔴", "alto": "🟠", "medio": "🟡", "bajo": "🟢", "seguro": "🟢",
    "flecha": "→", "punto": "•", "modulo": "⬡", "shark": "🦈",
    "file": "📄", "lock": "🔒", "key": "🔑", "network": "🌐", "shield": "🛡",
    "danger": "⚡", "reloj": "🕒", "equipo": "💻", "servidor": "🖥",
    "movil": "📱", "router": "📡", "descarga": "⬇", "subida": "⬆",
}

# Icono por familia de sistema operativo, para leer el inventario de un vistazo.
ICONO_SO = {
    "Windows": "🪟", "Linux": "🐧", "Apple": "🍎", "macOS": "🍎", "iOS": "📱",
    "Android": "🤖", "BSD": "😈", "Red": "📡", "IoT": "💡", "Virtual": "📦",
    "Escaner": "🔍", "Consola": "🎮", "ChromeOS": "🌐",
}


def icono_so(familia: str) -> str:
    return ICONO_SO.get(familia, "❔")


# ──────────────────────────────────────────────────────
# Severidad y confianza
# ──────────────────────────────────────────────────────
ORDEN_SEVERIDAD = {"critico": 0, "alto": 1, "medio": 2, "bajo": 3, "info": 4}

_SEVERIDAD = {
    "critico": ("CRITICO", "sev_critico", "🔴"),
    "alto":    ("ALTO",    "sev_alto",    "🟠"),
    "medio":   ("MEDIO",   "sev_medio",   "🟡"),
    "bajo":    ("BAJO",    "sev_bajo",    "🟢"),
    "info":    ("INFO",    "sev_info",    "ℹ"),
}


def severidad(nivel: str, con_icono: bool = True) -> str:
    """'critico' -> markup rich de una etiqueta de severidad."""
    nombre, estilo, icono = _SEVERIDAD.get(nivel, _SEVERIDAD["info"])
    prefijo = f"{icono} " if con_icono else ""
    return f"[{estilo}] {prefijo}{nombre} [/]"


def estilo_severidad(nivel: str) -> str:
    """Compatibilidad con la API anterior."""
    return severidad(nivel)


def color_severidad(nivel: str) -> str:
    return _SEVERIDAD.get(nivel, _SEVERIDAD["info"])[1]


def confianza(nivel: str) -> str:
    mapa = {
        "alta":  "[conf_alta]confianza alta[/]",
        "media": "[conf_media]confianza media[/]",
        "baja":  "[conf_baja]confianza baja[/]",
    }
    return mapa.get(nivel, f"[dim]{nivel}[/]")


def estilo_confianza(nivel: str) -> str:
    return confianza(nivel)


# ──────────────────────────────────────────────────────
# Separadores y cabeceras
# ──────────────────────────────────────────────────────
ANCHO = 78
SEPARADOR = "[separador]" + "─" * ANCHO + "[/]"
SEPARADOR_FINO = "[separador]" + "┄" * ANCHO + "[/]"
SEP_MODULO_OPEN = "═" * ANCHO
SEP_MODULO_CLOSE = "─" * ANCHO


def cabecera_modulo(num: int, nombre: str, subtitulo: str = "") -> Panel:
    """Cabecera de modulo: numero, nombre y una linea de que hace."""
    texto = Text()
    texto.append(f"{num:02d}  ", style="bold color(75)")
    texto.append(nombre.upper(), style="bold white")
    if subtitulo:
        texto.append(f"\n    {subtitulo}", style="dim color(245)")
    return Panel(texto, box=box.HEAVY_EDGE, border_style="color(75)",
                 padding=(0, 1), expand=True)


def pie_modulo() -> str:
    return "[separador]" + "─" * ANCHO + "[/]\n"


def titulo_seccion(texto: str, icono: str = "") -> str:
    prefijo = f"{icono} " if icono else ""
    return f"\n  [titulo]{prefijo}{texto}[/]"


# ──────────────────────────────────────────────────────
# Tablas
# ──────────────────────────────────────────────────────
def tabla(titulo: str = "", **kwargs) -> Table:
    """Tabla con el estilo de la herramienta ya aplicado."""
    opciones = {
        "show_header": True,
        "header_style": "tabla_header",
        "box": CAJA,
        "border_style": "tabla_border",
        "padding": (0, 1),
        "expand": False,
    }
    opciones.update(kwargs)
    if titulo:
        opciones["title"] = titulo
        opciones.setdefault("title_style", "bold white")
        opciones.setdefault("title_justify", "left")
    return Table(**opciones)


def tabla_clave_valor(pares: Sequence[tuple], titulo: str = "") -> Table:
    """Tabla de dos columnas para fichas de datos."""
    t = tabla(titulo, show_header=False, box=None, padding=(0, 2))
    t.add_column(style="etiqueta", justify="right", no_wrap=True)
    t.add_column(style="valor")
    for clave, valor in pares:
        t.add_row(str(clave), str(valor))
    return t


# ──────────────────────────────────────────────────────
# Graficos de texto
# ──────────────────────────────────────────────────────
_BLOQUES = " ▁▂▃▄▅▆▇█"


def sparkline(valores: Sequence[float], ancho: int = 48) -> str:
    """Grafico compacto de la evolucion de una serie."""
    valores = list(valores)
    if not valores:
        return ""
    if len(valores) > ancho:
        # Se agrupa en 'ancho' cubos sumando, para no perder picos.
        paso = len(valores) / ancho
        agrupados = []
        for i in range(ancho):
            ini = int(i * paso)
            fin = max(ini + 1, int((i + 1) * paso))
            agrupados.append(sum(valores[ini:fin]))
        valores = agrupados

    maximo = max(valores) or 1
    # Un valor distinto de cero nunca se dibuja como hueco: si hubo trafico,
    # tiene que verse aunque sea minimo comparado con el pico.
    return "".join(
        _BLOQUES[0] if v <= 0 else _BLOQUES[max(1, min(8, round(v / maximo * 8)))]
        for v in valores
    )


def barra(valor: float, maximo: float, ancho: int = 24, estilo: str = "cyan") -> str:
    """Barra horizontal proporcional."""
    if maximo <= 0:
        return ""
    llenos = int(round((valor / maximo) * ancho))
    llenos = max(0, min(ancho, llenos))
    return f"[{estilo}]{'█' * llenos}[/][separador]{'░' * (ancho - llenos)}[/]"


def porcentaje(parte: float, total: float) -> str:
    if not total:
        return "0.0%"
    return f"{parte / total * 100:.1f}%"


# ──────────────────────────────────────────────────────
# Bloques de lectura
# ──────────────────────────────────────────────────────
def panel_hallazgo(titulo: str, severidad_nivel: str, que_significa: str = "",
                   evidencia: str = "", recomendacion: str = "",
                   confianza_nivel: str = "", mitre: str = "") -> Panel:
    """`confianza_nivel` es el nivel plano ('alta'/'media'/'baja')."""
    """Un hallazgo presentado para leerse, no para descifrarse."""
    color = {"critico": "red", "alto": "color(208)", "medio": "yellow",
             "bajo": "green", "info": "cyan"}.get(severidad_nivel, "cyan")

    cuerpo = Text()
    if que_significa:
        cuerpo.append("Que significa   ", style="bold color(245)")
        cuerpo.append(que_significa + "\n", style="white")
    if evidencia:
        cuerpo.append("Evidencia       ", style="bold color(245)")
        cuerpo.append(evidencia + "\n", style="bright_cyan")
    if recomendacion:
        cuerpo.append("Que hacer       ", style="bold color(245)")
        cuerpo.append(recomendacion + "\n", style="white")
    if mitre:
        cuerpo.append("MITRE ATT&CK    ", style="bold color(245)")
        cuerpo.append(mitre + "\n", style="color(75)")
    if confianza_nivel:
        estilo_conf = {"alta": "bright_green", "media": "yellow",
                       "baja": "color(245)"}.get(confianza_nivel, "color(245)")
        cuerpo.append("Fiabilidad      ", style="bold color(245)")
        cuerpo.append(f"confianza {confianza_nivel}", style=estilo_conf)

    etiqueta = _SEVERIDAD.get(severidad_nivel, _SEVERIDAD["info"])
    encabezado = (f"[{etiqueta[1]}] {etiqueta[2]} {etiqueta[0]} [/]  "
                  f"[bold white]{escape(titulo)}[/]")

    return Panel(cuerpo, title=encabezado, title_align="left",
                 border_style=color, box=box.ROUNDED, padding=(0, 2))


def bloque_http(metodo: str, url: str, codigo: int, tipo: str, tamano: str,
                cliente: str, so_cliente: str = "", agente: str = "",
                extra: Optional[List[str]] = None) -> Text:
    """Una transaccion HTTP escrita como se lee."""
    t = Text()
    color_codigo = ("green" if 200 <= codigo < 300 else
                    "yellow" if 300 <= codigo < 400 else
                    "red" if codigo >= 400 else "dim")

    t.append(f"  {metodo:<7}", style="bold bright_cyan")
    t.append(url[:96], style="white")
    t.append("\n          ")
    if codigo:
        t.append(f"{codigo}", style=f"bold {color_codigo}")
    else:
        t.append("sin respuesta", style="dim")
    if tipo:
        t.append(f"  {tipo}", style="color(245)")
    if tamano:
        t.append(f"  {tamano}", style="color(245)")
    t.append("\n          desde ", style="color(240)")
    t.append(cliente, style="bright_cyan")
    if so_cliente:
        t.append(f" ({so_cliente})", style="color(114)")
    if agente:
        t.append(f" · {agente}", style="color(245)")
    for linea in (extra or []):
        t.append(f"\n          {linea}", style="color(208)")
    return t


def caja_explicativa(texto: str, titulo: str = "Como se lee esto") -> Panel:
    """Nota didactica: que estas mirando y por que importa."""
    return Panel(Text(texto, style="color(245)"), title=f"[dim]{titulo}[/]",
                 title_align="left", border_style="separador",
                 box=box.MINIMAL, padding=(0, 2))


def linea_evento(hora: str, actor: str, accion: str, detalle: str = "",
                 nivel: str = "info") -> Text:
    """Una linea de la narrativa cronologica."""
    color = {"critico": "red", "alto": "color(208)", "medio": "yellow",
             "bajo": "green", "info": "color(250)"}.get(nivel, "color(250)")
    t = Text()
    t.append(f"  {hora}  ", style="color(240)")
    t.append(f"{actor:<22}", style="bright_cyan")
    t.append(accion, style=color)
    if detalle:
        t.append(f"  {detalle}", style="color(244)")
    return t


def sangrar(renderizable, izquierda: int = 2):
    return Padding(renderizable, (0, 0, 0, izquierda))


def sin_hallazgos(mensaje: str) -> str:
    return f"  [exito]{ICONOS['ok']}[/] [dim_text]{mensaje}[/]"
