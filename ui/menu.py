"""
ui/menu.py — Modo interactivo.

Pensado para que alguien que abre la herramienta por primera vez no tenga que
leerse el --help. Todo tiene un valor por defecto sensato: pulsar Enter en cada
pregunta produce un analisis completo y correcto.
"""

from __future__ import annotations

import glob
import os
from typing import List, Optional, Tuple

from rich.console import Console
from rich.prompt import Confirm, Prompt

from core.pcap_reader import es_captura
from ui import theme

# El registro de modulos vive en el entrypoint; aqui se replica solo el menu.
MENU_ITEMS = [
    {"num": "1",  "id": "ip_hosts",   "name": "Equipos",              "desc": "quien hay en la red y con que sistema"},
    {"num": "2",  "id": "protocols",  "name": "Protocolos",           "desc": "que se habla y cuanto va sin cifrar"},
    {"num": "3",  "id": "dns",        "name": "DNS",                  "desc": "que nombres se pidieron y cuales no cuadran"},
    {"num": "4",  "id": "http",       "name": "HTTP",                 "desc": "peticiones y respuestas, con quien las lanzo"},
    {"num": "5",  "id": "files",      "name": "Ficheros",             "desc": "que se descargo y si era lo que decia ser"},
    {"num": "6",  "id": "tls",        "name": "TLS y certificados",   "desc": "a donde va el trafico cifrado (JA3)"},
    {"num": "7",  "id": "creds",      "name": "Credenciales",         "desc": "contrasenas capturadas en claro"},
    {"num": "8",  "id": "secrets",    "name": "Material sensible",    "desc": "claves y tokens dentro del trafico"},
    {"num": "9",  "id": "os_fp",      "name": "Sistemas operativos",  "desc": "que es cada equipo y por que"},
    {"num": "10", "id": "layer2",     "name": "Red local",            "desc": "ARP, DHCP y ataques de capa 2"},
    {"num": "11", "id": "heuristics", "name": "Comportamiento",       "desc": "escaneos, beaconing, exfiltracion"},
    {"num": "12", "id": "reputation", "name": "Reputacion offline",   "desc": "cruce con tus listas locales"},
    {"num": "13", "id": "timeline",   "name": "Cronologia",           "desc": "la captura contada en orden"},
    {"num": "14", "id": "mitre",      "name": "MITRE ATT&CK",         "desc": "en que fase de un ataque encaja todo"},
]

MODULOS_POR_DEFECTO = [m["id"] for m in MENU_ITEMS]


def _limpiar_ruta(texto: str) -> str:
    """Quita comillas y espacios: al arrastrar un fichero al terminal se cuelan."""
    return texto.strip().strip('"').strip("'").strip()


def _capturas_cercanas(limite: int = 8) -> List[str]:
    """Busca capturas en el directorio actual y en los sitios habituales."""
    patrones = ["*.pcap", "*.pcapng", "*.pcap.gz", "*.pcapng.gz", "*.cap"]
    carpetas = [".", "capturas", "captures", "tests/sample_pcaps",
                os.path.expanduser("~/Downloads"), os.path.expanduser("~/Descargas")]
    encontradas: List[str] = []
    for carpeta in carpetas:
        if not os.path.isdir(carpeta):
            continue
        for patron in patrones:
            for ruta in sorted(glob.glob(os.path.join(carpeta, patron))):
                if ruta not in encontradas:
                    encontradas.append(ruta)
                if len(encontradas) >= limite:
                    return encontradas
    return encontradas


def solicitar_archivo(console: Console, titulo: str = "captura") -> Optional[str]:
    """Pide la ruta del pcap, ofreciendo las capturas que encuentre cerca."""
    sugerencias = _capturas_cercanas()

    if sugerencias:
        console.print(f"  [titulo]Capturas encontradas cerca:[/]")
        console.print()
        for i, ruta in enumerate(sugerencias, 1):
            tamano = os.path.getsize(ruta)
            console.print(f"    [bold bright_cyan][{i}][/] {ruta}  "
                          f"[dim_text]({tamano:,} bytes)[/]")
        console.print(f"    [dim_text]o escribe una ruta cualquiera[/]")
        console.print()

    while True:
        try:
            respuesta = Prompt.ask(f"  [bold cyan]Ruta de la {titulo}[/]",
                                   console=console)
        except (KeyboardInterrupt, EOFError):
            return None

        respuesta = _limpiar_ruta(respuesta)
        if not respuesta:
            console.print("  [advertencia]⚠ No has escrito nada.[/]")
            continue

        if respuesta.isdigit() and sugerencias:
            indice = int(respuesta) - 1
            if 0 <= indice < len(sugerencias):
                respuesta = sugerencias[indice]

        if not os.path.isfile(respuesta):
            console.print(f"  [error]✘ No existe el fichero:[/] {respuesta}")
            continue

        if not es_captura(respuesta):
            console.print(f"  [advertencia]⚠ '{os.path.basename(respuesta)}' no "
                          f"parece un .pcap/.pcapng valido.[/]")
            try:
                if not Confirm.ask("  [dim]¿Intentarlo de todos modos?[/]",
                                   console=console, default=False):
                    continue
            except (KeyboardInterrupt, EOFError):
                return None

        console.print(f"  [exito]✔[/] {os.path.basename(respuesta)} "
                      f"[dim_text]({os.path.getsize(respuesta):,} bytes)[/]")
        console.print()
        return respuesta


def solicitar_archivo_diff(console: Console) -> Optional[Tuple[str, str]]:
    console.print("  [titulo]Comparativa entre dos capturas[/]")
    console.print()
    primera = solicitar_archivo(console, "captura de REFERENCIA (antes)")
    if not primera:
        return None
    segunda = solicitar_archivo(console, "captura a COMPARAR (despues)")
    if not segunda:
        return None
    return (primera, segunda)


def seleccionar_modulos(console: Console) -> Optional[List[str]]:
    """Menu de modulos. Enter = analisis completo."""
    console.print("  [titulo]¿Que quieres analizar?[/]")
    console.print()

    mitad = (len(MENU_ITEMS) + 1) // 2
    izquierda, derecha = MENU_ITEMS[:mitad], MENU_ITEMS[mitad:]

    for i in range(mitad):
        linea = _celda(izquierda[i])
        if i < len(derecha):
            linea += _celda(derecha[i])
        console.print(linea)

    console.print()
    console.print("    [bold cyan][A][/]  [titulo]Todo[/] "
                  "[dim_text](recomendado — es lo mas rapido y lo mas completo)[/]")
    console.print("    [bold cyan][R][/]  Solo lo relevante para seguridad "
                  "[dim_text](sin inventario ni estadisticas)[/]")
    console.print("    [bold cyan][0][/]  Salir")
    console.print()
    console.print("  [dim_text]Puedes combinar: «1,4,7» o «1 4 7».[/]")
    console.print()

    try:
        seleccion = Prompt.ask("  [bold cyan]>[/]", console=console, default="A")
    except (KeyboardInterrupt, EOFError):
        return None

    seleccion = seleccion.strip().upper()
    if seleccion == "0":
        return None
    if seleccion in ("A", ""):
        return list(MODULOS_POR_DEFECTO)
    if seleccion == "R":
        return ["http", "files", "creds", "secrets", "tls", "layer2",
                "heuristics", "reputation", "timeline", "mitre"]

    validos = {m["num"]: m["id"] for m in MENU_ITEMS}
    elegidos = []
    for parte in seleccion.replace(",", " ").split():
        if parte in validos:
            elegidos.append(validos[parte])
        else:
            console.print(f"  [advertencia]⚠ Opcion '{parte}' ignorada.[/]")

    if not elegidos:
        console.print("  [error]✘ No seleccionaste ningun modulo.[/]")
        return None
    return elegidos


def _celda(item: dict) -> str:
    numero = item["num"].rjust(2)
    return f"    [bold cyan][{numero}][/] {item['name']:<22}"


def solicitar_opciones(console: Console) -> dict:
    """Preguntas rapidas sobre el modo de analisis."""
    opciones = {}
    console.print()
    try:
        opciones["deep_mode"] = Confirm.ask(
            "  [bold cyan]¿Activar heuristicas de comportamiento?[/] "
            "[dim](escaneos, beaconing, exfiltracion)[/]",
            console=console, default=True)
        opciones["mitre_mode"] = Confirm.ask(
            "  [bold cyan]¿Mapear los hallazgos a MITRE ATT&CK?[/]",
            console=console, default=True)
    except (KeyboardInterrupt, EOFError):
        return {"deep_mode": True, "mitre_mode": True}
    return opciones


def solicitar_exportacion(console: Console) -> Optional[str]:
    console.print()
    console.print("  [titulo]¿Generar informe?[/]")
    console.print("    [bold cyan][1][/] HTML  [dim_text](el mas legible, se abre en el navegador)[/]")
    console.print("    [bold cyan][2][/] Markdown")
    console.print("    [bold cyan][3][/] JSON  [dim_text](para procesarlo con otra herramienta)[/]")
    console.print("    [bold cyan][4][/] CSV   [dim_text](hallazgos para hoja de calculo o SIEM)[/]")
    console.print("    [bold cyan][5][/] Todos")
    console.print("    [bold cyan][0][/] No generar informe")
    console.print()

    try:
        opcion = Prompt.ask("  [bold cyan]>[/]", console=console, default="1")
    except (KeyboardInterrupt, EOFError):
        return None

    return {
        "1": "html", "2": "md", "3": "json", "4": "csv",
        "5": "html,md,json,csv", "0": None,
    }.get(opcion.strip(), "html")


def solicitar_ruta_salida(console: Console, formatos: str, base: str) -> str:
    defecto = f"informe_{base}"
    try:
        nombre = Prompt.ask("  [bold cyan]Nombre del informe[/] [dim](sin extension)[/]",
                            console=console, default=defecto)
    except (KeyboardInterrupt, EOFError):
        return defecto
    return _limpiar_ruta(nombre) or defecto


def mostrar_resumen_captura(console: Console, info: dict) -> None:
    console.print(
        f"  [marca]🦈[/] [titulo]{info.get('nombre', '?')}[/] "
        f"[dim_text]· {info.get('paquetes', 0):,} paquetes · "
        f"{info.get('duracion', '?')}[/]"
    )
