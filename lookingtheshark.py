#!/usr/bin/env python3
"""
lookingtheshark.py — Punto de entrada de LookingTheShark.

Traductor forense de capturas de red: convierte un .pcap en una explicacion
de que paso, quien lo hizo y que conviene hacer al respecto.

Flujo:
    banner → analisis en una sola pasada → modulos que interpretan → informe

No necesita Wireshark ni tshark: el lector de capturas, los disectores y todos
los parsers de protocolo son Python puro (paquete core/). Las unicas
dependencias son rich (presentacion) y jinja2 (informes), ambas puras.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional

VERSION = "2.0.0"
PYTHON_MINIMO = (3, 9)


def _salir_con_ayuda(mensaje: str, detalle: str = "") -> None:
    """Error de arranque con instrucciones, no con un traceback."""
    print(f"\n  [ERROR] {mensaje}\n")
    if detalle:
        print(detalle)
    print()
    sys.exit(1)


if sys.version_info < PYTHON_MINIMO:
    _salir_con_ayuda(
        f"LookingTheShark necesita Python {PYTHON_MINIMO[0]}.{PYTHON_MINIMO[1]} "
        f"o superior (tienes {sys.version_info.major}.{sys.version_info.minor}).",
        "  Instala una version mas reciente desde https://python.org o con el\n"
        "  gestor de paquetes de tu sistema.")

# El directorio del script va primero en sys.path para que 'core' y 'modules'
# se resuelvan aunque se invoque desde cualquier sitio.
_RAIZ = os.path.dirname(os.path.abspath(__file__))
if _RAIZ not in sys.path:
    sys.path.insert(0, _RAIZ)

try:
    from rich.console import Console
    from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                               TimeElapsedColumn)
except ImportError:
    _salir_con_ayuda(
        "Falta la dependencia 'rich'.",
        "  Instala las dependencias:\n\n"
        "    Linux / macOS   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n"
        "    Windows         python -m venv .venv && .venv\\Scripts\\pip install -r requirements.txt\n\n"
        "  O ejecuta el instalador:  bash install.sh   /   powershell -File install.ps1")

from core.pcap_reader import CapturaInvalida, es_captura
from core.session import Analisis
from modules import Finding, filtrar_por_confianza, formatear_bytes, ordenar_hallazgos
from ui import theme
from ui.banner import mostrar_banner
from ui.menu import (MENU_ITEMS, MODULOS_POR_DEFECTO, seleccionar_modulos,
                     solicitar_archivo, solicitar_archivo_diff,
                     solicitar_exportacion, solicitar_opciones,
                     solicitar_ruta_salida)

import modules.behavior_heuristics
import modules.credentials_plain
import modules.diff_engine
import modules.dns_analysis
import modules.file_extraction
import modules.http_analysis
import modules.ip_hosts
import modules.layer2_anomalies
import modules.mitre_mapping
import modules.os_fingerprint
import modules.protocols
import modules.report_builder
import modules.reputation_offline
import modules.secrets_scan
import modules.timeline
import modules.tls_analysis


# ──────────────────────────────────────────────────────
# Registro de modulos
# ──────────────────────────────────────────────────────
MODULOS = {
    "ip_hosts":   ("Equipos",             modules.ip_hosts.run),
    "protocols":  ("Protocolos",          modules.protocols.run),
    "dns":        ("DNS",                 modules.dns_analysis.run),
    "http":       ("HTTP",                modules.http_analysis.run),
    "files":      ("Ficheros",            modules.file_extraction.run),
    "tls":        ("TLS",                 modules.tls_analysis.run),
    "creds":      ("Credenciales",        modules.credentials_plain.run),
    "secrets":    ("Material sensible",   modules.secrets_scan.run),
    "os_fp":      ("Sistemas operativos", modules.os_fingerprint.run),
    "layer2":     ("Red local",           modules.layer2_anomalies.run),
    "heuristics": ("Comportamiento",      modules.behavior_heuristics.run),
    "reputation": ("Reputacion offline",  modules.reputation_offline.run),
    "timeline":   ("Cronologia",          modules.timeline.run),
    # mitre y diff tienen firma propia y se ejecutan aparte.
    "mitre":      ("MITRE ATT&CK",        None),
    "diff":       ("Comparativa",         None),
}

# Alias para que los nombres antiguos de --modules sigan funcionando.
ALIAS_MODULOS = {
    "hosts": "ip_hosts", "ips": "ip_hosts", "equipos": "ip_hosts",
    "proto": "protocols", "protocolos": "protocols",
    "web": "http", "ficheros": "files", "archivos": "files",
    "credenciales": "creds", "passwords": "creds",
    "secretos": "secrets", "os": "os_fp", "so": "os_fp",
    "l2": "layer2", "arp": "layer2",
    "comportamiento": "heuristics", "deep": "heuristics",
    "reputacion": "reputation", "cronologia": "timeline",
}


def resolver_modulos(texto: str) -> List[str]:
    """Convierte '--modules http,creds' en una lista de IDs validos."""
    pedidos = []
    for bruto in texto.replace(";", ",").split(","):
        nombre = bruto.strip().lower()
        if not nombre:
            continue
        nombre = ALIAS_MODULOS.get(nombre, nombre)
        if nombre in MODULOS:
            pedidos.append(nombre)
        else:
            print(f"  [!] Modulo desconocido: '{bruto.strip()}' (se ignora)")
    return pedidos


# ──────────────────────────────────────────────────────
# Analisis
# ──────────────────────────────────────────────────────
def analizar_captura(ruta: str, config: dict, console: Console) -> Optional[Analisis]:
    """Ejecuta la pasada unica sobre el fichero mostrando el progreso."""
    tamano = os.path.getsize(ruta) if os.path.isfile(ruta) else 0
    nombre = os.path.basename(ruta)

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28, complete_style="cyan", finished_style="green"),
        TextColumn("[dim]{task.fields[detalle]}[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progreso:
        tarea = progreso.add_task(
            f"[cyan]Leyendo {nombre}", total=max(tamano, 1), detalle="")

        def avance(paquetes: int, leidos: int) -> None:
            progreso.update(tarea, completed=min(leidos, tamano or leidos),
                            detalle=f"{paquetes:,} paquetes")

        analisis = Analisis(ruta, config)
        try:
            analisis.ejecutar(avance)
        except CapturaInvalida as exc:
            progreso.stop()
            console.print(f"  [error]✘ {exc}[/]")
            return None
        except (OSError, MemoryError) as exc:
            progreso.stop()
            console.print(f"  [error]✘ No se pudo leer la captura:[/] {exc}")
            return None

    return analisis


def mostrar_cabecera_analisis(analisis: Analisis, console: Console) -> None:
    """Ficha de la captura, antes de que empiecen los modulos."""
    from modules import formatear_duracion, formatear_hora

    velocidad = (analisis.total_paquetes / analisis.tiempo_analisis
                 if analisis.tiempo_analisis > 0 else 0)

    console.print(theme.tabla_clave_valor([
        ("Captura", f"[valor]{analisis.nombre}[/] [dim_text]({analisis.formato})[/]"),
        ("Paquetes", f"[valor]{analisis.total_paquetes:,}[/]"
                     + (f"  [dim_text]({analisis.paquetes_malformados:,} ilegibles)[/]"
                        if analisis.paquetes_malformados else "")),
        ("Volumen", formatear_bytes(analisis.bytes_totales)),
        ("Periodo", f"{formatear_hora(analisis.primer_ts, con_fecha=True)} "
                    f"[separador]→[/] {formatear_hora(analisis.ultimo_ts)} "
                    f"[dim_text]({formatear_duracion(analisis.duracion)})[/]"),
        ("Equipos", f"[lan]{len(analisis.hosts_locales)} locales[/] · "
                    f"[wan]{len(analisis.hosts_externos)} externos[/]"),
        ("Reconstruido", f"{len(analisis.reensamblador):,} flujos TCP · "
                         f"{len(analisis.http):,} HTTP · {len(analisis.tls):,} TLS · "
                         f"{len(analisis.dns):,} DNS"),
        ("Analizado en", f"[exito]{analisis.tiempo_analisis:.2f} s[/]"
                         f"  [dim_text]({velocidad:,.0f} paquetes/s)[/]"),
    ]))
    console.print()


def ejecutar_modulos(analisis: Analisis, seleccion: List[str], config: dict,
                     console: Console) -> List[Finding]:
    """Lanza cada modulo seleccionado sobre el analisis ya hecho."""
    hallazgos: List[Finding] = []

    for mod_id in seleccion:
        if mod_id in ("mitre", "diff"):
            continue
        entrada = MODULOS.get(mod_id)
        if not entrada or not entrada[1]:
            continue
        nombre, funcion = entrada
        try:
            resultado = funcion(analisis, config, console)
            if resultado:
                hallazgos.extend(resultado)
        except Exception as exc:
            console.print(f"  [error]✘ El modulo «{nombre}» fallo:[/] {exc}")
            if config.get("debug"):
                import traceback
                console.print_exception()
            console.print("  [dim_text]El resto del analisis continua.[/]")
            console.print()

    # El mapeo MITRE siempre enriquece los hallazgos aunque no se pinte.
    if "mitre" in seleccion or config.get("mitre_mode"):
        config["mitre_mode"] = True
        try:
            modules.mitre_mapping.run(hallazgos, config, console)
        except Exception as exc:
            console.print(f"  [error]✘ El mapeo MITRE fallo:[/] {exc}")
    else:
        modules.mitre_mapping.enriquecer(hallazgos)

    return hallazgos


def mostrar_veredicto(hallazgos: List[Finding], analisis: Analisis,
                      console: Console) -> None:
    """Resumen final: lo primero que mira quien ejecuta la herramienta."""
    from modules.report_builder import resumen_ejecutivo

    resumen = resumen_ejecutivo(hallazgos, analisis)
    console.print()
    console.print("[separador]" + "═" * 78 + "[/]")
    console.print()

    color = {"critico": "sev_critico", "alto": "sev_alto",
             "medio": "sev_medio", "bajo": "exito"}[resumen["nivel"]]
    console.print(f"  [{color}] {resumen['veredicto'].upper()} [/]")
    console.print()
    console.print(f"  {resumen['explicacion']}")
    console.print()

    if resumen["por_severidad"]:
        partes = []
        for nivel in ("critico", "alto", "medio", "bajo", "info"):
            cantidad = resumen["por_severidad"].get(nivel)
            if cantidad:
                partes.append(f"{theme.severidad(nivel, con_icono=False)} "
                              f"[valor]{cantidad}[/]")
        console.print("  " + "   ".join(partes))
        console.print()

    if resumen["prioridades"]:
        console.print("  [titulo]Por donde empezar[/]")
        console.print()
        for i, p in enumerate(resumen["prioridades"], 1):
            console.print(f"  [bold cyan]{i}.[/] {theme.severidad(p['severidad'])} "
                          f"[titulo]{p['titulo']}[/]")
            console.print(f"     [dim_text]→ {p['accion']}[/]")
            console.print()


# ──────────────────────────────────────────────────────
# Modos especiales
# ──────────────────────────────────────────────────────
def modo_diff(rutas, config: dict, console: Console) -> int:
    ruta_a, ruta_b = rutas
    for ruta in (ruta_a, ruta_b):
        if not os.path.isfile(ruta):
            console.print(f"  [error]✘ No existe:[/] {ruta}")
            return 1

    console.print(f"  [titulo]Comparativa[/] [dim_text]{os.path.basename(ruta_a)} "
                  f"↔ {os.path.basename(ruta_b)}[/]")
    console.print()

    analisis_a = analizar_captura(ruta_a, dict(config), console)
    analisis_b = analizar_captura(ruta_b, dict(config), console)
    if not analisis_a or not analisis_b:
        return 1

    hallazgos = modules.diff_engine.run(analisis_a, analisis_b, config, console)

    if config.get("format"):
        config["output_base"] = config.get("output_base") or "informe_comparativa"
        rutas_escritas = modules.report_builder.build_reports(
            hallazgos, config, analisis_b)
        for ruta in rutas_escritas:
            console.print(f"  [exito]✔[/] Informe generado: [dato]{ruta}[/]")
    return 0


def modo_listar(console: Console) -> int:
    console.print("  [titulo]Modulos disponibles[/]")
    console.print()
    t = theme.tabla()
    t.add_column("ID", style="bold bright_cyan", width=13)
    t.add_column("Nombre", width=22)
    t.add_column("Que hace", max_width=44)
    for item in MENU_ITEMS:
        t.add_row(item["id"], item["name"], item["desc"])
    console.print(t)
    console.print()
    console.print("  [dim_text]Uso:[/] [dato]--modules http,creds,secrets[/]")
    console.print()
    return 0


def modo_autodiagnostico(console: Console) -> int:
    """Comprueba que todo esta en su sitio. Util para depurar una instalacion."""
    console.print("  [titulo]Comprobacion del entorno[/]")
    console.print()

    filas = []
    ok = True

    version_py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    filas.append(("Python", version_py, sys.version_info >= PYTHON_MINIMO))

    for paquete in ("rich", "jinja2"):
        try:
            modulo = __import__(paquete)
            filas.append((paquete, getattr(modulo, "__version__", "instalado"), True))
        except ImportError:
            filas.append((paquete, "NO INSTALADO", False))
            ok = False

    for opcional, para_que in (("geoip2", "geolocalizacion de IPs"),
                               ("brotli", "cuerpos HTTP comprimidos con Brotli"),
                               ("zstandard", "capturas comprimidas con zstd")):
        try:
            __import__(opcional)
            filas.append((f"{opcional} (opcional)", "instalado", True))
        except ImportError:
            filas.append((f"{opcional} (opcional)", f"ausente — sin {para_que}", None))

    for nombre in ("os_signatures.json", "ja3_fingerprints.json",
                   "mitre_map.json", "oui.json"):
        ruta = os.path.join(_RAIZ, "data", nombre)
        existe = os.path.isfile(ruta)
        filas.append((f"data/{nombre}", "presente" if existe else "FALTA", existe))
        ok = ok and existe

    for nombre in ("report.html.j2", "report.md.j2"):
        ruta = os.path.join(_RAIZ, "templates", nombre)
        existe = os.path.isfile(ruta)
        filas.append((f"templates/{nombre}", "presente" if existe else "FALTA", existe))
        ok = ok and existe

    feeds = os.path.join(_RAIZ, "data", "reputation_feeds")
    n_feeds = len([f for f in os.listdir(feeds)
                   if f.endswith((".txt", ".csv", ".list", ".ioc"))]) \
        if os.path.isdir(feeds) else 0
    filas.append(("Listas de reputacion",
                  f"{n_feeds} fichero(s)" if n_feeds else "ninguna (opcional)",
                  True if n_feeds else None))

    t = theme.tabla()
    t.add_column("Componente", width=30)
    t.add_column("Estado", max_width=40)
    t.add_column("", width=4)
    for nombre, estado, correcto in filas:
        marca = ("[exito]✔[/]" if correcto else
                 "[dim_text]—[/]" if correcto is None else "[error]✘[/]")
        t.add_row(nombre, estado, marca)
    console.print(t)
    console.print()

    # Prueba real de extremo a extremo con una captura generada al vuelo.
    console.print("  [dim_text]Probando el motor con una captura sintetica…[/]")
    try:
        import tempfile
        sys.path.insert(0, os.path.join(_RAIZ, "tests"))
        from generar_pcap_demo import generar
        with tempfile.TemporaryDirectory() as tmp:
            ruta = generar(os.path.join(tmp, "autotest.pcap"))
            analisis = Analisis(ruta, {}).ejecutar()
        console.print(f"  [exito]✔[/] Motor operativo: "
                      f"{analisis.total_paquetes} paquetes, "
                      f"{len(analisis.hosts)} equipos, "
                      f"{len(analisis.http)} transacciones HTTP en "
                      f"{analisis.tiempo_analisis:.3f} s")
    except Exception as exc:
        console.print(f"  [error]✘ La prueba del motor fallo:[/] {exc}")
        ok = False

    console.print()
    if ok:
        console.print("  [exito]✔ Todo listo. Ejecuta:[/] "
                      "[dato]python lookingtheshark.py[/]")
    else:
        console.print("  [error]✘ Faltan componentes.[/] Ejecuta el instalador: "
                      "[dato]bash install.sh[/] o [dato]powershell -File install.ps1[/]")
    console.print()
    return 0 if ok else 1


# ──────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────
def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lookingtheshark",
        description="LookingTheShark — traductor forense de capturas de red.",
        epilog=(
            "Ejemplos:\n"
            "  %(prog)s                                  modo interactivo\n"
            "  %(prog)s -f captura.pcapng                analisis completo\n"
            "  %(prog)s -f captura.pcapng --deep --mitre --format html\n"
            "  %(prog)s -f captura.pcapng -m http,creds,secrets\n"
            "  %(prog)s --diff antes.pcap despues.pcap\n"
            "  %(prog)s --check                          comprobar la instalacion\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    entrada = parser.add_argument_group("entrada")
    entrada.add_argument("-f", "--file", help="captura .pcap / .pcapng (admite .gz)")
    entrada.add_argument("--diff", nargs=2, metavar=("ANTES", "DESPUES"),
                         help="compara dos capturas")
    entrada.add_argument("-m", "--modules",
                         help="modulos a ejecutar, separados por coma (ver --list)")
    entrada.add_argument("--list", action="store_true",
                         help="lista los modulos disponibles y sale")

    analisis = parser.add_argument_group("analisis")
    analisis.add_argument("--deep", action="store_true",
                          help="activa las heuristicas de comportamiento")
    analisis.add_argument("--mitre", action="store_true",
                          help="mapea los hallazgos a MITRE ATT&CK")
    analisis.add_argument("--baseline", metavar="JSON",
                          help="perfil de red normal para reducir falsos positivos")
    analisis.add_argument("--whitelist-ips", metavar="FICHERO",
                          help="fichero con IPs a excluir, una por linea")
    analisis.add_argument("--time-range", metavar="HH:MM-HH:MM",
                          help="analiza solo esa franja horaria")
    analisis.add_argument("--confidence-threshold", choices=["bajo", "medio", "alto"],
                          default="bajo", metavar="NIVEL",
                          help="descarta hallazgos por debajo de esa confianza")
    analisis.add_argument("--max-stream-mb", type=int, default=4, metavar="N",
                          help="memoria maxima por sentido de flujo TCP (por defecto 4)")
    analisis.add_argument("--max-memory-mb", type=int, default=512, metavar="N",
                          help="techo global de reensamblado (por defecto 512)")
    analisis.add_argument("--full-reassembly", action="store_true",
                          help="reensambla todos los flujos, no solo los de puertos conocidos")
    analisis.add_argument("--max-flows", type=int, default=200000, metavar="N",
                          help="numero maximo de conexiones TCP a seguir (por defecto 200000)")

    salida = parser.add_argument_group("salida")
    salida.add_argument("--format", default="", metavar="LISTA",
                        help="md, html, json, csv (combinables por coma)")
    salida.add_argument("-o", "--output", metavar="RUTA",
                        help="ruta base del informe, sin extension")
    salida.add_argument("--extract-dir", metavar="CARPETA",
                        help="guarda en disco los ficheros reconstruidos")
    salida.add_argument("--anonymize", action="store_true",
                        help="sustituye las IPs por alias en el informe")
    salida.add_argument("--quiet", action="store_true",
                        help="solo el veredicto final y los informes")
    salida.add_argument("--no-banner", action="store_true", help="omite el banner")
    salida.add_argument("--color", choices=["auto", "si", "no"], default="auto",
                        help="fuerza o desactiva el color")
    salida.add_argument("--width", type=int, metavar="N",
                        help="ancho fijo de salida (util al redirigir a fichero)")

    otros = parser.add_argument_group("otros")
    otros.add_argument("--menu", action="store_true", help="fuerza el modo interactivo")
    otros.add_argument("--check", action="store_true",
                       help="comprueba la instalacion y sale")
    otros.add_argument("--debug", action="store_true",
                       help="muestra la traza completa si un modulo falla")
    otros.add_argument("--version", action="version",
                       version=f"LookingTheShark {VERSION}")
    return parser


def main() -> int:
    parser = construir_parser()
    args = parser.parse_args()

    forzar = {"auto": None, "si": True, "no": False}[args.color]
    console = Console(theme=theme.SHARK_THEME, force_terminal=forzar,
                      width=args.width, highlight=False,
                      no_color=(args.color == "no"))

    if args.check:
        mostrar_banner(console, compacto=True)
        return modo_autodiagnostico(console)

    if args.list:
        return modo_listar(console)

    if not args.no_banner and not args.quiet:
        mostrar_banner(console)

    # ── Configuracion ─────────────────────────────────
    whitelist: List[str] = []
    if args.whitelist_ips:
        if os.path.isfile(args.whitelist_ips):
            with open(args.whitelist_ips, "r", encoding="utf-8") as fh:
                whitelist = [l.strip() for l in fh
                             if l.strip() and not l.lstrip().startswith("#")]
            console.print(f"  [dim_text]Excluyendo {len(whitelist)} IPs de la "
                          f"lista blanca.[/]")
        else:
            console.print(f"  [advertencia]⚠ No existe la lista blanca "
                          f"'{args.whitelist_ips}'; se ignora.[/]")

    baseline = {}
    if args.baseline:
        import json
        try:
            with open(args.baseline, "r", encoding="utf-8") as fh:
                baseline = json.load(fh)
        except (OSError, ValueError) as exc:
            console.print(f"  [advertencia]⚠ No se pudo leer el baseline:[/] {exc}")

    config = {
        "deep_mode": args.deep,
        "mitre_mode": args.mitre,
        "baseline_profile": baseline,
        "whitelist_ips": whitelist,
        "time_range": args.time_range,
        "confidence_threshold": args.confidence_threshold,
        "anonymize": args.anonymize,
        "format": args.format,
        "output_base": args.output,
        "extract_dir": args.extract_dir,
        "debug": args.debug,
        "quiet": args.quiet,
        "max_stream_bytes": max(1, args.max_stream_mb) * 1024 * 1024,
        "max_memoria_bytes": max(16, args.max_memory_mb) * 1024 * 1024,
        "reensamblar_todo": args.full_reassembly,
        "max_flujos": max(1000, args.max_flows),
    }

    # ── Modo comparativa ──────────────────────────────
    if args.diff:
        return modo_diff(args.diff, config, console)

    # ── Modo interactivo ──────────────────────────────
    interactivo = args.menu or not args.file
    if interactivo:
        ruta = solicitar_archivo(console)
        if not ruta:
            console.print("\n  [dim_text]Hasta luego.[/]\n")
            return 0

        seleccion = seleccionar_modulos(console)
        if not seleccion:
            console.print("\n  [dim_text]Hasta luego.[/]\n")
            return 0

        opciones = solicitar_opciones(console)
        config.update(opciones)

        formato = solicitar_exportacion(console)
        if formato:
            config["format"] = formato
            base = os.path.splitext(os.path.basename(ruta))[0]
            config["output_base"] = solicitar_ruta_salida(console, formato, base)
        else:
            config["format"] = ""
        console.print()
    else:
        ruta = args.file
        if not os.path.isfile(ruta):
            console.print(f"\n  [error]✘ No existe el fichero:[/] {ruta}\n")
            return 1
        if not es_captura(ruta):
            console.print(f"\n  [advertencia]⚠ '{os.path.basename(ruta)}' no parece "
                          f"un .pcap/.pcapng. Se intentara igualmente.[/]\n")
        seleccion = (resolver_modulos(args.modules) if args.modules
                     else list(MODULOS_POR_DEFECTO))
        if not seleccion:
            console.print("\n  [error]✘ Ningun modulo valido seleccionado.[/]\n")
            return 1
        if args.deep and "heuristics" not in seleccion:
            seleccion.append("heuristics")
        if args.mitre and "mitre" not in seleccion:
            seleccion.append("mitre")

    # ── Analisis ──────────────────────────────────────
    inicio = time.perf_counter()
    analisis = analizar_captura(ruta, config, console)
    if analisis is None:
        return 1

    if analisis.total_paquetes == 0:
        console.print("  [advertencia]⚠ La captura no contiene ningun paquete.[/]\n")
        return 1

    if not args.quiet:
        mostrar_cabecera_analisis(analisis, console)

    # Si algun techo recorto el analisis hay que decirlo: un informe incompleto
    # que se presenta como completo es peor que no tener informe.
    if analisis.limites_alcanzados:
        console.print("  [advertencia]⚠ La captura supera algunos limites y el "
                      "analisis es parcial:[/]")
        for aviso in analisis.limites_alcanzados:
            console.print(f"      [dim_text]· {aviso}[/]")
        console.print("      [dim_text]Sube los techos con --max-flows, "
                      "--max-stream-mb y --max-memory-mb si tienes RAM de sobra.[/]")
        console.print()

    # ── Modulos ───────────────────────────────────────
    if args.quiet:
        # La consola silenciosa tiene que llevar el MISMO tema: sin el, los
        # estilos propios de la herramienta no existen y rich aborta el modulo.
        consola_modulos = Console(theme=theme.SHARK_THEME, quiet=True,
                                  width=args.width or 100, highlight=False)
        hallazgos = ejecutar_modulos(analisis, seleccion, config, consola_modulos)
    else:
        hallazgos = ejecutar_modulos(analisis, seleccion, config, console)

    hallazgos = filtrar_por_confianza(hallazgos, config["confidence_threshold"])
    hallazgos = ordenar_hallazgos(hallazgos)

    # ── Veredicto ─────────────────────────────────────
    mostrar_veredicto(hallazgos, analisis, console)

    # ── Informes ──────────────────────────────────────
    if config.get("format"):
        if not config.get("output_base"):
            base = os.path.splitext(os.path.basename(ruta))[0]
            config["output_base"] = f"informe_{base}"
        rutas = modules.report_builder.build_reports(hallazgos, config, analisis)
        for escrito in rutas:
            console.print(f"  [exito]✔[/] Informe generado: "
                          f"[dato]{os.path.abspath(escrito)}[/]")
        console.print()

    total = time.perf_counter() - inicio
    console.print(f"  [dim_text]Completado en {total:.2f} s "
                  f"({analisis.tiempo_analisis:.2f} s de analisis + "
                  f"{total - analisis.tiempo_analisis:.2f} s de presentacion).[/]")
    console.print()

    # Codigo de salida util para scripts y CI.
    if any(f.severidad == "critico" for f in hallazgos):
        return 2
    if any(f.severidad == "alto" for f in hallazgos):
        return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n  Interrumpido por el usuario.\n")
        sys.exit(130)
    except BrokenPipeError:
        # Ocurre al hacer `| head`. No es un error del programa.
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
