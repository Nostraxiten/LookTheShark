"""
modules/diff_engine.py — Comparar dos capturas.

Responde a "¿que ha cambiado?". Sirve para tres casos concretos:
  - antes y despues de aplicar una regla de firewall: ¿de verdad corta lo que
    tenia que cortar y nada mas?
  - antes y despues de un incidente: ¿que apareció que antes no estaba?
  - dos equipos que deberian comportarse igual: ¿por que uno hace algo raro?

Compara perfiles completos, no solo IPs: tambien equipos, sistemas operativos,
dominios, ficheros y hallazgos.
"""

from __future__ import annotations

from typing import List

from rich.console import Console

from core import services
from core.session import Analisis
from modules import (Finding, formatear_bytes, formatear_duracion, plural,
                     truncar)
from ui import theme

MODULE_NUM = 15
MODULE_NAME = "Comparativa"
MODULE_ID = "diff"
MODULE_DESC = "Que aparece, que desaparece y que cambia entre dos capturas"


def _perfil(analisis: Analisis) -> dict:
    """Resume una captura en conjuntos comparables."""
    return {
        "hosts": set(analisis.hosts),
        "puertos": {p for p in analisis.puertos_destino if not services.es_efimero(p)},
        "protocolos": set(analisis.protocolos_app),
        "flujos": {(f.cliente_ip, f.servidor_ip, f.servidor_puerto)
                   for f in analisis.flujos},
        "dominios": {e.nombre.lower() for e in analisis.dns if e.nombre},
        "sni": {s.sni.lower() for s in analisis.tls if s.sni},
        "so": {ip: h.so for ip, h in analisis.hosts.items() if h.so},
        "ficheros": {f.sha256 for f in analisis.ficheros if f.sha256},
        "nombres_fichero": {f.sha256: f.nombre for f in analisis.ficheros if f.sha256},
    }


def _bloque(console: Console, titulo: str, elementos, color: str,
            maximo: int = 15, formato=str) -> None:
    if not elementos:
        return
    elementos = sorted(elementos, key=lambda x: str(x))
    console.print(f"  [{color}]{titulo} ({len(elementos)})[/]")
    for e in elementos[:maximo]:
        console.print(f"      {formato(e)}")
    if len(elementos) > maximo:
        console.print(f"      [dim_text]… y {len(elementos) - maximo} mas[/]")
    console.print()


def run(analisis_a: Analisis, analisis_b: Analisis, config: dict,
        console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    a, b = _perfil(analisis_a), _perfil(analisis_b)

    # ── Comparativa de cifras ─────────────────────────
    t = theme.tabla("Las dos capturas en cifras")
    t.add_column("", style="etiqueta", justify="right", width=22)
    t.add_column(truncar(analisis_a.nombre, 26), justify="right", width=20)
    t.add_column(truncar(analisis_b.nombre, 26), justify="right", width=20)
    t.add_column("Cambio", justify="right", width=14)

    def fila(nombre, va, vb, formateador=str):
        if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
            delta = vb - va
            signo = "+" if delta > 0 else ""
            estilo = "exito" if delta == 0 else ("sev_medio" if delta > 0 else "dato")
            cambio = f"[{estilo}]{signo}{formateador(delta) if delta else '='}[/]"
        else:
            cambio = ""
        t.add_row(nombre, formateador(va), formateador(vb), cambio)

    fila("Paquetes", analisis_a.total_paquetes, analisis_b.total_paquetes,
         lambda n: f"{n:,}")
    fila("Duracion", analisis_a.duracion, analisis_b.duracion, formatear_duracion)
    fila("Volumen", analisis_a.bytes_totales, analisis_b.bytes_totales, formatear_bytes)
    fila("Equipos", len(a["hosts"]), len(b["hosts"]))
    fila("Puertos distintos", len(a["puertos"]), len(b["puertos"]))
    fila("Flujos", len(a["flujos"]), len(b["flujos"]))
    fila("Dominios DNS", len(a["dominios"]), len(b["dominios"]))
    fila("Ficheros", len(a["ficheros"]), len(b["ficheros"]))
    console.print(t)
    console.print()

    # ── Novedades ─────────────────────────────────────
    console.print(f"  [titulo]▲ APARECE en «{truncar(analisis_b.nombre, 40)}»[/]")
    console.print()

    nuevos_hosts = b["hosts"] - a["hosts"]
    _bloque(console, "Equipos nuevos", nuevos_hosts, "exito",
            formato=lambda ip: f"[bright_cyan]{ip}[/] "
                               f"[dim_text]{b['so'].get(ip, 'sin identificar')}[/]")
    _bloque(console, "Protocolos nuevos", b["protocolos"] - a["protocolos"], "exito")
    _bloque(console, "Puertos nuevos", b["puertos"] - a["puertos"], "exito",
            formato=lambda p: f"{p} [dim_text]{services.servicio(p)}[/]")
    _bloque(console, "Conexiones nuevas", b["flujos"] - a["flujos"], "exito",
            formato=lambda f: f"{f[0]} → {f[1]}:{f[2]} "
                              f"[dim_text]{services.servicio(f[2])}[/]")
    _bloque(console, "Dominios nuevos", (b["dominios"] | b["sni"]) - (a["dominios"] | a["sni"]),
            "exito", formato=lambda d: truncar(d, 60))
    _bloque(console, "Ficheros nuevos", b["ficheros"] - a["ficheros"], "exito",
            formato=lambda h: f"{truncar(b['nombres_fichero'].get(h, '?'), 34)} "
                              f"[dim]{h[:16]}…[/]")

    # ── Desaparecidos ─────────────────────────────────
    console.print(f"  [titulo]▼ DESAPARECE respecto a «{truncar(analisis_a.nombre, 40)}»[/]")
    console.print()

    _bloque(console, "Equipos que ya no se ven", a["hosts"] - b["hosts"], "sev_medio")
    _bloque(console, "Puertos que ya no se usan", a["puertos"] - b["puertos"], "sev_medio",
            formato=lambda p: f"{p} [dim_text]{services.servicio(p)}[/]")
    _bloque(console, "Conexiones cortadas", a["flujos"] - b["flujos"], "sev_medio",
            formato=lambda f: f"{f[0]} → {f[1]}:{f[2]}")

    # ── Cambios de sistema operativo ──────────────────
    cambios_so = {ip: (a["so"][ip], b["so"][ip])
                  for ip in a["so"].keys() & b["so"].keys()
                  if a["so"][ip] != b["so"][ip]}
    if cambios_so:
        console.print("  [sev_alto]Equipos que ahora parecen otro sistema[/]")
        for ip, (antes, ahora) in list(cambios_so.items())[:10]:
            console.print(f"      [bright_cyan]{ip}[/]: {antes} → [sev_alto]{ahora}[/]")
        console.print("      [dim_text]Una IP que cambia de sistema operativo entre "
                      "dos capturas suele ser DHCP reasignando la direccion… o "
                      "alguien suplantandola.[/]")
        console.print()

    # ── Hallazgos ─────────────────────────────────────
    if nuevos_hosts:
        hallazgos.append(Finding(
            titulo=f"{plural(len(nuevos_hosts), 'equipo nuevo', 'equipos nuevos')} "
                   f"en la segunda captura",
            descripcion=(
                "Aparecen equipos que no estaban en la captura de referencia. En una "
                "red controlada, cada equipo nuevo deberia poder explicarse."
            ),
            severidad="medio" if len(nuevos_hosts) > 3 else "bajo",
            confianza="alta",
            modulo=MODULE_ID,
            evidencia=", ".join(sorted(nuevos_hosts)[:8]),
            recomendacion="Contrasta la lista con tu inventario de activos.",
            patron="",
        ))

    nuevos_flujos_externos = {f for f in b["flujos"] - a["flujos"]
                              if not f[1].startswith(("10.", "192.168.", "172."))}
    if nuevos_flujos_externos:
        hallazgos.append(Finding(
            titulo=f"{plural(len(nuevos_flujos_externos), 'conexion nueva', 'conexiones nuevas')} "
                   f"hacia Internet",
            descripcion=(
                "Hay destinos externos que no aparecian antes. Si esta comparativa "
                "es de antes y despues de un incidente, aqui es donde suele estar "
                "el canal de control del atacante."
            ),
            severidad="medio",
            confianza="media",
            modulo=MODULE_ID,
            evidencia="; ".join(f"{f[0]} → {f[1]}:{f[2]}"
                                for f in sorted(nuevos_flujos_externos)[:6]),
            recomendacion=(
                "Comprueba a quien pertenecen esos destinos y que proceso los "
                "contacta."
            ),
            patron="",
        ))

    if cambios_so:
        hallazgos.append(Finding(
            titulo=f"{plural(len(cambios_so), 'IP cambia', 'IPs cambian')} de "
                   f"sistema operativo entre capturas",
            descripcion=(
                "Una misma direccion IP se identifica como sistemas distintos en "
                "cada captura. Lo habitual es que el DHCP haya reasignado la "
                "direccion a otro equipo. La alternativa es que alguien este usando "
                "esa IP sin permiso."
            ),
            severidad="medio",
            confianza="media",
            modulo=MODULE_ID,
            evidencia="; ".join(f"{ip}: {x} → {y}" for ip, (x, y) in
                                list(cambios_so.items())[:5]),
            recomendacion=(
                "Cruza con las concesiones del servidor DHCP para confirmar que el "
                "cambio es legitimo."
            ),
            patron="os_conflict",
        ))

    if not (nuevos_hosts or b["flujos"] - a["flujos"] or cambios_so):
        console.print(theme.sin_hallazgos(
            "La segunda captura no aporta nada nuevo respecto a la primera."))

    console.print(theme.pie_modulo())
    return hallazgos
