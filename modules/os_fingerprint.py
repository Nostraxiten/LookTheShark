"""
modules/os_fingerprint.py — Que sistema operativo tiene cada equipo, y por que.

Este modulo no vuelve a analizar nada: el nucleo ya cruzo seis fuentes distintas
durante la unica pasada. Lo que hace aqui es ensenar el razonamiento, porque una
atribucion sin explicacion no vale para un informe forense.

Fuentes, de mas a menos concluyente:
  User-Agent      exacto, pero se falsea con una linea de codigo
  DHCP option 55  muy fiable, cuesta falsearlo, no siempre esta
  JA3             identifica el programa, no el sistema
  TCP SYN         nada facil de falsear sin tocar el kernel
  MAC OUI         solo dice el fabricante del interfaz
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import List

from rich.console import Console

from core import fingerprint
from modules import (Confianza, Finding, Severidad, formatear_hora, plural,
                     truncar)
from ui import theme

MODULE_NUM = 9
MODULE_NAME = "Sistemas operativos"
MODULE_ID = "os_fp"
MODULE_DESC = "Que es cada equipo y en que evidencia se basa la conclusion"


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    identificados = [h for h in analisis.hosts.values() if h.so and h.so != "Desconocido"]
    if not identificados:
        console.print("  [dim_text]No hubo suficiente trafico para identificar "
                      "ningun sistema operativo.[/]")
        console.print("  [dim_text]Hace falta al menos un SYN TCP, una peticion "
                      "DHCP o una cabecera User-Agent.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    familias = Counter(h.familia or "sin clasificar" for h in identificados)
    console.print(
        "  " + "   ".join(f"{theme.icono_so(f)} [valor]{c}[/] [dim_text]{f}[/]"
                          for f, c in familias.most_common())
    )
    console.print()

    # ── Tabla de atribucion ───────────────────────────
    t = theme.tabla("Atribucion por equipo")
    t.add_column("Equipo", style="bold bright_cyan", no_wrap=True)
    t.add_column("Sistema", max_width=28)
    t.add_column("Fiab.", width=7)
    t.add_column("Basado en", max_width=30)
    t.add_column("Saltos", justify="right", width=7)

    for h in sorted(identificados, key=lambda x: (not x.es_local, x.ip)):
        conf = {"alta": "[conf_alta]alta[/]", "media": "[conf_media]media[/]"}.get(
            h.confianza, "[conf_baja]baja[/]")
        t.add_row(
            h.ip,
            f"{theme.icono_so(h.familia)} {truncar(h.so, 26)}",
            conf,
            truncar(", ".join(h.fuentes) or "—", 28),
            str(h.saltos) if h.saltos else "—",
        )
    console.print(t)
    console.print()

    # ── El razonamiento, equipo a equipo ──────────────
    console.print("  [titulo]Como se llego a cada conclusion[/]")
    console.print()
    for h in sorted(identificados, key=lambda x: (not x.es_local, x.ip))[:12]:
        console.print(f"  [bright_cyan]{h.ip}[/]  "
                      f"{theme.icono_so(h.familia)} [titulo]{h.so}[/] "
                      f"[dim_text]({h.confianza})[/]")
        for candidato in h.candidatos_so[:5]:
            marca = "[exito]✔[/]" if candidato.os == h.so else "[dim] ·[/]"
            console.print(f"      {marca} [etiqueta]{candidato.fuente:<16}[/]"
                          f"{theme.esc(truncar(candidato.os, 28))}"
                          f"  [dim_text]{theme.esc(truncar(candidato.detalle, 44))}[/]")
        if h.firma_tcp:
            f = h.firma_tcp
            console.print(f"        [dim_text]huella TCP: TTL {f.ttl_obs}→{f.ttl_inicial}, "
                          f"ventana {f.window}, MSS {f.mss}, "
                          f"opciones «{f.orden_opciones or 'ninguna'}»[/]")
        if h.hostnames:
            console.print(f"        [dim_text]nombre anunciado: "
                          f"{theme.esc(', '.join(sorted(h.hostnames)[:3]))}[/]")
        if h.conflicto_so:
            console.print(f"        [sev_medio]⚠ {h.conflicto_so}[/]")
        console.print()

    # ── Clientes y agentes usados ─────────────────────
    con_clientes = [h for h in analisis.hosts.values() if h.clientes]
    if con_clientes:
        t2 = theme.tabla("Programas que generaron trafico")
        t2.add_column("Equipo", style="bright_cyan", no_wrap=True)
        t2.add_column("Programa", max_width=32)
        t2.add_column("Veces", justify="right", width=7)
        t2.add_column("Tipo", width=14)
        for h in con_clientes[:12]:
            for nombre, veces in sorted(h.clientes.items(), key=lambda x: -x[1])[:3]:
                categoria = ""
                for ua in h.user_agents:
                    info = fingerprint.analizar_user_agent(ua)
                    if info["cliente"] == nombre:
                        categoria = info["categoria"]
                        break
                estilo = "sev_alto" if categoria in ("escaner", "sospechoso") else "dim_text"
                t2.add_row(h.ip, theme.esc(truncar(nombre, 30)), str(veces),
                           f"[{estilo}]{categoria or '—'}[/]")
        console.print(t2)
        console.print()

    # ── Banners de servicio ───────────────────────────
    if analisis.banners:
        t3 = theme.tabla("Software identificado por su banner")
        t3.add_column("Servidor", style="bright_cyan", no_wrap=True)
        t3.add_column("Servicio", width=10)
        t3.add_column("Version", max_width=24)
        t3.add_column("Banner completo", max_width=40)
        for b in analisis.banners[:12]:
            t3.add_row(f"{b['ip']}:{b['puerto']}", b["servicio"] or "—",
                       theme.esc(b["version"]) or "[dim]—[/]",
                       theme.esc(truncar(b["banner"], 38)))
        console.print(t3)
        console.print()

    hallazgos.extend(_sistemas_obsoletos(analisis, identificados))
    hallazgos.extend(_escaneres_detectados(analisis, identificados))
    hallazgos.extend(_banners_informativos(analisis))

    for f in hallazgos:
        console.print(theme.panel_hallazgo(
            f.titulo, f.severidad, f.descripcion, f.evidencia,
            f.recomendacion, f.confianza))

    console.print(theme.pie_modulo())
    return hallazgos


# Sistemas sin soporte: aparecen tal cual en el nombre detectado.
SIN_SOPORTE = {
    "Windows XP": "sin actualizaciones desde 2014",
    "Windows 7": "sin actualizaciones desde enero de 2020",
    "Windows 8": "sin soporte desde 2016",
    "Windows Server 2012": "sin soporte extendido desde octubre de 2023",
    "kernel 2.4": "kernel de hace mas de dos decadas",
    "kernel 2.6": "kernel sin mantenimiento desde 2016",
    "kernel 3.x": "rama sin soporte de seguridad",
    "Solaris 10": "fuera de soporte general",
}


def _sistemas_obsoletos(analisis, identificados) -> List[Finding]:
    hallazgos = []
    for h in identificados:
        for clave, motivo in SIN_SOPORTE.items():
            if clave.lower() not in h.so.lower():
                continue
            hallazgos.append(Finding(
                titulo=f"Sistema sin soporte en la red: {h.so} ({h.ip})",
                descripcion=(
                    f"Se identifico {h.so}, {motivo}. Un sistema sin parches acumula "
                    f"vulnerabilidades publicas conocidas que no se van a corregir "
                    f"nunca. En una red plana, un solo equipo asi es la puerta de "
                    f"entrada al resto."
                ),
                severidad=Severidad.ALTO,
                confianza=h.confianza,
                modulo=MODULE_ID,
                evidencia=f"{h.ip} · identificado por {', '.join(h.fuentes) or 'huella TCP'}"
                          + (f" · nombre: {next(iter(h.hostnames))}" if h.hostnames else ""),
                recomendacion=(
                    "Actualiza el equipo o, si no es posible (equipo industrial, "
                    "software heredado), aislalo en su propia VLAN con acceso "
                    "restringido y monitorizado."
                ),
                patron="outdated_os",
                host=h.ip,
                host_so=h.so,
            ))
            break
    return hallazgos


def _escaneres_detectados(analisis, identificados) -> List[Finding]:
    """La huella TCP de un escaner no se parece a la de un sistema operativo."""
    hallazgos = []
    for h in identificados:
        if h.familia != "Escaner":
            continue
        puertos = len(h.puertos_contactados)
        hallazgos.append(Finding(
            titulo=f"Huella de herramienta de escaneo en {h.ip}",
            descripcion=(
                f"Los paquetes SYN de esta IP no tienen la forma que genera ningun "
                f"sistema operativo: coinciden con {h.so}. Los escaneres construyen "
                f"los paquetes a mano y dejan una huella caracteristica (ventana "
                f"pequena, casi sin opciones TCP)."
                + (f" Contacto con {puertos} puertos distintos." if puertos > 5 else "")
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.ALTA if h.confianza == "alta" else Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=(f"{h.ip}: ventana {h.firma_tcp.window}, opciones "
                       f"«{h.firma_tcp.orden_opciones or 'ninguna'}», "
                       f"TTL inicial {h.firma_tcp.ttl_inicial}"
                       if h.firma_tcp else h.ip),
            recomendacion=(
                "Confirma si el escaneo estaba autorizado. Si no, identifica el "
                "equipo por su MAC y desconectalo de la red mientras se investiga."
            ),
            patron="portscan",
            host=h.ip,
            host_so=h.so,
        ))
    return hallazgos


def _banners_informativos(analisis) -> List[Finding]:
    """Un banner con version exacta le regala el trabajo a un atacante."""
    hallazgos = []
    con_version = [b for b in analisis.banners if b["version"]]
    if not con_version:
        return hallazgos

    hallazgos.append(Finding(
        titulo=f"Servicios anunciando su version exacta ({len(con_version)})",
        descripcion=(
            "Varios servicios responden con su nombre y numero de version en el "
            "banner. Eso permite a cualquiera buscar directamente los CVE de esa "
            "version sin lanzar un solo exploit de prueba. No es una vulnerabilidad "
            "en si, pero acorta muchisimo el trabajo de quien esta enumerando."
        ),
        severidad=Severidad.BAJO,
        confianza=Confianza.ALTA,
        modulo=MODULE_ID,
        evidencia="; ".join(f"{b['ip']}:{b['puerto']} → {b['version']}"
                            for b in con_version[:5]),
        recomendacion=(
            "Configura los servicios para no revelar la version (ServerTokens Prod "
            "en Apache, server_tokens off en nginx, banners personalizados en SSH y "
            "FTP) y comprueba que esas versiones estan al dia."
        ),
        patron="banner_disclosure",
        host=con_version[0]["ip"],
    ))
    return hallazgos
