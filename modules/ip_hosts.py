"""
modules/ip_hosts.py — Inventario de equipos.

En vez de una lista de IPs, un inventario: quien es cada maquina, con que
sistema operativo, que fabricante, que nombre tiene, si actua de cliente o de
servidor, y con quien habla. Una IP no dice nada; "Windows 11 llamado PC-JUANA
que se conecta a 45.33.32.156 cada 30 segundos" lo dice todo.
"""

from __future__ import annotations

from typing import List

from rich.console import Console

from core import services
from modules import (Confianza, Finding, Severidad, formatear_bytes,
                     formatear_duracion, plural, truncar)
from ui import theme

MODULE_NUM = 1
MODULE_NAME = "Equipos"
MODULE_ID = "ip_hosts"
MODULE_DESC = "Quien hay en la red, con que sistema y con quien habla"


def _geolocalizar(ip: str) -> str:
    """Geolocalizacion opcional: solo si el usuario ha puesto la base GeoLite2."""
    return _geo_cache.get(ip) or _geo_lookup(ip)


_geo_cache = {}
_geo_reader = None
_geo_intentado = False


def _geo_lookup(ip: str) -> str:
    global _geo_reader, _geo_intentado
    if not _geo_intentado:
        _geo_intentado = True
        try:
            import os
            import geoip2.database
            for nombre in ("GeoLite2-City.mmdb", "GeoLite2-Country.mmdb"):
                ruta = os.path.join(os.path.dirname(__file__), "..", "data", "geoip", nombre)
                if os.path.isfile(ruta):
                    _geo_reader = geoip2.database.Reader(ruta)
                    break
        except Exception:
            _geo_reader = None

    if _geo_reader is None:
        _geo_cache[ip] = ""
        return ""
    try:
        try:
            resp = _geo_reader.city(ip)
            partes = [p for p in (resp.city.name, resp.country.iso_code) if p]
        except AttributeError:
            resp = _geo_reader.country(ip)
            partes = [resp.country.iso_code] if resp.country.iso_code else []
        valor = ", ".join(partes)
    except Exception:
        valor = ""
    _geo_cache[ip] = valor
    return valor


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    hosts = analisis.hosts
    if not hosts:
        console.print("  [dim_text]No se encontro trafico IP en la captura.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    locales = analisis.hosts_locales
    externos = analisis.hosts_externos

    console.print(theme.tabla_clave_valor([
        ("Equipos vistos", f"[valor]{len(hosts)}[/]"),
        ("En la red local", f"[lan]{len(locales)}[/]"),
        ("En Internet", f"[wan]{len(externos)}[/]"),
        ("Conversaciones", f"[valor]{len(analisis.conversaciones)}[/]"),
    ]))
    console.print()

    # ── Inventario de equipos locales ─────────────────
    perfiles = sorted(hosts.values(),
                      key=lambda h: (not h.es_local,
                                     -(h.bytes_enviados + h.bytes_recibidos)))

    t = theme.tabla("Inventario de equipos")
    t.add_column("IP", style="bold bright_cyan", no_wrap=True)
    t.add_column("Sistema operativo", max_width=30)
    t.add_column("Fiab.", width=6)
    t.add_column("Fabricante / nombre", max_width=26)
    t.add_column("Rol", width=9)
    t.add_column("Trafico", justify="right", width=10)

    for h in perfiles[:25]:
        icono = theme.icono_so(h.familia)
        so = f"{icono} {truncar(h.so or 'sin determinar', 26)}"
        nombre = next(iter(h.hostnames), "")
        etiqueta = h.fabricante or ""
        if nombre:
            etiqueta = f"{nombre}" + (f" · {etiqueta}" if etiqueta else "")
        estilo_ip = "lan" if h.es_local else "wan"
        conf = {"alta": "[conf_alta]alta[/]", "media": "[conf_media]media[/]"}.get(
            h.confianza, "[conf_baja]baja[/]") if h.so else "[dim]—[/]"

        t.add_row(
            f"[{estilo_ip}]{h.ip}[/]",
            so,
            conf,
            theme.esc(truncar(etiqueta, 24)) or "[dim]—[/]",
            h.rol,
            formatear_bytes(h.bytes_enviados + h.bytes_recibidos),
        )
    console.print(t)
    if len(perfiles) > 25:
        console.print(f"  [dim_text]… y {len(perfiles) - 25} equipos mas.[/]")
    console.print()

    # ── Conversaciones principales ────────────────────
    conversaciones = analisis.top_conversaciones(10)
    if conversaciones:
        maximo = conversaciones[0].bytes or 1
        t2 = theme.tabla("Quien habla con quien")
        t2.add_column("Conversacion", max_width=44)
        t2.add_column("Volumen", justify="right", width=10)
        t2.add_column("", width=26)
        t2.add_column("Servicios", max_width=22)

        for c in conversaciones:
            servicios = ", ".join(sorted(
                services.servicio(p) for p in sorted(c.puertos)
                if not services.es_efimero(p))[:3]) or "—"
            t2.add_row(
                f"{c.a} [separador]↔[/] {c.b}",
                formatear_bytes(c.bytes),
                theme.barra(c.bytes, maximo, 22),
                truncar(servicios, 20),
            )
        console.print(t2)
        console.print()

    # ── Salidas a Internet sin cifrar ─────────────────
    externos_contactados = [h for h in hosts.values() if not h.es_local]
    if externos_contactados:
        t3 = theme.tabla("Destinos en Internet")
        t3.add_column("IP", style="wan", no_wrap=True)
        t3.add_column("Dominio asociado", max_width=32)
        t3.add_column("Puertos", max_width=22)
        t3.add_column("Geo", width=10)
        t3.add_column("Recibido", justify="right", width=10)

        for h in sorted(externos_contactados,
                        key=lambda x: -(x.bytes_enviados + x.bytes_recibidos))[:12]:
            dominio = next(iter(sorted(h.dominios)), "")
            puertos = ", ".join(
                f"{p}/{services.servicio(p)}" for p in sorted(h.puertos_servidos)[:3]
            ) or "—"
            t3.add_row(h.ip, theme.esc(truncar(dominio, 30)) or "[dim]—[/]",
                       truncar(puertos, 20), _geolocalizar(h.ip) or "[dim]—[/]",
                       formatear_bytes(h.bytes_enviados))
        console.print(t3)
        console.print()

    # ── Hallazgos ─────────────────────────────────────
    hallazgos.extend(_detectar_conflictos(analisis))
    hallazgos.extend(_detectar_hosts_ruidosos(analisis))

    for f in hallazgos:
        console.print(theme.panel_hallazgo(
            f.titulo, f.severidad, f.descripcion, f.evidencia,
            f.recomendacion, f.confianza))

    if not hallazgos:
        console.print(theme.sin_hallazgos(
            "Sin anomalias en el inventario: ningun equipo se comporta de forma rara."))

    console.print(theme.pie_modulo())
    return hallazgos


def _detectar_conflictos(analisis) -> List[Finding]:
    """Una IP que parece dos sistemas a la vez merece una mirada."""
    hallazgos = []
    for h in analisis.hosts.values():
        if not h.conflicto_so:
            continue
        hallazgos.append(Finding(
            titulo=f"Indicios contradictorios de sistema operativo en {h.ip}",
            descripcion=(
                f"Se identifico como «{h.so}», pero {h.conflicto_so}. "
                f"Lo normal es que detras de esa IP haya varios equipos (NAT), "
                f"un proxy, o contenedores. Si no deberia haberlos, alguien esta "
                f"falseando su identidad."
            ),
            severidad=Severidad.INFO,
            confianza=Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"Fuentes consultadas: {', '.join(h.fuentes) or 'varias'}",
            recomendacion=(
                "Comprueba si esa IP corresponde a un router NAT o a un proxy. "
                "Si es un equipo unico, revisa por que su User-Agent no coincide "
                "con su pila TCP."
            ),
            patron="os_conflict",
            host=h.ip,
            host_so=h.so,
        ))
    return hallazgos


def _detectar_hosts_ruidosos(analisis) -> List[Finding]:
    """Un equipo que habla con demasiada gente distinta destaca solo."""
    hallazgos = []
    if len(analisis.hosts) < 4:
        return hallazgos

    destinos = {}
    for (a, b) in analisis.conversaciones:
        destinos.setdefault(a, set()).add(b)
        destinos.setdefault(b, set()).add(a)

    total_hosts = len(analisis.hosts)
    for ip, contactos in destinos.items():
        perfil = analisis.hosts.get(ip)
        if not perfil or not perfil.es_local:
            continue
        # Habla con mas de la mitad de la red y con al menos 8 equipos.
        if len(contactos) >= max(8, total_hosts * 0.5):
            hallazgos.append(Finding(
                titulo=f"{ip} habla con casi toda la red ({len(contactos)} equipos)",
                descripcion=(
                    f"Un equipo normal habla con el router, el DNS y unos pocos "
                    f"servidores. Este contacta con {len(contactos)} de los "
                    f"{total_hosts} equipos vistos. Eso encaja con un escaneo, un "
                    f"gusano propagandose, o con que sea un servidor central "
                    f"legitimo (DHCP, dominio, antivirus)."
                ),
                severidad=Severidad.MEDIO,
                confianza=Confianza.MEDIA,
                modulo=MODULE_ID,
                evidencia=f"{plural(len(contactos), 'equipo contactado', 'equipos contactados')}",
                recomendacion=(
                    "Confirma si esa IP es un servidor de infraestructura. Si no lo "
                    "es, aislala y revisa el modulo de heuristicas para ver si hay "
                    "escaneo de puertos."
                ),
                patron="portscan" if len(perfil.puertos_contactados) > 10 else "",
                host=ip,
                host_so=perfil.so,
            ))
    return hallazgos
