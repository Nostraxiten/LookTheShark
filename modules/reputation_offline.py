"""
modules/reputation_offline.py — Cruce contra listas locales.

Nunca consulta APIs externas. Motivo: si estas analizando una captura de un
incidente, consultar una IP en un servicio online avisa al atacante de que le
han visto, y ademas manda datos del cliente a un tercero. Todo el cruce se hace
contra ficheros que el usuario deja en data/reputation_feeds/.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections import defaultdict
from typing import Dict, List, Set

from rich.console import Console

from modules import (Confianza, Finding, Severidad, es_ip_privada,
                     formatear_hora, plural, truncar)
from ui import theme

MODULE_NUM = 12
MODULE_NAME = "Reputacion offline"
MODULE_ID = "reputation"
MODULE_DESC = "Cruce contra listas negras locales, sin consultar nada online"

_FEEDS = {"ips": {}, "redes": [], "dominios": {}, "hashes": {}}
_CARGADO = False

_RE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_RED = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
_RE_HASH = re.compile(r"^[a-fA-F0-9]{32,64}$")


def _cargar_feeds() -> dict:
    """Lee todos los .txt/.csv de data/reputation_feeds/.

    Formato admitido por linea:
        1.2.3.4
        1.2.3.0/24
        dominio.malo.tld
        <sha256>
        valor[,;<tab>]etiqueta          (la etiqueta se muestra en el informe)
    """
    global _CARGADO
    if _CARGADO:
        return _FEEDS
    _CARGADO = True

    carpeta = os.path.join(os.path.dirname(__file__), "..", "data", "reputation_feeds")
    if not os.path.isdir(carpeta):
        return _FEEDS

    for nombre in sorted(os.listdir(carpeta)):
        if not nombre.lower().endswith((".txt", ".csv", ".list", ".ioc")):
            continue
        etiqueta_fichero = os.path.splitext(nombre)[0]
        try:
            with open(os.path.join(carpeta, nombre), "r", encoding="utf-8",
                      errors="replace") as fh:
                for linea in fh:
                    linea = linea.strip()
                    if not linea or linea[0] in "#;":
                        continue
                    partes = re.split(r"[,;\t]", linea, maxsplit=1)
                    valor = partes[0].strip().strip('"')
                    etiqueta = (partes[1].strip() if len(partes) > 1
                                else etiqueta_fichero)
                    if not valor:
                        continue

                    if _RE_RED.match(valor):
                        try:
                            _FEEDS["redes"].append(
                                (ipaddress.ip_network(valor, strict=False), etiqueta))
                        except ValueError:
                            pass
                    elif _RE_IP.match(valor):
                        _FEEDS["ips"][valor] = etiqueta
                    elif _RE_HASH.match(valor):
                        _FEEDS["hashes"][valor.lower()] = etiqueta
                    elif "." in valor:
                        _FEEDS["dominios"][valor.lower().lstrip("*.").rstrip(".")] = etiqueta
        except OSError:
            continue
    return _FEEDS


def _en_red_negra(ip: str, redes) -> str:
    if not redes:
        return ""
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for red, etiqueta in redes:
        if direccion.version == red.version and direccion in red:
            return etiqueta
    return ""


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    feeds = _cargar_feeds()
    total_iocs = (len(feeds["ips"]) + len(feeds["redes"])
                  + len(feeds["dominios"]) + len(feeds["hashes"]))

    if not total_iocs:
        console.print("  [dim_text]No hay listas locales en "
                      "[/][dato]data/reputation_feeds/[/][dim_text].[/]")
        console.print("  [dim_text]Deja ahi cualquier .txt con IPs, redes CIDR, "
                      "dominios o hashes (uno por linea) y este modulo los cruzara "
                      "con la captura. Hay instrucciones en el README de esa "
                      "carpeta.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    console.print(theme.tabla_clave_valor([
        ("Indicadores cargados", f"[valor]{total_iocs:,}[/]"),
        ("  IPs", f"{len(feeds['ips']):,}"),
        ("  Redes", f"{len(feeds['redes']):,}"),
        ("  Dominios", f"{len(feeds['dominios']):,}"),
        ("  Hashes", f"{len(feeds['hashes']):,}"),
    ]))
    console.print()

    coincidencias = []

    # ── IPs y redes ───────────────────────────────────
    for ip, perfil in analisis.hosts.items():
        if es_ip_privada(ip):
            continue
        etiqueta = feeds["ips"].get(ip) or _en_red_negra(ip, feeds["redes"])
        if not etiqueta:
            continue
        contactos = sorted({
            otro for (a, b) in analisis.conversaciones
            for otro in ((b,) if a == ip else (a,) if b == ip else ())
            if es_ip_privada(otro)
        })
        coincidencias.append({
            "tipo": "IP", "valor": ip, "etiqueta": etiqueta,
            "afectados": contactos,
            "bytes": perfil.bytes_enviados + perfil.bytes_recibidos,
        })

    # ── Dominios ──────────────────────────────────────
    vistos_dominio = {}
    for evento in analisis.dns:
        if evento.nombre:
            vistos_dominio.setdefault(evento.nombre.lower().rstrip("."), evento.src)
    for sesion in analisis.tls:
        if sesion.sni:
            vistos_dominio.setdefault(sesion.sni.lower(), sesion.cliente_ip)
    for tr in analisis.http:
        if tr.host:
            vistos_dominio.setdefault(tr.host.split(":")[0].lower(), tr.cliente_ip)

    for dominio, origen in vistos_dominio.items():
        etiqueta = feeds["dominios"].get(dominio)
        if not etiqueta:
            # Coincidencia por dominio padre: bloquear 'malo.tld' cubre sus subdominios.
            partes = dominio.split(".")
            for i in range(1, len(partes) - 1):
                etiqueta = feeds["dominios"].get(".".join(partes[i:]))
                if etiqueta:
                    break
        if etiqueta:
            coincidencias.append({
                "tipo": "Dominio", "valor": dominio, "etiqueta": etiqueta,
                "afectados": [origen], "bytes": 0,
            })

    # ── Hashes de ficheros ────────────────────────────
    for fichero in analisis.ficheros:
        for h in (fichero.sha256, fichero.md5):
            etiqueta = feeds["hashes"].get((h or "").lower())
            if etiqueta:
                coincidencias.append({
                    "tipo": "Hash", "valor": fichero.nombre, "etiqueta": etiqueta,
                    "afectados": [fichero.destino], "bytes": fichero.tamano,
                    "hash": h,
                })
                break

    if not coincidencias:
        console.print(theme.sin_hallazgos(
            "Ninguna IP, dominio ni fichero de la captura aparece en tus listas."))
        console.print("  [dim_text]Esto NO significa que sea limpio: significa que "
                      "no esta en las listas que tienes cargadas.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    console.print(f"  [sev_critico] {len(coincidencias)} coincidencias [/] "
                  f"con tus listas locales")
    console.print()

    t = theme.tabla("Indicadores encontrados en la captura")
    t.add_column("Tipo", width=9)
    t.add_column("Valor", style="bold bright_cyan", max_width=34)
    t.add_column("Lista / etiqueta", max_width=24)
    t.add_column("Equipos afectados", max_width=26)
    for c in coincidencias[:20]:
        t.add_row(c["tipo"], theme.esc(truncar(c["valor"], 32)),
                  theme.esc(truncar(c["etiqueta"], 22)),
                  truncar(", ".join(c["afectados"][:3]) or "—", 24))
    console.print(t)
    console.print()

    for c in coincidencias:
        afectados = c["afectados"]
        principal = afectados[0] if afectados else ""
        hallazgos.append(Finding(
            titulo=f"{c['tipo']} en lista negra: {truncar(c['valor'], 48)}",
            descripcion=(
                f"Aparece en tu lista «{c['etiqueta']}». Contacto con "
                f"{plural(len(afectados), 'equipo', 'equipos')} de la red"
                + (f": {', '.join(afectados[:4])}" if afectados else "") + ". "
                + "La fiabilidad de este hallazgo es exactamente la de la lista de "
                  "la que sale, asi que confirma el origen del indicador antes de "
                  "actuar sobre un equipo de produccion."
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=(f"{c['tipo']} {c['valor']}"
                       + (f" · SHA-256 {c.get('hash', '')[:24]}…" if c.get("hash") else "")
                       + (f" · {c['bytes']:,} bytes intercambiados" if c["bytes"] else "")),
            recomendacion=(
                f"Bloquea el indicador en el perimetro y revisa los equipos "
                f"{', '.join(afectados[:3]) or 'implicados'}: si contactaron con un "
                f"indicador conocido, hay que asumir compromiso hasta demostrar lo "
                f"contrario."
            ),
            patron="known_bad",
            host=principal,
            host_so=analisis.so_de(principal) if principal else "",
            datos={"tipo": c["tipo"], "valor": c["valor"], "lista": c["etiqueta"]},
        ))

    console.print(theme.pie_modulo())
    return hallazgos
