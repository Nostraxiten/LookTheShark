"""
modules/tls_analysis.py — Que hay detras del trafico cifrado.

TLS oculta el contenido, no la conversacion. De cada handshake se puede sacar:
a que dominio se conecta (SNI), que version se negocio, que suites se ofrecieron
y, sobre todo, el fingerprint JA3 del cliente: la huella de la implementacion
TLS que hizo la conexion. Un navegador, curl, un agente de Cobalt Strike y un
malware concreto tienen JA3 distintos aunque todos vayan al puerto 443.

El JA3 se calcula aqui, en Python nativo (core/tls.py). Antes se dependia de
que tshark lo generase, cosa que la mayoria de compilaciones no hace, asi que
en la practica este modulo nunca daba resultados.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from typing import Dict, List

from rich.console import Console

from core import tls as tlsmod
from modules import (Confianza, Finding, Severidad, es_ip_privada,
                     formatear_hora, plural, truncar)
from ui import theme

MODULE_NUM = 6
MODULE_NAME = "TLS y certificados"
MODULE_ID = "tls"
MODULE_DESC = "A donde va el trafico cifrado y que cliente lo genera (JA3)"

_JA3_DB: Dict[str, dict] = {}
_JA3_CARGADA = False


def _cargar_ja3() -> Dict[str, dict]:
    global _JA3_DB, _JA3_CARGADA
    if _JA3_CARGADA:
        return _JA3_DB
    _JA3_CARGADA = True
    ruta = os.path.join(os.path.dirname(__file__), "..", "data", "ja3_fingerprints.json")
    try:
        with open(ruta, "r", encoding="utf-8") as fh:
            _JA3_DB = json.load(fh).get("fingerprints", {})
    except (OSError, ValueError):
        _JA3_DB = {}
    return _JA3_DB


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    sesiones = analisis.tls
    if not sesiones:
        console.print("  [dim_text]No se observaron handshakes TLS en la captura.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    db = _cargar_ja3()
    snis = Counter(s.sni for s in sesiones if s.sni)
    versiones = Counter(s.version_servidor or s.version_cliente for s in sesiones)

    console.print(theme.tabla_clave_valor([
        ("Handshakes TLS", f"[valor]{len(sesiones)}[/]"),
        ("Dominios distintos (SNI)", f"[valor]{len(snis)}[/]"),
        ("Versiones negociadas", ", ".join(f"{v} ({c})" for v, c in versiones.most_common(4))),
        ("Sin SNI", f"[valor]{sum(1 for s in sesiones if not s.sni)}[/]"
                    "  [dim_text](conexion directa por IP)[/]"),
    ]))
    console.print()

    # ── A donde van ───────────────────────────────────
    t = theme.tabla("Destinos cifrados")
    t.add_column("Dominio (SNI)", style="bright_cyan", max_width=38)
    t.add_column("IP", max_width=16)
    t.add_column("Version", width=9)
    t.add_column("Conex.", justify="right", width=7)
    t.add_column("Pedido por", max_width=20)

    por_destino = defaultdict(list)
    for s in sesiones:
        por_destino[(s.sni or s.servidor_ip, s.servidor_ip)].append(s)

    for (destino, ip), lista in sorted(por_destino.items(), key=lambda x: -len(x[1]))[:15]:
        clientes = sorted({x.cliente_ip for x in lista})
        version = lista[0].version_servidor or lista[0].version_cliente or "?"
        estilo = "sev_medio" if version in ("SSL 3.0", "TLS 1.0", "TLS 1.1") else "white"
        t.add_row(theme.esc(truncar(destino, 36)), ip, f"[{estilo}]{version}[/]",
                  str(len(lista)), truncar(", ".join(clientes[:2]), 18))
    console.print(t)
    console.print()

    # ── Fingerprints JA3 ──────────────────────────────
    por_ja3 = defaultdict(list)
    for s in sesiones:
        if s.ja3:
            por_ja3[s.ja3].append(s)

    if por_ja3:
        t2 = theme.tabla("Clientes TLS identificados (JA3)")
        t2.add_column("JA3", style="dim", width=34)
        t2.add_column("Cliente reconocido", max_width=28)
        t2.add_column("Riesgo", width=9)
        t2.add_column("Usado por", max_width=18)
        t2.add_column("Conex.", justify="right", width=7)

        for ja3, lista in sorted(por_ja3.items(), key=lambda x: -len(x[1]))[:12]:
            info = db.get(ja3, {})
            cliente = info.get("client", "no catalogado")
            riesgo = info.get("risk", "unknown")
            estilo = {"high": "sev_critico", "medium": "sev_medio",
                      "low": "dim_text", "none": "exito"}.get(riesgo, "dim_text")
            etiqueta = {"high": "alto", "medium": "medio", "low": "bajo",
                        "none": "conocido"}.get(riesgo, "—")
            origenes = sorted({x.cliente_ip for x in lista})
            t2.add_row(ja3, theme.esc(truncar(cliente, 26)), f"[{estilo}]{etiqueta}[/]",
                       truncar(", ".join(origenes[:2]), 16), str(len(lista)))
        console.print(t2)
        console.print()
        console.print(theme.caja_explicativa(
            "El JA3 es la huella de COMO negocia TLS un programa, no de a donde se "
            "conecta. Dos conexiones al mismo sitio con JA3 distintos significan "
            "dos programas distintos. Un JA3 de herramienta ofensiva saliendo de un "
            "equipo de usuario es una senal muy fuerte, aunque el destino parezca "
            "normal.",
            "Como se lee un JA3"))
        console.print()

    # ── Certificados ──────────────────────────────────
    con_cert = [s for s in sesiones if s.certificados]
    if con_cert:
        t3 = theme.tabla("Certificados presentados")
        t3.add_column("Servidor", style="bright_cyan", max_width=26)
        t3.add_column("Comun (CN)", max_width=26)
        t3.add_column("Emisor", max_width=24)
        t3.add_column("Estado", max_width=18)

        for s in con_cert[:12]:
            cert = s.certificados[0]
            estado = []
            if cert.autofirmado:
                estado.append("[sev_medio]autofirmado[/]")
            if cert.caducado:
                estado.append("[sev_alto]caducado[/]")
            if not estado:
                estado.append("[exito]correcto[/]")
            t3.add_row(theme.esc(truncar(s.sni or s.servidor_ip, 24)),
                       theme.esc(truncar(cert.subject_cn or "—", 24)),
                       theme.esc(truncar(cert.issuer_cn or "—", 22)),
                       " ".join(estado))
        console.print(t3)
        console.print()

    # ── Hallazgos ─────────────────────────────────────
    hallazgos.extend(_versiones_obsoletas(analisis, sesiones))
    hallazgos.extend(_ja3_peligrosos(analisis, por_ja3, db))
    hallazgos.extend(_ciphers_debiles(analisis, sesiones))
    hallazgos.extend(_certificados_problematicos(analisis, con_cert))
    hallazgos.extend(_sin_sni(analisis, sesiones))

    for f in hallazgos:
        console.print(theme.panel_hallazgo(
            f.titulo, f.severidad, f.descripcion, f.evidencia,
            f.recomendacion, f.confianza))

    if not hallazgos:
        console.print(theme.sin_hallazgos(
            "TLS sin anomalias: versiones modernas y clientes reconocidos."))

    console.print(theme.pie_modulo())
    return hallazgos


def _versiones_obsoletas(analisis, sesiones) -> List[Finding]:
    hallazgos = []
    afectadas = [s for s in sesiones
                 if (s.version_servidor or s.version_cliente) in
                 ("SSL 3.0", "TLS 1.0", "TLS 1.1")]
    if not afectadas:
        return hallazgos

    por_version = defaultdict(list)
    for s in afectadas:
        por_version[s.version_servidor or s.version_cliente].append(s)

    for version, lista in por_version.items():
        destinos = sorted({s.sni or s.servidor_ip for s in lista})[:5]
        hallazgos.append(Finding(
            titulo=f"Conexiones negociando {version}",
            descripcion=(
                f"{version} esta oficialmente obsoleto y tiene ataques practicos "
                f"publicados (POODLE, BEAST, downgrade). Que el servidor lo acepte "
                f"significa que un atacante en el camino puede forzar esa version y "
                f"atacar el cifrado."
            ),
            severidad=Severidad.MEDIO if version != "SSL 3.0" else Severidad.ALTO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"{plural(len(lista), 'conexion', 'conexiones')} hacia "
                      f"{', '.join(destinos)}",
            recomendacion=(
                "Configura los servidores para aceptar solo TLS 1.2 y 1.3, y "
                "actualiza los clientes que aun no los soporten."
            ),
            patron="tls_downgrade",
            host=lista[0].cliente_ip,
            host_so=analisis.so_de(lista[0].cliente_ip),
        ))
    return hallazgos


def _ja3_peligrosos(analisis, por_ja3, db) -> List[Finding]:
    hallazgos = []
    for ja3, lista in por_ja3.items():
        info = db.get(ja3)
        if not info or info.get("risk") not in ("high", "medium"):
            continue
        cliente = info.get("client", "desconocido")
        categoria = info.get("category", "")
        origenes = sorted({s.cliente_ip for s in lista})
        destinos = sorted({s.sni or s.servidor_ip for s in lista})[:4]
        alto = info["risk"] == "high"

        hallazgos.append(Finding(
            titulo=f"Cliente TLS catalogado como {categoria or 'sospechoso'}: {cliente}",
            descripcion=(
                f"El fingerprint JA3 de estas conexiones coincide con {cliente}"
                + (f", clasificado como {categoria}" if categoria else "") + ". "
                + ("Los marcos de C2 y el malware tienen pilas TLS propias con "
                   "huellas muy reconocibles: esta es una de ellas. "
                   if alto else
                   "Es una herramienta legitima, pero verla salir de un equipo de "
                   "usuario en vez de un servidor merece explicacion. ")
                + f"Salio de {', '.join(origenes)} hacia {', '.join(destinos)}."
            ),
            severidad=Severidad.CRITICO if alto else Severidad.MEDIO,
            confianza=Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"JA3 {ja3} · {plural(len(lista), 'conexion', 'conexiones')} "
                      f"desde {', '.join(origenes[:3])}",
            recomendacion=(
                "Identifica el proceso que abre esas conexiones en el equipo de "
                "origen. Cruza el JA3 con tu inventario de software aprobado: si "
                "ningun programa autorizado lo genera, el equipo esta comprometido."
                if alto else
                "Confirma que hay un motivo operativo para esa herramienta en ese "
                "equipo."
            ),
            patron="unusual_ja3" if alto else "tool_ja3",
            host=origenes[0],
            host_so=analisis.so_de(origenes[0]),
            timestamp=formatear_hora(lista[0].ts),
            datos={"ja3": ja3, "cliente": cliente},
        ))
    return hallazgos


def _ciphers_debiles(analisis, sesiones) -> List[Finding]:
    hallazgos = []
    con_debiles = [s for s in sesiones if s.ciphers_debiles]
    if not con_debiles:
        return hallazgos

    suites = Counter()
    for s in con_debiles:
        suites.update(s.ciphers_debiles)

    ejemplo = con_debiles[0]
    hallazgos.append(Finding(
        titulo=f"Se ofrecen suites de cifrado debiles "
               f"({plural(len(suites), 'suite distinta', 'suites distintas')})",
        descripcion=(
            "Algunos clientes siguen ofreciendo suites con RC4, 3DES o CBC sin "
            "AEAD. Si el servidor acepta una de ellas, el cifrado que protege esa "
            "conexion es mucho mas debil de lo que aparenta el candado del navegador."
        ),
        severidad=Severidad.MEDIO,
        confianza=Confianza.ALTA,
        modulo=MODULE_ID,
        evidencia=", ".join(f"{n} ({c}×)" for n, c in suites.most_common(4)),
        recomendacion=(
            "Restringe la lista de suites en los servidores a las AEAD modernas "
            "(AES-GCM y ChaCha20-Poly1305) y actualiza los clientes antiguos."
        ),
        patron="weak_cipher",
        host=ejemplo.cliente_ip,
        host_so=analisis.so_de(ejemplo.cliente_ip),
    ))
    return hallazgos


def _certificados_problematicos(analisis, sesiones) -> List[Finding]:
    hallazgos = []
    for s in sesiones:
        cert = s.certificados[0]
        problemas = []
        if cert.autofirmado:
            problemas.append("esta autofirmado (nadie ajeno respalda su identidad)")
        if cert.caducado:
            problemas.append("esta caducado")
        if cert.dias_validez > 825:
            problemas.append(f"tiene una validez de {cert.dias_validez} dias, "
                             f"muy por encima del maximo aceptado por los navegadores")
        if not problemas:
            continue

        externo = not es_ip_privada(s.servidor_ip)
        hallazgos.append(Finding(
            titulo=f"Certificado problematico en {s.sni or s.servidor_ip}",
            descripcion=(
                f"El certificado presentado {' y '.join(problemas)}. "
                + ("En un servidor interno puede ser normal. " if not externo else
                   "En un servidor de Internet esto no deberia pasar: puede ser un "
                   "servidor de control improvisado o una interceptacion del trafico. ")
            ),
            severidad=Severidad.MEDIO if not externo else Severidad.ALTO,
            confianza=Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"CN={cert.subject_cn or '?'} · emisor={cert.issuer_cn or '?'} · "
                      f"{s.cliente_ip} → {s.servidor_ip}:{s.servidor_puerto}",
            recomendacion=(
                "Verifica a quien pertenece realmente ese servidor. Si el cliente "
                "acepto el certificado sin avisar, revisa si hay una CA propia "
                "instalada en el equipo que no deberia estar."
            ),
            patron="suspicious_cert",
            host=s.cliente_ip,
            host_so=analisis.so_de(s.cliente_ip),
        ))
    return hallazgos[:6]


def _sin_sni(analisis, sesiones) -> List[Finding]:
    """TLS a una IP sin decir a que dominio: raro en trafico normal."""
    sin = [s for s in sesiones if not s.sni and not es_ip_privada(s.servidor_ip)]
    if len(sin) < 3:
        return []

    destinos = Counter(s.servidor_ip for s in sin)
    origenes = sorted({s.cliente_ip for s in sin})
    return [Finding(
        titulo=f"Conexiones TLS a Internet sin indicar dominio ({len(sin)})",
        descripcion=(
            "Todo cliente moderno manda el SNI para que el servidor sepa que "
            "certificado presentar. Conectarse directamente a una IP sin SNI es lo "
            "que hace un agente que ya sabe a donde va y no quiere que el nombre "
            "aparezca en los registros del proxy."
        ),
        severidad=Severidad.MEDIO,
        confianza=Confianza.BAJA,
        modulo=MODULE_ID,
        evidencia="Destinos: " + ", ".join(f"{ip} ({c}×)"
                                           for ip, c in destinos.most_common(4)),
        recomendacion=(
            "Comprueba a quien pertenecen esas IPs y que proceso las contacta. "
            "Muchas aplicaciones moviles legitimas tambien lo hacen, asi que "
            "confirma antes de actuar."
        ),
        patron="no_sni",
        host=origenes[0] if origenes else "",
        host_so=analisis.so_de(origenes[0]) if origenes else "",
    )]
