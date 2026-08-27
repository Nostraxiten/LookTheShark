"""
modules/dns_analysis.py — Que nombres se resolvieron y cuales huelen mal.

DNS es el mejor resumen de lo que hizo un equipo: aunque el trafico vaya
cifrado, los nombres que pidio no mienten. Aqui se ven los dominios, quien los
pidio, si alguno tiene pinta de generado por algoritmo (DGA), y si alguien esta
usando DNS como tunel para sacar datos.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import List

from rich.console import Console

from modules import (Confianza, Finding, Severidad, formatear_hora, plural,
                     truncar)
from ui import theme

MODULE_NUM = 3
MODULE_NAME = "DNS"
MODULE_ID = "dns"
MODULE_DESC = "Que nombres pidio cada equipo y cuales no cuadran"

UMBRAL_ENTROPIA = 3.6
LARGO_TUNEL = 45          # caracteres en una sola etiqueta
QPS_TUNEL = 8.0           # consultas por segundo hacia el mismo servidor
MIN_CONSULTAS_TUNEL = 25

# TLD baratos y muy usados en campanas de malware y phishing.
TLD_RIESGO = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "link",
    "work", "loan", "download", "bid", "win", "review", "date", "stream",
    "racing", "party", "science", "men", "zip", "mov", "rest", "cyou",
}

# Dominios cuya entropia alta es normal (hashes de CDN, UUIDs de servicios).
DOMINIOS_ENTROPIA_NORMAL = re.compile(
    r"(?:cloudfront\.net|akamai(?:edge|hd)?\.net|azureedge\.net|fastly\.net|"
    r"cdn\.|edgekey\.net|amazonaws\.com|googleusercontent\.com|1e100\.net|"
    r"gvt\d\.com|windowsupdate\.com|office365\.com|icloud\.com|"
    r"digicert\.com|sectigo\.com|letsencrypt\.org|ocsp\.|crl\.)", re.I)


def entropia(texto: str) -> float:
    """Entropia de Shannon en bits por caracter."""
    if not texto:
        return 0.0
    frecuencias = Counter(texto.lower())
    total = len(texto)
    return -sum((c / total) * math.log2(c / total) for c in frecuencias.values())


def _dominio_registrable(nombre: str) -> str:
    """'a.b.ejemplo.co.uk' -> 'ejemplo.co.uk' (aproximacion sin lista PSL)."""
    partes = nombre.rstrip(".").split(".")
    if len(partes) <= 2:
        return ".".join(partes)
    # TLD de segundo nivel mas comunes.
    if partes[-2] in ("co", "com", "org", "net", "gov", "edu", "ac") and len(partes[-1]) == 2:
        return ".".join(partes[-3:])
    return ".".join(partes[-2:])


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    eventos = analisis.dns
    if not eventos:
        console.print("  [dim_text]No hay trafico DNS en la captura.[/]")
        console.print("  [dim_text]Si el equipo usa DoH/DoT (DNS cifrado) las "
                      "consultas viajan dentro de TLS y no se ven aqui.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    consultas = [e for e in eventos if not e.es_respuesta]
    respuestas = [e for e in eventos if e.es_respuesta]
    dominios = Counter(e.nombre for e in consultas if e.nombre)
    fallidas = [e for e in respuestas if e.rcode not in ("NOERROR",)]

    console.print(theme.tabla_clave_valor([
        ("Consultas", f"[valor]{len(consultas)}[/]"),
        ("Respuestas", f"[valor]{len(respuestas)}[/]"),
        ("Dominios unicos", f"[valor]{len(dominios)}[/]"),
        ("Resoluciones fallidas", f"[valor]{len(fallidas)}[/]"
         + (f"  [dim_text]({len(fallidas)/max(1,len(respuestas))*100:.0f}% del total)[/]"
            if respuestas else "")),
    ]))
    console.print()

    # ── Dominios mas consultados ──────────────────────
    t = theme.tabla("Dominios mas consultados")
    t.add_column("Dominio", style="bright_cyan", max_width=46)
    t.add_column("Veces", justify="right", width=7)
    t.add_column("Entropia", justify="right", width=9)
    t.add_column("Pedido por", max_width=18)
    t.add_column("Resuelve a", max_width=20)

    quien_pide = defaultdict(set)
    for e in consultas:
        if e.nombre:
            quien_pide[e.nombre].add(e.src)
    resuelve_a = {}
    for e in respuestas:
        if e.nombre and e.respuestas:
            resuelve_a.setdefault(e.nombre, e.respuestas[0])

    for dominio, cuenta in dominios.most_common(15):
        ent = entropia(_etiqueta_significativa(dominio))
        estilo_ent = "sev_medio" if ent >= UMBRAL_ENTROPIA else "dim_text"
        pedidores = sorted(quien_pide.get(dominio, set()))
        t.add_row(
            theme.esc(truncar(dominio, 44)),
            str(cuenta),
            f"[{estilo_ent}]{ent:.2f}[/]",
            truncar(", ".join(pedidores[:2]), 16) or "—",
            theme.esc(truncar(resuelve_a.get(dominio, ""), 18)) or "[dim]—[/]",
        )
    console.print(t)
    console.print()

    # ── Que pidio cada equipo ─────────────────────────
    por_host = defaultdict(list)
    for e in consultas:
        if e.nombre:
            por_host[e.src].append(e.nombre)

    if len(por_host) > 1:
        t2 = theme.tabla("Que busco cada equipo")
        t2.add_column("Equipo", style="bold bright_cyan", no_wrap=True)
        t2.add_column("Sistema", max_width=20)
        t2.add_column("Consultas", justify="right", width=10)
        t2.add_column("Dominios distintos", justify="right", width=18)
        t2.add_column("Ejemplo", max_width=28)

        for ip, nombres in sorted(por_host.items(), key=lambda x: -len(x[1]))[:10]:
            perfil = analisis.hosts.get(ip)
            so = f"{theme.icono_so(perfil.familia)} {perfil.so}" if perfil and perfil.so else "—"
            unicos = sorted(set(nombres))
            t2.add_row(ip, truncar(so, 18), str(len(nombres)), str(len(unicos)),
                       theme.esc(truncar(unicos[0] if unicos else "", 26)))
        console.print(t2)
        console.print()

    # ── Hallazgos ─────────────────────────────────────
    hallazgos.extend(_detectar_dga(analisis, consultas))
    hallazgos.extend(_detectar_tunel(analisis, consultas))
    hallazgos.extend(_detectar_nxdomain_masivo(analisis, respuestas))
    hallazgos.extend(_detectar_tld_riesgo(analisis, consultas))
    hallazgos.extend(_detectar_transferencia_zona(analisis, consultas))

    for f in hallazgos:
        console.print(theme.panel_hallazgo(
            f.titulo, f.severidad, f.descripcion, f.evidencia,
            f.recomendacion, f.confianza))

    if not hallazgos:
        console.print(theme.sin_hallazgos("Trafico DNS sin patrones anomalos."))

    console.print(theme.pie_modulo())
    return hallazgos


def _etiqueta_significativa(dominio: str) -> str:
    """La parte del nombre que aporta informacion (sin TLD ni 'www')."""
    partes = dominio.rstrip(".").split(".")
    if len(partes) <= 1:
        return dominio
    utiles = [p for p in partes[:-1] if p.lower() != "www"]
    return ".".join(utiles) or partes[0]


def _detectar_dga(analisis, consultas) -> List[Finding]:
    """Dominios con pinta de generados por algoritmo."""
    hallazgos = []
    candidatos = {}

    for e in consultas:
        nombre = e.nombre
        if not nombre or DOMINIOS_ENTROPIA_NORMAL.search(nombre):
            continue
        registrable = _dominio_registrable(nombre)
        etiqueta = registrable.split(".")[0]
        if len(etiqueta) < 8 or registrable in candidatos:
            continue

        ent = entropia(etiqueta)
        if ent < UMBRAL_ENTROPIA:
            continue
        # Sin vocales o con muchas consonantes seguidas: senal fuerte de DGA.
        vocales = sum(1 for c in etiqueta.lower() if c in "aeiou")
        ratio_vocales = vocales / len(etiqueta)
        digitos = sum(1 for c in etiqueta if c.isdigit()) / len(etiqueta)
        if ratio_vocales > 0.38 and digitos < 0.2:
            continue   # se parece demasiado a una palabra

        candidatos[registrable] = (e, ent, ratio_vocales)

    for registrable, (e, ent, ratio) in list(candidatos.items())[:10]:
        hallazgos.append(Finding(
            titulo=f"Dominio con aspecto generado por algoritmo: {registrable}",
            descripcion=(
                f"Entropia {ent:.2f} (umbral {UMBRAL_ENTROPIA}) y solo un "
                f"{ratio*100:.0f}% de vocales. Los dominios que registran las "
                f"personas se pronuncian; los que genera un algoritmo, no. El "
                f"malware moderno usa dominios generados a diario para que "
                f"bloquear uno no sirva de nada."
            ),
            severidad=Severidad.MEDIO,
            confianza=Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"{e.nombre} consultado por {e.src} a las {formatear_hora(e.ts)}",
            recomendacion=(
                "Comprueba la fecha de registro del dominio (un dominio de hace "
                "dos dias es mala senal) y busca el proceso que lo resolvio en el "
                "equipo de origen."
            ),
            patron="dga",
            host=e.src,
            host_so=analisis.so_de(e.src),
            timestamp=formatear_hora(e.ts),
        ))
    return hallazgos


def _detectar_tunel(analisis, consultas) -> List[Finding]:
    """DNS usado como canal de datos en vez de para resolver nombres."""
    hallazgos = []

    # 1. Etiquetas largas: los datos van codificados en el subdominio.
    vistos = set()
    for e in consultas:
        nombre = e.nombre
        if not nombre:
            continue
        etiquetas = nombre.split(".")
        larga = max(etiquetas, key=len) if etiquetas else ""
        if len(larga) <= LARGO_TUNEL:
            continue
        base = _dominio_registrable(nombre)
        if base in vistos:
            continue
        vistos.add(base)

        hallazgos.append(Finding(
            titulo=f"Posible tunel DNS hacia {base}",
            descripcion=(
                f"Una de las etiquetas del nombre mide {len(larga)} caracteres. "
                f"Los nombres de dominio reales rara vez pasan de 20. Una etiqueta "
                f"asi de larga suele ser un bloque de datos codificado en Base32 o "
                f"Base64: es como se saca informacion de una red que solo deja "
                f"salir DNS."
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.ALTA if len(larga) > 55 else Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"{truncar(nombre, 90)} (desde {e.src})",
            recomendacion=(
                f"Bloquea el dominio {base} en el resolver y busca en el equipo "
                f"{e.src} el proceso que genera esas consultas. Considera limitar "
                f"el DNS saliente a tus propios resolvers."
            ),
            patron="dns_tunneling",
            host=e.src,
            host_so=analisis.so_de(e.src),
            timestamp=formatear_hora(e.ts),
        ))

    # 2. Volumen: muchisimas consultas al mismo dominio base.
    por_base = defaultdict(list)
    for e in consultas:
        if e.nombre:
            por_base[_dominio_registrable(e.nombre)].append(e)

    for base, lista in por_base.items():
        if len(lista) < MIN_CONSULTAS_TUNEL or base in vistos:
            continue
        subdominios = len({x.nombre for x in lista})
        if subdominios < len(lista) * 0.8:
            continue     # se repiten: es cache normal, no tunel

        tiempos = sorted(x.ts for x in lista if x.ts)
        span = (tiempos[-1] - tiempos[0]) if len(tiempos) >= 2 else 0
        qps = len(lista) / span if span > 0 else 0
        if span > 0 and qps < QPS_TUNEL:
            continue

        hallazgos.append(Finding(
            titulo=f"Volumen anomalo de subdominios bajo {base}",
            descripcion=(
                f"{len(lista)} consultas hacia {subdominios} subdominios distintos "
                f"de {base}" + (f" a {qps:.1f} consultas por segundo" if qps else "")
                + ". Que casi ninguna se repita significa que el nombre transporta "
                "datos, no que se este resolviendo un servicio."
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"{subdominios} subdominios unicos, "
                      f"ejemplo: {truncar(lista[0].nombre, 60)}",
            recomendacion=(
                f"Bloquea {base} y revisa el equipo {lista[0].src}. Un tunel DNS "
                f"activo suele significar que ya hay una via de salida abierta."
            ),
            patron="dns_tunneling",
            host=lista[0].src,
            host_so=analisis.so_de(lista[0].src),
        ))

    return hallazgos[:8]


def _detectar_nxdomain_masivo(analisis, respuestas) -> List[Finding]:
    """Muchos NXDOMAIN seguidos: malware buscando su servidor de control."""
    hallazgos = []
    fallidas = defaultdict(list)
    for e in respuestas:
        if e.rcode == "NXDOMAIN":
            fallidas[e.dst].append(e)

    for ip, lista in fallidas.items():
        total_de_ese_host = sum(1 for e in respuestas if e.dst == ip)
        if len(lista) < 15 or not total_de_ese_host:
            continue
        ratio = len(lista) / total_de_ese_host
        if ratio < 0.4:
            continue

        hallazgos.append(Finding(
            titulo=f"{ip} recibe muchas resoluciones fallidas ({len(lista)} NXDOMAIN)",
            descripcion=(
                f"El {ratio*100:.0f}% de las respuestas DNS que recibe este equipo "
                f"son 'ese dominio no existe'. Un equipo normal casi siempre acierta. "
                f"Este patron es tipico del malware con generacion de dominios: "
                f"prueba nombres hasta que uno responde."
            ),
            severidad=Severidad.MEDIO,
            confianza=Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"{len(lista)} NXDOMAIN de {total_de_ese_host} respuestas · "
                      f"ejemplo: {truncar(lista[0].nombre, 50)}",
            recomendacion=(
                "Lista los dominios fallidos: si no se parecen a nada humano, "
                "busca el proceso responsable en el equipo."
            ),
            patron="dga",
            host=ip,
            host_so=analisis.so_de(ip),
        ))
    return hallazgos


def _detectar_tld_riesgo(analisis, consultas) -> List[Finding]:
    """TLD gratuitos o baratos muy usados en campanas maliciosas."""
    hallazgos = []
    por_tld = defaultdict(set)
    ejemplo = {}
    for e in consultas:
        if not e.nombre or "." not in e.nombre:
            continue
        tld = e.nombre.rstrip(".").rsplit(".", 1)[-1].lower()
        if tld in TLD_RIESGO:
            por_tld[tld].add(_dominio_registrable(e.nombre))
            ejemplo.setdefault(tld, e)

    for tld, dominios in por_tld.items():
        e = ejemplo[tld]
        hallazgos.append(Finding(
            titulo=f"Consultas a dominios .{tld} ({len(dominios)} distintos)",
            descripcion=(
                f"El TLD .{tld} es gratuito o muy barato y sin apenas verificacion, "
                f"por eso concentra una proporcion desmesurada de phishing y "
                f"servidores de control. No es prueba de nada por si solo: hay "
                f"sitios legitimos usandolo."
            ),
            severidad=Severidad.BAJO,
            confianza=Confianza.BAJA,
            modulo=MODULE_ID,
            evidencia=", ".join(sorted(dominios)[:5]),
            recomendacion=(
                f"Comprueba si tu organizacion tiene motivo para visitar dominios "
                f".{tld}. Si no, plantea bloquear el TLD entero en el resolver."
            ),
            patron="suspicious_tld",
            host=e.src,
            host_so=analisis.so_de(e.src),
        ))
    return hallazgos[:4]


def _detectar_transferencia_zona(analisis, consultas) -> List[Finding]:
    """AXFR/IXFR: alguien intentando descargarse la zona DNS entera."""
    hallazgos = []
    for e in consultas:
        if e.tipo not in ("AXFR", "IXFR"):
            continue
        hallazgos.append(Finding(
            titulo=f"Intento de transferencia de zona DNS ({e.tipo})",
            descripcion=(
                f"Una consulta {e.tipo} pide al servidor la zona DNS completa: "
                f"todos los nombres internos, servidores y subredes de golpe. Es "
                f"uno de los primeros movimientos de un reconocimiento y ningun "
                f"cliente normal la lanza."
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"{e.src} → {e.dst} pidiendo {e.tipo} de {e.nombre}",
            recomendacion=(
                "Restringe las transferencias de zona a las IPs de tus servidores "
                "secundarios en la configuracion del DNS."
            ),
            patron="zone_transfer",
            host=e.src,
            host_so=analisis.so_de(e.src),
            timestamp=formatear_hora(e.ts),
        ))
    return hallazgos[:3]
