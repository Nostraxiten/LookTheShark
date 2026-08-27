"""
modules/http_analysis.py — Que pidio cada equipo por HTTP y que le devolvieron.

Este es el modulo que convierte una captura en algo que se lee. En vez de
paquetes, transacciones completas:

    GET  http://cdn.ejemplo.com/descargas/vacaciones.jpg
         200  image/jpeg  2.1 KB
         desde 192.168.1.50 (Windows 10/11) · Chrome 121

Con la atribucion de sistema operativo delante, porque saber QUIEN pidio algo
cambia por completo la lectura: no es lo mismo que un Windows de usuario baje
un .exe a que lo baje el servidor de actualizaciones.

Ademas marca lo que merece una segunda mirada: descargas de ejecutables,
errores 401/403 en rafaga (fuerza bruta), metodos raros (PUT/DELETE), rutas de
webshell conocidas, y peticiones lanzadas por herramientas y no por personas.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import List

from rich.console import Console

from core import fingerprint
from modules import (Confianza, Finding, Severidad, es_ip_privada,
                     formatear_bytes, formatear_hora, plural, truncar)
from ui import theme

MODULE_NUM = 4
MODULE_NAME = "HTTP"
MODULE_ID = "http"
MODULE_DESC = "Peticiones y respuestas reconstruidas, con quien las lanzo"

# Extensiones cuya descarga por HTTP merece atencion.
EXT_PELIGROSAS = {
    ".exe", ".dll", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jar", ".hta", ".wsf", ".apk", ".elf", ".so", ".iso", ".img", ".lnk",
    ".reg", ".chm", ".pif", ".com", ".cpl",
}

# Rutas que solo se piden si alguien esta buscando o usando una puerta trasera.
RUTAS_WEBSHELL = re.compile(
    r"/(?:c99|r57|b374k|wso|shell|cmd|backdoor|adminer|webshell|alfa|indoxploit)"
    r"[\w-]*\.(?:php|asp|aspx|jsp|jspx)\b", re.I)

RUTAS_SENSIBLES = re.compile(
    r"/(?:\.git/|\.env\b|\.svn/|wp-config\.php|web\.config|phpinfo\.php|"
    r"\.aws/credentials|\.ssh/id_|id_rsa|backup\.(?:sql|zip|tar)|"
    r"config\.(?:json|yml|yaml|php)|actuator/env|server-status|"
    r"admin/config|\.DS_Store|composer\.lock)", re.I)

RECORRIDO_RUTAS = re.compile(r"(?:\.\./|\.\.%2f|%2e%2e/|\.\.\\)", re.I)

INYECCION = re.compile(
    r"(?:'\s*or\s*'?1'?\s*=\s*'?1|union\s+select|<script[ >]|javascript:|"
    r"\bexec\s*\(|/etc/passwd|cmd\.exe|powershell\s+-e|base64_decode\s*\()", re.I)


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    transacciones = analisis.http
    if not transacciones:
        console.print("  [dim_text]No hay HTTP en claro en esta captura.[/]")
        if analisis.tls:
            console.print(f"  [dim_text]Si hay {len(analisis.tls)} sesiones TLS: "
                          f"el contenido va cifrado y solo se ve el dominio "
                          f"(modulo TLS).[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    # ── Resumen ───────────────────────────────────────
    metodos = Counter(t.metodo for t in transacciones)
    codigos = Counter(t.codigo for t in transacciones if t.codigo)
    hosts_web = Counter(t.host or t.servidor_ip for t in transacciones)
    volumen = sum(t.tamano_respuesta for t in transacciones)

    console.print(theme.tabla_clave_valor([
        ("Transacciones", f"[valor]{len(transacciones)}[/]"),
        ("Sitios contactados", f"[valor]{len(hosts_web)}[/]"),
        ("Metodos", ", ".join(f"{m} ({c})" for m, c in metodos.most_common(5))),
        ("Descargado", formatear_bytes(volumen)),
    ]))
    console.print()

    # ── Quien navega: perfil por equipo ───────────────
    por_host = analisis.http_por_host()
    t = theme.tabla("Quien hizo las peticiones")
    t.add_column("Equipo", style="bold bright_cyan", no_wrap=True)
    t.add_column("Sistema operativo", max_width=24)
    t.add_column("Cliente usado", max_width=26)
    t.add_column("Peticiones", justify="right", width=11)
    t.add_column("Descargado", justify="right", width=11)

    for ip, lista in sorted(por_host.items(), key=lambda x: -len(x[1]))[:12]:
        perfil = analisis.hosts.get(ip)
        so = f"{theme.icono_so(perfil.familia)} {perfil.so}" if perfil and perfil.so \
            else "[dim]sin determinar[/]"
        agentes = Counter()
        for tr in lista:
            if tr.user_agent:
                info = fingerprint.analizar_user_agent(tr.user_agent)
                agentes[info["cliente"] or "?"] += 1
        cliente = ", ".join(c for c, _ in agentes.most_common(2)) or "[dim]—[/]"
        t.add_row(ip, truncar(so, 22), theme.esc(truncar(cliente, 24)), str(len(lista)),
                  formatear_bytes(sum(x.tamano_respuesta for x in lista)))
    console.print(t)
    console.print()

    # ── Transcripcion de peticiones ───────────────────
    limite = int(config.get("http_max_mostradas", 25))
    console.print(f"  [titulo]Peticiones (las {min(limite, len(transacciones))} "
                  f"primeras de {len(transacciones)})[/]")
    console.print()

    for tr in transacciones[:limite]:
        perfil = analisis.hosts.get(tr.cliente_ip)
        so = perfil.so if perfil else ""
        agente = ""
        if tr.user_agent:
            info = fingerprint.analizar_user_agent(tr.user_agent)
            agente = info["cliente"]
            if info["automatizado"]:
                agente += " [automatizado]"

        avisos = _avisos_de(tr)
        console.print(theme.bloque_http(
            tr.metodo, tr.url, tr.codigo, tr.content_type,
            formatear_bytes(tr.tamano_respuesta) if tr.tamano_respuesta else "",
            tr.cliente_ip, so, agente, avisos))
        console.print()

    if len(transacciones) > limite:
        console.print(f"  [dim_text]… y {len(transacciones) - limite} peticiones mas "
                      f"(estan todas en el informe exportado).[/]")
        console.print()

    # ── Sitios mas visitados ──────────────────────────
    if len(hosts_web) > 1:
        t2 = theme.tabla("Sitios contactados")
        t2.add_column("Sitio", style="bright_cyan", max_width=40)
        t2.add_column("Peticiones", justify="right", width=11)
        t2.add_column("Descargado", justify="right", width=11)
        t2.add_column("Codigos", max_width=20)
        for sitio, cuenta in hosts_web.most_common(12):
            del_sitio = [x for x in transacciones if (x.host or x.servidor_ip) == sitio]
            cods = Counter(x.codigo for x in del_sitio if x.codigo)
            t2.add_row(theme.esc(truncar(sitio, 38)), str(cuenta),
                       formatear_bytes(sum(x.tamano_respuesta for x in del_sitio)),
                       ", ".join(f"{c}×{n}" for c, n in cods.most_common(3)))
        console.print(t2)
        console.print()

    # ── Hallazgos ─────────────────────────────────────
    hallazgos.extend(_descargas_peligrosas(analisis))
    hallazgos.extend(_rutas_sospechosas(analisis))
    hallazgos.extend(_fuerza_bruta(analisis))
    hallazgos.extend(_metodos_de_escritura(analisis))
    hallazgos.extend(_clientes_automatizados(analisis))

    for f in hallazgos:
        console.print(theme.panel_hallazgo(
            f.titulo, f.severidad, f.descripcion, f.evidencia,
            f.recomendacion, f.confianza))

    if not hallazgos:
        console.print(theme.sin_hallazgos(
            "Trafico HTTP sin patrones sospechosos (aun asi va sin cifrar)."))

    console.print(theme.pie_modulo())
    return hallazgos


def _avisos_de(tr) -> List[str]:
    """Etiquetas cortas que se pintan bajo la peticion."""
    avisos = []
    if tr.extension in EXT_PELIGROSAS:
        avisos.append(f"⚠ descarga de {tr.extension}")
    if tr.autorizacion:
        avisos.append("🔑 lleva cabecera Authorization")
    if RUTAS_WEBSHELL.search(tr.uri):
        avisos.append("⚠ ruta tipica de webshell")
    elif RUTAS_SENSIBLES.search(tr.uri):
        avisos.append("⚠ intenta leer un fichero sensible")
    if RECORRIDO_RUTAS.search(tr.uri):
        avisos.append("⚠ recorrido de directorios (../)")
    if INYECCION.search(tr.uri) or (
            tr.cuerpo_peticion and INYECCION.search(
                tr.cuerpo_peticion[:2048].decode("utf-8", "replace"))):
        avisos.append("⚠ patron de inyeccion en los parametros")
    if tr.codigo in (401, 403):
        avisos.append(f"acceso denegado ({tr.codigo})")
    return avisos


def _descargas_peligrosas(analisis) -> List[Finding]:
    hallazgos = []
    for tr in analisis.http:
        if tr.extension not in EXT_PELIGROSAS or not tr.codigo == 200:
            continue
        perfil = analisis.hosts.get(tr.cliente_ip)
        so = perfil.so if perfil else "sistema no identificado"
        externo = not es_ip_privada(tr.servidor_ip)

        hallazgos.append(Finding(
            titulo=f"Descarga de ejecutable por HTTP: {truncar(tr.nombre_fichero or tr.ruta, 48)}",
            descripcion=(
                f"Un {so} descargo un fichero {tr.extension} por HTTP sin cifrar "
                f"{'desde Internet' if externo else 'desde la red interna'}. "
                f"Al ir sin TLS, cualquiera en el camino pudo modificar el binario "
                f"antes de que llegara. Es la via de entrada mas comun de malware "
                f"en un equipo de usuario."
            ),
            severidad=Severidad.ALTO if externo else Severidad.MEDIO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"{tr.metodo} {tr.url} → {tr.codigo}, "
                      f"{formatear_bytes(tr.tamano_respuesta)}, "
                      f"pedido por {tr.cliente_ip}",
            recomendacion=(
                "Busca el hash del fichero en el modulo de ficheros y comprueba "
                "que proceso lo lanzo en el equipo. Si no lo reconoces, aisla el "
                "equipo antes de seguir."
            ),
            patron="malware_download",
            host=tr.cliente_ip,
            host_so=so,
            timestamp=formatear_hora(tr.ts),
            datos={"url": tr.url, "tamano": tr.tamano_respuesta},
        ))
    return hallazgos[:10]


def _rutas_sospechosas(analisis) -> List[Finding]:
    hallazgos = []
    vistos = set()

    for tr in analisis.http:
        motivo = severidad = None
        if RUTAS_WEBSHELL.search(tr.uri):
            motivo = ("La ruta corresponde a nombres de webshell conocidos. Si el "
                      "servidor responde 200, hay una puerta trasera instalada y "
                      "alguien la esta usando.")
            severidad = Severidad.CRITICO if tr.codigo == 200 else Severidad.ALTO
            patron = "webshell"
        elif RECORRIDO_RUTAS.search(tr.uri):
            motivo = ("La peticion incluye '../' para salirse del directorio web e "
                      "intentar leer ficheros del sistema.")
            severidad = Severidad.ALTO
            patron = "path_traversal"
        elif INYECCION.search(tr.uri):
            motivo = ("Los parametros llevan patrones de inyeccion (SQL, XSS o "
                      "ejecucion de comandos).")
            severidad = Severidad.ALTO
            patron = "web_injection"
        elif RUTAS_SENSIBLES.search(tr.uri):
            motivo = ("Se esta pidiendo un fichero que nunca deberia ser accesible "
                      "por web: contiene credenciales, configuracion o el codigo "
                      "fuente del sitio.")
            severidad = Severidad.ALTO if tr.codigo == 200 else Severidad.MEDIO
            patron = "sensitive_file"
        if not motivo:
            continue

        clave = (patron, tr.cliente_ip, tr.ruta[:60])
        if clave in vistos:
            continue
        vistos.add(clave)

        hallazgos.append(Finding(
            titulo=f"Peticion sospechosa: {truncar(tr.ruta, 52)}",
            descripcion=motivo + (
                f" El servidor respondio {tr.codigo}, asi que el intento "
                f"{'funciono' if tr.codigo == 200 else 'no prospero'}."
                if tr.codigo else " No se capturo la respuesta."),
            severidad=severidad,
            confianza=Confianza.ALTA if tr.codigo == 200 else Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"{tr.metodo} {truncar(tr.url, 100)} → {tr.codigo or '?'} "
                      f"(desde {tr.cliente_ip})",
            recomendacion=(
                "Revisa los registros del servidor web para esa ruta y esa IP. Si "
                "hubo respuesta 200, trata el servidor como comprometido."
            ),
            patron=patron,
            host=tr.cliente_ip,
            host_so=analisis.so_de(tr.cliente_ip),
            timestamp=formatear_hora(tr.ts),
        ))
    return hallazgos[:12]


def _fuerza_bruta(analisis) -> List[Finding]:
    """Muchos 401/403 desde el mismo origen contra el mismo sitio."""
    hallazgos = []
    intentos = defaultdict(list)
    for tr in analisis.http:
        if tr.codigo in (401, 403) or (tr.codigo == 200 and tr.autorizacion):
            intentos[(tr.cliente_ip, tr.host or tr.servidor_ip)].append(tr)

    for (origen, destino), lista in intentos.items():
        fallidos = [t for t in lista if t.codigo in (401, 403)]
        if len(fallidos) < 8:
            continue
        exito = any(t.codigo == 200 for t in lista)
        span = max(t.ts for t in lista) - min(t.ts for t in lista)

        hallazgos.append(Finding(
            titulo=f"Posible fuerza bruta HTTP contra {destino}",
            descripcion=(
                f"{len(fallidos)} respuestas 401/403 desde {origen} hacia {destino}"
                + (f" en {span:.0f} segundos" if span > 0 else "") + ". "
                + ("Ademas hay una respuesta 200 con credenciales: el intento "
                   "acabo funcionando, hay una cuenta comprometida."
                   if exito else
                   "No se ve ninguna autenticacion correcta en la captura.")
            ),
            severidad=Severidad.CRITICO if exito else Severidad.ALTO,
            confianza=Confianza.ALTA if len(fallidos) > 20 else Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"{origen} → {destino}: {len(fallidos)} fallos"
                      + (", 1 exito" if exito else ""),
            recomendacion=(
                "Bloquea la IP de origen, fuerza el cambio de contrasena de las "
                "cuentas afectadas y activa limitacion de intentos en el servidor."
            ),
            patron="brute_force",
            host=origen,
            host_so=analisis.so_de(origen),
        ))
    return hallazgos


def _metodos_de_escritura(analisis) -> List[Finding]:
    """PUT, DELETE y WebDAV en un servidor son casi siempre un error de config."""
    hallazgos = []
    escrituras = [t for t in analisis.http
                  if t.metodo in ("PUT", "DELETE", "MKCOL", "MOVE", "COPY", "PROPPATCH")]
    if not escrituras:
        return hallazgos

    exitosos = [t for t in escrituras if t.codigo and 200 <= t.codigo < 300]
    ejemplo = (exitosos or escrituras)[0]

    hallazgos.append(Finding(
        titulo=f"Metodos HTTP de escritura en uso ({len(escrituras)} peticiones)",
        descripcion=(
            "PUT, DELETE y los metodos WebDAV permiten crear o borrar ficheros en "
            "el servidor. En un sitio web normal deberian estar deshabilitados: "
            "son la forma clasica de subir una webshell."
            + (f" {len(exitosos)} de ellas fueron aceptadas por el servidor."
               if exitosos else " Ninguna fue aceptada.")
        ),
        severidad=Severidad.ALTO if exitosos else Severidad.MEDIO,
        confianza=Confianza.ALTA,
        modulo=MODULE_ID,
        evidencia=f"{ejemplo.metodo} {truncar(ejemplo.url, 90)} → {ejemplo.codigo or '?'}",
        recomendacion=(
            "Deshabilita los metodos de escritura en el servidor web salvo que la "
            "aplicacion los necesite, y en ese caso exige autenticacion."
        ),
        patron="webdav_write",
        host=ejemplo.cliente_ip,
        host_so=analisis.so_de(ejemplo.cliente_ip),
    ))
    return hallazgos


def _clientes_automatizados(analisis) -> List[Finding]:
    """Herramientas y escaneres identificados por su User-Agent."""
    hallazgos = []
    por_agente = defaultdict(list)

    for tr in analisis.http:
        if not tr.user_agent:
            continue
        info = fingerprint.analizar_user_agent(tr.user_agent)
        if info["categoria"] in ("escaner", "sospechoso"):
            por_agente[(info["cliente"], tr.cliente_ip)].append(tr)

    for (cliente, origen), lista in por_agente.items():
        destinos = sorted({t.host or t.servidor_ip for t in lista})[:4]
        hallazgos.append(Finding(
            titulo=f"Herramienta de escaneo detectada: {cliente}",
            descripcion=(
                f"{len(lista)} peticiones desde {origen} con un User-Agent de "
                f"herramienta ofensiva o escaner de vulnerabilidades. El User-Agent "
                f"se falsea trivialmente, asi que esto detecta al que no se molesta "
                f"en ocultarse: un atacante serio no aparecera aqui."
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"{origen} → {', '.join(destinos)} · "
                      f"UA: {truncar(lista[0].user_agent, 70)}",
            recomendacion=(
                "Comprueba si el escaneo estaba autorizado. Si no, bloquea la IP y "
                "revisa que consiguio: mira los codigos 200 de esas peticiones."
            ),
            patron="scanner_ua",
            host=origen,
            host_so=analisis.so_de(origen),
        ))
    return hallazgos
