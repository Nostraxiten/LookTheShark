"""
modules/timeline.py — La captura contada como una historia.

Todos los demas modulos miran la captura por temas. Este la mira por tiempo, que
es como funciona un incidente de verdad: primero paso esto, luego aquello, y por
eso acabo asi.

Produce dos vistas:
  Cronologia   los hechos relevantes en orden, con la hora y el protagonista
  Por equipo   que hizo cada maquina, resumido en frases

No genera hallazgos propios: reordena lo que ya se sabe para que se lea.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List

from rich.console import Console

from core import services
from modules import (Finding, es_ip_privada, formatear_bytes, formatear_duracion,
                     formatear_hora, plural, truncar)
from ui import theme

MODULE_NUM = 13
MODULE_NAME = "Cronologia"
MODULE_ID = "timeline"
MODULE_DESC = "Que paso, en que orden y quien lo hizo"

# Extensiones que convierten una descarga en un evento destacado.
EXT_RELEVANTES = {".exe", ".dll", ".msi", ".ps1", ".bat", ".scr", ".jar",
                  ".vbs", ".hta", ".apk", ".elf", ".zip", ".rar", ".7z"}


class Evento:
    __slots__ = ("ts", "actor", "accion", "detalle", "nivel", "categoria")

    def __init__(self, ts, actor, accion, detalle="", nivel="info", categoria=""):
        self.ts = ts
        self.actor = actor
        self.accion = accion
        self.detalle = detalle
        self.nivel = nivel
        self.categoria = categoria


def construir_eventos(analisis) -> List[Evento]:
    """Recoge de todos los subsistemas los hechos que merecen contarse."""
    eventos: List[Evento] = []

    # ── DHCP: un equipo entrando en la red ────────────
    for d in analisis.dhcp:
        if d["tipo"] in (1, 3):
            nombre = d["hostname"] or d["client_mac"]
            eventos.append(Evento(
                d["ts"], nombre,
                f"pide direccion IP ({d['tipo_nombre']})",
                d["vendor_class"] or "", "info", "red"))
        elif d["tipo"] == 5 and d.get("yiaddr", "0.0.0.0") != "0.0.0.0":
            eventos.append(Evento(
                d["ts"], d["src"], f"asigna la IP {d['yiaddr']}",
                d["hostname"] or "", "info", "red"))

    # ── Credenciales ──────────────────────────────────
    for c in analisis.credenciales:
        eventos.append(Evento(
            c.ts, c.src,
            f"se autentica en {c.dst}:{c.puerto} por {c.protocolo} SIN CIFRAR",
            f"usuario «{c.usuario}»", "critico", "credenciales"))

    # ── HTTP relevante ────────────────────────────────
    for t in analisis.http:
        nivel = "info"
        accion = f"{t.metodo} {truncar(t.host or t.servidor_ip, 30)}{truncar(t.ruta, 34)}"
        detalle = f"{t.codigo or '?'}"
        if t.extension in EXT_RELEVANTES and t.codigo == 200:
            nivel = "alto"
            accion = f"descarga {truncar(t.nombre_fichero or t.ruta, 40)}"
            detalle = f"{formatear_bytes(t.tamano_respuesta)} desde {t.host or t.servidor_ip}"
        elif t.metodo == "POST" and t.campos_formulario:
            nivel = "medio"
            accion = f"envia un formulario a {truncar(t.host or t.servidor_ip, 34)}"
            detalle = f"{plural(len(t.campos_formulario), 'campo', 'campos')}"
        elif t.codigo in (401, 403):
            nivel = "medio"
        eventos.append(Evento(t.ts, t.cliente_ip, accion, detalle, nivel, "web"))

    # ── Ficheros sospechosos ──────────────────────────
    for f in analisis.ficheros_sospechosos():
        eventos.append(Evento(
            f.ts, f.destino,
            f"recibe «{truncar(f.nombre, 32)}» que en realidad es {f.tipo_real}",
            f"SHA-256 {f.sha256[:16]}…", "critico", "fichero"))

    # ── Material sensible ─────────────────────────────
    for s in analisis.secretos:
        if s.severidad not in ("critico", "alto"):
            continue
        eventos.append(Evento(
            s.ts, s.src or "?", f"expone {s.nombre.lower()} sin cifrar",
            s.muestra, s.severidad, "secreto"))

    # ── TLS: destinos cifrados ────────────────────────
    for s in analisis.tls:
        if not s.sni:
            continue
        eventos.append(Evento(
            s.ts, s.cliente_ip, f"abre conexion cifrada con {truncar(s.sni, 40)}",
            s.version_servidor or s.version_cliente, "info", "web"))

    # ── ARP spoofing ──────────────────────────────────
    for g in analisis.arp_gratuitos[:20]:
        eventos.append(Evento(
            g["ts"], g["mac"], f"anuncia por ARP ser {g['ip']}",
            "respuesta ARP no solicitada", "alto", "red"))

    # ── Comandos remotos ──────────────────────────────
    for c in analisis.comandos:
        eventos.append(Evento(
            c.ts, c.src, f"ejecuta por {c.protocolo}: {truncar(c.comando, 44)}",
            f"en {c.dst}", "alto", "comando"))

    # ── Correo saliente ───────────────────────────────
    for m in analisis.correos:
        eventos.append(Evento(
            m.ts, m.src,
            f"envia correo a {truncar(', '.join(m.destinatarios[:2]), 36)}",
            truncar(m.asunto, 40) + (f" · {len(m.adjuntos)} adjuntos"
                                     if m.adjuntos else ""),
            "medio", "correo"))

    # ── DNS con mala pinta ────────────────────────────
    for e in analisis.dns:
        if e.es_respuesta or not e.nombre:
            continue
        etiqueta_larga = max(e.nombre.split("."), key=len)
        if len(etiqueta_larga) > 45:
            eventos.append(Evento(
                e.ts, e.src, f"consulta un nombre DNS de {len(e.nombre)} caracteres",
                truncar(e.nombre, 44), "alto", "dns"))

    eventos.sort(key=lambda x: x.ts or 0)
    return eventos


def run(analisis, config: dict, console: Console) -> List[Finding]:
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    eventos = construir_eventos(analisis)
    if not eventos:
        console.print("  [dim_text]No hay hechos destacables que ordenar en el "
                      "tiempo.[/]")
        console.print(theme.pie_modulo())
        return []

    inicio = formatear_hora(analisis.primer_ts, con_fecha=True)
    console.print(f"  [dim_text]La captura empieza el {inicio} y dura "
                  f"{formatear_duracion(analisis.duracion)}.[/]")
    console.print()

    # ── Cronologia ────────────────────────────────────
    limite = int(config.get("timeline_max", 40))
    destacados = [e for e in eventos if e.nivel in ("critico", "alto")]
    mostrar = destacados if len(destacados) >= limite else eventos

    console.print(f"  [titulo]Que fue pasando[/]"
                  + (f" [dim_text](solo lo relevante: {len(destacados)} de "
                     f"{len(eventos)} eventos)[/]" if mostrar is destacados else ""))
    console.print()

    ultimo_actor = None
    for e in mostrar[:limite]:
        actor = e.actor
        perfil = analisis.hosts.get(actor)
        if perfil and perfil.so and actor != ultimo_actor:
            actor = f"{actor}"
        # linea_evento devuelve un Text: no interpreta markup, es seguro.
        console.print(theme.linea_evento(
            formatear_hora(e.ts), truncar(actor, 21), e.accion, e.detalle, e.nivel))
        ultimo_actor = e.actor

    if len(mostrar) > limite:
        console.print(f"  [dim_text]… y {len(mostrar) - limite} eventos mas "
                      f"(la cronologia completa esta en el informe exportado).[/]")
    console.print()

    # ── Resumen por equipo ────────────────────────────
    por_actor = defaultdict(list)
    for e in eventos:
        por_actor[e.actor].append(e)

    console.print("  [titulo]Que hizo cada equipo[/]")
    console.print()

    for actor, lista in sorted(por_actor.items(), key=lambda x: -len(x[1]))[:10]:
        perfil = analisis.hosts.get(actor)
        cabecera = f"[bright_cyan]{actor}[/]"
        if perfil and perfil.so:
            cabecera += f"  {theme.icono_so(perfil.familia)} [lan]{perfil.so}[/]"
        if perfil and perfil.hostnames:
            cabecera += f"  [dim_text]«{theme.esc(next(iter(perfil.hostnames)))}»[/]"
        console.print(f"  {cabecera}")

        for frase in _resumir_actor(analisis, actor, lista):
            console.print(f"      [dim_text]•[/] {frase}")
        console.print()

    console.print(theme.caja_explicativa(
        "Esta vista no anade informacion: reordena la que ya hay. Sirve para "
        "responder a «¿que ocurrio primero?», que es la pregunta que decide si un "
        "equipo fue el origen del incidente o solo una victima mas.",
        "Para que sirve la cronologia"))

    console.print(theme.pie_modulo())
    return []


def _resumir_actor(analisis, actor: str, eventos) -> List[str]:
    """Frases que resumen lo que hizo un equipo."""
    frases = []
    perfil = analisis.hosts.get(actor)

    if perfil:
        if perfil.puertos_contactados:
            servicios = sorted({services.servicio(p) for p in perfil.puertos_contactados
                                if not services.es_efimero(p)})[:5]
            if servicios:
                frases.append(f"Se conecto a: {', '.join(servicios)}")
        if perfil.puertos_servidos:
            servicios = sorted({services.servicio(p) for p in perfil.puertos_servidos})[:5]
            frases.append(f"Ofrece servicio en: {', '.join(servicios)}")
        if perfil.dominios:
            frases.append(f"Resolvio {plural(len(perfil.dominios), 'dominio', 'dominios')}"
                          f": {', '.join(sorted(perfil.dominios)[:3])}")
        if perfil.bytes_enviados or perfil.bytes_recibidos:
            frases.append(f"Trafico: {formatear_bytes(perfil.bytes_enviados)} enviados, "
                          f"{formatear_bytes(perfil.bytes_recibidos)} recibidos")

    categorias = defaultdict(int)
    for e in eventos:
        categorias[e.categoria] += 1

    graves = [e for e in eventos if e.nivel in ("critico", "alto")]
    if graves:
        frases.append(f"[sev_alto]{plural(len(graves), 'evento relevante', 'eventos relevantes')}[/]: "
                      + truncar("; ".join(e.accion for e in graves[:3]), 90))

    return frases[:5]
