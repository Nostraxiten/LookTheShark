"""
modules/report_builder.py — Informes en Markdown, HTML, JSON y CSV.

El informe no es un volcado: es el mismo contenido que se ve en pantalla pero
ordenado para que alguien que no estaba delante entienda que paso. Empieza por
un resumen ejecutivo en lenguaje llano y despues baja al detalle.

La anonimizacion sustituye cada IP por un alias estable (equipo-A, equipo-B…)
manteniendo la coherencia en todo el documento, para poder compartir el informe
sin exponer el direccionamiento real.
"""

from __future__ import annotations

import csv
import dataclasses
import ipaddress
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List

from modules import (Finding, ORDEN_SEVERIDAD, formatear_bytes,
                     formatear_duracion, formatear_hora, ordenar_hallazgos,
                     plural, truncar)

MODULE_ID = "report"
VERSION_INFORME = "2.0"

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")


# ──────────────────────────────────────────────────────
# Anonimizacion
# ──────────────────────────────────────────────────────
class Anonimizador:
    """Sustituye direcciones por alias estables durante todo el informe."""

    def __init__(self):
        self.mapa: Dict[str, str] = {}
        self._siguiente = 0

    def alias(self, ip: str) -> str:
        if ip in self.mapa:
            return self.mapa[ip]
        # Las direcciones no enrutables se conservan: no identifican a nadie.
        try:
            direccion = ipaddress.ip_address(ip)
            if direccion.is_loopback or direccion.is_unspecified or direccion.is_multicast:
                self.mapa[ip] = ip
                return ip
        except ValueError:
            return ip

        indice = self._siguiente
        self._siguiente += 1
        letra = chr(ord("A") + indice % 26)
        sufijo = f"{indice // 26}" if indice >= 26 else ""
        self.mapa[ip] = f"equipo-{letra}{sufijo}"
        return self.mapa[ip]

    def _sustituir_ipv4(self, m) -> str:
        valor = m.group(0)
        # Un numero de version como "Chrome/121.0.0.0" encaja con el patron de
        # una IPv4. Se comprueba que los cuatro octetos esten en rango antes de
        # sustituir, y aun asi solo se toca lo que se parece a una direccion.
        partes = valor.split(".")
        if any(not p.isdigit() or int(p) > 255 for p in partes):
            return valor
        return self.alias(valor)

    def texto(self, texto: str) -> str:
        if not texto:
            return texto
        texto = _RE_IPV4.sub(self._sustituir_ipv4, texto)
        return _RE_IPV6.sub(lambda m: self.alias(m.group(0)) if ":" in m.group(0)
                            else m.group(0), texto)

    def valor(self, dato):
        """Anonimiza recursivamente cualquier estructura de datos."""
        if isinstance(dato, str):
            return self.texto(dato)
        if isinstance(dato, dict):
            return {k: self.valor(v) for k, v in dato.items()}
        if isinstance(dato, (list, tuple, set)):
            return [self.valor(v) for v in dato]
        return dato

    def hallazgo(self, f: Finding) -> Finding:
        copia = dataclasses.replace(f)
        copia.titulo = self.texto(f.titulo)
        copia.descripcion = self.texto(f.descripcion)
        copia.evidencia = self.texto(f.evidencia)
        copia.recomendacion = self.texto(f.recomendacion)
        copia.host = self.alias(f.host) if f.host else ""
        # Sin esto, el bloque `datos` del JSON seguia publicando las IPs reales.
        copia.datos = self.valor(f.datos)
        copia.referencias = self.valor(f.referencias)
        return copia


# ──────────────────────────────────────────────────────
# Resumen ejecutivo
# ──────────────────────────────────────────────────────
def resumen_ejecutivo(hallazgos: List[Finding], analisis=None) -> dict:
    """Traduce los hallazgos a un veredicto en lenguaje llano."""
    por_severidad = Counter(f.severidad for f in hallazgos)
    criticos = por_severidad.get("critico", 0)
    altos = por_severidad.get("alto", 0)

    if criticos:
        veredicto = "Requiere accion inmediata"
        explicacion = (
            f"Se han encontrado {plural(criticos, 'problema critico', 'problemas criticos')}. "
            f"Un hallazgo critico significa que algo ya esta comprometido o expuesto "
            f"ahora mismo, no que podria estarlo: credenciales capturables, un equipo "
            f"hablando con infraestructura maliciosa o un ataque en curso en la red local."
        )
        nivel = "critico"
    elif altos:
        veredicto = "Requiere revision prioritaria"
        explicacion = (
            f"No hay nada comprometido de forma evidente, pero si "
            f"{plural(altos, 'problema grave', 'problemas graves')} que dejan la red "
            f"expuesta: servicios que no deberian estar accesibles, protocolos sin "
            f"cifrar o comportamientos que encajan con un ataque."
        )
        nivel = "alto"
    elif por_severidad.get("medio"):
        veredicto = "Higiene mejorable"
        explicacion = (
            "No se observa actividad maliciosa. Lo encontrado son malas practicas "
            "que amplian la superficie de ataque sin ser un incidente en si."
        )
        nivel = "medio"
    else:
        veredicto = "Sin hallazgos relevantes"
        explicacion = (
            "El trafico analizado no presenta indicadores de compromiso ni "
            "configuraciones peligrosas. Recuerda que un analisis de red solo ve lo "
            "que paso durante la captura."
        )
        nivel = "bajo"

    prioridades = []
    for f in ordenar_hallazgos(hallazgos)[:5]:
        prioridades.append({
            "titulo": f.titulo,
            "severidad": f.severidad,
            "accion": f.recomendacion or "Revisar manualmente.",
            "host": f.host,
        })

    datos = {
        "veredicto": veredicto,
        "nivel": nivel,
        "explicacion": explicacion,
        "por_severidad": dict(por_severidad),
        "total": len(hallazgos),
        "prioridades": prioridades,
    }

    if analisis is not None:
        equipos_afectados = {f.host for f in hallazgos if f.host}
        datos["contexto"] = {
            "equipos_totales": len(analisis.hosts),
            "equipos_afectados": len(equipos_afectados),
            "credenciales": len(analisis.credenciales),
            "secretos": len(analisis.secretos),
            "ficheros_sospechosos": len(analisis.ficheros_sospechosos()),
        }
    return datos


def _contexto_captura(analisis) -> dict:
    """Datos de la captura para las plantillas."""
    if analisis is None:
        return {}
    return {
        "nombre": analisis.nombre,
        "ruta": analisis.ruta,
        "formato": analisis.formato,
        "paquetes": analisis.total_paquetes,
        "analizados": analisis.paquetes_analizados,
        "bytes": analisis.bytes_totales,
        "bytes_legible": formatear_bytes(analisis.bytes_totales),
        "duracion": formatear_duracion(analisis.duracion),
        "inicio": formatear_hora(analisis.primer_ts, con_fecha=True),
        "fin": formatear_hora(analisis.ultimo_ts, con_fecha=True),
        "hosts": len(analisis.hosts),
        "locales": len(analisis.hosts_locales),
        "externos": len(analisis.hosts_externos),
        "flujos": len(analisis.reensamblador),
        "http": len(analisis.http),
        "tls": len(analisis.tls),
        "dns": len(analisis.dns),
        "tiempo_analisis": round(analisis.tiempo_analisis, 2),
    }


def _inventario(analisis, anonimo) -> List[dict]:
    if analisis is None:
        return []
    salida = []
    for h in sorted(analisis.hosts.values(),
                    key=lambda x: -(x.bytes_enviados + x.bytes_recibidos)):
        salida.append({
            "ip": anonimo.alias(h.ip) if anonimo else h.ip,
            "so": h.so or "sin identificar",
            "familia": h.familia,
            "confianza": h.confianza,
            "fuentes": ", ".join(h.fuentes),
            "fabricante": h.fabricante,
            "nombre": next(iter(h.hostnames), ""),
            "rol": h.rol,
            "local": h.es_local,
            "bytes": h.bytes_enviados + h.bytes_recibidos,
            "bytes_legible": formatear_bytes(h.bytes_enviados + h.bytes_recibidos),
            "puertos_servidos": sorted(h.puertos_servidos)[:12],
            "dominios": sorted(h.dominios)[:12],
        })
    return salida


def _transacciones(analisis, anonimo, maximo: int = 500) -> List[dict]:
    if analisis is None:
        return []
    salida = []
    for t in analisis.http[:maximo]:
        salida.append({
            "hora": formatear_hora(t.ts),
            "metodo": t.metodo,
            "url": anonimo.texto(t.url) if anonimo else t.url,
            "codigo": t.codigo,
            "tipo": t.content_type,
            "tamano": formatear_bytes(t.tamano_respuesta),
            "cliente": anonimo.alias(t.cliente_ip) if anonimo else t.cliente_ip,
            "so_cliente": analisis.so_de(t.cliente_ip),
            "user_agent": t.user_agent,
            "servidor": t.servidor,
        })
    return salida


def _cronologia(analisis, anonimo, maximo: int = 300) -> List[dict]:
    if analisis is None:
        return []
    from modules.timeline import construir_eventos
    salida = []
    for e in construir_eventos(analisis)[:maximo]:
        salida.append({
            "hora": formatear_hora(e.ts),
            "actor": anonimo.alias(e.actor) if anonimo else e.actor,
            "accion": anonimo.texto(e.accion) if anonimo else e.accion,
            "detalle": anonimo.texto(e.detalle) if anonimo else e.detalle,
            "nivel": e.nivel,
        })
    return salida


# ──────────────────────────────────────────────────────
# Exportadores
# ──────────────────────────────────────────────────────
def _entorno_jinja():
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    carpeta = os.path.join(os.path.dirname(__file__), "..", "templates")
    return Environment(
        loader=FileSystemLoader(carpeta),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _contexto(hallazgos, analisis, anonimo) -> dict:
    resumen = resumen_ejecutivo(hallazgos, analisis)
    captura = _contexto_captura(analisis)
    if anonimo and captura:
        # El nombre del fichero de captura suele llevar la IP del equipo.
        captura["nombre"] = anonimo.texto(captura["nombre"])
        captura["ruta"] = anonimo.texto(captura["ruta"])
    por_modulo = defaultdict(list)
    for f in hallazgos:
        por_modulo[f.modulo].append(f)

    return {
        "version": VERSION_INFORME,
        "generado": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "resumen": resumen,
        "hallazgos": hallazgos,
        "por_modulo": dict(por_modulo),
        "captura": captura,
        "inventario": _inventario(analisis, anonimo),
        "http": _transacciones(analisis, anonimo),
        "cronologia": _cronologia(analisis, anonimo),
        "anonimizado": anonimo is not None,
        "orden_severidad": ORDEN_SEVERIDAD,
    }


def exportar_markdown(contexto: dict, ruta: str) -> None:
    try:
        plantilla = _entorno_jinja().get_template("report.md.j2")
        contenido = plantilla.render(**contexto)
    except Exception:
        contenido = _markdown_basico(contexto)
    with open(ruta, "w", encoding="utf-8") as fh:
        fh.write(contenido)


def _markdown_basico(contexto: dict) -> str:
    """Salida de emergencia si la plantilla falla o falta."""
    lineas = [f"# Informe LookingTheShark", ""]
    captura = contexto.get("captura", {})
    if captura:
        lineas.append(f"**Captura:** {captura.get('nombre')}  ")
        lineas.append(f"**Paquetes:** {captura.get('paquetes', 0):,}  ")
        lineas.append("")
    resumen = contexto["resumen"]
    lineas += [f"## {resumen['veredicto']}", "", resumen["explicacion"], ""]
    for f in contexto["hallazgos"]:
        lineas += [f"### [{f.severidad.upper()}] {f.titulo}", "",
                   f.descripcion, "",
                   f"- **Evidencia:** {f.evidencia}",
                   f"- **Que hacer:** {f.recomendacion}"]
        if f.mitre_name:
            lineas.append(f"- **MITRE:** {f.mitre_name}")
        lineas.append("")
    return "\n".join(lineas)


def exportar_html(contexto: dict, ruta: str) -> None:
    plantilla = _entorno_jinja().get_template("report.html.j2")
    with open(ruta, "w", encoding="utf-8") as fh:
        fh.write(plantilla.render(**contexto))


def exportar_json(contexto: dict, ruta: str) -> None:
    datos = {
        "metadatos": {
            "herramienta": "LookingTheShark",
            "version_informe": contexto["version"],
            "generado": contexto["generado"],
            "anonimizado": contexto["anonimizado"],
        },
        "captura": contexto["captura"],
        "resumen": contexto["resumen"],
        "inventario": contexto["inventario"],
        "hallazgos": [dataclasses.asdict(f) for f in contexto["hallazgos"]],
        "http": contexto["http"],
        "cronologia": contexto["cronologia"],
    }
    with open(ruta, "w", encoding="utf-8") as fh:
        json.dump(datos, fh, indent=2, ensure_ascii=False)


def exportar_csv(contexto: dict, ruta: str) -> None:
    """CSV de hallazgos, para meterlos en una hoja de calculo o un SIEM."""
    campos = ["severidad", "confianza", "modulo", "titulo", "descripcion",
              "evidencia", "recomendacion", "host", "host_so", "mitre_id",
              "mitre_name", "mitre_tactica", "timestamp"]
    with open(ruta, "w", encoding="utf-8", newline="") as fh:
        escritor = csv.DictWriter(fh, fieldnames=campos, extrasaction="ignore")
        escritor.writeheader()
        for f in contexto["hallazgos"]:
            escritor.writerow({c: getattr(f, c, "") for c in campos})


FORMATOS = {
    "md": ("markdown", exportar_markdown),
    "markdown": ("markdown", exportar_markdown),
    "html": ("html", exportar_html),
    "json": ("json", exportar_json),
    "csv": ("csv", exportar_csv),
}


def build_reports(hallazgos: List[Finding], config: dict, analisis=None) -> List[str]:
    """Genera todos los formatos pedidos. Devuelve las rutas escritas."""
    anonimo = Anonimizador() if config.get("anonymize") else None
    if anonimo:
        hallazgos = [anonimo.hallazgo(f) for f in hallazgos]

    hallazgos = ordenar_hallazgos(hallazgos)
    contexto = _contexto(hallazgos, analisis, anonimo)

    base = config.get("output_base") or "informe_captura"
    formatos = [f.strip().lower() for f in str(config.get("format", "md")).split(",")
                if f.strip()]

    escritos = []
    for formato in dict.fromkeys(formatos):
        entrada = FORMATOS.get(formato)
        if not entrada:
            continue
        extension, exportador = entrada
        extension = {"markdown": "md"}.get(extension, extension)
        ruta = f"{base}.{extension}"
        carpeta = os.path.dirname(os.path.abspath(ruta))
        if carpeta:
            os.makedirs(carpeta, exist_ok=True)
        try:
            exportador(contexto, ruta)
            escritos.append(ruta)
        except Exception as exc:
            print(f"  [!] No se pudo generar {ruta}: {exc}")
    return escritos


# Compatibilidad con el nombre antiguo de la API.
def anonymize_findings(hallazgos: List[Finding]) -> List[Finding]:
    anonimo = Anonimizador()
    return [anonimo.hallazgo(f) for f in hallazgos]
