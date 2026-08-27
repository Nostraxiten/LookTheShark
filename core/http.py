"""
core/http.py — Parser de transacciones HTTP/1.x sobre flujos reensamblados.

Aqui es donde una captura deja de ser "paquetes" y pasa a leerse como lo que
realmente ocurrio: quien pidio que, a quien, con que cliente, que le
respondieron y que fichero viajo dentro.

Empareja peticiones con respuestas por orden dentro de la misma conexion
(HTTP/1.1 keep-alive es secuencial, asi que el orden es la relacion correcta) y
resuelve Content-Length, Transfer-Encoding: chunked y Content-Encoding
gzip/deflate/br para poder mirar dentro del cuerpo.

HTTP/2 y HTTP/3 van cifrados dentro de TLS/QUIC: de esos solo se ve el SNI, que
lo aporta core/tls.py.
"""

from __future__ import annotations

import gzip
import re
import zlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote_plus

METODOS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH",
           b"TRACE", b"CONNECT", b"PROPFIND", b"PROPPATCH", b"MKCOL", b"COPY",
           b"MOVE", b"LOCK", b"UNLOCK", b"SEARCH", b"REPORT")

MAX_CABECERA = 64 * 1024        # cabeceras mas largas = trafico raro o ataque
MAX_CUERPO_GUARDADO = 8 * 1024 * 1024
MAX_TRANSACCIONES_POR_FLUJO = 512

# Cabeceras cuyo valor es interesante mostrar tal cual en el informe.
CABECERAS_INTERES = (
    "host", "user-agent", "referer", "authorization", "cookie", "set-cookie",
    "content-type", "content-length", "content-encoding", "server",
    "location", "x-forwarded-for", "origin", "x-requested-with",
    "www-authenticate", "proxy-authorization", "x-api-key", "authentication",
)

_RE_ESTADO = re.compile(rb"^HTTP/(\d)\.(\d) (\d{3})(?: (.*))?$")


class TransaccionHTTP:
    """Una peticion HTTP y su respuesta."""

    __slots__ = (
        "metodo", "uri", "version", "host", "cabeceras_peticion",
        "cuerpo_peticion", "user_agent", "referer", "cookies", "autorizacion",
        "codigo", "razon", "cabeceras_respuesta", "cuerpo_respuesta",
        "content_type", "content_length", "servidor",
        "cliente_ip", "cliente_puerto", "servidor_ip", "servidor_puerto",
        "ts", "ts_respuesta", "flujo_id", "cuerpo_truncado", "campos_formulario",
        "nombre_fichero", "es_descarga", "cuerpo_peticion_truncado",
    )

    def __init__(self):
        self.metodo = ""
        self.uri = ""
        self.version = "1.1"
        self.host = ""
        self.cabeceras_peticion: Dict[str, str] = {}
        self.cuerpo_peticion = b""
        self.user_agent = ""
        self.referer = ""
        self.cookies = ""
        self.autorizacion = ""
        self.codigo = 0
        self.razon = ""
        self.cabeceras_respuesta: Dict[str, str] = {}
        self.cuerpo_respuesta = b""
        self.content_type = ""
        self.content_length = 0
        self.servidor = ""
        self.cliente_ip = ""
        self.cliente_puerto = 0
        self.servidor_ip = ""
        self.servidor_puerto = 0
        self.ts = 0.0
        self.ts_respuesta = 0.0
        self.flujo_id = 0
        self.cuerpo_truncado = False
        self.cuerpo_peticion_truncado = False
        self.campos_formulario: List[Tuple[str, str]] = []
        self.nombre_fichero = ""
        self.es_descarga = False

    # ── Vistas de lectura ─────────────────────────────
    @property
    def url(self) -> str:
        """URL completa reconstruida a partir del Host y la URI."""
        if self.uri.startswith("http://") or self.uri.startswith("https://"):
            return self.uri
        esquema = "https" if self.servidor_puerto == 443 else "http"
        host = self.host or self.servidor_ip
        return f"{esquema}://{host}{self.uri}"

    @property
    def ruta(self) -> str:
        return self.uri.split("?", 1)[0]

    @property
    def query(self) -> str:
        return self.uri.split("?", 1)[1] if "?" in self.uri else ""

    @property
    def extension(self) -> str:
        ruta = self.ruta.rstrip("/")
        if "." in ruta.rsplit("/", 1)[-1]:
            return "." + ruta.rsplit(".", 1)[-1].lower()
        return ""

    @property
    def tiene_respuesta(self) -> bool:
        return self.codigo > 0

    @property
    def latencia_ms(self) -> float:
        if self.ts and self.ts_respuesta and self.ts_respuesta >= self.ts:
            return (self.ts_respuesta - self.ts) * 1000.0
        return 0.0

    @property
    def tamano_respuesta(self) -> int:
        return self.content_length or len(self.cuerpo_respuesta)

    def resumen(self) -> str:
        estado = f"{self.codigo}" if self.codigo else "sin respuesta"
        return f"{self.metodo} {self.url} -> {estado}"

    def __repr__(self) -> str:
        return f"<HTTP {self.resumen()}>"


# ──────────────────────────────────────────────────────
# Utilidades de bajo nivel
# ──────────────────────────────────────────────────────
def _parsear_cabeceras(bloque: bytes) -> Dict[str, str]:
    """Convierte el bloque de cabeceras en un dict en minusculas."""
    cabeceras: Dict[str, str] = {}
    for linea in bloque.split(b"\r\n"):
        if not linea:
            continue
        if b":" not in linea:
            continue
        nombre, _, valor = linea.partition(b":")
        clave = nombre.decode("latin-1").strip().lower()
        texto = valor.decode("latin-1").strip()
        if clave in cabeceras:
            # Set-Cookie y similares pueden repetirse.
            cabeceras[clave] += "; " + texto
        else:
            cabeceras[clave] = texto
    return cabeceras


def _descomprimir(datos: bytes, codificacion: str) -> bytes:
    """Deshace Content-Encoding para poder mirar dentro del cuerpo."""
    if not datos or not codificacion:
        return datos
    cod = codificacion.lower().strip()
    try:
        if "gzip" in cod or "x-gzip" in cod:
            return gzip.decompress(datos)
        if "deflate" in cod:
            try:
                return zlib.decompress(datos)
            except zlib.error:
                return zlib.decompress(datos, -zlib.MAX_WBITS)
        if "br" in cod:
            try:
                import brotli  # opcional
                return brotli.decompress(datos)
            except Exception:
                return datos
    except (OSError, zlib.error, EOFError):
        # Cuerpo cortado por el snaplen: intentamos lo que se pueda.
        if "gzip" in cod:
            try:
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                return d.decompress(datos)
            except zlib.error:
                return datos
    return datos


def _leer_chunked(datos: bytes, maximo: int) -> Tuple[bytes, int, bool]:
    """Decodifica Transfer-Encoding: chunked. Devuelve (cuerpo, consumido, completo)."""
    salida = bytearray()
    pos = 0
    total = len(datos)

    while pos < total:
        fin_linea = datos.find(b"\r\n", pos)
        if fin_linea == -1:
            return bytes(salida), pos, False
        cabecera = datos[pos:fin_linea].split(b";", 1)[0].strip()
        try:
            largo = int(cabecera, 16)
        except ValueError:
            return bytes(salida), pos, False

        pos = fin_linea + 2
        if largo == 0:
            # Trailers opcionales hasta la linea en blanco.
            fin = datos.find(b"\r\n", pos)
            return bytes(salida), (fin + 2 if fin != -1 else pos), True
        if pos + largo > total:
            salida += datos[pos:total]
            return bytes(salida), total, False
        if len(salida) < maximo:
            salida += datos[pos:pos + largo]
        pos += largo + 2

    return bytes(salida), pos, False


def _nombre_desde_disposition(valor: str) -> str:
    """Saca el filename de un Content-Disposition."""
    if not valor:
        return ""
    m = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)\"?", valor, re.I)
    if m:
        return unquote_plus(m.group(1).strip())
    return ""


# ──────────────────────────────────────────────────────
# Parseo de un sentido
# ──────────────────────────────────────────────────────
def _parsear_peticiones(datos: bytes) -> List[dict]:
    """Extrae todas las peticiones del sentido cliente -> servidor."""
    peticiones = []
    pos = 0
    total = len(datos)

    while pos < total and len(peticiones) < MAX_TRANSACCIONES_POR_FLUJO:
        # Buscar el inicio de una peticion valida.
        if not any(datos.startswith(m + b" ", pos) for m in METODOS):
            siguiente = -1
            for m in METODOS:
                idx = datos.find(b"\r\n" + m + b" ", pos)
                if idx != -1 and (siguiente == -1 or idx < siguiente):
                    siguiente = idx
            if siguiente == -1:
                break
            pos = siguiente + 2
            continue

        fin_cabeceras = datos.find(b"\r\n\r\n", pos)
        if fin_cabeceras == -1 or fin_cabeceras - pos > MAX_CABECERA:
            break

        bloque = datos[pos:fin_cabeceras]
        lineas = bloque.split(b"\r\n", 1)
        linea_inicial = lineas[0]
        partes = linea_inicial.split(b" ")
        if len(partes) < 2:
            pos = fin_cabeceras + 4
            continue

        metodo = partes[0].decode("latin-1")
        uri = partes[1].decode("latin-1", "replace")
        version = partes[2].decode("latin-1", "replace") if len(partes) > 2 else "HTTP/1.1"
        cabeceras = _parsear_cabeceras(lineas[1] if len(lineas) > 1 else b"")

        cuerpo_inicio = fin_cabeceras + 4
        cuerpo = b""
        truncado = False

        if cabeceras.get("transfer-encoding", "").lower().find("chunked") != -1:
            cuerpo, consumido, completo = _leer_chunked(
                datos[cuerpo_inicio:], MAX_CUERPO_GUARDADO)
            truncado = not completo
            pos = cuerpo_inicio + consumido
        else:
            try:
                largo = int(cabeceras.get("content-length", "0") or 0)
            except ValueError:
                largo = 0
            largo = max(0, min(largo, MAX_CUERPO_GUARDADO))
            disponible = total - cuerpo_inicio
            if largo > disponible:
                largo = disponible
                truncado = True
            cuerpo = datos[cuerpo_inicio:cuerpo_inicio + largo]
            pos = cuerpo_inicio + largo

        peticiones.append({
            "metodo": metodo, "uri": uri, "version": version,
            "cabeceras": cabeceras, "cuerpo": cuerpo, "truncado": truncado,
            "offset": fin_cabeceras,
        })

    return peticiones


def _parsear_respuestas(datos: bytes) -> List[dict]:
    """Extrae todas las respuestas del sentido servidor -> cliente."""
    respuestas = []
    pos = 0
    total = len(datos)

    while pos < total and len(respuestas) < MAX_TRANSACCIONES_POR_FLUJO:
        if not datos.startswith(b"HTTP/", pos):
            idx = datos.find(b"\r\nHTTP/", pos)
            if idx == -1:
                break
            pos = idx + 2
            continue

        fin_cabeceras = datos.find(b"\r\n\r\n", pos)
        if fin_cabeceras == -1:
            # Respuesta cortada: guardamos lo que hay de cabeceras.
            fin_cabeceras = total
            bloque = datos[pos:total]
        else:
            bloque = datos[pos:fin_cabeceras]

        lineas = bloque.split(b"\r\n", 1)
        m = _RE_ESTADO.match(lineas[0].strip())
        if not m:
            pos = fin_cabeceras + 4
            continue

        version = f"{m.group(1).decode()}.{m.group(2).decode()}"
        codigo = int(m.group(3))
        razon = (m.group(4) or b"").decode("latin-1", "replace").strip()
        cabeceras = _parsear_cabeceras(lineas[1] if len(lineas) > 1 else b"")

        if fin_cabeceras >= total:
            respuestas.append({"codigo": codigo, "razon": razon, "version": version,
                               "cabeceras": cabeceras, "cuerpo": b"", "truncado": True})
            break

        cuerpo_inicio = fin_cabeceras + 4
        cuerpo = b""
        truncado = False

        sin_cuerpo = codigo in (204, 304) or 100 <= codigo < 200
        te = cabeceras.get("transfer-encoding", "").lower()

        if sin_cuerpo:
            pos = cuerpo_inicio
        elif "chunked" in te:
            cuerpo, consumido, completo = _leer_chunked(
                datos[cuerpo_inicio:], MAX_CUERPO_GUARDADO)
            truncado = not completo
            pos = cuerpo_inicio + consumido
        elif "content-length" in cabeceras:
            try:
                largo = int(cabeceras["content-length"] or 0)
            except ValueError:
                largo = 0
            largo = max(0, largo)
            disponible = total - cuerpo_inicio
            guardar = min(largo, MAX_CUERPO_GUARDADO, disponible)
            if largo > disponible:
                truncado = True
            cuerpo = datos[cuerpo_inicio:cuerpo_inicio + guardar]
            pos = cuerpo_inicio + min(largo, disponible)
        else:
            # Sin Content-Length ni chunked: el cuerpo llega hasta el cierre.
            cuerpo = datos[cuerpo_inicio:cuerpo_inicio + MAX_CUERPO_GUARDADO]
            truncado = (total - cuerpo_inicio) > MAX_CUERPO_GUARDADO
            pos = total

        cuerpo = _descomprimir(cuerpo, cabeceras.get("content-encoding", ""))

        respuestas.append({"codigo": codigo, "razon": razon, "version": version,
                           "cabeceras": cabeceras, "cuerpo": cuerpo,
                           "truncado": truncado})

    return respuestas


def parece_http(datos: bytes) -> bool:
    """True si el inicio del flujo parece HTTP en claro."""
    if len(datos) < 5:
        return False
    if datos.startswith(b"HTTP/"):
        return True
    return any(datos.startswith(m + b" ") for m in METODOS)


def extraer_transacciones(flujo) -> List[TransaccionHTTP]:
    """Reconstruye las transacciones HTTP de un FlujoTCP reensamblado."""
    peticion_bytes = bytes(flujo.cliente.datos)
    respuesta_bytes = bytes(flujo.servidor.datos)

    if not parece_http(peticion_bytes) and not parece_http(respuesta_bytes):
        return []

    peticiones = _parsear_peticiones(peticion_bytes)
    respuestas = _parsear_respuestas(respuesta_bytes)

    transacciones: List[TransaccionHTTP] = []
    for i, p in enumerate(peticiones):
        t = TransaccionHTTP()
        t.flujo_id = flujo.id
        t.cliente_ip = flujo.cliente_ip
        t.cliente_puerto = flujo.cliente_puerto
        t.servidor_ip = flujo.servidor_ip
        t.servidor_puerto = flujo.servidor_puerto
        t.ts = flujo.cliente.primer_ts or flujo.primer_ts
        t.ts_respuesta = flujo.servidor.primer_ts or 0.0

        t.metodo = p["metodo"]
        t.uri = p["uri"]
        t.version = p["version"].replace("HTTP/", "")
        t.cabeceras_peticion = p["cabeceras"]
        t.cuerpo_peticion = p["cuerpo"]
        t.cuerpo_peticion_truncado = p["truncado"]
        t.host = p["cabeceras"].get("host", "")
        t.user_agent = p["cabeceras"].get("user-agent", "")
        t.referer = p["cabeceras"].get("referer", "")
        t.cookies = p["cabeceras"].get("cookie", "")
        t.autorizacion = (p["cabeceras"].get("authorization", "")
                          or p["cabeceras"].get("proxy-authorization", ""))

        # Campos de formulario urlencoded: aqui viven los logins en claro.
        tipo_peticion = p["cabeceras"].get("content-type", "").lower()
        if t.cuerpo_peticion and "application/x-www-form-urlencoded" in tipo_peticion:
            try:
                t.campos_formulario = parse_qsl(
                    t.cuerpo_peticion.decode("utf-8", "replace"),
                    keep_blank_values=True)[:64]
            except ValueError:
                pass
        elif t.query:
            try:
                t.campos_formulario = parse_qsl(t.query, keep_blank_values=True)[:64]
            except ValueError:
                pass

        if i < len(respuestas):
            r = respuestas[i]
            t.codigo = r["codigo"]
            t.razon = r["razon"]
            t.cabeceras_respuesta = r["cabeceras"]
            t.cuerpo_respuesta = r["cuerpo"]
            t.cuerpo_truncado = r["truncado"]
            t.content_type = r["cabeceras"].get("content-type", "").split(";")[0].strip()
            t.servidor = r["cabeceras"].get("server", "")
            try:
                t.content_length = int(r["cabeceras"].get("content-length", "0") or 0)
            except ValueError:
                t.content_length = len(r["cuerpo"])
            if not t.content_length:
                t.content_length = len(r["cuerpo"])

            disposition = r["cabeceras"].get("content-disposition", "")
            t.nombre_fichero = _nombre_desde_disposition(disposition)
            t.es_descarga = bool(
                t.nombre_fichero
                or "attachment" in disposition.lower()
                or (t.content_type and not t.content_type.startswith(("text/html",
                                                                     "text/css",
                                                                     "application/javascript",
                                                                     "text/javascript")))
            )
            if not t.nombre_fichero:
                base = t.ruta.rstrip("/").rsplit("/", 1)[-1]
                if base and "." in base:
                    t.nombre_fichero = unquote_plus(base)

        transacciones.append(t)

    # Respuestas sin peticion (flujo empezado a mitad): se conservan igualmente
    # porque suelen llevar el fichero descargado.
    for r in respuestas[len(peticiones):]:
        t = TransaccionHTTP()
        t.flujo_id = flujo.id
        t.cliente_ip = flujo.cliente_ip
        t.servidor_ip = flujo.servidor_ip
        t.servidor_puerto = flujo.servidor_puerto
        t.ts = flujo.primer_ts
        t.metodo = "?"
        t.uri = "(peticion no capturada)"
        t.codigo = r["codigo"]
        t.razon = r["razon"]
        t.cabeceras_respuesta = r["cabeceras"]
        t.cuerpo_respuesta = r["cuerpo"]
        t.content_type = r["cabeceras"].get("content-type", "").split(";")[0].strip()
        t.servidor = r["cabeceras"].get("server", "")
        transacciones.append(t)

    return transacciones
