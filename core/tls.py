"""
core/tls.py — Parser nativo del handshake TLS.

Extrae de un ClientHello / ServerHello lo que de verdad sirve para atribuir e
identificar clientes: SNI, ALPN, versiones ofrecidas y aceptadas, y los
fingerprints JA3 / JA3S calculados aqui (antes dependian de que tshark los
generase, cosa que la mayoria de builds no hace).

JA3  = MD5(version,ciphers,extensiones,curvas,formatos_de_punto)   [cliente]
JA3S = MD5(version,cipher,extensiones)                             [servidor]

Tambien lee la cadena de certificados con un recorrido DER minimo para sacar
CN, emisor y fechas de validez sin depender de cryptography/pyOpenSSL.
"""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone
from typing import List, Optional

# ── Tipos de registro / handshake ─────────────────────
REC_CHANGE_CIPHER = 20
REC_ALERT         = 21
REC_HANDSHAKE     = 22
REC_APP_DATA      = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE  = 11

VERSIONES = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

VERSIONES_INSEGURAS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}

# GREASE (RFC 8701): valores de relleno que hay que excluir del JA3 o el
# fingerprint cambia en cada conexion del mismo navegador.
GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# Suites que no deberian negociarse en 2026.
CIPHERS_DEBILES = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "RSA_WITH_NULL_MD5",
    0x0002: "RSA_WITH_NULL_SHA",
    0x0004: "RSA_WITH_RC4_128_MD5",
    0x0005: "RSA_WITH_RC4_128_SHA",
    0x000A: "RSA_WITH_3DES_EDE_CBC_SHA",
    0x0013: "DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0016: "DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "RSA_WITH_AES_128_CBC_SHA",
    0x0035: "RSA_WITH_AES_256_CBC_SHA",
    0xC011: "ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
}

NOMBRE_CIPHER = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "ECDHE_RSA_WITH_CHACHA20_POLY1305",
    0xCCA9: "ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
}
NOMBRE_CIPHER.update(CIPHERS_DEBILES)


class HelloCliente:
    __slots__ = ("version", "version_max", "sni", "alpn", "ciphers", "extensiones",
                 "curvas", "formatos_punto", "ja3", "ja3_cadena", "session_id_len",
                 "versiones_soportadas", "ciphers_debiles")

    def __init__(self):
        self.version = 0
        self.version_max = 0
        self.sni = ""
        self.alpn: List[str] = []
        self.ciphers: List[int] = []
        self.extensiones: List[int] = []
        self.curvas: List[int] = []
        self.formatos_punto: List[int] = []
        self.ja3 = ""
        self.ja3_cadena = ""
        self.session_id_len = 0
        self.versiones_soportadas: List[int] = []
        self.ciphers_debiles: List[str] = []

    @property
    def version_texto(self) -> str:
        v = self.version_max or self.version
        return VERSIONES.get(v, f"0x{v:04x}")


class HelloServidor:
    __slots__ = ("version", "cipher", "cipher_nombre", "extensiones", "ja3s",
                 "alpn", "version_negociada")

    def __init__(self):
        self.version = 0
        self.cipher = 0
        self.cipher_nombre = ""
        self.extensiones: List[int] = []
        self.ja3s = ""
        self.alpn = ""
        self.version_negociada = 0

    @property
    def version_texto(self) -> str:
        v = self.version_negociada or self.version
        return VERSIONES.get(v, f"0x{v:04x}")


class Certificado:
    __slots__ = ("subject_cn", "issuer_cn", "no_antes", "no_despues",
                 "autofirmado", "caducado", "dias_validez", "serie")

    def __init__(self):
        self.subject_cn = ""
        self.issuer_cn = ""
        self.no_antes: Optional[datetime] = None
        self.no_despues: Optional[datetime] = None
        self.autofirmado = False
        self.caducado = False
        self.dias_validez = 0
        self.serie = ""


def _sin_grease(valores) -> List[int]:
    return [v for v in valores if v not in GREASE]


# ──────────────────────────────────────────────────────
# Extensiones
# ──────────────────────────────────────────────────────
def _parsear_extensiones(datos: bytes, pos: int, fin: int, cliente: bool):
    """Devuelve (lista_ids, sni, alpn, curvas, formatos, versiones_soportadas)."""
    ids: List[int] = []
    sni = ""
    alpn: List[str] = []
    curvas: List[int] = []
    formatos: List[int] = []
    versiones: List[int] = []

    if pos + 2 > fin:
        return ids, sni, alpn, curvas, formatos, versiones

    total = struct.unpack_from("!H", datos, pos)[0]
    pos += 2
    limite = min(pos + total, fin)

    while pos + 4 <= limite:
        ext_id, ext_len = struct.unpack_from("!HH", datos, pos)
        pos += 4
        cuerpo_fin = pos + ext_len
        if cuerpo_fin > limite:
            break

        if ext_id not in GREASE:
            ids.append(ext_id)

        try:
            if ext_id == 0x0000 and cliente:          # server_name
                if pos + 5 <= cuerpo_fin:
                    largo_nombre = struct.unpack_from("!H", datos, pos + 3)[0]
                    sni = datos[pos + 5:pos + 5 + largo_nombre].decode("utf-8", "replace")

            elif ext_id == 0x000A:                     # supported_groups
                if pos + 2 <= cuerpo_fin:
                    n = struct.unpack_from("!H", datos, pos)[0]
                    curvas = _sin_grease(
                        struct.unpack_from("!" + "H" * (n // 2), datos, pos + 2)
                    ) if n and pos + 2 + n <= cuerpo_fin else []

            elif ext_id == 0x000B:                     # ec_point_formats
                if pos < cuerpo_fin:
                    n = datos[pos]
                    formatos = list(datos[pos + 1:pos + 1 + n])

            elif ext_id == 0x0010:                     # ALPN
                if pos + 2 <= cuerpo_fin:
                    p = pos + 2
                    while p < cuerpo_fin:
                        n = datos[p]
                        p += 1
                        alpn.append(datos[p:p + n].decode("ascii", "replace"))
                        p += n

            elif ext_id == 0x002B:                     # supported_versions
                if cliente and pos < cuerpo_fin:
                    n = datos[pos]
                    if pos + 1 + n <= cuerpo_fin and n >= 2:
                        versiones = _sin_grease(
                            struct.unpack_from("!" + "H" * (n // 2), datos, pos + 1)
                        )
                elif not cliente and pos + 2 <= cuerpo_fin:
                    versiones = [struct.unpack_from("!H", datos, pos)[0]]
        except (struct.error, IndexError, ValueError):
            pass

        pos = cuerpo_fin

    return ids, sni, alpn, curvas, formatos, versiones


# ──────────────────────────────────────────────────────
# ClientHello / ServerHello
# ──────────────────────────────────────────────────────
def parsear_client_hello(datos: bytes) -> Optional[HelloCliente]:
    """Parsea el cuerpo de un handshake ClientHello (sin la cabecera de 4 bytes)."""
    try:
        if len(datos) < 38:
            return None
        h = HelloCliente()
        h.version = struct.unpack_from("!H", datos, 0)[0]

        pos = 34                                   # 2 version + 32 random
        sid_len = datos[pos]
        h.session_id_len = sid_len
        pos += 1 + sid_len

        if pos + 2 > len(datos):
            return None
        ciphers_len = struct.unpack_from("!H", datos, pos)[0]
        pos += 2
        if pos + ciphers_len > len(datos) or ciphers_len % 2:
            return None
        h.ciphers = _sin_grease(
            struct.unpack_from("!" + "H" * (ciphers_len // 2), datos, pos)
        )
        pos += ciphers_len

        if pos >= len(datos):
            return None
        comp_len = datos[pos]
        pos += 1 + comp_len

        (h.extensiones, h.sni, h.alpn, h.curvas,
         h.formatos_punto, h.versiones_soportadas) = _parsear_extensiones(
            datos, pos, len(datos), cliente=True)

        h.version_max = max(h.versiones_soportadas) if h.versiones_soportadas else h.version
        h.ciphers_debiles = [CIPHERS_DEBILES[c] for c in h.ciphers if c in CIPHERS_DEBILES]

        h.ja3_cadena = "{},{},{},{},{}".format(
            h.version,
            "-".join(str(c) for c in h.ciphers),
            "-".join(str(e) for e in h.extensiones),
            "-".join(str(c) for c in h.curvas),
            "-".join(str(f) for f in h.formatos_punto),
        )
        h.ja3 = hashlib.md5(h.ja3_cadena.encode()).hexdigest()
        return h
    except (struct.error, IndexError, ValueError):
        return None


def parsear_server_hello(datos: bytes) -> Optional[HelloServidor]:
    """Parsea el cuerpo de un ServerHello y calcula JA3S."""
    try:
        if len(datos) < 38:
            return None
        h = HelloServidor()
        h.version = struct.unpack_from("!H", datos, 0)[0]

        pos = 34
        sid_len = datos[pos]
        pos += 1 + sid_len
        if pos + 3 > len(datos):
            return None
        h.cipher = struct.unpack_from("!H", datos, pos)[0]
        h.cipher_nombre = NOMBRE_CIPHER.get(h.cipher, f"0x{h.cipher:04x}")
        pos += 3                                   # cipher (2) + compresion (1)

        ids, _sni, alpn, _curvas, _fmt, versiones = _parsear_extensiones(
            datos, pos, len(datos), cliente=False)
        h.extensiones = ids
        h.alpn = alpn[0] if alpn else ""
        h.version_negociada = versiones[0] if versiones else h.version

        h.ja3s = hashlib.md5(
            "{},{},{}".format(
                h.version, h.cipher, "-".join(str(e) for e in h.extensiones)
            ).encode()
        ).hexdigest()
        return h
    except (struct.error, IndexError, ValueError):
        return None


# ──────────────────────────────────────────────────────
# Certificados (recorrido DER minimo)
# ──────────────────────────────────────────────────────
_OID_CN = b"\x55\x04\x03"   # 2.5.4.3 commonName


def _fecha_asn1(raw: bytes) -> Optional[datetime]:
    """UTCTime (YYMMDDhhmmssZ) o GeneralizedTime (YYYYMMDDhhmmssZ)."""
    txt = raw.decode("ascii", "ignore").rstrip("Z")
    try:
        if len(txt) >= 12 and len(raw) <= 14:
            anio = int(txt[:2])
            anio += 2000 if anio < 50 else 1900
            resto = txt[2:12]
        elif len(txt) >= 14:
            anio = int(txt[:4])
            resto = txt[4:14]
        else:
            return None
        return datetime(anio, int(resto[0:2]), int(resto[2:4]), int(resto[4:6]),
                        int(resto[6:8]), int(resto[8:10]), tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def _cn_desde_rdn(datos: bytes) -> str:
    """Busca el primer commonName dentro de un bloque Name codificado en DER."""
    idx = datos.find(_OID_CN)
    while idx != -1:
        pos = idx + 3
        if pos + 2 <= len(datos):
            tipo = datos[pos]
            largo = datos[pos + 1]
            # Tipos de cadena ASN.1 admitidos para un CN.
            if tipo in (0x0C, 0x13, 0x16, 0x14, 0x1E) and largo < 0x80:
                return datos[pos + 2:pos + 2 + largo].decode("utf-8", "replace")
        idx = datos.find(_OID_CN, idx + 1)
    return ""


def parsear_certificado(der: bytes) -> Certificado:
    """Saca CN, emisor y validez de un certificado X.509 en DER.

    No valida firmas ni cadenas: para eso hace falta una libreria de cripto.
    Lo que buscamos es contexto forense (a quien dice pertenecer, si esta
    caducado, si es autofirmado).
    """
    cert = Certificado()

    # Las dos fechas de validez son los dos primeros UTCTime/GeneralizedTime.
    fechas = []
    pos = 0
    while pos + 2 < len(der) and len(fechas) < 2:
        if der[pos] in (0x17, 0x18):
            largo = der[pos + 1]
            if largo < 0x80 and pos + 2 + largo <= len(der):
                f = _fecha_asn1(der[pos + 2:pos + 2 + largo])
                if f:
                    fechas.append(f)
                pos += 2 + largo
                continue
        pos += 1

    if len(fechas) == 2:
        cert.no_antes, cert.no_despues = fechas
        cert.dias_validez = max(0, (cert.no_despues - cert.no_antes).days)
        cert.caducado = cert.no_despues < datetime.now(timezone.utc)

    # El emisor aparece antes que el sujeto en el TBSCertificate.
    primer_cn = der.find(_OID_CN)
    if primer_cn != -1:
        cert.issuer_cn = _cn_desde_rdn(der[primer_cn:primer_cn + 512])
        segundo = der.find(_OID_CN, primer_cn + 3)
        if segundo != -1:
            cert.subject_cn = _cn_desde_rdn(der[segundo:segundo + 512])
        else:
            cert.subject_cn = cert.issuer_cn
    cert.autofirmado = bool(cert.subject_cn) and cert.subject_cn == cert.issuer_cn
    return cert


# ──────────────────────────────────────────────────────
# Recorrido de records
# ──────────────────────────────────────────────────────
def parece_tls(datos: bytes) -> bool:
    """Heuristica barata: cabecera de record TLS valida al principio."""
    if len(datos) < 5:
        return False
    return datos[0] in (REC_CHANGE_CIPHER, REC_ALERT, REC_HANDSHAKE, REC_APP_DATA) \
        and datos[1] == 0x03 and datos[2] <= 0x04


def iterar_handshakes(flujo: bytes, max_bytes: int = 262144):
    """Recorre los records TLS de un flujo y cede (tipo_handshake, cuerpo).

    Reensambla mensajes de handshake partidos en varios records, que es lo
    normal cuando el servidor manda una cadena de certificados larga.
    """
    pos = 0
    limite = min(len(flujo), max_bytes)
    buffer_hs = bytearray()

    while pos + 5 <= limite:
        tipo, _ver, largo = struct.unpack_from("!BHH", flujo, pos)
        if tipo not in (REC_CHANGE_CIPHER, REC_ALERT, REC_HANDSHAKE, REC_APP_DATA):
            return
        if largo > 16640:            # maximo legal de un record TLS
            return
        cuerpo = flujo[pos + 5:pos + 5 + largo]
        pos += 5 + largo

        if tipo != REC_HANDSHAKE:
            if tipo == REC_APP_DATA:
                return               # ya esta cifrado: no hay mas que leer
            continue

        buffer_hs += cuerpo
        while len(buffer_hs) >= 4:
            hs_tipo = buffer_hs[0]
            hs_largo = int.from_bytes(buffer_hs[1:4], "big")
            if len(buffer_hs) < 4 + hs_largo:
                break
            yield hs_tipo, bytes(buffer_hs[4:4 + hs_largo])
            del buffer_hs[:4 + hs_largo]


def extraer_certificados(cuerpo: bytes, maximo: int = 4) -> List[Certificado]:
    """Parsea el mensaje Certificate: lista de certificados DER encadenados."""
    certs: List[Certificado] = []
    if len(cuerpo) < 3:
        return certs
    total = int.from_bytes(cuerpo[0:3], "big")
    pos = 3
    fin = min(3 + total, len(cuerpo))
    while pos + 3 <= fin and len(certs) < maximo:
        largo = int.from_bytes(cuerpo[pos:pos + 3], "big")
        pos += 3
        if largo <= 0 or pos + largo > fin:
            break
        certs.append(parsear_certificado(cuerpo[pos:pos + largo]))
        pos += largo
    return certs
