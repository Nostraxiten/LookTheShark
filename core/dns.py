"""
core/dns.py — Parser nativo de mensajes DNS (RFC 1035) y mDNS/LLMNR.

Devuelve preguntas y respuestas con los nombres ya descomprimidos. Es
deliberadamente tolerante: un mensaje truncado devuelve lo que se pudo leer en
vez de lanzar, porque en una captura real hay paquetes cortados por el snaplen.
"""

from __future__ import annotations

import socket
import struct
from typing import List, Optional

TIPOS = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
    16: "TXT", 17: "RP", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC",
    33: "SRV", 35: "NAPTR", 39: "DNAME", 41: "OPT", 43: "DS", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 52: "TLSA", 59: "CDS", 64: "SVCB",
    65: "HTTPS", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA",
}

CODIGOS_RESPUESTA = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}

# Un nombre DNS no puede pasar de 255 bytes; el contador de saltos corta
# los bucles de punteros de compresion (mensajes malformados o maliciosos).
MAX_SALTOS = 32
MAX_NOMBRE = 255


class RegistroDNS:
    __slots__ = ("nombre", "tipo", "tipo_num", "clase", "ttl", "valor")

    def __init__(self, nombre, tipo, tipo_num, clase, ttl, valor):
        self.nombre = nombre
        self.tipo = tipo
        self.tipo_num = tipo_num
        self.clase = clase
        self.ttl = ttl
        self.valor = valor

    def __repr__(self):
        return f"<RR {self.nombre} {self.tipo} {self.valor}>"


class MensajeDNS:
    __slots__ = ("txid", "es_respuesta", "opcode", "rcode", "rcode_nombre",
                 "preguntas", "respuestas", "autoridad", "adicional", "truncado")

    def __init__(self):
        self.txid = 0
        self.es_respuesta = False
        self.opcode = 0
        self.rcode = 0
        self.rcode_nombre = "NOERROR"
        self.preguntas: List[tuple] = []      # [(nombre, tipo_str, tipo_num)]
        self.respuestas: List[RegistroDNS] = []
        self.autoridad: List[RegistroDNS] = []
        self.adicional: List[RegistroDNS] = []
        self.truncado = False

    @property
    def nombre_consultado(self) -> str:
        return self.preguntas[0][0] if self.preguntas else ""

    @property
    def tipo_consultado(self) -> str:
        return self.preguntas[0][1] if self.preguntas else ""

    def ips_resueltas(self) -> List[str]:
        """IPs (A/AAAA) que devuelve la respuesta, en orden."""
        return [r.valor for r in self.respuestas if r.tipo in ("A", "AAAA")]

    def cadena_cname(self) -> List[str]:
        return [r.valor for r in self.respuestas if r.tipo == "CNAME"]


def _leer_nombre(datos: bytes, offset: int) -> tuple:
    """Lee un nombre DNS con compresion. Devuelve (nombre, offset_siguiente)."""
    etiquetas = []
    saltos = 0
    pos = offset
    fin_real = -1
    total = len(datos)
    longitud_acumulada = 0

    while pos < total:
        largo = datos[pos]

        if largo == 0:
            pos += 1
            break

        if largo & 0xC0 == 0xC0:            # puntero de compresion
            if pos + 1 >= total:
                break
            destino = ((largo & 0x3F) << 8) | datos[pos + 1]
            if fin_real < 0:
                fin_real = pos + 2
            saltos += 1
            if saltos > MAX_SALTOS or destino >= total or destino == pos:
                break
            pos = destino
            continue

        if largo & 0xC0:                     # etiqueta con bits reservados
            break

        pos += 1
        etiqueta = datos[pos:pos + largo]
        longitud_acumulada += largo + 1
        if longitud_acumulada > MAX_NOMBRE:
            break
        etiquetas.append(etiqueta.decode("utf-8", "replace"))
        pos += largo

    nombre = ".".join(etiquetas)
    return nombre, (fin_real if fin_real >= 0 else pos)


def _leer_rdata(datos: bytes, tipo: int, offset: int, longitud: int) -> str:
    """Interpreta el RDATA segun el tipo de registro."""
    trozo = datos[offset:offset + longitud]
    try:
        if tipo == 1 and longitud == 4:
            return socket.inet_ntoa(trozo)
        if tipo == 28 and longitud == 16:
            return socket.inet_ntop(socket.AF_INET6, trozo)
        if tipo in (2, 5, 12, 39):           # NS, CNAME, PTR, DNAME
            return _leer_nombre(datos, offset)[0]
        if tipo == 15 and longitud >= 3:     # MX
            pref = struct.unpack_from("!H", datos, offset)[0]
            return f"{pref} {_leer_nombre(datos, offset + 2)[0]}"
        if tipo == 33 and longitud >= 7:     # SRV
            prio, peso, puerto = struct.unpack_from("!HHH", datos, offset)
            destino = _leer_nombre(datos, offset + 6)[0]
            return f"{prio} {peso} {destino}:{puerto}"
        if tipo == 16:                       # TXT: una o varias cadenas
            partes = []
            pos = offset
            fin = offset + longitud
            while pos < fin:
                n = datos[pos]
                pos += 1
                partes.append(datos[pos:pos + n].decode("utf-8", "replace"))
                pos += n
            return " ".join(partes)
        if tipo == 6:                        # SOA
            mname, pos = _leer_nombre(datos, offset)
            rname, _ = _leer_nombre(datos, pos)
            return f"{mname} {rname}"
        if tipo == 257:                      # CAA
            if longitud >= 2:
                largo_tag = datos[offset + 1]
                tag = datos[offset + 2:offset + 2 + largo_tag].decode("ascii", "replace")
                valor = datos[offset + 2 + largo_tag:offset + longitud].decode("utf-8", "replace")
                return f"{tag} {valor}"
    except (struct.error, IndexError, ValueError, OSError):
        pass
    return trozo.hex()[:96]


def parsear(datos: bytes) -> Optional[MensajeDNS]:
    """Parsea un mensaje DNS completo. Devuelve None si no lo parece."""
    if len(datos) < 12:
        return None

    try:
        txid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", datos, 0)
    except struct.error:
        return None

    # Filtro barato contra falsos positivos: nadie manda 200 preguntas.
    if qd > 64 or an > 512 or ns > 512 or ar > 512:
        return None

    msg = MensajeDNS()
    msg.txid = txid
    msg.es_respuesta = bool(flags & 0x8000)
    msg.opcode = (flags >> 11) & 0x0F
    msg.truncado = bool(flags & 0x0200)
    msg.rcode = flags & 0x000F
    msg.rcode_nombre = CODIGOS_RESPUESTA.get(msg.rcode, f"RCODE{msg.rcode}")

    pos = 12
    try:
        for _ in range(qd):
            nombre, pos = _leer_nombre(datos, pos)
            if pos + 4 > len(datos):
                return msg
            tipo, _clase = struct.unpack_from("!HH", datos, pos)
            pos += 4
            msg.preguntas.append((nombre, TIPOS.get(tipo, str(tipo)), tipo))

        for lista, cantidad in ((msg.respuestas, an), (msg.autoridad, ns), (msg.adicional, ar)):
            for _ in range(cantidad):
                nombre, pos = _leer_nombre(datos, pos)
                if pos + 10 > len(datos):
                    return msg
                tipo, clase, ttl, rdlen = struct.unpack_from("!HHIH", datos, pos)
                pos += 10
                if pos + rdlen > len(datos):
                    return msg
                valor = _leer_rdata(datos, tipo, pos, rdlen)
                pos += rdlen
                lista.append(RegistroDNS(nombre, TIPOS.get(tipo, str(tipo)),
                                         tipo, clase, ttl, valor))
    except (struct.error, IndexError):
        pass

    return msg
