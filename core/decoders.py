"""
core/decoders.py — Disectores de capa 2/3/4 en Python puro.

Convierte los bytes de un PaqueteCrudo en un objeto Paquete con los campos que
necesitan los modulos. Esta escrito para ser rapido: struct precompilado,
__slots__, y sin construir capas intermedias que nadie va a mirar.

Cobertura:
  Enlace   Ethernet, VLAN 802.1Q/QinQ, Linux SLL y SLL2, NULL/loopback,
           IP crudo, PPP, MPLS (se salta al payload IP)
  Red      IPv4 (con opciones y fragmentacion), IPv6 (con cabeceras de
           extension), ARP, ICMP, ICMPv6
  Trans.   TCP (flags y opciones), UDP, SCTP (basico)
"""

from __future__ import annotations

import socket
import struct
from typing import Optional


# ── DLT / linktypes ───────────────────────────────────
DLT_NULL      = 0
DLT_EN10MB    = 1     # Ethernet
DLT_PPP       = 9
DLT_RAW       = 101   # IP crudo (Linux)
DLT_RAW_BSD   = 12    # IP crudo (BSD/OpenBSD)
DLT_LOOP      = 108
DLT_LINUX_SLL = 113
DLT_IEEE802_11 = 105
DLT_IPV4      = 228
DLT_IPV6      = 229
DLT_LINUX_SLL2 = 276

# ── EtherTypes ────────────────────────────────────────
ETH_IPV4  = 0x0800
ETH_ARP   = 0x0806
ETH_IPV6  = 0x86DD
ETH_VLAN  = 0x8100
ETH_QINQ  = 0x88A8
ETH_QINQ2 = 0x9100
ETH_MPLS  = 0x8847
ETH_PPPOE = 0x8864
ETH_LLDP  = 0x88CC

# ── Protocolos IP ─────────────────────────────────────
IP_ICMP   = 1
IP_IGMP   = 2
IP_TCP    = 6
IP_UDP    = 17
IP_IPV6   = 41
IP_GRE    = 47
IP_ESP    = 50
IP_AH     = 51
IP_ICMPV6 = 58
IP_SCTP   = 132

NOMBRE_PROTO = {
    IP_ICMP: "ICMP", IP_IGMP: "IGMP", IP_TCP: "TCP", IP_UDP: "UDP",
    IP_IPV6: "IPv6-in-IPv4", IP_GRE: "GRE", IP_ESP: "ESP", IP_AH: "AH",
    IP_ICMPV6: "ICMPv6", IP_SCTP: "SCTP",
}

# Cabeceras de extension IPv6 que hay que saltarse para llegar al transporte.
IPV6_EXT = {0, 43, 44, 51, 60, 135, 139, 140}

# ── Flags TCP ─────────────────────────────────────────
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


def flags_tcp_texto(flags: int) -> str:
    """Representa los flags TCP como los muestra Wireshark: [SYN, ACK]."""
    nombres = []
    if flags & TCP_FIN: nombres.append("FIN")
    if flags & TCP_SYN: nombres.append("SYN")
    if flags & TCP_RST: nombres.append("RST")
    if flags & TCP_PSH: nombres.append("PSH")
    if flags & TCP_ACK: nombres.append("ACK")
    if flags & TCP_URG: nombres.append("URG")
    if flags & TCP_ECE: nombres.append("ECE")
    if flags & TCP_CWR: nombres.append("CWR")
    return ",".join(nombres) if nombres else "—"


# ── Structs precompilados (evita reparsear el formato en cada paquete) ──
_S_ETH      = struct.Struct("!6s6sH")
_S_IPV4     = struct.Struct("!BBHHHBBH4s4s")
_S_IPV6     = struct.Struct("!IHBB16s16s")
_S_TCP      = struct.Struct("!HHIIBBHHH")
_S_UDP      = struct.Struct("!HHHH")
_S_ARP      = struct.Struct("!HHBBH6s4s6s4s")
_S_VLAN     = struct.Struct("!HH")
_S_SLL      = struct.Struct("!HHH8sH")
_S_SLL2     = struct.Struct("!HHIHBB8s")

_inet_ntoa = socket.inet_ntoa


def _ipv6_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        return raw.hex()


def mac_str(raw: bytes) -> str:
    """b'\\x00\\x11\\x22\\x33\\x44\\x55' -> '00:11:22:33:44:55'."""
    return ":".join(f"{b:02x}" for b in raw)


class Paquete:
    """Un paquete ya disectado.

    Los campos que no aplican quedan a None / 0. Los modulos comprueban
    `pkt.proto` o `pkt.tipo_l3` en vez de hacer hasattr como con pyshark.
    """

    __slots__ = (
        "num", "ts", "wirelen", "caplen",
        "eth_src", "eth_dst", "ethertype", "vlan",
        "tipo_l3", "src", "dst", "ip_version", "ttl", "ip_len", "ip_id",
        "ip_df", "ip_mf", "ip_frag_offset", "dscp",
        "proto", "proto_nombre",
        "sport", "dport", "tcp_flags", "seq", "ack", "window", "tcp_opts",
        "payload", "payload_len",
        "icmp_type", "icmp_code",
        "arp_op", "arp_src_mac", "arp_src_ip", "arp_dst_mac", "arp_dst_ip",
        "capa_alta", "malformado",
    )

    def __init__(self):
        self.num = 0
        self.ts = 0.0
        self.wirelen = 0
        self.caplen = 0
        self.eth_src = ""
        self.eth_dst = ""
        self.ethertype = 0
        self.vlan = None
        self.tipo_l3 = ""        # "ipv4" | "ipv6" | "arp" | "otro"
        self.src = ""
        self.dst = ""
        self.ip_version = 0
        self.ttl = 0
        self.ip_len = 0
        self.ip_id = 0
        self.ip_df = False
        self.ip_mf = False
        self.ip_frag_offset = 0
        self.dscp = 0
        self.proto = 0
        self.proto_nombre = ""
        self.sport = None
        self.dport = None
        self.tcp_flags = 0
        self.seq = 0
        self.ack = 0
        self.window = 0
        self.tcp_opts = b""
        self.payload = b""
        self.payload_len = 0
        self.icmp_type = None
        self.icmp_code = None
        self.arp_op = 0
        self.arp_src_mac = ""
        self.arp_src_ip = ""
        self.arp_dst_mac = ""
        self.arp_dst_ip = ""
        self.capa_alta = ""      # etiqueta de la capa mas alta reconocida
        self.malformado = False

    # ── Ayudas de lectura ─────────────────────────────
    @property
    def es_tcp(self) -> bool:
        return self.proto == IP_TCP

    @property
    def es_udp(self) -> bool:
        return self.proto == IP_UDP

    @property
    def flujo(self) -> tuple:
        """Clave direccional del flujo: (src, sport, dst, dport, proto)."""
        return (self.src, self.sport, self.dst, self.dport, self.proto)

    @property
    def flujo_bidireccional(self) -> tuple:
        """Clave del flujo sin direccion: los dos extremos ordenados."""
        a = (self.src, self.sport)
        b = (self.dst, self.dport)
        return (a, b, self.proto) if a <= b else (b, a, self.proto)

    def __repr__(self) -> str:
        return (f"<Paquete #{self.num} {self.src}:{self.sport} -> "
                f"{self.dst}:{self.dport} {self.capa_alta}>")


# ──────────────────────────────────────────────────────
# Disectores
# ──────────────────────────────────────────────────────
def _decode_tcp(pkt: Paquete, data: bytes, off: int, fin: int) -> None:
    if fin - off < 20:
        pkt.malformado = True
        return
    (sport, dport, seq, ack, off_res, flags,
     window, _cksum, _urg) = _S_TCP.unpack_from(data, off)

    pkt.sport = sport
    pkt.dport = dport
    pkt.seq = seq
    pkt.ack = ack
    pkt.tcp_flags = flags
    pkt.window = window

    hlen = (off_res >> 4) * 4
    if hlen < 20 or off + hlen > fin:
        # Data offset invalido: tratamos los 20 bytes minimos y marcamos.
        pkt.malformado = True
        hlen = 20
    if hlen > 20:
        pkt.tcp_opts = data[off + 20:off + hlen]

    cuerpo = data[off + hlen:fin]
    pkt.payload = cuerpo
    pkt.payload_len = len(cuerpo)
    pkt.capa_alta = "TCP"


def _decode_udp(pkt: Paquete, data: bytes, off: int, fin: int) -> None:
    if fin - off < 8:
        pkt.malformado = True
        return
    sport, dport, longitud, _cksum = _S_UDP.unpack_from(data, off)
    pkt.sport = sport
    pkt.dport = dport

    # La longitud UDP incluye la cabecera; si miente, nos quedamos con lo real.
    final = off + longitud if 8 <= longitud <= (fin - off) else fin
    cuerpo = data[off + 8:final]
    pkt.payload = cuerpo
    pkt.payload_len = len(cuerpo)
    pkt.capa_alta = "UDP"


def _decode_transporte(pkt: Paquete, data: bytes, off: int, fin: int) -> None:
    proto = pkt.proto
    pkt.proto_nombre = NOMBRE_PROTO.get(proto, f"IP/{proto}")

    if proto == IP_TCP:
        _decode_tcp(pkt, data, off, fin)
    elif proto == IP_UDP:
        _decode_udp(pkt, data, off, fin)
    elif proto in (IP_ICMP, IP_ICMPV6):
        if fin - off >= 2:
            pkt.icmp_type = data[off]
            pkt.icmp_code = data[off + 1]
            pkt.payload = data[off + 4:fin]
            pkt.payload_len = len(pkt.payload)
        pkt.capa_alta = "ICMPv6" if proto == IP_ICMPV6 else "ICMP"
    elif proto == IP_SCTP:
        if fin - off >= 12:
            pkt.sport, pkt.dport = struct.unpack_from("!HH", data, off)
        pkt.capa_alta = "SCTP"
    else:
        pkt.payload = data[off:fin]
        pkt.payload_len = len(pkt.payload)
        pkt.capa_alta = pkt.proto_nombre


def _decode_ipv4(pkt: Paquete, data: bytes, off: int, fin: int) -> None:
    if fin - off < 20:
        pkt.malformado = True
        return
    (ver_ihl, tos, total_len, ident, flags_frag,
     ttl, proto, _cksum, src, dst) = _S_IPV4.unpack_from(data, off)

    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20:
        pkt.malformado = True
        return

    pkt.tipo_l3 = "ipv4"
    pkt.ip_version = 4
    pkt.src = _inet_ntoa(src)
    pkt.dst = _inet_ntoa(dst)
    pkt.ttl = ttl
    pkt.proto = proto
    pkt.ip_id = ident
    pkt.dscp = tos >> 2
    pkt.ip_df = bool(flags_frag & 0x4000)
    pkt.ip_mf = bool(flags_frag & 0x2000)
    pkt.ip_frag_offset = (flags_frag & 0x1FFF) * 8
    # total_len es lo que dice la cabecera; puede exceder lo capturado (snaplen).
    pkt.ip_len = total_len if total_len else (fin - off)

    final = min(off + total_len, fin) if total_len >= ihl else fin

    # Un fragmento que no es el primero no tiene cabecera de transporte.
    if pkt.ip_frag_offset > 0:
        pkt.proto_nombre = NOMBRE_PROTO.get(proto, f"IP/{proto}")
        pkt.capa_alta = "IPv4-frag"
        pkt.payload = data[off + ihl:final]
        pkt.payload_len = len(pkt.payload)
        return

    _decode_transporte(pkt, data, off + ihl, final)


def _decode_ipv6(pkt: Paquete, data: bytes, off: int, fin: int) -> None:
    if fin - off < 40:
        pkt.malformado = True
        return
    ver_tc_fl, plen, nxt, hlim, src, dst = _S_IPV6.unpack_from(data, off)

    pkt.tipo_l3 = "ipv6"
    pkt.ip_version = 6
    pkt.src = _ipv6_str(src)
    pkt.dst = _ipv6_str(dst)
    pkt.ttl = hlim
    pkt.dscp = (ver_tc_fl >> 22) & 0x3F
    pkt.ip_len = plen + 40

    pos = off + 40
    final = min(pos + plen, fin) if plen else fin

    # Saltar cabeceras de extension hasta llegar al transporte real.
    saltos = 0
    while nxt in IPV6_EXT and pos + 8 <= final and saltos < 16:
        siguiente = data[pos]
        if nxt == 44:            # Fragment header: longitud fija de 8 bytes
            longitud = 8
        elif nxt == 51:          # AH: longitud en palabras de 4 bytes + 2
            longitud = (data[pos + 1] + 2) * 4
        else:
            longitud = (data[pos + 1] + 1) * 8
        if longitud <= 0:
            break
        pos += longitud
        nxt = siguiente
        saltos += 1

    pkt.proto = nxt
    if pos >= final:
        pkt.proto_nombre = NOMBRE_PROTO.get(nxt, f"IP/{nxt}")
        pkt.capa_alta = pkt.proto_nombre
        return
    _decode_transporte(pkt, data, pos, final)


def _decode_arp(pkt: Paquete, data: bytes, off: int, fin: int) -> None:
    if fin - off < 28:
        pkt.malformado = True
        return
    (_hw, proto_tipo, hlen, plen, op,
     src_mac, src_ip, dst_mac, dst_ip) = _S_ARP.unpack_from(data, off)

    # Solo tiene sentido para IPv4 sobre Ethernet.
    if proto_tipo != ETH_IPV4 or hlen != 6 or plen != 4:
        pkt.tipo_l3 = "arp"
        pkt.capa_alta = "ARP"
        return

    pkt.tipo_l3 = "arp"
    pkt.arp_op = op
    pkt.arp_src_mac = mac_str(src_mac)
    pkt.arp_src_ip = _inet_ntoa(src_ip)
    pkt.arp_dst_mac = mac_str(dst_mac)
    pkt.arp_dst_ip = _inet_ntoa(dst_ip)
    pkt.src = pkt.arp_src_ip
    pkt.dst = pkt.arp_dst_ip
    pkt.capa_alta = "ARP"


def _decode_ethertype(pkt: Paquete, etype: int, data: bytes, off: int, fin: int) -> None:
    """Despacha por EtherType, desenrollando VLAN / MPLS / PPPoE por el camino."""
    saltos = 0
    while saltos < 8:
        saltos += 1

        if etype in (ETH_VLAN, ETH_QINQ, ETH_QINQ2):
            if fin - off < 4:
                pkt.malformado = True
                return
            tci, etype = _S_VLAN.unpack_from(data, off)
            if pkt.vlan is None:
                pkt.vlan = tci & 0x0FFF
            off += 4
            continue

        if etype == ETH_MPLS:
            # Pilas MPLS: cada etiqueta ocupa 4 bytes; el bit S marca la ultima.
            while off + 4 <= fin:
                fondo = data[off + 2] & 0x01
                off += 4
                if fondo:
                    break
            if off < fin:
                version = data[off] >> 4
                etype = ETH_IPV4 if version == 4 else (ETH_IPV6 if version == 6 else 0)
                continue
            return

        if etype == ETH_PPPOE:
            if fin - off < 8:
                return
            proto_ppp = struct.unpack_from("!H", data, off + 6)[0]
            off += 8
            etype = {0x0021: ETH_IPV4, 0x0057: ETH_IPV6}.get(proto_ppp, 0)
            if etype == 0:
                return
            continue

        break

    pkt.ethertype = etype
    if etype == ETH_IPV4:
        _decode_ipv4(pkt, data, off, fin)
    elif etype == ETH_IPV6:
        _decode_ipv6(pkt, data, off, fin)
    elif etype == ETH_ARP:
        _decode_arp(pkt, data, off, fin)
    elif etype == ETH_LLDP:
        pkt.tipo_l3 = "otro"
        pkt.capa_alta = "LLDP"
    elif etype <= 1500:
        # EtherType menor que la MTU = campo de longitud 802.3 (LLC/STP/IPX).
        pkt.tipo_l3 = "otro"
        pkt.capa_alta = "802.3/LLC"
    else:
        pkt.tipo_l3 = "otro"
        pkt.capa_alta = f"Eth/0x{etype:04x}"


def _decode_ip_crudo(pkt: Paquete, data: bytes, off: int, fin: int) -> None:
    """Para enlaces sin cabecera Ethernet: el primer nibble dice la version."""
    if off >= fin:
        pkt.malformado = True
        return
    version = data[off] >> 4
    if version == 4:
        _decode_ipv4(pkt, data, off, fin)
    elif version == 6:
        _decode_ipv6(pkt, data, off, fin)
    else:
        pkt.tipo_l3 = "otro"
        pkt.capa_alta = "Desconocido"


def decodificar(crudo, pkt: Optional[Paquete] = None) -> Paquete:
    """Disecta un PaqueteCrudo y devuelve un Paquete.

    Si se pasa `pkt`, se reutiliza el objeto (util en bucles calientes donde no
    se guarda el paquete). Nunca lanza: un paquete ilegible sale marcado con
    `malformado=True` para que el analisis no se caiga por un byte raro.
    """
    if pkt is None:
        pkt = Paquete()
    else:
        pkt.__init__()

    data = crudo.data
    pkt.num = crudo.num
    pkt.ts = crudo.ts
    pkt.caplen = crudo.caplen
    pkt.wirelen = crudo.origlen or crudo.caplen
    fin = len(data)
    dlt = crudo.linktype

    try:
        if dlt == DLT_EN10MB:
            if fin < 14:
                pkt.malformado = True
                return pkt
            dst_mac, src_mac, etype = _S_ETH.unpack_from(data, 0)
            pkt.eth_dst = mac_str(dst_mac)
            pkt.eth_src = mac_str(src_mac)
            _decode_ethertype(pkt, etype, data, 14, fin)

        elif dlt == DLT_LINUX_SLL:
            if fin < 16:
                pkt.malformado = True
                return pkt
            _tipo, _hw, _hlen, addr, etype = _S_SLL.unpack_from(data, 0)
            pkt.eth_src = mac_str(addr[:6])
            _decode_ethertype(pkt, etype, data, 16, fin)

        elif dlt == DLT_LINUX_SLL2:
            if fin < 20:
                pkt.malformado = True
                return pkt
            etype, _res, _ifidx, _hw, _tipo, _hlen, addr = _S_SLL2.unpack_from(data, 0)
            pkt.eth_src = mac_str(addr[:6])
            _decode_ethertype(pkt, etype, data, 20, fin)

        elif dlt in (DLT_RAW, DLT_RAW_BSD, DLT_IPV4, DLT_IPV6):
            _decode_ip_crudo(pkt, data, 0, fin)

        elif dlt in (DLT_NULL, DLT_LOOP):
            if fin < 4:
                pkt.malformado = True
                return pkt
            # La familia va en orden nativo en NULL y en big endian en LOOP.
            familia = struct.unpack_from("<I" if dlt == DLT_NULL else ">I", data, 0)[0]
            if familia in (2,):
                _decode_ipv4(pkt, data, 4, fin)
            elif familia in (24, 28, 30):
                _decode_ipv6(pkt, data, 4, fin)
            else:
                _decode_ip_crudo(pkt, data, 4, fin)

        elif dlt == DLT_PPP:
            desplazamiento = 4 if fin >= 4 and data[0] == 0xFF else 2
            if fin > desplazamiento:
                _decode_ip_crudo(pkt, data, desplazamiento, fin)

        elif dlt == DLT_IEEE802_11:
            # 802.11 sin disectar (haria falta gestionar QoS, WEP, A-MSDU...).
            pkt.tipo_l3 = "otro"
            pkt.capa_alta = "802.11"

        else:
            _decode_ip_crudo(pkt, data, 0, fin)

    except (struct.error, IndexError, ValueError):
        pkt.malformado = True

    if not pkt.capa_alta:
        pkt.capa_alta = "Desconocido"
    return pkt
