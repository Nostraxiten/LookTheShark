"""
core/ — Nucleo nativo de LookingTheShark.

Este paquete sustituye por completo la dependencia de pyshark/tshark:

  pcap_reader  Lector nativo de .pcap / .pcapng (streaming, sin cargar en RAM).
  decoders     Disectores de Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP / ICMP / ARP.
  dns          Parser de mensajes DNS con descompresion de nombres.
  tls          Parser de TLS handshake: SNI, ALPN, versiones, JA3 / JA3S.
  streams      Reensamblado de flujos TCP con limites de memoria.
  http         Parser de transacciones HTTP/1.x sobre flujos reensamblados.
  carving      Identificacion de ficheros por magic bytes + hashing.
  secrets      Escaneo de material sensible dentro de los payloads.
  fingerprint  Fingerprinting pasivo de sistema operativo.
  session      Analisis de una captura en UNA sola pasada.

Todo es Python puro de la libreria estandar: se instala con pip sin compilar
nada y funciona igual en Windows y en Linux.
"""

__all__ = [
    "pcap_reader",
    "decoders",
    "dns",
    "tls",
    "streams",
    "http",
    "carving",
    "secrets",
    "fingerprint",
    "session",
]
