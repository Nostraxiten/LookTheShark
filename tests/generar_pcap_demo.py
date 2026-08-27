#!/usr/bin/env python3
"""
tests/generar_pcap_demo.py — Genera una captura .pcap sintetica de demostracion.

Sirve para dos cosas:
  - Probar LookingTheShark sin necesitar una captura real ni permisos de root.
  - Validar en los tests que cada detector encuentra lo que tiene que encontrar.

La captura incluye a proposito: navegacion HTTP con descarga de un ejecutable
disfrazado de imagen, un login FTP en claro, una API con token filtrado,
consultas DNS normales y una con pinta de DGA, un handshake TLS, un escaneo de
puertos, beaconing regular hacia un C2, ARP spoofing y trafico DHCP.

Uso:  python tests/generar_pcap_demo.py [salida.pcap]
"""

import os
import struct
import sys
import zlib

# ── Constantes de red ─────────────────────────────────
ETH_IPV4 = 0x0800
ETH_ARP  = 0x0806
IP_TCP, IP_UDP, IP_ICMP = 6, 17, 1
SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04

MAC_ROUTER   = "aa:bb:cc:00:00:01"
MAC_VICTIMA  = "00:0c:29:1a:2b:3c"   # VMware
MAC_PORTATIL = "b8:27:eb:aa:bb:cc"   # Raspberry Pi
MAC_ATACANTE = "de:ad:be:ef:00:99"

IP_ROUTER   = "192.168.1.1"
IP_VICTIMA  = "192.168.1.50"
IP_PORTATIL = "192.168.1.51"
IP_ATACANTE = "192.168.1.66"
IP_WEB      = "93.184.216.34"
IP_C2       = "45.33.32.156"
IP_DNS      = "192.168.1.1"


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def checksum(datos: bytes) -> int:
    if len(datos) % 2:
        datos += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(datos) // 2), datos))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def eth(src: str, dst: str, tipo: int, carga: bytes) -> bytes:
    return mac_bytes(dst) + mac_bytes(src) + struct.pack("!H", tipo) + carga


def ipv4(src: str, dst: str, proto: int, carga: bytes, ttl: int = 64,
         ident: int = 0) -> bytes:
    total = 20 + len(carga)
    cab = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000,
                      ttl, proto, 0, ip_bytes(src), ip_bytes(dst))
    cks = checksum(cab)
    cab = cab[:10] + struct.pack("!H", cks) + cab[12:]
    return cab + carga


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
        carga: bytes = b"", window: int = 64240, opciones: bytes = b"") -> bytes:
    if opciones and len(opciones) % 4:
        opciones += b"\x00" * (4 - len(opciones) % 4)
    offset = (20 + len(opciones)) // 4
    return (struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                        offset << 4, flags, window, 0, 0) + opciones + carga)


def udp(sport: int, dport: int, carga: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(carga), 0) + carga


# Opciones TCP tipicas de cada sistema, para que el fingerprinting acierte.
OPTS_WINDOWS = bytes([2, 4, 0x05, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2])          # mss,nop,ws,nop,nop,sack
OPTS_LINUX   = bytes([2, 4, 0x05, 0xB4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7])
OPTS_NMAP    = bytes([2, 4, 0x05, 0xB4])                                   # solo mss


class Escritor:
    """Escribe un fichero .pcap classic little-endian."""

    def __init__(self, ruta: str, ts_inicial: float = 1770000000.0):
        self.fh = open(ruta, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.ts = ts_inicial

    def escribir(self, trama: bytes, avance: float = 0.001) -> None:
        self.ts += avance
        seg = int(self.ts)
        usec = int((self.ts - seg) * 1_000_000)
        self.fh.write(struct.pack("<IIII", seg, usec, len(trama), len(trama)))
        self.fh.write(trama)

    def close(self):
        self.fh.close()


# ──────────────────────────────────────────────────────
# Constructores de escenas
# ──────────────────────────────────────────────────────
def sesion_http(w, mac_cli, ip_cli, ip_srv, sport, peticion: bytes,
                respuesta: bytes, opts=OPTS_WINDOWS, ttl=128, mac_srv=MAC_ROUTER):
    """Handshake + peticion + respuesta + cierre de una conexion HTTP."""
    seq_c, seq_s = 1000, 5000
    w.escribir(eth(mac_cli, mac_srv, ETH_IPV4,
                   ipv4(ip_cli, ip_srv, IP_TCP,
                        tcp(sport, 80, seq_c, 0, SYN, opciones=opts), ttl=ttl)))
    w.escribir(eth(mac_srv, mac_cli, ETH_IPV4,
                   ipv4(ip_srv, ip_cli, IP_TCP,
                        tcp(80, sport, seq_s, seq_c + 1, SYN | ACK, opciones=OPTS_LINUX), ttl=54)))
    w.escribir(eth(mac_cli, mac_srv, ETH_IPV4,
                   ipv4(ip_cli, ip_srv, IP_TCP,
                        tcp(sport, 80, seq_c + 1, seq_s + 1, ACK), ttl=ttl)))

    w.escribir(eth(mac_cli, mac_srv, ETH_IPV4,
                   ipv4(ip_cli, ip_srv, IP_TCP,
                        tcp(sport, 80, seq_c + 1, seq_s + 1, PSH | ACK, peticion), ttl=ttl)))

    # La respuesta se parte en segmentos para ejercitar el reensamblado.
    seq = seq_s + 1
    for i in range(0, len(respuesta), 1400):
        trozo = respuesta[i:i + 1400]
        w.escribir(eth(mac_srv, mac_cli, ETH_IPV4,
                       ipv4(ip_srv, ip_cli, IP_TCP,
                            tcp(80, sport, seq, seq_c + 1 + len(peticion), PSH | ACK, trozo),
                            ttl=54)))
        seq += len(trozo)

    w.escribir(eth(mac_cli, mac_srv, ETH_IPV4,
                   ipv4(ip_cli, ip_srv, IP_TCP,
                        tcp(sport, 80, seq_c + 1 + len(peticion), seq, FIN | ACK), ttl=ttl)))


def nombre_dns(nombre: str) -> bytes:
    salida = b""
    for etiqueta in nombre.split("."):
        salida += bytes([len(etiqueta)]) + etiqueta.encode()
    return salida + b"\x00"


def consulta_dns(w, ip_cli, mac_cli, nombre: str, txid: int, ip_resuelta=None):
    pregunta = nombre_dns(nombre) + struct.pack("!HH", 1, 1)
    w.escribir(eth(mac_cli, MAC_ROUTER, ETH_IPV4,
                   ipv4(ip_cli, IP_DNS, IP_UDP,
                        udp(53000 + (txid % 1000), 53,
                            struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + pregunta))))
    if ip_resuelta:
        respuesta = (struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + pregunta
                     + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip_bytes(ip_resuelta))
        w.escribir(eth(MAC_ROUTER, mac_cli, ETH_IPV4,
                       ipv4(IP_DNS, ip_cli, IP_UDP, udp(53, 53000 + (txid % 1000), respuesta))))


def client_hello_tls(sni: str) -> bytes:
    """Construye un ClientHello TLS 1.2 minimo pero valido."""
    sni_b = sni.encode()
    ext_sni = (struct.pack("!HH", 0x0000, len(sni_b) + 5)
               + struct.pack("!HBH", len(sni_b) + 3, 0, len(sni_b)) + sni_b)
    curvas = struct.pack("!HHH", 0x000A, 8, 6) + struct.pack("!HHH", 0x001D, 0x0017, 0x0018)
    formatos = struct.pack("!HH", 0x000B, 2) + b"\x01\x00"
    alpn_p = b"\x02h2\x08http/1.1"
    alpn = struct.pack("!HHH", 0x0010, len(alpn_p) + 2, len(alpn_p)) + alpn_p
    extensiones = ext_sni + curvas + formatos + alpn

    ciphers = struct.pack("!HHHH", 0x1301, 0xC02F, 0xC030, 0x002F)   # incluye una debil
    cuerpo = (struct.pack("!H", 0x0303) + b"\xAB" * 32 + b"\x00"
              + struct.pack("!H", len(ciphers)) + ciphers
              + b"\x01\x00"
              + struct.pack("!H", len(extensiones)) + extensiones)
    handshake = b"\x01" + len(cuerpo).to_bytes(3, "big") + cuerpo
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def generar(ruta: str) -> str:
    w = Escritor(ruta)

    # ── 1. ARP inicial: la red se descubre ────────────
    for ip, mac in ((IP_VICTIMA, MAC_VICTIMA), (IP_PORTATIL, MAC_PORTATIL)):
        arp = struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, 1) + mac_bytes(mac) + ip_bytes(ip) \
            + b"\x00" * 6 + ip_bytes(IP_ROUTER)
        w.escribir(eth(mac, "ff:ff:ff:ff:ff:ff", ETH_ARP, arp))
        arp_r = struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, 2) + mac_bytes(MAC_ROUTER) \
            + ip_bytes(IP_ROUTER) + mac_bytes(mac) + ip_bytes(ip)
        w.escribir(eth(MAC_ROUTER, mac, ETH_ARP, arp_r))

    # ── 2. DHCP: el portatil pide IP (huella de Windows) ──
    opciones = (b"\x63\x82\x53\x63"
                + b"\x35\x01\x01"                       # DHCP DISCOVER
                + b"\x0c\x08" + b"PC-JUANA"             # hostname
                + b"\x3c\x08" + b"MSFT 5.0"             # vendor class
                + b"\x37\x0e" + bytes([1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252])
                + b"\xff")
    bootp = (b"\x01\x01\x06\x00" + struct.pack("!I", 0x12345678) + b"\x00" * 8
             + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 4
             + mac_bytes(MAC_VICTIMA) + b"\x00" * 10 + b"\x00" * 192 + opciones)
    w.escribir(eth(MAC_VICTIMA, "ff:ff:ff:ff:ff:ff", ETH_IPV4,
                   ipv4("0.0.0.0", "255.255.255.255", IP_UDP, udp(68, 67, bootp))))

    # ── 3. DNS normal + uno con pinta de DGA ──────────
    consulta_dns(w, IP_VICTIMA, MAC_VICTIMA, "www.ejemplo.com", 0x1001, IP_WEB)
    consulta_dns(w, IP_VICTIMA, MAC_VICTIMA, "cdn.ejemplo.com", 0x1002, IP_WEB)
    consulta_dns(w, IP_VICTIMA, MAC_VICTIMA,
                 "xkqjvbzmrtwfpldhgncs.biz", 0x1003, IP_C2)
    consulta_dns(w, IP_VICTIMA, MAC_VICTIMA,
                 "aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbHRyYXRpb24gZGF0YQ.tunel.example.org",
                 0x1004)

    # ── 4. Navegacion HTTP normal ─────────────────────
    peticion = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: www.ejemplo.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        b"(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36\r\n"
        b"Accept: text/html\r\n"
        b"Cookie: sessionid=a1b2c3d4e5f6a7b8c9d0e1f2\r\n\r\n"
    )
    cuerpo = b"<!DOCTYPE html><html><body><h1>Hola</h1></body></html>"
    respuesta = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
                 b"Content-Type: text/html; charset=utf-8\r\n"
                 + f"Content-Length: {len(cuerpo)}\r\n\r\n".encode() + cuerpo)
    sesion_http(w, MAC_VICTIMA, IP_VICTIMA, IP_WEB, 49152, peticion, respuesta)

    # ── 5. Descarga de un EXE disfrazado de JPG ───────
    exe_falso = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + os.urandom(2048)
    peticion2 = (b"GET /descargas/vacaciones.jpg HTTP/1.1\r\n"
                 b"Host: cdn.ejemplo.com\r\n"
                 b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0\r\n\r\n")
    respuesta2 = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
                  b"Content-Type: image/jpeg\r\n"
                  + f"Content-Length: {len(exe_falso)}\r\n\r\n".encode() + exe_falso)
    sesion_http(w, MAC_VICTIMA, IP_VICTIMA, IP_WEB, 49153, peticion2, respuesta2)

    # ── 6. API con token y clave AWS filtrados ────────
    json_cuerpo = (b'{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE",'
                   b'"user":"jsmith","note":"despliegue"}')
    peticion3 = (b"POST /api/v1/deploy HTTP/1.1\r\n"
                 b"Host: api.interna.local\r\n"
                 b"User-Agent: python-requests/2.31.0\r\n"
                 b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                 b"eyJzdWIiOiJqc21pdGgiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE5OTk5OTk5OTl9."
                 b"dQw4w9WgXcQdQw4w9WgXcQdQw4w9WgXcQ\r\n"
                 b"Content-Type: application/json\r\n"
                 + f"Content-Length: {len(json_cuerpo)}\r\n\r\n".encode() + json_cuerpo)
    respuesta3 = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"
    sesion_http(w, MAC_PORTATIL, IP_PORTATIL, IP_WEB, 49154, peticion3, respuesta3,
                opts=OPTS_LINUX, ttl=64)

    # ── 7. Login por formulario HTTP sin cifrar ───────
    formulario = b"username=admin&password=Verano2026!&submit=Entrar"
    peticion4 = (b"POST /login.php HTTP/1.1\r\n"
                 b"Host: intranet.local\r\n"
                 b"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/122.0\r\n"
                 b"Content-Type: application/x-www-form-urlencoded\r\n"
                 + f"Content-Length: {len(formulario)}\r\n\r\n".encode() + formulario)
    respuesta4 = b"HTTP/1.1 302 Found\r\nLocation: /panel\r\nContent-Length: 0\r\n\r\n"
    sesion_http(w, MAC_PORTATIL, IP_PORTATIL, IP_ROUTER, 49155, peticion4, respuesta4,
                opts=OPTS_LINUX, ttl=64)

    # ── 8. Login FTP en claro ─────────────────────────
    seq_c, seq_s = 2000, 7000
    w.escribir(eth(MAC_VICTIMA, MAC_ROUTER, ETH_IPV4,
                   ipv4(IP_VICTIMA, IP_ROUTER, IP_TCP,
                        tcp(49160, 21, seq_c, 0, SYN, opciones=OPTS_WINDOWS), ttl=128)))
    w.escribir(eth(MAC_ROUTER, MAC_VICTIMA, ETH_IPV4,
                   ipv4(IP_ROUTER, IP_VICTIMA, IP_TCP,
                        tcp(21, 49160, seq_s, seq_c + 1, SYN | ACK, opciones=OPTS_LINUX))))
    banner = b"220 (vsFTPd 3.0.5) Servidor de copias\r\n"
    w.escribir(eth(MAC_ROUTER, MAC_VICTIMA, ETH_IPV4,
                   ipv4(IP_ROUTER, IP_VICTIMA, IP_TCP,
                        tcp(21, 49160, seq_s + 1, seq_c + 1, PSH | ACK, banner))))
    comandos = b"USER backup\r\nPASS C0p1as2026\r\nRETR nominas_2026.xlsx\r\nQUIT\r\n"
    w.escribir(eth(MAC_VICTIMA, MAC_ROUTER, ETH_IPV4,
                   ipv4(IP_VICTIMA, IP_ROUTER, IP_TCP,
                        tcp(49160, 21, seq_c + 1, seq_s + 1 + len(banner), PSH | ACK, comandos),
                        ttl=128)))

    # ── 9. Handshake TLS con SNI ──────────────────────
    hello = client_hello_tls("banca.ejemplo.com")
    seq_c, seq_s = 3000, 9000
    w.escribir(eth(MAC_VICTIMA, MAC_ROUTER, ETH_IPV4,
                   ipv4(IP_VICTIMA, IP_WEB, IP_TCP,
                        tcp(49170, 443, seq_c, 0, SYN, opciones=OPTS_WINDOWS), ttl=128)))
    w.escribir(eth(MAC_ROUTER, MAC_VICTIMA, ETH_IPV4,
                   ipv4(IP_WEB, IP_VICTIMA, IP_TCP,
                        tcp(443, 49170, seq_s, seq_c + 1, SYN | ACK, opciones=OPTS_LINUX))))
    w.escribir(eth(MAC_VICTIMA, MAC_ROUTER, ETH_IPV4,
                   ipv4(IP_VICTIMA, IP_WEB, IP_TCP,
                        tcp(49170, 443, seq_c + 1, seq_s + 1, PSH | ACK, hello), ttl=128)))

    # ── 10. Escaneo de puertos desde el atacante ──────
    for puerto in (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                   993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443):
        w.escribir(eth(MAC_ATACANTE, MAC_VICTIMA, ETH_IPV4,
                       ipv4(IP_ATACANTE, IP_VICTIMA, IP_TCP,
                            tcp(40000 + puerto, puerto, 100, 0, SYN,
                                window=1024, opciones=OPTS_NMAP), ttl=64)),
                   avance=0.02)
        w.escribir(eth(MAC_VICTIMA, MAC_ATACANTE, ETH_IPV4,
                       ipv4(IP_VICTIMA, IP_ATACANTE, IP_TCP,
                            tcp(puerto, 40000 + puerto, 0, 101, RST | ACK), ttl=128)),
                   avance=0.001)

    # ── 11. Beaconing regular hacia un C2 ─────────────
    for i in range(14):
        w.escribir(eth(MAC_VICTIMA, MAC_ROUTER, ETH_IPV4,
                       ipv4(IP_VICTIMA, IP_C2, IP_TCP,
                            tcp(50000 + i, 8443, 500 + i, 0, SYN, opciones=OPTS_WINDOWS),
                            ttl=128)),
                   avance=30.0)
        w.escribir(eth(MAC_ROUTER, MAC_VICTIMA, ETH_IPV4,
                       ipv4(IP_C2, IP_VICTIMA, IP_TCP,
                            tcp(8443, 50000 + i, 900, 501 + i, SYN | ACK, opciones=OPTS_LINUX))),
                   avance=0.05)

    # ── 12. ARP spoofing del atacante ─────────────────
    for _ in range(4):
        arp = (struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, 2)
               + mac_bytes(MAC_ATACANTE) + ip_bytes(IP_ROUTER)
               + mac_bytes(MAC_VICTIMA) + ip_bytes(IP_VICTIMA))
        w.escribir(eth(MAC_ATACANTE, MAC_VICTIMA, ETH_ARP, arp), avance=1.0)

    # ── 13. Telnet a un equipo de red ─────────────────
    seq_c, seq_s = 4000, 11000
    w.escribir(eth(MAC_ATACANTE, MAC_ROUTER, ETH_IPV4,
                   ipv4(IP_ATACANTE, IP_ROUTER, IP_TCP,
                        tcp(49180, 23, seq_c, 0, SYN, opciones=OPTS_LINUX), ttl=64)))
    w.escribir(eth(MAC_ROUTER, MAC_ATACANTE, ETH_IPV4,
                   ipv4(IP_ROUTER, IP_ATACANTE, IP_TCP,
                        tcp(23, 49180, seq_s, seq_c + 1, SYN | ACK, opciones=OPTS_LINUX))))
    eco = (b"\r\nRouter login: admin\r\nPassword: \r\n"
           b"router> show running-config\r\nrouter> enable\r\n")
    w.escribir(eth(MAC_ROUTER, MAC_ATACANTE, ETH_IPV4,
                   ipv4(IP_ROUTER, IP_ATACANTE, IP_TCP,
                        tcp(23, 49180, seq_s + 1, seq_c + 1, PSH | ACK, eco))))
    w.escribir(eth(MAC_ATACANTE, MAC_ROUTER, ETH_IPV4,
                   ipv4(IP_ATACANTE, IP_ROUTER, IP_TCP,
                        tcp(49180, 23, seq_c + 1, seq_s + 1 + len(eco), PSH | ACK,
                            b"admin\r\nCisco123\r\nshow running-config\r\n"), ttl=64)))

    # ── 14. Transferencia grande (posible exfiltracion) ──
    seq = 20000
    for i in range(60):
        relleno = os.urandom(1400)
        w.escribir(eth(MAC_VICTIMA, MAC_ROUTER, ETH_IPV4,
                       ipv4(IP_VICTIMA, IP_C2, IP_TCP,
                            tcp(51000, 8443, seq, 1, PSH | ACK, relleno), ttl=128)),
                   avance=0.01)
        seq += len(relleno)

    w.close()
    return ruta


if __name__ == "__main__":
    destino = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "sample_pcaps", "demo.pcap")
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    ruta = generar(destino)
    print(f"Captura de demostracion generada: {ruta} ({os.path.getsize(ruta):,} bytes)")
