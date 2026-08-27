#!/usr/bin/env python3
"""
tests/test_lookingtheshark.py — Bateria de pruebas de LookingTheShark.

No necesita pytest ni ninguna dependencia externa: se ejecuta directamente.

    python tests/test_lookingtheshark.py

Cubre tres niveles:
  1. Unidades   parsers y utilidades por separado, con datos construidos a mano
  2. Motor      analisis completo de una captura sintetica de extremo a extremo
  3. Deteccion  que cada detector encuentre lo que la captura de prueba esconde
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import traceback

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)
sys.path.insert(0, os.path.join(RAIZ, "tests"))

from core import carving, dns as dnsmod, decoders, fingerprint, http as httpmod
from core import pcap_reader, secrets as secretsmod, services, tls as tlsmod
from core.session import Analisis
from core.streams import Reensamblador
from modules import formatear_bytes, formatear_duracion, ordenar_hallazgos

_fallos = []
_pasados = 0


def comprobar(condicion, descripcion: str) -> None:
    global _pasados
    if condicion:
        _pasados += 1
        print(f"  \033[32m✔\033[0m {descripcion}")
    else:
        _fallos.append(descripcion)
        print(f"  \033[31m✘ {descripcion}\033[0m")


def seccion(titulo: str) -> None:
    print(f"\n\033[1m{titulo}\033[0m")


# ══════════════════════════════════════════════════════
# 1. Unidades
# ══════════════════════════════════════════════════════
def test_lector_pcap():
    seccion("Lector de capturas")

    with tempfile.TemporaryDirectory() as tmp:
        # pcap clasico little-endian con un paquete minimo.
        ruta = os.path.join(tmp, "min.pcap")
        with open(ruta, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            carga = b"\xaa" * 60
            fh.write(struct.pack("<IIII", 1700000000, 500000, len(carga), len(carga)))
            fh.write(carga)

        comprobar(pcap_reader.es_captura(ruta), "reconoce un pcap valido")
        with pcap_reader.abrir_captura(ruta) as cap:
            paquetes = list(cap)
        comprobar(len(paquetes) == 1, "lee el unico paquete del fichero")
        comprobar(abs(paquetes[0].ts - 1700000000.5) < 1e-6,
                  "reconstruye el timestamp con la fraccion correcta")

        # Big endian: mismo contenido, orden de bytes invertido.
        ruta_be = os.path.join(tmp, "be.pcap")
        with open(ruta_be, "wb") as fh:
            fh.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            fh.write(struct.pack(">IIII", 1700000000, 0, 4, 4))
            fh.write(b"test")
        with pcap_reader.abrir_captura(ruta_be) as cap:
            comprobar(len(list(cap)) == 1, "lee un pcap en big endian")

        # Un fichero que no es una captura tiene que fallar con un mensaje claro.
        basura = os.path.join(tmp, "basura.bin")
        with open(basura, "wb") as fh:
            fh.write(b"esto no es una captura")
        comprobar(not pcap_reader.es_captura(basura), "rechaza un fichero cualquiera")
        try:
            pcap_reader.abrir_captura(basura)
            comprobar(False, "lanza CapturaInvalida ante un fichero no valido")
        except pcap_reader.CapturaInvalida:
            comprobar(True, "lanza CapturaInvalida ante un fichero no valido")

        # Un pcap vacio (solo cabecera) no debe romper nada.
        vacio = os.path.join(tmp, "vacio.pcap")
        with open(vacio, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        with pcap_reader.abrir_captura(vacio) as cap:
            comprobar(list(cap) == [], "un pcap sin paquetes devuelve una lista vacia")

        # Captura truncada a mitad de paquete: se cede lo que haya, sin excepcion.
        truncada = os.path.join(tmp, "truncada.pcap")
        with open(truncada, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            fh.write(struct.pack("<IIII", 1700000000, 0, 100, 100))
            fh.write(b"solo veinte bytes.")
        with pcap_reader.abrir_captura(truncada) as cap:
            comprobar(len(list(cap)) <= 1, "tolera una captura cortada a la mitad")


def test_disectores():
    seccion("Disectores de paquetes")

    class Crudo:
        def __init__(self, data, linktype=1):
            self.num, self.ts, self.caplen = 1, 0.0, len(data)
            self.origlen, self.linktype, self.data = len(data), linktype, data

    # Ethernet + IPv4 + TCP con opciones.
    eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 60, 1, 0x4000, 64, 6, 0,
                     bytes([192, 168, 1, 10]), bytes([93, 184, 216, 34]))
    opts = bytes([2, 4, 0x05, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2])
    tcp = struct.pack("!HHIIBBHHH", 54321, 443, 1000, 0, 8 << 4, 0x02, 64240, 0, 0) + opts
    pkt = decoders.decodificar(Crudo(eth + ip + tcp))

    comprobar(pkt.src == "192.168.1.10" and pkt.dst == "93.184.216.34",
              "extrae las direcciones IPv4")
    comprobar(pkt.sport == 54321 and pkt.dport == 443, "extrae los puertos TCP")
    comprobar(pkt.tcp_flags == 0x02, "detecta el flag SYN")
    comprobar(pkt.eth_src == "66:77:88:99:aa:bb", "extrae la MAC de origen")
    comprobar(pkt.ttl == 64 and pkt.ip_df, "lee el TTL y el bit Don't Fragment")

    # IPv6 + UDP.
    eth6 = bytes(6) + bytes(6) + b"\x86\xdd"
    ipv6 = struct.pack("!IHBB", 0x60000000, 8, 17, 64) + bytes(16) + bytes(15) + b"\x01"
    udp = struct.pack("!HHHH", 5000, 53, 8, 0)
    pkt6 = decoders.decodificar(Crudo(eth6 + ipv6 + udp))
    comprobar(pkt6.ip_version == 6 and pkt6.dport == 53, "disecta IPv6 con UDP")

    # VLAN 802.1Q: la cabecera IP va 4 bytes mas adelante.
    ethv = bytes(6) + bytes(6) + b"\x81\x00" + struct.pack("!HH", 0x0064, 0x0800)
    pktv = decoders.decodificar(Crudo(ethv + ip + tcp))
    comprobar(pktv.vlan == 100 and pktv.src == "192.168.1.10",
              "atraviesa una etiqueta VLAN")

    # ARP.
    arp = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
           + bytes.fromhex("aabbccddeeff") + bytes([192, 168, 1, 1])
           + bytes(6) + bytes([192, 168, 1, 50]))
    pkta = decoders.decodificar(Crudo(bytes(6) + bytes(6) + b"\x08\x06" + arp))
    comprobar(pkta.tipo_l3 == "arp" and pkta.arp_src_ip == "192.168.1.1",
              "disecta una respuesta ARP")

    # Un paquete truncado no debe lanzar excepcion.
    corto = decoders.decodificar(Crudo(b"\x00\x01\x02"))
    comprobar(corto.malformado, "marca como malformado un paquete demasiado corto")


def test_dns():
    seccion("Parser DNS")

    def nombre(n):
        return b"".join(bytes([len(e)]) + e.encode() for e in n.split(".")) + b"\x00"

    pregunta = nombre("www.ejemplo.com") + struct.pack("!HH", 1, 1)
    consulta = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + pregunta
    msg = dnsmod.parsear(consulta)
    comprobar(msg is not None and msg.nombre_consultado == "www.ejemplo.com",
              "lee el nombre de una consulta")
    comprobar(not msg.es_respuesta and msg.tipo_consultado == "A",
              "distingue consulta de respuesta y lee el tipo")

    # Respuesta con puntero de compresion (0xC00C apunta al nombre inicial).
    respuesta = (struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + pregunta
                 + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4)
                 + bytes([93, 184, 216, 34]))
    msg2 = dnsmod.parsear(respuesta)
    comprobar(msg2.es_respuesta and msg2.ips_resueltas() == ["93.184.216.34"],
              "resuelve una respuesta A con compresion de nombres")

    # Un puntero que apunta a si mismo no debe colgar el parser.
    bucle = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    comprobar(dnsmod.parsear(bucle) is not None,
              "sobrevive a un bucle de punteros de compresion")
    comprobar(dnsmod.parsear(b"\x00\x01") is None,
              "descarta datos que no son DNS")


def test_tls():
    seccion("Parser TLS y JA3")

    sni = b"ejemplo.com"
    ext_sni = (struct.pack("!HH", 0, len(sni) + 5)
               + struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni)
    curvas = struct.pack("!HHH", 0x000A, 4, 2) + struct.pack("!H", 0x001D)
    formatos = struct.pack("!HH", 0x000B, 2) + b"\x01\x00"
    exts = ext_sni + curvas + formatos
    ciphers = struct.pack("!HH", 0x1301, 0xC02F)
    cuerpo = (struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00"
              + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00"
              + struct.pack("!H", len(exts)) + exts)

    hello = tlsmod.parsear_client_hello(cuerpo)
    comprobar(hello is not None and hello.sni == "ejemplo.com", "extrae el SNI")
    comprobar(len(hello.ja3) == 32, "calcula un hash JA3 de 32 caracteres")
    comprobar(hello.ciphers == [0x1301, 0xC02F], "lee la lista de suites")

    # El JA3 tiene que ser estable: mismo ClientHello, mismo hash.
    comprobar(tlsmod.parsear_client_hello(cuerpo).ja3 == hello.ja3,
              "el JA3 es determinista")

    # Los valores GREASE se excluyen o el JA3 cambiaria en cada conexion.
    ciphers_grease = struct.pack("!HHH", 0x0A0A, 0x1301, 0xC02F)
    cuerpo_g = (struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00"
                + struct.pack("!H", len(ciphers_grease)) + ciphers_grease + b"\x01\x00"
                + struct.pack("!H", len(exts)) + exts)
    comprobar(tlsmod.parsear_client_hello(cuerpo_g).ja3 == hello.ja3,
              "los valores GREASE no alteran el JA3")

    handshake = b"\x01" + len(cuerpo).to_bytes(3, "big") + cuerpo
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    comprobar(tlsmod.parece_tls(record), "reconoce un record TLS")
    tipos = [t for t, _ in tlsmod.iterar_handshakes(record)]
    comprobar(tipos == [tlsmod.HS_CLIENT_HELLO], "itera los handshakes de un flujo")


def test_http():
    seccion("Parser HTTP")

    class Sentido:
        def __init__(self, datos):
            self.datos = bytearray(datos)
            self.primer_ts = 1.0

    class Flujo:
        id = 1
        cliente_ip, cliente_puerto = "10.0.0.5", 40000
        servidor_ip, servidor_puerto = "10.0.0.9", 80
        primer_ts = 1.0

        def __init__(self, pet, resp):
            self.cliente = Sentido(pet)
            self.servidor = Sentido(resp)

    cuerpo = b'{"ok":true}'
    peticion = (b"POST /api/login HTTP/1.1\r\nHost: sitio.local\r\n"
                b"User-Agent: curl/8.4.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: 30\r\n\r\nusername=ana&password=Secreta1")
    respuesta = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\n"
                 + f"Content-Length: {len(cuerpo)}\r\n\r\n".encode() + cuerpo)

    trs = httpmod.extraer_transacciones(Flujo(peticion, respuesta))
    comprobar(len(trs) == 1, "empareja una peticion con su respuesta")
    t = trs[0]
    comprobar(t.metodo == "POST" and t.ruta == "/api/login", "lee metodo y ruta")
    comprobar(t.host == "sitio.local" and t.codigo == 200, "lee Host y codigo de estado")
    comprobar(dict(t.campos_formulario).get("password") == "Secreta1",
              "descompone los campos del formulario")
    comprobar(t.url == "http://sitio.local/api/login", "reconstruye la URL completa")

    # Transfer-Encoding: chunked.
    chunked = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"5\r\nHola \r\n6\r\nmundo!\r\n0\r\n\r\n")
    tr = httpmod.extraer_transacciones(Flujo(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", chunked))
    comprobar(tr and tr[0].cuerpo_respuesta == b"Hola mundo!",
              "decodifica un cuerpo con Transfer-Encoding: chunked")

    # Varias peticiones en la misma conexion (keep-alive).
    dobles = (b"GET /uno HTTP/1.1\r\nHost: x\r\n\r\nGET /dos HTTP/1.1\r\nHost: x\r\n\r\n")
    respuestas = (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"
                  b"HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nB")
    varias = httpmod.extraer_transacciones(Flujo(dobles, respuestas))
    comprobar(len(varias) == 2 and varias[1].codigo == 404,
              "empareja varias transacciones en una conexion keep-alive")

    # Cuerpo comprimido con gzip.
    import gzip as _gz
    comprimido = _gz.compress(b"contenido descomprimido")
    resp_gz = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
               + f"Content-Length: {len(comprimido)}\r\n\r\n".encode() + comprimido)
    tg = httpmod.extraer_transacciones(Flujo(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", resp_gz))
    comprobar(tg and b"descomprimido" in tg[0].cuerpo_respuesta,
              "descomprime un cuerpo con Content-Encoding: gzip")


def test_reensamblado():
    seccion("Reensamblado TCP")

    class Pkt:
        def __init__(self, src, sport, dst, dport, seq, flags, payload=b"", ts=1.0):
            self.src, self.sport, self.dst, self.dport = src, sport, dst, dport
            self.seq, self.tcp_flags, self.payload = seq, flags, payload
            self.payload_len, self.ts, self.num = len(payload), ts, 1
            self.ack = self.window = 0
            self.tcp_opts = b""
            self.ip_df = False
            self.ttl = 64

    r = Reensamblador()
    r.agregar(Pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100, 0x02))          # SYN
    r.agregar(Pkt("10.0.0.2", 80, "10.0.0.1", 5000, 500, 0x12))          # SYN/ACK
    r.agregar(Pkt("10.0.0.1", 5000, "10.0.0.2", 80, 101, 0x18, b"GET "))
    r.agregar(Pkt("10.0.0.1", 5000, "10.0.0.2", 80, 105, 0x18, b"/ HTTP/1.1"))

    flujo = next(iter(r.flujos.values()))
    comprobar(bytes(flujo.cliente.datos) == b"GET / HTTP/1.1",
              "reensambla segmentos en orden")
    comprobar(flujo.handshake_completo, "detecta el handshake de tres vias")
    comprobar(flujo.cliente_ip == "10.0.0.1", "identifica quien es el cliente")

    # Segmentos desordenados: llega antes el segundo que el primero.
    r2 = Reensamblador()
    r2.agregar(Pkt("10.0.0.1", 6000, "10.0.0.2", 80, 200, 0x02))
    r2.agregar(Pkt("10.0.0.1", 6000, "10.0.0.2", 80, 206, 0x18, b"MUNDO"))
    r2.agregar(Pkt("10.0.0.1", 6000, "10.0.0.2", 80, 201, 0x18, b"HOLA "))
    f2 = next(iter(r2.flujos.values()))
    comprobar(bytes(f2.cliente.datos) == b"HOLA MUNDO",
              "ordena segmentos que llegan desordenados")

    # Una retransmision exacta no debe duplicar los datos.
    r3 = Reensamblador()
    r3.agregar(Pkt("10.0.0.1", 7000, "10.0.0.2", 80, 300, 0x02))
    r3.agregar(Pkt("10.0.0.1", 7000, "10.0.0.2", 80, 301, 0x18, b"DATO"))
    r3.agregar(Pkt("10.0.0.1", 7000, "10.0.0.2", 80, 301, 0x18, b"DATO"))
    f3 = next(iter(r3.flujos.values()))
    comprobar(bytes(f3.cliente.datos) == b"DATO", "descarta retransmisiones")

    # El techo de memoria tiene que respetarse.
    r4 = Reensamblador(max_por_sentido=100)
    r4.agregar(Pkt("10.0.0.1", 8000, "10.0.0.2", 80, 400, 0x02))
    r4.agregar(Pkt("10.0.0.1", 8000, "10.0.0.2", 80, 401, 0x18, b"X" * 500))
    f4 = next(iter(r4.flujos.values()))
    comprobar(len(f4.cliente.datos) == 100 and f4.cliente.truncado,
              "respeta el limite de memoria por sentido")


def test_fingerprint():
    seccion("Fingerprinting de sistema operativo")

    opts_win = bytes([2, 4, 0x05, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2])
    firma = fingerprint.FirmaTCP(117, 64240, opts_win)
    comprobar(firma.orden_opciones == "mss,nop,ws,nop,nop,sack",
              "lee el orden de las opciones TCP")
    comprobar(firma.ttl_inicial == 128 and firma.saltos == 11,
              "estima el TTL inicial y los saltos de red")
    resultado = fingerprint.identificar_por_tcp(firma)
    comprobar("Windows" in resultado.os, "identifica Windows por su huella TCP")

    firma_nmap = fingerprint.FirmaTCP(64, 1024, bytes([2, 4, 0x05, 0xB4]))
    comprobar("Nmap" in fingerprint.identificar_por_tcp(firma_nmap).os,
              "distingue un escaner Nmap de un sistema operativo")

    ua = fingerprint.analizar_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0")
    comprobar(ua["os"] == "Windows 10/11" and ua["cliente"].startswith("Chrome"),
              "descompone un User-Agent de navegador")
    comprobar(fingerprint.analizar_user_agent("curl/8.4.0")["automatizado"],
              "marca curl como cliente automatizado")

    dhcp = fingerprint.identificar_por_dhcp(
        "1,3,6,15,31,33,43,44,46,47,119,121,249,252")
    comprobar(dhcp and "Windows" in dhcp.os, "identifica Windows por la option 55 de DHCP")

    comprobar(fingerprint.fabricante_mac("00:50:56:11:22:33") == "VMware",
              "resuelve el fabricante a partir del OUI")
    comprobar(fingerprint.mac_es_aleatoria("de:ad:be:ef:00:01"),
              "detecta una MAC localmente administrada")


def test_secretos():
    seccion("Deteccion de material sensible")

    muestra = (b'{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE",'
               b'"password":"Sup3rS3cret!","card":"4532015112830366"}')
    hallados = {s.tipo for s in secretsmod.escanear(muestra)}
    comprobar("aws_access_key" in hallados, "detecta una clave de AWS")
    comprobar("password_field" in hallados, "detecta un campo de contrasena")
    comprobar("credit_card" in hallados, "detecta una tarjeta con Luhn valido")

    # Una tarjeta con checksum invalido no debe reportarse.
    falsa = {s.tipo for s in secretsmod.escanear(b"card: 4532015112830367")}
    comprobar("credit_card" not in falsa, "descarta tarjetas con Luhn invalido")

    # Los valores de ejemplo de la documentacion no son fugas.
    ruido = {s.tipo for s in secretsmod.escanear(b'password="changeme"')}
    comprobar("password_field" not in ruido, "ignora contrasenas de relleno conocidas")

    # El secreto nunca se imprime entero.
    s = secretsmod.escanear(b"AKIAIOSFODNN7EXAMPLE")[0]
    comprobar("IOSFODNN7" not in s.muestra and "*" in s.muestra,
              "enmascara el valor del secreto")

    clave = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"
    comprobar(any(x.tipo == "private_key" for x in secretsmod.escanear(clave)),
              "detecta una clave privada PEM")


def test_identificacion_ficheros():
    seccion("Identificacion de ficheros")

    pe = b"MZ\x90\x00" + b"\x00" * 100
    tipo, ejecutable, _ = carving.identificar(pe)
    comprobar("PE" in tipo and ejecutable, "identifica un ejecutable de Windows")

    f = carving.analizar_fichero("foto.jpg", pe, "image/jpeg")
    comprobar(f.sospechoso, "marca como sospechoso un EXE con extension .jpg")
    comprobar(len(f.sha256) == 64 and len(f.md5) == 32, "calcula los hashes")

    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    legitimo = carving.analizar_fichero("imagen.png", png, "image/png")
    comprobar(not legitimo.sospechoso, "no marca un PNG legitimo como sospechoso")

    elf = b"\x7fELF" + b"\x00" * 60
    comprobar(carving.identificar(elf)[1], "identifica un ejecutable ELF")

    # Nombre con separadores de ruta: no debe poder escapar del directorio.
    peligroso = carving.analizar_fichero("../../../etc/passwd", b"root:x:0:0", "")
    with tempfile.TemporaryDirectory() as tmp:
        destino = carving.guardar(peligroso, tmp)
        comprobar(destino and os.path.dirname(os.path.abspath(destino))
                  == os.path.abspath(tmp),
                  "un nombre con ../ no escribe fuera del directorio de salida")


def test_utilidades():
    seccion("Utilidades")

    comprobar(formatear_bytes(500) == "500 B", "formatea bytes")
    comprobar(formatear_bytes(1536) == "1.5 KB", "formatea kilobytes")
    comprobar(formatear_bytes(1536 * 1024) == "1.5 MB", "formatea megabytes")
    comprobar(formatear_duracion(3725) == "01:02:05", "formatea horas, minutos y segundos")
    comprobar(formatear_duracion(65) == "01:05", "formatea minutos y segundos")
    comprobar(services.servicio(443) == "HTTPS" and services.esta_cifrado(443),
              "conoce el puerto 443")
    comprobar(not services.esta_cifrado(23), "sabe que Telnet no va cifrado")
    comprobar(services.es_efimero(54321), "reconoce un puerto efimero")


# ══════════════════════════════════════════════════════
# 2 y 3. Motor completo y detectores
# ══════════════════════════════════════════════════════
def test_motor_completo():
    seccion("Motor completo sobre la captura de demostracion")

    from generar_pcap_demo import generar

    with tempfile.TemporaryDirectory() as tmp:
        ruta = generar(os.path.join(tmp, "demo.pcap"))
        analisis = Analisis(ruta, {}).ejecutar()

        comprobar(analisis.total_paquetes > 100, "lee todos los paquetes")
        comprobar(analisis.paquetes_malformados == 0, "ningun paquete queda ilegible")
        comprobar(len(analisis.hosts) >= 5, "construye el inventario de equipos")
        comprobar(analisis.duracion > 0, "calcula la duracion de la captura")
        comprobar(analisis.tiempo_analisis < 5.0,
                  f"termina en menos de 5 s (tardo {analisis.tiempo_analisis:.2f} s)")

        seccion("Deteccion sobre la captura de demostracion")

        # ── Sistemas operativos ───────────────────────
        so_windows = analisis.so_de("192.168.1.50")
        comprobar("Windows" in so_windows,
                  f"atribuye Windows al equipo de la victima (dijo «{so_windows}»)")
        comprobar("Nmap" in analisis.so_de("192.168.1.66"),
                  "identifica al atacante como un escaner")
        comprobar(analisis.hosts["192.168.1.50"].fabricante == "VMware",
                  "resuelve el fabricante por la MAC")

        # ── HTTP ──────────────────────────────────────
        comprobar(len(analisis.http) >= 4, "reconstruye las transacciones HTTP")
        urls = [t.url for t in analisis.http]
        comprobar(any("vacaciones.jpg" in u for u in urls),
                  "recupera la URL de la descarga")
        descarga = next(t for t in analisis.http if "vacaciones" in t.url)
        comprobar(descarga.codigo == 200 and descarga.content_type == "image/jpeg",
                  "lee el codigo y el tipo de contenido de la respuesta")

        # ── Ficheros ──────────────────────────────────
        sospechosos = analisis.ficheros_sospechosos()
        comprobar(len(sospechosos) >= 1, "detecta el fichero disfrazado")
        disfrazado = sospechosos[0]
        comprobar("PE" in disfrazado.tipo_real,
                  "sabe que el .jpg es en realidad un ejecutable")
        comprobar(len(disfrazado.sha256) == 64, "calcula el hash del fichero extraido")

        # ── Credenciales ──────────────────────────────
        protocolos = {c.protocolo for c in analisis.credenciales}
        comprobar("FTP" in protocolos, "captura el login de FTP")
        comprobar("Telnet" in protocolos, "captura el login de Telnet")
        comprobar("HTTP formulario" in protocolos, "captura el formulario de login")
        ftp = next(c for c in analisis.credenciales if c.protocolo == "FTP")
        comprobar(ftp.usuario == "backup", "lee el usuario de FTP")
        comprobar("C0p1as2026" not in ftp.password_enmascarada,
                  "no imprime la contrasena en claro")

        # ── Material sensible ─────────────────────────
        tipos = {s.tipo for s in analisis.secretos}
        comprobar("aws_access_key" in tipos, "encuentra la clave de AWS en el cuerpo")
        comprobar("jwt" in tipos, "encuentra el JWT en la cabecera Authorization")
        jwt = next(s for s in analisis.secretos if s.tipo == "jwt")
        comprobar("role=admin" in jwt.contexto, "decodifica el contenido del JWT")

        # ── TLS ───────────────────────────────────────
        comprobar(len(analisis.tls) >= 1, "detecta el handshake TLS")
        sesion = analisis.tls[0]
        comprobar(sesion.sni == "banca.ejemplo.com", "extrae el SNI")
        comprobar(len(sesion.ja3) == 32, "calcula el JA3 del cliente")
        comprobar(sesion.ciphers_debiles, "detecta la suite de cifrado debil")

        # ── DNS ───────────────────────────────────────
        dominios = set(analisis.dominios_consultados())
        comprobar(any("xkqjvbzmrtwfpldhgncs" in d for d in dominios),
                  "registra el dominio con pinta de DGA")
        comprobar(any(len(max(d.split("."), key=len)) > 45 for d in dominios),
                  "conserva el subdominio largo del tunel DNS")

        # ── Capa 2 ────────────────────────────────────
        comprobar(len(analisis.arp.get("192.168.1.1", set())) >= 2,
                  "ve dos MACs reclamando la IP del router (ARP spoofing)")
        comprobar(analisis.dhcp and analisis.dhcp[0]["hostname"] == "PC-JUANA",
                  "lee el nombre del equipo de la peticion DHCP")

        # ── Banners y comandos ────────────────────────
        comprobar(any("vsFTPd" in b["banner"] for b in analisis.banners),
                  "captura el banner del servidor FTP")
        comprobar(any("nominas" in c.comando for c in analisis.comandos),
                  "registra el fichero descargado por FTP")

        return analisis


def test_modulos_y_informes(analisis):
    seccion("Modulos e informes")

    from rich.console import Console
    import modules.report_builder as rb
    from lookingtheshark import MODULOS, ejecutar_modulos
    from ui.theme import SHARK_THEME

    # Con el tema puesto: una consola sin el haria fallar cualquier modulo que
    # use un estilo propio, y la prueba no mediria lo que cree medir.
    consola = Console(theme=SHARK_THEME, quiet=True, width=100, highlight=False)
    config = {"deep_mode": True, "mitre_mode": True, "confidence_threshold": "bajo"}
    seleccion = [m for m in MODULOS if m != "diff"]

    hallazgos = ejecutar_modulos(analisis, seleccion, config, consola)

    comprobar(len(hallazgos) > 0, f"los modulos producen hallazgos ({len(hallazgos)})")
    comprobar(any(f.severidad == "critico" for f in hallazgos),
              "hay al menos un hallazgo critico")
    comprobar(all(f.recomendacion for f in hallazgos),
              "todos los hallazgos incluyen una recomendacion")
    comprobar(all(f.descripcion for f in hallazgos),
              "todos los hallazgos explican que significan")
    comprobar(any(f.mitre_id for f in hallazgos),
              "el mapeo MITRE enriquece los hallazgos")

    ordenados = ordenar_hallazgos(hallazgos)
    comprobar(ordenados[0].severidad == "critico",
              "los hallazgos se ordenan por gravedad")

    patrones = {f.patron for f in hallazgos if f.patron}
    esperados = {"cleartext_creds", "file_transfer_mismatch", "portscan",
                 "beaconing", "arp_spoof", "dns_tunneling"}
    faltan = esperados - patrones
    comprobar(not faltan, f"se detectan los ataques de la captura de prueba"
                          + (f" (faltan: {faltan})" if faltan else ""))

    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "informe")
        rutas = rb.build_reports(hallazgos,
                                {"format": "md,html,json,csv", "output_base": base},
                                analisis)
        comprobar(len(rutas) == 4, "genera los cuatro formatos de informe")
        for ruta in rutas:
            comprobar(os.path.getsize(ruta) > 500,
                      f"el informe {os.path.splitext(ruta)[1]} tiene contenido")

        import json
        with open(base + ".json", encoding="utf-8") as fh:
            datos = json.load(fh)
        comprobar(datos["resumen"]["total"] == len(hallazgos),
                  "el JSON refleja todos los hallazgos")
        with open(base + ".html", encoding="utf-8") as fh:
            html = fh.read()
        comprobar("<!DOCTYPE html>" in html and "</html>" in html,
                  "el HTML esta bien formado")

        # Anonimizacion: no debe quedar ninguna IP real en el informe.
        base_anon = os.path.join(tmp, "anon")
        rb.build_reports(hallazgos,
                         {"format": "json", "output_base": base_anon,
                          "anonymize": True}, analisis)
        with open(base_anon + ".json", encoding="utf-8") as fh:
            datos_anon = json.load(fh)
        # Se ignora 'http', donde el User-Agent puede llevar un numero de
        # version con forma de IP ("Chrome/121.0.0.0") que no identifica a nadie.
        revisable = json.dumps({k: v for k, v in datos_anon.items() if k != "http"},
                               ensure_ascii=False)
        ips_reales = [ip for ip in analisis.hosts if ip in revisable]
        comprobar(not ips_reales and "equipo-" in revisable,
                  "la anonimizacion sustituye las IPs por alias"
                  + (f" (quedan: {ips_reales})" if ips_reales else ""))


def test_robustez():
    seccion("Robustez ante entradas rotas")

    import random
    random.seed(1234)

    with tempfile.TemporaryDirectory() as tmp:
        # Un pcap con paquetes de bytes aleatorios no debe hacer caer nada.
        ruta = os.path.join(tmp, "aleatorio.pcap")
        with open(ruta, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for _ in range(300):
                n = random.randint(1, 200)
                datos = bytes(random.getrandbits(8) for _ in range(n))
                fh.write(struct.pack("<IIII", 1700000000, 0, n, n))
                fh.write(datos)
        try:
            analisis = Analisis(ruta, {}).ejecutar()
            comprobar(analisis.total_paquetes == 300,
                      "procesa 300 paquetes de bytes aleatorios sin caerse")
        except Exception as exc:
            comprobar(False, f"cae con paquetes aleatorios: {exc}")

        # Longitudes de cabecera IP y TCP imposibles.
        ruta2 = os.path.join(tmp, "malformado.pcap")
        with open(ruta2, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            eth = bytes(12) + b"\x08\x00"
            ip_mala = struct.pack("!BBHHHBBH4s4s", 0x4F, 0, 20, 0, 0, 64, 6, 0,
                                  bytes(4), bytes(4))
            tcp_malo = struct.pack("!HHIIBBHHH", 80, 80, 0, 0, 0xF0, 0, 0, 0, 0)
            trama = eth + ip_mala + tcp_malo
            fh.write(struct.pack("<IIII", 1700000000, 0, len(trama), len(trama)))
            fh.write(trama)
        try:
            Analisis(ruta2, {}).ejecutar()
            comprobar(True, "tolera cabeceras con longitudes imposibles")
        except Exception as exc:
            comprobar(False, f"cae con cabeceras imposibles: {exc}")


def main() -> int:
    print("\n\033[1;36m  LookingTheShark — bateria de pruebas\033[0m")

    pruebas = [test_lector_pcap, test_disectores, test_dns, test_tls, test_http,
               test_reensamblado, test_fingerprint, test_secretos,
               test_identificacion_ficheros, test_utilidades, test_robustez]

    for prueba in pruebas:
        try:
            prueba()
        except Exception:
            _fallos.append(f"{prueba.__name__} lanzo una excepcion")
            print(f"  \033[31m✘ {prueba.__name__} lanzo una excepcion:\033[0m")
            traceback.print_exc()

    try:
        analisis = test_motor_completo()
        if analisis:
            test_modulos_y_informes(analisis)
    except Exception:
        _fallos.append("el motor completo lanzo una excepcion")
        traceback.print_exc()

    print()
    print("─" * 66)
    if _fallos:
        print(f"\033[31m  {len(_fallos)} prueba(s) fallidas de "
              f"{_pasados + len(_fallos)}\033[0m")
        for f in _fallos:
            print(f"    · {f}")
        print()
        return 1

    print(f"\033[32m  Las {_pasados} pruebas pasan.\033[0m")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
