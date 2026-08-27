"""
core/fingerprint.py — Identificacion pasiva de dispositivos y sistemas operativos.

El objetivo no es acertar la version exacta, es poder decir en el informe
"esta peticion la lanzo un Windows 11 desde 192.168.1.34 usando Chrome" en vez
de "hay un paquete TCP con TTL 128".

Se combinan seis fuentes independientes, cada una con su peso:

  1. TCP SYN      TTL inicial, tamano de ventana, orden de las opciones, MSS
                  y window scale (estilo p0f). Funciona con cualquier trafico.
  2. User-Agent   Exacto cuando hay HTTP en claro.
  3. DHCP         Option 55 (lista de parametros pedidos) y option 60 (vendor
                  class): identifica el SO incluso sin trafico saliente.
  4. TLS / JA3    Cliente TLS concreto (navegador, curl, herramienta, C2).
  5. mDNS/NBNS    Nombre del equipo anunciado en la red local.
  6. MAC OUI      Fabricante del interfaz (Apple, Intel, VMware, Raspberry...).

Cuando varias fuentes coinciden la confianza sube; cuando se contradicen se
reporta el conflicto, que es en si mismo un indicador (proxy, NAT, spoofing).
"""

from __future__ import annotations

import json
import os
import re
import struct
from typing import Dict, List, Optional, Tuple

from core.decoders import TCP_ACK, TCP_SYN

_DIR_DATOS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


# ──────────────────────────────────────────────────────
# 1. Fingerprint TCP (estilo p0f simplificado)
# ──────────────────────────────────────────────────────
# Opciones TCP: (kind, longitud). Nos interesa el ORDEN, que es muy estable
# por sistema operativo y muy dificil de falsificar sin tocar el kernel.
NOMBRE_OPCION = {
    0: "eol", 1: "nop", 2: "mss", 3: "ws", 4: "sack", 5: "sackblk",
    8: "ts", 28: "uto", 29: "authopt", 34: "fo",
}


def parsear_opciones_tcp(opts: bytes) -> Tuple[str, int, int, bool, bool]:
    """Devuelve (orden, mss, window_scale, tiene_sack, tiene_timestamps)."""
    orden: List[str] = []
    mss = 0
    wscale = -1
    sack = False
    ts = False

    pos = 0
    fin = len(opts)
    while pos < fin:
        kind = opts[pos]
        if kind == 0:                     # EOL
            orden.append("eol")
            break
        if kind == 1:                     # NOP
            orden.append("nop")
            pos += 1
            continue
        if pos + 1 >= fin:
            break
        largo = opts[pos + 1]
        if largo < 2 or pos + largo > fin:
            break

        nombre = NOMBRE_OPCION.get(kind, f"opt{kind}")
        orden.append(nombre)

        if kind == 2 and largo == 4:
            mss = struct.unpack_from("!H", opts, pos + 2)[0]
        elif kind == 3 and largo == 3:
            wscale = opts[pos + 2]
        elif kind == 4:
            sack = True
        elif kind == 8:
            ts = True

        pos += largo

    return (",".join(orden), mss, wscale, sack, ts)


def ttl_inicial(observado: int) -> int:
    """Estima el TTL con el que salio el paquete (32/64/128/255)."""
    for base in (32, 64, 128, 255):
        if observado <= base:
            return base
    return 255


def saltos_estimados(observado: int) -> int:
    """Numero de routers atravesados = TTL inicial - TTL observado."""
    return max(0, ttl_inicial(observado) - observado)


class FirmaTCP:
    """La huella TCP observada en un SYN."""

    __slots__ = ("ttl_obs", "ttl_inicial", "saltos", "window", "mss",
                 "wscale", "orden_opciones", "sack", "timestamps", "df")

    def __init__(self, ttl_obs=0, window=0, opts=b"", df=False):
        self.ttl_obs = ttl_obs
        self.ttl_inicial = ttl_inicial(ttl_obs) if ttl_obs else 0
        self.saltos = saltos_estimados(ttl_obs) if ttl_obs else 0
        self.window = window
        self.df = df
        (self.orden_opciones, self.mss, self.wscale,
         self.sack, self.timestamps) = parsear_opciones_tcp(opts)

    @property
    def clave(self) -> str:
        return f"{self.ttl_inicial}:{self.window}:{self.orden_opciones}"

    def __repr__(self) -> str:
        return f"<FirmaTCP ttl={self.ttl_inicial} win={self.window} opts={self.orden_opciones}>"


class ResultadoSO:
    __slots__ = ("os", "familia", "confianza", "fuente", "detalle")

    def __init__(self, os="", familia="", confianza="baja", fuente="", detalle=""):
        self.os = os
        self.familia = familia
        self.confianza = confianza
        self.fuente = fuente
        self.detalle = detalle

    def __repr__(self):
        return f"<SO {self.os} ({self.confianza}, {self.fuente})>"


_FIRMAS_TCP: List[dict] = []


def _cargar_firmas_tcp() -> List[dict]:
    global _FIRMAS_TCP
    if _FIRMAS_TCP:
        return _FIRMAS_TCP
    ruta = os.path.join(_DIR_DATOS, "os_signatures.json")
    try:
        with open(ruta, "r", encoding="utf-8") as fh:
            datos = json.load(fh)
        _FIRMAS_TCP = datos.get("tcp", datos) if isinstance(datos, dict) else datos
    except (OSError, ValueError):
        _FIRMAS_TCP = []
    return _FIRMAS_TCP


def identificar_por_tcp(firma: FirmaTCP) -> ResultadoSO:
    """Compara la huella TCP contra la base de firmas."""
    firmas = _cargar_firmas_tcp()

    # Nivel 1: TTL + ventana + orden exacto de opciones -> muy fiable.
    for sig in firmas:
        if (sig.get("ttl") == firma.ttl_inicial
                and sig.get("window") == firma.window
                and sig.get("options") == firma.orden_opciones):
            return ResultadoSO(sig["os"], sig.get("family", ""), "alta", "TCP SYN",
                               f"TTL {firma.ttl_inicial}, win {firma.window}, opts {firma.orden_opciones}")

    # Nivel 2: TTL + orden de opciones (la ventana varia con el autotuning).
    for sig in firmas:
        if (sig.get("ttl") == firma.ttl_inicial
                and sig.get("options") == firma.orden_opciones):
            return ResultadoSO(sig["os"], sig.get("family", ""), "media", "TCP SYN",
                               f"TTL {firma.ttl_inicial}, opts {firma.orden_opciones}")

    # Nivel 3: TTL + ventana.
    for sig in firmas:
        if sig.get("ttl") == firma.ttl_inicial and sig.get("window") == firma.window:
            return ResultadoSO(sig["os"], sig.get("family", ""), "media", "TCP SYN",
                               f"TTL {firma.ttl_inicial}, win {firma.window}")

    # Nivel 4: solo la familia por TTL. Generico pero casi siempre correcto.
    generico = {
        32:  ("Windows 95/98 o dispositivo antiguo", "Windows"),
        64:  ("Linux / macOS / Android / iOS", "Unix-like"),
        128: ("Windows", "Windows"),
        255: ("Equipo de red (Cisco/Juniper) o BSD/Solaris", "Red"),
    }.get(firma.ttl_inicial)

    if generico:
        # Timestamps activos + wscale alto = pila tipo Linux moderna.
        detalle = f"TTL inicial {firma.ttl_inicial}"
        if firma.ttl_inicial == 64 and firma.timestamps and firma.wscale >= 7:
            return ResultadoSO("Linux moderno (kernel 4.x+)", "Linux", "baja",
                               "TCP SYN", detalle + ", timestamps + wscale alto")
        if firma.ttl_inicial == 128 and not firma.timestamps:
            return ResultadoSO("Windows", "Windows", "baja", "TCP SYN",
                               detalle + ", sin TCP timestamps (tipico de Windows)")
        return ResultadoSO(generico[0], generico[1], "baja", "TCP SYN", detalle)

    return ResultadoSO("Desconocido", "", "baja", "TCP SYN", "")


# ──────────────────────────────────────────────────────
# 2. User-Agent
# ──────────────────────────────────────────────────────
_UA_SO = [
    (re.compile(r"Windows NT 10\.0.*?(?:Win64|WOW64|x64)?", re.I), "Windows 10/11", "Windows"),
    (re.compile(r"Windows NT 6\.3", re.I), "Windows 8.1", "Windows"),
    (re.compile(r"Windows NT 6\.2", re.I), "Windows 8", "Windows"),
    (re.compile(r"Windows NT 6\.1", re.I), "Windows 7", "Windows"),
    (re.compile(r"Windows NT 5\.1", re.I), "Windows XP", "Windows"),
    (re.compile(r"Windows Phone", re.I), "Windows Phone", "Windows"),
    (re.compile(r"Windows", re.I), "Windows", "Windows"),
    (re.compile(r"Android[ /](\d+)", re.I), "Android {0}", "Android"),
    (re.compile(r"(?:iPhone|iPad|iPod).*?OS (\d+)[_.](\d+)", re.I), "iOS {0}.{1}", "iOS"),
    (re.compile(r"CrOS", re.I), "ChromeOS", "ChromeOS"),
    (re.compile(r"Mac OS X (\d+)[_.](\d+)", re.I), "macOS {0}.{1}", "macOS"),
    (re.compile(r"Macintosh", re.I), "macOS", "macOS"),
    (re.compile(r"Ubuntu", re.I), "Ubuntu Linux", "Linux"),
    (re.compile(r"Debian", re.I), "Debian Linux", "Linux"),
    (re.compile(r"Fedora", re.I), "Fedora Linux", "Linux"),
    (re.compile(r"X11.*Linux", re.I), "Linux (escritorio)", "Linux"),
    (re.compile(r"Linux", re.I), "Linux", "Linux"),
    (re.compile(r"FreeBSD", re.I), "FreeBSD", "BSD"),
]

_UA_CLIENTE = [
    (re.compile(r"Edg(?:e|A|iOS)?/(\d+)", re.I), "Microsoft Edge {0}", "navegador"),
    (re.compile(r"OPR/(\d+)", re.I), "Opera {0}", "navegador"),
    (re.compile(r"Chrome/(\d+)", re.I), "Chrome {0}", "navegador"),
    (re.compile(r"Firefox/(\d+)", re.I), "Firefox {0}", "navegador"),
    (re.compile(r"Version/(\d+).*Safari", re.I), "Safari {0}", "navegador"),
    (re.compile(r"MSIE (\d+)", re.I), "Internet Explorer {0}", "navegador"),
    (re.compile(r"^curl/([\d.]+)", re.I), "curl {0}", "herramienta"),
    (re.compile(r"^Wget/([\d.]+)", re.I), "wget {0}", "herramienta"),
    (re.compile(r"python-requests/([\d.]+)", re.I), "python-requests {0}", "script"),
    (re.compile(r"python-urllib/?([\d.]*)", re.I), "python-urllib {0}", "script"),
    (re.compile(r"^Go-http-client/([\d.]+)", re.I), "Go net/http {0}", "script"),
    (re.compile(r"^Java/([\d.]+)", re.I), "Java {0}", "script"),
    (re.compile(r"^PowerShell/?([\d.]*)", re.I), "PowerShell {0}", "script"),
    (re.compile(r"WindowsPowerShell", re.I), "PowerShell", "script"),
    (re.compile(r"^Microsoft-CryptoAPI", re.I), "Windows CryptoAPI (CRL/OCSP)", "sistema"),
    (re.compile(r"^Microsoft BITS", re.I), "Windows BITS (descarga en segundo plano)", "sistema"),
    (re.compile(r"^Microsoft-WNS", re.I), "Windows Notification Service", "sistema"),
    (re.compile(r"^WindowsUpdateAgent|Windows-Update-Agent", re.I), "Windows Update", "sistema"),
    (re.compile(r"^apt/?|Debian APT", re.I), "APT (gestor de paquetes)", "sistema"),
    (re.compile(r"^libdnf|dnf/", re.I), "DNF (gestor de paquetes)", "sistema"),
    (re.compile(r"^Nmap", re.I), "Nmap", "escaner"),
    (re.compile(r"(?:sqlmap|nikto|dirb|gobuster|ffuf|wpscan|hydra|masscan|nuclei|feroxbuster)", re.I),
     "Herramienta ofensiva", "escaner"),
    (re.compile(r"(?:Burp|ZAP|Acunetix|Nessus|Qualys|OpenVAS)", re.I), "Escaner de seguridad", "escaner"),
    (re.compile(r"^Mozilla/4\.0 \(compatible; MSIE 7\.0", re.I), "UA generico de malware/C2", "sospechoso"),
    (re.compile(r"(?:bot|crawler|spider|slurp)", re.I), "Bot / rastreador", "bot"),
]

# User-Agents que en 2026 casi siempre significan automatizacion, no persona.
UA_NO_HUMANOS = {"herramienta", "script", "escaner", "bot", "sospechoso"}


def analizar_user_agent(ua: str) -> dict:
    """Descompone un User-Agent en SO + cliente + categoria."""
    resultado = {"os": "", "familia": "", "cliente": "", "categoria": "",
                 "automatizado": False, "raw": ua}
    if not ua:
        return resultado

    for patron, plantilla, familia in _UA_SO:
        m = patron.search(ua)
        if m:
            try:
                resultado["os"] = plantilla.format(*m.groups()) if m.groups() else plantilla
            except (IndexError, KeyError):
                resultado["os"] = plantilla
            resultado["familia"] = familia
            break

    for patron, plantilla, categoria in _UA_CLIENTE:
        m = patron.search(ua)
        if m:
            try:
                resultado["cliente"] = (plantilla.format(*m.groups()) if m.groups()
                                        else plantilla).strip()
            except (IndexError, KeyError):
                resultado["cliente"] = plantilla
            resultado["categoria"] = categoria
            break

    if not resultado["cliente"]:
        resultado["cliente"] = ua.split("/")[0][:40] or "desconocido"
        resultado["categoria"] = "desconocido"

    resultado["automatizado"] = resultado["categoria"] in UA_NO_HUMANOS
    return resultado


# ──────────────────────────────────────────────────────
# 3. DHCP (option 55 fingerprint + vendor class)
# ──────────────────────────────────────────────────────
# La lista de parametros que pide un cliente DHCP es sorprendentemente
# distintiva: cada SO pide unos y en un orden concreto.
_DHCP_FP = {
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": ("Windows 10/11", "Windows", "alta"),
    "1,15,3,6,44,46,47,31,33,121,249,43": ("Windows 7/8/10", "Windows", "alta"),
    "1,15,3,6,44,46,47,31,33,121,249,43,252": ("Windows 7/8", "Windows", "alta"),
    "1,3,6,15,119,252": ("macOS / iOS", "Apple", "alta"),
    "1,121,3,6,15,119,252,95,44,46": ("macOS", "Apple", "alta"),
    "1,3,6,15,119,78,79,95,252": ("macOS antiguo", "Apple", "media"),
    "1,3,6,12,15,28,42": ("Linux (dhclient)", "Linux", "alta"),
    "1,28,2,3,15,6,119,12,44,47,26,121,42": ("Linux (dhclient/Debian)", "Linux", "alta"),
    "1,3,6,15,26,28,51,58,59,43": ("Android", "Android", "alta"),
    "1,3,6,15,26,28,51,58,59": ("Android", "Android", "media"),
    "1,3,6,12,15,17,23,28,29,31,33,40,41,42": ("Linux (systemd-networkd)", "Linux", "media"),
    "1,3,6,15,66,67": ("Dispositivo de arranque PXE / IoT", "IoT", "media"),
    "1,3,6,12,15,28,40,41,42,26,119": ("Linux embebido / IoT", "Linux", "baja"),
}

_DHCP_VENDOR = [
    (re.compile(r"MSFT", re.I), "Windows", "Windows"),
    (re.compile(r"android-dhcp-(\d+)", re.I), "Android {0}", "Android"),
    (re.compile(r"dhcpcd", re.I), "Linux (dhcpcd)", "Linux"),
    (re.compile(r"udhcp", re.I), "Linux embebido (BusyBox)", "Linux"),
    (re.compile(r"Cisco|ciscopnp", re.I), "Equipo Cisco", "Red"),
    (re.compile(r"Ubiquiti|UBNT", re.I), "Equipo Ubiquiti", "Red"),
    (re.compile(r"HUAWEI|Honor", re.I), "Dispositivo Huawei", "Android"),
    (re.compile(r"PXEClient", re.I), "Arranque PXE", "Red"),
]


def identificar_por_dhcp(param_list: str, vendor_class: str = "",
                         hostname: str = "") -> Optional[ResultadoSO]:
    """Identifica el SO a partir de una peticion DHCP."""
    if param_list and param_list in _DHCP_FP:
        os_, familia, conf = _DHCP_FP[param_list]
        return ResultadoSO(os_, familia, conf, "DHCP option 55",
                           f"parametros pedidos: {param_list}")

    if vendor_class:
        for patron, plantilla, familia in _DHCP_VENDOR:
            m = patron.search(vendor_class)
            if m:
                nombre = plantilla.format(*m.groups()) if m.groups() else plantilla
                return ResultadoSO(nombre, familia, "media", "DHCP option 60",
                                   f"vendor class: {vendor_class[:48]}")

    if param_list:
        # Coincidencia parcial: mismo conjunto de opciones aunque en otro orden.
        pedidas = set(param_list.split(","))
        mejor, solape_max = None, 0
        for firma, (os_, familia, _c) in _DHCP_FP.items():
            solape = len(pedidas & set(firma.split(",")))
            if solape > solape_max:
                solape_max, mejor = solape, (os_, familia)
        if mejor and solape_max >= 6:
            return ResultadoSO(mejor[0], mejor[1], "baja", "DHCP option 55",
                               f"coincidencia parcial ({solape_max} opciones)")
    return None


def parsear_opciones_dhcp(payload: bytes) -> dict:
    """Extrae las opciones utiles de un paquete DHCP/BOOTP."""
    info = {"tipo": 0, "param_list": "", "vendor_class": "", "hostname": "",
            "client_mac": "", "requested_ip": "", "server_id": "", "txid": 0,
            "yiaddr": "", "client_id": ""}
    if len(payload) < 240:
        return info
    try:
        info["txid"] = struct.unpack_from("!I", payload, 4)[0]
        info["yiaddr"] = ".".join(str(b) for b in payload[16:20])
        info["client_mac"] = ":".join(f"{b:02x}" for b in payload[28:34])

        if payload[236:240] != b"\x63\x82\x53\x63":   # magic cookie DHCP
            return info

        pos = 240
        fin = len(payload)
        while pos < fin:
            codigo = payload[pos]
            if codigo == 255:
                break
            if codigo == 0:
                pos += 1
                continue
            if pos + 1 >= fin:
                break
            largo = payload[pos + 1]
            valor = payload[pos + 2:pos + 2 + largo]
            pos += 2 + largo

            if codigo == 53 and largo >= 1:
                info["tipo"] = valor[0]
            elif codigo == 55:
                info["param_list"] = ",".join(str(b) for b in valor)
            elif codigo == 60:
                info["vendor_class"] = valor.decode("utf-8", "replace")
            elif codigo == 12:
                info["hostname"] = valor.decode("utf-8", "replace")
            elif codigo == 50 and largo == 4:
                info["requested_ip"] = ".".join(str(b) for b in valor)
            elif codigo == 54 and largo == 4:
                info["server_id"] = ".".join(str(b) for b in valor)
            elif codigo == 61:
                info["client_id"] = valor.hex()
    except (struct.error, IndexError):
        pass
    return info


DHCP_TIPOS = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
              5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


# ──────────────────────────────────────────────────────
# 4. MAC OUI → fabricante
# ──────────────────────────────────────────────────────
_OUI: Dict[str, str] = {}
_OUI_CARGADO = False


def _cargar_oui() -> Dict[str, str]:
    """Carga data/oui.json. Si el usuario deja un oui.txt del IEEE, lo usa."""
    global _OUI, _OUI_CARGADO
    if _OUI_CARGADO:
        return _OUI
    _OUI_CARGADO = True

    ruta_json = os.path.join(_DIR_DATOS, "oui.json")
    try:
        with open(ruta_json, "r", encoding="utf-8") as fh:
            _OUI = {k.upper().replace("-", ":"): v for k, v in json.load(fh).items()}
    except (OSError, ValueError):
        _OUI = {}

    # Fichero completo del IEEE, opcional (no se distribuye por tamano).
    ruta_txt = os.path.join(_DIR_DATOS, "oui.txt")
    if os.path.isfile(ruta_txt):
        try:
            patron = re.compile(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$")
            with open(ruta_txt, "r", encoding="utf-8", errors="replace") as fh:
                for linea in fh:
                    m = patron.match(linea.strip())
                    if m:
                        clave = f"{m.group(1)}:{m.group(2)}:{m.group(3)}"
                        _OUI[clave] = m.group(4).strip()
        except OSError:
            pass
    return _OUI


def fabricante_mac(mac: str) -> str:
    """Devuelve el fabricante de una MAC, o '' si no se conoce."""
    if not mac or len(mac) < 8:
        return ""
    oui = _cargar_oui()
    prefijo = mac[:8].upper()

    # Bit 'locally administered': MAC generada, no asignada por el IEEE.
    try:
        primer_byte = int(mac[:2], 16)
        if primer_byte & 0x02:
            return oui.get(prefijo, "(MAC aleatoria / privacidad)")
    except ValueError:
        pass
    return oui.get(prefijo, "")


def mac_es_aleatoria(mac: str) -> bool:
    """True si la MAC tiene el bit de administracion local (privacidad WiFi)."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


# ──────────────────────────────────────────────────────
# 5. Consolidacion: perfil de dispositivo
# ──────────────────────────────────────────────────────
_PESO_FUENTE = {
    "User-Agent": 100,
    "DHCP option 55": 90,
    "DHCP option 60": 85,
    "JA3": 70,
    "TCP SYN": 60,
    "MAC OUI": 30,
}

_PESO_CONFIANZA = {"alta": 1.0, "media": 0.7, "baja": 0.4}


class PerfilDispositivo:
    """Todo lo que sabemos de un host visto en la captura."""

    __slots__ = ("ip", "macs", "fabricante", "hostnames", "candidatos_so",
                 "so", "familia", "confianza", "fuentes", "clientes",
                 "firma_tcp", "ja3", "paquetes_enviados", "paquetes_recibidos",
                 "bytes_enviados", "bytes_recibidos", "puertos_servidos",
                 "puertos_contactados", "dominios", "primer_ts", "ultimo_ts",
                 "conflicto_so", "es_local", "rol", "saltos", "user_agents")

    def __init__(self, ip: str):
        self.ip = ip
        self.macs = set()
        self.fabricante = ""
        self.hostnames = set()
        self.candidatos_so: List[ResultadoSO] = []
        self.so = ""
        self.familia = ""
        self.confianza = "baja"
        self.fuentes: List[str] = []
        self.clientes = {}                # nombre -> veces visto
        self.user_agents = {}             # UA crudo -> veces
        self.firma_tcp: Optional[FirmaTCP] = None
        self.ja3 = ""
        self.paquetes_enviados = 0
        self.paquetes_recibidos = 0
        self.bytes_enviados = 0
        self.bytes_recibidos = 0
        self.puertos_servidos = set()     # puertos donde acepta conexiones
        self.puertos_contactados = set()  # puertos a los que se conecta
        self.dominios = set()
        self.primer_ts = 0.0
        self.ultimo_ts = 0.0
        self.conflicto_so = ""
        self.es_local = False
        self.rol = ""                     # cliente | servidor | ambos
        self.saltos = 0

    def anadir_candidato(self, r: Optional[ResultadoSO]) -> None:
        if r and r.os and r.os != "Desconocido":
            self.candidatos_so.append(r)

    def consolidar(self) -> None:
        """Elige el SO mas probable ponderando fuente y confianza."""
        if not self.candidatos_so:
            self.so = "Desconocido"
            return

        puntuaciones: Dict[str, float] = {}
        mejor_por_os: Dict[str, ResultadoSO] = {}

        for c in self.candidatos_so:
            peso = _PESO_FUENTE.get(c.fuente, 40) * _PESO_CONFIANZA.get(c.confianza, 0.4)
            puntuaciones[c.os] = puntuaciones.get(c.os, 0.0) + peso
            if c.os not in mejor_por_os or _PESO_FUENTE.get(c.fuente, 0) > \
                    _PESO_FUENTE.get(mejor_por_os[c.os].fuente, 0):
                mejor_por_os[c.os] = c

        ganador = max(puntuaciones, key=puntuaciones.get)
        elegido = mejor_por_os[ganador]
        self.so = elegido.os
        self.familia = elegido.familia
        self.fuentes = sorted({c.fuente for c in self.candidatos_so if c.os == ganador})

        # Mas de una fuente independiente coincidiendo = confianza alta.
        if len(self.fuentes) >= 2:
            self.confianza = "alta"
        else:
            self.confianza = elegido.confianza

        # Familias distintas apuntando a cosas distintas: hay algo detras
        # (NAT, proxy, contenedor, o un UA falseado).
        familias = {c.familia for c in self.candidatos_so if c.familia}
        if len(familias) > 1:
            otras = sorted(familias - {self.familia})
            self.conflicto_so = (
                f"tambien hay indicios de {', '.join(otras)} desde esta IP "
                f"(NAT, proxy, contenedor o User-Agent falseado)"
            )

    @property
    def descripcion(self) -> str:
        partes = [self.so or "SO desconocido"]
        if self.fabricante:
            partes.append(f"({self.fabricante})")
        nombre = next(iter(self.hostnames), "")
        if nombre:
            partes.append(f"«{nombre}»")
        return " ".join(partes)

    def __repr__(self) -> str:
        return f"<Perfil {self.ip} {self.so}>"


def extraer_firma_syn(pkt) -> Optional[FirmaTCP]:
    """Devuelve la FirmaTCP de un SYN puro (no SYN/ACK), o None."""
    if not pkt.es_tcp:
        return None
    if not (pkt.tcp_flags & TCP_SYN) or (pkt.tcp_flags & TCP_ACK):
        return None
    return FirmaTCP(pkt.ttl, pkt.window, pkt.tcp_opts, pkt.ip_df)
