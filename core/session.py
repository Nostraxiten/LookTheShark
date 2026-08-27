"""
core/session.py — Analisis completo de una captura en UNA sola pasada.

Antes cada modulo recorria la lista entera de paquetes por su cuenta: con once
modulos activos eso eran mas de treinta recorridos sobre los mismos datos, y
todos los paquetes tenian que estar en RAM a la vez.

Ahora hay un unico recorrido en streaming que va alimentando todos los
acumuladores. Los modulos ya no leen paquetes: leen este objeto Analisis, que
llega con el trabajo hecho. El resultado es un orden de magnitud mas rapido y
memoria practicamente constante.

Fases:
  1. Recorrido    Se lee el fichero paquete a paquete: contadores, flujos,
                  DNS, DHCP, ARP, ICMP, huellas TCP y reensamblado.
  2. Protocolos   Sobre los flujos ya reensamblados: HTTP, TLS, FTP, SMTP,
                  POP3/IMAP, Telnet, IRC y banners.
  3. Contenido    Ficheros transferidos, hashes, y escaneo de secretos.
  4. Perfilado    Se consolida quien es cada host y con que sistema operativo.
"""

from __future__ import annotations

import ipaddress
import os
import time
from collections import Counter, defaultdict
from typing import Callable, Dict, List, Optional, Set, Tuple

from core import carving, dns as dnsmod, fingerprint, http as httpmod
from core import plaintext, secrets as secretsmod, services, tls as tlsmod
from core.decoders import (IP_ICMP, IP_ICMPV6, IP_TCP, IP_UDP, TCP_ACK, TCP_FIN,
                           TCP_RST, TCP_SYN, Paquete, decodificar)
from core.pcap_reader import CapturaInvalida, abrir_captura
from core.streams import Reensamblador

# Techos para que una captura enorme no se coma la RAM.
MAX_DNS_GUARDADAS = 200_000
MAX_EVENTOS_BEACON = 300_000
MAX_HTTP = 100_000
MAX_SECRETOS = 5_000
MAX_FICHEROS = 5_000
MAX_FLUJOS_DEFECTO = 200_000

# Puertos donde merece la pena reensamblar el flujo completo. El resto se
# reensambla solo hasta un limite pequeno (basta para banners y para detectar
# el protocolo), lo que ahorra muchisima memoria en capturas grandes.
PUERTOS_INTERESANTES = (
    services.PUERTOS_HTTP | services.PUERTOS_TLS | services.PUERTOS_TEXTO
    | {20, 22, 69, 139, 445, 1433, 3306, 5432, 6379, 27017, 6667, 4444, 50050}
)


class ConversacionIP:
    """Trafico agregado entre dos hosts."""

    __slots__ = ("a", "b", "paquetes", "bytes", "primer_ts", "ultimo_ts",
                 "protocolos", "puertos")

    def __init__(self, a: str, b: str, ts: float):
        self.a = a
        self.b = b
        self.paquetes = 0
        self.bytes = 0
        self.primer_ts = ts
        self.ultimo_ts = ts
        self.protocolos: Set[str] = set()
        self.puertos: Set[int] = set()

    @property
    def duracion(self) -> float:
        return max(0.0, self.ultimo_ts - self.primer_ts)


class SesionTLS:
    """Un handshake TLS observado."""

    __slots__ = ("cliente_ip", "servidor_ip", "servidor_puerto", "sni", "ja3",
                 "ja3s", "version_cliente", "version_servidor", "alpn",
                 "cipher", "certificados", "ts", "ciphers_debiles", "flujo_id")

    def __init__(self):
        self.cliente_ip = ""
        self.servidor_ip = ""
        self.servidor_puerto = 443
        self.sni = ""
        self.ja3 = ""
        self.ja3s = ""
        self.version_cliente = ""
        self.version_servidor = ""
        self.alpn: List[str] = []
        self.cipher = ""
        self.certificados: List = []
        self.ts = 0.0
        self.ciphers_debiles: List[str] = []
        self.flujo_id = 0

    @property
    def destino(self) -> str:
        return self.sni or self.servidor_ip


class EventoDNS:
    __slots__ = ("nombre", "tipo", "src", "dst", "ts", "es_respuesta",
                 "respuestas", "rcode", "transporte")

    def __init__(self):
        self.nombre = ""
        self.tipo = ""
        self.src = ""
        self.dst = ""
        self.ts = 0.0
        self.es_respuesta = False
        self.respuestas: List[str] = []
        self.rcode = "NOERROR"
        self.transporte = "UDP"


class Analisis:
    """Resultado completo del analisis de una captura."""

    def __init__(self, ruta: str, config: Optional[dict] = None):
        self.config = config or {}
        self.ruta = ruta
        self.nombre = os.path.basename(ruta)
        self.tamano_fichero = os.path.getsize(ruta) if os.path.isfile(ruta) else 0
        self.formato = ""

        # ── Metricas globales ─────────────────────────
        self.total_paquetes = 0
        self.paquetes_analizados = 0
        self.paquetes_malformados = 0
        self.bytes_totales = 0
        self.primer_ts = 0.0
        self.ultimo_ts = 0.0
        self.tiempo_analisis = 0.0
        self.truncada = False
        # Techos alcanzados durante el analisis: se avisan al usuario porque
        # significan que el informe describe una parte de la captura, no toda.
        self.limites_alcanzados: List[str] = []

        # ── Contadores ────────────────────────────────
        self.protocolos = Counter()          # capa mas alta reconocida
        self.protocolos_app = Counter()      # protocolo de aplicacion resuelto
        self.puertos_destino = Counter()
        self.puertos_origen = Counter()
        self.tamanos = Counter()             # histograma de tamanos
        self.actividad = Counter()           # segundo -> paquetes
        self.vlans = Counter()

        # ── Hosts y conversaciones ────────────────────
        self.hosts: Dict[str, fingerprint.PerfilDispositivo] = {}
        self.conversaciones: Dict[Tuple[str, str], ConversacionIP] = {}

        # ── Protocolos concretos ──────────────────────
        self.dns: List[EventoDNS] = []
        self.dhcp: List[dict] = []
        self.arp: Dict[str, Set[str]] = defaultdict(set)
        self.mac_a_ips: Dict[str, Set[str]] = defaultdict(set)
        self.gateways: Set[str] = set()
        self.arp_gratuitos: List[dict] = []
        self.icmp = Counter()
        self.icmp_eventos: List[dict] = []

        # ── Flujos ────────────────────────────────────
        self.reensamblador = Reensamblador(
            max_por_sentido=int(self.config.get("max_stream_bytes", 4 * 1024 * 1024)),
            max_total=int(self.config.get("max_memoria_bytes", 512 * 1024 * 1024)),
            max_flujos=int(self.config.get("max_flujos", MAX_FLUJOS_DEFECTO)),
        )
        self.flujos_udp: Dict[Tuple, dict] = {}

        # ── Deteccion de comportamiento ───────────────
        self.syn_por_origen: Dict[str, Dict[str, Set[int]]] = defaultdict(lambda: defaultdict(set))
        self.syn_sin_respuesta: Counter = Counter()
        self.rst_por_destino: Counter = Counter()
        self.conexiones_ts: Dict[Tuple, List[float]] = defaultdict(list)
        self.bytes_por_flujo: Counter = Counter()

        # ── Resultados de la fase 2 y 3 ───────────────
        self.http: List[httpmod.TransaccionHTTP] = []
        self.tls: List[SesionTLS] = []
        self.credenciales: List[plaintext.Credencial] = []
        self.correos: List[plaintext.CorreoSMTP] = []
        self.comandos: List[plaintext.ComandoRemoto] = []
        self.banners: List[dict] = []
        self.ficheros: List[carving.FicheroTransferido] = []
        self.secretos: List[secretsmod.Secreto] = []
        self.irc: List[dict] = []
        self.transcripciones: List[dict] = []
        self._banners_vistos: Set[Tuple] = set()

        # Filtros
        self.whitelist: Set[str] = set(self.config.get("whitelist_ips", []) or [])
        self._ts_min, self._ts_max = self._rango_temporal()

    # ──────────────────────────────────────────────────
    # Propiedades derivadas
    # ──────────────────────────────────────────────────
    @property
    def duracion(self) -> float:
        return max(0.0, self.ultimo_ts - self.primer_ts)

    @property
    def hosts_locales(self) -> List[str]:
        return sorted(ip for ip, h in self.hosts.items() if h.es_local)

    @property
    def hosts_externos(self) -> List[str]:
        return sorted(ip for ip, h in self.hosts.items() if not h.es_local)

    @property
    def flujos(self):
        return self.reensamblador.flujos.values()

    def host(self, ip: str) -> fingerprint.PerfilDispositivo:
        """Devuelve (creando si hace falta) el perfil de una IP."""
        perfil = self.hosts.get(ip)
        if perfil is None and ip in _NO_SON_HOSTS:
            # 0.0.0.0 y los broadcast son artefactos de DHCP/ARP, no equipos.
            return _PERFIL_NULO
        if perfil is None:
            perfil = fingerprint.PerfilDispositivo(ip)
            perfil.es_local = _es_privada(ip)
            self.hosts[ip] = perfil
        return perfil

    def so_de(self, ip: str) -> str:
        """Sistema operativo atribuido a una IP (para anotar peticiones)."""
        perfil = self.hosts.get(ip)
        return perfil.so if perfil and perfil.so else ""

    def descripcion_de(self, ip: str) -> str:
        perfil = self.hosts.get(ip)
        return perfil.descripcion if perfil else ip

    # ──────────────────────────────────────────────────
    # Fase 1: recorrido unico
    # ──────────────────────────────────────────────────
    def _rango_temporal(self) -> Tuple[float, float]:
        """Interpreta --time-range HH:MM-HH:MM en segundos desde medianoche."""
        rango = self.config.get("time_range")
        if not rango or "-" not in rango:
            return (0.0, 0.0)
        try:
            ini, fin = rango.split("-", 1)
            def a_segundos(t):
                partes = [int(p) for p in t.strip().split(":")]
                while len(partes) < 3:
                    partes.append(0)
                return partes[0] * 3600 + partes[1] * 60 + partes[2]
            return (float(a_segundos(ini)), float(a_segundos(fin)))
        except (ValueError, IndexError):
            return (0.0, 0.0)

    def _fuera_de_rango(self, ts: float) -> bool:
        if not self._ts_max:
            return False
        segundos_dia = (ts % 86400)
        if self._ts_min <= self._ts_max:
            return not (self._ts_min <= segundos_dia <= self._ts_max)
        return not (segundos_dia >= self._ts_min or segundos_dia <= self._ts_max)

    def ejecutar(self, progreso: Optional[Callable[[int, int], None]] = None) -> "Analisis":
        """Lanza el analisis completo. `progreso(paquetes, bytes)` es opcional."""
        inicio = time.perf_counter()
        self._recorrer(progreso)
        self._analizar_flujos()
        self._perfilar_hosts()
        self._revisar_limites()
        self.tiempo_analisis = time.perf_counter() - inicio
        return self

    def _revisar_limites(self) -> None:
        """Anota que techos se alcanzaron, para poder decirselo al usuario."""
        avisos = []
        if self.reensamblador.flujos_descartados:
            avisos.append(
                f"{self.reensamblador.flujos_descartados:,} conexiones TCP no se "
                f"siguieron al superarse el limite de "
                f"{self.reensamblador.max_flujos:,} flujos (--max-flows)")
        truncados = sum(1 for f in self.reensamblador.flujos.values()
                        if f.cliente.truncado or f.servidor.truncado)
        if truncados:
            avisos.append(
                f"{truncados:,} conexiones se leyeron solo parcialmente al llegar "
                f"al techo de memoria por flujo (--max-stream-mb)")
        if len(self.dns) >= MAX_DNS_GUARDADAS:
            avisos.append(f"solo se guardaron las primeras "
                          f"{MAX_DNS_GUARDADAS:,} consultas DNS")
        if len(self.http) >= MAX_HTTP:
            avisos.append(f"solo se guardaron las primeras "
                          f"{MAX_HTTP:,} transacciones HTTP")
        if len(self.secretos) >= MAX_SECRETOS:
            avisos.append(f"se alcanzo el limite de {MAX_SECRETOS:,} secretos")
        if len(self.ficheros) >= MAX_FICHEROS:
            avisos.append(f"se alcanzo el limite de {MAX_FICHEROS:,} ficheros")
        self.limites_alcanzados = avisos
        self.truncada = bool(avisos)

    def _recorrer(self, progreso: Optional[Callable[[int, int], None]]) -> None:
        captura = abrir_captura(self.ruta)
        self.formato = captura.formato

        pkt = Paquete()
        reensamblar = self.reensamblador.agregar
        whitelist = self.whitelist
        filtrar_tiempo = bool(self._ts_max)
        cada = 5000
        bytes_leidos = 0

        try:
            for crudo in captura:
                self.total_paquetes += 1
                bytes_leidos += crudo.caplen

                if progreso is not None and self.total_paquetes % cada == 0:
                    progreso(self.total_paquetes, bytes_leidos)

                pkt = decodificar(crudo, pkt)

                if pkt.malformado and not pkt.src:
                    self.paquetes_malformados += 1
                    continue

                ts = pkt.ts
                if filtrar_tiempo and ts and self._fuera_de_rango(ts):
                    continue
                if whitelist and (pkt.src in whitelist or pkt.dst in whitelist):
                    continue

                self.paquetes_analizados += 1
                self._contabilizar(pkt)

                if pkt.tipo_l3 == "arp":
                    self._procesar_arp(pkt)
                    continue

                if pkt.proto == IP_TCP:
                    # Sin puertos legibles no hay flujo que construir: la
                    # cabecera estaba truncada o corrupta.
                    if pkt.sport is not None and pkt.dport is not None:
                        self._procesar_tcp(pkt)
                        if self._reensamblar_este(pkt):
                            reensamblar(pkt)
                elif pkt.proto == IP_UDP:
                    if pkt.sport is not None and pkt.dport is not None:
                        self._procesar_udp(pkt)
                elif pkt.proto in (IP_ICMP, IP_ICMPV6):
                    self._procesar_icmp(pkt)
        finally:
            captura.close()

        if progreso is not None:
            progreso(self.total_paquetes, bytes_leidos)

    def _reensamblar_este(self, pkt) -> bool:
        """Decide si merece la pena guardar los bytes de este flujo."""
        if self.config.get("reensamblar_todo"):
            return True
        return (pkt.dport in PUERTOS_INTERESANTES
                or pkt.sport in PUERTOS_INTERESANTES
                or pkt.payload_len > 0 and (pkt.dport or 0) < 1024
                or (pkt.sport or 0) < 1024)

    def _contabilizar(self, pkt) -> None:
        ts = pkt.ts
        if ts:
            if not self.primer_ts or ts < self.primer_ts:
                self.primer_ts = ts
            if ts > self.ultimo_ts:
                self.ultimo_ts = ts
            self.actividad[int(ts)] += 1

        longitud = pkt.wirelen or pkt.caplen
        self.bytes_totales += longitud
        self.protocolos[pkt.capa_alta] += 1
        self.tamanos[_bucket_tamano(longitud)] += 1
        if pkt.vlan is not None:
            self.vlans[pkt.vlan] += 1

        app = self._clasificar_app(pkt)
        if app:
            self.protocolos_app[app] += 1

        if not pkt.src or pkt.src in _NO_SON_HOSTS:
            return

        origen = self.host(pkt.src)
        origen.paquetes_enviados += 1
        origen.bytes_enviados += longitud
        if pkt.eth_src and origen.es_local:
            # Para un host remoto la MAC de origen es la del router, no la suya.
            origen.macs.add(pkt.eth_src)
            self.mac_a_ips[pkt.eth_src].add(pkt.src)
        if not origen.primer_ts:
            origen.primer_ts = ts
        origen.ultimo_ts = ts
        if pkt.ttl and not origen.saltos:
            origen.saltos = fingerprint.saltos_estimados(pkt.ttl)

        if pkt.dst and pkt.dst not in _NO_SON_HOSTS:
            destino = self.host(pkt.dst)
            destino.paquetes_recibidos += 1
            destino.bytes_recibidos += longitud
            if not destino.primer_ts:
                destino.primer_ts = ts
            destino.ultimo_ts = ts

            clave = (pkt.src, pkt.dst) if pkt.src <= pkt.dst else (pkt.dst, pkt.src)
            conv = self.conversaciones.get(clave)
            if conv is None:
                conv = ConversacionIP(clave[0], clave[1], ts)
                self.conversaciones[clave] = conv
            conv.paquetes += 1
            conv.bytes += longitud
            conv.ultimo_ts = ts
            conv.protocolos.add(app or pkt.capa_alta)
            if pkt.dport:
                conv.puertos.add(pkt.dport)

        if pkt.dport:
            self.puertos_destino[pkt.dport] += 1
        if pkt.sport:
            self.puertos_origen[pkt.sport] += 1

    def _clasificar_app(self, pkt) -> str:
        """Resuelve el protocolo de aplicacion mirando puerto y payload."""
        proto = pkt.proto
        if proto not in (IP_TCP, IP_UDP):
            return pkt.capa_alta

        sport, dport = pkt.sport or 0, pkt.dport or 0
        puerto = dport if dport < sport else sport

        if puerto in (53, 5353, 5355):
            return "DNS" if puerto == 53 else ("mDNS" if puerto == 5353 else "LLMNR")
        if puerto in (67, 68):
            return "DHCP"
        if puerto == 123:
            return "NTP"
        if puerto in services.PUERTOS_HTTP:
            return "HTTP"
        if puerto in services.PUERTOS_TLS:
            return "TLS"
        if puerto == 443 and proto == IP_UDP:
            return "QUIC"
        if puerto == 22:
            return "SSH"
        if puerto in (137, 138, 139, 445):
            return "SMB/NetBIOS"

        nombre = services.SERVICIOS.get(puerto)
        if nombre:
            return nombre[0]

        # Sin puerto conocido: mirar el payload.
        carga = pkt.payload
        if carga:
            if httpmod.parece_http(carga):
                return "HTTP"
            if tlsmod.parece_tls(carga):
                return "TLS"
        return "TCP" if proto == IP_TCP else "UDP"

    # ── TCP ───────────────────────────────────────────
    def _procesar_tcp(self, pkt) -> None:
        flags = pkt.tcp_flags
        es_syn = (flags & TCP_SYN) and not (flags & TCP_ACK)

        if es_syn:
            self.syn_por_origen[pkt.src][pkt.dst].add(pkt.dport)
            clave = (pkt.src, pkt.dst, pkt.dport)
            if len(self.conexiones_ts) < MAX_EVENTOS_BEACON:
                self.conexiones_ts[clave].append(pkt.ts)

            perfil = self.host(pkt.src)
            if perfil.firma_tcp is None:
                firma = fingerprint.extraer_firma_syn(pkt)
                if firma:
                    perfil.firma_tcp = firma
                    perfil.anadir_candidato(fingerprint.identificar_por_tcp(firma))
            perfil.puertos_contactados.add(pkt.dport)

        elif (flags & TCP_SYN) and (flags & TCP_ACK):
            # Quien contesta con SYN/ACK esta sirviendo en ese puerto, y su
            # SYN/ACK tambien lleva huella de pila (menos fiable que el SYN
            # porque la ventana la ajusta segun lo que ofrecio el cliente).
            perfil = self.host(pkt.src)
            perfil.puertos_servidos.add(pkt.sport)
            if perfil.firma_tcp is None:
                firma = fingerprint.FirmaTCP(pkt.ttl, pkt.window, pkt.tcp_opts, pkt.ip_df)
                perfil.firma_tcp = firma
                resultado = fingerprint.identificar_por_tcp(firma)
                if resultado.confianza == "alta":
                    resultado.confianza = "media"   # el SYN/ACK es menos concluyente
                resultado.fuente = "TCP SYN/ACK"
                perfil.anadir_candidato(resultado)

        if flags & TCP_RST:
            self.rst_por_destino[pkt.dst] += 1

        if pkt.payload_len:
            self.bytes_por_flujo[(pkt.src, pkt.dst)] += pkt.payload_len

    # ── UDP ───────────────────────────────────────────
    def _procesar_udp(self, pkt) -> None:
        sport, dport = pkt.sport or 0, pkt.dport or 0
        carga = pkt.payload
        if not carga:
            return

        if dport in (53, 5353, 5355) or sport in (53, 5353, 5355):
            self._procesar_dns(pkt, carga, "UDP")
        elif dport in (67, 68) or sport in (67, 68):
            self._procesar_dhcp(pkt, carga)
        elif dport == 137 or sport == 137:
            self._procesar_nbns(pkt, carga)

        if pkt.payload_len:
            self.bytes_por_flujo[(pkt.src, pkt.dst)] += pkt.payload_len

    def _procesar_dns(self, pkt, carga: bytes, transporte: str) -> None:
        if len(self.dns) >= MAX_DNS_GUARDADAS:
            return
        msg = dnsmod.parsear(carga)
        if msg is None or not msg.preguntas:
            return

        ev = EventoDNS()
        ev.nombre = msg.nombre_consultado
        ev.tipo = msg.tipo_consultado
        ev.src = pkt.src
        ev.dst = pkt.dst
        ev.ts = pkt.ts
        ev.es_respuesta = msg.es_respuesta
        ev.rcode = msg.rcode_nombre
        ev.transporte = transporte
        ev.respuestas = [r.valor for r in msg.respuestas][:8]
        self.dns.append(ev)

        if ev.nombre:
            self.host(pkt.src if not msg.es_respuesta else pkt.dst).dominios.add(
                ev.nombre.lower())

        # Un nombre anunciado por mDNS suele ser el nombre del equipo.
        if pkt.dport == 5353 or pkt.sport == 5353:
            for r in msg.respuestas:
                if r.tipo in ("A", "AAAA") and r.nombre.endswith(".local"):
                    self.host(r.valor).hostnames.add(r.nombre[:-6])

    def _procesar_dhcp(self, pkt, carga: bytes) -> None:
        info = fingerprint.parsear_opciones_dhcp(carga)
        if not info["tipo"]:
            return
        info["src"] = pkt.src
        info["dst"] = pkt.dst
        info["ts"] = pkt.ts
        info["mac_ethernet"] = pkt.eth_src
        info["tipo_nombre"] = fingerprint.DHCP_TIPOS.get(info["tipo"], str(info["tipo"]))
        self.dhcp.append(info)

        # DISCOVER/REQUEST vienen del cliente: ahi esta su huella.
        if info["tipo"] in (1, 3, 8):
            ip_cliente = pkt.src if pkt.src != "0.0.0.0" else (info["requested_ip"] or "")
            if ip_cliente:
                perfil = self.host(ip_cliente)
                if info["hostname"]:
                    perfil.hostnames.add(info["hostname"])
                perfil.anadir_candidato(
                    fingerprint.identificar_por_dhcp(
                        info["param_list"], info["vendor_class"], info["hostname"])
                )
                if info["client_mac"] and info["client_mac"] != "00:00:00:00:00:00":
                    perfil.macs.add(info["client_mac"])

    def _procesar_nbns(self, pkt, carga: bytes) -> None:
        """NetBIOS Name Service: el nombre del equipo va codificado en el nombre."""
        msg = dnsmod.parsear(carga)
        if not msg or not msg.preguntas:
            return
        nombre = msg.preguntas[0][0]
        decodificado = _decodificar_nbns(nombre)
        if decodificado:
            self.host(pkt.src).hostnames.add(decodificado)

    # ── ARP / ICMP ────────────────────────────────────
    def _procesar_arp(self, pkt) -> None:
        if not pkt.arp_src_ip or pkt.arp_src_ip == "0.0.0.0":
            return
        self.arp[pkt.arp_src_ip].add(pkt.arp_src_mac)
        perfil = self.host(pkt.arp_src_ip)
        perfil.macs.add(pkt.arp_src_mac)
        perfil.es_local = True

        # ARP gratuito: anuncia su propia IP sin que nadie pregunte.
        if pkt.arp_src_ip == pkt.arp_dst_ip and pkt.arp_op == 2:
            self.arp_gratuitos.append({
                "ip": pkt.arp_src_ip, "mac": pkt.arp_src_mac, "ts": pkt.ts,
            })

    def _procesar_icmp(self, pkt) -> None:
        tipo = pkt.icmp_type
        if tipo is None:
            return
        self.icmp[tipo] += 1
        # Los "destino inaccesible" y "tiempo excedido" cuentan la topologia.
        if tipo in (3, 11, 5) and len(self.icmp_eventos) < 5000:
            self.icmp_eventos.append({
                "tipo": tipo, "codigo": pkt.icmp_code,
                "src": pkt.src, "dst": pkt.dst, "ts": pkt.ts,
            })

    # ──────────────────────────────────────────────────
    # Fase 2: protocolos sobre flujos reensamblados
    # ──────────────────────────────────────────────────
    def _analizar_flujos(self) -> None:
        for flujo in self.reensamblador.flujos.values():
            datos_cliente = bytes(flujo.cliente.datos)
            datos_servidor = bytes(flujo.servidor.datos)
            if not datos_cliente and not datos_servidor:
                continue

            puerto = flujo.servidor_puerto

            # Banner del servidor: identifica el software y su version.
            servicio, banner = plaintext.detectar_banner(datos_servidor)
            clave_banner = (flujo.servidor_ip, puerto, banner)
            if banner and servicio != "HTTP" and clave_banner not in self._banners_vistos:
                self._banners_vistos.add(clave_banner)
                flujo.servicio = servicio or services.servicio(puerto)
                self.banners.append({
                    "ip": flujo.servidor_ip, "puerto": puerto,
                    "servicio": flujo.servicio, "banner": banner[:160],
                    "version": plaintext.version_software(banner),
                    "ts": flujo.primer_ts,
                })
                self.host(flujo.servidor_ip).puertos_servidos.add(puerto)

            # ── HTTP ──────────────────────────────────
            if httpmod.parece_http(datos_cliente) or httpmod.parece_http(datos_servidor):
                if len(self.http) < MAX_HTTP:
                    self._procesar_http(flujo)
                continue

            # ── TLS ───────────────────────────────────
            if tlsmod.parece_tls(datos_cliente) or tlsmod.parece_tls(datos_servidor):
                self._procesar_tls(flujo)
                continue

            # ── Protocolos de texto ───────────────────
            self._procesar_texto(flujo, puerto, datos_cliente, datos_servidor)

        # Los bytes ya no hacen falta: liberamos antes de seguir.
        if not self.config.get("conservar_flujos"):
            self.reensamblador.liberar_memoria()

    def _procesar_http(self, flujo) -> None:
        for t in httpmod.extraer_transacciones(flujo):
            self.http.append(t)

            perfil = self.host(t.cliente_ip)
            if t.user_agent:
                perfil.user_agents[t.user_agent] = perfil.user_agents.get(t.user_agent, 0) + 1
                info = fingerprint.analizar_user_agent(t.user_agent)
                if info["os"]:
                    perfil.anadir_candidato(fingerprint.ResultadoSO(
                        info["os"], info["familia"], "alta", "User-Agent",
                        t.user_agent[:120]))
                if info["cliente"]:
                    perfil.clientes[info["cliente"]] = perfil.clientes.get(info["cliente"], 0) + 1
            if t.host:
                perfil.dominios.add(t.host.split(":")[0].lower())

            servidor = self.host(t.servidor_ip)
            servidor.puertos_servidos.add(t.servidor_puerto)

            self._extraer_credenciales_http(t)
            self._extraer_contenido_http(t)

    def _extraer_credenciales_http(self, t: httpmod.TransaccionHTTP) -> None:
        import base64 as _b64

        if t.autorizacion.lower().startswith("basic "):
            try:
                claro = _b64.b64decode(t.autorizacion.split(" ", 1)[1] + "==").decode(
                    "utf-8", "replace")
                usuario, _, password = claro.partition(":")
            except Exception:
                usuario, password = "(no decodificable)", ""
            c = plaintext.Credencial()
            c.protocolo = "HTTP Basic"
            c.usuario = usuario
            c.password = password
            c.src = t.cliente_ip
            c.dst = t.servidor_ip
            c.puerto = t.servidor_puerto
            c.ts = t.ts
            c.metodo = "Authorization: Basic (Base64, equivale a texto plano)"
            c.evidencia = f"{t.metodo} {t.url}"
            self.credenciales.append(c)

        # Formularios de login enviados por HTTP sin cifrar.
        if t.campos_formulario:
            campos = {k.lower(): v for k, v in t.campos_formulario}
            clave_pass = next((k for k in campos if k in (
                "password", "passwd", "pass", "pwd", "contrasena", "senha",
                "j_password", "user_password", "login_password")), "")
            if clave_pass:
                clave_user = next((k for k in campos if k in (
                    "user", "username", "usuario", "login", "email", "correo",
                    "uname", "j_username", "userid", "user_name", "account")), "")
                c = plaintext.Credencial()
                c.protocolo = "HTTP formulario"
                c.usuario = campos.get(clave_user, "(campo no identificado)")
                c.password = campos[clave_pass]
                c.src = t.cliente_ip
                c.dst = t.servidor_ip
                c.puerto = t.servidor_puerto
                c.ts = t.ts
                c.metodo = f"{t.metodo} con campo '{clave_pass}' sin cifrar"
                c.evidencia = f"{t.metodo} {t.url}"
                self.credenciales.append(c)

    def _extraer_contenido_http(self, t: httpmod.TransaccionHTTP) -> None:
        contexto = {
            "protocolo": "HTTP", "src": t.cliente_ip, "dst": t.servidor_ip,
            "url": t.url, "ts": t.ts,
        }

        # Secretos en cabeceras (Authorization, Cookie, X-Api-Key...).
        if len(self.secretos) < MAX_SECRETOS:
            cabeceras = {k: v for k, v in t.cabeceras_peticion.items()
                         if k in httpmod.CABECERAS_INTERES}
            self.secretos.extend(
                secretsmod.escanear_cabeceras(cabeceras, origen="cabecera de peticion",
                                              **contexto))

        # Secretos en el cuerpo enviado (formularios, JSON de APIs).
        if t.cuerpo_peticion and len(self.secretos) < MAX_SECRETOS:
            self.secretos.extend(secretsmod.escanear(
                t.cuerpo_peticion, origen=f"cuerpo de {t.metodo}",
                content_type=t.cabeceras_peticion.get("content-type", ""), **contexto))

        # Fichero descargado o subido.
        cuerpo = t.cuerpo_respuesta
        if cuerpo and len(self.ficheros) < MAX_FICHEROS:
            f = carving.analizar_fichero(t.nombre_fichero or t.ruta.rsplit("/", 1)[-1],
                                         cuerpo, t.content_type)
            f.protocolo = "HTTP"
            f.origen = t.servidor_ip
            f.destino = t.cliente_ip
            f.url = t.url
            f.ts = t.ts_respuesta or t.ts
            f.truncado = t.cuerpo_truncado
            if f.tamano >= 16:
                self.ficheros.append(f)

            if len(self.secretos) < MAX_SECRETOS:
                self.secretos.extend(secretsmod.escanear(
                    cuerpo, origen=f"contenido de {f.nombre or t.ruta}",
                    content_type=t.content_type, **contexto))

        if t.cuerpo_peticion and len(t.cuerpo_peticion) > 512 and len(self.ficheros) < MAX_FICHEROS:
            tipo_subida = t.cabeceras_peticion.get("content-type", "")
            if "multipart/form-data" in tipo_subida or t.metodo in ("PUT", "POST"):
                subido = carving.analizar_fichero(
                    f"subida_{t.ruta.rsplit('/', 1)[-1] or 'datos'}",
                    t.cuerpo_peticion, tipo_subida)
                subido.protocolo = "HTTP (subida)"
                subido.origen = t.cliente_ip
                subido.destino = t.servidor_ip
                subido.url = t.url
                subido.ts = t.ts
                if subido.tipo_real not in ("Texto plano", "vacio"):
                    self.ficheros.append(subido)

    def _procesar_tls(self, flujo) -> None:
        sesion = SesionTLS()
        sesion.cliente_ip = flujo.cliente_ip
        sesion.servidor_ip = flujo.servidor_ip
        sesion.servidor_puerto = flujo.servidor_puerto
        sesion.ts = flujo.primer_ts
        sesion.flujo_id = flujo.id

        for tipo, cuerpo in tlsmod.iterar_handshakes(bytes(flujo.cliente.datos)):
            if tipo == tlsmod.HS_CLIENT_HELLO:
                hello = tlsmod.parsear_client_hello(cuerpo)
                if hello:
                    sesion.sni = hello.sni
                    sesion.ja3 = hello.ja3
                    sesion.version_cliente = hello.version_texto
                    sesion.alpn = hello.alpn
                    sesion.ciphers_debiles = hello.ciphers_debiles
                break

        for tipo, cuerpo in tlsmod.iterar_handshakes(bytes(flujo.servidor.datos)):
            if tipo == tlsmod.HS_SERVER_HELLO:
                hello = tlsmod.parsear_server_hello(cuerpo)
                if hello:
                    sesion.ja3s = hello.ja3s
                    sesion.version_servidor = hello.version_texto
                    sesion.cipher = hello.cipher_nombre
            elif tipo == tlsmod.HS_CERTIFICATE:
                sesion.certificados = tlsmod.extraer_certificados(cuerpo)

        if sesion.ja3 or sesion.sni or sesion.version_servidor:
            self.tls.append(sesion)
            perfil = self.host(flujo.cliente_ip)
            if sesion.ja3 and not perfil.ja3:
                perfil.ja3 = sesion.ja3
            if sesion.sni:
                perfil.dominios.add(sesion.sni.lower())
            self.host(flujo.servidor_ip).puertos_servidos.add(flujo.servidor_puerto)

    def _procesar_texto(self, flujo, puerto: int,
                        datos_cliente: bytes, datos_servidor: bytes) -> None:
        if puerto in (21,):
            creds, comandos, _ficheros = plaintext.analizar_ftp(flujo)
            self.credenciales.extend(creds)
            self.comandos.extend(comandos)

        elif puerto in (25, 587, 2525):
            creds, correos = plaintext.analizar_smtp(flujo)
            self.credenciales.extend(creds)
            self.correos.extend(correos)

        elif puerto == 110:
            self.credenciales.extend(plaintext.analizar_pop_imap(flujo, "POP3"))

        elif puerto == 143:
            self.credenciales.extend(plaintext.analizar_pop_imap(flujo, "IMAP"))

        elif puerto == 23:
            creds, comandos, transcripcion = plaintext.analizar_telnet(flujo)
            self.credenciales.extend(creds)
            self.comandos.extend(comandos)
            if transcripcion.strip():
                self.transcripciones.append({
                    "protocolo": "Telnet", "src": flujo.cliente_ip,
                    "dst": flujo.servidor_ip, "puerto": puerto,
                    "texto": transcripcion[:4000], "ts": flujo.primer_ts,
                })

        elif puerto in (6667, 6666, 6697, 194):
            nicks, canales, mensajes = plaintext.analizar_irc(flujo)
            if nicks or canales:
                self.irc.append({
                    "src": flujo.cliente_ip, "dst": flujo.servidor_ip,
                    "puerto": puerto, "nicks": nicks, "canales": canales,
                    "mensajes": mensajes, "ts": flujo.primer_ts,
                })

        elif puerto == 69:
            self._procesar_tftp(flujo, datos_cliente)

        # Escaneo de secretos en cualquier payload en claro que no sea TLS.
        if len(self.secretos) < MAX_SECRETOS and datos_cliente:
            self.secretos.extend(secretsmod.escanear(
                datos_cliente[:262144],
                origen=f"flujo {services.servicio(puerto)} en claro",
                protocolo=services.servicio(puerto),
                src=flujo.cliente_ip, dst=flujo.servidor_ip, ts=flujo.primer_ts))

    def _procesar_tftp(self, flujo, datos: bytes) -> None:
        if len(datos) > 4 and datos[:2] in (b"\x00\x01", b"\x00\x02"):
            nombre = datos[2:].split(b"\x00")[0].decode("utf-8", "replace")
            self.comandos.append(plaintext.ComandoRemoto(
                "TFTP", f"{'RRQ' if datos[1] == 1 else 'WRQ'} {nombre}",
                flujo.cliente_ip, flujo.servidor_ip, 69, flujo.primer_ts))

    # ──────────────────────────────────────────────────
    # Fase 3: perfilado de hosts
    # ──────────────────────────────────────────────────
    def _perfilar_hosts(self) -> None:
        # Una MAC que responde por muchas IPs es un router, no un equipo: su
        # fabricante no dice nada del sistema operativo de esas IPs.
        macs_de_router = {mac for mac, ips in self.mac_a_ips.items() if len(ips) > 3}
        for mac in macs_de_router:
            for ip in self.arp:
                if mac in self.arp[ip]:
                    self.gateways.add(ip)

        for perfil in self.hosts.values():
            perfil.macs -= macs_de_router if len(perfil.macs) > 1 else set()
            for mac in perfil.macs:
                marca = fingerprint.fabricante_mac(mac)
                if marca and not marca.startswith("("):
                    perfil.fabricante = marca
                    perfil.anadir_candidato(_so_por_fabricante(marca))
                    break
            else:
                if perfil.macs:
                    perfil.fabricante = fingerprint.fabricante_mac(next(iter(perfil.macs)))

            perfil.consolidar()

            sirve = bool(perfil.puertos_servidos)
            contacta = bool(perfil.puertos_contactados)
            perfil.rol = ("ambos" if sirve and contacta else
                          "servidor" if sirve else
                          "cliente" if contacta else "pasivo")

    # ──────────────────────────────────────────────────
    # Consultas de conveniencia para los modulos
    # ──────────────────────────────────────────────────
    def top_hosts(self, n: int = 15) -> List[fingerprint.PerfilDispositivo]:
        return sorted(self.hosts.values(),
                      key=lambda h: h.bytes_enviados + h.bytes_recibidos,
                      reverse=True)[:n]

    def top_conversaciones(self, n: int = 15) -> List[ConversacionIP]:
        return sorted(self.conversaciones.values(), key=lambda c: c.bytes, reverse=True)[:n]

    def dominios_consultados(self) -> Counter:
        """Dominios consultados conservando el caso original.

        El caso importa: en un tunel DNS los datos van codificados en Base64
        dentro del subdominio y pasarlo a minusculas destruye la evidencia.
        """
        return Counter(e.nombre for e in self.dns if not e.es_respuesta and e.nombre)

    def http_por_host(self) -> Dict[str, List[httpmod.TransaccionHTTP]]:
        salida: Dict[str, List] = defaultdict(list)
        for t in self.http:
            salida[t.cliente_ip].append(t)
        return salida

    def ficheros_sospechosos(self) -> List[carving.FicheroTransferido]:
        return [f for f in self.ficheros if f.sospechoso]

    def secretos_criticos(self) -> List[secretsmod.Secreto]:
        return [s for s in self.secretos if s.severidad == "critico"]

    def resumen(self) -> dict:
        """Cifras de cabecera para el informe."""
        return {
            "nombre": self.nombre,
            "formato": self.formato,
            "paquetes": self.total_paquetes,
            "analizados": self.paquetes_analizados,
            "bytes": self.bytes_totales,
            "duracion": self.duracion,
            "hosts": len(self.hosts),
            "locales": len(self.hosts_locales),
            "externos": len(self.hosts_externos),
            "conversaciones": len(self.conversaciones),
            "flujos_tcp": len(self.reensamblador),
            "dns": len(self.dns),
            "http": len(self.http),
            "tls": len(self.tls),
            "credenciales": len(self.credenciales),
            "ficheros": len(self.ficheros),
            "secretos": len(self.secretos),
            "tiempo": self.tiempo_analisis,
        }


# ──────────────────────────────────────────────────────
# Ayudas
# ──────────────────────────────────────────────────────
# Direcciones que aparecen en el trafico pero no representan a ningun equipo.
_NO_SON_HOSTS = {"0.0.0.0", "255.255.255.255", "::", "::1"}
_PERFIL_NULO = fingerprint.PerfilDispositivo("(sin direccion)")


def _es_privada(ip: str) -> bool:
    try:
        direccion = ipaddress.ip_address(ip)
        return (direccion.is_private or direccion.is_loopback
                or direccion.is_link_local or direccion.is_multicast)
    except ValueError:
        return False


def _bucket_tamano(n: int) -> str:
    for limite in (64, 128, 256, 512, 1024, 1514):
        if n <= limite:
            return f"<={limite}"
    return ">1514"


def _decodificar_nbns(nombre: str) -> str:
    """El nombre NetBIOS va codificado en pares de letras (RFC 1001)."""
    if len(nombre) < 32:
        return ""
    try:
        crudo = nombre[:32]
        salida = []
        for i in range(0, 32, 2):
            alto = ord(crudo[i]) - ord("A")
            bajo = ord(crudo[i + 1]) - ord("A")
            if not (0 <= alto <= 15 and 0 <= bajo <= 15):
                return ""
            salida.append(chr((alto << 4) | bajo))
        return "".join(salida).strip().rstrip("\x00")[:15].strip()
    except (ValueError, IndexError):
        return ""


_FABRICANTE_SO = {
    "Apple": ("macOS / iOS", "Apple"),
    "Raspberry Pi Foundation": ("Raspberry Pi OS (Linux)", "Linux"),
    "Raspberry Pi Trading": ("Raspberry Pi OS (Linux)", "Linux"),
    "Espressif": ("Firmware IoT (ESP8266/ESP32)", "IoT"),
    "VMware": ("Maquina virtual VMware", "Virtual"),
    "VirtualBox (Oracle)": ("Maquina virtual VirtualBox", "Virtual"),
    "QEMU / KVM": ("Maquina virtual QEMU/KVM", "Virtual"),
    "Microsoft Hyper-V": ("Maquina virtual Hyper-V", "Virtual"),
    "Docker (bridge)": ("Contenedor Docker", "Virtual"),
    "Xen": ("Maquina virtual Xen", "Virtual"),
    "Nintendo": ("Consola Nintendo", "Consola"),
    "MikroTik": ("RouterOS", "Red"),
    "Ubiquiti": ("Equipo de red Ubiquiti", "Red"),
    "Cisco": ("Equipo de red Cisco", "Red"),
}


def _so_por_fabricante(marca: str) -> Optional[fingerprint.ResultadoSO]:
    for clave, (nombre, familia) in _FABRICANTE_SO.items():
        if marca.startswith(clave):
            return fingerprint.ResultadoSO(nombre, familia, "baja", "MAC OUI",
                                           f"fabricante del interfaz: {marca}")
    return None


def analizar(ruta: str, config: Optional[dict] = None,
             progreso: Optional[Callable[[int, int], None]] = None) -> Analisis:
    """Atajo: crea el Analisis y lo ejecuta."""
    return Analisis(ruta, config).ejecutar(progreso)
