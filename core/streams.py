"""
core/streams.py — Reensamblado de flujos TCP.

Sin esto solo se ven paquetes sueltos. Con esto se ven conversaciones: una
peticion HTTP completa, un login FTP, un handshake TLS entero aunque venga
partido en cinco segmentos.

Decisiones de diseno:
  - Se reensambla por sentido (cliente->servidor y servidor->cliente por
    separado), que es lo que necesitan los parsers de protocolo.
  - Hay un techo de bytes por sentido y otro global. Al llegar al techo se deja
    de acumular pero el flujo sigue contabilizandose: una captura de 10 GB no
    puede tumbar la herramienta por quedarse sin RAM.
  - Se descartan retransmisiones y se toleran huecos: si falta un segmento se
    marca el flujo como incompleto y se sigue. Un analisis forense con un hueco
    vale mas que una excepcion.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from core.decoders import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN

# Techos por defecto. Se pueden subir desde la configuracion (--max-stream-mb).
MAX_BYTES_POR_SENTIDO = 4 * 1024 * 1024

# No todos los flujos necesitan el mismo presupuesto. De una conexion TLS solo
# se lee el handshake, que va al principio: guardar los megas de datos cifrados
# que vienen despues no aporta nada y es lo que dispara la memoria en capturas
# grandes. Puerto de servidor -> bytes que merece la pena conservar por sentido.
PRESUPUESTO_POR_PUERTO = {
    # TLS/SSL: ClientHello + ServerHello + cadena de certificados caben de sobra.
    443: 48 * 1024, 465: 48 * 1024, 636: 48 * 1024, 989: 48 * 1024,
    990: 48 * 1024, 993: 48 * 1024, 995: 48 * 1024, 1194: 48 * 1024,
    4443: 48 * 1024, 5061: 48 * 1024, 5986: 48 * 1024, 8443: 48 * 1024,
    9443: 48 * 1024, 10443: 48 * 1024,
    # SSH: solo interesa el banner de version.
    22: 8 * 1024,
    # Protocolos de texto: las conversaciones son cortas.
    21: 256 * 1024, 23: 256 * 1024, 110: 256 * 1024, 143: 256 * 1024,
    161: 64 * 1024,
}
MAX_BYTES_TOTAL       = 512 * 1024 * 1024
MAX_SEGMENTOS_FUERA_DE_ORDEN = 64
MAX_FLUJOS = 200_000


class Sentido:
    """Un sentido de una conexion TCP: los bytes que van de A a B."""

    __slots__ = ("datos", "seq_inicial", "seq_esperado", "pendientes",
                 "bytes_totales", "paquetes", "truncado", "huecos",
                 "primer_ts", "ultimo_ts", "iniciado")

    def __init__(self):
        self.datos = bytearray()
        self.seq_inicial: Optional[int] = None
        self.seq_esperado: Optional[int] = None
        self.pendientes: Dict[int, bytes] = {}
        self.bytes_totales = 0     # bytes de payload vistos en el cable
        self.paquetes = 0
        self.truncado = False      # se alcanzo el techo de memoria
        self.huecos = 0            # segmentos que faltaron
        self.primer_ts = 0.0
        self.ultimo_ts = 0.0
        self.iniciado = False      # se vio el SYN de este sentido

    def __len__(self) -> int:
        return len(self.datos)

    @property
    def completo(self) -> bool:
        return self.iniciado and self.huecos == 0 and not self.truncado


class FlujoTCP:
    """Una conexion TCP completa, con sus dos sentidos."""

    __slots__ = ("id", "cliente_ip", "cliente_puerto", "servidor_ip", "servidor_puerto",
                 "cliente", "servidor", "primer_ts", "ultimo_ts", "syn_visto",
                 "syn_ack_visto", "fin_visto", "rst_visto", "primer_num",
                 "servicio", "cerrado", "presupuesto")

    def __init__(self, fid: int, cip: str, cport: int, sip: str, sport: int, ts: float):
        self.id = fid
        self.cliente_ip = cip
        self.cliente_puerto = cport
        self.servidor_ip = sip
        self.servidor_puerto = sport
        self.cliente = Sentido()    # cliente -> servidor (peticiones)
        self.servidor = Sentido()   # servidor -> cliente (respuestas)
        self.primer_ts = ts
        self.ultimo_ts = ts
        self.primer_num = 0
        self.syn_visto = False
        self.syn_ack_visto = False
        self.fin_visto = False
        self.rst_visto = False
        self.cerrado = False
        self.servicio = ""
        self.presupuesto = MAX_BYTES_POR_SENTIDO

    @property
    def clave(self) -> str:
        return (f"{self.cliente_ip}:{self.cliente_puerto} -> "
                f"{self.servidor_ip}:{self.servidor_puerto}")

    @property
    def duracion(self) -> float:
        return max(0.0, self.ultimo_ts - self.primer_ts)

    @property
    def bytes_totales(self) -> int:
        return self.cliente.bytes_totales + self.servidor.bytes_totales

    @property
    def handshake_completo(self) -> bool:
        return self.syn_visto and self.syn_ack_visto

    @property
    def rechazado(self) -> bool:
        """SYN sin SYN/ACK y con RST: el puerto estaba cerrado."""
        return self.syn_visto and not self.syn_ack_visto and self.rst_visto

    @property
    def sin_respuesta(self) -> bool:
        """SYN sin respuesta ninguna: filtrado o host caido."""
        return self.syn_visto and not self.syn_ack_visto and not self.rst_visto

    def __repr__(self) -> str:
        return f"<FlujoTCP {self.clave} {self.bytes_totales}B>"


def _dentro(seq: int, esperado: int) -> int:
    """Distancia de seq respecto a esperado teniendo en cuenta el wrap de 32 bits."""
    return ((seq - esperado) + 2**31) % 2**32 - 2**31


class Reensamblador:
    """Acumula segmentos TCP y reconstruye los dos sentidos de cada conexion."""

    def __init__(self,
                 max_por_sentido: int = MAX_BYTES_POR_SENTIDO,
                 max_total: int = MAX_BYTES_TOTAL,
                 max_flujos: int = MAX_FLUJOS):
        self.flujos: Dict[Tuple, FlujoTCP] = {}
        self.max_por_sentido = max_por_sentido
        self.max_total = max_total
        self.max_flujos = max_flujos   # se cita en los avisos de truncado
        self.bytes_en_memoria = 0
        self.flujos_descartados = 0
        self._siguiente_id = 0

    # ── Alta / busqueda de flujo ──────────────────────
    def _clave(self, pkt) -> Tuple:
        # Los puertos pueden llegar a None si la cabecera venia truncada; se
        # normalizan a -1 para que la clave siga siendo ordenable.
        a = (pkt.src, pkt.sport if pkt.sport is not None else -1)
        b = (pkt.dst, pkt.dport if pkt.dport is not None else -1)
        return (a, b) if a <= b else (b, a)

    def _obtener(self, pkt) -> Optional[FlujoTCP]:
        clave = self._clave(pkt)
        flujo = self.flujos.get(clave)
        if flujo is not None:
            return flujo

        if len(self.flujos) >= self.max_flujos:
            self.flujos_descartados += 1
            return None

        # Quien manda el SYN es el cliente. Si no hemos visto el SYN, usamos el
        # puerto mas bajo como servidor, que acierta en la practica totalidad
        # de los casos (80, 443, 22, 21...).
        es_syn = (pkt.tcp_flags & TCP_SYN) and not (pkt.tcp_flags & TCP_ACK)
        if es_syn or pkt.dport < pkt.sport:
            cip, cport, sip, sport = pkt.src, pkt.sport, pkt.dst, pkt.dport
        else:
            cip, cport, sip, sport = pkt.dst, pkt.dport, pkt.src, pkt.sport

        self._siguiente_id += 1
        flujo = FlujoTCP(self._siguiente_id, cip, cport, sip, sport, pkt.ts)
        flujo.primer_num = pkt.num
        flujo.presupuesto = min(
            self.max_por_sentido,
            PRESUPUESTO_POR_PUERTO.get(sport, self.max_por_sentido))
        self.flujos[clave] = flujo
        return flujo

    # ── Ingesta ───────────────────────────────────────
    def agregar(self, pkt) -> Optional[FlujoTCP]:
        """Mete un paquete TCP en su flujo. Devuelve el flujo afectado."""
        flujo = self._obtener(pkt)
        if flujo is None:
            return None

        flujo.ultimo_ts = pkt.ts
        flags = pkt.tcp_flags
        del_cliente = (pkt.src == flujo.cliente_ip and pkt.sport == flujo.cliente_puerto)
        sentido = flujo.cliente if del_cliente else flujo.servidor

        if sentido.primer_ts == 0.0:
            sentido.primer_ts = pkt.ts
        sentido.ultimo_ts = pkt.ts
        sentido.paquetes += 1

        if flags & TCP_SYN:
            if flags & TCP_ACK:
                flujo.syn_ack_visto = True
            else:
                flujo.syn_visto = True
            sentido.iniciado = True
            # El SYN consume un numero de secuencia.
            sentido.seq_inicial = pkt.seq
            sentido.seq_esperado = (pkt.seq + 1) & 0xFFFFFFFF

        if flags & TCP_FIN:
            flujo.fin_visto = True
        if flags & TCP_RST:
            flujo.rst_visto = True
            flujo.cerrado = True

        if pkt.payload_len:
            sentido.bytes_totales += pkt.payload_len
            self._insertar(sentido, pkt.seq, pkt.payload, flujo.presupuesto)

        return flujo

    def _insertar(self, sentido: Sentido, seq: int, datos: bytes,
                  presupuesto: int) -> None:
        if sentido.seq_esperado is None:
            # No vimos el SYN: empezamos a contar desde este segmento.
            sentido.seq_inicial = seq
            sentido.seq_esperado = seq

        if sentido.truncado or self.bytes_en_memoria >= self.max_total:
            sentido.truncado = True
            return

        delta = _dentro(seq, sentido.seq_esperado)

        if delta == 0:
            self._anexar(sentido, datos, presupuesto)
            sentido.seq_esperado = (sentido.seq_esperado + len(datos)) & 0xFFFFFFFF
            self._drenar_pendientes(sentido, presupuesto)

        elif delta < 0:
            # Retransmision total o parcial: quedarnos solo con la parte nueva.
            solapado = -delta
            if solapado < len(datos):
                nuevo = datos[solapado:]
                self._anexar(sentido, nuevo, presupuesto)
                sentido.seq_esperado = (sentido.seq_esperado + len(nuevo)) & 0xFFFFFFFF
                self._drenar_pendientes(sentido, presupuesto)

        else:
            # Fuera de orden: guardar y esperar al que falta.
            if sentido.truncado:
                return          # ya no se guarda nada de este sentido
            if len(sentido.pendientes) < MAX_SEGMENTOS_FUERA_DE_ORDEN:
                if seq not in sentido.pendientes or len(datos) > len(sentido.pendientes[seq]):
                    sentido.pendientes[seq] = datos
            else:
                # Demasiados huecos: damos por perdido el segmento que falta y
                # saltamos al mas antiguo pendiente para no bloquear el flujo.
                menor = min(sentido.pendientes)
                sentido.huecos += 1
                sentido.seq_esperado = menor
                self._drenar_pendientes(sentido, presupuesto)

    def _anexar(self, sentido: Sentido, datos: bytes, presupuesto: int) -> None:
        espacio = presupuesto - len(sentido.datos)
        if espacio <= 0:
            sentido.truncado = True
            # Los segmentos guardados ya no se van a usar: se sueltan ahora en
            # vez de arrastrarlos hasta el final del analisis.
            sentido.pendientes = {}
            return
        if len(datos) > espacio:
            datos = datos[:espacio]
            sentido.truncado = True
        sentido.datos += datos
        self.bytes_en_memoria += len(datos)

    def _drenar_pendientes(self, sentido: Sentido, presupuesto: int) -> None:
        """Vuelca los segmentos guardados que ya encajan tras el ultimo anexado."""
        if not sentido.pendientes:
            return
        while True:
            seq = sentido.seq_esperado
            datos = sentido.pendientes.pop(seq, None)
            if datos is None:
                # Puede que encaje uno parcialmente solapado.
                encontrado = None
                for s in list(sentido.pendientes):
                    d = _dentro(s, seq)
                    if d < 0 and -d < len(sentido.pendientes[s]):
                        encontrado = s
                        break
                if encontrado is None:
                    return
                datos = sentido.pendientes.pop(encontrado)[-_dentro(encontrado, seq):]
            self._anexar(sentido, datos, presupuesto)
            sentido.seq_esperado = (seq + len(datos)) & 0xFFFFFFFF
            if not sentido.pendientes:
                return

    # ── Consulta ──────────────────────────────────────
    def liberar_memoria(self) -> None:
        """Suelta los buffers reensamblados dejando solo los metadatos.

        Se llama cuando los parsers de protocolo ya han terminado: a partir de
        ahi solo se necesitan contadores, no los bytes.
        """
        for flujo in self.flujos.values():
            flujo.cliente.datos = bytearray()
            flujo.cliente.pendientes = {}
            flujo.servidor.datos = bytearray()
            flujo.servidor.pendientes = {}
        self.bytes_en_memoria = 0

    def por_puerto(self, *puertos: int) -> List[FlujoTCP]:
        objetivo = set(puertos)
        return [f for f in self.flujos.values() if f.servidor_puerto in objetivo]

    def con_datos(self) -> List[FlujoTCP]:
        return [f for f in self.flujos.values() if f.bytes_totales > 0]

    def __len__(self) -> int:
        return len(self.flujos)
