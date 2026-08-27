"""
core/pcap_reader.py — Lector nativo de capturas .pcap y .pcapng.

Sustituye a pyshark/tshark para la lectura del fichero. Trabaja en streaming:
lee bloque a bloque y va cediendo paquetes, asi que la memoria usada no depende
del tamano de la captura.

Formatos soportados:
  - libpcap clasico (big/little endian, marcas de tiempo en us y en ns)
  - pcapng (SHB / IDB / EPB / SPB / ISB), varias interfaces por fichero
  - cualquiera de los dos comprimido con gzip (.gz) — se detecta por magic

Uso:
    with abrir_captura("captura.pcapng") as cap:
        for raw in cap:
            raw.ts, raw.linktype, raw.data
"""

from __future__ import annotations

import gzip
import io
import os
import struct
from typing import Iterator, Optional


# ── Magics ────────────────────────────────────────────
PCAP_MAGIC_LE      = 0xA1B2C3D4   # us,  little endian al leer como LE
PCAP_MAGIC_BE      = 0xD4C3B2A1
PCAP_MAGIC_NS_LE   = 0xA1B23C4D   # ns
PCAP_MAGIC_NS_BE   = 0x4D3CB2A1
PCAPNG_BLOCK_SHB   = 0x0A0D0D0A

GZIP_MAGIC = b"\x1f\x8b"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# Techo defensivo: un bloque pcapng mayor que esto es un fichero corrupto,
# no una captura. Evita reservar GB por un campo de longitud manipulado.
MAX_BLOQUE = 128 * 1024 * 1024
# Techo por paquete. tcpdump admite snaplen enormes; 64 MB es de sobra.
MAX_PAQUETE = 64 * 1024 * 1024


class CapturaInvalida(Exception):
    """El fichero no es una captura pcap/pcapng legible."""


class PaqueteCrudo:
    """Un paquete tal y como sale del fichero, sin disectar.

    Usa __slots__ (y no dataclass) porque se instancia una vez por paquete:
    en capturas de millones de paquetes la diferencia de memoria es real.
    """

    __slots__ = ("num", "ts", "caplen", "origlen", "linktype", "data")

    def __init__(self, num: int, ts: float, caplen: int, origlen: int,
                 linktype: int, data: bytes):
        self.num = num            # 1-indexado, orden de aparicion en el fichero
        self.ts = ts              # epoch en segundos (con fraccion)
        self.caplen = caplen      # bytes realmente guardados
        self.origlen = origlen    # bytes que habia en el cable
        self.linktype = linktype  # DLT_* de la interfaz que lo capturo
        self.data = data

    def __repr__(self) -> str:
        return f"<PaqueteCrudo #{self.num} {self.caplen}B dlt={self.linktype}>"


# ──────────────────────────────────────────────────────
# Utilidades de apertura
# ──────────────────────────────────────────────────────
def _abrir_binario(path: str):
    """Abre el fichero descomprimiendo si hace falta.

    Detecta gzip por magic (no por extension) para que funcione igual con
    'captura.pcap.gz' que con un gzip renombrado.
    """
    fh = open(path, "rb")
    cabecera = fh.read(4)
    fh.seek(0)

    if cabecera[:2] == GZIP_MAGIC:
        fh.close()
        return gzip.open(path, "rb")

    if cabecera[:4] == ZSTD_MAGIC:
        fh.close()
        try:
            import zstandard  # opcional, no esta en requirements
        except ImportError:
            raise CapturaInvalida(
                "La captura esta comprimida con zstd. Descomprimela primero "
                "(zstd -d captura.pcapng.zst) o instala el paquete 'zstandard'."
            )
        dctx = zstandard.ZstdDecompressor()
        return dctx.stream_reader(open(path, "rb"))

    # Un buffer generoso reduce muchisimo las llamadas al SO en capturas grandes.
    return io.BufferedReader(fh, buffer_size=1024 * 1024)


def _leer_exacto(fh, n: int) -> bytes:
    """Lee exactamente n bytes o devuelve lo que haya si se acaba el fichero."""
    if n <= 0:
        return b""
    trozos = []
    restantes = n
    while restantes > 0:
        trozo = fh.read(restantes)
        if not trozo:
            break
        trozos.append(trozo)
        restantes -= len(trozo)
    return b"".join(trozos)


# ──────────────────────────────────────────────────────
# Lector libpcap clasico
# ──────────────────────────────────────────────────────
class LectorPcap:
    """Itera un fichero libpcap clasico."""

    def __init__(self, fh, magic: int):
        self.fh = fh
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            self.endian = "<"
        else:
            self.endian = ">"
        self.resolucion_ns = magic in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE)

        cab = _leer_exacto(fh, 20)
        if len(cab) < 20:
            raise CapturaInvalida("Cabecera pcap truncada.")
        (self.vmajor, self.vminor, _tz, _sigfigs,
         self.snaplen, linktype) = struct.unpack(self.endian + "HHiIII", cab)
        # El linktype lleva flags en los bits altos (FCS length).
        self.linktype = linktype & 0x0000FFFF
        self._cab = struct.Struct(self.endian + "IIII")

    @property
    def formato(self) -> str:
        return "pcap (ns)" if self.resolucion_ns else "pcap"

    def __iter__(self) -> Iterator[PaqueteCrudo]:
        divisor = 1_000_000_000.0 if self.resolucion_ns else 1_000_000.0
        unpack = self._cab.unpack
        leer = self.fh.read
        num = 0

        while True:
            cab = leer(16)
            if len(cab) < 16:
                return
            ts_sec, ts_frac, caplen, origlen = unpack(cab)

            if caplen > MAX_PAQUETE:
                raise CapturaInvalida(
                    f"Paquete #{num + 1} declara {caplen} bytes: fichero corrupto."
                )

            data = leer(caplen)
            if len(data) < caplen:
                # Captura truncada (proceso matado a mitad). Cedemos lo que hay.
                if data:
                    num += 1
                    yield PaqueteCrudo(num, ts_sec + ts_frac / divisor,
                                       len(data), origlen, self.linktype, data)
                return

            num += 1
            yield PaqueteCrudo(num, ts_sec + ts_frac / divisor,
                               caplen, origlen, self.linktype, data)


# ──────────────────────────────────────────────────────
# Lector pcapng
# ──────────────────────────────────────────────────────
class LectorPcapng:
    """Itera un fichero pcapng (el formato por defecto de Wireshark)."""

    BT_SHB = 0x0A0D0D0A
    BT_IDB = 0x00000001
    BT_SPB = 0x00000003
    BT_EPB = 0x00000006
    BT_ISB = 0x00000005

    def __init__(self, fh, primeros_bytes: bytes):
        self.fh = fh
        self._pendiente = primeros_bytes
        self.endian = "<"
        # Cada IDB anade una interfaz: (linktype, divisor_de_tiempo)
        self.interfaces: list[tuple[int, float]] = []
        self.snaplen = 0
        self.formato = "pcapng"

    def _leer(self, n: int) -> bytes:
        if self._pendiente:
            if len(self._pendiente) >= n:
                out, self._pendiente = self._pendiente[:n], self._pendiente[n:]
                return out
            out = self._pendiente
            self._pendiente = b""
            return out + _leer_exacto(self.fh, n - len(out))
        return _leer_exacto(self.fh, n)

    def _procesar_shb(self, cuerpo: bytes) -> None:
        # byte-order magic: 0x1A2B3C4D leido con el endianness correcto
        if cuerpo[:4] == b"\x4d\x3c\x2b\x1a":
            self.endian = "<"
        elif cuerpo[:4] == b"\x1a\x2b\x3c\x4d":
            self.endian = ">"
        # Un SHB nuevo reinicia la tabla de interfaces (fichero concatenado).
        self.interfaces = []

    def _procesar_idb(self, cuerpo: bytes) -> None:
        if len(cuerpo) < 8:
            self.interfaces.append((1, 1e6))
            return
        linktype, _res, snaplen = struct.unpack(self.endian + "HHI", cuerpo[:8])
        self.snaplen = max(self.snaplen, snaplen)

        # if_tsresol (codigo 9) define la resolucion de los timestamps.
        divisor = 1e6
        for codigo, valor in self._opciones(cuerpo[8:]):
            if codigo == 9 and valor:
                raw = valor[0]
                if raw & 0x80:
                    divisor = float(2 ** (raw & 0x7F))
                else:
                    divisor = float(10 ** raw)
                break
        self.interfaces.append((linktype, divisor))

    def _opciones(self, datos: bytes):
        """Recorre la lista de opciones TLV de un bloque pcapng."""
        pos = 0
        fin = len(datos)
        while pos + 4 <= fin:
            codigo, longitud = struct.unpack(self.endian + "HH", datos[pos:pos + 4])
            pos += 4
            if codigo == 0:  # opt_endofopt
                return
            valor = datos[pos:pos + longitud]
            pos += longitud + ((4 - longitud % 4) % 4)  # padding a 32 bits
            yield codigo, valor

    def __iter__(self) -> Iterator[PaqueteCrudo]:
        num = 0
        while True:
            cab = self._leer(8)
            if len(cab) < 8:
                return
            tipo, total = struct.unpack(self.endian + "II", cab)

            if tipo == self.BT_SHB:
                # El SHB manda sobre el endianness: releemos su longitud despues
                # de mirar el byte-order magic.
                cuerpo = self._leer(4)
                if len(cuerpo) < 4:
                    return
                if cuerpo == b"\x1a\x2b\x3c\x4d":
                    self.endian = ">"
                elif cuerpo == b"\x4d\x3c\x2b\x1a":
                    self.endian = "<"
                total = struct.unpack(self.endian + "I", cab[4:8])[0]
                if total < 12 or total > MAX_BLOQUE:
                    raise CapturaInvalida("Bloque SHB con longitud invalida.")
                resto = self._leer(total - 12)
                self._procesar_shb(cuerpo + resto)
                continue

            if total < 12 or total > MAX_BLOQUE:
                raise CapturaInvalida(
                    f"Bloque pcapng de tipo 0x{tipo:08x} con longitud invalida ({total})."
                )

            cuerpo = self._leer(total - 12)
            if len(cuerpo) < total - 12:
                return
            self._leer(4)  # total_length repetido al final del bloque

            if tipo == self.BT_IDB:
                self._procesar_idb(cuerpo)

            elif tipo == self.BT_EPB:
                if len(cuerpo) < 20:
                    continue
                iface, ts_hi, ts_lo, caplen, origlen = struct.unpack(
                    self.endian + "IIIII", cuerpo[:20]
                )
                if caplen > MAX_PAQUETE:
                    continue
                data = cuerpo[20:20 + caplen]
                linktype, divisor = self._iface(iface)
                ts = ((ts_hi << 32) | ts_lo) / divisor
                num += 1
                yield PaqueteCrudo(num, ts, len(data), origlen, linktype, data)

            elif tipo == self.BT_SPB:
                if len(cuerpo) < 4:
                    continue
                origlen = struct.unpack(self.endian + "I", cuerpo[:4])[0]
                data = cuerpo[4:]
                linktype, _divisor = self._iface(0)
                num += 1
                # El SPB no lleva timestamp; se marca a 0 y el llamante lo sabe.
                yield PaqueteCrudo(num, 0.0, len(data), origlen, linktype, data)

            # ISB y demas bloques (NRB, DSB, custom) se ignoran a proposito.

    def _iface(self, idx: int) -> tuple[int, float]:
        if idx < len(self.interfaces):
            return self.interfaces[idx]
        return (1, 1e6)  # Ethernet / microsegundos por defecto


# ──────────────────────────────────────────────────────
# API publica
# ──────────────────────────────────────────────────────
class Captura:
    """Contexto iterable sobre una captura. Cierra el fichero al salir."""

    def __init__(self, path: str):
        self.path = path
        self.tamano = os.path.getsize(path) if os.path.isfile(path) else 0
        self._fh = _abrir_binario(path)

        magic_bytes = _leer_exacto(self._fh, 4)
        if len(magic_bytes) < 4:
            self._fh.close()
            raise CapturaInvalida(f"'{os.path.basename(path)}' esta vacio o es demasiado corto.")

        magic_le = struct.unpack("<I", magic_bytes)[0]

        if magic_le in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
            self._lector = LectorPcap(self._fh, magic_le)
        elif magic_le == PCAPNG_BLOCK_SHB:
            self._lector = LectorPcapng(self._fh, magic_bytes)
        else:
            self._fh.close()
            raise CapturaInvalida(
                f"'{os.path.basename(path)}' no parece un .pcap/.pcapng "
                f"(magic 0x{magic_le:08x}). Si es un .cap de otra herramienta, "
                f"conviertelo con: editcap fichero.cap fichero.pcapng"
            )

    @property
    def formato(self) -> str:
        return getattr(self._lector, "formato", "pcap")

    def __iter__(self) -> Iterator[PaqueteCrudo]:
        return iter(self._lector)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

    def __enter__(self) -> "Captura":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def abrir_captura(path: str) -> Captura:
    """Abre una captura y devuelve un objeto iterable de PaqueteCrudo."""
    if not os.path.isfile(path):
        raise CapturaInvalida(f"No existe el fichero '{path}'.")
    return Captura(path)


def es_captura(path: str) -> bool:
    """True si el fichero parece una captura soportada (mira el magic)."""
    try:
        with open(path, "rb") as fh:
            cab = fh.read(4)
        if cab[:2] == GZIP_MAGIC:
            with gzip.open(path, "rb") as gz:
                cab = gz.read(4)
        if len(cab) < 4:
            return False
        magic = struct.unpack("<I", cab)[0]
        return magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE,
                         PCAP_MAGIC_NS_BE, PCAPNG_BLOCK_SHB)
    except Exception:
        return False
