"""
modules/__init__.py — Contrato comun de todos los modulos de analisis.

Un modulo de LookingTheShark es una funcion:

    def run(analisis: core.session.Analisis, config: dict, console) -> List[Finding]

Ya no recibe una lista de paquetes: recibe el objeto Analisis, que llega con
todo el trabajo pesado hecho en una sola pasada. El modulo solo tiene que
interpretar y contar la historia.

Un Finding no es solo "algo malo": lleva ademas que significa y que hacer,
porque un informe que solo dice "puerto 23 detectado" no le sirve a nadie.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional


# ──────────────────────────────────────────────────────
# Niveles
# ──────────────────────────────────────────────────────
class Confianza:
    ALTA = "alta"
    MEDIA = "media"
    BAJA = "baja"


class Severidad:
    CRITICO = "critico"
    ALTO = "alto"
    MEDIO = "medio"
    BAJO = "bajo"
    INFO = "info"


ORDEN_SEVERIDAD = {"critico": 0, "alto": 1, "medio": 2, "bajo": 3, "info": 4}
ORDEN_CONFIANZA = {"alta": 0, "media": 1, "baja": 2}

UMBRAL_CONFIANZA = {"bajo": 2, "medio": 1, "alto": 0}


@dataclass
class Finding:
    """Un hallazgo, escrito para que lo entienda quien lo lea.

    titulo         Que ha pasado, en una linea.
    descripcion    Que significa y por que importa.
    recomendacion  Que hacer a continuacion. Sin esto el informe no acciona.
    evidencia      El dato concreto que lo respalda (IP, URL, hash, hora).
    """
    titulo: str
    descripcion: str
    severidad: str
    confianza: str
    modulo: str
    evidencia: str = ""
    recomendacion: str = ""
    mitre_id: str = ""
    mitre_name: str = ""
    mitre_tactica: str = ""
    patron: str = ""
    timestamp: str = ""
    host: str = ""            # IP protagonista del hallazgo
    host_so: str = ""         # sistema operativo atribuido a ese host
    referencias: List[str] = field(default_factory=list)
    datos: dict = field(default_factory=dict)   # detalles para el informe

    @property
    def peso(self) -> tuple:
        """Clave de orden: primero lo grave y lo fiable."""
        return (ORDEN_SEVERIDAD.get(self.severidad, 5),
                ORDEN_CONFIANZA.get(self.confianza, 3))

    @property
    def mitre(self) -> str:
        return self.mitre_name or self.mitre_id


def ordenar_hallazgos(hallazgos: List[Finding]) -> List[Finding]:
    return sorted(hallazgos, key=lambda f: f.peso)


def filtrar_por_confianza(hallazgos: List[Finding], umbral: str) -> List[Finding]:
    """Descarta hallazgos por debajo del umbral pedido (bajo/medio/alto)."""
    maximo = UMBRAL_CONFIANZA.get(umbral, 2)
    return [f for f in hallazgos if ORDEN_CONFIANZA.get(f.confianza, 3) <= maximo]


# ──────────────────────────────────────────────────────
# Utilidades compartidas
# ──────────────────────────────────────────────────────
def es_ip_privada(ip_str: str) -> bool:
    """RFC1918, loopback, link-local o multicast."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return False


def formatear_bytes(n: float) -> str:
    """1536 -> '1.5 KB'."""
    n = float(n)
    if n < 1024:
        return f"{int(n)} B"
    for unidad, limite in (("KB", 1024 ** 2), ("MB", 1024 ** 3), ("GB", 1024 ** 4)):
        if n < limite:
            return f"{n / (limite / 1024):.1f} {unidad}"
    return f"{n / 1024 ** 4:.2f} TB"


def formatear_duracion(segundos: float) -> str:
    """125 -> '02:05'. Mas de una hora -> 'HH:MM:SS'."""
    segundos = max(0.0, float(segundos))
    h = int(segundos // 3600)
    m = int((segundos % 3600) // 60)
    s = int(segundos % 60)
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def formatear_hora(ts: float, con_fecha: bool = False) -> str:
    """Epoch -> 'HH:MM:SS' local."""
    if not ts:
        return "--:--:--"
    from datetime import datetime
    try:
        d = datetime.fromtimestamp(ts)
        return d.strftime("%Y-%m-%d %H:%M:%S" if con_fecha else "%H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return "--:--:--"


def truncar(texto: str, largo: int = 60, sufijo: str = "…") -> str:
    texto = str(texto)
    return texto if len(texto) <= largo else texto[:largo - len(sufijo)] + sufijo


def plural(n: int, singular: str, plural_: Optional[str] = None) -> str:
    """1 equipo / 3 equipos."""
    if n == 1:
        return f"{n} {singular}"
    return f"{n} {plural_ or singular + 's'}"


# Compatibilidad con modulos antiguos que usaban estos ayudantes de pyshark.
def safe_get_attr(pkt, layer_name: str, attr_name: str, default=""):
    """Obsoleto: el nucleo nativo ya expone los campos directamente."""
    try:
        capa = getattr(pkt, layer_name, None)
        if capa is None:
            return default
        valor = getattr(capa, attr_name, default)
        return str(valor) if valor is not None else default
    except Exception:
        return default


def safe_int(valor, default: int = 0) -> int:
    try:
        return int(valor)
    except (ValueError, TypeError):
        return default


def safe_float(valor, default: float = 0.0) -> float:
    try:
        return float(valor)
    except (ValueError, TypeError):
        return default
