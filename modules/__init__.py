"""
modules/__init__.py — Núcleo compartido de todos los módulos de LookingTheShark.

Define:
  - Finding: dataclass estándar de hallazgo que todos los módulos producen
             y que report_builder consume.
  - Utilidades comunes para todos los módulos.
"""

from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime


# ──────────────────────────────────────────────────────
# Niveles de confianza
# ──────────────────────────────────────────────────────
class Confianza:
    ALTA  = "alta"
    MEDIA = "media"
    BAJA  = "baja"


# ──────────────────────────────────────────────────────
# Hallazgo de seguridad genérico
# Cada módulo produce una lista de estos.
# ──────────────────────────────────────────────────────
@dataclass
class Finding:
    """Representa un hallazgo de seguridad con nivel de confianza.

    Attributes:
        titulo:      Resumen corto del hallazgo.
        descripcion: Explicación detallada.
        severidad:   'critico' | 'alto' | 'medio' | 'bajo' | 'info'
        confianza:   Confianza.ALTA / MEDIA / BAJA
        modulo:      ID del módulo que generó el hallazgo.
        evidencia:   Paquetes, rango de tiempo, IPs concretas.
        mitre_id:    Técnica MITRE ATT&CK (se rellena en mitre_mapping).
        mitre_name:  Nombre de la técnica MITRE.
        patron:      Clave interna para el mapeo MITRE (ej. 'portscan').
        timestamp:   Momento del hallazgo en la captura (si aplica).
    """
    titulo: str
    descripcion: str
    severidad: str
    confianza: str
    modulo: str
    evidencia: str = ""
    mitre_id: str = ""
    mitre_name: str = ""
    patron: str = ""
    timestamp: str = ""
    interpretacion: str = ""


# ──────────────────────────────────────────────────────
# Utilidades comunes
# ──────────────────────────────────────────────────────
import ipaddress


def es_ip_privada(ip_str: str) -> bool:
    """Comprueba si una IP es privada (RFC 1918 / link-local / loopback)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def formatear_bytes(n: int) -> str:
    """Convierte bytes a formato legible (KB, MB, GB)."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 ** 3:
        return f"{n / (1024 ** 2):.1f} MB"
    else:
        return f"{n / (1024 ** 3):.2f} GB"


def formatear_duracion(segundos: float) -> str:
    """Convierte segundos a formato HH:MM:SS."""
    h = int(segundos // 3600)
    m = int((segundos % 3600) // 60)
    s = int(segundos % 60)
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def safe_get_attr(pkt, layer_name: str, attr_name: str, default=""):
    """Extrae un atributo de un paquete pyshark de forma segura."""
    try:
        layer = getattr(pkt, layer_name, None)
        if layer is None:
            return default
        val = getattr(layer, attr_name, default)
        return str(val) if val is not None else default
    except Exception:
        return default


def safe_int(value, default: int = 0) -> int:
    """Convierte a int de forma segura."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value, default: float = 0.0) -> float:
    """Convierte a float de forma segura."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default
