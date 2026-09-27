"""
modules/__init__.py — Shared core for all LookingTheShark modules.

Defines:
  - Finding: standard finding dataclass produced by every module
             and consumed by report_builder.
  - Common utilities shared across all modules.
"""

from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime


# ──────────────────────────────────────────────────────
# Confidence levels
# ──────────────────────────────────────────────────────
class Confianza:
    ALTA  = "alta"
    MEDIA = "media"
    BAJA  = "baja"


# ──────────────────────────────────────────────────────
# Generic security finding.
# Each module produces a list of these.
# ──────────────────────────────────────────────────────
@dataclass
class Finding:
    """Represents a security finding with a confidence level.

    Attributes:
        titulo:         Short summary of the finding.
        descripcion:    Detailed explanation.
        severidad:      'critico' | 'alto' | 'medio' | 'bajo' | 'info'
        confianza:      Confianza.ALTA / MEDIA / BAJA
        modulo:         ID of the module that generated the finding.
        evidencia:      Packets, time range, specific IPs.
        mitre_id:       MITRE ATT&CK technique (filled in by mitre_mapping).
        mitre_name:     Name of the MITRE technique.
        patron:         Internal key for MITRE mapping (e.g. 'portscan').
        timestamp:      Moment of the finding in the capture (if applicable).
        interpretacion: Pipe-separated context string (attack | pattern | legit).
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
# Common utilities
# ──────────────────────────────────────────────────────
import ipaddress


def es_ip_privada(ip_str: str) -> bool:
    """Returns True if the IP is private (RFC 1918 / link-local / loopback)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def formatear_bytes(n: int) -> str:
    """Converts bytes to a human-readable string (KB, MB, GB)."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 ** 3:
        return f"{n / (1024 ** 2):.1f} MB"
    else:
        return f"{n / (1024 ** 3):.2f} GB"


def formatear_duracion(segundos: float) -> str:
    """Converts seconds to HH:MM:SS format."""
    h = int(segundos // 3600)
    m = int((segundos % 3600) // 60)
    s = int(segundos % 60)
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def safe_get_attr(pkt, layer_name: str, attr_name: str, default=""):
    """Safely extracts an attribute from a pyshark packet layer."""
    try:
        layer = getattr(pkt, layer_name, None)
        if layer is None:
            return default
        val = getattr(layer, attr_name, default)
        return str(val) if val is not None else default
    except Exception:
        return default


def safe_int(value, default: int = 0) -> int:
    """Safely converts a value to int."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value, default: float = 0.0) -> float:
    """Safely converts a value to float."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default
