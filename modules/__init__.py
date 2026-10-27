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
import asyncio

# Python 3.14+ compatibility:
# In Python 3.14, asyncio child watchers (set_child_watcher, SafeChildWatcher, etc.)
# were removed. Current versions of pyshark (<=0.6) attempt to call
# asyncio.set_child_watcher(asyncio.SafeChildWatcher()) on POSIX systems (Linux/Kali).
# This shim provides no-op implementations so pyshark initializes cleanly.
if not hasattr(asyncio, "set_child_watcher"):
    class _CompatibilityChildWatcher:
        def attach_loop(self, loop):
            pass
        def close(self):
            pass
        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    asyncio.set_child_watcher = lambda watcher: None
    asyncio.get_child_watcher = lambda: _CompatibilityChildWatcher()
    asyncio.SafeChildWatcher = _CompatibilityChildWatcher


# ──────────────────────────────────────────────────────
# Confidence levels
# ──────────────────────────────────────────────────────
class Confidence:
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


# ──────────────────────────────────────────────────────
# Generic security finding.
# Each module produces a list of these.
# ──────────────────────────────────────────────────────
@dataclass
class Finding:
    """Represents a security finding with a confidence level.

    Attributes:
        title:          Short summary of the finding.
        description:    Detailed explanation.
        severity:       'critical' | 'high' | 'medium' | 'low' | 'info'
        confidence:     Confidence.HIGH / MEDIUM / LOW
        module:         ID of the module that generated the finding.
        evidence:       Packets, time range, specific IPs.
        mitre_id:       MITRE ATT&CK technique (filled in by mitre_mapping).
        mitre_name:     Name of the MITRE technique.
        pattern:        Internal key for MITRE mapping (e.g. 'portscan').
        timestamp:      Moment of the finding in the capture (if applicable).
        interpretation: Pipe-separated context string (attack | pattern | legit).
    """
    title: str
    description: str
    severity: str
    confidence: str
    module: str
    evidence: str = ""
    mitre_id: str = ""
    mitre_name: str = ""
    pattern: str = ""
    timestamp: str = ""
    interpretation: str = ""


# ──────────────────────────────────────────────────────
# Common utilities
# ──────────────────────────────────────────────────────
import ipaddress


def is_private_ip(ip_str: str) -> bool:
    """Returns True if the IP is private (RFC 1918 / link-local / loopback)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def format_bytes(n: int) -> str:
    """Converts bytes to a human-readable string (KB, MB, GB)."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 ** 3:
        return f"{n / (1024 ** 2):.1f} MB"
    else:
        return f"{n / (1024 ** 3):.2f} GB"


def format_duration(seconds: float) -> str:
    """Converts seconds to HH:MM:SS format."""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
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
