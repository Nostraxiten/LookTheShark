"""
core/carving.py — Identificacion y extraccion de ficheros transferidos.

Antes esto dependia de `tshark --export-objects`, que obligaba a tener
Wireshark instalado y a releer el pcap cuatro veces. Ahora los ficheros salen
directamente de los flujos ya reensamblados: HTTP (cuerpos), FTP-DATA, TFTP y
SMB basico.

Lo interesante no es solo listar ficheros, sino contestar preguntas concretas:
  - ¿lo que se descargo era de verdad lo que decia ser? (magic vs extension
    vs Content-Type)
  - ¿es ejecutable?
  - ¿que hash tiene para cruzarlo con VirusTotal a mano despues?
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import List, Optional, Tuple

# ── Magic bytes → (tipo legible, extensiones tipicas, ejecutable) ──
# Ordenado por longitud de firma al construir la tabla: gana la mas especifica.
FIRMAS: List[Tuple[bytes, str, tuple, bool]] = [
    (b"MZ",                                 "PE ejecutable (EXE/DLL)", (".exe", ".dll", ".sys", ".scr", ".ocx"), True),
    (b"\x7fELF",                            "ELF ejecutable (Linux)", (".elf", ".so", ".bin", ""), True),
    (b"\xca\xfe\xba\xbe",                   "Mach-O universal (macOS) o Java class", (".dylib", ".class", ""), True),
    (b"\xcf\xfa\xed\xfe",                   "Mach-O 64-bit (macOS)", (".dylib", ""), True),
    (b"\xce\xfa\xed\xfe",                   "Mach-O 32-bit (macOS)", (".dylib", ""), True),
    (b"\xfe\xed\xfa\xce",                   "Mach-O (macOS, BE)", (".dylib", ""), True),
    (b"dex\n",                              "Android DEX", (".dex", ".apk"), True),
    (b"PK\x03\x04",                         "ZIP / OOXML / JAR / APK", (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt"), False),
    (b"PK\x05\x06",                         "ZIP vacio", (".zip",), False),
    (b"PK\x07\x08",                         "ZIP spanned", (".zip",), False),
    (b"Rar!\x1a\x07",                       "RAR", (".rar",), False),
    (b"7z\xbc\xaf\x27\x1c",                 "7-Zip", (".7z",), False),
    (b"\x1f\x8b",                           "GZIP", (".gz", ".tgz"), False),
    (b"BZh",                                "BZIP2", (".bz2",), False),
    (b"\xfd7zXZ",                           "XZ", (".xz",), False),
    (b"\x04\x22\x4d\x18",                   "LZ4", (".lz4",), False),
    (b"\x28\xb5\x2f\xfd",                   "Zstandard", (".zst",), False),
    (b"\x89PNG\r\n\x1a\n",                  "Imagen PNG", (".png",), False),
    (b"\xff\xd8\xff",                       "Imagen JPEG", (".jpg", ".jpeg"), False),
    (b"GIF87a",                             "Imagen GIF", (".gif",), False),
    (b"GIF89a",                             "Imagen GIF", (".gif",), False),
    (b"BM",                                 "Imagen BMP", (".bmp",), False),
    (b"RIFF",                               "RIFF (WAV/AVI/WEBP)", (".wav", ".avi", ".webp"), False),
    (b"%PDF",                               "Documento PDF", (".pdf",), False),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",   "MS Office antiguo (OLE2)", (".doc", ".xls", ".ppt", ".msi"), False),
    (b"{\\rtf",                             "Documento RTF", (".rtf",), False),
    (b"OggS",                               "Audio/video OGG", (".ogg", ".opus"), False),
    (b"ID3",                                "Audio MP3", (".mp3",), False),
    (b"\x1a\x45\xdf\xa3",                   "Video MKV/WebM", (".mkv", ".webm"), False),
    (b"\x00\x00\x01\xba",                   "Video MPEG-PS", (".mpg",), False),
    (b"#!",                                 "Script con shebang", (".sh", ".py", ".pl", ".rb", ""), True),
    (b"<?php",                              "Codigo PHP", (".php",), True),
    (b"\xed\xab\xee\xdb",                   "Paquete RPM", (".rpm",), False),
    (b"!<arch>\ndebian",                    "Paquete DEB", (".deb",), False),
    (b"SQLite format 3\x00",                "Base de datos SQLite", (".db", ".sqlite"), False),
    (b"\x30\x82",                           "Certificado/clave DER", (".der", ".cer", ".p12", ".pfx"), False),
    (b"-----BEGIN",                         "Material PEM (clave/certificado)", (".pem", ".key", ".crt"), False),
]

# Firma en offset fijo distinto de 0.
FIRMAS_CON_OFFSET = [
    (4, b"ftyp", "Video MP4/MOV", (".mp4", ".mov", ".m4v"), False),
    (257, b"ustar", "Archivo TAR", (".tar",), False),
]

# Extensiones que un usuario ve como inofensivas.
EXTENSIONES_INOCUAS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".txt", ".csv", ".log", ".xml", ".json", ".md", ".html", ".htm",
    ".mp3", ".wav", ".ogg", ".mp4", ".avi", ".mkv", ".pdf",
}

EXTENSIONES_EJECUTABLES = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".msi", ".msix",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".jar", ".apk", ".elf", ".so", ".bin", ".run", ".sh",
    ".py", ".pl", ".rb", ".php", ".lnk", ".reg", ".inf", ".iso", ".img",
}

# Content-Type que anuncia binario ejecutable.
TIPOS_EJECUTABLES = {
    "application/x-msdownload", "application/x-msdos-program",
    "application/vnd.microsoft.portable-executable", "application/x-executable",
    "application/x-dosexec", "application/x-sharedlib", "application/x-elf",
    "application/octet-stream", "application/x-msi", "application/java-archive",
    "application/vnd.android.package-archive",
}


class FicheroTransferido:
    """Un fichero visto viajando por la red."""

    __slots__ = ("nombre", "protocolo", "tipo_declarado", "tipo_real",
                 "extension", "tamano", "md5", "sha256", "origen", "destino",
                 "url", "ts", "ejecutable", "sospechoso", "motivo_sospecha",
                 "datos", "guardado_en", "truncado")

    def __init__(self):
        self.nombre = ""
        self.protocolo = ""
        self.tipo_declarado = ""      # Content-Type que anunciaba el servidor
        self.tipo_real = ""           # lo que dicen los magic bytes
        self.extension = ""
        self.tamano = 0
        self.md5 = ""
        self.sha256 = ""
        self.origen = ""
        self.destino = ""
        self.url = ""
        self.ts = 0.0
        self.ejecutable = False
        self.sospechoso = False
        self.motivo_sospecha = ""
        self.datos = b""
        self.guardado_en = ""
        self.truncado = False

    def __repr__(self) -> str:
        return f"<Fichero {self.nombre} {self.tipo_real} {self.tamano}B>"


def identificar(datos: bytes) -> Tuple[str, bool, tuple]:
    """Devuelve (tipo_legible, es_ejecutable, extensiones_tipicas)."""
    if not datos:
        return ("vacio", False, ())

    for offset, firma, tipo, exts, ejec in FIRMAS_CON_OFFSET:
        if len(datos) > offset + len(firma) and datos[offset:offset + len(firma)] == firma:
            return (tipo, ejec, exts)

    for firma, tipo, exts, ejec in FIRMAS:
        if datos.startswith(firma):
            return (tipo, ejec, exts)

    cabeza = datos[:1024].lstrip()
    if cabeza.startswith(b"<!DOCTYPE html") or cabeza.lower().startswith(b"<html"):
        return ("HTML", False, (".html", ".htm"))
    if cabeza.startswith(b"<?xml"):
        return ("XML", False, (".xml",))
    if cabeza[:1] in (b"{", b"[") and _parece_json(cabeza):
        return ("JSON", False, (".json",))

    # Texto plano si (casi) todo son bytes imprimibles.
    muestra = datos[:2048]
    if muestra:
        imprimibles = sum(1 for b in muestra if 9 <= b <= 13 or 32 <= b <= 126 or b >= 160)
        if imprimibles / len(muestra) > 0.92:
            return ("Texto plano", False, (".txt",))

    return ("Binario desconocido", False, ())


def _parece_json(datos: bytes) -> bool:
    try:
        import json
        json.loads(datos.decode("utf-8", "ignore"))
        return True
    except Exception:
        return b'":' in datos or b'": ' in datos


def analizar_fichero(nombre: str, datos: bytes, tipo_declarado: str = "") -> FicheroTransferido:
    """Construye un FicheroTransferido con hashes y deteccion de disfraz."""
    f = FicheroTransferido()
    f.nombre = nombre or "(sin nombre)"
    f.datos = datos
    f.tamano = len(datos)
    f.tipo_declarado = tipo_declarado
    f.extension = os.path.splitext(nombre)[1].lower() if nombre else ""

    tipo, ejecutable, exts_tipicas = identificar(datos)
    f.tipo_real = tipo
    f.ejecutable = ejecutable or f.extension in EXTENSIONES_EJECUTABLES

    if datos:
        f.md5 = hashlib.md5(datos).hexdigest()
        f.sha256 = hashlib.sha256(datos).hexdigest()

    # ── Deteccion de disfraz ──────────────────────────
    motivos = []
    if f.extension and exts_tipicas and f.extension not in exts_tipicas:
        if f.extension in EXTENSIONES_INOCUAS:
            motivos.append(
                f"se descargo como '{f.extension}' pero el contenido es {tipo}"
            )
    if ejecutable and f.extension in EXTENSIONES_INOCUAS:
        motivos.append("contenido ejecutable con extension de fichero inofensivo")
    if ejecutable and tipo_declarado and tipo_declarado.startswith(("image/", "text/")):
        motivos.append(
            f"el servidor lo anuncio como '{tipo_declarado}' pero es {tipo}"
        )
    if f.extension in EXTENSIONES_EJECUTABLES and f.extension not in (".js", ".php"):
        motivos.append("descarga de fichero ejecutable")

    f.motivo_sospecha = "; ".join(dict.fromkeys(motivos))
    f.sospechoso = bool(motivos)
    return f


def guardar(fichero: FicheroTransferido, directorio: str) -> str:
    """Escribe el fichero a disco con un nombre seguro. Devuelve la ruta."""
    os.makedirs(directorio, exist_ok=True)

    base = re.sub(r"[^A-Za-z0-9._-]", "_", fichero.nombre or "objeto")[:96]
    if not base or base in (".", ".."):
        base = "objeto"
    # El hash en el nombre evita colisiones y deja el fichero trazable.
    prefijo = fichero.sha256[:12] if fichero.sha256 else "sinhash"
    ruta = os.path.join(directorio, f"{prefijo}_{base}")

    try:
        with open(ruta, "wb") as fh:
            fh.write(fichero.datos)
        fichero.guardado_en = ruta
        return ruta
    except OSError:
        return ""
