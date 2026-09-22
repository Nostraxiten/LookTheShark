"""
modules/file_extraction.py — Transferred Files / Objects Module.

Extraction of objects via tshark --export-objects, MD5/SHA256 hashing,
Shannon entropy calculation, and detection of extension vs magic bytes mismatch.
"""

import os
import math
import hashlib
import subprocess
import tempfile
import shutil
from datetime import datetime
from collections import Counter
from typing import List

from rich.console import Console
from rich.table import Table
from rich import box

from modules import Finding, Confianza
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 4
MODULE_NAME = "Files / Objects"
MODULE_ID   = "files"

# ──────────────────────────────────────────────────────
# Magic bytes -> actual file type
# ──────────────────────────────────────────────────────
MAGIC_SIGNATURES = {
    b"\x4d\x5a":                       "PE Executable (EXE/DLL)",
    b"\x7f\x45\x4c\x46":              "ELF Executable",
    b"\x50\x4b\x03\x04":              "ZIP Archive",
    b"\x50\x4b\x05\x06":              "ZIP Archive (empty)",
    b"\x52\x61\x72\x21":              "RAR Archive",
    b"\x1f\x8b":                       "GZIP",
    b"\x42\x5a\x68":                   "BZIP2",
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": "PNG Image",
    b"\xff\xd8\xff":                   "JPEG Image",
    b"\x47\x49\x46\x38":              "GIF Image",
    b"\x25\x50\x44\x46":              "PDF Document",
    b"\xd0\xcf\x11\xe0":              "MS Office (OLE)",
    b"\x50\x4b\x03\x04":              "MS Office (OOXML) / ZIP",
    b"\x7b\x5c\x72\x74\x66":          "RTF Document",
    b"\x4f\x67\x67\x53":              "OGG Media",
    b"\x49\x44\x33":                   "MP3 Audio",
    b"\x00\x00\x00\x1c\x66\x74\x79\x70": "MP4 Video",
    b"\x1a\x45\xdf\xa3":              "MKV/WebM Video",
    b"\x23\x21":                       "Script (shebang)",
}

EXTENSIONES_PELIGROSAS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".msi", ".scr", ".pif", ".com", ".hta", ".cpl",
    ".elf", ".sh", ".bin", ".run",
}

EXTENSIONES_INOCUAS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
    ".txt", ".csv", ".log", ".xml", ".json",
    ".mp3", ".wav", ".ogg", ".mp4", ".avi", ".mkv",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
}


def compute_entropy(filepath: str) -> float:
    """Calculates Shannon entropy (0.00 to 8.00) of a file."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        occ = Counter(data)
        total = len(data)
        entropy = -sum((count / total) * math.log2(count / total) for count in occ.values())
        return round(entropy, 2)
    except Exception:
        return 0.0


def detect_magic(data: bytes) -> str:
    """Detects file type using magic bytes."""
    for sig, tipo in MAGIC_SIGNATURES.items():
        if data[:len(sig)] == sig:
            return tipo
    # ASCII text check
    try:
        sample = data[:512]
        sample.decode("ascii")
        return "ASCII Text"
    except (UnicodeDecodeError, ValueError):
        pass
    return "Unknown"


def hash_file(filepath: str) -> dict:
    """Computes MD5 and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def extract_objects(pcap_path: str, output_dir: str) -> list:
    """
    Uses tshark --export-objects to extract transferred files.
    Supports HTTP, SMB, TFTP, IMF.
    """
    extracted = []
    protocols = ["http", "smb", "tftp", "imf"]

    for proto in protocols:
        proto_dir = os.path.join(output_dir, proto)
        os.makedirs(proto_dir, exist_ok=True)

        try:
            subprocess.run(
                [
                    "tshark", "-r", pcap_path,
                    "--export-objects", f"{proto},{proto_dir}",
                    "-Q",
                ],
                capture_output=True, timeout=120,
                check=False,
            )
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            continue

        if os.path.isdir(proto_dir):
            for fname in os.listdir(proto_dir):
                fpath = os.path.join(proto_dir, fname)
                if os.path.isfile(fpath) and os.path.getsize(fpath) > 0:
                    ext = os.path.splitext(fname)[1].lower()
                    mtime = os.path.getmtime(fpath)
                    t_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                    entropy_score = compute_entropy(fpath)
                    if entropy_score > 7.0:
                        entropy_label = f"{entropy_score:.2f} (High)"
                    elif entropy_score >= 5.0:
                        entropy_label = f"{entropy_score:.2f} (Medium)"
                    else:
                        entropy_label = f"{entropy_score:.2f} (Low)"

                    extracted.append({
                        "protocol": proto.upper(),
                        "filename": fname,
                        "filepath": fpath,
                        "size": os.path.getsize(fpath),
                        "extension": ext,
                        "timestamp": t_str,
                        "entropy_score": entropy_score,
                        "entropy_label": entropy_label,
                    })

    return extracted


def detect_filetype_mismatch(extracted_files: list) -> List[Finding]:
    """
    Detects mismatch between extension and magic bytes.
    If a file is transferred as .jpg but has PE executable headers,
    that indicates evasion or masquerading.
    """
    findings = []

    for finfo in extracted_files:
        ext = finfo.get("extension", "")
        if not ext:
            continue

        try:
            with open(finfo["filepath"], "rb") as f:
                header = f.read(32)
        except Exception:
            continue

        magic_type = detect_magic(header)
        finfo["magic_type"] = magic_type

        is_executable_content = any(
            kw in magic_type.lower()
            for kw in ["executable", "elf", "pe ", "script"]
        )

        if ext in EXTENSIONES_INOCUAS and is_executable_content:
            findings.append(Finding(
                titulo=f"File type mismatch: {finfo['filename']} ({magic_type})",
                descripcion=(
                    f"File has extension '{ext}' but magic bytes indicate "
                    f"'{magic_type}'. Strong indicator of evasion / masqueraded file. "
                    f"Review manually."
                ),
                severidad="alto",
                confianza=Confianza.ALTA,
                modulo=MODULE_ID,
                evidencia=f"Protocol: {finfo['protocol']}, Size: {finfo['size']} bytes",
                patron="file_transfer_mismatch",
                interpretacion=(
                    "Masquerading: Masquerade File Type | "
                    "File extension mismatch against magic bytes header (executable disguised as document/media) | "
                    "Inadvertent file renaming, legacy system quirks, or unusual application container format"
                )
            ))

    return findings


def detect_high_entropy(extracted_files: list) -> List[Finding]:
    """
    Detects files with unusually high entropy (>7.2) indicating potential encryption,
    packing, or obfuscation, while suppressing known archives and media.
    """
    findings = []
    compressed_keywords = ["zip", "rar", "gzip", "bzip2", "tar", "7z", "compressed", "archive", "image", "audio", "video", "pdf"]

    for finfo in extracted_files:
        score = finfo.get("entropy_score", 0.0)
        magic_type = finfo.get("magic_type", "").lower()
        ext = finfo.get("extension", "").lower()

        is_compressed = any(kw in magic_type for kw in compressed_keywords) or ext in {
            ".zip", ".rar", ".gz", ".tar", ".bz2", ".7z", ".png", ".jpg", ".jpeg", ".mp4", ".mp3", ".pdf"
        }

        if score > 7.2 and not is_compressed:
            findings.append(Finding(
                titulo=f"High entropy payload: {finfo['filename']} (Entropy: {score:.2f})",
                descripcion=(
                    f"File '{finfo['filename']}' has a Shannon entropy score of {score:.2f}/8.00 "
                    f"without matching a known compressed format. This suggests encrypted, packed, or obfuscated content."
                ),
                severidad="medio",
                confianza=Confianza.MEDIA,
                modulo=MODULE_ID,
                evidencia=f"File: {finfo['filename']}, Entropy: {score:.2f}, Size: {finfo['size']} bytes",
                patron="data_encoding",
                interpretacion=(
                    "Obfuscated / Encrypted File Transfer (Data Encoding) | "
                    "Shannon entropy above 7.2/8.0 in a non-standard archive format suggesting encrypted or packed payload | "
                    "Proprietary encrypted database formats, compiled binaries, custom compressed assets, or encrypted configuration files"
                )
            ))

    return findings


def run(packets, config: dict, console: Console) -> List[Finding]:
    """Executes file extraction and analysis."""
    findings = []

    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    pcap_path = config.get("pcap_path", "")
    if not pcap_path:
        console.print("  [dim]No pcap path provided for extraction.[/]")
        console.print(pie_modulo())
        return findings

    output_dir = config.get("extract_dir", "")
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(pcap_path), "looktheshark_extracted")
    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Extracting objects with tshark...[/]")
    extracted = extract_objects(pcap_path, output_dir)

    if not extracted:
        console.print("  [dim]No transferred files extracted.[/]")
        console.print(f"  [dim](Verify that tshark is installed and on PATH)[/]")
        console.print(pie_modulo())
        return findings

    console.print(f"  Extracted files: [bold white]{len(extracted)}[/]")
    console.print(f"  Directory: [dim]{output_dir}[/]")
    console.print()

    # ── File Table ─────────────────────────────────────
    tabla = Table(
        show_header=True,
        header_style="tabla_header",
        box=box.SIMPLE_HEAVY,
        border_style="tabla_border",
        padding=(0, 1),
    )
    tabla.add_column("Protocol", style="bold cyan", width=8)
    tabla.add_column("File", width=22)
    tabla.add_column("Ext", width=6)
    tabla.add_column("Size", justify="right", width=9)
    tabla.add_column("Timestamp", style="dim", width=19)
    tabla.add_column("Entropy", width=14)
    tabla.add_column("Type (magic)", width=20)
    tabla.add_column("MD5", style="dim", width=16)

    for finfo in extracted[:20]:
        try:
            with open(finfo["filepath"], "rb") as f:
                header = f.read(32)
            magic_type = detect_magic(header)
        except Exception:
            magic_type = "?"

        try:
            hashes = hash_file(finfo["filepath"])
            md5_short = hashes["md5"][:13] + "..."
        except Exception:
            md5_short = "—"

        finfo["magic_type"] = magic_type
        finfo["hashes"] = hashes if "hashes" in locals() else {}

        from modules import formatear_bytes
        tabla.add_row(
            finfo["protocol"],
            finfo["filename"][:22],
            finfo.get("extension", "") or "-",
            formatear_bytes(finfo["size"]),
            finfo.get("timestamp", "-"),
            finfo.get("entropy_label", "-"),
            magic_type[:20],
            md5_short,
        )

    console.print(tabla)
    console.print()

    # ── Mismatch & Entropy Detection ───────────────────
    mismatch_findings = detect_filetype_mismatch(extracted)
    entropy_findings = detect_high_entropy(extracted)
    
    findings.extend(mismatch_findings)
    findings.extend(entropy_findings)

    if findings:
        for f in findings:
            console.print(f"  {estilo_severidad(f.severidad)}  {f.titulo}")
            console.print(f"      [dim]{f.descripcion}[/]")
        console.print()
    else:
        console.print("  [bold bright_green][OK][/] [dim]No file type mismatches or suspicious high-entropy payloads detected.[/]")
        console.print()

    console.print(pie_modulo())
    return findings
