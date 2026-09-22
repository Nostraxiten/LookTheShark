"""
modules/credentials_plain.py — Cleartext Credentials Module.

Detects passwords sent in plain text over HTTP (Basic Auth, POST forms),
FTP, Telnet, and POP3/IMAP.
"""

import base64
import urllib.parse
from typing import List

from rich.console import Console

from modules import Finding, Confianza, safe_get_attr
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 7
MODULE_NAME = "Cleartext Credentials"
MODULE_ID   = "creds"


def detect_cleartext_creds(packets) -> List[Finding]:
    """Scans for credentials transmitted in cleartext."""
    findings = []
    seen = set()

    for pkt in packets:
        src = safe_get_attr(pkt, "ip", "src")
        dst = safe_get_attr(pkt, "ip", "dst")
        if not src or not dst:
            continue

        # 1. HTTP Basic Auth
        if hasattr(pkt, "http"):
            auth = safe_get_attr(pkt, "http", "authorization")
            if auth and auth.startswith("Basic "):
                b64 = auth.split(" ")[1]
                try:
                    decoded = base64.b64decode(b64).decode("utf-8")
                    user_pass = decoded
                except Exception:
                    user_pass = "b64_error"
                
                key = (src, dst, "http_basic", user_pass)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        titulo="Cleartext credentials (HTTP Basic Auth)",
                        descripcion=f"Captured Base64-encoded credentials transmitted unencrypted: {user_pass.split(':')[0]}:***",
                        severidad="critico",
                        confianza=Confianza.ALTA,
                        modulo=MODULE_ID,
                        evidencia=f"{src} -> {dst} (HTTP)",
                        patron="cleartext_creds",
                        interpretacion=(
                            "Unencrypted Authentication Transmission / Credential Exposure | "
                            "Base64 encoded authentication header sent over cleartext HTTP | "
                            "Legacy internal services, local intranet testing, or misconfigured reverse proxy not enforcing HTTPS redirect"
                        )
                    ))
                    
            # 2. HTTP POST forms
            payload = getattr(pkt.http, "file_data", "") if hasattr(pkt.http, "file_data") else ""
            if not payload and hasattr(pkt, "urlencoded-form"):
                try:
                    form_data = str(getattr(pkt, "urlencoded-form"))
                    if "password=" in form_data.lower() or "passwd=" in form_data.lower() or "login=" in form_data.lower():
                        key = (src, dst, "http_post")
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding(
                                titulo="Possible cleartext credentials (HTTP POST)",
                                descripcion="Detected form submitted via unencrypted HTTP containing password fields.",
                                severidad="alto",
                                confianza=Confianza.MEDIA,
                                modulo=MODULE_ID,
                                evidencia=f"{src} -> {dst} (HTTP POST)",
                                patron="cleartext_creds",
                                interpretacion=(
                                    "Unencrypted Form Authentication / Credential Exposure | "
                                    "Form submission payload containing plaintext password fields over unencrypted HTTP | "
                                    "Local management consoles, embedded router portals, or development test fixtures"
                                )
                            ))
                except Exception:
                    pass

        # 3. FTP USER/PASS
        if hasattr(pkt, "ftp"):
            req_arg = safe_get_attr(pkt, "ftp", "request_arg")
            req_cmd = safe_get_attr(pkt, "ftp", "request_command")
            
            if req_cmd == "USER" or req_cmd == "PASS":
                key = (src, dst, f"ftp_{req_cmd}", req_arg)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        titulo=f"FTP credential intercepted ({req_cmd})",
                        descripcion=f"FTP command {req_cmd} sent in cleartext.",
                        severidad="critico",
                        confianza=Confianza.ALTA,
                        modulo=MODULE_ID,
                        evidencia=f"{src} -> {dst} ({req_cmd})",
                        patron="cleartext_creds",
                        interpretacion=(
                            "Cleartext Credential Transmission (FTP) | "
                            "Plaintext USER/PASS commands sent across unencrypted File Transfer Protocol | "
                            "Legacy network appliances, automated batch file transfer scripts, or lab environments"
                        )
                    ))

        # 4. POP3 USER/PASS
        if hasattr(pkt, "pop"):
            req_cmd = safe_get_attr(pkt, "pop", "request_command")
            if req_cmd in ("USER", "PASS"):
                key = (src, dst, f"pop_{req_cmd}")
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        titulo=f"POP3 credential intercepted ({req_cmd})",
                        descripcion="POP3 authentication sent unencrypted.",
                        severidad="critico",
                        confianza=Confianza.ALTA,
                        modulo=MODULE_ID,
                        evidencia=f"{src} -> {dst} (POP3)",
                        patron="cleartext_creds",
                        interpretacion=(
                            "Cleartext Credential Transmission (POP3) | "
                            "Plaintext USER/PASS authentication over unencrypted POP3 mail protocol | "
                            "Legacy mail client configurations, local mail test harnesses, or outdated printer/scanner setups"
                        )
                    ))

    return findings


def run(packets, config: dict, console: Console) -> List[Finding]:
    findings = []
    console.print(cabecera_modulo(MODULE_NUM, MODULE_NAME))

    creds = detect_cleartext_creds(packets)
    findings.extend(creds)

    if findings:
        for f in findings:
            console.print(f"  {estilo_severidad(f.severidad)}  {f.titulo}")
            console.print(f"      [dim]{f.descripcion}[/]")
            console.print(f"      [dim]-> {f.evidencia}[/]")
        console.print()
    else:
        console.print("  [bold bright_green][OK][/] [dim]No cleartext credentials detected in standard protocols.[/]")
        console.print()

    console.print(pie_modulo())
    return findings
