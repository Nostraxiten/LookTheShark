"""
modules/credentials_plain.py — Cleartext Credentials & Sensitive Data Module.

Detects passwords, usernames, authentication tokens, and exposed email addresses
transmitted in plain text over HTTP (Basic Auth, POST forms), FTP, Telnet, POP3, IMAP, and SMTP.
"""

import base64
import json
import re
import urllib.parse
from collections import defaultdict
from typing import List, Tuple, Dict, Any

from rich.console import Console
from rich.table import Table
from rich import box

from modules import Finding, Confidence, safe_get_attr
from ui.theme import module_header, module_footer, severity_style


MODULE_NUM  = 7
MODULE_NAME = "Cleartext Credentials & Sensitive Data"
MODULE_ID   = "creds"

# Case-insensitive field names that indicate a credential field in form data
_CRED_FIELDS = re.compile(
    r"\b(password|passwd|pwd|pass|login|user|username|email|correo|contrasena|clave)\s*=",
    re.IGNORECASE,
)

# Email address extraction regex
_EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b",
    re.IGNORECASE,
)

# File and resource extensions to filter out from email false positives
_EMAIL_EXCLUDE_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".zip", ".tar", ".gz"
)


def _decode_hex_payload(hex_str: str) -> str:
    """Decode a pyshark colon-separated hex payload string to UTF-8 text."""
    try:
        raw = bytes.fromhex(hex_str.replace(":", "").replace(" ", ""))
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_emails_from_text(text: str) -> List[str]:
    """Extract valid email addresses from text, avoiding common false positives."""
    if not text:
        return []
    matches = _EMAIL_REGEX.findall(text)
    valid_emails = []
    for m in matches:
        m_lower = m.lower()
        if any(m_lower.endswith(ext) for ext in _EMAIL_EXCLUDE_EXTS):
            continue
        if m_lower.startswith(("http:", "https:", "ftp:")):
            continue
        if m not in valid_emails:
            valid_emails.append(m)
    return valid_emails


def _extract_http_form_fields(pkt) -> str:
    """Return URL-decoded form body text from an HTTP packet, or empty string."""
    text_parts = []

    # Path 1: decode the hex payload from http.file_data
    if hasattr(pkt, "http"):
        if hasattr(pkt.http, "file_data"):
            try:
                hex_raw = str(pkt.http.file_data)
                decoded = _decode_hex_payload(hex_raw)
                if decoded:
                    text_parts.append(decoded)
            except Exception:
                pass

        if hasattr(pkt.http, "request_uri_query"):
            try:
                text_parts.append(str(pkt.http.request_uri_query))
            except Exception:
                pass

    # Path 2: urlencoded-form layer
    if hasattr(pkt, "urlencoded-form"):
        try:
            text_parts.append(str(getattr(pkt, "urlencoded-form")))
        except Exception:
            pass

    return " ".join(text_parts)


def _parse_credentials_from_text(text: str) -> Dict[str, Any]:
    """Parse username, password, and email fields from URL-encoded strings, JSON, or key-value pairs."""
    result: Dict[str, Any] = {"user": "", "pass": "", "emails": [], "all_fields": {}}
    if not text:
        return result

    result["emails"] = _extract_emails_from_text(text)

    # 1. Try parsing as JSON
    stripped = text.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                for k, v in data.items():
                    k_str = str(k).strip()
                    v_str = str(v).strip()
                    result["all_fields"][k_str] = v_str
                    k_lower = k_str.lower()
                    if any(u in k_lower for u in ("user", "login", "account", "usuario", "usr")) and not result["user"]:
                        result["user"] = v_str
                    elif any(p in k_lower for p in ("password", "passwd", "pwd", "pass", "clave", "contrasena", "secret")) and not result["pass"]:
                        result["pass"] = v_str
                    elif any(e in k_lower for e in ("email", "mail", "correo")):
                        if not result["user"]:
                            result["user"] = v_str
        except Exception:
            pass

    # 2. Try parsing URL-encoded query pairs
    chunks = re.split(r'[&\r\n;]', text)
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            k, _, v = chunk.partition("=")
            k_clean = urllib.parse.unquote_plus(k.strip())
            v_clean = urllib.parse.unquote_plus(v.strip())
        elif ":" in chunk and not chunk.startswith(("http:", "https:")):
            k, _, v = chunk.partition(":")
            k_clean = k.strip()
            v_clean = v.strip()
        else:
            continue

        if not k_clean:
            continue

        result["all_fields"][k_clean] = v_clean
        k_lower = k_clean.lower()

        # Password matching
        if any(p == k_lower or k_lower.startswith(p) or k_lower.endswith(p) for p in ("password", "passwd", "pwd", "pass", "clave", "contrasena", "secret")):
            if not result["pass"] and v_clean:
                result["pass"] = v_clean
        # User matching
        elif any(u == k_lower or k_lower.startswith(u) or k_lower.endswith(u) for u in ("username", "user", "login", "usr", "usuario", "account", "uname")):
            if not result["user"] and v_clean:
                result["user"] = v_clean
        # Email matching
        elif any(e == k_lower or "email" in k_lower or "correo" in k_lower for e in ("email", "mail")):
            if not result["user"] and v_clean:
                result["user"] = v_clean
            if v_clean not in result["emails"] and _extract_emails_from_text(v_clean):
                result["emails"].append(v_clean)

    # Fallback: if username is empty but email was captured, use email
    if not result["user"] and result["emails"]:
        result["user"] = result["emails"][0]

    return result


def scan_cleartext_data(packets) -> Tuple[List[Finding], List[Dict[str, str]], List[Dict[str, str]]]:
    """Scans packets for unencrypted credentials and emails.

    Returns:
        (findings, cred_records, email_records)
    """
    findings: List[Finding] = []
    cred_records: List[Dict[str, str]] = []
    email_records: List[Dict[str, str]] = []

    seen_creds = set()
    seen_emails = set()

    # Per-stream Telnet state: stream_key -> list of (direction, data)
    telnet_streams = defaultdict(list)

    # State tracking for protocols with multi-packet auth (FTP, POP3)
    ftp_sessions = defaultdict(dict)
    pop_sessions = defaultdict(dict)

    for pkt in packets:
        src = safe_get_attr(pkt, "ip", "src")
        dst = safe_get_attr(pkt, "ip", "dst")
        if not src or not dst:
            continue

        # ── 1. HTTP Basic Auth ─────────────────────────────
        if hasattr(pkt, "http"):
            auth = safe_get_attr(pkt, "http", "authorization")
            if auth and auth.startswith("Basic "):
                b64 = auth.split(" ")[1]
                try:
                    decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                except Exception:
                    decoded = ""

                if decoded:
                    if ":" in decoded:
                        u, p = decoded.split(":", 1)
                    else:
                        u, p = decoded, "<no password>"

                    key = (src, dst, "http_basic", u, p)
                    if key not in seen_creds:
                        seen_creds.add(key)
                        cred_records.append({
                            "proto": "HTTP Basic Auth",
                            "src": src,
                            "dst": dst,
                            "user": u,
                            "pass": p
                        })
                        for em in _extract_emails_from_text(u):
                            if (em, src, dst) not in seen_emails:
                                seen_emails.add((em, src, dst))
                                email_records.append({
                                    "email": em, "proto": "HTTP Basic Auth", "src": src, "dst": dst
                                })

                        findings.append(Finding(
                            title="Cleartext credentials (HTTP Basic Auth)",
                            description=f"Captured unencrypted HTTP Basic Auth credentials — Usuario: {u} | Contraseña: {p}",
                            severity="critical",
                            confidence=Confidence.HIGH,
                            module=MODULE_ID,
                            evidence=f"{src} -> {dst} (HTTP)",
                            pattern="cleartext_creds",
                            interpretation=(
                                "Unencrypted Authentication Transmission / Credential Exposure | "
                                "Base64 encoded authentication header sent over cleartext HTTP | "
                                "Legacy internal services, local intranet testing, or misconfigured reverse proxy not enforcing HTTPS redirect"
                            )
                        ))

            # ── 2. HTTP POST form credentials ───────────────
            form_text = _extract_http_form_fields(pkt)
            if form_text and _CRED_FIELDS.search(form_text):
                parsed = _parse_credentials_from_text(form_text)
                u = parsed["user"] or "<not specified>"
                p = parsed["pass"] or "<not specified>"

                for em in parsed["emails"]:
                    if (em, src, dst) not in seen_emails:
                        seen_emails.add((em, src, dst))
                        email_records.append({
                            "email": em, "proto": "HTTP POST", "src": src, "dst": dst
                        })

                key = (src, dst, "http_post", u, p)
                if key not in seen_creds:
                    seen_creds.add(key)
                    cred_records.append({
                        "proto": "HTTP POST",
                        "src": src,
                        "dst": dst,
                        "user": u,
                        "pass": p
                    })
                    findings.append(Finding(
                        title="Cleartext credentials (HTTP POST)",
                        description=(
                            f"Detected unencrypted HTTP form submission — "
                            f"Usuario: {u} | Contraseña: {p}"
                        ),
                        severity="high" if (u != "<not specified>" or p != "<not specified>") else "medium",
                        confidence=Confidence.HIGH if p != "<not specified>" else Confidence.MEDIUM,
                        module=MODULE_ID,
                        evidence=f"{src} -> {dst} (HTTP POST)",
                        pattern="cleartext_creds",
                        interpretation=(
                            "Unencrypted Form Authentication / Credential Exposure | "
                            "Form submission payload containing plaintext password fields over unencrypted HTTP | "
                            "Local management consoles, embedded router portals, or development test fixtures"
                        )
                    ))

            # Check HTTP request headers / URIs for exposed emails
            uri = safe_get_attr(pkt, "http", "request_full_uri") or safe_get_attr(pkt, "http", "request_uri")
            if uri:
                for em in _extract_emails_from_text(uri):
                    if (em, src, dst) not in seen_emails:
                        seen_emails.add((em, src, dst))
                        email_records.append({"email": em, "proto": "HTTP URI", "src": src, "dst": dst})

        # ── 3. FTP USER/PASS ───────────────────────────────
        if hasattr(pkt, "ftp"):
            req_cmd = safe_get_attr(pkt, "ftp", "request_command")
            req_arg = safe_get_attr(pkt, "ftp", "request_arg")
            session_key = (src, dst)

            if req_cmd == "USER":
                ftp_sessions[session_key]["user"] = req_arg
                for em in _extract_emails_from_text(req_arg):
                    if (em, src, dst) not in seen_emails:
                        seen_emails.add((em, src, dst))
                        email_records.append({"email": em, "proto": "FTP", "src": src, "dst": dst})
            elif req_cmd == "PASS":
                ftp_sessions[session_key]["pass"] = req_arg
                u = ftp_sessions[session_key].get("user") or "<unknown>"
                p = req_arg
                key = (src, dst, "ftp_cred", u, p)
                if key not in seen_creds:
                    seen_creds.add(key)
                    cred_records.append({
                        "proto": "FTP",
                        "src": src,
                        "dst": dst,
                        "user": u,
                        "pass": p
                    })
                    findings.append(Finding(
                        title="FTP credential intercepted (USER/PASS)",
                        description=f"FTP credentials captured in cleartext — Usuario: {u} | Contraseña: {p}",
                        severity="critical",
                        confidence=Confidence.HIGH,
                        module=MODULE_ID,
                        evidence=f"{src} -> {dst} (FTP)",
                        pattern="cleartext_creds",
                        interpretation=(
                            "Cleartext Credential Transmission (FTP) | "
                            "Plaintext USER/PASS commands sent across unencrypted File Transfer Protocol | "
                            "Legacy network appliances, automated batch file transfer scripts, or lab environments"
                        )
                    ))

        # ── 4. POP3 USER/PASS ──────────────────────────────
        if hasattr(pkt, "pop"):
            req_cmd = safe_get_attr(pkt, "pop", "request_command")
            req_arg = safe_get_attr(pkt, "pop", "request_arg") or safe_get_attr(pkt, "pop", "request_parameter")
            session_key = (src, dst)

            if req_cmd == "USER":
                pop_sessions[session_key]["user"] = req_arg
                for em in _extract_emails_from_text(req_arg):
                    if (em, src, dst) not in seen_emails:
                        seen_emails.add((em, src, dst))
                        email_records.append({"email": em, "proto": "POP3", "src": src, "dst": dst})
            elif req_cmd == "PASS":
                pop_sessions[session_key]["pass"] = req_arg
                u = pop_sessions[session_key].get("user") or "<unknown>"
                p = req_arg
                key = (src, dst, "pop_cred", u, p)
                if key not in seen_creds:
                    seen_creds.add(key)
                    cred_records.append({
                        "proto": "POP3",
                        "src": src,
                        "dst": dst,
                        "user": u,
                        "pass": p
                    })
                    findings.append(Finding(
                        title="POP3 credential intercepted (USER/PASS)",
                        description=f"POP3 authentication captured in cleartext — Usuario: {u} | Contraseña: {p}",
                        severity="critical",
                        confidence=Confidence.HIGH,
                        module=MODULE_ID,
                        evidence=f"{src} -> {dst} (POP3)",
                        pattern="cleartext_creds",
                        interpretation=(
                            "Cleartext Credential Transmission (POP3) | "
                            "Plaintext USER/PASS authentication over unencrypted POP3 mail protocol | "
                            "Legacy mail client configurations, local mail test harnesses, or outdated printer/scanner setups"
                        )
                    ))

        # ── 5. SMTP Email detection ────────────────────────
        if hasattr(pkt, "smtp"):
            smtp_cmd = safe_get_attr(pkt, "smtp", "command_line") or safe_get_attr(pkt, "smtp", "req_parameter")
            if smtp_cmd:
                for em in _extract_emails_from_text(smtp_cmd):
                    if (em, src, dst) not in seen_emails:
                        seen_emails.add((em, src, dst))
                        email_records.append({"email": em, "proto": "SMTP", "src": src, "dst": dst})

        # ── 6. Telnet credential extraction ────────────────
        if hasattr(pkt, "telnet"):
            telnet_data = safe_get_attr(pkt, "telnet", "data", "")
            if not telnet_data:
                continue

            sport = safe_get_attr(pkt, "tcp", "srcport", "")
            is_server = (sport == "23")
            stream_key = tuple(sorted([src, dst]))

            direction = "server" if is_server else "client"
            telnet_streams[stream_key].append((direction, telnet_data))

    # ── Post-loop: analyse collected Telnet stream sequences ──────────────────
    _LOGIN_PROMPT    = re.compile(r"login\s*:", re.IGNORECASE)
    _PASSWORD_PROMPT = re.compile(r"password\s*:", re.IGNORECASE)

    for stream_key, events in telnet_streams.items():
        captured_user = None
        captured_pass = None
        awaiting = None

        for direction, data in events:
            if direction == "server":
                if _LOGIN_PROMPT.search(data):
                    awaiting = "user"
                elif _PASSWORD_PROMPT.search(data):
                    awaiting = "password"
            else:  # client response
                if awaiting == "user" and data.strip():
                    captured_user = data.strip()
                    awaiting = None
                elif awaiting == "password" and data.strip():
                    captured_pass = data.strip()
                    awaiting = None

        if captured_user or captured_pass:
            host_a, host_b = stream_key
            u = captured_user or "<unknown>"
            p = captured_pass or "<not captured>"
            key = (host_a, host_b, "telnet_cred", u, p)
            if key not in seen_creds:
                seen_creds.add(key)
                cred_records.append({
                    "proto": "Telnet",
                    "src": host_a,
                    "dst": host_b,
                    "user": u,
                    "pass": p
                })
                findings.append(Finding(
                    title="Telnet credential intercepted",
                    description=(
                        f"Telnet login sequence captured in cleartext — "
                        f"Usuario: {u} | Contraseña: {p}"
                    ),
                    severity="critical",
                    confidence=Confidence.HIGH,
                    module=MODULE_ID,
                    evidence=f"{host_a} <-> {host_b} (Telnet)",
                    pattern="cleartext_creds",
                    interpretation=(
                        "Cleartext Credential Transmission (Telnet) | "
                        "Plaintext username/password exchanged over unencrypted Telnet session | "
                        "Legacy network device management, embedded systems, or isolated lab environments"
                    )
                ))

    # Generate Findings for exposed emails
    for rec in email_records:
        em = rec["email"]
        proto = rec["proto"]
        s = rec["src"]
        d = rec["dst"]
        key = ("email_finding", em, s, d)
        if key not in seen_creds:
            seen_creds.add(key)
            findings.append(Finding(
                title=f"Cleartext email address exposed ({proto})",
                description=f"Observed cleartext email transmission in network traffic — Correo: {em}",
                severity="medium",
                confidence=Confidence.HIGH,
                module=MODULE_ID,
                evidence=f"{s} -> {d} ({proto})",
                pattern="email_exposure",
                interpretation=(
                    "Sensitive Data Exposure / Cleartext Email | "
                    "Plaintext email address observed without transport encryption | "
                    "Target for OSINT reconnaissance, phishing, or compliance violation"
                )
            ))

    return findings, cred_records, email_records


def detect_cleartext_creds(packets) -> List[Finding]:
    """Compatibility wrapper returning findings list."""
    findings, _, _ = scan_cleartext_data(packets)
    return findings


def run(packets, config: dict, console: Console) -> List[Finding]:
    findings: List[Finding] = []
    console.print(module_header(MODULE_NUM, MODULE_NAME))

    creds_findings, cred_records, email_records = scan_cleartext_data(packets)
    findings.extend(creds_findings)

    # ── 1. Table of Intercepted Credentials ──────────────────
    if cred_records:
        console.print("  [bold white]Captured Cleartext Credentials / Credenciales Extraídas:[/]")
        console.print()

        table_c = Table(
            show_header=True,
            header_style="table_header",
            box=box.SIMPLE_HEAVY,
            border_style="table_border",
            padding=(0, 1),
        )
        table_c.add_column("Protocol", style="bold cyan", width=18)
        table_c.add_column("Source IP", width=16)
        table_c.add_column("Destination IP", width=16)
        table_c.add_column("Usuario", style="bold bright_yellow", width=24)
        table_c.add_column("Contraseña", style="bold bright_red", width=26)

        for rec in cred_records:
            table_c.add_row(
                rec["proto"],
                rec["src"],
                rec["dst"],
                rec["user"],
                rec["pass"],
            )
        console.print(table_c)
        console.print()

    # ── 2. Table of Exposed Email Addresses ───────────────────
    if email_records:
        console.print("  [bold white]Exposed Email Addresses / Correos Electrónicos Detectados:[/]")
        console.print()

        table_e = Table(
            show_header=True,
            header_style="table_header",
            box=box.SIMPLE_HEAVY,
            border_style="table_border",
            padding=(0, 1),
        )
        table_e.add_column("Correo Electrónico / Email", style="bold bright_cyan", width=34)
        table_e.add_column("Protocolo / Contexto", style="white", width=20)
        table_e.add_column("Origen (Src)", width=16)
        table_e.add_column("Destino (Dst)", width=16)

        for rec in email_records:
            table_e.add_row(
                rec["email"],
                rec["proto"],
                rec["src"],
                rec["dst"],
            )
        console.print(table_e)
        console.print()

    # ── 3. Findings Detail ────────────────────────────────────
    if findings:
        console.print("  [bold white]Findings Detail / Detalle de Hallazgos:[/]")
        for f in findings:
            console.print(f"  {severity_style(f.severity)}  {f.title}")
            console.print(f"      [bold white]{f.description}[/]")
            console.print(f"      [dim]-> {f.evidence}[/]")
        console.print()
    else:
        console.print("  [bold bright_green][OK][/] [dim]No cleartext credentials or email addresses detected in capture.[/]")
        console.print()

    console.print(module_footer())
    return findings
