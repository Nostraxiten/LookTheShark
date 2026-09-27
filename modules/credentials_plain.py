"""
modules/credentials_plain.py — Cleartext Credentials Module.

Detects passwords sent in plain text over HTTP (Basic Auth, POST forms),
FTP, Telnet, and POP3/IMAP.
"""

import base64
import re
from collections import defaultdict
from typing import List

from rich.console import Console

from modules import Finding, Confianza, safe_get_attr
from ui.theme import cabecera_modulo, pie_modulo, estilo_severidad


MODULE_NUM  = 7
MODULE_NAME = "Cleartext Credentials"
MODULE_ID   = "creds"

# Case-insensitive field names that indicate a credential field in form data
_CRED_FIELDS = re.compile(
    r"\b(password|passwd|pwd|pass|login|user|username|email)\s*=",
    re.IGNORECASE,
)


def _decode_hex_payload(hex_str: str) -> str:
    """Decode a pyshark colon-separated hex payload string to UTF-8 text.

    Root cause of the original bug: pyshark populates http.file_data as a
    colon-separated hex string (e.g. "75:73:65:72:6e:61:6d:65:3d...") rather
    than decoded text.  Because the raw hex string is always truthy, the
    ``if not payload`` branch that checked for the urlencoded-form layer was
    never reached.  We now decode the hex string explicitly.
    """
    try:
        raw = bytes.fromhex(hex_str.replace(":", ""))
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_http_form_fields(pkt) -> str:
    """Return URL-decoded form body text from an HTTP packet, or empty string.

    Strategy (in priority order):
      1. Decode http.file_data (colon-hex → bytes → UTF-8).
      2. Read the urlencoded-form layer's string representation directly.

    Both paths are checked regardless of which one succeeds first, because
    some builds of pyshark/tshark populate one but not the other.
    """
    text_parts = []

    # Path 1: decode the hex payload from http.file_data
    if hasattr(pkt, "http") and hasattr(pkt.http, "file_data"):
        try:
            hex_raw = str(pkt.http.file_data)
            decoded = _decode_hex_payload(hex_raw)
            if decoded:
                text_parts.append(decoded)
        except Exception:
            pass

    # Path 2: urlencoded-form layer (populated by tshark's HTTP dissector)
    if hasattr(pkt, "urlencoded-form"):
        try:
            text_parts.append(str(getattr(pkt, "urlencoded-form")))
        except Exception:
            pass

    return " ".join(text_parts)


def detect_cleartext_creds(packets) -> List[Finding]:
    """Scans for credentials transmitted in cleartext."""
    findings = []
    seen = set()

    # Per-stream Telnet state: stream_key -> list of (direction, data) tuples
    # direction: "server" or "client"
    telnet_streams = defaultdict(list)

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

            # ── 2. HTTP POST form credentials ───────────────
            # Fixed: decode the hex payload AND check the urlencoded-form layer
            # regardless of whether http.file_data is present, since that field
            # is almost always truthy (it holds raw bytes as colon-hex).
            form_text = _extract_http_form_fields(pkt)
            if form_text and _CRED_FIELDS.search(form_text):
                key = (src, dst, "http_post")
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        titulo="Possible cleartext credentials (HTTP POST)",
                        descripcion=(
                            "Detected form submission via unencrypted HTTP containing "
                            "password/credential fields."
                        ),
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

        # ── 3. FTP USER/PASS ───────────────────────────────
        if hasattr(pkt, "ftp"):
            req_arg = safe_get_attr(pkt, "ftp", "request_arg")
            req_cmd = safe_get_attr(pkt, "ftp", "request_command")

            if req_cmd in ("USER", "PASS"):
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

        # ── 4. POP3 USER/PASS ──────────────────────────────
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

        # ── 5. Telnet credential extraction ────────────────
        # pyshark exposes plaintext Telnet payload via telnet.data per packet.
        # We track per-TCP-stream the sequence of server prompts and client
        # responses to reconstruct login/password exchanges.
        if hasattr(pkt, "telnet"):
            telnet_data = safe_get_attr(pkt, "telnet", "data", "")
            if not telnet_data:
                continue

            # Determine traffic direction from port convention:
            # server-side packets originate from port 23; client packets go to 23.
            sport = safe_get_attr(pkt, "tcp", "srcport", "")
            dport = safe_get_attr(pkt, "tcp", "dstport", "")
            is_server = (sport == "23")
            stream_key = tuple(sorted([src, dst]))  # bidirectional key

            direction = "server" if is_server else "client"
            telnet_streams[stream_key].append((direction, telnet_data))

    # ── Post-loop: analyse collected Telnet stream sequences ──────────────────
    _LOGIN_PROMPT    = re.compile(r"login\s*:", re.IGNORECASE)
    _PASSWORD_PROMPT = re.compile(r"password\s*:", re.IGNORECASE)

    for stream_key, events in telnet_streams.items():
        captured_user = None
        captured_pass = None
        awaiting = None   # "user" | "password"

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
            key = (host_a, host_b, "telnet_cred", captured_user)
            if key not in seen:
                seen.add(key)
                user_display = captured_user or "<unknown>"
                findings.append(Finding(
                    titulo="Telnet credential intercepted",
                    descripcion=(
                        f"Telnet login sequence captured in cleartext: "
                        f"{user_display}:{'***' if captured_pass else '<not captured>'}"
                    ),
                    severidad="critico",
                    confianza=Confianza.ALTA,
                    modulo=MODULE_ID,
                    evidencia=f"{host_a} <-> {host_b} (Telnet)",
                    patron="cleartext_creds",
                    interpretacion=(
                        "Cleartext Credential Transmission (Telnet) | "
                        "Plaintext username/password exchanged over unencrypted Telnet session | "
                        "Legacy network device management, embedded systems, or isolated lab environments"
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
