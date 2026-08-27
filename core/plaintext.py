"""
core/plaintext.py — Lectura de protocolos de texto plano sobre flujos TCP.

Estos protocolos son conversaciones linea a linea, asi que una vez reensamblado
el flujo se leen como un dialogo. Aqui salen las credenciales de verdad, los
correos enviados, los comandos ejecutados por Telnet y los canales de IRC que
usan las botnets.

Cubre: FTP, SMTP, POP3, IMAP, Telnet, IRC y SMB (solo metadatos).
"""

from __future__ import annotations

import base64
import re
from typing import Dict, List, Optional, Tuple

MAX_LINEAS = 2000
MAX_LARGO_LINEA = 4096


class Credencial:
    """Un par usuario/contrasena visto viajando sin cifrar."""

    __slots__ = ("protocolo", "usuario", "password", "src", "dst", "puerto",
                 "ts", "metodo", "evidencia", "servidor_banner")

    def __init__(self):
        self.protocolo = ""
        self.usuario = ""
        self.password = ""
        self.src = ""
        self.dst = ""
        self.puerto = 0
        self.ts = 0.0
        self.metodo = ""
        self.evidencia = ""
        self.servidor_banner = ""

    @property
    def password_enmascarada(self) -> str:
        if not self.password:
            return ""
        n = len(self.password)
        if n <= 2:
            return "*" * n
        return f"{self.password[0]}{'*' * (n - 1)}  ({n} car.)"

    def __repr__(self) -> str:
        return f"<Credencial {self.protocolo} {self.usuario}@{self.dst}>"


class ComandoRemoto:
    """Un comando visto en una sesion interactiva sin cifrar (Telnet, FTP...)."""

    __slots__ = ("protocolo", "comando", "src", "dst", "puerto", "ts", "respuesta")

    def __init__(self, protocolo="", comando="", src="", dst="", puerto=0, ts=0.0):
        self.protocolo = protocolo
        self.comando = comando
        self.src = src
        self.dst = dst
        self.puerto = puerto
        self.ts = ts
        self.respuesta = ""


class CorreoSMTP:
    """Un correo enviado por SMTP sin cifrar."""

    __slots__ = ("remitente", "destinatarios", "asunto", "adjuntos", "src",
                 "dst", "ts", "tamano", "cuerpo_muestra")

    def __init__(self):
        self.remitente = ""
        self.destinatarios: List[str] = []
        self.asunto = ""
        self.adjuntos: List[str] = []
        self.src = ""
        self.dst = ""
        self.ts = 0.0
        self.tamano = 0
        self.cuerpo_muestra = ""


def _lineas(datos: bytes, maximo: int = MAX_LINEAS) -> List[str]:
    """Parte un flujo en lineas de texto, tolerando bytes binarios."""
    salida = []
    for bruto in datos.split(b"\n")[:maximo]:
        linea = bruto.rstrip(b"\r")[:MAX_LARGO_LINEA]
        salida.append(linea.decode("utf-8", "replace"))
    return salida


def _decodificar_b64(texto: str) -> str:
    try:
        relleno = texto + "=" * (-len(texto) % 4)
        return base64.b64decode(relleno).decode("utf-8", "replace")
    except Exception:
        return ""


# ──────────────────────────────────────────────────────
# FTP
# ──────────────────────────────────────────────────────
def analizar_ftp(flujo) -> Tuple[List[Credencial], List[ComandoRemoto], List[str]]:
    """Extrae credenciales, comandos y ficheros de una sesion FTP."""
    creds: List[Credencial] = []
    comandos: List[ComandoRemoto] = []
    ficheros: List[str] = []

    cliente = _lineas(bytes(flujo.cliente.datos))
    servidor = _lineas(bytes(flujo.servidor.datos))
    banner = next((l for l in servidor if l.startswith("220")), "")

    usuario = ""
    for linea in cliente:
        if not linea:
            continue
        partes = linea.split(" ", 1)
        cmd = partes[0].upper()
        arg = partes[1].strip() if len(partes) > 1 else ""

        if cmd == "USER":
            usuario = arg
        elif cmd == "PASS":
            c = Credencial()
            c.protocolo = "FTP"
            c.usuario = usuario or "(desconocido)"
            c.password = arg
            c.src = flujo.cliente_ip
            c.dst = flujo.servidor_ip
            c.puerto = flujo.servidor_puerto
            c.ts = flujo.primer_ts
            c.metodo = "USER/PASS en claro"
            c.servidor_banner = banner
            c.evidencia = f"USER {c.usuario} / PASS <{len(arg)} caracteres>"
            creds.append(c)
        elif cmd in ("RETR", "STOR", "APPE", "DELE", "RNTO"):
            ficheros.append(f"{cmd} {arg}")
            comandos.append(ComandoRemoto("FTP", linea, flujo.cliente_ip,
                                          flujo.servidor_ip, flujo.servidor_puerto,
                                          flujo.primer_ts))
        elif cmd in ("CWD", "MKD", "RMD", "SITE", "EXEC"):
            comandos.append(ComandoRemoto("FTP", linea, flujo.cliente_ip,
                                          flujo.servidor_ip, flujo.servidor_puerto,
                                          flujo.primer_ts))

    return creds, comandos, ficheros


# ──────────────────────────────────────────────────────
# SMTP
# ──────────────────────────────────────────────────────
_RE_ASUNTO = re.compile(r"^Subject:\s*(.+)$", re.I | re.M)
_RE_DE = re.compile(r"^From:\s*(.+)$", re.I | re.M)
_RE_PARA = re.compile(r"^To:\s*(.+)$", re.I | re.M)
_RE_ADJUNTO = re.compile(r'filename="?([^"\r\n;]+)"?', re.I)


def analizar_smtp(flujo) -> Tuple[List[Credencial], List[CorreoSMTP]]:
    """Extrae autenticaciones y correos de una sesion SMTP."""
    creds: List[Credencial] = []
    correos: List[CorreoSMTP] = []

    crudo = bytes(flujo.cliente.datos)
    cliente = _lineas(crudo)

    esperando_auth = None
    usuario_pendiente = ""

    correo = CorreoSMTP()
    correo.src = flujo.cliente_ip
    correo.dst = flujo.servidor_ip
    correo.ts = flujo.primer_ts
    en_datos = False
    cuerpo: List[str] = []

    for linea in cliente:
        alto = linea.upper()

        if en_datos:
            if linea == ".":
                en_datos = False
                texto = "\n".join(cuerpo)
                correo.tamano = len(texto)
                m = _RE_ASUNTO.search(texto)
                if m:
                    correo.asunto = m.group(1).strip()[:200]
                if not correo.remitente:
                    m = _RE_DE.search(texto)
                    if m:
                        correo.remitente = m.group(1).strip()[:120]
                correo.adjuntos = list(dict.fromkeys(_RE_ADJUNTO.findall(texto)))[:20]
                correo.cuerpo_muestra = "\n".join(
                    l for l in cuerpo if l and not l.startswith(("Content-", "MIME-", "--"))
                )[:400]
                if correo.remitente or correo.destinatarios or correo.asunto:
                    correos.append(correo)
                correo = CorreoSMTP()
                correo.src = flujo.cliente_ip
                correo.dst = flujo.servidor_ip
                correo.ts = flujo.primer_ts
                cuerpo = []
            elif len(cuerpo) < 500:
                cuerpo.append(linea)
            continue

        if alto.startswith("MAIL FROM"):
            correo.remitente = linea.split(":", 1)[-1].strip().strip("<>")[:120]
        elif alto.startswith("RCPT TO"):
            correo.destinatarios.append(linea.split(":", 1)[-1].strip().strip("<>")[:120])
        elif alto == "DATA":
            en_datos = True
        elif alto.startswith("AUTH LOGIN"):
            resto = linea[10:].strip()
            if resto:
                usuario_pendiente = _decodificar_b64(resto)
                esperando_auth = "password"
            else:
                esperando_auth = "usuario"
        elif alto.startswith("AUTH PLAIN"):
            resto = linea[10:].strip()
            if resto:
                partes = _decodificar_b64(resto).split("\x00")
                if len(partes) >= 3:
                    creds.append(_cred_smtp(flujo, partes[1], partes[2], "AUTH PLAIN"))
            else:
                esperando_auth = "plain"
        elif esperando_auth == "usuario":
            usuario_pendiente = _decodificar_b64(linea)
            esperando_auth = "password"
        elif esperando_auth == "password":
            creds.append(_cred_smtp(flujo, usuario_pendiente,
                                    _decodificar_b64(linea), "AUTH LOGIN (Base64)"))
            esperando_auth = None
        elif esperando_auth == "plain":
            partes = _decodificar_b64(linea).split("\x00")
            if len(partes) >= 3:
                creds.append(_cred_smtp(flujo, partes[1], partes[2], "AUTH PLAIN (Base64)"))
            esperando_auth = None

    return creds, correos


def _cred_smtp(flujo, usuario: str, password: str, metodo: str) -> Credencial:
    c = Credencial()
    c.protocolo = "SMTP"
    c.usuario = usuario
    c.password = password
    c.src = flujo.cliente_ip
    c.dst = flujo.servidor_ip
    c.puerto = flujo.servidor_puerto
    c.ts = flujo.primer_ts
    c.metodo = metodo
    c.evidencia = f"{metodo}: {usuario}"
    return c


# ──────────────────────────────────────────────────────
# POP3 / IMAP
# ──────────────────────────────────────────────────────
def analizar_pop_imap(flujo, protocolo: str) -> List[Credencial]:
    """Extrae credenciales de POP3 o IMAP en claro."""
    creds: List[Credencial] = []
    cliente = _lineas(bytes(flujo.cliente.datos))
    usuario = ""

    for linea in cliente:
        partes = linea.split(" ")
        if protocolo == "POP3":
            if len(partes) >= 2 and partes[0].upper() == "USER":
                usuario = partes[1]
            elif len(partes) >= 2 and partes[0].upper() == "PASS":
                creds.append(_cred_generica(flujo, protocolo, usuario,
                                            " ".join(partes[1:]), "USER/PASS en claro"))
        else:  # IMAP: "<tag> LOGIN usuario password"
            if len(partes) >= 4 and partes[1].upper() == "LOGIN":
                creds.append(_cred_generica(flujo, protocolo,
                                            partes[2].strip('"'),
                                            partes[3].strip('"'),
                                            "LOGIN en claro"))
            elif len(partes) >= 3 and partes[1].upper() == "AUTHENTICATE" \
                    and partes[2].upper() == "PLAIN":
                # La credencial va en la linea siguiente en Base64.
                idx = cliente.index(linea)
                if idx + 1 < len(cliente):
                    campos = _decodificar_b64(cliente[idx + 1]).split("\x00")
                    if len(campos) >= 3:
                        creds.append(_cred_generica(flujo, protocolo, campos[1],
                                                    campos[2], "AUTHENTICATE PLAIN"))
    return creds


def _cred_generica(flujo, protocolo, usuario, password, metodo) -> Credencial:
    c = Credencial()
    c.protocolo = protocolo
    c.usuario = usuario or "(desconocido)"
    c.password = password
    c.src = flujo.cliente_ip
    c.dst = flujo.servidor_ip
    c.puerto = flujo.servidor_puerto
    c.ts = flujo.primer_ts
    c.metodo = metodo
    c.evidencia = f"{metodo}: {usuario}"
    return c


# ──────────────────────────────────────────────────────
# Telnet
# ──────────────────────────────────────────────────────
def _limpiar_telnet(datos: bytes) -> str:
    """Quita la negociacion IAC y deja solo lo que se tecleo/imprimio."""
    salida = bytearray()
    pos = 0
    fin = len(datos)
    while pos < fin:
        b = datos[pos]
        if b == 0xFF:                     # IAC
            if pos + 1 < fin and datos[pos + 1] == 0xFA:   # subnegociacion
                cierre = datos.find(b"\xff\xf0", pos)
                pos = (cierre + 2) if cierre != -1 else fin
            else:
                pos += 3
            continue
        if b in (0x00, 0x07):
            pos += 1
            continue
        salida.append(b)
        pos += 1
    return salida.decode("utf-8", "replace")


def analizar_telnet(flujo) -> Tuple[List[Credencial], List[ComandoRemoto], str]:
    """Reconstruye una sesion Telnet: login y comandos tecleados."""
    creds: List[Credencial] = []
    comandos: List[ComandoRemoto] = []

    texto_cliente = _limpiar_telnet(bytes(flujo.cliente.datos))
    texto_servidor = _limpiar_telnet(bytes(flujo.servidor.datos))

    # En Telnet el servidor hace eco de lo tecleado, asi que la transcripcion
    # del servidor es la sesion legible; el cliente son las pulsaciones.
    transcripcion = texto_servidor[:8000]

    m = re.search(r"(?:login|Username|user)\s*:\s*([^\r\n]{1,64})", transcripcion, re.I)
    usuario = m.group(1).strip() if m else ""

    # La contrasena no se hace eco: hay que sacarla de las pulsaciones del
    # cliente que van justo despues del prompt de password.
    password = ""
    if re.search(r"password\s*:", transcripcion, re.I):
        lineas_cliente = [l for l in texto_cliente.replace("\r", "\n").split("\n") if l.strip()]
        if usuario:
            for i, l in enumerate(lineas_cliente):
                if l.strip() == usuario and i + 1 < len(lineas_cliente):
                    password = lineas_cliente[i + 1].strip()
                    break
        elif len(lineas_cliente) >= 2:
            password = lineas_cliente[1].strip()

    if usuario or password:
        c = Credencial()
        c.protocolo = "Telnet"
        c.usuario = usuario or "(desconocido)"
        c.password = password
        c.src = flujo.cliente_ip
        c.dst = flujo.servidor_ip
        c.puerto = flujo.servidor_puerto
        c.ts = flujo.primer_ts
        c.metodo = "sesion Telnet sin cifrar"
        c.evidencia = "Login capturado del eco de la sesion"
        creds.append(c)

    # Comandos: lineas del eco que van detras de un prompt tipico.
    for linea in re.findall(r"[$#>]\s*([^\r\n]{2,120})", transcripcion):
        limpio = linea.strip()
        if limpio and not limpio.lower().startswith(("password", "login")):
            comandos.append(ComandoRemoto("Telnet", limpio, flujo.cliente_ip,
                                          flujo.servidor_ip, flujo.servidor_puerto,
                                          flujo.primer_ts))

    return creds, comandos[:40], transcripcion


# ──────────────────────────────────────────────────────
# IRC
# ──────────────────────────────────────────────────────
def analizar_irc(flujo) -> Tuple[List[str], List[str], List[str]]:
    """Devuelve (nicks, canales, mensajes) de una sesion IRC."""
    nicks, canales, mensajes = [], [], []
    for linea in _lineas(bytes(flujo.cliente.datos)) + _lineas(bytes(flujo.servidor.datos)):
        if linea.startswith("NICK "):
            nicks.append(linea[5:].strip())
        elif linea.startswith("JOIN "):
            canales.append(linea[5:].strip())
        elif " PRIVMSG " in linea:
            mensajes.append(linea.split(" PRIVMSG ", 1)[1][:200])
    return (list(dict.fromkeys(nicks))[:10],
            list(dict.fromkeys(canales))[:10],
            mensajes[:30])


# ──────────────────────────────────────────────────────
# Banners de servicio
# ──────────────────────────────────────────────────────
_BANNERS = [
    (re.compile(rb"^SSH-([\d.]+)-(\S+)"), "SSH"),
    (re.compile(rb"^220[- ].*?(?:FTP|FileZilla|vsFTPd|ProFTPD|Pure-FTPd)", re.I), "FTP"),
    (re.compile(rb"^220[- ].*?(?:SMTP|ESMTP|Postfix|Exim|Sendmail)", re.I), "SMTP"),
    (re.compile(rb"^\+OK .*(?:POP3|Dovecot)", re.I), "POP3"),
    (re.compile(rb"^\* OK .*IMAP", re.I), "IMAP"),
    (re.compile(rb"^RFB (\d{3}\.\d{3})"), "VNC"),
    (re.compile(rb"^HTTP/1\.[01] \d{3}"), "HTTP"),
    (re.compile(rb"^\x00\x00\x00.\xffSMB"), "SMB"),
    (re.compile(rb"MySQL|mariadb", re.I), "MySQL"),
    (re.compile(rb"^-ERR|^\+PONG|^\$-1", re.I), "Redis"),
]


def detectar_banner(datos: bytes) -> Tuple[str, str]:
    """Devuelve (servicio, banner_legible) del primer bloque de un servidor."""
    if not datos:
        return ("", "")
    primera = datos.split(b"\r\n", 1)[0][:200]
    for patron, servicio in _BANNERS:
        if patron.search(primera):
            return (servicio, primera.decode("utf-8", "replace").strip())
    # Banner generico: si es texto imprimible, lo mostramos igual.
    if primera and all(9 <= b <= 13 or 32 <= b <= 126 for b in primera[:60]):
        return ("", primera.decode("ascii", "replace").strip())
    return ("", "")


def version_software(banner: str) -> str:
    """Saca 'producto version' de un banner para poder buscar CVEs a mano."""
    if not banner:
        return ""
    m = re.search(r"([A-Za-z][A-Za-z0-9_+-]{2,24})[/ _-]v?(\d+\.\d+(?:\.\d+)?)", banner)
    return f"{m.group(1)} {m.group(2)}" if m else ""
