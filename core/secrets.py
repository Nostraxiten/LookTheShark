"""
core/secrets.py — Deteccion de material sensible dentro del trafico.

Esto es lo que convierte "se transfirio un fichero de 40 KB" en "ese fichero
llevaba dentro una clave privada SSH y un token de AWS". Se aplica sobre
cuerpos HTTP, ficheros extraidos y payloads en claro de cualquier protocolo.

Reglas de la casa:
  - Nunca se imprime el secreto entero. Se muestra un fragmento enmascarado
    suficiente para localizarlo y rotarlo, no para reutilizarlo.
  - Cada patron lleva una comprobacion posterior (longitud, checksum, entropia)
    para bajar los falsos positivos: una regex a pelo sobre trafico real es un
    generador de ruido.
"""

from __future__ import annotations

import base64
import math
import re
from typing import Iterable, List, Optional

# ── Definicion de patrones ────────────────────────────
# (id, nombre legible, regex, severidad, requiere_entropia)
PATRONES = [
    ("aws_access_key", "AWS Access Key ID",
     re.compile(rb"\b((?:AKIA|ASIA|ABIA|ACCA|AIDA)[A-Z0-9]{16})\b"), "critico", False),
    ("aws_secret", "AWS Secret Access Key",
     re.compile(rb"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"), "critico", True),
    ("github_token", "Token de GitHub",
     re.compile(rb"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), "critico", False),
    ("gitlab_token", "Token de GitLab",
     re.compile(rb"\b(glpat-[A-Za-z0-9_-]{20,})\b"), "critico", False),
    ("slack_token", "Token de Slack",
     re.compile(rb"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), "critico", False),
    ("google_api", "Clave de API de Google",
     re.compile(rb"\b(AIza[0-9A-Za-z_-]{35})\b"), "alto", False),
    ("stripe_key", "Clave de Stripe",
     re.compile(rb"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"), "critico", False),
    ("openai_key", "Clave de API tipo OpenAI/Anthropic",
     re.compile(rb"\b((?:sk-proj-|sk-ant-|sk-)[A-Za-z0-9_-]{20,})\b"), "critico", False),
    ("private_key", "Clave privada (PEM)",
     re.compile(rb"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"), "critico", False),
    ("putty_key", "Clave privada PuTTY",
     re.compile(rb"PuTTY-User-Key-File-\d"), "critico", False),
    ("jwt", "JSON Web Token",
     re.compile(rb"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"), "alto", False),
    ("basic_auth_url", "Credenciales embebidas en URL",
     re.compile(rb"[a-z][a-z0-9+.-]*://([^/\s:@]{1,64}):([^/\s:@]{1,64})@"), "critico", False),
    ("password_field", "Campo de contrasena en claro",
     re.compile(rb"(?i)\b(?:password|passwd|pwd|pass|senha|contrasena|clave)\b['\"]?\s*[=:]\s*['\"]?([^'\"&\s,;}]{4,64})"), "alto", False),
    ("api_key_generic", "Clave de API generica",
     re.compile(rb"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret)\b['\"]?\s*[=:]\s*['\"]?([A-Za-z0-9_\-./+=]{16,80})"), "alto", True),
    ("connection_string", "Cadena de conexion con credenciales",
     re.compile(rb"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql|ftp|sftp)://[^\s:@]{1,64}:[^\s:@]{1,64}@[^\s'\"]{3,}"), "critico", False),
    ("bearer", "Cabecera Bearer con token",
     re.compile(rb"(?i)\bBearer\s+([A-Za-z0-9_\-.=]{20,})"), "alto", False),
    ("azure_sas", "Firma SAS de Azure",
     re.compile(rb"\bsig=([A-Za-z0-9%+/=]{40,})"), "alto", False),
    ("twilio", "Credencial de Twilio",
     re.compile(rb"\b(SK[0-9a-fA-F]{32}|AC[0-9a-fA-F]{32})\b"), "alto", False),
    ("sendgrid", "Clave de SendGrid",
     re.compile(rb"\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b"), "critico", False),
    ("npm_token", "Token de npm",
     re.compile(rb"\b(npm_[A-Za-z0-9]{36})\b"), "critico", False),
    ("ssh_pub", "Clave publica SSH autorizada",
     re.compile(rb"\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]{100,}"), "medio", False),
    ("credit_card", "Numero de tarjeta de credito",
     re.compile(rb"\b((?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{2,4})\b"), "critico", False),
    ("iban", "IBAN",
     re.compile(rb"\b([A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){3,7}[A-Z0-9]{1,4})\b"), "alto", False),
    ("dni_es", "DNI/NIE espanol",
     re.compile(rb"\b([0-9XYZ]\d{7}[A-HJ-NP-TV-Z])\b"), "medio", False),
    ("email_pass", "Par correo:contrasena",
     re.compile(rb"\b([\w.+-]+@[\w-]+\.[\w.]{2,})[:|]([^\s:,;|]{6,40})\b"), "alto", False),
    ("cookie_sesion", "Cookie de sesion en claro",
     re.compile(rb"(?i)\b(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session(?:id|_id)?|sid)=([A-Za-z0-9%_-]{12,})"), "medio", False),
]

# Valores que aparecen en documentacion y plantillas: no son fugas reales.
LISTA_BLANCA = {
    b"password", b"changeme", b"your_password", b"xxxxxxxx", b"placeholder",
    b"example", b"yourpassword", b"secret", b"123456", b"12345678", b"test",
    b"redacted", b"dummy", b"none", b"null", b"undefined", b"todo",
    b"your_api_key", b"your-api-key", b"insert_key_here", b"changeit",
    b"aaaaaaaaaaaaaaaa", b"0000000000000000", b"admin", b"root",
}

# Content-Type que casi nunca contienen secretos y generan mucho ruido.
TIPOS_IGNORADOS = ("image/", "video/", "audio/", "font/", "application/font")

MAX_BYTES_ESCANEADOS = 2 * 1024 * 1024
MAX_HALLAZGOS_POR_ORIGEN = 25


class Secreto:
    """Un dato sensible localizado dentro del trafico."""

    __slots__ = ("tipo", "nombre", "severidad", "muestra", "origen", "contexto",
                 "protocolo", "src", "dst", "ts", "url", "confianza")

    def __init__(self):
        self.tipo = ""
        self.nombre = ""
        self.severidad = "medio"
        self.muestra = ""        # SIEMPRE enmascarada
        self.origen = ""         # fichero / cuerpo / cabecera donde aparece
        self.contexto = ""
        self.protocolo = ""
        self.src = ""
        self.dst = ""
        self.ts = 0.0
        self.url = ""
        self.confianza = "media"

    def __repr__(self) -> str:
        return f"<Secreto {self.tipo} {self.muestra}>"


def enmascarar(valor: str) -> str:
    """Deja lo justo para identificar el secreto sin poder usarlo."""
    valor = valor.strip()
    n = len(valor)
    if n <= 8:
        return valor[0] + "*" * max(0, n - 1)
    visible = 4 if n < 24 else 6
    return f"{valor[:visible]}{'*' * 8}{valor[-2:]}  ({n} car.)"


def entropia(texto: bytes) -> float:
    """Entropia de Shannon en bits por caracter."""
    if not texto:
        return 0.0
    frecuencias = {}
    for b in texto:
        frecuencias[b] = frecuencias.get(b, 0) + 1
    total = len(texto)
    return -sum((c / total) * math.log2(c / total) for c in frecuencias.values())


def _luhn_valido(numero: str) -> bool:
    """Checksum de Luhn: descarta la mayoria de falsos positivos de tarjetas."""
    digitos = [int(c) for c in numero if c.isdigit()]
    if len(digitos) < 13:
        return False
    suma = 0
    par = False
    for d in reversed(digitos):
        if par:
            d *= 2
            if d > 9:
                d -= 9
        suma += d
        par = not par
    return suma % 10 == 0


# Tipos cuyo formato ya esta validado por checksum o prefijo: no se les aplica
# el filtro de "poca variedad de caracteres" (una tarjeta 4111... es repetitiva
# pero perfectamente valida).
TIPOS_ESTRUCTURADOS = {"credit_card", "iban", "dni_es", "aws_access_key",
                       "github_token", "private_key", "putty_key"}


def _es_ruido(valor: bytes, tipo: str = "") -> bool:
    limpio = valor.strip().strip(b"'\"").lower()
    if limpio in LISTA_BLANCA:
        return True
    if tipo not in TIPOS_ESTRUCTURADOS and len(set(limpio)) <= 2:
        return True                       # 'aaaaaaa', '0000000'
    if limpio.startswith((b"$", b"{{", b"<%", b"%(", b"${")):  # plantilla
        return True
    return False


_LETRAS_DNI = "TRWAGMYFPDXBNJZSQVHLCKE"


def _dni_valido(texto: str) -> bool:
    """Comprueba la letra de control de un DNI/NIE (modulo 23)."""
    texto = texto.upper()
    if len(texto) != 9:
        return False
    cuerpo, letra = texto[:8], texto[8]
    cuerpo = cuerpo.replace("X", "0").replace("Y", "1").replace("Z", "2")
    if not cuerpo.isdigit():
        return False
    return _LETRAS_DNI[int(cuerpo) % 23] == letra


def _decodificar_jwt(token: bytes) -> str:
    """Saca el 'sub'/'email'/'iss' del payload de un JWT para dar contexto."""
    try:
        payload = token.split(b".")[1]
        payload += b"=" * (-len(payload) % 4)
        import json
        datos = json.loads(base64.urlsafe_b64decode(payload))
        partes = []
        for clave in ("iss", "sub", "email", "name", "aud", "scope", "role"):
            if clave in datos:
                partes.append(f"{clave}={str(datos[clave])[:48]}")
        if "exp" in datos:
            partes.append(f"exp={datos['exp']}")
        return ", ".join(partes[:4])
    except Exception:
        return ""


def escanear(datos: bytes,
             origen: str = "",
             protocolo: str = "",
             src: str = "",
             dst: str = "",
             url: str = "",
             ts: float = 0.0,
             content_type: str = "",
             maximo: int = MAX_HALLAZGOS_POR_ORIGEN) -> List[Secreto]:
    """Busca secretos en un bloque de bytes. Devuelve como mucho `maximo`."""
    if not datos:
        return []
    if content_type and content_type.lower().startswith(TIPOS_IGNORADOS):
        return []

    muestra = datos[:MAX_BYTES_ESCANEADOS]
    encontrados: List[Secreto] = []
    vistos = set()

    for tipo, nombre, patron, severidad, exige_entropia in PATRONES:
        if len(encontrados) >= maximo:
            break

        for m in patron.finditer(muestra):
            if len(encontrados) >= maximo:
                break

            valor = m.group(1) if m.lastindex else m.group(0)
            if _es_ruido(valor, tipo):
                continue

            # Comprobaciones especificas para bajar falsos positivos.
            if exige_entropia and entropia(valor) < 3.2:
                continue
            if tipo == "credit_card" and not _luhn_valido(valor.decode("ascii", "ignore")):
                continue
            if tipo == "iban" and len(valor.replace(b" ", b"")) < 15:
                continue
            if tipo == "password_field" and len(valor) < 4:
                continue
            if tipo == "dni_es" and not _dni_valido(valor.decode("ascii", "ignore")):
                continue

            texto = valor.decode("utf-8", "replace")
            clave = (tipo, texto)
            if clave in vistos:
                continue
            vistos.add(clave)

            s = Secreto()
            s.tipo = tipo
            s.nombre = nombre
            s.severidad = severidad
            s.protocolo = protocolo
            s.src = src
            s.dst = dst
            s.url = url
            s.ts = ts
            s.origen = origen
            s.confianza = "alta" if not exige_entropia and tipo not in (
                "password_field", "api_key_generic", "dni_es") else "media"

            if tipo == "basic_auth_url":
                usuario = m.group(1).decode("utf-8", "replace")
                s.muestra = f"{usuario}:{enmascarar(m.group(2).decode('utf-8', 'replace'))}"
            elif tipo == "email_pass":
                correo = m.group(1).decode("utf-8", "replace")
                s.muestra = f"{correo}:{enmascarar(m.group(2).decode('utf-8', 'replace'))}"
            elif tipo == "private_key":
                s.muestra = texto
                s.confianza = "alta"
            else:
                s.muestra = enmascarar(texto)

            if tipo == "jwt":
                s.contexto = _decodificar_jwt(valor)

            # Un poco de contexto alrededor ayuda a saber donde mirar despues.
            if not s.contexto:
                ini = max(0, m.start() - 40)
                trozo = muestra[ini:m.start()].decode("utf-8", "replace")
                s.contexto = re.sub(r"\s+", " ", trozo).strip()[-40:]

            encontrados.append(s)

    return encontrados


def escanear_cabeceras(cabeceras: dict, **kwargs) -> List[Secreto]:
    """Escanea un dict de cabeceras HTTP (Authorization, Cookie, X-Api-Key...)."""
    if not cabeceras:
        return []
    texto = "\n".join(f"{k}: {v}" for k, v in cabeceras.items()).encode("utf-8", "replace")
    return escanear(texto, **kwargs)


def resumir(secretos: Iterable[Secreto]) -> dict:
    """Agrupa por tipo para el resumen ejecutivo."""
    resumen = {}
    for s in secretos:
        entrada = resumen.setdefault(s.nombre, {"cantidad": 0, "severidad": s.severidad})
        entrada["cantidad"] += 1
    return resumen
