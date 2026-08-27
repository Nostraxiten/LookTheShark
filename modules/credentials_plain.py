"""
modules/credentials_plain.py — Contrasenas que viajaron legibles.

Un login capturado no es un aviso teorico: es una cuenta que ya esta
comprometida frente a cualquiera que estuviera escuchando. Este modulo recoge
lo que los parsers de protocolo ya extrajeron (HTTP Basic, formularios, FTP,
SMTP, POP3, IMAP, Telnet) y lo presenta de forma que se pueda actuar.

Las contrasenas se muestran siempre enmascaradas: se ve la primera letra y la
longitud, que es lo que hace falta para identificarla y cambiarla.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List

from rich.console import Console

from modules import (Confianza, Finding, Severidad, es_ip_privada,
                     formatear_hora, plural, truncar)
from ui import theme

MODULE_NUM = 7
MODULE_NAME = "Credenciales en claro"
MODULE_ID = "creds"
MODULE_DESC = "Cuentas comprometidas por viajar sin cifrar"

ALTERNATIVA = {
    "FTP": "SFTP (sobre SSH) o FTPS",
    "Telnet": "SSH",
    "HTTP Basic": "HTTPS, y mejor con tokens en vez de Basic",
    "HTTP formulario": "HTTPS con HSTS activado",
    "SMTP": "SMTP con STARTTLS obligatorio o SMTPS (465)",
    "POP3": "POP3S (995)",
    "IMAP": "IMAPS (993)",
}


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    credenciales = analisis.credenciales
    if not credenciales:
        console.print(theme.sin_hallazgos(
            "No se capturo ninguna credencial en texto plano."))
        console.print("  [dim_text]Ojo: esto solo cubre los protocolos sin cifrar. "
                      "Un login por HTTPS no aparece aqui aunque exista.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    console.print(f"  [sev_critico] {len(credenciales)} credenciales capturadas [/] "
                  f"en texto plano")
    console.print()

    t = theme.tabla("Cuentas expuestas")
    t.add_column("Protocolo", style="bold bright_cyan", width=17)
    t.add_column("Usuario", max_width=24)
    t.add_column("Contrasena", max_width=18)
    t.add_column("Origen → destino", max_width=32)
    t.add_column("Hora", width=9)

    for c in credenciales:
        perfil = analisis.hosts.get(c.src)
        origen = c.src + (f" [lan]({perfil.so})[/]" if perfil and perfil.so else "")
        t.add_row(
            c.protocolo,
            theme.esc(truncar(c.usuario, 22)) or "[dim]—[/]",
            f"[sev_alto]{theme.esc(c.password_enmascarada)}[/]" if c.password else "[dim]—[/]",
            truncar(f"{origen} → {c.dst}:{c.puerto}", 30),
            formatear_hora(c.ts),
        )
    console.print(t)
    console.print()

    # ── Detalle por credencial ────────────────────────
    for c in credenciales[:12]:
        console.print(f"  [titulo]{c.protocolo}[/] [dim_text]· {theme.esc(c.metodo)}[/]")
        console.print(f"      [etiqueta]Usuario    [/] [dato]{theme.esc(c.usuario)}[/]")
        if c.password:
            console.print(f"      [etiqueta]Contrasena [/] "
                          f"[sev_alto]{theme.esc(c.password_enmascarada)}[/]")
        console.print(f"      [etiqueta]Capturada  [/] {c.src} → {c.dst}:{c.puerto} "
                      f"a las {formatear_hora(c.ts)}")
        if c.servidor_banner:
            console.print(f"      [etiqueta]Servidor   [/] "
                          f"[dim_text]{theme.esc(truncar(c.servidor_banner, 60))}[/]")
        console.print()

    hallazgos.extend(_hallazgos(analisis, credenciales))

    console.print(theme.caja_explicativa(
        "Estas contrasenas ya no son secretas. No hace falta que nadie las "
        "'descifre': viajaron legibles y esta captura lo demuestra. La respuesta "
        "correcta es cambiarlas todas y migrar el protocolo, en ese orden.",
        "Que significa realmente"))

    console.print(theme.pie_modulo())
    return hallazgos


def _hallazgos(analisis, credenciales) -> List[Finding]:
    hallazgos = []
    por_protocolo = defaultdict(list)
    for c in credenciales:
        por_protocolo[c.protocolo].append(c)

    for protocolo, lista in por_protocolo.items():
        usuarios = sorted({c.usuario for c in lista if c.usuario})
        destinos = sorted({f"{c.dst}:{c.puerto}" for c in lista})
        # Que la conexion salga a Internet lo empeora: mas gente en el camino.
        externa = any(not es_ip_privada(c.dst) for c in lista)

        hallazgos.append(Finding(
            titulo=f"Credenciales de {protocolo} capturadas en claro "
                   f"({plural(len(lista), 'cuenta', 'cuentas')})",
            descripcion=(
                f"El protocolo {protocolo} transmitio usuario y contrasena de forma "
                f"legible. Cualquier equipo del camino — un switch mal configurado, "
                f"un punto WiFi, el ISP, o alguien haciendo ARP spoofing en la misma "
                f"red — pudo quedarse con ellas."
                + (" Ademas la conexion sale a Internet, asi que el numero de "
                   "posibles observadores es mucho mayor." if externa else "")
            ),
            severidad=Severidad.CRITICO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=(f"Usuarios: {', '.join(usuarios[:5]) or 'no identificados'} · "
                       f"hacia {', '.join(destinos[:3])}"),
            recomendacion=(
                f"1) Cambia ahora la contrasena de {', '.join(usuarios[:3]) or 'las cuentas afectadas'}. "
                f"2) Migra a {ALTERNATIVA.get(protocolo, 'una version cifrada del protocolo')}. "
                f"3) Revisa los accesos recientes de esas cuentas por si ya se usaron."
            ),
            patron="cleartext_creds",
            host=lista[0].src,
            host_so=analisis.so_de(lista[0].src),
            timestamp=formatear_hora(lista[0].ts),
            datos={"protocolo": protocolo, "usuarios": usuarios[:10],
                   "cuentas": len(lista)},
        ))

    # Reutilizacion de la misma contrasena en varios sitios.
    por_password = defaultdict(list)
    for c in credenciales:
        if c.password:
            por_password[c.password].append(c)
    for password, lista in por_password.items():
        servicios = {f"{c.protocolo}@{c.dst}" for c in lista}
        if len(servicios) < 2:
            continue
        hallazgos.append(Finding(
            titulo="La misma contrasena se reutiliza en varios servicios",
            descripcion=(
                f"Una contrasena identica aparece en {len(servicios)} servicios "
                f"distintos. Al haber sido capturada una vez, quedan comprometidos "
                f"todos ellos a la vez."
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=", ".join(sorted(servicios)[:5]),
            recomendacion=(
                "Cambia la contrasena en todos los servicios afectados con valores "
                "distintos y despliega un gestor de contrasenas."
            ),
            patron="password_reuse",
            host=lista[0].src,
            host_so=analisis.so_de(lista[0].src),
        ))

    return hallazgos
