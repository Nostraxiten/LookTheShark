"""
modules/protocols.py — Que se habla en esta red.

Desglose de protocolos y puertos con una lectura encima: cuanto trafico va sin
cifrar, que protocolos deprecados siguen vivos, y que puertos no deberian estar
saliendo a Internet.
"""

from __future__ import annotations

from typing import List

from rich.console import Console

from core import services
from modules import (Confianza, Finding, Severidad, es_ip_privada,
                     formatear_bytes, plural, truncar)
from ui import theme

MODULE_NUM = 2
MODULE_NAME = "Protocolos"
MODULE_ID = "protocols"
MODULE_DESC = "Que se habla, cuanto va sin cifrar y que no deberia estar ahi"

# Protocolo -> (severidad, por que importa, que hacer)
DEPRECADOS = {
    23: ("critico", "Telnet manda todo en texto plano, incluidas las contrasenas y cada tecla pulsada.",
         "Sustituir por SSH y cerrar el puerto 23 en el firewall."),
    21: ("alto", "FTP envia usuario y contrasena legibles por cualquiera que este en el camino.",
         "Migrar a SFTP o FTPS y deshabilitar FTP plano."),
    69: ("alto", "TFTP no tiene ni autenticacion ni cifrado: cualquiera puede leer o escribir ficheros.",
         "Limitarlo a la VLAN de aprovisionamiento o eliminarlo."),
    161: ("medio", "SNMPv1/v2c manda la community string en claro, que equivale a una contrasena.",
          "Pasar a SNMPv3 con autenticacion y cifrado."),
    110: ("alto", "POP3 sin TLS entrega las credenciales del correo en texto plano.",
          "Usar POP3S (995) o IMAPS (993)."),
    143: ("medio", "IMAP sin TLS expone las credenciales del correo.",
          "Forzar STARTTLS o usar IMAPS (993)."),
    80: ("medio", "HTTP sin cifrar: URLs, cookies de sesion y formularios son legibles.",
         "Redirigir a HTTPS y activar HSTS."),
    1723: ("alto", "PPTP esta roto criptograficamente desde hace mas de una decada.",
           "Sustituir la VPN por WireGuard, IPsec/IKEv2 u OpenVPN."),
    512: ("critico", "rexec transmite credenciales en claro.", "Eliminar los servicios r* del sistema."),
    513: ("critico", "rlogin confia en la IP de origen y va sin cifrar.",
          "Eliminar los servicios r* y usar SSH."),
}

# Puertos que casi nunca deberian verse saliendo hacia Internet.
NO_DEBERIA_SALIR = {
    445: "SMB", 139: "NetBIOS", 137: "NetBIOS-NS", 135: "MSRPC",
    3389: "RDP", 5985: "WinRM", 1433: "MSSQL", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
    11211: "Memcached", 623: "IPMI", 2375: "API de Docker", 5900: "VNC",
}


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    total = analisis.paquetes_analizados or 1
    apps = analisis.protocolos_app

    # ── Cuanto va cifrado ─────────────────────────────
    cifrado = sum(c for p, c in analisis.puertos_destino.items() if services.esta_cifrado(p))
    en_claro = sum(c for p, c in analisis.puertos_destino.items()
                   if p in services.SERVICIOS and not services.esta_cifrado(p))
    conocido = cifrado + en_claro

    if conocido:
        pct_claro = en_claro / conocido * 100
        estilo = "sev_critico" if pct_claro > 60 else "sev_medio" if pct_claro > 25 else "exito"
        console.print(
            f"  De los paquetes hacia servicios identificables, "
            f"[{estilo}]{pct_claro:.0f}% viaja sin cifrar[/] "
            f"[dim_text]({en_claro:,} en claro / {cifrado:,} cifrados)[/]"
        )
        console.print("  " + theme.barra(en_claro, conocido, 40, "color(208)")
                      + f"  [dim_text]en claro[/]")
        console.print()

    # ── Protocolos de aplicacion ──────────────────────
    t = theme.tabla("Protocolos de aplicacion")
    t.add_column("Protocolo", style="bold bright_cyan", width=16)
    t.add_column("Paquetes", justify="right", width=11)
    t.add_column("%", justify="right", width=7)
    t.add_column("", width=24)
    t.add_column("Cifrado", width=9)

    maximo = max(apps.values()) if apps else 1
    for proto, cuenta in apps.most_common(14):
        cifrado_txt = "[exito]si[/]" if proto in ("TLS", "HTTPS", "SSH", "QUIC", "IMAPS",
                                                  "POP3S", "SMTPS", "LDAPS", "RDP") \
            else "[sev_medio]no[/]"
        t.add_row(proto, f"{cuenta:,}", theme.porcentaje(cuenta, total),
                  theme.barra(cuenta, maximo, 22), cifrado_txt)
    console.print(t)
    console.print()

    # ── Puertos ───────────────────────────────────────
    puertos = analisis.puertos_destino
    if puertos:
        t2 = theme.tabla("Puertos de destino mas usados")
        t2.add_column("Puerto", style="bold bright_cyan", width=8)
        t2.add_column("Servicio", width=18)
        t2.add_column("Paquetes", justify="right", width=11)
        t2.add_column("Que significa verlo", max_width=44)

        for puerto, cuenta in puertos.most_common(30):
            if services.es_efimero(puerto):
                continue
            explicacion = services.explicacion(puerto) or ""
            t2.add_row(str(puerto), services.servicio(puerto), f"{cuenta:,}",
                       f"[dim_text]{truncar(explicacion, 42)}[/]")
            if t2.row_count >= 12:
                break
        console.print(t2)
        console.print()

    # ── Actividad en el tiempo ────────────────────────
    if analisis.actividad and analisis.duracion > 2:
        segundos = sorted(analisis.actividad)
        inicio, fin = segundos[0], segundos[-1]
        # Se rellenan los segundos sin trafico para que los silencios se vean.
        if fin - inicio < 200_000:
            serie = [analisis.actividad.get(s, 0) for s in range(inicio, fin + 1)]
        else:
            serie = [analisis.actividad[s] for s in segundos]
        console.print(f"  [titulo]Ritmo del trafico[/] [dim_text](picos = rafagas)[/]")
        console.print(f"  [dato]{theme.sparkline(serie, 64)}[/]")
        console.print(f"  [dim_text]{len(serie)} segundos de captura, "
                      f"pico de {max(serie) if serie else 0} paquetes/s[/]")
        console.print()

    # ── Hallazgos ─────────────────────────────────────
    hallazgos.extend(_protocolos_deprecados(analisis, config))
    hallazgos.extend(_servicios_expuestos(analisis))
    hallazgos.extend(_puertos_sospechosos(analisis))

    for f in hallazgos:
        console.print(theme.panel_hallazgo(
            f.titulo, f.severidad, f.descripcion, f.evidencia,
            f.recomendacion, f.confianza))

    if not hallazgos:
        console.print(theme.sin_hallazgos(
            "Ningun protocolo deprecado ni servicio expuesto donde no deberia."))

    console.print(theme.pie_modulo())
    return hallazgos


def _protocolos_deprecados(analisis, config: dict) -> List[Finding]:
    hallazgos = []
    esperados = {p.lower() for p in
                 (config.get("baseline_profile") or {}).get("expected_protocols", [])}

    for puerto, (sev, motivo, arreglo) in DEPRECADOS.items():
        cuenta = analisis.puertos_destino.get(puerto, 0)
        if not cuenta:
            continue
        nombre = services.servicio(puerto)
        if nombre.lower() in esperados:
            continue

        # Quien lo usa: eso convierte el dato en algo accionable.
        usuarios = sorted({
            f.cliente_ip for f in analisis.flujos if f.servidor_puerto == puerto
        })[:5]
        servidores = sorted({
            f.servidor_ip for f in analisis.flujos if f.servidor_puerto == puerto
        })[:5]

        evidencia = f"{cuenta:,} paquetes hacia el puerto {puerto}"
        if usuarios and servidores:
            evidencia += f" · {', '.join(usuarios)} → {', '.join(servidores)}"

        hallazgos.append(Finding(
            titulo=f"{nombre} en uso (puerto {puerto})",
            descripcion=motivo,
            severidad=sev,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=evidencia,
            recomendacion=arreglo,
            patron="cleartext_protocol",
            host=usuarios[0] if usuarios else "",
            datos={"puerto": puerto, "clientes": usuarios, "servidores": servidores},
        ))
    return hallazgos


def _servicios_expuestos(analisis) -> List[Finding]:
    """Servicios internos hablando con Internet: eso no deberia pasar."""
    hallazgos = []
    vistos = set()

    for flujo in analisis.flujos:
        puerto = flujo.servidor_puerto
        if puerto not in NO_DEBERIA_SALIR:
            continue
        cliente_local = es_ip_privada(flujo.cliente_ip)
        servidor_local = es_ip_privada(flujo.servidor_ip)
        if cliente_local == servidor_local:
            continue  # ambos dentro o ambos fuera: no es el caso peligroso

        clave = (puerto, flujo.servidor_ip)
        if clave in vistos:
            continue
        vistos.add(clave)

        nombre = NO_DEBERIA_SALIR[puerto]
        hallazgos.append(Finding(
            titulo=f"{nombre} atravesando la frontera de Internet (puerto {puerto})",
            descripcion=(
                f"{nombre} es un servicio de red interna. Verlo cruzar entre la LAN "
                f"e Internet significa que esta expuesto o que alguien lo esta usando "
                f"como canal. Los puertos {puerto} abiertos hacia fuera son la via de "
                f"entrada mas explotada por ransomware y botnets."
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"{flujo.cliente_ip} → {flujo.servidor_ip}:{puerto}",
            recomendacion=(
                f"Bloquea el puerto {puerto} en el perimetro. Si necesitas ese acceso "
                f"desde fuera, ponlo detras de una VPN, nunca publicado directamente."
            ),
            patron="exposed_service",
            host=flujo.servidor_ip,
            host_so=analisis.so_de(flujo.servidor_ip),
            datos={"puerto": puerto},
        ))
    return hallazgos[:12]


def _puertos_sospechosos(analisis) -> List[Finding]:
    """Puertos asociados historicamente a herramientas ofensivas y C2."""
    hallazgos = []
    for puerto, cuenta in analisis.puertos_destino.items():
        if services.categoria(puerto) != "sospechoso" or not cuenta:
            continue
        nombre, _cifrado, _cat, motivo = services.SERVICIOS[puerto]
        clientes = sorted({f.cliente_ip for f in analisis.flujos
                           if f.servidor_puerto == puerto})[:4]
        hallazgos.append(Finding(
            titulo=f"Trafico hacia el puerto {puerto} ({nombre})",
            descripcion=(
                f"{motivo} Por si solo no prueba nada — cualquiera puede usar ese "
                f"puerto para algo legitimo — pero merece una comprobacion manual."
            ),
            severidad=Severidad.MEDIO,
            confianza=Confianza.BAJA,
            modulo=MODULE_ID,
            evidencia=f"{cuenta:,} paquetes"
                      + (f" desde {', '.join(clientes)}" if clientes else ""),
            recomendacion=(
                f"Identifica que proceso escucha o se conecta al puerto {puerto} en "
                f"los equipos implicados antes de dar nada por bueno."
            ),
            patron="suspicious_port",
            host=clientes[0] if clientes else "",
            datos={"puerto": puerto},
        ))
    return hallazgos
