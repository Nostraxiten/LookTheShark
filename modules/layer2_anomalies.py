"""
modules/layer2_anomalies.py — Lo que pasa por debajo de IP.

En la capa 2 estan los ataques que dejan a un atacante en medio de toda la
conversacion sin tocar ningun servidor: ARP spoofing, DHCP falso, inundacion de
la tabla MAC. Son silenciosos y no aparecen en ningun log de aplicacion; solo se
ven en una captura.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import List

from rich.console import Console

from core import fingerprint
from modules import (Confianza, Finding, Severidad, formatear_hora, plural,
                     truncar)
from ui import theme

MODULE_NUM = 10
MODULE_NAME = "Red local (capa 2)"
MODULE_ID = "layer2"
MODULE_DESC = "ARP, DHCP y quien podria estar en medio de la conversacion"


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    if not analisis.arp and not analisis.dhcp:
        console.print("  [dim_text]No hay trafico ARP ni DHCP: la captura no se "
                      "tomo en un segmento de red local, o solo recoge trafico "
                      "enrutado.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    # ── Tabla ARP observada ───────────────────────────
    if analisis.arp:
        t = theme.tabla("Tabla ARP reconstruida")
        t.add_column("IP", style="bold bright_cyan", no_wrap=True)
        t.add_column("MAC", width=19)
        t.add_column("Fabricante", max_width=26)
        t.add_column("Sistema", max_width=22)

        for ip in sorted(analisis.arp, key=_orden_ip):
            macs = sorted(analisis.arp[ip])
            perfil = analisis.hosts.get(ip)
            so = f"{theme.icono_so(perfil.familia)} {perfil.so}" if perfil and perfil.so else "—"
            for i, mac in enumerate(macs):
                conflicto = len(macs) > 1
                estilo_mac = "sev_critico" if conflicto else "white"
                t.add_row(
                    ip if i == 0 else "",
                    f"[{estilo_mac}]{mac}[/]",
                    theme.esc(truncar(fingerprint.fabricante_mac(mac) or "—", 24)),
                    truncar(so, 20) if i == 0 else "",
                )
        console.print(t)
        console.print()

    # ── DHCP ──────────────────────────────────────────
    if analisis.dhcp:
        t2 = theme.tabla("Actividad DHCP")
        t2.add_column("Tipo", width=10)
        t2.add_column("Cliente", max_width=18)
        t2.add_column("Nombre del equipo", max_width=20)
        t2.add_column("Vendor class", max_width=20)
        t2.add_column("Servidor", max_width=16)

        for d in analisis.dhcp[:15]:
            t2.add_row(d["tipo_nombre"],
                       truncar(d["client_mac"] or d["src"], 16),
                       theme.esc(truncar(d["hostname"] or "—", 18)),
                       theme.esc(truncar(d["vendor_class"] or "—", 18)),
                       truncar(d["server_id"] or d["src"], 14))
        console.print(t2)
        console.print()

    hallazgos.extend(_arp_spoofing(analisis))
    hallazgos.extend(_dhcp_rogue(analisis))
    hallazgos.extend(_arp_gratuitos(analisis))
    hallazgos.extend(_inundacion_mac(analisis))

    for f in hallazgos:
        console.print(theme.panel_hallazgo(
            f.titulo, f.severidad, f.descripcion, f.evidencia,
            f.recomendacion, f.confianza))

    if not hallazgos:
        console.print(theme.sin_hallazgos(
            "Capa 2 limpia: cada IP tiene una sola MAC y un solo servidor DHCP."))

    console.print(theme.pie_modulo())
    return hallazgos


def _orden_ip(ip: str):
    try:
        return tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def _arp_spoofing(analisis) -> List[Finding]:
    hallazgos = []
    for ip, macs in analisis.arp.items():
        if len(macs) < 2:
            continue

        fabricantes = {m: fingerprint.fabricante_mac(m) or "desconocido" for m in macs}
        detalle = ", ".join(f"{m} ({f})" for m, f in fabricantes.items())

        # Que la IP sea la del gateway lo convierte en el caso grave: el
        # atacante se pone entre todos los equipos e Internet.
        parece_gateway = ip.endswith(".1") or ip.endswith(".254") or ip in analisis.gateways

        hallazgos.append(Finding(
            titulo=f"ARP spoofing: {len(macs)} MACs reclaman la IP {ip}",
            descripcion=(
                f"Dos o mas tarjetas de red dicen ser {ip}. Como los equipos hacen "
                f"caso a la ultima respuesta ARP que reciben, quien envie mas "
                f"respuestas se queda en medio de la conversacion y puede leer y "
                f"modificar todo lo que pase por ahi."
                + (" Ademas esa IP parece ser la puerta de enlace, con lo que el "
                   "atacante estaria interceptando TODO el trafico hacia Internet."
                   if parece_gateway else
                   " La otra explicacion posible es un conflicto de IP por un error "
                   "de configuracion.")
            ),
            severidad=Severidad.CRITICO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"IP {ip} anunciada por: {detalle}",
            recomendacion=(
                "Localiza fisicamente las MACs implicadas por el puerto del switch. "
                "Como medida permanente activa Dynamic ARP Inspection y DHCP "
                "Snooping en los switches; sin eso, este ataque siempre funciona."
            ),
            patron="arp_spoof",
            host=ip,
            datos={"ip": ip, "macs": sorted(macs)},
        ))
    return hallazgos


def _dhcp_rogue(analisis) -> List[Finding]:
    """Mas de un servidor DHCP respondiendo = alguien reparte configuracion falsa."""
    hallazgos = []
    servidores = defaultdict(set)
    for d in analisis.dhcp:
        if d["tipo"] in (2, 5):          # OFFER / ACK
            if d["server_id"] or d["src"]:
                servidores[d["src"]].add(d.get("mac_ethernet", ""))

    if len(servidores) < 2:
        return hallazgos

    lista = sorted(servidores)
    hallazgos.append(Finding(
        titulo=f"Varios servidores DHCP en la misma red ({len(lista)})",
        descripcion=(
            "Mas de un equipo esta repartiendo configuracion de red. Un servidor "
            "DHCP no autorizado puede asignarse a si mismo como puerta de enlace y "
            "como DNS, con lo que ve y puede redirigir todo el trafico de los "
            "equipos que le hagan caso. Tambien puede ser simplemente un router "
            "domestico que alguien enchufo sin avisar."
        ),
        severidad=Severidad.ALTO,
        confianza=Confianza.ALTA,
        modulo=MODULE_ID,
        evidencia="Servidores que responden: " + ", ".join(lista),
        recomendacion=(
            "Identifica cual es el servidor legitimo, localiza el otro por su MAC y "
            "desconectalo. Activa DHCP Snooping en los switches para que solo el "
            "puerto del servidor autorizado pueda responder."
        ),
        patron="dhcp_rogue",
        host=lista[0],
    ))
    return hallazgos


def _arp_gratuitos(analisis) -> List[Finding]:
    """Anuncios ARP no solicitados en rafaga: la firma del envenenamiento activo."""
    hallazgos = []
    if len(analisis.arp_gratuitos) < 5:
        return hallazgos

    por_mac = Counter(g["mac"] for g in analisis.arp_gratuitos)
    mac, veces = por_mac.most_common(1)[0]
    if veces < 5:
        return hallazgos

    ips = sorted({g["ip"] for g in analisis.arp_gratuitos if g["mac"] == mac})
    hallazgos.append(Finding(
        titulo=f"Anuncios ARP no solicitados en rafaga desde {mac}",
        descripcion=(
            f"Esa MAC envio {veces} respuestas ARP que nadie habia pedido. Un "
            f"equipo normal manda una o dos al arrancar. Repetirlas continuamente "
            f"es la forma de mantener envenenada la cache de los demas equipos: "
            f"cada anuncio sobrescribe la entrada correcta."
        ),
        severidad=Severidad.ALTO,
        confianza=Confianza.MEDIA,
        modulo=MODULE_ID,
        evidencia=f"{mac} ({fingerprint.fabricante_mac(mac) or 'fabricante desconocido'}) "
                  f"anunciando {', '.join(ips[:4])}",
        recomendacion=(
            "Comprueba si hay un balanceador o un cluster que use ARP gratuito de "
            "forma legitima. Si no, aisla esa MAC."
        ),
        patron="arp_spoof",
        datos={"mac": mac, "veces": veces},
    ))
    return hallazgos


def _inundacion_mac(analisis) -> List[Finding]:
    """Muchisimas MACs distintas: intento de desbordar la tabla del switch."""
    hallazgos = []
    macs = set()
    for conjunto in analisis.arp.values():
        macs |= conjunto
    for perfil in analisis.hosts.values():
        macs |= perfil.macs

    if len(macs) < 200:
        return hallazgos

    hallazgos.append(Finding(
        titulo=f"Numero anormal de direcciones MAC distintas ({len(macs)})",
        descripcion=(
            "Una red local normal tiene tantas MACs como equipos. Ver cientos en "
            "una captura corta encaja con un ataque de inundacion (MAC flooding): "
            "se llena la tabla del switch para que empiece a reenviar todo el "
            "trafico por todos los puertos, convirtiendolo en un concentrador y "
            "permitiendo escuchar conversaciones ajenas."
        ),
        severidad=Severidad.ALTO,
        confianza=Confianza.MEDIA,
        modulo=MODULE_ID,
        evidencia=f"{len(macs)} MACs distintas frente a "
                  f"{len(analisis.hosts_locales)} equipos con IP",
        recomendacion=(
            "Activa port security en los switches limitando el numero de MACs por "
            "puerto. Localiza el puerto por el que entran esas MACs."
        ),
        patron="mac_flooding",
    ))
    return hallazgos
