"""
modules/file_extraction.py — Que ficheros cruzaron la red.

Ya no se llama a `tshark --export-objects`: los ficheros salen directamente de
los flujos reensamblados por el nucleo, en la misma pasada que todo lo demas.
Eso elimina la dependencia de Wireshark y cuatro relecturas completas del pcap.

De cada fichero interesa: que dice ser, que es de verdad (magic bytes), quien lo
mando a quien, y su hash para cruzarlo con VirusTotal o con la lista de hashes
conocidos de la organizacion.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import List

from rich.console import Console

from core import carving
from modules import (Confianza, Finding, Severidad, es_ip_privada,
                     formatear_bytes, formatear_hora, plural, truncar)
from ui import theme

MODULE_NUM = 5
MODULE_NAME = "Ficheros transferidos"
MODULE_ID = "files"
MODULE_DESC = "Que se descargo y subio, y si era lo que decia ser"


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    ficheros = analisis.ficheros
    if not ficheros:
        console.print("  [dim_text]No se reconstruyo ningun fichero.[/]")
        if analisis.tls:
            console.print("  [dim_text]La mayor parte del trafico va cifrado: los "
                          "ficheros que viajen por HTTPS no se pueden extraer de "
                          "una captura sin las claves de sesion.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    tipos = Counter(f.tipo_real for f in ficheros)
    volumen = sum(f.tamano for f in ficheros)
    sospechosos = analisis.ficheros_sospechosos()

    console.print(theme.tabla_clave_valor([
        ("Ficheros reconstruidos", f"[valor]{len(ficheros)}[/]"),
        ("Volumen total", formatear_bytes(volumen)),
        ("Tipos distintos", f"[valor]{len(tipos)}[/]"),
        ("Marcados como sospechosos",
         f"[sev_alto]{len(sospechosos)}[/]" if sospechosos else "[exito]0[/]"),
    ]))
    console.print()

    # ── Tabla de ficheros ─────────────────────────────
    t = theme.tabla("Ficheros vistos")
    t.add_column("", width=2)
    t.add_column("Nombre", style="bright_cyan", max_width=28)
    t.add_column("Es realmente", max_width=26)
    t.add_column("Tamano", justify="right", width=9)
    t.add_column("Ruta", max_width=24)
    t.add_column("SHA-256", style="dim", width=14)

    for f in sorted(ficheros, key=lambda x: (not x.sospechoso, -x.tamano))[:25]:
        marca = "[sev_alto]⚠[/]" if f.sospechoso else " "
        tipo = f.tipo_real
        if f.tipo_declarado and f.tipo_declarado.split("/")[0] not in tipo.lower():
            tipo = f"[sev_medio]{tipo}[/]"
        t.add_row(marca, theme.esc(truncar(f.nombre, 26)), truncar(tipo, 24),
                  formatear_bytes(f.tamano),
                  truncar(f"{f.origen} → {f.destino}", 22),
                  (f.sha256[:12] + "…") if f.sha256 else "—")
    console.print(t)
    if len(ficheros) > 25:
        console.print(f"  [dim_text]… y {len(ficheros) - 25} ficheros mas.[/]")
    console.print()

    # ── Guardado opcional a disco ─────────────────────
    destino = config.get("extract_dir")
    if destino:
        guardados = 0
        for f in ficheros:
            if carving.guardar(f, destino):
                guardados += 1
        console.print(f"  [exito]✔[/] {plural(guardados, 'fichero guardado', 'ficheros guardados')} "
                      f"en [dato]{os.path.abspath(destino)}[/]")
        console.print("  [dim_text]Los nombres llevan delante los primeros 12 "
                      "caracteres del SHA-256 para que sean trazables.[/]")
        console.print()

    # ── Hallazgos ─────────────────────────────────────
    hallazgos.extend(_ficheros_disfrazados(analisis, ficheros))
    hallazgos.extend(_ejecutables_descargados(analisis, ficheros))
    hallazgos.extend(_ficheros_subidos(analisis, ficheros))

    for f in hallazgos:
        console.print(theme.panel_hallazgo(
            f.titulo, f.severidad, f.descripcion, f.evidencia,
            f.recomendacion, f.confianza))

    if not hallazgos:
        console.print(theme.sin_hallazgos(
            "Todos los ficheros son del tipo que dicen ser y ninguno es ejecutable."))

    console.print(theme.pie_modulo())
    return hallazgos


def _ficheros_disfrazados(analisis, ficheros) -> List[Finding]:
    """El caso mas claro: la extension y el contenido no coinciden."""
    hallazgos = []
    for f in ficheros:
        if not f.sospechoso or not f.ejecutable:
            continue
        if "extension" not in f.motivo_sospecha and "anuncio" not in f.motivo_sospecha:
            continue

        hallazgos.append(Finding(
            titulo=f"Fichero disfrazado: «{f.nombre}» es en realidad {f.tipo_real}",
            descripcion=(
                f"El fichero {f.motivo_sospecha}. Renombrar un ejecutable con una "
                f"extension inofensiva es la tecnica mas antigua y mas usada para "
                f"colar codigo en un equipo: el usuario cree que abre una foto."
            ),
            severidad=Severidad.CRITICO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=(f"{f.url or f.nombre} · {formatear_bytes(f.tamano)} · "
                       f"{f.origen} → {f.destino} · SHA-256 {f.sha256}"),
            recomendacion=(
                f"Busca el hash {f.sha256[:16]}… en VirusTotal. Aisla el equipo "
                f"{f.destino} y comprueba si el fichero llego a ejecutarse."
            ),
            patron="file_transfer_mismatch",
            host=f.destino,
            host_so=analisis.so_de(f.destino),
            timestamp=formatear_hora(f.ts),
            datos={"sha256": f.sha256, "md5": f.md5, "url": f.url,
                   "tamano": f.tamano, "tipo_real": f.tipo_real},
        ))
    return hallazgos[:10]


def _ejecutables_descargados(analisis, ficheros) -> List[Finding]:
    """Ejecutables que llegaron sin ir disfrazados: menos grave, igual de relevante."""
    hallazgos = []
    ya_reportados = {f.sha256 for f in ficheros
                     if f.sospechoso and "extension" in f.motivo_sospecha}

    for f in ficheros:
        if not f.ejecutable or f.sha256 in ya_reportados:
            continue
        if "subida" in f.protocolo.lower():
            continue
        externo = not es_ip_privada(f.origen)

        hallazgos.append(Finding(
            titulo=f"Ejecutable transferido por la red: {f.nombre}",
            descripcion=(
                f"Se reconstruyo un {f.tipo_real} de {formatear_bytes(f.tamano)} "
                f"que viajo {'desde Internet' if externo else 'dentro de la red'} "
                f"sin cifrar. Al ir en claro, cualquiera en el camino pudo "
                f"modificarlo antes de que llegara a su destino."
            ),
            severidad=Severidad.ALTO if externo else Severidad.MEDIO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"{f.url or f.nombre} · SHA-256 {f.sha256}",
            recomendacion=(
                "Comprueba el hash contra la fuente oficial del software y contra "
                "VirusTotal. Si el binario deberia venir firmado, verifica la firma "
                "en el equipo de destino."
            ),
            patron="malware_download",
            host=f.destino,
            host_so=analisis.so_de(f.destino),
            timestamp=formatear_hora(f.ts),
            datos={"sha256": f.sha256, "md5": f.md5, "url": f.url},
        ))
    return hallazgos[:8]


def _ficheros_subidos(analisis, ficheros) -> List[Finding]:
    """Datos saliendo: lo que se sube importa tanto como lo que se baja."""
    hallazgos = []
    subidas = [f for f in ficheros if "subida" in f.protocolo.lower() and f.tamano > 4096]
    if not subidas:
        return hallazgos

    total = sum(f.tamano for f in subidas)
    externas = [f for f in subidas if not es_ip_privada(f.destino)]

    hallazgos.append(Finding(
        titulo=f"{plural(len(subidas), 'fichero subido', 'ficheros subidos')} "
               f"por HTTP ({formatear_bytes(total)})",
        descripcion=(
            "Se detectaron cuerpos de peticion con contenido binario o de "
            "formulario, es decir, ficheros saliendo del equipo"
            + (" hacia servidores de Internet" if externas else " hacia la red interna")
            + ". Conviene confirmar que ese envio es esperado y que no hay datos "
            "de la organizacion saliendo por un canal sin control."
        ),
        severidad=Severidad.MEDIO if externas else Severidad.BAJO,
        confianza=Confianza.MEDIA,
        modulo=MODULE_ID,
        evidencia="; ".join(f"{truncar(f.nombre, 30)} → {f.destino} "
                            f"({formatear_bytes(f.tamano)})" for f in subidas[:4]),
        recomendacion=(
            "Revisa el destino de las subidas. Si es un servicio externo no "
            "aprobado, se trata de una fuga de informacion en curso."
        ),
        patron="exfiltration",
        host=subidas[0].origen,
        host_so=analisis.so_de(subidas[0].origen),
    ))
    return hallazgos
