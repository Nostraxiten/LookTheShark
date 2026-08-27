"""
modules/behavior_heuristics.py — Comportamientos, no firmas.

Las firmas detectan lo que ya se conoce. Estas heuristicas detectan la FORMA de
lo que esta pasando, que es mucho mas dificil de cambiar para quien ataca:

  escaneo       un origen tocando muchos puertos o muchos equipos en poco tiempo
  beaconing     conexiones al mismo destino con una regularidad de reloj
  exfiltracion  un equipo interno subiendo mucho mas de lo que baja
  horario raro  actividad concentrada fuera de la jornada
  fallos        muchas conexiones rechazadas o sin respuesta

Todas necesitan interpretacion: un servidor de copias tambien sube mucho de
madrugada. Por eso cada hallazgo dice que lo explicaria de forma legitima.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import List

from rich.console import Console

from core import services
from modules import (Confianza, Finding, Severidad, es_ip_privada,
                     formatear_bytes, formatear_duracion, formatear_hora,
                     plural, truncar)
from ui import theme

MODULE_NUM = 11
MODULE_NAME = "Comportamiento"
MODULE_ID = "heuristics"
MODULE_DESC = "Escaneos, beaconing, exfiltracion y ritmos que no cuadran"

# Umbrales por defecto; se pueden ajustar desde la configuracion.
PUERTOS_ESCANEO = 15
EQUIPOS_BARRIDO = 12
MIN_BEACONS = 6
DESVIACION_BEACON = 0.15      # coeficiente de variacion maximo
BYTES_EXFILTRACION = 5 * 1024 * 1024
RATIO_SUBIDA = 3.0


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    if not config.get("deep_mode", False):
        console.print("  [dim_text]Heuristicas desactivadas. Anade [/]"
                      "[dato]--deep[/][dim_text] para activarlas.[/]")
        console.print("  [dim_text]Cuestan una fraccion de segundo: el analisis ya "
                      "esta hecho, solo se interpreta.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    hallazgos.extend(_escaneo_puertos(analisis, config))
    hallazgos.extend(_barrido_red(analisis))
    hallazgos.extend(_beaconing(analisis, config))
    hallazgos.extend(_exfiltracion(analisis, config))
    hallazgos.extend(_conexiones_fallidas(analisis))
    hallazgos.extend(_horario_anomalo(analisis))

    hallazgos.sort(key=lambda f: f.peso)

    if hallazgos:
        console.print(f"  [sev_alto]{plural(len(hallazgos), 'comportamiento anomalo detectado', 'comportamientos anomalos detectados')}[/]")
        console.print()
        for f in hallazgos:
            console.print(theme.panel_hallazgo(
                f.titulo, f.severidad, f.descripcion, f.evidencia,
                f.recomendacion, f.confianza))
    else:
        console.print(theme.sin_hallazgos(
            "Ningun patron de escaneo, beaconing ni exfiltracion en esta captura."))

    console.print(theme.pie_modulo())
    return hallazgos


def _escaneo_puertos(analisis, config) -> List[Finding]:
    """Un origen tocando muchos puertos del mismo destino."""
    hallazgos = []
    umbral = int(config.get("umbral_escaneo", PUERTOS_ESCANEO))

    for origen, destinos in analisis.syn_por_origen.items():
        for destino, puertos in destinos.items():
            if len(puertos) < umbral:
                continue

            # Cuanto duro: un escaneo se hace en segundos, no en horas.
            tiempos = []
            for (o, d, p), ts_lista in analisis.conexiones_ts.items():
                if o == origen and d == destino:
                    tiempos.extend(ts_lista)
            span = (max(tiempos) - min(tiempos)) if len(tiempos) >= 2 else 0.0
            velocidad = len(puertos) / span if span > 0 else float(len(puertos))

            rechazos = analisis.rst_por_destino.get(origen, 0)
            perfil = analisis.hosts.get(origen)
            cerrados = sum(1 for f in analisis.flujos
                           if f.cliente_ip == origen and f.servidor_ip == destino
                           and (f.rechazado or f.sin_respuesta))

            confianza = (Confianza.ALTA if (span < 10 or cerrados > umbral * 0.5)
                         else Confianza.MEDIA)
            interesantes = sorted(p for p in puertos if p in services.SERVICIOS)[:8]

            hallazgos.append(Finding(
                titulo=f"Escaneo de puertos: {origen} → {destino} "
                       f"({len(puertos)} puertos)",
                descripcion=(
                    f"Se enviaron SYN a {len(puertos)} puertos distintos de "
                    f"{destino}"
                    + (f" en {formatear_duracion(span)} ({velocidad:.1f} puertos/s)"
                       if span > 0 else " practicamente a la vez") + ". "
                    + (f"{cerrados} conexiones fueron rechazadas o quedaron sin "
                       f"respuesta, que es exactamente lo que produce un escaneo: "
                       f"casi todos los puertos estan cerrados. " if cerrados else "")
                    + (f"El origen tiene huella de {perfil.so}. "
                       if perfil and perfil.familia == "Escaner" else "")
                    + "Lo unico que lo explicaria de forma legitima es un inventario "
                      "de seguridad autorizado o una herramienta de monitorizacion."
                ),
                severidad=Severidad.ALTO,
                confianza=confianza,
                modulo=MODULE_ID,
                evidencia=(f"{origen} → {destino}, puertos incluyendo "
                           + ", ".join(f"{p}/{services.servicio(p)}" for p in interesantes)),
                recomendacion=(
                    "Comprueba si el escaneo estaba autorizado y anotado. Si no, "
                    "bloquea el origen y revisa que puertos respondieron: son los "
                    "que el atacante intentara despues."
                ),
                patron="portscan",
                host=origen,
                host_so=perfil.so if perfil else "",
                datos={"puertos": sorted(puertos)[:60], "destino": destino},
            ))
    return hallazgos[:8]


def _barrido_red(analisis) -> List[Finding]:
    """Un origen tocando el mismo puerto en muchos equipos: busca victimas."""
    hallazgos = []
    for origen, destinos in analisis.syn_por_origen.items():
        if len(destinos) < EQUIPOS_BARRIDO:
            continue

        puertos_comunes = Counter()
        for puertos in destinos.values():
            puertos_comunes.update(puertos)
        objetivo, veces = puertos_comunes.most_common(1)[0]
        if veces < EQUIPOS_BARRIDO:
            continue

        perfil = analisis.hosts.get(origen)
        hallazgos.append(Finding(
            titulo=f"Barrido de red desde {origen}: puerto {objetivo} en "
                   f"{veces} equipos",
            descripcion=(
                f"El mismo puerto ({objetivo}/{services.servicio(objetivo)}) se "
                f"probo en {veces} equipos distintos. Eso no es navegar: es buscar "
                f"todos los equipos de la red que ofrecen ese servicio. Es el paso "
                f"previo tipico de un movimiento lateral o de la propagacion de un "
                f"gusano — SMB (445) y RDP (3389) son los objetivos habituales."
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.ALTA,
            modulo=MODULE_ID,
            evidencia=f"{origen} contacto {len(destinos)} equipos; "
                      f"{services.servicio(objetivo)} en {veces} de ellos",
            recomendacion=(
                "Aisla el equipo de origen: si esta comprometido, cada minuto que "
                "pasa es un equipo mas. Revisa que equipos respondieron al puerto "
                f"{objetivo} y parchea ese servicio."
            ),
            patron="network_sweep",
            host=origen,
            host_so=perfil.so if perfil else "",
            datos={"puerto": objetivo, "equipos": veces},
        ))
    return hallazgos[:5]


def _beaconing(analisis, config) -> List[Finding]:
    """Conexiones repetidas con intervalo casi constante: un agente llamando a casa."""
    hallazgos = []
    minimo = int(config.get("min_beacons", MIN_BEACONS))

    for (origen, destino, puerto), tiempos in analisis.conexiones_ts.items():
        if len(tiempos) < minimo:
            continue
        tiempos = sorted(tiempos)
        intervalos = [tiempos[i] - tiempos[i - 1] for i in range(1, len(tiempos))]
        intervalos = [i for i in intervalos if i > 0.05]
        if len(intervalos) < minimo - 1:
            continue

        media = statistics.fmean(intervalos)
        if media < 1.0:
            continue      # rafaga, no latido
        desviacion = statistics.pstdev(intervalos) if len(intervalos) > 1 else 0.0
        coeficiente = desviacion / media if media else 1.0
        if coeficiente > DESVIACION_BEACON:
            continue

        externo = not es_ip_privada(destino)
        perfil = analisis.hosts.get(origen)
        dominio = ""
        for s in analisis.tls:
            if s.servidor_ip == destino and s.sni:
                dominio = s.sni
                break

        hallazgos.append(Finding(
            titulo=f"Beaconing hacia {dominio or destino}:{puerto} "
                   f"cada ~{media:.0f} s",
            descripcion=(
                f"{len(tiempos)} conexiones desde {origen} hacia {destino}:{puerto} "
                f"separadas por {media:.1f} segundos con una variacion de solo "
                f"{coeficiente*100:.1f}%. Una persona no genera ese ritmo; un "
                f"programa que pregunta «¿hay ordenes?» a intervalo fijo, si. Es la "
                f"firma de un agente de control remoto."
                + (" El destino esta en Internet, lo que refuerza la hipotesis."
                   if externo else
                   " El destino es interno: podria ser tambien un agente de "
                   "monitorizacion o de inventario legitimo.")
            ),
            severidad=Severidad.CRITICO if externo else Severidad.MEDIO,
            confianza=Confianza.ALTA if coeficiente < 0.08 else Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=(f"{len(tiempos)} conexiones entre "
                       f"{formatear_hora(tiempos[0])} y {formatear_hora(tiempos[-1])}, "
                       f"intervalo {media:.1f}±{desviacion:.1f} s"),
            recomendacion=(
                f"Identifica el proceso que abre esas conexiones en {origen}. "
                f"Bloquea {destino} en el perimetro mientras investigas. Comprueba "
                f"si alguna herramienta de gestion tuya usa ese intervalo antes de "
                f"dar por hecho que es malicioso."
            ),
            patron="beaconing",
            host=origen,
            host_so=perfil.so if perfil else "",
            timestamp=formatear_hora(tiempos[0]),
            datos={"destino": destino, "puerto": puerto,
                   "intervalo": round(media, 2), "conexiones": len(tiempos)},
        ))
    return sorted(hallazgos, key=lambda f: f.peso)[:8]


def _exfiltracion(analisis, config) -> List[Finding]:
    """Un equipo interno que sube mucho mas de lo que baja."""
    hallazgos = []
    umbral = int(config.get("umbral_exfiltracion", BYTES_EXFILTRACION))

    for (origen, destino), enviados in analisis.bytes_por_flujo.items():
        if enviados < umbral:
            continue
        if not es_ip_privada(origen) or es_ip_privada(destino):
            continue        # solo interesa lo que sale de dentro hacia fuera

        recibidos = analisis.bytes_por_flujo.get((destino, origen), 0)
        ratio = enviados / recibidos if recibidos else float("inf")
        if ratio < RATIO_SUBIDA:
            continue        # descarga normal: se recibe mas de lo que se manda

        perfil = analisis.hosts.get(origen)
        dominio = next((s.sni for s in analisis.tls
                        if s.servidor_ip == destino and s.sni), "")

        hallazgos.append(Finding(
            titulo=f"Salida masiva de datos: {origen} → {dominio or destino} "
                   f"({formatear_bytes(enviados)})",
            descripcion=(
                f"El equipo interno {origen} envio {formatear_bytes(enviados)} hacia "
                f"{destino} y solo recibio {formatear_bytes(recibidos)}. La relacion "
                f"normal es la contraria: se descarga mucho mas de lo que se sube. "
                f"Una proporcion de {ratio:.0f} a 1 hacia fuera es lo que produce "
                f"una copia de datos saliendo de la organizacion."
                + (" Puede ser tambien una copia de seguridad en la nube o una "
                   "sincronizacion de ficheros legitima." )
            ),
            severidad=Severidad.ALTO,
            confianza=Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=(f"{formatear_bytes(enviados)} enviados / "
                       f"{formatear_bytes(recibidos)} recibidos"
                       + (f" · destino {dominio}" if dominio else "")),
            recomendacion=(
                f"Averigua a quien pertenece {destino} y que proceso en {origen} "
                f"esta subiendo. Si no es un servicio aprobado, corta la conexion y "
                f"trata el equipo como comprometido."
            ),
            patron="exfiltration",
            host=origen,
            host_so=perfil.so if perfil else "",
            datos={"destino": destino, "enviados": enviados, "recibidos": recibidos},
        ))
    return sorted(hallazgos, key=lambda f: -f.datos.get("enviados", 0))[:6]


def _conexiones_fallidas(analisis) -> List[Finding]:
    """Muchos intentos que no llegan a establecerse."""
    hallazgos = []
    por_origen = defaultdict(lambda: {"total": 0, "fallidos": 0, "destinos": set()})

    for flujo in analisis.flujos:
        datos = por_origen[flujo.cliente_ip]
        datos["total"] += 1
        if flujo.rechazado or flujo.sin_respuesta:
            datos["fallidos"] += 1
            datos["destinos"].add(f"{flujo.servidor_ip}:{flujo.servidor_puerto}")

    for origen, datos in por_origen.items():
        if datos["total"] < 20 or datos["fallidos"] < 15:
            continue
        ratio = datos["fallidos"] / datos["total"]
        if ratio < 0.6:
            continue
        # Si ya lo hemos reportado como escaneo, no repetir.
        if len(analisis.syn_por_origen.get(origen, {})) > 1 and any(
                len(p) >= PUERTOS_ESCANEO
                for p in analisis.syn_por_origen[origen].values()):
            continue

        hallazgos.append(Finding(
            titulo=f"{origen}: {ratio*100:.0f}% de sus conexiones no se establecen",
            descripcion=(
                f"{datos['fallidos']} de {datos['total']} intentos terminaron en "
                f"rechazo o sin respuesta. Un equipo sano acierta casi siempre. Este "
                f"patron aparece cuando un programa busca a ciegas servicios que no "
                f"existen, o cuando intenta salir a destinos que el firewall bloquea."
            ),
            severidad=Severidad.MEDIO,
            confianza=Confianza.MEDIA,
            modulo=MODULE_ID,
            evidencia=f"Destinos fallidos: "
                      + ", ".join(sorted(datos["destinos"])[:5]),
            recomendacion=(
                "Mira que destinos son. Si son IPs externas concretas, puede ser un "
                "agente intentando alcanzar su servidor de control con el firewall "
                "haciendo su trabajo."
            ),
            patron="failed_connections",
            host=origen,
            host_so=analisis.so_de(origen),
        ))
    return hallazgos[:5]


def _horario_anomalo(analisis) -> List[Finding]:
    """Actividad concentrada en horas en las que no deberia haber nadie."""
    hallazgos = []
    if analisis.duracion < 3600 or not analisis.actividad:
        return hallazgos

    por_hora = Counter()
    for segundo, cuenta in analisis.actividad.items():
        try:
            por_hora[datetime.fromtimestamp(segundo).hour] += cuenta
        except (OSError, ValueError, OverflowError):
            continue

    total = sum(por_hora.values()) or 1
    nocturno = sum(c for h, c in por_hora.items() if h < 6 or h >= 22)
    ratio = nocturno / total
    if ratio < 0.5 or nocturno < 500:
        return hallazgos

    horas_pico = ", ".join(f"{h:02d}:00 ({c:,} pkts)"
                           for h, c in por_hora.most_common(3))
    hallazgos.append(Finding(
        titulo=f"El {ratio*100:.0f}% del trafico ocurre fuera del horario laboral",
        descripcion=(
            "La mayor parte de la actividad se concentra entre las 22:00 y las "
            "06:00. En una red de oficina eso deberia ser un valle, no un pico. "
            "Puede ser perfectamente normal (copias de seguridad, actualizaciones "
            "programadas, servidores) pero si la captura es de puestos de trabajo, "
            "alguien o algo esta trabajando cuando no deberia haber nadie."
        ),
        severidad=Severidad.BAJO,
        confianza=Confianza.BAJA,
        modulo=MODULE_ID,
        evidencia=f"Horas con mas trafico: {horas_pico}",
        recomendacion=(
            "Contrasta con las tareas programadas de la organizacion. Lo que no "
            "cuadre con una tarea conocida, investigalo equipo por equipo."
        ),
        patron="odd_hours",
    ))
    return hallazgos
