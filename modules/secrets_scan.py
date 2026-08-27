"""
modules/secrets_scan.py — Que material sensible viajo por la red.

El modulo que contesta a "vale, ¿pero que habia DENTRO?". Recorre todo lo que
viajo sin cifrar — cabeceras HTTP, cuerpos de peticion y respuesta, ficheros
transferidos, sesiones de texto plano — y localiza claves de API, tokens,
claves privadas, contrasenas, cadenas de conexion y datos personales.

Nunca se imprime el secreto completo: se ensena lo justo para localizarlo y
rotarlo. Un informe forense no deberia ser el sitio donde se filtre la clave
por segunda vez.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import List

from rich.console import Console

from modules import (Confianza, Finding, Severidad, formatear_hora, plural,
                     truncar)
from ui import theme

MODULE_NUM = 8
MODULE_NAME = "Material sensible"
MODULE_ID = "secrets"
MODULE_DESC = "Claves, tokens y datos personales que viajaron sin cifrar"

# Que hacer con cada tipo de secreto. Sin esto el hallazgo no acciona.
ACCIONES = {
    "aws_access_key": "Revoca la clave en IAM ahora mismo y revisa CloudTrail por si ya se uso.",
    "aws_secret": "Revoca el par de claves en IAM y rota cualquier despliegue que las use.",
    "github_token": "Revoca el token en github.com/settings/tokens y revisa la actividad de la cuenta.",
    "gitlab_token": "Revoca el token en GitLab y audita los proyectos a los que daba acceso.",
    "slack_token": "Revoca el token en la administracion del workspace de Slack.",
    "google_api": "Regenera la clave en Google Cloud Console y limitala por IP o referrer.",
    "stripe_key": "Revoca la clave en el panel de Stripe. Si es 'sk_live', hay riesgo economico directo.",
    "openai_key": "Revoca la clave en el panel del proveedor: el gasto se factura a quien la tenga.",
    "private_key": "Considera la clave comprometida: generala de nuevo y retira la publica de todos los servidores.",
    "putty_key": "Genera un par de claves nuevo y retira el antiguo de las claves autorizadas.",
    "jwt": "Invalida la sesion y acorta la caducidad de los tokens. Comprueba los permisos que llevaba dentro.",
    "basic_auth_url": "Cambia la contrasena y deja de meter credenciales en la URL: quedan en logs, historial y proxies.",
    "password_field": "Cambia esa contrasena y sirve el formulario por HTTPS.",
    "api_key_generic": "Identifica el servicio, rota la clave y sacala del codigo a una variable de entorno.",
    "connection_string": "Cambia la contrasena de la base de datos y deja de pasar la cadena de conexion por la red en claro.",
    "bearer": "Invalida el token y revisa desde donde se ha usado.",
    "azure_sas": "Revoca la firma SAS en Azure y regenera la clave de la cuenta de almacenamiento.",
    "twilio": "Rota las credenciales en el panel de Twilio: permiten enviar SMS y llamadas con cargo.",
    "sendgrid": "Revoca la clave en SendGrid: permite enviar correo en nombre del dominio.",
    "npm_token": "Revoca el token en npm: permite publicar paquetes en nombre del propietario.",
    "credit_card": "Notifica al titular y al responsable de proteccion de datos. Guardar o transmitir PAN sin cifrar incumple PCI-DSS.",
    "iban": "Trata el dato como personal: revisa la base legal para que viajara sin cifrar.",
    "dni_es": "Dato personal identificativo circulando sin cifrar: valoralo frente al RGPD.",
    "email_pass": "Cambia esas contrasenas y comprueba si el par aparece en filtraciones publicas.",
    "cookie_sesion": "La cookie permite suplantar la sesion: forzarla a HTTPS con los flags Secure y HttpOnly.",
    "ssh_pub": "Comprueba que esa clave publica deberia estar autorizada en ese servidor.",
}


def run(analisis, config: dict, console: Console) -> List[Finding]:
    hallazgos: List[Finding] = []
    console.print(theme.cabecera_modulo(MODULE_NUM, MODULE_NAME, MODULE_DESC))

    secretos = analisis.secretos
    if not secretos:
        console.print(theme.sin_hallazgos(
            "No se encontro material sensible en el trafico en claro."))
        if analisis.tls and not analisis.http:
            console.print("  [dim_text]Casi todo el trafico va cifrado, asi que "
                          "no hay nada que leer dentro. Eso es buena senal.[/]")
        console.print(theme.pie_modulo())
        return hallazgos

    # ── Resumen por tipo ──────────────────────────────
    por_tipo = defaultdict(list)
    for s in secretos:
        por_tipo[s.tipo].append(s)

    criticos = [s for s in secretos if s.severidad == "critico"]
    console.print(
        f"  [sev_critico] {plural(len(secretos), 'hallazgo', 'hallazgos')} [/] "
        f"de material sensible en trafico sin cifrar"
        + (f", [sev_critico]{plural(len(criticos), 'critico', 'criticos')}[/]"
           if criticos else "")
    )
    console.print()

    t = theme.tabla("Que se encontro")
    t.add_column("Tipo", style="bold bright_cyan", max_width=32)
    t.add_column("Sev.", width=10)
    t.add_column("Veces", justify="right", width=7)
    t.add_column("Ejemplo (enmascarado)", max_width=34)

    for tipo, lista in sorted(por_tipo.items(),
                              key=lambda x: (theme.ORDEN_SEVERIDAD.get(
                                  x[1][0].severidad, 9), -len(x[1]))):
        s = lista[0]
        t.add_row(s.nombre, theme.severidad(s.severidad, con_icono=False),
                  str(len(lista)), theme.esc(truncar(s.muestra, 32)))
    console.print(t)
    console.print()

    # ── Detalle de los mas graves ─────────────────────
    graves = sorted(secretos, key=lambda s: theme.ORDEN_SEVERIDAD.get(s.severidad, 9))
    limite = int(config.get("secretos_max_mostrados", 15))

    console.print(f"  [titulo]Detalle[/]")
    console.print()
    for s in graves[:limite]:
        origen = s.src or "?"
        perfil = analisis.hosts.get(origen)
        so = f" ({perfil.so})" if perfil and perfil.so else ""
        lineas = [
            f"[etiqueta]Valor      [/] [dato]{theme.esc(s.muestra)}[/]",
            f"[etiqueta]Aparece en [/] {theme.esc(truncar(s.origen, 60))}",
        ]
        if s.url:
            lineas.append(f"[etiqueta]URL        [/] {theme.esc(truncar(s.url, 66))}")
        if s.src:
            lineas.append(f"[etiqueta]Enviado por[/] [bright_cyan]{origen}[/]"
                          f"[lan]{so}[/] → {s.dst or '?'}")
        if s.contexto:
            lineas.append(f"[etiqueta]Contexto   [/] "
                          f"[dim_text]{theme.esc(truncar(s.contexto, 60))}[/]")

        console.print(f"  {theme.severidad(s.severidad)} [titulo]{s.nombre}[/]")
        for linea in lineas:
            console.print(f"      {linea}")
        accion = ACCIONES.get(s.tipo)
        if accion:
            console.print(f"      [etiqueta]Que hacer  [/] [white]{accion}[/]")
        console.print()

    if len(graves) > limite:
        console.print(f"  [dim_text]… y {len(graves) - limite} hallazgos mas "
                      f"(estan todos en el informe exportado).[/]")
        console.print()

    # ── Hallazgos formales ────────────────────────────
    hallazgos.extend(_hallazgos_por_tipo(analisis, por_tipo))

    console.print(theme.caja_explicativa(
        "Cada uno de estos valores viajo legible por la red. Cualquiera con acceso "
        "al cable, al WiFi o a un equipo intermedio pudo copiarlo sin dejar rastro. "
        "Que la captura los muestre significa que ya estan expuestos: rotarlos no "
        "es opcional.",
        "Por que esto importa"))

    console.print(theme.pie_modulo())
    return hallazgos


def _hallazgos_por_tipo(analisis, por_tipo) -> List[Finding]:
    """Un Finding por tipo de secreto, con todas sus apariciones agrupadas."""
    hallazgos = []

    for tipo, lista in por_tipo.items():
        s = lista[0]
        origenes = sorted({x.src for x in lista if x.src})[:5]
        destinos = sorted({x.dst for x in lista if x.dst})[:5]
        protocolos = sorted({x.protocolo for x in lista if x.protocolo})

        descripcion = (
            f"Se localizaron {plural(len(lista), 'aparicion', 'apariciones')} de "
            f"«{s.nombre}» viajando sin cifrar"
            + (f" por {', '.join(protocolos)}" if protocolos else "") + ". "
        )
        if s.tipo == "jwt" and s.contexto:
            descripcion += (f"El token contiene: {s.contexto}. Cualquiera que lo "
                            f"capture puede reutilizarlo hasta que caduque. ")
        elif s.tipo == "private_key":
            descripcion += ("Una clave privada que ha circulado por la red debe "
                            "considerarse comprometida sin mas discusion. ")
        elif s.tipo == "credit_card":
            descripcion += ("Transmitir numeros de tarjeta sin cifrar incumple "
                            "PCI-DSS y es notificable. ")

        hallazgos.append(Finding(
            titulo=f"{s.nombre} expuesto en la red ({len(lista)}×)",
            descripcion=descripcion.strip(),
            severidad=s.severidad,
            confianza=s.confianza,
            modulo=MODULE_ID,
            evidencia=(f"{s.muestra} · en {truncar(s.origen, 40)}"
                       + (f" · {', '.join(origenes)} → {', '.join(destinos)}"
                          if origenes else "")),
            recomendacion=ACCIONES.get(s.tipo,
                                       "Rota el valor y transporta ese dato solo por un canal cifrado."),
            patron="credential_exposure" if s.severidad == "critico" else "data_exposure",
            host=origenes[0] if origenes else "",
            host_so=analisis.so_de(origenes[0]) if origenes else "",
            timestamp=formatear_hora(s.ts),
            datos={"tipo": s.tipo, "apariciones": len(lista),
                   "muestras": [x.muestra for x in lista[:5]]},
        ))

    return sorted(hallazgos, key=lambda f: f.peso)
