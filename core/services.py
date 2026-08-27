"""
core/services.py — Puertos, servicios y su lectura en clave de riesgo.

No es solo "puerto 445 = SMB": cada entrada dice ademas si el protocolo va en
claro, si no deberia verse saliendo a Internet, y una frase en castellano que
explica que significa verlo en la captura.
"""

from __future__ import annotations

from typing import Optional

# puerto -> (nombre, cifrado, categoria, explicacion)
SERVICIOS = {
    20:    ("FTP-Data", False, "transferencia", "Canal de datos de FTP: los ficheros viajan sin cifrar."),
    21:    ("FTP", False, "transferencia", "FTP manda usuario y contrasena en texto plano."),
    22:    ("SSH", True, "administracion", "Acceso remoto cifrado. Vigilar quien y desde donde."),
    23:    ("Telnet", False, "administracion", "Administracion remota SIN cifrar: todo es legible, teclas incluidas."),
    25:    ("SMTP", False, "correo", "Envio de correo. Sin STARTTLS va en claro."),
    53:    ("DNS", False, "infraestructura", "Resolucion de nombres. Es el canal preferido para exfiltrar datos."),
    67:    ("DHCP-Servidor", False, "infraestructura", "Asignacion de IPs. Un servidor DHCP no autorizado permite un MITM completo."),
    68:    ("DHCP-Cliente", False, "infraestructura", "Peticion de configuracion de red de un equipo."),
    69:    ("TFTP", False, "transferencia", "Transferencia sin autenticacion ni cifrado. Tipico en despliegues y en malware."),
    80:    ("HTTP", False, "web", "Web sin cifrar: URLs, cookies y formularios son legibles."),
    88:    ("Kerberos", False, "autenticacion", "Autenticacion de dominio Windows."),
    110:   ("POP3", False, "correo", "Descarga de correo con credenciales en claro."),
    111:   ("RPCbind", False, "infraestructura", "Mapeador de puertos RPC: util para un atacante que enumera."),
    119:   ("NNTP", False, "otros", "Protocolo de noticias, practicamente obsoleto."),
    123:   ("NTP", False, "infraestructura", "Sincronizacion horaria. Se abusa para amplificacion DDoS."),
    135:   ("MSRPC", False, "windows", "RPC de Windows. No deberia salir nunca a Internet."),
    137:   ("NetBIOS-NS", False, "windows", "Resolucion de nombres NetBIOS: filtra nombres de equipo y de usuario."),
    138:   ("NetBIOS-DGM", False, "windows", "Datagramas NetBIOS."),
    139:   ("NetBIOS-SSN", False, "windows", "Sesiones SMB antiguas."),
    143:   ("IMAP", False, "correo", "Acceso a correo con credenciales en claro si no hay TLS."),
    161:   ("SNMP", False, "administracion", "SNMPv1/v2c manda la community string en claro."),
    162:   ("SNMP-Trap", False, "administracion", "Alertas SNMP."),
    389:   ("LDAP", False, "autenticacion", "Directorio sin cifrar: credenciales de bind legibles."),
    443:   ("HTTPS", True, "web", "Web cifrada. Se ve el SNI (a que dominio), no el contenido."),
    445:   ("SMB", False, "windows", "Ficheros compartidos de Windows. Objetivo numero uno de ransomware."),
    465:   ("SMTPS", True, "correo", "Envio de correo cifrado."),
    500:   ("IKE/IPsec", True, "vpn", "Negociacion de VPN IPsec."),
    514:   ("Syslog", False, "administracion", "Registros enviados sin cifrar."),
    515:   ("LPD", False, "impresion", "Impresion en red."),
    587:   ("SMTP-Submission", False, "correo", "Envio de correo autenticado; sin STARTTLS va en claro."),
    593:   ("RPC-HTTP", False, "windows", "RPC sobre HTTP."),
    623:   ("IPMI", False, "administracion", "Gestion fuera de banda de servidores. Historial de fallos graves."),
    636:   ("LDAPS", True, "autenticacion", "Directorio cifrado."),
    873:   ("rsync", False, "transferencia", "Sincronizacion de ficheros sin cifrar."),
    993:   ("IMAPS", True, "correo", "Correo cifrado."),
    995:   ("POP3S", True, "correo", "Correo cifrado."),
    1080:  ("SOCKS", False, "proxy", "Proxy SOCKS. Muy usado por tuneles y malware."),
    1194:  ("OpenVPN", True, "vpn", "Tunel VPN."),
    1433:  ("MSSQL", False, "base_datos", "SQL Server. Exponerlo es critico."),
    1434:  ("MSSQL-Browser", False, "base_datos", "Descubrimiento de instancias SQL Server."),
    1521:  ("Oracle", False, "base_datos", "Base de datos Oracle."),
    1723:  ("PPTP", False, "vpn", "VPN obsoleta y rota criptograficamente."),
    1883:  ("MQTT", False, "iot", "Mensajeria IoT sin cifrar."),
    2049:  ("NFS", False, "transferencia", "Ficheros compartidos Unix."),
    2375:  ("Docker-API", False, "administracion", "API de Docker SIN TLS: control total del host."),
    2376:  ("Docker-API-TLS", True, "administracion", "API de Docker cifrada."),
    3128:  ("Squid-Proxy", False, "proxy", "Proxy HTTP."),
    3306:  ("MySQL", False, "base_datos", "Base de datos MySQL/MariaDB."),
    3389:  ("RDP", True, "administracion", "Escritorio remoto de Windows. Vector clasico de ransomware."),
    3690:  ("SVN", False, "desarrollo", "Control de versiones Subversion."),
    4444:  ("Metasploit (habitual)", False, "sospechoso", "Puerto por defecto de payloads de Metasploit."),
    4445:  ("Metasploit (habitual)", False, "sospechoso", "Puerto asociado a herramientas ofensivas."),
    5432:  ("PostgreSQL", False, "base_datos", "Base de datos PostgreSQL."),
    5060:  ("SIP", False, "voip", "Senalizacion de telefonia sin cifrar."),
    5061:  ("SIPS", True, "voip", "Senalizacion de telefonia cifrada."),
    5222:  ("XMPP", False, "mensajeria", "Mensajeria Jabber/XMPP."),
    5353:  ("mDNS", False, "infraestructura", "Descubrimiento local (Bonjour): revela nombres y servicios del equipo."),
    5355:  ("LLMNR", False, "windows", "Resolucion de nombres de Windows. Se abusa para robar hashes NTLM."),
    5555:  ("ADB / Android Debug", False, "sospechoso", "Depuracion de Android abierta: ejecucion remota sin autenticar."),
    5900:  ("VNC", False, "administracion", "Escritorio remoto sin cifrar por defecto."),
    5985:  ("WinRM", False, "administracion", "Administracion remota de Windows en claro."),
    5986:  ("WinRM-HTTPS", True, "administracion", "Administracion remota de Windows cifrada."),
    6379:  ("Redis", False, "base_datos", "Redis sin autenticacion por defecto: RCE trivial si esta expuesto."),
    6666:  ("IRC (habitual)", False, "sospechoso", "IRC: canal clasico de botnets."),
    6667:  ("IRC", False, "sospechoso", "IRC: canal clasico de botnets."),
    8000:  ("HTTP-Alt", False, "web", "Servidor web alternativo."),
    8008:  ("HTTP-Alt", False, "web", "Servidor web alternativo."),
    8080:  ("HTTP-Proxy/Alt", False, "web", "Web o proxy en puerto alternativo."),
    8443:  ("HTTPS-Alt", True, "web", "Web cifrada en puerto alternativo."),
    8888:  ("HTTP-Alt", False, "web", "Servidor web alternativo (Jupyter, paneles...)."),
    9001:  ("Tor (habitual)", False, "sospechoso", "Puerto de relay Tor."),
    9050:  ("Tor SOCKS", False, "sospechoso", "Proxy SOCKS de Tor en local."),
    9200:  ("Elasticsearch", False, "base_datos", "Elasticsearch sin autenticacion por defecto."),
    9300:  ("Elasticsearch-Nodos", False, "base_datos", "Comunicacion entre nodos de Elasticsearch."),
    11211: ("Memcached", False, "base_datos", "Memcached sin autenticacion; se abusa para amplificacion DDoS."),
    27017: ("MongoDB", False, "base_datos", "MongoDB sin autenticacion por defecto en versiones antiguas."),
    27018: ("MongoDB-Shard", False, "base_datos", "Shard de MongoDB."),
    31337: ("Back Orifice (habitual)", False, "sospechoso", "Puerto historico de puertas traseras."),
    50050: ("Cobalt Strike (por defecto)", False, "sospechoso", "Puerto por defecto del servidor de equipo de Cobalt Strike."),
}

# Puertos en los que esperamos encontrar HTTP en claro.
PUERTOS_HTTP = {80, 591, 3128, 8000, 8008, 8080, 8081, 8088, 8888, 9080, 5000, 8090}
# Puertos donde esperamos TLS.
PUERTOS_TLS = {443, 465, 636, 989, 990, 993, 995, 1194, 4443, 5061, 5986, 8443, 9443, 10443}
# Protocolos de texto plano con credenciales.
PUERTOS_TEXTO = {21, 23, 25, 110, 143, 512, 513, 514, 587, 3306, 6667}

CATEGORIA_RIESGO = {
    "sospechoso": "alto",
    "administracion": "medio",
    "base_datos": "medio",
    "windows": "medio",
}


def servicio(puerto: Optional[int]) -> str:
    """Nombre del servicio de un puerto, o 'puerto/N'."""
    if puerto is None:
        return "—"
    entrada = SERVICIOS.get(puerto)
    return entrada[0] if entrada else f"puerto/{puerto}"


def esta_cifrado(puerto: Optional[int]) -> bool:
    entrada = SERVICIOS.get(puerto) if puerto is not None else None
    return bool(entrada and entrada[1])


def explicacion(puerto: Optional[int]) -> str:
    """Frase que explica que significa ver ese puerto en la captura."""
    entrada = SERVICIOS.get(puerto) if puerto is not None else None
    return entrada[3] if entrada else ""


def categoria(puerto: Optional[int]) -> str:
    entrada = SERVICIOS.get(puerto) if puerto is not None else None
    return entrada[2] if entrada else ""


def es_efimero(puerto: Optional[int]) -> bool:
    """Puerto de cliente asignado por el sistema (no identifica un servicio)."""
    return puerto is not None and puerto >= 32768
