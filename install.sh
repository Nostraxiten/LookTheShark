#!/usr/bin/env bash
#
# install.sh — Instalador de LookingTheShark para Linux y macOS.
#
# Desde la version 2.0 no hace falta Wireshark ni tshark: el lector de capturas
# es nativo. Eso reduce la instalacion a crear un entorno virtual e instalar dos
# wheels de Python puro, sin sudo y sin compilar nada.
#
#   bash install.sh                 instalacion normal
#   bash install.sh --con-extras    anade geoip2, brotli y zstandard
#   bash install.sh --recrear       borra .venv y empieza de cero
#   bash install.sh --sin-red       usa solo lo que ya este en la cache de pip
#
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# ── Colores (se desactivan si la salida no es un terminal) ────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    V=$'\033[0;32m'; R=$'\033[0;31m'; A=$'\033[0;33m'; C=$'\033[0;36m'
    B=$'\033[1m';    O=$'\033[0m'
else
    V=""; R=""; A=""; C=""; B=""; O=""
fi
ok()   { printf '  %s✔%s %s\n'  "$V" "$O" "$*"; }
info() { printf '  %s·%s %s\n'  "$C" "$O" "$*"; }
warn() { printf '  %s!%s %s\n'  "$A" "$O" "$*"; }
err()  { printf '  %s✘%s %s\n'  "$R" "$O" "$*" >&2; }
paso() { printf '\n%s%s%s\n' "$B" "$*" "$O"; }

CON_EXTRAS=0; RECREAR=0; SIN_RED=0
for arg in "$@"; do
    case "$arg" in
        --con-extras|--with-extras) CON_EXTRAS=1 ;;
        --recrear|--recreate)       RECREAR=1 ;;
        --sin-red|--offline)        SIN_RED=1 ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) warn "Opcion desconocida: $arg (se ignora)" ;;
    esac
done

printf '\n%s%s  LookingTheShark — instalacion%s\n' "$B" "$C" "$O"

# ── 1. Python ─────────────────────────────────────────────────────────────
paso "1/3  Buscando Python"

PY=""
# Se prueban las versiones concretas primero: en algunos sistemas 'python3'
# apunta a una version antigua mientras hay una moderna instalada al lado.
for cand in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
            PY="$cand"
            break
        fi
    fi
done

if [ -z "$PY" ]; then
    err "No se encontro Python 3.9 o superior."
    echo
    echo "  Instalalo con el gestor de paquetes de tu sistema:"
    echo "    Debian / Ubuntu / Kali    sudo apt install -y python3 python3-venv"
    echo "    Fedora / RHEL             sudo dnf install -y python3"
    echo "    Arch / BlackArch          sudo pacman -S --noconfirm python"
    echo "    openSUSE                  sudo zypper install -y python3"
    echo "    Alpine                    sudo apk add python3"
    echo "    macOS (Homebrew)          brew install python"
    echo
    exit 1
fi
ok "$($PY --version 2>&1) en $(command -v "$PY")"

# ── 2. Entorno virtual ────────────────────────────────────────────────────
paso "2/3  Preparando el entorno virtual"

if [ "$RECREAR" -eq 1 ] && [ -d .venv ]; then
    info "Borrando el entorno anterior (--recrear)…"
    rm -rf .venv
fi

if [ -x ".venv/bin/python" ]; then
    ok "Reutilizando el entorno existente en .venv"
else
    info "Creando .venv …"
    if ! "$PY" -m venv .venv >/dev/null 2>&1; then
        warn "El modulo venv no esta disponible."
        SUDO=""
        [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
        if command -v apt-get >/dev/null 2>&1; then
            info "Instalando python3-venv…"
            $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv >/dev/null
        elif command -v dnf >/dev/null 2>&1; then
            $SUDO dnf install -y python3-virtualenv >/dev/null
        fi
        if ! "$PY" -m venv .venv >/dev/null 2>&1; then
            err "No se pudo crear el entorno virtual."
            echo
            echo "  Alternativa sin entorno virtual (instala para tu usuario):"
            echo "    $PY -m pip install --user -r requirements.txt"
            echo "    $PY lookingtheshark.py"
            echo
            exit 1
        fi
    fi
    ok "Entorno virtual creado"
fi

VENV_PY="$DIR/.venv/bin/python"

# ── 3. Dependencias ───────────────────────────────────────────────────────
paso "3/3  Instalando dependencias"

PIP_FLAGS=(--disable-pip-version-check --no-input -q)
[ "$SIN_RED" -eq 1 ] && PIP_FLAGS+=(--no-index)

# Si rich y jinja2 ya estan, no se toca nada: la reinstalacion es lo que hacia
# lenta la instalacion antigua.
if "$VENV_PY" -c 'import rich, jinja2' 2>/dev/null && [ "$RECREAR" -eq 0 ]; then
    ok "Las dependencias ya estan instaladas"
else
    info "Instalando rich y jinja2 (Python puro, sin compilar)…"
    if ! "$VENV_PY" -m pip install "${PIP_FLAGS[@]}" -r requirements.txt; then
        err "Fallo la instalacion de dependencias."
        echo
        echo "  Si estas detras de un proxy, exportalo antes de reintentar:"
        echo "    export HTTPS_PROXY=http://tu.proxy:puerto"
        echo
        echo "  Sin conexion, descarga los wheels en otra maquina y ejecuta:"
        echo "    .venv/bin/pip install rich-*.whl jinja2-*.whl markupsafe-*.whl"
        echo
        exit 1
    fi
    ok "rich y jinja2 instalados"
fi

if [ "$CON_EXTRAS" -eq 1 ]; then
    info "Instalando extras opcionales…"
    if "$VENV_PY" -m pip install "${PIP_FLAGS[@]}" -r requirements-optional.txt; then
        ok "Extras instalados"
    else
        warn "Algun extra fallo. No pasa nada: son opcionales."
    fi
fi

chmod +x run.sh lookingtheshark.py 2>/dev/null || true

# ── Verificacion ──────────────────────────────────────────────────────────
paso "Comprobando la instalacion"
if "$VENV_PY" lookingtheshark.py --check --no-banner >/dev/null 2>&1; then
    ok "Todo correcto"
else
    warn "La comprobacion devolvio avisos. Ejecuta para ver el detalle:"
    echo "      ./run.sh --check"
fi

printf '\n%s%s  Instalacion completada%s\n\n' "$B" "$V" "$O"
echo "  Empieza por aqui:"
echo
printf '    %s./run.sh%s                                    modo interactivo\n' "$C" "$O"
printf '    %s./run.sh -f captura.pcapng --deep --mitre%s   analisis completo\n' "$C" "$O"
printf '    %s./run.sh --check%s                            comprobar el entorno\n' "$C" "$O"
echo
echo "  ¿No tienes ninguna captura a mano? Genera una de prueba:"
echo
printf '    %s.venv/bin/python tests/generar_pcap_demo.py%s\n' "$C" "$O"
printf '    %s./run.sh -f tests/sample_pcaps/demo.pcap --deep --mitre --format html%s\n' "$C" "$O"
echo
