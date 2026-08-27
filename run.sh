#!/usr/bin/env bash
#
# run.sh — Lanzador de LookingTheShark en Linux y macOS.
#
# Usa el Python del entorno virtual, asi no hay que acordarse de activarlo en
# cada terminal. Todos los argumentos se pasan tal cual a la herramienta.
#
#   ./run.sh                                        modo interactivo
#   ./run.sh -f captura.pcapng --deep --mitre --format html
#
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if [ -x ".venv/bin/python" ]; then
    exec ./.venv/bin/python lookingtheshark.py "$@"
fi

# Sin entorno virtual: si las dependencias estan en el sistema, se tira con eso
# antes de dar un error. Es lo que espera quien instalo con el gestor de la
# distribucion o con pipx.
for PY in python3 python; do
    if command -v "$PY" >/dev/null 2>&1 && \
       "$PY" -c 'import rich, jinja2' >/dev/null 2>&1; then
        exec "$PY" lookingtheshark.py "$@"
    fi
done

echo "[X] No hay entorno virtual en .venv ni dependencias en el sistema." >&2
echo >&2
echo "    Ejecuta primero:  bash install.sh" >&2
echo >&2
echo "    O a mano:" >&2
echo "      python3 -m venv .venv" >&2
echo "      .venv/bin/pip install -r requirements.txt" >&2
echo >&2
exit 1
