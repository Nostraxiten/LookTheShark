@echo off
REM run.bat - Lanzador de LookingTheShark en Windows.
REM
REM Usa el Python del entorno virtual, asi no hay que acordarse de activarlo
REM en cada consola. Todos los argumentos se pasan tal cual a la herramienta.
REM
REM Uso:  run.bat -f captura.pcapng --deep --mitre --format html
REM       run.bat                    (modo interactivo)

setlocal
cd /d "%~dp0"

REM UTF-8 en la consola para que el banner y los acentos se vean bien.
chcp 65001 >nul 2>&1

set "VENV_PY=%~dp0.venv\Scripts\python.exe"

if exist "%VENV_PY%" goto ejecutar

echo.
echo   No hay entorno virtual en .venv
echo   Ejecuta primero el instalador:
echo.
echo     install.bat
echo.
echo   O crea el entorno a mano:
echo     python -m venv .venv
echo     .venv\Scripts\python.exe -m pip install -r requirements.txt
echo.
REM Si se ha llegado aqui por doble clic, la pausa deja leer el mensaje.
if /i "%~1"=="" pause
exit /b 1

:ejecutar
"%VENV_PY%" "%~dp0lookingtheshark.py" %*
set "CODIGO=%ERRORLEVEL%"

REM Sin argumentos = probablemente doble clic: se espera antes de cerrar.
if /i "%~1"=="" pause
exit /b %CODIGO%
