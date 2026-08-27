@echo off
REM install.bat - Instalador de LookingTheShark para Windows.
REM
REM Existe para que se pueda instalar con doble clic, sin pelearse con la
REM politica de ejecucion de PowerShell. Solo llama a install.ps1 saltandose
REM esa politica UNICAMENTE para este script (no cambia nada del sistema).
REM
REM Uso:  install.bat            o bien:  install.bat --con-extras

setlocal
cd /d "%~dp0"

set "EXTRA="
:leer_args
if "%~1"=="" goto lanzar
if /i "%~1"=="--con-extras" set "EXTRA=%EXTRA% -ConExtras"
if /i "%~1"=="--recrear"    set "EXTRA=%EXTRA% -Recrear"
if /i "%~1"=="--sin-red"    set "EXTRA=%EXTRA% -SinRed"
shift
goto leer_args

:lanzar
where powershell >nul 2>&1
if errorlevel 1 goto sin_powershell

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"%EXTRA%
set "CODIGO=%ERRORLEVEL%"

echo.
if not "%CODIGO%"=="0" (
    echo   La instalacion termino con errores. Revisa los mensajes de arriba.
)
REM Sin la pausa, al hacer doble clic la ventana se cierra antes de poder leer nada.
pause
exit /b %CODIGO%

:sin_powershell
echo.
echo   No se encontro PowerShell en este equipo.
echo   Instala las dependencias a mano:
echo.
echo     python -m venv .venv
echo     .venv\Scripts\python.exe -m pip install -r requirements.txt
echo     .venv\Scripts\python.exe lookingtheshark.py
echo.
pause
exit /b 1
