<#
.SYNOPSIS
    Instalador de LookingTheShark para Windows.

.DESCRIPTION
    Desde la version 2.0 la herramienta no necesita Wireshark ni tshark: el
    lector de capturas es nativo. La instalacion se reduce a crear un entorno
    virtual e instalar dos paquetes de Python puro, sin permisos de
    administrador y sin compilar nada.

.PARAMETER ConExtras
    Instala tambien los extras opcionales (geoip2, brotli, zstandard).

.PARAMETER Recrear
    Borra el entorno virtual existente y lo crea de nuevo.

.PARAMETER SinRed
    Instala usando solo la cache local de pip, sin salir a Internet.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1 -ConExtras
#>
[CmdletBinding()]
param(
    [switch]$ConExtras,
    [switch]$Recrear,
    [switch]$SinRed
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# ── Salida con color, degradando bien en consolas antiguas ────────────────
$UsarColor = $Host.UI.RawUI -and -not $env:NO_COLOR
function Escribir($Texto, $Color = 'Gray') {
    if ($UsarColor) { Write-Host $Texto -ForegroundColor $Color } else { Write-Host $Texto }
}
function Ok($m)    { Escribir "  [OK]  $m"   'Green' }
function Info($m)  { Escribir "  ...   $m"   'Cyan' }
function Aviso($m) { Escribir "  [!]   $m"   'Yellow' }
function Fallo($m) { Escribir "  [X]   $m"   'Red' }
function Paso($m)  { Write-Host ''; Escribir $m 'White' }

# UTF-8 en la consola: sin esto los acentos y los simbolos salen rotos.
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

Write-Host ''
Escribir '  LookingTheShark - instalacion' 'Cyan'

# ── 1. Python ─────────────────────────────────────────────────────────────
Paso '1/3  Buscando Python'

function Buscar-Python {
    # El lanzador 'py' es la forma fiable en Windows: respeta las versiones
    # instaladas aunque no esten en el PATH.
    $candidatos = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($v in '-3.13', '-3.12', '-3.11', '-3.10', '-3.9', '-3') {
            $candidatos += ,@('py', $v)
        }
    }
    foreach ($nombre in 'python', 'python3') {
        if (Get-Command $nombre -ErrorAction SilentlyContinue) {
            $candidatos += ,@($nombre)
        }
    }

    foreach ($c in $candidatos) {
        $exe = $c[0]
        $args = @()
        if ($c.Count -gt 1) { $args = @($c[1]) }
        try {
            $prueba = $args + @('-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)')
            & $exe @prueba 2>$null
            if ($LASTEXITCODE -eq 0) { return ,@($exe, $args) }
        } catch { }
    }
    return $null
}

$py = Buscar-Python
if (-not $py) {
    Fallo 'No se encontro Python 3.9 o superior.'
    Write-Host ''
    Write-Host '  Instalalo de una de estas formas:'
    Write-Host ''
    Escribir '    winget install Python.Python.3.12' 'Cyan'
    Write-Host '      o descargalo de https://www.python.org/downloads/windows/'
    Write-Host ''
    Aviso 'En el instalador de python.org marca "Add python.exe to PATH".'
    Write-Host '  Despues cierra y vuelve a abrir esta ventana.'
    Write-Host ''
    exit 1
}
$PyExe = $py[0]
$PyArgs = $py[1]
$version = (& $PyExe @($PyArgs + @('--version')) 2>&1)
Ok "$version"

# ── 2. Entorno virtual ────────────────────────────────────────────────────
Paso '2/3  Preparando el entorno virtual'

$VenvPy = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'

if ($Recrear -and (Test-Path '.venv')) {
    Info 'Borrando el entorno anterior (-Recrear)...'
    Remove-Item -Recurse -Force '.venv'
}

if (Test-Path $VenvPy) {
    Ok 'Reutilizando el entorno existente en .venv'
} else {
    Info 'Creando .venv ...'
    & $PyExe @($PyArgs + @('-m', 'venv', '.venv'))
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPy)) {
        Fallo 'No se pudo crear el entorno virtual.'
        Write-Host ''
        Write-Host '  Alternativa, instalando para tu usuario:'
        Escribir "    $PyExe -m pip install --user -r requirements.txt" 'Cyan'
        Escribir "    $PyExe lookingtheshark.py" 'Cyan'
        Write-Host ''
        exit 1
    }
    Ok 'Entorno virtual creado'
}

# ── 3. Dependencias ───────────────────────────────────────────────────────
Paso '3/3  Instalando dependencias'

$PipFlags = @('--disable-pip-version-check', '--no-input', '-q')
if ($SinRed) { $PipFlags += '--no-index' }

& $VenvPy -c 'import rich, jinja2' 2>$null
$YaEstan = ($LASTEXITCODE -eq 0)

if ($YaEstan -and -not $Recrear) {
    Ok 'Las dependencias ya estan instaladas'
} else {
    Info 'Instalando rich y jinja2 (Python puro, sin compilar)...'
    & $VenvPy -m pip install @PipFlags -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Fallo 'Fallo la instalacion de dependencias.'
        Write-Host ''
        Write-Host '  Si estas detras de un proxy corporativo:'
        Escribir '    $env:HTTPS_PROXY = "http://tu.proxy:puerto"' 'Cyan'
        Write-Host ''
        Write-Host '  Si el antivirus bloquea pip, permite temporalmente la carpeta del proyecto.'
        Write-Host ''
        exit 1
    }
    Ok 'rich y jinja2 instalados'
}

if ($ConExtras) {
    Info 'Instalando extras opcionales...'
    & $VenvPy -m pip install @PipFlags -r requirements-optional.txt
    if ($LASTEXITCODE -eq 0) { Ok 'Extras instalados' }
    else { Aviso 'Algun extra fallo. No pasa nada: son opcionales.' }
}

# ── Verificacion ──────────────────────────────────────────────────────────
Paso 'Comprobando la instalacion'
& $VenvPy lookingtheshark.py --check --no-banner *> $null
if ($LASTEXITCODE -eq 0) {
    Ok 'Todo correcto'
} else {
    Aviso 'La comprobacion devolvio avisos. Ejecuta para ver el detalle:'
    Write-Host '        .\run.bat --check'
}

Write-Host ''
Escribir '  Instalacion completada' 'Green'
Write-Host ''
Write-Host '  Empieza por aqui:'
Write-Host ''
Escribir '    .\run.bat                                    modo interactivo' 'Cyan'
Escribir '    .\run.bat -f captura.pcapng --deep --mitre   analisis completo' 'Cyan'
Escribir '    .\run.bat --check                            comprobar el entorno' 'Cyan'
Write-Host ''
Write-Host '  Sin ninguna captura a mano, genera una de prueba:'
Write-Host ''
Escribir '    .venv\Scripts\python.exe tests\generar_pcap_demo.py' 'Cyan'
Escribir '    .\run.bat -f tests\sample_pcaps\demo.pcap --deep --mitre --format html' 'Cyan'
Write-Host ''
