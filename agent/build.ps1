# Build VulnWatchAgent.exe (Windows). Dublu-click sau:
#     powershell -ExecutionPolicy Bypass -File agent\build.ps1
#
# Rezultat: dist\VulnWatchAgent.exe

$ErrorActionPreference = "Stop"

# Mergi in radacina repo-ului (parent al directorului acestui script).
Set-Location -Path (Join-Path $PSScriptRoot "..")

Write-Host "==> Verific Python..." -ForegroundColor Cyan
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) {
    Write-Error "Python nu e in PATH. Instaleaza Python 3.10+ de pe https://python.org si bifeaza 'Add to PATH'."
    exit 1
}
& $python --version

Write-Host "==> Creez/activez venv local pentru build (.venv-build)..." -ForegroundColor Cyan
$venv = ".\.venv-build"
if (-not (Test-Path $venv)) {
    & $python -m venv $venv
}
$venvPython = Join-Path $venv "Scripts\python.exe"

Write-Host "==> Instalare dependente (poate dura 1-2 minute prima data)..." -ForegroundColor Cyan
& $venvPython -m pip install --quiet --upgrade pip
& $venvPython -m pip install --quiet -r .\agent\requirements-dev.txt

Write-Host "==> Build cu PyInstaller..." -ForegroundColor Cyan
& $venvPython -m PyInstaller --clean --noconfirm .\agent\VulnWatchAgent.spec

$exe = ".\dist\VulnWatchAgent.exe"
if (-not (Test-Path $exe)) {
    Write-Error "Build esuat - nu s-a produs $exe"
    exit 2
}

$size = "{0:N1} MB" -f ((Get-Item $exe).Length / 1MB)
Write-Host ""
Write-Host "==> SUCCES" -ForegroundColor Green
Write-Host "    Output  : $exe"
Write-Host "    Marime  : $size"
Write-Host ""
Write-Host "Distribuie acest .exe pe orice masina Windows. La dublu-click se deschide GUI-ul de inrolare." -ForegroundColor Cyan

# Optional: copiaza .exe-ul in folderul static al backend-ului ca sa fie servit la /api/v1/agent/download/windows
$staticTarget = ".\server\app\static\agent"
if (Test-Path ".\server\app") {
    New-Item -ItemType Directory -Path $staticTarget -Force | Out-Null
    Copy-Item -Path $exe -Destination (Join-Path $staticTarget "VulnWatchAgent.exe") -Force
    Write-Host "    Copiat si in: $staticTarget\VulnWatchAgent.exe (servit din UI)" -ForegroundColor Cyan
}

# Pauza la dublu-click ca user-ul sa vada output-ul
if ($Host.Name -eq "ConsoleHost") {
    Read-Host "Apasa Enter pentru a inchide"
}
