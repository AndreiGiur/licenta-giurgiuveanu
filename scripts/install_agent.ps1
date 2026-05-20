# install_agent.ps1 - Re-instaleaza VulnWatchAgent in path stabil.
#
# Ruleaza:
#     powershell -ExecutionPolicy Bypass -File scripts\install_agent.ps1
#
# NU necesita admin. Toate operatiile sunt in profilul user-ului curent.

$ErrorActionPreference = "Stop"

# 1. Path-uri.
$src = Join-Path $PSScriptRoot "..\dist\VulnWatchAgent.exe" | Resolve-Path -ErrorAction Stop
$dstDir = Join-Path $env:LOCALAPPDATA "VulnWatch"
$dstExe = Join-Path $dstDir "VulnWatchAgent.exe"

Write-Host "==> Sursa : $src" -ForegroundColor Cyan
Write-Host "==> Tinta : $dstExe" -ForegroundColor Cyan

# 2. Opreste orice instanta veche a agent-ului.
$running = Get-Process -Name "VulnWatchAgent" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "==> Opresc $($running.Count) instanta(e) existenta(e)..." -ForegroundColor Yellow
    $running | Stop-Process -Force
    Start-Sleep -Seconds 1
}

# 3. Sterge startup-ul vechi (cel cu path %temp%).
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$oldVal = (Get-ItemProperty -Path $runKey -Name VulnWatchAgent -ErrorAction SilentlyContinue).VulnWatchAgent
if ($oldVal) {
    Write-Host "==> Curat vechiul startup entry..." -ForegroundColor Yellow
    Write-Host "    (era: $oldVal)" -ForegroundColor DarkGray
    Remove-ItemProperty -Path $runKey -Name VulnWatchAgent -Force
}

# 4. Creeaza folder + copiaza .exe.
if (-not (Test-Path $dstDir)) {
    New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
}
Copy-Item -Path $src -Destination $dstExe -Force
Write-Host "==> Copiat in $dstExe" -ForegroundColor Green

# 5. Verifica daca exista config-ul de inrolare (~/.vulnwatch/config.ini).
$cfg = Join-Path $env:USERPROFILE ".vulnwatch\config.ini"
if (Test-Path $cfg) {
    Write-Host "==> Config existent: $cfg (se pastreaza)" -ForegroundColor Green
} else {
    Write-Host "==> NU exista config - vei face inrolarea cand pornesti agent-ul." -ForegroundColor Yellow
}

# 6. Set startup nou (path stabil).
$startupCmd = "`"$dstExe`" daemon"
Set-ItemProperty -Path $runKey -Name VulnWatchAgent -Value $startupCmd
Write-Host "==> Startup setat: $startupCmd" -ForegroundColor Green

# 7. Sterge fisierele orfane din %temp% (best-effort).
$tempPattern = Join-Path $env:LOCALAPPDATA "Temp\scoped_dir*"
$orphans = Get-ChildItem -Path $tempPattern -Filter "VulnWatchAgent*.exe" -Recurse -ErrorAction SilentlyContinue
if ($orphans) {
    Write-Host "==> Sterg $($orphans.Count) copie(i) orfana(e) din %temp%..." -ForegroundColor Yellow
    $orphans | Remove-Item -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "==> INSTALARE COMPLETA" -ForegroundColor Green
Write-Host ""
Write-Host "Urmatorii pasi:" -ForegroundColor Cyan
Write-Host ("  1. Porneste agent-ul: " + $dstExe)
Write-Host "  2. Daca nu e inrolat, va deschide GUI pentru login (Google sau email/parola)."
Write-Host "  3. Apoi va rula in background si va aparea ca online in dashboard-ul VulnWatch."
Write-Host ""
Write-Host "Pornesc agent-ul acum..." -ForegroundColor Cyan
Start-Process -FilePath $dstExe
