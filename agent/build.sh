#!/usr/bin/env bash
# Build vulnwatch-agent (Linux). Ruleaza din radacina repo-ului:
#     bash agent/build.sh
#
# Rezultat: dist/vulnwatch-agent (binar standalone, fara extensie).
set -e

# Mergi in radacina repo-ului (parent al directorului acestui script).
cd "$(dirname "$0")/.."

echo "==> Verific Python..."
PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then
  echo "Python nu e in PATH. Instaleaza Python 3.10+." >&2
  exit 1
fi
"$PY" --version

echo "==> Creez/activez venv local pentru build (.venv-build)..."
[ -d .venv-build ] || "$PY" -m venv .venv-build
VPY=.venv-build/bin/python

echo "==> Instalare dependente (poate dura 1-2 minute prima data)..."
"$VPY" -m pip install --quiet --upgrade pip
# Doar dependinte cross-platform (pywin32 e Windows-only si nu se instaleaza pe Linux).
"$VPY" -m pip install --quiet pyinstaller psutil requests google-auth google-auth-oauthlib pillow pystray

echo "==> Build cu PyInstaller..."
"$VPY" -m PyInstaller --clean --noconfirm agent/VulnWatchAgent.spec

BIN=dist/vulnwatch-agent
if [ ! -f "$BIN" ]; then
  echo "Build esuat - nu s-a produs $BIN" >&2
  exit 2
fi
chmod +x "$BIN"
echo ""
echo "==> SUCCES"
echo "    Output : $BIN ($(du -h "$BIN" | cut -f1))"

# Optional: copiaza binarul in folderul static al backend-ului ca sa fie servit
# la /api/v1/agent/download/linux.
if [ -d server/app ]; then
  mkdir -p server/app/static/agent
  cp "$BIN" server/app/static/agent/vulnwatch-agent
  echo "    Copiat in: server/app/static/agent/vulnwatch-agent (servit din UI)"
fi
