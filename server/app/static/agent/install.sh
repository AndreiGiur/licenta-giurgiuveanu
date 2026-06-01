#!/usr/bin/env bash
# VulnWatch Agent - installer Linux (Debian / Ubuntu / Kali).
#
# Descarca acest fisier din platforma (butonul "Descarca installer Linux") sau
# ruleaza-l din checkout-ul repo-ului. Face tot ce trebuie ca sa rulezi agentul:
#   - instaleaza dependintele de sistem (python3, venv, tk) prin apt
#   - aduce sursa (din checkout local SAU git clone)
#   - creeaza un venv + instaleaza dependintele Python
#   - creeaza un launcher ./vulnwatch-agent
#
# Utilizare pe Kali:
#   bash install.sh
#   ./vulnwatch-agent            # GUI
#   ./vulnwatch-agent enroll     # inrolare din CLI
#   ./vulnwatch-agent daemon     # daemon din CLI
set -e

REPO_URL="https://github.com/AndreiGiur/licenta-giurgiuveanu.git"
INSTALL_DIR="${VULNWATCH_DIR:-$HOME/vulnwatch-agent}"

echo "==> VulnWatch Agent - installer Linux"

# ── 1) Dependinte de sistem (apt) ─────────────────────────────────────────────
need_apt=()
command -v python3 >/dev/null 2>&1 || need_apt+=("python3")
python3 -c "import venv" >/dev/null 2>&1 || need_apt+=("python3-venv")
python3 -c "import tkinter" >/dev/null 2>&1 || need_apt+=("python3-tk")
if [ "${#need_apt[@]}" -gt 0 ]; then
  echo "==> Instalez dependinte de sistem: ${need_apt[*]}"
  if command -v sudo >/dev/null 2>&1; then
    sudo apt-get update -y && sudo apt-get install -y "${need_apt[@]}"
  else
    echo "    Ruleaza ca root sau instaleaza manual: apt-get install -y ${need_apt[*]}" >&2
  fi
fi

# ── 2) Sursa: checkout local sau git clone ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
if [ -f "$SCRIPT_DIR/agent/scan.py" ]; then
  SRC="$SCRIPT_DIR"                       # rulat din radacina repo-ului
elif [ -f "$SCRIPT_DIR/scan.py" ]; then
  SRC="$(dirname "$SCRIPT_DIR")"          # rulat din agent/
else
  echo "==> Aduc sursa de la: $REPO_URL"
  command -v git >/dev/null 2>&1 || {
    if command -v sudo >/dev/null 2>&1; then sudo apt-get install -y git; else apt-get install -y git; fi
  }
  if [ ! -d "$INSTALL_DIR/.git" ]; then
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  else
    echo "    $INSTALL_DIR exista deja; fac git pull"
    (cd "$INSTALL_DIR" && git pull --ff-only) || true
  fi
  SRC="$INSTALL_DIR"
fi
echo "==> Sursa agentului: $SRC"

# ── 3) venv + dependinte Python ───────────────────────────────────────────────
VENV="$SRC/.venv"
echo "==> Creez venv si instalez dependintele Python..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet psutil requests google-auth google-auth-oauthlib pillow pystray

# ── 4) Launcher ───────────────────────────────────────────────────────────────
LAUNCHER="$SRC/vulnwatch-agent"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
cd "$SRC"
exec "$VENV/bin/python" -m agent.scan "\$@"
EOF
chmod +x "$LAUNCHER"

echo ""
echo "==> Gata! Ruleaza agentul:"
echo "    $LAUNCHER            # GUI (necesita python3-tk)"
echo "    $LAUNCHER enroll     # inrolare din CLI"
echo "    $LAUNCHER daemon     # daemon din CLI"
echo ""
echo "Pentru scanari deep ai nevoie de nmap:"
echo "    sudo apt-get install -y nmap"
echo "    (sau butonul 'Instaleaza nmap' din aplicatie)"
