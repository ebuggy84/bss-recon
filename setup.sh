#!/usr/bin/env bash
#
# BSS Recon — first-time setup
# Creates a virtualenv, installs dependencies, and prepares config.yaml.
#
# Usage:
#   ./setup.sh
#
set -euo pipefail

# Always run from the directory this script lives in (the repo root).
cd "$(dirname "$0")"

# Pick an available Python interpreter.
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "[!] Python 3 is required but was not found on PATH. Install Python 3.10+ and re-run." >&2
  exit 1
fi

echo "=================================================================="
echo "  BSS Recon — Setup"
echo "=================================================================="
echo

# ── 1. Create the virtual environment ────────────────────────────────
if [ -d "venv" ]; then
  echo "[*] Virtual environment 'venv' already exists — reusing it."
else
  echo "[*] Creating virtual environment (venv) ..."
  "$PY" -m venv venv
fi

# ── 2. Activate it ───────────────────────────────────────────────────
echo "[*] Activating virtual environment ..."
# shellcheck disable=SC1091
source venv/bin/activate

# ── 3. Install requirements ──────────────────────────────────────────
echo "[*] Upgrading pip and installing requirements.txt ..."
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt

# ── 4. Prepare config.yaml (never overwrite an existing one) ─────────
if [ -f "config.yaml" ]; then
  echo "[*] config.yaml already exists — leaving it untouched."
else
  echo "[*] Creating config.yaml from config.yaml.example ..."
  cp config.yaml.example config.yaml
fi

# ── 5 & 6. Friendly next-steps message ───────────────────────────────
echo
echo "=================================================================="
echo "  Setup complete."
echo "=================================================================="
echo
echo "  API keys (optional):"
echo "    For full functionality, add your API keys to config.yaml:"
echo "      - shodan       (https://account.shodan.io)"
echo "      - virustotal   (https://www.virustotal.com/gui/join-us)"
echo "      - hunter_io    (https://hunter.io/api-keys)"
echo "    The tool works out of the box with zero configuration —"
echo "    modules without a key are skipped automatically."
echo
echo "  Run your first scan:"
echo "    source venv/bin/activate"
echo "    python -m bssrecon scan example.com"
echo
echo "    (add --active to enable modules that touch the target directly,"
echo "     only against systems you are authorized to test.)"
echo
