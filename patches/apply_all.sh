#!/bin/bash
# BSS Recon — Apply all patches
# Run from Kali: cd ~/bss-recon && bash patches/apply_all.sh

set -e

echo "=========================================="
echo " BSS Recon — Patch Installer"
echo "=========================================="
echo ""

# Make sure we're in the right place
if [ ! -d "$HOME/bss-recon/bssrecon" ]; then
    echo "ERROR: ~/bss-recon/bssrecon not found. Run from the bss-recon directory."
    exit 1
fi

cd "$HOME/bss-recon"

# Activate venv if it exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "Activated venv"
fi

# Make sure reportlab is installed (needed for PDF patch)
pip install reportlab --quiet 2>/dev/null && echo "reportlab: installed" || echo "reportlab: already installed or pip unavailable"

echo ""
echo "--- PATCH 1: Fix dashboard backend (main.py) ---"
python3 patches/fix_main_py.py

echo ""
echo "--- PATCH 2: Add monitor + PDF to CLI (cli.py) ---"
python3 patches/patch_cli_py.py

echo ""
echo "=========================================="
echo " All patches applied!"
echo "=========================================="
echo ""
echo "To restart the dashboard:"
echo "  pkill -f uvicorn 2>/dev/null; pkill -f 'http.server 3000' 2>/dev/null"
echo "  cd ~/bss-recon/bss-dashboard/backend && uvicorn main:app --host 0.0.0.0 --port 8000 &"
echo "  cd ~/bss-recon/bss-dashboard/frontend && python3 -m http.server 3000 --bind 0.0.0.0 &"
echo ""
echo "To test the CLI patches:"
echo "  python -m bssrecon scan example.com -r              # passive scan"
echo "  python -m bssrecon report example.com -f pdf         # PDF report"
echo "  python -m bssrecon scan example.com -r --monitor 6   # monitor mode"
echo ""
echo "To test the dashboard:"
echo "  Open http://10.0.20.162:3000 and run a scan"
echo "  Check terminal for '[BSS Dashboard] Loaded N real modules' message"
