#!/bin/sh
set -e

# On first run, create a working config.yaml from the example unless the user
# has mounted their own. Blank API keys simply cause those modules to skip.
if [ ! -f /app/config.yaml ]; then
    cp /app/config.yaml.example /app/config.yaml
    echo "[bss-recon] No config.yaml found — created one from config.yaml.example."
    echo "[bss-recon] Add API keys (shodan / virustotal / hunter_io) to enable keyed modules."
fi

exec "$@"
