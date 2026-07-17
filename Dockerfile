# syntax=docker/dockerfile:1
#
# BSS Recon — container image
#   * Python CLI          →  python -m bssrecon scan <target>
#   * FastAPI web dashboard → served on port 8000
#   * Bundles nmap + nuclei so active modules work out of the box.
#
FROM python:3.12-slim

# ── System dependencies ──────────────────────────────────────────────
#   nmap                        active port/service scanning module
#   curl / unzip / ca-certs     used to fetch the nuclei release below
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        nmap curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# ── nuclei (latest linux/amd64 release) ──────────────────────────────
# Resolve the latest tag from the GitHub API so we never pin a stale/invalid
# version, then install the matching binary. Pin `ver` to a fixed value here
# if you prefer reproducible builds.
RUN set -eux; \
    ver="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
           | grep -oE '"tag_name":[[:space:]]*"v[0-9.]+"' \
           | grep -oE 'v[0-9.]+' | head -n1 | tr -d v)"; \
    curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${ver}/nuclei_${ver}_linux_amd64.zip"; \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei; \
    rm -f /tmp/nuclei.zip; \
    nuclei -version

WORKDIR /app

# ── Python dependencies (CLI + dashboard) ────────────────────────────
# Copied first so the pip layer stays cached until requirements change.
COPY requirements.txt ./requirements.txt
COPY bss-dashboard/backend/requirements.txt ./dashboard-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r dashboard-requirements.txt

# ── Application source ───────────────────────────────────────────────
COPY bssrecon ./bssrecon
COPY bss-dashboard ./bss-dashboard
COPY config.yaml.example ./config.yaml.example
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# bssrecon must be importable by both the CLI and the dashboard backend.
# (uvicorn --app-dir adds the backend dir to sys.path for `main:app`;
#  PYTHONPATH=/app makes the bssrecon package importable from there.)
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# Default command launches the web dashboard. Override to run the CLI, e.g.
#   docker compose run --rm bss-recon python -m bssrecon scan example.com
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "bss-dashboard/backend"]
