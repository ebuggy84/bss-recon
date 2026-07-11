# bss-recon

**A 19-module OSINT and reconnaissance platform for security assessments.** `bss-recon` unifies
passive intelligence gathering and active scanning behind a single CLI and web dashboard: point it
at a target and it runs WHOIS/DNS/SSL enumeration, subdomain discovery, WAF and technology
fingerprinting, JavaScript secret analysis, Shodan/VirusTotal/Hunter.io lookups, Nmap and Nuclei
scanning, and more — then produces a scored, framework-mapped assessment report in Markdown and PDF.

Built by **Burgohy Security Solutions** for repeatable, evidence-backed target assessments.

---

## Modules

Passive and active modules can be run individually or as a pipeline (`--modules`).

| # | Module | Type | Description |
|---|--------|------|-------------|
| 1  | `whois`      | Passive | WHOIS registration, registrar, and age lookup |
| 2  | `dns`        | Passive | DNS record enumeration (A/AAAA/MX/NS/TXT/CNAME) |
| 3  | `subdomains` | Passive | Subdomain discovery from multiple sources |
| 4  | `submutate`  | Passive | **SubMutate** — permutation/mutation-based subdomain expansion |
| 5  | `ssl`        | Passive | SSL/TLS certificate inspection and chain analysis |
| 6  | `wafdetect`  | Active  | Web Application Firewall detection and fingerprinting |
| 7  | `headers`    | Active  | Security-header analysis (HSTS, CSP, CORS, framing) |
| 8  | `techdetect` | Active  | Technology-stack fingerprinting |
| 9  | `webprobe`   | Active  | **Web probe v2** — liveness, status, titles, redirect chains |
| 10 | `jsanalyze`  | Active  | JavaScript bundle analysis — secrets, API keys, endpoints |
| 11 | `dorks`      | Passive | Google dork generation for the target |
| 12 | `wayback`    | Passive | **Wayback Machine CDX** historical URL harvesting |
| 13 | `diff`       | Passive | Change detection across successive scans |
| 14 | `shodan`     | Passive | Shodan host/service intelligence |
| 15 | `virustotal` | Passive | VirusTotal domain/IP reputation |
| 16 | `hunter`     | Passive | Hunter.io email/contact discovery |
| 17 | `nmap`       | Active  | Nmap port and service scanning |
| 18 | `nuclei`     | Active  | Nuclei template-based vulnerability scanning |
| 19 | `score`      | Passive | Attack-surface scoring and target prioritisation |

Additional tooling: an **IDOR candidate finder** (`bssrecon/tools/idor_finder.py`) and
**OWASP / MITRE ATT&CK** mapping of findings (`bssrecon/frameworks/`).

---

## Reporting & dashboard

- **Markdown + PDF reports** — per-target assessment reports with findings mapped to OWASP and
  MITRE ATT&CK (`bssrecon/reporting/`).
- **Web dashboard** — a **FastAPI** backend and **React** single-page frontend
  (`bss-dashboard/`) for launching scans and browsing results interactively.

---

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Some active modules shell out to external tools that must be installed separately and available on
`PATH`: **nmap** and **nuclei**.

---

## Configuration

API-key-driven modules (Shodan, VirusTotal, Hunter.io, and optional AI analysis) read their keys
from `config.yaml`. Copy the template and add your own keys:

```bash
cp config.yaml.example config.yaml
# edit config.yaml — add API keys for the modules you want to use
```

```yaml
api_keys:
  shodan: ""
  virustotal: ""
  hunter_io: ""
```

> **Never commit `config.yaml`.** It holds live API keys and is excluded by `.gitignore`; only
> `config.yaml.example` (blank placeholders) is tracked. Modules with a blank key are skipped
> automatically. Rotate any key that is ever exposed.

---

## Usage

```bash
# Run the default module pipeline against a target
python -m bssrecon scan example.com

# Run specific modules only
python -m bssrecon scan example.com --modules whois,dns,subdomains,ssl,shodan

# Launch the web dashboard (FastAPI backend)
cd bss-dashboard/backend && uvicorn main:app --port 8000
```

Raw results are written to `output/` and formatted reports to `reports/` — both git-ignored.

---

## Project structure

```
bss-recon/
├── bssrecon/
│   ├── cli.py              # CLI entry point
│   ├── config.py           # config.yaml loader
│   ├── core/               # the 19 recon modules
│   ├── tools/              # IDOR finder and extras
│   ├── ingest/             # parsers (e.g. Nmap XML)
│   ├── frameworks/         # OWASP + MITRE ATT&CK mapping
│   ├── reporting/          # Markdown + PDF report generation
│   ├── utils/              # display / helpers
│   └── wordlists/          # discovery wordlists
├── bss-dashboard/
│   ├── backend/            # FastAPI backend
│   └── frontend/           # React single-page dashboard
├── config.yaml.example     # API-key template (safe to commit)
├── requirements.txt
└── README.md
```

---

## Responsible use

`bss-recon` is for **authorised security assessments only**. Run it exclusively against systems you
own or are explicitly permitted to test. Active modules (nmap, nuclei, webprobe, wafdetect) generate
traffic that may be logged or disruptive — stay within your engagement's scope and rate limits. The
operator is responsible for lawful, authorised use.

---

## License

Released under the MIT License.
