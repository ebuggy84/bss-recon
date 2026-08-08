"""
BSS Recon Web Dashboard — FastAPI Backend

Usage:
    cd bss-dashboard/backend
    pip install -r requirements.txt
    # Activate the bss-recon venv first so bssrecon is importable:
    source ~/bss-recon/venv/bin/activate
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Without the bssrecon venv, the server starts in DEMO MODE with stub modules
that return realistic fake data so the frontend can be developed and tested.
"""
from __future__ import annotations

import asyncio
import json
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = FastAPI(title="BSS Recon Dashboard API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_executor = ThreadPoolExecutor(max_workers=4)
_lock = threading.Lock()
_scans: dict[str, dict] = {}
_ws_queues: dict[str, asyncio.Queue] = {}
_main_loop: asyncio.AbstractEventLoop | None = None

# Unified scan-output directory — SHARED with the CLI. Resolved from the same
# bssrecon config (output.output_dir) the CLI uses, anchored to the repo root so
# the dashboard and `python -m bssrecon scan` read and write the SAME folder
# regardless of working directory. Falls back to a local "dashboard_output" only
# if bssrecon can't be imported (pure demo mode).
try:
    from bssrecon.config import load_config as _load_cfg, get_output_dir as _get_out
    OUTPUT_DIR = _get_out(_load_cfg())
except Exception:  # bssrecon not importable — demo/dev fallback
    OUTPUT_DIR = Path("dashboard_output")
    OUTPUT_DIR.mkdir(exist_ok=True)


@app.on_event("startup")
async def _on_startup() -> None:
    global _main_loop
    _main_loop = asyncio.get_event_loop()


# ---------------------------------------------------------------------------
# Module loading — imports real bssrecon or falls back to stubs
# ---------------------------------------------------------------------------

def _load_registry() -> dict[str, Any]:
    """Load real bssrecon modules as instantiated objects, or fall back to stubs.

    MODULE_REGISTRY contains CLASSES, not instances. Each class requires
    __init__(config) before .run(target) works. cli.py does this correctly;
    this function now mirrors that pattern.
    """
    try:
        from bssrecon.core import MODULE_REGISTRY  # type: ignore
        from bssrecon.config import load_config     # type: ignore

        config = load_config()
        registry: dict[str, Any] = {}

        for name, cls in MODULE_REGISTRY.items():
            try:
                instance = cls(config)
                registry[name] = instance
            except Exception as exc:
                import sys
                print(f"[BSS Dashboard] Failed to instantiate module '{name}': {exc}", file=sys.stderr)

        if registry:
            import sys
            print(f"[BSS Dashboard] Loaded {len(registry)} real modules: {', '.join(registry.keys())}", file=sys.stderr)
            return registry

        # If all modules failed to instantiate, fall back to stubs
        import sys
        print("[BSS Dashboard] All modules failed to instantiate, falling back to stubs", file=sys.stderr)
        return _build_stubs()

    except ImportError as exc:
        import sys
        print(f"[BSS Dashboard] Cannot import bssrecon ({exc}), using demo stubs", file=sys.stderr)
        return _build_stubs()


def _build_stubs() -> dict[str, Any]:
    import random
    import time as _t

    class _Stub:
        def __init__(self, name: str, description: str, mode: str) -> None:
            self.name = name
            self.description = description
            self.mode = mode

        def run(self, target: str) -> dict:
            _t.sleep(random.uniform(0.6, 2.2))
            owasp = [
                "A01:2021 Broken Access Control",
                "A02:2021 Cryptographic Failures",
                "A03:2021 Injection",
                "A05:2021 Security Misconfiguration",
                "A06:2021 Vulnerable and Outdated Components",
                "A07:2021 Identification and Authentication Failures",
                "A10:2021 Server-Side Request Forgery",
            ]
            mitre = [
                "T1190 - Exploit Public-Facing Application",
                "T1046 - Network Service Discovery",
                "T1021.004 - Remote Services: SSH",
                "T1552 - Unsecured Credentials",
                "T1082 - System Information Discovery",
                "T1078 - Valid Accounts",
            ]
            severity_weights = ["critical","high","high","medium","medium","medium","low","low","info","info"]
            n = random.randint(0, 5) if random.random() > 0.2 else 0
            findings = []
            for i in range(n):
                sev = random.choice(severity_weights)
                findings.append({
                    "severity": sev,
                    "title": _stub_title(self.name, sev, i),
                    "detail": (
                        f"Demo finding #{i+1} from the {self.name} module scanning {target}. "
                        "Install the full bssrecon package on this host for real findings."
                    ),
                    "owasp": random.choice(owasp),
                    "mitre": random.choice(mitre),
                    "remediation": (
                        "This is a demo result. Connect this backend to a Kali box "
                        "with bssrecon installed to see real remediation guidance."
                    ),
                })
            extras: dict[str, Any] = {}
            if self.name == "subdomains":
                extras["subdomains"] = [f"sub{i}.{target}" for i in range(random.randint(2, 12))]
            if self.name == "nmap":
                extras["open_ports"] = [
                    {"port": p, "protocol": "tcp", "service": s}
                    for p, s in random.sample(
                        [(80,"http"),(443,"https"),(22,"ssh"),(8080,"http-proxy"),
                         (3306,"mysql"),(6379,"redis"),(27017,"mongodb")], k=random.randint(2, 5)
                    )
                ]
            return {"domain": target, "findings": findings, **extras}

    def _stub_title(module: str, sev: str, idx: int) -> str:
        titles = {
            "whois":     ["Registrar contact exposed", "Domain registered recently", "WHOIS privacy disabled"],
            "dns":       ["Missing DMARC record", "SPF policy too permissive", "Zone transfer permitted"],
            "ssl":       ["TLS 1.0 enabled", "Certificate expiring soon", "Weak cipher suite detected"],
            "headers":   ["Content-Security-Policy absent", "HSTS max-age too low", "X-Frame-Options missing"],
            "webprobe":  [".git directory exposed", ".env file accessible", "Admin panel reachable"],
            "jsanalyze": ["API key in bundle", "Internal endpoint in JS", "S3 bucket URL exposed"],
            "nuclei":    ["CVE-2023-44487 (HTTP/2 Rapid Reset)", "Default credentials accepted", "Swagger UI exposed"],
            "nmap":      ["Redis exposed without auth", "MySQL bound to 0.0.0.0", "SSH allows root login"],
            "wafdetect": ["No WAF detected — direct origin reachable", "Cloudflare bypass possible"],
            "techdetect":["WordPress 6.2 (outdated)", "jQuery 1.x detected", "PHP version disclosed"],
        }
        pool = titles.get(module, ["Security misconfiguration", "Sensitive data exposure", "Access control issue"])
        return pool[idx % len(pool)]

    modules: dict[str, Any] = {}
    for name, desc, mode in [
        ("whois",      "Domain registration + registrar info",         "passive"),
        ("dns",        "DNS records + SPF/DKIM/DMARC analysis",        "passive"),
        ("subdomains", "Certificate Transparency subdomain enum",      "passive"),
        ("ssl",        "TLS cert chain + cipher analysis",             "passive"),
        ("shodan",     "Shodan port/service/CVE lookup",               "passive"),
        ("dorks",      "Google dork query generator (47 queries)",     "passive"),
        ("virustotal", "Domain reputation + malware history",          "passive"),
        ("hunter",     "Email address discovery",                      "passive"),
        ("diff",       "Change detection vs prior scan",               "passive"),
        ("wafdetect",  "WAF/CDN canary detection",                     "active"),
        ("headers",    "HTTP security headers (8 checks)",             "active"),
        ("techdetect", "Technology stack fingerprinting",              "active"),
        ("webprobe",   "Sensitive path probing (40+ paths)",           "active"),
        ("jsanalyze",  "JS bundle secrets + API endpoint analysis",    "active"),
        ("nuclei",     "Nuclei vulnerability scanner (default templates)","active"),
        ("nmap",       "Nmap service scan — top-1000 ports",           "active"),
        ("score",      "Attack surface scoring + priority ranking",    "passive"),
    ]:
        modules[name] = _Stub(name, desc, mode)
    return modules


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str
    active: bool = False
    modules: Optional[list[str]] = None
    profile: str = "balanced"   # stealth | balanced | aggressive


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------

def _push(scan_id: str, event: dict) -> None:
    if _main_loop and scan_id in _ws_queues:
        _main_loop.call_soon_threadsafe(_ws_queues[scan_id].put_nowait, event)


def _sev_counts(findings: list[dict]) -> dict[str, int]:
    c: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info").lower()
        c[s] = c.get(s, 0) + 1
    return c


def _surface_score(results_map: dict) -> tuple:
    """Compute the unified 0-100 attack-surface score + tier using the SAME math
    as the score module (saturating curve + subdomain surface + tier bands), so
    the dashboard ring and the score card show one identical number. results_map
    is a {module_name: result} mapping. Returns (score, raw_score, tier) or
    (None, None, None) if the scoring engine isn't importable (demo mode)."""
    try:
        from bssrecon.core.target_score import (  # type: ignore
            _score_results, _normalize_score, _tier,
        )
    except Exception:
        return None, None, None
    raw, _breakdown, _priority = _score_results(results_map or {})
    score = _normalize_score(raw)
    return score, raw, _tier(score)


def _run_scan(scan_id: str, target: str, active: bool, requested: list[str] | None,
              profile: str = "balanced") -> None:
    registry = _load_registry()

    to_run: dict[str, Any] = {
        name: mod for name, mod in registry.items()
        if (not requested or name in requested)
        and (active or getattr(mod, "mode", "passive") != "active")
    }

    # Apply the selected concurrency profile to each module's config so active
    # modules pace themselves accordingly (stealth/balanced/aggressive).
    for _mod in to_run.values():
        _cfg = getattr(_mod, "config", None)
        if isinstance(_cfg, dict):
            _cfg.setdefault("scan", {})["profile"] = profile

    with _lock:
        _scans[scan_id].update({
            "status": "running",
            "total_modules": len(to_run),
            "completed_modules": 0,
            "modules": {
                n: {
                    "status": "pending",
                    "description": getattr(m, "description", ""),
                    "mode": getattr(m, "mode", "passive"),
                    "finding_count": 0,
                }
                for n, m in to_run.items()
            },
        })

    _push(scan_id, {
        "type": "started",
        "modules": [
            {
                "name": n,
                "description": getattr(m, "description", ""),
                "mode": getattr(m, "mode", "passive"),
            }
            for n, m in to_run.items()
        ],
    })

    all_findings: list[dict] = []
    results_map: dict[str, Any] = {}  # raw per-module results, for the score module

    # 'score' aggregates every other module's findings, so run it LAST and give
    # it the results collected so far (otherwise it always scored 0).
    ordered = sorted(to_run.items(), key=lambda kv: kv[0] == "score")
    for name, mod in ordered:
        with _lock:
            _scans[scan_id]["modules"][name]["status"] = "running"
        _push(scan_id, {"type": "module_start", "module": name})

        try:
            if name == "score":
                mod.scan_results = results_map
            result = mod.run(target)
            results_map[name] = result
            findings = result.get("findings", [])
            for f in findings:
                f.setdefault("module", name)
            all_findings.extend(findings)

            module_entry = {
                "status": "done",
                "description": getattr(mod, "description", ""),
                "mode": getattr(mod, "mode", "passive"),
                "finding_count": len(findings),
                # Store non-findings data (subdomains, open_ports, etc.) for the UI
                "data": {k: v for k, v in result.items() if k != "findings"},
            }
            with _lock:
                _scans[scan_id]["modules"][name] = module_entry
                _scans[scan_id]["completed_modules"] += 1

            _push(scan_id, {
                "type": "module_done",
                "module": name,
                "finding_count": len(findings),
                "completed": _scans[scan_id]["completed_modules"],
                "total": _scans[scan_id]["total_modules"],
            })

        except Exception as exc:
            with _lock:
                _scans[scan_id]["modules"][name] = {
                    "status": "error",
                    "description": getattr(mod, "description", ""),
                    "mode": getattr(mod, "mode", "passive"),
                    "finding_count": 0,
                    "error": str(exc),
                }
                _scans[scan_id]["completed_modules"] += 1

            _push(scan_id, {
                "type": "module_error",
                "module": name,
                "error": str(exc),
                "completed": _scans[scan_id]["completed_modules"],
                "total": _scans[scan_id]["total_modules"],
            })

    sev = _sev_counts(all_findings)
    surface_score, surface_raw, surface_tier = _surface_score(results_map)
    finished_at = datetime.now(timezone.utc).isoformat()

    with _lock:
        _scans[scan_id].update({
            "status": "complete",
            "findings": all_findings,
            "severity_counts": sev,
            # Unified attack-surface score (drives the ring AND the score card).
            "score": surface_score,
            "raw_score": surface_raw,
            "tier": surface_tier,
            "finished_at": finished_at,
        })

    _persist(scan_id)

    _push(scan_id, {
        "type": "complete",
        "finding_count": len(all_findings),
        "severity_counts": sev,
        "finished_at": finished_at,
    })


def _persist(scan_id: str) -> None:
    with _lock:
        data = dict(_scans[scan_id])
    # Never rewrite a file that originated from the CLI — it lives in the shared
    # output dir in the CLI's own format, and overwriting it with the dashboard
    # record shape would corrupt it for the `bssrecon report` command.
    if data.get("source") == "cli":
        return
    (OUTPUT_DIR / f"{scan_id}.json").write_text(
        json.dumps(data, indent=2, default=str), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# CLI ↔ dashboard format bridge
#
# The CLI writes scans as {module_name: {..., "findings": [...]}} while the
# dashboard uses {scan_id, target, findings[], severity_counts{}, modules{}}.
# Since both now share one output dir, the dashboard normalizes CLI-format
# files on read so a `python -m bssrecon scan` shows up here WITH findings.
# ---------------------------------------------------------------------------

def _module_meta() -> dict[str, tuple[str, str]]:
    """name -> (description, mode) from the real registry (best effort)."""
    meta: dict[str, tuple[str, str]] = {}
    try:
        from bssrecon.core import MODULE_REGISTRY  # type: ignore
        for name, cls in MODULE_REGISTRY.items():
            meta[name] = (getattr(cls, "description", ""), getattr(cls, "mode", "passive"))
    except Exception:
        pass
    return meta


def _looks_like_cli_format(raw: Any) -> bool:
    """True if `raw` is a CLI scan file (mapping of module -> result dict)."""
    if not isinstance(raw, dict) or "scan_id" in raw or "severity_counts" in raw:
        return False
    for v in raw.values():
        if isinstance(v, dict) and ("findings" in v or "domain" in v or "error" in v):
            return True
    return False


def _normalize_cli_record(raw: dict, path: Path) -> dict:
    """Convert a CLI-format scan dict into the dashboard record shape."""
    import re

    meta = _module_meta()
    stem = path.stem

    # Target: prefer a module's own domain/target field, else parse the filename.
    target = ""
    for v in raw.values():
        if isinstance(v, dict) and (v.get("domain") or v.get("target")):
            target = v.get("domain") or v.get("target")
            break
    if not target:
        m = re.match(r"^(.*)_\d{8}_\d{6}$", stem)
        target = (m.group(1) if m else stem).replace("_", ".")

    # Timestamp: prefer the _YYYYmmdd_HHMMSS filename suffix, else file mtime.
    started_at = None
    m = re.search(r"_(\d{8})_(\d{6})$", stem)
    if m:
        try:
            started_at = datetime.strptime(
                m.group(1) + m.group(2), "%Y%m%d%H%M%S"
            ).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            started_at = None
    if not started_at:
        started_at = datetime.fromtimestamp(
            path.stat().st_mtime, timezone.utc
        ).isoformat()

    modules: dict[str, Any] = {}
    all_findings: list[dict] = []
    for name, data in raw.items():
        if not isinstance(data, dict):
            continue
        findings = data.get("findings", []) or []
        for f in findings:
            if isinstance(f, dict):
                f.setdefault("module", name)
                all_findings.append(f)
        desc, mode = meta.get(name, ("", "passive"))
        errored = "error" in data
        entry = {
            "status": "error" if errored else "done",
            "description": desc,
            "mode": mode,
            "finding_count": len(findings),
            "data": {k: v for k, v in data.items() if k != "findings"},
        }
        if errored:
            entry["error"] = data.get("error")
        modules[name] = entry

    sev = _sev_counts(all_findings)

    return {
        "scan_id": stem,
        "target": target,
        "status": "complete",
        "active": any(m.get("mode") == "active" for m in modules.values()),
        "requested_modules": list(modules.keys()),
        "started_at": started_at,
        "finished_at": started_at,
        "total_modules": len(modules),
        "completed_modules": len(modules),
        "modules": modules,
        "findings": all_findings,
        "severity_counts": sev,
        "source": "cli",
    }


def _apply_surface_score(record: dict) -> dict:
    """Attach the unified 0-100 score/tier to a dashboard-shaped record and
    refresh the score module's own finding so the ring and the score card always
    agree — including for scans saved before the scoring fix."""
    if not isinstance(record, dict):
        return record
    modules = record.get("modules") or {}
    findings = record.get("findings") or []
    # Rebuild the {module: {..., findings}} mapping the scorer expects.
    results_map: dict[str, Any] = {}
    for name, mod in modules.items():
        if not isinstance(mod, dict):
            continue
        data = dict(mod.get("data") or {})
        data["findings"] = [f for f in findings if f.get("module") == name]
        results_map[name] = data

    score, raw, tier = _surface_score(results_map)
    if score is None:
        return record

    record["score"] = score
    record["raw_score"] = raw
    record["tier"] = tier
    # Keep the score module's finding title in sync with the recomputed value.
    for f in findings:
        if isinstance(f, dict) and f.get("module") == "score":
            f["title"] = f"Attack Surface Score: {score}/100 — {tier}"
    return record


def _read_record(path: Path) -> dict:
    """Read a scan file, normalizing CLI-format files to the dashboard shape and
    attaching the unified attack-surface score."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    record = _normalize_cli_record(raw, path) if _looks_like_cli_format(raw) else raw
    return _apply_surface_score(record)


# Valid scan ids are hex (dashboard) or CLI filename stems: letters, digits,
# '_' and '-' only. No dots (blocks ".."), no path separators. Used to build
# filenames under OUTPUT_DIR, so this is the gate against path traversal.
_SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _safe_scan_id(scan_id: str) -> str:
    """Reject any scan id that isn't a plain identifier, so a crafted id like
    '../../etc/passwd' can never escape OUTPUT_DIR when used as a filename."""
    if not isinstance(scan_id, str) or not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan id.")
    return scan_id


def _scan_file(scan_id: str) -> Path:
    """Resolve OUTPUT_DIR/<scan_id>.json, validated and confined to OUTPUT_DIR."""
    _safe_scan_id(scan_id)
    path = OUTPUT_DIR / f"{scan_id}.json"
    # Defense in depth: the resolved file must still live directly in OUTPUT_DIR.
    if path.resolve().parent != OUTPUT_DIR.resolve():
        raise HTTPException(400, "Invalid scan id.")
    return path


def _fetch(scan_id: str) -> dict:
    _safe_scan_id(scan_id)
    with _lock:
        if scan_id in _scans:
            return dict(_scans[scan_id])
    path = _scan_file(scan_id)
    if path.exists():
        data = _read_record(path)
        with _lock:
            _scans[scan_id] = data
        return data
    raise HTTPException(404, f"Scan '{scan_id}' not found")


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.post("/api/scan")
async def start_scan(req: ScanRequest) -> dict:
    scan_id = uuid.uuid4().hex[:10]
    now = datetime.now(timezone.utc).isoformat()

    with _lock:
        _scans[scan_id] = {
            "scan_id": scan_id,
            "target": req.target,
            "status": "queued",
            "active": req.active,
            "requested_modules": req.modules,
            "started_at": now,
            "finished_at": None,
            "total_modules": 0,
            "completed_modules": 0,
            "modules": {},
            "findings": [],
            "severity_counts": {},
        }
        _ws_queues[scan_id] = asyncio.Queue()

    asyncio.get_event_loop().run_in_executor(
        _executor, _run_scan, scan_id, req.target, req.active, req.modules, req.profile
    )

    return {"scan_id": scan_id, "target": req.target, "status": "queued", "started_at": now}


@app.get("/api/scan/{scan_id}/status")
async def get_status(scan_id: str) -> dict:
    s = _fetch(scan_id)
    return {
        "scan_id": scan_id,
        "status": s["status"],
        "target": s["target"],
        "total_modules": s.get("total_modules", 0),
        "completed_modules": s.get("completed_modules", 0),
        "modules": s.get("modules", {}),
        "severity_counts": s.get("severity_counts", {}),
        "finding_count": len(s.get("findings", [])),
        "started_at": s.get("started_at"),
        "finished_at": s.get("finished_at"),
        "active": s.get("active", False),
        "score": s.get("score"),
        "raw_score": s.get("raw_score"),
        "tier": s.get("tier"),
    }


@app.get("/api/scan/{scan_id}/results")
async def get_results(scan_id: str) -> dict:
    s = _fetch(scan_id)
    return {
        "scan_id": scan_id,
        "target": s["target"],
        "status": s["status"],
        "active": s.get("active", False),
        "started_at": s.get("started_at"),
        "finished_at": s.get("finished_at"),
        "findings": s.get("findings", []),
        "modules": s.get("modules", {}),
        "severity_counts": s.get("severity_counts", {}),
        "score": s.get("score"),
        "raw_score": s.get("raw_score"),
        "tier": s.get("tier"),
    }


@app.get("/api/scans")
async def list_scans() -> list:
    rows: list[dict] = []
    seen: set[str] = set()

    for path in sorted(OUTPUT_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            d = _read_record(path)
            sid = d.get("scan_id", path.stem)
            seen.add(sid)
            rows.append({
                "scan_id": sid,
                "target": d.get("target", ""),
                "status": d.get("status", ""),
                "active": d.get("active", False),
                "started_at": d.get("started_at", ""),
                "finished_at": d.get("finished_at"),
                "finding_count": len(d.get("findings", [])),
                "severity_counts": d.get("severity_counts", {}),
            })
        except Exception:
            pass

    with _lock:
        mem = dict(_scans)
    for sid, s in mem.items():
        if sid not in seen:
            rows.insert(0, {
                "scan_id": sid,
                "target": s.get("target", ""),
                "status": s.get("status", ""),
                "active": s.get("active", False),
                "started_at": s.get("started_at", ""),
                "finished_at": s.get("finished_at"),
                "finding_count": len(s.get("findings", [])),
                "severity_counts": s.get("severity_counts", {}),
            })

    return rows


@app.delete("/api/scans")
async def clear_scans() -> dict:
    """Clear ALL scan history: delete every scan file in the unified output dir
    (JSON + generated PDFs) and drop the in-memory cache. Used by the dashboard's
    "Clear History" button. This also removes CLI-produced scans, since the CLI
    and dashboard now share one history."""
    deleted = 0
    for pattern in ("*.json", "*.pdf"):
        for path in OUTPUT_DIR.glob(pattern):
            try:
                path.unlink()
                deleted += 1
            except OSError:
                pass
    with _lock:
        _scans.clear()
    return {"status": "cleared", "deleted_files": deleted}


@app.get("/api/export/{scan_id}/json")
async def export_json(scan_id: str):
    s = _fetch(scan_id)
    _persist(scan_id)
    path = OUTPUT_DIR / f"{scan_id}.json"
    return FileResponse(
        str(path),
        media_type="application/json",
        filename=f"bss-recon-{scan_id}-{s['target']}.json",
    )


@app.get("/api/export/{scan_id}/pdf")
async def export_pdf(scan_id: str):
    s = _fetch(scan_id)
    try:
        from bssrecon.reporting.pdf_report import generate_pdf_report  # type: ignore
    except ImportError:
        raise HTTPException(
            501,
            "PDF export requires the bssrecon package with ReportLab. "
            "Activate the bss-recon venv and install reportlab.",
        )

    config = {
        "reporting": {
            "company_name": "Burgohy Security Solutions",
            "analyst_name": "Emilio Burgohy",
            "report_dir": str(OUTPUT_DIR),
        }
    }
    all_results = []
    for mod_name, mod_data in s.get("modules", {}).items():
        if isinstance(mod_data, dict) and mod_data.get("status") == "done":
            r = dict(mod_data.get("data", {}))
            r["module"] = mod_name
            r["findings"] = [f for f in s.get("findings", []) if f.get("module") == mod_name]
            all_results.append(r)

    pdf_path = generate_pdf_report(
        s["target"], all_results, config,
        output_path=str(OUTPUT_DIR / f"{scan_id}.pdf"),
    )
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"bss-recon-{scan_id}-{s['target']}.pdf",
    )


@app.get("/api/compare/{id_a}/{id_b}")
async def compare_scans(id_a: str, id_b: str) -> dict:
    a = _fetch(id_a)
    b = _fetch(id_b)

    def _key(f: dict) -> str:
        return f"{f.get('severity','').lower()}|{f.get('title','').lower().strip()}"

    a_map = {_key(f): f for f in a.get("findings", [])}
    b_map = {_key(f): f for f in b.get("findings", [])}

    return {
        "scan_a": {
            "scan_id": id_a,
            "target": a["target"],
            "started_at": a.get("started_at"),
            "severity_counts": a.get("severity_counts", {}),
        },
        "scan_b": {
            "scan_id": id_b,
            "target": b["target"],
            "started_at": b.get("started_at"),
            "severity_counts": b.get("severity_counts", {}),
        },
        "new_in_b": [f for k, f in b_map.items() if k not in a_map],
        "resolved_in_b": [f for k, f in a_map.items() if k not in b_map],
        "common_count": len(set(a_map) & set(b_map)),
        "severity_delta": {
            s: b.get("severity_counts", {}).get(s, 0) - a.get("severity_counts", {}).get(s, 0)
            for s in ["critical", "high", "medium", "low", "info"]
        },
    }


# ---------------------------------------------------------------------------
# Compliance bridge — map a scan's attack-surface findings to GRC controls
# (NIST 800-53 / CIS / SOC 2) via the bss-bridge engine.
# ---------------------------------------------------------------------------

def _scan_path_for(scan_id: str) -> Path:
    path = _scan_file(scan_id)  # validates scan_id + confines to OUTPUT_DIR
    if not path.exists():
        raise HTTPException(404, f"Scan '{scan_id}' not found")
    return path


def _cli_shaped_scan(path: Path) -> dict:
    """Return the scan as a CLI-format dict ({module: {...}}), which the bridge
    engine expects. CLI scans are already this shape; dashboard-native records
    keep their module data under modules[name]['data'], so rebuild it."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "scan_id" in raw and "modules" in raw:
        out: dict[str, Any] = {"target": raw.get("target")}
        for name, mod in (raw.get("modules") or {}).items():
            if not isinstance(mod, dict):
                continue
            entry = dict(mod.get("data") or {})
            entry["findings"] = [f for f in raw.get("findings", []) if f.get("module") == name]
            out[name] = entry
        return out
    return raw


def _run_bridge(scan_id: str) -> dict:
    """Run bridge_scan() against a scan, adapting format as needed."""
    try:
        from bssrecon.control_bridge import bridge_scan  # type: ignore
    except ImportError:
        raise HTTPException(
            501,
            "Compliance bridge engine not installed (bssrecon.control_bridge). "
            "Activate the bss-recon venv so bssrecon is importable.",
        )
    path = _scan_path_for(scan_id)
    scan = _cli_shaped_scan(path)

    # bridge_scan() takes a file path; feed it the (possibly reshaped) scan via
    # a short-lived temp file so the original on-disk scan is never modified.
    import os
    import tempfile
    fd, tmp = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(scan, f, default=str)
        return bridge_scan(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


@app.get("/api/scan/{scan_id}/compliance")
async def compliance(scan_id: str) -> dict:
    """Map a scan's findings to NIST 800-53 / CIS / SOC 2 controls."""
    report = _run_bridge(scan_id)
    report["scan_id"] = scan_id
    return report


@app.get("/api/scan/{scan_id}/compliance/report")
async def compliance_report(scan_id: str):
    """Branded HTML 'Attack Surface Compliance Report' for download/print."""
    report = _run_bridge(scan_id)
    try:
        from bssrecon.bridge_report import render  # type: ignore
    except ImportError:
        raise HTTPException(501, "Compliance report renderer not installed.")
    return HTMLResponse(render(report))


@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()

    if scan_id not in _ws_queues:
        _ws_queues[scan_id] = asyncio.Queue()

    # If already done, send a snapshot and close
    try:
        s = _fetch(scan_id)
        if s.get("status") in ("complete", "error"):
            await websocket.send_json({
                "type": "complete",
                "finding_count": len(s.get("findings", [])),
                "severity_counts": s.get("severity_counts", {}),
                "finished_at": s.get("finished_at"),
                "modules": s.get("modules", {}),
            })
            await websocket.close()
            return
    except HTTPException:
        pass

    queue = _ws_queues[scan_id]
    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=25.0)
                await websocket.send_json(msg)
                if msg.get("type") == "complete":
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        _ws_queues.pop(scan_id, None)


@app.get("/")
async def root():
    frontend = Path(__file__).parent.parent / "frontend" / "index.html"
    if frontend.exists():
        return FileResponse(str(frontend))
    return JSONResponse({"message": "BSS Recon API running", "docs": "/docs"})


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
