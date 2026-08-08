"""
CISA KEV (Known Exploited Vulnerabilities) integration for BSS Recon.

Cross-references CVEs discovered in a scan against CISA's catalog of
actively-exploited vulnerabilities and escalates any match to critical.

Data source (free, no API key):
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The catalog is cached locally (cache/kev_catalog.json) and only re-downloaded
once it is older than the configured max age (default 24h), so a scan never
hammers CISA. If the download fails we fall back to the cached copy and keep
going — a network hiccup must never break a scan.
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from pathlib import Path

from bssrecon.config import REPO_ROOT

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_CACHE_PATH = REPO_ROOT / "cache" / "kev_catalog.json"
DEFAULT_MAX_AGE_HOURS = 24
FETCH_TIMEOUT = 20

# CVE ids appear in finding titles/details in mixed case and spacing; match them
# loosely and normalise to the canonical upper-case form.
_CVE_RE = re.compile(r"CVE[-\s]?(\d{4})[-\s]?(\d{4,7})", re.IGNORECASE)
_KEV_TAG = "ACTIVELY EXPLOITED (CISA KEV)"


def _log(msg: str) -> None:
    print(f"[BSS KEV] {msg}", file=sys.stderr)


def normalize_cve(value) -> str | None:
    """Return the canonical CVE id (CVE-YYYY-NNNN) found in `value`, or None."""
    if not value:
        return None
    m = _CVE_RE.search(str(value))
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2)}"


def _ransomware_flag(entry: dict) -> bool:
    return str(entry.get("knownRansomwareCampaignUse", "")).strip().lower() in (
        "known", "yes", "true",
    )


class KevCatalog:
    """Loads (and caches) the CISA KEV catalog and indexes it by CVE id."""

    def __init__(self, config: dict | None = None, max_age_hours: float | None = None,
                 cache_path: Path | None = None):
        cfg = (config or {}).get("kev", {}) if config else {}
        if max_age_hours is None:
            max_age_hours = cfg.get("max_age_hours", DEFAULT_MAX_AGE_HOURS)
        self.max_age = float(max_age_hours) * 3600
        self.cache_path = Path(cache_path or cfg.get("cache_path") or DEFAULT_CACHE_PATH)
        self._index: dict[str, dict] | None = None

    # -- catalog acquisition ------------------------------------------------

    def _fetch(self) -> dict:
        req = urllib.request.Request(
            KEV_URL, headers={"User-Agent": "BSS-Recon/1.0 (Security Assessment)"}
        )
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _read_cache(self) -> dict | None:
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _cache_is_fresh(self) -> bool:
        try:
            age = time.time() - self.cache_path.stat().st_mtime
            return age < self.max_age
        except OSError:
            return False

    def catalog(self) -> dict:
        """Return the KEV catalog dict, using a fresh cache when available,
        otherwise fetching (and refreshing the cache), otherwise a stale cache,
        otherwise an empty catalog. Never raises for network reasons."""
        if self._cache_is_fresh():
            cached = self._read_cache()
            if cached is not None:
                return cached

        try:
            data = self._fetch()
            try:
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.cache_path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(data), encoding="utf-8")
                tmp.replace(self.cache_path)
            except Exception as exc:  # caching is best-effort
                _log(f"could not write cache: {exc}")
            count = len(data.get("vulnerabilities", []))
            _log(f"fetched KEV catalog: {count} known-exploited CVEs")
            return data
        except Exception as exc:
            stale = self._read_cache()
            if stale is not None:
                _log(f"fetch failed ({exc}); using cached catalog")
                return stale
            _log(f"fetch failed ({exc}) and no cache available; KEV check skipped")
            return {"vulnerabilities": []}

    def index(self) -> dict[str, dict]:
        """CVE id -> KEV entry, built once per instance."""
        if self._index is None:
            idx: dict[str, dict] = {}
            for entry in self.catalog().get("vulnerabilities", []):
                cid = normalize_cve(entry.get("cveID"))
                if cid:
                    idx[cid] = entry
            self._index = idx
        return self._index  # NOT `idx` — that's undefined on cached (2nd+) calls

    # -- lookups ------------------------------------------------------------

    def check(self, cve_ids) -> dict[str, dict]:
        """Given an iterable of CVE ids, return {CVE: metadata} for KEV matches."""
        idx = self.index()
        out: dict[str, dict] = {}
        for raw in cve_ids or []:
            cid = normalize_cve(raw)
            if cid and cid in idx and cid not in out:
                e = idx[cid]
                out[cid] = {
                    "cveID": cid,
                    "vulnerabilityName": e.get("vulnerabilityName"),
                    "vendorProject": e.get("vendorProject"),
                    "product": e.get("product"),
                    "dateAdded": e.get("dateAdded"),
                    "requiredAction": e.get("requiredAction"),
                    "dueDate": e.get("dueDate"),
                    "shortDescription": e.get("shortDescription"),
                    "ransomware": _ransomware_flag(e),
                }
        return out


def finding_cve(finding: dict) -> str | None:
    """Extract a CVE id from a finding dict (title, explicit cve field, detail)."""
    if not isinstance(finding, dict):
        return None
    for key in ("cve", "cve_id", "cveID", "title", "name", "detail"):
        cid = normalize_cve(finding.get(key))
        if cid:
            return cid
    return None


def escalate_findings(findings: list[dict], config: dict | None = None,
                      catalog: KevCatalog | None = None) -> list[dict]:
    """Escalate every finding whose CVE is on the KEV list, in place.

    A matched finding is bumped to critical severity, tagged as actively
    exploited, and annotated with the KEV metadata (date added, required action,
    due date, ransomware flag). Idempotent: findings already flagged are skipped.
    Returns the list of match records (one per escalated finding).
    """
    if config is not None and not (config.get("kev", {}) or {}).get("enabled", True):
        return []
    if not findings:
        return []

    cat = catalog or KevCatalog(config)
    cve_ids = [c for c in (finding_cve(f) for f in findings) if c]
    if not cve_ids:
        return []

    matches = cat.check(cve_ids)
    if not matches:
        return []

    escalated: list[dict] = []
    for f in findings:
        if not isinstance(f, dict) or f.get("kev"):
            continue
        cid = finding_cve(f)
        if not cid or cid not in matches:
            continue
        m = matches[cid]
        f["severity"] = "critical"
        f["kev"] = True
        f["kev_ransomware"] = m["ransomware"]
        f["kev_date_added"] = m.get("dateAdded")
        f["kev_due_date"] = m.get("dueDate")
        f["kev_required_action"] = m.get("requiredAction")
        f["kev_vulnerability_name"] = m.get("vulnerabilityName")
        if _KEV_TAG not in (f.get("title") or ""):
            f["title"] = f"{f.get('title', cid)} — {_KEV_TAG}"
        note = "This CVE is on the CISA Known Exploited Vulnerabilities catalog"
        note += " and is linked to ransomware campaigns." if m["ransomware"] else "."
        f["detail"] = (f.get("detail", "") + f" [{note}]").strip()
        escalated.append(m)
    if escalated:
        rw = sum(1 for m in escalated if m["ransomware"])
        _log(f"escalated {len(escalated)} actively-exploited CVE(s) to critical"
             + (f" ({rw} ransomware-linked)" if rw else ""))
    return escalated


def escalate_results(results: dict, config: dict | None = None,
                     catalog: KevCatalog | None = None) -> list[dict]:
    """Run KEV escalation across every module's findings in a scan results dict
    ({module_name: {..., 'findings': [...]}}). Returns all match records. A
    shared `catalog` can be passed to avoid rebuilding the index per call."""
    if not isinstance(results, dict):
        return []
    cat = catalog or KevCatalog(config)
    escalated: list[dict] = []
    for data in results.values():
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            escalated.extend(escalate_findings(data["findings"], config, catalog=cat))
    return escalated


if __name__ == "__main__":
    # Quick manual check: python -m bssrecon.kev_check CVE-2021-44228 CVE-2014-0160
    cat = KevCatalog()
    hits = cat.check(sys.argv[1:])
    print(json.dumps(hits, indent=2))
