"""
BSS Recon - Scope Enforcement Guardrail
-----------------------------------------
Purpose: Prevent active modules from touching out-of-scope assets during
bug bounty / client engagements. Loads a per-engagement scope file
(domains + optional CIDR ranges) and validates every target/resolved IP
before any active (packet-firing) module runs.

Usage:
    from scope_guard import ScopeGuard

    guard = ScopeGuard.load("scope.yaml")  # or pass a dict directly

    ok, reason = guard.check_domain("sub.example.com")
    if not ok:
        # quarantine — do not scan
        ...

    ok, reason = guard.check_ip("1.2.3.4")
"""

from __future__ import annotations
import ipaddress
import re
import socket
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ScopeGuard:
    allowed_domains: list[str] = field(default_factory=list)   # exact or wildcard, e.g. "*.example.com"
    allowed_cidrs: list[str] = field(default_factory=list)      # e.g. "203.0.113.0/24"
    denied_domains: list[str] = field(default_factory=list)     # explicit out-of-scope, takes priority
    denied_cidrs: list[str] = field(default_factory=list)
    program_name: str = "unnamed-engagement"
    quarantine_log: list[dict] = field(default_factory=list)

    # ---------- loading ----------

    @classmethod
    def load(cls, path: str) -> "ScopeGuard":
        """
        Load scope from a YAML file. Expected format:

        program_name: "Wolt Bug Bounty"
        allowed_domains:
          - "wolt.com"
          - "*.wolt.com"
        allowed_cidrs:
          - "203.0.113.0/24"
        denied_domains:
          - "partner-saas.wolt.com"   # explicitly out of scope even though it matches wildcard
        denied_cidrs: []
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"Scope file not found: {path}\n"
                f"Create one before running active modules. See scope.example.yaml."
            )
        data = yaml.safe_load(p.read_text()) or {}
        return cls(
            allowed_domains=data.get("allowed_domains", []),
            allowed_cidrs=data.get("allowed_cidrs", []),
            denied_domains=data.get("denied_domains", []),
            denied_cidrs=data.get("denied_cidrs", []),
            program_name=data.get("program_name", "unnamed-engagement"),
        )

    # ---------- domain matching ----------

    @staticmethod
    def _domain_matches(pattern: str, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            base = pattern[2:]
            return domain == base or domain.endswith("." + base)
        return domain == pattern

    def check_domain(self, domain: str) -> tuple[bool, str]:
        domain = domain.lower().strip()

        # denied list always wins, even if it also matches an allowed wildcard
        for pat in self.denied_domains:
            if self._domain_matches(pat, domain):
                reason = f"Explicitly denied by scope rule '{pat}'"
                self._quarantine(domain, reason)
                return False, reason

        for pat in self.allowed_domains:
            if self._domain_matches(pat, domain):
                return True, f"Matches allowed rule '{pat}'"

        reason = f"'{domain}' does not match any allowed_domains rule for {self.program_name}"
        self._quarantine(domain, reason)
        return False, reason

    # ---------- IP matching ----------

    def check_ip(self, ip: str) -> tuple[bool, str]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            reason = f"'{ip}' is not a valid IP address"
            self._quarantine(ip, reason)
            return False, reason

        for cidr in self.denied_cidrs:
            if addr in ipaddress.ip_network(cidr, strict=False):
                reason = f"IP {ip} explicitly denied by CIDR rule '{cidr}'"
                self._quarantine(ip, reason)
                return False, reason

        for cidr in self.allowed_cidrs:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True, f"IP {ip} matches allowed CIDR '{cidr}'"

        if not self.allowed_cidrs:
            # No CIDR restrictions configured — IP scope isn't enforced,
            # only domain scope is. That's a valid config for domain-only programs.
            return True, "No allowed_cidrs configured; IP scope not enforced"

        reason = f"IP {ip} does not match any allowed_cidrs rule for {self.program_name}"
        self._quarantine(ip, reason)
        return False, reason

    # ---------- combined check used by active modules ----------

    def check_target(self, domain: str) -> tuple[bool, str]:
        """
        Full check for an active module about to fire packets at `domain`.
        Validates the domain pattern AND resolves it to confirm the IP
        is also in scope (catches CNAME-to-third-party-SaaS cases).
        """
        ok, reason = self.check_domain(domain)
        if not ok:
            return False, reason

        try:
            resolved_ip = socket.gethostbyname(domain)
        except socket.gaierror:
            # can't resolve — let domain-level scope decision stand
            return True, reason

        ip_ok, ip_reason = self.check_ip(resolved_ip)
        if not ip_ok:
            combined = f"Domain '{domain}' resolves to {resolved_ip}, which is OUT OF SCOPE: {ip_reason}"
            self._quarantine(domain, combined)
            return False, combined

        return True, f"{reason}; resolves to in-scope IP {resolved_ip}"

    # ---------- quarantine tracking ----------

    def _quarantine(self, target: str, reason: str):
        self.quarantine_log.append({"target": target, "reason": reason})

    def get_quarantine_report(self) -> list[dict]:
        return self.quarantine_log


class ScopeFileError(Exception):
    """Raised when a scope file exists but cannot be parsed.

    Callers of active modules MUST treat this as fail-closed (refuse to scan).
    A malformed scope file must never be silently downgraded to "no scope
    enforcement" — that would let packets fly at unvetted targets.
    """


def _repo_root() -> Optional[Path]:
    try:
        from bssrecon.config import REPO_ROOT
        return REPO_ROOT
    except Exception:
        return None


def find_scope_file(config: Optional[dict] = None) -> Optional[Path]:
    """Locate the engagement scope file.

    config['scope']['file'] wins and is used ALONE — if an operator names a
    scope file, silently falling back to a different one would be dangerous.
    A RELATIVE configured path is resolved against the repo root (not the
    process CWD), because the CLI, dashboard and cron all run with different
    working directories and a missed scope file silently degrades to
    "unenforced" scanning.

    Raises ScopeFileError if an explicitly configured file does not exist —
    the operator asked for enforcement, so we fail closed rather than scan
    unenforced. Returns None only when NO scope file is configured at all.
    """
    explicit = ((config or {}).get("scope", {}) or {}).get("file")
    if explicit:
        p = Path(explicit)
        if not p.is_absolute():
            root = _repo_root()
            candidates = [p, (root / p) if root else None]
        else:
            candidates = [p]
        for c in candidates:
            if c is not None and c.exists():
                return c
        raise ScopeFileError(
            f"Configured scope file '{explicit}' does not exist. Refusing to run "
            f"active modules unenforced — create it or clear config scope.file."
        )

    root = _repo_root()
    candidates = [root / "scope.yaml"] if root else []
    candidates.append(Path.cwd() / "scope.yaml")
    for c in candidates:
        if c.exists():
            return c
    return None


def load_guard(config: Optional[dict] = None) -> tuple[Optional["ScopeGuard"], Optional[Path]]:
    """Return (guard, path) for the configured scope file, or (None, None) if
    no scope file is configured. Raises ScopeFileError if a scope file exists
    but is unreadable/malformed, so callers can fail closed.
    """
    path = find_scope_file(config)
    if path is None:
        return None, None
    try:
        return ScopeGuard.load(str(path)), path
    except Exception as exc:
        raise ScopeFileError(f"Could not parse scope file {path}: {exc}") from exc


def require_scope(guard: ScopeGuard):
    """
    Decorator for active-module scan functions. Wraps the function so it
    refuses to run against an out-of-scope target and instead returns a
    quarantine record.

    Usage:
        guard = ScopeGuard.load("scope.yaml")

        @require_scope(guard)
        def webprobe_scan(target, config):
            ...
    """
    def decorator(func):
        def wrapper(target, *args, **kwargs):
            ok, reason = guard.check_target(target)
            if not ok:
                return {
                    "module": func.__name__,
                    "target": target,
                    "status": "QUARANTINED",
                    "out_of_scope_reason": reason,
                }
            return func(target, *args, **kwargs)
        return wrapper
    return decorator
