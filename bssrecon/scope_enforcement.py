"""
Scope enforcement for modules that contact a target directly.

Every module that sends traffic AT the target (rather than querying a
third-party OSINT service about it) must pass through this gate before its
first packet. Enforcement is applied centrally by BaseModule.__init_subclass__
in bssrecon/core/__init__.py, so it cannot be forgotten when someone adds a new
module — the previous per-module approach only covered nuclei and left five
other active modules firing unchecked.

FAIL-CLOSED CONTRACT
    out-of-scope target      -> quarantine, log, no probe
    malformed scope file     -> quarantine (never degrade to "unenforced")
    configured file missing  -> quarantine (the operator asked for enforcement)
    no scope file configured -> ALLOW, but log loudly and flag the result
"""
from __future__ import annotations

import ipaddress
import sys


def _log(msg: str) -> None:
    print(f"[BSS Scope] {msg}", file=sys.stderr)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def quarantine_result(target: str, reason: str, module_name: str,
                      scope_path=None) -> dict:
    """Standard result for a target that FAILED the scope check.

    Shaped like every other module result (domain + findings) so the score,
    reports and dashboard consume it without special-casing.
    """
    _log(f"BLOCKED — {module_name} refusing to scan out-of-scope target "
         f"'{target}': {reason}")
    return {
        "domain": target,
        "module": module_name,
        "status": "QUARANTINED",
        "scanned": False,
        "scope_enforced": True,
        "scope_file": str(scope_path) if scope_path else None,
        "out_of_scope_reason": reason,
        "findings": [{
            "severity": "info",
            "title": f"{module_name} skipped — target out of scope",
            "detail": (
                f"Active module '{module_name}' was blocked by the engagement scope "
                f"guard before sending any traffic to '{target}'. Reason: {reason}"
            ),
            "owasp": "",
            "mitre": "",
            "remediation": (
                "If this target is genuinely in scope, add it to the scope file's "
                "allowed_domains (and allowed_cidrs if IP-restricted). Otherwise "
                "leave it blocked — scanning it may be unauthorised."
            ),
        }],
    }


def scope_gate(target: str, config: dict | None,
               module_name: str) -> tuple[bool, dict, dict | None]:
    """Check `target` against the engagement scope.

    Returns (allowed, scope_meta, blocked_result). When allowed is False the
    caller MUST return blocked_result and send nothing.
    """
    config = config or {}

    try:
        from bssrecon.scope_guard import load_guard, ScopeFileError
    except Exception as exc:
        reason = (f"Scope guard unavailable ({exc}); refusing to run an active "
                  f"module without scope enforcement")
        return False, {"scope_enforced": True}, quarantine_result(
            target, reason, module_name)

    try:
        guard, scope_path = load_guard(config)
    except ScopeFileError as exc:
        # Malformed, or explicitly configured but missing. Fail closed.
        return False, {"scope_enforced": True}, quarantine_result(
            target, str(exc), module_name)

    if guard is None:
        _log(f"WARNING: no scope file configured — '{module_name}' is contacting "
             f"'{target}' WITHOUT scope enforcement. Create scope.yaml (see "
             f"bssrecon/scope.example.yaml) before engagement work.")
        return True, {
            "scope_enforced": False,
            "scope_file": None,
            "scope_warning": (
                "Ran without scope enforcement — no scope file configured."
            ),
        }, None

    # A bare IP target can't match domain rules, so check it as an IP.
    # NOTE: ScopeGuard.check_ip intentionally allows any IP when no
    # allowed_cidrs are configured ("domain-only program"), so an IP target
    # under a domain-only scope file is permitted by design.
    if _is_ip(target):
        ok, reason = guard.check_ip(target)
    else:
        ok, reason = guard.check_target(target)

    if not ok:
        return False, {"scope_enforced": True}, quarantine_result(
            target, reason, module_name, scope_path)

    _log(f"scope OK for '{target}' via {module_name} ({guard.program_name})")
    return True, {
        "scope_enforced": True,
        "scope_file": str(scope_path),
        "scope_program": guard.program_name,
        "scope_reason": reason,
    }, None
