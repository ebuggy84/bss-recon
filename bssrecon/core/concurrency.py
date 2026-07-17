"""
Scan concurrency profiles and rate-limiting controller.

A ScanProfile selects how aggressively active modules probe a target:

  STEALTH     semaphore  5,  0.5s  delay  — quiet; preserves target bandwidth,
                                            avoids tripping IDS/WAF/rate limiters
  BALANCED    semaphore 25,  0.05s delay  — sensible default
  AGGRESSIVE  semaphore 150, no    delay  — fast; authorized/owned targets only

The default is always BALANCED. AGGRESSIVE must be an explicit opt-in.

The ConcurrencyController wraps async task execution with a shared semaphore and
a per-operation delay, and also exposes tool-flag hints so subprocess-based
modules (nmap, nuclei) and synchronous request loops (web_probe) honour the
selected profile.
"""

from __future__ import annotations

import asyncio
import time
from enum import Enum


class ScanProfile(Enum):
    STEALTH = "stealth"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


# Per-profile concurrency limit (semaphore) and inter-operation delay (seconds).
_PROFILE_SETTINGS = {
    ScanProfile.STEALTH:    {"semaphore": 5,   "delay": 0.5},
    ScanProfile.BALANCED:   {"semaphore": 25,  "delay": 0.05},
    ScanProfile.AGGRESSIVE: {"semaphore": 150, "delay": 0.0},
}

# The one and only default. Never AGGRESSIVE.
DEFAULT_PROFILE = ScanProfile.BALANCED


def get_profile(value) -> ScanProfile:
    """
    Resolve a profile from a string / enum / None. Unknown or missing values
    fall back to the safe default (BALANCED) — never AGGRESSIVE.
    """
    if isinstance(value, ScanProfile):
        return value
    if not value:
        return DEFAULT_PROFILE
    try:
        return ScanProfile(str(value).strip().lower())
    except ValueError:
        return DEFAULT_PROFILE


class _Slot:
    """Async context manager: hold a semaphore slot, then delay on release."""

    def __init__(self, controller: "ConcurrencyController"):
        self._c = controller

    async def __aenter__(self):
        await self._c.semaphore().acquire()
        return self

    async def __aexit__(self, *exc):
        try:
            if self._c.delay:
                await asyncio.sleep(self._c.delay)
        finally:
            self._c.semaphore().release()
        return False


class ConcurrencyController:
    """Governs how many operations run at once and how they are paced."""

    def __init__(self, profile=DEFAULT_PROFILE):
        self.profile = get_profile(profile)
        settings = _PROFILE_SETTINGS[self.profile]
        self.limit: int = settings["semaphore"]
        self.delay: float = settings["delay"]
        self._sem: asyncio.Semaphore | None = None

    # ── Async pacing ─────────────────────────────────────────────────────
    def semaphore(self) -> asyncio.Semaphore:
        """Lazily create the semaphore inside the running event loop."""
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.limit)
        return self._sem

    def slot(self) -> _Slot:
        """`async with controller.slot(): ...` — bounded + paced execution."""
        return _Slot(self)

    async def run(self, coro):
        """Run a coroutine under the semaphore + delay."""
        async with self.slot():
            return await coro

    # ── Synchronous pacing (for request loops like web_probe) ────────────
    def throttle_sync(self) -> None:
        """Sleep the per-operation delay (no-op for AGGRESSIVE)."""
        if self.delay:
            time.sleep(self.delay)

    # ── Subprocess tool flag hints (nmap / nuclei) ───────────────────────
    def nmap_flags(self) -> list[str]:
        """Timing template + packet-rate bounds matching the profile."""
        return {
            ScanProfile.STEALTH:    ["-T2", "--max-rate", "50"],
            ScanProfile.BALANCED:   ["-T3", "--max-rate", "500"],
            ScanProfile.AGGRESSIVE: ["-T4", "--min-rate", "1000"],
        }[self.profile]

    def nuclei_flags(self) -> list[str]:
        """Concurrency (-c) + rate-limit (-rl, req/sec) matching the profile."""
        return {
            ScanProfile.STEALTH:    ["-c", "5",   "-rl", "20"],
            ScanProfile.BALANCED:   ["-c", "25",  "-rl", "150"],
            ScanProfile.AGGRESSIVE: ["-c", "150", "-rl", "1000"],
        }[self.profile]

    def __repr__(self):
        return f"<ConcurrencyController {self.profile.value} sem={self.limit} delay={self.delay}>"


def controller_from_config(config) -> ConcurrencyController:
    """Build a controller from a config dict's scan.profile (safe default)."""
    profile = (config or {}).get("scan", {}).get("profile")
    return ConcurrencyController(get_profile(profile))
