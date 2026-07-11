#!/usr/bin/env python3
"""
Patch script for ~/bss-recon/bss-dashboard/backend/main.py

THE BUG: _load_registry() returns MODULE_REGISTRY which contains CLASSES,
but _run_scan() calls mod.run(target) expecting INSTANCES with config loaded.
cli.py does it right: cls(config) first, then .run(). main.py skips instantiation.

This script patches main.py in-place with a backup.

Run from Kali:
    cd ~/bss-recon
    python3 patches/fix_main_py.py
"""
import shutil
from pathlib import Path

MAIN_PY = Path.home() / "bss-recon" / "bss-dashboard" / "backend" / "main.py"

# --- The broken code ---
OLD_LOAD_REGISTRY = '''def _load_registry() -> dict[str, Any]:
    try:
        from bssrecon.core import MODULE_REGISTRY  # type: ignore
        return dict(MODULE_REGISTRY)
    except ImportError:
        return _build_stubs()'''

# --- The fixed code ---
NEW_LOAD_REGISTRY = '''def _load_registry() -> dict[str, Any]:
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
        return _build_stubs()'''


def main():
    if not MAIN_PY.exists():
        print(f"ERROR: {MAIN_PY} not found")
        return

    content = MAIN_PY.read_text()

    if OLD_LOAD_REGISTRY not in content:
        # Check if already patched
        if "load_config" in content and "cls(config)" in content:
            print("Already patched! main.py already has the fix.")
            return
        print("ERROR: Could not find the exact code block to replace.")
        print("The _load_registry function may have been modified manually.")
        return

    # Backup
    backup = MAIN_PY.with_suffix(".py.bak")
    shutil.copy2(MAIN_PY, backup)
    print(f"Backup saved: {backup}")

    # Patch
    new_content = content.replace(OLD_LOAD_REGISTRY, NEW_LOAD_REGISTRY)
    MAIN_PY.write_text(new_content)
    print(f"PATCHED: {MAIN_PY}")
    print("")
    print("What changed:")
    print("  - _load_registry() now imports load_config() from bssrecon.config")
    print("  - Each module CLASS is instantiated with config: cls(config)")
    print("  - Instances are returned (have .run(), .mode, .description)")
    print("  - Errors per-module are caught and logged to stderr")
    print("  - Falls back to stubs only if bssrecon can't be imported at all")
    print("")
    print("Restart uvicorn to pick up the change:")
    print("  pkill -f uvicorn; cd ~/bss-recon/bss-dashboard/backend && uvicorn main:app --host 0.0.0.0 --port 8000 &")


if __name__ == "__main__":
    main()
