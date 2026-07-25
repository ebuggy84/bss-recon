"""
Config loader for BSS Recon.
Reads config.yaml and provides settings to all modules.
"""
import os
import yaml
from pathlib import Path


DEFAULT_CONFIG = {
    "api_keys": {},
    "scan": {
        "timeout": 10,
        "max_subdomains": 500,
        "user_agent": "BSS-Recon/1.0 (Security Assessment)",
        "rate_limit": 1.0,
    },
    "reporting": {
        "company_name": "Burgohy Security Solutions",
        "analyst_name": "Emilio Burgohy",
        "report_dir": "./reports",
        "logo_path": "",
    },
    "output": {
        "save_json": True,
        "output_dir": "./output",
    },
    "default_modules": ["whois", "dns", "subdomains", "ssl"],
}


def find_config():
    """Look for config.yaml in common locations."""
    search_paths = [
        Path.cwd() / "config.yaml",
        Path.home() / ".bssrecon" / "config.yaml",
        Path(__file__).parent.parent / "config.yaml",
    ]
    for path in search_paths:
        if path.exists():
            return path
    return None


def load_config(config_path=None):
    """Load config from YAML file, falling back to defaults."""
    config = DEFAULT_CONFIG.copy()

    if config_path:
        path = Path(config_path)
    else:
        path = find_config()

    if path and path.exists():
        with open(path, "r") as f:
            user_config = yaml.safe_load(f) or {}
        # Merge user config over defaults
        for key, value in user_config.items():
            if isinstance(value, dict) and key in config:
                config[key].update(value)
            else:
                config[key] = value

    # Allow environment variables to override API keys
    # e.g. BSS_SHODAN_KEY overrides config.yaml
    env_keys = {
        "BSS_SHODAN_KEY": "shodan",
        "BSS_VT_KEY": "virustotal",
        "BSS_ST_KEY": "securitytrails",
        "BSS_HUNTER_KEY": "hunter_io",
        "BSS_ANTHROPIC_KEY": "anthropic",
    }
    for env_var, key_name in env_keys.items():
        env_value = os.environ.get(env_var)
        if env_value:
            config["api_keys"][key_name] = env_value

    return config


def get_api_key(config, service):
    """Get an API key, returning None if empty or missing."""
    key = config.get("api_keys", {}).get(service, "")
    return key if key else None


# Repo root = the directory containing the bssrecon package (one level up from
# this file). Used to anchor relative output paths so the CLI and the dashboard
# resolve to the SAME directory regardless of the process working directory.
REPO_ROOT = Path(__file__).resolve().parent.parent


def get_output_dir(config, create=True):
    """Return the unified scan-output directory as an absolute Path.

    Both the CLI and the web dashboard call this so a scan written by one is
    visible to the other. The location comes from config['output']['output_dir']
    (default './output'). Relative paths are resolved against the repo root
    (REPO_ROOT), NOT the current working directory — otherwise the dashboard
    (started with a different CWD) would land in a different folder than the CLI
    and the two histories would drift apart again.
    """
    raw = (config or {}).get("output", {}).get("output_dir", "./output")
    path = Path(raw)
    if not path.is_absolute():
        path = (REPO_ROOT / path).resolve()
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path
