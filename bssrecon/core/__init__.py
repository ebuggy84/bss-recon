"""
Core recon modules.
Every module inherits from BaseModule and registers itself automatically.
To add a new module: create a file, subclass BaseModule, done.

MODES:
  passive  = queries public databases and third-party services only.
             Never touches the target's servers. No permission needed.
  active   = makes direct requests to the target's servers.
             Requires authorization (bug bounty scope, signed engagement, or your own domain).
"""
from abc import ABC, abstractmethod


class BaseModule(ABC):
    """Base class for all recon modules."""

    name = "base"
    description = "Base module"
    # Set to True if this module needs an API key
    requires_api_key = False
    api_key_name = None
    # "passive" = no direct contact with target servers
    # "active"  = makes requests to target servers (needs permission)
    mode = "passive"

    def __init__(self, config=None):
        self.config = config or {}
        self.timeout = self.config.get("scan", {}).get("timeout", 10)
        self.rate_limit = self.config.get("scan", {}).get("rate_limit", 1.0)

    def get_api_key(self):
        """Get the API key for this module from config."""
        if not self.api_key_name:
            return None
        return self.config.get("api_keys", {}).get(self.api_key_name, "")

    def is_available(self):
        """Check if this module can run (has required API keys, etc)."""
        if self.requires_api_key:
            key = self.get_api_key()
            return bool(key)
        return True

    @abstractmethod
    def run(self, target: str) -> dict:
        """
        Run the module against a target domain.
        Returns a dict with results. Must include 'error' key if failed.
        """
        pass

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.name}>"


# Module registry - maps module names to their classes
MODULE_REGISTRY = {}


def register_module(cls):
    """Decorator to register a module class."""
    MODULE_REGISTRY[cls.name] = cls
    return cls


def get_module(name):
    """Get a module class by name."""
    return MODULE_REGISTRY.get(name)


def list_modules():
    """List all registered modules."""
    return dict(MODULE_REGISTRY)


# Import all modules so they register themselves
from bssrecon.core.whois_recon import WhoisModule
from bssrecon.core.dns_recon import DnsModule
from bssrecon.core.subdomain_enum import SubdomainModule
from bssrecon.core.ssl_analyzer import SslModule
from bssrecon.core.shodan_recon import ShodanModule
from bssrecon.core.headers_analyzer import HeadersModule
from bssrecon.core.tech_detect import TechDetectModule
from bssrecon.core.web_probe import WebProbeModule
from bssrecon.core.dork_generator import DorkGenModule
from bssrecon.core.virustotal_module import VirusTotalModule
from bssrecon.core.hunter_email import HunterModule
from bssrecon.core.js_analyzer import JsAnalyzerModule
from bssrecon.core.diff_tracker import DiffModule

from bssrecon.core.waf_detect import WafDetect
from bssrecon.core.target_score import TargetScore
from bssrecon.core.nuclei_scan import NucleiScan
from bssrecon.core.nmap_scan import NmapScan
from bssrecon.core.wayback_module import WaybackModule
from bssrecon.core.submutate_module import SubMutateModule
