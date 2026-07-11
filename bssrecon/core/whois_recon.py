"""
WHOIS Recon Module
Queries WHOIS servers for domain registration data.
No API key required - talks directly to WHOIS servers.
"""
import whois
from datetime import datetime
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import print_section, print_whois_results, print_error


@register_module
class WhoisModule(BaseModule):
    name = "whois"
    description = "WHOIS domain registration lookup"
    requires_api_key = False

    def run(self, target: str) -> dict:
        print_section("WHOIS Lookup", "📋")

        try:
            w = whois.whois(target)

            # Normalize dates to strings
            def format_date(d):
                if isinstance(d, list):
                    d = d[0]
                if isinstance(d, datetime):
                    return d.strftime("%Y-%m-%d")
                return str(d) if d else "N/A"

            # Normalize list fields
            def format_list(val):
                if isinstance(val, list):
                    return [str(v) for v in val]
                return [str(val)] if val else []

            results = {
                "domain": target,
                "registrar": str(w.registrar) if w.registrar else "N/A",
                "creation_date": format_date(w.creation_date),
                "updated_date": format_date(w.updated_date),
                "expiration_date": format_date(w.expiration_date),
                "name_servers": format_list(w.name_servers),
                "status": format_list(w.status),
                "org": str(w.org) if w.org else "N/A",
                "country": str(w.country) if w.country else "N/A",
                "state": str(w.state) if w.state else "N/A",
                "dnssec": str(w.dnssec) if hasattr(w, "dnssec") and w.dnssec else "N/A",
                "emails": format_list(w.emails) if hasattr(w, "emails") else [],
            }

            # Calculate domain age
            if w.creation_date:
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                if isinstance(created, datetime):
                    # Strip timezone info to avoid naive vs aware mismatch
                    created_naive = created.replace(tzinfo=None)
                    age_days = (datetime.now() - created_naive).days
                    results["domain_age_days"] = age_days
                    results["domain_age_years"] = round(age_days / 365.25, 1)

            # Calculate days until expiration
            if w.expiration_date:
                exp = w.expiration_date
                if isinstance(exp, list):
                    exp = exp[0]
                if isinstance(exp, datetime):
                    exp_naive = exp.replace(tzinfo=None)
                    days_left = (exp_naive - datetime.now()).days
                    results["days_until_expiry"] = days_left

            print_whois_results(results)
            return results

        except Exception as e:
            error_msg = f"WHOIS lookup failed: {str(e)}"
            print_error(error_msg)
            return {"error": error_msg, "domain": target}
