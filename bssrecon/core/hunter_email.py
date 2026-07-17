"""
Hunter.io Email Discovery Module

Finds email addresses associated with a target domain and
identifies the email pattern the organization uses.

Free tier: 25 searches/month.
API key: https://hunter.io/api-keys

Why this matters:
- Know the email format (first.last@, firstinitiallast@, etc)
- Discover employee email addresses for social engineering scope
- Identify key personnel and their roles
- Find leaked or publicly posted email addresses
"""
import requests
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_key_value,
    print_error,
    print_progress,
    print_table,
    print_warning,
    print_success,
)


@register_module
class HunterModule(BaseModule):
    name = "hunter"
    description = "Hunter.io email address discovery"
    requires_api_key = True
    api_key_name = "hunter_io"

    def run(self, target: str) -> dict:
        print_section("Email Discovery (Hunter.io)", "📧")

        api_key = self.get_api_key()
        if not api_key:
            print_warning(
                "[SKIP] Hunter.io module skipped — no API key configured in config.yaml "
                "(set 'hunter_io' in config.yaml or the BSS_HUNTER_KEY env var; "
                "free tier: https://hunter.io/api-keys)"
            )
            return {"domain": target, "skipped": True, "reason": "no_api_key", "findings": []}

        print_progress(f"Searching for email addresses at {target}")

        try:
            url = "https://api.hunter.io/v2/domain-search"
            params = {
                "domain": target,
                "api_key": api_key,
            }
            resp = requests.get(url, params=params, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json().get("data", {})

                # Domain info
                organization = data.get("organization", "N/A")
                email_count = data.get("emails", [])
                pattern = data.get("pattern", "N/A")
                disposable = data.get("disposable", False)
                webmail = data.get("webmail", False)

                print_key_value("Organization", organization)
                print_key_value("Email Pattern", pattern or "Unknown")
                print_key_value("Emails Found", len(email_count))
                print_key_value("Disposable", "Yes" if disposable else "No")
                print_key_value("Webmail", "Yes" if webmail else "No")

                # Display found emails
                emails = data.get("emails", [])
                if emails:
                    rows = []
                    for email_info in emails[:20]:
                        email = email_info.get("value", "")
                        first = email_info.get("first_name", "")
                        last = email_info.get("last_name", "")
                        position = email_info.get("position", "")
                        confidence = email_info.get("confidence", 0)
                        name = f"{first} {last}".strip()

                        rows.append((
                            email,
                            name,
                            position or "N/A",
                            f"{confidence}%",
                        ))

                    print_table(
                        f"Email Addresses ({len(emails)} found)",
                        [
                            ("Email", "cyan"),
                            ("Name", "white"),
                            ("Position", "dim"),
                            ("Confidence", "yellow"),
                        ],
                        rows,
                    )

                    if len(emails) > 20:
                        print_key_value(
                            "Note",
                            f"Showing 20 of {len(emails)} total emails",
                        )

                # Format for report
                email_list = []
                for e in emails:
                    email_list.append({
                        "email": e.get("value", ""),
                        "first_name": e.get("first_name", ""),
                        "last_name": e.get("last_name", ""),
                        "position": e.get("position", ""),
                        "confidence": e.get("confidence", 0),
                        "sources_count": len(e.get("sources", [])),
                    })

                results = {
                    "domain": target,
                    "organization": organization,
                    "email_pattern": pattern,
                    "emails_found": len(email_list),
                    "emails": email_list,
                    "disposable": disposable,
                    "webmail": webmail,
                    "findings": [],
                }

                return results

            elif resp.status_code == 401:
                print_error("Invalid Hunter.io API key")
                return {"error": "Invalid API key", "domain": target}
            elif resp.status_code == 429:
                print_warning("Hunter.io rate limit reached.")
                return {"error": "Rate limited", "domain": target}
            else:
                print_error(f"Hunter.io returned status {resp.status_code}")
                return {"error": f"HTTP {resp.status_code}", "domain": target}

        except requests.exceptions.Timeout:
            print_error("Hunter.io request timed out")
            return {"error": "Timeout", "domain": target}
        except Exception as e:
            print_error(f"Hunter.io lookup failed: {str(e)}")
            return {"error": str(e), "domain": target}
