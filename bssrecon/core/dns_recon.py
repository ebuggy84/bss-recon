"""
DNS Recon Module
Enumerates DNS records for a target domain.
No API key required - queries DNS servers directly via dnspython.
"""
import dns.resolver
import dns.reversename
import socket
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import print_section, print_dns_results, print_key_value, print_error, print_warning, print_finding


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR"]


@register_module
class DnsModule(BaseModule):
    name = "dns"
    description = "DNS record enumeration"
    requires_api_key = False

    def run(self, target: str) -> dict:
        print_section("DNS Enumeration", "🌐")

        records = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(target, rtype)
                for rdata in answers:
                    record = {
                        "type": rtype,
                        "value": str(rdata),
                        "ttl": answers.rrset.ttl,
                    }
                    records.append(record)
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                print_error(f"Domain {target} does not exist (NXDOMAIN)")
                return {"error": f"NXDOMAIN: {target}", "records": []}
            except dns.resolver.Timeout:
                print_warning(f"Timeout querying {rtype} records")
                continue
            except dns.resolver.NoNameservers:
                print_warning(f"No nameservers available for {rtype}")
                continue
            except Exception:
                continue

        # Resolve IP addresses for the domain
        ip_addresses = []
        for record in records:
            if record["type"] == "A":
                ip_addresses.append(record["value"])

        # Try reverse DNS on discovered IPs
        reverse_dns = {}
        for ip in ip_addresses:
            try:
                hostname = socket.gethostbyaddr(ip)
                reverse_dns[ip] = hostname[0]
            except (socket.herror, socket.gaierror, OSError):
                reverse_dns[ip] = "No PTR record"

        # Check for zone transfer possibility (informational)
        zone_transfer_possible = False
        ns_records = [r["value"] for r in records if r["type"] == "NS"]
        # Note: we don't actually attempt zone transfers as that's active
        # Just flag that NS records were found for manual follow-up

        # Check for SPF, DKIM, DMARC (email security posture)
        email_security = {
            "spf": False,
            "dkim": False,
            "dmarc": False,
        }
        for record in records:
            if record["type"] == "TXT":
                val = record["value"].lower()
                if "v=spf1" in val:
                    email_security["spf"] = True
                if "v=dkim1" in val:
                    email_security["dkim"] = True

        # Check DMARC specifically
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{target}", "TXT")
            for rdata in dmarc_answers:
                txt = str(rdata).lower()
                if "v=dmarc1" in txt:
                    email_security["dmarc"] = True
                    records.append({
                        "type": "TXT",
                        "value": f"_dmarc.{target}: {str(rdata)}",
                        "ttl": dmarc_answers.rrset.ttl,
                    })
        except Exception:
            pass

        print_dns_results(records)

        # Print email security summary
        print_key_value("Email Security", "")
        for protocol, found in email_security.items():
            status = "✓ Found" if found else "✗ Missing"
            color = "green" if found else "red"
            from rich.console import Console
            Console().print(f"    [{color}]{status}[/{color}] {protocol.upper()}")

        if reverse_dns:
            print_key_value("Reverse DNS", "")
            for ip, hostname in reverse_dns.items():
                print_key_value(f"  {ip}", hostname, indent=2)

        # Generate findings for missing email security
        findings = []
        if not email_security["spf"]:
            findings.append({
                "severity": "medium",
                "title": "Missing SPF Record",
                "detail": (
                    "No SPF record found. The domain is vulnerable to "
                    "email spoofing attacks."
                ),
                "owasp": "A05:2021 Security Misconfiguration",
                "mitre": "T1566 - Phishing",
            })
            print_finding("medium", "Missing SPF Record",
                         "Domain vulnerable to email spoofing")

        if not email_security["dmarc"]:
            findings.append({
                "severity": "medium",
                "title": "Missing DMARC Record",
                "detail": (
                    "No DMARC policy found. Attackers can send emails "
                    "that appear to come from this domain."
                ),
                "owasp": "A05:2021 Security Misconfiguration",
                "mitre": "T1566 - Phishing",
            })
            print_finding("medium", "Missing DMARC Record",
                         "No policy to prevent email spoofing")

        if not email_security["dkim"]:
            findings.append({
                "severity": "low",
                "title": "Missing DKIM Record",
                "detail": (
                    "No DKIM record found in public DNS. Email "
                    "authenticity cannot be cryptographically verified."
                ),
                "owasp": "A05:2021 Security Misconfiguration",
                "mitre": "T1566 - Phishing",
            })
            print_finding("low", "Missing DKIM Record",
                         "Email authenticity not verifiable")

        results = {
            "domain": target,
            "records": records,
            "record_count": len(records),
            "ip_addresses": ip_addresses,
            "reverse_dns": reverse_dns,
            "email_security": email_security,
            "nameservers": ns_records,
            "findings": findings,
        }

        return results
