"""
SSL/TLS Certificate Analyzer Module
Connects directly to the target and pulls certificate information.
No API key required - uses Python's built-in ssl and socket libraries.

This is the same kind of analysis you did at BIT when the itelinc.com
cert expired and cascaded into AVD failures. Now it's automated.
"""
import ssl
import socket
from datetime import datetime
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_ssl_results,
    print_error,
    print_progress,
    print_finding,
)


@register_module
class SslModule(BaseModule):
    name = "ssl"
    description = "SSL/TLS certificate analysis"
    requires_api_key = False

    def _connect(self, host, port):
        """Open a TCP connection to host:port, trying IPv4 before IPv6.

        socket.create_connection() resolves with AF_UNSPEC and may try an IPv6
        (AAAA) address first. On a host with no IPv6 route that connect fails
        immediately with OSError [Errno 101] Network is unreachable, and the
        error surfaced to the caller is that IPv6 failure even when IPv4 would
        have worked. We resolve explicitly and try IPv4 addresses first, only
        falling back to IPv6, so a missing IPv6 route no longer breaks the scan.
        Raises the last OSError if every address fails.
        """
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        # IPv4 (AF_INET) first, then IPv6 (AF_INET6).
        infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)

        # If every address fails, surface the FIRST (preferred-family, i.e.
        # IPv4) error rather than the last. On an IPv4-only host the IPv6 attempt
        # fails with ENETUNREACH, which would mask the far more useful IPv4 result
        # (e.g. ECONNREFUSED = the target simply doesn't serve HTTPS on 443).
        first_error = None
        for family, socktype, proto, _canon, sockaddr in infos:
            sock = None
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(self.timeout)
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                if first_error is None:
                    first_error = exc
                if sock is not None:
                    sock.close()
        if first_error is not None:
            raise first_error
        raise OSError(f"Could not resolve any address for {host}:{port}")

    def run(self, target: str) -> dict:
        print_section("SSL/TLS Analysis", "🔒")
        print_progress(f"Connecting to {target}:443")

        try:
            # Create SSL context
            context = ssl.create_default_context()

            # Connect (IPv4-first) and get certificate
            with self._connect(target, 443) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

            # Parse subject
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            # Parse dates
            not_before = datetime.strptime(
                cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
            )
            not_after = datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            )
            days_until_expiry = (not_after - datetime.now()).days

            # Parse SANs (Subject Alternative Names)
            san_list = []
            for san_type, san_value in cert.get("subjectAltName", []):
                san_list.append(san_value)

            # Build results
            results = {
                "domain": target,
                "subject": subject.get("commonName", "N/A"),
                "issuer": issuer.get("organizationName", "N/A"),
                "issuer_cn": issuer.get("commonName", "N/A"),
                "not_before": not_before.strftime("%Y-%m-%d"),
                "not_after": not_after.strftime("%Y-%m-%d"),
                "days_until_expiry": days_until_expiry,
                "serial": cert.get("serialNumber", "N/A"),
                "version": cert.get("version", "N/A"),
                "san": san_list,
                "san_count": len(san_list),
                "cipher_suite": cipher[0] if cipher else "N/A",
                "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else "N/A",
                "protocol": protocol,
                "findings": [],
            }

            print_ssl_results(results)

            # Security findings based on cert analysis
            findings = []

            # Check expiration
            if days_until_expiry < 0:
                finding = {
                    "severity": "critical",
                    "title": "SSL Certificate Expired",
                    "detail": f"Certificate expired {abs(days_until_expiry)} days ago",
                    "owasp": "A05:2021 Security Misconfiguration",
                    "mitre": "T1557 - Adversary-in-the-Middle",
                }
                findings.append(finding)
                print_finding(**{k: v for k, v in finding.items() if k in ["severity", "title", "detail"]})

            elif days_until_expiry < 30:
                finding = {
                    "severity": "medium",
                    "title": "SSL Certificate Expiring Soon",
                    "detail": f"Certificate expires in {days_until_expiry} days",
                    "owasp": "A05:2021 Security Misconfiguration",
                    "mitre": "T1557 - Adversary-in-the-Middle",
                }
                findings.append(finding)
                print_finding(**{k: v for k, v in finding.items() if k in ["severity", "title", "detail"]})

            # Check for weak protocol
            if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                finding = {
                    "severity": "high",
                    "title": f"Weak TLS Protocol: {protocol}",
                    "detail": "Vulnerable to known attacks (POODLE, BEAST, etc)",
                    "owasp": "A02:2021 Cryptographic Failures",
                    "mitre": "T1557.002 - ARP Cache Poisoning",
                }
                findings.append(finding)
                print_finding(**{k: v for k, v in finding.items() if k in ["severity", "title", "detail"]})

            # Check for self-signed cert
            if subject.get("commonName") == issuer.get("commonName"):
                finding = {
                    "severity": "medium",
                    "title": "Potentially Self-Signed Certificate",
                    "detail": "Subject CN matches Issuer CN",
                    "owasp": "A05:2021 Security Misconfiguration",
                    "mitre": "T1557 - Adversary-in-the-Middle",
                }
                findings.append(finding)
                print_finding(**{k: v for k, v in finding.items() if k in ["severity", "title", "detail"]})

            # Check for wildcard cert
            if results["subject"].startswith("*."):
                finding = {
                    "severity": "info",
                    "title": "Wildcard Certificate in Use",
                    "detail": f"Covers: {results['subject']}",
                    "owasp": "N/A",
                    "mitre": "N/A",
                }
                findings.append(finding)
                print_finding(**{k: v for k, v in finding.items() if k in ["severity", "title", "detail"]})

            # Check cipher strength
            if cipher and cipher[2] < 128:
                finding = {
                    "severity": "high",
                    "title": f"Weak Cipher: {cipher[0]} ({cipher[2]} bits)",
                    "detail": "Cipher strength below 128 bits",
                    "owasp": "A02:2021 Cryptographic Failures",
                    "mitre": "T1600 - Weaken Encryption",
                }
                findings.append(finding)
                print_finding(**{k: v for k, v in finding.items() if k in ["severity", "title", "detail"]})

            results["findings"] = findings
            return results

        except ssl.SSLCertVerificationError as e:
            print_error(f"SSL verification failed: {str(e)}")
            return {
                "error": f"SSL verification failed: {str(e)}",
                "domain": target,
                "findings": [{
                    "severity": "high",
                    "title": "SSL Certificate Verification Failed",
                    "detail": str(e),
                    "owasp": "A02:2021 Cryptographic Failures",
                    "mitre": "T1557 - Adversary-in-the-Middle",
                }],
            }
        except socket.timeout:
            print_error(f"Connection to {target}:443 timed out")
            return {"error": "Connection timed out", "domain": target}
        except ConnectionRefusedError:
            print_error(f"Connection refused on {target}:443 (no HTTPS?)")
            return {"error": "Connection refused", "domain": target}
        except socket.gaierror as e:
            msg = f"DNS resolution failed for {target}: {e}"
            print_error(msg)
            return {"error": msg, "domain": target}
        except OSError as e:
            # Network-level failure (e.g. Errno 101 Network is unreachable /
            # Errno 113 No route to host). We already try IPv4 before IPv6, so
            # reaching here means no address was reachable at all. Fail with a
            # clear, actionable message instead of a raw traceback.
            import errno
            if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
                msg = (
                    f"Cannot reach {target}:443 — network unreachable "
                    f"(Errno {e.errno}). No route to the host on any resolved "
                    f"IPv4/IPv6 address. Check connectivity/VPN and that the "
                    f"target serves HTTPS."
                )
            else:
                msg = f"SSL connection to {target}:443 failed: {e}"
            print_error(msg)
            return {"error": msg, "domain": target}
        except Exception as e:
            print_error(f"SSL analysis failed: {str(e)}")
            return {"error": str(e), "domain": target}
