"""
BSS Recon - Subdomain Mutation & Mass Resolution Module (v2 - Async)

Takes subdomains found by the standard subdomains module (crt.sh) and generates
mutations to find undocumented subdomains. Uses async DNS resolution for
500-1000 queries per second from a single core.

Also loads custom wordlists from bssrecon/wordlists/mutation_prefixes.txt
that grow smarter as you study more bug bounty writeups.

Mode: PASSIVE (queries public DNS resolvers, not the target's servers)
API Key: None required
"""
import asyncio
import socket
import time
import random
import string
from collections import defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_success,
    print_warning,
    print_error,
    print_progress,
    console,
)


# Try to import aiodns for fast async resolution, fall back to thread pool
try:
    import aiodns
    HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False


@register_module
class SubMutateModule(BaseModule):
    name = "submutate"
    description = "Subdomain mutation & mass DNS resolution (async)"
    requires_api_key = False
    mode = "passive"

    BASE_WORDLIST = [
        "admin", "api", "app", "auth", "beta", "blog", "cdn", "ci",
        "cms", "cpanel", "dashboard", "db", "demo", "dev", "docs",
        "email", "ftp", "gateway", "git", "gitlab", "grafana",
        "graphql", "help", "internal", "intranet", "jenkins",
        "jira", "kibana", "login", "mail", "manage", "monitor",
        "mysql", "new", "old", "ops", "panel", "portal", "prod",
        "proxy", "qa", "redis", "remote", "sandbox", "secure",
        "sentry", "shop", "signin", "signup", "sso", "stage",
        "staging", "static", "status", "stg", "support", "swagger",
        "test", "testing", "tools", "uat", "upload", "v1", "v2",
        "v3", "vault", "vpn", "webmail", "wiki", "www",
    ]

    MUTATIONS = [
        "-dev", "-staging", "-stg", "-prod", "-production", "-test",
        "-testing", "-qa", "-uat", "-sandbox", "-demo", "-beta",
        "-alpha", "-preview", "-canary",
        "-v1", "-v2", "-v3", "-v4", "-old", "-new", "-legacy",
        "-next", "-current", "-latest",
        "-api", "-app", "-web", "-cdn", "-cache", "-db", "-admin",
        "-internal", "-external", "-public", "-private",
        "-backup", "-bak", "-mirror", "-replica",
        "-us", "-eu", "-ap", "-east", "-west",
        "-us-east", "-us-west", "-eu-west",
    ]

    PREFIX_MUTATIONS = [
        "dev-", "staging-", "test-", "api-", "admin-", "internal-",
        "old-", "new-", "v2-", "beta-", "pre-", "post-",
    ]

    RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]

    def run(self, target):
        print_section("Subdomain Mutation & Resolution", "\U0001F9EC")

        findings = []
        max_candidates = int(self.config.get("scan", {}).get("submutate_max", 5000))

        # Step 1: Load known subdomains
        known_subs = self._load_known_subdomains(target)
        print_progress(f"Known subdomains from prior scans: {len(known_subs)}")

        # Step 2: Load custom wordlist
        custom_words = self._load_custom_wordlist()
        if custom_words:
            print_progress(f"Loaded {len(custom_words)} custom mutation prefixes")

        # Step 3: Generate candidates
        candidates = self._generate_candidates(target, known_subs, custom_words)
        if len(candidates) > max_candidates:
            print_warning(f"Candidate list ({len(candidates)}) exceeds max ({max_candidates}). Trimming.")
            candidates = list(candidates)[:max_candidates]
        else:
            candidates = list(candidates)

        print_progress(f"Generated {len(candidates)} mutation candidates")

        # Step 4: Check for wildcard DNS first
        wildcard_ip = self._check_wildcard(target)
        if wildcard_ip:
            console.print(f"  [yellow]\u26a0 Wildcard DNS detected: *.{target} \u2192 {wildcard_ip}[/yellow]")
            console.print(f"  [dim]Will filter wildcard responses from results[/dim]")

        # Step 5: Mass DNS resolution
        if HAS_AIODNS:
            print_progress(f"Resolving via async DNS (aiodns) - high speed mode")
            alive = self._resolve_async(candidates, wildcard_ip)
        else:
            print_progress(f"Resolving via thread pool (install aiodns for 10x speed: pip install aiodns)")
            alive = self._resolve_threaded(candidates, wildcard_ip)

        # Step 6: Categorize
        new_discoveries = [s for s in alive if s["subdomain"] not in known_subs]
        known_confirmed = [s for s in alive if s["subdomain"] in known_subs]

        # Print results
        console.print(f"\n  [bold]Resolution Complete:[/bold]")
        console.print(f"    Candidates checked:  {len(candidates)}")
        console.print(f"    Total alive:         [green]{len(alive)}[/green]")
        console.print(f"    New discoveries:     [bold green]{len(new_discoveries)}[/bold green]")
        console.print(f"    Previously known:    {len(known_confirmed)}")

        if new_discoveries:
            console.print(f"\n  [bold cyan]New Subdomain Discoveries:[/bold cyan]")

            interesting_keywords = [
                "admin", "internal", "dev", "staging", "test", "api",
                "jenkins", "gitlab", "jira", "grafana", "kibana",
                "sentry", "vault", "vpn", "debug", "old", "legacy",
                "backup", "k8s", "docker", "redis", "mongo", "elastic",
                "swagger", "graphql", "auth", "sso",
            ]

            interesting_subs = []
            for s in new_discoveries:
                sub = s["subdomain"]
                ip = s["ip"]
                is_interesting = any(kw in sub for kw in interesting_keywords)

                if is_interesting:
                    console.print(f"    [bold yellow]\u26a0[/bold yellow] {sub} \u2192 {ip} [yellow](interesting)[/yellow]")
                    interesting_subs.append(s)
                else:
                    console.print(f"    [green]\u2022[/green] {sub} \u2192 {ip}")

            if interesting_subs:
                findings.append({
                    "severity": "medium",
                    "title": f"Discovered {len(interesting_subs)} potentially sensitive subdomains",
                    "detail": (
                        f"Subdomain mutation discovered subdomains that may expose "
                        f"development, staging, or administrative interfaces: "
                        f"{', '.join(s['subdomain'] for s in interesting_subs[:10])}"
                    ),
                    "owasp": "A05:2021 Security Misconfiguration",
                    "mitre": "T1046 - Network Service Discovery",
                    "remediation": (
                        "Review all discovered subdomains. Development, staging, and "
                        "administrative subdomains should not be publicly accessible. "
                        "Implement DNS restrictions or firewall rules to limit access."
                    ),
                })

            if new_discoveries:
                findings.append({
                    "severity": "info",
                    "title": f"Discovered {len(new_discoveries)} new subdomains via mutation",
                    "detail": (
                        f"DNS mutation resolved {len(new_discoveries)} subdomains not found "
                        f"in certificate transparency logs."
                    ),
                    "owasp": "A05:2021 Security Misconfiguration",
                    "mitre": "T1018 - Remote System Discovery",
                    "remediation": "Review all subdomains for unnecessary public exposure.",
                })

        return {
            "domain": target,
            "findings": findings,
            "alive_subdomains": [s["subdomain"] for s in alive],
            "new_discoveries": [s["subdomain"] for s in new_discoveries],
            "known_confirmed": [s["subdomain"] for s in known_confirmed],
            "total_checked": len(candidates),
            "wildcard_ip": wildcard_ip,
        }

    def _generate_candidates(self, target, known_subs, custom_words=None):
        """Generate mutation candidates from known subdomains + wordlists."""
        candidates = set()

        # Base wordlist
        for word in self.BASE_WORDLIST:
            candidates.add(f"{word}.{target}")

        # Custom wordlist
        if custom_words:
            for word in custom_words:
                candidates.add(f"{word}.{target}")

        # Mutate known subdomains
        if known_subs:
            for sub in known_subs:
                parts = sub.replace(f".{target}", "").split(".")
                base = parts[0] if parts else sub

                for suffix in self.MUTATIONS:
                    candidates.add(f"{base}{suffix}.{target}")

                for prefix in self.PREFIX_MUTATIONS:
                    candidates.add(f"{prefix}{base}.{target}")

                if base in ("api", "app", "web", "mail", "cdn", "auth", "admin"):
                    for env in ["dev", "staging", "test", "prod", "v2", "old", "internal"]:
                        candidates.add(f"{base}-{env}.{target}")
                        candidates.add(f"{env}-{base}.{target}")
                        candidates.add(f"{env}.{base}.{target}")

        candidates.discard(target)
        candidates.discard(f"www.{target}")
        return candidates

    def _resolve_async(self, candidates, wildcard_ip):
        """Async DNS resolution using aiodns - 500-1000 queries/sec."""
        alive = []
        checked = 0
        start = time.time()

        async def resolve_batch(subs):
            nonlocal checked
            resolver = aiodns.DNSResolver(
                nameservers=self.RESOLVERS,
                timeout=3.0,
                tries=2,
            )

            ctrl = self.concurrency   # profile-governed limit + delay
            results = []

            async def resolve_one(sub):
                nonlocal checked
                async with ctrl.slot():
                    try:
                        resp = await resolver.query(sub, 'A')
                        if resp:
                            ip = resp[0].host
                            if wildcard_ip and ip == wildcard_ip:
                                return None
                            checked += 1
                            return {"subdomain": sub, "ip": ip}
                    except (aiodns.error.DNSError, asyncio.TimeoutError):
                        pass
                    checked += 1
                    return None

            tasks = [resolve_one(sub) for sub in subs]

            # Process in chunks and show progress
            chunk_size = 200
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i + chunk_size]
                chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
                for r in chunk_results:
                    if isinstance(r, dict) and r is not None:
                        results.append(r)
                        console.print(f"    [green]\u2714[/green] {r['subdomain']} \u2192 {r['ip']}")

                elapsed = time.time() - start
                rate = checked / elapsed if elapsed > 0 else 0
                if (i + chunk_size) % 500 == 0:
                    console.print(
                        f"    [dim]Progress: {min(checked, len(subs))}/{len(subs)} "
                        f"({rate:.0f}/sec) - Found: {len(results)}[/dim]"
                    )

            return results

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            alive = loop.run_until_complete(resolve_batch(candidates))
            loop.close()
        except Exception as e:
            print_warning(f"Async resolution failed ({e}), falling back to threads")
            alive = self._resolve_threaded(candidates, wildcard_ip)

        elapsed = time.time() - start
        console.print(f"    [dim]Resolved {len(candidates)} in {elapsed:.1f}s ({len(candidates)/elapsed:.0f}/sec)[/dim]")
        return alive

    def _resolve_threaded(self, candidates, wildcard_ip):
        """Fallback threaded DNS resolution."""
        alive = []
        checked = 0
        start = time.time()
        max_workers = self.concurrency.limit   # profile-governed concurrency

        def resolve_one(sub):
            try:
                result = socket.getaddrinfo(sub, None, socket.AF_INET, socket.SOCK_STREAM)
                if result:
                    ip = result[0][4][0]
                    if wildcard_ip and ip == wildcard_ip:
                        return None
                    return {"subdomain": sub, "ip": ip}
            except (socket.gaierror, socket.timeout, OSError):
                return None
            return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(resolve_one, sub): sub for sub in candidates}
            for future in futures:
                try:
                    result = future.result(timeout=10)
                    checked += 1
                    if result:
                        alive.append(result)
                        console.print(f"    [green]\u2714[/green] {result['subdomain']} \u2192 {result['ip']}")
                except Exception:
                    checked += 1

                if checked % 200 == 0:
                    elapsed = time.time() - start
                    rate = checked / elapsed if elapsed > 0 else 0
                    console.print(
                        f"    [dim]Progress: {checked}/{len(candidates)} "
                        f"({rate:.0f}/sec) - Found: {len(alive)}[/dim]"
                    )

        elapsed = time.time() - start
        console.print(f"    [dim]Resolved {len(candidates)} in {elapsed:.1f}s ({len(candidates)/elapsed:.0f}/sec)[/dim]")
        return alive

    def _check_wildcard(self, target):
        """Check if the domain has wildcard DNS."""
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=16))
        test_domain = f"{random_sub}.{target}"
        try:
            result = socket.getaddrinfo(test_domain, None, socket.AF_INET, socket.SOCK_STREAM)
            if result:
                return result[0][4][0]
        except (socket.gaierror, socket.timeout, OSError):
            return None
        return None

    def _load_known_subdomains(self, target):
        """Load subdomains from previous scan results."""
        known = set()
        output_dir = Path(self.config.get("output", {}).get("output_dir", "./output"))
        prefix = target.replace(".", "_")

        json_files = sorted(
            output_dir.glob(f"{prefix}_*.json"),
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
            reverse=True,
        )

        if json_files:
            import json
            try:
                with open(json_files[0]) as f:
                    data = json.load(f)
                sub_data = data.get("subdomains", {})
                if isinstance(sub_data, dict):
                    known.update(sub_data.get("subdomains", []))
                elif isinstance(sub_data, list):
                    known.update(sub_data)
            except Exception:
                pass

        return known

    def _load_custom_wordlist(self):
        """Load custom mutation prefixes from wordlist file."""
        words = []
        wordlist_paths = [
            Path(__file__).parent.parent / "wordlists" / "mutation_prefixes.txt",
            Path.home() / "bss-recon" / "bssrecon" / "wordlists" / "mutation_prefixes.txt",
            Path.cwd() / "bssrecon" / "wordlists" / "mutation_prefixes.txt",
        ]

        for path in wordlist_paths:
            if path.exists():
                try:
                    with open(path) as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                words.append(line)
                    return words
                except Exception:
                    continue

        return words
