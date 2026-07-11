"""
Google Dork Generator Module

Generates Google search queries (dorks) tailored to the target domain
that can reveal exposed files, login pages, error messages, and
sensitive information indexed by search engines.

No API key required - it generates the queries, you paste them into Google.

This is pure OSINT. Google has already crawled and indexed everything.
You're just asking it the right questions.
"""
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_key_value,
    print_progress,
)


# Dork categories and their queries
DORK_TEMPLATES = {
    "Exposed Login Pages": [
        ('site:{target} inurl:login', "Find login pages"),
        ('site:{target} inurl:admin', "Find admin pages"),
        ('site:{target} inurl:signin OR inurl:signup', "Find auth pages"),
        ('site:{target} intitle:"login" OR intitle:"sign in"', "Login pages by title"),
        ('site:{target} inurl:wp-login.php', "WordPress login"),
    ],
    "Exposed Files & Documents": [
        ('site:{target} filetype:pdf', "PDF documents"),
        ('site:{target} filetype:doc OR filetype:docx', "Word documents"),
        ('site:{target} filetype:xls OR filetype:xlsx', "Spreadsheets"),
        ('site:{target} filetype:sql', "SQL database files"),
        ('site:{target} filetype:log', "Log files"),
        ('site:{target} filetype:env', "Environment files"),
        ('site:{target} filetype:xml', "XML files"),
        ('site:{target} filetype:conf OR filetype:cfg', "Config files"),
        ('site:{target} filetype:bak OR filetype:backup', "Backup files"),
        ('site:{target} filetype:csv', "CSV data files"),
    ],
    "Sensitive Directories": [
        ('site:{target} inurl:"/admin/"', "Admin directories"),
        ('site:{target} inurl:"/backup/"', "Backup directories"),
        ('site:{target} inurl:"/config/"', "Config directories"),
        ('site:{target} inurl:"/private/"', "Private directories"),
        ('site:{target} inurl:"/upload/" OR inurl:"/uploads/"', "Upload directories"),
        ('site:{target} intitle:"index of"', "Directory listings"),
        ('site:{target} intitle:"index of" "parent directory"', "Open directory listings"),
    ],
    "Error Messages & Debug Info": [
        ('site:{target} "PHP Parse error" OR "PHP Warning"', "PHP errors"),
        ('site:{target} "mysql_" OR "mysqli_" error', "MySQL errors"),
        ('site:{target} "ORA-" error', "Oracle DB errors"),
        ('site:{target} "Stack Trace" OR "Traceback"', "Stack traces"),
        ('site:{target} inurl:debug', "Debug pages"),
        ('site:{target} "not intended for public release"', "Unintended content"),
        ('site:{target} "internal use only"', "Internal documents"),
    ],
    "Credentials & Sensitive Data": [
        ('site:{target} "password" filetype:log', "Passwords in logs"),
        ('site:{target} inurl:credentials', "Credential pages"),
        ('site:{target} "api_key" OR "apikey" OR "api-key"', "API keys"),
        ('site:{target} "secret_key" OR "private_key"', "Secret keys"),
        ('site:{target} "access_token" OR "auth_token"', "Access tokens"),
        ('site:{target} inurl:token', "Token endpoints"),
    ],
    "Technology & Infrastructure": [
        ('site:{target} inurl:wp-content', "WordPress content"),
        ('site:{target} inurl:wp-json', "WordPress API"),
        ('site:{target} inurl:xmlrpc.php', "WordPress XML-RPC"),
        ('site:{target} "powered by" OR "built with"', "Technology disclosure"),
        ('site:{target} inurl:phpinfo', "PHP info pages"),
        ('site:{target} inurl:server-status', "Server status pages"),
    ],
    "Subdomains & Related Sites": [
        ('site:*.{target} -www', "Subdomains indexed by Google"),
        ('site:{target} -www -inurl:www', "Non-www pages"),
        ('"{target}" -site:{target}', "References on other sites"),
    ],
    "Old & Cached Content": [
        ('site:{target} inurl:old OR inurl:archive OR inurl:legacy', "Old content"),
        ('site:{target} inurl:test OR inurl:staging OR inurl:dev', "Test/staging content"),
        ('cache:site:{target}', "Google cached version"),
    ],
}


@register_module
class DorkGenModule(BaseModule):
    name = "dorks"
    description = "Google Dork query generator for OSINT"
    requires_api_key = False

    def run(self, target: str) -> dict:
        print_section("Google Dork Queries", "🔍")
        print_progress(
            "These are search queries to paste into Google. "
            "Each one can reveal information indexed by search engines."
        )

        all_dorks = []
        dork_count = 0

        for category, dorks in DORK_TEMPLATES.items():
            print_key_value(f"\n  {category}", "")

            category_dorks = []
            for template, description in dorks:
                query = template.format(target=target)
                google_url = (
                    f"https://www.google.com/search?q="
                    f"{query.replace(' ', '+')}"
                )
                category_dorks.append({
                    "query": query,
                    "description": description,
                    "url": google_url,
                })
                dork_count += 1

                from rich.console import Console
                Console().print(
                    f"    [cyan]{query}[/cyan]"
                )
                Console().print(
                    f"      [dim]{description}[/dim]"
                )

            all_dorks.append({
                "category": category,
                "dorks": category_dorks,
            })

        print_key_value(
            f"\n  Total Dorks Generated", f"{dork_count}"
        )
        print_key_value(
            "  Usage",
            "Copy any query above and paste it into Google"
        )

        results = {
            "domain": target,
            "dork_categories": all_dorks,
            "total_dorks": dork_count,
            "findings": [],  # Dorks don't generate findings directly
        }

        return results
