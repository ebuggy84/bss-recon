"""
MITRE ATT&CK Framework Mapping

Maps reconnaissance and initial access findings to MITRE ATT&CK techniques.
Focused on techniques relevant to external assessments and bug bounty.

Reference: https://attack.mitre.org/
"""

# Reconnaissance techniques (TA0043)
RECON_TECHNIQUES = {
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "subtechniques": {
            "T1595.001": "Scanning IP Blocks",
            "T1595.002": "Vulnerability Scanning",
            "T1595.003": "Wordlist Scanning",
        },
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "subtechniques": {
            "T1592.001": "Hardware",
            "T1592.002": "Software",
            "T1592.003": "Firmware",
            "T1592.004": "Client Configurations",
        },
    },
    "T1590": {
        "name": "Gather Victim Network Information",
        "tactic": "Reconnaissance",
        "subtechniques": {
            "T1590.001": "Domain Properties",
            "T1590.002": "DNS",
            "T1590.004": "Network Topology",
            "T1590.005": "IP Addresses",
            "T1590.006": "Network Security Appliances",
        },
    },
    "T1589": {
        "name": "Gather Victim Identity Information",
        "tactic": "Reconnaissance",
        "subtechniques": {
            "T1589.001": "Credentials",
            "T1589.002": "Email Addresses",
            "T1589.003": "Employee Names",
        },
    },
    "T1593": {
        "name": "Search Open Websites/Domains",
        "tactic": "Reconnaissance",
        "subtechniques": {
            "T1593.001": "Social Media",
            "T1593.002": "Search Engines",
            "T1593.003": "Code Repositories",
        },
    },
    "T1596": {
        "name": "Search Open Technical Databases",
        "tactic": "Reconnaissance",
        "subtechniques": {
            "T1596.001": "DNS/Passive DNS",
            "T1596.002": "WHOIS",
            "T1596.003": "Digital Certificates",
            "T1596.004": "CDNs",
            "T1596.005": "Scan Databases (Shodan, Censys)",
        },
    },
    "T1597": {
        "name": "Search Closed Sources",
        "tactic": "Reconnaissance",
        "subtechniques": {
            "T1597.001": "Threat Intel Vendors",
            "T1597.002": "Purchase Technical Data",
        },
    },
}

# Initial Access techniques (TA0001) - what recon findings lead to
INITIAL_ACCESS_TECHNIQUES = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploiting vulnerabilities in internet-facing applications",
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Leveraging exposed remote services (RDP, VPN, SSH)",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Using compromised or default credentials",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Using gathered contact info for targeted phishing",
    },
    "T1199": {
        "name": "Trusted Relationship",
        "tactic": "Initial Access",
        "description": "Abusing trusted third-party relationships",
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": "Intercepting communications due to weak crypto",
    },
}

# Maps our module findings to ATT&CK techniques
MODULE_TECHNIQUE_MAP = {
    "whois": ["T1596.002", "T1590.001"],
    "dns": ["T1596.001", "T1590.002", "T1590.005"],
    "subdomains": ["T1596.003", "T1595.003", "T1590.001"],
    "ssl": ["T1596.003", "T1557"],
    "shodan": ["T1596.005", "T1592.002", "T1590.005"],
    "nmap_import": ["T1595.001", "T1595.002"],
}


def get_technique(technique_id):
    """Get technique details by ID."""
    # Check main techniques
    for tech_id, tech_data in {**RECON_TECHNIQUES, **INITIAL_ACCESS_TECHNIQUES}.items():
        if tech_id == technique_id:
            return tech_data
        # Check subtechniques
        if "subtechniques" in tech_data:
            if technique_id in tech_data["subtechniques"]:
                return {
                    "name": tech_data["subtechniques"][technique_id],
                    "parent": tech_data["name"],
                    "tactic": tech_data["tactic"],
                }
    return None


def get_techniques_for_module(module_name):
    """Get relevant ATT&CK techniques for a given module."""
    technique_ids = MODULE_TECHNIQUE_MAP.get(module_name, [])
    techniques = []
    for tid in technique_ids:
        tech = get_technique(tid)
        if tech:
            techniques.append({"id": tid, **tech})
    return techniques


def format_technique_reference(technique_id):
    """Format a technique as a reference string for reports."""
    tech = get_technique(technique_id)
    if tech:
        return f"{technique_id} - {tech['name']}"
    return technique_id
