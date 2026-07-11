"""
BSS IDOR Finder - Analyzes Burp Suite exported traffic for IDOR candidates.

Usage:
  1. In Burp: Proxy > HTTP History > Select all > Right-click > Save items (as XML)
  2. Transfer the XML file to Kali
  3. Run: python -m bssrecon.tools.idor_finder burp_export.xml

Or use standalone against a list of URLs:
  python -m bssrecon.tools.idor_finder --urls urls.txt
"""
import re
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from collections import defaultdict


IDOR_PATTERNS = [
    (r'/(\d{4,})', 'Numeric ID in path'),
    (r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'UUID in path'),
    (r'[?&](id|user_id|userId|account_id|accountId|order_id|orderId|file_id|fileId|doc_id|return_id|tax_id|olTaxId)=', 'ID parameter in query'),
    (r'/(user|account|order|invoice|document|file|return|profile|report|tax)/(\d+)', 'Resource with numeric ID'),
    (r'/(api|v\d)/\w+/(\d{3,})', 'API endpoint with numeric ID'),
]

SENSITIVE_KEYWORDS = [
    'user', 'account', 'profile', 'admin', 'private', 'personal',
    'ssn', 'tax', 'payment', 'billing', 'order', 'invoice',
    'document', 'file', 'download', 'export', 'report',
    'email', 'phone', 'address', 'password', 'credential',
    'basicinfo', 'fields', 'settings', 'preferences',
]

SKIP_DOMAINS = [
    'doubleclick.net', 'google-analytics.com', 'googletagmanager.com',
    'googlesyndication.com', 'googleadservices.com', 'google.com',
    'facebook.net', 'facebook.com', 'linkedin.com', 'pinterest.com',
    'bing.com', 'adsrvr.org', 'snapchat.com', 'reddit.com',
    'optimizely.com', 'datadoghq', 'zoom.us', 'cookielaw.org',
    'milestoneinternet.com', 'pinimg.com',
]


def is_noise(url):
    for domain in SKIP_DOMAINS:
        if domain in url:
            return True
    return False


def analyze_url(url):
    if is_noise(url):
        return None

    findings = []
    parsed = urlparse(url)
    full_path = parsed.path

    for pattern, description in IDOR_PATTERNS:
        matches = re.findall(pattern, url)
        if matches:
            flat = []
            for m in matches:
                if isinstance(m, tuple):
                    flat.append(m[0])
                else:
                    flat.append(m)
            findings.append({
                'pattern': description,
                'matches': flat,
            })

    params = parse_qs(parsed.query)
    id_params = {}
    for key, values in params.items():
        key_lower = key.lower()
        if any(kw in key_lower for kw in ['id', 'uid', 'num', 'ref', 'key', 'token']):
            id_params[key] = values[0] if values else ''

    if id_params:
        findings.append({
            'pattern': 'ID-like query parameters',
            'matches': id_params,
        })

    sensitive_hits = []
    path_lower = full_path.lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in path_lower:
            sensitive_hits.append(kw)

    if findings or sensitive_hits:
        return {
            'url': url,
            'method': 'GET',
            'host': parsed.hostname,
            'path': full_path,
            'findings': findings,
            'sensitive_keywords': sensitive_hits,
            'risk': _score_risk(findings, sensitive_hits),
        }
    return None


def _score_risk(findings, sensitive_hits):
    score = 0
    for f in findings:
        if 'Numeric ID' in f['pattern']:
            score += 3
        elif 'UUID' in f['pattern']:
            score += 2
        elif 'parameter' in f['pattern']:
            score += 2
    for kw in sensitive_hits:
        if kw in ('ssn', 'tax', 'payment', 'password', 'credential'):
            score += 3
        elif kw in ('user', 'account', 'profile', 'personal', 'billing'):
            score += 2
        else:
            score += 1
    if score >= 6:
        return 'HIGH'
    elif score >= 3:
        return 'MEDIUM'
    else:
        return 'LOW'


def parse_burp_xml(filepath):
    tree = ET.parse(filepath)
    root = tree.getroot()
    urls = []
    for item in root.findall('.//item'):
        url_elem = item.find('url')
        method_elem = item.find('method')
        status_elem = item.find('status')
        if url_elem is not None:
            url = url_elem.text
            method = method_elem.text if method_elem is not None else 'GET'
            status = status_elem.text if status_elem is not None else ''
            urls.append({'url': url, 'method': method, 'status': status})
    return urls


def parse_url_list(filepath):
    urls = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and line.startswith('http'):
                urls.append({'url': line, 'method': 'GET', 'status': ''})
    return urls


def analyze_traffic(urls):
    candidates = []
    seen = set()

    for entry in urls:
        url = entry['url']
        dedup_key = re.sub(r'/\d{4,}', '/{id}', urlparse(url).path)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        result = analyze_url(url)
        if result:
            result['method'] = entry.get('method', 'GET')
            result['status'] = entry.get('status', '')
            candidates.append(result)

    risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    candidates.sort(key=lambda x: risk_order.get(x['risk'], 3))
    return candidates


def print_report(candidates):
    print("")
    print("=" * 70)
    print("  BSS IDOR Finder - Potential IDOR Candidates")
    print("=" * 70)

    if not candidates:
        print("\n  No IDOR candidates found in traffic.\n")
        return

    print(f"\n  Found {len(candidates)} potential IDOR candidates:\n")

    for i, c in enumerate(candidates, 1):
        risk_color = {'HIGH': '\033[91m', 'MEDIUM': '\033[93m', 'LOW': '\033[92m'}
        reset = '\033[0m'
        color = risk_color.get(c['risk'], '')

        print(f"  {color}[{c['risk']}]{reset} #{i}")
        print(f"    {c['method']} {c['url'][:120]}")
        if c['findings']:
            for f in c['findings']:
                print(f"    -> {f['pattern']}: {f['matches']}")
        if c['sensitive_keywords']:
            print(f"    -> Sensitive context: {', '.join(c['sensitive_keywords'])}")
        print()

    high = sum(1 for c in candidates if c['risk'] == 'HIGH')
    med = sum(1 for c in candidates if c['risk'] == 'MEDIUM')
    low = sum(1 for c in candidates if c['risk'] == 'LOW')
    print(f"  Summary: {high} HIGH / {med} MEDIUM / {low} LOW")
    print(f"\n  Next steps:")
    print(f"    1. Send HIGH risk requests to Burp Repeater")
    print(f"    2. Change the numeric ID/UUID to a different value")
    print(f"    3. Check if the response returns another user's data")
    print(f"    4. If it does - that is an IDOR finding, write it up\n")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m bssrecon.tools.idor_finder <burp_export.xml>")
        print("  python -m bssrecon.tools.idor_finder --urls <urls.txt>")
        print("  echo 'https://example.com/api/user/123' | python -m bssrecon.tools.idor_finder --stdin")
        sys.exit(1)

    if sys.argv[1] == '--urls':
        urls = parse_url_list(sys.argv[2])
    elif sys.argv[1] == '--stdin':
        urls = [{'url': line.strip(), 'method': 'GET', 'status': ''}
                for line in sys.stdin if line.strip().startswith('http')]
    elif sys.argv[1].endswith('.xml'):
        urls = parse_burp_xml(sys.argv[1])
    else:
        urls = parse_url_list(sys.argv[1])

    candidates = analyze_traffic(urls)
    print_report(candidates)

    output_path = Path('output') / 'idor_candidates.json'
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(candidates, f, indent=2, default=str)
    print(f"  Results saved: {output_path}\n")


if __name__ == '__main__':
    main()
