"""
heuristics.py
Rule-based checks that flag suspicious URLs WITHOUT needing any API key.
Each check returns (is_flagged: bool, reason: str)
"""

import re
import tldextract

# Use the bundled offline suffix list snapshot instead of fetching it live
# from the internet on every run (avoids network calls / warnings).
_extract = tldextract.TLDExtract(suffix_list_urls=())
tldextract.extract = _extract


# --- Reference data -------------------------------------------------------

# Popular domains commonly impersonated in phishing (extend as needed)
POPULAR_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "paypal.com", "instagram.com", "netflix.com", "linkedin.com", "twitter.com",
    "whatsapp.com", "bankofamerica.com", "chase.com", "hdfcbank.com",
    "icicibank.com", "sbi.co.in", "flipkart.com", "irctc.co.in",
]

# Known URL shortener services (link destination is hidden)
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
]

# Suspicious / high-abuse top-level domains (commonly used in phishing campaigns)
SUSPICIOUS_TLDS = [
    "zip", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "work", "click",
    "loan", "win", "review", "country", "kim", "science",
]

# Characters/patterns that are red flags in a URL
SUSPICIOUS_CHAR_PATTERNS = [
    (r"@", "Contains '@' symbol (can hide the real destination before it)"),
    (r"-{2,}", "Contains multiple consecutive hyphens"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Uses a raw IP address instead of a domain name"),
    (r"%[0-9a-fA-F]{2}", "Contains URL-encoded characters (possible obfuscation)"),
    (r"xn--", "Uses punycode encoding (possible homograph/lookalike attack)"),
]


def _levenshtein(a: str, b: str) -> int:
    """Simple edit distance, used for typosquatting detection."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def check_typosquatting(url: str):
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}".lower()
    for popular in POPULAR_DOMAINS:
        if domain == popular:
            return False, None  # exact match to a known safe domain
        dist = _levenshtein(domain, popular)
        # Close but not equal => likely typosquat (e.g. "gooogle.com" vs "google.com")
        if 0 < dist <= 2 and len(domain) >= len(popular) - 2:
            return True, f"Domain '{domain}' looks very similar to '{popular}' (possible typosquatting)"
    return False, None


def check_shortener(url: str):
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}".lower()
    if domain in URL_SHORTENERS:
        return True, f"'{domain}' is a URL shortener — real destination is hidden"
    return False, None


def check_suspicious_tld(url: str):
    ext = tldextract.extract(url)
    if ext.suffix.lower() in SUSPICIOUS_TLDS:
        return True, f"Uses a high-abuse top-level domain: .{ext.suffix}"
    return False, None


def check_suspicious_chars(url: str):
    reasons = []
    for pattern, msg in SUSPICIOUS_CHAR_PATTERNS:
        if re.search(pattern, url):
            reasons.append(msg)
    return (len(reasons) > 0), reasons


def check_https(url: str):
    if not url.lower().startswith("https://"):
        return True, "Not using HTTPS (connection is not encrypted)"
    return False, None


def check_subdomain_count(url: str):
    ext = tldextract.extract(url)
    if ext.subdomain and ext.subdomain.count(".") >= 2:
        return True, f"Unusually many subdomains: '{ext.subdomain}'"
    return False, None


def run_all_heuristics(url: str) -> dict:
    """Runs every heuristic check and returns a structured result."""
    flags = []
    score = 0  # higher = more suspicious

    checks = [
        (check_typosquatting, 3),
        (check_shortener, 1),
        (check_suspicious_tld, 2),
        (check_https, 1),
        (check_subdomain_count, 1),
    ]

    for func, weight in checks:
        flagged, reason = func(url)
        if flagged:
            flags.append(reason)
            score += weight

    char_flagged, char_reasons = check_suspicious_chars(url)
    if char_flagged:
        flags.extend(char_reasons)
        score += len(char_reasons)

    if score == 0:
        verdict = "LIKELY SAFE"
    elif score <= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY MALICIOUS"

    return {"url": url, "score": score, "verdict": verdict, "flags": flags}
