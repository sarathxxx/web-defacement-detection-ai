"""
URL Feature Extractor - Extracts 33 structural, lexical, and heuristic features from URLs.
Based on techniques from the phishing detection notebook + malicious_phish.csv dataset.
"""

import re
import math
import urllib.parse
from typing import Dict, List


# Generic suspicious action words — NOT brand names (brands cause false positives on legit domains)
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'update', 'banking',
    'confirm', 'password', 'credential', 'wallet', 'winner', 'prize',
    'webscr', 'cmd', 'dispatch', 'redirect', 'invoice', 'suspended',
    'validate', 'recover', 'unlock', 'alert', 'notice', 'urgent',
    'billing', 'statement', 'activation', 'reactivate', 'cancel',
]

# Brand names used in subdomains / paths of PHISHING sites (not direct hits)
BRAND_KEYWORDS = [
    'paypal', 'ebay', 'amazon', 'apple', 'google', 'microsoft',
    'netflix', 'instagram', 'facebook', 'twitter', 'whatsapp', 'dropbox',
    'citibank', 'bankofamerica', 'chase', 'wellsfargo',
]

HIGH_RISK_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top', 'xyz', 'click', 'link',
    'work', 'party', 'gdn', 'stream', 'download', 'racing', 'win', 'loan',
    'date', 'faith', 'review', 'trade', 'accountant', 'science', 'men',
    'kim', 'country', 'bid', 'cricket', 'webcam',
}

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
    'amazon.com', 'wikipedia.org', 'reddit.com', 'linkedin.com', 'github.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'instagram.com', 'whatsapp.com',
    'stackoverflow.com', 'dropbox.com', 'zoom.us', 'slack.com', 'adobe.com',
    'paypal.com', 'ebay.com', 'walmart.com', 'yahoo.com', 'bing.com',
}


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def extract_features(url: str) -> Dict[str, float]:
    """Extract 33 numeric features from a URL string."""
    url = str(url).strip()

    # Normalize - add scheme if missing
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url_for_parse = 'http://' + url
    else:
        url_for_parse = url

    try:
        parsed = urllib.parse.urlparse(url_for_parse)
        netloc   = parsed.netloc or ''
        path     = parsed.path or ''
        query    = parsed.query or ''
        fragment = parsed.fragment or ''
        scheme   = parsed.scheme or ''

        # Remove port from netloc for hostname analysis
        hostname = netloc.split(':')[0].lower()
        parts    = hostname.split('.')
        tld      = parts[-1] if len(parts) >= 1 else ''
        domain   = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    except Exception:
        hostname = netloc = path = query = fragment = scheme = tld = domain = subdomain = ''

    full_url  = url
    url_lower = full_url.lower()

    feats = {}

    # === Length features ===
    feats['url_length']      = len(full_url)
    feats['hostname_length'] = len(hostname)
    feats['path_length']     = len(path)
    feats['query_length']    = len(query)

    # === Count features ===
    feats['num_dots']           = full_url.count('.')
    feats['num_hyphens']        = full_url.count('-')
    feats['num_underscores']    = full_url.count('_')
    feats['num_slashes']        = full_url.count('/')
    feats['num_at_signs']       = full_url.count('@')
    feats['num_question_marks'] = full_url.count('?')
    feats['num_equals']         = full_url.count('=')
    feats['num_ampersands']     = full_url.count('&')
    feats['num_percent']        = full_url.count('%')
    feats['num_digits']         = sum(c.isdigit() for c in full_url)
    feats['num_letters']        = sum(c.isalpha() for c in full_url)
    feats['num_special_chars']  = sum(not c.isalnum() and c not in ('/', '.', ':') for c in full_url)
    feats['num_subdomains']     = len(subdomain.split('.')) if subdomain else 0
    feats['num_query_params']   = len(urllib.parse.parse_qs(query))

    # === Boolean / flag features ===
    feats['has_https']               = int(scheme == 'https')
    feats['has_ip_address']          = int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname)))
    feats['has_port']                = int(':' in netloc and netloc.split(':')[-1].isdigit())
    feats['has_at_sign']             = int('@' in full_url)
    feats['has_double_slash_in_path'] = int('//' in path)
    feats['has_hex_encoding']        = int('%' in full_url and bool(re.search(r'%[0-9a-fA-F]{2}', full_url)))

    # Brand name in SUBDOMAIN (not the registered domain itself)
    # e.g. paypal.secure-login.tk → brand in subdomain → suspicious
    # vs   paypal.com              → brand IS the domain → fine
    brand_in_subdomain = int(
        any(b in subdomain.lower() for b in BRAND_KEYWORDS)
        and domain not in TRUSTED_DOMAINS
    )
    feats['domain_in_subdomain'] = brand_in_subdomain

    feats['is_trusted_domain'] = int(domain in TRUSTED_DOMAINS)

    # === Entropy ===
    feats['url_entropy']      = round(shannon_entropy(full_url), 4)
    feats['hostname_entropy'] = round(shannon_entropy(hostname), 4)
    feats['path_entropy']     = round(shannon_entropy(path), 4)

    # === Heuristic / semantic features ===
    # Suspicious action words
    feats['num_suspicious_keywords'] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    feats['is_high_risk_tld']        = int(tld.lower() in HIGH_RISK_TLDS)

    # Ratio features
    total_chars            = len(full_url) or 1
    feats['digit_ratio']  = feats['num_digits']  / total_chars
    feats['letter_ratio'] = feats['num_letters'] / total_chars

    return feats


def get_feature_names() -> List[str]:
    """Return the ordered list of feature names."""
    sample = extract_features('http://example.com/path?q=test')
    return list(sample.keys())


def features_to_vector(url: str) -> list:
    """Return features as an ordered list (for model input)."""
    feats = extract_features(url)
    return list(feats.values())


def get_threat_keywords_found(url: str) -> list:
    """Return which suspicious keywords were found in the URL."""
    url_lower = url.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    # Also check brand names in subdomain context
    try:
        if not url.startswith(('http://', 'https://')):
            url_p = 'http://' + url
        else:
            url_p = url
        parsed = urllib.parse.urlparse(url_p)
        hostname = parsed.netloc.split(':')[0].lower()
        parts = hostname.split('.')
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
        if domain not in TRUSTED_DOMAINS:
            found += [b for b in BRAND_KEYWORDS if b in subdomain.lower()]
            found += [b for b in BRAND_KEYWORDS if b in (parsed.path or '').lower()]
    except Exception:
        pass
    return list(set(found))


if __name__ == '__main__':
    test_urls = [
        ('https://www.google.com',                       'benign'),
        ('https://amazon.com/checkout/cart',              'benign'),
        ('http://paypal-login-verify.tk/update?id=123',  'phishing'),
        ('http://192.168.1.1/admin/panel',               'malware'),
        ('https://amazon-secure.xyz/checkout',           'phishing'),
        ('http://apple.secureID-login.ml/verify',        'phishing'),
    ]
    for u, expected in test_urls:
        feats = extract_features(u)
        print(f'\n[expected={expected}]  {u}')
        print(f'  trusted_domain:      {bool(feats["is_trusted_domain"])}')
        print(f'  suspicious_keywords: {feats["num_suspicious_keywords"]}')
        print(f'  high_risk_tld:       {bool(feats["is_high_risk_tld"])}')
        print(f'  brand_in_subdomain:  {bool(feats["domain_in_subdomain"])}')
        print(f'  has_https:           {bool(feats["has_https"])}')
        print(f'  url_entropy:         {feats["url_entropy"]}')
