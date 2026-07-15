"""Local, zero-network heuristics run against the redirect chain and final URL."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

from vetlnk.models import HeuristicFinding, Hop

# A small starter list of commonly-spoofed brands for homoglyph/typosquat checks.
# Not exhaustive by design — this is a fast local signal, not a full brand database.
COMMONLY_SPOOFED_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal", "netflix", "facebook",
    "instagram", "bankofamerica", "wellsfargo", "chase", "citibank", "coinbase",
    "binance", "steam", "discord", "twitter", "linkedin", "adobe", "dropbox",
    "github", "outlook", "office365", "docusign", "irs", "usps", "fedex", "dhl",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "gq", "cf", "tk", "ml", "ga", "work", "click",
    "link", "loan", "download", "review", "country", "kim", "science", "party",
}

SUSPICIOUS_QUERY_PARAM_KEYS = {
    "token", "auth", "session", "verify", "redirect", "url", "return", "next",
    "continue", "login", "password", "otp",
}

MAX_REASONABLE_REDIRECT_DEPTH = 4


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _check_punycode_homoglyph(host: str) -> HeuristicFinding:
    if host.startswith("xn--") or ".xn--" in host:
        return HeuristicFinding(
            name="punycode_domain",
            triggered=True,
            detail=f"Host contains punycode-encoded label ({host}) — often used to spoof "
            "look-alike brand domains with non-ASCII characters.",
            severity="high",
        )
    return HeuristicFinding(name="punycode_domain", triggered=False)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            curr[j] = min(
                prev[j] + 1,  # deletion
                curr[j - 1] + 1,  # insertion
                prev[j - 1] + (ca != cb),  # substitution
            )
        prev = curr
    return prev[-1]


def _check_brand_lookalike(host: str) -> HeuristicFinding:
    labels = host.lower().split(".")
    registrable_raw = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
    registrable = registrable_raw.replace("-", "")
    tokens = registrable_raw.split("-") + [registrable]

    for brand in COMMONLY_SPOOFED_BRANDS:
        if brand == registrable:
            continue
        if brand in registrable and len(registrable) <= len(brand) + 4:
            return HeuristicFinding(
                name="brand_lookalike",
                triggered=True,
                detail=f"Domain '{host}' embeds brand name '{brand}' but isn't the brand's "
                "own domain — a common phishing pattern.",
                severity="medium",
            )
        for token in tokens:
            if token == brand or not token:
                continue
            # Catches single-character typosquats like "paypa1" (digit for letter),
            # "gooogle" (doubled letter), "microsft" (dropped letter) — distance-1 only,
            # so it doesn't fire on unrelated short words that merely resemble a brand.
            if abs(len(token) - len(brand)) <= 1 and _levenshtein(token, brand) == 1:
                return HeuristicFinding(
                    name="brand_lookalike",
                    triggered=True,
                    detail=f"Domain '{host}' looks like a one-character typosquat of "
                    f"'{brand}' — a common phishing pattern.",
                    severity="medium",
                )
    return HeuristicFinding(name="brand_lookalike", triggered=False)


def _check_suspicious_tld(host: str) -> HeuristicFinding:
    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        return HeuristicFinding(
            name="suspicious_tld",
            triggered=True,
            detail=f"TLD '.{tld}' is disproportionately used for abuse/phishing campaigns.",
            severity="low",
        )
    return HeuristicFinding(name="suspicious_tld", triggered=False)


def _check_ip_literal(host: str) -> HeuristicFinding:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return HeuristicFinding(name="ip_literal_url", triggered=False)
    return HeuristicFinding(
        name="ip_literal_url",
        triggered=True,
        detail=f"URL uses a raw IP address ({host}) instead of a domain name — legitimate "
        "sites rarely link directly to IPs.",
        severity="medium",
    )


def _check_redirect_depth(hops: list[Hop]) -> HeuristicFinding:
    depth = len(hops) - 1
    if depth > MAX_REASONABLE_REDIRECT_DEPTH:
        return HeuristicFinding(
            name="excessive_redirect_depth",
            triggered=True,
            detail=f"{depth} redirect hops before landing — chains this long are often used "
            "to evade link scanners or obscure the final destination.",
            severity="medium",
        )
    return HeuristicFinding(name="excessive_redirect_depth", triggered=False)


def _check_url_entropy(url: str) -> HeuristicFinding:
    path_and_query = urlsplit(url).path + urlsplit(url).query
    entropy = _shannon_entropy(path_and_query)
    if entropy > 4.2 and len(path_and_query) > 20:
        return HeuristicFinding(
            name="high_url_entropy",
            triggered=True,
            detail=f"Path/query has high entropy ({entropy:.2f} bits/char) — consistent with "
            "randomly-generated tracking or payload-hiding paths.",
            severity="low",
        )
    return HeuristicFinding(name="high_url_entropy", triggered=False)


def _check_query_params(url: str) -> HeuristicFinding:
    params = dict(parse_qsl(urlsplit(url).query))
    hits = [k for k in params if k.lower() in SUSPICIOUS_QUERY_PARAM_KEYS]
    if hits:
        return HeuristicFinding(
            name="suspicious_query_params",
            triggered=True,
            detail=f"Query string carries sensitive-sounding parameter(s): {', '.join(hits)}.",
            severity="low",
        )
    return HeuristicFinding(name="suspicious_query_params", triggered=False)


_AT_SIGN_RE = re.compile(r"://[^/]*@")


def _check_userinfo_obfuscation(url: str) -> HeuristicFinding:
    if _AT_SIGN_RE.search(url):
        return HeuristicFinding(
            name="userinfo_obfuscation",
            triggered=True,
            detail="URL embeds an '@' before the host — everything before it is ignored by "
            "browsers and commonly used to disguise the real destination.",
            severity="high",
        )
    return HeuristicFinding(name="userinfo_obfuscation", triggered=False)


def run_heuristics(final_url: str, hops: list[Hop]) -> list[HeuristicFinding]:
    host = urlsplit(final_url).hostname or ""
    findings = [
        _check_punycode_homoglyph(host),
        _check_brand_lookalike(host),
        _check_suspicious_tld(host),
        _check_ip_literal(host),
        _check_redirect_depth(hops),
        _check_url_entropy(final_url),
        _check_query_params(final_url),
        _check_userinfo_obfuscation(final_url),
    ]
    return findings
