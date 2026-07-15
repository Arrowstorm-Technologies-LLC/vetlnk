from vetlnk.heuristics import run_heuristics
from vetlnk.models import Hop


def _hop(url: str) -> Hop:
    return Hop(url=url, status_code=200, headers={}, elapsed_ms=10)


def _triggered(findings, name):
    return next(f for f in findings if f.name == name).triggered


def test_ip_literal_url_flagged():
    findings = run_heuristics("http://8.8.8.8/path", [_hop("http://8.8.8.8/path")])
    assert _triggered(findings, "ip_literal_url")


def test_normal_domain_not_flagged_as_ip():
    findings = run_heuristics("https://example.com/", [_hop("https://example.com/")])
    assert not _triggered(findings, "ip_literal_url")


def test_punycode_domain_flagged():
    findings = run_heuristics(
        "https://xn--pypal-4ve.com/login", [_hop("https://xn--pypal-4ve.com/login")]
    )
    assert _triggered(findings, "punycode_domain")


def test_brand_lookalike_flagged():
    findings = run_heuristics(
        "https://paypa1-secure.tk/", [_hop("https://paypa1-secure.tk/")]
    )
    assert _triggered(findings, "brand_lookalike")


def test_brand_own_domain_not_flagged():
    findings = run_heuristics("https://paypal.com/", [_hop("https://paypal.com/")])
    assert not _triggered(findings, "brand_lookalike")


def test_suspicious_tld_flagged():
    findings = run_heuristics("https://freebies.zip/", [_hop("https://freebies.zip/")])
    assert _triggered(findings, "suspicious_tld")


def test_excessive_redirect_depth_flagged():
    hops = [_hop(f"https://example.com/{i}") for i in range(6)]
    findings = run_heuristics(hops[-1].url, hops)
    assert _triggered(findings, "excessive_redirect_depth")


def test_shallow_redirect_depth_not_flagged():
    hops = [_hop("https://example.com/a"), _hop("https://example.com/b")]
    findings = run_heuristics(hops[-1].url, hops)
    assert not _triggered(findings, "excessive_redirect_depth")


def test_suspicious_query_params_flagged():
    url = "https://example.com/reset?token=abc123&next=/account"
    findings = run_heuristics(url, [_hop(url)])
    assert _triggered(findings, "suspicious_query_params")


def test_userinfo_obfuscation_flagged():
    url = "https://real-bank.com@evil.example/phish"
    findings = run_heuristics(url, [_hop(url)])
    assert _triggered(findings, "userinfo_obfuscation")


def test_high_entropy_path_flagged():
    url = "https://example.com/a8x2kZ9pQmR7vT3nL5cW1eY6uI0oP4sD8fG2hJ6kM9nB3vC7x"
    findings = run_heuristics(url, [_hop(url)])
    assert _triggered(findings, "high_url_entropy")


def test_clean_url_triggers_nothing():
    url = "https://example.com/about"
    findings = run_heuristics(url, [_hop(url)])
    assert not any(f.triggered for f in findings)
