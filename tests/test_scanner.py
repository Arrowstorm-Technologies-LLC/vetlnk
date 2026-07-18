from vetlnk import scanner
from vetlnk.models import DnsblResult, DomainInfo


def test_normalize_adds_https_when_scheme_missing():
    normalized, note = scanner._normalize_url("arrowstorm.xyz")
    assert normalized == "https://arrowstorm.xyz"
    assert note is not None and "arrowstorm.xyz" in note


def test_normalize_adds_https_for_bare_host_with_path():
    normalized, note = scanner._normalize_url("arrowstorm.xyz/path?q=1")
    assert normalized == "https://arrowstorm.xyz/path?q=1"
    assert note is not None


def test_normalize_leaves_explicit_http_scheme_alone():
    normalized, note = scanner._normalize_url("http://arrowstorm.xyz")
    assert normalized == "http://arrowstorm.xyz"
    assert note is None


def test_normalize_leaves_explicit_https_scheme_alone():
    normalized, note = scanner._normalize_url("https://arrowstorm.xyz")
    assert normalized == "https://arrowstorm.xyz"
    assert note is None


def test_normalize_does_not_mangle_a_non_http_scheme():
    normalized, note = scanner._normalize_url("ftp://arrowstorm.xyz")
    assert normalized == "ftp://arrowstorm.xyz"
    assert note is None


def test_scan_url_normalizes_bare_domain_before_scanning(monkeypatch):
    captured_urls = {}

    def _fake_follow_redirects(url, client=None):
        captured_urls["redirects"] = url
        return []

    def _fake_lookup_domain_age(domain):
        captured_urls["whois_domain"] = domain
        return DomainInfo(domain=domain)

    def _fake_check_domain(domain):
        captured_urls["dnsbl_domain"] = domain
        return [DnsblResult(list_name="test", listed=False)]

    monkeypatch.setattr(scanner, "follow_redirects", _fake_follow_redirects)
    monkeypatch.setattr(scanner.whois_lookup, "lookup_domain_age", _fake_lookup_domain_age)
    monkeypatch.setattr(scanner.dnsbl, "check_domain", _fake_check_domain)

    result = scanner.scan_url("arrowstorm.xyz")

    assert captured_urls["redirects"] == "https://arrowstorm.xyz"
    assert captured_urls["whois_domain"] == "arrowstorm.xyz"
    assert captured_urls["dnsbl_domain"] == "arrowstorm.xyz"
    assert result.final_url == "https://arrowstorm.xyz"
    assert any("assuming https://" in err for err in result.scan_errors)
