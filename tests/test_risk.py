from vetlnk.models import (
    DnsblResult,
    DomainInfo,
    FileInfo,
    HeuristicFinding,
    Hop,
    RiskLevel,
    ScanResult,
)
from vetlnk.risk import synthesize_risk


def _base_result(url="https://example.com/") -> ScanResult:
    hop = Hop(url=url, status_code=200, headers={}, elapsed_ms=5)
    return ScanResult(input_url=url, final_url=url, hops=[hop])


def test_no_signals_is_unknown_not_clean():
    result = ScanResult(input_url="https://example.com/")
    synthesize_risk(result)
    assert result.risk_level == RiskLevel.UNKNOWN


def test_clean_when_only_negative_signals_present():
    result = _base_result()
    result.domain_info = DomainInfo(domain="example.com", registered_on="2000-01-01", age_days=9000)
    result.dnsbl_results = [DnsblResult(list_name="Spamhaus DBL", listed=False)]
    synthesize_risk(result)
    assert result.risk_level == RiskLevel.CLEAN


def test_dnsbl_listing_pushes_to_high_risk():
    result = _base_result()
    result.dnsbl_results = [DnsblResult(list_name="Spamhaus DBL", listed=True, detail="127.0.1.4")]
    synthesize_risk(result)
    assert result.risk_level == RiskLevel.HIGH
    assert any("Spamhaus DBL" in r for r in result.risk_reasons)


def test_fresh_domain_raises_risk():
    result = _base_result()
    result.domain_info = DomainInfo(domain="example.com", registered_on="2026-07-10", age_days=2)
    synthesize_risk(result)
    assert result.risk_level in (RiskLevel.LOW, RiskLevel.SUSPICIOUS, RiskLevel.HIGH)
    assert result.risk_level != RiskLevel.CLEAN


def test_file_type_mismatch_pushes_to_high_risk():
    result = _base_result()
    result.file_info = FileInfo(
        declared_filename="invoice.pdf",
        declared_content_type="application/pdf",
        content_length=51200,
        true_type="Windows PE executable (.exe/.dll/.scr/.com)",
        type_mismatch=True,
        risk_note="This is a Windows executable.",
    )
    synthesize_risk(result)
    assert result.risk_level == RiskLevel.HIGH


def test_heuristic_severity_weights_accumulate():
    result = _base_result()
    result.heuristics = [
        HeuristicFinding(name="ip_literal_url", triggered=True, detail="raw IP", severity="medium"),
        HeuristicFinding(name="suspicious_tld", triggered=True, detail="bad tld", severity="low"),
    ]
    synthesize_risk(result)
    assert result.risk_level in (RiskLevel.LOW, RiskLevel.SUSPICIOUS)
    assert len(result.risk_reasons) == 2
