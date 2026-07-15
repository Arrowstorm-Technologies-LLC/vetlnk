import json

from rich.console import Console

from vetlnk.models import DnsblResult, DomainInfo, Hop, RiskLevel, ScanResult
from vetlnk.report import render_terminal, to_dict, write_json, write_markdown


def _sample_result() -> ScanResult:
    result = ScanResult(
        input_url="https://example.com/",
        final_url="https://example.com/",
        hops=[
            Hop(
                url="https://example.com/",
                status_code=200,
                headers={},
                elapsed_ms=12.3,
                ip="203.0.113.5",
            )
        ],
        domain_info=DomainInfo(domain="example.com", registered_on="2000-01-01", age_days=9000),
        dnsbl_results=[DnsblResult(list_name="Spamhaus DBL", listed=False)],
        risk_level=RiskLevel.CLEAN,
        risk_reasons=["No notable risk signals detected."],
    )
    return result


def test_render_terminal_does_not_raise():
    console = Console(record=True, width=100)
    render_terminal(_sample_result(), console)
    output = console.export_text()
    assert "Clean" in output
    assert "example.com" in output


def test_to_dict_serializes_enum_as_string():
    data = to_dict(_sample_result())
    assert data["risk_level"] == "Clean"
    assert isinstance(data["risk_level"], str)


def test_write_json_produces_valid_json(tmp_path):
    path = tmp_path / "report.json"
    write_json([_sample_result()], str(path))
    payload = json.loads(path.read_text())
    assert len(payload) == 1
    assert payload[0]["risk_level"] == "Clean"
    assert payload[0]["input_url"] == "https://example.com/"


def test_write_markdown_contains_expected_sections(tmp_path):
    path = tmp_path / "report.md"
    write_markdown([_sample_result()], str(path))
    text = path.read_text()
    assert "# vetlnk report" in text
    assert "**Risk level:** Clean" in text
    assert "example.com" in text
