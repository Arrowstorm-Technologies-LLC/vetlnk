from rich.console import Console
from typer.testing import CliRunner

from vetlnk import cli
from vetlnk.models import DetonationResult, FileInfo, ScanResult

runner = CliRunner()


def _fake_result(with_file: bool = True) -> ScanResult:
    result = ScanResult(input_url="https://example.com/file")
    if with_file:
        result.file_info = FileInfo(
            declared_filename="payload.exe",
            declared_content_type="application/octet-stream",
            content_length=1024,
            true_type="application/x-dosexec",
        )
    return result


def test_should_detonate_true_when_flag_passed():
    result = _fake_result(with_file=False)
    assert cli._should_detonate(None, result, detonate_flag=True) is True


def test_should_detonate_false_when_no_file():
    result = _fake_result(with_file=False)
    assert cli._should_detonate(None, result, detonate_flag=False) is False
    assert result.scan_errors == []


def test_should_detonate_skips_prompt_when_not_interactive(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    result = _fake_result(with_file=True)

    assert cli._should_detonate(Console(), result, detonate_flag=False) is False
    assert any("not running interactively" in e for e in result.scan_errors)


def test_should_detonate_prompts_and_honors_yes(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    result = _fake_result(with_file=True)

    assert cli._should_detonate(Console(), result, detonate_flag=False) is True


def test_should_detonate_prompts_and_honors_no(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: False)
    result = _fake_result(with_file=True)

    assert cli._should_detonate(Console(), result, detonate_flag=False) is False


def test_scan_command_skips_detonation_prompt_when_noninteractive(monkeypatch):
    monkeypatch.setattr(cli, "scan_url", lambda url, **kwargs: _fake_result())
    monkeypatch.setattr(cli, "run_enhanced_checks", lambda result, **kwargs: None)

    result = runner.invoke(cli.app, ["scan", "https://example.com/file.exe"])
    assert result.exit_code == 0, result.output
    assert "not running interactively" in result.output.lower()


def test_scan_command_auto_detonates_with_flag_no_prompt(monkeypatch):
    called = {}

    def fake_run_detonation(result):
        called["ran"] = True
        return DetonationResult(attempted=True, backend="docker-static", verdict="clean")

    monkeypatch.setattr(cli, "scan_url", lambda url, **kwargs: _fake_result())
    monkeypatch.setattr(cli, "run_enhanced_checks", lambda result, **kwargs: None)
    monkeypatch.setattr(cli, "run_detonation", fake_run_detonation)

    result = runner.invoke(cli.app, ["scan", "https://example.com/file.exe", "--detonate"])
    assert result.exit_code == 0, result.output
    assert called.get("ran") is True


def test_scan_command_no_file_no_prompt(monkeypatch):
    monkeypatch.setattr(cli, "scan_url", lambda url, **kwargs: _fake_result(with_file=False))
    monkeypatch.setattr(cli, "run_enhanced_checks", lambda result, **kwargs: None)

    result = runner.invoke(cli.app, ["scan", "https://example.com/"])
    assert result.exit_code == 0, result.output
    assert "detonate" not in result.output.lower()
