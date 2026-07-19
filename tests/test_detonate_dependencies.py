"""Tests for the Docker dependency-detection/install/confirm flow added so
detonation works with no API key: if Docker itself isn't ready, vetlnk asks
before installing/starting it (Linux only — see `detonate._install_docker`)
and falls back to a sudo-wrapped `docker` CLI for the one run right after a
fresh install, since a new `docker` group membership needs a new login to
take effect.
"""

import subprocess

from vetlnk import detonate
from vetlnk.models import ScanResult


def _completed(returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(
        args=["docker"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_missing_deps_none_when_docker_cli_present_and_working(monkeypatch):
    monkeypatch.setattr(detonate.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(detonate.subprocess, "run", lambda *a, **k: _completed(returncode=0))

    assert detonate._detect_missing_docker_deps() is None


def test_missing_deps_cli_absent(monkeypatch):
    monkeypatch.setattr(detonate.shutil, "which", lambda name: None)
    monkeypatch.setattr(detonate.platform, "system", lambda: "Linux")

    missing = detonate._detect_missing_docker_deps()
    assert missing is not None
    assert missing.auto_fixable is True
    assert any("not installed" in item for item in missing.items)


def test_missing_deps_cli_absent_not_auto_fixable_on_macos(monkeypatch):
    monkeypatch.setattr(detonate.shutil, "which", lambda name: None)
    monkeypatch.setattr(detonate.platform, "system", lambda: "Darwin")

    missing = detonate._detect_missing_docker_deps()
    assert missing is not None
    assert missing.auto_fixable is False


def test_missing_deps_permission_denied(monkeypatch):
    monkeypatch.setattr(detonate.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(detonate.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        detonate.subprocess,
        "run",
        lambda *a, **k: _completed(returncode=1, stderr=b"permission denied"),
    )

    missing = detonate._detect_missing_docker_deps()
    assert missing is not None
    assert any("group membership" in item for item in missing.items)


def test_missing_deps_daemon_not_running(monkeypatch):
    monkeypatch.setattr(detonate.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(detonate.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        detonate.subprocess,
        "run",
        lambda *a, **k: _completed(returncode=1, stderr=b"Cannot connect to the Docker daemon"),
    )

    missing = detonate._detect_missing_docker_deps()
    assert missing is not None
    assert any("not running" in item for item in missing.items)


def test_confirm_dependency_install_calls_typer_confirm(monkeypatch):
    monkeypatch.setattr(detonate.typer, "confirm", lambda *a, **k: True)
    assert detonate._confirm_dependency_install(["Docker Engine (not installed)"]) is True

    monkeypatch.setattr(detonate.typer, "confirm", lambda *a, **k: False)
    assert detonate._confirm_dependency_install(["Docker Engine (not installed)"]) is False


def test_install_docker_refuses_on_non_linux(monkeypatch):
    monkeypatch.setattr(detonate.platform, "system", lambda: "Darwin")
    ok, err = detonate._install_docker()
    assert ok is False
    assert "Linux" in err


def test_install_docker_fails_when_sudo_not_granted(monkeypatch):
    monkeypatch.setattr(detonate.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detonate.subprocess, "run", lambda cmd, **k: _completed(returncode=1))
    ok, err = detonate._install_docker()
    assert ok is False
    assert "sudo" in err.lower()


def test_install_docker_fails_when_no_package_manager_found(monkeypatch):
    monkeypatch.setattr(detonate.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detonate.subprocess, "run", lambda cmd, **k: _completed(returncode=0))
    monkeypatch.setattr(detonate.shutil, "which", lambda name: None)
    ok, err = detonate._install_docker()
    assert ok is False
    assert "package manager" in err.lower()


def test_install_docker_happy_path_installs_enables_and_adds_group(monkeypatch):
    calls = []

    def fake_which(name):
        return "/usr/bin/" + name if name in ("pacman", "systemctl") else None

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _completed(returncode=0)

    monkeypatch.setattr(detonate.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detonate.shutil, "which", fake_which)
    monkeypatch.setattr(detonate.subprocess, "run", fake_run)

    ok, err = detonate._install_docker()
    assert ok is True
    assert err is None

    # sudo -v priming, pacman install, systemctl enable --now, usermod -aG
    joined = [" ".join(c) for c in calls]
    assert any("sudo -v" == c for c in joined)
    assert any("pacman" in c and "docker" in c for c in joined)
    assert any("systemctl enable --now docker" in c for c in joined)
    assert any("usermod -aG docker" in c for c in joined)


def test_install_docker_stops_if_package_install_fails(monkeypatch):
    def fake_which(name):
        return "/usr/bin/" + name if name == "pacman" else None

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "pacman" in cmd:
            return _completed(returncode=1)  # install fails
        return _completed(returncode=0)

    monkeypatch.setattr(detonate.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detonate.shutil, "which", fake_which)
    monkeypatch.setattr(detonate.subprocess, "run", fake_run)

    ok, err = detonate._install_docker()
    assert ok is False
    assert "pacman" in err
    # Should not have gone on to try enabling the service.
    assert not any("systemctl" in " ".join(c) for c in calls)


def test_run_docker_static_analysis_cli_uses_hardened_flags(tmp_path, monkeypatch):
    sample = tmp_path / "sample"
    sample.write_bytes(b"dummy")

    captured = {}

    def fake_docker_cli(args, *, sudo, timeout=None, capture=True):
        if args[0] == "run":
            captured["args"] = args
            captured["sudo"] = sudo
            return _completed(returncode=0, stdout=b'{"ok": true}')
        # ps -aq sweep call
        return _completed(returncode=0, stdout=b"")

    monkeypatch.setattr(detonate, "_docker_cli", fake_docker_cli)

    result = detonate._run_docker_static_analysis_cli(sample, sudo=True)
    assert result == {"ok": True}

    args = captured["args"]
    assert captured["sudo"] is True
    assert "--network" in args and args[args.index("--network") + 1] == "none"
    assert "--read-only" in args
    assert "--user" in args and args[args.index("--user") + 1] == detonate._ANALYZER_USER
    assert "--cap-drop" in args and args[args.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in args
    assert "no-new-privileges:true" in args
    assert "--memory" in args and args[args.index("--memory") + 1] == detonate._ANALYZER_MEM_LIMIT
    assert "--pids-limit" in args
    assert "--rm" in args
    assert args[-3:] == ["python", "/analyze.py", f"/data/{sample.name}"]


def test_run_docker_static_analysis_cli_returns_none_on_nonzero_exit(tmp_path, monkeypatch):
    sample = tmp_path / "sample"
    sample.write_bytes(b"dummy")

    def fake_docker_cli(args, *, sudo, timeout=None, capture=True):
        if args[0] == "run":
            return _completed(returncode=1)
        return _completed(returncode=0, stdout=b"")

    monkeypatch.setattr(detonate, "_docker_cli", fake_docker_cli)
    assert detonate._run_docker_static_analysis_cli(sample, sudo=True) is None


def test_run_docker_static_analysis_cli_returns_none_on_malformed_json(tmp_path, monkeypatch):
    sample = tmp_path / "sample"
    sample.write_bytes(b"dummy")

    def fake_docker_cli(args, *, sudo, timeout=None, capture=True):
        if args[0] == "run":
            return _completed(returncode=0, stdout=b"not json")
        return _completed(returncode=0, stdout=b"")

    monkeypatch.setattr(detonate, "_docker_cli", fake_docker_cli)
    assert detonate._run_docker_static_analysis_cli(sample, sudo=True) is None


def test_sweep_orphaned_containers_cli_kills_and_removes(monkeypatch):
    calls = []

    def fake_docker_cli(args, *, sudo, timeout=None, capture=True):
        calls.append(args)
        if args[:2] == ["ps", "-aq"]:
            return _completed(returncode=0, stdout=b"abc123\n")
        return _completed(returncode=0)

    monkeypatch.setattr(detonate, "_docker_cli", fake_docker_cli)
    detonate._sweep_orphaned_containers_cli("some-run-id", sudo=True)

    assert ["kill", "abc123"] in calls
    assert ["rm", "-f", "abc123"] in calls


def test_ensure_analyzer_image_cli_skips_build_when_hash_matches(monkeypatch):
    monkeypatch.setattr(detonate, "_compute_build_hash", lambda build_dir: "abc123")
    build_calls = []

    def fake_docker_cli(args, *, sudo, timeout=None, capture=True):
        if args[0] == "build":
            build_calls.append(args)
            return _completed(returncode=0)
        assert args[:2] == ["image", "inspect"]
        return _completed(returncode=0, stdout=b"abc123")

    monkeypatch.setattr(detonate, "_docker_cli", fake_docker_cli)
    assert detonate._ensure_analyzer_image_cli(sudo=True) is True
    assert build_calls == []


def test_ensure_analyzer_image_cli_rebuilds_when_hash_differs(monkeypatch):
    monkeypatch.setattr(detonate, "_compute_build_hash", lambda build_dir: "new-hash")
    build_calls = []

    def fake_docker_cli(args, *, sudo, timeout=None, capture=True):
        if args[0] == "build":
            build_calls.append(args)
            return _completed(returncode=0)
        assert args[:2] == ["image", "inspect"]
        return _completed(returncode=0, stdout=b"stale-hash")

    monkeypatch.setattr(detonate, "_docker_cli", fake_docker_cli)
    assert detonate._ensure_analyzer_image_cli(sudo=True) is True
    assert len(build_calls) == 1
    assert "vetlnk.analyzer-build-hash=new-hash" in build_calls[0]


def test_ensure_analyzer_image_cli_rebuilds_when_no_image_yet(monkeypatch):
    monkeypatch.setattr(detonate, "_compute_build_hash", lambda build_dir: "new-hash")
    build_calls = []

    def fake_docker_cli(args, *, sudo, timeout=None, capture=True):
        if args[0] == "build":
            build_calls.append(args)
            return _completed(returncode=0)
        assert args[:2] == ["image", "inspect"]
        return _completed(returncode=1)  # no such image yet

    monkeypatch.setattr(detonate, "_docker_cli", fake_docker_cli)
    assert detonate._ensure_analyzer_image_cli(sudo=True) is True
    assert len(build_calls) == 1


def test_run_detonation_prompts_and_cancels_on_no(monkeypatch):
    result = ScanResult(input_url="http://example.com/f.exe")
    from vetlnk.models import FileInfo

    result.file_info = FileInfo(
        declared_filename="f.exe", declared_content_type=None, content_length=None, true_type="x"
    )

    monkeypatch.setattr(detonate, "resolve_key", lambda provider_id: None)
    monkeypatch.setattr(detonate, "_docker_client", lambda: None)
    monkeypatch.setattr(detonate.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        detonate,
        "_detect_missing_docker_deps",
        lambda: detonate._MissingDockerDeps(
            items=["Docker Engine (not installed)"], auto_fixable=True
        ),
    )
    monkeypatch.setattr(detonate, "_confirm_dependency_install", lambda items: False)

    outcome = detonate.run_detonation(result)
    assert outcome.attempted is True
    assert outcome.backend is None
    assert "cancelled" in outcome.refused_reason.lower()


def test_run_detonation_skips_prompt_when_noninteractive(monkeypatch):
    result = ScanResult(input_url="http://example.com/f.exe")
    from vetlnk.models import FileInfo

    result.file_info = FileInfo(
        declared_filename="f.exe", declared_content_type=None, content_length=None, true_type="x"
    )

    monkeypatch.setattr(detonate, "resolve_key", lambda provider_id: None)
    monkeypatch.setattr(detonate, "_docker_client", lambda: None)
    monkeypatch.setattr(detonate.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(
        detonate,
        "_detect_missing_docker_deps",
        lambda: detonate._MissingDockerDeps(
            items=["Docker Engine (not installed)"], auto_fixable=True
        ),
    )

    confirm_called = []

    def fake_confirm(items):
        confirm_called.append(items)
        return False

    monkeypatch.setattr(detonate, "_confirm_dependency_install", fake_confirm)

    outcome = detonate.run_detonation(result)
    assert confirm_called == []
    assert outcome.attempted is True
    assert "non-interactively" in outcome.refused_reason.lower()


def test_run_detonation_falls_back_to_sudo_cli_after_fresh_install(monkeypatch, tmp_path):
    result = ScanResult(input_url="http://example.com/f.exe")
    from vetlnk.models import FileInfo

    result.file_info = FileInfo(
        declared_filename="f.exe", declared_content_type=None, content_length=None, true_type="x"
    )
    result.final_url = "http://example.com/f.exe"

    monkeypatch.setattr(detonate, "resolve_key", lambda provider_id: None)
    monkeypatch.setattr(detonate, "_docker_client", lambda: None)  # never becomes available via SDK
    monkeypatch.setattr(detonate.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        detonate,
        "_detect_missing_docker_deps",
        lambda: detonate._MissingDockerDeps(
            items=["Docker Engine (not installed)"], auto_fixable=True
        ),
    )
    monkeypatch.setattr(detonate, "_confirm_dependency_install", lambda items: True)
    monkeypatch.setattr(detonate, "_install_docker", lambda: (True, None))
    monkeypatch.setattr(detonate, "_ensure_analyzer_image_cli", lambda *, sudo: True)
    monkeypatch.setattr(
        detonate,
        "_download_for_detonation",
        lambda url: (tmp_path / "sample", "deadbeef", 4),
    )
    (tmp_path / "sample").write_bytes(b"dummy")
    monkeypatch.setattr(
        detonate,
        "_run_docker_static_analysis_cli",
        lambda path, *, sudo: {"yara_matches": []},
    )
    monkeypatch.setattr(detonate, "_secure_delete", lambda path: None)

    outcome = detonate.run_detonation(result)
    assert outcome.attempted is True
    assert outcome.backend == "docker-static"
    assert outcome.verdict == "no static rule matches"
    assert any("sudo" in e.lower() for e in result.scan_errors)
