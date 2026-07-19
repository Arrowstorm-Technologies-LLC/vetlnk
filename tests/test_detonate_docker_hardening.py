"""Regression tests for the Docker detonation path's isolation guarantees.

These don't need a live Docker daemon — they intercept the exact kwargs
`vetlnk` passes to the docker SDK and assert the hardening flags are really
there, so a future edit can't silently drop --network none, the non-root
user, the resource limits, or the wall-clock timeout without a test failing.
"""

import docker.errors
import pytest

from vetlnk import detonate


class _FakeContainer:
    def __init__(self):
        self.killed = False
        self.removed = False

    def kill(self):
        self.killed = True

    def remove(self, force=False):
        self.removed = True


class _FakeContainers:
    def __init__(self, output=b'{"ok": true}', raise_exc=None, lingering=None):
        self.run_calls = []
        self._output = output
        self._raise_exc = raise_exc
        self._lingering = lingering or []

    def run(self, image, **kwargs):
        self.run_calls.append((image, kwargs))
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._output

    def list(self, all=False, filters=None):  # noqa: A002 - matches docker-py's signature
        return self._lingering


class _FakeImage:
    def __init__(self, labels=None):
        self.labels = labels or {}


class _FakeImages:
    def __init__(self, existing=None):
        self._existing = existing  # a _FakeImage, or None if no image is cached yet
        self.build_calls = []

    def get(self, tag):
        if self._existing is None:
            raise Exception("no such image")  # noqa: TRY002 - stands in for docker.errors.ImageNotFound
        return self._existing

    def build(self, **kwargs):
        self.build_calls.append(kwargs)
        self._existing = _FakeImage(labels=kwargs.get("labels", {}))
        return (self._existing, iter([]))


class _FakeClient:
    def __init__(self, images_kwargs=None, **container_kwargs):
        self.containers = _FakeContainers(**container_kwargs)
        self.images = _FakeImages(**(images_kwargs or {}))


def test_docker_run_uses_hardened_isolation_flags(tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"dummy")
    client = _FakeClient()

    result = detonate._run_docker_static_analysis(client, sample)

    assert result == {"ok": True}
    assert len(client.containers.run_calls) == 1
    image, kwargs = client.containers.run_calls[0]

    assert image == detonate._ANALYZER_IMAGE

    # --network none (or equivalent)
    assert kwargs["network_mode"] == "none"

    # non-root user
    assert kwargs["user"] == detonate._ANALYZER_USER
    assert kwargs["user"] != "0:0"
    assert kwargs["user"] != "root"

    # read-only rootfs with exactly one host-backed scratch mount (the sample),
    # plus a non-persisted tmpfs for actual scratch space
    assert kwargs["read_only"] is True
    assert len(kwargs["volumes"]) == 1
    ((_host_dir, mount_spec),) = kwargs["volumes"].items()
    assert mount_spec["bind"] == "/data"
    assert mount_spec["mode"] == "ro"
    assert "/tmp" in kwargs["tmpfs"]
    assert "noexec" in kwargs["tmpfs"]["/tmp"]

    # resource limits
    assert kwargs["mem_limit"] == detonate._ANALYZER_MEM_LIMIT
    assert kwargs["memswap_limit"] == detonate._ANALYZER_MEM_LIMIT
    assert kwargs["nano_cpus"] == detonate._ANALYZER_NANO_CPUS
    assert kwargs["pids_limit"] == detonate._ANALYZER_PIDS_LIMIT

    # extra lockdown
    assert kwargs["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in kwargs["security_opt"]

    # daemon-side auto-remove, independent of the host process staying alive
    assert kwargs["remove"] is True

    # wall-clock cutoff baked into the command itself, not just a client-side timeout
    command = kwargs["command"]
    assert command[0] == "timeout"
    assert f"{detonate._CONTAINER_TIMEOUT_SECONDS}s" in command
    assert command[-2:] == ["python", "/analyze.py"] or "/analyze.py" in command


def test_container_error_returns_none_not_a_crash(tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"dummy")
    exc = docker.errors.ContainerError(
        container="fake-id", exit_status=124, command=["timeout"], image="img", stderr=None
    )
    client = _FakeClient(raise_exc=exc)

    result = detonate._run_docker_static_analysis(client, sample)

    assert result is None


def test_malformed_output_returns_none_not_a_crash(tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"dummy")
    client = _FakeClient(output=b"not json")

    result = detonate._run_docker_static_analysis(client, sample)

    assert result is None


def test_cleanup_sweep_kills_and_removes_lingering_containers(tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"dummy")
    lingering = _FakeContainer()
    client = _FakeClient(lingering=[lingering])

    detonate._run_docker_static_analysis(client, sample)

    assert lingering.killed is True
    assert lingering.removed is True


def test_cleanup_sweep_runs_even_when_run_raises(tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"dummy")
    lingering = _FakeContainer()
    exc = docker.errors.APIError("connection lost")
    client = _FakeClient(raise_exc=exc, lingering=[lingering])

    result = detonate._run_docker_static_analysis(client, sample)

    assert result is None
    assert lingering.killed is True
    assert lingering.removed is True


def test_analyzer_build_context_resolves_to_a_real_dockerfile():
    with detonate._analyzer_build_context() as path:
        assert path is not None
        assert path.is_dir()
        assert (path / "Dockerfile").exists()
        assert (path / "analyze.py").exists()
        assert (path / "rules" / "starter.yar").exists()


def test_dockerfile_declares_a_non_root_user():
    with detonate._analyzer_build_context() as path:
        dockerfile_text = (path / "Dockerfile").read_text()
    assert "USER 10001:10001" in dockerfile_text
    assert "10001" in dockerfile_text


def test_compute_build_hash_changes_when_content_changes(tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "Dockerfile").write_text("FROM a\n")
    (tmp_path / "rules" / "starter.yar").write_text("rule A { condition: true }")

    original = detonate._compute_build_hash(tmp_path)
    unchanged = detonate._compute_build_hash(tmp_path)
    assert original == unchanged, "hash must be deterministic for unchanged content"

    (tmp_path / "rules" / "starter.yar").write_text(
        "rule A { condition: true }\nrule B { condition: true }"
    )
    changed = detonate._compute_build_hash(tmp_path)
    assert changed != original, "hash must change when rule content changes"


def test_ensure_analyzer_image_skips_build_when_hash_matches(monkeypatch):
    monkeypatch.setattr(detonate, "_compute_build_hash", lambda build_dir: "abc123")
    client = _FakeClient(
        images_kwargs={"existing": _FakeImage(labels={detonate._BUILD_HASH_LABEL: "abc123"})}
    )

    assert detonate._ensure_analyzer_image(client) is True
    assert client.images.build_calls == []


def test_ensure_analyzer_image_rebuilds_when_hash_differs(monkeypatch):
    monkeypatch.setattr(detonate, "_compute_build_hash", lambda build_dir: "new-hash")
    client = _FakeClient(
        images_kwargs={"existing": _FakeImage(labels={detonate._BUILD_HASH_LABEL: "old-hash"})}
    )

    assert detonate._ensure_analyzer_image(client) is True
    assert len(client.images.build_calls) == 1
    assert client.images.build_calls[0]["labels"] == {detonate._BUILD_HASH_LABEL: "new-hash"}


def test_ensure_analyzer_image_builds_when_no_image_yet(monkeypatch):
    monkeypatch.setattr(detonate, "_compute_build_hash", lambda build_dir: "new-hash")
    client = _FakeClient(images_kwargs={"existing": None})

    assert detonate._ensure_analyzer_image(client) is True
    assert len(client.images.build_calls) == 1


def test_starter_ruleset_covers_expected_indicators_and_dropped_the_weak_rule():
    """Structural check only — no `yara` import here on purpose. Host code
    never parses untrusted bytes with YARA/libmagic; only the isolated
    container does (see the `dev` extra's comment in pyproject.toml and
    analyze.py's docstring). The ruleset itself was validated by compiling
    and test-matching it with yara-python in a throwaway venv outside the
    repo, not via an automated host-side test.
    """
    with detonate._analyzer_build_context() as path:
        rules_text = (path / "rules" / "starter.yar").read_text()

    for expected_rule in (
        "Suspicious_PE_High_Entropy",
        "Suspicious_PE_Process_Injection_APIs",
        "Embedded_PowerShell_Download_Cradle",
        "LOLBin_Download_And_Execute",
        "Office_Macro_Auto_Exec",
        "ELF_Reverse_Shell_Indicators",
        "Ransom_Note_Indicators",
        "Obfuscated_Script_Base64_Payload",
    ):
        assert f"rule {expected_rule}" in rules_text

    # Old "Double_Extension_Script" rule dropped: it checked for a shebang at
    # offset 0 but never actually looked at the filename despite its name;
    # that's already covered properly by filetype.py.
    assert "rule Double_Extension_Script" not in rules_text
    assert 'import "math"' in rules_text
    assert 'import "pe"' in rules_text


@pytest.mark.parametrize("bad_run_id", ["", "not-a-real-id"])
def test_sweep_with_no_matching_containers_is_a_noop(bad_run_id):
    client = _FakeClient(lingering=[])
    # Should not raise even if nothing matches.
    detonate._sweep_orphaned_containers(client, bad_run_id)
