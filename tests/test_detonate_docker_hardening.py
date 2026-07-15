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


class _FakeClient:
    def __init__(self, **container_kwargs):
        self.containers = _FakeContainers(**container_kwargs)


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


@pytest.mark.parametrize("bad_run_id", ["", "not-a-real-id"])
def test_sweep_with_no_matching_containers_is_a_noop(bad_run_id):
    client = _FakeClient(lingering=[])
    # Should not raise even if nothing matches.
    detonate._sweep_orphaned_containers(client, bad_run_id)
