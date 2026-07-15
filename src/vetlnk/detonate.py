"""Opt-in detonation mode (`-d` / `--detonate`).

Only ever triggers if the default scan found a downloadable file. Picks a
backend in priority order and refuses cleanly if neither is safely available —
it never falls back to executing the file locally.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import uuid
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

import httpx

from vetlnk.enhanced import resolve_key
from vetlnk.models import DetonationResult, ScanResult

_ANALYZER_IMAGE = "vetlnk-analyzer:latest"
_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50MB safety cap for detonation-mode download
_USER_AGENT = "vetlnk/0.1 (+https://github.com/Arrowstorm-Technologies-LLC/vetlnk)"

# Hard wall-clock cutoff enforced *inside* the container via the `timeout`
# binary (see _run_docker_static_analysis) — this is what survives the host
# vetlnk process being killed mid-analysis, since it doesn't depend on any
# code here still being alive to enforce it. The docker-py client's own HTTP
# timeout is set comfortably longer so a normal-length run never trips it.
_CONTAINER_TIMEOUT_SECONDS = 90
_CONTAINER_KILL_GRACE_SECONDS = 5
_DOCKER_CLIENT_TIMEOUT = _CONTAINER_TIMEOUT_SECONDS + _CONTAINER_KILL_GRACE_SECONDS + 30

_ANALYZER_MEM_LIMIT = "512m"
_ANALYZER_NANO_CPUS = 1_000_000_000  # 1 CPU core
_ANALYZER_PIDS_LIMIT = 64
_ANALYZER_USER = "10001:10001"  # matches the `analyzer` user baked into the image


def _docker_client():
    try:
        import docker

        client = docker.from_env(timeout=_DOCKER_CLIENT_TIMEOUT)
        client.ping()
        return client
    except Exception:  # noqa: BLE001 - docker package missing, daemon down, no perms, etc.
        return None


@contextmanager
def _analyzer_build_context():
    """Yield a real filesystem path to the bundled analyzer_image/ build
    context, whether vetlnk is running from an editable checkout or a
    normally-installed (pipx/pip) wheel — `importlib.resources.as_file`
    extracts to a temp dir if the package happens to be zipped.
    """
    try:
        traversable = resources.files("vetlnk") / "analyzer_image"
    except (ModuleNotFoundError, TypeError):
        yield None
        return

    try:
        with resources.as_file(traversable) as path:
            yield path if path.is_dir() else None
    except FileNotFoundError:
        yield None


def _ensure_analyzer_image(client) -> bool:
    try:
        client.images.get(_ANALYZER_IMAGE)
        return True
    except Exception:  # noqa: BLE001 - not found, try to build
        pass

    with _analyzer_build_context() as build_dir:
        if build_dir is None:
            return False
        try:
            client.images.build(path=str(build_dir), tag=_ANALYZER_IMAGE, rm=True)
            return True
        except Exception:  # noqa: BLE001
            return False


def _download_for_detonation(url: str) -> tuple[Path, str, int] | None:
    tmp_dir = Path(tempfile.mkdtemp(prefix="vetlnk-detonate-"))
    tmp_path = tmp_dir / "sample"
    hasher = hashlib.sha256()
    size = 0
    succeeded = False

    try:
        with httpx.stream(
            "GET", url, follow_redirects=True, timeout=30.0, headers={"User-Agent": _USER_AGENT}
        ) as resp:
            resp.raise_for_status()
            with tmp_path.open("wb") as f:
                for chunk in resp.iter_bytes(chunk_size=65536):
                    size += len(chunk)
                    if size > _MAX_DOWNLOAD_BYTES:
                        limit_mb = _MAX_DOWNLOAD_BYTES // (1024 * 1024)
                        raise ValueError(f"file exceeds {limit_mb}MB detonation limit")
                    hasher.update(chunk)
                    f.write(chunk)
        succeeded = True
        return tmp_path, hasher.hexdigest(), size
    except (httpx.HTTPError, ValueError):
        return None
    finally:
        # Covers every exit path, not just the two exception types handled
        # above — in particular a KeyboardInterrupt from the SIGTERM handler
        # in cli.py firing mid-download (or a plain Ctrl+C) previously fell
        # through both the `except` and the caller's own try/finally (which
        # never got a `path` to clean up, since this call never returned),
        # leaving the partial file on disk.
        if not succeeded:
            _secure_delete(tmp_path)


def _secure_delete(path: Path) -> None:
    if not path.exists():
        return
    try:
        size = path.stat().st_size
        with path.open("r+b") as f:
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
    finally:
        path.unlink(missing_ok=True)
        with_parent = path.parent
        try:
            with_parent.rmdir()
        except OSError:
            pass


def _sweep_orphaned_containers(client, run_id: str) -> None:
    """Belt-and-suspenders cleanup, run in a `finally` alongside the run below.

    `remove=True` on the run itself tells dockerd to delete the container the
    instant it exits, *at the daemon*, independent of whether this Python
    process is still around to see it happen — that's what actually survives
    a `kill -9` of vetlnk mid-analysis (nothing running in this process can
    survive SIGKILL; only daemon-side auto-remove plus the in-container
    `timeout` cutoff can bound the damage). This sweep additionally catches
    the case where the blocking call below raised for a reason that left a
    container behind before dockerd's auto-remove had a chance to fire (e.g.
    we lost the HTTP connection to the daemon mid-wait).
    """
    import docker.errors

    try:
        containers = client.containers.list(
            all=True, filters={"label": f"vetlnk-run-id={run_id}"}
        )
    except docker.errors.DockerException:
        return

    for container in containers:
        try:
            container.kill()
        except docker.errors.APIError:
            pass
        try:
            container.remove(force=True)
        except docker.errors.APIError:
            pass


def _run_docker_static_analysis(client, file_path: Path) -> dict | None:
    import docker.errors

    run_id = uuid.uuid4().hex
    # In-container wall-clock cutoff: SIGTERM at _CONTAINER_TIMEOUT_SECONDS,
    # SIGKILL _CONTAINER_KILL_GRACE_SECONDS later if it's still alive. This
    # is what actually bounds a hung analysis — see _sweep_orphaned_containers.
    command = [
        "timeout",
        "-k",
        str(_CONTAINER_KILL_GRACE_SECONDS),
        f"{_CONTAINER_TIMEOUT_SECONDS}s",
        "python",
        "/analyze.py",
        f"/data/{file_path.name}",
    ]

    try:
        output = client.containers.run(
            _ANALYZER_IMAGE,
            command=command,
            labels={"vetlnk-analysis": "1", "vetlnk-run-id": run_id},
            volumes={str(file_path.parent): {"bind": "/data", "mode": "ro"}},
            network_mode="none",  # equivalent to `docker run --network none`
            read_only=True,  # root filesystem is read-only except the tmpfs scratch mount below
            tmpfs={"/tmp": "size=64m,mode=1777,noexec,nosuid,nodev"},
            user=_ANALYZER_USER,  # non-root even if the image is ever rebuilt without USER
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit=_ANALYZER_MEM_LIMIT,
            memswap_limit=_ANALYZER_MEM_LIMIT,  # no swap headroom beyond mem_limit
            nano_cpus=_ANALYZER_NANO_CPUS,
            pids_limit=_ANALYZER_PIDS_LIMIT,
            remove=True,  # daemon-side auto-remove — see _sweep_orphaned_containers
            stdout=True,
            stderr=False,
        )
        return json.loads(output.decode("utf-8", errors="replace"))
    except docker.errors.ContainerError:
        # Non-zero exit — most likely the in-container `timeout` fired (the
        # analysis hung) or analyze.py crashed. Either way: no execution of
        # the sample occurred, we just don't have a verdict to report.
        return None
    except (json.JSONDecodeError, docker.errors.APIError, docker.errors.DockerException):
        return None
    finally:
        _sweep_orphaned_containers(client, run_id)


def run_detonation(result: ScanResult) -> DetonationResult:
    if not result.file_info:
        return DetonationResult(attempted=False)

    url = result.final_url or result.input_url

    vt_key = resolve_key("virustotal")
    if vt_key:
        from vetlnk.providers import virustotal

        downloaded = _download_for_detonation(url)
        if downloaded is None:
            return DetonationResult(
                attempted=True,
                backend="virustotal",
                refused_reason="Could not safely download the file for VirusTotal submission.",
            )
        path, sha256, size = downloaded
        try:
            verdict = virustotal.query_file_hash(sha256, vt_key)
            if verdict.note and "not known" in verdict.note:
                verdict = virustotal.submit_file(path.read_bytes(), path.name, vt_key)
            summary = (
                f"{verdict.malicious} malicious / {verdict.total_engines} engines"
                if verdict.malicious is not None
                else (verdict.note or verdict.error or "no verdict")
            )
            return DetonationResult(
                attempted=True,
                backend="virustotal",
                verdict=summary,
                details={"sha256": sha256, "size_bytes": size, "permalink": verdict.permalink},
            )
        finally:
            _secure_delete(path)

    docker_client = _docker_client()
    if docker_client is not None and _ensure_analyzer_image(docker_client):
        downloaded = _download_for_detonation(url)
        if downloaded is None:
            return DetonationResult(
                attempted=True,
                backend="docker-static",
                refused_reason="Could not safely download the file for static analysis.",
            )
        path, sha256, size = downloaded
        try:
            analysis = _run_docker_static_analysis(docker_client, path)
            if analysis is None:
                return DetonationResult(
                    attempted=True,
                    backend="docker-static",
                    refused_reason="Static analysis container failed to produce a result.",
                )
            yara_hits = analysis.get("yara_matches", [])
            verdict = (
                f"YARA matched: {', '.join(yara_hits)}" if yara_hits else "no static rule matches"
            )
            return DetonationResult(
                attempted=True, backend="docker-static", verdict=verdict, details=analysis
            )
        finally:
            _secure_delete(path)

    return DetonationResult(
        attempted=True,
        backend=None,
        refused_reason=(
            "Detonation requested but no safe detonation backend is configured "
            "(no VT_API_KEY, no Docker available). Refusing to execute the file locally. "
            "Set VT_API_KEY or install Docker to enable -d."
        ),
    )
