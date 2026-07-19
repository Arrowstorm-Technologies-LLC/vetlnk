"""Opt-in detonation mode (`-d` / `--detonate`).

Only ever triggers if the default scan found a downloadable file. Picks a
backend in priority order and refuses cleanly if neither is safely available —
it never falls back to executing the file locally.

No API key is required: if Docker itself isn't installed/running, this asks
before doing anything about it (see `_detect_missing_docker_deps` and
`run_detonation`) and only ever installs/configures Docker on Linux, where it
can be done unattended via the native package manager + systemd. macOS/Windows
use Docker Desktop, which needs a GUI first-run — not something safe to script
— so those just get a clear manual-install message instead.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import httpx
import typer
from rich.console import Console

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


@dataclass
class _MissingDockerDeps:
    items: list[str]
    auto_fixable: bool  # only true on Linux, where install+start can be scripted unattended


_PACKAGE_MANAGERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("pacman", ("pacman", "-Sy", "--noconfirm", "docker")),
    ("apt-get", ("apt-get", "install", "-y", "docker.io")),
    ("dnf", ("dnf", "install", "-y", "docker")),
    ("yum", ("yum", "install", "-y", "docker")),
    ("zypper", ("zypper", "--non-interactive", "install", "docker")),
    ("apk", ("apk", "add", "docker")),
)


def _detect_missing_docker_deps() -> _MissingDockerDeps | None:
    """What's missing for Docker to work for the *current* user, or None if
    Docker itself looks fine (meaning `_docker_client()` failing must be
    something else, e.g. the `docker` Python package not being importable —
    not something an OS-level install can fix).
    """
    is_linux = platform.system() == "Linux"

    if shutil.which("docker") is None:
        return _MissingDockerDeps(
            items=["Docker Engine (not installed)", "Docker daemon (systemd service)"],
            auto_fixable=is_linux,
        )

    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return _MissingDockerDeps(items=["Docker daemon (not responding)"], auto_fixable=is_linux)

    if proc.returncode == 0:
        return None

    stderr = proc.stderr.decode("utf-8", errors="replace").lower()
    if "permission denied" in stderr:
        item = f"Docker group membership for {getpass.getuser()}"
    else:
        item = "Docker daemon (not running)"
    return _MissingDockerDeps(items=[item], auto_fixable=is_linux)


def _confirm_dependency_install(items: list[str]) -> bool:
    console = Console()
    console.print(
        "[yellow]Detonation requires the following dependencies not on your system:[/yellow]"
    )
    for item in items:
        console.print(f"  - {item}")
    return typer.confirm("Install and run?", default=False)


def _run_privileged(cmd: list[str]) -> bool:
    """Run a command with sudo, inheriting the terminal so sudo can prompt
    for a password and package-manager output streams live.
    """
    try:
        return subprocess.run(["sudo", *cmd]).returncode == 0
    except FileNotFoundError:
        return False


def _detect_package_manager() -> tuple[str, tuple[str, ...]] | None:
    for name, install_cmd in _PACKAGE_MANAGERS:
        if shutil.which(name):
            return name, install_cmd
    return None


def _install_docker() -> tuple[bool, str | None]:
    """Best-effort install + start of Docker on Linux. Returns (ok, error)."""
    if platform.system() != "Linux":
        return False, (
            "Automatic Docker installation is only supported on Linux (macOS/Windows use "
            "Docker Desktop, which needs a GUI first-run). Install Docker manually, then re-run."
        )

    console = Console()
    console.print("[dim]This requires sudo access to install and configure Docker.[/dim]")
    try:
        if subprocess.run(["sudo", "-v"]).returncode != 0:
            return False, "sudo access was not granted — cannot install Docker."
    except FileNotFoundError:
        return False, (
            "`sudo` is not available on this system — cannot install Docker automatically."
        )

    if shutil.which("docker") is None:
        pm = _detect_package_manager()
        if pm is None:
            return False, (
                "Could not detect a supported package manager "
                "(pacman/apt/dnf/yum/zypper/apk) to install Docker."
            )
        name, install_cmd = pm
        console.print(f"[dim]Installing Docker via {name}...[/dim]")
        if not _run_privileged(list(install_cmd)):
            return False, f"Failed to install Docker via {name}."

    if shutil.which("systemctl"):
        if not _run_privileged(["systemctl", "enable", "--now", "docker"]):
            return False, "Failed to enable/start the Docker service via systemctl."
    elif shutil.which("service"):
        if not _run_privileged(["service", "docker", "start"]):
            return False, "Failed to start the Docker service."
    else:
        return False, "Could not find systemctl or service to start the Docker daemon."

    # Best-effort so future runs don't need sudo at all — group changes need a
    # new login session to take effect, so this run still falls back to sudo.
    _run_privileged(["usermod", "-aG", "docker", getpass.getuser()])

    return True, None


def _docker_cli(
    args: list[str], *, sudo: bool, timeout: float | None = None, capture: bool = True
) -> subprocess.CompletedProcess:
    cmd = ["sudo", "docker", *args] if sudo else ["docker", *args]
    return subprocess.run(cmd, capture_output=capture, timeout=timeout)


def _ensure_analyzer_image_cli(*, sudo: bool) -> bool:
    with _analyzer_build_context() as build_dir:
        if build_dir is None:
            check = _docker_cli(["image", "inspect", _ANALYZER_IMAGE], sudo=sudo, timeout=10)
            return check.returncode == 0

        build_hash = _compute_build_hash(build_dir)
        label_format = f'{{{{ index .Config.Labels "{_BUILD_HASH_LABEL}" }}}}'
        try:
            inspect = _docker_cli(
                ["image", "inspect", "--format", label_format, _ANALYZER_IMAGE],
                sudo=sudo,
                timeout=10,
            )
            if inspect.returncode == 0:
                existing_hash = inspect.stdout.decode("utf-8", errors="replace").strip()
                if existing_hash == build_hash:
                    return True
        except (subprocess.TimeoutExpired, OSError):
            pass

        try:
            build = _docker_cli(
                [
                    "build",
                    "--rm",
                    "--label",
                    f"{_BUILD_HASH_LABEL}={build_hash}",
                    "-t",
                    _ANALYZER_IMAGE,
                    str(build_dir),
                ],
                sudo=sudo,
                capture=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        return build.returncode == 0


def _sweep_orphaned_containers_cli(run_id: str, *, sudo: bool) -> None:
    try:
        listing = _docker_cli(
            ["ps", "-aq", "--filter", f"label=vetlnk-run-id={run_id}"], sudo=sudo, timeout=10
        )
    except (subprocess.TimeoutExpired, OSError):
        return

    if listing.returncode != 0:
        return

    for cid in listing.stdout.decode("utf-8", errors="replace").split():
        try:
            _docker_cli(["kill", cid], sudo=sudo, timeout=10)
            _docker_cli(["rm", "-f", cid], sudo=sudo, timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            pass


def _run_docker_static_analysis_cli(file_path: Path, *, sudo: bool) -> dict | None:
    """CLI-subprocess equivalent of `_run_docker_static_analysis`, used only
    when talking to the daemon needs `sudo` for this run (freshly installed,
    group membership not active yet without a new login) — see `run_detonation`.
    Mirrors the exact same hardening flags, just expressed as `docker run` args
    instead of docker-py kwargs.
    """
    run_id = uuid.uuid4().hex
    tmpfs_opts = "size=64m,mode=1777,noexec,nosuid,nodev"
    cpus = str(_ANALYZER_NANO_CPUS / 1_000_000_000)
    args = [
        "run",
        "--rm",
        "--label",
        "vetlnk-analysis=1",
        "--label",
        f"vetlnk-run-id={run_id}",
        "-v",
        f"{file_path.parent}:/data:ro",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        f"/tmp:{tmpfs_opts}",
        "--user",
        _ANALYZER_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        _ANALYZER_MEM_LIMIT,
        "--memory-swap",
        _ANALYZER_MEM_LIMIT,
        "--cpus",
        cpus,
        "--pids-limit",
        str(_ANALYZER_PIDS_LIMIT),
        _ANALYZER_IMAGE,
        "timeout",
        "-k",
        str(_CONTAINER_KILL_GRACE_SECONDS),
        f"{_CONTAINER_TIMEOUT_SECONDS}s",
        "python",
        "/analyze.py",
        f"/data/{file_path.name}",
    ]

    try:
        proc = _docker_cli(args, sudo=sudo, timeout=_DOCKER_CLIENT_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError):
        proc = None
    finally:
        _sweep_orphaned_containers_cli(run_id, sudo=sudo)

    if proc is None or proc.returncode != 0:
        # `docker run`'s own stderr (daemon/CLI errors, not the container's)
        # would otherwise vanish here — surface it so a failure is diagnosable
        # instead of just "produced no result".
        if proc is not None and proc.stderr:
            stderr_text = proc.stderr.decode("utf-8", errors="replace").strip()
            if stderr_text:
                Console().print(f"[red]docker run failed:[/red] {stderr_text[:2000]}")
        return None
    try:
        return json.loads(proc.stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
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


_BUILD_HASH_LABEL = "vetlnk.analyzer-build-hash"


def _compute_build_hash(build_dir: Path) -> str:
    """Content hash of the analyzer_image build context (Dockerfile,
    analyze.py, rules/*.yar), stamped onto the built image as a label so a
    stale cached image from before a rules/Dockerfile update gets rebuilt
    instead of silently running outdated detection logic forever.
    """
    hasher = hashlib.sha256()
    for path in sorted(p for p in build_dir.rglob("*") if p.is_file()):
        hasher.update(str(path.relative_to(build_dir)).encode())
        hasher.update(path.read_bytes())
    return hasher.hexdigest()


def _ensure_analyzer_image(client) -> bool:
    with _analyzer_build_context() as build_dir:
        if build_dir is None:
            try:
                client.images.get(_ANALYZER_IMAGE)
                return True
            except Exception:  # noqa: BLE001 - image not found, nothing to build from
                return False

        build_hash = _compute_build_hash(build_dir)
        try:
            image = client.images.get(_ANALYZER_IMAGE)
            if image.labels.get(_BUILD_HASH_LABEL) == build_hash:
                return True
        except Exception:  # noqa: BLE001 - not found, or no label yet; rebuild below
            pass

        try:
            client.images.build(
                path=str(build_dir),
                tag=_ANALYZER_IMAGE,
                rm=True,
                labels={_BUILD_HASH_LABEL: build_hash},
            )
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
        # The analyzer container always runs as a fixed non-root uid (10001)
        # that never matches the host user who owns this tempdir — mkdtemp's
        # default 0700 would leave it unreadable across that uid boundary once
        # bind-mounted in. Widening to "other"-readable is safe here: the bind
        # mount into the container is read-only, network is disabled, and the
        # file is secure-deleted (see _secure_delete) as soon as analysis ends.
        tmp_dir.chmod(0o755)
        tmp_path.chmod(0o644)
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
    used_sudo_cli = False

    if docker_client is None:
        missing = _detect_missing_docker_deps()
        if missing is not None:
            if not missing.auto_fixable:
                return DetonationResult(
                    attempted=True,
                    backend=None,
                    refused_reason=(
                        f"Docker isn't available ({'; '.join(missing.items)}) and automatic "
                        "installation is only supported on Linux. Install/start Docker "
                        "manually, then re-run."
                    ),
                )
            if not sys.stdin.isatty():
                return DetonationResult(
                    attempted=True,
                    backend=None,
                    refused_reason=(
                        f"Docker isn't available ({'; '.join(missing.items)}) and can't be "
                        "installed non-interactively. Install Docker manually, or run vetlnk "
                        "in an interactive terminal so it can ask to install it."
                    ),
                )
            if not _confirm_dependency_install(missing.items):
                return DetonationResult(
                    attempted=True,
                    backend=None,
                    refused_reason="Detonation cancelled — required Docker dependencies "
                    "were not installed.",
                )

            ok, err = _install_docker()
            if not ok:
                return DetonationResult(attempted=True, backend=None, refused_reason=err)

            docker_client = _docker_client()
            used_sudo_cli = docker_client is None
            if used_sudo_cli:
                result.scan_errors.append(
                    "Docker was just installed and started for this run via sudo. Log out and "
                    "back in (or run `newgrp docker`) so future scans don't need to ask again."
                )

    image_ready = (
        _ensure_analyzer_image(docker_client)
        if docker_client is not None
        else (_ensure_analyzer_image_cli(sudo=True) if used_sudo_cli else False)
    )

    if image_ready:
        downloaded = _download_for_detonation(url)
        if downloaded is None:
            return DetonationResult(
                attempted=True,
                backend="docker-static",
                refused_reason="Could not safely download the file for static analysis.",
            )
        path, sha256, size = downloaded
        try:
            analysis = (
                _run_docker_static_analysis(docker_client, path)
                if docker_client is not None
                else _run_docker_static_analysis_cli(path, sudo=True)
            )
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
            "Detonation requested but no safe detonation backend is available "
            "(no VT_API_KEY, Docker could not be made available). Refusing to execute the "
            "file locally."
        ),
    )
