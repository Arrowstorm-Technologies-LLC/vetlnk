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
from pathlib import Path

import httpx

from vetlnk.enhanced import resolve_key
from vetlnk.models import DetonationResult, ScanResult

_ANALYZER_IMAGE = "vetlnk-analyzer:latest"
_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50MB safety cap for detonation-mode download
_USER_AGENT = "vetlnk/0.1 (+https://github.com/Arrowstorm-Technologies-LLC/vetlnk)"


def _docker_client():
    try:
        import docker

        client = docker.from_env()
        client.ping()
        return client
    except Exception:  # noqa: BLE001 - docker package missing, daemon down, no perms, etc.
        return None


def _analyzer_dockerfile_dir() -> Path | None:
    # Repo layout: <repo_root>/docker/analyzer relative to this installed package.
    candidate = Path(__file__).resolve().parents[2] / "docker" / "analyzer"
    return candidate if candidate.is_dir() else None


def _ensure_analyzer_image(client) -> bool:
    try:
        client.images.get(_ANALYZER_IMAGE)
        return True
    except Exception:  # noqa: BLE001 - not found, try to build
        pass

    build_dir = _analyzer_dockerfile_dir()
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
    except (httpx.HTTPError, ValueError):
        _secure_delete(tmp_path)
        return None

    return tmp_path, hasher.hexdigest(), size


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


def _run_docker_static_analysis(client, file_path: Path) -> dict | None:
    try:
        output = client.containers.run(
            _ANALYZER_IMAGE,
            command=[f"/data/{file_path.name}"],
            volumes={str(file_path.parent): {"bind": "/data", "mode": "ro"}},
            network_disabled=True,
            mem_limit="256m",
            pids_limit=64,
            remove=True,
            stdout=True,
            stderr=False,
        )
        return json.loads(output.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return None


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
