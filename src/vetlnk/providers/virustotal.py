"""VirusTotal integration — key validation and URL/file verdict queries.

Uses direct httpx calls for validation (fast, no extra dependency) and vt-py
for the richer scan queries, matching the tech-stack choice in the spec.
"""

from __future__ import annotations

import base64

import httpx

from vetlnk.models import ProviderVerdict

_API_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 10.0


def validate_key(key: str) -> tuple[bool, str]:
    """VT allows self-lookup via /users/{id} where id may be the API key itself."""
    try:
        resp = httpx.get(
            f"{_API_BASE}/users/{key}",
            headers={"x-apikey": key},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            return True, "Key is valid."
        if resp.status_code in (401, 403):
            return False, "Key was rejected by VirusTotal (unauthorized)."
        return False, f"Unexpected response from VirusTotal (HTTP {resp.status_code})."
    except httpx.HTTPError as exc:
        return False, f"Could not reach VirusTotal: {exc}"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def query_url_vt_py(url: str, api_key: str) -> ProviderVerdict:
    """Preferred path: the official vt-py SDK, per the spec's tech-stack choice.

    Falls back to the raw REST call in `query_url` if vt-py isn't installed
    (it's an optional extra) — same underlying API either way.
    """
    try:
        import vt
    except ImportError:
        return query_url(url, api_key)

    try:
        with vt.Client(api_key) as client:
            url_id = vt.url_id(url)
            try:
                obj = client.get_object(f"/urls/{url_id}")
            except vt.APIError as exc:
                if exc.code == "NotFoundError":
                    return ProviderVerdict(
                        provider="VirusTotal",
                        available=True,
                        note="URL not previously scanned by VirusTotal.",
                    )
                raise
            stats = obj.last_analysis_stats
            return ProviderVerdict(
                provider="VirusTotal",
                available=True,
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                harmless=stats.get("harmless", 0),
                total_engines=sum(stats.values()),
                permalink=f"https://www.virustotal.com/gui/url/{url_id}",
            )
    except Exception as exc:  # noqa: BLE001 - vt-py raises its own error hierarchy
        return ProviderVerdict(provider="VirusTotal", available=True, error=str(exc))


def query_url(url: str, api_key: str) -> ProviderVerdict:
    try:
        resp = httpx.get(
            f"{_API_BASE}/urls/{_url_id(url)}",
            headers={"x-apikey": api_key},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return ProviderVerdict(
                provider="VirusTotal",
                available=True,
                note="URL not previously scanned by VirusTotal.",
            )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return ProviderVerdict(
            provider="VirusTotal",
            available=True,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            total_engines=sum(stats.values()),
            permalink=f"https://www.virustotal.com/gui/url/{_url_id(url)}",
        )
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return ProviderVerdict(provider="VirusTotal", available=True, error=str(exc))


def query_file_hash(sha256: str, api_key: str) -> ProviderVerdict:
    try:
        resp = httpx.get(
            f"{_API_BASE}/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return ProviderVerdict(
                provider="VirusTotal", available=True, note="File hash not known to VirusTotal."
            )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return ProviderVerdict(
            provider="VirusTotal",
            available=True,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            total_engines=sum(stats.values()),
            permalink=f"https://www.virustotal.com/gui/file/{sha256}",
        )
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return ProviderVerdict(provider="VirusTotal", available=True, error=str(exc))


def submit_file(data: bytes, filename: str, api_key: str) -> ProviderVerdict:
    """Submit a small file's bytes to VT for sandbox analysis (detonation mode only)."""
    try:
        resp = httpx.post(
            f"{_API_BASE}/files",
            headers={"x-apikey": api_key},
            files={"file": (filename, data)},
            timeout=60.0,
        )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]
        return ProviderVerdict(
            provider="VirusTotal",
            available=True,
            note=f"Submitted for sandbox analysis (analysis id: {analysis_id}).",
            permalink=f"https://www.virustotal.com/gui/file-analysis/{analysis_id}",
        )
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return ProviderVerdict(provider="VirusTotal", available=True, error=str(exc))
