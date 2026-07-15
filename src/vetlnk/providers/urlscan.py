"""urlscan.io integration — key validation and URL verdict/screenshot queries."""

from __future__ import annotations

import time

import httpx

from vetlnk.models import ProviderVerdict

_API_BASE = "https://urlscan.io/api/v1"
_TIMEOUT = 10.0


def validate_key(key: str) -> tuple[bool, str]:
    try:
        resp = httpx.get(
            f"{_API_BASE}/quotas/",
            headers={"API-Key": key},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            return True, "Key is valid."
        if resp.status_code in (400, 401, 403):
            return False, "Key was rejected by urlscan.io (invalid or unauthorized)."
        return False, f"Unexpected response from urlscan.io (HTTP {resp.status_code})."
    except httpx.HTTPError as exc:
        return False, f"Could not reach urlscan.io: {exc}"


def query_url(url: str, api_key: str, *, wait_for_result: bool = True) -> ProviderVerdict:
    """Search existing scans first (no quota cost); optionally submit + poll a new one."""
    try:
        search_resp = httpx.get(
            f"{_API_BASE}/search/",
            params={"q": f'page.url:"{url}"'},
            headers={"API-Key": api_key},
            timeout=_TIMEOUT,
        )
        search_resp.raise_for_status()
        results = search_resp.json().get("results", [])
        if results:
            latest = results[0]
            verdicts = latest.get("verdicts", {}).get("overall", {})
            return ProviderVerdict(
                provider="urlscan.io",
                available=True,
                malicious=1 if verdicts.get("malicious") else 0,
                permalink=latest.get("result"),
                screenshot_url=latest.get("screenshot"),
                note="Result from a prior scan of this URL.",
            )

        if not wait_for_result:
            return ProviderVerdict(
                provider="urlscan.io", available=True, note="No prior scan found."
            )

        submit_resp = httpx.post(
            f"{_API_BASE}/scan/",
            json={"url": url, "visibility": "unlisted"},
            headers={"API-Key": api_key},
            timeout=_TIMEOUT,
        )
        submit_resp.raise_for_status()
        submission = submit_resp.json()
        result_url = submission["api"]

        for _ in range(10):
            time.sleep(3)
            poll = httpx.get(result_url, timeout=_TIMEOUT)
            if poll.status_code == 200:
                data = poll.json()
                verdicts = data.get("verdicts", {}).get("overall", {})
                return ProviderVerdict(
                    provider="urlscan.io",
                    available=True,
                    malicious=1 if verdicts.get("malicious") else 0,
                    permalink=submission.get("result"),
                    screenshot_url=data.get("task", {}).get("screenshotURL"),
                    note="New scan submitted for this URL.",
                )

        return ProviderVerdict(
            provider="urlscan.io",
            available=True,
            note="Scan submitted but did not complete in time.",
            permalink=submission.get("result"),
        )
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return ProviderVerdict(provider="urlscan.io", available=True, error=str(exc))
