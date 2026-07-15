"""Optional enhanced reputation checks — only run if a key is configured.

Key resolution order: OS keychain / config-file (via `vetlnk config`) first,
then the VT_API_KEY / URLSCAN_API_KEY env vars as a power-user/CI fallback.
Missing keys are not an error — the report just notes the check was skipped.
"""

from __future__ import annotations

import os
from dataclasses import asdict

from vetlnk import cache as ioc_cache
from vetlnk import config as key_store
from vetlnk.models import ProviderVerdict, ScanResult
from vetlnk.providers import urlscan, virustotal
from vetlnk.providers.base import REGISTRY


def resolve_key(provider_id: str) -> str | None:
    stored = key_store.get_key(provider_id)
    if stored:
        return stored
    return os.environ.get(REGISTRY[provider_id].env_var) or None


def _cached_verdict(domain: str, provider: str, query) -> ProviderVerdict:
    cached = ioc_cache.get("domain", domain, provider)
    if cached is not None:
        return ProviderVerdict(**cached)
    verdict = query()
    if verdict.available and not verdict.error:
        ioc_cache.put("domain", domain, provider, asdict(verdict))
    return verdict


def run_enhanced_checks(result: ScanResult, *, use_cache: bool = False) -> None:
    url = result.final_url or result.input_url
    from urllib.parse import urlsplit

    domain = urlsplit(url).hostname or url

    vt_key = resolve_key("virustotal")
    if vt_key:
        query = lambda: virustotal.query_url_vt_py(url, vt_key)  # noqa: E731
        verdict = _cached_verdict(domain, "virustotal", query) if use_cache else query()
        result.provider_verdicts.append(verdict)
    else:
        result.provider_verdicts.append(
            ProviderVerdict(
                provider="VirusTotal",
                available=False,
                note="No VirusTotal API key configured (run `vetlnk config` or set VT_API_KEY).",
            )
        )

    urlscan_key = resolve_key("urlscan")
    if urlscan_key:
        query = lambda: urlscan.query_url(url, urlscan_key, wait_for_result=False)  # noqa: E731
        verdict = _cached_verdict(domain, "urlscan", query) if use_cache else query()
        result.provider_verdicts.append(verdict)
    else:
        result.provider_verdicts.append(
            ProviderVerdict(
                provider="urlscan.io",
                available=False,
                note=(
                    "No urlscan.io API key configured "
                    "(run `vetlnk config` or set URLSCAN_API_KEY)."
                ),
            )
        )
