"""Provider registry — the single place to add a new optional reputation source.

Adding a provider (e.g. AbuseIPDB, Google Safe Browsing) later means adding one
entry here plus a query/validate module; nothing else in vetlnk needs to change.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    id: str
    display_name: str
    env_var: str
    key_page_url: str
    validate: Callable[[str], tuple[bool, str]]  # (key) -> (is_valid, message)


def _virustotal_validate(key: str) -> tuple[bool, str]:
    from vetlnk.providers import virustotal

    return virustotal.validate_key(key)


def _urlscan_validate(key: str) -> tuple[bool, str]:
    from vetlnk.providers import urlscan

    return urlscan.validate_key(key)


REGISTRY: dict[str, Provider] = {
    "virustotal": Provider(
        id="virustotal",
        display_name="VirusTotal",
        env_var="VT_API_KEY",
        key_page_url="https://www.virustotal.com/gui/my-apikey",
        validate=_virustotal_validate,
    ),
    "urlscan": Provider(
        id="urlscan",
        display_name="urlscan.io",
        env_var="URLSCAN_API_KEY",
        key_page_url="https://urlscan.io/user/profile/",
        validate=_urlscan_validate,
    ),
}
