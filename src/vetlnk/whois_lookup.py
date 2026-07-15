"""Domain age lookup via WHOIS (python-whois), with RDAP fallback over httpx.

Freshly-registered domains are a risk signal — anything under ~30 days old
should be flagged by the caller.
"""

from __future__ import annotations

import contextlib
import io
from datetime import UTC, datetime

import httpx
import whois

from vetlnk.models import DomainInfo

_RDAP_TIMEOUT = 8.0
_RDAP_BOOTSTRAP = "https://rdap.org/domain/"


def _first_date(value):
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value
    return None


def _via_python_whois(domain: str) -> DomainInfo | None:
    try:
        # python-whois prints (not logs) transport errors from referral servers
        # it tries along the way — that's noise, not a failure, so swallow it.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            record = whois.whois(domain)
    except Exception:  # noqa: BLE001 - fall through to RDAP
        return None

    created = _first_date(getattr(record, "creation_date", None))
    if created is None:
        return None

    age_days = (datetime.now(UTC) - created).days
    registrar = getattr(record, "registrar", None)
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None

    return DomainInfo(
        domain=domain,
        registered_on=created.date().isoformat(),
        age_days=age_days,
        registrar=registrar,
    )


def _via_rdap(domain: str) -> DomainInfo | None:
    try:
        resp = httpx.get(f"{_RDAP_BOOTSTRAP}{domain}", timeout=_RDAP_TIMEOUT, follow_redirects=True)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None

    registered_on = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            registered_on = event.get("eventDate")
            break

    if not registered_on:
        return None

    try:
        created = datetime.fromisoformat(registered_on.replace("Z", "+00:00"))
    except ValueError:
        return None

    age_days = (datetime.now(UTC) - created).days
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        registrar = field[3]
                        break
            break

    return DomainInfo(
        domain=domain,
        registered_on=created.date().isoformat(),
        age_days=age_days,
        registrar=registrar,
    )


def lookup_domain_age(domain: str) -> DomainInfo:
    """Try python-whois first, fall back to RDAP, report a clean error if both fail."""
    result = _via_python_whois(domain)
    if result is not None:
        return result

    result = _via_rdap(domain)
    if result is not None:
        return result

    return DomainInfo(domain=domain, error="WHOIS and RDAP lookups both failed or returned no data")
