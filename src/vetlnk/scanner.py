"""Orchestrates the default (safe, read-only) scan pass for a single URL."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict
from urllib.parse import urlsplit

import httpx

from vetlnk import cache as ioc_cache
from vetlnk import dnsbl, filetype, heuristics, whois_lookup
from vetlnk.models import DnsblResult, DomainInfo, ScanResult
from vetlnk.redirects import follow_redirects


def _cached_domain_lookup(domain: str) -> DomainInfo:
    cached = ioc_cache.get("domain", domain, "whois")
    if cached is not None:
        return DomainInfo(**cached)
    info = whois_lookup.lookup_domain_age(domain)
    if not info.error:
        ioc_cache.put("domain", domain, "whois", asdict(info))
    return info


def _cached_dnsbl_check(domain: str) -> list[DnsblResult]:
    results = []
    for zone_label, zone in dnsbl.ZONES.items():
        cached = ioc_cache.get("domain", domain, f"dnsbl:{zone_label}")
        if cached is not None:
            results.append(DnsblResult(**cached))
            continue
        result = dnsbl.query_zone(domain, zone)
        if not result.error:
            ioc_cache.put("domain", domain, f"dnsbl:{zone_label}", asdict(result))
        results.append(result)
    return results


def scan_url(
    url: str, *, client: httpx.Client | None = None, use_cache: bool = False
) -> ScanResult:
    result = ScanResult(input_url=url)

    try:
        hops = follow_redirects(url, client=client)
    except Exception as exc:  # noqa: BLE001 - never let one bad URL kill a batch
        result.scan_errors.append(f"redirect tracking failed: {exc}")
        hops = []
    result.hops = hops

    if not hops or hops[-1].error:
        result.final_url = hops[-1].url if hops else url
        if hops and hops[-1].error:
            result.scan_errors.append(hops[-1].error)
    else:
        result.final_url = hops[-1].url

    final_host = urlsplit(result.final_url).hostname or ""
    is_ip_literal = False
    if final_host:
        try:
            ipaddress.ip_address(final_host)
            is_ip_literal = True
        except ValueError:
            pass

    if final_host and is_ip_literal:
        result.scan_errors.append(
            "Host is a raw IP address — domain-based WHOIS age and DNSBL (Spamhaus DBL/SURBL) "
            "checks don't apply and were skipped; see the 'IP-literal URL' heuristic instead."
        )
    elif final_host:
        try:
            result.domain_info = (
                _cached_domain_lookup(final_host)
                if use_cache
                else whois_lookup.lookup_domain_age(final_host)
            )
        except Exception as exc:  # noqa: BLE001
            result.scan_errors.append(f"WHOIS lookup failed: {exc}")

        try:
            result.dnsbl_results = (
                _cached_dnsbl_check(final_host) if use_cache else dnsbl.check_domain(final_host)
            )
        except Exception as exc:  # noqa: BLE001
            result.scan_errors.append(f"DNSBL lookup failed: {exc}")

    try:
        result.heuristics = heuristics.run_heuristics(result.final_url, hops)
    except Exception as exc:  # noqa: BLE001
        result.scan_errors.append(f"heuristics failed: {exc}")

    last_hop = hops[-1] if hops else None
    if last_hop and last_hop.status_code and last_hop.status_code < 400:
        try:
            result.file_info = filetype.probe_file(result.final_url, client=client)
        except Exception as exc:  # noqa: BLE001
            result.scan_errors.append(f"file probe failed: {exc}")

    return result
