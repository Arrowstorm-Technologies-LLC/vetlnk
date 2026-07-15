"""Zero-signup DNS blocklist queries (Spamhaus DBL, SURBL) — plain DNS lookups, no API key."""

from __future__ import annotations

import dns.exception
import dns.resolver

from vetlnk.models import DnsblResult

_TIMEOUT = 4.0

# domain-based blocklists: query "<domain>.<zone>" for an A record; any A response
# in the 127.0.0.0/8 range means "listed".
ZONES: dict[str, str] = {
    "Spamhaus DBL": "dbl.spamhaus.org",
    "SURBL": "multi.surbl.org",
}


def query_zone(domain: str, zone: str) -> DnsblResult:
    query = f"{domain}.{zone}"
    try:
        answer = dns.resolver.resolve(query, "A", lifetime=_TIMEOUT)
        codes = [str(rdata) for rdata in answer]
        return DnsblResult(list_name=zone, listed=True, detail=", ".join(codes))
    except dns.resolver.NXDOMAIN:
        return DnsblResult(list_name=zone, listed=False)
    except dns.resolver.NoAnswer:
        return DnsblResult(list_name=zone, listed=False)
    except dns.exception.DNSException as exc:
        return DnsblResult(list_name=zone, listed=False, error=str(exc))


def check_domain(domain: str) -> list[DnsblResult]:
    """Query all configured DNSBL zones for a domain. Errors are non-fatal per zone."""
    return [query_zone(domain, zone) for zone in ZONES.values()]
