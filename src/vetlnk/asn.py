"""Zero-signup ASN lookup via Team Cymru's DNS-based whois service."""

from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver

_TIMEOUT = 4.0


def _reverse_ipv4(ip: str) -> str:
    octets = ip.split(".")
    return ".".join(reversed(octets))


def lookup_asn(ip: str) -> tuple[str | None, str | None]:
    """Return (asn, asn_org) for an IPv4/IPv6 address, or (None, None) on failure."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, None

    if addr.version != 4:
        # Team Cymru's IPv6 origin lookup uses a different nibble format; skip for v0.1.
        return None, None

    try:
        query = f"{_reverse_ipv4(ip)}.origin.asn.cymru.com"
        answer = dns.resolver.resolve(query, "TXT", lifetime=_TIMEOUT)
        # Format: "ASN | prefix | country | registry | allocated"
        txt = b"".join(answer[0].strings).decode("utf-8", errors="replace")
        asn = txt.split("|")[0].strip()
        asn = f"AS{asn}" if asn and not asn.startswith("AS") else asn

        org_query = f"{asn}.asn.cymru.com"
        org_answer = dns.resolver.resolve(org_query, "TXT", lifetime=_TIMEOUT)
        org_txt = b"".join(org_answer[0].strings).decode("utf-8", errors="replace")
        # Format: "ASN | country | registry | allocated | AS Name"
        parts = [p.strip() for p in org_txt.split("|")]
        asn_org = parts[-1] if parts else None

        return asn, asn_org
    except (dns.exception.DNSException, OSError, IndexError):
        return None, None
