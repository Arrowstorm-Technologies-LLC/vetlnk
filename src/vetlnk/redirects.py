"""Manual (non-auto-follow) redirect chain tracking with per-hop TLS/IP capture."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from datetime import UTC, datetime

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from vetlnk.asn import lookup_asn
from vetlnk.models import Hop, TLSInfo

MAX_HOPS = 15
REQUEST_TIMEOUT = 10.0
USER_AGENT = "vetlnk/0.1 (+https://github.com/Arrowstorm-Technologies-LLC/vetlnk)"

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


def _get_tls_info(hostname: str, port: int = 443) -> TLSInfo:
    try:
        # Verification is deliberately disabled: we want to *inspect* self-signed
        # or mismatched certs, not have the handshake fail before we can see them.
        # getpeercert(binary_form=False) only returns a parsed dict for *validated*
        # chains, so we pull the raw DER and parse it ourselves instead.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)

        if not der_cert:
            return TLSInfo(
                issuer=None,
                subject=None,
                not_before=None,
                not_after=None,
                age_days=None,
                self_signed=False,
                san_mismatch=False,
                error="no certificate returned",
            )

        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        not_before_dt = cert.not_valid_before_utc
        not_after_dt = cert.not_valid_after_utc
        age_days = (datetime.now(UTC) - not_before_dt).days

        self_signed = issuer == subject and bool(issuer)

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_entries = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_entries = []

        san_mismatch = bool(san_entries) and not any(
            hostname == san or (san.startswith("*.") and hostname.endswith(san[1:]))
            for san in san_entries
        )

        return TLSInfo(
            issuer=issuer or None,
            subject=subject or None,
            not_before=not_before_dt.isoformat(),
            not_after=not_after_dt.isoformat(),
            age_days=age_days,
            self_signed=self_signed,
            san_mismatch=san_mismatch,
        )
    except Exception as exc:  # noqa: BLE001 - report, don't crash the scan
        return TLSInfo(
            issuer=None,
            subject=None,
            not_before=None,
            not_after=None,
            age_days=None,
            self_signed=False,
            san_mismatch=False,
            error=str(exc),
        )


def _resolve_ip(hostname: str) -> str | None:
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def follow_redirects(url: str, client: httpx.Client | None = None) -> list[Hop]:
    """Manually walk a redirect chain, capturing per-hop metadata.

    Does NOT let httpx auto-follow redirects — each hop is a distinct request
    so we can log status/headers/timing/TLS/IP for every step.
    """
    owns_client = client is None
    client = client or httpx.Client(
        follow_redirects=False,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )

    hops: list[Hop] = []
    current_url = url
    seen: set[str] = set()

    try:
        for _ in range(MAX_HOPS):
            if current_url in seen:
                hops.append(
                    Hop(
                        url=current_url,
                        status_code=None,
                        headers={},
                        elapsed_ms=0,
                        error="redirect loop detected",
                    )
                )
                break
            seen.add(current_url)

            hostname = httpx.URL(current_url).host
            ip = _resolve_ip(hostname) if hostname else None
            scheme = httpx.URL(current_url).scheme

            start = time.perf_counter()
            try:
                resp = client.get(current_url)
                elapsed_ms = (time.perf_counter() - start) * 1000
            except httpx.HTTPError as exc:
                hops.append(
                    Hop(
                        url=current_url,
                        status_code=None,
                        headers={},
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                        ip=ip,
                        error=str(exc),
                    )
                )
                break

            tls_info = _get_tls_info(hostname) if scheme == "https" and hostname else None

            asn, asn_org = lookup_asn(ip) if ip else (None, None)

            hop = Hop(
                url=current_url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                elapsed_ms=elapsed_ms,
                ip=ip,
                asn=asn,
                asn_org=asn_org,
                tls=tls_info,
            )
            hops.append(hop)

            if resp.status_code in REDIRECT_STATUS_CODES and "location" in resp.headers:
                next_url = str(resp.next_request.url) if resp.next_request else None
                if not next_url:
                    next_url = str(httpx.URL(current_url).join(resp.headers["location"]))
                current_url = next_url
                continue

            break
    finally:
        if owns_client:
            client.close()

    return hops
