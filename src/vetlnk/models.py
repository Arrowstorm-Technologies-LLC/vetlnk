"""Shared data models for a single URL's scan result."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class RiskLevel(StrEnum):
    CLEAN = "Clean"
    LOW = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH = "High Risk"
    UNKNOWN = "Unknown"


@dataclass
class Hop:
    url: str
    status_code: int | None
    headers: dict[str, str]
    elapsed_ms: float
    ip: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    tls: TLSInfo | None = None
    error: str | None = None


@dataclass
class TLSInfo:
    issuer: str | None
    subject: str | None
    not_before: str | None
    not_after: str | None
    age_days: int | None
    self_signed: bool
    san_mismatch: bool
    error: str | None = None


@dataclass
class DomainInfo:
    domain: str
    registered_on: str | None = None
    age_days: int | None = None
    registrar: str | None = None
    error: str | None = None


@dataclass
class DnsblResult:
    list_name: str
    listed: bool
    detail: str | None = None
    error: str | None = None


@dataclass
class HeuristicFinding:
    name: str
    triggered: bool
    detail: str = ""
    severity: str = "info"  # info | low | medium | high


@dataclass
class FileInfo:
    declared_filename: str | None
    declared_content_type: str | None
    content_length: int | None
    true_type: str | None
    true_type_source: str = "magic-bytes"
    type_mismatch: bool = False
    risk_note: str | None = None
    hosting_domain: str | None = None


@dataclass
class ProviderVerdict:
    provider: str
    available: bool
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    total_engines: int | None = None
    permalink: str | None = None
    screenshot_url: str | None = None
    note: str | None = None
    error: str | None = None


@dataclass
class DetonationResult:
    attempted: bool
    backend: str | None = None  # "virustotal" | "docker-static" | None
    verdict: str | None = None
    details: dict = field(default_factory=dict)
    refused_reason: str | None = None


@dataclass
class ScanResult:
    input_url: str
    hops: list[Hop] = field(default_factory=list)
    final_url: str | None = None
    domain_info: DomainInfo | None = None
    dnsbl_results: list[DnsblResult] = field(default_factory=list)
    heuristics: list[HeuristicFinding] = field(default_factory=list)
    file_info: FileInfo | None = None
    provider_verdicts: list[ProviderVerdict] = field(default_factory=list)
    detonation: DetonationResult | None = None
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_reasons: list[str] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)
