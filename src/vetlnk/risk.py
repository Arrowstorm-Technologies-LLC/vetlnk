"""Synthesizes all collected signals into a single risk rating with reasoning.

This is deliberately a weighted heuristic sum, not a black-box "score" — every
point added is tied to a human-readable reason so the report can explain itself.
"""

from __future__ import annotations

from vetlnk.models import RiskLevel, ScanResult

_SEVERITY_WEIGHTS = {"high": 30, "medium": 15, "low": 5, "info": 0}


def synthesize_risk(result: ScanResult) -> None:
    """Populate result.risk_level and result.risk_reasons in place."""
    score = 0
    reasons: list[str] = []
    had_any_signal = False

    for hop in result.hops:
        if hop.error:
            continue
        had_any_signal = True

    for dnsbl in result.dnsbl_results:
        if dnsbl.listed:
            had_any_signal = True
            score += 75
            reasons.append(f"Listed on {dnsbl.list_name} ({dnsbl.detail}).")

    if result.domain_info and result.domain_info.age_days is not None:
        had_any_signal = True
        age = result.domain_info.age_days
        if age < 7:
            score += 35
            reasons.append(f"Domain registered only {age} day(s) ago — very freshly created.")
        elif age < 30:
            score += 20
            reasons.append(
                f"Domain registered {age} days ago — under the 30-day freshness threshold."
            )

    for hop in result.hops:
        if not hop.tls:
            continue
        had_any_signal = True
        if hop.tls.self_signed:
            score += 25
            reasons.append(f"Self-signed TLS certificate on {hop.url}.")
        if hop.tls.san_mismatch:
            score += 20
            reasons.append(f"TLS certificate SAN does not match hostname on {hop.url}.")
        if hop.tls.age_days is not None and hop.tls.age_days < 2:
            score += 15
            reasons.append(f"TLS certificate issued within the last 2 days on {hop.url}.")

    for finding in result.heuristics:
        if finding.triggered:
            had_any_signal = True
            score += _SEVERITY_WEIGHTS.get(finding.severity, 0)
            reasons.append(finding.detail)

    if result.file_info:
        had_any_signal = True
        if result.file_info.type_mismatch:
            score += 75
            reasons.append(
                f"Declared file '{result.file_info.declared_filename}' does not match its true "
                f"type ({result.file_info.true_type}) — a common malware-delivery trick."
            )
        elif result.file_info.true_type in {
            "Windows PE executable (.exe/.dll/.scr/.com)",
            "Linux ELF executable/library",
            "Script with shebang (shell/interpreter)",
        }:
            score += 20
            reasons.append(f"Link serves an executable file ({result.file_info.true_type}).")

    for verdict in result.provider_verdicts:
        if not verdict.available:
            continue
        had_any_signal = True
        if verdict.malicious:
            ratio_note = (
                f"{verdict.malicious}/{verdict.total_engines}"
                if verdict.total_engines
                else str(verdict.malicious)
            )
            score += min(50, 15 + verdict.malicious * 5)
            reasons.append(f"{verdict.provider} flagged as malicious by {ratio_note} engines.")
        elif verdict.suspicious:
            score += 15
            reasons.append(
                f"{verdict.provider} flagged as suspicious by {verdict.suspicious} engine(s)."
            )

    if result.detonation and result.detonation.verdict:
        had_any_signal = True
        if "malicious" in result.detonation.verdict.lower():
            score += 40
            reasons.append(f"Detonation verdict: {result.detonation.verdict}.")

    if not had_any_signal:
        result.risk_level = RiskLevel.UNKNOWN
        result.risk_reasons = reasons or ["Not enough data was gathered to form a rating."]
        return

    if score >= 70:
        level = RiskLevel.HIGH
    elif score >= 40:
        level = RiskLevel.SUSPICIOUS
    elif score >= 15:
        level = RiskLevel.LOW
    else:
        level = RiskLevel.CLEAN
        reasons = reasons or ["No notable risk signals detected."]

    result.risk_level = level
    result.risk_reasons = reasons
