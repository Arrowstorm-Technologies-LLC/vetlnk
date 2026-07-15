"""Report rendering: rich terminal output plus --json / --markdown export."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vetlnk.models import RiskLevel, ScanResult

_RISK_STYLE = {
    RiskLevel.CLEAN: "bold green",
    RiskLevel.LOW: "bold cyan",
    RiskLevel.SUSPICIOUS: "bold yellow",
    RiskLevel.HIGH: "bold red",
    RiskLevel.UNKNOWN: "bold white on grey35",
}


def render_terminal(result: ScanResult, console: Console) -> None:
    style = _RISK_STYLE.get(result.risk_level, "bold white")
    header = Text(f"{result.risk_level.value}", style=style)
    console.print(Panel(header, title=f"vetlnk report — {result.input_url}", expand=False))

    if result.risk_reasons:
        console.print("[bold]Why:[/bold]")
        for reason in result.risk_reasons:
            console.print(f"  • {reason}")
        console.print()

    if result.hops:
        table = Table(title="Redirect chain", show_lines=False)
        table.add_column("#")
        table.add_column("URL", overflow="fold")
        table.add_column("Status")
        table.add_column("IP / ASN")
        table.add_column("TLS")
        table.add_column("ms")
        for i, hop in enumerate(result.hops, start=1):
            tls_note = "-"
            if hop.tls:
                if hop.tls.error:
                    tls_note = "err"
                else:
                    flags = []
                    if hop.tls.self_signed:
                        flags.append("self-signed")
                    if hop.tls.san_mismatch:
                        flags.append("SAN mismatch")
                    tls_note = ", ".join(flags) if flags else "ok"
            ip_asn = hop.ip or "-"
            if hop.asn:
                ip_asn += f" ({hop.asn}{' ' + hop.asn_org if hop.asn_org else ''})"
            table.add_row(
                str(i),
                hop.url,
                str(hop.status_code) if hop.status_code else (hop.error or "error"),
                ip_asn,
                tls_note,
                f"{hop.elapsed_ms:.0f}",
            )
        console.print(table)

    if result.domain_info:
        di = result.domain_info
        if di.error:
            console.print(f"[dim]Domain age: unavailable ({di.error})[/dim]")
        else:
            console.print(
                f"[bold]Domain age:[/bold] {di.age_days} days "
                f"(registered {di.registered_on}, registrar: {di.registrar or 'unknown'})"
            )

    if result.dnsbl_results:
        listed = [d for d in result.dnsbl_results if d.listed]
        clean = [d for d in result.dnsbl_results if not d.listed and not d.error]
        console.print(
            "[bold]DNSBL:[/bold] "
            + (f"[red]listed on {', '.join(d.list_name for d in listed)}[/red] " if listed else "")
            + (f"clean on {', '.join(d.list_name for d in clean)}" if clean else "")
        )

    if result.file_info:
        fi = result.file_info
        mismatch_note = " [bold red](TYPE MISMATCH)[/bold red]" if fi.type_mismatch else ""
        console.print(
            f"[bold]File:[/bold] {fi.declared_filename or 'unknown'} — true type: "
            f"{fi.true_type}{mismatch_note}"
        )
        if fi.risk_note:
            console.print(f"  [dim]{fi.risk_note}[/dim]")

    if result.provider_verdicts:
        for v in result.provider_verdicts:
            if not v.available:
                console.print(f"[dim]{v.provider}: not configured — {v.note or 'skipped'}[/dim]")
            elif v.error:
                console.print(f"[dim]{v.provider}: error — {v.error}[/dim]")
            else:
                console.print(
                    f"[bold]{v.provider}:[/bold] {v.malicious or 0} malicious / "
                    f"{v.suspicious or 0} suspicious / {v.total_engines or 0} engines"
                )

    if result.detonation and result.detonation.attempted:
        det = result.detonation
        if det.refused_reason:
            console.print(f"[bold yellow]Detonation refused:[/bold yellow] {det.refused_reason}")
        else:
            console.print(f"[bold]Detonation ({det.backend}):[/bold] {det.verdict}")

    if result.scan_errors:
        console.print()
        for err in result.scan_errors:
            console.print(f"[dim yellow]note: {err}[/dim yellow]")


def to_dict(result: ScanResult) -> dict:
    data = asdict(result)
    data["risk_level"] = result.risk_level.value
    return data


def write_json(results: list[ScanResult], path: str) -> None:
    payload = [to_dict(r) for r in results]
    Path(path).write_text(json.dumps(payload, indent=2, default=str))


def write_markdown(results: list[ScanResult], path: str) -> None:
    lines: list[str] = ["# vetlnk report", ""]
    for result in results:
        lines.append(f"## {result.input_url}")
        lines.append("")
        lines.append(f"**Risk level:** {result.risk_level.value}")
        lines.append("")
        if result.risk_reasons:
            lines.append("**Why:**")
            for reason in result.risk_reasons:
                lines.append(f"- {reason}")
            lines.append("")

        if result.hops:
            lines.append("**Redirect chain:**")
            lines.append("")
            lines.append("| # | URL | Status | IP / ASN | ms |")
            lines.append("|---|-----|--------|----------|----|")
            for i, hop in enumerate(result.hops, start=1):
                ip_asn = hop.ip or "-"
                if hop.asn:
                    ip_asn += f" ({hop.asn})"
                status = str(hop.status_code) if hop.status_code else (hop.error or "error")
                lines.append(f"| {i} | {hop.url} | {status} | {ip_asn} | {hop.elapsed_ms:.0f} |")
            lines.append("")

        if result.domain_info and not result.domain_info.error:
            di = result.domain_info
            lines.append(f"**Domain age:** {di.age_days} days (registered {di.registered_on})")
            lines.append("")

        if result.file_info:
            fi = result.file_info
            mismatch = " **(TYPE MISMATCH)**" if fi.type_mismatch else ""
            lines.append(
                f"**File:** {fi.declared_filename or 'unknown'} — "
                f"true type: {fi.true_type}{mismatch}"
            )
            lines.append("")

        if result.scan_errors:
            lines.append("**Notes:**")
            for err in result.scan_errors:
                lines.append(f"- {err}")
            lines.append("")

    Path(path).write_text("\n".join(lines))
