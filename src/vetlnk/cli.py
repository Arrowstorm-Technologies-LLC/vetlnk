"""vetlnk CLI entry point."""

from __future__ import annotations

import signal

import httpx
import typer
from rich.console import Console

from vetlnk import config as config_module
from vetlnk import report
from vetlnk.detonate import run_detonation
from vetlnk.enhanced import run_enhanced_checks
from vetlnk.models import ScanResult
from vetlnk.risk import synthesize_risk
from vetlnk.scanner import scan_url


def _raise_keyboard_interrupt(signum, frame):
    raise KeyboardInterrupt()


# Plain `kill <pid>` sends SIGTERM, which — unlike Ctrl+C's SIGINT — Python
# does *not* turn into a catchable exception by default, so the try/finally
# cleanup around detonation (secure-deleting the downloaded sample, killing
# and removing the analysis container) would silently be skipped. Converting
# it to a KeyboardInterrupt makes an ordinary `kill` unwind through those
# finally blocks the same way Ctrl+C already does. `kill -9` (SIGKILL) is
# fundamentally uncatchable by any process — no signal handler can run for
# it — so it isn't covered by this; the container's own baked-in wall-clock
# timeout plus Docker's daemon-side auto-remove are what bound the damage
# in that case instead. See detonate.py and the README's detonation
# verification section.
signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)

app = typer.Typer(
    name="vetlnk",
    help="Vet a suspicious link before you click it — safe, read-only by default.",
    no_args_is_help=True,
)
config_module.register(app)


@app.command("scan")
def scan(
    urls: str = typer.Argument(..., help="One or more URLs, comma-separated."),
    detonate: bool = typer.Option(
        False, "-d", "--detonate", help="Attempt safe detonation of any downloadable file found."
    ),
    cache_iocs: bool = typer.Option(
        False, "--cache-iocs", help="Cache hash/domain/verdict lookups locally in SQLite."
    ),
    json_out: str | None = typer.Option(None, "--json", help="Write a JSON report to this path."),
    markdown_out: str | None = typer.Option(
        None, "--markdown", help="Write a Markdown report to this path."
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Show extra diagnostic detail."),
) -> None:
    """Run the default safe, read-only vetting pass on one or more URLs."""
    console = Console()
    targets = [u.strip() for u in urls.split(",") if u.strip()]
    if not targets:
        console.print("[red]No URLs provided.[/red]")
        raise typer.Exit(code=1)

    results: list[ScanResult] = []
    with httpx.Client(follow_redirects=False, timeout=10.0) as client:
        for url in targets:
            with console.status(f"Scanning {url}..."):
                result = scan_url(url, client=client, use_cache=cache_iocs)
                run_enhanced_checks(result, use_cache=cache_iocs)

                if detonate:
                    if result.file_info:
                        with console.status("Attempting detonation..."):
                            result.detonation = run_detonation(result)
                    else:
                        result.scan_errors.append(
                            "-d/--detonate requested but no downloadable file was found."
                        )

                synthesize_risk(result)
            results.append(result)
            report.render_terminal(result, console)
            console.print()

    if json_out:
        report.write_json(results, json_out)
        console.print(f"[dim]JSON report written to {json_out}[/dim]")
    if markdown_out:
        report.write_markdown(results, markdown_out)
        console.print(f"[dim]Markdown report written to {markdown_out}[/dim]")


if __name__ == "__main__":
    app()
