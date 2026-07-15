"""API key storage (OS keychain via `keyring`, with a permission-locked TOML
fallback) and the `vetlnk config` interactive menu.

VirusTotal and urlscan.io have no OAuth/device-code login for third-party CLIs,
so this never fakes a login flow — it only stores a key you paste in yourself,
optionally after opening the provider's key page in your browser to copy it from.
"""

from __future__ import annotations

import os
import stat
import webbrowser
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import keyring
import keyring.errors
import tomli_w
import typer
from rich.console import Console
from rich.table import Table

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

from vetlnk.providers.base import REGISTRY

_SERVICE_NAME = "vetlnk"
_CONFIG_DIR = Path(os.environ.get("VETLNK_CONFIG_DIR", Path.home() / ".config" / "vetlnk"))
_CONFIG_FILE = _CONFIG_DIR / "config.toml"


@dataclass
class ProviderStatus:
    provider_id: str
    linked: bool
    backend: str | None = None
    last_checked: str | None = None


def _load_file_config() -> dict:
    if not _CONFIG_FILE.exists():
        return {}
    with _CONFIG_FILE.open("rb") as f:
        return tomllib.load(f)


def _save_file_config(data: dict) -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with _CONFIG_FILE.open("wb") as f:
        tomli_w.dump(data, f)
    _CONFIG_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600


def _keyring_available() -> bool:
    try:
        backend = keyring.get_keyring()
        return not isinstance(backend, keyring.backends.fail.Keyring)
    except Exception:  # noqa: BLE001
        return False


def get_key(provider_id: str) -> str | None:
    """Stored-key lookup only (keychain, then config-file fallback). Env vars are
    checked separately by callers, per the spec's keychain-first / env-var-second order.
    """
    try:
        key = keyring.get_password(_SERVICE_NAME, provider_id)
        if key:
            return key
    except keyring.errors.KeyringError:
        pass

    data = _load_file_config()
    return data.get(provider_id, {}).get("key")


def store_key(provider_id: str, key: str) -> str:
    """Store a validated key; returns the backend used ("keyring" or "file")."""
    now = datetime.now(UTC).isoformat()

    if _keyring_available():
        try:
            keyring.set_password(_SERVICE_NAME, provider_id, key)
            data = _load_file_config()
            data[provider_id] = {"linked": True, "backend": "keyring", "last_checked": now}
            _save_file_config(data)
            return "keyring"
        except keyring.errors.KeyringError:
            pass

    data = _load_file_config()
    data[provider_id] = {"linked": True, "backend": "file", "last_checked": now, "key": key}
    _save_file_config(data)
    return "file"


def unlink_key(provider_id: str) -> None:
    try:
        keyring.delete_password(_SERVICE_NAME, provider_id)
    except keyring.errors.KeyringError:
        pass

    data = _load_file_config()
    if provider_id in data:
        del data[provider_id]
        _save_file_config(data)


def get_status(provider_id: str) -> ProviderStatus:
    data = _load_file_config().get(provider_id, {})
    key = get_key(provider_id)
    return ProviderStatus(
        provider_id=provider_id,
        linked=bool(key),
        backend=data.get("backend"),
        last_checked=data.get("last_checked"),
    )


def run_config_menu(console: Console) -> None:
    import questionary

    console.print(
        "[bold]vetlnk config[/bold] — link optional API keys for enhanced reputation checks.\n"
        "[dim]VirusTotal and urlscan.io don't support CLI login (no OAuth/device-code flow), "
        "so this only stores a key you paste in yourself.[/dim]\n"
    )

    while True:
        table = Table(title="Linked providers")
        table.add_column("Provider")
        table.add_column("Status")
        table.add_column("Storage")
        table.add_column("Last checked")
        for provider in REGISTRY.values():
            status = get_status(provider.id)
            state = "[green]linked[/green]" if status.linked else "[dim]not linked[/dim]"
            table.add_row(
                provider.display_name, state, status.backend or "-", status.last_checked or "-"
            )
        console.print(table)

        choices = [
            questionary.Choice(title=p.display_name, value=p.id) for p in REGISTRY.values()
        ]
        choices.append(questionary.Choice(title="Exit", value="__exit__"))
        selected = questionary.select("Select a provider:", choices=choices).ask()

        if selected is None or selected == "__exit__":
            break

        _configure_provider(console, REGISTRY[selected])


def _configure_provider(console: Console, provider) -> None:
    import questionary

    status = get_status(provider.id)
    action_choices = [
        questionary.Choice(title="Paste API key directly", value="paste"),
        questionary.Choice(title="Open provider's API key page in my browser", value="browser"),
    ]
    if status.linked:
        action_choices.append(
            questionary.Choice(title="Unlink (delete stored key)", value="unlink")
        )
    action_choices.append(questionary.Choice(title="Back", value="back"))

    action = questionary.select(f"{provider.display_name}:", choices=action_choices).ask()

    if action is None or action == "back":
        return

    if action == "unlink":
        unlink_key(provider.id)
        console.print(f"[yellow]Unlinked {provider.display_name}.[/yellow]")
        return

    if action == "browser":
        console.print(
            f"[dim]Opening {provider.key_page_url} — log in there, copy your existing key, "
            "then come back here to paste it. This does not link your account automatically.[/dim]"
        )
        webbrowser.open(provider.key_page_url)

    key = questionary.password(f"Paste your {provider.display_name} API key:").ask()
    if not key:
        console.print("[dim]No key entered — nothing changed.[/dim]")
        return

    console.print("Validating key...")
    is_valid, message = provider.validate(key)
    if not is_valid:
        console.print(f"[red]{message}[/red]")
        return

    backend = store_key(provider.id, key)
    console.print(f"[green]{message} Stored via {backend}.[/green]")


def register(app: typer.Typer) -> None:
    @app.command("config")
    def config_command() -> None:
        """Interactively link/unlink VirusTotal and urlscan.io API keys."""
        console = Console()
        run_config_menu(console)
