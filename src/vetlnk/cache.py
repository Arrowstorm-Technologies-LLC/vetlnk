"""Opt-in local IOC cache (`--cache-iocs`). Off by default — nothing persists
between runs unless the flag is set. Stores hash/domain/verdict lookups in
SQLite so repeat scans of the same indicator can hit cache before re-querying.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

_CACHE_DIR = Path(os.environ.get("VETLNK_CONFIG_DIR", Path.home() / ".config" / "vetlnk"))
_CACHE_FILE = _CACHE_DIR / "ioc_cache.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_cache (
    indicator_type TEXT NOT NULL,   -- 'domain' | 'hash'
    indicator TEXT NOT NULL,
    provider TEXT NOT NULL,         -- e.g. 'virustotal', 'urlscan', 'dnsbl', 'whois'
    verdict_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (indicator_type, indicator, provider)
);
"""


@contextmanager
def _connect():
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_CACHE_FILE)
    try:
        conn.execute(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def get(indicator_type: str, indicator: str, provider: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT verdict_json FROM ioc_cache WHERE indicator_type = ? AND indicator = ? "
            "AND provider = ?",
            (indicator_type, indicator, provider),
        ).fetchone()
    return json.loads(row[0]) if row else None


def put(indicator_type: str, indicator: str, provider: str, verdict: dict) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO ioc_cache (indicator_type, indicator, provider, verdict_json, fetched_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(indicator_type, indicator, provider) DO UPDATE SET "
            "verdict_json = excluded.verdict_json, fetched_at = excluded.fetched_at",
            (
                indicator_type,
                indicator,
                provider,
                json.dumps(verdict),
                datetime.now(UTC).isoformat(),
            ),
        )
