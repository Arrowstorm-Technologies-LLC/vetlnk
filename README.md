# vetlnk

A fast, zero-friction command-line link-vetting tool for checking a suspicious
link **before you click it**.

By default, `vetlnk` does a safe, **read-only** vetting pass: no file
download, no execution, no signup required. An explicit opt-in flag
(`-d`/`--detonate`) attempts real detonation of a downloaded file, and fails
safely and clearly if it can't do that safely.

## Install

```bash
pipx install vetlnk
```

(Or `pip install vetlnk` inside a virtualenv if you don't use pipx.)

## Quickstart — no signup needed

```bash
vetlnk scan https://example.com
vetlnk scan https://example.com,https://another-site.example
```

That's it. With zero configuration, `vetlnk` will:

1. Manually follow the redirect chain (not auto-follow), logging every hop's
   URL, status code, headers, timing, TLS certificate info, and IP/ASN.
2. Run zero-signup reputation checks: Spamhaus DBL / SURBL DNS blocklist
   queries, WHOIS/RDAP domain-age lookup (freshly-registered domains are
   flagged), TLS certificate inspection, and local heuristics (punycode /
   homoglyph brand spoofing, suspicious TLDs, IP-literal URLs, excessive
   redirect depth, high-entropy paths, suspicious query parameters).
3. If the final hop offers a file download, determine its **true** file type
   from magic bytes (via a `HEAD` request and, if needed, a short ~256-byte
   ranged `GET` — never a full download) rather than trusting the declared
   `Content-Type` or filename extension. Mismatches (e.g. a `.pdf`-looking
   name that's actually a Windows executable) are flagged as a major red flag.
4. Print a color-coded risk report (`Clean` / `Low Risk` / `Suspicious` /
   `High Risk` / `Unknown`) with plain-language reasoning, not just a score.

## Optional: enhanced checks (VirusTotal / urlscan.io)

Enhanced multi-engine verdicts and screenshots from VirusTotal and urlscan.io
are entirely optional. Link an API key with:

```bash
vetlnk config
```

This opens an interactive menu. VirusTotal and urlscan.io don't support
OAuth/device-code login for third-party CLIs, so `vetlnk config` never fakes
an account link — it either takes a key you paste in, or opens the
provider's key page in your browser so you can copy your existing key. Keys
are validated immediately and stored in your OS keychain (macOS Keychain /
Windows Credential Manager / Linux Secret Service or KWallet), falling back
to a `0600`-permissioned `~/.config/vetlnk/config.toml` if no keychain
backend is available.

`VT_API_KEY` and `URLSCAN_API_KEY` environment variables are also supported
as a secondary path (useful for CI) — `vetlnk` checks the keychain/config
file first, then falls back to env vars.

If no keys are configured, `vetlnk` simply notes in the report that enhanced
checks were unavailable — it is never an error.

## Detonation mode (opt-in)

```bash
vetlnk scan <url> -d
```

Only triggers if the default scan found a downloadable file. `vetlnk` picks a
backend in this priority order and never falls back to running the file
locally:

1. **`VT_API_KEY` configured** — download the file, hash it, and submit the
   hash (or the file itself, if the hash is unknown to VirusTotal) for their
   sandbox verdict. Execution happens on VirusTotal's infrastructure, not
   locally.
2. **Docker available** — run static-only analysis (file-type via libmagic,
   entropy, strings, a small starter YARA ruleset) inside a network-isolated,
   ephemeral container. Still no execution — inspection only.
3. **Neither available** — `vetlnk` refuses immediately and tells you exactly
   why, rather than attempting any fallback that risks local execution.

Any file downloaded for detonation is securely deleted (overwritten, then
unlinked) immediately after analysis.

## SAFETY

| | Default scan | `-d` / `--detonate` |
|---|---|---|
| Downloads the file? | No — `HEAD` + a short ranged `GET` (~256 bytes) for magic-byte typing only | Yes, but only to VirusTotal's sandbox or an isolated local Docker container — never executed on your machine |
| Executes anything? | Never | Never locally. VirusTotal's sandbox executes it on their infrastructure; the Docker path only performs static inspection |
| Requires a signup? | No | No — but needs `VT_API_KEY` or Docker to do anything beyond refusing cleanly |
| Persists data? | No, unless `--cache-iocs` is set (local SQLite cache of hash/domain/verdict lookups, nothing else) | Same, plus downloaded files are securely deleted right after analysis |

## Output formats

```bash
vetlnk scan <url> --json report.json --markdown report.md
```

## Development

```bash
pip install -e ".[dev,vt]"
ruff check .
pytest
```

## License

MIT — see [LICENSE](LICENSE).
