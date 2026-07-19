# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-07-19

### Added

- Detonation no longer requires an API key or pre-installed Docker: if
  Docker isn't ready, `vetlnk` now asks before doing anything about it
  ("Detonation requires the following dependencies not on your system.
  Install and run? [y/N]") and, on Linux, installs and starts it via the
  native package manager + systemd, falling back to `sudo docker` for that
  same run since a fresh `docker` group membership needs a new login to
  take effect. macOS/Windows (Docker Desktop, needs a GUI first-run) get a
  clear manual-install message instead of a fragile auto-install attempt.
- Expanded the detonation-mode starter YARA ruleset from 4 narrow rules to
  8: packed/high-entropy PEs, classic process-injection API combos,
  PowerShell download cradles, LOLBin abuse, Office macro auto-exec, ELF
  reverse-shell indicators, ransom-note strings, and base64-obfuscated
  scripts. Dropped a rule that claimed to check file extensions but never
  actually did.
- The analyzer image is now rebuilt automatically when the bundled
  Dockerfile/rules change, via a content-hash label — previously a cached
  image from an older vetlnk version would silently keep running outdated
  detection logic forever.
- `docker run` failures during static analysis now surface the container's
  actual stderr instead of a generic "produced no result" message.

### Fixed

- The downloaded sample's temp directory is now made readable by the
  analyzer container's fixed non-root uid — previously `tempfile.mkdtemp()`'s
  default owner-only permissions silently made every static-analysis run
  fail with a permission error once bind-mounted into the container.
- Release binaries now bundle the `docker` Python package (`pip install
  ".[detonate]"` in the release workflow) — previously `-d` could never
  work on an official release build regardless of what was installed on
  the host machine.

## [0.4.0] - 2026-07-19

### Added

- `vetlnk scan` now prompts interactively — `File detected: <name>. Detonate?
  [y/N]` — when a downloadable file is found and `-d`/`--detonate` wasn't
  passed, instead of requiring the flag to be known upfront. Answering `n`
  (or skipping the prompt in a non-interactive context) finishes the scan
  with the same report as a plain scan. `-d`/`--detonate` still detonates
  immediately with no prompt, for scripts and CI.

## [0.3.0] - 2026-07-19

### Added

- `vetlnk config export`/`vetlnk config import` — move linked API keys to
  another device via a passphrase-encrypted file (AES-256-GCM, scrypt-derived
  key), instead of re-pasting them into every new install.

## [0.2.1] - 2026-07-18

### Added

- `linux-arm64` added to the release build matrix.

### Fixed

- Scheme-less URLs (e.g. missing `https://`) are now normalized before
  scanning instead of failing.

## [0.2.0] - 2026-07-16

### Added

- macOS and Windows release binaries alongside Linux.

### Changed

- Install instructions updated: vetlnk isn't on PyPI, install from a GitHub
  release via `rack`.

### Fixed

- Release workflow was missing a checkout step, breaking `gh release create`.

### Removed

- `macos-13` (Intel) dropped from the release matrix.

## [0.1.0] - 2026-07-16

### Added

- Initial implementation of vetlnk: a fast, zero-friction link-vetting CLI
  with safe, read-only scanning by default.
- Docker-based detonation path for downloadable files, hardened and verified.
- Release workflow to publish a standalone Linux binary.
