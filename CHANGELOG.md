# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
