# vetlnk

A fast, zero-friction command-line link-vetting tool for checking a suspicious
link **before you click it**.

By default, `vetlnk` does a safe, **read-only** vetting pass: no file
download, no execution, no signup required. An explicit opt-in flag
(`-d`/`--detonate`) attempts real detonation of a downloaded file, and fails
safely and clearly if it can't do that safely.

## Install

`vetlnk` isn't published on PyPI — install it from a GitHub release instead.

### Via [rack](https://github.com/Arrowstorm-Technologies-LLC/rack) (recommended)

Each tagged release publishes standalone binaries for Linux, macOS
(Apple Silicon and Intel), and Windows — built by
[`.github/workflows/release.yml`](.github/workflows/release.yml), no Python
needed on the target machine. `rack` itself is a single cross-platform
binary too, so this works the same way in any terminal on any of the three:

```bash
rack vetlnk Arrowstorm-Technologies-LLC/vetlnk
```

This resolves the latest release, auto-selects the asset matching your OS
and architecture, installs it (`~/.local/bin/vetlnk` on Linux/macOS,
`%LOCALAPPDATA%\rack\bin\vetlnk.exe` on Windows), and registers it so
`rack update` picks up future releases automatically.

### Manual binary download

Grab the asset matching your platform from the [latest
release](https://github.com/Arrowstorm-Technologies-LLC/vetlnk/releases/latest)
(`vetlnk-linux-x86_64`, `vetlnk-macos-arm64`, `vetlnk-macos-x86_64`, or
`vetlnk-windows-amd64.exe`), then:

```bash
chmod +x vetlnk-linux-x86_64   # or the macOS asset
mv vetlnk-linux-x86_64 ~/.local/bin/vetlnk
```

### From source

```bash
git clone https://github.com/Arrowstorm-Technologies-LLC/vetlnk.git
cd vetlnk
pip install -e .
```

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
   entropy, strings, a small starter YARA ruleset) inside an ephemeral
   container hardened as follows — see [Verifying detonation
   mode](#verifying-detonation-mode) below to confirm all of this yourself:
   - `--network none` (no egress, no DNS)
   - non-root, unprivileged user (uid 10001), `--cap-drop ALL`,
     `no-new-privileges`
   - read-only root filesystem, with a single `noexec` tmpfs scratch mount
     for `/tmp` — the sample itself is bind-mounted read-only, never written to
   - memory (512MB, no swap headroom), CPU (1 core), and process-count (64)
     limits
   - a wall-clock cutoff baked into the container's own command (via
     coreutils' `timeout`), so a hung analysis is bounded even if the
     `vetlnk` process itself dies mid-run — combined with Docker's daemon-side
     `--rm`, the container cleans itself up independent of the host process
3. **Neither available** — `vetlnk` refuses immediately and tells you exactly
   why, rather than attempting any fallback that risks local execution.

Any file downloaded for detonation is securely deleted (overwritten, then
unlinked) as soon as analysis finishes — or as soon as an ordinary `kill` or
Ctrl+C interrupts it. `kill -9` can't be caught by any process (that's true
of all software, not a vetlnk gap) — the container-side timeout + Docker's
own auto-remove are what bound *that* case instead; see the note in
[Verifying detonation mode](#verifying-detonation-mode).

## SAFETY

| | Default scan | `-d` / `--detonate` |
|---|---|---|
| Downloads the file? | No — `HEAD` + a short ranged `GET` (~256 bytes) for magic-byte typing only | Yes, but only to VirusTotal's sandbox or an isolated local Docker container — never executed on your machine |
| Executes anything? | Never | Never locally. VirusTotal's sandbox executes it on their infrastructure; the Docker path only performs static inspection |
| Requires a signup? | No | No — but needs `VT_API_KEY` or Docker to do anything beyond refusing cleanly |
| Persists data? | No, unless `--cache-iocs` is set (local SQLite cache of hash/domain/verdict lookups, nothing else) | Same, plus downloaded files are securely deleted right after analysis |

## Verifying detonation mode

The Docker static-analysis fallback can't be exercised in most CI/sandbox
environments (no Docker daemon available), so it's worth confirming
end-to-end on your own machine before trusting it against anything real. Run
these three checks — each one is copy-pasteable as-is.

**0. Build the analyzer image once** (vetlnk will also auto-build it on the
first `-d` run if it's missing; this just lets you inspect the build/output
directly):

```bash
docker build -t vetlnk-analyzer:latest \
  "$(python3 -c 'import vetlnk, pathlib; print(pathlib.Path(vetlnk.__file__).parent / "analyzer_image")')"
```

### a) Happy path against a known-benign file

```bash
mkdir -p /tmp/vetlnk-verify && cd /tmp/vetlnk-verify
echo "hello from vetlnk verification" > hello.txt
zip test.zip hello.txt
python3 -m http.server 8934 --bind 127.0.0.1 &

vetlnk scan http://127.0.0.1:8934/test.zip -d --verbose
```

Expect `backend: docker-static`, a `verdict` of `no static rule matches`, and
`details` containing `sha256`/`size_bytes`/`magic_type: Zip archive data`. To
also see the type-mismatch + high-risk path, try a fake executable instead:

```bash
printf 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' > invoice.pdf
vetlnk scan http://127.0.0.1:8934/invoice.pdf -d --verbose
# kill %1  # stop the http.server when done
```

### b) Confirm network egress is actually blocked

The analyzer image deliberately has no `curl`/`ping` installed (smaller
attack surface), but it does have Python, which is enough to prove the
point. First, the isolated case — this **must fail**:

```bash
docker run --rm --network none --user 10001:10001 --read-only \
  --tmpfs /tmp:size=16m vetlnk-analyzer:latest \
  timeout 5 python3 -c "import urllib.request; urllib.request.urlopen('http://1.1.1.1', timeout=3); print('REACHED')"
echo "exit code: $?"   # expect non-zero, and no REACHED line
```

Then the control case, *without* `--network none` — this should succeed, to
prove the failure above is really about the isolation flag and not, say, a
broken Docker network on your machine:

```bash
docker run --rm --user 10001:10001 --read-only --tmpfs /tmp:size=16m \
  vetlnk-analyzer:latest \
  timeout 5 python3 -c "import urllib.request; urllib.request.urlopen('http://1.1.1.1', timeout=3); print('REACHED')"
echo "exit code: $?"   # expect 0 and a REACHED line (proves the test itself is valid)
```

### c) Confirm cleanup after a forced kill

Plain `kill` (SIGTERM) and Ctrl+C (SIGINT) are caught by `vetlnk` and trigger
its normal cleanup — the downloaded sample is securely deleted and any
analysis container is killed and removed, the same way a clean exit would.
**`kill -9` (SIGKILL) cannot be caught by any process, ever** — that's an OS
guarantee, not something any tool can work around — so it isn't a fair test
of vetlnk's own cleanup code; it's only useful for confirming the *backstop*
(Docker's own daemon-side auto-remove + the container's baked-in timeout)
still bounds the damage even when nothing in the vetlnk process gets to run.

A plain `python3 -m http.server` on localhost serves too fast to reliably
land a signal mid-download, so drip-feed a file slowly instead — this
matches what a slow/adversarial server looks like from vetlnk's side, and is
exactly what was used to validate this behavior during development:

```bash
cat > /tmp/slow_server.py <<'EOF'
import http.server, time

class SlowHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", "20000000")
        self.end_headers()
        self.wfile.write(b"PK\x03\x04" + b"\x00" * 96)  # valid ZIP magic bytes
        for _ in range(200):
            self.wfile.write(b"A" * 100000)
            self.wfile.flush()
            time.sleep(0.3)   # ~60s total — plenty of window to signal into

http.server.HTTPServer(("127.0.0.1", 8935), SlowHandler).serve_forever()
EOF
python3 /tmp/slow_server.py &

# --- graceful case: plain kill / Ctrl+C, cleanup IS expected ---
vetlnk scan "http://127.0.0.1:8935/payload.zip" -d --verbose &
VPID=$!
sleep 2                      # confirm it's mid-download before signaling
kill $VPID                   # plain SIGTERM, not -9
sleep 1
docker ps -a --filter "label=vetlnk-analysis"   # expect: empty
ls /tmp | grep vetlnk-detonate                  # expect: nothing

# --- SIGKILL case: only the container-side backstop applies ---
vetlnk scan "http://127.0.0.1:8935/payload.zip" -d --verbose &
VPID=$!
sleep 2
kill -9 $VPID
sleep 1
ps -p $VPID                                     # expect: gone
docker ps -a --filter "label=vetlnk-analysis"   # expect: empty within ~95s
                                                 # (the container's own internal
                                                 # `timeout` + Docker's --rm clean
                                                 # it up on their own timeline,
                                                 # independent of the dead host
                                                 # process — give it a moment)
ls /tmp | grep vetlnk-detonate                  # a leftover HERE is expected —
                                                 # nothing can run in the host
                                                 # process after SIGKILL, so the
                                                 # downloaded sample's temp file
                                                 # is not cleaned up in this one
                                                 # case; a plain
                                                 # `rm -rf /tmp/vetlnk-detonate-*`
                                                 # clears it (or a reboot will)

kill %1   # stop slow_server.py when done
```

If Docker is running on your machine, this also exercises the actual
container lifecycle (isolation flags, timeout, auto-remove) end-to-end,
which the automated test suite can only assert the *invocation shape* of
(see `tests/test_detonate_docker_hardening.py`) since there's no Docker
daemon available in most CI/sandbox environments.

## Output formats

```bash
vetlnk scan <url> --json report.json --markdown report.md
```

## Development

```bash
pip install -e ".[dev,vt,detonate]"
ruff check .
pytest
```

## License

MIT — see [LICENSE](LICENSE).
