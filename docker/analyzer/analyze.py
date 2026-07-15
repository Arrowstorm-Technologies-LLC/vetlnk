"""Static-only analysis entrypoint run inside the network-isolated vetlnk-analyzer
container. Reads a single file, never executes it, prints a JSON verdict.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

import magic
import yara

RULES_DIR = Path("/rules")
MIN_STRING_LEN = 5
MAX_STRINGS = 40
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> list[str]:
    found = [m.group().decode("ascii", errors="replace") for m in _PRINTABLE_RE.finditer(data)]
    return found[:limit]


def compile_rules() -> yara.Rules | None:
    rule_files = {p.stem: str(p) for p in RULES_DIR.glob("*.yar")}
    if not rule_files:
        return None
    return yara.compile(filepaths=rule_files)


def main() -> None:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: analyze.py <path>"}))
        sys.exit(1)

    path = Path(sys.argv[1])
    data = path.read_bytes()

    result = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "magic_type": magic.from_buffer(data),
        "magic_mime": magic.from_buffer(data, mime=True),
        "entropy": round(shannon_entropy(data), 3),
        "sample_strings": extract_strings(data),
        "yara_matches": [],
    }

    rules = compile_rules()
    if rules is not None:
        matches = rules.match(data=data)
        result["yara_matches"] = [m.rule for m in matches]

    print(json.dumps(result))


if __name__ == "__main__":
    main()
