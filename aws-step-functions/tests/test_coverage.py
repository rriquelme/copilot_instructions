#!/usr/bin/env python3
"""test_coverage.py - every diagnostic code the linter can emit must be pinned by at least one golden fixture.

Collects every code literal in scripts/lint_asl.py (regex [SJVP]\\d{3}) and every code that appears in an expected
file (tests/expected/*.expected.json, plus tests/optional/*.expected.json for codes that need an optional parser,
such as J006). Fails, listing the missing codes, when a code is never expected anywhere: add a fixture that fires it
(tests/fixtures/<code>_<what>.json) and one that stays clean (ok_<what>.json), then
python3 tests/run_tests.py --update <code>_. Nothing is hard-coded, so codes added later are checked too.

Usage: python3 tests/test_coverage.py      exit 1 when a code is not covered. Standard library only (Python 3.9+).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LINTER = HERE.parent / "scripts" / "lint_asl.py"
CODE_RE = re.compile(r"\b[SJVP]\d{3}\b")


def linter_codes() -> set[str]:
    return set(CODE_RE.findall(LINTER.read_text(encoding="utf-8")))


def expected_codes() -> dict[str, set[str]]:
    """code -> names of the expected files that contain it."""
    out: dict[str, set[str]] = {}
    for d in (HERE / "expected", HERE / "optional"):
        for p in sorted(d.glob("*.expected.json")) if d.is_dir() else []:
            for row in json.loads(p.read_text(encoding="utf-8")).get("diagnostics", []):
                out.setdefault(row[1], set()).add(p.name)
    return out


def main() -> int:
    codes = linter_codes()
    covered = expected_codes()
    missing = sorted(c for c in codes if c not in covered)
    stale = sorted(c for c in covered if c not in codes)
    print(f"{len(codes)} code(s) in lint_asl.py, {len(codes) - len(missing)} covered by an expected file")
    if stale:
        print(f"note: expected files mention codes the linter no longer has: {' '.join(stale)}")
    if missing:
        print(f"FAIL no fixture expects: {' '.join(missing)}")
        print("    add tests/fixtures/<code>_<what>.json (fires) and ok_<what>.json (stays clean), then run "
              "python3 tests/run_tests.py --update <code>_")
        return 1
    print("-- all codes covered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
