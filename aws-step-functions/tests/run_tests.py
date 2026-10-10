#!/usr/bin/env python3
"""run_tests.py - golden-file tests for scripts/lint_asl.py.

Usage:
    python3 tests/run_tests.py            run every fixture, compare with tests/expected/
    python3 tests/run_tests.py --update   rewrite tests/expected/ from the current linter output
    python3 tests/run_tests.py <name>...  run only fixtures whose file name contains <name>

Each tests/fixtures/<file> has tests/expected/<file>.expected.json:
    {"type": "STANDARD" | "EXPRESS", "diagnostics": [[severity, code, location], ...]}
Messages are not compared, so rewording a message does not break tests; adding, removing or
moving a diagnostic does. The optional jsonata-python parser is disabled so results are the
same on every machine. Exit code 1 when any test fails. Standard library only (Python 3.9+).
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
EXPECTED = HERE / "expected"


def load_linter():
    sys.dont_write_bytecode = True  # keep __pycache__ out of the skill folder
    spec = importlib.util.spec_from_file_location("lint_asl", HERE.parent / "scripts" / "lint_asl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def run(lint, fixture: Path, execution_type: str) -> list[list[str]]:
    diags, _count = lint.lint_text(fixture.read_text(encoding="utf-8"), None, execution_type)
    return sorted([d["severity"], d["code"], d["location"]] for d in diags.items)


def main(argv: list[str]) -> int:
    update = "--update" in argv
    filters = [a for a in argv[1:] if not a.startswith("--")]
    lint = load_linter()
    EXPECTED.mkdir(exist_ok=True)
    fixtures = sorted(p for p in FIXTURES.iterdir() if p.is_file() and (not filters or any(f in p.name for f in filters)))
    failed = 0
    for fx in fixtures:
        exp_path = EXPECTED / f"{fx.name}.expected.json"
        expected = json.loads(exp_path.read_text(encoding="utf-8")) if exp_path.exists() else None
        execution_type = (expected or {}).get("type") or ("EXPRESS" if re.search(r"(^|_)express(_|\.)", fx.name) else "STANDARD")
        got = run(lint, fx, execution_type)
        if update:
            rows = ",\n".join(f"  {json.dumps(d)}" for d in got)
            body = f"[\n{rows}\n]" if got else "[]"
            with open(exp_path, "w", encoding="utf-8", newline="\n") as fh:  # LF on every OS
                fh.write(f'{{"type": "{execution_type}", "diagnostics": {body}}}\n')
            continue
        if expected is None:
            failed += 1
            print(f"FAIL {fx.name}: no expected file (run with --update after checking the output)")
            continue
        want = sorted(expected["diagnostics"])
        if got != want:
            failed += 1
            print(f"FAIL {fx.name}")
            for d in want:
                if d not in got:
                    print(f"    missing     {' '.join(d)}")
            for d in got:
                if d not in want:
                    print(f"    unexpected  {' '.join(d)}")
    if update:
        print(f"updated {len(fixtures)} expected file(s)")
        return 0
    print(f"-- {len(fixtures) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
