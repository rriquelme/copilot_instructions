#!/usr/bin/env python3
"""run_tests.py - golden-file tests for scripts/lint_asl.py.

Usage:
    python3 tests/run_tests.py                   run every fixture, compare with tests/expected/
    python3 tests/run_tests.py <name>...         run only fixtures whose file name contains <name>
    python3 tests/run_tests.py --update <name>... rewrite the expected files of the matching fixtures and print a diff
    python3 tests/run_tests.py --update --all    rewrite every expected file (prints the diff of each one that changed)

Each tests/fixtures/<file> has tests/expected/<file>.expected.json:
    {"type": "STANDARD" | "EXPRESS", "diagnostics": [[severity, code, location], ...],
     "contains": {"<CODE>@<location>": "<substring>", ...}}          <- "contains" is optional
Messages are not compared, so rewording a message does not break tests; adding, removing or
moving a diagnostic does. "contains" pins important message text: some diagnostic with that code
at that location must have a message containing the substring (use it for did-you-mean hints).
--update keeps "contains" as is. The optional jsonata-python parser and PyYAML are disabled so
results are the same on every machine (tests/test_optional_parsers.py covers them). Exit code 1
when any test fails. Standard library only (Python 3.9+).
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
    if hasattr(mod, "load_yaml"):
        mod.load_yaml = lambda: None  # same results with or without PyYAML installed
    return mod


def run(lint, fixture: Path, execution_type: str) -> list[dict]:
    diags, _count = lint.lint_text(fixture.read_text(encoding="utf-8"), None, execution_type)
    return diags.items


def triples(items: list[dict]) -> list[list[str]]:
    return sorted([d["severity"], d["code"], d["location"]] for d in items)


def check_contains(contains: dict, items: list[dict]) -> list[str]:
    """Problems with the optional "contains" pins: '<CODE>@<location>' -> substring of the message."""
    out = []
    for key, sub in contains.items():
        code, _, loc = key.partition("@")
        msgs = [d["message"] for d in items if d["code"] == code and d["location"] == loc]
        if not msgs:
            out.append(f"contains    {key}: no such diagnostic")
        elif not any(sub in m for m in msgs):
            out.append(f"contains    {key}: no message contains {json.dumps(sub)}; got: {msgs[0][:200]}")
    return out


def write_expected(path: Path, execution_type: str, got: list[list[str]], contains: dict | None) -> None:
    rows = ",\n".join(f"  {json.dumps(d)}" for d in got)
    body = f"[\n{rows}\n]" if got else "[]"
    extra = ""
    if contains:
        pins = ",\n".join(f"  {json.dumps(k)}: {json.dumps(v)}" for k, v in contains.items())
        extra = f', "contains": {{\n{pins}\n}}'
    with open(path, "w", encoding="utf-8", newline="\n") as fh:  # LF on every OS
        fh.write(f'{{"type": "{execution_type}", "diagnostics": {body}{extra}}}\n')


def main(argv: list[str]) -> int:
    update = "--update" in argv
    update_all = "--all" in argv
    filters = [a for a in argv[1:] if not a.startswith("--")]
    if update and not filters and not update_all:
        print("--update needs a fixture name filter (e.g. --update s004_) or --all to rewrite every expected file")
        return 2
    lint = load_linter()
    EXPECTED.mkdir(exist_ok=True)
    fixtures = sorted(p for p in FIXTURES.iterdir() if p.is_file() and (not filters or any(f in p.name for f in filters)))
    failed = changed = 0
    for fx in fixtures:
        exp_path = EXPECTED / f"{fx.name}.expected.json"
        expected = json.loads(exp_path.read_text(encoding="utf-8")) if exp_path.exists() else None
        execution_type = (expected or {}).get("type") or ("EXPRESS" if re.search(r"(^|_)express(_|\.)", fx.name) else "STANDARD")
        items = run(lint, fx, execution_type)
        got = triples(items)
        contains = (expected or {}).get("contains") or {}
        if update:
            want = sorted(expected["diagnostics"]) if expected else None
            if want != got:
                changed += 1
                print(f"{'new' if want is None else 'changed'} {fx.name}")
                for d in want or []:
                    if d not in got:
                        print(f"    - {' '.join(d)}")
                for d in got:
                    if d not in (want or []):
                        print(f"    + {' '.join(d)}")
            for problem in check_contains(contains, items):
                print(f"    ! {fx.name}: {problem} (fix or remove the pin in {exp_path.name})")
            write_expected(exp_path, execution_type, got, contains)
            continue
        if expected is None:
            failed += 1
            print(f"FAIL {fx.name}: no expected file (run with --update {fx.name} after checking the output)")
            continue
        want = sorted(expected["diagnostics"])
        problems = [f"missing     {' '.join(d)}" for d in want if d not in got]
        problems += [f"unexpected  {' '.join(d)}" for d in got if d not in want]
        problems += check_contains(contains, items)
        if problems:
            failed += 1
            print(f"FAIL {fx.name}")
            for p in problems:
                print(f"    {p}")
    if update:
        print(f"updated {len(fixtures)} expected file(s), {changed} changed")
        return 0
    print(f"-- {len(fixtures) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
