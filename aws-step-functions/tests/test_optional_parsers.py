#!/usr/bin/env python3
"""test_optional_parsers.py - golden tests that need an optional package: the jsonata-python parser (J006 syntax
errors) or PyYAML (CloudFormation/SAM YAML-native Definition). The linter never requires either one, so run_tests.py
disables both; this script runs only the cases whose package imports, and prints SKIP for the others.

Each tests/optional/<file> has tests/optional/<file>.expected.json:
    {"requires": ["jsonata" | "yaml", ...], "type": "STANDARD", "diagnostics": [[severity, code, location], ...],
     "contains": {"<CODE>@<location>": "<substring>"},          <- "contains" is optional, as in run_tests.py
     "lines": {"<CODE>@<location>": <line in the file>}}        <- optional: pins the reported line
With jsonata-python installed it also lints every tests/fixtures/ok_* fixture with the parser on and fails on any
J006 there (the parser must accept everything the golden suite calls clean).

Usage:
    python3 tests/test_optional_parsers.py                    run (exit 1 on failure; skips are not failures)
    python3 tests/test_optional_parsers.py --update <name>... rewrite the expected files of matching cases
Install the packages to run everything: pip install jsonata-python pyyaml. Standard library only otherwise (3.9+).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OPTIONAL = HERE / "optional"
FIXTURES = HERE / "fixtures"


def load(name: str, path: Path):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def main(argv: list[str]) -> int:
    update = "--update" in argv
    filters = [a for a in argv[1:] if not a.startswith("--")]
    if update and not filters:
        print("--update needs a case name filter")
        return 2
    lint = load("lint_asl", HERE.parent / "scripts" / "lint_asl.py")
    runner = load("run_tests", HERE / "run_tests.py")  # same contains-pin check and expected-file layout
    real_load_yaml = getattr(lint, "load_yaml", lambda: None)
    available = {"jsonata": lint.load_jsonata(), "yaml": real_load_yaml()}
    failed = skipped = passed = 0
    for fx in sorted(p for p in OPTIONAL.iterdir() if p.is_file() and not p.name.endswith(".expected.json")):
        if filters and not any(f in fx.name for f in filters):
            continue
        exp_path = OPTIONAL / f"{fx.name}.expected.json"
        expected = json.loads(exp_path.read_text(encoding="utf-8")) if exp_path.exists() else {}
        requires = expected.get("requires") or (["yaml"] if fx.suffix in (".yaml", ".yml") else ["jsonata"])
        missing = [r for r in requires if available.get(r) is None]
        if missing:
            skipped += 1
            print(f"SKIP {fx.name}: needs {' and '.join({'jsonata': 'jsonata-python', 'yaml': 'PyYAML'}[m] for m in missing)} "
                  f"(pip install {' '.join({'jsonata': 'jsonata-python', 'yaml': 'pyyaml'}[m] for m in missing)})")
            continue
        lint.load_yaml = real_load_yaml if "yaml" in requires else (lambda: None)
        execution_type = expected.get("type", "STANDARD")
        diags, _count = lint.lint_text(fx.read_text(encoding="utf-8"), available["jsonata"] if "jsonata" in requires else None,
                                       execution_type, fx.name)
        got = runner.triples(diags.items)
        if update:
            runner.write_expected(exp_path, execution_type, got, expected.get("contains"))
            text = exp_path.read_text(encoding="utf-8")
            if expected.get("lines"):
                text = text.rstrip()[:-1] + ', "lines": ' + json.dumps(expected["lines"]) + "}" + chr(10)
            exp_path.write_bytes(text.replace("{", '{"requires": ' + json.dumps(requires) + ", ", 1).encode("utf-8"))
            print(f"updated {fx.name}")
            continue
        want = sorted(expected.get("diagnostics", []))
        problems = [f"missing     {' '.join(d)}" for d in want if d not in got]
        problems += [f"unexpected  {' '.join(d)}" for d in got if d not in want]
        problems += runner.check_contains(expected.get("contains") or {}, diags.items) if expected else ["no expected file"]
        for key, line in (expected.get("lines") or {}).items():
            code, loc = key.split("@", 1)
            got_lines = [d.get("line") for d in diags.items if d["code"] == code and d["location"] == loc]
            if line not in got_lines:
                problems.append(f"line        {key}: want line {line}, got {got_lines}")
        if problems:
            failed += 1
            print(f"FAIL {fx.name}")
            for p in problems:
                print(f"    {p}")
        else:
            passed += 1
            print(f"PASS {fx.name}")
    lint.load_yaml = real_load_yaml
    if update:
        return 0
    if available["jsonata"] is not None and not filters:
        lint.load_yaml = lambda: None
        bad = 0
        for fx in sorted(FIXTURES.glob("ok_*")):
            diags, _ = lint.lint_text(fx.read_text(encoding="utf-8"), available["jsonata"], "STANDARD")
            for d in diags.items:
                if d["code"] == "J006":
                    bad += 1
                    print(f"FAIL {fx.name}: the JSONata parser rejects a clean fixture: {d['location']}: {d['message'][:200]}")
        failed += bad
        passed += 0 if bad else 1
        print(f"{'PASS' if not bad else 'FAIL'} jsonata parser accepts every tests/fixtures/ok_* fixture")
    elif not filters:
        skipped += 1
        print("SKIP jsonata parser sweep over tests/fixtures/ok_*: needs jsonata-python")
    print(f"-- {passed} passed, {failed} failed, {skipped} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
