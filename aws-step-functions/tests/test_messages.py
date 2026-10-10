#!/usr/bin/env python3
"""test_messages.py - wording checks for the core structural diagnostics of scripts/lint_asl.py.

run_tests.py compares only (severity, code, location). This file checks what the golden files cannot:
- every core-check message follows "<what is wrong>; <exact fix>" (it has a "; " and a fix after it);
- unknown Retry / Catch / Choice-rule / top-level / state fields, state Types and States.* error names get a
  did-you-mean suggestion when one is close.

Usage: python3 tests/test_messages.py   prints PASS/FAIL per case, exit 1 when any case fails.
Standard library only (Python 3.9+).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True  # keep __pycache__ out of the skill folder
from run_tests import FIXTURES, load_linter  # noqa: E402

# Codes owned by the core checks (Scope.analyse/analyse_state field checks, Retry/Catch, Map/Parallel, top level).
CORE_CODES = {"S001", "S002", "S003", "S004", "S005", "S006", "S007", "S008", "S009", "S010", "S011", "S012", "S013",
              "S014", "S015", "P005"} | {f"S0{n}" for n in range(40, 51)}

SUGGESTIONS = [
    ("s012_retry_shape.json", "S012", "/States/A/Retry/0/MaxAttempt", 'did you mean "MaxAttempts"?'),
    ("s040_catch_shape.json", "S040", "/States/A/Catch/0/Nxt", 'rename it to "Next"'),
    ("s040_catch_shape.json", "S040", "/States/A/Catch/2/Outptu", 'did you mean "Output"?'),
    ("s041_error_equals.json", "S041", "/States/A/Retry/2/ErrorEquals", 'did you mean "States.Timeout"?'),
    ("s006_choice_structure.json", "S006", "/States/Pick/Choices/0/Nxet", 'did you mean "Next"?'),
    ("s046_top_level_fields.json", "S046", "/startat", 'did you mean "StartAt"?'),
    ("s046_top_level_fields.json", "S046", "/Timeout", "allowed: Comment, QueryLanguage, StartAt"),
    ("s009_field_suggestions.json", "S009", "/States/A/Resouce", 'did you mean "Resource"?'),
    ("s009_field_suggestions.json", "S009", "/States/B/Type", 'use "Type": "Pass"'),
    ("s050_task_timeouts.json", "S050", "/States/B/HeartbeatSeconds", '"HeartbeatSeconds": 30'),
    ("p005_lambda_no_retry.json", "P005", "/States/NoRetry", "Lambda.TooManyRequestsException"),
]


def main() -> int:
    lint = load_linter()
    failed = 0
    cache: dict[str, list] = {}

    def diags(name: str) -> list:
        if name not in cache:
            cache[name] = lint.lint_text((FIXTURES / name).read_text(encoding="utf-8"), None, "STANDARD")[0].items
        return cache[name]

    for fx in sorted(p.name for p in FIXTURES.iterdir() if p.is_file()):
        for d in diags(fx):
            if d["code"] in CORE_CODES and ("; " not in d["message"] or not d["message"].split("; ", 1)[1].strip()):
                failed += 1
                print(f"FAIL template {fx}: {d['code']} {d['location']}: {d['message']}")
    for fx, code, loc, needle in SUGGESTIONS:
        hits = [d for d in diags(fx) if d["code"] == code and d["location"] == loc]
        ok = any(needle in d["message"] for d in hits)
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'} {fx} {code} {loc}: {needle}" + ("" if ok else f" (got {[d['message'] for d in hits]})"))
    print(f"-- {'all passed' if not failed else f'{failed} failure(s)'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
