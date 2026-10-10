#!/usr/bin/env python3
"""test_jsonata_hints.py - the J001 replacement hint must never suggest a field the state type does not allow.

For every state type and every JSONPath-only field, lint a JSONata state that uses the field, read the field(s)
the J001 hint tells the model to use instead, apply that suggestion, and check the linter does not then reject
the suggested field (S009 unknown field / J001 wrong language). Standard library only (Python 3.9+).
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_linter():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("lint_asl", HERE.parent / "scripts" / "lint_asl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def base_state(stype: str) -> dict:
    st: dict = {"Type": stype}
    if stype == "Task":
        st.update(Resource="arn:aws:states:::aws-sdk:s3:listBuckets", End=True)
    elif stype == "Choice":
        st.update(Choices=[{"Condition": "{% true %}", "Next": "Done"}], Default="Done")
    elif stype == "Wait":
        st.update(Seconds=1, End=True)
    elif stype == "Parallel":
        st.update(Branches=[{"StartAt": "B", "States": {"B": {"Type": "Pass", "End": True}}}], End=True)
    elif stype == "Map":
        st.update(ItemProcessor={"StartAt": "I", "States": {"I": {"Type": "Pass", "End": True}}}, End=True)
    elif stype in ("Pass",):
        st.update(End=True)
    return st


def lint_state(lint, st: dict):
    definition = {"QueryLanguage": "JSONata", "StartAt": "S", "States": {"S": st, "Done": {"Type": "Succeed"}}}
    diags = lint.Diagnostics()
    lint.lint_definition(definition, diags)
    return diags.items


def main() -> int:
    lint = load_linter()
    failures = 0
    checked = 0
    for stype, spec in lint.FIELDS.items():
        for field in spec["jsonpath"]:
            st = base_state(stype)
            st[field] = "$.x"
            items = lint_state(lint, st)
            j001 = [d for d in items if d["code"] == "J001" and d["location"] == f"/States/S/{field}"]
            if not j001:
                failures += 1
                print(f"FAIL {stype}.{field}: no J001 reported")
                continue
            msg = j001[0]["message"]
            hint = msg.split(" - ", 1)[1] if " - " in msg else ""
            # fields the hint tells the model to write: 'use "X"' / 'with "X"' (capitalised ASL field names only)
            suggested = [f for f in re.findall(r'(?:use|with) "([A-Z][A-Za-z]*)"', hint)]
            for new in suggested:
                checked += 1
                fixed = {k: v for k, v in st.items() if k != field}
                fixed[new] = {} if new in ("ItemSelector", "Assign") else "{% 1 %}"
                bad = [d for d in lint_state(lint, fixed)
                       if d["code"] in ("S009", "J001", "S004") and d["location"] == f"/States/S/{new}"]
                if bad:
                    failures += 1
                    print(f"FAIL {stype}.{field}: hint suggests \"{new}\" but the linter then reports: {bad[0]['message']}")
    print(f"-- {checked} suggestion(s) checked, {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
