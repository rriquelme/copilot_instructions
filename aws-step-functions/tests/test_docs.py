#!/usr/bin/env python3
"""test_docs.py - every ```json block in SKILL.md and reference/*.md must lint clean.

The models copy these snippets, so a snippet the linter rejects is a bug in the docs (or in the linter). Each block is
parsed as JSON (or, for a member list such as  "Name": {...}, "Other": {...},  wrapped in braces), recognised as a
state machine, a state, a map of states, Retry/Catch entries, a Choice rule, a set of state fields or an Arguments
payload, wrapped in a minimal state machine and linted. Only context-only findings are allowed: S002 (Next to a state
outside the snippet), S003, V001, V002, V006 (variables assigned/read outside the snippet) and any INFO.
Blocks that are intentionally incomplete ("...", <placeholders>) must be fenced as ```json-abridged; they are skipped.

Usage: python3 tests/test_docs.py      exit 1 when a block fails. Standard library only (Python 3.9+).
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILL = HERE.parent
ALLOWED = {"S002", "S003", "V001", "V002", "V006"}
BLOCK_RE = re.compile(r"^```(json|json-abridged)[ \t]*\r?\n(.*?)^```[ \t]*$", re.M | re.S)
RULE_KEYS = {"Condition", "Variable", "And", "Or", "Not"}
TASK = "arn:aws:states:::aws-sdk:s3:listBuckets"


def load_linter():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("lint_asl", SKILL / "scripts" / "lint_asl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def parse(block: str):
    for text in (block, "{" + block + "}"):
        try:
            return json.loads(text)
        except ValueError:
            pass
    return None


def wrap(frag, lint, jsonata: bool) -> tuple[str, dict]:
    """(kind, state machine) for a parsed snippet."""
    def machine(states: dict, start: str) -> dict:
        m: dict = {"StartAt": start, "States": states}
        if jsonata:
            m["QueryLanguage"] = "JSONata"
        return m

    def task(**fields) -> dict:
        return {"Type": "Task", "Resource": TASK, **fields, "End": True}

    if isinstance(frag, list) and frag and all(isinstance(x, dict) and "ErrorEquals" in x for x in frag):
        frag = {"Catch" if all("Next" in x for x in frag) else "Retry": frag}
    if not isinstance(frag, dict) or not frag:
        return "unrecognised", {}
    if "StartAt" in frag and "States" in frag:
        return "state machine", frag
    if "Type" in frag:
        return "state", machine({"Snippet": frag}, "Snippet")
    if all(isinstance(v, dict) and "Type" in v for v in frag.values()):
        return "states", machine(frag, next(iter(frag)))
    if set(frag) <= {"Retry", "Catch"}:
        return "Retry/Catch", machine({"Snippet": task(**frag)}, "Snippet")
    if "ErrorEquals" in frag:
        key = "Catch" if "Next" in frag else "Retry"
        return f"{key} entry", machine({"Snippet": task(**{key: [frag]})}, "Snippet")
    if RULE_KEYS & set(frag) and "Next" in frag:
        return "Choice rule", machine({"Snippet": {"Type": "Choice", "Choices": [frag], "Default": frag["Next"]}}, "Snippet")
    lang = "jsonata" if jsonata else "jsonpath"
    pass_fields = set(lint.COMMON_FIELDS) | set(lint.FIELDS["Pass"]["both"]) | set(lint.FIELDS["Pass"][lang])
    task_fields = set(lint.COMMON_FIELDS) | set(lint.FIELDS["Task"]["both"]) | set(lint.FIELDS["Task"][lang])
    if set(frag) <= pass_fields:
        return "Pass fields", machine({"Snippet": {"Type": "Pass", **frag, "End": True}}, "Snippet")
    if set(frag) <= task_fields:
        return "Task fields", machine({"Snippet": task(**frag)}, "Snippet")
    payload = "Arguments" if jsonata else "Parameters"
    return f"{payload} payload", machine({"Snippet": task(**{payload: frag})}, "Snippet")


def main() -> int:
    lint = load_linter()
    docs = [SKILL / "SKILL.md", *sorted((SKILL / "reference").glob("*.md"))]
    failed = passed = skipped = 0
    for doc in docs:
        text = doc.read_text(encoding="utf-8")
        for m in BLOCK_RE.finditer(text):
            where = f"{doc.relative_to(SKILL).as_posix()}:{text.count(chr(10), 0, m.start()) + 1}"
            if m.group(1) == "json-abridged":
                skipped += 1
                print(f"SKIP {where} (json-abridged)")
                continue
            block = m.group(2)
            frag = parse(block)
            if frag is None:
                failed += 1
                print(f"FAIL {where}: not valid JSON (nor a JSON member list); fix it, or fence it as ```json-abridged "
                      "if it is intentionally incomplete")
                continue
            kind, definition = wrap(frag, lint, "{%" in block)
            if not definition:
                failed += 1
                print(f"FAIL {where}: unrecognised snippet shape; fence it as ```json-abridged or extend tests/test_docs.py")
                continue
            diags = lint.Diagnostics()
            lint.lint_definition(definition, diags)
            bad = [d for d in diags.items if d["severity"] != "INFO" and d["code"] not in ALLOWED]
            if bad:
                failed += 1
                print(f"FAIL {where} ({kind})")
                for d in bad:
                    print(f"    {d['severity']} {d['code']} {d['location']}: {d['message'][:200]}")
            else:
                passed += 1
                print(f"PASS {where} ({kind})")
    print(f"-- {passed} passed, {failed} failed, {skipped} abridged")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
