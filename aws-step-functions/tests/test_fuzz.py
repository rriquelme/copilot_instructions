#!/usr/bin/env python3
"""test_fuzz.py - mutation fuzzer: scripts/lint_asl.py must never raise, whatever JSON (or text) it gets.

Usage:
    python3 tests/test_fuzz.py [--seed N] [--n MUTATIONS] [--raw RAW_CASES]

Takes every tests/fixtures/*.json (plus the definitions embedded in the other fixtures), applies random structural
mutations (wrong-typed values at any depth, deleted/renamed keys, duplicated states, wrong-typed well-known fields)
and runs each through lint_text in STANDARD and EXPRESS mode; then runs random raw-text corruptions (truncate,
delete a character, insert a brace) and a few very deeply nested inputs. Every exception is reported with a
shrunk reproducer. Prints "fuzz: N cases, 0 crashes"; exit code 1 on any crash. Standard library only.
"""
from __future__ import annotations

import importlib.util
import json
import random
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"


def load_linter():
    sys.dont_write_bytecode = True  # keep __pycache__ out of the skill folder
    spec = importlib.util.spec_from_file_location("lint_asl", HERE.parent / "scripts" / "lint_asl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def deep_list(depth: int):
    v: list = []
    for _ in range(depth - 1):
        v = [v]
    return v


WEIRD = [None, 0, -1, 1.5, True, "", "x", "{% %}", "{% $ %}", [], {}, [1], {"a": 1}, "DEEP300"]
SPECIAL = ["Next", "Default", "StartAt", "Type", "Resource", "States", "Branches", "ItemProcessor", "Iterator", "Choices",
           "Catch", "Retry", "Assign", "Arguments", "Output", "Parameters", "ErrorEquals", "QueryLanguage", "End",
           "ProcessorConfig", "Condition", "Variable", "And", "Or", "Not", "Items", "ItemSelector", "ResultPath",
           "TimeoutSeconds", "HeartbeatSeconds", "Seconds", "Timestamp", "MaxAttempts", "BackoffRate", "MaxDelaySeconds"]
# meaningful values that switch the linter onto other code paths (query language, state type, Map mode, ...)
MEANINGFUL = ["JSONata", "JSONPath", "Task", "Pass", "Choice", "Wait", "Succeed", "Fail", "Parallel", "Map", "DISTRIBUTED",
              "INLINE", "EXPRESS", "arn:aws:states:::lambda:invoke", "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
              "arn:aws:states:::glue:startJobRun.sync", "arn:aws:states:us-east-1:1:activity:a", "$.x", "$$.Task.Token",
              "States.ALL", "States.Format('{}', $.a)", "{% $states.context.Task.Token %}", "{% $x %}", "${tpl}",
              {"Variable": "$.x", "StringEquals": "a", "Next": "A"}, {"Not": {"Not": 1}}, {"And": [1, {}]},
              {"ErrorEquals": ["States.ALL"], "Next": "A"}, {"StartAt": "A", "States": {"A": {"Type": "Succeed"}}}]
RENAMES = SPECIAL + ["Iterator", "Mode", "ExecutionType", "Comment", "Foo", "Next.$", "x.$", "$bad", "states", "Result"]


def weird_value(w):
    return deep_list(300) if w == "DEEP300" else clone(w)


def paths(o, max_depth: int = 40):
    """Every path into o (iterative; does not descend below max_depth, so deep values are mutated only as a whole)."""
    out, work = [], [(o, ())]
    while work:
        v, p = work.pop()
        out.append(p)
        if len(p) < max_depth:
            items = v.items() if isinstance(v, dict) else enumerate(v) if isinstance(v, list) else ()
            work.extend((x, p + (k,)) for k, x in items)
    return sorted(out, key=lambda p: [str(k) for k in p])


def clone(o):
    return json.loads(json.dumps(o))  # C-implemented: copes with the 300-deep lists that copy.deepcopy cannot


def get(o, p):
    for k in p:
        o = o[k]
    return o


def mutate(rng: random.Random, d):
    """Apply one random mutation in place; return (mutated document, description)."""
    ps = [p for p in paths(d) if p]
    kind = rng.randrange(6)
    if not ps:
        return d, "unchanged"
    if kind == 0:  # replace any value
        p, w = rng.choice(ps), rng.choice(WEIRD)
        get(d, p[:-1])[p[-1]] = weird_value(w)
        return d, f"set {'/'.join(map(str, p))} = {json.dumps(w)}"
    if kind == 1:  # delete a key
        kp = [p for p in ps if isinstance(get(d, p[:-1]), dict)]
        if kp:
            p = rng.choice(kp)
            del get(d, p[:-1])[p[-1]]
            return d, f"delete {'/'.join(map(str, p))}"
    if kind == 2:  # rename a key
        kp = [p for p in ps if isinstance(get(d, p[:-1]), dict)]
        if kp:
            p = rng.choice(kp)
            parent, new = get(d, p[:-1]), rng.choice(RENAMES)
            parent[new] = parent.pop(p[-1])
            return d, f"rename {'/'.join(map(str, p))} -> {new}"
    if kind == 3:  # duplicate a state (same name in another scope, or a copy under a new name)
        sp = [p for p in ps if p[-1] == "States" and isinstance(get(d, p), dict) and get(d, p)]
        if len(sp) >= 1:
            src = get(d, rng.choice(sp))
            dst = get(d, rng.choice(sp))
            name = rng.choice(list(src))
            new = name if dst is not src else name + "Copy"
            dst[new] = clone(src[name])
            return d, f"duplicate state {name} as {new}"
    if kind == 5:  # a meaningful value somewhere
        p, w = rng.choice(ps), rng.choice(MEANINGFUL)
        get(d, p[:-1])[p[-1]] = clone(w)
        return d, f"set {'/'.join(map(str, p))} = {json.dumps(w)}"
    sp = [p for p in ps if p[-1] in SPECIAL]  # wrong-typed well-known field
    if sp:
        p, w = rng.choice(sp), rng.choice(WEIRD)
        get(d, p[:-1])[p[-1]] = weird_value(w)
        return d, f"swap {'/'.join(map(str, p))} = {json.dumps(w)}"
    p, w = rng.choice(ps), rng.choice(WEIRD)
    get(d, p[:-1])[p[-1]] = weird_value(w)
    return d, f"set {'/'.join(map(str, p))} = {json.dumps(w)}"


def corrupt(rng: random.Random, text: str) -> tuple[str, str]:
    if not text:
        return "{", "empty"
    i = rng.randrange(len(text))
    kind = rng.randrange(4)
    if kind == 0:
        return text[:i], f"truncate at {i}"
    if kind == 1:
        return text[:i] + text[i + 1:], f"delete char {i}"
    if kind == 2:
        return text[:i] + rng.choice("{}[]") + text[i:], f"insert brace at {i}"
    j = rng.randrange(len(text))
    return text[:i] + text[j:j + 20] + text[i:], f"splice {j} at {i}"


def crash_key(e: BaseException) -> str:
    tb = traceback.extract_tb(e.__traceback__)
    last = tb[-1] if tb else None
    return f"{type(e).__name__} at line {last.lineno if last else '?'} ({last.name if last else '?'})"


def try_lint(lint, text: str, mode: str):
    try:
        lint.lint_text(text, None, mode)
        return None
    except Exception as e:  # noqa: BLE001 - any exception is a bug
        return e


def shrink(lint, d, mode: str, key: str):
    """Greedy: drop dict keys / list items while the same crash still happens."""
    changed, budget = True, 400
    while changed and budget > 0:
        changed = False
        for p in sorted((p for p in paths(d) if p), key=len):
            budget -= 1
            if budget <= 0:
                break
            trial = clone(d)
            try:
                del get(trial, p[:-1])[p[-1]]
            except (KeyError, IndexError, TypeError):
                continue
            try:
                text = json.dumps(trial)
            except (ValueError, RecursionError):
                continue
            e = try_lint(lint, text, mode)
            if e is not None and crash_key(e) == key:
                d, changed = trial, True
                break
    return d


def main(argv: list[str]) -> int:
    seed, n, n_raw = 1, 5000, 500
    for flag in ("--seed", "--n", "--raw"):
        if flag in argv:
            val = int(argv[argv.index(flag) + 1])
            seed, n, n_raw = (val, n, n_raw) if flag == "--seed" else (seed, val, n_raw) if flag == "--n" else (seed, n, val)
    lint = load_linter()
    rng = random.Random(seed)
    texts = {p.name: p.read_text(encoding="utf-8-sig") for p in sorted(FIXTURES.iterdir()) if p.is_file()}
    docs = []
    for name, text in texts.items():
        if name.endswith(".json"):
            try:
                docs.append((name, json.loads(text)))
            except ValueError:
                continue  # deliberately invalid fixtures are covered by the raw-text corruptions
        else:
            docs += [(name, d) for d, _note in lint.extract_definitions(text)]
    start = time.time()
    cases, crashes = 0, {}

    def record(e, repro: str) -> None:
        key = crash_key(e)
        crashes.setdefault(key, (repro, "".join(traceback.format_exception_only(type(e), e)).strip()))

    for _ in range(n):
        name, doc = rng.choice(docs)
        d, what = mutate(rng, clone(doc))
        while rng.random() < 0.4:
            d, what2 = mutate(rng, d)
            what += "; " + what2
        text = json.dumps(d)
        for mode in ("STANDARD", "EXPRESS"):
            cases += 1
            e = try_lint(lint, text, mode)
            if e is not None and crash_key(e) not in crashes:
                small = shrink(lint, d, mode, crash_key(e))
                record(e, f"[{mode}] {name}: {what}\n      {json.dumps(small)[:600]}")
    for _ in range(n_raw):
        name = rng.choice(list(texts))
        text, what = corrupt(rng, texts[name])
        cases += 1
        e = try_lint(lint, text, "STANDARD")
        if e is not None:
            record(e, f"[raw] {name}: {what}")
    # very deep nesting: json.loads itself and every recursive walker
    deep = '{"StartAt":"A","States":{"A":{"Type":"Pass","Result":' + "[" * 3000 + "]" * 3000 + ',"End":true}}}'
    deep_jsonata = ('{"QueryLanguage":"JSONata","StartAt":"A","States":{"A":{"Type":"Pass","Output":' + '{"a":' * 3000 + '"{% $x %}"'
                    + "}" * 3000 + ',"Assign":{"x":' + "[" * 900 + "1" + "]" * 900 + '},"End":true}}}')
    deep_mid = '{"StartAt":"A","States":{"A":{"Type":"Pass","Parameters":' + '{"a":' * 600 + '"$.x"' + "}" * 600 + ',"End":true}}}'
    for label, text in (("deep 3000 list", deep), ("deep 3000 JSONata object", deep_jsonata), ("deep 600 object", deep_mid),
                        ("deep 100000 list", "[" * 100000), ("embedded deep", "x = " + deep)):
        for mode in ("STANDARD", "EXPRESS"):
            cases += 1
            e = try_lint(lint, text, mode)
            if e is not None:
                record(e, f"[{mode}] {label}")
    elapsed = time.time() - start
    print(f"fuzz: {cases} cases, {len(crashes)} crashes (seed {seed}, {elapsed:.1f} s)")
    for key, (repro, msg) in crashes.items():
        print(f"  CRASH {key}: {msg[:200]}\n    {repro}")
    return 1 if crashes else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
