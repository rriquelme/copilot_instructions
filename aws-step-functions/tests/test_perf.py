#!/usr/bin/env python3
"""test_perf.py - pathological inputs that used to crash or hang scripts/lint_asl.py (quadratic regexes and scans,
Python's int-digit limit). Each case is generated in memory, linted in-process with lint_text, and must finish
within its time budget without an exception or a "linter internal error" diagnostic.

Usage: python3 tests/test_perf.py     prints PASS/FAIL per case, exit 1 when any case fails.
Standard library only (Python 3.9+).

Cases: (name, make_text, filename or None, check(diags, count) -> problem or None). INPUT_CASES cover input
discovery / extraction / CLI helpers; ANALYSIS_CASES (when present) cover the definition checks.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LINTER = HERE.parent / "scripts" / "lint_asl.py"
BUDGET_SECONDS = 3.0 * float(os.environ.get("LINT_PERF_BUDGET_SCALE", "1"))  # CI runners are slower: the workflow scales it


def _messages(diags) -> str:
    return "\n".join(d["message"] for d in diags.items)


def _expect_count(n: int):
    return lambda diags, count: None if count == n else f"expected {n} definitions, got {count}"


def _expect_text(s: str):
    return lambda diags, count: None if s in _messages(diags) else f"expected a diagnostic mentioning {s!r}"


def _max_diags(n: int):
    return lambda diags, count: None if len(diags.items) <= n else f"expected at most {n} diagnostics, got {len(diags.items)}"


INPUT_CASES = [
    # C1: integers longer than Python's int-digit limit raise ValueError (not JSONDecodeError) in json.loads
    ("c1 bigint 4301 digits (plain JSON)", lambda: '{"n":' + "1" * 4301 + "}", None, _expect_text("integer with thousands of digits")),
    ("c1 bigint in an embedded definition", lambda: 'x {"StartAt":"A","States":{},"n":' + "1" * 4301 + "}", "main.tf",
     _expect_text("integer with thousands of digits")),
    ("c1 bigint in a Wait Seconds", lambda: json.dumps({"StartAt": "A", "States": {"A": {"Type": "Wait", "End": True}}})
     .replace('"End"', '"Seconds": ' + "9" * 5000 + ', "End"'), None, _expect_count(1)),
    # H1: ^\s* with re.M crossed newlines in nothing_found_message
    ("h1 200k blank lines", lambda: "x" + "\n" * 200000, None, _expect_count(0)),
    ("h1 200k blank lines (.yaml)", lambda: "x" + "\n" * 200000, "t.yaml", _expect_count(0)),
    ("h1 200k CRLF blank lines (.yaml)", lambda: "x" + "\r\n" * 100000, "t.yaml", _expect_count(0)),
    # H2: every unterminated ${ scanned to EOF in substitute_placeholders
    ("h2 ${ x 32000 (64k)", lambda: "x " + "${" * 32000, "main.tf", _expect_count(0)),
    ("h2 %{ if x 20000", lambda: "x " + "%{ if " * 20000, "main.tf", _expect_count(0)),
    ("h2 ${ x 32000 in a JSON file", lambda: '{"StartAt":"A","States":{},"x":' + "${" * 32000, "a.json", _expect_count(0)),
    # H9-H11: extract_embedded sliced / regex-searched / parsed every nested brace pair
    ("h8 256k nested braces around both keys", lambda: "x" + "{" * 256000 + '"States":1,"StartAt":1' + "}" * 256000, None,
     _expect_count(0)),
    ("h9 18000 invalid embedded definitions", lambda: "x\n" + '{"StartAt":"A","States":{,}}\n' * 18000, None, _max_diags(25)),
    ("h12 10000 embedded definitions", lambda: "x\n" + '{"StartAt":"A","States":{"A":{"Type":"Succeed"}}}\n' * 10000, None,
     _expect_count(10000)),
    ("h12 2000 definitions on one line", lambda: "x " + '{"StartAt":"A","States":{"A":{"Type":"Succeed"}}} ' * 2000, None,
     _expect_count(2000)),
    # H14: RESOURCE_PLACEHOLDER_RE rescanned to the next "}" from every "{{" / "${" / "#{"
    ("h13 Resource {{ x 50000", lambda: json.dumps({"StartAt": "A", "States": {"A": {"Type": "Task", "Resource": "{{" * 50000,
                                                                                   "End": True}}}), None, _expect_count(1)),
    ("h13 Resource ${ x 50000", lambda: json.dumps({"StartAt": "A", "States": {"A": {"Type": "Task", "Resource": "${" * 50000,
                                                                                   "End": True}}}), None, _expect_count(1)),
    ("h13 Resource {{ x 50000 then }x", lambda: json.dumps({"StartAt": "A", "States": {"A": {
        "Type": "Task", "Resource": "{{" * 50000 + "}x", "End": True}}}), None, _expect_count(1)),
]

# Terraform jsonencode({...}) HCL conversion and the PyYAML path (the YAML cases run the fallback when PyYAML is absent)
_TF_STATE = '  S{i} = {{ Type = "Pass", Next = "S{j}" }}\n'
INPUT_CASES += [
    ("hcl jsonencode({ x 30000", lambda: "jsonencode({" * 30000, "main.tf", _expect_count(0)),
    ("hcl jsonencode( in 30000 strings", lambda: "jsonencode({ a = \"" + 'jsonencode({ a = \\"x' * 30000 + '\nStartAt States',
     "main.tf", _max_diags(25)),
    ("hcl nested objects x 100000", lambda: "jsonencode({StartAt=1, States=" + "{a=" * 100000 + "1" + "}" * 100000 + "})",
     "main.tf", _expect_count(0)),
    ("hcl nested parens in a reference x 100000", lambda: "jsonencode({StartAt=1, States=f" + "(" * 100000 + ")" * 100000 + "})",
     "main.tf", _expect_count(0)),
    ("hcl 20000 unterminated heredocs", lambda: "jsonencode({StartAt=\"A\", States={\n" + "a = <<EOT\n" * 20000, "main.tf",
     _max_diags(25)),
    ("hcl 5000 jsonencode definitions", lambda: 'definition = jsonencode({ StartAt = "A", States = { A = { Type = "Succeed" } } })\n' * 5000,
     "main.tf", _expect_count(5000)),
    ("hcl 20000-state definition", lambda: "definition = jsonencode({\nStartAt = \"S0\"\nStates = {\n"
     + "".join(_TF_STATE.format(i=i, j=i + 1) for i in range(20000)) + '  S20000 = { Type = "Succeed" }\n}\n})\n',
     "main.tf", _expect_count(1)),
    ("yaml 20000-state definition", lambda: "Resources:\n  SM:\n    Properties:\n      Definition:\n        StartAt: S0\n        States:\n"
     + "".join(f"          S{i}: {{Type: Pass, Next: S{i + 1}}}\n" for i in range(20000)) + "          S20000: {Type: Succeed}\n",
     "t.yaml", None),
    ("yaml billion laughs", lambda: "a: &a [x, x, x, x, x, x, x, x, x]\n" + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [*{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}, "
        f"*{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}]\n" for i in range(20)) + "Resources: {}\nStartAt: States\n",
     "t.yaml", None),
]


def jsonata_def(states: dict, start: str) -> str:
    return json.dumps({"StartAt": start, "States": states, "QueryLanguage": "JSONata"})


def expr_def(expr: str) -> str:
    return jsonata_def({"A": {"Type": "Pass", "Output": "{% " + expr + " %}", "End": True}}, "A")


def chain_def(order) -> str:
    states = {f"S{i}": {"Type": "Pass", "Next": f"S{i + 1}"} for i in order}
    states[f"S{max(order) + 1}"] = {"Type": "Succeed"}
    return jsonata_def(states, "S0")


def unknown_vars_def(k: int, read) -> str:
    states: dict = {"A": {"Type": "Pass", "Assign": {f"v{i}": 0 for i in range(k)}, "Next": "S0"}}
    for i in range(k):
        states[f"S{i}"] = {"Type": "Pass", "Output": "{% $" + read(i) + " %}", "Next": f"S{i + 1}"}
    states[f"S{k}"] = {"Type": "Succeed"}
    return jsonata_def(states, "A")


def intrinsic_def(value: str) -> str:
    return json.dumps({"StartAt": "A", "States": {"A": {"Type": "Pass", "End": True, "Parameters": {"x.$": value}}}})


# Analysis side (Scope dataflow/reachability/loops, expression analysis, intrinsics, suggestions): (name, builder)
ANALYSIS_CASES = [
    ("c2_choices_int_loop", lambda: json.dumps({"StartAt": "A", "States": {
        "A": {"Type": "Pass", "Choices": 1, "Next": "B"},
        "B": {"Type": "Choice", "Choices": [{"Variable": "$.x", "IsNull": True, "Next": "A"}], "Default": "C"},
        "C": {"Type": "Succeed"}}})),
    ("c2_choices_true_selfloop", lambda: json.dumps({"StartAt": "A", "States": {
        "A": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "Choices": True, "Next": "A",
              "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "B"}]}, "B": {"Type": "Succeed"}}})),
    ("c3_intrinsic_nested_1000", lambda: intrinsic_def("States.Array(" * 1000 + ")" * 1000)),
    ("c3_intrinsic_nested_5000", lambda: intrinsic_def("States.Array(" * 5000 + ")" * 5000)),
    ("c3_intrinsic_wide_20000", lambda: intrinsic_def("States.Array(" + ", ".join(["States.Array(1)"] * 20000) + ")")),
    ("h3_reverse_chain_1000", lambda: chain_def(range(999, -1, -1))),
    ("h3_reverse_chain_10000", lambda: chain_def(range(9999, -1, -1))),
    ("h15_forward_chain_10000", lambda: chain_def(range(10000))),
    ("h4_slashes_64k", lambda: expr_def("1" + "/1" * 32000)),
    ("h5_arity_4000_calls", lambda: expr_def(" + ".join(["$count(x)"] * 4000))),
    ("h5_arity_nested_4000", lambda: expr_def("$count(" * 4000 + "x" + ")" * 4000)),
    ("h6_unknown_vars_1500", lambda: unknown_vars_def(1500, lambda i: f"u{i}")),
    ("h6_unknown_vars_5000", lambda: unknown_vars_def(5000, lambda i: f"u{i}")),
    ("h6_unknown_vars_far_3000", lambda: unknown_vars_def(3000, lambda i: f"xy{i}z")),
    ("h7_dollar_dot_brackets_512k", lambda: expr_def("[" * 256000 + "1" + "]" * 256000 + " + x[$.a]")),
    ("h7_dollar_dot_step_calls_256k", lambda: expr_def("x" + ".$f(" * 50000 + ")" * 50000 + " + $.a")),
    ("h10_long_intrinsic_name_256k", lambda: intrinsic_def("States." + "Q" * 256000 + "()")),
    ("h14_choice_rule_long_key_100k", lambda: json.dumps({"StartAt": "A", "States": {
        "A": {"Type": "Choice", "Choices": [{"Not": {"Q" * 100000: 1}, "Next": "B"}], "Default": "B"},
        "B": {"Type": "Succeed"}}})),
    ("h14_state_long_key_100k", lambda: json.dumps({"StartAt": "A", "States": {
        "A": {"Type": "Pass", "Q" * 100000: 1, "End": True}}})),
    ("h11_function_paren_256k", lambda: expr_def("function(" * 28000)),
]


# round 4: V001 hint search, invalid-key rename hint, nested %{ } directives, Terraform resource labels, deletion index
def _vars_def(n_assigned: int, n_reads: int, assign_fmt: str, read_fmt: str) -> str:
    assign = {assign_fmt % i: i for i in range(n_assigned)}
    reads = ",".join("$" + read_fmt % i for i in range(n_reads))
    return json.dumps({"QueryLanguage": "JSONata", "StartAt": "A", "States": {
        "A": {"Type": "Pass", "Assign": assign, "Next": "B"},
        "B": {"Type": "Pass", "Output": "{% [" + reads + "] %}", "End": True}}})


ANALYSIS_CASES += [
    ("r4_hint_long_names_3000x3000", lambda: _vars_def(3000, 3000, "a%04d" + "x" * 20, "b%04d" + "x" * 20)),
    ("r4_invalid_key_hint_5000x5000", lambda: _vars_def(5000, 5000, "%da", "v%d")),
    ("r4_deletion_index_30000_vars", lambda: _vars_def(30000, 1, "k%05d" + "q" * 20, "zz%d")),
    ("r4_nested_tf_if_40000", lambda: "%{if}" * 40000),
    ("r4_tf_resource_header_spans_lines", lambda: "\n" * 100000 + 'resource\n"a" "b" ' + '{"StartAt":"A","States":{}}' * 2000),
]


# round 5: V007 rename collisions, counter-loop check with many Tasks, per-file hint budget
def _loop_def(k: int) -> str:
    states = {"Check": {"Type": "Choice", "Choices": [{"Variable": "$.x", "NumericEquals": 0, "Next": "T0"}], "Default": "End"},
              "End": {"Type": "Succeed"}}
    for i in range(k):
        states[f"T{i}"] = {"Type": "Task", "Resource": "arn:aws:lambda:us-east-1:123456789012:function:f", "ResultPath": "$.x",
                           "Next": f"T{i + 1}" if i + 1 < k else "Check"}
    return json.dumps({"StartAt": "Check", "States": states})


def _collide_def(n_taken: int) -> str:
    assign = {"a": 0, **{f"a{i}": i for i in range(2, n_taken)}, "_a": 1}
    return json.dumps({"QueryLanguage": "JSONata", "StartAt": "A", "States": {"A": {"Type": "Pass", "Assign": assign, "End": True}}})


def _multi_tf(ndef: int, nvars: int, nreads: int) -> str:
    parts = []
    for d in range(ndef):
        parts.append('resource "aws_sfn_state_machine" "m%d" {\n  definition = <<EOF\n%s\nEOF\n}\n'
                     % (d, _vars_def(nvars, nreads, "v%04d" + "q" * 21, "v%04d" + "z" * 21)))
    return "\n".join(parts)


ANALYSIS_CASES += [
    ("r5_v007_suffix_exhaustion_10000", lambda: _collide_def(10000)),
    ("r5_counter_loop_2000_tasks", lambda: _loop_def(2000)),
    ("r5_hint_budget_per_file_25_defs", lambda: _multi_tf(25, 1001, 200)),
]


# CLI round: S002 "did you mean" over many states, S003 orphan roots, line numbers, lint-allow suppressions
def _typo_def(n: int) -> str:  # every state targets a near-miss name: n S002 suggestions over n names
    states = {f"State{i:05d}": {"Type": "Pass", "Next": f"Stat{i + 1:05d}" if i + 1 < n else "Nope"} for i in range(n)}
    return json.dumps({"StartAt": "State00000", "States": states})


def _orphans_def(n: int) -> str:  # n/2 orphan roots each starting a chain, plus an unreachable loop
    states = {"A": {"Type": "Succeed"}}
    for i in range(n):
        states[f"O{i}"] = {"Type": "Pass", "Next": f"O{i + 1}" if i % 2 == 0 else "A"}
    states["L1"] = {"Type": "Pass", "Next": "L2"}
    states["L2"] = {"Type": "Pass", "Next": "L1"}
    return json.dumps({"StartAt": "A", "States": states}, indent=2)


def _allow_def(n: int) -> str:  # n states, each with a suppressed and an unsuppressed diagnostic
    states = {f"S{i}": {"Type": "Pass", "Comment": "lint-allow S009: generated", "Bogus": 1,
                        "Next": f"S{i + 1}" if i + 1 < n else "Missing"} for i in range(n)}
    return json.dumps({"StartAt": "S0", "States": states}, indent=2)


ANALYSIS_CASES += [
    ("cli_s002_suggestions_5000", lambda: _typo_def(5000)),
    ("cli_s003_orphan_roots_20000", lambda: _orphans_def(20000)),
    ("cli_lint_allow_10000", lambda: _allow_def(10000)),
]


def load_linter():
    sys.dont_write_bytecode = True  # keep __pycache__ out of the skill folder
    spec = importlib.util.spec_from_file_location("lint_asl_perf_test", LINTER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def main() -> int:
    cases = INPUT_CASES + globals().get("ANALYSIS_CASES", [])
    lint = load_linter()
    failures = 0
    for case in cases:
        name, make_text, filename, check = (tuple(case) + (None, None))[:4]  # ANALYSIS_CASES are (name, make_text)
        text = make_text()
        start = time.perf_counter()
        try:
            diags, count = lint.lint_text(text, None, "STANDARD", filename)
            secs = time.perf_counter() - start
            internal = [d["message"] for d in diags.items if "internal error" in d["message"]]
            problem = (f"linter internal error: {internal[0][:300]}" if internal else
                       f"took {secs:.2f} s (budget {BUDGET_SECONDS:.0f} s)" if secs > BUDGET_SECONDS else
                       check(diags, count) if check else None)
        except BaseException as ex:  # noqa: BLE001 - a crash is a test failure, not a test-runner crash
            secs, problem = time.perf_counter() - start, f"{type(ex).__name__}: {str(ex)[:300]}"
        failures += problem is not None
        print(f"{'PASS' if problem is None else 'FAIL'} {name} ({secs:.2f} s)" + (f"\n    {problem}" if problem else ""))
    print(f"-- {len(cases) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
