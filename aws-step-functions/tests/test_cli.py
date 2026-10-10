#!/usr/bin/env python3
"""test_cli.py - command-line behaviour of scripts/lint_asl.py that the golden runner cannot see:
exit codes, file errors, encodings (BOM, UTF-16, piped non-ASCII output), glob expansion, stdin,
and the internal-error safety net. Independent of run_tests.py.

Usage: python3 tests/test_cli.py     prints PASS/FAIL per case, exit 1 when any case fails.
Standard library only (Python 3.9+).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
LINTER = HERE.parent / "scripts" / "lint_asl.py"

CLEAN = '{"QueryLanguage": "JSONata", "StartAt": "A", "States": {"A": {"Type": "Pass", "End": true}}}'
BAD_NEXT = '{"QueryLanguage": "JSONata", "StartAt": "A", "States": {"A": {"Type": "Pass", "Next": "Nope"}}}'
UNICODE = '{"QueryLanguage": "JSONata", "StartAt": "注文", "States": {"注文": {"Type": "Pass", "Next": "終了✓"}}}'
INVALID_NESTED = ('{"QueryLanguage":"JSONata","StartAt":"M","States":{"M":{"Type":"Map","Items":"{% $states.input %}",'
                  '"ItemProcessor":{"StartAt":"S","States":{"S":{"Type":"Succeed"}}},"Next":"X",}}}')
HCL = 'resource "aws_sfn_state_machine" "a" {\n  definition = jsonencode({\n    StartAt = "A"\n    States = {}\n  })\n}\n'
HCL_FOR = ('resource "aws_sfn_state_machine" "a" {\n  definition = jsonencode({\n    StartAt = "A"\n'
           '    States = { for s in var.states : s.name => s.body }\n  })\n}\n')

failures = 0


def run(args: list[str], stdin: bytes | None = None, cwd: str | None = None) -> tuple[int, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    p = subprocess.run([sys.executable, str(LINTER), *args], input=stdin, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, cwd=cwd, env=env)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def check(name: str, ok: bool, detail: str = "") -> None:
    global failures
    if not ok:
        failures += 1
    print(f"{'PASS' if ok else 'FAIL'} {name}" + ("" if ok else f"\n    {detail.strip()[:600]}"))


WARN_ONLY = ('{"QueryLanguage": "JSONata", "StartAt": "C", "States": {"C": {"Type": "Choice", "Choices": '
             '[{"Condition": "{% $states.input.ok %}", "Next": "D"}]}, "D": {"Type": "Succeed"}}}')
INFO_ONLY = '{"StartAt": "A", "States": {"A": {"Type": "Pass", "End": true}}}'  # JSONPath: INFO J000 only


def parse_json(out: str):
    try:
        return json.loads(out)
    except ValueError:
        return None


def cli_flags(d: Path, tmp: str) -> None:
    (d / "warn.json").write_text(WARN_ONLY, encoding="utf-8")
    (d / "info.json").write_text(INFO_ONLY, encoding="utf-8")
    code, out = run(["--bogus", "bad.json"], cwd=tmp)
    check("unknown flag -> usage message, exit 2", code == 2 and "usage:" in out and "--bogus" in out, out)
    code, out = run(["--js", "bad.json"], cwd=tmp)
    check("abbreviated flag (--js) is not accepted -> exit 2", code == 2 and "usage:" in out, out)
    code, out = run([], cwd=tmp)
    check("no files -> usage, exit 2", code == 2 and "usage:" in out, out)
    code, out = run(["--help"], cwd=tmp)
    check("--help -> exit 0 and lists the flags", code == 0 and "--strict" in out and "--explain" in out, out)
    code, out = run(["--type", "bad", "clean.json"], cwd=tmp)
    check("--type with a bad value -> exit 2", code == 2 and "STANDARD or EXPRESS" in out, out)
    code, out = run(["--type=express", "clean.json"], cwd=tmp)
    check("--type=express (any case) accepted", code == 0, out)
    code, out = run(["--type", "EXPRESS", "bad.json"], cwd=tmp)
    check("--type EXPRESS before the file", code == 1 and "S002" in out, out)

    code, out = run(["warn.json"], cwd=tmp)
    check("warnings only -> exit 0", code == 0 and "WARNING S049" in out, out)
    code, out = run(["--strict", "warn.json"], cwd=tmp)
    check("--strict: warnings -> exit 1", code == 1 and "WARNING S049" in out, out)
    code, out = run(["--strict", "clean.json"], cwd=tmp)
    check("--strict: clean file -> exit 0", code == 0, out)
    code, out = run(["--strict", "info.json"], cwd=tmp)
    check("--strict: INFO only -> exit 0", code == 0 and "INFO J000" in out, out)

    code, out = run(["--quiet", "info.json"], cwd=tmp)
    check("--quiet hides INFO in text output", code == 0 and "INFO" not in out and "0 error(s)" in out, out)
    code, out = run(["--quiet", "--format", "json", "info.json"], cwd=tmp)
    data = parse_json(out)
    check("--quiet hides INFO in JSON output", data is not None and data["files"][0]["diagnostics"] == [], out)

    code1, out1 = run(["--json", "bad.json"], cwd=tmp)
    code2, out2 = run(["--format", "json", "bad.json"], cwd=tmp)
    check("--json is --format json", code1 == code2 == 1 and out1 == out2 and parse_json(out1) is not None, out1 + out2)
    code, out = run(["--format", "yaml", "bad.json"], cwd=tmp)
    check("--format with an unknown value -> exit 2", code == 2 and "usage:" in out, out)

    code, out = run(["--format", "github", "bad.json", "info.json"], cwd=tmp)
    lines = out.splitlines()
    check("--format github: ::error annotations with file, line and code",
          code == 1 and lines[0].startswith("::error file=bad.json,line=1,title=S002::/States/A/Next: ")
          and any(line.startswith("::notice file=info.json,line=1,title=J000::") for line in lines)
          and not any(line.startswith("==") for line in lines), out)

    code, out = run(["--format", "sarif", "bad.json", "warn.json", "missing.json"], cwd=tmp)
    log = parse_json(out)
    try:
        run0 = log["runs"][0]
        rules = [r["id"] for r in run0["tool"]["driver"]["rules"]]
        res = {r["ruleId"]: r for r in run0["results"]}
        ok = (code == 2 and log["version"] == "2.1.0" and "$schema" in log and run0["tool"]["driver"]["name"] == "lint_asl"
              and res["S002"]["level"] == "error" and res["S049"]["level"] == "warning"
              and res["S002"]["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": "bad.json"}, "region": {"startLine": 1}}
              and all(rules[r["ruleIndex"]] == r["ruleId"] for r in run0["results"]) and "S000" in res
              and "region" not in res["S000"]["locations"][0]["physicalLocation"])
    except (TypeError, KeyError, IndexError):
        ok = False
    check("--format sarif: a valid minimal SARIF 2.1.0 log (rules, levels, file and line)", ok, out)

    code, out = run(["--list-codes"])
    listed = {line.split()[0] for line in out.splitlines() if line.strip()}
    source = LINTER.read_text(encoding="utf-8")
    emitted = set(re.findall(r'\.(?:error|warn|info|add)\(\s*(?:[^,()]+,\s*)?"([A-Z]\d{3})"', source))
    check("--list-codes lists every code the linter emits", code == 0 and emitted and emitted <= listed,
          f"missing: {sorted(emitted - listed)}\n{out}")
    code, out = run(["--explain", "s017"])
    check("--explain S017: title and a before/after recipe, exit 0",
          code == 0 and out.startswith("S017 (WARNING)") and "Before:" in out and "After:" in out, out)
    code, out = run(["--explain", "X999"])
    check("--explain with an unknown code -> message, exit 2", code == 2 and "unknown code" in out, out)


def line_numbers(d: Path, tmp: str) -> None:
    pretty = json.dumps(json.loads(BAD_NEXT), indent=2)  # "Next": "Nope" is on line 7
    (d / "pretty.json").write_text(pretty, encoding="utf-8")
    want = pretty.splitlines().index('      "Next": "Nope"') + 1
    code, out = run(["pretty.json"], cwd=tmp)
    check("text output: <file>:<line>: SEVERITY CODE <location>: <message>",
          code == 1 and f"pretty.json:{want}: ERROR S002 /States/A/Next: Next targets" in out, out)
    code, out = run(["--json", "pretty.json"], cwd=tmp)
    data = parse_json(out)
    check("--json: diagnostics carry the line", data is not None and data["files"][0]["diagnostics"][0]["line"] == want, out)
    code, out = run(["-"], stdin=pretty.encode("utf-8"), cwd=tmp)
    check("stdin: <stdin>:<line>:", f"<stdin>:{want}: ERROR S002" in out, out)

    tf = ('resource "aws_sfn_state_machine" "sm" {\n  name = "x"\n  definition = <<EOF\n{\n  "QueryLanguage": "JSONata",\n'
          '  "StartAt": "A",\n  "States": {\n    "A": {"Type": "Pass",\n          "Next": "${next}"}, "B": {"Type": "Pass",\n'
          '          "Next": "Nope"}\n  }\n}\nEOF\n}\n')
    (d / "sm.tf").write_text(tf, encoding="utf-8")
    code, out = run(["sm.tf"], cwd=tmp)
    check("Terraform heredoc: the line in the .tf file (chunk start line added)",
          code == 1 and "sm.tf:10: ERROR S002 /States/B/Next" in out and "sm.tf:4: INFO S000 /: extracted" in out, out)

    yaml = ("Resources:\n  SM:\n    Type: AWS::StepFunctions::StateMachine\n    Properties:\n      DefinitionString: !Sub |\n"
            "        {\n          \"QueryLanguage\": \"JSONata\",\n          \"StartAt\": \"A\",\n          \"States\": {\n"
            "            \"A\": {\"Type\": \"Pass\",\n                  \"Next\": \"Nope\"}\n          }\n        }\n")
    (d / "sm.yaml").write_text(yaml, encoding="utf-8")
    code, out = run(["sm.yaml"], cwd=tmp)
    check("CloudFormation YAML DefinitionString: the line in the template", code == 1 and "sm.yaml:11: ERROR S002" in out, out)

    cfn = json.dumps({"Resources": {"SM": {"Type": "AWS::StepFunctions::StateMachine",
                                           "Properties": {"DefinitionString": BAD_NEXT}}}}, indent=2)
    (d / "cfn.json").write_text(cfn, encoding="utf-8")
    want = next(i for i, line in enumerate(cfn.splitlines(), 1) if '"DefinitionString"' in line)
    code, out = run(["cfn.json"], cwd=tmp)
    check("CloudFormation JSON DefinitionString (one string): the line of the string", f"cfn.json:{want}: ERROR S002" in out, out)

    code, out = run(["invalid.json"], cwd=tmp)
    check("invalid JSON: the line from the parser error", "invalid.json:1: ERROR S000" in out, out)
    code, out = run(["missing.json"], cwd=tmp)
    check("unreadable file: no line number", "missing.json: ERROR S000" in out, out)


def order_and_grouping(d: Path, tmp: str) -> None:
    states = {f"S{i}": {"Type": "Pass", "Next": f"NoSuchStateNumber{i}"} for i in range(1, 13)}
    (d / "order.json").write_text(json.dumps({"QueryLanguage": "JSONata", "StartAt": "S1", "States": states}, indent=2), encoding="utf-8")
    code, out = run(["order.json"], cwd=tmp)
    pos = [out.find(f"/States/S{i}/Next:") for i in range(1, 13)]
    check("text output in document order (S2 before S10), not by location string", all(p >= 0 for p in pos) and pos == sorted(pos), out)

    st = {"QueryLanguage": "JSONata", "StartAt": "A", "States": {
        "A": {"Type": "Pass", "Next": "B", "Bogus": 1},
        "B": {"Type": "Choice", "Choices": [{"Condition": "{% $states.input.x %}", "Next": "Z"}]},
        "Z": {"Type": "Succeed"}}}
    (d / "sev.json").write_text(json.dumps(st, indent=2), encoding="utf-8")
    code, out = run(["sev.json"], cwd=tmp)
    check("state order first: A's ERROR, then B's WARNING", 0 <= out.find("ERROR S009 /States/A/Bogus") < out.find("WARNING S049 /States/B"), out)

    code, out = run(["two.json"], cwd=tmp)
    check("several definitions: definition index first", 0 <= out.find("[1:") < out.find("[2:"), out)

    rep = {f"S{i}": {"Type": "Pass", "Bogus": 1, "Next": f"S{i + 1}" if i < 4 else "S5"} for i in range(5)}
    rep["S5"] = {"Type": "Pass", "Bogus": 1, "End": True}
    (d / "rep.json").write_text(json.dumps({"QueryLanguage": "JSONata", "StartAt": "S0", "States": rep}, indent=2), encoding="utf-8")
    code, out = run(["rep.json"], cwd=tmp)
    lines = [line for line in out.splitlines() if "S009" in line]
    check("same code and message 4+ times: printed once with every location and line",
          len(lines) == 1 and "S009 at 6 locations: /States/S0/Bogus (line " in lines[0] and "/States/S5/Bogus (line " in lines[0]
          and lines[0].startswith("rep.json:") and "6 error(s)" in out, out)
    code, out = run(["--json", "rep.json"], cwd=tmp)
    data = parse_json(out)
    check("--json: repeated diagnostics stay one item each",
          data is not None and len([x for x in data["files"][0]["diagnostics"] if x["code"] == "S009"]) == 6, out)

    typo = json.dumps({"QueryLanguage": "JSONata", "StartAt": "Get", "States": {
        "Get": {"Type": "Pass", "Next": "ChargeOrdr"}, "ChargeOrder": {"Type": "Pass", "Next": "Done"}, "Done": {"Type": "Succeed"}}})
    (d / "typo.json").write_text(typo, encoding="utf-8")
    code, out = run(["typo.json"], cwd=tmp)
    check("S002 suggests the closest state; that state is not also reported as S003",
          code == 1 and '(did you mean "ChargeOrder"?)' in out and "S003" not in out, out)
    orphan = json.dumps({"QueryLanguage": "JSONata", "StartAt": "A", "States": {
        "A": {"Type": "Succeed"}, "Refund": {"Type": "Pass", "Next": "Notify"}, "Notify": {"Type": "Pass", "Next": "Done"},
        "Done": {"Type": "Succeed"}}})
    (d / "orphan.json").write_text(orphan, encoding="utf-8")
    code, out = run(["orphan.json"], cwd=tmp)
    check("S003 only for the orphan root, listing what is unreachable through it",
          out.count("S003") == 1 and 'state "Refund" is unreachable' in out and "also unreachable through it: Notify, Done" in out, out)


def suppressions(d: Path, tmp: str) -> None:
    def sm(comment: str) -> str:
        return json.dumps({"QueryLanguage": "JSONata", "StartAt": "A", "States": {
            "A": {"Type": "Pass", "Comment": comment, "Bogus": 1, "End": True}}}, indent=2)
    (d / "allow.json").write_text(sm("lint-allow S009: Bogus is read by our deploy tooling and stripped before upload"), encoding="utf-8")
    (d / "allow2.json").write_text(sm("lint-allow S017, S009: generated"), encoding="utf-8")
    (d / "noreason.json").write_text(sm("lint-allow S009"), encoding="utf-8")
    (d / "other.json").write_text(sm("lint-allow S017: unrelated"), encoding="utf-8")
    code, out = run(["allow.json"], cwd=tmp)
    check("lint-allow with a reason: the error is suppressed, exit 0, '-- 1 suppressed'",
          code == 0 and "S009" not in out and "0 error(s)" in out and out.rstrip().splitlines()[-1].startswith("-- 1 suppressed"), out)
    code, out = run(["--show-suppressed", "allow.json"], cwd=tmp)
    check("--show-suppressed lists it with its reason",
          code == 0 and "suppressed ERROR S009 /States/A/Bogus" in out and "Bogus is read by our deploy tooling" in out, out)
    code, out = run(["--json", "allow.json"], cwd=tmp)
    data = parse_json(out)
    check("--json: suppressed diagnostics in a separate list",
          data is not None and data["files"][0]["diagnostics"] == [] and data["files"][0]["suppressed"][0]["code"] == "S009"
          and data["files"][0]["suppressed"][0]["suppressedBy"].startswith("Bogus is read"), out)
    code, out = run(["allow2.json"], cwd=tmp)
    check("lint-allow with several codes", code == 0 and "1 suppressed" in out, out)
    code, out = run(["noreason.json"], cwd=tmp)
    check("lint-allow without a reason: ignored, with an INFO saying why, still exit 1",
          code == 1 and "ERROR S009" in out and "INFO S000 /States/A/Comment" in out and "no reason" in out and "suppressed" not in out.splitlines()[-1], out)
    code, out = run(["other.json"], cwd=tmp)
    check("lint-allow of another code does not suppress", code == 1 and "ERROR S009" in out, out)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "clean.json").write_text(CLEAN, encoding="utf-8")
        (d / "bad.json").write_text(BAD_NEXT, encoding="utf-8")
        (d / "uni.json").write_text(UNICODE, encoding="utf-8")
        (d / "bom.json").write_bytes(b"\xef\xbb\xbf" + BAD_NEXT.encode("utf-8"))
        (d / "u16le.json").write_bytes(BAD_NEXT.encode("utf-16"))  # with BOM
        (d / "u16be.json").write_bytes(b"\xfe\xff" + BAD_NEXT.encode("utf-16-be"))
        (d / "u16nobom.json").write_bytes(BAD_NEXT.encode("utf-16-le"))
        (d / "empty.json").write_bytes(b"")
        (d / "binary.json").write_bytes(b'{"a": "\xff\x80\x81"}')
        (d / "invalid.json").write_text(INVALID_NESTED, encoding="utf-8")
        (d / "main.tf").write_text(HCL, encoding="utf-8")
        (d / "for.tf").write_text(HCL_FOR, encoding="utf-8")
        (d / "sub").mkdir()

        code, out = run(["clean.json"], cwd=tmp)
        check("clean file -> exit 0", code == 0 and "0 error(s)" in out, out)
        code, out = run(["bad.json"], cwd=tmp)
        check("errors -> exit 1", code == 1 and "S002" in out, out)

        code, out = run(["uni.json"], cwd=tmp)  # stdout is a pipe: must not crash with UnicodeEncodeError
        check("piped non-ASCII output does not crash", code == 1 and "Traceback" not in out and "終了✓" in out, out)

        for f in ("bom.json", "u16le.json", "u16be.json", "u16nobom.json"):
            code, out = run([f], cwd=tmp)
            check(f"{f}: decoded and linted as plain JSON", code == 1 and "S002" in out and "extracted" not in out, out)
        code, out = run(["-"], stdin=BAD_NEXT.encode("utf-16"), cwd=tmp)
        check("stdin UTF-16 with BOM", code == 1 and "S002" in out, out)
        code, out = run(["-"], stdin=b"\xef\xbb\xbf" + UNICODE.encode("utf-8"), cwd=tmp)
        check("stdin UTF-8 with BOM and non-ASCII", code == 1 and "終了✓" in out and "extracted" not in out, out)

        code, out = run(["missing.json", "clean.json"], cwd=tmp)
        check("missing file reported, other files still linted, exit 2",
              code == 2 and "cannot read file" in out and "== clean.json" in out and "Traceback" not in out, out)
        code, out = run(["sub"], cwd=tmp)
        check("directory argument -> message suggesting a glob, exit 2", code == 2 and "directory" in out and "*.json" in out, out)
        code, out = run(["binary.json"], cwd=tmp)
        check("undecodable file -> cannot read file, exit 2", code == 2 and "cannot read file" in out, out)
        code, out = run(["empty.json"], cwd=tmp)
        check("empty file -> clear message, exit 2", code == 2 and "empty" in out, out)
        code, out = run([os.devnull], cwd=tmp)  # a device (Windows CON would block reading the console)
        check(f"device {os.devnull} -> not a regular file, exit 2", code == 2 and "not a regular file" in out, out)

        code, out = run(["c*.json"], cwd=tmp)
        check("glob expanded by the linter", code == 0 and "== clean.json" in out, out)
        code, out = run(["nomatch*.json"], cwd=tmp)
        check("glob without matches -> message, exit 2", code == 2 and "no files match" in out, out)

        code, out = run(["invalid.json"], cwd=tmp)
        check("invalid JSON -> S000 with line/column, exit 2 (not a clean run)",
              code == 2 and "S000" in out and "line 1 column" in out, out)
        code, out = run(["main.tf"], cwd=tmp)
        check("Terraform jsonencode -> converted from HCL and linted, exit 1",
              code == 1 and "converted the Terraform jsonencode" in out and "S001" in out, out)
        code, out = run(["for.tf"], cwd=tmp)
        check("Terraform jsonencode with a for expression -> render hint, exit 2",
              code == 2 and "terraform show -json" in out and "for expression" in out, out)
        code, out = run(["--json", "bad.json", "missing.json"], cwd=tmp)
        try:
            data = json.loads(out)
            ok = code == 2 and [f["file"] for f in data["files"]] == ["bad.json", "missing.json"]
        except ValueError:
            ok = False
        check("--json output stays valid JSON with a file error", ok, out)

        (d / "two.json").write_text(json.dumps({"Resources": {
            "A": {"Properties": {"Definition": json.loads(CLEAN)}},
            "B": {"Properties": {"DefinitionString": {"Fn::Sub": BAD_NEXT}}}}}), encoding="utf-8")
        code, out = run(["two.json"], cwd=tmp)
        check("two definitions: every diagnostic says which one, one note per definition",
              code == 1 and "S002 [2:/Resources/B/Properties/DefinitionString] /States/A/Next" in out
              and "[1:/Resources/A/Properties/Definition] /: linted" in out
              and "[2:/Resources/B/Properties/DefinitionString] /: linted" in out, out)
        code, out = run(["--json", "two.json"], cwd=tmp)
        try:
            diags = json.loads(out)["files"][0]["diagnostics"]
            s002 = [x for x in diags if x["code"] == "S002"]
            ok = len(s002) == 1 and s002[0]["definition"] == {
                "index": 2, "label": "/Resources/B/Properties/DefinitionString", "path": "/States/A/Next"}
        except (ValueError, KeyError, IndexError):
            ok = False
        check("--json: multi-definition diagnostics carry a definition field", ok, out)
        code, out = run(["bad.json", "--json"], cwd=tmp)
        check("--json: single-definition diagnostics unchanged (no definition field, plain location)",
              '"definition"' not in out and '"location": "/States/A/Next"' in out, out)

        (d / "sm.asl.json").write_text('{"StartAt": "A", "States": {"A": {"Type": "Pass",\n%{ if x }"Next": "B"},'
                                       '"B": {"Type": "Pass", "End": true}\n%{ else }"End": true}\n%{ endif }}}', encoding="utf-8")
        code, out = run(["sm.asl.json"], cwd=tmp)
        check("template %{ if }/%{ else }: only the if branch is linted (no invalid-JSON error)",
              code == 0 and "S000" in out and "invalid JSON" not in out, out)
        (d / "broken.asl.json").write_text('{"StartAt": "A", "States": {\n%{ for s in xs }"${s}": {"Type": "Pass", "End": true}\n'
                                           '%{ endfor }"Z": {"Type": "Pass", "End": true}}}', encoding="utf-8")
        code, out = run(["broken.asl.json"], cwd=tmp)
        check("template still invalid after removing directives -> WARNING 'could not lint this template', exit 2",
              code == 2 and "WARNING S000" in out and "could not lint this template" in out and "ERROR" not in out, out)

        cli_flags(d, tmp)
        line_numbers(d, tmp)
        order_and_grouping(d, tmp)
        suppressions(d, tmp)

    # S039 definition size quota (1 MB); a fixture this large would bloat tests/fixtures
    with tempfile.TemporaryDirectory() as tmp:
        states = {f"P{i}": {"Type": "Pass", "Output": {"blob": "x" * 200_000}, "Next": f"P{i + 1}"} for i in range(6)}
        states["P6"] = {"Type": "Succeed"}
        big = json.dumps({"QueryLanguage": "JSONata", "StartAt": "P0", "States": states})
        (Path(tmp) / "big.json").write_text(big, encoding="utf-8")
        code, out = run(["big.json"], cwd=tmp)
        check("definition over 1 MB -> ERROR S039 at /, no per-field WARNING for 200 KB literals, exit 1",
              code == 1 and "ERROR S039 /:" in out and "WARNING S039" not in out, out)

    # internal-error safety net (in-process: force lint_definition to crash)
    spec = importlib.util.spec_from_file_location("lint_asl_cli_test", LINTER)
    mod = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    for exc in (TypeError("'int' object is not iterable"), RecursionError("maximum recursion depth exceeded")):
        def boom(*_a, _exc=exc, **_k):
            raise _exc
        mod.lint_definition = boom
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.json"
            p.write_text(CLEAN, encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = mod.main(["lint_asl.py", str(p)])
        out = buf.getvalue()
        check(f"internal {type(exc).__name__} -> S000 'linter internal error', exit 3",
              code == 3 and "linter internal error" in out and type(exc).__name__ in out, out)

    print(f"-- {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
