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
