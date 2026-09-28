#!/usr/bin/env python3
"""lint_asl.py - static checks for AWS Step Functions state machine definitions
(Amazon States Language, JSONata and JSONPath query languages).

Usage:
    python3 lint_asl.py <file> [<file>...]   JSON, .asl.json, or any text file that embeds a
                                             definition (Terraform templatefile/heredoc,
                                             CloudFormation YAML DefinitionString, SAM, ...)
    python3 lint_asl.py -                    read a definition from stdin
    python3 lint_asl.py --json <file>        machine-readable diagnostics

Exit code 1 when any ERROR is reported, 0 otherwise. Standard library only (Python 3.9+).
If the optional `jsonata-python` package is installed (pip install jsonata-python) every
{% %} expression is also parsed for syntax.
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

STATE_TYPES = ["Task", "Pass", "Choice", "Wait", "Succeed", "Fail", "Parallel", "Map"]
COMMON_FIELDS = ["Type", "Comment", "QueryLanguage"]

# Fields allowed per state type, split by query language.
FIELDS: dict[str, dict[str, list[str]]] = {
    "Task": {
        "both": ["Resource", "Next", "End", "Retry", "Catch", "TimeoutSeconds", "HeartbeatSeconds", "Credentials", "Assign"],
        "jsonata": ["Arguments", "Output"],
        "jsonpath": ["Parameters", "ResultSelector", "ResultPath", "InputPath", "OutputPath", "TimeoutSecondsPath", "HeartbeatSecondsPath"],
    },
    "Pass": {
        "both": ["Next", "End", "Assign"],
        "jsonata": ["Output"],
        "jsonpath": ["Result", "ResultPath", "Parameters", "InputPath", "OutputPath"],
    },
    "Choice": {
        "both": ["Choices", "Default", "Assign"],
        "jsonata": ["Output"],
        "jsonpath": ["InputPath", "OutputPath"],
    },
    "Wait": {
        "both": ["Next", "End", "Seconds", "Timestamp", "Assign"],
        "jsonata": ["Output"],
        "jsonpath": ["SecondsPath", "TimestampPath", "InputPath", "OutputPath"],
    },
    "Succeed": {"both": [], "jsonata": ["Output"], "jsonpath": ["InputPath", "OutputPath"]},
    "Fail": {"both": ["Error", "Cause"], "jsonata": [], "jsonpath": ["ErrorPath", "CausePath"]},
    "Parallel": {
        "both": ["Branches", "Next", "End", "Retry", "Catch", "Assign"],
        "jsonata": ["Arguments", "Output"],
        "jsonpath": ["Parameters", "ResultPath", "ResultSelector", "InputPath", "OutputPath"],
    },
    "Map": {
        "both": ["ItemProcessor", "Iterator", "ItemSelector", "ItemReader", "ItemBatcher", "ResultWriter", "MaxConcurrency",
                 "ToleratedFailureCount", "ToleratedFailurePercentage", "Label", "Next", "End", "Retry", "Catch", "Assign"],
        "jsonata": ["Items", "Output"],
        "jsonpath": ["ItemsPath", "Parameters", "ResultPath", "ResultSelector", "InputPath", "OutputPath",
                     "MaxConcurrencyPath", "ToleratedFailureCountPath", "ToleratedFailurePercentagePath"],
    },
}

CHOICE_RULE_FIELDS = {
    "jsonata": ["Condition", "Next", "Assign", "Output", "Comment"],
    "jsonpath": ["Variable", "Next", "Assign", "Comment", "And", "Or", "Not",
                 "BooleanEquals", "BooleanEqualsPath", "IsBoolean", "IsNull", "IsNumeric", "IsPresent", "IsString", "IsTimestamp",
                 "NumericEquals", "NumericEqualsPath", "NumericGreaterThan", "NumericGreaterThanPath", "NumericGreaterThanEquals",
                 "NumericGreaterThanEqualsPath", "NumericLessThan", "NumericLessThanPath", "NumericLessThanEquals",
                 "NumericLessThanEqualsPath", "StringEquals", "StringEqualsPath", "StringGreaterThan", "StringGreaterThanPath",
                 "StringGreaterThanEquals", "StringGreaterThanEqualsPath", "StringLessThan", "StringLessThanPath",
                 "StringLessThanEquals", "StringLessThanEqualsPath", "StringMatches", "TimestampEquals", "TimestampEqualsPath",
                 "TimestampGreaterThan", "TimestampGreaterThanPath", "TimestampGreaterThanEquals", "TimestampGreaterThanEqualsPath",
                 "TimestampLessThan", "TimestampLessThanPath", "TimestampLessThanEquals", "TimestampLessThanEqualsPath"],
}

RETRY_FIELDS = ["ErrorEquals", "IntervalSeconds", "MaxAttempts", "BackoffRate", "MaxDelaySeconds", "JitterStrategy", "Comment"]
CATCH_FIELDS = {"both": ["ErrorEquals", "Next", "Assign", "Comment"], "jsonata": ["Output"], "jsonpath": ["ResultPath"]}

ASSIGN_ALLOWED = {"Pass", "Task", "Map", "Parallel", "Choice", "Wait"}
RETRY_CATCH_ALLOWED = {"Task", "Map", "Parallel"}
RESULT_ALLOWED = {"Task", "Map", "Parallel"}
TERMINAL_TYPES = {"Succeed", "Fail"}

# JSONata 2.0.x built-ins supported by Step Functions, plus the Step Functions extras.
JSONATA_FUNCTIONS = {
    # string
    "string", "length", "substring", "substringBefore", "substringAfter", "uppercase", "lowercase", "trim", "pad",
    "contains", "split", "join", "match", "replace", "base64encode", "base64decode", "encodeUrlComponent", "encodeUrl",
    "decodeUrlComponent", "decodeUrl",
    # numeric
    "number", "abs", "floor", "ceil", "round", "power", "sqrt", "random", "formatNumber", "formatBase", "formatInteger",
    "parseInteger",
    # aggregation
    "sum", "max", "min", "average",
    # boolean
    "boolean", "not", "exists",
    # array
    "count", "append", "sort", "reverse", "shuffle", "distinct", "zip",
    # object
    "keys", "lookup", "spread", "merge", "sift", "each", "error", "assert", "type",
    # date/time
    "now", "millis", "fromMillis", "toMillis",
    # higher order
    "map", "filter", "single", "reduce",
    # Step Functions additions
    "partition", "range", "hash", "uuid", "parse",
}

# Frequently invented names -> what to use instead.
FUNCTION_HINTS = {
    "eval": "$parse(str) - $eval is not supported by Step Functions",
    "size": "$count(array) for arrays, $length(str) for strings",
    "len": "$count(array) for arrays, $length(str) for strings",
    "isEmpty": "$count(x) = 0, or $not($exists(x))",
    "empty": "$count(x) = 0, or $not($exists(x))",
    "toString": "$string(x)",
    "str": "$string(x)",
    "stringify": "$string(x)",
    "toJson": "$string(x)",
    "toNumber": "$number(x)",
    "int": "$number(x) or $floor($number(x))",
    "parseInt": "$number(x) or $floor($number(x))",
    "parseFloat": "$number(x)",
    "float": "$number(x)",
    "upper": "$uppercase(str)",
    "lower": "$lowercase(str)",
    "toUpperCase": "$uppercase(str)",
    "toLowerCase": "$lowercase(str)",
    "toUpper": "$uppercase(str)",
    "toLower": "$lowercase(str)",
    "concat": "the & operator ('a' & 'b'), or $join(array, sep) for arrays",
    "startsWith": "$substring(str, 0, $length(prefix)) = prefix",
    "endsWith": "$substring(str, -$length(suffix)) = suffix",
    "indexOf": "$contains(str, sub) for a boolean, or $match(str, /re/) for positions",
    "includes": "'x' in array, or $contains(str, sub)",
    "has": "$exists(obj.key), or key in $keys(obj)",
    "in": "the in operator: 'x' in array",
    "isArray": "$type(x) = 'array'",
    "isString": "$type(x) = 'string'",
    "isNumber": "$type(x) = 'number'",
    "isNull": "$x = null",
    "typeof": "$type(x)",
    "first": "array[0]",
    "last": "array[-1]",
    "head": "array[0]",
    "tail": "array[[1..$count(array)-1]]",
    "slice": "array[[start..end]] for arrays, $substring(str, start, len) for strings",
    "substr": "$substring(str, start, len)",
    "push": "$append(array, [item])",
    "concatArrays": "$append(a, b)",
    "flatten": "$reduce(arrays, function($a, $b) { $append($a, $b) }, [])",
    "find": "$filter(array, fn)[0], or $single(array, fn)",
    "some": "$count($filter(array, fn)) > 0",
    "every": "$count($filter(array, fn)) = $count(array)",
    "unique": "$distinct(array)",
    "date": "$now(), $millis(), $fromMillis(ms, picture)",
    "today": "$now('[Y0001]-[M01]-[D01]')",
    "timestamp": "$now() or $millis()",
    "formatDate": "$fromMillis(ms, picture)",
    "dateFormat": "$fromMillis(ms, picture)",
    "parseJson": "$parse(str)",
    "fromJson": "$parse(str)",
    "jsonParse": "$parse(str)",
    "json": "$parse(str) to read, $string(x) to write",
    "if": "condition ? a : b",
    "ifElse": "condition ? a : b",
    "coalesce": "a ?? b",
    "default": "a ?? b",
    "ifNull": "a ?? b",
    "entries": '$each(obj, function($v, $k) { {"key": $k, "value": $v} })',
    "values": "$each(obj, function($v) { $v })",
    "pairs": "$spread(obj)",
    "object": '{ "key": value } object constructor, or $merge([...])',
    "mergeObjects": "$merge([a, b])",
    "assign": "$merge([a, b])",
    "extend": "$merge([a, b])",
    "groupBy": "the object constructor with grouping: array{ key: value }",
    "sumBy": "$sum(array.field)",
    "uuidv4": "$uuid()",
    "guid": "$uuid()",
    "randomUUID": "$uuid()",
    "chunk": "$partition(array, size)",
    "sequence": "$range(start, end, step) or [start..end]",
    "sha256": "$hash(str, 'SHA-256')",
    "md5": "$hash(str, 'MD5')",
    "base64": "$base64encode(str) / $base64decode(str)",
    "btoa": "$base64encode(str)",
    "atob": "$base64decode(str)",
    "env": "$states.context",
    "context": "$states.context",
    "input": "$states.input",
    "result": "$states.result (only in Output/Assign of Task, Map, Parallel)",
    "trunc": "$floor(x)",
    "mod": "the % operator: a % b",
    "pow": "$power(base, exp)",
    "strip": "$trim(str)",
    "format": "the & operator, e.g. 'Order ' & $id",
}

ERROR_NAMES = {"States.ALL", "States.DataLimitExceeded", "States.ExceedToleratedFailureThreshold",
               "States.HeartbeatTimeout", "States.Http.Socket", "States.ItemReaderFailed", "States.Permissions",
               "States.ResultWriterFailed", "States.Runtime", "States.TaskFailed", "States.Timeout", "States.QueryEvaluationError",
               "States.BranchFailed", "States.NoChoiceMatched", "States.IntrinsicFailure", "States.ParameterPathFailure",
               "States.ResultPathMatchFailure"}

JSONATA_REPLACEMENT = {
    "Parameters": ' - use "Arguments"',
    "ResultSelector": ' - use "Output" with $states.result',
    "ResultPath": ' - use "Output" (e.g. "{% $merge([$states.input, {\'result\': $states.result}]) %}") or store the value with "Assign"',
    "InputPath": " - select inside expressions with $states.input.<path>",
    "OutputPath": ' - use "Output"',
    "Result": ' - use "Output"',
    "ItemsPath": ' - use "Items": "{% $states.input.<array> %}"',
    "SecondsPath": ' - use "Seconds": "{% <expr> %}"',
    "TimestampPath": ' - use "Timestamp": "{% <expr> %}"',
    "TimeoutSecondsPath": ' - use "TimeoutSeconds": "{% <expr> %}"',
    "HeartbeatSecondsPath": ' - use "HeartbeatSeconds": "{% <expr> %}"',
    "MaxConcurrencyPath": ' - use "MaxConcurrency": "{% <expr> %}"',
    "ErrorPath": ' - use "Error": "{% <expr> %}"',
    "CausePath": ' - use "Cause": "{% <expr> %}"',
    "ToleratedFailureCountPath": ' - use "ToleratedFailureCount": "{% <expr> %}"',
    "ToleratedFailurePercentagePath": ' - use "ToleratedFailurePercentage": "{% <expr> %}"',
}

# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


class Diagnostics:
    def __init__(self) -> None:
        self.items: list[dict[str, str]] = []

    def add(self, severity: str, code: str, location: str, message: str) -> None:
        self.items.append({"severity": severity, "code": code, "location": location, "message": message})

    def error(self, code: str, loc: str, msg: str) -> None:
        self.add("ERROR", code, loc, msg)

    def warn(self, code: str, loc: str, msg: str) -> None:
        self.add("WARNING", code, loc, msg)

    def info(self, code: str, loc: str, msg: str) -> None:
        self.add("INFO", code, loc, msg)

    @property
    def errors(self) -> int:
        return sum(1 for d in self.items if d["severity"] == "ERROR")

    @property
    def warnings(self) -> int:
        return sum(1 for d in self.items if d["severity"] == "WARNING")


# ---------------------------------------------------------------------------
# Optional real JSONata parser (pip install jsonata-python)
# ---------------------------------------------------------------------------


def load_jsonata():
    try:
        import jsonata  # type: ignore

        def parse(expr: str) -> None:
            jsonata.Jsonata(expr)

        return parse
    except Exception:  # noqa: BLE001 - any import problem means "not available"
        return None


# ---------------------------------------------------------------------------
# Expression scanning
# ---------------------------------------------------------------------------

EXPR_RE = re.compile(r"^\{%([\s\S]*)%\}$")
IDENT = r"[A-Za-z_À-￿][\wÀ-￿]*"
CALL_RE = re.compile(r"\$(" + IDENT + r")\s*\(")
VAR_RE = re.compile(r"\$(" + IDENT + r")(?![\wÀ-￿])(?!\s*\()")
BIND_RE = re.compile(r"\$(" + IDENT + r")\s*:=")
FUNC_PARAMS_RE = re.compile(r"(?:function|λ)\s*\(([^)]*)\)")


def is_expression(s: Any) -> bool:
    return isinstance(s, str) and EXPR_RE.match(s) is not None


def strip_literals(src: str) -> str:
    """Blank out comments, string literals and regex literals (length preserved)."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            stop = n if end == -1 else end + 2
            out.append(" " * (stop - i))
            i = stop
            continue
        if c in ('"', "'"):
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\":
                    j += 1
                j += 1
            out.append(c + " " * max(0, j - i - 1) + c)
            i = j + 1
            continue
        if c == "`":
            j = src.find("`", i + 1)
            stop = n if j == -1 else j
            out.append("`" + " " * max(0, stop - i - 1) + "`")
            i = stop + 1
            continue
        if c == "/":
            prev = "".join(out).rstrip()[-1:] if out else ""
            if prev == "" or prev in "(,=~&|?:[":
                j = i + 1
                while j < n and src[j] != "/" and src[j] != "\n":
                    if src[j] == "\\":
                        j += 1
                    j += 1
                if j < n and src[j] == "/":
                    k = j + 1
                    while k < n and src[k] in "im":
                        k += 1
                    out.append("/" + " " * max(0, k - i - 2) + "/")
                    i = k
                    continue
        out.append(c)
        i += 1
    return "".join(out)


class ExprAnalysis:
    def __init__(self) -> None:
        self.calls: set[str] = set()
        self.vars: set[str] = set()
        self.bound: set[str] = set()
        self.states_result = False
        self.states_error_output = False
        self.jsonpath_context = False
        self.jsonpath_dollar_dot = False
        self.intrinsic = False
        self.bad_ops: list[str] = []


def analyse_expression(expr: str) -> ExprAnalysis:
    code = strip_literals(expr)
    a = ExprAnalysis()
    for m in BIND_RE.finditer(code):
        a.bound.add(m.group(1))
    for m in FUNC_PARAMS_RE.finditer(code):
        for p in m.group(1).split(","):
            name = p.strip().lstrip("$")
            if name:
                a.bound.add(name)
    for m in CALL_RE.finditer(code):
        a.calls.add(m.group(1))
    for m in VAR_RE.finditer(code):
        a.vars.add(m.group(1))

    a.states_result = re.search(r"\$states\s*\.\s*result\b", code) is not None
    a.states_error_output = re.search(r"\$states\s*\.\s*errorOutput\b", code) is not None
    a.jsonpath_context = re.search(r"\$\$\s*\.", code) is not None
    a.jsonpath_dollar_dot = re.search(r"(^|[^\w$.])\$\.(?=[A-Za-z_`])", code) is not None
    a.intrinsic = re.search(r"\bStates\.[A-Z][A-Za-z]+\s*\(", code) is not None
    if re.search(r"(^|[^=!<>])==(?!=)", code) or "===" in code:
        a.bad_ops.append("== (JSONata equality is a single =)")
    if "!==" in code:
        a.bad_ops.append("!== (use !=)")
    if "&&" in code:
        a.bad_ops.append("&& (use and)")
    if "||" in code:
        a.bad_ops.append("|| (use or)")
    if re.search(r"(^|[^!<>=])!(?![=])", code):
        a.bad_ops.append("! prefix (use $not(x) or x = false)")

    for b in a.bound:
        a.vars.discard(b)
        a.calls.discard(b)
    a.vars.discard("states")
    for c in a.calls:
        a.vars.discard(c)
    return a


# ---------------------------------------------------------------------------
# Definition discovery (plain JSON or embedded in another file)
# ---------------------------------------------------------------------------


def try_parse(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def match_braces(text: str) -> list[tuple[int, int]]:
    pairs: list[tuple[int, int]] = []
    stack: list[int] = []
    in_str = False
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            stack.append(i)
        elif c == "}" and stack:
            pairs.append((stack.pop(), i))
        i += 1
    return pairs


def extract_definitions(text: str) -> list[tuple[dict, Optional[str]]]:
    direct = try_parse(text)
    if isinstance(direct, dict):
        return [(direct, None)]
    variants = [
        re.sub(r"\$\{[^}]*\}", "__TPL__", text),
        re.sub(r"\$\{[^}]*\}", '"__TPL__"', text),
        text,
    ]
    found: list[tuple[dict, Optional[str]]] = []
    for v in variants:
        taken: list[tuple[int, int]] = []
        for s, e in sorted(match_braces(v)):
            if any(s >= ts and e <= te for ts, te in taken):
                continue
            chunk = v[s:e + 1]
            if not re.search(r'"States"\s*:', chunk) or not re.search(r'"StartAt"\s*:', chunk):
                continue
            obj = try_parse(chunk)
            if isinstance(obj, dict) and obj.get("States") and obj.get("StartAt"):
                found.append((obj, "extracted embedded definition (template placeholders replaced by __TPL__)"))
                taken.append((s, e))
        if found:
            break
    return found


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def assign_keys(assign: Any) -> set[str]:
    return set(assign.keys()) if isinstance(assign, dict) else set()


def is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def suggest_field(k: str, allowed: set[str]) -> str:
    lower = k.lower()
    for a in allowed:
        if a.lower() == lower or levenshtein(a.lower(), lower) <= 2:
            return f' (did you mean "{a}"?)'
    return ""


def check_error_equals(ee: Any, loc: str, is_last: bool, diags: Diagnostics) -> None:
    if not isinstance(ee, list) or not ee:
        diags.error("S012", f"{loc}/ErrorEquals", "ErrorEquals must be a non-empty array of error names")
        return
    for e in ee:
        if not isinstance(e, str):
            diags.error("S012", f"{loc}/ErrorEquals", "error names must be strings")
            continue
        if e.startswith("States.") and e not in ERROR_NAMES:
            diags.error("S012", f"{loc}/ErrorEquals", f'"{e}" is not a predefined States.* error name')
    if "States.ALL" in ee:
        if len(ee) > 1:
            diags.error("S012", f"{loc}/ErrorEquals", "States.ALL must appear alone in ErrorEquals")
        if not is_last:
            diags.error("S012", f"{loc}/ErrorEquals", "the retrier/catcher with States.ALL must be the last one in the array")


def walk_keys(obj: Any, fn, skip_keys: list[str], prefix: str = "") -> None:
    """Visit every key (path, key, value) without descending into sub-scopes at the top level."""
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            walk_keys(v, fn, skip_keys, f"{prefix}{i}/")
        return
    if not isinstance(obj, dict):
        return
    for k, v in obj.items():
        if prefix == "" and k in skip_keys:
            continue
        fn(f"{prefix}{k}", k, v)
        walk_keys(v, fn, skip_keys, f"{prefix}{k}/")


def collect_expressions(st: dict) -> list[tuple[str, str, bool, bool]]:
    """Every {% %} candidate in a state: (field path, raw string, result allowed, errorOutput allowed)."""
    out: list[tuple[str, str, bool, bool]] = []
    stype = st.get("Type")
    skip = {"ItemProcessor", "Iterator", "Branches", "Retry", "Type", "Comment", "Resource", "Next", "Default", "End",
            "QueryLanguage", "ProcessorConfig", "ReaderConfig", "WriterConfig", "Label"}

    def visit(v: Any, parts: list[str], result_ok: bool, error_ok: bool) -> None:
        if isinstance(v, str):
            if "{%" in v or "%}" in v:
                out.append(("/".join(parts), v, result_ok, error_ok))
        elif isinstance(v, list):
            for i, x in enumerate(v):
                visit(x, parts + [str(i)], result_ok, error_ok)
        elif isinstance(v, dict):
            for k, x in v.items():
                visit(x, parts + [k], result_ok, error_ok)

    for k, v in st.items():
        if k in skip:
            continue
        if k == "Catch":
            for i, c in enumerate(v if isinstance(v, list) else []):
                if isinstance(c, dict):
                    for ck, cv in c.items():
                        if ck in ("Output", "Assign"):
                            visit(cv, ["Catch", str(i), ck], False, True)
            continue
        if k == "Choices" and isinstance(v, list):
            for i, r in enumerate(v):
                visit(r, ["Choices", str(i)], False, False)
            continue
        result_ok = stype in RESULT_ALLOWED and k in ("Output", "Assign")
        visit(v, [k], result_ok, False)
    return out


def check_expression(raw: str, loc: str, *, result_ok: bool, error_ok: bool, in_vars: set[str], ever_assigned: set[str],
                     all_assigned: dict[str, str], outer_for_distributed: Optional[set[str]], diags: Diagnostics, jsonata) -> None:
    m = EXPR_RE.match(raw)
    if not m:
        diags.error("J003", loc, 'string contains "{%" or "%}" but is not a well-formed expression: it must start with "{%" '
                    f'and end with "%}}" with no surrounding whitespace: {json.dumps(raw[:60])}')
        return
    expr = m.group(1)
    if not expr.strip():
        diags.error("J003", loc, "empty JSONata expression")
        return

    a = analyse_expression(expr)

    if a.intrinsic:
        diags.error("J008", loc, "intrinsic functions (States.Format, States.ArrayLength, ...) are JSONPath-only; use JSONata "
                    "equivalents (&, $count, $partition, $range, $hash, $uuid, $parse)")
    if a.jsonpath_context:
        diags.error("J009", loc, '"$$." is JSONPath context syntax; use $states.context.<field> '
                    "(e.g. $states.context.Execution.Id, $states.context.Map.Item.Value)")
    if a.jsonpath_dollar_dot:
        diags.warn("J009", loc, '"$.field" looks like a JSONPath habit; in Step Functions JSONata the state input is $states.input.field')
    for op in a.bad_ops:
        diags.error("J007", loc, f"invalid operator {op}")
    if a.states_result and not result_ok:
        diags.error("J004", loc, "$states.result is only available in Output and Assign of Task, Map and Parallel states "
                    "(not in Arguments, Items, Conditions, Pass/Wait/Choice states, or Catch)")
    if a.states_error_output and not error_ok:
        diags.error("J004", loc, "$states.errorOutput is only available inside Catch (Output/Assign)")

    for fn in sorted(a.calls):
        if fn in JSONATA_FUNCTIONS:
            continue
        hint = f" - use {FUNCTION_HINTS[fn]}" if fn in FUNCTION_HINTS else " - see reference/jsonata-functions.md for the allowed list"
        diags.error("J005", loc, f"${fn}() is not a JSONata/Step Functions function{hint}")

    for v in sorted(a.vars):
        if outer_for_distributed is not None and v in outer_for_distributed:
            diags.error("V003", loc, f"${v} is an outer-scope variable; Distributed Map child workflows cannot reference outer "
                        "variables (pass the value through Items/ItemSelector instead)")
            continue
        if v in in_vars:
            continue
        if v not in ever_assigned:
            if v in all_assigned:
                diags.error("V002", loc, f"${v} is assigned inside the Map/Parallel scope {all_assigned[v]}, which is not visible "
                            "here; variables die when that state completes - pass the value out through its Output instead")
                continue
            hint = f" (did you mean {FUNCTION_HINTS[v]}?)" if v in FUNCTION_HINTS else ""
            diags.error("V001", loc, f"${v} is never assigned anywhere in the state machine{hint}")
        else:
            diags.error("V002", loc, f"${v} is not assigned on every path that reaches this state (assigned later, in this "
                        "same state, inside a Map/Parallel scope, or only on some branches)")

    if jsonata is not None:
        try:
            jsonata(expr)
        except Exception as e:  # noqa: BLE001 - parser raises its own exception type
            diags.error("J006", loc, f"JSONata syntax error: {e}")


# ---------------------------------------------------------------------------
# Scope: one States object (top level, a Map ItemProcessor, or a Parallel branch)
# ---------------------------------------------------------------------------


class Scope:
    def __init__(self, *, states: dict, start_at: Any, location: str, top_lang: str, diags: Diagnostics, jsonata,
                 all_names: dict[str, str], all_assigned: dict[str, str], outer_assigned: set[str], distributed: bool) -> None:
        self.states = states
        self.start_at = start_at
        self.location = location
        self.top_lang = top_lang
        self.diags = diags
        self.jsonata = jsonata
        self.all_names = all_names
        self.all_assigned = all_assigned
        self.outer_assigned = outer_assigned
        self.distributed = distributed
        self.names = list(states.keys())
        self.edges: list[tuple[str, str, set[str], str]] = []  # from, to, gen, via
        self.preds: dict[str, list[tuple[str, str]]] = {n: [] for n in self.names}
        self.state_langs: dict[str, str] = {}
        self.children: list[tuple[str, "Scope"]] = []
        self.reachable: set[str] = set()
        self.scope_assigned: set[str] = set()

    # -- edges ---------------------------------------------------------------
    def target(self, frm: str, field: str, to: Any, gen: set[str], via: str) -> None:
        loc = f"{self.location}/{frm}/{field}"
        if not isinstance(to, str) or not to:
            self.diags.error("S002", loc, f"{field} must be a state name string")
            return
        if to not in self.names:
            elsewhere = ""
            if to in self.all_names:
                elsewhere = f' ("{to}" exists at {self.all_names[to]}, but transitions cannot cross Map/Parallel scope boundaries)'
            self.diags.error("S002", loc, f'{field} targets "{to}", which is not a state in this scope{elsewhere}')
            return
        self.edges.append((frm, to, gen, via))
        self.preds[to].append((frm, via))

    # -- structural pass ------------------------------------------------------
    def analyse(self) -> None:
        d = self.diags
        for name in self.names:
            loc = f"{self.location}/{name}"
            if len(name) > 80:
                d.error("S008", loc, "state name longer than 80 characters")
            if name in self.all_names:
                d.error("S007", loc, f'state name "{name}" already used at {self.all_names[name]}; names must be unique across the whole state machine')
            else:
                self.all_names[name] = loc
        if self.start_at is not None and self.start_at not in self.names:
            d.error("S001", f"{re.sub(r'/States$', '', self.location)}/StartAt", f'StartAt "{self.start_at}" is not a state in this scope')

        for st in self.states.values():
            if not isinstance(st, dict):
                continue
            self.scope_assigned |= assign_keys(st.get("Assign"))
            for r in st.get("Choices") or []:
                if isinstance(r, dict):
                    self.scope_assigned |= assign_keys(r.get("Assign"))
            for c in st.get("Catch") or []:
                if isinstance(c, dict):
                    self.scope_assigned |= assign_keys(c.get("Assign"))
        for v in sorted(self.scope_assigned):
            self.all_assigned.setdefault(v, self.location)
            if v in self.outer_assigned:
                d.error("V004", self.location, f'variable "{v}" is assigned both in this scope and in an enclosing scope; inner scopes cannot reuse outer variable names')

        for name in self.names:
            self.analyse_state(name)

        if self.start_at in self.names:
            stack = [self.start_at]
            while stack:
                n = stack.pop()
                if n in self.reachable:
                    continue
                self.reachable.add(n)
                for frm, to, _gen, _via in self.edges:
                    if frm == n and to not in self.reachable:
                        stack.append(to)
        for name in self.names:
            if name not in self.reachable:
                d.error("S003", f"{self.location}/{name}", f'state "{name}" is unreachable: nothing transitions to it (orphan)')

    def analyse_state(self, name: str) -> None:  # noqa: C901 - one long, flat checklist on purpose
        d = self.diags
        st = self.states[name]
        loc = f"{self.location}/{name}"
        if not isinstance(st, dict):
            d.error("S009", loc, "state must be a JSON object")
            return
        stype = st.get("Type")
        if stype not in STATE_TYPES:
            d.error("S009", f"{loc}/Type", f"unknown state Type {json.dumps(stype)}")
            return

        lang = st.get("QueryLanguage", self.top_lang)
        if "QueryLanguage" in st and st["QueryLanguage"] not in ("JSONPath", "JSONata"):
            d.error("S000", f"{loc}/QueryLanguage", 'QueryLanguage must be "JSONPath" or "JSONata"')
        if self.top_lang == "JSONata" and st.get("QueryLanguage") == "JSONPath":
            d.error("J000", f"{loc}/QueryLanguage", "a JSONata state machine cannot contain JSONPath states (the reverse is allowed)")
        self.state_langs[name] = lang
        is_jsonata = lang == "JSONata"
        spec = FIELDS[stype]
        allowed = set(COMMON_FIELDS) | set(spec["both"]) | set(spec["jsonata"] if is_jsonata else spec["jsonpath"])
        wrong_lang = set(spec["jsonpath"] if is_jsonata else spec["jsonata"])

        for k in st:
            if k in allowed:
                continue
            if k in wrong_lang:
                other = "JSONPath" if is_jsonata else "JSONata"
                d.error("J001", f"{loc}/{k}", f'field "{k}" is {other}-only but this state uses {lang}{JSONATA_REPLACEMENT.get(k, "") if is_jsonata else ""}')
            elif k == "Assign" and stype not in ASSIGN_ALLOWED:
                d.error("S009", f"{loc}/Assign", f"{stype} states do not support Assign")
            elif k in ("Retry", "Catch") and stype not in RETRY_CATCH_ALLOWED:
                d.error("S014", f"{loc}/{k}", f"{k} is only allowed on Task, Map and Parallel states")
            elif k == "Output" and stype == "Fail":
                d.error("S009", f"{loc}/Output", "Fail states do not support Output")
            elif k in ("Next", "End") and (stype == "Choice" or stype in TERMINAL_TYPES):
                extra = " (Next belongs inside each Choices rule, or in Default)" if stype == "Choice" else ""
                d.error("S004", f"{loc}/{k}", f"{stype} states must not have {k}{extra}")
            else:
                d.error("S009", f"{loc}/{k}", f'unknown field "{k}" for a {stype} state{suggest_field(k, allowed)}')

        if is_jsonata:
            def dollar_keys(key_path: str, key: str, _v: Any) -> None:
                if key.endswith(".$"):
                    d.error("J002", f"{loc}/{key_path}", f'key "{key}" uses the JSONPath ".$" convention; in JSONata drop ".$" and write the value as "{{% ... %}}"')
            walk_keys(st, dollar_keys, ["ItemProcessor", "Iterator", "Branches"])

        has_next, has_end = "Next" in st, "End" in st
        if stype != "Choice" and stype not in TERMINAL_TYPES:
            if has_next and has_end:
                d.error("S005", loc, "state has both Next and End; use exactly one")
            if not has_next and not has_end:
                d.error("S004", loc, f'{stype} state needs either "Next" or "End": true')
            if has_end and st["End"] is not True:
                d.error("S004", f"{loc}/End", "End must be the boolean true")
            if has_next:
                self.target(name, "Next", st["Next"], assign_keys(st.get("Assign")), "Next")

        if stype == "Choice":
            choices = st.get("Choices")
            if not isinstance(choices, list) or not choices:
                d.error("S006", f"{loc}/Choices", "Choice needs a non-empty Choices array")
            else:
                for i, rule in enumerate(choices):
                    rloc = f"{loc}/Choices/{i}"
                    if not isinstance(rule, dict):
                        d.error("S006", rloc, "rule must be an object")
                        continue
                    rule_allowed = CHOICE_RULE_FIELDS["jsonata" if is_jsonata else "jsonpath"]
                    rule_other = CHOICE_RULE_FIELDS["jsonpath" if is_jsonata else "jsonata"]
                    for k in rule:
                        if k in rule_allowed:
                            continue
                        if k in rule_other:
                            fix = 'use "Condition": "{% ... %}"' if is_jsonata else "use Variable + a comparison operator"
                            d.error("J001", f"{rloc}/{k}", f'rule field "{k}" is {"JSONPath" if is_jsonata else "JSONata"}-only; {fix}')
                        else:
                            d.error("S006", f"{rloc}/{k}", f'unknown Choice rule field "{k}"')
                    if "Next" not in rule:
                        d.error("S006", rloc, "Choice rule is missing Next")
                    else:
                        self.target(name, f"Choices/{i}/Next", rule["Next"], assign_keys(rule.get("Assign")), "Choice")
                    if is_jsonata:
                        if "Condition" not in rule:
                            d.error("S006", rloc, 'JSONata Choice rule needs "Condition": "{% <boolean expression> %}"')
                        elif not is_expression(rule["Condition"]):
                            d.error("J012", f"{rloc}/Condition", 'Condition must be a JSONata expression string "{% ... %}" that evaluates to true or false')
                    elif "Variable" not in rule and not any(k in rule for k in ("And", "Or", "Not")):
                        d.error("S006", rloc, "JSONPath Choice rule needs Variable + comparison, or And/Or/Not")
            if "Default" not in st:
                d.warn("S006", loc, "Choice has no Default; if no rule matches the execution fails with States.NoChoiceMatched")
            else:
                self.target(name, "Default", st["Default"], assign_keys(st.get("Assign")), "Default")

        if stype == "Wait":
            present = [f for f in ("Seconds", "Timestamp", "SecondsPath", "TimestampPath") if f in st]
            if len(present) != 1:
                opts = "Seconds, Timestamp" + ("" if is_jsonata else ", SecondsPath, TimestampPath")
                d.error("S010", loc, f"Wait needs exactly one of {opts} (found: {', '.join(present) or 'none'})")
            if "Seconds" in st and not is_expression(st["Seconds"]) and not (is_int(st["Seconds"]) and st["Seconds"] >= 0):
                d.error("S010", f"{loc}/Seconds", 'Seconds must be a non-negative integer or a "{% %}" expression evaluating to one')
            if "Timestamp" in st and not is_expression(st["Timestamp"]) and not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$", str(st["Timestamp"])):
                d.error("S010", f"{loc}/Timestamp", 'Timestamp must be RFC3339 with uppercase T and Z (e.g. 2025-01-31T10:00:00Z) or a "{% %}" expression producing one')

        if stype == "Fail":
            if "Error" in st and "ErrorPath" in st:
                d.error("S011", loc, "Fail cannot have both Error and ErrorPath")
            if "Cause" in st and "CausePath" in st:
                d.error("S011", loc, "Fail cannot have both Cause and CausePath")

        if stype == "Task":
            res = st.get("Resource")
            if not isinstance(res, str) or not res:
                d.error("S015", f"{loc}/Resource", "Task needs a constant string Resource")
            else:
                if is_expression(res):
                    d.error("S015", f"{loc}/Resource", "Resource must be a constant string, not a JSONata expression")
                if res == "arn:aws:states:::lambda:invoke" and is_jsonata:
                    args = st.get("Arguments")
                    if not isinstance(args, dict) or "FunctionName" not in args:
                        d.error("S015", f"{loc}/Arguments", "lambda:invoke needs Arguments.FunctionName (and usually Arguments.Payload)")
                    out_str = json.dumps(st.get("Output", "")) + json.dumps(st.get("Assign", ""))
                    if "Output" not in st and "$states.result.Payload" not in out_str:
                        d.info("P001", loc, 'lambda:invoke returns {ExecutedVersion, Payload, StatusCode}; most workflows want "Output": "{% $states.result.Payload %}"')
                if res.endswith(".waitForTaskToken"):
                    s = json.dumps(st.get("Arguments", st.get("Parameters", {})))
                    if "Task.Token" not in s:
                        d.error("S015", loc, '.waitForTaskToken tasks must pass the token: "{% $states.context.Task.Token %}" (JSONata) or "$$.Task.Token" (JSONPath) inside Arguments/Parameters')
                    if "HeartbeatSeconds" not in st and "TimeoutSeconds" not in st:
                        d.warn("P002", loc, ".waitForTaskToken without HeartbeatSeconds or TimeoutSeconds can wait up to one year")
            ts = st.get("TimeoutSeconds")
            if ts is not None and not is_expression(ts) and not (is_int(ts) and ts > 0):
                d.error("S015", f"{loc}/TimeoutSeconds", 'TimeoutSeconds must be a positive integer or a "{% %}" expression')
            hb = st.get("HeartbeatSeconds")
            if is_int(hb) and is_int(ts) and hb >= ts:
                d.error("S015", f"{loc}/HeartbeatSeconds", "HeartbeatSeconds must be smaller than TimeoutSeconds")

        retry = st.get("Retry")
        if isinstance(retry, list):
            for i, r in enumerate(retry):
                rloc = f"{loc}/Retry/{i}"
                if not isinstance(r, dict):
                    d.error("S012", rloc, "retrier must be an object")
                    continue
                for k in r:
                    if k not in RETRY_FIELDS:
                        d.error("S012", f"{rloc}/{k}", f'unknown Retry field "{k}"')
                check_error_equals(r.get("ErrorEquals"), rloc, i == len(retry) - 1, d)
                if "MaxAttempts" in r and not (is_int(r["MaxAttempts"]) and r["MaxAttempts"] >= 0):
                    d.error("S012", f"{rloc}/MaxAttempts", "MaxAttempts must be a non-negative integer")
                if "IntervalSeconds" in r and not (is_int(r["IntervalSeconds"]) and r["IntervalSeconds"] > 0):
                    d.error("S012", f"{rloc}/IntervalSeconds", "IntervalSeconds must be a positive integer")
                br = r.get("BackoffRate")
                if br is not None and not (isinstance(br, (int, float)) and not isinstance(br, bool) and br >= 1):
                    d.error("S012", f"{rloc}/BackoffRate", "BackoffRate must be a number >= 1.0")
                if "JitterStrategy" in r and r["JitterStrategy"] not in ("FULL", "NONE"):
                    d.error("S012", f"{rloc}/JitterStrategy", 'JitterStrategy must be "FULL" or "NONE"')
        elif retry is not None:
            d.error("S012", f"{loc}/Retry", "Retry must be an array")

        catch = st.get("Catch")
        if isinstance(catch, list):
            for i, c in enumerate(catch):
                cloc = f"{loc}/Catch/{i}"
                if not isinstance(c, dict):
                    d.error("S012", cloc, "catcher must be an object")
                    continue
                allowed_c = set(CATCH_FIELDS["both"]) | set(CATCH_FIELDS["jsonata" if is_jsonata else "jsonpath"])
                for k in c:
                    if k in allowed_c:
                        continue
                    if k == "ResultPath" and is_jsonata:
                        d.error("J001", f"{cloc}/ResultPath", 'Catch.ResultPath is JSONPath-only; in JSONata use "Output": {...} with $states.errorOutput and/or $states.input')
                    elif k == "Output" and not is_jsonata:
                        d.error("J001", f"{cloc}/Output", "Catch.Output is JSONata-only; in JSONPath use ResultPath")
                    else:
                        d.error("S012", f"{cloc}/{k}", f'unknown Catch field "{k}"')
                check_error_equals(c.get("ErrorEquals"), cloc, i == len(catch) - 1, d)
                if "Next" not in c:
                    d.error("S012", cloc, "Catch needs Next")
                else:
                    self.target(name, f"Catch/{i}/Next", c["Next"], assign_keys(c.get("Assign")), "Catch")
        elif catch is not None:
            d.error("S012", f"{loc}/Catch", "Catch must be an array")

        child_outer = self.outer_assigned | self.scope_assigned

        if stype == "Map":
            proc = st.get("ItemProcessor", st.get("Iterator"))
            if "Iterator" in st:
                d.warn("S013", f"{loc}/Iterator", "Iterator is deprecated; use ItemProcessor")
            if "Iterator" in st and "ItemProcessor" in st:
                d.error("S013", loc, "Map has both Iterator and ItemProcessor")
            if not isinstance(proc, dict):
                d.error("S013", loc, "Map needs an ItemProcessor with StartAt and States")
            else:
                cfg = proc.get("ProcessorConfig") or {}
                mode = cfg.get("Mode", "INLINE") if isinstance(cfg, dict) else "INLINE"
                if mode not in ("INLINE", "DISTRIBUTED"):
                    d.error("S013", f"{loc}/ItemProcessor/ProcessorConfig/Mode", "Mode must be INLINE or DISTRIBUTED")
                if mode == "DISTRIBUTED" and (not isinstance(cfg, dict) or cfg.get("ExecutionType") not in ("STANDARD", "EXPRESS")):
                    d.error("S013", f"{loc}/ItemProcessor/ProcessorConfig", 'DISTRIBUTED mode requires ExecutionType "STANDARD" or "EXPRESS"')
                if mode == "INLINE" and any(f in st for f in ("ItemReader", "ResultWriter", "ItemBatcher", "ToleratedFailureCount", "ToleratedFailurePercentage", "Label")):
                    d.error("S013", loc, 'ItemReader, ResultWriter, ItemBatcher, ToleratedFailure* and Label are only valid with ProcessorConfig.Mode "DISTRIBUTED"')
                if is_jsonata and "Items" not in st and "ItemReader" not in st:
                    d.warn("S013", loc, 'JSONata Map without Items iterates the whole state input; set "Items": "{% $states.input.<array> %}" unless the input itself is the array')
                items = st.get("Items")
                if is_jsonata and "Items" in st and not is_expression(items) and not isinstance(items, (list, dict)):
                    d.error("S013", f"{loc}/Items", 'Items must be a JSON array/object or a "{% %}" expression evaluating to one')
                mc = st.get("MaxConcurrency")
                if mc is not None and not is_expression(mc) and not (is_int(mc) and mc >= 0):
                    d.error("S013", f"{loc}/MaxConcurrency", 'MaxConcurrency must be a non-negative integer or a "{% %}" expression')
                for k in ("ItemReader", "ResultWriter"):
                    v = st.get(k)
                    if isinstance(v, dict):
                        if is_jsonata and "Parameters" in v:
                            d.error("J001", f"{loc}/{k}/Parameters", f'{k}.Parameters is JSONPath-only; use "Arguments" in JSONata')
                        if not is_jsonata and "Arguments" in v:
                            d.error("J001", f"{loc}/{k}/Arguments", f'{k}.Arguments is JSONata-only; use "Parameters" in JSONPath')
                if not proc.get("StartAt"):
                    d.error("S013", f"{loc}/ItemProcessor/StartAt", "ItemProcessor needs StartAt")
                if isinstance(proc.get("States"), dict):
                    child = Scope(states=proc["States"], start_at=proc.get("StartAt"),
                                  location=f"{loc}/{'ItemProcessor' if 'ItemProcessor' in st else 'Iterator'}/States",
                                  top_lang=self.top_lang, diags=d, jsonata=self.jsonata, all_names=self.all_names,
                                  all_assigned=self.all_assigned, outer_assigned=child_outer, distributed=mode == "DISTRIBUTED")
                    child.analyse()
                    self.children.append((name, child))
                else:
                    d.error("S013", f"{loc}/ItemProcessor/States", "ItemProcessor needs a States object")

        if stype == "Parallel":
            branches = st.get("Branches")
            if not isinstance(branches, list) or not branches:
                d.error("S013", f"{loc}/Branches", "Parallel needs a non-empty Branches array")
            else:
                for i, b in enumerate(branches):
                    bloc = f"{loc}/Branches/{i}"
                    if not isinstance(b, dict) or not isinstance(b.get("States"), dict):
                        d.error("S013", bloc, "branch needs StartAt and States")
                        continue
                    if not b.get("StartAt"):
                        d.error("S013", f"{bloc}/StartAt", "branch needs StartAt")
                    child = Scope(states=b["States"], start_at=b.get("StartAt"), location=f"{bloc}/States", top_lang=self.top_lang,
                                  diags=d, jsonata=self.jsonata, all_names=self.all_names, all_assigned=self.all_assigned,
                                  outer_assigned=child_outer, distributed=False)
                    child.analyse()
                    self.children.append((name, child))

    # -- definite assignment dataflow ---------------------------------------
    def dataflow(self, entry: set[str]) -> dict[str, Optional[set[str]]]:
        """IN[s] = intersection over incoming edges of (IN[pred] | gen(edge)). None = not yet reached."""
        IN: dict[str, Optional[set[str]]] = {n: None for n in self.names}
        if self.start_at in self.names:
            IN[self.start_at] = set(entry)
        changed, guard = True, 0
        while changed and guard < 10000:
            changed = False
            guard += 1
            for n in self.names:
                if n == self.start_at:
                    continue
                acc: Optional[set[str]] = None
                for frm, to, gen, _via in self.edges:
                    if to != n or IN[frm] is None:
                        continue
                    out = IN[frm] | gen  # type: ignore[operator]
                    acc = out if acc is None else (acc & out)
                if acc is None:
                    continue
                if IN[n] != acc:
                    IN[n] = acc
                    changed = True
        return IN

    def finish(self, entry: set[str], outer_for_distributed: Optional[set[str]]) -> None:
        d = self.diags
        IN = self.dataflow(entry)
        ever_assigned = self.outer_assigned | self.scope_assigned | entry

        for name in self.names:
            if name not in self.reachable:
                continue
            st = self.states[name]
            if not isinstance(st, dict) or st.get("Type") not in STATE_TYPES:
                continue
            loc = f"{self.location}/{name}"
            lang = self.state_langs.get(name)
            in_vars = IN.get(name) or set(entry)

            if lang == "JSONata":
                for field_path, expr, result_ok, error_ok in collect_expressions(st):
                    check_expression(expr, f"{loc}/{field_path}", result_ok=result_ok, error_ok=error_ok, in_vars=in_vars,
                                     ever_assigned=ever_assigned, all_assigned=self.all_assigned,
                                     outer_for_distributed=outer_for_distributed if self.distributed else None,
                                     diags=d, jsonata=self.jsonata)
                for f in ("Seconds", "TimeoutSeconds", "HeartbeatSeconds", "MaxConcurrency"):
                    if isinstance(st.get(f), str) and not is_expression(st[f]):
                        d.error("J003", f"{loc}/{f}", f'{f} is a plain string; use a number or a "{{% %}}" expression')
            else:
                def jp(key_path: str, key: str, value: Any) -> None:
                    if key.endswith(".$") and isinstance(value, str) and not re.match(r"^\$|^States\.", value):
                        d.error("P010", f"{loc}/{key_path}", f'"{key}" must be a JSONPath ("$.x", "$$.x", "$var") or an intrinsic ("States.Format(...)")')
                    if isinstance(value, str) and EXPR_RE.match(value):
                        d.error("J001", f"{loc}/{key_path}", 'JSONata "{% %}" expression inside a JSONPath state; set "QueryLanguage": "JSONata" on this state or the state machine')
                walk_keys(st, jp, ["ItemProcessor", "Iterator", "Branches"])

            if st.get("Type") == "Pass" and st.get("Assign") and "Output" not in st and name != self.start_at:
                ps = self.preds.get(name, [])
                if len(ps) == 1 and ps[0][1] == "Next" and (self.states.get(ps[0][0]) or {}).get("Type") in ASSIGN_ALLOWED:
                    d.warn("V005", loc, f'Pass state only assigns variables; fold its Assign into the previous state "{ps[0][0]}" '
                           "(Assign runs after that state's result is known) and delete this Pass")
                elif len(ps) == 1 and ps[0][1] == "Choice":
                    d.warn("V005", loc, f'Pass state only assigns variables after a Choice; put the Assign inside the matching Choices rule of "{ps[0][0]}" instead')

        for parent_name, child in self.children:
            parent_in = IN.get(parent_name) or set(entry)
            if child.distributed:
                child.finish(set(), parent_in | self.outer_assigned | self.scope_assigned)
            else:
                child.finish(parent_in, None)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def lint_definition(definition: dict, diags: Diagnostics, jsonata=None) -> None:
    top_lang = definition.get("QueryLanguage", "JSONPath")
    if top_lang not in ("JSONPath", "JSONata"):
        diags.error("S000", "/QueryLanguage", f'QueryLanguage must be "JSONPath" or "JSONata", got {json.dumps(top_lang)}')
    for k in definition:
        if k not in ("Comment", "StartAt", "States", "Version", "TimeoutSeconds", "QueryLanguage"):
            diags.error("S000", f"/{k}", f'unknown top-level field "{k}"')
    ts = definition.get("TimeoutSeconds")
    if ts is not None and not (is_int(ts) and ts > 0):
        diags.error("S000", "/TimeoutSeconds", "top-level TimeoutSeconds must be a positive integer")
    states = definition.get("States")
    if not isinstance(states, dict):
        diags.error("S001", "/States", "missing States object")
        return
    if not definition.get("StartAt"):
        diags.error("S001", "/StartAt", "missing StartAt")
    if top_lang == "JSONPath" and not any(isinstance(s, dict) and s.get("QueryLanguage") == "JSONata" for s in states.values()):
        diags.info("J000", "/QueryLanguage", 'state machine uses JSONPath; new state machines should set "QueryLanguage": "JSONata" at the top level')

    scope = Scope(states=states, start_at=definition.get("StartAt"), location="/States", top_lang=top_lang, diags=diags,
                  jsonata=jsonata, all_names={}, all_assigned={}, outer_assigned=set(), distributed=False)
    scope.analyse()
    scope.finish(set(), None)


def lint_text(text: str, jsonata=None) -> tuple[Diagnostics, int]:
    diags = Diagnostics()
    defs = extract_definitions(text)
    if not defs:
        diags.error("S000", "/", "no state machine definition found (file is not JSON and no embedded object with StartAt + States could be parsed)")
    for i, (definition, note) in enumerate(defs):
        if note and i == 0:
            diags.info("S000", "/", note)
        lint_definition(definition, diags, jsonata)
    return diags, len(defs)


def main(argv: list[str]) -> int:
    args = argv[1:]
    as_json = "--json" in args
    files = [a for a in args if not a.startswith("--")]
    if not files:
        print("usage: python3 lint_asl.py [--json] <definition.json|file-with-embedded-definition|->", file=sys.stderr)
        return 2
    jsonata = load_jsonata()
    exit_code = 0
    report = []
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    for f in files:
        text = sys.stdin.read() if f == "-" else open(f, encoding="utf-8").read()
        diags, count = lint_text(text, jsonata)
        report.append({"file": f, "diagnostics": diags.items})
        if diags.errors:
            exit_code = 1
        if not as_json:
            items = sorted(diags.items, key=lambda x: (order[x["severity"]], x["location"]))
            print(f"== {f}{f' ({count} definitions)' if count > 1 else ''}")
            for it in items:
                print(f"{it['severity']:<7} {it['code']} {it['location']}: {it['message']}")
            note = "" if jsonata else " [jsonata-python not installed: expression syntax not parsed; pip install jsonata-python]"
            print(f"-- {diags.errors} error(s), {diags.warnings} warning(s){note}")
    if as_json:
        print(json.dumps({"jsonataParser": jsonata is not None, "files": report}, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
