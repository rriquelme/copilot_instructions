#!/usr/bin/env python3
"""lint_asl.py - static checks for AWS Step Functions state machine definitions
(Amazon States Language, JSONata and JSONPath query languages).

Usage:
    python3 lint_asl.py <file> [<file>...]   JSON, .asl.json, or any text file that embeds a JSON
                                             definition (Terraform templatefile/heredoc,
                                             CloudFormation JSON, YAML DefinitionString, ...);
                                             "*.json" globs are expanded (PowerShell does not)
    python3 lint_asl.py -                    read a definition from stdin
    python3 lint_asl.py --json <file>        machine-readable diagnostics
    python3 lint_asl.py --type EXPRESS <file>  also enforce Express workflow limits (no .sync,
                                             no .waitForTaskToken, no Distributed Map, no
                                             activities, <= 300 s); default --type STANDARD
    python3 lint_asl.py --format text|json|github|sarif <file>   output format (--json = --format json)
    python3 lint_asl.py --strict <file>      exit 1 on WARNING too;  --quiet hides INFO
    python3 lint_asl.py --list-codes         every diagnostic code;  --explain S017: how to fix one
    --show-suppressed                        list diagnostics silenced by "lint-allow <CODE>: <reason>"
                                             in a state's Comment

Text output: <file>:<line>: SEVERITY CODE <location>: <message>, in document order.
Exit code 0 clean, 1 when any ERROR is reported (or WARNING with --strict), 2 when nothing could be
linted (no definition found, invalid JSON, unreadable file) or on a usage error, 3 on a linter
internal error. Standard library only (Python 3.9+).
If the optional `jsonata-python` package is installed (pip install jsonata-python) every
{% %} expression is also parsed for syntax.
"""
from __future__ import annotations

import argparse
import bisect
import functools
import glob
import json
import os
import re
import stat
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
    "coalesce": "$exists(a) ? a : b",
    "default": "$exists(a) ? a : b",
    "ifNull": "$exists(a) ? a : b",
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

# Argument counts: name -> (min, max, context_able, usage example); max None = variadic. From the JSONata 2.0
# signatures (docs.jsonata.org) plus the AWS Step Functions extras. context_able marks a "-" first parameter
# (e.g. <s-:n>): JSONata then accepts one fewer argument and uses the context value instead (name.$uppercase()).
# Conservative choice: the one-fewer form is accepted only when the call is a path step - directly preceded by
# "." , inside a [...] predicate, or inside a .( ... ) block - so a bare $substring(x) is still flagged.
JSONATA_ARITY = {
    "string": (1, 2, True, "$string(value)"), "length": (1, 1, True, "$length(str)"),
    "substring": (2, 3, True, "$substring(str, start, length)"),
    "substringBefore": (2, 2, True, "$substringBefore(str, chars)"),
    "substringAfter": (2, 2, True, "$substringAfter(str, chars)"),
    "uppercase": (1, 1, True, "$uppercase(str)"), "lowercase": (1, 1, True, "$lowercase(str)"),
    "trim": (1, 1, True, "$trim(str)"), "pad": (2, 3, True, "$pad(str, width, char)"),
    "contains": (2, 2, True, "$contains(str, pattern)"), "split": (2, 3, True, "$split(str, separator, limit)"),
    "join": (1, 2, False, "$join(array, separator)"), "match": (2, 3, True, "$match(str, /regex/, limit)"),
    "replace": (3, 4, True, "$replace(str, pattern, replacement)"),
    "base64encode": (1, 1, True, "$base64encode(str)"), "base64decode": (1, 1, True, "$base64decode(str)"),
    "encodeUrlComponent": (1, 1, True, "$encodeUrlComponent(str)"), "encodeUrl": (1, 1, True, "$encodeUrl(str)"),
    "decodeUrlComponent": (1, 1, True, "$decodeUrlComponent(str)"), "decodeUrl": (1, 1, True, "$decodeUrl(str)"),
    "number": (1, 1, True, "$number(x)"), "abs": (1, 1, True, "$abs(n)"), "floor": (1, 1, True, "$floor(n)"),
    "ceil": (1, 1, True, "$ceil(n)"), "round": (1, 2, True, "$round(n, precision)"),
    "power": (2, 2, True, "$power(base, exponent)"), "sqrt": (1, 1, True, "$sqrt(n)"),
    "random": (0, 1, False, "$random() or $random(seed)"),
    "formatNumber": (2, 3, True, "$formatNumber(n, '#,##0.00')"), "formatBase": (1, 2, True, "$formatBase(n, 16)"),
    "formatInteger": (2, 2, True, "$formatInteger(n, 'w')"), "parseInteger": (2, 2, True, "$parseInteger(str, 'w')"),
    "sum": (1, 1, False, "$sum(array)"), "max": (1, 1, False, "$max(array)"), "min": (1, 1, False, "$min(array)"),
    "average": (1, 1, False, "$average(array)"),
    "boolean": (1, 1, True, "$boolean(x)"), "not": (1, 1, True, "$not(x)"), "exists": (1, 1, False, "$exists(x)"),
    "count": (1, 1, False, "$count(array)"), "append": (2, 2, False, "$append(array1, array2)"),
    "sort": (1, 2, False, "$sort(array, function($l, $r) { $l > $r })"), "reverse": (1, 1, False, "$reverse(array)"),
    "shuffle": (1, 1, False, "$shuffle(array)"), "distinct": (1, 1, False, "$distinct(array)"),
    "zip": (1, None, False, "$zip(array1, array2)"),
    "keys": (1, 1, True, "$keys(obj)"), "lookup": (2, 2, True, "$lookup(obj, 'key')"), "spread": (1, 1, True, "$spread(obj)"),
    "merge": (1, 1, False, "$merge([obj1, obj2])"), "sift": (1, 2, True, "$sift(obj, function($v, $k) { ... })"),
    "each": (1, 2, True, "$each(obj, function($v, $k) { ... })"), "error": (0, 1, False, "$error('message')"),
    "assert": (1, 2, False, "$assert(condition, 'message')"), "type": (1, 1, False, "$type(x)"),
    "now": (0, 2, False, "$now() or $now(picture, timezone)"), "millis": (0, 0, False, "$millis()"),
    "fromMillis": (1, 3, True, "$fromMillis(ms) or $fromMillis(ms, picture, timezone)"),
    "toMillis": (1, 2, True, "$toMillis(timestamp) or $toMillis(timestamp, picture)"),
    "map": (2, 2, False, "$map(array, function($v) { ... })"), "filter": (2, 2, False, "$filter(array, function($v) { ... })"),
    "single": (1, 2, False, "$single(array, function($v) { ... })"),
    "reduce": (2, 3, False, "$reduce(array, function($acc, $v) { ... }, init)"),
    "partition": (2, 2, False, "$partition(array, chunkSize)"), "range": (3, 3, False, "$range(start, end, step)"),
    "hash": (2, 2, False, "$hash(str, 'SHA-256')"), "uuid": (0, 0, False, "$uuid()"), "parse": (1, 1, False, "$parse(jsonString)"),
}

ERROR_NAMES = {"States.ALL", "States.DataLimitExceeded", "States.ExceedToleratedFailureThreshold",
               "States.HeartbeatTimeout", "States.Http.Socket", "States.ItemReaderFailed", "States.Permissions",
               "States.ResultWriterFailed", "States.Runtime", "States.TaskFailed", "States.Timeout", "States.QueryEvaluationError",
               "States.BranchFailed", "States.NoChoiceMatched", "States.IntrinsicFailure", "States.ParameterPathFailure",
               "States.ResultPathMatchFailure"}
ERROR_NAME_PATTERNS = (re.compile(r"^States\.Http\.StatusCode\.\d{3}$"),)  # HTTP Task: States.Http.StatusCode.429 etc.

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
# Per-state-type overrides: the replacement must be a field the JSONata version of that state type allows.
JSONATA_REPLACEMENT_BY_TYPE = {
    ("Parameters", "Map"): ' - use "ItemSelector" to shape each item, e.g. "ItemSelector": {"value": '
                           '"{% $states.context.Map.Item.Value %}", "index": "{% $states.context.Map.Item.Index %}"}',
    ("Parameters", "Pass"): ' - use "Output" (e.g. "Output": {"id": "{% $states.input.id %}"})',
    ("ResultPath", "Pass"): ' - use "Output" (e.g. "{% $merge([$states.input, {\'extra\': <value>}]) %}") or store the value '
                            'with "Assign"',
}


def jsonata_replacement(field: str, stype: str) -> str:
    return JSONATA_REPLACEMENT_BY_TYPE.get((field, stype), JSONATA_REPLACEMENT.get(field, ""))

# Task Resource shapes (S019). Template placeholders are normalised to "__TPL__" before matching.
ARN_PARTITIONS = ("aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f", "aws-eusc")


class _ResourcePlaceholderPattern:
    """RESOURCE_PLACEHOLDER_RE.sub(repl, s): same result as the regex below (leftmost, non-overlapping matches), in
    linear time - the regex rescans to the next "}" from every "${" / "#{" / "{{" (O(n^2) on "{{" * 50000). Results
    are cached, so the several checks of one Resource scan it once. Other attributes delegate to the real regex."""
    regex = re.compile(r"\$\{[^}]*\}|#\{[^}]*\}|\{\{[^}]*\}\}|<[^<>]*>|__TPL__")
    _start = re.compile(r"[$#{<_]")
    _angle = re.compile(r"[<>]")

    def __getattr__(self, name: str) -> Any:
        return getattr(self.regex, name)

    def spans(self, s: str) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        close = angle = -2  # cached "next } / next < or >" at or after the scan position (-1: none left)
        i, n = 0, len(s)
        while True:
            m = self._start.search(s, i)
            if not m:
                return out
            i = m.start()
            end = -1
            if s.startswith(("${", "#{", "{{"), i):
                if close != -1 and close < i + 2:
                    close = s.find("}", i + 2)
                if close >= 0 and (s[i] != "{" or s.startswith("}", close + 1)):
                    end = close + (2 if s[i] == "{" else 1)
            elif s[i] == "<":
                if angle != -1 and angle < i + 1:
                    am = self._angle.search(s, i + 1)
                    angle = am.start() if am else -1
                if angle >= 0 and s[angle] == ">":
                    end = angle + 1
            elif s.startswith("__TPL__", i):
                end = i + 7
            if end < 0:
                i += 1
            else:
                out.append((i, end))
                i = end

    @functools.lru_cache(maxsize=256)
    def _sub(self, repl: str, s: str) -> str:
        parts, last = [], 0
        for a, b in self.spans(s):
            parts += [s[last:a], repl]
            last = b
        return "".join(parts) + s[last:]

    def sub(self, repl: Any, string: str, count: int = 0) -> str:
        if not isinstance(repl, str) or count or "\\" in repl:
            return self.regex.sub(repl, string, count)
        return self._sub(repl, string)


RESOURCE_PLACEHOLDER_RE = _ResourcePlaceholderPattern()
RESOURCE_INTEGRATION_RE = re.compile(r"^arn:([^:]+):states:::([^:]+):(.+)$")
RESOURCE_LAMBDA_RE = re.compile(r"^arn:([^:]+):lambda:[^:]+:[^:]+:function:[^:]+(:[^:]+)?$")
RESOURCE_ACTIVITY_RE = re.compile(r"^arn:([^:]+):states:[^:]+:[^:]+:activity:[^:]+$")
RESOURCE_SUFFIXES = (".sync:2", ".sync", ".waitForTaskToken")
# Optimized integrations -> suffixes they support besides request-response ("Integrating optimized
# services" support table). Services/actions not listed are not suffix-checked; aws-sdk:* never allows .sync.
INTEGRATION_SUFFIXES: dict[str, set[str]] = {
    "lambda:invoke": {".waitForTaskToken"},
    "sqs:sendMessage": {".waitForTaskToken"},
    "sns:publish": {".waitForTaskToken"},
    "events:putEvents": {".waitForTaskToken"},
    "apigateway:invoke": {".waitForTaskToken"},
    "http:invoke": set(),
    "dynamodb:*": set(),
    "ecs:*": {".sync", ".waitForTaskToken"},
    "eks:*": {".sync", ".waitForTaskToken"},
    "bedrock:*": {".sync", ".waitForTaskToken"},
    "glue:*": {".sync"},
    "batch:*": {".sync"},
    "codebuild:*": {".sync"},
    "athena:*": {".sync"},
    "elasticmapreduce:*": {".sync"},
    "emr-containers:*": {".sync"},
    "emr-serverless:*": {".sync"},
    "databrew:*": {".sync"},
    "mediaconvert:*": {".sync"},
    "sagemaker:*": {".sync"},
    "states:startExecution": {".sync", ".sync:2", ".waitForTaskToken"},
}
STATES_INPUT_PATH_RE = re.compile(r"\$states\s*\.\s*input((?:\s*\.\s*[A-Za-z_]\w*)+)")
JSONPATH_DOT_PATH_RE = re.compile(r"^\$\.([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$")
PAGINATION_RE = re.compile(r"token|marker|cursor|next_?page|last_?evaluated_?key|exclusive_?start_?key|has_?more|is_?truncated",
                           re.IGNORECASE)
LAMBDA_TRANSIENT_ERRORS = {"Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException",
                           "Lambda.TooManyRequestsException", "Lambda.ClientExecutionTimeoutException",
                           "States.ALL", "States.TaskFailed"}
LAMBDA_RETRY_SNIPPET = ('{"ErrorEquals": ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", '
                        '"Lambda.TooManyRequestsException"], "IntervalSeconds": 1, "MaxAttempts": 3, "BackoffRate": 2, '
                        '"JitterStrategy": "FULL"}')

# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


class Diagnostics:
    def __init__(self) -> None:
        self.items: list[dict[str, str]] = []

        self.suppressed: list[dict] = []  # items silenced by a "lint-allow <CODE>: <reason>" state Comment
        self.positions: dict[int, int] = {}  # id(item) -> offset of its location in the source (document order)

    def add(self, severity: str, code: str, location: str, message: str) -> None:
        self.items.append({"severity": severity, "code": code, "location": location, "message": message, "line": None})

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
IDENT = r"[A-Za-z_ªµºÀ-￿𐀀-􏿿][\w·À-￿𐀀-􏿿]*"  # ª µ º: Latin-1 ID_Start letters below À; · (U+00B7) is ID_Continue; plus characters beyond the BMP
CALL_RE = re.compile(r"\$(" + IDENT + r")\s*\(")
VAR_RE = re.compile(r"\$(" + IDENT + r")(?![\wÀ-￿])(?!\s*\()")
BIND_RE = re.compile(r"\$(" + IDENT + r")\s*:=")
FUNC_PARAMS_RE = re.compile(r"(?:function|λ)\s*\(")  # the parameter list runs to the next ")" (see func_params)
POS_BIND_RE = re.compile(r"[@#]\s*\$(" + IDENT + r")")  # items@$item, items#$index
DOLLAR_DOT_RE = re.compile(r"(^|[^\w$.])\$\.(?=[A-Za-z_`])")
STEP_CALL_RE = re.compile(r"\.\s*\$" + IDENT + r"\s*$")
VALUE_END = set("_`)]}\"'$%*")  # plus letters/digits: a "[" or "{" after these is a predicate / group-by, not a constructor


def is_expression(s: Any) -> bool:
    return isinstance(s, str) and EXPR_RE.match(s) is not None


def strip_literals(src: str) -> str:
    """Blank out comments, string literals and regex literals (length preserved)."""
    out: list[str] = []
    prev = ""  # last non-whitespace character written to out (comments are blanked to spaces)
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
            prev = c
            i = j + 1
            continue
        if c == "`":
            j = src.find("`", i + 1)
            stop = n if j == -1 else j
            out.append("`" + " " * max(0, stop - i - 1) + "`")
            prev = "`"
            i = stop + 1
            continue
        if c == "/":
            # A regex can only start where an operand is expected; after a value (name, number, ")", "]", "}",
            # a string, a backtick name, or the * and % wildcard/parent values) "/" is division: $a / $b, x/2, ($a)/2.
            if prev == "" or prev in "(,=~&|?:[;{!<>+-":
                j, in_class = i + 1, False
                while j < n and src[j] != "\n" and (in_class or src[j] != "/"):
                    if src[j] == "\\":
                        j += 1
                    elif src[j] == "[":
                        in_class = True
                    elif src[j] == "]":
                        in_class = False
                    j += 1
                if j < n and src[j] == "/":
                    k = j + 1
                    while k < n and src[k] in "im":
                        k += 1
                    out.append("/" + " " * max(0, k - i - 2) + "/")
                    prev = "/"
                    i = k
                    continue
        out.append(c)
        if not c.isspace():
            prev = c
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
        self.func_refs: set[str] = set()  # built-in function names used without "(" ($map(xs, $string))
        self.intrinsic = False
        self.bad_ops: list[str] = []
        self.newer_ops: list[str] = []  # JSONata 2.1+ operators (?? and ?:) that Step Functions (2.0.6) predates
        self.arity: list[tuple[str, int, bool, bool]] = []  # (function, arg count, is a path step, follows ~>)


_ID_CHAR = re.compile(r"[\wÀ-￿]").match
_ID_START = re.compile(r"[A-Za-z_À-￿]").match


def ends_with_step_call(code: str, e: int) -> bool:
    """STEP_CALL_RE.search(code[:e]) for a code[:e] without trailing whitespace, scanning back from e only."""
    k = e
    while k > 0 and _ID_CHAR(code[k - 1]):
        k -= 1
    if k == e or k == 0 or not _ID_START(code[k]) or code[k - 1] != "$":
        return False
    k -= 1
    while k > 0 and code[k - 1].isspace():
        k -= 1
    return k > 0 and code[k - 1] == "."


def ends_with_signature(code: str, e: int) -> bool:
    """True if code[:e] (no trailing whitespace) ends with a lambda signature ") <...>"; scans back from e only."""
    if e == 0 or code[e - 1] != ">":
        return False
    k = e - 1
    while k > 0 and code[k - 1] not in "<>()":
        k -= 1
    if k == 0 or code[k - 1] != "<":
        return False
    k -= 1
    while k > 0 and code[k - 1].isspace():
        k -= 1
    return k > 0 and code[k - 1] == ")"


def root_dollar_dot(code: str) -> bool:
    """True if "$.name" appears where $ is still the root context (the JSONPath "$.field" habit).

    $ means the current context item inside a predicate x[...], a path step x.(...) / x.{...} / x.[...] /
    x.$f(...), an order-by x^(...), a group-by x{...}, a lambda body function(){...} and a transform |...|...|, so $.field is
    valid there. Function-call arguments, grouping/blocks ( ... ), array constructors [ ... ] and a top-level
    object constructor { ... } keep the outer context, so the habit is still reported inside them."""
    hits = {m.start() + len(m.group(1)) for m in DOLLAR_DOT_RE.finditer(code)}
    if not hits:
        return False
    stack: list[list] = [[False, 0]]  # [opaque, pipe count] per bracket level
    end = 0  # code[:end] == code[:i].rstrip(), kept up to date instead of re-stripping the prefix per bracket
    for i, ch in enumerate(code):
        top = stack[-1]
        inside = top[0] or top[1] % 3 != 0
        if i in hits and not inside:
            return True
        if ch in "([{":
            p = code[end - 1] if end else ""
            if ch == "(":
                # x^(...) is an order-by: $ is each item being sorted (items^($.price), items^(>$.a, <$.b))
                opaque = p in (".", "^") or ends_with_step_call(code, end)
            else:  # also a lambda body after a signature: function($v)<n:n>{ ... }
                opaque = p == "." or p in VALUE_END or p.isalnum() or ends_with_signature(code, end)
            stack.append([inside or opaque, 0])
        elif ch in ")]}":
            if len(stack) > 1:
                stack.pop()
        elif ch == "|":
            top[1] += 1
        if not ch.isspace():
            end = i + 1
    return False


def func_params(code: str) -> list[str]:
    """Parameter lists of function(...) / λ(...): the text up to the next ")". Same matches as a finditer of the
    regex "function( ... )" with [^)]* inside, without its quadratic rescans when a ")" is missing (once one list
    is unclosed, no later one can be closed either)."""
    out: list[str] = []
    pos = 0
    for m in FUNC_PARAMS_RE.finditer(code):
        if m.start() < pos:
            continue
        close = code.find(")", m.end())
        if close == -1:
            break
        out.append(code[m.end():close])
        pos = close + 1
    return out


def call_contexts(code: str, opens: set[int]) -> dict[int, tuple[int, int, bool]]:
    """One pass over the bracket structure, for the J014 arity check. For each "(" index in opens: (index of the
    bracket that closes it or -1, number of commas directly inside it, whether an enclosing bracket is a "[" or a
    path step ".(")."""
    result: dict[int, tuple[int, int, bool]] = {}
    stack: list[list] = []  # [open index, is "[" or ".(", commas directly inside]
    squares = 0  # how many entries of stack are "[" or ".("
    end = 0  # code[:end] == code[:i].rstrip()
    for i, ch in enumerate(code):
        if ch in "([{":
            sq = ch == "[" or (ch == "(" and end > 0 and code[end - 1] == ".")
            if i in opens:
                result[i] = (-1, 0, squares > 0)
            stack.append([i, sq, 0])
            squares += sq
        elif ch in ")]}":
            if stack:
                o, sq, commas = stack.pop()
                squares -= sq
                if o in opens:
                    result[o] = (i, commas, result[o][2])
        elif ch == "," and stack:
            stack[-1][2] += 1
        if not ch.isspace():
            end = i + 1
    return result


def analyse_expression(expr: str) -> ExprAnalysis:
    code = strip_literals(expr)
    a = ExprAnalysis()
    for m in BIND_RE.finditer(code):
        a.bound.add(m.group(1))
    for params in func_params(code):
        for p in params.split(","):
            name = p.strip().lstrip("$")
            if name:
                a.bound.add(name)
    for m in POS_BIND_RE.finditer(code):
        a.bound.add(m.group(1))
    for m in CALL_RE.finditer(code):
        a.calls.add(m.group(1))
    checked = [m for m in CALL_RE.finditer(code) if m.group(1) not in a.bound and m.group(1) in JSONATA_ARITY]
    ctx = call_contexts(code, {m.end() - 1 for m in checked}) if checked else {}
    for m in checked:
        i, nargs, in_square = ctx[m.end() - 1]
        if i < 0:
            continue
        k = m.end()
        while k < i and code[k].isspace():
            k += 1
        if k < i:
            nargs += 1
        e = m.start()  # code[:e] == code[:m.start()].rstrip()
        while e > 0 and code[e - 1].isspace():
            e -= 1
        chained = code[max(0, e - 2):e] == "~>"
        nargs += chained
        in_path = e > 0 and code[e - 1] == "."
        a.arity.append((m.group(1), nargs, in_path or in_square, chained))
    for m in VAR_RE.finditer(code):
        # $string in $map(xs, $string) / x ~> $uppercase is a built-in passed by reference; check_expression still
        # treats it as a variable when a variable of that name is assigned somewhere.
        (a.func_refs if m.group(1) in JSONATA_FUNCTIONS else a.vars).add(m.group(1))

    a.states_result = re.search(r"\$states\s*\.\s*result\b", code) is not None
    a.states_error_output = re.search(r"\$states\s*\.\s*errorOutput\b", code) is not None
    # $$ alone is valid JSONata (the root context); only $$.Execution / $$.State / ... is the JSONPath context-object habit.
    a.jsonpath_context = re.search(r"\$\$\s*\.\s*(?:Execution|StateMachine|State|Task|Map)(?![\wÀ-￿])", code) is not None
    a.jsonpath_dollar_dot = root_dollar_dot(code)
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
    # Adjacent characters only: "a ? b : c" and "a ? (b) : c" are the conditional operator.
    if "??" in code:
        a.newer_ops.append("?? is JSONata 2.1.0+: write $exists(a) ? a : b instead of a ?? b")
    if "?:" in code:
        a.newer_ops.append("?: is JSONata 2.1.0+: write a ? a : b instead of a ?: b")

    for b in a.bound:
        a.vars.discard(b)
        a.calls.discard(b)
        a.func_refs.discard(b)
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
    except (ValueError, RecursionError):  # RecursionError: nesting too deep for the parser (reported by lint_text)
        return None


BIG_INT_PROBLEM = ("the JSON contains an integer with thousands of digits (more than Python's int limit); it was read as "
                   "a float (infinity) so the rest could be linted - no ASL field accepts such a number, shorten it")


def _parse_big_int(s: str) -> Any:
    try:
        return int(s)
    except ValueError:  # more digits than sys.get_int_max_str_digits() (Python 3.11+)
        return float(s)


def json_loads(text: str, problems: Optional[list] = None) -> Any:
    """json.loads, but an integer longer than Python's int-digit limit (a plain ValueError, not JSONDecodeError) is
    read as a float and BIG_INT_PROBLEM is added to `problems` instead of crashing. Raises JSONDecodeError as usual."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise
    except ValueError:
        obj = json.loads(text, parse_int=_parse_big_int)
        if problems is not None and BIG_INT_PROBLEM not in problems:
            problems.append(BIG_INT_PROBLEM)
        return obj


TPL_LITERAL_RE = re.compile(r"\$\{[^{}\s]+\}")


def is_placeholder(v: Any) -> bool:
    """True for a template placeholder: replaced by __TPL__ during extraction, or a literal ${Name} left in valid JSON
    (CloudFormation DefinitionSubstitutions, an unrendered templatefile) that is substituted before deployment."""
    return isinstance(v, str) and ("__TPL__" in v or TPL_LITERAL_RE.search(v) is not None)


TPL_DIRECTIVE_RE = re.compile(r"%\{~?\s*(if|else|endif|for|endfor)\b")
JSON_OBJECT_START_RE = re.compile(r'\{\s*(?:"|\})')
SPACES_RE = re.compile(r"\s*")


def placeholder_end(text: str, i: int) -> int:
    """Index just past the "}" that closes the "${" / "%{" starting at text[i] (nested braces and quoted
    strings allowed, e.g. ${jsonencode({a = "}"})}); -1 when it is not closed."""
    depth, j, n, quote = 0, i + 1, len(text), False
    while j < n:
        c = text[j]
        if quote:
            if c == "\\":
                j += 1
            elif c == '"':
                quote = False
        elif c == '"':
            quote = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return -1


PLACEHOLDER_FAIL_BUDGET = 1_000_000  # keeps "${" * 32000 (each unclosed, each scanned to EOF) linear


def substitute_placeholders(text: str) -> str:
    """Replace template placeholders in one pass, by context: ${...} inside a JSON string becomes __TPL__, outside
    a string "__TPL__" (so `"MaxConcurrency": ${mc}` stays valid JSON). Terraform directives: %{ if }...%{ else }...
    %{ endif } keeps only the "if" branch (nesting allowed), %{ for }...%{ endfor } keeps the body once (a trailing
    comma left before a closing } or ] is dropped). Dropped text keeps its newlines, so line numbers stay stable."""
    if "${" not in text and "%{" not in text:
        return text
    out: list[str] = []
    frames: list[list] = []  # one per open %{ if } / %{ for }: [keyword, in_else branch]
    suppressed = False  # inside an %{ else } branch: its text is dropped
    else_frames = 0  # open frames currently in their else branch (kept as a count: no rescan of the stack per directive)
    i, n, in_str = 0, len(text), False
    budget = PLACEHOLDER_FAIL_BUDGET  # an unclosed "${" / "%{" scans to EOF: after this many such chars the rest is literal
    while i < n:
        c = text[i]
        if text.startswith("$${", i) or text.startswith("%%{", i):  # Terraform escapes for a literal ${ / %{
            if not suppressed:
                out.append(text[i + 1:i + 3])
            i += 3
            continue
        directive = TPL_DIRECTIVE_RE.match(text, i) if c == "%" and budget > 0 else None
        if budget > 0 and ((c == "$" and text.startswith("{", i + 1)) or directive):
            end = placeholder_end(text, i)
            if end < 0:
                budget -= n - i
            if end > 0:
                was_suppressed = suppressed
                if directive:
                    kw = directive.group(1)
                    if kw in ("if", "for"):
                        frames.append([kw, False])
                    elif kw == "else" and frames and frames[-1][0] == "if":
                        if not frames[-1][1]:
                            else_frames += 1
                        frames[-1][1] = True
                    elif kw in ("endif", "endfor") and frames:
                        if frames.pop()[1]:
                            else_frames -= 1
                        if kw == "endfor" and not suppressed and not in_str:  # body kept once: drop "a," before "}"/"]"
                            k = len(out) - 1
                            while k >= 0 and out[k].isspace():
                                k -= 1
                            after = SPACES_RE.match(text, end).end()  # type: ignore[union-attr]
                            if k >= 0 and out[k] == "," and text[after:after + 1] in ("}", "]"):
                                out[k] = ""
                    suppressed = else_frames > 0
                elif not suppressed:
                    out.append("__TPL__" if in_str else '"__TPL__"')
                if was_suppressed or suppressed or not in_str:
                    out.append("\n" * text.count("\n", i, end))  # keep line numbers stable
                i = end
                continue
        if suppressed:
            if c == "\n":
                out.append(c)
            i += 1
            continue
        if in_str:
            if c == "\\":
                out.append(text[i:i + 2])
                i += 2
                continue
            if c in '"\n':
                in_str = False
        elif c == '"':
            in_str = True
        out.append(c)
        i += 1
    return "".join(out)


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
            elif c in '"\n':  # JSON/HCL strings never span lines: a stray quote in a comment cannot derail the scan
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            stack.append(i)
        elif c == "}" and stack:
            pairs.append((stack.pop(), i))
        i += 1
    return pairs


def looks_like_asl(text: str) -> bool:
    return bool(re.search(r'"States"\s*:', text) and re.search(r'"StartAt"\s*:', text))


def is_definition(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("States"), dict) and bool(obj.get("StartAt"))


def json_error(ex: json.JSONDecodeError, text: str, offset: int = 0, newlines: Optional[list[int]] = None) -> str:
    """'<msg> at line L column C (near: ...)' with positions in `text` (ex positions are relative to text[offset:]).
    `newlines` (sorted positions of every newline in `text`) makes it O(log n) for callers reporting many errors."""
    pos = offset + ex.pos
    if newlines is None:
        line_start = text.rfind("\n", 0, pos) + 1
        line_end = text.find("\n", pos)
        line_no = text.count(chr(10), 0, pos) + 1
    else:
        k = bisect.bisect_left(newlines, pos)
        line_start = newlines[k - 1] + 1 if k else 0
        line_end = newlines[k] if k < len(newlines) else -1
        line_no = k + 1
    col = pos - line_start
    near = text[max(line_start, pos - 40):min(line_end if line_end >= 0 else len(text), pos + 40)].strip()
    return f"{ex.msg} at line {line_no} column {col + 1} (near: {near})"


TF_RESOURCE_RE = re.compile(r'^[ \t]*(resource|data|locals|module|output|variable)\b(?:\s+"([^"]+)"\s+"([^"]+)")?', re.M)
TEMPLATE_UNLINTABLE = ("could not lint this template: after removing %{{ }} directives the JSON is invalid ({}); nothing was "
                       "linted. Render the template (terraform console: templatefile(\"<file>\", {{...}}), or terraform plan) "
                       "and pipe the JSON to: python3 lint_asl.py -")


def template_text(v: Any) -> Optional[str]:
    """The text of a CloudFormation string-building intrinsic ({"Fn::Sub": str | [str, {...}]}, {"Fn::Join": [sep, [...]]}),
    with every non-string part (Ref, Fn::GetAtt, ...) written as a ${...} placeholder; None for anything else."""
    if not isinstance(v, dict) or len(v) != 1:
        return None
    (fn, arg), = v.items()
    if fn == "Fn::Sub":
        arg = arg[0] if isinstance(arg, list) and arg else arg
        return arg if isinstance(arg, str) else None
    if fn == "Fn::Join" and isinstance(arg, list) and len(arg) == 2 and isinstance(arg[0], str) and isinstance(arg[1], list):
        parts = [p if isinstance(p, str) else template_text(p) for p in arg[1]]
        return arg[0].join("${CFN}" if p is None else p for p in parts)
    return None


def definition_label(path: str) -> str:
    """CloudFormation-style path of a definition, without the intrinsic-function tail (/Fn::Sub/0, /Fn::Join/1/3)."""
    parts = path.split("/")
    for i, part in enumerate(parts):
        if part.startswith("Fn::"):
            parts = parts[:i]
            break
    return "/".join(parts) or "/"


def is_intrinsic(v: Any) -> bool:
    """{"Ref": ...} / {"Fn::GetAtt": ...} / ... - a CloudFormation intrinsic function, resolved before deployment."""
    if not isinstance(v, dict) or len(v) != 1:
        return False
    key = next(iter(v))
    return key == "Ref" or key.startswith("Fn::")


def replace_intrinsics(definition: dict) -> None:
    """In a definition inside a template (CloudFormation/SAM Definition, Serverless definition), replace every intrinsic
    function value (e.g. "Resource": {"Fn::GetAtt": ["fn", "Arn"]}) by the placeholder "__TPL__", in place."""
    stack: list[Any] = [definition]
    while stack:
        node = stack.pop()
        items = node.items() if isinstance(node, dict) else enumerate(node)
        for k, v in list(items):
            if is_intrinsic(v):
                node[k] = "__TPL__"
            elif isinstance(v, (dict, list)):
                stack.append(v)


def find_nested_definitions(obj: Any, path: str = "", problems: Optional[list] = None) -> list[tuple[dict, Optional[str], str]]:
    """Definitions inside an already-parsed JSON document (CloudFormation JSON Definition / DefinitionString, ...), as
    (definition, note, label) where label is the path of the definition in the document."""
    if is_definition(obj):
        if path:
            replace_intrinsics(obj)
        return [(obj, f"linted the state machine definition found at {path or '/'}", path or "/")]
    found: list[tuple[dict, Optional[str], str]] = []
    items = obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else []
    for k, v in items:
        built = template_text(v)
        if isinstance(v, str) and looks_like_asl(v) or built is not None and looks_like_asl(built):
            where = f"{path}/{k}"
            how = "embedded in the string at" if built is None else "built from the intrinsic function at"
            defs, embedded_problems = extract_embedded(v if built is None else built)
            for p in embedded_problems if problems is not None else []:
                problems.append((p[0], f"{p[1]} (in the string at {where})") if isinstance(p, tuple) else f"{p} (in the string at {where})")
            found.extend((d, f"linted the state machine definition {how} {where}", definition_label(where)) for d, _n, _l in defs)
        elif isinstance(v, (dict, list)):
            found.extend(find_nested_definitions(v, f"{path}/{k}", problems))
    return found


def terraform_resource(text: str, line: int) -> str:
    """'<type>.<name>' of the Terraform resource block that contains 1-based `line` of `text`, or ''."""
    pos = 0
    for _ in range(line - 1):
        pos = text.find("\n", pos) + 1
        if pos == 0:
            return ""
    last = None
    for last in TF_RESOURCE_RE.finditer(text, 0, pos):
        pass
    if last is None or last.group(1) != "resource" or not last.group(2):
        return ""
    return f"{last.group(2)}.{last.group(3)}"


def terraform_resources(text: str):
    """terraform_resource(text, line) as a lookup function that indexes `text` once: O(log n) per line instead of
    O(n), for files that embed thousands of definitions."""
    newlines = [m.start() for m in re.finditer("\n", text)]
    matches = list(TF_RESOURCE_RE.finditer(text))
    starts = [m.start() for m in matches]

    def lookup(line: int) -> str:
        if line - 1 > len(newlines):
            return ""
        pos = newlines[line - 2] + 1 if line >= 2 else 0
        k = bisect.bisect_left(starts, pos) - 1
        if k >= 0 and matches[k].end() > pos:  # that header spans into this line: use the last one that ends before it
            k -= 1
        if k < 0 or matches[k].group(1) != "resource" or not matches[k].group(2):
            return ""
        return f"{matches[k].group(2)}.{matches[k].group(3)}"
    return lookup


MAX_EMBEDDED_PROBLEMS = 20  # invalid embedded definitions reported one by one; the rest are counted


def extract_embedded(text: str) -> tuple[list[tuple[dict, Optional[str], str]], list]:
    """Definitions embedded in a non-JSON file (Terraform heredoc/templatefile, CloudFormation DefinitionString, ...).
    Outermost objects win. A JSON-looking object that has "StartAt" and "States" but does not parse is reported as a
    problem and nothing nested inside it is linted (that would silently lint an inner Map/Parallel instead).
    Returns ([(definition, note, label "line N[, resource]"), ...], problems); a problem is a message (an error) or
    ("WARNING", message)."""
    v = substitute_placeholders(text)  # keeps line numbers: line N of v is line N of text
    found: list[tuple[dict, Optional[str], str]] = []
    problems: list = []
    invalid = 0
    note = "extracted embedded definition" + (" (template placeholders replaced by __TPL__)" if v != text else "")
    # Near-linear: key positions are found once (a pair "looks like ASL" when both keys start inside it), pairs are
    # visited outermost first and everything inside a parsed or reported pair is skipped (brace pairs nest, so only
    # the end of the last taken pair matters). Every chunk that is sliced and parsed is taken, so slicing is O(n).
    states_at = [m.start() for m in re.finditer(r'"States"\s*:', v)]
    start_at = [m.start() for m in re.finditer(r'"StartAt"\s*:', v)]
    v_newlines: list[int] = []
    text_newlines: list[int] = []
    resource_at = None
    taken_end = -1
    for s, e in sorted(match_braces(v)) if states_at and start_at else []:
        if s <= taken_end:
            continue
        k1, k2 = bisect.bisect_left(states_at, s), bisect.bisect_left(start_at, s)
        if k1 == len(states_at) or states_at[k1] > e or k2 == len(start_at) or start_at[k2] > e:
            continue
        if not JSON_OBJECT_START_RE.match(v, s):
            continue  # "{" not followed by '"' or "}" cannot parse; something nested inside still may
        if not v_newlines:
            v_newlines = [m.start() for m in re.finditer("\n", v)] or [len(v)]
        first_line = bisect.bisect_left(v_newlines, s) + 1
        chunk = v[s:e + 1]
        taken_end = e  # parsed: the nested pairs are its own sub-objects, which find_nested_definitions searches
        try:
            obj = json_loads(chunk, problems)
        except json.JSONDecodeError as ex:
            invalid += 1
            if invalid > MAX_EMBEDDED_PROBLEMS:
                continue
            if not text_newlines:
                text_newlines = [m.start() for m in re.finditer("\n", text)] or [len(text)]
            last_line = first_line + chunk.count("\n")  # the source lines of the chunk: first_line..last_line
            a = 0 if first_line < 2 else text_newlines[first_line - 2] + 1 if first_line - 2 < len(text_newlines) else len(text)
            b = text_newlines[last_line - 1] if last_line - 1 < len(text_newlines) else len(text)
            where = json_error(ex, v, s, v_newlines)
            if TPL_DIRECTIVE_RE.search(text, a, max(a, b)):
                problems.append(("WARNING", TEMPLATE_UNLINTABLE.format(f"{where}, in the definition starting at line {first_line}")))
            else:
                problems.append(f"invalid JSON in the embedded state machine definition starting at line {first_line}: "
                                f"{where}; nothing inside it was linted - fix the JSON syntax and re-run")
            continue
        resource_at = resource_at or terraform_resources(text)
        resource = resource_at(first_line)
        label = f"line {first_line}" + (f" {resource}" if resource else "")
        if is_definition(obj):
            found.append((obj, note, label))
        else:
            nested = find_nested_definitions(obj, "", problems)
            found.extend((d, n, label if lb == "/" else f"{label} {lb}") for d, n, lb in nested)
    if invalid > MAX_EMBEDDED_PROBLEMS:
        problems.append(f"... and {invalid - MAX_EMBEDDED_PROBLEMS} more embedded state machine definitions with invalid "
                        "JSON (not listed); nothing inside them was linted - fix the JSON syntax and re-run")
    return found, problems


def definitions_elsewhere(obj: Any) -> list[str]:
    """'<resource>: <property> <file>' for every state machine of a CloudFormation/SAM template whose definition is in
    another file (SAM DefinitionUri, CloudFormation DefinitionS3Location)."""
    out: list[str] = []
    resources = obj.get("Resources") if isinstance(obj, dict) else None
    for name, res in resources.items() if isinstance(resources, dict) else []:
        props = res.get("Properties") if isinstance(res, dict) else None
        for key in ("DefinitionUri", "DefinitionS3Location"):
            if isinstance(props, dict) and key in props:
                uri = props[key]
                where = uri if isinstance(uri, str) else (f"s3://{uri.get('Bucket')}/{uri.get('Key')}"
                                                          if isinstance(uri, dict) and "Key" in uri else json.dumps(uri))
                out.append(f"{name}: {key} {where}")
    return out


def extract_definitions(text: str, filename: Optional[str] = None,
                        problems: Optional[list] = None, labels: Optional[list[str]] = None) -> list[tuple[dict, Optional[str]]]:
    """Definitions in `text`; reasons nothing (or not everything) could be linted are appended to `problems` (a message
    is an error, ("WARNING", message) a warning); where each definition is - its path in a JSON template, or
    "line N[ <terraform resource>]" - is appended to `labels`."""
    found = _extract_definitions(text, filename, [] if problems is None else problems)
    if labels is not None:
        labels.extend(label for _d, _n, label in found)
    return [(d, n) for d, n, _label in found]


def _extract_definitions(text: str, filename: Optional[str], problems: list) -> list[tuple[dict, Optional[str], str]]:
    text = text.lstrip("﻿")
    try:
        direct, err, err_text = json_loads(text, problems), None, text
    except json.JSONDecodeError as ex:
        direct, err, err_text = None, ex, text
    jsonish = (filename or "").lower().endswith(".json") or text.lstrip().startswith(("{", "["))
    note = None
    if err is not None and jsonish:
        templated = substitute_placeholders(text)
        directives = templated != text and TPL_DIRECTIVE_RE.search(text)
        if templated != text:
            try:
                direct, err, note = json_loads(templated, problems), None, "template placeholders replaced by __TPL__"
            except json.JSONDecodeError as ex:
                err, err_text = ex, templated
        if err is not None and directives:  # a template, not broken JSON: it may be fine once rendered
            problems.append(("WARNING", TEMPLATE_UNLINTABLE.format(json_error(err, err_text))))
            return []
        if err is not None:
            problems.append(f"invalid JSON: {json_error(err, err_text)}"
                            f"{' (after replacing ${...} template placeholders)' if err_text is not text else ''}; "
                            "nothing was linted - fix the JSON syntax and re-run")
            return []
        if directives:
            note = f"{note}; Terraform %{{ }} directives: only the first (if) branch of each %{{ if }} was linted"
    if err is None:
        if isinstance(direct, dict) and ("States" in direct or "StartAt" in direct):
            return [(direct, note, "/")]
        if isinstance(direct, str) and looks_like_asl(direct):  # a JSON-encoded definition, e.g. `terraform console` output
            return extract_embedded(direct)[0]
        nested = find_nested_definitions(direct, "", problems)
        if not nested and isinstance(direct, dict) and ("Resources" in direct or "AWSTemplateFormatVersion" in direct):
            elsewhere = definitions_elsewhere(direct)
            if [p for p in problems if p != BIG_INT_PROBLEM]:  # e.g. the DefinitionString is invalid JSON: already reported
                pass
            elif elsewhere:
                problems.append("this template has no inline state machine definition: it is in another file ("
                                + "; ".join(elsewhere) + "); lint that file instead: python3 lint_asl.py <file>")
            else:
                problems.append("this JSON template contains no state machine definition (no object with \"StartAt\" and \"States\", "
                                "and no DefinitionString containing one)")
            return []
        elsewhere = definitions_elsewhere(direct) if nested else []
        if elsewhere:
            problems.append(("INFO", "not linted: state machine definitions in other files (" + "; ".join(elsewhere)
                             + "); lint those files too: python3 lint_asl.py <file>"))
        if nested or isinstance(direct, dict):
            return nested or [(direct, note, "/")]
        problems.append(f"the input is valid JSON but its top level is { {list: 'an array', str: 'a string', bool: 'a boolean'}.get(type(direct), 'null' if direct is None else 'a number')}, "
                        'not a state machine object ({"StartAt": ..., "States": {...}})')
        return []
    found, embedded_problems = extract_embedded(text)
    problems.extend(embedded_problems)
    return found


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def assign_keys(assign: Any) -> set[str]:
    """Variable names assigned by an Assign object (a JSONPath key "name.$" assigns the variable "name")."""
    return {k[:-2] if k.endswith(".$") else k for k in assign} if isinstance(assign, dict) else set()


def valid_var_name(name: str) -> bool:
    """AWS variable name syntax: Unicode identifier (ID_Start, then ID_Continue), at most 80 characters, not $states.
    str.isidentifier() is XID_Start/XID_Continue plus a leading "_"; "_" is not ID_Start, so it is excluded."""
    return name.isidentifier() and not name.startswith("_") and len(name) <= 80 and name != "states"


def as_list(v: Any) -> list:
    """v if it is a list, else [] (wrong types are reported by the field's own check)."""
    return v if isinstance(v, list) else []


MAX_DEPTH = 200


def clip_depth(definition: dict, diags: Diagnostics) -> dict:
    """Copy of the definition with values nested deeper than MAX_DEPTH replaced by null (iterative, no recursion),
    so every recursive walker stays far below Python's recursion limit. Warns once if anything was cut."""
    root: dict = {}
    work: list[tuple[Any, Any, int, str]] = [(definition, root, 0, "")]
    cut = ""
    while work:
        src, dst, depth, path = work.pop()
        items = src.items() if isinstance(src, dict) else enumerate(src)
        for k, v in items:
            kpath = f"{path}/{k}"
            if isinstance(v, (dict, list)) and depth >= MAX_DEPTH:
                v = None
                cut = cut or re.sub(r"(/\d+)+$", "", "/".join(kpath.split("/")[:8]))
            elif isinstance(v, (dict, list)):
                new: Any = {} if isinstance(v, dict) else []
                work.append((v, new, depth + 1, kpath))
                v = new
            if isinstance(dst, dict):
                dst[k] = v
            else:
                dst.append(v)
    if cut:
        diags.warn("S000", cut, f"nesting deeper than {MAX_DEPTH} levels not checked; flatten this value (e.g. pass it as a "
                   "JSON string and $parse / States.StringToJson it) or move it out of the definition")
    return root


def is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def levenshtein(a: str, b: str, limit: Optional[int] = None) -> int:
    """Edit distance. With a limit, the exact distance if it is <= limit, else limit + 1: only the diagonal band
    |i - j| <= limit is computed and it stops early, so huge strings cost O(len * limit) at most."""
    if limit is None:
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i]
            for j, cb in enumerate(b, 1):
                cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            prev = cur
        return prev[-1]
    big = limit + 1
    la, lb = len(a), len(b)
    if abs(la - lb) > limit:
        return big
    # A cell (i, j) outside the band is >= |i - j| > limit, so it is read as big; values are capped at big.
    # Two row buffers; row i only reads row i-1 at columns lo-1..hi, which row i-1 wrote (or set to big).
    prev = [big] * (lb + 2)
    for j in range(min(limit, lb) + 1):
        prev[j] = j
    cur = [big] * (lb + 2)
    for i in range(1, la + 1):
        ca = a[i - 1]
        lo, hi = max(1, i - limit), min(lb, i + limit)
        cur[lo - 1] = i if lo == 1 else big
        row_min = cur[lo - 1]
        for j in range(lo, hi + 1):
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != b[j - 1]), big)
            cur[j] = v
            if v < row_min:
                row_min = v
        cur[hi + 1] = big
        if row_min > limit:
            return big
        prev, cur = cur, prev
    return min(prev[lb], big)


def suggest_field(k: str, allowed: set[str]) -> str:
    """Closest allowed field within 2 edits (ignoring case); ties go to the alphabetically first, so the
    suggestion does not depend on set iteration order."""
    lower = k.lower()
    best = min(((0 if a.lower() == lower else levenshtein(a.lower(), lower, 2), a) for a in allowed), default=None)
    return f' (did you mean "{best[1]}"?)' if best and best[0] <= 2 else ""


def check_error_equals(ee: Any, loc: str, is_last: bool, diags: Diagnostics) -> None:
    if not isinstance(ee, list) or not ee:
        diags.error("S012", f"{loc}/ErrorEquals", "ErrorEquals must be a non-empty array of error names")
        return
    for e in ee:
        if not isinstance(e, str):
            diags.error("S012", f"{loc}/ErrorEquals", "error names must be strings")
            continue
        if e.startswith("States.") and e not in ERROR_NAMES and not any(p.match(e) for p in ERROR_NAME_PATTERNS):
            extra = (" - HTTP Task status errors need a three-digit code, one entry per code (e.g. \"States.Http.StatusCode.503\")"
                     if e.startswith("States.Http.StatusCode.") else "")
            diags.error("S012", f"{loc}/ErrorEquals", f'"{e}" is not a predefined States.* error name{extra}')
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
                # ASL Comment fields (Choice rules, ...) are never evaluated: skip them, unless the value is a whole
                # "{% %}" expression - then it is a service parameter that happens to be named Comment (CloudFront, Route 53)
                if k != "Comment" or is_expression(x):
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


SHORT_NAME = 24  # variable names up to this length go into the deletion index of similar_variable_hint
MAX_INDEXED_VARS = 1000  # more assigned variables than this: no deletion index, compare by length bucket instead
HINT_COMPARE_BUDGET = 200_000  # candidate comparisons per file (lint_text call) for V001 "did you mean" hints
_similar_cache: dict[str, Any] = {"src": None}


def deletions(s: str, k: int) -> list[set[str]]:
    """[{s}, s minus 1 character, ..., s minus k characters]."""
    out = [{s}]
    for _ in range(k):
        out.append({x[:i] + x[i + 1:] for x in out[-1] for i in range(len(x))})
    return out


def plain_lower(s: str) -> bool:
    """str.lower() maps s character by character to the same length (not so for U+0130 and the final sigma)."""
    return "Σ" not in s and len(s.lower()) == len(s)


def similar_variable_hint(v: str, all_assigned: dict[str, str]) -> str:
    """V001 hint, same result as scanning every assigned variable a != v that equals v ignoring case or is within
    min(2, len(v) - 1) edits of it, and taking the smallest (edit distance ignoring case, name). Uses an index of
    the lower-cased names (and their 1- and 2-deletion variants: two strings within d edits share a variant with
    at most d deletions on each side), built once per all_assigned and cached with the answers, so a read of an
    unknown variable does not compare against every assigned variable."""
    c = _similar_cache
    if c["src"] is not all_assigned or c["size"] != len(all_assigned):
        by_lower: dict[str, list[str]] = {}
        by_len: dict[int, list[str]] = {}
        dels: list[dict[str, list[str]]] = [{}, {}, {}]  # variant -> names, by number of deletions
        odd: list[str] = []
        bad_fix: dict[str, list[str]] = {}  # invalid Assign key -> the name V007 suggests (for the rename hint)
        # the deletion index costs ~350 entries per name: at most MAX_INDEXED_VARS names per definition and per file
        left = c.get("index_left", MAX_INDEXED_VARS)
        indexed = len(all_assigned) <= min(MAX_INDEXED_VARS, left)
        if indexed:
            c["index_left"] = left - len(all_assigned)
        for name in all_assigned:
            low = name.lower()
            by_lower.setdefault(low, []).append(name)
            by_len.setdefault(len(name), []).append(name)
            if not valid_var_name(name):
                bad_fix.setdefault(suggest_var_name(name), []).append(name)
            if not plain_lower(name):
                odd.append(name)
            elif indexed and len(name) <= SHORT_NAME + 2:
                for nd, variants in enumerate(deletions(low, 2)):
                    for x in variants:
                        dels[nd].setdefault(x, []).append(name)
        c.update(src=all_assigned, size=len(all_assigned), by_lower=by_lower, by_len=by_len, dels=dels, odd=odd, hints={},
                 bad_fix=bad_fix, indexed=indexed)
    if v in c["hints"]:
        return c["hints"][v]
    if c.get("budget", HINT_COMPARE_BUDGET) <= 0:  # suggestions are a convenience: past the budget, no more hints
        return ""
    k = min(2, len(v) - 1)
    vl = v.lower()
    found: list[tuple[int, str]] = []

    def consider(names) -> None:
        c["budget"] = c.get("budget", HINT_COMPARE_BUDGET) - len(names)
        for a in names:
            if a != v and valid_var_name(a) and (a.lower() == vl or levenshtein(a, v, k) <= k):
                dist = levenshtein(vl, a.lower(), 2)
                if dist > 2:  # only possible when lower() is not character by character
                    dist = levenshtein(vl, a.lower())
                found.append((dist, a))

    consider(c["by_lower"].get(vl, []))
    if not plain_lower(v):
        consider(all_assigned)
    elif len(v) > SHORT_NAME or not c["indexed"]:
        for n in range(len(v) - k, len(v) + k + 1):
            consider(c["by_len"].get(n, []))
    else:
        # lower() is character by character here, so the distance ignoring case is <= the plain distance <= k:
        # the answer shares a variant with at most d deletions on both sides, for its distance d <= k.
        consider(c["odd"])
        dels = c["dels"]
        vvars = deletions(vl, k)
        for d in range(1, k + 1):
            if any(dist <= d - 1 for dist, _a in found):
                break
            cands: set[str] = set()
            for i in range(d + 1):
                for x in vvars[i]:
                    for j in range(d + 1):
                        if i == d or j == d:  # pairs with both counts < d were collected for d - 1
                            cands.update(dels[j].get(x, ()))
            consider(cands)
    hint = f" (did you mean ${min(found)[1]}?)" if found else ""
    c["hints"][v] = hint
    return hint


def check_expression(raw: str, loc: str, *, result_ok: bool, error_ok: bool, in_vars: set[str], ever_assigned: set[str],
                     all_assigned: dict[str, str], outer_for_distributed: Optional[set[str]], diags: Diagnostics, jsonata) -> None:
    m = EXPR_RE.match(raw)
    if not m:
        if raw.lstrip().startswith("{%"):  # meant as an expression: " {% $x %}", "{% $x %} ", "{% $x"
            diags.error("J003", loc, 'string contains "{%" or "%}" but is not a well-formed expression: it must start with "{%" '
                        f'and end with "%}}" with no surrounding whitespace: {json.dumps(raw[:60])}')
        else:  # "<p>{% raw %}</p>", "50%}", "Hello {% $name %}": a literal string, never evaluated
            diags.warn("J003", loc, 'string contains "{%" or "%}" but does not start with "{%", so Step Functions treats the whole '
                       "string as literal text (nothing inside is evaluated). That is fine for literal text such as a template; "
                       'if it was meant as an expression, the whole string must be one expression that starts with "{%" and '
                       "ends with \"%}\" with no surrounding whitespace (build text with &, e.g. \"{% 'Hello ' & $name %}\"): "
                       f"{json.dumps(raw[:60])}")
        return
    # a template placeholder inside the expression ("{% $x > ${threshold} %}", CloudFormation DefinitionSubstitutions /
    # templatefile) is rendered before deployment: check it as a plain name, the same as extraction's __TPL__
    expr = TPL_LITERAL_RE.sub("__TPL__", m.group(1))
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
    for op in a.newer_ops:
        diags.warn("J007", loc, f"operator {op} (Step Functions implements JSONata 2.0.6, so the operator is likely "
                   "rejected; the replacement works in every JSONata version)")
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
    for fn, got, in_path, chained in a.arity:
        lo, hi, ctx, example = JSONATA_ARITY[fn]
        if ctx and in_path:
            lo -= 1
        if lo <= got and (hi is None or got <= hi):
            continue
        takes = "no arguments" if hi == 0 else (f"at least {lo}" if hi is None else str(lo) if lo == hi else f"{lo}-{hi}") +             (" argument" if lo == hi == 1 else " arguments")
        note = " (the path value counts as the first argument here)" if ctx and in_path else             " (x ~> $f(...) passes x as the first argument)" if chained else ""
        diags.error("J014", loc, f"${fn}() takes {takes}, got {got}{note} - e.g. {example}")

    # a built-in name without "(" is a function reference unless a variable of that name exists
    used = a.vars | {f for f in a.func_refs if f in in_vars or f in ever_assigned or f in all_assigned
                     or (outer_for_distributed is not None and f in outer_for_distributed)}
    check_variable_reads(used, loc, in_vars=in_vars, ever_assigned=ever_assigned, all_assigned=all_assigned,
                         outer_for_distributed=outer_for_distributed, diags=diags)

    if jsonata is not None:
        try:
            jsonata(expr)
        except Exception as e:  # noqa: BLE001 - parser raises its own exception type
            diags.error("J006", loc, f"JSONata syntax error: {e}")


def check_variable_reads(used: set[str], loc: str, *, in_vars: set[str], ever_assigned: set[str], all_assigned: dict[str, str],
                         outer_for_distributed: Optional[set[str]], diags: Diagnostics, jsonata_hints: bool = True) -> None:
    """V001/V002/V003 for the variables read at one location (JSONata expression or JSONPath field)."""
    for v in sorted(used):
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
            hint = f" (did you mean {FUNCTION_HINTS[v]}?)" if jsonata_hints and v in FUNCTION_HINTS else ""
            if not hint:
                hint = similar_variable_hint(v, all_assigned)
                if not hint:
                    bad = sorted(_similar_cache["bad_fix"].get(v, [])) if _similar_cache["src"] is all_assigned else []
                    if bad:
                        hint = f' (the Assign key "{bad[0]}" is not a valid name; rename it to "{v}" as V007 says)'
            diags.error("V001", loc, f"${v} is never assigned anywhere in the state machine{hint}")
        else:
            diags.error("V002", loc, f"${v} is not assigned on every path that reaches this state (assigned later, in this "
                        "same state, inside a Map/Parallel scope, or only on some branches)")


# $states.* fields and the Step Functions context object. None = single value, "*" = free-form JSON below.
STATES_FIELDS = ("input", "result", "errorOutput", "context")
STATES_FIELD_HINTS = {
    "output": "$states.result (in Output/Assign of Task, Map, Parallel); a state cannot read its own output",
    "error": "$states.errorOutput.Error (inside Catch)",
    "cause": "$states.errorOutput.Cause (inside Catch)",
    "ctx": "$states.context",
    "vars": "the variable itself, e.g. $myVar (variables have no $states. prefix)",
    "variables": "the variable itself, e.g. $myVar (variables have no $states. prefix)",
    "item": "$states.context.Map.Item.Value (in a Map ItemSelector)",
    "execution": "$states.context.Execution.<field>",
    "token": "$states.context.Task.Token",
    "taskToken": "$states.context.Task.Token",
}
CONTEXT_TREE: dict[str, Any] = {
    "Execution": {"Id": None, "Input": "*", "Name": None, "RoleArn": None, "StartTime": None, "RedriveCount": None,
                  "RedriveTime": None},
    "State": {"EnteredTime": None, "Name": None, "RetryCount": None},
    "StateMachine": {"Id": None, "Name": None},
    "Task": {"Token": None},
    "Map": {"Item": {"Index": None, "Value": "*", "Key": None, "Source": "*"}},
}
STATES_REF_RE = re.compile(r"\$states(?![\wÀ-￿])((?:\s*\.\s*" + IDENT + r")*)")
VAR_NAME_RE = re.compile(r"^" + IDENT + r"$")


def closest_name(name: str, options) -> Optional[str]:
    best: Optional[tuple[int, str]] = None
    for o in sorted(options):  # sorted: ties resolve the same way on every run
        dist = levenshtein(o.lower(), name.lower(), 2)
        if dist <= 2 and (best is None or dist < best[0]):
            best = (dist, o)
    return best[1] if best else None


def check_states_refs(st: dict, loc: str, diags: Diagnostics) -> None:
    """J013: $states.<field> and $states.context.<path> must exist, and Map.Item / Task.Token must be used where set."""
    stype = st.get("Type")
    res = st.get("Resource")
    wait_token = stype == "Task" and isinstance(res, str) and res.endswith(".waitForTaskToken")
    for field_path, raw, _result_ok, _error_ok in collect_expressions(st):
        m = EXPR_RE.match(raw)
        if not m:
            continue
        floc = f"{loc}/{field_path}"
        seen: set[str] = set()
        for ref in STATES_REF_RE.finditer(strip_literals(m.group(1))):
            parts = [p.strip() for p in ref.group(1).split(".")[1:]]
            if not parts or ".".join(parts) in seen:
                continue
            seen.add(".".join(parts))
            top = parts[0]
            if top not in STATES_FIELDS:
                guess = closest_name(top, STATES_FIELDS)
                use = STATES_FIELD_HINTS.get(top, STATES_FIELD_HINTS.get(top.lower()))
                hint = f" - did you mean $states.{guess}?" if guess else (f" - use {use}" if use else "")
                diags.error("J013", floc, f"$states.{top} does not exist; $states only has input, result, errorOutput and context{hint}")
                continue
            if top != "context":
                continue
            node: Any = CONTEXT_TREE
            path = "$states.context"
            for p in parts[1:]:
                if node == "*":
                    break
                if node is None:
                    diags.error("J013", floc, f'{path} is a single value (string or number) with no field "{p}"; use {path} by itself')
                    break
                if p not in node:
                    guess = closest_name(p, node)
                    dym = f" (did you mean {path}.{guess}?)" if guess else ""
                    diags.warn("J013", floc, f"{path}.{p} is not a known Step Functions context field{dym}; known fields under "
                                f"{path}: {', '.join(node)}")
                    break
                node = node[p]
                path += f".{p}"
            if parts[1:3] == ["Map", "Item"] and not (stype == "Map" and field_path.split("/")[0] == "ItemSelector"):
                diags.warn("J013", floc, "$states.context.Map.Item.* is only set while a Map state evaluates its ItemSelector; add "
                           '"ItemSelector": {"value": "{% $states.context.Map.Item.Value %}", "index": "{% $states.context.Map.Item.Index %}"} '
                           "to the Map and read $states.input.value / $states.input.index in the states inside ItemProcessor")
            if parts[1:3] == ["Task", "Token"] and not wait_token:
                diags.warn("J013", floc, "$states.context.Task.Token is only set for callback tasks; use it in the Arguments of a Task "
                           'whose Resource ends with ".waitForTaskToken" (e.g. "arn:aws:states:::sqs:sendMessage.waitForTaskToken")')


def suggest_var_name(name: str) -> str:
    """A valid variable name close to an invalid Assign key: "1st" -> "v1st", "_tmp" -> "tmp", "order.total" -> "order_total"."""
    fixed = "".join(c if ("a" + c).isidentifier() else "_" for c in name.lstrip("$"))
    fixed = re.sub(r"_+", "_", fixed).strip("_") or "value"
    if not fixed.isidentifier():  # starts with a digit or another ID_Continue-only character
        fixed = "v" + fixed
    if fixed == "states":
        fixed = "statesData"
    return fixed[:80]


def check_assign_names(st: dict, loc: str, diags: Diagnostics) -> None:
    """V007: Assign keys (state, Choices rule, Catch) must be plain variable names."""
    targets: list[tuple[str, Any]] = [("Assign", st.get("Assign"))]
    for field in ("Choices", "Catch"):
        items = st.get(field)
        for i, x in enumerate(items if isinstance(items, list) else []):
            if isinstance(x, dict) and "Assign" in x:
                targets.append((f"{field}/{i}/Assign", x.get("Assign")))
    for path, assign in targets:
        if not isinstance(assign, dict):
            if (path != "Assign" or "Assign" in st) and not is_placeholder(assign):
                diags.error("S009", f"{loc}/{path}", 'Assign must be an object mapping variable names to values, e.g. "Assign": {"count": 0}')
            continue
        taken = {k[:-2] if k.endswith(".$") else k for k in assign}
        next_suffix: dict[str, int] = {}  # base name -> next suffix to try, so N colliding keys cost O(N), not O(N^2)
        for key in assign:
            suffix = ".$" if key.endswith(".$") else ""  # JSONPath "name.$": "$.path"; in JSONata J002 already reports ".$"
            name = key[:-2] if suffix else key
            kloc = f"{loc}/{path}/{key}"
            if valid_var_name(name):
                continue
            if name.isidentifier() and not name.startswith("_") and name != "states":
                diags.error("V007", kloc, f'variable name "{name}" is longer than the 80-character maximum; use a shorter name')
                continue
            fixed = suggest_var_name(name)
            if fixed in taken:  # "_tmp" next to an existing "tmp": don't suggest a duplicate key
                base, i = fixed, next_suffix.get(fixed, 2)
                while f"{base}{i}" in taken:
                    i += 1
                next_suffix[base] = i + 1
                fixed = f"{base}{i}"
            taken.add(fixed)
            if name == "states":
                why = "is reserved ($states holds input, result, errorOutput and context)"
            elif name.startswith("$"):
                why = 'must not start with "$" (the $ is only written when reading the variable)'
            else:
                why = ("is not a valid variable name (start with a letter, then only letters, digits and _; "
                       "no leading _, no dots, spaces or dashes)")
            diags.error("V007", kloc, f'Assign key "{key}" {why}: write "{fixed}{suffix}" and read it later as ${fixed}')


# ---------------------------------------------------------------------------
# JSONPath checks (Choice rules, intrinsic functions, path syntax)
# ---------------------------------------------------------------------------

# Intrinsic function -> (min args, max args); None = no upper limit.
INTRINSIC_ARGS: dict[str, tuple[int, Optional[int]]] = {
    "States.Format": (1, None), "States.StringToJson": (1, 1), "States.JsonToString": (1, 1),
    "States.Array": (0, None), "States.ArrayPartition": (2, 2), "States.ArrayContains": (2, 2),
    "States.ArrayRange": (3, 3), "States.ArrayGetItem": (2, 2), "States.ArrayLength": (1, 1),
    "States.ArrayUnique": (1, 1), "States.Base64Encode": (1, 1), "States.Base64Decode": (1, 1),
    "States.Hash": (2, 2), "States.JsonMerge": (3, 3), "States.MathRandom": (2, 3), "States.MathAdd": (2, 2),
    "States.StringSplit": (2, 2), "States.UUID": (0, 0),
}
INTRINSIC_USAGE = {
    "States.Format": "States.Format('text {} more {}', $.a, $.b)", "States.StringToJson": "States.StringToJson($.jsonString)",
    "States.JsonToString": "States.JsonToString($.obj)", "States.Array": "States.Array($.a, $.b, 'c')",
    "States.ArrayPartition": "States.ArrayPartition($.array, 4)", "States.ArrayContains": "States.ArrayContains($.array, $.value)",
    "States.ArrayRange": "States.ArrayRange(1, 9, 2)", "States.ArrayGetItem": "States.ArrayGetItem($.array, 0)",
    "States.ArrayLength": "States.ArrayLength($.array)", "States.ArrayUnique": "States.ArrayUnique($.array)",
    "States.Base64Encode": "States.Base64Encode($.text)", "States.Base64Decode": "States.Base64Decode($.base64)",
    "States.Hash": "States.Hash($.text, 'SHA-256')", "States.JsonMerge": "States.JsonMerge($.a, $.b, false)",
    "States.MathRandom": "States.MathRandom(1, 100) or States.MathRandom(1, 100, $.seed)",
    "States.MathAdd": "States.MathAdd($.n, 1)", "States.StringSplit": "States.StringSplit($.text, ',')",
    "States.UUID": "States.UUID()",
}
CHOICE_OPERATORS = [k for k in CHOICE_RULE_FIELDS["jsonpath"] if k not in ("Variable", "Next", "Assign", "Comment", "And", "Or", "Not")]
RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
FIELDS_JSONPATH_PATHS = {f for spec in FIELDS.values() for f in spec["jsonpath"] if f.endswith("Path")}


def jsonpath_problem(p: str, reference: bool) -> Optional[str]:
    """Return a short description of an obvious JSONPath syntax error, or None (conservative)."""
    quote, depth_b, depth_p, out, i = None, 0, 0, [], 0
    while i < len(p):
        c = p[i]
        if quote:
            if c == "\\":
                out.append("xx")
                i += 2
                continue
            out.append(c if c == quote else "x")
            if c == quote:
                quote = None
        else:
            if c in "'\"":
                quote = c
            elif c == "[":
                depth_b += 1
            elif c == "]":
                depth_b -= 1
                if depth_b < 0:
                    return 'unbalanced "]"'
            elif c == "(":
                depth_p += 1
            elif c == ")":
                depth_p -= 1
                if depth_p < 0:
                    return 'unbalanced ")"'
            out.append(c)
        i += 1
    if quote:
        return f"unclosed {quote} quote"
    if depth_b:
        return 'unbalanced "[" / "]"'
    if depth_p:
        return 'unbalanced "(" / ")"'
    code = "".join(out)
    m = re.match(r"^\$(\$|" + IDENT + r")?", code)
    rest = code[m.end():] if m else code
    if rest and rest[0] not in ".[":
        return f'unexpected "{rest[0]}" after "{code[:len(code) - len(rest)]}" (write "$.field" or "$[\'field\']")'
    if "..." in code:
        return 'empty path segment "..."'
    if code.endswith("."):
        return 'path ends with "." (remove it or add the field name)'
    if re.search(r"\[\s*\]", code):
        return 'empty "[]"'
    if reference:
        for bad, what in (("..", 'deep scan ".."'), ("[?", "filter [?(...)]"), ("*", 'wildcard "*"'), ("@", '"@"'),
                          (",", 'union ","'), (":", 'slice ":"')):
            if bad in code:
                return f"{what} is not allowed in a reference path"
    return None


def check_jsonpath_string(p: Any, loc: str, field: str, diags: Diagnostics, *, reference: bool = False,
                          allow_null: bool = False) -> None:
    if p is None and allow_null:
        return
    if isinstance(p, str) and "__TPL__" in p:
        return
    if not isinstance(p, str) or not p.startswith("$"):
        null = " or null" if allow_null else ""
        diags.error("P012", loc, f'{field} must be a JSONPath string starting with "$" (e.g. "$.field"){null}, got {json.dumps(p)[:60]}')
        return
    if reference and field == "ResultPath" and p.startswith("$$"):
        diags.error("P012", loc, f'{field} cannot write to the context object "$$"; use a path into the state input such as "$.result"')
        return
    if reference and field == "ResultPath" and re.match(r"^\$[A-Za-z_]", p):
        var = re.match(r"^\$(\w+)", p).group(1)
        diags.error("P012", loc, f'variables cannot be used in ResultPath ({json.dumps(p)[:60]}); ResultPath places the result into the state input, '
                    f'e.g. "ResultPath": "$.{var}" - to keep the result in a variable instead use "Assign": {{"{var}.$": "$"}} (in a Task/Map/Parallel Assign "$" is the result, in a Catch Assign the error output)')
        return
    problem = jsonpath_problem(p, reference)
    if problem:
        diags.error("P012", loc, f"{field} {json.dumps(p)[:80]} is not a valid JSONPath: {problem}")


SPLIT_TOKEN_RE = re.compile(r"[\\'()\[\],]")  # the only characters split_intrinsic_args acts on
PAREN_TOKEN_RE = re.compile(r"[\\'()]")


def split_intrinsic_args(src: str) -> Optional[list[str]]:
    """Split a top-level argument list (text between the outer parentheses); None if quotes/parens are unbalanced."""
    args, start, depth, quote, i = [], 0, 0, False, 0
    while True:
        m = SPLIT_TOKEN_RE.search(src, i)  # jump to the next character that matters
        if not m:
            break
        i = m.start()
        c = src[i]
        if quote:
            if c == "\\" and i + 1 < len(src):
                i += 2
                continue
            if c == "'":
                quote = False
        elif c == "'":
            quote = True
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
            if depth < 0:
                return None
        elif c == "," and depth == 0:
            args.append(src[start:i].strip())
            start = i + 1
        i += 1
    if quote or depth:
        return None
    last = src[start:].strip()
    if last or args:
        args.append(last)
    return args


MAX_INTRINSIC_DEPTH = 50


def check_intrinsic(raw: str, loc: str, diags: Diagnostics) -> None:
    """P011 for an intrinsic call and the intrinsic calls nested in its arguments (iterative, in the same order
    as a recursive walk; nesting deeper than MAX_INTRINSIC_DEPTH is reported once and not checked)."""
    work = [(raw, 1)]
    too_deep = False
    while work:
        raw, depth = work.pop()
        if depth > MAX_INTRINSIC_DEPTH:
            if not too_deep:
                too_deep = True
                diags.warn("P011", loc, f"intrinsic calls nested deeper than {MAX_INTRINSIC_DEPTH} levels not checked; "
                           "flatten the expression (compute parts in earlier states, e.g. into variables)")
            continue
        nested = check_one_intrinsic(raw, loc, diags)
        work.extend((a, depth + 1) for a in reversed(nested))


def check_one_intrinsic(raw: str, loc: str, diags: Diagnostics) -> list[str]:
    """Checks one intrinsic call; returns its arguments that are intrinsic calls themselves."""
    if "__TPL__" in raw:
        return []
    s = raw.strip()
    m = re.match(r"^(States\.[A-Za-z0-9_]+)\s*\(", s)
    if not m:
        diags.error("P011", loc, f'{json.dumps(s)[:60]} is not an intrinsic call; write States.<Function>(args), e.g. "States.Format(\'Hello {{}}\', $.name)"')
        return []
    name = m.group(1)
    if name not in INTRINSIC_ARGS:
        close = [k for k in INTRINSIC_ARGS if k.lower() == name.lower() or levenshtein(k.lower(), name.lower(), 3) <= 3]
        hint = f' (did you mean "{close[0]}"?)' if close else ""
        diags.error("P011", loc, f'unknown intrinsic function "{name}"{hint}; valid: {", ".join(sorted(INTRINSIC_ARGS))}')
        return []
    body = s[m.end():]
    # find the matching close parenthesis
    depth, quote, end, i = 1, False, -1, 0
    while True:
        m = PAREN_TOKEN_RE.search(body, i)  # jump to the next character that matters
        if not m:
            break
        i = m.start()
        c = body[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                quote = False
        elif c == "'":
            quote = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
        i += 1
    args = split_intrinsic_args(body[:end]) if end >= 0 else None
    if args is None:
        diags.error("P011", loc, f"{name}(...) has unbalanced parentheses or quotes; string literals use single quotes and "
                    "escape a quote as \\' - e.g. " + INTRINSIC_USAGE[name])
        return []
    if body[end + 1:].strip():
        diags.error("P011", loc, f'unexpected text after {name}(...): {json.dumps(body[end + 1:].strip())[:40]}; the whole value must be one intrinsic call')
    if any(a == "" for a in args):
        diags.error("P011", loc, f"{name}(...) has an empty argument (doubled or trailing comma); usage: {INTRINSIC_USAGE[name]}")
        return []
    lo, hi = INTRINSIC_ARGS[name]
    if len(args) < lo or (hi is not None and len(args) > hi):
        want = f"{lo}" if lo == hi else (f"at least {lo}" if hi is None else f"{lo} to {hi}")
        diags.error("P011", loc, f"{name} takes {want} argument(s) but got {len(args)}; usage: {INTRINSIC_USAGE[name]}")
    if name == "States.Format" and args and args[0].startswith("'"):
        lit, k, holes = args[0][1:-1], 0, 0
        while k < len(lit):
            if lit[k] == "\\":
                k += 2
                continue
            if lit[k:k + 2] == "{}":
                holes += 1
            k += 1
        if holes != len(args) - 1:
            diags.error("P011", loc, f"States.Format template has {holes} '{{}}' placeholder(s) but {len(args) - 1} value argument(s); "
                        "they must match one-to-one, e.g. States.Format('Order {} for {}', $.id, $.name)")
    return [a for a in args if a.startswith("States.")]


def check_jsonpath_rule(rule: Any, rloc: str, nested: bool, diags: Diagnostics) -> None:
    """S021/S022: a JSONPath Choice rule (top-level when nested=False), recursing into And/Or/Not."""
    if not isinstance(rule, dict):
        diags.error("S021", rloc, 'nested Choice rule must be an object such as {"Variable": "$.x", "StringEquals": "a"}')
        return
    if nested:
        for k in ("Next", "Assign"):
            if k in rule:
                diags.error("S022", f"{rloc}/{k}", f"{k} is only allowed on top-level Choices rules, not on rules nested inside And/Or/Not; move it to the enclosing top-level rule")
        allowed = set(CHOICE_RULE_FIELDS["jsonpath"]) - {"Next", "Assign"}
        for k in rule:
            if k not in allowed and k not in ("Next", "Assign"):
                diags.error("S021", f"{rloc}/{k}", f'unknown Choice rule field "{k}"{suggest_field(k, allowed)}')
    ops = [k for k in CHOICE_OPERATORS if k in rule]
    combos = [k for k in ("And", "Or", "Not") if k in rule]
    if "Variable" in rule:
        check_jsonpath_string(rule["Variable"], f"{rloc}/Variable", "Variable", diags, reference=True)
        if combos:
            diags.error("S021", rloc, f"a rule cannot combine Variable with {'/'.join(combos)}; put the comparison inside the {combos[0]} array as its own rule")
        if len(ops) != 1:
            found = ", ".join(ops) or "none"
            diags.error("S021", rloc, f'rule with Variable needs exactly one comparison operator (found: {found}); e.g. {{"Variable": "$.status", "StringEquals": "DONE"}} - combine several with "And": [...]')
    else:
        if ops:
            diags.error("S021", rloc, f'comparison {ops[0]} needs a "Variable": "$.field" in the same rule')
        if not combos and nested and not ops:
            diags.error("S021", rloc, "nested Choice rule needs Variable + one comparison operator, or And/Or/Not")
    if len(combos) > 1:
        diags.error("S021", rloc, f"a rule can have only one of And/Or/Not (found: {', '.join(combos)}); nest them instead")
    for op in ops:
        v, oloc = rule[op], f"{rloc}/{op}"
        if isinstance(v, str) and "__TPL__" in v:
            continue
        if op.endswith("Path"):
            if not isinstance(v, str) or not v.startswith("$"):
                diags.error("S021", oloc, f'{op} compares against another path and needs a string like "$.other"; to compare with a constant use {op[:-4]}')
            else:
                check_jsonpath_string(v, oloc, op, diags, reference=True)
        elif op.startswith("Is"):
            if not isinstance(v, bool) and not is_placeholder(v):
                diags.error("S021", oloc, f"{op} takes a boolean: true or false (not {json.dumps(v)[:30]})")
        elif op.startswith("Boolean"):
            if not isinstance(v, bool) and not is_placeholder(v):
                diags.error("S021", oloc, f"{op} takes a boolean: true or false (not the string {json.dumps(v)[:30]})" if isinstance(v, str) else f"{op} takes a boolean: true or false")
        elif op.startswith("Numeric"):
            if (isinstance(v, bool) or not isinstance(v, (int, float))) and not is_placeholder(v):
                diags.error("S021", oloc, f"{op} takes a JSON number (e.g. 10, not \"10\"); for a string use String{op[7:]}")
        elif op.startswith("Timestamp"):
            if (not isinstance(v, str) or not RFC3339_RE.match(v)) and not is_placeholder(v):
                diags.error("S021", oloc, f'{op} takes an RFC3339 timestamp string, e.g. "2025-01-31T10:00:00Z"')
        elif not isinstance(v, str):
            alt = f"; for numbers use Numeric{op[6:]}" if isinstance(v, (int, float)) and not isinstance(v, bool) and op != "StringMatches" else ""
            diags.error("S021", oloc, f"{op} takes a string (e.g. \"DONE\"){alt}")
    for k in ("And", "Or"):
        if k in rule:
            v = rule[k]
            if not isinstance(v, list) or not v:
                diags.error("S021", f"{rloc}/{k}", f'{k} must be a non-empty array of rules, e.g. "{k}": [{{"Variable": "$.a", "IsPresent": true}}, ...]')
            else:
                for j, sub in enumerate(v):
                    check_jsonpath_rule(sub, f"{rloc}/{k}/{j}", True, diags)
    if "Not" in rule:
        if not isinstance(rule["Not"], dict):
            diags.error("S021", f"{rloc}/Not", 'Not takes a single rule object (not an array), e.g. "Not": {"Variable": "$.a", "StringEquals": "x"}')
        else:
            check_jsonpath_rule(rule["Not"], f"{rloc}/Not", True, diags)


def check_jsonpath_value(key_path: str, key: str, value: Any, loc: str, diags: Diagnostics) -> None:
    """P011/P012 for one key visited by walk_keys in a JSONPath state."""
    if isinstance(value, str) and EXPR_RE.match(value):
        return  # already reported as J001
    if key.endswith(".$") and isinstance(value, str):
        if value.startswith("States."):
            check_intrinsic(value, loc, diags)
        elif value.startswith("$"):
            check_jsonpath_string(value, loc, f'"{key}"', diags)
        return
    if not ("/" not in key_path or re.match(r"^Catch/\d+/ResultPath$", key_path)):
        return
    if key == "ResultPath":
        check_jsonpath_string(value, loc, "ResultPath", diags, reference=True, allow_null=True)
    elif key in ("InputPath", "OutputPath"):
        check_jsonpath_string(value, loc, key, diags, allow_null=True)
    elif key in ("ErrorPath", "CausePath") and isinstance(value, str) and value.startswith("States."):
        check_intrinsic(value, loc, diags)
    elif key.endswith("Path") and key in FIELDS_JSONPATH_PATHS:
        check_jsonpath_string(value, loc, key, diags)



# JSONPath fields whose value is a path that may read a variable ($name / $name.field); ResultPath cannot (AWS docs).
JSONPATH_VAR_FIELD_RE = re.compile(r"^(?:\w+Path|(?:ItemReader/ReaderConfig|ItemBatcher)/\w+Path"
                                   r"|Choices/\d+(?:/(?:And|Or)/\d+|/Not)*/(?:Variable|\w+Path))$")


def jsonpath_var_reads(key_path: str, key: str, value: Any) -> set[str]:
    """Variables read by one JSONPath-state field: "$name", "$name.x" (not "$", "$.x", "$$.x", "$[0]") in a ".$" value,
    a *Path field or a Choice rule Variable / *Path operand; inside intrinsic arguments, quoted 'text $x' is skipped."""
    if not isinstance(value, str) or "__TPL__" in value or key == "ResultPath":
        return set()
    if not (key.endswith(".$") or JSONPATH_VAR_FIELD_RE.match(key_path)):
        return set()
    if value.startswith("States."):
        text = re.sub(r"'(?:\\.|[^'\\])*'", "''", value)
        found = set(re.findall(r"(?<![\w$.])\$(" + IDENT + r")", text))
    else:
        m = re.match(r"\$(" + IDENT + r")", value)
        found = {m.group(1)} if m else set()
    return found - {"states"}  # $states only exists in JSONata states; not a variable that could be assigned


# ---------------------------------------------------------------------------
# Scope: one States object (top level, a Map ItemProcessor, or a Parallel branch)
# ---------------------------------------------------------------------------


SUGGEST_BUDGET = 20_000  # state-name comparisons per file (lint_text call) for S002 "did you mean" hints
_suggest_budget = {"left": SUGGEST_BUDGET}


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
        self.name_set = set(self.names)
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
        if to not in self.name_set and is_placeholder(to):
            self.tpl_target = True  # template placeholder: the real target is unknown, so S002/S003 can't judge it
            return
        if to not in self.name_set:
            elsewhere = ""
            if to in self.all_names:
                elsewhere = f' ("{to}" exists at {self.all_names[to]}, but transitions cannot cross Map/Parallel scope boundaries)'
            else:
                guess = self.closest_state(to, frm)
                if guess:
                    elsewhere = f' (did you mean "{guess}"?)'
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
        if self.start_at is not None and not isinstance(self.start_at, str):
            d.error("S001", f"{re.sub(r'/States$', '', self.location)}/StartAt", 'StartAt must be a state name string, e.g. "StartAt": "FirstState"')
        elif self.start_at is not None and self.start_at not in self.names:
            d.error("S001", f"{re.sub(r'/States$', '', self.location)}/StartAt", f'StartAt "{self.start_at}" is not a state in this scope')

        for st in self.states.values():
            if not isinstance(st, dict):
                continue
            self.scope_assigned |= assign_keys(st.get("Assign"))
            for r in as_list(st.get("Choices")):
                if isinstance(r, dict):
                    self.scope_assigned |= assign_keys(r.get("Assign"))
            for c in as_list(st.get("Catch")):
                if isinstance(c, dict):
                    self.scope_assigned |= assign_keys(c.get("Assign"))
        for v in sorted(self.scope_assigned):
            self.all_assigned.setdefault(v, self.location)
            if v in self.outer_assigned:
                d.error("V004", self.location, f'variable "{v}" is assigned both in this scope and in an enclosing scope; inner scopes cannot reuse outer variable names')

        for name in self.names:
            self.analyse_state(name)

        if isinstance(self.start_at, str) and self.start_at in self.name_set:
            succ: dict[str, list[str]] = {}
            for frm, to, _gen, _via in self.edges:
                succ.setdefault(frm, []).append(to)
            stack = [self.start_at]
            while stack:
                n = stack.pop()
                if n in self.reachable:
                    continue
                self.reachable.add(n)
                for to in succ.get(n, ()):
                    if to not in self.reachable:
                        stack.append(to)
        if not getattr(self, "tpl_target", False):
            self.report_orphans([n for n in self.names if n not in self.reachable and not is_placeholder(n)])
        self.check_termination()

    # -- S002 "did you mean" / S003 orphan roots --------------------------------
    MAX_ORPHAN_LIST = 50  # states named in one S003 message; the rest are counted

    def closest_state(self, to: str, frm: str) -> Optional[str]:
        """The state of this scope that `to` is probably a typo of (never `frm` itself), remembered so that S003 does
        not also report it as unreachable: the typo is the cause."""
        if _suggest_budget["left"] < len(self.names):
            return None
        _suggest_budget["left"] -= len(self.names)
        guess = closest_name(to, [n for n in self.names if n != frm])
        if guess:
            self.__dict__.setdefault("suggested", set()).add(guess)
        return guess

    def report_orphans(self, unreached: list[str]) -> None:
        """S003 once per orphan root (an unreachable state that no other unreachable state transitions to, or the
        first state of an unreachable loop that nothing outside it enters); the states reachable only through a root
        are listed in its message. States named by an S002 "did you mean" (and what follows them) are skipped."""
        if not unreached:
            return
        pending = set(unreached)
        succ: dict[str, list[str]] = {}
        has_pred: set[str] = set()
        for frm, to, _gen, _via in self.edges:
            if frm in pending and to in pending and frm != to:
                succ.setdefault(frm, []).append(to)
                has_pred.add(to)
        covered: set[str] = set()
        order = {n: k for k, n in enumerate(self.names)}

        def claim(root: str) -> list[str]:
            """Mark everything reachable from root (within the unreachable states) as covered; the newly covered states
            other than root, in document order."""
            covered.add(root)
            stack, got = [root], []
            while stack:
                for to in succ.get(stack.pop(), ()):
                    if to not in covered:
                        covered.add(to)
                        got.append(to)
                        stack.append(to)
            return got

        for name in unreached:
            if name in self.__dict__.get("suggested", ()):
                claim(name)
        rest: list[tuple[str, Optional[list[str]], list[str]]] = [  # (root, its loop or None, states through it)
            (n, None, claim(n)) for n in unreached if n not in has_pred and n not in covered]
        left = [n for n in unreached if n not in covered]
        if left:  # unreachable loops: report each loop that nothing outside it enters, at its first state
            left_set = set(left)
            comps = self.sccs(left, {n: [t for t in succ.get(n, ()) if t in left_set] for n in left})
            comp_of = {n: k for k, comp in enumerate(comps) for n in comp}
            entered = {comp_of[t] for n in left for t in succ.get(n, ()) if t in left_set and comp_of[t] != comp_of[n]}
            for k in sorted((k for k in range(len(comps)) if k not in entered), key=lambda k: order[comps[k][0]]):
                if comps[k][0] not in covered:
                    rest.append((comps[k][0], comps[k], claim(comps[k][0])))
        for name, loop, through in sorted(rest, key=lambda r: order[r[0]]):
            members = set(loop or ())
            through = sorted((n for n in through if n not in members), key=lambda n: order[n])
            why = ("nothing transitions to it (orphan)" if loop is None else
                   "only states in its own loop (" + ", ".join(f'"{m}"' for m in loop) + ") transition to it, and no state outside the loop does")
            also = ""
            if through:
                shown = through[:self.MAX_ORPHAN_LIST]
                more = f" and {len(through) - len(shown)} more" if len(through) > len(shown) else ""
                also = f"; also unreachable through it: {', '.join(shown)}{more}"
            fix = ("connect it: point a \"Next\", \"Default\", Choices rule or Catch of a reachable state at it (or StartAt), or delete it"
                   + (" together with the states listed" if through else ""))
            self.diags.error("S003", f"{self.location}/{name}", f'state "{name}" is unreachable: {why}{also}; {fix}')

    # -- termination / loop checks (S016, S017, S018) ---------------------------
    def sccs(self, nodes: list[str], adj: dict[str, list[str]]) -> list[list[str]]:
        """Iterative Tarjan; returns strongly-connected components (members in self.names order)."""
        index: dict[str, int] = {}
        low: dict[str, int] = {}
        on_stack: set[str] = set()
        stack: list[str] = []
        result: list[list[str]] = []
        order = {n: k for k, n in enumerate(self.names)}
        counter = 0
        for root in nodes:
            if root in index:
                continue
            work = [(root, 0)]
            while work:
                v, i = work.pop()
                if i == 0:
                    index[v] = low[v] = counter
                    counter += 1
                    stack.append(v)
                    on_stack.add(v)
                succ = adj.get(v, [])
                if i < len(succ):
                    work.append((v, i + 1))
                    w = succ[i]
                    if w not in index:
                        work.append((w, 0))
                    elif w in on_stack:
                        low[v] = min(low[v], index[w])
                    continue
                if low[v] == index[v]:
                    comp = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp.append(w)
                        if w == v:
                            break
                    result.append(sorted(comp, key=lambda n: order.get(n, 0)))
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[v])
        return result

    def written_outside(self, comp: list[str], target: str) -> bool:
        """Some state outside the loop writes the JSONPath data path `target` (or a parent/child of it) via ResultPath.
        Cached per (loop, target): a loop with many Tasks writing the same path asks the same question many times."""
        cache = self.__dict__.setdefault("_written_outside_cache", {})
        key = (tuple(comp), target)
        if key not in cache:
            cache[key] = self._written_outside(set(comp), target)
        return cache[key]

    def _written_outside(self, comp: set[str], target: str) -> bool:
        for n, st in self.states.items():
            if n in comp or not isinstance(st, dict):
                continue
            rp = st.get("ResultPath", "$")
            m = JSONPATH_DOT_PATH_RE.match(rp) if isinstance(rp, str) else None
            if m and (m.group(1) == target or target.startswith(m.group(1) + ".") or m.group(1).startswith(target + ".")):
                return True
            # a Pass that builds the whole state ("ResultPath": "$" or omitted) with the counter's top-level key in its
            # Result / Parameters: {"iterator": {"count": 10, "index": 0}} or {"iterator": {...}, "data.$": "$"}
            if rp == "$" and st.get("Type") == "Pass":
                top = target.split(".")[0]
                for body in (st.get("Result"), st.get("Parameters")):
                    if isinstance(body, dict) and (top in body or f"{top}.$" in body):
                        return True
        return False

    def counter_loop(self, comp: list[str]) -> bool:
        """S017 guard: some Choice in the loop tests a variable (JSONata $var in a Condition, JSONPath "$var" in
        Variable or a *Path operand) that a state or Choice rule inside the loop updates from its own old value
        (a counter / cursor such as "i": "{% $i + 1 %}" or "i.$": "States.MathAdd($i, 1)"). A variable that is
        merely refreshed from a task result (status polling) does not count.
        The counter may also live in the state data: a Choice tests "$states.input.i" / "$.iterator.index" and a state
        in the loop rewrites that path from its old value (JSONata Output "{% $states.input.i + 1 %}", JSONPath
        "States.MathAdd($.i, 1)" written back by ResultPath, or a Lambda Task that receives the input and writes its result
        over the tested path with ResultPath, as in the AWS "Iterate a loop with a Lambda function" tutorial)."""
        assigned: set[str] = set()
        tested: set[str] = set()
        tested_paths: dict[str, set[str]] = {}  # state-data path ("iterator.index") -> comparison operators used on it

        def add_path(path: str, op: str) -> None:
            tested_paths.setdefault(path, set()).add(op)

        def self_updates(assign: Any) -> set[str]:
            out: set[str] = set()
            for k, v in (assign.items() if isinstance(assign, dict) else []):
                var = k[:-2] if k.endswith(".$") else k
                if not isinstance(v, str):
                    continue
                m = EXPR_RE.match(v)
                reads = analyse_expression(m.group(1)).vars if m else set(JSONPATH_VAR_RE.findall(v)) if k.endswith(".$") else set()
                if var in reads:
                    out.add(var)
            return out

        def rule_vars(rule: Any, jsonata: bool) -> None:
            if isinstance(rule, dict):
                ops = [k for k in CHOICE_OPERATORS if k in rule]
                for k, v in rule.items():
                    if k in ("Next", "Assign", "Output", "Comment"):
                        continue
                    if isinstance(v, str):
                        m = EXPR_RE.match(v)
                        if jsonata and k == "Condition" and m:
                            tested.update(analyse_expression(m.group(1)).vars)
                            for pm in STATES_INPUT_PATH_RE.finditer(m.group(1)):
                                add_path(re.sub(r"\s+", "", pm.group(1)).lstrip("."), "Condition")
                        elif not jsonata and (k == "Variable" or k.endswith("Path")):
                            tested.update(JSONPATH_VAR_RE.findall(v))
                            pm = JSONPATH_DOT_PATH_RE.match(v)
                            if pm:
                                for op in ops or [k]:
                                    add_path(pm.group(1), op)
                    else:
                        rule_vars(v, jsonata)
            elif isinstance(rule, list):
                for r in rule:
                    rule_vars(r, jsonata)

        for n in comp:
            st = self.states.get(n)
            if not isinstance(st, dict):
                continue
            assigned |= self_updates(st.get("Assign"))
            for r in as_list(st.get("Choices")):
                if isinstance(r, dict):
                    assigned |= self_updates(r.get("Assign"))
            if st.get("Type") == "Choice":
                rule_vars(st.get("Choices"), self.state_langs.get(n) == "JSONata")
        if tested & assigned:
            return True

        def covers(prefix: str, path: str) -> bool:
            return path == prefix or path.startswith(prefix + ".")

        for n in comp:
            st = self.states.get(n)
            if not isinstance(st, dict):
                continue
            if self.state_langs.get(n) == "JSONata":
                # Output / Assign that rewrites a tested $states.input path with +/- arithmetic on its old value
                text = json.dumps([st.get("Output"), st.get("Assign")])
                for path in tested_paths:
                    ref = r"\$states\s*\.\s*input\s*\.\s*" + r"\s*\.\s*".join(map(re.escape, path.split("."))) + r"(?![\w.])"
                    if re.search(ref + r"\s*[-+]\s*\d|\d\s*[-+]\s*" + ref, text):
                        return True
                continue
            rp = st.get("ResultPath")
            rpm = JSONPATH_DOT_PATH_RE.match(rp) if isinstance(rp, str) else None
            if not rpm:
                continue
            target = rpm.group(1)
            for path, ops in tested_paths.items():
                if not covers(target, path):
                    continue
                # Pass/Task computing the new value from the old one: States.MathAdd($.i, 1) written back via ResultPath
                text = json.dumps([st.get("Parameters"), st.get("ResultSelector")])
                if re.search(r"States\.MathAdd\(\s*\$\." + re.escape(target) + r"(?![\w])", text):
                    return True
                # Task that receives the old value (whole input, or an InputPath/Parameters containing it) and writes its
                # result over the tested path; only numeric/boolean tests count (StringEquals "DONE" ... is status polling)
                if st.get("Type") != "Task" or not all(op.startswith(("Numeric", "Boolean")) for op in ops):
                    continue
                # a counter is read-modify-write of a value set up before the loop (the tutorial's ConfigureCount writes
                # $.iterator); a status poll writes a fresh field, usually narrowed from the API response by ResultSelector
                if "ResultSelector" in st or not self.written_outside(comp, target):
                    continue
                ip = st.get("InputPath", "$")
                ipm = JSONPATH_DOT_PATH_RE.match(ip) if isinstance(ip, str) else None
                if not (ip == "$" or (ipm and covers(ipm.group(1), target))):
                    continue
                params = st.get("Parameters")
                if params is None or re.search(r'"\$"|"\$\.' + re.escape(target) + r'["\.\[]', json.dumps(params)):
                    return True
        return False

    def check_termination(self) -> None:
        d = self.diags
        reach = [n for n in self.names if n in self.reachable]
        if not reach:
            return

        def stype(n: str) -> Any:
            st = self.states.get(n)
            return st.get("Type") if isinstance(st, dict) else None

        out: dict[str, list[str]] = {n: [] for n in self.names}
        for frm, to, _gen, _via in self.edges:
            out[frm].append(to)
        # S016: states with no path to an explicit exit. States with no valid outgoing edge, or with any
        # target outside this scope, are treated as exits here (already reported by S002/S004).
        def broken_target(st: dict) -> bool:
            targets = [st.get("Next"), st.get("Default")]
            targets += [r.get("Next") for r in as_list(st.get("Choices")) if isinstance(r, dict)]
            targets += [c.get("Next") for c in as_list(st.get("Catch")) if isinstance(c, dict)]
            return any(t is not None and (not isinstance(t, str) or t not in self.states) for t in targets)

        can_exit: set[str] = set()
        for n in self.names:
            st = self.states.get(n)
            if (not isinstance(st, dict) or st.get("Type") in ("Succeed", "Fail") or st.get("End") is True
                    or not out[n] or broken_target(st)):
                can_exit.add(n)
        rev: dict[str, list[str]] = {n: [] for n in self.names}
        for frm, to, _gen, _via in self.edges:
            rev[to].append(frm)
        work = list(can_exit)
        while work:
            n = work.pop()
            for p in rev[n]:
                if p not in can_exit:
                    can_exit.add(p)
                    work.append(p)
        stuck = [n for n in reach if n not in can_exit]
        if stuck:
            stuck_set = set(stuck)
            adj = {n: [t for t in out[n] if t in stuck_set] for n in stuck}
            for comp in self.sccs(stuck, adj):
                first = comp[0]
                if len(comp) > 1:
                    members = ", ".join(f'"{m}"' for m in comp)
                    d.error("S016", f"{self.location}/{first}",
                            f"states {members} form a loop with no way out: no path from them reaches a Succeed/Fail state or a state with \"End\": true, "
                            "so the execution can never finish; add a Choice rule that leaves the loop (e.g. to a Succeed state), or end one of them with \"End\": true")
                else:
                    d.error("S016", f"{self.location}/{first}",
                            f'state "{first}" can never reach a Succeed/Fail state or a state with "End": true, so the execution can never finish; '
                            'add a Choice rule or "Next" that leads to a Succeed/Fail state, or set "End": true on the last state')

        # S017: loops (Next/Choice/Default only) without a Wait state
        flow = {n: [] for n in reach}
        for frm, to, _gen, via in self.edges:
            if via != "Catch" and frm in flow and to in flow:
                flow[frm].append(to)
        for comp in self.sccs(reach, flow):
            if len(comp) == 1 and comp[0] not in flow[comp[0]]:
                continue
            if any(stype(m) == "Wait" for m in comp) or comp[0] not in can_exit:
                continue  # has a Wait, or already reported as an endless loop by S016
            if any(stype(m) == "Choice" and PAGINATION_RE.search(json.dumps(self.states[m].get("Choices"))) for m in comp):
                continue  # pagination loop: each pass fetches the next page, no Wait needed
            if self.counter_loop(comp):
                continue  # bounded loop: a Choice tests a variable that the loop itself updates (e.g. $i < $count($items))
            first = comp[0]
            members = ", ".join(f'"{m}"' for m in comp)
            d.warn("S017", f"{self.location}/{first}",
                   f"loop over {members} has no Wait state: a fast loop burns state transitions and can hit the 25,000 execution-history-event limit. "
                   'If this loop polls an external job, insert a Wait state in it (e.g. {"Type": "Wait", "Seconds": 10, "Next": "<next state>"}) '
                   "and cap the number of polls; if it is a bounded loop (counter/pagination) this warning can be ignored with a reason")

        # S018: Catch that sends the state back to itself without a Wait/Choice in between
        for name in reach:
            st = self.states.get(name)
            if not isinstance(st, dict) or not isinstance(st.get("Catch"), list):
                continue
            for i, c in enumerate(st["Catch"]):
                if not isinstance(c, dict) or not isinstance(c.get("Next"), str) or c["Next"] not in out:
                    continue
                tgt = c["Next"]
                seen: set[str] = set()
                work = [tgt]
                loops = False
                while work:
                    n = work.pop()
                    if n == name:
                        loops = True
                        break
                    if n in seen or stype(n) in ("Wait", "Choice"):
                        continue
                    seen.add(n)
                    work.extend(out[n])
                if loops:
                    how = "itself" if tgt == name else f'itself (via "{tgt}")'
                    d.warn("S018", f"{self.location}/{name}/Catch/{i}/Next",
                           f'Catch sends "{name}" back to {how} with no Wait or Choice in between, so a persistent error retries forever; '
                           'remove this catcher and use "Retry": [{"ErrorEquals": [...], "IntervalSeconds": 2, "MaxAttempts": 3, "BackoffRate": 2}] instead, '
                           "and point Catch at a Fail state or error handler")

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
                d.error("J001", f"{loc}/{k}", f'field "{k}" is {other}-only but this state uses {lang}{jsonata_replacement(k, stype) if is_jsonata else ""}')
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

        for k in ("Parameters", "ResultSelector", "ItemSelector", "Arguments"):
            if k in st and not isinstance(st[k], dict) and not is_expression(st[k]) and not is_placeholder(st[k]) and k in allowed:
                d.error("S009", f"{loc}/{k}", f'{k} must be a JSON object, e.g. "{k}": {{"key": "value"}}'
                        + (' (or a "{% %}" expression)' if is_jsonata else ""))
        if is_jsonata:
            def dollar_keys(key_path: str, key: str, _v: Any) -> None:
                if key.endswith(".$"):
                    d.error("J002", f"{loc}/{key_path}", f'key "{key}" uses the JSONPath ".$" convention; in JSONata drop ".$" and write the value as "{{% ... %}}"')
            walk_keys(st, dollar_keys, ["ItemProcessor", "Iterator", "Branches"])
            check_states_refs(st, loc, d)
        check_assign_names(st, loc, d)

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
                            if not is_jsonata and k == "Output":
                                fix = ("JSONPath Choice rules cannot shape output - remove it "
                                       '(use "OutputPath" on the Choice state, or "Assign" in the rule to keep a value)')
                            elif not is_jsonata:
                                fix = ('use "Variable": "$.field" + one comparison operator, e.g. {"Variable": "$.status", "StringEquals": "DONE", "Next": ...} '
                                       '(or set "QueryLanguage": "JSONata" on this state to keep Condition)')
                            elif k in ("And", "Or", "Not"):
                                expr = {"And": "$states.input.a > 1 and $states.input.b = 'x'", "Or": "$states.input.a > 1 or $states.input.b = 'x'",
                                        "Not": "$not($states.input.status = 'DONE')"}[k]
                                fix = f'write the whole test as one "Condition" expression instead, e.g. "Condition": "{{% {expr} %}}"'
                            else:
                                fix = "replace Variable + comparison operators with one \"Condition\", e.g. \"Condition\": \"{% $states.input.status = 'DONE' %}\""
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
                        elif not is_expression(rule["Condition"]) and not is_placeholder(rule["Condition"]):
                            d.error("J012", f"{rloc}/Condition", 'Condition must be a JSONata expression string "{% ... %}" that evaluates to true or false')
                    elif "Variable" not in rule and not any(k in rule for k in ("And", "Or", "Not")):
                        d.error("S006", rloc, "JSONPath Choice rule needs Variable + comparison, or And/Or/Not")
                    if not is_jsonata:
                        check_jsonpath_rule(rule, rloc, False, d)
            if "Default" not in st:
                d.warn("S006", loc, "Choice has no Default; if no rule matches the execution fails with States.NoChoiceMatched")
            else:
                self.target(name, "Default", st["Default"], assign_keys(st.get("Assign")), "Default")

        if stype == "Wait":
            present = [f for f in ("Seconds", "Timestamp", "SecondsPath", "TimestampPath") if f in st]
            if len(present) != 1:
                opts = "Seconds, Timestamp" + ("" if is_jsonata else ", SecondsPath, TimestampPath")
                d.error("S010", loc, f"Wait needs exactly one of {opts} (found: {', '.join(present) or 'none'})")
            if "Seconds" in st and not is_expression(st["Seconds"]) and not is_placeholder(st["Seconds"]) and not (is_int(st["Seconds"]) and st["Seconds"] >= 0):
                d.error("S010", f"{loc}/Seconds", 'Seconds must be a non-negative integer or a "{% %}" expression evaluating to one')
            if "Timestamp" in st and not is_expression(st["Timestamp"]) and not is_placeholder(st["Timestamp"]) and not RFC3339_RE.match(str(st["Timestamp"])):
                d.error("S010", f"{loc}/Timestamp", 'Timestamp must be RFC3339 with an uppercase T and an uppercase Z or a numeric offset '
                        '(e.g. 2025-01-31T10:00:00Z or 2025-01-31T10:00:00+05:30) or a "{% %}" expression producing one')

        if stype == "Fail":
            if "Error" in st and "ErrorPath" in st:
                d.error("S011", loc, "Fail cannot have both Error and ErrorPath")
            if "Cause" in st and "CausePath" in st:
                d.error("S011", loc, "Fail cannot have both Cause and CausePath")
            for k in ("Error", "Cause", "ErrorPath", "CausePath"):
                if k in st and not isinstance(st[k], str):
                    d.error("S011", f"{loc}/{k}", f'{k} must be a string, e.g. "{k}": ' + ('"$.error"' if k.endswith("Path") else '"OrderFailed"'))

        if stype == "Task":
            res = st.get("Resource")
            if not isinstance(res, str) or not res:
                d.error("S015", f"{loc}/Resource", "Task needs a constant string Resource")
            else:
                if is_expression(res):
                    d.error("S015", f"{loc}/Resource", "Resource must be a constant string, not a JSONata expression")
                if res == "arn:aws:states:::lambda:invoke" and is_jsonata:
                    args = st.get("Arguments")
                    if not is_expression(args) and (not isinstance(args, dict) or "FunctionName" not in args):
                        d.error("S015", f"{loc}/Arguments", "lambda:invoke needs Arguments.FunctionName (and usually Arguments.Payload)")
                    out_str = json.dumps(st.get("Output", "")) + json.dumps(st.get("Assign", ""))
                    if "Output" not in st and "$states.result.Payload" not in out_str:
                        d.info("P001", loc, 'lambda:invoke returns {ExecutedVersion, Payload, StatusCode}; most workflows want "Output": "{% $states.result.Payload %}"')
                if res.endswith(".waitForTaskToken"):
                    s = json.dumps(st.get("Arguments", st.get("Parameters", {})))
                    if "Task.Token" not in s:
                        d.error("S015", loc, '.waitForTaskToken tasks must pass the token: "{% $states.context.Task.Token %}" (JSONata) or "$$.Task.Token" (JSONPath) inside Arguments/Parameters')
                    if not any(f in st for f in ("HeartbeatSeconds", "TimeoutSeconds", "HeartbeatSecondsPath", "TimeoutSecondsPath")):
                        d.warn("P002", loc, ".waitForTaskToken without HeartbeatSeconds or TimeoutSeconds can wait up to one year; "
                               'set "TimeoutSeconds": <seconds>' + ("" if is_jsonata else ' (or "TimeoutSecondsPath": "$.<field>" - never both)'))
            if not is_jsonata:
                for f in ("TimeoutSeconds", "HeartbeatSeconds"):
                    if f in st and f + "Path" in st:
                        d.error("S015", f"{loc}/{f}Path", f"a Task state cannot include both {f} and {f}Path; keep only one of them")
            ts = st.get("TimeoutSeconds")
            if "TimeoutSeconds" in st and not is_expression(ts) and not is_placeholder(ts) and not (is_int(ts) and ts > 0):
                d.error("S015", f"{loc}/TimeoutSeconds", 'TimeoutSeconds must be a positive integer or a "{% %}" expression')
            hb = st.get("HeartbeatSeconds")
            if "HeartbeatSeconds" in st and not is_expression(hb) and not is_placeholder(hb) and not (is_int(hb) and hb > 0):
                d.error("S015", f"{loc}/HeartbeatSeconds", 'HeartbeatSeconds must be a positive integer or a "{% %}" expression')
            if is_int(hb) and is_int(ts) and hb >= ts:
                d.error("S015", f"{loc}/HeartbeatSeconds", "HeartbeatSeconds must be smaller than TimeoutSeconds")
            if isinstance(res, str) and res and not is_expression(res):
                check_task_resource(res, f"{loc}/Resource", d)
                nres = RESOURCE_PLACEHOLDER_RE.sub("__TPL__", res)
                if re.match(r"^arn:[^:]+:states:::lambda:invoke(\.waitForTaskToken)?$", nres) or RESOURCE_LAMBDA_RE.match(nres):
                    rl = st.get("Retry")
                    covered = isinstance(rl, list) and any(
                        isinstance(r, dict) and isinstance(r.get("ErrorEquals"), list) and LAMBDA_TRANSIENT_ERRORS & set(
                            e for e in r["ErrorEquals"] if isinstance(e, str)) for r in rl)
                    if not covered and (rl is None or isinstance(rl, list)):
                        d.info("P005", loc, "Lambda tasks should retry transient Lambda service errors; add this as the first "
                               f'"Retry" entry: {LAMBDA_RETRY_SNIPPET}')

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
                if "MaxAttempts" in r and not is_placeholder(r["MaxAttempts"]) and not (is_int(r["MaxAttempts"]) and r["MaxAttempts"] >= 0):
                    d.error("S012", f"{rloc}/MaxAttempts", "MaxAttempts must be a non-negative integer")
                if "IntervalSeconds" in r and not is_placeholder(r["IntervalSeconds"]) and not (is_int(r["IntervalSeconds"]) and r["IntervalSeconds"] > 0):
                    d.error("S012", f"{rloc}/IntervalSeconds", "IntervalSeconds must be a positive integer")
                br = r.get("BackoffRate")
                if "BackoffRate" in r and not is_placeholder(br) and not (isinstance(br, (int, float)) and not isinstance(br, bool) and br >= 1):
                    d.error("S012", f"{rloc}/BackoffRate", "BackoffRate must be a number >= 1.0")
                if "JitterStrategy" in r and r["JitterStrategy"] not in ("FULL", "NONE") and not is_placeholder(r["JitterStrategy"]):
                    d.error("S012", f"{rloc}/JitterStrategy", 'JitterStrategy must be "FULL" or "NONE"')
                ee = r.get("ErrorEquals")
                # Only States.Runtime: AWS docs say States.DataLimitExceeded CAN be retried/caught when named explicitly.
                for term in ("States.Runtime",):
                    if isinstance(ee, list) and term in ee:
                        fix = "it always fails the execution, so fix the cause (e.g. a path applied to a null payload)"
                        d.warn("P003", f"{rloc}/ErrorEquals", f"{term} is a terminal error and is never retried; remove it from Retry - {fix}")
                if "MaxDelaySeconds" in r:
                    mds = r["MaxDelaySeconds"]
                    if not (is_int(mds) and 0 < mds < 31622401) and not is_placeholder(mds):
                        d.error("P004", f"{rloc}/MaxDelaySeconds", "MaxDelaySeconds must be a positive integer number of seconds "
                                "(1 to 31622400), e.g. \"MaxDelaySeconds\": 30")
                    elif br == 1 and not isinstance(br, bool):  # absent BackoffRate defaults to 2.0, which is fine
                        d.warn("P004", f"{rloc}/MaxDelaySeconds", "MaxDelaySeconds caps an exponential backoff, but BackoffRate is "
                               '1.0 so the interval never grows; set "BackoffRate": 2 or remove MaxDelaySeconds')
        elif "Retry" in st and not is_placeholder(retry):
            d.error("S012", f"{loc}/Retry", 'Retry must be an array of retriers, e.g. "Retry": [{"ErrorEquals": ["States.ALL"], "MaxAttempts": 3}]')

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
        elif "Catch" in st and not is_placeholder(catch):
            d.error("S012", f"{loc}/Catch", 'Catch must be an array of catchers, e.g. "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "HandleError"}]')

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
                if "ProcessorConfig" in proc and not isinstance(proc["ProcessorConfig"], dict) and not is_placeholder(proc["ProcessorConfig"]):
                    d.error("S013", f"{loc}/ItemProcessor/ProcessorConfig", 'ProcessorConfig must be an object, e.g. "ProcessorConfig": {"Mode": "INLINE"}')
                mode = cfg.get("Mode", "INLINE") if isinstance(cfg, dict) else "INLINE"
                if mode not in ("INLINE", "DISTRIBUTED") and not is_placeholder(mode):
                    d.error("S013", f"{loc}/ItemProcessor/ProcessorConfig/Mode", "Mode must be INLINE or DISTRIBUTED")
                if mode == "DISTRIBUTED" and (not isinstance(cfg, dict) or cfg.get("ExecutionType") not in ("STANDARD", "EXPRESS") and not is_placeholder(cfg.get("ExecutionType"))):
                    d.error("S013", f"{loc}/ItemProcessor/ProcessorConfig", 'DISTRIBUTED mode requires ExecutionType "STANDARD" or "EXPRESS"')
                if mode == "INLINE" and any(f in st for f in ("ItemReader", "ResultWriter", "ItemBatcher", "ToleratedFailureCount", "ToleratedFailurePercentage", "Label")):
                    d.error("S013", loc, 'ItemReader, ResultWriter, ItemBatcher, ToleratedFailure* and Label are only valid with ProcessorConfig.Mode "DISTRIBUTED"')
                if is_jsonata and "Items" not in st and "ItemReader" not in st:
                    d.info("S013", loc, 'JSONata Map without Items iterates the state input itself; if the state input is not itself the array, set "Items": "{% $states.input.<array> %}"')
                items = st.get("Items")
                if is_jsonata and "Items" in st and not is_expression(items) and not is_placeholder(items) and not isinstance(items, (list, dict)):
                    d.error("S013", f"{loc}/Items", 'Items must be a JSON array/object or a "{% %}" expression evaluating to one')
                if not is_jsonata:
                    for f in ("MaxConcurrency", "ToleratedFailureCount", "ToleratedFailurePercentage"):
                        if f in st and f + "Path" in st:
                            d.error("S013", f"{loc}/{f}Path", f"a Map state cannot include both {f} and {f}Path; keep only one of them")
                mc = st.get("MaxConcurrency")
                if mc is not None and not is_expression(mc) and not is_placeholder(mc) and not (is_int(mc) and mc >= 0):
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

    def pass_assign_foldable(self, name: str, st: dict) -> bool:
        """V005 guard: True only when moving this Pass's Assign into its single predecessor keeps its meaning.
        Not foldable when the Pass reshapes data (JSONPath Parameters/Result/*Path), reads its input or the context
        ($states / "$." / "$$." - the predecessor would see its own input instead), or reads a variable that the
        predecessor assigns (Assign values are evaluated with the variables' old values)."""
        ps = self.preds.get(name, [])
        if len(ps) != 1:
            return False
        pred_name, via = ps[0]
        pred = self.states.get(pred_name)
        lang = self.state_langs.get(name)
        if not isinstance(pred, dict) or self.state_langs.get(pred_name) != lang:
            return False
        if lang != "JSONata" and any(k in st for k in ("Parameters", "Result", "InputPath", "OutputPath", "ResultPath")):
            return False
        pred_assigned = assign_keys(pred.get("Assign"))
        if via == "Choice":
            for r in as_list(pred.get("Choices")):
                if isinstance(r, dict) and r.get("Next") == name:
                    pred_assigned |= assign_keys(r.get("Assign"))
        pred_assigned = {k[:-2] if k.endswith(".$") else k for k in pred_assigned}
        reads: set[str] = set()

        def scan(key: str, v: Any) -> bool:
            if isinstance(v, dict):
                return all(scan(k, x) for k, x in v.items())
            if isinstance(v, list):
                return all(scan(key, x) for x in v)
            if not isinstance(v, str):
                return True
            if lang == "JSONata":
                if "{%" not in v and "%}" not in v:
                    return True
                m = EXPR_RE.match(v)
                if not m or re.search(r"\$states(?![\wÀ-￿])", strip_literals(m.group(1))):
                    return False
                reads.update(analyse_expression(m.group(1)).vars)
                return True
            if not key.endswith(".$"):
                return True
            if re.search(r"\$(?![A-Za-z_À-￿])", v):  # "$", "$.x", "$[...]", "$$.x": state input / context
                return False
            reads.update(JSONPATH_VAR_RE.findall(v))
            return True

        return scan("Assign", st.get("Assign")) and not (reads & pred_assigned)

    # -- definite assignment dataflow ---------------------------------------
    def dataflow(self, entry: set[str]) -> dict[str, Optional[set[str]]]:
        """IN[s] = intersection over incoming edges of (IN[pred] | gen(edge)). None = not yet reached."""
        IN: dict[str, Optional[set[str]]] = {n: None for n in self.names}
        if not isinstance(self.start_at, str) or self.start_at not in self.name_set:
            return IN
        IN[self.start_at] = set(entry)
        # IN only shrinks from "unreached" (None = everything), so any evaluation order reaches the same greatest
        # fixpoint. Worklist in reverse postorder from StartAt: one pass for an acyclic flow, whatever the
        # order of the States object; each re-evaluation only reads the state's own incoming edges.
        incoming: dict[str, list[tuple[str, set[str]]]] = {}
        succ: dict[str, list[str]] = {}
        for frm, to, gen, _via in self.edges:
            incoming.setdefault(to, []).append((frm, gen))
            succ.setdefault(frm, []).append(to)
        post: list[str] = []
        seen = {self.start_at}
        dfs = [(self.start_at, iter(succ.get(self.start_at, ())))]
        while dfs:
            n, it = dfs[-1]
            for t in it:
                if t not in seen:
                    seen.add(t)
                    dfs.append((t, iter(succ.get(t, ()))))
                    break
            else:
                dfs.pop()
                post.append(n)
        import heapq
        rank = {n: k for k, n in enumerate(reversed(post))}
        heap = sorted(rank[t] for t in set(succ.get(self.start_at, ())) if t != self.start_at)
        queued = set(heap)
        order = list(reversed(post))
        while heap:
            k = heapq.heappop(heap)
            queued.discard(k)
            n = order[k]
            acc: Optional[set[str]] = None
            for frm, gen in incoming.get(n, ()):
                if IN[frm] is None:
                    continue
                # sets in IN are never modified in place, so a state without Assign can share its predecessor's set
                out = IN[frm] | gen if gen else IN[frm]  # type: ignore[operator]
                acc = out if acc is None else (acc & out)
            if acc is None or IN[n] is acc or IN[n] == acc:
                continue
            IN[n] = acc
            for t in succ.get(n, ()):
                if t != self.start_at and rank[t] not in queued:
                    queued.add(rank[t])
                    heapq.heappush(heap, rank[t])
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
                    if isinstance(st.get(f), str) and not is_expression(st[f]) and not is_placeholder(st[f]):
                        d.error("J003", f"{loc}/{f}", f'{f} is a plain string; use a number or a "{{% %}}" expression')
            else:
                def jp(key_path: str, key: str, value: Any) -> None:
                    if key.endswith(".$") and not isinstance(value, str):
                        d.error("P010", f"{loc}/{key_path}", f'"{key}" ends with ".$" so its value must be a JSONPath or intrinsic string '
                                f'(e.g. "$.x"); for a literal value drop ".$" from the key: "{key[:-2]}"')
                    if key.endswith(".$") and isinstance(value, str) and not re.match(r"^\$|^States\.", value):
                        d.error("P010", f"{loc}/{key_path}", f'"{key}" must be a JSONPath ("$.x", "$$.x", "$var") or an intrinsic ("States.Format(...)")')
                    if isinstance(value, str) and EXPR_RE.match(value):
                        d.error("J001", f"{loc}/{key_path}", 'JSONata "{% %}" expression inside a JSONPath state; set "QueryLanguage": "JSONata" on this state or the state machine')
                    check_jsonpath_value(key_path, key, value, f"{loc}/{key_path}", d)
                    check_variable_reads(jsonpath_var_reads(key_path, key, value), f"{loc}/{key_path}", in_vars=in_vars,
                                         ever_assigned=ever_assigned, all_assigned=self.all_assigned,
                                         outer_for_distributed=outer_for_distributed if self.distributed else None,
                                         diags=d, jsonata_hints=False)
                walk_keys(st, jp, ["ItemProcessor", "Iterator", "Branches"])

            if st.get("Type") == "Pass" and st.get("Assign") and "Output" not in st and name != self.start_at \
                    and self.pass_assign_foldable(name, st):
                ps = self.preds.get(name, [])
                if len(ps) == 1 and ps[0][1] == "Next" and (self.states.get(ps[0][0]) or {}).get("Type") in ASSIGN_ALLOWED:
                    d.warn("V005", loc, f'Pass state only assigns variables; fold its Assign into the previous state "{ps[0][0]}" '
                           "(Assign runs after that state's result is known) and delete this Pass")
                elif len(ps) == 1 and ps[0][1] == "Choice":
                    d.warn("V005", loc, f'Pass state only assigns variables after a Choice; put the Assign inside the matching Choices rule of "{ps[0][0]}" instead')

        for parent_name, child in self.children:
            parent_in = IN.get(parent_name) or set(entry)
            if child.distributed:
                # a variable the child assigns itself is its own (V004 reports the name clash), not an outer read
                child.finish(set(), (parent_in | self.outer_assigned | self.scope_assigned) - child.scope_assigned)
            else:
                child.finish(parent_in, None)


def check_task_resource(res: str, loc: str, diags: Diagnostics) -> None:
    """S019: Task Resource ARN shape, partition, integration suffix and aws-sdk action casing."""
    norm = RESOURCE_PLACEHOLDER_RE.sub("__TPL__", res)
    if "__TPL__" in norm and not norm.startswith("arn:"):
        return
    shapes = ('use one of: "arn:aws:states:::<service>:<action>" (optimized, e.g. "arn:aws:states:::lambda:invoke"), '
              '"arn:aws:states:::aws-sdk:<service>:<camelCaseAction>" (e.g. "arn:aws:states:::aws-sdk:s3:getObject"), '
              '"arn:aws:states:::http:invoke", "arn:aws:lambda:<region>:<account>:function:<name>" or '
              '"arn:aws:states:<region>:<account>:activity:<name>"')
    parts = norm.split(":")
    if len(parts) > 1 and parts[0] == "arn" and parts[1] not in ARN_PARTITIONS and "__TPL__" not in parts[1]:
        diags.warn("S019", loc, f'unknown ARN partition "{parts[1]}"; known partitions: {", ".join(ARN_PARTITIONS)} '
                   '- most workflows use "aws", e.g. "arn:aws:states:::lambda:invoke"')
        return
    if RESOURCE_LAMBDA_RE.match(norm) or RESOURCE_ACTIVITY_RE.match(norm):
        return
    m = RESOURCE_INTEGRATION_RE.match(norm)
    if not m:
        hint = ""
        if re.match(r"^arn:[^:]+:states:", norm):
            hint = ('; service integrations have an empty region and account, i.e. three colons after "states": '
                    f'"arn:{parts[1]}:states:::<service>:<action>"')
        diags.error("S019", loc, f"Task Resource {json.dumps(res)} is not a valid Task ARN{hint}; {shapes}")
        return
    service, rest = m.group(2), m.group(3)
    suffix = next((s for s in RESOURCE_SUFFIXES if rest.endswith(s)), "")
    rest = rest[:len(rest) - len(suffix)]
    sdk_service = ""
    if service == "aws-sdk":
        sm = re.match(r"^([^:]+):([^:]+)$", rest)
        if not sm:
            diags.error("S019", loc, f'Task Resource {json.dumps(res)}: aws-sdk integrations need exactly '
                        '"arn:aws:states:::aws-sdk:<service>:<camelCaseAction>", e.g. "arn:aws:states:::aws-sdk:s3:getObject"')
            return
        sdk_service, rest = sm.group(1), sm.group(2)
    if not re.match(r"^[a-z0-9-]+$", service.replace("__TPL__", "x")) or (sdk_service and not re.match(r"^[a-z0-9-]+$", sdk_service.replace("__TPL__", "x"))) \
            or not re.match(r"^[A-Za-z][A-Za-z0-9]*$", rest.replace("__TPL__", "x")):
        diags.error("S019", loc, f"Task Resource {json.dumps(res)} is malformed (service names are lowercase, the action is a single "
                    f"camelCase word, optional suffix .sync, .sync:2 or .waitForTaskToken); {shapes}")
        return
    if sdk_service and rest[0].isupper():
        fixed = rest[0].lower() + rest[1:]
        diags.error("S019", loc, f'aws-sdk action names are camelCase with a lowercase first letter: use '
                    f'"{res.replace(":" + rest, ":" + fixed, 1)}" ("{fixed}", not "{rest}")')
    if not suffix:
        return
    key = f"{service}:{rest}"
    base = res[:len(res) - len(suffix)]
    if suffix == ".sync:2" and key != "states:startExecution":
        diags.error("S019", loc, f'".sync:2" is only valid on "arn:aws:states:::states:startExecution.sync:2"; for {key} use '
                    f'"{base}" or "{base}.sync" if the service supports the Run a Job pattern')
    elif service == "aws-sdk" and suffix.startswith(".sync"):
        diags.error("S019", loc, f'AWS SDK integrations do not support "{suffix}"; use "{base}" (request-response) and poll the job '
                    "status with a Wait + Choice loop, or use the optimized integration (e.g. ecs:runTask.sync, glue:startJobRun.sync) if one exists")
    else:
        supported = INTEGRATION_SUFFIXES.get(key, INTEGRATION_SUFFIXES.get(f"{service}:*"))
        if supported is not None and suffix not in supported:
            ok = ", ".join(sorted(supported)) or "none"
            what = ("it already waits for the call to finish" if suffix.startswith(".sync") else "it has no callback pattern")
            diags.error("S019", loc, f'{key} does not support "{suffix}" (supported suffixes: {ok}); use "{base}" - {what}')


def check_express_mode(definition: dict, diags: Diagnostics) -> None:
    """S020: features that Express workflows do not support."""
    ts = definition.get("TimeoutSeconds")
    if is_int(ts) and ts > 300:
        diags.warn("S020", "/TimeoutSeconds", f"Express workflows run for at most 300 seconds (5 minutes), so TimeoutSeconds {ts} "
                   'is never reached; set "TimeoutSeconds": 300 or less, or create the state machine as STANDARD')

    def walk(states: Any, base: str) -> None:
        if not isinstance(states, dict):
            return
        for name, st in states.items():
            if not isinstance(st, dict):
                continue
            loc = f"{base}/{name}"
            res = st.get("Resource")
            if st.get("Type") == "Task" and isinstance(res, str) and not is_expression(res):
                m = re.search(r"\.(sync(?::2)?|waitForTaskToken)$", res)
                if m and m.group(1).startswith("sync"):
                    diags.error("S020", f"{loc}/Resource", f'Express workflows do not support ".{m.group(1)}" (Run a Job); use '
                                f'"{res[:m.start()]}" (request-response) and poll with a Wait + Choice loop, or make the state machine STANDARD')
                elif m:
                    diags.error("S020", f"{loc}/Resource", 'Express workflows do not support ".waitForTaskToken" (callback); use '
                                f'"{res[:m.start()]}" (request-response), or make the state machine STANDARD')
                if RESOURCE_ACTIVITY_RE.match(RESOURCE_PLACEHOLDER_RE.sub("__TPL__", res)):
                    diags.error("S020", f"{loc}/Resource", "Express workflows do not support activities; call the worker through "
                                '"arn:aws:states:::lambda:invoke" (or another integration), or make the state machine STANDARD')
            if st.get("Type") == "Map":
                key = "ItemProcessor" if "ItemProcessor" in st else "Iterator"
                proc = st.get(key)
                if isinstance(proc, dict):
                    cfg = proc.get("ProcessorConfig")
                    if isinstance(cfg, dict) and cfg.get("Mode") == "DISTRIBUTED":
                        diags.error("S020", f"{loc}/{key}/ProcessorConfig/Mode", 'Express workflows do not support Distributed Map; '
                                    'use "ProcessorConfig": {"Mode": "INLINE"} (max 40 concurrent iterations) or make the parent '
                                    'state machine STANDARD (its children can still run as "ExecutionType": "EXPRESS")')
                    walk(proc.get("States"), f"{loc}/{key}/States")
            if st.get("Type") == "Parallel" and isinstance(st.get("Branches"), list):
                for i, b in enumerate(st["Branches"]):
                    if isinstance(b, dict):
                        walk(b.get("States"), f"{loc}/Branches/{i}/States")

    walk(definition.get("States"), "/States")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def lint_definition(definition: dict, diags: Diagnostics, jsonata=None, execution_type: str = "STANDARD") -> None:
    definition = clip_depth(definition, diags)
    top_lang = definition.get("QueryLanguage", "JSONPath")
    if top_lang not in ("JSONPath", "JSONata"):
        diags.error("S000", "/QueryLanguage", f'QueryLanguage must be "JSONPath" or "JSONata", got {json.dumps(top_lang)}')
    for k in definition:
        if k not in ("Comment", "StartAt", "States", "Version", "TimeoutSeconds", "QueryLanguage"):
            diags.error("S000", f"/{k}", f'unknown top-level field "{k}"')
    ts = definition.get("TimeoutSeconds")
    if "TimeoutSeconds" in definition and not is_placeholder(ts) and not (is_int(ts) and ts > 0):
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
    check_unused_variables(definition, diags)
    if execution_type == "EXPRESS":
        check_express_mode(definition, diags)


JSONPATH_VAR_RE = re.compile(r"(?<![\w$])\$(" + IDENT + r")")


def check_unused_variables(definition: dict, diags: Diagnostics) -> None:
    """V006: a variable assigned somewhere but read nowhere (by name, machine-wide)."""
    first_assign: dict[str, str] = {}
    reads: set[str] = set()

    def scan_states(states: Any, location: str) -> None:
        if not isinstance(states, dict):
            return
        for name, st in states.items():
            if not isinstance(st, dict):
                continue
            loc = f"{location}/{name}"
            spots = [(f"{loc}/Assign", st.get("Assign"))]
            spots += [(f"{loc}/Choices/{i}/Assign", r.get("Assign")) for i, r in enumerate(as_list(st.get("Choices"))) if isinstance(r, dict)]
            spots += [(f"{loc}/Catch/{i}/Assign", c.get("Assign")) for i, c in enumerate(as_list(st.get("Catch"))) if isinstance(c, dict)]
            for aloc, assign in spots:
                for k in sorted(assign if isinstance(assign, dict) else ()):
                    var = k[:-2] if k.endswith(".$") else k
                    if valid_var_name(var):  # malformed names are reported by V007 (with a rename); don't guess
                        first_assign.setdefault(var, f"{aloc}/{k}")
            for key in ("ItemProcessor", "Iterator"):
                if isinstance(st.get(key), dict):
                    scan_states(st[key].get("States"), f"{loc}/{key}/States")
            for i, b in enumerate(as_list(st.get("Branches"))):
                if isinstance(b, dict):
                    scan_states(b.get("States"), f"{loc}/Branches/{i}/States")

    def scan_reads(v: Any, key: str) -> bool:
        """Collect variable reads from every string; False if some expression could not be analysed."""
        if isinstance(v, dict):
            return all(scan_reads(x, k) for k, x in v.items() if k != "Comment" or is_expression(x))
        if isinstance(v, list):
            return all(scan_reads(x, key) for x in v)
        if not isinstance(v, str):
            return True
        if "{%" in v or "%}" in v:
            m = EXPR_RE.match(v)
            if not m:
                return not v.lstrip().startswith("{%")  # literal text ("<p>{% raw %}</p>") is never evaluated
            a = analyse_expression(m.group(1))
            reads.update(a.vars | a.bound | a.calls | a.func_refs)
        elif key.endswith(".$") or key.endswith("Path") or key == "Variable":
            reads.update(JSONPATH_VAR_RE.findall(v))
        return True

    scan_states(definition.get("States"), "/States")
    if not first_assign or not scan_reads(definition, ""):
        return
    suggested = {m.group(1) for it in diags.items if it["code"] == "V001"
                 for m in re.finditer(r"\(did you mean \$(" + IDENT + r")\?\)", it["message"])}
    for var, loc in first_assign.items():
        if var not in reads and var != "states" and var not in suggested:
            diags.warn("V006", loc, f'variable ${var} is assigned here but never read anywhere in the state machine; delete the "{var}" '
                       f"entry from this Assign (or, if a later state needs it, reference it there as ${var})")


TERRAFORM_HCL_HINT = (
    "Terraform jsonencode({...}) is HCL, not JSON, so it cannot be linted from the .tf file. Render the definition to JSON "
    "and pipe it to the linter: terraform plan -out=tfplan && terraform show -json tfplan | python3 -c \"import sys,json;"
    "m=json.load(sys.stdin)['planned_values']['root_module'];print([r['values']['definition'] for r in m.get('resources',[]) "
    "if r['type']=='aws_sfn_state_machine'][0])\" | python3 lint_asl.py -   (or, once applied: echo "
    "'aws_sfn_state_machine.<name>.definition' | terraform console | python3 lint_asl.py -  - the printed quoted string is accepted). "
    "Simplest long-term fix: keep the definition in a .asl.json file loaded with templatefile() and lint that file directly")
CLOUDFORMATION_YAML_HINT = (
    "the definition is a YAML mapping (CloudFormation/SAM Definition or DefinitionBody, Serverless definition), which this "
    "stdlib-only linter cannot parse; only a JSON string (DefinitionString: |, or !Sub |) is extracted from YAML. Convert the "
    "template to JSON and lint that (the definition is found inside it): python3 -c \"import sys,json,yaml;"
    "yaml.SafeLoader.add_multi_constructor('!',lambda l,s,n:n.value if s=='Sub' and isinstance(n.value,str) else '__TPL__');print(json.dumps(yaml.safe_load(open(sys.argv[1]))))\" "
    "template.yaml | python3 lint_asl.py -   (needs PyYAML: pip install pyyaml), or: cfn-flip template.yaml template.json && "
    "python3 lint_asl.py template.json, or lint the synthesized JSON template (cdk synth --json / sam build output)")


def nothing_found_message(text: str, filename: Optional[str]) -> str:
    """Why no definition was found, with the exact way to get something lintable."""
    if not text.strip():
        return "the input is empty; nothing to lint (pass the state machine definition JSON, or a file that embeds it)"
    if "jsonencode(" in text:
        return TERRAFORM_HCL_HINT
    yamlish = (filename or "").lower().endswith((".yaml", ".yml", ".template"))
    # [^\S\n] (whitespace but not a newline), not \s: with re.M a leading \s* runs over every following blank line
    # from each line start, O(n^2) on a file of blank lines
    if (re.search(r"^[^\S\n]*(?:definition|definitionbody)[^\S\n]*:[^\S\n]*(?:#.*)?$", text, re.M | re.I)
            or (yamlish and re.search(r"^[^\S\n]*States[^\S\n]*:", text, re.M))):
        return CLOUDFORMATION_YAML_HINT
    return ('no state machine definition found: the input is not JSON and contains no embedded JSON object with "StartAt" and '
            '"States"; pass the definition JSON file (or pipe it to: python3 lint_asl.py -)')


# ---------------------------------------------------------------------------
# Diagnostic codes (--list-codes, --explain, SARIF rules)
# ---------------------------------------------------------------------------
# CODES: every code the linter emits -> (usual severity, title, fix recipe with a tiny before/after example).
# Some codes are also emitted with another severity for milder cases; the message always says what to do.
# Keep this one block, sorted by code: new codes (e.g. S040-S059) are added here.
CODES: dict[str, tuple[str, str, str]] = {
    "J000": ("ERROR", "query language of the state machine",
             'A JSONata state machine (top-level "QueryLanguage": "JSONata") cannot contain JSONPath states; the INFO variant only '
             'recommends JSONata for new machines. Remove the per-state "QueryLanguage": "JSONPath" and convert that state\'s '
             'fields. Before: {"Type": "Pass", "QueryLanguage": "JSONPath", "Parameters": {"id.$": "$.id"}, "End": true} '
             'After: {"Type": "Pass", "Output": {"id": "{% $states.input.id %}"}, "End": true}'),
    "J001": ("ERROR", "field belongs to the other query language",
             "JSONata states use Arguments, Output, Assign and Condition; JSONPath states use Parameters, InputPath, ResultSelector, "
             "ResultPath, OutputPath and Variable rules. Replace the field with its equivalent (the message names it). "
             'Before (JSONata): "Parameters": {"FunctionName": "f"}, "ResultPath": "$.r" '
             'After: "Arguments": {"FunctionName": "f"}, "Output": {"r": "{% $states.result %}"}'),
    "J002": ("ERROR", '".$" key in a JSONata state',
             'In JSONata the ".$" suffix does nothing; drop it and write the value as a {% %} expression. '
             'Before: "Arguments": {"id.$": "$.id"}  After: "Arguments": {"id": "{% $states.input.id %}"}'),
    "J003": ("ERROR", "malformed {% %} expression or plain string",
             'A JSONata value is either a JSON literal or one string that starts with "{%" and ends with "%}". A number field '
             'takes a number, not a string. Before: "Seconds": "10", "Output": "{% $x"  After: "Seconds": 10, "Output": "{% $x %}"'),
    "J004": ("ERROR", "$states.result / $states.errorOutput used where it is not set",
             "$states.result exists only in Output and Assign of Task, Map and Parallel states; $states.errorOutput only inside a "
             'Catch (Output/Assign). Before: "Arguments": {"r": "{% $states.result %}"}  After: move it to the Output of the '
             'state that produced it: "Output": {"r": "{% $states.result %}"}'),
    "J005": ("ERROR", "unknown JSONata function",
             "Use a JSONata 2.0.6 or Step Functions function (the message suggests the closest one). "
             'Before: "{% $toUpper($name) %}"  After: "{% $uppercase($name) %}"'),
    "J006": ("ERROR", "JSONata syntax error",
             "The expression does not parse (reported only when jsonata-python is installed). Fix the syntax at the position "
             'given. Before: "{% $sum($states.input.items.price %}"  After: "{% $sum($states.input.items.price) %}"'),
    "J007": ("ERROR", "invalid JSONata operator",
             "JSONata uses = and != for comparison, and/or for logic, & to join strings. "
             'Before: "{% $a == 1 && $b %}"  After: "{% $a = 1 and $b %}"'),
    "J008": ("ERROR", "intrinsic function in a JSONata expression",
             "States.Format, States.ArrayLength, ... are JSONPath-only; use the JSONata equivalent. "
             'Before: "{% States.Format(\'Hi {}\', $name) %}"  After: "{% \'Hi \' & $name %}"'),
    "J009": ("ERROR", "JSONPath syntax inside a JSONata expression",
             "$$. (context) and $.field (input) are JSONPath; in JSONata use $states.context and $states.input. "
             'Before: "{% $$.Execution.Id %}", "{% $.id %}"  After: "{% $states.context.Execution.Id %}", "{% $states.input.id %}"'),
    "J012": ("ERROR", "Choice Condition is not a {% %} expression",
             "A JSONata Choice rule needs a Condition expression that evaluates to true or false. "
             'Before: {"Condition": "$.ok", "Next": "A"}  After: {"Condition": "{% $states.input.ok %}", "Next": "A"}'),
    "J013": ("ERROR", "unknown $states field or context field",
             "$states has only input, result, errorOutput and context; context fields follow the Step Functions context object. "
             'Before: "{% $states.inputs.id %}"  After: "{% $states.input.id %}"'),
    "J014": ("ERROR", "wrong number of arguments to a JSONata function",
             "Call the function with the arguments it takes (the message gives an example). "
             'Before: "{% $substring($s) %}"  After: "{% $substring($s, 0, 3) %}"'),
    "P001": ("INFO", "lambda:invoke output is wrapped",
             "lambda:invoke returns {ExecutedVersion, Payload, StatusCode}; usually only Payload is wanted. "
             'Before: no Output  After: "Output": "{% $states.result.Payload %}" (JSONPath: "OutputPath": "$.Payload")'),
    "P002": ("WARNING", "callback task without a timeout",
             ".waitForTaskToken tasks wait up to one year unless a timeout is set. "
             'Before: {"Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken", ...}  After: add '
             '"TimeoutSeconds": 3600, "HeartbeatSeconds": 300'),
    "P003": ("WARNING", "terminal error listed in Retry",
             "Some errors (e.g. States.Runtime, States.DataLimitExceeded) are never retried; remove them from Retry and handle "
             'them with Catch. Before: "Retry": [{"ErrorEquals": ["States.Runtime"]}]  After: "Catch": [{"ErrorEquals": '
             '["States.Runtime"], "Next": "HandleError"}]'),
    "P004": ("ERROR", "MaxDelaySeconds misuse",
             "MaxDelaySeconds must be a positive integer and only caps an exponential backoff (BackoffRate > 1). "
             'Before: {"ErrorEquals": ["States.ALL"], "MaxDelaySeconds": 0}  After: {"ErrorEquals": ["States.ALL"], '
             '"BackoffRate": 2, "MaxDelaySeconds": 30}'),
    "P005": ("INFO", "Lambda task without a retry for transient errors",
             "Add the retrier shown in the message as the first entry of Retry. Before: no Retry  After: "
             '"Retry": [{"ErrorEquals": ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", '
             '"Lambda.TooManyRequestsException"], "IntervalSeconds": 1, "MaxAttempts": 3, "BackoffRate": 2, "JitterStrategy": "FULL"}]'),
    "P010": ("ERROR", '".$" key without a path value',
             'A key ending in ".$" takes a JSONPath ("$.x", "$$.x", "$var") or an intrinsic call; a constant needs a key without ".$". '
             'Before: "status.$": "DONE"  After: "status": "DONE" (or "status.$": "$.status")'),
    "P011": ("ERROR", "malformed intrinsic function call",
             "Write States.<Function>(args) with single-quoted string literals and the right number of arguments. "
             'Before: "States.Format(\\"Hi {}\\", $.name)"  After: "States.Format(\'Hi {}\', $.name)"'),
    "P012": ("ERROR", "invalid JSONPath in a path field",
             'InputPath, ResultPath, OutputPath, ... take a JSONPath starting with "$". '
             'Before: "ResultPath": "result"  After: "ResultPath": "$.result"'),
    "S000": ("ERROR", "input could not be linted, or top-level field",
             "Invalid JSON, no definition found, an unknown or invalid top-level field, or a linter note (INFO). Do what the "
             'message says and re-run. Before: {"StartAt": "A", "States": {...}, "Timeout": 60}  After: {"StartAt": "A", '
             '"States": {...}, "TimeoutSeconds": 60}'),
    "S001": ("ERROR", "StartAt or States missing or wrong",
             "StartAt must name a state of the same States object. "
             'Before: "StartAt": "Frist", "States": {"First": {...}}  After: "StartAt": "First"'),
    "S002": ("ERROR", "transition to a state that does not exist",
             "Next, Default and Catch.Next must name a state in the same scope (states inside a Map/Parallel cannot jump "
             'outside it). Before: "Next": "ChargeOrdr"  After: "Next": "ChargeOrder"'),
    "S003": ("ERROR", "unreachable state",
             "Nothing transitions to the state (the states listed in the message are reachable only through it). Connect it "
             'from a reachable state or delete it. Before: "A": {"Type": "Pass", "End": true}, "B": {...}  After: '
             '"A": {"Type": "Pass", "Next": "B"}, "B": {...}'),
    "S004": ("ERROR", "Next/End missing or not allowed",
             'Task, Pass, Wait, Map and Parallel need "Next" or "End": true; Choice, Succeed and Fail must have neither. '
             'Before: {"Type": "Pass"}, {"Type": "Succeed", "End": true}  After: {"Type": "Pass", "End": true}, {"Type": "Succeed"}'),
    "S005": ("ERROR", "both Next and End",
             'Use exactly one. Before: {"Type": "Pass", "Next": "B", "End": true}  After: {"Type": "Pass", "Next": "B"}'),
    "S006": ("ERROR", "Choice state rules",
             "A Choice needs a non-empty Choices array of rules, each with a condition and Next; add a Default (WARNING when "
             'missing). Before: {"Type": "Choice", "Choices": [{"Condition": "{% $x > 1 %}"}]}  After: {"Type": "Choice", '
             '"Choices": [{"Condition": "{% $x > 1 %}", "Next": "Big"}], "Default": "Small"}'),
    "S007": ("ERROR", "duplicate state name",
             "State names must be unique in the whole state machine, including inside Map and Parallel. Rename one and update "
             'every Next/StartAt/Default that targets it. Before: two states named "Check"  After: "CheckOrder" and "CheckStock"'),
    "S008": ("ERROR", "state name too long",
             'State names are at most 80 characters. Before: "ProcessTheIncomingOrderAndThen..." (90 chars)  After: "ProcessOrder"'),
    "S009": ("ERROR", "state shape: Type, unknown field, field type",
             "Each state is an object with a valid Type and only the fields that Type allows (the message suggests the right "
             'name). Before: {"Type": "Pass", "Nxt": "B"}  After: {"Type": "Pass", "Next": "B"}'),
    "S010": ("ERROR", "Wait state fields",
             "A Wait needs exactly one of Seconds, Timestamp, SecondsPath, TimestampPath; Seconds is a non-negative integer. "
             'Before: {"Type": "Wait", "Seconds": "10", "Next": "B"}  After: {"Type": "Wait", "Seconds": 10, "Next": "B"}'),
    "S011": ("ERROR", "Fail state fields",
             "Use Error or ErrorPath (not both) and Cause or CausePath (not both), as strings. "
             'Before: {"Type": "Fail", "Error": "X", "ErrorPath": "$.e"}  After: {"Type": "Fail", "Error": "X"}'),
    "S012": ("ERROR", "Retry/Catch shape or error names",
             "Retry and Catch are arrays of objects with a non-empty ErrorEquals; a catcher needs Next; States.ALL must be alone "
             'and last. Before: "Catch": [{"ErrorEquals": ["States.ALL"]}]  After: "Catch": [{"ErrorEquals": ["States.ALL"], '
             '"Next": "HandleError"}]'),
    "S013": ("ERROR", "Map/Parallel structure",
             "A Map needs an ItemProcessor (StartAt + States; Iterator is deprecated) and a Parallel a non-empty Branches array. "
             'Before: {"Type": "Map", "Iterator": {"StartAt": "S", "States": {...}}}  After: {"Type": "Map", "ItemProcessor": '
             '{"ProcessorConfig": {"Mode": "INLINE"}, "StartAt": "S", "States": {...}}}'),
    "S014": ("ERROR", "Retry/Catch on a state that cannot fail",
             "Only Task, Map and Parallel states take Retry and Catch; move them to the state that can fail. "
             'Before: {"Type": "Pass", "Retry": [...]}  After: {"Type": "Pass"} and "Retry": [...] on the Task'),
    "S015": ("ERROR", "Task state fields",
             "A Task needs a constant Resource ARN and the fields its integration requires; timeouts are positive integers. "
             'Before: "Arguments": {"Payload": "{% $states.input %}"} (lambda:invoke)  After: "Arguments": {"FunctionName": '
             '"my-fn", "Payload": "{% $states.input %}"}'),
    "S016": ("ERROR", "the execution can never finish",
             "No path from these states reaches a Succeed/Fail state or a state with End. Add an exit. Before: A -> B -> A  "
             'After: B is a Choice: {"Choices": [{"Condition": "{% $done %}", "Next": "Finished"}], "Default": "A"}'),
    "S017": ("WARNING", "loop without a Wait state",
             "A polling loop without a Wait burns state transitions. Insert a Wait and cap the polls; for a bounded loop add "
             '"lint-allow S017: <reason>" to the Comment of the reported state. Before: Poll -> Check -> Poll  After: '
             'Poll -> Check -> Pause -> Poll with "Pause": {"Type": "Wait", "Seconds": 10, "Next": "Poll"}'),
    "S018": ("WARNING", "Catch loops back to the failing state",
             "A persistent error then retries forever; use Retry for retries and point Catch at an error handler. "
             'Before: "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "CallApi"}] on CallApi  After: "Retry": [{"ErrorEquals": '
             '["States.ALL"], "MaxAttempts": 3, "BackoffRate": 2}], "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "Failed"}]'),
    "S019": ("ERROR", "invalid Task Resource ARN",
             "Use a valid Lambda, activity or arn:<partition>:states:::<service>:<action>[.sync|.waitForTaskToken] ARN. "
             'Before: "arn:aws:states:::aws-sdk:s3:GetObject"  After: "arn:aws:states:::aws-sdk:s3:getObject"'),
    "S020": ("ERROR", "not supported in Express workflows",
             "Express workflows (--type EXPRESS) have no .sync, .waitForTaskToken, activities or Distributed Map and run at "
             'most 300 s. Before: "arn:aws:states:::glue:startJobRun.sync"  After: "arn:aws:states:::glue:startJobRun" '
             "(or make the workflow STANDARD)"),
    "S021": ("ERROR", "JSONPath Choice rule shape or operand type",
             "A rule has Variable plus exactly one comparison of the right type, or And/Or/Not. "
             'Before: {"Variable": "$.n", "NumericEquals": "10", "Next": "X"}  After: {"Variable": "$.n", "NumericEquals": 10, '
             '"Next": "X"}'),
    "S022": ("ERROR", "Next/Assign on a nested Choice rule",
             "Only top-level Choices rules take Next (and Assign/Comment); move it out of And/Or/Not. "
             'Before: {"And": [{"Variable": "$.a", "IsPresent": true, "Next": "X"}]}  After: {"And": [{"Variable": "$.a", '
             '"IsPresent": true}], "Next": "X"}'),
    "V001": ("ERROR", "variable never assigned",
             "The variable is read but no Assign sets it (the message may suggest the intended name). "
             'Before: "{% $orderID %}" with "Assign": {"orderId": ...}  After: "{% $orderId %}"'),
    "V002": ("ERROR", "variable not assigned on every path / not visible here",
             "Assign it on every path that reaches this state (e.g. in the first state), and remember that variables assigned "
             'inside a Map/Parallel are not visible outside. Before: only one Choice branch assigns $total  After: "Assign": '
             '{"total": 0} in the first state'),
    "V003": ("ERROR", "outer variable read in a Distributed Map",
             "Distributed Map child workflows cannot see outer variables; pass them in through ItemSelector. "
             'Before: "{% $limit %}" inside the Map  After: "ItemSelector": {"limit": "{% $limit %}", "item": '
             '"{% $states.context.Map.Item.Value %}"} and read $states.input.limit'),
    "V004": ("ERROR", "variable shadows an outer variable",
             "A Map/Parallel scope cannot assign a variable that an enclosing scope also assigns; rename the inner one. "
             'Before: inner "Assign": {"total": ...}  After: inner "Assign": {"itemTotal": ...}'),
    "V005": ("WARNING", "Pass state only assigns variables",
             "Fold the Assign into the previous state (or the matching Choices rule) and delete the Pass state. "
             'Before: A -> SetVars {"Type": "Pass", "Assign": {"x": 1}, "Next": "B"}  After: A with "Assign": {"x": 1}, "Next": "B"'),
    "V006": ("WARNING", "variable never read",
             'Delete the unused Assign entry. Before: "Assign": {"id": "{% $states.input.id %}", "tmp": 1}  After: '
             '"Assign": {"id": "{% $states.input.id %}"}'),
    "V007": ("ERROR", "invalid variable name in Assign",
             "Variable names are identifiers (letters, digits, _; no leading digit; at most 80 characters). "
             'Before: "Assign": {"order-id": 1}  After: "Assign": {"order_id": 1}, read as $order_id'),
}


# ---------------------------------------------------------------------------
# Output: source line numbers, document order, "lint-allow" suppressions, formats
# ---------------------------------------------------------------------------

JSON_TOKEN_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[{}\[\],:]|[^\s{}\[\],:"]+')
BRACE_RE = re.compile(r"\{")


def json_key_offsets(text: str, start: int) -> dict[str, int]:
    """Offset in `text` of every key path ("" for the root, "/States/A/Next", "/States/A/Catch/0") of the JSON value
    starting at text[start]: the key's offset for an object member, the value's for an array element. One pass with
    a regex tokenizer; tolerant (never raises on malformed text) and it stops at the end of that value."""
    offsets: dict[str, int] = {}
    frames: list[list] = []  # [path, is_object, current key (None: a key comes next) or element index]
    for m in JSON_TOKEN_RE.finditer(text, start):
        tok = m.group()
        c = tok[0]
        top = frames[-1] if frames else None
        if c == ":":
            continue
        if c == ",":
            if top is not None:
                if top[1]:
                    top[2] = None
                else:
                    top[2] += 1
            continue
        if c in "}]":
            if frames:
                frames.pop()
            if not frames:
                break
            continue
        if top is not None and top[1] and top[2] is None:
            if c == '"':  # a key
                key = tok[1:-1]
                if "\\" in key:
                    try:
                        key = json.loads(tok)
                    except ValueError:
                        pass
                top[2] = key
                offsets[f"{top[0]}/{key}"] = m.start()
            continue
        if top is None:
            path = ""
            offsets[path] = m.start()
        else:
            path = f"{top[0]}/{top[2]}"
            if not top[1]:
                offsets[path] = m.start()
        if c == "{":
            frames.append([path, True, None])
        elif c == "[":
            frames.append([path, False, 0])
        elif top is None:
            break
    return offsets


def offset_of(offsets: dict[str, int], prefix: str, location: str) -> Optional[int]:
    """Offset of the longest prefix of prefix + location (a diagnostic location such as "/States/A/Next") that exists
    in the source: a missing field maps to its state, a missing state to its States object."""
    p = prefix + ("" if location == "/" else location)
    while True:
        if p in offsets:
            return offsets[p]
        if not p:
            return None
        k = p.rfind("/")
        p = p[:k] if k > 0 else ""


class SourceMap:
    """Where each linted definition is in the source text, as key-path offsets computed once per definition."""

    MAX_CANDIDATES = 20  # "{" tried on the start line of an embedded definition

    def __init__(self, text: str) -> None:
        # placeholders replaced the way extraction does (line numbers are kept), so "${x}" values tokenize as JSON
        self.text = substitute_placeholders(text) if ("${" in text or "%{" in text) else text
        self.newlines: Optional[list[int]] = None
        self.root: Optional[dict[str, int]] = None
        self.used: set[tuple[int, str]] = set()  # embedded (chunk start, path) already matched to a definition

    def line(self, pos: int) -> int:
        if self.newlines is None:
            self.newlines = [m.start() for m in re.finditer("\n", self.text)]
        return bisect.bisect_left(self.newlines, pos) + 1

    def root_offsets(self) -> dict[str, int]:
        if self.root is None:
            start = SPACES_RE.match(self.text).end()  # type: ignore[union-attr]
            self.root = json_key_offsets(self.text, start)
            m = JSON_TOKEN_RE.match(self.text, start)
            if m and m.group().startswith('"') and not self.text[m.end():].strip():
                self.root["string"] = start  # the whole input is one JSON string (terraform console output)
        return self.root

    def definition(self, label: str) -> tuple[dict[str, int], str]:
        """(offsets, path of the definition in them) for the definition with this extraction label: "/" (the input),
        a JSON path in the input (CloudFormation JSON), or "line N[ resource][ /path]" (embedded at line N)."""
        root = self.root_offsets()
        if not label.startswith("line "):
            return root, "" if label == "/" else label
        if "string" in root:  # lines inside a JSON-encoded string are all on the string's line
            return {"": root["string"]}, ""
        m = re.match(r"line (\d+)", label)
        rest = label[m.end():] if m else ""
        k = rest.find(" /")
        path = rest[k + 1:] if k >= 0 else ""
        n = int(m.group(1)) if m else 1
        self.line(0)
        nl = self.newlines or []
        lo = 0 if n < 2 else nl[n - 2] + 1 if n - 2 < len(nl) else len(self.text)
        hi = nl[n - 1] if n - 1 < len(nl) else len(self.text)
        tries = 0
        for b in BRACE_RE.finditer(self.text, lo, hi):
            s = b.start()
            if (s, path) in self.used or not JSON_OBJECT_START_RE.match(self.text, s):
                continue
            tries += 1
            if tries > self.MAX_CANDIDATES:
                break
            offsets = json_key_offsets(self.text, s)
            if (path in offsets) if path else ("/StartAt" in offsets and "/States" in offsets):
                self.used.add((s, path))
                return offsets, path
        return {"": lo}, ""  # not found: everything on the definition's first line


def add_lines(diags: Diagnostics, items: list[dict], smap: SourceMap, label: str) -> None:
    """Set item["line"] and the document position of each item of one definition (locations not yet prefixed)."""
    offsets, prefix = smap.definition(label)
    for item in items:
        pos = offset_of(offsets, prefix, item["location"])
        if pos is not None:
            item["line"] = smap.line(pos)
            diags.positions[id(item)] = pos


LINT_ALLOW_RE = re.compile(r"lint-allow\b[ \t]*([A-Za-z]\d{3}(?:[ \t]*,[ \t]*[A-Za-z]\d{3})*)?[ \t]*"
                           r"(?::[ \t]*((?:(?!lint-allow\b)[\s\S])*))?")


def lint_allows(definition: Any) -> tuple[dict[str, dict[str, str]], set[str], list[tuple[str, str]]]:
    """"lint-allow <CODE>[,<CODE>]: <reason>" in state Comments: ({state location: {code: reason}}, every state
    location, [(Comment location, why a directive was ignored)]). A directive without a reason suppresses nothing."""
    allows: dict[str, dict[str, str]] = {}
    state_locs: set[str] = set()
    ignored: list[tuple[str, str]] = []
    stack = [(definition.get("States") if isinstance(definition, dict) else None, "/States")]
    while stack:
        states, location = stack.pop()
        if not isinstance(states, dict):
            continue
        for name, st in states.items():
            if not isinstance(st, dict):
                continue
            loc = f"{location}/{name}"
            state_locs.add(loc)
            comment = st.get("Comment")
            for m in LINT_ALLOW_RE.finditer(comment) if isinstance(comment, str) else ():
                codes = [c.strip().upper() for c in (m.group(1) or "").split(",") if c.strip()]
                reason = (m.group(2) or "").strip()
                if not codes:
                    ignored.append((f"{loc}/Comment", 'lint-allow ignored: name the codes and the reason, e.g. '
                                    '"lint-allow S017: bounded loop, at most 10 passes"; nothing was suppressed'))
                elif not reason:
                    ignored.append((f"{loc}/Comment", f'"lint-allow {",".join(codes)}" has no reason, so it is ignored and '
                                    f'nothing was suppressed; write why after a colon: "lint-allow {",".join(codes)}: <why this '
                                    'is intended>"'))
                else:
                    for c in codes:
                        if c in CODES:
                            allows.setdefault(loc, {})[c] = reason
                        else:
                            ignored.append((f"{loc}/Comment", f"lint-allow: unknown code {c} (python3 lint_asl.py --list-codes "
                                            "lists them); it suppresses nothing"))
            for key in ("ItemProcessor", "Iterator"):
                if isinstance(st.get(key), dict):
                    stack.append((st[key].get("States"), f"{loc}/{key}/States"))
            for i, b in enumerate(as_list(st.get("Branches"))):
                if isinstance(b, dict):
                    stack.append((b.get("States"), f"{loc}/Branches/{i}/States"))
    return allows, state_locs, ignored


def apply_suppressions(definition: Any, diags: Diagnostics, first: int) -> None:
    """Move diags.items[first:] silenced by a lint-allow of their state (the innermost state containing the location;
    a Map/Parallel's Comment does not cover the states inside it) to diags.suppressed; INFO for ignored directives."""
    allows, state_locs, ignored = lint_allows(definition)
    if allows:
        kept = []
        for item in diags.items[first:]:
            p = item["location"]
            while p and p not in state_locs:
                k = p.rfind("/")
                p = p[:k] if k > 0 else ""
            reason = allows.get(p, {}).get(item["code"])
            if reason is None:
                kept.append(item)
            else:
                item["suppressedBy"] = reason
                diags.suppressed.append(item)
        diags.items[first:] = kept
    for loc, msg in ignored:
        diags.info("S000", loc, msg)


SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}
FORMATS = ("text", "json", "github", "sarif")
GROUP_MIN = 4  # the same code and message this many times or more: text output prints it once with every location


def document_order(diags: Diagnostics, items: list[dict]) -> list[dict]:
    """Definition, then position in the source (state order, then field order), then severity."""
    seq = {id(it): k for k, it in enumerate(items)}
    return sorted(items, key=lambda it: (it.get("definition", {}).get("index", 0), diags.positions.get(id(it), -1),
                                         SEVERITY_ORDER.get(it["severity"], 3), seq[id(it)]))


def text_lines(name: str, items: list[dict]) -> list[str]:
    """`<file>:<line>: SEVERITY CODE <location>: <message>`; a code+message repeated GROUP_MIN+ times is printed once."""
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for it in items:
        groups.setdefault((it["severity"], it["code"], it["message"]), []).append(it)
    out = []
    for it in items:
        group = groups[(it["severity"], it["code"], it["message"])]
        where = f"{name}:{it['line']}:" if it.get("line") else f"{name}:"
        if len(group) < GROUP_MIN:
            out.append(f"{where} {it['severity']} {it['code']} {it['location']}: {it['message']}")
        elif group[0] is it:
            locs = ", ".join(f"{g['location']} (line {g['line']})" if g.get("line") else g["location"] for g in group)
            out.append(f"{where} {it['severity']} {it['code']} at {len(group)} locations: {locs}: {it['message']}")
    return out


def github_escape(s: str, prop: bool = False) -> str:
    s = s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return s.replace(":", "%3A").replace(",", "%2C") if prop else s


def github_lines(name: Optional[str], items: list[dict]) -> list[str]:
    """GitHub Actions workflow commands: ::error file=F,line=L,title=CODE::<location>: <message>."""
    level = {"ERROR": "error", "WARNING": "warning", "INFO": "notice"}
    out = []
    for it in items:
        props = ([f"file={github_escape(name, True)}"] if name else []) + \
                ([f"line={it['line']}"] if it.get("line") else []) + [f"title={it['code']}"]
        out.append(f"::{level.get(it['severity'], 'notice')} {','.join(props)}::"
                   f"{github_escape(it['location'] + ': ' + it['message'])}")
    return out


def sarif_log(report: list[dict]) -> dict:
    """A minimal SARIF 2.1.0 log: one run, a rule per code used (help = the --explain recipe), one result per item."""
    level = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}
    used = sorted({it["code"] for f in report for it in f["diagnostics"]})
    rules = [{"id": c, "shortDescription": {"text": CODES[c][1] if c in CODES else c},
              "help": {"text": CODES[c][2] if c in CODES else ""},
              "defaultConfiguration": {"level": level.get(CODES[c][0] if c in CODES else "ERROR", "error")}} for c in used]
    index = {c: k for k, c in enumerate(used)}
    results = []
    for f in report:
        uri = "stdin" if f["file"] == "-" else f["file"].replace("\\", "/")
        for it in f["diagnostics"]:
            phys: dict[str, Any] = {"artifactLocation": {"uri": uri}}
            if it.get("line"):
                phys["region"] = {"startLine": it["line"]}
            results.append({"ruleId": it["code"], "ruleIndex": index[it["code"]], "level": level.get(it["severity"], "note"),
                            "message": {"text": f"{it['location']}: {it['message']}"},
                            "locations": [{"physicalLocation": phys,
                                           "logicalLocations": [{"fullyQualifiedName": it["location"]}]}]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "lint_asl", "rules": rules}}, "results": results}]}


def explain_code(code: str) -> str:
    severity, title, recipe = CODES[code]
    return f"{code} ({severity}): {title}\n{recipe}"


def lint_text(text: str, jsonata=None, execution_type: str = "STANDARD",
              filename: Optional[str] = None) -> tuple[Diagnostics, int]:
    diags = Diagnostics()
    _similar_cache["budget"] = HINT_COMPARE_BUDGET  # V001 "did you mean" comparisons: one budget per file
    _similar_cache["index_left"] = 4 * MAX_INDEXED_VARS  # names put in the deletion index, per file
    _suggest_budget["left"] = SUGGEST_BUDGET
    text = text.lstrip("﻿")
    problems: list = []
    labels: list[str] = []
    try:
        defs = extract_definitions(text, filename, problems, labels) if text.strip() else []
    except RecursionError:
        defs, problems = [], ["the input is nested too deeply to parse (thousands of levels of [ or {); nothing was linted"]
    for p in problems:
        diags.add(p[0], "S000", "/", p[1]) if isinstance(p, tuple) else diags.error("S000", "/", p)
    if not defs and not problems:
        diags.error("S000", "/", nothing_found_message(text, filename))
    for item in diags.items:  # input problems: the line their message names ("invalid JSON: ... at line 3 column 5")
        m = re.search(r"\bline (\d+)", item["message"])
        item["line"] = int(m.group(1)) if m else None
    smap: Optional[SourceMap] = None
    for i, (definition, note) in enumerate(defs):
        first = len(diags.items)
        first_suppressed = len(diags.suppressed)
        if note:
            diags.info("S000", "/", note)
        try:
            lint_definition(definition, diags, jsonata, execution_type)
        except (Exception, RecursionError) as ex:  # noqa: BLE001 - safety net: report instead of a traceback
            diags.crashed = True  # type: ignore[attr-defined]
            where = f" (definition {i + 1} of {len(defs)})" if len(defs) > 1 else ""
            why = ("the definition is nested too deeply" if isinstance(ex, RecursionError) else
                   "the definition probably has a field of the wrong type - fix the other errors first, then re-run")
            diags.error("S000", "/", f"linter internal error{where} ({type(ex).__name__}: {ex}); {why}")
        label = labels[i] if i < len(labels) else "/"
        try:  # suppressions and line numbers only annotate the result: they must never turn a lint into a crash
            apply_suppressions(definition, diags, first)
            smap = smap or SourceMap(text)
            add_lines(diags, diags.items[first:] + diags.suppressed[first_suppressed:], smap, label)
        except (Exception, RecursionError):  # noqa: BLE001
            pass
        if len(defs) > 1:  # say which definition each diagnostic is about: "[2:/Resources/SM2/Properties/Definition] /States/A"
            for item in diags.items[first:] + diags.suppressed[first_suppressed:]:
                item["definition"] = {"index": i + 1, "label": label, "path": item["location"]}  # type: ignore[assignment]
                item["location"] = f"[{i + 1}:{label}] {item['location']}"
    return diags, len(defs)


def decode_bytes(data: bytes) -> str:
    """UTF-8 (with or without BOM) or UTF-16 (BOM, or BOM-less ASCII-range text as written by Windows tools)."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if len(data) >= 2 and data[0] and not data[1]:
        return data.decode("utf-16-le")
    if len(data) >= 2 and not data[0] and data[1]:
        return data.decode("utf-16-be")
    return data.decode("utf-8")


def read_input(f: str) -> tuple[Optional[str], Optional[str]]:
    """(text, None) or (None, reason it cannot be read)."""
    try:
        if f == "-":
            stream = sys.stdin
            if stream is None:
                return None, "cannot read stdin: no standard input"
            data = stream.buffer.read() if hasattr(stream, "buffer") else stream.read().encode("utf-8")
        elif os.path.isdir(f):
            return None, (f'"{f}" is a directory, not a file; pass the files instead, e.g. '
                          f'python3 lint_asl.py "{os.path.join(f, "*.json")}"')
        elif not os.path.isfile(f) and os.path.exists(f) and not stat.S_ISFIFO(os.stat(f).st_mode):
            # a device (Windows CON / CONIN$ / NUL, /dev/tty, ...): reading CON would wait for console input forever.
            # FIFOs stay allowed for bash process substitution: python3 lint_asl.py <(terraform console ...)
            return None, (f'"{f}" is not a regular file (it is a device{" - CON, NUL, AUX, PRN, COM1 and LPT1 are reserved names on Windows" if os.name == "nt" else ""}); '
                          "pass a file path, or - to read standard input")
        else:
            with open(f, "rb") as fh:
                data = fh.read()
        return decode_bytes(data), None
    except FileNotFoundError:
        return None, "cannot read file: no such file (check the path; it is relative to the current directory)"
    except UnicodeDecodeError as ex:
        return None, (f"cannot read file: it is not UTF-8 or UTF-16 text (byte 0x{ex.object[ex.start]:02x} at offset {ex.start}); "
                      "save it as UTF-8 and re-run")
    except OSError as ex:
        return None, f"cannot read file: {ex.strerror or ex}"


def expand_globs(files: list[str]) -> list[str]:
    """Expand * and ? ourselves (PowerShell and cmd pass them through unexpanded)."""
    out: list[str] = []
    for f in files:
        pattern = f[4:] if f.startswith(("\\\\?\\", "//?/")) else f  # Windows long-path prefix \\?\ is not a glob
        if f != "-" and ("*" in pattern or "?" in pattern):
            matches = sorted(m for m in glob.glob(f, recursive=True) if os.path.isfile(m))
            out.extend(matches or [f])
        else:
            out.append(f)
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lint_asl.py", allow_abbrev=False,
        description="Static checks for AWS Step Functions state machine definitions (JSONata and JSONPath).",
        epilog="Exit code 0 clean, 1 errors (or warnings with --strict), 2 nothing linted or usage error, 3 linter "
               'internal error. Silence one diagnostic with "lint-allow <CODE>: <reason>" in the Comment of its state.')
    p.add_argument("files", nargs="*", metavar="FILE",
                   help='definition JSON, a file that embeds one (Terraform, CloudFormation), a quoted glob ("sfn/*.json"), or - for stdin')
    p.add_argument("--format", choices=FORMATS, default="text", help="output format (default: text)")
    p.add_argument("--json", action="store_true", help="same as --format json")
    p.add_argument("--type", default="STANDARD", metavar="STANDARD|EXPRESS",
                   help="workflow type; EXPRESS also enforces Express limits (default: STANDARD)")
    p.add_argument("--strict", action="store_true", help="exit 1 when there is any WARNING too")
    p.add_argument("--quiet", action="store_true", help="hide INFO diagnostics")
    p.add_argument("--show-suppressed", action="store_true", help='list the diagnostics silenced by "lint-allow" comments')
    p.add_argument("--list-codes", action="store_true", help="list every diagnostic code and exit")
    p.add_argument("--explain", metavar="CODE", help="explain how to fix one code (e.g. --explain S017) and exit")
    return p


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:  # piped output on Windows defaults to the ANSI code page and crashes on non-ASCII state names
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass
    parser = build_arg_parser()
    try:
        args = parser.parse_intermixed_args(argv[1:])
    except SystemExit as ex:  # unknown flag or bad value: argparse printed the usage and the error (--help: exit 0)
        return ex.code if isinstance(ex.code, int) else 2
    if args.list_codes:
        for code, (severity, title, _recipe) in CODES.items():
            print(f"{code} {severity:<7} {title}")
        return 0
    if args.explain is not None:
        code = args.explain.strip().upper()
        if code not in CODES:
            print(f"error: unknown code {args.explain!r}; python3 lint_asl.py --list-codes lists every code", file=sys.stderr)
            return 2
        print(explain_code(code))
        return 0
    exec_type = args.type.upper()
    if exec_type not in ("STANDARD", "EXPRESS"):
        print("error: --type must be STANDARD or EXPRESS", file=sys.stderr)
        return 2
    fmt = "json" if args.json else args.format
    files = expand_globs(args.files)
    if not files:
        parser.print_usage(sys.stderr)
        print("error: no input: pass a definition file, a quoted glob, or - for stdin", file=sys.stderr)
        return 2
    jsonata = load_jsonata()
    exit_code = 0
    report = []
    for f in files:
        text, read_error = read_input(f)
        if text is None:
            diags, count = Diagnostics(), 0
            bare = f[4:] if f.startswith(("\\\\?\\", "//?/")) else f  # Windows long-path prefix \\?\ is not a glob
            pattern = f != "-" and ("*" in bare or "?" in bare)
            diags.error("S000", "/", "no files match this pattern" if pattern else str(read_error))
        else:
            diags, count = lint_text(text, jsonata, exec_type, None if f == "-" else f)
        if diags.errors or (args.strict and diags.warnings):
            exit_code = max(exit_code, 1)
        if count == 0:
            exit_code = max(exit_code, 2)
        if getattr(diags, "crashed", False):
            exit_code = 3
        items = document_order(diags, [it for it in diags.items if not (args.quiet and it["severity"] == "INFO")])
        report.append({"file": f, "diagnostics": items, "suppressed": document_order(diags, diags.suppressed)})
        if fmt == "github":
            for line in github_lines(None if f == "-" else f, items):
                print(line)
        elif fmt == "text":
            name = "<stdin>" if f == "-" else f
            print(f"== {f}{f' ({count} definitions)' if count > 1 else ''}")
            for line in text_lines(name, items):
                print(line)
            note = "" if jsonata else " [jsonata-python not installed: expression syntax not parsed; pip install jsonata-python]"
            if count == 0:
                note = " - nothing was linted"
            print(f"-- {diags.errors} error(s), {diags.warnings} warning(s){note}")
            if diags.suppressed:
                if args.show_suppressed:
                    for it in document_order(diags, diags.suppressed):
                        where = f"{name}:{it['line']}:" if it.get("line") else f"{name}:"
                        print(f"{where} suppressed {it['severity']} {it['code']} {it['location']}: {it['message']} "
                              f"[lint-allow: {it.get('suppressedBy', '')}]")
                print(f"-- {len(diags.suppressed)} suppressed" + ("" if args.show_suppressed else " (--show-suppressed lists them)"))
    if fmt == "json":
        print(json.dumps({"jsonataParser": jsonata is not None, "files": report}, indent=2))
    elif fmt == "sarif":
        print(json.dumps(sarif_log(report), indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
