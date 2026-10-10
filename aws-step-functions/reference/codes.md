# Linter codes

Every code `scripts/lint_asl.py` emits. One code = one kind of fix. Each output line is
`SEVERITY CODE location: <what is wrong>; <fix>`; the message carries the exact fix for that
case, this table is the overview.

**Fix every `ERROR` and every `WARNING`.** A WARNING may stay only with a one-line reason in
the report (e.g. "S017: bounded pagination loop"). `INFO` is a hint: act on it unless the
reason in the message does not apply. Exit code: 0 no ERROR (WARNING/INFO may remain), 1 at
least one ERROR, 2 something could not be linted (an `S000` line says why), 3 linter crash.

## S0xx structure

| Code | Severity | Meaning | Fix |
|---|---|---|---|
| S000 | ERROR / WARNING / INFO | the input could not be read or no definition was found (invalid JSON, empty file, Terraform `jsonencode`, YAML mapping, unrenderable template, nesting too deep); INFO notes what was linted | follow the message: fix the JSON, or render the definition to JSON and pipe it to `lint_asl.py -` |
| S001 | ERROR | `StartAt` / `States` missing, or `StartAt` names no state of its scope | set `"StartAt"` to the first state of the same `States` block |
| S002 | ERROR | `Next` / `Default` / rule `Next` / `Catch.Next` names no state of its scope | point it at a state of the same `States` block (Map/Parallel bodies are separate scopes) |
| S003 | ERROR | state unreachable from `StartAt` (orphan) | add a transition to it, or delete it |
| S004 | ERROR | `Next`/`End` missing, or on Choice/Succeed/Fail, or `End` is not `true` | non-terminal states: exactly one of `"Next": "<state>"` / `"End": true`; Choice/Succeed/Fail: neither |
| S005 | ERROR | state has both `Next` and `End` | keep one |
| S006 | ERROR | Choice structure: empty `Choices`, rule not an object, unknown rule field, rule without `Next`, JSONata rule without `Condition`, JSONPath rule without `Variable`/`And`/`Or`/`Not` | write each rule as `{"Condition": "{% ... %}", "Next": "X"}` (JSONata) |
| S007 | ERROR | state name used twice (names are unique across the whole machine, Map/Parallel bodies included) | rename one and update its transitions |
| S008 | ERROR | state name longer than 80 characters | shorten it and update its transitions |
| S009 | ERROR | state not an object, unknown `Type`, unknown field for the state type, field not allowed on that type (`Assign` on Succeed/Fail, `Output` on Fail), object field with a non-object value | use the field the message suggests, or remove it |
| S010 | ERROR | Wait: not exactly one of `Seconds`/`Timestamp`(/`*Path`), negative `Seconds`, malformed `Timestamp` | `"Seconds": 30` or `"Timestamp": "2025-01-31T10:00:00Z"` |
| S011 | ERROR | Fail: `Error`+`ErrorPath` or `Cause`+`CausePath`, or a non-string value | keep one of each pair, as strings |
| S012 | ERROR | Retry shape: not an array, entry not an object, unknown field, bad `MaxAttempts`/`IntervalSeconds`/`BackoffRate`/`JitterStrategy` | `"Retry": [{"ErrorEquals": [...], "IntervalSeconds": 2, "MaxAttempts": 3, "BackoffRate": 2}]` |
| S013 | ERROR | Map structure: no `ItemProcessor`, both `Iterator` and `ItemProcessor`, bad `ProcessorConfig`/`Mode`/`Items`/`MaxConcurrency`, both `X` and `XPath`, processor without `StartAt`/`States` | `"ItemProcessor": {"ProcessorConfig": {"Mode": "INLINE"}, "StartAt": "A", "States": {...}}` |
| S014 | ERROR | `Retry`/`Catch` on a state other than Task, Map, Parallel | remove it |
| S015 | ERROR | Task: no constant string `Resource`, `Resource` is an expression, `lambda:invoke` without `Arguments.FunctionName`, `.waitForTaskToken` without the token | constant ARN in `Resource`, dynamic values in `Arguments` |
| S016 | ERROR | a state or loop can never reach a Succeed/Fail/`End` state | add a Choice rule or `Next` that leaves the loop |
| S017 | WARNING | loop without a Wait state | add a Wait in a polling loop; bounded counter/pagination loops: keep and justify |
| S018 | WARNING | `Catch` sends the state back to itself with no Wait/Choice in between | use `Retry` for retries; point `Catch` at an error handler |
| S019 | ERROR / WARNING | Task `Resource` ARN malformed, wrong aws-sdk action casing, or unsupported `.sync`/`.sync:2`/`.waitForTaskToken` suffix; WARNING for an unknown partition | use the ARN shape the message gives |
| S020 | ERROR / WARNING | `--type EXPRESS`: `.sync`, `.waitForTaskToken`, activities or Distributed Map; WARNING for `TimeoutSeconds` > 300 | request-response integrations only, at most 300 s |
| S021 | ERROR | JSONPath Choice rule: operator/type mismatch, `Variable` with no or several comparisons, bad `And`/`Or`/`Not` | `{"Variable": "$.x", "StringEquals": "a", "Next": "B"}` |
| S022 | ERROR | `Next`/`Assign` on a rule nested inside `And`/`Or`/`Not` | move it to the top-level rule |
| S023 | ERROR | optimized integration action that the service's optimized integration does not support, or `arn:aws:states:::s3:...` as a Task `Resource` | call it through the AWS SDK integration, e.g. `arn:aws:states:::aws-sdk:dynamodb:query` |
| S024 | ERROR | duplicate JSON key: a state name defined twice in one `States` object, or any other key repeated in one object (JSON keeps only the last) | keep exactly one; give duplicated states unique names |
| S025 | ERROR | unknown or misplaced key inside `ItemProcessor`, `ProcessorConfig`, a Parallel branch, `ItemReader`/`ReaderConfig`, `ItemBatcher`, `ResultWriter`/`WriterConfig`, `Credentials`; `*Path` variant in JSONata | move it where the message says (e.g. `"ProcessorConfig": {"Mode": "DISTRIBUTED", ...}`), or remove it |
| S026 | ERROR / WARNING | Distributed Map values: `ItemReader` Resource/`ReaderConfig`/Bucket/Key, `ItemBatcher` limits, `ResultWriter` Resource/Bucket/`WriterConfig`, `ToleratedFailure*` range, `Label`; WARNING for missing `InputType`, CSV header, batch limit, or a batched child reading one item | use the value the message gives, e.g. `"ReaderConfig": {"InputType": "JSONL"}` |
| S027 | ERROR / WARNING | inside an `"ExecutionType": "EXPRESS"` Distributed Map child: `.sync`, `.waitForTaskToken`, activities or a nested Distributed Map; WARNING for Wait `Seconds` / Task `TimeoutSeconds` > 300 (also under `--type EXPRESS`) | request-response integrations and at most 300 s, or `"ExecutionType": "STANDARD"` |
| S028 | ERROR | wrong aws-sdk service name (`states`/`stepfunctions`, `events`, `logs`) | `aws-sdk:sfn:...`, `aws-sdk:eventbridge:...`, `aws-sdk:cloudwatchlogs:...` |
| S030 | ERROR / WARNING | DynamoDB `Item`/`Key`/`ExpressionAttributeValues` value is not a typed attribute value (or `S`/`N` not a string); WARNING for an expression or `.$` value | `{"S": "text"}`, `{"N": "42"}`, `{"BOOL": true}` |
| S031 | ERROR | camelCase top-level `Arguments`/`Parameters` key of an optimized or aws-sdk integration | rename it to PascalCase (`QueueUrl`, not `queueUrl`) |
| S032 | ERROR | required parameter missing (`sqs:sendMessage`, `sns:publish`, `events:putEvents`, `dynamodb:*Item`, `startExecution`, `http:invoke`), or HTTP Task without a connection ARN | add the parameter the message names |
| S033 | ERROR | HTTP Task `Method` not GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD, or a reserved header (`Authorization`, `Host`, `x-amz-*`, ...) | a valid method; credentials in the EventBridge connection, not in `Headers` |
| S034 | WARNING | error name already matched by an earlier retrier/catcher, or a custom error after `States.TaskFailed` | remove it, or move the specific entry first |
| S035 | WARNING | `States.Runtime` in a `Catch` (never caught) | remove it; fix the cause |
| S036 | WARNING | Fail `Error` begins with `States.` (reserved) | use your own error name |
| S037 | ERROR / WARNING | aws-sdk error name with the wrong prefix casing (`DynamoDB.` vs `DynamoDb.`, `s3.` vs `S3.`); WARNING when the `Exception` suffix is missing | use the name the message gives, e.g. `S3.NoSuchKeyException` |
| S038 | ERROR | value over 99999999 (Wait `Seconds`, Task timeouts, Retry `IntervalSeconds`/`MaxAttempts`), `Version` not `"1.0"`, non-string `Comment`, `Credentials` not an object with `RoleArn` | follow the message |
| S039 | ERROR / WARNING | definition over 1 MB; WARNING for one literal field over 256 KiB | store large data in S3/DynamoDB and pass a reference, or split into child state machines |
| S040 | ERROR | Catch shape: not an array, entry not an object, unknown field, catcher without `Next` | `"Catch": [{"ErrorEquals": ["States.ALL"], "Next": "HandleError"}]` |
| S041 | ERROR | `ErrorEquals`: empty or not an array, non-string name, unknown `States.*` name, `States.ALL` not alone or not in the last entry | specific errors first; `["States.ALL"]` alone, in the last entry |
| S042 | ERROR | Parallel structure: empty `Branches`, branch without `StartAt`/`States` | `"Branches": [{"StartAt": "A", "States": {...}}]` |
| S043 | ERROR | Distributed-only Map fields (`ItemReader`, `ResultWriter`, `ItemBatcher`, `ToleratedFailure*`, `Label`) on an INLINE Map, or DISTRIBUTED without `ExecutionType` | `"ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"}`, or remove those fields |
| S044 | INFO | JSONata Map without `Items` iterates the whole state input | `"Items": "{% $states.input.<array> %}"` unless the input is the array |
| S045 | WARNING | deprecated `Iterator` on a Map | rename `Iterator` to `ItemProcessor` |
| S046 | ERROR | unknown top-level field, or top-level `TimeoutSeconds` not a positive integer | top level allows `Comment`, `QueryLanguage`, `StartAt`, `States`, `TimeoutSeconds`, `Version` |
| S047 | ERROR | `QueryLanguage` is not exactly `"JSONPath"` or `"JSONata"` | `"QueryLanguage": "JSONata"` |
| S048 | ERROR | a JSONata state machine contains a state with `"QueryLanguage": "JSONPath"` | convert the state to JSONata, or make the top level JSONPath |
| S049 | WARNING | Choice without `Default` (no match fails with `States.NoChoiceMatched`) | `"Default": "<fallback state>"` |
| S050 | ERROR | Task `TimeoutSeconds`/`HeartbeatSeconds` not a positive integer, both `X` and `XPath`, or `HeartbeatSeconds` >= `TimeoutSeconds` | positive integers, heartbeat smaller than timeout |

## J0xx JSONata mode

| Code | Severity | Meaning | Fix |
|---|---|---|---|
| J000 | INFO | the state machine is JSONPath | new machines: `"QueryLanguage": "JSONata"` at the top |
| J001 | ERROR | field or rule field of the other query language (`Parameters`, `ResultPath`, `Variable`, ... in JSONata; `Arguments`, `Output`, `Condition` in JSONPath) | use the replacement in the message |
| J002 | ERROR | key ending in `.$` in a JSONata state | drop `.$`, write the value as `"{% ... %}"` |
| J003 | ERROR / WARNING | `{% %}` malformed, empty, or not the whole string; plain string where a number/expression is needed | the string must start with `{%` and end with `%}` |
| J004 | ERROR | `$states.result` / `$states.errorOutput` where it does not exist | result: `Output`/`Assign` of Task, Map, Parallel; errorOutput: inside `Catch` |
| J005 | ERROR | function that does not exist in Step Functions JSONata | use the replacement in the message (see `jsonata-functions.md`) |
| J006 | ERROR | JSONata syntax error (only with `jsonata-python` installed) | fix the expression |
| J007 | ERROR / WARNING | invalid operator (`==`, `&&`, `||`, `!`) or JSONata 2.1+ operator (`??`, `?:`) | `=`, `and`, `or`, `$not()`, `$exists(a) ? a : b` |
| J008 | ERROR | `States.*` intrinsic in a JSONata state | use the JSONata function |
| J009 | ERROR / WARNING | `$$.` context or `$.field` JSONPath habit inside JSONata | `$states.context.<field>`, `$states.input.<field>` |
| J012 | ERROR | Choice `Condition` is not a `{% %}` expression | `"Condition": "{% <boolean> %}"` |
| J013 | ERROR / WARNING | unknown `$states.<field>` or context path, or `Map.Item` / `Task.Token` used where it is not set | use the field the message names |
| J014 | ERROR | wrong number of arguments for a JSONata function | follow the usage in the message |

## V0xx variables

| Code | Severity | Meaning | Fix |
|---|---|---|---|
| V001 | ERROR | variable never assigned anywhere | assign it earlier, or use the suggested name |
| V002 | ERROR | variable not assigned on every path to this state (or only later / in an inner scope) | assign it on every path before the read |
| V003 | ERROR | outer variable read inside a Distributed Map | pass it in through `ItemSelector` |
| V004 | ERROR | inner scope assigns a name an outer scope assigns | rename the inner variable |
| V005 | WARNING | Pass state that only assigns variables | move the `Assign` to the previous state or the matching Choice rule |
| V006 | WARNING | variable assigned but never read | delete it from the `Assign` |
| V007 | ERROR | invalid `Assign` key (syntax, `.`/`[`, over 80 characters) | rename as the message says |

## P0xx practice and JSONPath correctness

Not all hints: P004 (ERROR case), P010, P011, P012 are runtime failures.

| Code | Severity | Meaning | Fix |
|---|---|---|---|
| P001 | INFO | `lambda:invoke` output is the raw invoke response | `"Output": "{% $states.result.Payload %}"` unless the raw response is wanted |
| P002 | WARNING | `.waitForTaskToken` without `TimeoutSeconds`/`HeartbeatSeconds` | add `TimeoutSeconds` |
| P003 | WARNING | `States.Runtime` in a retrier (never retried) | remove it; fix the cause |
| P004 | ERROR / WARNING | `MaxDelaySeconds` out of range (ERROR) or useless with `BackoffRate` 1 (WARNING) | 1..31622400; `BackoffRate` > 1 |
| P005 | WARNING | Lambda task without a Retry for transient Lambda errors | add the Lambda retrier from `patterns.md` as the first `Retry` entry |
| P010 | ERROR | JSONPath `.$` key whose value is not a path or intrinsic | `"x.$": "$.field"` or `States.Format(...)` |
| P011 | ERROR / WARNING | malformed or unknown intrinsic function, wrong argument count | follow the usage in the message |
| P012 | ERROR | invalid JSONPath in a `*Path` field (`$$` in `ResultPath`, variables in `ResultPath`, bad syntax) | a path into the state input, e.g. `"$.result"` |
| P013 | INFO | HTTP Task `TimeoutSeconds` > 60 (the request itself times out after 60 s) | `"TimeoutSeconds": 60` or less |
| P014 | WARNING | `Payload` read from the result of a task that is not a Lambda invoke | read the response field itself, e.g. `$states.result.Item` |
| P015 | WARNING | `Output.<field>` after `states:startExecution.sync` (Output is a JSON string) | `startExecution.sync:2`, or `$parse($states.result.Output).<field>` |
| P016 | WARNING / INFO | a Catch target reads input fields, but the catcher has no `Output`/`ResultPath` so its input is only `{Error, Cause}`; INFO when the target is also reached normally | keep the input: `"Output": "{% $merge([$states.input, {'error': $states.errorOutput}]) %}"` or `"ResultPath": "$.error"` |
