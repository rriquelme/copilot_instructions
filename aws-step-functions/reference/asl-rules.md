# Amazon States Language rules (JSONata mode)

Source: AWS Step Functions Developer Guide, 2026. Hard rules; the linter enforces
the mechanical ones, this page is for writing them right the first time.

## Top level

```json
{
  "Comment": "...",
  "QueryLanguage": "JSONata",
  "StartAt": "<state name>",
  "TimeoutSeconds": 3600,
  "States": { ... }
}
```

- `QueryLanguage` defaults to `JSONPath`. New machines: `"JSONata"` at the top.
- A JSONata machine cannot contain JSONPath states. A JSONPath machine may
  contain states with `"QueryLanguage": "JSONata"`.
- `StartAt` must name a state in the same `States` object. Case-sensitive.
- State names: unique across the **whole** definition, including inside Map and
  Parallel, max 80 characters.

## Fields by state type

Fields valid for every state: `Type`, `Comment`, `QueryLanguage`.
Never in JSONata states: `InputPath`, `OutputPath`, `Parameters`, `ResultSelector`,
`ResultPath`, `Result`, `ItemsPath`, any `*Path` field, keys ending in `.$`,
`Variable` + comparison operators in Choice rules.

| Type | Required | Optional (JSONata) | Transition |
|---|---|---|---|
| `Task` | `Resource` | `Arguments`, `Output`, `Assign`, `Retry`, `Catch`, `TimeoutSeconds`, `HeartbeatSeconds`, `Credentials` | `Next` or `End: true` |
| `Pass` | | `Output`, `Assign` | `Next` or `End: true` |
| `Choice` | `Choices` | `Default` (always set it), `Assign`, `Output` | `Next` only inside each rule and in `Default`; no state-level `Next`/`End` |
| `Wait` | one of `Seconds`, `Timestamp` | `Output`, `Assign` | `Next` or `End: true` |
| `Succeed` | | `Output` | none |
| `Fail` | | `Error`, `Cause` (both accept `{% %}`) | none; no `Assign`, no `Output` |
| `Parallel` | `Branches` | `Arguments`, `Output`, `Assign`, `Retry`, `Catch` | `Next` or `End: true` |
| `Map` | `ItemProcessor` | `Items`, `ItemSelector`, `MaxConcurrency`, `Output`, `Assign`, `Retry`, `Catch`; Distributed only: `ItemReader`, `ItemBatcher`, `ResultWriter`, `ToleratedFailureCount`, `ToleratedFailurePercentage`, `Label` | `Next` or `End: true` |

`Retry` and `Catch` exist only on Task, Map, Parallel. `Assign` exists on
everything except Succeed and Fail.

### Choice rules

```json
{ "Condition": "{% $states.input.status = 'ok' and $count($items) > 0 %}", "Next": "Proceed", "Assign": { "route": "ok" } }
```

- `Condition` must evaluate to a boolean. A string `"true"` is a runtime error.
- Rules are evaluated in order; first match wins.
- Per-rule `Assign` runs only when that rule matches. The state-level `Assign`
  runs only when no rule matches (the `Default` path).
- No `Default` and no match: execution fails with `States.NoChoiceMatched`.

### Wait

- `Seconds`: integer 0 to 99,999,999 or `{% %}` evaluating to one.
- `Timestamp`: `2025-01-31T10:00:00Z` (uppercase T and Z) or `{% %}` producing one.
- Exactly one of the two.

### Task

- `Resource` is a constant string, never an expression.
- Optimized Lambda: `arn:aws:states:::lambda:invoke` with
  `Arguments: { FunctionName, Payload }`; result is
  `{ ExecutedVersion, Payload, StatusCode }`, so use `"Output": "{% $states.result.Payload %}"`.
- SDK integration: `arn:aws:states:::aws-sdk:<service>:<apiAction>` (camelCase action);
  `Arguments` are the API request fields in PascalCase as the API defines them.
- Suffixes: `.sync` (wait for job), `.waitForTaskToken` (pause until
  `SendTaskSuccess`/`SendTaskFailure`; pass `{% $states.context.Task.Token %}` in
  Arguments and set `HeartbeatSeconds` or `TimeoutSeconds`).
- `HeartbeatSeconds` < `TimeoutSeconds`. Set `TimeoutSeconds` on every Task that
  can hang (default is 99,999,999 seconds).

### Map

```json
"Process items": {
  "Type": "Map",
  "Items": "{% $states.input.items %}",
  "ItemSelector": { "item": "{% $states.context.Map.Item.Value %}", "index": "{% $states.context.Map.Item.Index %}", "orderId": "{% $orderId %}" },
  "MaxConcurrency": 10,
  "ItemProcessor": {
    "ProcessorConfig": { "Mode": "INLINE" },
    "StartAt": "Handle item",
    "States": { "Handle item": { "Type": "Task", "...": "...", "End": true } }
  },
  "Output": "{% $states.result %}",
  "Next": "After map"
}
```

- `Items` must be an array (or `{% %}` producing one). Without `Items` the whole
  state input is iterated.
- Inside `ItemSelector`, `$states.input` is the **Map state's** input, the item is
  `$states.context.Map.Item.Value`.
- Inside `ItemProcessor`, `$states.input` is the item (or the `ItemSelector` result).
- `$states.result` of the Map is the array of iteration outputs, in order.
- INLINE: max 40 concurrent, input array ≤ 256 KiB, shares the parent history.
  DISTRIBUTED: requires `ProcessorConfig.ExecutionType` (`STANDARD` or `EXPRESS`),
  child executions, cannot read outer-scope variables at all.
- `Iterator` and `Parameters` on Map are deprecated; use `ItemProcessor` and `ItemSelector`.
- `Retry` on a Map retries **all** iterations, not just the failed one.

### Parallel

- Each branch has its own `StartAt` and `States`; branches cannot transition to
  states outside themselves and nothing outside can jump in.
- `$states.result` is an array with one element per branch, in `Branches` order.
  Merge objects with `"Output": "{% $merge($states.result) %}"`.
- Every branch receives the Parallel state's input (shaped by `Arguments` if present).
- Any branch failing fails the Parallel state; the others are stopped.

## Data flow inside a state

```
state input
  └─ $states.input ──► Arguments ──► resource ──► $states.result
                                                  ├─► Output  (becomes next state's input)
                                                  └─► Assign  (variables; visible from the NEXT state)
```

- `Output` and `Assign` are evaluated **in parallel** from the same inputs. A
  variable assigned in this state is not visible in this state's `Output`.
- All expressions in an `Assign` see variable values as they were **on state
  entry**; the assignments happen after every expression is evaluated, so
  `"Assign": { "x": "{% $a %}", "nextX": "{% $x %}" }` gives `nextX` the old `x`.
- Without `Output`, a Task's output is its raw result; a Pass/Wait/Choice passes
  its input through unchanged.
- Payload between states max 256 KiB. Store large data in S3 and pass the key.

## Variables

- Declared by `Assign`: `"Assign": { "orderId": "{% $states.input.orderId %}", "attempt": 0 }`.
  Values are literals or `{% %}` expressions; whole values only (`"x.y"` is not
  assignable).
- Names: identifier characters, max 80. Referenced as `$name`.
- Scope: the `States` block that assigns them. Map iterations and Parallel branches
  **read** outer variables but their own assignments vanish when the Map/Parallel
  completes. Pass data out through `Output`.
- An inner scope may not assign a name that an outer scope assigns.
- A `Catch`'s `Assign` writes into the scope that contains the failing state.
- Distributed Map bodies cannot reference outer variables; pass them via `ItemSelector`.
- Limits: 256 KiB per variable and per `Assign`, 10 MiB total per execution.
- Referencing a variable that no earlier state on that path assigned is a
  runtime failure (undefined). Every read needs a definite prior assignment.

## Errors, Retry, Catch

Predefined error names: `States.ALL`, `States.TaskFailed` (any error except
`States.Timeout`), `States.Timeout`, `States.HeartbeatTimeout`,
`States.Permissions`, `States.QueryEvaluationError` (JSONata failure),
`States.DataLimitExceeded` (not matched by ALL), `States.Runtime` (never
catchable), `States.NoChoiceMatched`, `States.ExceedToleratedFailureThreshold`,
`States.ItemReaderFailed`, `States.ResultWriterFailed`, `States.Http.Socket`.
Service errors look like `Lambda.TooManyRequestsException`, `DynamoDB.ConditionalCheckFailedException`,
`Glue.EntityNotFoundException`. Lambda function exceptions surface under their
own name (`MyCustomError`) or as `States.TaskFailed`.

```json
"Retry": [
  { "ErrorEquals": ["Lambda.ClientExecutionTimeoutException", "Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"],
    "IntervalSeconds": 2, "MaxAttempts": 6, "BackoffRate": 2, "JitterStrategy": "FULL" },
  { "ErrorEquals": ["States.Timeout"], "MaxAttempts": 0 },
  { "ErrorEquals": ["States.ALL"], "IntervalSeconds": 1, "MaxAttempts": 2, "BackoffRate": 2, "MaxDelaySeconds": 30 }
],
"Catch": [
  { "ErrorEquals": ["MyBusinessError"], "Assign": { "reason": "{% $states.errorOutput.Cause %}" }, "Next": "Handle business error" },
  { "ErrorEquals": ["States.ALL"], "Output": { "error": "{% $states.errorOutput %}", "input": "{% $states.input %}" }, "Next": "Failed" }
]
```

- `ErrorEquals` non-empty. `States.ALL` alone in its array and in the **last**
  retrier/catcher.
- Retry fields: `IntervalSeconds` (default 1), `MaxAttempts` (default 3, 0 = no retry),
  `BackoffRate` (default 2.0), `MaxDelaySeconds`, `JitterStrategy` `FULL|NONE`.
- Catch fields in JSONata: `ErrorEquals`, `Next`, `Output`, `Assign`. `ResultPath`
  is JSONPath-only. Without `Output` the catch target receives
  `{ "Error", "Cause" }` only, the original input is lost unless you include it.
- `$states.errorOutput.Cause` from a Lambda is a JSON **string**; `$parse()` it.
- Retry then Catch: retriers exhaust first, then the first matching catcher runs.
- `Fail` with `Error`/`Cause` set is caught by an enclosing Map/Parallel's `Catch`
  and surfaces to a parent workflow as `States.TaskFailed`.

## Integration patterns quick table

| Need | Resource | Notes |
|---|---|---|
| Lambda | `arn:aws:states:::lambda:invoke` | `Output: {% $states.result.Payload %}`; add the Lambda transient-error Retry |
| DynamoDB | `arn:aws:states:::dynamodb:putItem` / `getItem` / `updateItem` / `query` | attribute values are typed: `{"S": "{% $string($id) %}"}`, `{"N": "{% $string($n) %}"}` |
| SQS | `arn:aws:states:::sqs:sendMessage` | `MessageBody` accepts a string or object |
| SNS | `arn:aws:states:::sns:publish` | `Message` string |
| EventBridge | `arn:aws:states:::events:putEvents` | `Entries[].Detail` object |
| Child workflow | `arn:aws:states:::states:startExecution.sync:2` | `Input` object; `.sync:2` returns parsed output |
| Human/async callback | `<service>.waitForTaskToken` | include `{% $states.context.Task.Token %}`, set `HeartbeatSeconds` |
| Any AWS API | `arn:aws:states:::aws-sdk:<service>:<action>` | request fields as the API defines them |
| HTTPS | `arn:aws:states:::http:invoke` | `ApiEndpoint`, `Method`, `Authentication.ConnectionArn`; 60 s max |

## Checklist that the linter cannot see

- Every `Arguments` field name matches the target API exactly (case-sensitive).
- Lambda `Payload` shape matches what the function reads.
- Types coming from Lambda/DynamoDB are what the expressions assume (DynamoDB
  numbers arrive as strings in `"N"`).
- IAM role of the state machine allows every `Resource` action (plus
  `states:StartExecution`/`DescribeExecution` for Distributed Map,
  `events:PutTargets|PutRule|DescribeRule` for `.sync`).
- `TimeoutSeconds` on long or external tasks; top-level `TimeoutSeconds` on
  Standard workflows that must not run for a year.
- Express workflows: 5-minute limit, no `.sync`, no `.waitForTaskToken`, no
  Distributed Map, no Activities.
