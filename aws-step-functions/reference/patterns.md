# Copy-safe patterns (JSONata mode)

Every snippet here has been linted. Replace names and ARNs; keep the shape.

## Capture input into variables once, at the start

```json
"Store inputs": {
  "Type": "Pass",
  "Assign": {
    "orderId": "{% $states.input.orderId %}",
    "items": "{% $states.input.items ?? [] %}",
    "requestedBy": "{% $states.input.user.email ?? 'unknown' %}"
  },
  "Next": "Validate"
}
```

This is the only legitimate "Pass just to assign": it is `StartAt`, it captures
the execution input. Anywhere else, put `Assign` on the state that produces the
value.

## Lambda invoke with transient-error retry and typed catch

```json
"Price order": {
  "Type": "Task",
  "Resource": "arn:aws:states:::lambda:invoke",
  "Arguments": {
    "FunctionName": "arn:aws:lambda:eu-west-1:123456789012:function:price-order",
    "Payload": { "orderId": "{% $orderId %}", "items": "{% $items %}" }
  },
  "Output": "{% $states.result.Payload %}",
  "Assign": { "total": "{% $states.result.Payload.total %}" },
  "TimeoutSeconds": 60,
  "Retry": [
    { "ErrorEquals": ["Lambda.ClientExecutionTimeoutException", "Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"],
      "IntervalSeconds": 2, "MaxAttempts": 6, "BackoffRate": 2, "JitterStrategy": "FULL" }
  ],
  "Catch": [
    { "ErrorEquals": ["PricingUnavailable"], "Assign": { "pricingError": "{% $states.errorOutput.Cause %}" }, "Next": "Use cached price" },
    { "ErrorEquals": ["States.ALL"], "Output": { "error": "{% $states.errorOutput %}", "orderId": "{% $orderId %}" }, "Next": "Order failed" }
  ],
  "Next": "Charge"
}
```

## Choice with per-rule Assign and a Default

```json
"Route by amount": {
  "Type": "Choice",
  "Choices": [
    { "Condition": "{% $total >= 1000 %}", "Assign": { "tier": "manual-review" }, "Next": "Manual review" },
    { "Condition": "{% $total > 0 and $total < 1000 %}", "Assign": { "tier": "auto" }, "Next": "Auto approve" }
  ],
  "Default": "Reject",
  "Assign": { "tier": "rejected" }
}
```

Every path out of the Choice assigns `tier`, so later states may read `$tier`.

## Poll loop with counter and backoff

```json
"Init poll": { "Type": "Pass", "Assign": { "attempt": 0, "maxAttempts": 20 }, "Next": "Get status" },
"Get status": {
  "Type": "Task",
  "Resource": "arn:aws:states:::aws-sdk:glue:getJobRun",
  "Arguments": { "JobName": "nightly", "RunId": "{% $runId %}" },
  "Assign": { "status": "{% $states.result.JobRun.JobRunState %}", "attempt": "{% $attempt + 1 %}" },
  "Output": "{% $states.input %}",
  "Next": "Finished?"
},
"Finished?": {
  "Type": "Choice",
  "Choices": [
    { "Condition": "{% $status = 'SUCCEEDED' %}", "Next": "Done" },
    { "Condition": "{% $status in ['FAILED', 'ERROR', 'TIMEOUT', 'STOPPED'] %}", "Next": "Job failed" },
    { "Condition": "{% $attempt >= $maxAttempts %}", "Next": "Gave up" }
  ],
  "Default": "Backoff"
},
"Backoff": { "Type": "Wait", "Seconds": "{% $min([300, 10 * $power(2, $attempt)]) %}", "Next": "Get status" }
```

`$attempt + 1` in `Get status` reads the value on entry, so the first pass yields 1.
`Output: {% $states.input %}` keeps the original payload flowing.

## Inline Map with item context and outer variable

```json
"Process items": {
  "Type": "Map",
  "Items": "{% $items %}",
  "ItemSelector": {
    "item": "{% $states.context.Map.Item.Value %}",
    "position": "{% $states.context.Map.Item.Index %}",
    "orderId": "{% $orderId %}"
  },
  "MaxConcurrency": 5,
  "ItemProcessor": {
    "ProcessorConfig": { "Mode": "INLINE" },
    "StartAt": "Reserve stock",
    "States": {
      "Reserve stock": {
        "Type": "Task",
        "Resource": "arn:aws:states:::dynamodb:updateItem",
        "Arguments": {
          "TableName": "stock",
          "Key": { "sku": { "S": "{% $states.input.item.sku %}" } },
          "UpdateExpression": "SET reserved = reserved + :q",
          "ConditionExpression": "available >= :q",
          "ExpressionAttributeValues": { ":q": { "N": "{% $string($states.input.item.qty) %}" } }
        },
        "Output": { "sku": "{% $states.input.item.sku %}", "reserved": true },
        "Catch": [
          { "ErrorEquals": ["DynamoDB.ConditionalCheckFailedException"], "Output": { "sku": "{% $states.input.item.sku %}", "reserved": false }, "Next": "Item done" }
        ],
        "Next": "Item done"
      },
      "Item done": { "Type": "Pass", "End": true }
    }
  },
  "Assign": { "unreserved": "{% $states.result[reserved = false].sku[] %}" },
  "Output": "{% $states.result %}",
  "Next": "All reserved?"
}
```

`$states.result[reserved = false].sku[]` filters the iteration outputs; the trailing
`[]` keeps an array even when one item matches.

## Parallel with merged output

```json
"Enrich": {
  "Type": "Parallel",
  "Branches": [
    { "StartAt": "Get customer", "States": { "Get customer": { "Type": "Task", "Resource": "arn:aws:states:::dynamodb:getItem", "Arguments": { "TableName": "customers", "Key": { "id": { "S": "{% $customerId %}" } } }, "Output": { "customer": "{% $states.result.Item %}" }, "End": true } } },
    { "StartAt": "Get limits", "States": { "Get limits": { "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "Arguments": { "FunctionName": "arn:aws:lambda:eu-west-1:123456789012:function:limits", "Payload": { "customerId": "{% $customerId %}" } }, "Output": { "limits": "{% $states.result.Payload %}" }, "End": true } } }
  ],
  "Output": "{% $merge($states.result) %}",
  "Assign": { "creditLimit": "{% $states.result[1].limits.credit %}" },
  "Next": "Decide"
}
```

## Wait for a human via task token

```json
"Request approval": {
  "Type": "Task",
  "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
  "Arguments": {
    "QueueUrl": "https://sqs.eu-west-1.amazonaws.com/123456789012/approvals",
    "MessageBody": { "orderId": "{% $orderId %}", "taskToken": "{% $states.context.Task.Token %}" }
  },
  "HeartbeatSeconds": 3600,
  "TimeoutSeconds": 86400,
  "Assign": { "approval": "{% $states.result %}" },
  "Catch": [ { "ErrorEquals": ["States.Timeout", "States.HeartbeatTimeout"], "Next": "Approval expired" } ],
  "Next": "Approved?"
}
```

`$states.result` is whatever `SendTaskSuccess` passed as `output`.

## Catch that keeps the original input and parses a Lambda cause

```json
"Catch": [
  {
    "ErrorEquals": ["States.ALL"],
    "Assign": { "lastError": "{% $states.errorOutput.Error %}", "lastCause": "{% $states.errorOutput.Cause %}" },
    "Output": {
      "input": "{% $states.input %}",
      "error": "{% $states.errorOutput.Error %}",
      "details": "{% $contains($states.errorOutput.Cause, '{') ? $parse($states.errorOutput.Cause) : $states.errorOutput.Cause %}"
    },
    "Next": "Compensate"
  }
]
```

## Terminal states

```json
"Done": { "Type": "Succeed", "Output": { "orderId": "{% $orderId %}", "total": "{% $total %}", "tier": "{% $tier %}" } },
"Order failed": { "Type": "Fail", "Error": "OrderFailed", "Cause": "{% 'order ' & $orderId & ': ' & $string($states.input.error.Cause) %}" }
```

`Fail` has no `Assign` and no `Output`; anything it needs must already be in the
input or in variables.

## Optional field guards

```json
"Output": {
  "note": "{% $states.input.note ?? null %}",
  "count": "{% $exists($states.input.items) ? $count($states.input.items) : 0 %}",
  "email": "{% $lowercase($trim($states.input.email ?? '')) %}"
}
```

## DynamoDB values are typed strings

```json
"Item": {
  "pk": { "S": "{% 'ORDER#' & $orderId %}" },
  "total": { "N": "{% $string($total) %}" },
  "paid": { "BOOL": "{% $paid %}" },
  "tags": { "L": "{% $map($tags, function($t) { { 'S': $t } }) %}" },
  "createdAt": { "S": "{% $now() %}" }
}
```

Reading back: `{% $number($states.result.Item.total.N) %}`.
