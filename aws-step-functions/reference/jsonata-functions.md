# JSONata in Step Functions: allowed functions and operators

Step Functions implements JSONata 2.0.6. Everything below is the **complete** list.
If a function is not on this page it does not exist. Do not guess a name; compose
from the functions here, or move the transformation into a Lambda.

Every expression is a JSON string that starts with `{%` and ends with `%}`, no
leading or trailing whitespace: `"{% $states.input.id %}"`.

## Reserved variable `$states`

| Path | Meaning | Available in |
|---|---|---|
| `$states.input` | the state's input (unchanged by Arguments) | every JSONata field |
| `$states.result` | raw result of the Task / Map / Parallel | `Output` and `Assign` of Task, Map, Parallel **only** |
| `$states.errorOutput` | `{ "Error": "...", "Cause": "..." }` | `Output` and `Assign` inside a `Catch` **only** |
| `$states.context` | context object (below) | every JSONata field |

`$states.context` fields: `Execution.Id`, `Execution.Input`, `Execution.Name`,
`Execution.RoleArn`, `Execution.StartTime`, `Execution.RedriveCount`,
`Execution.RedriveTime`, `State.EnteredTime`, `State.Name`, `State.RetryCount`,
`StateMachine.Id`, `StateMachine.Name`, `Task.Token` (only in `.waitForTaskToken`
tasks), `Map.Item.Index`, `Map.Item.Value`, `Map.Item.Key`, `Map.Item.Source`
(only inside a Map state's `ItemSelector`).

Workflow variables: `$name` where `name` was declared in an `Assign` of an
earlier state on every path. Variables assigned in the current state are usable
only from the **next** state.

## Functions

Arguments in `[ ]` are optional. `array` means a JSON array, never a
comma-separated list: `$max([a, b])`, not `$max(a, b)`.

### String

| Function | Notes |
|---|---|
| `$string(x [, prettify])` | any value to string; objects become JSON text |
| `$length(str)` | characters in a **string** (arrays: `$count`) |
| `$substring(str, start [, length])` | zero-based; negative start counts from the end |
| `$substringBefore(str, chars)` / `$substringAfter(str, chars)` | |
| `$uppercase(str)` / `$lowercase(str)` | |
| `$trim(str)` | collapses whitespace runs and trims |
| `$pad(str, width [, char])` | negative width pads on the left |
| `$contains(str, pattern)` | pattern is a string or `/regex/` |
| `$split(str, separator [, limit])` | separator string or `/regex/` |
| `$join(array [, separator])` | array of strings first |
| `$match(str, /regex/ [, limit])` | returns `[{match, index, groups}]` |
| `$replace(str, pattern, replacement [, limit])` | replaces all by default; no `g` flag |
| `$base64encode(str)` / `$base64decode(str)` | |
| `$encodeUrlComponent(str)` / `$encodeUrl(str)` / `$decodeUrlComponent(str)` / `$decodeUrl(str)` | |

### Numeric

`$number(x)`, `$abs(n)`, `$floor(n)`, `$ceil(n)`, `$round(n [, precision])`,
`$power(base, exp)`, `$sqrt(n)`, `$random([seed])`, `$formatNumber(n, picture [, options])`,
`$formatBase(n [, radix])`, `$formatInteger(n, picture)`, `$parseInteger(str, picture)`.

Arithmetic operators: `+ - * / %` (modulo). `$number('12')` converts strings;
`'a' + 1` is a runtime error.

### Aggregation (one array argument)

`$sum(array)`, `$max(array)`, `$min(array)`, `$average(array)`.

### Boolean

`$boolean(x)`, `$not(x)`, `$exists(x)`.
Logic operators: `and`, `or` (lowercase words). Negation is `$not(x)`.

### Array

`$count(array)`, `$append(a, b)`, `$sort(array [, function($l, $r) { ... }])`,
`$reverse(array)`, `$shuffle(array)`, `$distinct(array)`, `$zip(a, b, ...)`.

Indexing: `arr[0]` first, `arr[-1]` last, `arr[[1..3]]` slice, `arr[price > 10]`
filter, `arr.name` map to a field. A single-element result is auto-unwrapped;
append `[]` to keep an array: `arr[price > 10][]`.

### Object

`$keys(obj)`, `$lookup(obj, key)`, `$spread(obj)`, `$merge([obj1, obj2])`,
`$sift(obj, function($v, $k) { ... })`, `$each(obj, function($v, $k) { ... })`,
`$error(message)`, `$assert(condition, message)`, `$type(x)` (returns
`'null' | 'number' | 'string' | 'boolean' | 'array' | 'object' | 'function'`).

Object constructor: `{ 'id': $states.input.id, 'total': $sum($items.price) }`.
Grouping: `$items{ category: $sum(price) }`.

### Date / time

`$now([picture [, timezone]])` ISO-8601 UTC string, `$millis()` epoch ms,
`$fromMillis(ms [, picture [, timezone]])`, `$toMillis(timestamp [, picture])`.

Picture strings follow XPath `format-dateTime`: `'[Y0001]-[M01]-[D01]T[H01]:[m01]:[s01]Z'`.
A future Wait timestamp: `{% $fromMillis($millis() + 3600000) %}`.

### Higher-order

`$map(array, function($v [, $i [, $a]]) { ... })`,
`$filter(array, function($v [, $i [, $a]]) { ... })`,
`$single(array, function($v [, $i [, $a]]) { ... })`,
`$reduce(array, function($acc, $v [, $i [, $a]]) { ... } [, init])`,
`$sift(obj, function($v [, $k [, $o]]) { ... })`.

Anonymous function syntax is `function($x) { $x + 1 }`. Chain with `~>`:
`$states.input.name ~> $trim() ~> $uppercase()`.

### Step Functions additions (replace intrinsic functions)

| Function | Replaces |
|---|---|
| `$partition(array, chunkSize)` | `States.ArrayPartition` |
| `$range(start, end, step)` | `States.ArrayRange` |
| `$hash(str, 'MD5' \| 'SHA-1' \| 'SHA-256' \| 'SHA-384' \| 'SHA-512')` | `States.Hash` |
| `$random([seed])` | `States.MathRandom` |
| `$uuid()` | `States.UUID` |
| `$parse(jsonString)` | `States.StringToJson` (and `$eval`, which is **not supported**) |

`States.Format`, `States.ArrayLength`, `States.JsonToString` and every other
`States.*` intrinsic are JSONPath-only. Inside `{% %}` use `&`, `$count`, `$string`.

## Operators

| Kind | Operators |
|---|---|
| Comparison | `=` `!=` `<` `>` `<=` `>=` `in` (single `=`; there is no `==`) |
| Logic | `and` `or` (no `&&`, `\|\|`, `!`) |
| String concat | `&` (`'id-' & $states.input.id`; non-strings need `$string()`) |
| Conditional | `cond ? a : b` |
| Default | `a ?? b` (b when a is undefined), `a ?: b` (b when a is falsy) |
| Binding | `$x := expr` inside a block `( $x := 1; $x + 1 )` |
| Chain | `expr ~> $fn(args)` |
| Path | `.` map, `[ ]` filter/index, `^( )` sort, `{ }` group, `*` wildcard, `**` descendants, `%` parent, `#$i` position, `@$v` context |
| Range | `[1..5]` |
| Comments | `/* ... */` |

Regex literals: `/pattern/flags`, flags `i` and `m` only.

## Common inventions and their replacements

| Wrong | Right |
|---|---|
| `$length(array)` | `$count(array)` |
| `$size`, `$len` | `$count` / `$length` |
| `$toString`, `$str`, `$stringify` | `$string(x)` |
| `$toNumber`, `$parseInt`, `$int`, `$float` | `$number(x)`, `$floor($number(x))` |
| `$upper`, `$toUpperCase`, `$lower` | `$uppercase`, `$lowercase` |
| `$concat(a, b)` | `a & b`, or `$join([a, b], '')` |
| `$startsWith(s, p)` | `$substring(s, 0, $length(p)) = p` |
| `$endsWith(s, p)` | `$substring(s, -$length(p)) = p` |
| `$includes`, `$indexOf`, `$has` | `x in array`, `$contains(str, sub)`, `$exists(obj.key)` |
| `$isArray`, `$isString`, `$typeof` | `$type(x) = 'array'` |
| `$isEmpty`, `$isNull` | `$count(x) = 0`, `x = null`, `$not($exists(x))` |
| `$first`, `$last`, `$slice` | `arr[0]`, `arr[-1]`, `arr[[a..b]]` |
| `$push`, `$flatten` | `$append(arr, [x])`, `$reduce(arrs, function($a,$b){$append($a,$b)}, [])` |
| `$find`, `$some`, `$every` | `$filter(arr, fn)[0]`, `$count($filter(arr, fn)) > 0` |
| `$unique` | `$distinct` |
| `$max(a, b)` | `$max([a, b])` |
| `$mod`, `$pow`, `$trunc` | `a % b`, `$power`, `$floor` |
| `$if`, `$coalesce`, `$default`, `$ifNull` | `c ? a : b`, `a ?? b` |
| `$parseJson`, `$fromJson`, `$eval` | `$parse(str)` |
| `$toJson` | `$string(obj)` |
| `$date`, `$today`, `$timestamp`, `$formatDate` | `$now()`, `$millis()`, `$fromMillis(ms, picture)` |
| `$uuidv4`, `$guid` | `$uuid()` |
| `$sha256`, `$md5` | `$hash(str, 'SHA-256')` |
| `$mergeObjects`, `$assign`, `$extend` | `$merge([a, b])` |
| `$entries`, `$values` | `$each(obj, function($v, $k) {...})`, `$spread(obj)` |
| `$$.Execution.Id` | `$states.context.Execution.Id` |
| `$.field`, `$input.field` | `$states.input.field` |
| `$result.x` | `$states.result.x` (Output/Assign of Task, Map, Parallel only) |
| `States.Format('a{}', x)` | `'a' & $string(x)` |
| `x == 1`, `a && b`, `!a` | `x = 1`, `a and b`, `$not(a)` |

## Runtime failure modes (all raise `States.QueryEvaluationError`)

- **Undefined result.** `$states.input.missing` yields nothing, and a field cannot
  hold "nothing". Guard optional fields: `$states.input.note ?? null`,
  `$exists($x) ? $x : 0`.
- **Type mismatch.** `Seconds`, `TimeoutSeconds`, `MaxConcurrency` need integers;
  `Condition` needs a boolean; `Timestamp` needs an RFC3339 string. Convert
  with `$number()`, `$boolean()`, `$string()`.
- **Arithmetic on strings.** `$states.input.qty * 2` fails if `qty` is `"2"`.
- **Aggregations on non-numbers.** `$sum(items.price)` fails if any price is a string.
- **Limits.** One second of evaluation time, memory-capped; heavy transformations
  belong in a Lambda.
