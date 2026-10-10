definition = <<JSON
{"StartAt":"W","TimeoutSeconds":${t},"States":{
 "W":{"Type":"Wait","Seconds":${s},"Next":"W2"},
 "W2":{"Type":"Wait","Timestamp":"${ts}","Next":"T"},
 "T":{"Type":"Task","Resource":"arn:aws:states:::sqs:sendMessage","Parameters":{"QueueUrl":"${q}","MessageBody.$":"$.x"},"TimeoutSeconds":${timeout},"HeartbeatSeconds":${hb},
   "Retry":[{"ErrorEquals":["States.ALL"],"MaxAttempts":${n},"IntervalSeconds":${i},"BackoffRate":${b}}],"ResultPath":"$.r","Next":"M"},
 "M":{"Type":"Map","ItemsPath":"$.items","MaxConcurrency":${mc},"ItemProcessor":{"StartAt":"S","States":{"S":{"Type":"Succeed"}}},"Next":"C"},
 "C":{"Type":"Choice","Choices":[{"Variable":"$.a","NumericEquals":${num},"Next":"P"},{"Variable":"$.a","BooleanEquals":${bo},"Next":"P"},{"Variable":"$.a","IsPresent":${ip},"Next":"P"},{"Variable":"$.a","TimestampEquals":"${tse}","Next":"P"},{"Variable":"$.a","StringEquals":${se},"Next":"P"}],"Default":"P"},
 "P":{"Type":"Pass","Result":${res},"End":true}}}
JSON
