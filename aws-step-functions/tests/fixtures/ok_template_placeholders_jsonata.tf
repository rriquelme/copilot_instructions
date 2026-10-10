definition = <<JSON
{"QueryLanguage":"JSONata","TimeoutSeconds":${t},"StartAt":"W","States":{
 "W":{"Type":"Wait","Seconds":${s},"Next":"W2"},
 "W2":{"Type":"Wait","Timestamp":${ts},"Next":"W3"},
 "W3":{"Type":"Wait","Timestamp":"${ts}","Next":"T"},
 "T":{"Type":"Task","Resource":"${arn}","Arguments":{"QueueUrl":"${q}","MessageBody":${body}},"TimeoutSeconds":${timeout},"HeartbeatSeconds":${hb},
   "Retry":[{"ErrorEquals":["States.ALL"],"MaxAttempts":${n},"IntervalSeconds":${i},"BackoffRate":${b},"MaxDelaySeconds":${md},"JitterStrategy":${j}}],"Next":"M"},
 "M":{"Type":"Map","Items":${items},"MaxConcurrency":${mc},"ItemProcessor":{"ProcessorConfig":{"Mode":${mode},"ExecutionType":"${et}"},"StartAt":"S","States":{"S":{"Type":"Succeed"}}},"ToleratedFailureCount":${tfc},"ToleratedFailurePercentage":${tfp},"Next":"C"},
 "C":{"Type":"Choice","Choices":[{"Condition":${cond},"Next":"P"}],"Default":"P"},
 "P":{"Type":"Pass","Output":${out},"End":true}}}
JSON
