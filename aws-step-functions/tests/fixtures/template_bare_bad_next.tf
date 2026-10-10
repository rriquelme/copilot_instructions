definition = <<JSON
{"QueryLanguage":"JSONata","StartAt":"W","States":{
 "W":{"Type":"Wait","Seconds":${wait_seconds},"Next":"Nope"},
 "T":{"Type":"Task","Resource":"arn:aws:states:::sqs:sendMessage","Arguments":{"QueueUrl":"q","MessageBody":"x"},"TimeoutSeconds":${timeout},"HeartbeatSeconds":${hb},"Retry":[{"ErrorEquals":["States.ALL"],"MaxAttempts":${n},"IntervalSeconds":${i},"BackoffRate":${b}}],"Next":"M"},
 "M":{"Type":"Map","Items":${items},"MaxConcurrency":${mc},"ItemProcessor":{"StartAt":"S","States":{"S":{"Type":"Succeed"}}},"End":true}}}
JSON
