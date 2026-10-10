resource "aws_sfn_state_machine" "x" {
  definition = templatefile("sm.json", {})
}
# sm.json content:
{"QueryLanguage":"JSONata","StartAt":"T","States":{
 "T":{"Type":"Task","Resource":"arn:aws:states:::lambda:invoke","Arguments":{"FunctionName":"${fn_arn}","Payload":"{% $states.input %}"},
      "Retry":[{"ErrorEquals":["States.TaskFailed"],"MaxAttempts":${max_attempts}}],
      "TimeoutSeconds":${timeout},"Output":"{% $states.result.Payload %}","Next":"M"},
 "M":{"Type":"Map","Items":"{% $states.input.items %}","MaxConcurrency":${mc},"ItemProcessor":{"StartAt":"S","States":{"S":{"Type":"Succeed"}}},"End":true}}}
