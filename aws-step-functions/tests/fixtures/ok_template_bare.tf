resource "aws_sfn_state_machine" "x" {
  definition = <<JSON
{"StartAt":"C","States":{
 "C":{"Type":"Choice","Choices":[{"Variable":"$.n","NumericEquals":${limit},"Next":"D"},{"Variable":"$.b","BooleanEquals":${flag},"Next":"D"}],"Default":"D"},
 "D":{"Type":"Pass","ResultPath":${rp},"End":true}}}
JSON
}
