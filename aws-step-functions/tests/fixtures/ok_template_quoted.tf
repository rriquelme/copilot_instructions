resource "aws_sfn_state_machine" "x" {
  definition = <<JSON
{"StartAt":"C","States":{
 "C":{"Type":"Choice","Choices":[{"Variable":"${var_path}","StringEquals":"${val}","Next":"D"},{"Variable":"$.n","NumericEquals":"${n}","Next":"D"}],"Default":"D"},
 "D":{"Type":"Pass","Parameters":{"a.$":"States.Format('${tpl} {}', $.x)","b.$":"$.${field}","c.$":"States.${fn}($.x)"},"ResultPath":"$.${out}","InputPath":"${in}","End":true}}}
JSON
}
