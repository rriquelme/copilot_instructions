resource "aws_sfn_state_machine" "a" {
  name     = "a"
  definition = <<JSON
{
  "QueryLanguage": "JSONata",
  "StartAt": "A",
  "States": {
    "A": {"Type": "Task", "Resource": "${lambda_arn}", "Next": "B"},
    "B": {"Type": "Pass", "Output": "{% $foo %}", "End": true}
  }
}
JSON
}
resource "aws_sfn_state_machine" "b" {
  definition = <<JSON
{"StartAt": "A", "States": {"A": {"Type": "Map", "ItemProcessor": {"StartAt": "S", "States": {"S": {"Type": "Succeed"}}}, "End": true,}}}
JSON
}
