resource "aws_sfn_state_machine" "a" {
  definition = <<EOT
{"StartAt": "A", "States": {
%{ for s in steps ~}
  "${s}": {"Type": "Pass", "End": true}
%{ endfor ~}
  "Z": {"Type": "Pass", "End": true}
}}
EOT
}
