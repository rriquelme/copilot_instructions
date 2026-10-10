resource "aws_sfn_state_machine" "orders" {
  name     = "orders"
  role_arn = var.role_arn

  definition = <<EOF
{
  "QueryLanguage": "JSONata",
  "StartAt": "Validate",
  "States": {
    "Validate": {"Type": "Pass", "Next": "Done"},
    "Done": {"Type": "Succeed"},
    "Validate": {"Type": "Pass", "Next": "Done"}
  }
}
EOF
}
