resource "aws_sfn_state_machine" "heredoc" {
  name       = "heredoc"
  definition = <<EOF
{
  "QueryLanguage": "JSONata",
  "StartAt": "A",
  "States": { "A": { "Type": "Pass", "Next": "B" } }
}
EOF
}

resource "aws_sfn_state_machine" "generated" {
  name = "generated"
  definition = jsonencode({
    StartAt = "First"
    States  = { for s in var.states : s.name => s.body }
  })
}
