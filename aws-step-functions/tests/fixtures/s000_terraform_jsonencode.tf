resource "aws_sfn_state_machine" "a" {
  name     = "a"
  role_arn = aws_iam_role.r.arn
  definition = jsonencode({
    QueryLanguage = "JSONata"
    StartAt       = "A"
    States = {
      A = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Arguments = { FunctionName = aws_lambda_function.f.arn }
        Next     = "B"
      }
    }
  })
}
