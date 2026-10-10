# IAM policies are jsonencode()d too: not a state machine, so ignored
resource "aws_iam_role_policy" "p" {
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = "*" }]
  })
}

resource "aws_sfn_state_machine" "orders" {
  name     = "orders-${var.env}"
  role_arn = aws_iam_role.sfn.arn
  definition = jsonencode({
    Comment       = "Order flow for ${var.env}" // interpolation inside a string
    QueryLanguage = "JSONata"
    StartAt       = "Price order"
    TimeoutSeconds = var.timeout_seconds
    States = {
      /* a block comment
         spanning lines */
      "Price order" = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Arguments = {
          FunctionName = aws_lambda_function.price.arn
          Payload      = "{% $states.input %}"
        }
        Output         = "{% $states.result.Payload %}"
        TimeoutSeconds = 60
        Retry = [
          { ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException",
            "Lambda.TooManyRequestsException"], IntervalSeconds = 2, MaxAttempts = 6, BackoffRate = 2.0, JitterStrategy = "FULL" },
        ]
        Catch = [{
          ErrorEquals = ["States.ALL"],
          Output      = { error = "{% $states.errorOutput %}" },
          Next        = "Order failed",
        }]
        Next = "Route"
      }
      Route = {
        Type = "Choice"
        Choices = [
          { Condition = "{% $states.input.total > ${var.threshold} %}", Next = "Manual review" },
        ]
        Default = "Done"
      }
      "Manual review" : {
        Type    = "Wait"
        Seconds = var.review_wait > 0 ? var.review_wait : 60
        Next    = "Done"
      }
      Done = { Type = "Succeed" }
      "Order failed" = {
        Type  = "Fail"
        Error = "OrderFailed"
        Cause = <<-EOT
          Pricing failed for ${var.env}
        EOT
      }
    }
  })
}
