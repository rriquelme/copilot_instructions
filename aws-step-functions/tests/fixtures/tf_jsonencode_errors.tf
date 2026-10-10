resource "aws_sfn_state_machine" "a" {
  name = "a"
  definition = jsonencode({
    QueryLanguage = "JSONata",
    StartAt       = "Load",
    States = {
      Load = {
        Type      = "Task",
        Resource  = "arn:aws:states:::dynamodb:getItem",
        Arguments = { TableName = var.table, Key = { id = { S = "{% $states.input.id %}" } } },
        Nxt       = "Done",
        End       = true,
      },
      Done = { Type = "Succeed" },
    },
  })
}

resource "aws_sfn_state_machine" "b" {
  name = "b"
  definition = jsonencode({
    "QueryLanguage" = "JSONata"
    "StartAt"       = "Wait"
    "States" = {
      "Wait" = { "Type" = "Wait", "Seconds" = "10", "Next" = "Missing" }
    }
  })
}
