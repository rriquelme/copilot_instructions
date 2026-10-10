resource "aws_sfn_state_machine" "fan_out" {
  name = "fan-out"
  definition = jsonencode({
    QueryLanguage = "JSONata"
    StartAt       = "Start"
    States = merge({ Start = { Type = "Pass", Next = "Step0" } }, {
      for i, name in var.steps : "Step${i}" => { Type = "Pass", End = true }
    })
  })
}
