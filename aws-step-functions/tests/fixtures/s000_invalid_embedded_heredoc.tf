resource "x" "y" {
  definition = <<JSON
{"QueryLanguage":"JSONata","StartAt":"M","States":{"M":{"Type":"Map","Items":"{% $states.input %}","ItemProcessor":{"StartAt":"S","States":{"S":{"Type":"Succeed"}}},"Next":"X",}}}
JSON
}
