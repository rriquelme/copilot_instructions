definition = <<JSON
{"QueryLanguage":"JSONata","StartAt":"A","States":{
 "A":{"Type":"Pass",%{ if debug }"Comment":"dbg",%{ endif }"Output":${jsonencode({a = "}", b = [1]})},"Next":"B"},
 "B":{"Type":"Pass","Output":"{% '${prefix}' & $states.input.x & '$${literal}' %}","End":true}}}
JSON
