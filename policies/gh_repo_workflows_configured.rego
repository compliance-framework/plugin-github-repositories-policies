package compliance_framework.workflows_configured

violation[{}] if {
	count(input.workflows) == 0
}

violation[{}] if {
	every workflow in input.workflows {
		not contains(lower(workflow.name), "build")
		not contains(lower(workflow.name), "ci")
	}
}

title := "Repository has workflows configured"
description := "All repositories must have workflows configured."
