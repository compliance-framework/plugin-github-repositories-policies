package compliance_framework.required_workflows_exist

# Check that all required workflows exist in the repository

default has_required_workflows := false
has_required_workflows if {
    input.required_workflows != null
    count(input.required_workflows) > 0
}

# Violation: Required workflow does not exist
violation[{"workflow": w.path, "name": w.name}] if {
    has_required_workflows
    w := input.required_workflows[_]
    not w.exists
}

title := "Required workflows exist"
description := "All required CI/CD workflows must exist in the repository."
