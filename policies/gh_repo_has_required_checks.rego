package compliance_framework.has_required_checks

violation[{}] if {
    count(input.required_status_checks) == 0
}

title := "Repository has required status checks"
description := "A repository must have required status checks configured to ensure that all code changes are properly tested and validated before being merged."
