package compliance_framework.check_protected_branch_exists

violation[{}] if {
    count(input.protected_branches) == 0
}

title := "Repository has at least one protected branch"
description := "All repositories must have at least one protected branch configured."
