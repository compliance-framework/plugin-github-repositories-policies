package compliance_framework.workflow_health

total := count(input.workflow_runs)
passed := count([x |
    x := input.workflow_runs[_]
    x.conclusion == "success"
])
tolerance := 0.2

violation[{}] if {
    tolerance_amount = max([total, passed]) * tolerance
	abs(total - passed) > tolerance_amount
}

title := "Repository has healthy workflow runs"
description := sprintf("All repositories must have healthy workflow runs. [%d/%d - tolerance %d%%]", [passed, total, tolerance * 100])
remarks := sprintf("All repositories must have healthy workflow runs. Healthy workflow runs are calculated with a tolerance of %d%%", [tolerance * 100])