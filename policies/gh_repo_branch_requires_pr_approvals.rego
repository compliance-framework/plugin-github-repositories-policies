package compliance_framework.branch_requires_pr_approvals

import future.keywords.if

min_required_approvals := 1

title := "Branch protection enforces minimum PR approvals"
description := sprintf("Protected branches must require at least %d approving review(s) before merging.", [min_required_approvals])

violation[{"remarks": sprintf("Branch protection for %q requires fewer than %d approvals before merging.", [branch, min_required_approvals])}] if {
	branch := input.protected_branches[_]
	not branch_meets_approval_requirement(branch)
}

branch_meets_approval_requirement(branch) if {
	settings := branch_protection_settings(branch)
	required_approvals(settings) >= min_required_approvals
}

branch_protection_settings(branch) := settings if {
	protection := object.get(input.branch_protection_rules, branch, {})
	settings := object.get(protection, "required_pull_request_reviews", {})
}

required_approvals(settings) := object.get(settings, "required_approving_review_count", 0)
