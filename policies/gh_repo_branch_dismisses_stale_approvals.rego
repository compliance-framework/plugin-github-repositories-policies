package compliance_framework.branch_dismisses_stale_approvals

import future.keywords.if

title := "Branch protection dismisses stale approvals"
description := "Protected branches must dismiss outdated approvals when new commits are pushed to ensure reviewers revalidate changes."

violation[{"remarks": sprintf("Branch protection for %q does not dismiss stale approvals after new commits.", [branch])}] if {
	branch := input.protected_branches[_]
	not branch_dismisses_stale_reviews(branch)
}

branch_dismisses_stale_reviews(branch) if {
	settings := branch_protection_settings(branch)
	require_dismiss_stale_reviews(settings)
}

branch_protection_settings(branch) := settings if {
	protection := object.get(input.branch_protection_rules, branch, {})
	settings := object.get(protection, "required_pull_request_reviews", {})
}

require_dismiss_stale_reviews(settings) if {
	object.get(settings, "dismiss_stale_reviews", false)
}
