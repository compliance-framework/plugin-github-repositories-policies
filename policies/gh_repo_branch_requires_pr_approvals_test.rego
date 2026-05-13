package compliance_framework.branch_requires_pr_approvals_test

import data.compliance_framework.branch_requires_pr_approvals as policy

test_violation_when_required_approvals_zero if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"main": {
				"required_pull_request_reviews": {
					"required_approving_review_count": 0,
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_required_approvals_missing if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"main": {
				"required_pull_request_reviews": {
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}
test_violation_when_branch_protection_not_set if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"not-main": {
				"required_pull_request_reviews": {
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}
test_pass_when_required_approvals_met if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"main": {
				"required_pull_request_reviews": {
					"required_approving_review_count": 2,
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_required_approvals_met_in_effective_rules if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {},
		"effective_branch_rules": {
			"main": {
				"required_approving_review_count": 1,
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_required_approvals_zero_in_effective_rules if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {},
		"effective_branch_rules": {
			"main": {
				"required_approving_review_count": 0,
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_skip_when_no_protected_branches if {
	inp := {"protected_branches": []}
	policy.skip_reason != "" with input as inp
}
