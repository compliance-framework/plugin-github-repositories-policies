package compliance_framework.branch_dismisses_stale_approvals_test

import data.compliance_framework.branch_dismisses_stale_approvals as policy

# Branch that fails to dismiss stale reviews should trigger a violation.
test_violation_when_stale_reviews_not_dismissed if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"main": {
				"required_pull_request_reviews": {
					"dismiss_stale_reviews": false,
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_stale_reviews_not_set if {
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

test_violation_when_bpr_not_set if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {},
	}
	violations := policy.violation with input as inp
	count(violations) == 1
}

# Branch dismissing stale reviews should pass.
test_pass_when_stale_reviews_dismissed if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"main": {
				"required_pull_request_reviews": {
					"dismiss_stale_reviews": true,
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}
