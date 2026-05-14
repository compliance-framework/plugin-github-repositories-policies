package compliance_framework.branch_requires_code_owner_reviews_test

import data.compliance_framework.branch_requires_code_owner_reviews as policy

test_violation_when_code_owner_reviews_disabled if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"main": {
				"required_pull_request_reviews": {
					"require_code_owner_reviews": false,
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_code_owner_reviews_not_set if {
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

test_violation_when_no_branch_protection_rules if {
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

test_violation_codeowners_not_set if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"main": {
				"required_pull_request_reviews": {
					"require_code_owner_reviews": true,
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_code_owner_is_empty if {
	inp := {
        "code_owners": {
            "content": ""
        },
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"main": {
				"required_pull_request_reviews": {
					"require_code_owner_reviews": true,
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_code_owner_is_and_bpr_are_set if {
	inp := {
        "code_owners": {
            "content": "something"
        },
		"protected_branches": ["main"],
		"branch_protection_rules": {
			"main": {
				"required_pull_request_reviews": {
					"require_code_owner_reviews": true,
				},
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_code_owner_is_and_effective_rules_are_set if {
	inp := {
        "code_owners": {
            "content": "something"
        },
		"protected_branches": ["main"],
		"branch_protection_rules": {},
		"effective_branch_rules": {
			"main": {
				"require_code_owner_review": true,
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_effective_rules_code_owner_disabled if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {},
		"effective_branch_rules": {
			"main": {
				"require_code_owner_review": false,
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_effective_rules_code_owner_not_set if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {},
		"effective_branch_rules": {
			"main": {},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_codeowners_not_set_with_effective_rules if {
	inp := {
        "code_owners": {
            "content": ""
        },
		"protected_branches": ["main"],
		"branch_protection_rules": {},
		"effective_branch_rules": {
			"main": {
				"require_code_owner_review": true,
			},
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

