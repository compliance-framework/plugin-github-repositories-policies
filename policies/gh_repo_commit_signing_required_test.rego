package compliance_framework.commit_signing_required_test

import data.compliance_framework.commit_signing_required as policy

test_violation_when_signing_missing_on_protected_branch if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {"main": {}},
		"effective_branch_rules": {"main": {"required_signatures": false}},
	}

	violations := policy.violation with input as inp
	violations[{"id": "commit_signing_not_required", "remarks": "Branch \"main\" does not require signed commits."}]
}

test_pass_when_ruleset_requires_signatures if {
	inp := {
		"protected_branches": ["main"],
		"effective_branch_rules": {"main": {"required_signatures": true}},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_branch_protection_requires_signatures if {
	inp := {
		"protected_branches": ["main"],
		"branch_protection_rules": {"main": {"required_signatures": {"enabled": true}}},
		"effective_branch_rules": {},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_signing_missing_on_default_branch if {
	inp := {
		"default_branch": "main",
		"protected_branches": [],
		"branch_protection_rules": {},
		"effective_branch_rules": {},
	}

	violations := policy.violation with input as inp
	violations[{"id": "commit_signing_not_required", "remarks": "Branch \"main\" does not require signed commits."}]
}

test_skip_when_no_rules_to_evaluate if {
	inp := {
		"protected_branches": [],
		"effective_branch_rules": {},
        "default_branch": "",
	}

	policy.skip_reason != "" with input as inp
}
