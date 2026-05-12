package compliance_framework.security_required_checks_test

import data.compliance_framework.security_required_checks as policy

test_violation_when_branch_has_only_build_check if {
	inp := {
		"protected_branches": ["main"],
		"required_status_checks": {"checks": [{"context": "build"}, {"context": "unit tests"}]},
		"effective_branch_rules": {},
	}

	violations := policy.violation with input as inp
	violations[{"id": "security_required_check_missing", "remarks": "Repository has no security-focused required check or code scanning ruleset."}]
}

test_pass_when_required_check_is_security_named if {
	inp := {
		"protected_branches": ["main"],
		"required_status_checks": {"checks": [{"context": "CodeQL / Analyze"}]},
		"effective_branch_rules": {},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_api_shaped_context_is_security_named if {
	inp := {
		"protected_branches": ["main"],
		"required_status_checks": {"contexts_url": "https://api.github.com/...", "contexts": ["security / scan"]},
		"effective_branch_rules": {},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_ruleset_has_code_scanning_tool if {
	inp := {
		"protected_branches": ["main"],
		"required_status_checks": {"checks": [{"context": "build"}]},
		"effective_branch_rules": {"main": {"code_scanning_tools": ["CodeQL"]}},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_api_shaped_required_status_checks_do_not_create_pseudo_branches if {
	inp := {
		"protected_branches": ["main"],
		"required_status_checks": {"contexts_url": "https://api.github.com/...", "contexts": ["build"]},
		"effective_branch_rules": {},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
	violations[{"id": "security_required_check_missing", "remarks": "Repository has no security-focused required check or code scanning ruleset."}]
}
