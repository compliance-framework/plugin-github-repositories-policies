package compliance_framework.repository_environment_protection_test

import data.compliance_framework.repository_environment_protection as policy

test_violation_when_environment_unprotected_with_policy_input if {
	inp := {
		"environments": [{"name": "production"}],
		"policy_input": {"environment_names": ["production"]},
	}

	violations := policy.violation with input as inp
	violations[{"id": "environment_unprotected", "remarks": "Environment \"production\" has no required reviewers, wait timer, or branch deployment policy."}]
}

test_violation_when_all_environments_unprotected_no_policy_input if {
	inp := {"environments": [{"name": "staging"}, {"name": "production"}]}

	violations := policy.violation with input as inp
	count(violations) == 2
}

test_skip_when_no_environments_and_no_policy_input if {
	inp := {"environments": []}

	policy.skip_reason != "" with input as inp
}

test_violation_when_expected_environment_missing if {
	inp := {
		"environments": [],
		"policy_input": {"environment_names": ["production"]},
	}

	violations := policy.violation with input as inp
	violations[{"id": "environment_missing", "remarks": "Expected environment \"production\" does not exist in repository."}]
}

test_pass_when_environment_has_reviewers_with_policy_input if {
	inp := {
		"environments": [{"name": "production", "reviewers": [{"type": "team", "id": 1}]}],
		"policy_input": {"environment_names": ["production"]},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_environment_has_branch_policy_with_policy_input if {
	inp := {
		"environments": [{"name": "production", "deployment_branch_policy": {"protected_branches": true}}],
		"policy_input": {"environment_names": ["production"]},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_non_specified_environment_unprotected if {
	inp := {
		"environments": [{"name": "staging"}, {"name": "production", "reviewers": [{"type": "team", "id": 1}]}],
		"policy_input": {"environment_names": ["production"]},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_specified_environment_unprotected_with_other_protected if {
	inp := {
		"environments": [{"name": "staging", "reviewers": [{"type": "team", "id": 1}]}, {"name": "production"}],
		"policy_input": {"environment_names": ["production"]},
	}

	violations := policy.violation with input as inp
	violations[{"id": "environment_unprotected", "remarks": "Environment \"production\" has no required reviewers, wait timer, or branch deployment policy."}]
}

test_pass_when_all_environments_protected_no_policy_input if {
	inp := {
		"environments": [
			{"name": "staging", "reviewers": [{"type": "team", "id": 1}]},
			{"name": "production", "deployment_branch_policy": {"protected_branches": true}},
		],
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_description_combined_missing_and_unprotected if {
	inp := {
		"environments": [{"name": "staging"}],
		"policy_input": {"environment_names": ["production", "staging"]},
	}

	desc := policy.description with input as inp
	desc == "Missing required environments: production. Environments without protection: staging"
}
