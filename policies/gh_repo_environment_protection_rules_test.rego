package compliance_framework.repository_environment_protection_test

import data.compliance_framework.repository_environment_protection as policy

test_violation_when_no_production_environment if {
	inp := {"environments": [{"name": "staging"}]}

	violations := policy.violation with input as inp
	violations[{"id": "production_environment_missing", "remarks": "Repository has no production-like deployment environment."}]
}

test_skip_when_no_environments if {
	inp := {"environments": []}

	policy.skip_reason != "" with input as inp
}

test_violation_when_production_environment_unprotected if {
	inp := {"environments": [{"name": "production"}]}

	violations := policy.violation with input as inp
	violations[{"id": "environment_unprotected", "remarks": "Environment \"production\" has no required reviewers, wait timer, or branch deployment policy."}]
}

test_pass_when_production_environment_has_reviewers if {
	inp := {"environments": [{"name": "prod", "reviewers": [{"type": "team", "id": 1}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_production_environment_has_branch_policy if {
	inp := {"environments": [{"name": "production", "deployment_branch_policy": {"protected_branches": true}}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_non_production_substrings_are_not_production_like if {
	inp := {"environments": [{"name": "product"}, {"name": "prod-test"}]}

	violations := policy.violation with input as inp
	violations[{"id": "production_environment_missing", "remarks": "Repository has no production-like deployment environment."}]
	count(violations) == 1
}

test_pass_when_common_production_variant_has_reviewers if {
	inp := {"environments": [{"name": "production-us-east", "reviewers": [{"type": "team", "id": 1}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
