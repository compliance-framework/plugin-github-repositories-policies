package compliance_framework.failed_deployments_tracked_test

import data.compliance_framework.failed_deployments_tracked as policy

test_violation_when_failed_deployment_unresolved if {
	inp := {
		"failed_deployments": [{"deployment": {"id": 42, "environment": "production"}, "statuses": [{"state": "failure"}]}],
		"deployments": [{"deployment": {"id": 42, "environment": "production"}, "statuses": [{"state": "failure"}]}],
	}

	violations := policy.violation with input as inp
	violations[{"id": "failed_deployment_unresolved", "remarks": "Deployment 42 failed and has no later successful deployment to the same environment."}]
}

test_pass_when_no_failed_deployments if {
	inp := {"failed_deployments": []}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_failed_deployment_has_later_success_by_id if {
	inp := {
		"failed_deployments": [{"deployment": {"id": 42, "environment": "production"}, "statuses": [{"state": "failure"}]}],
		"deployments": [
			{"deployment": {"id": 42, "environment": "production"}, "statuses": [{"state": "failure"}]},
			{"deployment": {"id": 43, "environment": "production"}, "statuses": [{"state": "success"}]},
		],
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_failed_deployment_has_later_success_by_created_at if {
	inp := {
		"failed_deployments": [{"deployment": {"id": 42, "environment": "production", "created_at": "2026-05-05T10:00:00Z"}, "statuses": [{"state": "failure"}]}],
		"deployments": [
			{"deployment": {"id": 42, "environment": "production", "created_at": "2026-05-05T10:00:00Z"}, "statuses": [{"state": "failure"}]},
			{"deployment": {"id": 41, "environment": "production", "created_at": "2026-05-05T11:00:00Z"}, "statuses": [{"state": "success"}]},
		],
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_later_success_is_different_environment if {
	inp := {
		"failed_deployments": [{"deployment": {"id": 42, "environment": "production"}, "statuses": [{"state": "failure"}]}],
		"deployments": [{"deployment": {"id": 43, "environment": "staging"}, "statuses": [{"state": "success"}]}],
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_success_has_higher_id_but_earlier_created_at if {
	inp := {
		"failed_deployments": [{"deployment": {"id": 42, "environment": "production", "created_at": "2026-05-05T10:00:00Z"}, "statuses": [{"state": "failure"}]}],
		"deployments": [{"deployment": {"id": 43, "environment": "production", "created_at": "2026-05-05T09:00:00Z"}, "statuses": [{"state": "success"}]}],
	}

	violations := policy.violation with input as inp
	violations[{"id": "failed_deployment_unresolved", "remarks": "Deployment 42 failed and has no later successful deployment to the same environment."}]
}
