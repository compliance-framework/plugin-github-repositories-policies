package compliance_framework.check_dependabot_pr_age

import data.compliance_framework.check_dependabot_pr_age as policy

test_recent_pr_ok if {
	now := time.parse_rfc3339_ns("2025-06-10T09:00:00Z")
	inp := {"pull_requests": [{
		"created_at": "2025-06-09T09:00:00Z",
		"user": {"login": "dependabot[bot]"},
	}]}
	v := count(policy.violation) with input as inp with time.now_ns as now
	v == 0
}

test_old_pr_violation if {
	now := time.parse_rfc3339_ns("2025-06-10T10:00:00Z")
	inp := {"pull_requests": [{
		"created_at": "2025-06-03T9:00:00Z",
		"user": {"login": "dependabot[bot]"},
	}]}
	v := count(policy.violation) with input as inp with time.now_ns as now
	v == 1
}


test_non_bot_pr_ok if {
	now := time.parse_rfc3339_ns("2025-06-10T09:00:00Z")
	inp := {"pull_requests": [{
		"created_at": "2025-05-09T09:00:00Z",
		"user": {"login": "michael"},
	}]}
	v := count(policy.violation) with input as inp with time.now_ns as now
	v == 0
}