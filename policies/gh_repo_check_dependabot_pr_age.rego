package compliance_framework.check_dependabot_pr_age

one_day_ns := ((24 * 60) * 60) * 1e9

reduce_day_ns(ns) := ns if {
	day := time.weekday(ns)
	day != "Sunday"
	day != "Saturday"
}

reduce_day_ns(ns) := working_day_ns if {
	day := time.weekday(ns)
	day == "Sunday"
	working_day_ns := ns - (2 * one_day_ns)
}

reduce_day_ns(ns) := working_day_ns if {
	day := time.weekday(ns)
	day == "Saturday"
	working_day_ns := ns - one_day_ns
}

# Throw violation if there exists a dependabot pull request older than 5 working days
violation[{}] if {
	some pr in input.pull_requests
	pr.user.login == "dependabot[bot]"
	time.parse_rfc3339_ns(pr.created_at) < reduce_day_ns(time.now_ns()) - (one_day_ns * 7)
}

title := "Enforcement of merging of pull requests after a grace period."
description := `
Automatic pull requests for dependency updates should be merged after 5 working days to reduce 
security vulnerabilities.
`

remarks := `
A good practice is to merge trusted dependencies (e.g. spring boot) after a grace period like one week. 
Often, patches, fixes and minor updates are automatically merged. Be aware that automated merging requires 
a high automated test coverage.
`
