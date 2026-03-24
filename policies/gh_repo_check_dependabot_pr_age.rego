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

risk_templates := [{
  "name": "Unmerged Dependabot security update",
  "title": "Known Vulnerable Dependency Left Unpatched",
  "statement": "Dependabot pull requests older than the allowed grace period indicate that known vulnerable dependencies have been identified but not remediated. Leaving these open increases the window of exposure to publicly disclosed CVEs and exploits targeting known dependency vulnerabilities.",
  "likelihood_hint": "high",
  "impact_hint": "moderate",
  "violation_ids": ["stale_dependabot_pr"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1104",
      "title": "Use of Unmaintained Third Party Components",
      "url": "https://cwe.mitre.org/data/definitions/1104.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-937",
      "title": "OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities",
      "url": "https://cwe.mitre.org/data/definitions/937.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1035",
      "title": "OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities",
      "url": "https://cwe.mitre.org/data/definitions/1035.html"
    }
  ],
  "remediation": {
    "title": "Merge or address stale Dependabot pull requests",
    "description": "Review and merge outstanding Dependabot security update PRs within the allowed grace period. For breaking changes, open a tracked issue and apply a temporary exception with documented risk acceptance.",
    "tasks": [
      { "title": "Review all open Dependabot PRs and triage by severity (critical/high first)" },
      { "title": "Merge security update PRs that pass automated test suites" },
      { "title": "For breaking changes, create a tracked remediation issue and document risk acceptance" },
      { "title": "Enable auto-merge for Dependabot PRs in repositories with sufficient test coverage" },
      { "title": "Configure Dependabot to group minor/patch updates to reduce PR volume" }
    ]
  }
}]

# Throw violation if there exists a dependabot pull request older than 5 working days
violation[{"id": "stale_dependabot_pr"}] if {
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
