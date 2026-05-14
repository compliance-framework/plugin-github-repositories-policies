package compliance_framework.security_required_checks

import future.keywords.if

required_status_checks := object.get(input, "required_status_checks", {})
effective_branch_rules := object.get(input, "effective_branch_rules", {})
security_keywords := {"sast", "dast", "codeql", "code scanning", "security", "dependency", "dependabot", "vulnerability", "container scan", "trivy", "grype", "semgrep", "sbom", "secret"}

title := "Repository requires security status checks"
description := "Repositories should require at least one security-focused status check or code scanning ruleset such as SAST, code scanning, dependency scanning, container scanning, SBOM, or secret scanning."

skip_reason := "Repository does not have any protected branches or effective rules, so required checks cannot be evaluated." if {
	count(object.get(input, "protected_branches", [])) == 0
	count(object.keys(effective_branch_rules)) == 0
}

risk_templates := [{
	"name": "No required security status checks",
	"title": "Security Validation Is Not Required Before Merge",
	"statement": "Required status checks without security-specific validation can allow vulnerable or secret-bearing code to merge as long as general build or test jobs pass.",
	"likelihood_hint": "moderate",
	"impact_hint": "high",
	"violation_ids": ["security_required_check_missing"],
	"remediation": {
		"title": "Require security checks before merge",
		"description": "Add at least one security-focused CI check to required status checks or enforce code scanning through repository rulesets.",
		"tasks": [
			{"title": "Add SAST, code scanning, dependency scanning, container scanning, SBOM, or secret scanning jobs"},
			{"title": "Mark the security job as required in branch protection or rulesets"},
			{"title": "Review required check names after workflow changes"},
		],
	},
}]

violation[{"id": "security_required_check_missing", "remarks": "Repository has no security-focused required check or code scanning ruleset."}] if {
	not repo_has_security_required_check
	not any_branch_has_security_rule
}

repo_has_security_required_check if {
	context := required_check_contexts[_]
	security_check_name(context)
}

required_check_contexts := {context |
	is_object(required_status_checks)
	checks := object.get(required_status_checks, "checks", [])
	is_array(checks)
	check := checks[_]
	is_object(check)
	context := object.get(check, "context", "")
	context != ""
} | {context |
	is_object(required_status_checks)
	contexts := object.get(required_status_checks, "contexts", [])
	is_array(contexts)
	context := contexts[_]
	is_string(context)
	context != ""
}

any_branch_has_security_rule if {
	branch := object.keys(effective_branch_rules)[_]
	rules := object.get(effective_branch_rules, branch, {})
	tool := object.get(rules, "code_scanning_tools", [])[_]
	tool != ""
}

security_check_name(name) if {
	lower_name := lower(name)
	keyword := security_keywords[_]
	contains(lower_name, keyword)
}
