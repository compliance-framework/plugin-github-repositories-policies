package compliance_framework.security_required_checks

import future.keywords.if

required_status_checks := object.get(input, "required_status_checks", {})
effective_branch_rules := object.get(input, "effective_branch_rules", {})
security_keywords := {"sast", "dast", "codeql", "code scanning", "security", "dependency", "dependabot", "vulnerability", "container scan", "trivy", "grype", "semgrep", "sbom", "secret"}

title := "Protected branches require security status checks"
description := "Protected and default branches should require at least one security-focused status check such as SAST, code scanning, dependency scanning, container scanning, SBOM, or secret scanning."

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
      {"title": "Review required check names after workflow changes"}
    ]
  }
}]

branches_to_check := {branch |
  branch := object.keys(required_status_checks)[_]
} | {branch |
  branch := object.keys(effective_branch_rules)[_]
}

violation[{"id": "security_required_check_missing", "remarks": sprintf("Branch %q has no security-focused required check.", [branch])}] if {
  branch := branches_to_check[_]
  not branch_has_security_check(branch)
}

branch_has_security_check(branch) if {
  checks := object.get(required_status_checks, branch, {})
  check := object.get(checks, "checks", [])[_]
  security_check_name(object.get(check, "context", ""))
}

branch_has_security_check(branch) if {
  checks := object.get(required_status_checks, branch, {})
  context := object.get(checks, "contexts", [])[_]
  security_check_name(context)
}

branch_has_security_check(branch) if {
  rules := object.get(effective_branch_rules, branch, {})
  tool := object.get(rules, "code_scanning_tools", [])[_]
  tool != ""
}

security_check_name(name) if {
  lower_name := lower(name)
  keyword := security_keywords[_]
  contains(lower_name, keyword)
}
