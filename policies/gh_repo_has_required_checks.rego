package compliance_framework.has_required_checks

title := "Repository has required status checks"
description := "A repository must have required status checks configured to ensure that all code changes are properly tested and validated before being merged."

skip_reason := "Repository does not have any protected branches, so required status checks cannot be evaluated." if {
	count(object.get(input, "protected_branches", [])) == 0
}

risk_templates := [{
  "name": "No required status checks configured",
  "title": "Untested Code Can Be Merged Without CI Validation",
  "statement": "Without required status checks, pull requests can be merged regardless of whether automated tests, security scans, or build verifications have passed or even run. This allows broken, vulnerable, or non-compliant code to enter protected branches and potentially reach production without any automated quality gate.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-358",
      "title": "Improperly Implemented Security Check for Standard",
      "url": "https://cwe.mitre.org/data/definitions/358.html"
    }
  ],
  "remediation": {
    "title": "Configure required status checks on protected branches",
    "description": "Add required status checks to branch protection rules so that all pull requests must pass configured CI/CD checks (build, test, security scan) before merging is allowed.",
    "tasks": [
      { "title": "Add required status checks in branch protection settings for main/master" },
      { "title": "Include at minimum: build, unit tests, and a security/SAST scan as required checks" },
      { "title": "Enable 'Require branches to be up to date before merging' alongside status checks" },
      { "title": "Verify that all required check names exactly match the CI job names" },
      { "title": "Review and update required checks whenever CI pipeline jobs are renamed or restructured" }
    ]
  }
}]

violation[{"id": "no_required_checks"}] if {
    count(input.required_status_checks) == 0
}
