package compliance_framework.branch_requires_pr_approvals

import future.keywords.if

min_required_approvals := 1

title := "Branch protection enforces minimum PR approvals"
description := sprintf("Protected branches must require at least %d approving review(s) before merging.", [min_required_approvals])

risk_templates := [{
  "name": "Insufficient peer review before merge",
  "title": "Unreviewed Code Merged into Protected Branches",
  "statement": "Without mandatory peer review approvals, defective, malicious, or non-compliant code can be merged directly into protected branches. This increases the risk of introducing vulnerabilities, business logic errors, or unauthorized changes that bypass all human oversight.",
  "likelihood_hint": "moderate",
  "impact_hint": "high",
  "violation_ids": ["insufficient_pr_approvals"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-284",
      "title": "Improper Access Control",
      "url": "https://cwe.mitre.org/data/definitions/284.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1188",
      "title": "Insecure Default Initialization of Resource",
      "url": "https://cwe.mitre.org/data/definitions/1188.html"
    }
  ],
  "remediation": {
    "title": "Enforce minimum PR approval count on protected branches",
    "description": "Configure branch protection to require at least one (preferably two) approving reviews before any pull request can be merged into protected branches.",
    "tasks": [
      { "title": "Set 'Required approving reviews' to at least 1 in branch protection settings" },
      { "title": "Apply to all protected branches (main, master, release/*)" },
      { "title": "Consider increasing to 2 approvals for critical or security-sensitive codebases" },
      { "title": "Enable 'Dismiss stale reviews when new commits are pushed' alongside this setting" },
      { "title": "Restrict who can dismiss reviews to prevent bypass by the PR author" }
    ]
  }
}]

violation[{"id": "insufficient_pr_approvals", "remarks": sprintf("Branch protection for %q requires fewer than %d approvals before merging.", [branch, min_required_approvals])}] if {
	branch := input.protected_branches[_]
	not branch_meets_approval_requirement(branch)
}

branch_meets_approval_requirement(branch) if {
	settings := branch_protection_settings(branch)
	required_approvals(settings) >= min_required_approvals
}

branch_protection_settings(branch) := settings if {
	protection := object.get(input.branch_protection_rules, branch, {})
	settings := object.get(protection, "required_pull_request_reviews", {})
}

required_approvals(settings) := object.get(settings, "required_approving_review_count", 0)
