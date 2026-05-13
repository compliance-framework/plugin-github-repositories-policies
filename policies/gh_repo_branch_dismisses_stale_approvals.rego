package compliance_framework.branch_dismisses_stale_approvals

import future.keywords.if

title := "Branch protection dismisses stale approvals"
description := "Protected branches must be configured to dismiss stale pull request approvals when new commits are pushed."

skip_reason := "Repository does not have any protected branches, so branch protection rules cannot be evaluated." if {
	count(input.protected_branches) == 0
}

skip_reason := "Neither classic branch protection nor rulesets are configured for pull request reviews." if {
	count(input.protected_branches) > 0
	not branch_protection_or_rulesets_configured
}

branch_protection_or_rulesets_configured if {
	branch := input.protected_branches[_]
	settings := branch_protection_settings(branch)
	require_dismiss_stale_reviews(settings)
}

branch_protection_or_rulesets_configured if {
	branch := input.protected_branches[_]
	rules := object.get(input.effective_branch_rules, branch, {})
	object.get(rules, "dismiss_stale_reviews_on_push", false)
}

risk_templates := [{
  "name": "Stale approvals accepted after code changes",
  "title": "Insufficient Code Review Integrity on Protected Branches",
  "statement": "When stale approvals are not dismissed, new commits pushed after an approval are merged without re-review. Attackers or insiders can inject malicious code after approval, bypassing the intended review gate and introducing unauthorized changes into protected branches.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "violation_ids": ["stale_approvals_not_dismissed"],
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
    }
  ],
  "remediation": {
    "title": "Enable stale review dismissal on protected branches",
    "description": "Configure branch protection rules to automatically dismiss pull request approvals when new commits are pushed, ensuring all code changes are reviewed in their final form before merging.",
    "tasks": [
      { "title": "Enable 'Dismiss stale pull request approvals when new commits are pushed' in branch protection settings" },
      { "title": "Apply this setting to all protected branches (e.g., main, master, release/*)" },
      { "title": "Audit recent merges to identify any that bypassed re-review after new commits" },
      { "title": "Consider also enabling 'Require review from Code Owners' for sensitive paths" }
    ]
  }
}]

violation[{"id": "stale_approvals_not_dismissed", "remarks": sprintf("Branch protection for %q does not dismiss stale approvals after new commits.", [branch])}] if {
	branch := input.protected_branches[_]
	not branch_dismisses_stale_reviews(branch)
}

branch_dismisses_stale_reviews(branch) if {
	settings := branch_protection_settings(branch)
	require_dismiss_stale_reviews(settings)
}

branch_dismisses_stale_reviews(branch) if {
	rules := object.get(input.effective_branch_rules, branch, {})
	object.get(rules, "dismiss_stale_reviews_on_push", false)
}

branch_protection_settings(branch) := settings if {
	protection := object.get(input.branch_protection_rules, branch, {})
	settings := object.get(protection, "required_pull_request_reviews", {})
}

require_dismiss_stale_reviews(settings) if {
	object.get(settings, "dismiss_stale_reviews", false)
}
