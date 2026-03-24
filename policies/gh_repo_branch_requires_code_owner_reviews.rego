package compliance_framework.branch_requires_code_owner_reviews

import future.keywords.if

title := "Branch protection requires code owner review"
description := "Protected branches must enforce CODEOWNERS approvals so domain experts approve changes before merging."

risk_templates := [
  {
    "name": "No CODEOWNERS review enforcement on protected branch",
    "title": "Unreviewed Changes to Sensitive Code Paths",
    "statement": "Without CODEOWNERS review enforcement, changes to security-sensitive or business-critical code paths can be merged without approval from the designated domain experts, increasing the risk of introducing defects, backdoors, or security regressions.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["codeowners_review_not_required"],
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
      "title": "Enable CODEOWNERS review requirement on protected branches",
      "description": "Add a CODEOWNERS file mapping sensitive paths to responsible teams, and enable 'Require review from Code Owners' in branch protection settings.",
      "tasks": [
        { "title": "Create or update CODEOWNERS file mapping critical paths to owning teams" },
        { "title": "Enable 'Require review from Code Owners' in branch protection settings" },
        { "title": "Apply the setting to all protected branches" },
        { "title": "Validate CODEOWNERS syntax using GitHub's built-in checker" }
      ]
    }
  },
  {
    "name": "CODEOWNERS review required but no valid CODEOWNERS file exists",
    "title": "Misconfigured CODEOWNERS Enforcement Creates False Security Assurance",
    "statement": "Requiring CODEOWNERS review without a valid CODEOWNERS file means the protection is silently ineffective. Approvals may proceed without genuinely involving domain owners, creating a false sense of security while sensitive code paths remain unprotected.",
    "likelihood_hint": "low",
    "impact_hint": "moderate",
    "violation_ids": ["codeowners_file_missing_or_empty"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Create a valid and populated CODEOWNERS file",
      "description": "Provide a well-formed CODEOWNERS file in the repository root, .github/, or docs/ directory that maps all sensitive code paths to their responsible teams.",
      "tasks": [
        { "title": "Create CODEOWNERS file at .github/CODEOWNERS or repository root" },
        { "title": "Map all security-sensitive and business-critical paths to owning teams" },
        { "title": "Validate CODEOWNERS syntax and ensure referenced teams/users have repository access" },
        { "title": "Test that CODEOWNERS review is correctly triggered on a sample pull request" }
      ]
    }
  }
]

violation[{"id": "codeowners_review_not_required", "remarks": sprintf("Branch protection for %q does not require CODEOWNERS review approval.", [branch])}] if {
	branch := input.protected_branches[_]
	not branch_requires_code_owner_reviews(branch)
}

violation[{"id": "codeowners_file_missing_or_empty", "remarks": sprintf("Branch protection for %q requires CODEOWNERS review but no CODEOWNERS file exists or is empty.", [branch])}] if {
	branch := input.protected_branches[_]
	settings := branch_protection_settings(branch)
	require_code_owner_reviews(settings)
	not has_valid_codeowners_file
}

branch_requires_code_owner_reviews(branch) if {
	settings := branch_protection_settings(branch)
	require_code_owner_reviews(settings)
}

branch_protection_settings(branch) := settings if {
	protection := object.get(input.branch_protection_rules, branch, {})
	settings := object.get(protection, "required_pull_request_reviews", {})
}

require_code_owner_reviews(settings) if {
	object.get(settings, "require_code_owner_reviews", false)
}

has_valid_codeowners_file if {
	code_owners := object.get(input, "code_owners", {})
	content := object.get(code_owners, "content", "")
	count(content) > 0
}
