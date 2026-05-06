package compliance_framework.commit_signing_required

import future.keywords.if

protected_branches := object.get(input, "protected_branches", [])
branch_protection_rules := object.get(input, "branch_protection_rules", {})
effective_branch_rules := object.get(input, "effective_branch_rules", {})
default_branch := object.get(input, "default_branch", "")

title := "Protected branches require signed commits"
description := "Protected and default branches should require verified commit signatures through branch protection or repository rulesets."

risk_templates := [{
	"name": "Commit signing not required",
	"title": "Unsigned Commits Weaken Source Authenticity Controls",
	"statement": "Without required signed commits, protected branches can accept commits whose author identity and integrity are not cryptographically verified, reducing traceability for production code changes.",
	"likelihood_hint": "moderate",
	"impact_hint": "moderate",
	"violation_ids": ["commit_signing_not_required"],
	"remediation": {
		"title": "Require signed commits",
		"description": "Enable required commit signatures in branch protection or repository rulesets for protected/default branches.",
		"tasks": [
			{"title": "Enable required signed commits for protected branches"},
			{"title": "Apply equivalent repository rulesets where branch protection is managed centrally"},
			{"title": "Educate developers on GPG, SSH, or S/MIME commit signing"},
		],
	},
}]

branches_to_check := ({branch |
	branch := protected_branches[_]
} | {branch |
	branch := object.keys(effective_branch_rules)[_]
}) | {branch |
	branch := default_branch
	branch != ""
}

violation[{"id": "commit_signing_not_required", "remarks": sprintf("Branch %q does not require signed commits.", [branch])}] if {
	branch := branches_to_check[_]
	not branch_requires_signatures(branch)
}

branch_requires_signatures(branch) if {
	rules := object.get(effective_branch_rules, branch, {})
	object.get(rules, "required_signatures", false)
}

branch_requires_signatures(branch) if {
	protection := object.get(branch_protection_rules, branch, {})
	signatures := object.get(protection, "required_signatures", {})
	object.get(signatures, "enabled", false)
}
