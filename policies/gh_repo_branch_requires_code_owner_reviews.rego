package compliance_framework.branch_requires_code_owner_reviews

import future.keywords.if

title := "Branch protection requires code owner review"
description := "Protected branches must enforce CODEOWNERS approvals so domain experts approve changes before merging."

violation[{"remarks": sprintf("Branch protection for %q does not require CODEOWNERS review approval.", [branch])}] if {
	branch := input.protected_branches[_]
	not branch_requires_code_owner_reviews(branch)
}

violation[{"remarks": sprintf("Branch protection for %q requires CODEOWNERS review but no CODEOWNERS file exists or is empty.", [branch])}] if {
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
