package compliance_framework.repository_environment_protection

import future.keywords.if

environments := object.get(input, "environments", [])

default environment_names := []

# data.environment_names comes from policies/data.json, which Regal doesn't read.
environment_names := data.environment_names if { # regal ignore:unresolved-reference
	is_array(data.environment_names) # regal ignore:unresolved-reference
}

title := sprintf("Do deployment environments require protection rules for repository %s", [input.settings.full_name])

missing_environment_names := [env_name |
	environment_names != []
	some env_name in environment_names
	not environment_exists(env_name)
]

unprotected_environment_names := [name |
	some env in environments_to_check
	name := object.get(env, "name", "")
	not environment_is_protected(env)
]

default description := "Specified GitHub environments should require reviewer or wait timer protection before deployment. If no environments are specified in policy data, all environments are checked."

description := msg if {
	missing_environment_names != []
	unprotected_environment_names == []
	msg := sprintf("Missing required environments: %s", [concat(", ", missing_environment_names)])
}

description := msg if {
	unprotected_environment_names != []
	missing_environment_names == []
	msg := sprintf("Environments without protection: %s", [concat(", ", unprotected_environment_names)])
}

description := msg if {
	missing_environment_names != []
	unprotected_environment_names != []
	msg := sprintf("Missing required environments: %s. Environments without protection: %s", [concat(", ", missing_environment_names), concat(", ", unprotected_environment_names)])
}

skip_reason := "Repository does not have any environments, so environment protection rules cannot be evaluated." if {
	count(environments) == 0
	environment_names == []
}

risk_templates := [{
	"name": "Deployment environment lacks protection rules",
	"title": "Deployments Can Proceed Without Environment-Level Approval",
	"statement": "GitHub environments without protection rules allow deployments to proceed without an independent approval or control gate, increasing the risk of unauthorized or unvalidated changes.",
	"likelihood_hint": "moderate",
	"impact_hint": "high",
	"violation_ids": ["environment_unprotected", "environment_missing"],
	"remediation": {
		"title": "Configure deployment environment protection",
		"description": "Use GitHub environment protection rules to require reviewers, wait timers, or protected branch deployment policies for the specified environments.",
		"tasks": [
			{"title": "Create environments for deployment workflows"},
			{"title": "Require reviewers for the specified environments"},
			{"title": "Restrict deployments to protected branches or approved branch policies"},
		],
	},
}]

environments_to_check := [env |
	some env in environments
	should_check_environment(env)
]

should_check_environment(_) if {
	environment_names == []
}

should_check_environment(env) if {
	name := object.get(env, "name", "")
	some env_name in environment_names
	name == env_name
}

violation[{"id": "environment_missing", "remarks": sprintf("Expected environment %q does not exist in repository.", [env_name])}] if {
	environment_names != []
	some env_name in environment_names
	not environment_exists(env_name)
}

violation[{"id": "environment_unprotected", "remarks": sprintf("Environment %q has no required reviewers, wait timer, or branch deployment policy.", [name])}] if {
	some env in environments_to_check
	name := object.get(env, "name", "")
	not environment_is_protected(env)
}

environment_exists(name) if {
	some env in environments
	object.get(env, "name", "") == name
}

environment_is_protected(env) if {
	count(object.get(env, "reviewers", [])) > 0
}

environment_is_protected(env) if {
	object.get(env, "wait_timer", 0) > 0
}

environment_is_protected(env) if {
	some rule in object.get(env, "protection_rules", [])
	rule.type == "required_reviewers"
	count(object.get(rule, "reviewers", [])) > 0
}

environment_is_protected(env) if {
	some rule in object.get(env, "protection_rules", [])
	rule.type == "wait_timer"
	object.get(rule, "wait_timer", 0) > 0
}

environment_is_protected(env) if {
	policy := object.get(env, "deployment_branch_policy", {})
	object.get(policy, "protected_branches", false) != false
}

environment_is_protected(env) if {
	policy := object.get(env, "deployment_branch_policy", {})
	object.get(policy, "custom_branch_policies", false) != false
}
