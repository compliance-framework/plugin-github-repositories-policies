package compliance_framework.repository_environment_protection

import future.keywords.if

environments := object.get(input, "environments", [])
environment_names := object.get(object.get(input, "policy_input", {}), "environment_names", [])

title := "Deployment environments require protection rules"
default description := "Specified GitHub environments should require reviewer or wait timer protection before deployment. If no environments are specified in policy input, all environments are checked."

missing_environment_names := [env_name |
	count(environment_names) > 0
	some env_name in environment_names
	not environment_exists(env_name)
]

unprotected_environment_names := [name |
	env := environments_to_check[_]
	name := object.get(env, "name", "")
	not environment_is_protected(env)
]

description := msg if {
	count(missing_environment_names) > 0
	count(unprotected_environment_names) == 0
	msg := sprintf("Missing required environments: %s", [concat(", ", missing_environment_names)])
}

description := msg if {
	count(unprotected_environment_names) > 0
	count(missing_environment_names) == 0
	msg := sprintf("Environments without protection: %s", [concat(", ", unprotected_environment_names)])
}

description := msg if {
	count(missing_environment_names) > 0
	count(unprotected_environment_names) > 0
	msg := sprintf("Missing required environments: %s. Environments without protection: %s", [concat(", ", missing_environment_names), concat(", ", unprotected_environment_names)])
}

skip_reason := "Repository does not have any environments, so environment protection rules cannot be evaluated." if {
	count(environments) == 0
	count(environment_names) == 0
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
	env := environments[_]
	should_check_environment(env)
]

should_check_environment(env) if {
	count(environment_names) == 0
}

should_check_environment(env) if {
	name := object.get(env, "name", "")
	some env_name in environment_names
	name == env_name
}

violation[{"id": "environment_missing", "remarks": sprintf("Expected environment %q does not exist in repository.", [env_name])}] if {
	count(environment_names) > 0
	some env_name in environment_names
	not environment_exists(env_name)
}

violation[{"id": "environment_unprotected", "remarks": sprintf("Environment %q has no required reviewers, wait timer, or branch deployment policy.", [name])}] if {
	env := environments_to_check[_]
	name := object.get(env, "name", "")
	not environment_is_protected(env)
}

environment_exists(name) if {
	env := environments[_]
	object.get(env, "name", "") == name
}

environment_is_protected(env) if {
	count(object.get(env, "reviewers", [])) > 0
}

environment_is_protected(env) if {
	object.get(env, "wait_timer", 0) > 0
}

environment_is_protected(env) if {
	rule := object.get(env, "protection_rules", [])[_]
	object.get(rule, "type", "") == "required_reviewers"
	count(object.get(rule, "reviewers", [])) > 0
}

environment_is_protected(env) if {
	rule := object.get(env, "protection_rules", [])[_]
	object.get(rule, "type", "") == "wait_timer"
	object.get(rule, "wait_timer", 0) > 0
}

environment_is_protected(env) if {
	policy := object.get(env, "deployment_branch_policy", {})
	object.get(policy, "protected_branches", false)
}

environment_is_protected(env) if {
	policy := object.get(env, "deployment_branch_policy", {})
	object.get(policy, "custom_branch_policies", false)
}
