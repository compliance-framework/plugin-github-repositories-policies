package compliance_framework.repository_environment_protection

import future.keywords.if

environments := object.get(input, "environments", [])

title := "Production deployment environments require protection rules"
description := "Production-like GitHub environments should require reviewer or wait timer protection before deployment."

skip_reason := "Repository does not have any environments, so environment protection rules cannot be evaluated." if {
	count(environments) == 0
}

risk_templates := [{
	"name": "Deployment environment lacks protection rules",
	"title": "Production Deployments Can Proceed Without Environment-Level Approval",
	"statement": "GitHub environments without protection rules allow deployments to proceed without an independent approval or control gate, increasing the risk of unauthorized or unvalidated production changes.",
	"likelihood_hint": "moderate",
	"impact_hint": "high",
	"violation_ids": ["production_environment_missing", "environment_unprotected"],
	"remediation": {
		"title": "Configure deployment environment protection",
		"description": "Use GitHub environment protection rules to require reviewers, wait timers, or protected branch deployment policies for production-like environments.",
		"tasks": [
			{"title": "Create a production environment for deployment workflows"},
			{"title": "Require reviewers for production-like environments"},
			{"title": "Restrict deployments to protected branches or approved branch policies"},
		],
	},
}]

production_environments := [env |
	env := environments[_]
	is_production_like(object.get(env, "name", ""))
]

violation[{"id": "production_environment_missing", "remarks": "Repository has no production-like deployment environment."}] if {
	count(production_environments) == 0
}

violation[{"id": "environment_unprotected", "remarks": sprintf("Environment %q has no required reviewers, wait timer, or branch deployment policy.", [name])}] if {
	env := production_environments[_]
	name := object.get(env, "name", "")
	not environment_is_protected(env)
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

is_production_like(name) if {
	lower_name := lower(name)
	lower_name == "prod"
}

is_production_like(name) if {
	lower_name := lower(name)
	lower_name == "production"
}

is_production_like(name) if {
	lower_name := lower(name)
	regex.match(`^(prod|production)[-_](live|primary|blue|green|us-east|us-west|eu-west|eu-central|ap-south|ap-southeast|ca-central|sa-east)$`, lower_name)
}
