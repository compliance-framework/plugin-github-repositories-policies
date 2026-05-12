package compliance_framework.repository_admin_access_limited

import future.keywords.if

max_admin_teams := 2
repository_teams := object.get(input, "repository_teams", [])
collaborators := object.get(input, "collaborators", [])

title := "Repository administrator access is limited"
description := sprintf("Repository admin access should be assigned through no more than %d team(s), with no direct admin collaborators.", [max_admin_teams])

risk_templates := [{
  "name": "Repository administrator access is too broad",
  "title": "Excessive Repository Administrative Access Increases Unauthorized Change Risk",
  "statement": "Broad or direct administrator access can allow privileged users to bypass review, alter repository controls, change branch protections, or grant additional access outside normal approval paths.",
  "likelihood_hint": "moderate",
  "impact_hint": "high",
  "violation_ids": ["direct_admin_collaborator", "too_many_admin_teams"],
  "remediation": {
    "title": "Restrict repository administrator access",
    "description": "Limit administrator permissions to a small number of role-based teams and remove direct admin collaborators.",
    "tasks": [
      {"title": "Review all users and teams with admin permissions"},
      {"title": "Move direct admin users into approved admin teams"},
      {"title": "Reduce the number of admin teams to the minimum required"}
    ]
  }
}]

admin_teams := [team |
  team := repository_teams[_]
  is_admin(team)
]

violation[{"id": "direct_admin_collaborator", "remarks": sprintf("Direct collaborator %q has repository admin access.", [login])}] if {
  collaborator := collaborators[_]
  is_admin(collaborator)
  login := object.get(collaborator, "login", "")
  login != ""
}

violation[{"id": "too_many_admin_teams", "remarks": sprintf("Repository has %d admin teams; allowed maximum is %d.", [count(admin_teams), max_admin_teams])}] if {
  count(admin_teams) > max_admin_teams
}

is_admin(principal) if {
  lower(object.get(principal, "role_name", "")) == "admin"
}

is_admin(principal) if {
  lower(object.get(principal, "permission", "")) == "admin"
}

is_admin(principal) if {
  permissions := object.get(principal, "permissions", {})
  object.get(permissions, "admin", false)
}
