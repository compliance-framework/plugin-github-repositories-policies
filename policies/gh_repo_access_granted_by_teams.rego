package compliance_framework.repository_team_access

import future.keywords.if

repository_teams := object.get(input, "repository_teams", [])
collaborators := object.get(input, "collaborators", [])

title := "Repository access is granted through teams"
description := "Repositories should grant access through GitHub teams and avoid direct user collaborators."

risk_templates := [{
  "name": "Repository access not granted through teams",
  "title": "Direct Repository Access Bypasses Role-Based Team Governance",
  "statement": "Direct repository collaborators make access harder to review, approve, and remove consistently because permissions are assigned outside the role-based team structure.",
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "violation_ids": ["no_repository_teams", "direct_repository_collaborator"],
  "remediation": {
    "title": "Move repository access to GitHub teams",
    "description": "Grant repository permissions through organization teams and remove direct collaborators unless a documented exception exists.",
    "tasks": [
      {"title": "Create or identify role-based teams for the repository"},
      {"title": "Grant repository permissions to teams instead of users"},
      {"title": "Remove direct collaborators after team access is verified"}
    ]
  }
}]

violation[{"id": "no_repository_teams", "remarks": "Repository has no teams with explicit access."}] if {
  count(repository_teams) == 0
}

violation[{"id": "direct_repository_collaborator", "remarks": sprintf("Repository has direct collaborator %q.", [login])}] if {
  collaborator := collaborators[_]
  login := object.get(collaborator, "login", "")
  login != ""
}
