package compliance_framework.repository_collaborators_in_org_teams

import future.keywords.if

raw_collaborators := object.get(input, "collaborators", null)
raw_org_teams := object.get(input, "org_teams", null)
collaborators := object.get(input, "collaborators", [])
org_teams := object.get(input, "org_teams", [])

title := "Direct repository collaborators belong to organization teams"
description := "Any direct repository collaborator should also be represented in an organization team for access review and offboarding visibility."

skip_reason := "Collaborator and organization team data is not available, so collaborator membership cannot be evaluated." if {
  raw_collaborators == null
}

skip_reason := "Collaborator and organization team data is not available, so collaborator membership cannot be evaluated." if {
  raw_org_teams == null
}

risk_templates := [{
  "name": "Repository collaborator missing from organization teams",
  "title": "Direct Collaborator Is Not Covered by Team-Based Access Review",
  "statement": "A direct repository collaborator who does not belong to any organization team may bypass periodic role-based access reviews and team-based offboarding workflows.",
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "violation_ids": ["collaborator_not_in_org_team"],
  "remediation": {
    "title": "Associate direct collaborators with reviewed teams",
    "description": "Move repository access to a team or add the user to an appropriate team so access can be reviewed and removed through the normal team lifecycle.",
    "tasks": [
      {"title": "Identify the role that justifies each direct collaborator"},
      {"title": "Add the collaborator to the matching organization team"},
      {"title": "Remove direct access after team permissions are confirmed"}
    ]
  }
}]

violation[{"id": "collaborator_not_in_org_team", "remarks": sprintf("Direct collaborator %q is not a member of any collected organization team.", [login])}] if {
  collaborator := collaborators[_]
  login := object.get(collaborator, "login", "")
  login != ""
  not collaborator_in_org_team(login)
}

collaborator_in_org_team(login) if {
  team := org_teams[_]
  members := object.get(team, "members", [])
  members[_] == login
}
