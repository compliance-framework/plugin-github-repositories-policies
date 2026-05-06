package compliance_framework.repository_team_access_test

import data.compliance_framework.repository_team_access as policy

test_violation_when_no_repository_teams if {
  inp := {"repository_teams": [], "collaborators": []}

  violations := policy.violation with input as inp
  violations[{"id": "no_repository_teams", "remarks": "Repository has no teams with explicit access."}]
}

test_violation_when_direct_collaborator_exists if {
  inp := {
    "repository_teams": [{"slug": "developers", "permissions": {"push": true}}],
    "collaborators": [{"login": "octocat", "role_name": "write"}],
  }

  violations := policy.violation with input as inp
  count(violations) == 1
  violations[{"id": "direct_repository_collaborator", "remarks": "Repository has direct collaborator \"octocat\"."}]
}

test_pass_when_team_access_without_direct_collaborators if {
  inp := {
    "repository_teams": [{"slug": "developers", "permissions": {"push": true}}],
    "collaborators": [],
  }

  violations := policy.violation with input as inp
  count(violations) == 0
}
