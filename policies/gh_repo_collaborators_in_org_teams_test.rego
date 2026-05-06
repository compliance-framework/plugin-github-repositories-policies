package compliance_framework.repository_collaborators_in_org_teams_test

import data.compliance_framework.repository_collaborators_in_org_teams as policy

test_violation_when_direct_collaborator_not_in_any_org_team if {
  inp := {
    "collaborators": [{"login": "octocat"}],
    "org_teams": [{"slug": "developers", "members": ["hubot"]}],
  }

  violations := policy.violation with input as inp
  violations[{"id": "collaborator_not_in_org_team", "remarks": "Direct collaborator \"octocat\" is not a member of any collected organization team."}]
}

test_pass_when_direct_collaborator_is_in_org_team if {
  inp := {
    "collaborators": [{"login": "octocat"}],
    "org_teams": [{"slug": "developers", "members": ["octocat"]}],
  }

  violations := policy.violation with input as inp
  count(violations) == 0
}

test_pass_when_no_direct_collaborators if {
  inp := {"collaborators": [], "org_teams": []}

  violations := policy.violation with input as inp
  count(violations) == 0
}
