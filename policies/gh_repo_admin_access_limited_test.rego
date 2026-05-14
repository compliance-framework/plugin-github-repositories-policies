package compliance_framework.repository_admin_access_limited_test

import data.compliance_framework.repository_admin_access_limited as policy

test_violation_when_direct_collaborator_has_admin if {
  inp := {
    "collaborators": [{"login": "octocat", "permissions": {"admin": true}}],
    "repository_teams": [{"slug": "admins", "permission": "admin"}],
  }

  violations := policy.violation with input as inp
  violations[{"id": "direct_admin_collaborator", "remarks": "Direct collaborator \"octocat\" has repository admin access."}]
}

test_violation_when_too_many_admin_teams if {
  inp := {
    "collaborators": [],
    "repository_teams": [
      {"slug": "admins-a", "permission": "admin"},
      {"slug": "admins-b", "permissions": {"admin": true}},
      {"slug": "admins-c", "permission": "ADMIN"},
    ],
  }

  violations := policy.violation with input as inp
  violations[{"id": "too_many_admin_teams", "remarks": "Repository has 3 admin teams; allowed maximum is 2."}]
}

test_pass_when_admin_access_limited_to_small_team_set if {
  inp := {
    "collaborators": [{"login": "dev", "permissions": {"push": true}}],
    "repository_teams": [
      {"slug": "admins", "permission": "admin"},
      {"slug": "developers", "permission": "push"},
    ],
  }

  violations := policy.violation with input as inp
  count(violations) == 0
}

test_pass_when_no_admins if {
  inp := {"repository_teams": [], "collaborators": []}

  violations := policy.violation with input as inp
  count(violations) == 0
}

test_skip_when_repository_teams_unavailable if {
  inp := {"repository_teams": null, "collaborators": []}

  policy.skip_reason != "" with input as inp
}

test_skip_when_collaborators_unavailable if {
  inp := {"repository_teams": [], "collaborators": null}

  policy.skip_reason != "" with input as inp
}
