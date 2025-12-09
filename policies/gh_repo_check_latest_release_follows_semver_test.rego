package compliance_framework.change_control_release_semver

test_satisfies_exists if {
  inp := {"last_release": {"body": "fix(AGILE-123): Body with release notes (#1234)", "tag_name": "v1.2.3"}}
  violations := { v | violation[v] with input as inp }
  count(violations) == 0
}

test_no_release_violation if {
  inp := {}
  violations := violation[v] with input as inp
  count(v) == 1
  v.remarks == "No releases available for this repository."
}

test_release_without_references_violation if {
  inp := {"last_release": {"body": "Body with release notes and no refs", "tag_name": "smth"}}
  violations := violation[v] with input as inp
  count(v) == 1
  v.remarks == "Latest Release tag does not follow semver convention."
}