package compliance_framework.workflows_configured_test

import data.compliance_framework.workflows_configured as policy

test_no_workflows_two_violations if {
  inp := {"workflows": []}

  # Both rules trigger: empty list and vacuous every{}
  count(policy.violation) with input as inp == 2
}

test_contains_build_ok if {
  inp := {"workflows": [
    {"name": "Build and Test"}
  ]}

  count(policy.violation) with input as inp == 0
}

test_no_build_violation if {
  inp := {"workflows": [
    {"name": "Lint"},
    {"name": "Deploy"}
  ]}

  count(policy.violation) with input as inp == 1
}

test_missing_name_no_violation if {
  # Missing name causes 'every' body to be undefined/false; rule does not trigger
  inp := {"workflows": [
    {},
    {"id": "abc"}
  ]}

  count(policy.violation) with input as inp == 0
}
