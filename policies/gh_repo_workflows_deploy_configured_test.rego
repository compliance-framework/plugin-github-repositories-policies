package compliance_framework.workflows_deploy_configured_test

import data.compliance_framework.workflows_deploy_configured as policy

test_no_workflows_violation if {
  inp := {"workflows": []}
  v := count(policy.violation) with input as inp
  v == 1
}

test_deploy_name_ok if {
  inp := {"workflows": [
    {"name": "Deploy to Prod", "path": ".github/workflows/deploy.yml"},
    {"name": "CI", "path": ".github/workflows/ci.yml"}
  ]}
  v := count(policy.violation) with input as inp
  v == 0
}

test_release_path_ok if {
  inp := {"workflows": [
    {"name": "Build", "path": ".github/workflows/release.yml"}
  ]}
  v := count(policy.violation) with input as inp
  v == 0
}

test_no_deploy_or_release_violation if {
  inp := {"workflows": [
    {"name": "CI", "path": ".github/workflows/main.yml"},
    {"name": "Lint", "path": ".github/workflows/lint.yml"}
  ]}
  v := count(policy.violation) with input as inp
  v == 1
}

