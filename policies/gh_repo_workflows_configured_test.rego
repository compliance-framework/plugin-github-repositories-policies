package compliance_framework.workflows_configured_test

import data.compliance_framework.workflows_configured as policy

test_no_workflows_cause_violation if {
  inp := {"workflows": []}

  # Multiple rules may be true but violations set de-duplicates identical objects.
  v := count(policy.violation) with input as inp
  v == 1
}

test_required_workflows_present if {
  inp := {
    "workflows": [
      {"path": ".github/workflows/ci.yml"},
      {"path": ".github/workflows/build.yml"}
    ]
  }

  v := count(policy.violation) with input as inp with data.workflow_names as ["ci.yml", "build.yml"]
  v == 0
}

test_required_workflows_missing if {
  inp := {
    "workflows": [
      {"path": ".github/workflows/ci.yml"}
    ]
  }

  v := count(policy.violation) with input as inp with data.workflow_names as ["ci.yml", "build.yml"]
  v == 1
}

test_no_policy_data_no_violation if {
  inp := {
    "workflows": [
      {"path": ".github/workflows/some-workflow.yml"}
    ]
  }

  v := count(policy.violation) with input as inp
  v == 0
}

test_description_no_workflows if {
  inp := {"workflows": []}
  desc := policy.description with input as inp
  desc == "No workflows configured in repository"
}

test_description_missing_required_workflow if {
  inp := {
    "workflows": [
      {"path": ".github/workflows/ci.yml"}
    ]
  }
  desc := policy.description with input as inp with data.workflow_names as ["ci.yml", "build.yml"]
  desc == "Missing required workflows: build.yml"
}

test_description_multiple_missing_required_workflows if {
  inp := {
    "workflows": [
      {"path": ".github/workflows/ci.yml"}
    ]
  }
  desc := policy.description with input as inp with data.workflow_names as ["ci.yml", "build.yml", "main.yml"]
  desc == "Missing required workflows: build.yml, main.yml"
}

test_description_required_workflows_present_from_policy_data if {
  inp := {
    "workflows": [
      {"path": ".github/workflows/ci.yml"},
      {"path": ".github/workflows/build.yml"}
    ]
  }
  desc := policy.description with input as inp with data.workflow_names as ["ci.yml", "build.yml"]
  desc == "All required workflows are configured: ci.yml, build.yml"
}

test_description_default if {
  inp := {
    "workflows": [
      {"path": ".github/workflows/ci.yml"},
      {"path": ".github/workflows/build.yml"}
    ]
  }
  desc := policy.description with input as inp
  desc == "All repositories must have workflows configured."
}
