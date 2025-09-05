package compliance_framework.workflow_health_test

import data.compliance_framework.workflow_health as policy

test_no_runs_ok if {
  inp := {"workflow_runs": []}

  count(policy.violation) with input as inp == 0
}

test_within_tolerance_ok if {
  inp := {"workflow_runs": [
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "failure"},
    {"conclusion": "cancelled"}
  ]}

  # 8/10 pass; 20% tolerance -> exactly at threshold => no violation
  count(policy.violation) with input as inp == 0
}

test_exceeds_tolerance_violation if {
  inp := {"workflow_runs": [
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "failure"},
    {"conclusion": "failure"},
    {"conclusion": "failure"},
    {"conclusion": "cancelled"}
  ]}

  # 6/10 pass; 20% tolerance -> abs(10-6)=4 > 2 => violation
  count(policy.violation) with input as inp == 1
}

test_small_set_within_tolerance_ok if {
  inp := {"workflow_runs": [
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "failure"}
  ]}

  # 4/5 pass; 20% of 5 is 1; abs(5-4)=1 -> not greater => ok
  count(policy.violation) with input as inp == 0
}

test_small_set_exceeds_tolerance_violation if {
  inp := {"workflow_runs": [
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "success"},
    {"conclusion": "failure"},
    {"conclusion": "failure"}
  ]}

  # 3/5 pass; abs=2 > 1 -> violation
  count(policy.violation) with input as inp == 1
}

test_description_includes_counts if {
  inp := {"workflow_runs": [
    {"conclusion": "success"},
    {"conclusion": "failure"},
    {"conclusion": "success"},
    {"conclusion": "cancelled"}
  ]}

  expected := "All repositories must have healthy workflow runs. [2/4 - tolerance 20%]"
  desc := policy.description with input as inp
  contains(desc, "[2/4 - tolerance 20%]")
}
