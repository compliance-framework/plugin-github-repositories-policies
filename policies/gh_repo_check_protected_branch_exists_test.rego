package compliance_framework.check_protected_branch_exists_test

import data.compliance_framework.check_protected_branch_exists as policy

test_no_protected_branches_violation if {
  inp := {"protected_branches": []}
  v := count(policy.violation) with input as inp
  v == 1
}

test_has_protected_branch_ok if {
  inp := {"protected_branches": ["main"]}
  v := count(policy.violation) with input as inp
  v == 0
}

