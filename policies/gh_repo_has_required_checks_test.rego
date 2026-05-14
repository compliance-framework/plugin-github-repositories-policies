package compliance_framework.has_required_checks_test

import data.compliance_framework.has_required_checks as policy

test_no_required_checks_violation if {
  # Mirrors empty object shape like testdata/* where the field exists but has no keys
  inp := {"protected_branches": ["main"], "required_status_checks": {}}
  v := count(policy.violation) with input as inp
  v == 1
}

test_skip_when_no_protected_branches if {
  inp := {"protected_branches": []}
  policy.skip_reason != "" with input as inp
}

test_has_required_checks_ok if {
  # Any key present causes count(obj) > 0
  inp := {"protected_branches": ["main"], "required_status_checks": {"contexts_url": "https://api.github.com/..."}}
  v := count(policy.violation) with input as inp
  v == 0
}

