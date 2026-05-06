package compliance_framework.security_required_checks_test

import data.compliance_framework.security_required_checks as policy

test_violation_when_branch_has_only_build_check if {
  inp := {
    "required_status_checks": {"main": {"checks": [{"context": "build"}, {"context": "unit tests"}]}},
    "effective_branch_rules": {},
  }

  violations := policy.violation with input as inp
  violations[{"id": "security_required_check_missing", "remarks": "Branch \"main\" has no security-focused required check."}]
}

test_pass_when_required_check_is_security_named if {
  inp := {
    "required_status_checks": {"main": {"checks": [{"context": "CodeQL / Analyze"}]}},
    "effective_branch_rules": {},
  }

  violations := policy.violation with input as inp
  count(violations) == 0
}

test_pass_when_ruleset_has_code_scanning_tool if {
  inp := {
    "required_status_checks": {"main": {"checks": [{"context": "build"}]}},
    "effective_branch_rules": {"main": {"code_scanning_tools": ["CodeQL"]}},
  }

  violations := policy.violation with input as inp
  count(violations) == 0
}
