package compliance_framework.secret_scanning_enabled_test

import data.compliance_framework.secret_scanning_enabled as policy

test_enabled_ok if {
  inp := {
    "settings": {
      "security_and_analysis": {
        "secret_scanning": {"status": "enabled"}
      }
    }
  }

  v := count(policy.violation) with input as inp
  v == 0
}

test_missing_security_and_analysis_three_violations if {
  inp := {}

  v := count(policy.violation) with input as inp
  v == 1
}

test_missing_feature_two_violations if {
  inp := {
    "settings": {
      "security_and_analysis": {}
    }
  }

  v := count(policy.violation) with input as inp
  v == 1
}

test_disabled_violation if {
  inp := {
    "settings": {
      "security_and_analysis": {
        "secret_scanning": {"status": "disabled"}
      }
    }
  }

  v := count(policy.violation) with input as inp
  v == 1
}

test_status_case_mismatch_violation if {
  inp := {
    "settings": {
      "security_and_analysis": {
        "secret_scanning": {"status": "ENABLED"}
      }
    }
  }

  # Exact string match is required
  v := count(policy.violation) with input as inp
  v == 1
}
