package compliance_framework.secret_scanning_push_protection_enabled_test

import data.compliance_framework.secret_scanning_push_protection_enabled as policy

test_push_protection_enabled_ok if {
  inp := {
    "settings": {
      "security_and_analysis": {
        "secret_scanning_push_protection": {"status": "enabled"}
      }
    }
  }

  v := count(policy.violation) with input as inp
  v == 0
}

test_push_protection_missing_security_and_analysis_triggers_all_checks if {
  inp := {}

  v := count(policy.violation) with input as inp
  v == 1
}

test_push_protection_missing_feature_triggers_2_violations if {
  inp := {
    "settings": {
      "security_and_analysis": {}
    }
  }

  v := count(policy.violation) with input as inp
  v == 1
}

test_push_protection_disabled_is_violation if {
  inp := {
    "settings": {
      "security_and_analysis": {
        "secret_scanning_push_protection": {"status": "disabled"}
      }
    }
  }

  v := count(policy.violation) with input as inp
  v == 1
}

test_push_protection_case_mismatch_is_violation_greybox if {
  inp := {
    "settings": {
      "security_and_analysis": {
        "secret_scanning_push_protection": {"status": "ENABLED"}
      }
    }
  }

  v := count(policy.violation) with input as inp
  v == 1
}
