package compliance_framework.dependabot_security_updates_enabled_test

import data.compliance_framework.dependabot_security_updates_enabled as policy

test_enabled_ok if {
  inp := {
    "settings": {
      "security_and_analysis": {
        "dependabot_security_updates": {"status": "enabled"}
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
        "dependabot_security_updates": {"status": "disabled"}
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
        "dependabot_security_updates": {"status": "ENABLED"}
      }
    }
  }

  v := count(policy.violation) with input as inp
  v == 1
}
