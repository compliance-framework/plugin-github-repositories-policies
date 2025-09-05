package compliance_framework.check_oss_license_test

import data.compliance_framework.check_oss_license as policy

test_valid_license_ok if {
  inp := {
    "settings": {
      "license": {"spdx_id": "MIT"}
    }
  }

  count(policy.violation) with input as inp == 0
}

test_invalid_license_violation if {
  inp := {
    "settings": {
      "license": {"spdx_id": "Proprietary"}
    }
  }

  count(policy.violation) with input as inp == 1
}

test_missing_spdx_violation if {
  inp := {
    "settings": {
      "license": {}
    }
  }

  count(policy.violation) with input as inp == 1
}

test_case_mismatch_violation if {
  inp := {
    "settings": {
      "license": {"spdx_id": "mit"}
    }
  }

  count(policy.violation) with input as inp == 1
}
