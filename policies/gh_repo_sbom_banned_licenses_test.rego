package compliance_framework.sbom_banned_licenses_test

import data.compliance_framework.sbom_banned_licenses as policy

test_no_banned_ok if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "MIT"},
    {"name": "b", "licenseConcluded": "Apache-2.0"}
  ]}}}
  count(policy.violation) with input as inp == 0
}

test_has_banned_violation if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "BUSL-1.1 OR MIT"},
    {"name": "b", "licenseConcluded": "MIT"}
  ]}}}
  count(policy.violation) with input as inp == 1
}
