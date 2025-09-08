package compliance_framework.sbom_banned_licenses_test

import data.compliance_framework.sbom_banned_licenses as policy

test_no_banned_ok if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "MIT"},
    {"name": "b", "licenseConcluded": "Apache-2.0"}
  ]}}}
  v := count(policy.violation) with input as inp
  v == 0
}

test_has_banned_violation if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "BUSL-1.1 OR MIT"},
    {"name": "b", "licenseConcluded": "MIT"}
  ]}}}
  v := count(policy.violation) with input as inp
  v == 1

  # Description should include offending package and license expression
  desc := policy.description with input as inp
  contains(desc, "a (BUSL-1.1")
}

test_sspl_banned_violation if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "SSPL-1.0"}
  ]}}}
  v := count(policy.violation) with input as inp
  v == 1
}

test_gpl_allowed_ok if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "GPL-3.0"},
    {"name": "b", "licenseConcluded": "AGPL-3.0"},
    {"name": "c", "licenseConcluded": "LGPL-3.0"}
  ]}}}
  v := count(policy.violation) with input as inp
  v == 0
}
