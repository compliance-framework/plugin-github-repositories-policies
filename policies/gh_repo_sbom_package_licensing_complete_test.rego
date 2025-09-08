package compliance_framework.sbom_package_licensing_complete_test

import data.compliance_framework.sbom_package_licensing_complete as policy

test_missing_license_detected_violation if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a"},
    {"name": "b", "licenseConcluded": "NOASSERTION"},
    {"name": "c", "licenseConcluded": "MIT"}
  ]}}}
  v := count(policy.violation) with input as inp
  v == 1
}

test_all_packages_have_license_ok if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "MIT"},
    {"name": "b", "licenseConcluded": "Apache-2.0"}
  ]}}}
  v := count(policy.violation) with input as inp
  v == 0
}
