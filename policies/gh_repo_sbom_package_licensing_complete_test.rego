package compliance_framework.sbom_package_licensing_complete_test

import data.compliance_framework.sbom_package_licensing_complete as policy

test_missing_license_detected_violation if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a"},
    {"name": "b", "licenseConcluded": "NOASSERTION"},
    {"name": "c", "licenseConcluded": "MIT"}
  ]}}}
  count(policy.violation) with input as inp == 1
}

test_all_packages_have_license_ok if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "MIT"},
    {"name": "b", "licenseConcluded": "Apache-2.0"}
  ]}}}
  count(policy.violation) with input as inp == 0
}

