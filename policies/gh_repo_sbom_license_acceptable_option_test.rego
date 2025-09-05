package compliance_framework.sbom_license_acceptable_option_test

import data.compliance_framework.sbom_license_acceptable_option as policy

test_all_packages_have_acceptable_option_ok if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "MIT"},
    {"name": "b", "licenseConcluded": "GPL-3.0 OR Apache-2.0"}
  ]}}}
  count(policy.violation) with input as inp == 0
}

test_some_package_lacks_acceptable_violation if {
  inp := {"sbom": {"sbom": {"packages": [
    {"name": "a", "licenseConcluded": "GPL-3.0-only"},
    {"name": "b", "licenseConcluded": "BUSL-1.1"}
  ]}}}
  count(policy.violation) with input as inp == 1
}

