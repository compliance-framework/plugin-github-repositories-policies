package compliance_framework.sbom_exists_test

import data.compliance_framework.sbom_exists as policy

test_satisfies_exists if {
  inp := {"sbom": {"sbom": {"spdxVersion": "SPDX-2.3", "packages": [
    {"name": "a", "licenseConcluded": "MIT"},
    {"name": "b", "licenseConcluded": "Apache-2.0"}
  ]}}}
  count(policy.violation) with input as inp == 0
}

test_missing_sbom_violation if {
  inp := {}
  count(policy.violation) with input as inp == 1
}

test_empty_packages_violation if {
  inp := {"sbom": {"sbom": {"spdxVersion": "SPDX-2.3", "packages": []}}}
  count(policy.violation) with input as inp == 1
}
