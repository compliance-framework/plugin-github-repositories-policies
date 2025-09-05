package compliance_framework.sbom_metadata_test

import data.compliance_framework.sbom_metadata as policy

test_metadata_ok if {
  inp := {"sbom": {"sbom": {"spdxVersion": "SPDX-2.3", "documentNamespace": "ns", "creationInfo": {"created": "2025-08-01T00:00:00Z"}}}}
  count(policy.violation) with input as inp == 0
}

test_missing_namespace_violation if {
  inp := {"sbom": {"sbom": {"spdxVersion": "SPDX-2.3", "documentNamespace": "", "creationInfo": {"created": "2025-01-01T00:00:00Z"}}}}
  count(policy.violation) with input as inp == 1
}

test_old_sbom_violation if {
  inp := {"sbom": {"sbom": {"spdxVersion": "SPDX-2.3", "documentNamespace": "ns", "creationInfo": {"created": "2000-01-01T00:00:00Z"}}}}
  count(policy.violation) with input as inp == 1
}
