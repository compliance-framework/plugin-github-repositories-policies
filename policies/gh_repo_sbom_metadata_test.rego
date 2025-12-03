package compliance_framework.sbom_metadata_test

import data.compliance_framework.sbom_metadata as policy

# Generate a recent timestamp (1 day ago) dynamically
recent_timestamp := time.format(time.now_ns() - (24 * 60 * 60 * 1000 * 1000 * 1000))

test_metadata_ok if {
  inp := {"sbom": {"sbom": {"spdxVersion": "SPDX-2.3", "documentNamespace": "ns", "creationInfo": {"created": recent_timestamp}}}}
  v := count(policy.violation) with input as inp
  v == 0
}

test_missing_namespace_violation if {
  inp := {"sbom": {"sbom": {"spdxVersion": "SPDX-2.3", "documentNamespace": "", "creationInfo": {"created": recent_timestamp}}}}
  v := count(policy.violation) with input as inp
  v == 1
}

test_old_sbom_violation if {
  inp := {"sbom": {"sbom": {"spdxVersion": "SPDX-2.3", "documentNamespace": "ns", "creationInfo": {"created": "2000-01-01T00:00:00Z"}}}}
  v := count(policy.violation) with input as inp
  v == 1
}

test_spdx_22_ok if {
  inp := {"sbom": {"sbom": {"spdxVersion": "SPDX-2.2", "documentNamespace": "ns", "creationInfo": {"created": recent_timestamp}}}}
  v := count(policy.violation) with input as inp
  v == 0
}
