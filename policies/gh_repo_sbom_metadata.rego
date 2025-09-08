package compliance_framework.sbom_metadata

sbom := input.sbom.sbom

default max_age_days := 90

violation[{}] if {
    sbom == null
}

violation[{}] if {
    sbom != null
    not valid_spdx_version
}

violation[{}] if {
    sbom != null
    not has_document_namespace
}

violation[{}] if {
    sbom != null
    sbom.creationInfo.created != ""
    created_ns := time.parse_rfc3339_ns(sbom.creationInfo.created)
    now_ns := time.now_ns()
    age_days := (now_ns - created_ns) / (1000 * 1000 * 1000 * 60 * 60 * 24)
    age_days > max_age_days
}

valid_spdx_version if { sbom.spdxVersion == "SPDX-2.3" }
valid_spdx_version if { sbom.spdxVersion == "SPDX-2.2" }

has_document_namespace if {
    ns := sbom.documentNamespace
    ns != null
    ns != ""
}

title := "Repository SBOM metadata is valid and fresh"
description := sprintf("SBOM must use SPDX 2.2/2.3, include a document namespace, and be generated within the last %d days.", [max_age_days])