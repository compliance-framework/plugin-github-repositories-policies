package compliance_framework.sbom_exists

sbom := input.sbom.sbom

violation[{}] if {
    not sbom_present
}

violation[{}] if {
    sbom_present
    not sbom_has_packages
}

sbom_present if {
    input.sbom.sbom != null
}

sbom_has_packages if {
    count(sbom.packages) > 0
}

title := "Repository SBOM exists"
description := "A repository must include an SPDX SBOM with at least one package. Expected shape: input.sbom.sbom.packages[]."
