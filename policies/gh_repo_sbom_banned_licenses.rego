package compliance_framework.sbom_banned_licenses

sbom := input.sbom.sbom

banned_licenses := {
    # Non-commercial or proprietary/source-available licenses
    "BUSL-1.1",                # Business Source License (source-available)
    "Elastic-2.0",             # Elastic License (source-available)
    "SSPL-1.0",                # Server Side Public License (non-OSI)
    "PolyForm-Noncommercial-1.0.0",
    "CC-BY-NC-4.0",
    "CC-BY-NC-SA-4.0",
    "CC-BY-NC-ND-4.0",
    # Generic markers frequently used for proprietary
    "proprietary",
    "unlicensed",
    "licenseref-proprietary"
}

violation[{}] if {
    sbom == null
}

violation[{}] if {
    some i
    pkg := sbom.packages[i]
    lic := license_text(pkg)
    bl := banned_licenses[_]
    lic != ""
    contains(lic, lower(bl))
}

license_text(pkg) := s if {
    is_string(pkg.licenseConcluded)
    s := lower(pkg.licenseConcluded)
}
license_text(pkg) := "" if {
    not is_string(pkg.licenseConcluded)
}

title := "SBOM contains banned licenses"
description := "Packages in the SBOM must not include non-commercial or proprietary licenses (e.g., BUSL, Elastic, SSPL, PolyForm Noncommercial, CC-BY-NC variants, or proprietary markers)."
