package compliance_framework.sbom_package_licensing_complete

sbom := input.sbom.sbom

pkg_missing_license(pkg) if {
    pkg.licenseConcluded == null
}
pkg_missing_license(pkg) if {
    lc := license_text(pkg)
    lc == "none"
}
pkg_missing_license(pkg) if {
    lc := license_text(pkg)
    lc == "noassertion"
}

license_text(pkg) := s if {
    is_string(pkg.licenseConcluded)
    s := lower(pkg.licenseConcluded)
}
license_text(pkg) := "" if {
    not is_string(pkg.licenseConcluded)
}

violation[{}] if {
    sbom == null
}

violation[{}] if {
    some i
    pkg := sbom.packages[i]
    pkg_missing_license(pkg)
}

title := "SBOM packages have concluded licenses"
description := "Every package in the SBOM must include a non-empty licenseConcluded value (not NONE/NOASSERTION)."
