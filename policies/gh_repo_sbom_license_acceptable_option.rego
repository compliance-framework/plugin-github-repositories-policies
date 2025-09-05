package compliance_framework.sbom_license_acceptable_option

sbom := input.sbom.sbom

allowed_licenses := {
    # Permissive
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MPL-2.0",
    # GPL family
    "GPL-2.0",
    "GPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "AGPL-3.0"
}

pkg_has_acceptable_license(pkg) if {
    lic := license_text(pkg)
    lic != ""
    al := allowed_licenses[_]
    contains(lic, lower(al))
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

# Violation if any package lacks an acceptable license option
violation[{}] if {
    sbom != null
    some i
    pkg := sbom.packages[i]
    not pkg_has_acceptable_license(pkg)
}

title := "SBOM packages include acceptable license options"
description := "Each package's license expression should include at least one acceptable license (permissive or GPL family). GPL variants (GPL/LGPL/AGPL) are acceptable."
