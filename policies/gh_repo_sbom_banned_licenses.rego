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

risk_templates := [
  {
    "name": "SBOM contains packages with banned licenses",
    "title": "Non-Commercial or Proprietary Dependency Creates Legal and Distribution Risk",
    "statement": "Including packages with non-commercial, source-available, or proprietary licenses in a software product can expose the organization to legal liability, prevent redistribution, and create compliance failures. Licenses like BUSL, SSPL, or PolyForm Noncommercial restrict commercial use and may conflict with the project's own open source license.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      }
    ],
    "remediation": {
      "title": "Remove or replace packages with banned licenses",
      "description": "Identify all packages in the SBOM with non-commercial or proprietary licenses and replace them with OSI-approved open source alternatives, or obtain a commercial license where replacement is not feasible.",
      "tasks": [
        { "title": "Review SBOM to identify all packages with banned license identifiers" },
        { "title": "Evaluate whether a replacement OSI-approved library is available for each offending package" },
        { "title": "Remove or replace banned-license packages in the dependency manifest" },
        { "title": "If replacement is not feasible, initiate a legal review and obtain a commercial license" },
        { "title": "Regenerate the SBOM after remediation to confirm no banned licenses remain" },
        { "title": "Add license scanning to CI/CD pipeline to prevent future introduction of banned licenses" }
      ]
    }
  }
]

violation[{"id": "sbom_absent"}] if {
    sbom == null
}

violation[{"id": "banned_license_present"}] if {
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

# Compose a human-readable list of offending packages for the description.
banned_entries := [
    sprintf("%s (%s)", [pkg_name(pkg), license_text_raw(pkg)]) |
    pkg := sbom.packages[_]
    lic_raw := license_text_raw(pkg)
    lic := lower(lic_raw)
    bl := banned_licenses[_]
    lic_raw != ""
    contains(lic, lower(bl))
]

# Detailed description including offending packages (when present).
description := sprintf(
    "Packages in the SBOM must not include non-commercial or proprietary licenses. Offenders: %s",
    [concat(", ", banned_entries)]
) if { count(banned_entries) > 0 }

# Fallback description when no offending packages are detected in input context.
description := "Packages in the SBOM must not include non-commercial or proprietary licenses (e.g., BUSL, Elastic, SSPL, PolyForm Noncommercial, CC-BY-NC variants, or proprietary markers)." if { count(banned_entries) == 0 }

license_text_raw(pkg) := s if {
    is_string(pkg.licenseConcluded)
    s := pkg.licenseConcluded
}
license_text_raw(pkg) := "" if {
    not is_string(pkg.licenseConcluded)
}

pkg_name(pkg) := n if {
    is_string(pkg.name)
    n := pkg.name
}
pkg_name(pkg) := "unknown" if {
    not is_string(pkg.name)
}
