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

risk_templates := [
  {
    "name": "SBOM packages have incomplete license information",
    "title": "Incomplete License Data Prevents Compliance Verification",
    "statement": "Packages with missing, NONE, or NOASSERTION license values in the SBOM cannot be assessed for license compliance. This creates legal blind spots where proprietary, viral, or incompatible licensed components may be present in the software without detection, exposing the organization to compliance violations and legal risk.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      }
    ],
    "remediation": {
      "title": "Ensure all SBOM packages have concluded license identifiers",
      "description": "Review all packages with missing or unknown license values and populate the licenseConcluded field with correct SPDX identifiers. Use license scanning tools to automate detection.",
      "tasks": [
        { "title": "Identify all packages in the SBOM with NONE, NOASSERTION, or null licenseConcluded values" },
        { "title": "Use a license scanning tool (e.g., scancode-toolkit, licensee) to detect the actual license for each package" },
        { "title": "Update the SBOM with correct SPDX license identifiers for all packages" },
        { "title": "For packages with genuinely unclear licensing, escalate to legal review" },
        { "title": "Integrate license detection into the SBOM generation pipeline to prevent future incomplete entries" }
      ]
    }
  }
]

violation[{"id": "sbom_absent"}] if {
    sbom == null
}

violation[{"id": "package_missing_license"}] if {
    some i
    pkg := sbom.packages[i]
    pkg_missing_license(pkg)
}

title := "SBOM packages have concluded licenses"
description := "Every package in the SBOM must include a non-empty licenseConcluded value (not NONE/NOASSERTION)."
