package compliance_framework.sbom_exists

sbom := input.sbom.sbom

risk_templates := [
  {
    "name": "SBOM is absent or contains no packages",
    "title": "Missing Software Bill of Materials Prevents Supply Chain Visibility",
    "statement": "Without an SBOM, the complete set of software components and their versions is unknown. This prevents vulnerability scanning, license compliance checks, and incident response when a new CVE is disclosed. Operators cannot determine whether their software is affected by known vulnerabilities without a component inventory.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1104",
        "title": "Use of Unmaintained Third Party Components",
        "url": "https://cwe.mitre.org/data/definitions/1104.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      }
    ],
    "remediation": {
      "title": "Generate and publish an SPDX SBOM for the repository",
      "description": "Integrate SBOM generation into the CI/CD pipeline using a tool such as syft, trivy, or GitHub's dependency graph export, and attach the SBOM to every release.",
      "tasks": [
        { "title": "Integrate an SBOM generation tool (e.g., syft, trivy sbom) into the CI/CD pipeline" },
        { "title": "Generate an SPDX 2.2 or 2.3 formatted SBOM on each release build" },
        { "title": "Attach the SBOM artifact to GitHub Releases" },
        { "title": "Validate the SBOM contains all direct and transitive dependencies" },
        { "title": "Store the SBOM in a location accessible to vulnerability scanning tooling" }
      ]
    }
  }
]

violation[{"id": "sbom_absent"}] if {
    not sbom_present
}

violation[{"id": "sbom_has_no_packages"}] if {
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
