package compliance_framework.sbom_metadata

sbom := input.sbom.sbom

default max_age_days := 90

risk_templates := [
  {
    "name": "SBOM is absent or has invalid metadata",
    "title": "Invalid SBOM Metadata Undermines Supply Chain Compliance",
    "statement": "An SBOM with missing or invalid metadata (wrong SPDX version, missing namespace, or absent) cannot be reliably processed by vulnerability scanners, license checkers, or compliance tooling. This creates blind spots in the software supply chain and may prevent meeting regulatory SBOM requirements.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1104",
        "title": "Use of Unmaintained Third Party Components",
        "url": "https://cwe.mitre.org/data/definitions/1104.html"
      }
    ],
    "remediation": {
      "title": "Regenerate SBOM with valid SPDX metadata",
      "description": "Ensure the SBOM uses SPDX 2.2 or 2.3, includes a unique document namespace, and is regenerated on every release build so it remains current.",
      "tasks": [
        { "title": "Regenerate the SBOM using a tool that produces SPDX 2.2 or 2.3 output" },
        { "title": "Ensure the documentNamespace field is set to a unique, stable URI" },
        { "title": "Automate SBOM generation in the CI/CD pipeline on every release" },
        { "title": "Validate SBOM structure using an SPDX validation tool before attaching to releases" }
      ]
    }
  },
  {
    "name": "SBOM is stale",
    "title": "Outdated SBOM Does Not Reflect Current Dependency Composition",
    "statement": "An SBOM older than the permitted threshold may no longer accurately represent the software's current dependency set. New dependencies may have been added, removed, or updated without an accompanying SBOM refresh, preventing accurate vulnerability and license assessment.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["sbom_stale"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      }
    ],
    "remediation": {
      "title": "Refresh the SBOM to reflect the current dependency state",
      "description": "Regenerate the SBOM to capture the current dependency composition and configure CI/CD to regenerate the SBOM on every release.",
      "tasks": [
        { "title": "Immediately regenerate the SBOM and attach it to a new release or repository artifact" },
        { "title": "Configure the release pipeline to regenerate the SBOM automatically on every tagged release" },
        { "title": "Set a maximum SBOM age policy and alert when it is approaching expiry" }
      ]
    }
  }
]

violation[{"id": "sbom_absent"}] if {
    sbom == null
}

violation[{"id": "sbom_invalid_spdx_version"}] if {
    sbom != null
    not valid_spdx_version
}

violation[{"id": "sbom_missing_namespace"}] if {
    sbom != null
    not has_document_namespace
}

violation[{"id": "sbom_stale"}] if {
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