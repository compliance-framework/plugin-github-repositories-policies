package compliance_framework.change_control_release_recency

# Maximum allowed age of the latest release (in days).
max_age_days := 90

latest := input.last_release

risk_templates := [
  {
    "name": "Repository has no releases",
    "title": "Absence of Release Process Indicates Uncontrolled Deployments",
    "statement": "A repository with no releases suggests that changes may be deployed without a formal, versioned release process. This lack of control increases the risk of deploying untested or unapproved changes, losing traceability over what is running in production, and inability to perform controlled rollbacks.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["no_release_present"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Establish a release process with tagged GitHub releases",
      "description": "Introduce a consistent release process using GitHub Releases with semantic versioning, release notes, and automated publishing workflows.",
      "tasks": [
        { "title": "Create an initial tagged release in the GitHub repository" },
        { "title": "Define a release cadence and document it in the repository README or CONTRIBUTING guide" },
        { "title": "Automate release creation using GitHub Actions on tag push events" },
        { "title": "Populate release notes with changes, linked issues, and contributors" }
      ]
    }
  },
  {
    "name": "Latest release is too old",
    "title": "Stale Release Indicates Accumulated Undeployed Changes",
    "statement": "A latest release older than the permitted threshold suggests that changes have accumulated without formal release. This increases the blast radius of any single deployment, reduces traceability, and may indicate that security patches or critical fixes are not being shipped in a timely manner.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["release_too_old"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1104",
        "title": "Use of Unmaintained Third Party Components",
        "url": "https://cwe.mitre.org/data/definitions/1104.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Establish a regular release cadence",
      "description": "Publish new releases at a regular cadence so that changes are shipped incrementally and security fixes reach production promptly.",
      "tasks": [
        { "title": "Create a new release for the accumulated changes since the last release" },
        { "title": "Define a maximum release interval policy (e.g., at least every 90 days)" },
        { "title": "Automate release publishing via CI/CD pipelines triggered on milestone completion" },
        { "title": "Include security advisories and dependency updates in release notes" }
      ]
    }
  }
]

violation[{"id": "release_too_old", "remarks": "Latest Release is too old (older than 90 days)"}] if {
    release_present
    release_too_old
}

violation[{"id": "no_release_present", "remarks": "No releases available for this repository."}] if {
    not release_present
}

release_present if {
    latest != null
}

release_too_old if {
    ts := latest.published_at
    ts != null

    release_ns := time.parse_rfc3339_ns(ts)
    now_ns := time.now_ns()

    age_ns := now_ns - release_ns
    max_ns := max_age_days * 24 * 60 * 60 * 1000000000

    age_ns > max_ns
}

title := "Latest release is recent"
description := "The most recent repository release must be no older than the allowed threshold (default 90 days). Expected shape: input.last_release.published_at as an RFC3339 timestamp."