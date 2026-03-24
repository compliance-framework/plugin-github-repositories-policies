package compliance_framework.change_control_release_semver

latest := input.last_release

risk_templates := [
  {
    "name": "Repository has no releases",
    "title": "Absence of Versioned Releases Prevents Reproducibility and Traceability",
    "statement": "Without any tagged releases, it is impossible to reliably identify what version of the software is deployed or to reproduce past builds. This hinders incident response, audit trails, and rollback capabilities.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["no_release_present"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      }
    ],
    "remediation": {
      "title": "Establish a versioned release process",
      "description": "Adopt semantic versioning and publish at least an initial release to establish a baseline version identifier for the software.",
      "tasks": [
        { "title": "Create an initial tagged release following SemVer (e.g., v1.0.0)" },
        { "title": "Automate tagging and release publishing in CI/CD pipelines" },
        { "title": "Document versioning conventions in repository README or CONTRIBUTING guide" }
      ]
    }
  },
  {
    "name": "Release tag does not follow semantic versioning",
    "title": "Non-Standard Version Tags Undermine Dependency Management and Automation",
    "statement": "Release tags that do not follow Semantic Versioning (SemVer) break automated tooling that relies on version ordering (e.g., Dependabot, package managers, deployment scripts). Non-standard tags increase the likelihood of deploying unintended versions and complicate vulnerability triage based on version ranges.",
    "likelihood_hint": "low",
    "impact_hint": "moderate",
    "violation_ids": ["tag_not_semver"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-710",
        "title": "Improper Adherence to Coding Standards",
        "url": "https://cwe.mitre.org/data/definitions/710.html"
      }
    ],
    "remediation": {
      "title": "Adopt Semantic Versioning for all release tags",
      "description": "Rename existing tags to follow SemVer (MAJOR.MINOR.PATCH) and enforce SemVer conventions in release automation to prevent non-conforming tags in the future.",
      "tasks": [
        { "title": "Re-tag the latest release using SemVer convention (e.g., v1.2.3)" },
        { "title": "Update CI/CD release workflows to enforce SemVer tag format before publishing" },
        { "title": "Add tag format validation to branch protection or release automation" },
        { "title": "Document the project versioning policy for contributors" }
      ]
    }
  }
]

violation[{"id": "no_release_present", "remarks": "No releases available for this repository."}] if {
    not release_present
}

violation[{"id": "tag_not_semver", "remarks": "Latest Release tag does not follow semver convention."}] if {
    release_present
    not tag_is_semver
}

release_present if {
    latest != null
    latest.tag_name != null
    trim_space(latest.tag_name) != ""
}

tag_is_semver if {
    tag := trim_space(latest.tag_name)

    # Allow optional leading "v" and enforce SemVer 2.0.0:
    # MAJOR.MINOR.PATCH(-prerelease)?(+buildmetadata)?
    semver_pattern := "^v?(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-[0-9A-Za-z-.]+)?(?:\\+[0-9A-Za-z-.]+)?$"

    regex.match(semver_pattern, tag)
}

title := "Latest release tag follows Semantic Versioning"
description := "The latest release tag must follow Semantic Versioning (SemVer), such as v1.2.3 or 1.2.3, with optional pre-release and build metadata. Expected shape: input.LatestRelease.tag_name."
