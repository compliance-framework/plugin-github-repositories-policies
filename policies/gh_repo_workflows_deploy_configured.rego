package compliance_framework.workflows_deploy_configured

# A repository should have at least one workflow that performs a deploy or release.

risk_templates := [
  {
    "name": "No deploy or release workflow configured",
    "title": "Absence of Automated Deployment Pipeline Enables Ad-Hoc and Uncontrolled Releases",
    "statement": "Without an automated deploy or release workflow, deployments may be performed manually, inconsistently, or by individuals without proper authorization. Manual deployments are error-prone, difficult to audit, and bypass any automated security or compliance checks that would normally run in a controlled pipeline.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-284",
        "title": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html"
      }
    ],
    "remediation": {
      "title": "Add an automated deploy or release workflow",
      "description": "Create a GitHub Actions workflow for deployment or release that automates the process, enforces approvals, and includes security checks prior to pushing to production.",
      "tasks": [
        { "title": "Create a workflow named 'deploy', 'release', or 'publish' in .github/workflows/" },
        { "title": "Configure the workflow to trigger on tag push, release creation, or manual dispatch with approvals" },
        { "title": "Include pre-deployment security and compliance checks (SAST, SBOM generation, container scanning)" },
        { "title": "Restrict deployment workflow permissions to the minimum required roles" },
        { "title": "Configure environment protection rules with required reviewers for production deployments" }
      ]
    }
  }
]

violation[{"id": "no_workflows_configured"}] if {
    count(input.workflows) == 0
}

violation[{"id": "no_deploy_or_release_workflow"}] if {
    count(input.workflows) > 0
    every workflow in input.workflows {
        not is_deploy_or_release(workflow)
    }
}

is_deploy_or_release(w) if {
    contains(lower(w.name), "deploy")
}

is_deploy_or_release(w) if {
    contains(lower(w.name), "release")
}

is_deploy_or_release(w) if {
    contains(lower(w.name), "publish")
}

is_deploy_or_release(w) if {
    contains(lower(w.path), "deploy")
}

is_deploy_or_release(w) if {
    contains(lower(w.path), "release")
}

is_deploy_or_release(w) if {
    contains(lower(w.path), "publish")
}

title := "Repository has deploy or release workflows"
description := "A repository must have at least one workflow configured for deploy or release."
