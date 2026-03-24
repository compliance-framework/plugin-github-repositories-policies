package compliance_framework.workflows_configured

risk_templates := [
  {
    "name": "No CI/CD workflows configured in repository",
    "title": "Absence of Automated Build and Test Pipelines Removes Quality Gate",
    "statement": "A repository with no CI/CD workflows has no automated mechanism to build, test, or validate code changes before they are merged or deployed. This means defects, security vulnerabilities, and regressions may go undetected until they reach production, significantly increasing risk exposure.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Add a CI workflow with build and test steps",
      "description": "Create a GitHub Actions workflow that builds the project and runs automated tests on every push and pull request to protected branches.",
      "tasks": [
        { "title": "Create a .github/workflows/ci.yml workflow triggered on push and pull_request events" },
        { "title": "Add build and unit test steps appropriate to the project's language and toolchain" },
        { "title": "Set the CI workflow as a required status check on protected branches" },
        { "title": "Include a security/SAST scan step in the CI workflow" }
      ]
    }
  },
  {
    "name": "No build or CI workflow found among configured workflows",
    "title": "No Automated Build Validation Despite Workflows Being Present",
    "statement": "Workflows exist in the repository but none are identifiable as a build or CI pipeline. Without an automated build validation step, code changes may be integrated without confirming the codebase compiles and tests pass, creating an undetected quality and security regression risk.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["no_build_or_ci_workflow"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Ensure at least one workflow is named to indicate build or CI purpose",
      "description": "Rename or add a workflow whose name includes 'build' or 'ci' to make automated build validation easily identifiable, and ensure it is configured as a required check.",
      "tasks": [
        { "title": "Review existing workflows and identify which one performs build and test steps" },
        { "title": "Rename that workflow to include 'build' or 'ci' in its name field" },
        { "title": "If no such workflow exists, create a dedicated CI workflow" },
        { "title": "Set the identified workflow as a required status check on protected branches" }
      ]
    }
  }
]

violation[{"id": "no_workflows_configured"}] if {
	count(input.workflows) == 0
}

violation[{"id": "no_build_or_ci_workflow"}] if {
	count(input.workflows) > 0
	every workflow in input.workflows {
		not contains(lower(workflow.name), "build")
		not contains(lower(workflow.name), "ci")
	}
}

title := "Repository has workflows configured"
description := "All repositories must have workflows configured."
