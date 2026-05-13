package compliance_framework.workflows_configured

risk_templates := [
  {
    "name": "No CI/CD workflows configured in repository",
    "title": "Absence of Automated Build and Test Pipelines Removes Quality Gate",
    "statement": "A repository with no CI/CD workflows has no automated mechanism to build, test, or validate code changes before they are merged or deployed. This means defects, security vulnerabilities, and regressions may go undetected until they reach production, significantly increasing risk exposure.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["no_workflows_configured"],
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
    "name": "Required CI/CD workflows missing",
    "title": "Missing Required CI/CD Workflows Compromises Quality Assurance",
    "statement": "When required CI/CD workflows are not present, critical build, test, or validation steps may be skipped, allowing defective or non-compliant code to merge without proper quality gates. This increases the risk of introducing vulnerabilities and regressions into production.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["required_workflows_missing"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Add missing required CI/CD workflows",
      "description": "Create the required GitHub Actions workflows specified in the policy configuration to ensure all necessary quality gates are in place.",
      "tasks": [
        { "title": "Identify which required workflows are missing from the repository" },
        { "title": "Create each missing workflow file in .github/workflows/" },
        { "title": "Configure triggers (push, pull_request, schedule) as appropriate" },
        { "title": "Add necessary build, test, and validation steps to each workflow" },
        { "title": "Set workflows as required status checks on protected branches if needed" }
      ]
    }
  }
]

violation[{"id": "no_workflows_configured"}] if {
	count(input.workflows) == 0
}

violation[{"id": "required_workflows_missing"}] if {
	count(input.workflows) > 0
	input.policy_input.workflow_names
	some workflow_name in input.policy_input.workflow_names
	not workflow_present(workflow_name)
}

workflow_present(name) if {
	some workflow in input.workflows
	workflow_filename(workflow) == name
}

workflow_filename(workflow) := filename if {
	path := object.get(workflow, "path", "")
	parts := split(path, "/")
	filename := parts[count(parts) - 1]
}


title := "Repository has workflows configured"

missing_workflow_names := [workflow_name |
	count(input.workflows) > 0
	input.policy_input.workflow_names
	some workflow_name in input.policy_input.workflow_names
	not workflow_present(workflow_name)
]

description := msg if {
	count(input.workflows) == 0
	msg := "No workflows configured in repository"
}

description := msg if {
	count(input.workflows) > 0
	count(missing_workflow_names) > 0
	msg := sprintf("Missing required workflow %s", [concat(", ", missing_workflow_names)])
}

description := "All repositories must have workflows configured." if {
	count(input.workflows) > 0
	count(missing_workflow_names) == 0
}
