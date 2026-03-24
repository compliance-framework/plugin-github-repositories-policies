package compliance_framework.workflow_health

total := count(input.workflow_runs)
passed := count([x |
    x := input.workflow_runs[_]
    x.conclusion == "success"
])
tolerance := 0.2

risk_templates := [{
  "name": "Repository has unhealthy workflow run failure rate",
  "title": "Excessive CI/CD Workflow Failures Indicate Systemic Build or Test Instability",
  "statement": "A high workflow failure rate beyond the allowed tolerance indicates that automated quality gates are not reliably passing. This suggests either that defective code is frequently being introduced, that the CI/CD pipeline itself is broken, or that required checks are being bypassed. Persistent failures erode trust in automated controls and increase the likelihood of defective or vulnerable changes reaching production.",
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
      "external_id": "CWE-358",
      "title": "Improperly Implemented Security Check for Standard",
      "url": "https://cwe.mitre.org/data/definitions/358.html"
    }
  ],
  "remediation": {
    "title": "Investigate and resolve persistent workflow failures",
    "description": "Review recent failed workflow runs to identify root causes (flaky tests, build infrastructure issues, defective code) and restore the pipeline to a consistently healthy state.",
    "tasks": [
      { "title": "Review recent failed workflow runs to identify patterns and root causes" },
      { "title": "Fix or quarantine flaky tests that contribute disproportionately to failures" },
      { "title": "Resolve any build infrastructure issues (runner availability, dependency fetching)" },
      { "title": "Ensure that required status checks cannot be bypassed when workflows are failing" },
      { "title": "Set up alerting for workflow failure rate exceeding the defined tolerance threshold" }
    ]
  }
}]

violation[{"id": "unhealthy_workflow_runs"}] if {
    tolerance_amount = max([total, passed]) * tolerance
	abs(total - passed) > tolerance_amount
}

title := "Repository has healthy workflow runs"
description := sprintf("All repositories must have healthy workflow runs. [%d/%d - tolerance %d%%]", [passed, total, tolerance * 100])
remarks := sprintf("All repositories must have healthy workflow runs. Healthy workflow runs are calculated with a tolerance of %d%%", [tolerance * 100])