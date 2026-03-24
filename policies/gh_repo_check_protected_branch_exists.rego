package compliance_framework.check_protected_branch_exists

risk_templates := [{
  "name": "No protected branches configured",
  "title": "Unprotected Branches Allow Direct Force-Push and Unreviewed Merges",
  "statement": "Without any branch protection rules, any contributor with write access can force-push directly to main/master, rewrite history, delete branches, or merge code without review. This eliminates all code review gates and allows malicious or erroneous changes to reach production without oversight.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-284",
      "title": "Improper Access Control",
      "url": "https://cwe.mitre.org/data/definitions/284.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-732",
      "title": "Incorrect Permission Assignment for Critical Resource",
      "url": "https://cwe.mitre.org/data/definitions/732.html"
    }
  ],
  "remediation": {
    "title": "Configure branch protection rules on all critical branches",
    "description": "Add branch protection rules to main/master and any release branches to prevent direct pushes, require pull request reviews, and enforce status checks before merging.",
    "tasks": [
      { "title": "Enable branch protection on main/master in GitHub repository settings" },
      { "title": "Require pull request reviews before merging" },
      { "title": "Enable required status checks to prevent merging broken builds" },
      { "title": "Disable force pushes and branch deletion for protected branches" },
      { "title": "Restrict who can push to protected branches to authorized teams only" }
    ]
  }
}]

violation[{"id": "no_protected_branch"}] if {
    count(input.protected_branches) == 0
}

title := "Repository has at least one protected branch"
description := "All repositories must have at least one protected branch configured."
