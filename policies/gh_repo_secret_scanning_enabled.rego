package compliance_framework.secret_scanning_enabled

risk_templates := [{
  "name": "Secret scanning not enabled on repository",
  "title": "Credentials and Secrets Committed to Repository Without Detection",
  "statement": "Without secret scanning, API keys, tokens, passwords, and other credentials accidentally committed to the repository will persist undetected in the git history. Exposed secrets can be harvested by attackers with repository access or via public repository indexing, leading to account takeover, data breaches, and supply chain compromise.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-312",
      "title": "Cleartext Storage of Sensitive Information",
      "url": "https://cwe.mitre.org/data/definitions/312.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-522",
      "title": "Insufficiently Protected Credentials",
      "url": "https://cwe.mitre.org/data/definitions/522.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-798",
      "title": "Use of Hard-coded Credentials",
      "url": "https://cwe.mitre.org/data/definitions/798.html"
    }
  ],
  "remediation": {
    "title": "Enable GitHub secret scanning on all repositories",
    "description": "Activate secret scanning in repository Security & Analysis settings to detect and alert on committed credentials across the current codebase and all future commits.",
    "tasks": [
      { "title": "Enable secret scanning in repository Security & Analysis settings" },
      { "title": "Review all existing secret scanning alerts and revoke any exposed credentials immediately" },
      { "title": "Rotate any credentials found in git history and invalidate old tokens/keys" },
      { "title": "Purge secrets from git history using git-filter-repo or BFG Repo Cleaner" },
      { "title": "Migrate secrets to a secrets manager (e.g., GitHub Actions secrets, Vault, AWS Secrets Manager)" },
      { "title": "Configure pre-commit hooks or a SAST tool to catch secrets before they are pushed" }
    ]
  }
}]

# Throw violation if security_and_analysis structure doesn't exist ...
violation[{"id": "secret_scanning_disabled"}] if {
    not input.settings.security_and_analysis
}

# ... or if secret_scanning doesn't exist ..
violation[{"id": "secret_scanning_disabled"}] if {
	not input.settings.security_and_analysis.secret_scanning
}

# .. finally, check if the status is enabled
violation[{"id": "secret_scanning_disabled"}] if {
	not input.settings.security_and_analysis.secret_scanning.status == "enabled"
}

title := "Repository has secret scanning enabled"
description := "All repositories must have secret scanning enabled."
remarks := "Enabling secret scanning helps to identify and prevent the accidental exposure of sensitive information, such as API keys and passwords, in your codebase. It is an essential security measure to protect your application and its users."
