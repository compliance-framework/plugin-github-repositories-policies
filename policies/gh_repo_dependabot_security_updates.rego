package compliance_framework.dependabot_security_updates_enabled

risk_templates := [{
  "name": "Dependabot security updates not enabled",
  "title": "Known Vulnerable Dependencies Not Automatically Remediated",
  "statement": "Without Dependabot security updates enabled, the repository will not automatically receive pull requests for dependencies with known CVEs. This means vulnerable dependencies can persist indefinitely, increasing the attack surface and the time-to-remediation window for exploitable vulnerabilities in the software supply chain.",
  "likelihood_hint": "high",
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
      "external_id": "CWE-937",
      "title": "OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities",
      "url": "https://cwe.mitre.org/data/definitions/937.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1035",
      "title": "OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities",
      "url": "https://cwe.mitre.org/data/definitions/1035.html"
    }
  ],
  "remediation": {
    "title": "Enable Dependabot security updates on all repositories",
    "description": "Activate Dependabot security updates in GitHub repository settings to receive automatic pull requests when dependencies with known vulnerabilities are detected.",
    "tasks": [
      { "title": "Enable Dependabot security updates in repository Security & Analysis settings" },
      { "title": "Ensure a supported dependency manifest file exists (e.g., package.json, go.mod, requirements.txt)" },
      { "title": "Configure Dependabot version updates in .github/dependabot.yml for comprehensive coverage" },
      { "title": "Establish a process to review and merge Dependabot PRs within the agreed SLA" },
      { "title": "Enable GitHub Advanced Security if available to surface additional vulnerability alerts" }
    ]
  }
}]

# Throw violation if security_and_analysis structure doesn't exist ...
violation[{"id": "dependabot_security_updates_disabled"}] if {
    not input.settings.security_and_analysis
}

# ... or if dependabot_security_updates doesn't exist ..
violation[{"id": "dependabot_security_updates_disabled"}] if {
	not input.settings.security_and_analysis.dependabot_security_updates
}

# .. finally, check if the status is enabled
violation[{"id": "dependabot_security_updates_disabled"}] if {
	not input.settings.security_and_analysis.dependabot_security_updates.status == "enabled"
}

title := "Repository has dependabot security updates enabled"
description := "All repositories must have dependabot security updates enabled."
remarks := "Enabling dependabot security updates helps to automatically keep your dependencies up to date with the latest security patches. This is an essential security measure to protect your application from vulnerabilities that could be exploited by attackers."