package compliance_framework.secret_scanning_push_protection_enabled

risk_templates := [{
  "name": "Secret scanning push protection not enabled",
  "title": "Credentials Can Be Pushed to Repository Without Being Blocked",
  "statement": "Without push protection, developers can push commits containing secrets (API keys, tokens, certificates) even when those patterns are recognized by secret scanning. Push protection is the only control that prevents secrets from entering the repository in the first place. Reactive detection after the fact leaves a window during which credentials are exposed and potentially harvested.",
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
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    }
  ],
  "remediation": {
    "title": "Enable secret scanning push protection on all repositories",
    "description": "Activate push protection in repository Security & Analysis settings so that pushes containing recognized secret patterns are blocked at the point of upload, before they can be stored in the git history.",
    "tasks": [
      { "title": "Enable 'Push protection' under Secret scanning in repository Security & Analysis settings" },
      { "title": "Ensure secret scanning itself is also enabled (required prerequisite)" },
      { "title": "Educate developers on the bypass workflow and when it is appropriate to use" },
      { "title": "Audit push protection bypass events regularly via the GitHub Security log" },
      { "title": "Configure organization-level push protection to apply the control to all new repositories by default" }
    ]
  }
}]

# Throw violation if security_and_analysis structure doesn't exist ...
violation[{"id": "push_protection_disabled"}] if {
    not input.settings.security_and_analysis
}

# ... or if secret_scanning doesn't exist ..
violation[{"id": "push_protection_disabled"}] if {
	not input.settings.security_and_analysis.secret_scanning_push_protection
}

# .. finally, check if the status is enabled
violation[{"id": "push_protection_disabled"}] if {
	not input.settings.security_and_analysis.secret_scanning_push_protection.status == "enabled"
}

title := "Repository has secret scanning push protection enabled"
description := "All repositories must have secret scanning push protection enabled."
remarks := "Enabling secret scanning push protection helps to identify and prevent the accidental exposure of sensitive information, such as API keys and passwords in your codebase. It is an essential security measure to protect your application and its users."
