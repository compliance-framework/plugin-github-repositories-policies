package compliance_framework.dependabot_security_updates_enabled

# Throw violation if security_and_analysis structure doesn't exist ...
violation[{}] if {
    not input.settings.security_and_analysis
}

# ... or if dependabot_security_updates doesn't exist ..
violation[{}] if {
	not input.settings.security_and_analysis.dependabot_security_updates
}

# .. finally, check if the status is enabled
violation[{}] if {
	not input.settings.security_and_analysis.dependabot_security_updates.status == "enabled"
}

title := "Repository has dependabot security updates enabled"
description := "All repositories must have dependabot security updates enabled."
remarks := "Enabling dependabot security updates helps to automatically keep your dependencies up to date with the latest security patches. This is an essential security measure to protect your application from vulnerabilities that could be exploited by attackers."