package compliance_framework.secret_scanning_push_protection_enabled

# Throw violation if security_and_analysis structure doesn't exist ...
violation[{}] if {
    not input.settings.security_and_analysis
}

# ... or if secret_scanning doesn't exist ..
violation[{}] if {
	not input.settings.security_and_analysis.secret_scanning_push_protection
}

# .. finally, check if the status is enabled
violation[{}] if {
	not input.settings.security_and_analysis.secret_scanning_push_protection.status == "enabled"
}

title := "Repository has secret scanning push protection enabled"
description := "All repositories must have secret scanning push protection enabled."
remarks := "Enabling secret scanning push protection helps to identify and prevent the accidental exposure of sensitive information, such as API keys and passwords in your codebase. It is an essential security measure to protect your application and its users."
