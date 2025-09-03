package compliance_framework.secret_scanning_enabled

# Throw violation if security_and_analysis structure doesn't exist ...
violation[{}] if {
    not input.settings.security_and_analysis
}

# ... or if secret_scanning doesn't exist ..
violation[{}] if {
	not input.settings.security_and_analysis.secret_scanning
}

# .. finally, check if the status is enabled
violation[{}] if {
	not input.settings.security_and_analysis.secret_scanning.status == "enabled"
}

title := "Repository has secret scanning enabled"
description := "All repositories must have secret scanning enabled."
remarks := "Enabling secret scanning helps to identify and prevent the accidental exposure of sensitive information, such as API keys and passwords, in your codebase. It is an essential security measure to protect your application and its users."
