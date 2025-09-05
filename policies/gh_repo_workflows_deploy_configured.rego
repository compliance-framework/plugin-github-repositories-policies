package compliance_framework.workflows_deploy_configured

# A repository should have at least one workflow that performs a deploy or release.

violation[{}] if {
    count(input.workflows) == 0
}

violation[{}] if {
    every workflow in input.workflows {
        not is_deploy_or_release(workflow)
    }
}

is_deploy_or_release(w) if {
    contains(lower(w.name), "deploy")
}

is_deploy_or_release(w) if {
    contains(lower(w.name), "release")
}

is_deploy_or_release(w) if {
    contains(lower(w.name), "publish")
}

is_deploy_or_release(w) if {
    contains(lower(w.path), "deploy")
}

is_deploy_or_release(w) if {
    contains(lower(w.path), "release")
}

is_deploy_or_release(w) if {
    contains(lower(w.path), "publish")
}

title := "Repository has deploy or release workflows"
description := "A repository must have at least one workflow configured for deploy or release."
