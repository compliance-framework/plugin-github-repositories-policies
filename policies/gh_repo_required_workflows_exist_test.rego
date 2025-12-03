package compliance_framework.required_workflows_exist_test

import data.compliance_framework.required_workflows_exist as policy

# Test: No required workflows configured (no violation)
test_no_required_workflows_no_violation if {
    inp := {}
    count(policy.violation) == 0 with input as inp
}

test_empty_required_workflows_no_violation if {
    inp := {"required_workflows": []}
    count(policy.violation) == 0 with input as inp
}

# Test: Required workflow does not exist
test_workflow_not_exists_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": false,
                "authorized_signers": ["devops@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"workflow": ".github/workflows/ci.yml", "name": "ci.yml"}]
}

# Test: Required workflow exists (no violation)
test_workflow_exists_no_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "attestation": {"exists": true, "verified": true},
                "authorized_signers": ["devops@company.com"]
            }
        ]
    }
    count(policy.violation) == 0 with input as inp
}

# Test: Multiple workflows with mixed existence
test_multiple_workflows_mixed_violations if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "authorized_signers": ["devops@company.com"]
            },
            {
                "name": "deploy.yml",
                "path": ".github/workflows/deploy.yml",
                "exists": false,
                "authorized_signers": ["devops@company.com"]
            },
            {
                "name": "security-scan.yml",
                "path": ".github/workflows/security-scan.yml",
                "exists": false,
                "authorized_signers": ["security@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 2
}

# Test: All required workflows exist
test_all_workflows_exist_no_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "authorized_signers": ["devops@company.com"]
            },
            {
                "name": "deploy.yml",
                "path": ".github/workflows/deploy.yml",
                "exists": true,
                "authorized_signers": ["devops@company.com"]
            }
        ]
    }
    count(policy.violation) == 0 with input as inp
}
