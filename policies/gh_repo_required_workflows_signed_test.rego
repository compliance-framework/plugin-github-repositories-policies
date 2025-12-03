package compliance_framework.required_workflows_signed_test

import data.compliance_framework.required_workflows_signed as policy

# Test: No required workflows configured (no violation)
test_no_required_workflows_no_violation if {
    inp := {}
    count(policy.violation) == 0 with input as inp
}

test_empty_required_workflows_no_violation if {
    inp := {"required_workflows": []}
    count(policy.violation) == 0 with input as inp
}

# Test: Workflow exists but attestation is null
test_workflow_no_attestation_null_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "attestation": null,
                "authorized_signers": ["devops@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"workflow": ".github/workflows/ci.yml", "reason": "no_attestation"}]
}

# Test: Workflow exists but attestation does not exist
test_workflow_attestation_not_exists_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "deploy.yml",
                "path": ".github/workflows/deploy.yml",
                "exists": true,
                "attestation": {"exists": false},
                "authorized_signers": ["devops@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"workflow": ".github/workflows/deploy.yml", "reason": "no_attestation"}]
}

# Test: Attestation exists but not verified
test_attestation_not_verified_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": false,
                    "error": "signature mismatch"
                },
                "authorized_signers": ["devops@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"workflow": ".github/workflows/ci.yml", "reason": "invalid_signature", "error": "signature mismatch"}]
}

# Test: Attestation verified but signer not authorized
test_unauthorized_signer_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "random@attacker.com"
                },
                "authorized_signers": ["devops@company.com", "sre@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"workflow": ".github/workflows/ci.yml", "reason": "unauthorized_signer", "signer": "random@attacker.com"}]
}

# Test: Valid attestation with authorized signer
test_valid_attestation_no_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "devops@company.com"
                },
                "authorized_signers": ["devops@company.com", "sre@company.com"]
            }
        ]
    }
    count(policy.violation) == 0 with input as inp
}

# Test: Workflow does not exist (no violation from this policy - handled by required_workflows_exist)
test_workflow_not_exists_no_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": false,
                "attestation": null,
                "authorized_signers": ["devops@company.com"]
            }
        ]
    }
    count(policy.violation) == 0 with input as inp
}

# Test: Multiple workflows with mixed results
test_multiple_workflows_mixed_violations if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "devops@company.com"
                },
                "authorized_signers": ["devops@company.com"]
            },
            {
                "name": "deploy.yml",
                "path": ".github/workflows/deploy.yml",
                "exists": true,
                "attestation": {"exists": false},
                "authorized_signers": ["devops@company.com"]
            },
            {
                "name": "security-scan.yml",
                "path": ".github/workflows/security-scan.yml",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "unauthorized@example.com"
                },
                "authorized_signers": ["security@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 2
}

# Test: No authorized signers configured (skip authorization check)
test_no_authorized_signers_no_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "anyone@example.com"
                },
                "authorized_signers": []
            }
        ]
    }
    count(policy.violation) == 0 with input as inp
}

# Test: OIDC workflow identity match
test_oidc_workflow_identity_match_no_violation if {
    inp := {
        "required_workflows": [
            {
                "name": "ci.yml",
                "path": ".github/workflows/ci.yml",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "https://github.com/my-org/my-repo/.github/workflows/sign.yml@refs/heads/main"
                },
                "authorized_signers": [".github/workflows/sign.yml"]
            }
        ]
    }
    count(policy.violation) == 0 with input as inp
}
