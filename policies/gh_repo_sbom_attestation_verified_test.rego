package compliance_framework.sbom_attestation_verified_test

import data.compliance_framework.sbom_attestation_verified as policy

# Test: No SBOM attestation data configured
test_no_sbom_attestation_data_violation if {
    inp := {}
    count(policy.violation) == 1 with input as inp
}

# Test: Attestation file does not exist
test_attestation_not_exists_violation if {
    inp := {
        "sbom_attestation_data": {
            "attestation": {
                "exists": false
            },
            "authorized_signers": ["security@company.com"]
        }
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"reason": "no_attestation"}]
}

# Test: Attestation exists but not verified
test_attestation_not_verified_violation if {
    inp := {
        "sbom_attestation_data": {
            "attestation": {
                "exists": true,
                "verified": false,
                "error": "signature mismatch"
            },
            "authorized_signers": ["security@company.com"]
        }
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"reason": "invalid_signature", "error": "signature mismatch"}]
}

# Test: Attestation verified but signer not authorized
test_unauthorized_signer_violation if {
    inp := {
        "sbom_attestation_data": {
            "attestation": {
                "exists": true,
                "verified": true,
                "signer_identity": "random@attacker.com"
            },
            "authorized_signers": ["security@company.com", "release-bot@company.com"]
        }
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"reason": "unauthorized_signer", "signer": "random@attacker.com"}]
}

# Test: Valid attestation with authorized signer (exact match)
test_valid_attestation_exact_match_no_violation if {
    inp := {
        "sbom_attestation_data": {
            "attestation": {
                "exists": true,
                "verified": true,
                "signer_identity": "security@company.com"
            },
            "authorized_signers": ["security@company.com", "release-bot@company.com"]
        }
    }
    count(policy.violation) == 0 with input as inp
}

# Test: Valid attestation with authorized signer (contains match for OIDC)
test_valid_attestation_contains_match_no_violation if {
    inp := {
        "sbom_attestation_data": {
            "attestation": {
                "exists": true,
                "verified": true,
                "signer_identity": "https://github.com/my-org/my-repo/.github/workflows/release.yml@refs/heads/main"
            },
            "authorized_signers": [".github/workflows/release.yml"]
        }
    }
    count(policy.violation) == 0 with input as inp
}

# Test: No authorized signers configured (skip authorization check)
test_no_authorized_signers_configured_no_violation if {
    inp := {
        "sbom_attestation_data": {
            "attestation": {
                "exists": true,
                "verified": true,
                "signer_identity": "anyone@example.com"
            },
            "authorized_signers": []
        }
    }
    count(policy.violation) == 0 with input as inp
}
