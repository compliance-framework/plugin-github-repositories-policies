package compliance_framework.critical_files_signed_test

import data.compliance_framework.critical_files_signed as policy

# Test: No tracked files configured (no violation)
test_no_tracked_files_no_violation if {
    inp := {}
    count(policy.violation) == 0 with input as inp
}

test_empty_tracked_files_no_violation if {
    inp := {"tracked_files": []}
    count(policy.violation) == 0 with input as inp
}

# Test: File exists but attestation is null
test_file_exists_no_attestation_null_violation if {
    inp := {
        "tracked_files": [
            {
                "path": "PLAN.md",
                "exists": true,
                "attestation": null,
                "authorized_signers": ["tech-lead@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"file": "PLAN.md", "reason": "no_attestation"}]
}

# Test: File exists but attestation does not exist
test_file_exists_attestation_not_exists_violation if {
    inp := {
        "tracked_files": [
            {
                "path": "SECURITY.md",
                "exists": true,
                "attestation": {"exists": false},
                "authorized_signers": ["security@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"file": "SECURITY.md", "reason": "no_attestation"}]
}

# Test: Attestation exists but not verified
test_attestation_not_verified_violation if {
    inp := {
        "tracked_files": [
            {
                "path": "PLAN.md",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": false,
                    "error": "signature mismatch"
                },
                "authorized_signers": ["tech-lead@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"file": "PLAN.md", "reason": "invalid_signature", "error": "signature mismatch"}]
}

# Test: Attestation verified but signer not authorized
test_unauthorized_signer_violation if {
    inp := {
        "tracked_files": [
            {
                "path": "PLAN.md",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "random@attacker.com"
                },
                "authorized_signers": ["tech-lead@company.com", "cto@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 1
    violations[{"file": "PLAN.md", "reason": "unauthorized_signer", "signer": "random@attacker.com"}]
}

# Test: Valid attestation with authorized signer
test_valid_attestation_no_violation if {
    inp := {
        "tracked_files": [
            {
                "path": "PLAN.md",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "tech-lead@company.com"
                },
                "authorized_signers": ["tech-lead@company.com", "cto@company.com"]
            }
        ]
    }
    count(policy.violation) == 0 with input as inp
}

# Test: File does not exist (no violation - file is optional)
test_file_not_exists_no_violation if {
    inp := {
        "tracked_files": [
            {
                "path": "OPTIONAL.md",
                "exists": false,
                "attestation": null,
                "authorized_signers": ["anyone@company.com"]
            }
        ]
    }
    count(policy.violation) == 0 with input as inp
}

# Test: Multiple files with mixed results
test_multiple_files_mixed_violations if {
    inp := {
        "tracked_files": [
            {
                "path": "PLAN.md",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "tech-lead@company.com"
                },
                "authorized_signers": ["tech-lead@company.com"]
            },
            {
                "path": "SECURITY.md",
                "exists": true,
                "attestation": {"exists": false},
                "authorized_signers": ["security@company.com"]
            },
            {
                "path": "README.md",
                "exists": true,
                "attestation": {
                    "exists": true,
                    "verified": true,
                    "signer_identity": "unauthorized@example.com"
                },
                "authorized_signers": ["docs@company.com"]
            }
        ]
    }
    violations := policy.violation with input as inp
    count(violations) == 2
}

# Test: No authorized signers configured (skip authorization check)
test_no_authorized_signers_no_violation if {
    inp := {
        "tracked_files": [
            {
                "path": "PLAN.md",
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
