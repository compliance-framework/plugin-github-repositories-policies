package compliance_framework.critical_files_signed

# Check that tracked critical files have valid attestations signed by authorized parties

default has_tracked_files := false
has_tracked_files if {
    input.tracked_files != null
    count(input.tracked_files) > 0
}

# Violation: File exists but has no attestation
violation[{"file": f.path, "reason": "no_attestation"}] if {
    has_tracked_files
    f := input.tracked_files[_]
    f.exists
    f.attestation == null
}

violation[{"file": f.path, "reason": "no_attestation"}] if {
    has_tracked_files
    f := input.tracked_files[_]
    f.exists
    f.attestation != null
    not f.attestation.exists
}

# Violation: Attestation exists but signature is not verified
violation[{"file": f.path, "reason": "invalid_signature", "error": f.attestation.error}] if {
    has_tracked_files
    f := input.tracked_files[_]
    f.exists
    f.attestation != null
    f.attestation.exists
    not f.attestation.verified
}

# Violation: Signature verified but signer is not authorized
violation[{"file": f.path, "reason": "unauthorized_signer", "signer": f.attestation.signer_identity}] if {
    has_tracked_files
    f := input.tracked_files[_]
    f.exists
    f.attestation != null
    f.attestation.exists
    f.attestation.verified
    count(f.authorized_signers) > 0
    not signer_authorized(f.attestation.signer_identity, f.authorized_signers)
}

signer_authorized(signer, authorized) if {
    some auth in authorized
    signer == auth
}

signer_authorized(signer, authorized) if {
    some auth in authorized
    contains(signer, auth)
}

title := "Critical files signed by authorized party"
description := "Tracked critical files must have valid in-repo attestations signed by authorized parties."
