package compliance_framework.sbom_attestation_verified

# Check SBOM attestation exists and is signed by an authorized party

default has_sbom_attestation_data := false
has_sbom_attestation_data if {
    input.sbom_attestation_data != null
}

att := input.sbom_attestation_data.attestation
authorized := input.sbom_attestation_data.authorized_signers

# Violation: No attestation data configured
violation[{"reason": "not_configured"}] if {
    not has_sbom_attestation_data
}

# Violation: Attestation file does not exist
violation[{"reason": "no_attestation"}] if {
    has_sbom_attestation_data
    att != null
    not att.exists
}

# Violation: Attestation exists but signature is not verified
violation[{"reason": "invalid_signature", "error": att.error}] if {
    has_sbom_attestation_data
    att != null
    att.exists
    not att.verified
}

# Violation: Signature verified but signer is not authorized
violation[{"reason": "unauthorized_signer", "signer": att.signer_identity}] if {
    has_sbom_attestation_data
    att != null
    att.exists
    att.verified
    count(authorized) > 0
    not signer_authorized(att.signer_identity)
}

signer_authorized(signer) if {
    some auth in authorized
    signer == auth
}

signer_authorized(signer) if {
    some auth in authorized
    contains(signer, auth)
}

title := "SBOM attestation verified"
description := "The repository SBOM must have a valid in-repo attestation signed by an authorized party."
