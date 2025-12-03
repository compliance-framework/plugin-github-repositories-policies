package compliance_framework.required_workflows_signed

# Check that required workflows have valid attestations signed by authorized parties

default has_required_workflows := false
has_required_workflows if {
    input.required_workflows != null
    count(input.required_workflows) > 0
}

# Violation: Workflow exists but has no attestation
violation[{"workflow": w.path, "reason": "no_attestation"}] if {
    has_required_workflows
    w := input.required_workflows[_]
    w.exists
    w.attestation == null
}

violation[{"workflow": w.path, "reason": "no_attestation"}] if {
    has_required_workflows
    w := input.required_workflows[_]
    w.exists
    w.attestation != null
    not w.attestation.exists
}

# Violation: Attestation exists but signature is not verified
violation[{"workflow": w.path, "reason": "invalid_signature", "error": w.attestation.error}] if {
    has_required_workflows
    w := input.required_workflows[_]
    w.exists
    w.attestation != null
    w.attestation.exists
    not w.attestation.verified
}

# Violation: Signature verified but signer is not authorized
violation[{"workflow": w.path, "reason": "unauthorized_signer", "signer": w.attestation.signer_identity}] if {
    has_required_workflows
    w := input.required_workflows[_]
    w.exists
    w.attestation != null
    w.attestation.exists
    w.attestation.verified
    count(w.authorized_signers) > 0
    not signer_authorized(w.attestation.signer_identity, w.authorized_signers)
}

signer_authorized(signer, authorized) if {
    some auth in authorized
    signer == auth
}

signer_authorized(signer, authorized) if {
    some auth in authorized
    contains(signer, auth)
}

title := "Required workflows signed by authorized party"
description := "Required CI/CD workflows must have valid in-repo attestations signed by authorized parties."
