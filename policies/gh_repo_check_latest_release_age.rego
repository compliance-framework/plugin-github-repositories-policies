package compliance_framework.change_control_release_recency

# Maximum allowed age of the latest release (in days).
max_age_days := 90

latest := input.last_release

violation[{"remarks": "Latest Release is too old (older than 90 days)"}] if {
    release_present
    release_too_old
}

violation[{"remarks": "No releases available for this repository."}] if {
    not release_present
}

release_present if {
    latest != null
}

release_too_old if {
    ts := latest.published_at
    ts != null

    release_ns := time.parse_rfc3339_ns(ts)
    now_ns := time.now_ns()

    age_ns := now_ns - release_ns
    max_ns := max_age_days * 24 * 60 * 60 * 1000000000

    age_ns > max_ns
}

title := "Latest release is recent"
description := "The most recent repository release must be no older than the allowed threshold (default 90 days). Expected shape: input.last_release.published_at as an RFC3339 timestamp."