package compliance_framework.change_control_release_semver

latest := input.last_release

violation[{"remarks": "No releases available for this repository."}] if {
    not release_present
}

violation[{"remarks": "Latest Release tag does not follow semver convention."}] if {
    release_present
    not tag_is_semver
}

release_present if {
    latest != null
    latest.tag_name != null
    trim_space(latest.tag_name) != ""
}

tag_is_semver if {
    tag := trim_space(latest.tag_name)

    # Allow optional leading "v" and enforce SemVer 2.0.0:
    # MAJOR.MINOR.PATCH(-prerelease)?(+buildmetadata)?
    semver_pattern := "^v?(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-[0-9A-Za-z-.]+)?(?:\\+[0-9A-Za-z-.]+)?$"

    regex.match(semver_pattern, tag)
}

title := "Latest release tag follows Semantic Versioning"
description := "The latest release tag must follow Semantic Versioning (SemVer), such as v1.2.3 or 1.2.3, with optional pre-release and build metadata. Expected shape: input.LatestRelease.tag_name."
