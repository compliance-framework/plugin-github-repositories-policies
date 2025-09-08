package compliance_framework.check_oss_license

violation[{}] if {
    not input.settings.license.spdx_id in [
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MIT",
        "MPL-2.0",
        "CDDL-1.0",
        "EPL-2.0",
        "Unlicense",
        "CC0-1.0"
    ]
}

violation[{}] if {
    # spdx_id missing
    not input.settings.license.spdx_id
}
violation[{}] if {
    # spdx_id empty string
    input.settings.license.spdx_id == ""
}

title = "Repository has a valid Open Source License"
description = "All repositories must have a valid Open Source License."
remarks = "Licensing your open source software is essential to clearly communicate the terms under which others can use, modify, and distribute your code. It helps protect your rights as an author, ensures compliance with legal requirements, and fosters trust and collaboration within the open source community. A well-defined license also prevents misuse and clarifies responsibilities for contributors and users."
