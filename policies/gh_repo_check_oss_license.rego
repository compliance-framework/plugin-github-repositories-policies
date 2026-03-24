package compliance_framework.check_oss_license

risk_templates := [
  {
    "name": "Repository uses a non-compliant or missing open source license",
    "title": "Missing or Non-Compliant License Exposes Legal and Distribution Risk",
    "statement": "A repository without a recognized open source license, or with a proprietary/non-commercial license, creates legal ambiguity for users, contributors, and downstream consumers. Organizations relying on unlicensed or non-OSI-approved software may face unexpected license violations, litigation, or inability to redistribute the software. This also undermines supply chain transparency.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1059",
        "title": "Incomplete Documentation",
        "url": "https://cwe.mitre.org/data/definitions/1059.html"
      }
    ],
    "remediation": {
      "title": "Add a recognized open source license to the repository",
      "description": "Select an appropriate OSI-approved open source license and add it as a LICENSE file in the repository root, ensuring the SPDX identifier is correctly reflected in GitHub repository settings.",
      "tasks": [
        { "title": "Select an appropriate OSI-approved license (e.g., Apache-2.0, MIT, GPL-3.0)" },
        { "title": "Add a LICENSE file to the repository root with the full license text" },
        { "title": "Ensure GitHub detects the license and displays the correct SPDX identifier" },
        { "title": "Review all dependencies for license compatibility with the chosen license" },
        { "title": "Document license requirements for contributors in CONTRIBUTING.md" }
      ]
    }
  }
]

violation[{"id": "non_compliant_license"}] if {
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

violation[{"id": "non_compliant_license"}] if {
    # spdx_id missing
    not input.settings.license.spdx_id
}
violation[{"id": "non_compliant_license"}] if {
    # spdx_id empty string
    input.settings.license.spdx_id == ""
}

title = "Repository has a valid Open Source License"
description = "All repositories must have a valid Open Source License."
remarks = "Licensing your open source software is essential to clearly communicate the terms under which others can use, modify, and distribute your code. It helps protect your rights as an author, ensures compliance with legal requirements, and fosters trust and collaboration within the open source community. A well-defined license also prevents misuse and clarifies responsibilities for contributors and users."
