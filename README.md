# Template for policies for use in the Github Settings plugin

## Testing


```shell
opa test policies
```

## Bundling

Policies are built into bundle to make distribution easier. 

You can easily build the policies by running 
```shell
make build
```

## Running policies locally

```shell
cat example-data/testorg-unremediated.json | opa eval -I -b policies -f pretty data.compliance_framework
```

## Writing policies.

Policies are written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.

```rego
package compliance-framework.mfa_enabled

violation[] {
	input.organization.two_factor_requirement_enabled == false
}

title := "Two Factor Authentication is required at an organization level"
description := "Two factor authentication should be enabled and enforced for all users within the Github Organization to make it harder for malicious actors to gain access to the organizations settings and repositories & settings"
remarks := "More information from Github can be found here: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization"

controls := [
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.5", 
        "statement-ids": [
            "4.e",
            "f.1.a",
        ]
    },
]
```

## Metadata

Plugins expect policies to contain a metadata section as comments, with a `# METADATA` line to indicate it. This metadata should be in a YAML format, and contain a title and description of the policy. Other configuration can be set also, like the schedule that a policy should run on, or the control that it is linked to.

Any other comments can be added as normal (before and after) with a line separator between them and the metadata.

Here is an example metadata:
```opa
# your custom comment

# METADATA
# title: <your-title>
# description: <your-description>
# custom:
#   controls:
#     - <control-id>
#   schedule: "<cron-string>"

# your custom comment
```