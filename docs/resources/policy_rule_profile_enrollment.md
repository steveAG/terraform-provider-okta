---
page_title: "Resource: okta_policy_rule_profile_enrollment"
description: |-
  Creates a Profile Enrollment Policy Rule.
  ~> WARNING: This feature is only available as a part of the Identity Engine. Contact support mailto:dev-inquiries@okta.com for further information.
  A profile enrollment
  policy https://developer.okta.com/docs/reference/api/policy/#profile-enrollment-policy
  is limited to one default rule. This resource does not create a rule for an
  enrollment policy, it allows the default policy rule to be updated.
---

# Resource: okta_policy_rule_profile_enrollment

Creates a Profile Enrollment Policy Rule.
		
~> **WARNING:** This feature is only available as a part of the Identity Engine. [Contact support](mailto:dev-inquiries@okta.com) for further information.
A [profile enrollment
policy](https://developer.okta.com/docs/reference/api/policy/#profile-enrollment-policy)
is limited to one default rule. This resource does not create a rule for an
enrollment policy, it allows the default policy rule to be updated.

## Example Usage

```terraform
resource "okta_policy_profile_enrollment" "example" {
  name = "My Enrollment Policy"
}

resource "okta_inline_hook" "example" {
  name    = "My Inline Hook"
  status  = "ACTIVE"
  type    = "com.okta.user.pre-registration"
  version = "1.0.3"

  channel = {
    type    = "HTTP"
    version = "1.0.0"
    uri     = "https://example.com/test2"
    method  = "POST"
  }
}

resource "okta_group" "example" {
  name        = "My Group"
  description = "Group of some users"
}

resource "okta_policy_rule_profile_enrollment" "example" {
  policy_id           = okta_policy_profile_enrollment.example.id
  inline_hook_id      = okta_inline_hook.example.id
  target_group_id     = okta_group.example.id
  unknown_user_action = "REGISTER"
  email_verification  = true
  access              = "ALLOW"
  profile_attributes {
    name     = "email"
    label    = "Email"
    required = true
  }
  profile_attributes {
    name     = "name"
    label    = "Name"
    required = true
  }
  profile_attributes {
    name     = "t-shirt"
    label    = "T-Shirt Size"
    required = false
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `policy_id` (String) ID of the policy
- `unknown_user_action` (String) Which action should be taken if this User is new. Valid values are: `DENY`, `REGISTER`

### Optional

- `access` (String) Allow or deny access based on the rule conditions. Valid values are: `ALLOW`, `DENY`. Default: `ALLOW`.
- `email_verification` (Boolean) Indicates whether email verification should occur before access is granted. Default: `true`.
- `enroll_authenticator_types` (Set of String) Enrolls authenticator types
- `inline_hook_id` (String) ID of a Registration Inline Hook
- `profile_attributes` (Block List) A list of attributes to prompt the user during registration or progressive profiling. Where defined on the User schema, these attributes are persisted in the User profile. Non-schema attributes may also be added, which aren't persisted to the User's profile, but are included in requests to the registration inline hook. A maximum of 10 Profile properties is supported.
	- 'label' - (Required) A display-friendly label for this property
	- 'name' - (Required) The name of a User Profile property
	- 'required' - (Required) Indicates if this property is required for enrollment. Default is 'false'. (see [below for nested schema](#nestedblock--profile_attributes))
- `progressive_profiling_action` (String) Enabled or disabled progressive profiling action rule conditions: `ENABLED` or `DISABLED`. Default: `DISABLED`
- `target_group_id` (String) The ID of a Group that this User should be added to
- `ui_schema_id` (String) Value created by the backend. If present all policy updates must include this attribute/value.

### Read-Only

- `id` (String) The ID of this resource.
- `name` (String) Name of the rule
- `status` (String) Status of the rule

<a id="nestedblock--profile_attributes"></a>
### Nested Schema for `profile_attributes`

Required:

- `label` (String) A display-friendly label for this property
- `name` (String) The name of a User Profile property

Optional:

- `required` (Boolean) Indicates if this property is required for enrollment

## Import

Import is supported using the following syntax:

```shell
terraform import okta_policy_rule_profile_enrollment.example <policy_id>/<rule_id>
```
