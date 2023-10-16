---
page_title: "Data Source: okta_email_template"
description: |-
  Get a single Email Template for a Brand belonging to an Okta organization.
---

# Data Source: okta_email_template

Get a single Email Template for a Brand belonging to an Okta organization.

## Example Usage

```terraform
data "okta_brands" "test" {
}

data "okta_email_template" "forgot_password" {
  brand_id = tolist(data.okta_brands.test.brands)[0].id
  name     = "ForgotPassword"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `brand_id` (String) Brand ID
- `name` (String) The name of the email template

### Read-Only

- `id` (String) The ID of this resource.
- `links` (String) Link relations for this object - JSON HAL - Discoverable resources related to the email template

