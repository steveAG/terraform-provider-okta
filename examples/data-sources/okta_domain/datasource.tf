resource "okta_domain" "test" {
  name = "testAcc-replace_with_uuid.example.com"
}

data "okta_domain" "by-id" {
  domain_id_or_name = okta_domain.test.id
}

data "okta_domain" "by-name" {
  domain_id_or_name = "testAcc-replace_with_uuid.example.com"

  depends_on = [
    okta_domain.test
  ]
}

resource "okta_domain" "test-downcase" {
  name = "downcase-testacc-replace_with_uuid.example.com"
}

data "okta_domain" "by-id-downcase" {
  domain_id_or_name = okta_domain.test-downcase.id
}

data "okta_domain" "by-name-downcase" {
  domain_id_or_name = "downcase-testacc-replace_with_uuid.example.com"

  depends_on = [
    okta_domain.test-downcase
  ]
}
