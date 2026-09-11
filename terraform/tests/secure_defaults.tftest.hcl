# Terraform's mock provider makes these tests entirely offline (no AWS credentials).
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
}
mock_provider "random" {}

run "secure_defaults" {
  command = plan
  assert {
    condition     = length(local.ingress_expected) == 0
    error_message = "Default demo must not allow inbound traffic."
  }
  assert {
    condition     = length(aws_security_group.demo.egress) == 0
    error_message = "Unused demo group needs no outbound traffic."
  }
  assert {
    condition     = alltrue(values(local.public_access_block))
    error_message = "All four S3 public access guards must be enabled."
  }
  assert {
    condition     = aws_s3_bucket.demo.force_destroy == false
    error_message = "Terraform must not silently delete stored user objects."
  }
  assert {
    condition     = length(aws_iam_role_policy_attachments_exclusive.demo.policy_arns) == 0
    error_message = "The demo role must have no managed policy attachments."
  }
}

run "trusted_ssh" {
  command = plan
  variables {
    trusted_admin_cidr = "203.0.113.10/32"
    allow_public_https = true
    enable_cloudtrail  = true
  }
  assert {
    condition     = length(local.ingress_expected) == 2 && local.ingress_expected[0].source == "203.0.113.10/32"
    error_message = "Optional SSH and HTTPS must match the authored contract."
  }
}

run "reject_public_admin_cidr" {
  command = plan
  variables {
    trusted_admin_cidr = "0.0.0.0/0"
  }
  expect_failures = [var.trusted_admin_cidr]
}
