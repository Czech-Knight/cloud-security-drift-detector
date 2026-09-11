# IMPORTANT: expected settings come from authored configuration, NOT refreshed
# security-group/role/bucket-policy attributes that could already contain drift.
output "security_baseline" {
  description = "Versioned detector contract. Generate a trusted baseline after apply."
  value = {
    schema_version      = 1
    aws_account_id      = data.aws_caller_identity.current.account_id
    aws_region          = var.aws_region
    terraform_workspace = terraform.workspace
    cloudtrail_enabled  = var.enable_cloudtrail
    resources = [
      {
        type = "s3", id = aws_s3_bucket.demo.id, arn = local.bucket_arn
        expected = {
          public_access_block = local.public_access_block
          policy              = local.bucket_policy
          policy_public       = false
          acl                 = [{ grantee = "$OWNER", permission = "FULL_CONTROL" }]
          ownership           = "BucketOwnerEnforced"
          encryption          = { algorithm = "AES256", kms_key_id = null, bucket_key_enabled = false }
          versioning          = "Enabled"
        }
      },
      {
        type     = "security_group", id = aws_security_group.demo.id, arn = aws_security_group.demo.arn
        expected = { ingress = local.ingress_expected, egress = [] }
      },
      {
        type = "iam_role", id = aws_iam_role.demo.name, arn = aws_iam_role.demo.arn
        expected = {
          trust_policy      = local.trust_policy
          inline_policies   = { DemoBucketRead = local.read_policy }
          attached_policies = {}
        }
      }
    ]
  }
  depends_on = [
    aws_s3_bucket_policy.demo, aws_s3_bucket_public_access_block.demo,
    aws_s3_bucket_server_side_encryption_configuration.demo,
    aws_s3_bucket_versioning.demo, aws_s3_bucket_ownership_controls.demo,
    aws_iam_role_policy.read, aws_iam_role_policies_exclusive.demo,
    aws_iam_role_policy_attachments_exclusive.demo
  ]
}

output "scanner_policy" {
  description = "Resource-scoped read-only scanner IAM policy; attach to a separate identity."
  value       = local.scanner_policy
}

output "demo_security_group_id" {
  value = aws_security_group.demo.id
}
output "demo_bucket_name" {
  value = aws_s3_bucket.demo.id
}
output "demo_role_name" {
  value = aws_iam_role.demo.name
}
output "aws_region" {
  value = var.aws_region
}
