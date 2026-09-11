# This JSON is an output, not a grant to the monitored demo role.
# Attach it to a SEPARATE scanner role/profile. No AWS write actions.
locals {
  scanner_policy = {
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "InspectDemoBucket"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketAcl", "s3:GetEncryptionConfiguration", "s3:GetBucketVersioning",
          "s3:GetBucketOwnershipControls"
        ]
        Resource = local.bucket_arn
      },
      {
        Sid       = "InspectSecurityGroups", Effect = "Allow",
        Action    = ["ec2:DescribeSecurityGroups"], Resource = "*",
        Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } }
      },
      {
        Sid      = "InspectDemoRole", Effect = "Allow",
        Action   = ["iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy"],
        Resource = aws_iam_role.demo.arn
      },
      {
        Sid    = "ReadAnyAttachedPolicyVersion", Effect = "Allow",
        Action = ["iam:GetPolicy", "iam:GetPolicyVersion"],
        Resource = [
          "arn:${data.aws_partition.current.partition}:iam::aws:policy/*",
          "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:policy/*"
        ]
      }
      ], var.enable_cloudtrail ? [{
        Sid    = "OptionalRecentActivity", Effect = "Allow",
        Action = ["cloudtrail:LookupEvents"], Resource = "*"
    }] : [])
  }
}
