resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_vpc" "demo" {
  cidr_block           = "10.77.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = false
  tags = {
    Name = "${var.project_name}-isolated"
  }
}

# Also close the default group automatically created by AWS for this VPC.
resource "aws_default_security_group" "closed" {
  vpc_id  = aws_vpc.demo.id
  ingress = []
  egress  = []
}

locals {
  bucket_name = "${var.project_name}-${data.aws_caller_identity.current.account_id}-${random_id.suffix.hex}"
  bucket_arn  = "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name}"
  public_access_block = {
    BlockPublicAcls       = true
    IgnorePublicAcls      = true
    BlockPublicPolicy     = true
    RestrictPublicBuckets = true
  }
  bucket_policy = {
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  }
  ingress_expected = concat(
    var.trusted_admin_cidr == null ? [] : [{
      protocol    = "tcp", from_port = 22, to_port = 22,
      source_type = "ipv4", source = var.trusted_admin_cidr
    }],
    var.allow_public_https ? [{
      protocol    = "tcp", from_port = 443, to_port = 443,
      source_type = "ipv4", source = "0.0.0.0/0"
    }] : []
  )
  trust_policy = {
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Action = "sts:AssumeRole",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  }
  read_policy = {
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = [local.bucket_arn] },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["${local.bucket_arn}/reports/*"] }
    ]
  }
}
