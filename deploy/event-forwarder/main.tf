terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100.0"
    }
  }
}

variable "aws_region" {
  description = "Deploy per source-account region; IAM global events commonly appear in us-east-1."
  type        = string
}
variable "central_event_bus_arn" {
  type = string
}

provider "aws" {
  region = var.aws_region
}

resource "aws_iam_role" "forwarder" {
  name = "drift-eventbridge-forwarder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "forwarder" {
  role = aws_iam_role.forwarder.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = var.central_event_bus_arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "writes" {
  name = "forward-drift-security-writes"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    source        = ["aws.s3", "aws.ec2", "aws.iam"]
    detail = {
      eventSource = ["s3.amazonaws.com", "ec2.amazonaws.com", "iam.amazonaws.com"]
      readOnly    = [false]
    }
  })
}

resource "aws_cloudwatch_event_target" "central_bus" {
  rule     = aws_cloudwatch_event_rule.writes.name
  arn      = var.central_event_bus_arn
  role_arn = aws_iam_role.forwarder.arn
}
