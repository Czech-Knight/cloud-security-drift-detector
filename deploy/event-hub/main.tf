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
  type = string
}
variable "allowed_account_ids" {
  description = "Explicit AWS accounts permitted to forward AWS API events to the central bus."
  type        = set(string)
}

provider "aws" {
  region = var.aws_region
}

resource "aws_cloudwatch_event_bus" "drift" {
  name = "drift-security-events"
}

resource "aws_cloudwatch_event_permission" "source_accounts" {
  for_each       = var.allowed_account_ids
  principal      = each.value
  statement_id   = format("AllowAccount%s", each.value)
  action         = "events:PutEvents"
  event_bus_name = aws_cloudwatch_event_bus.drift.name
}

resource "aws_sqs_queue" "dlq" {
  name                    = "drift-security-events-dlq"
  sqs_managed_sse_enabled = true
}

resource "aws_sqs_queue" "events" {
  name                       = "drift-security-events"
  visibility_timeout_seconds = 900
  receive_wait_time_seconds  = 20
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_cloudwatch_event_rule" "writes" {
  name           = "drift-security-writes"
  event_bus_name = aws_cloudwatch_event_bus.drift.name
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    source        = ["aws.s3", "aws.ec2", "aws.iam"]
    detail = {
      eventSource = ["s3.amazonaws.com", "ec2.amazonaws.com", "iam.amazonaws.com"]
      readOnly     = [false]
    }
  })
}

data "aws_iam_policy_document" "delivery" {
  statement {
    sid       = "OnlyThisEventRuleCanDeliver"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.events.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.writes.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "delivery" {
  queue_url = aws_sqs_queue.events.id
  policy    = data.aws_iam_policy_document.delivery.json
}

resource "aws_cloudwatch_event_target" "queue" {
  event_bus_name = aws_cloudwatch_event_bus.drift.name
  rule           = aws_cloudwatch_event_rule.writes.name
  arn            = aws_sqs_queue.events.arn
}

output "event_bus_arn" {
  value = aws_cloudwatch_event_bus.drift.arn
}
output "queue_url" {
  value = aws_sqs_queue.events.url
}
output "queue_arn" {
  value = aws_sqs_queue.events.arn
}
output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}
