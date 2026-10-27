# ──────────────────────────────────────────────────────────────────────────────
# Provider
# ──────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ──────────────────────────────────────────────────────────────────────────────
# GuardDuty detector
#
# enable = true starts the 30-day free trial the first time it's applied.
# Remember to disable the detector (or run terraform destroy) after testing
# to avoid post-trial charges.
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_guardduty_detector" "main" {
  enable = true
}

# ──────────────────────────────────────────────────────────────────────────────
# CloudWatch Log Group
#
# Lambda automatically creates /aws/lambda/<name> if the group doesn't exist,
# but creating it explicitly lets Terraform manage retention. 14 days is well
# within the free tier and keeps costs near zero.
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = 14
}

# ──────────────────────────────────────────────────────────────────────────────
# Lambda deployment package
#
# source_dir packages all six modules from lambda/ into terraform/build/lambda.zip.
# Writing the zip outside lambda/ prevents archive_file from including the zip
# inside itself on the next run.
#
# Exclusions:
#   .gitkeep       — placeholder files, not code
#   handler.zip    — stale artifact guard (file was deleted, but belt-and-suspenders)
#   __pycache__    — Python bytecode cache directories
#   *.pyc          — compiled bytecode files
#
# source_code_hash detects any change to the six source files and triggers a
# Lambda redeployment automatically on the next terraform apply.
# ──────────────────────────────────────────────────────────────────────────────

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/"
  output_path = "${path.module}/build/lambda.zip"

  excludes = [
    ".gitkeep",
    "handler.zip",
    "__pycache__",
    "**/__pycache__/**",
    "*.pyc",
  ]
}

# ──────────────────────────────────────────────────────────────────────────────
# Lambda function — full v1 triage pipeline
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_lambda_function" "triage" {
  function_name = var.project_name
  description   = "SOC triage pipeline v1 — Bedrock (Claude Haiku 4.5) + Slack."

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  runtime = "python3.12"
  handler = "handler.lambda_handler"

  role = aws_iam_role.lambda_exec.arn

  # 45s timeout: worst-case budget is sequential, not parallel.
  #   Bedrock: (connect 3s + read 8s) × 2 attempts = up to 22s
  #   Slack fail-safe: runs AFTER Bedrock fails, adds up to 10s
  #   Total worst-case: ~32s → 45s provides a safe margin.
  timeout = 45

  # 256 MB: boto3 + stdlib only, no large data. Extra memory gives proportionally
  # more CPU, reducing cold-start latency.
  memory_size = 256

  environment {
    variables = {
      # SLACK_WEBHOOK_URL is sensitive — value comes from TF_VAR_slack_webhook_url.
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      # PROMPT_VERSION is not sensitive — it mirrors the code version in prompts.py.
      PROMPT_VERSION = "v1"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy_attachment.lambda_logs,
    aws_iam_role_policy_attachment.lambda_bedrock,
  ]
}

# ──────────────────────────────────────────────────────────────────────────────
# EventBridge rule — matches every GuardDuty finding on the default bus
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project_name}-guardduty-findings"
  description = "Forward every GuardDuty finding to the triage Lambda."

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

# ──────────────────────────────────────────────────────────────────────────────
# EventBridge target — points the rule at the Lambda
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "${var.project_name}-lambda-target"
  arn       = aws_lambda_function.triage.arn
}

# ──────────────────────────────────────────────────────────────────────────────
# Lambda permission — allows EventBridge to invoke the function
#
# source_arn is scoped to the specific rule ARN (not a wildcard), so no other
# EventBridge rule can invoke this Lambda without an explicit permission.
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.triage.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}
