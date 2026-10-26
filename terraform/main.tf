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
# archive_file packages handler.py into a zip at plan time. Terraform detects
# changes to the source file via the output_file_md5 attribute, so it will
# automatically redeploy when the code changes.
# ──────────────────────────────────────────────────────────────────────────────

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/handler.py"
  output_path = "${path.module}/../lambda/handler.zip"
}

# ──────────────────────────────────────────────────────────────────────────────
# Lambda function
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_lambda_function" "triage" {
  function_name = var.project_name
  description   = "SOC triage pipeline — Phase 1-3 stub (logs event only)."

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  runtime = "python3.12"
  handler = "handler.lambda_handler"

  role = aws_iam_role.lambda_exec.arn

  # The log group is created above, so Lambda will use it rather than
  # auto-creating one without a retention policy.
  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy_attachment.lambda_logs,
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
