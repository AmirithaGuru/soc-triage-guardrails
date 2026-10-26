# ──────────────────────────────────────────────────────────────────────────────
# Lambda execution role — least privilege for Phases 1-3.
#
# The only permissions granted now are:
#   • logs:CreateLogStream  – create a stream inside the function's log group
#   • logs:PutLogEvents     – write log records to that stream
#
# Both are scoped to the function's own log group ARN; no wildcards.
# Bedrock and SSM permissions are added in later phases.
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "lambda_exec" {
  name        = "${var.project_name}-lambda-exec"
  description = "Execution role for the SOC triage Lambda."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_logs" {
  name        = "${var.project_name}-lambda-logs"
  description = "Allow the Lambda to write to its own CloudWatch log group only."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLogStreamAndEvents"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        # Scoped to the specific log group — no wildcard on the account level.
        Resource = "${aws_cloudwatch_log_group.lambda.arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_logs.arn
}
