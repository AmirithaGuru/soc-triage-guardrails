# ──────────────────────────────────────────────────────────────────────────────
# Lambda execution role and policies — least privilege.
#
# Two policies are attached to the Lambda execution role:
#
#   lambda_logs   — CloudWatch Logs
#     • logs:CreateLogStream  – create a stream in the function's own log group
#     • logs:PutLogEvents     – write records to that stream
#     Scoped to the function's log group ARN only; no wildcards.
#
#   lambda_bedrock — Bedrock Converse (added in Spec 2)
#     • bedrock:InvokeModel on the Claude Haiku 4.5 inference-profile ARN and
#       all three underlying foundation-model ARNs (us-east-1/2, us-west-2).
#     See the lambda_bedrock resource block below for the full ARN list and
#     the reasoning for each entry.
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

# ──────────────────────────────────────────────────────────────────────────────
# Bedrock invoke policy — least privilege for Claude Haiku 4.5
#
# Four ARNs are required:
#   1. inference-profile ARN  — this is the modelId passed to converse().
#      The account ID comes from data.aws_caller_identity so it is never
#      hardcoded and this config works in any AWS account.
#   2-4. foundation-model ARNs in us-east-1, us-east-2, us-west-2 — the
#      cross-region profile resolves to one of these at runtime; IAM is
#      evaluated at the point of the actual model invocation so all three
#      must be explicitly permitted.
#
# Effect = "Allow", Action = ["bedrock:InvokeModel"] only. No wildcards.
# ──────────────────────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}

resource "aws_iam_policy" "lambda_bedrock" {
  name        = "${var.project_name}-lambda-bedrock"
  description = "Allow the Lambda to invoke Claude Haiku 4.5 via the cross-region inference profile."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBedrockInvokeHaiku45"
        Effect = "Allow"
        Action = ["bedrock:InvokeModel"]
        Resource = [
          # 1. Inference profile ARN — the modelId sent to the Converse API.
          "arn:aws:bedrock:us-east-1:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0",

          # 2. Foundation model in us-east-1 — cross-region profile routes here.
          "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",

          # 3. Foundation model in us-east-2 — cross-region profile routes here.
          "arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",

          # 4. Foundation model in us-west-2 — cross-region profile routes here.
          "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_bedrock" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_bedrock.arn
}
