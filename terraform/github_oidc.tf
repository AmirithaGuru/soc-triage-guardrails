# ──────────────────────────────────────────────────────────────────────────────
# GitHub Actions -> AWS with OIDC (no stored AWS keys)
#
# How it works, in plain words:
#   1. A GitHub Actions job asks GitHub for a short-lived signed token that says
#      "I am the workflow of repo X running on branch Y".
#   2. The job sends that token to AWS. AWS checks the signature (that is what
#      the OIDC provider below is for) and checks the conditions on the role.
#   3. If they match, AWS returns temporary credentials that expire in an hour.
#
# The role can be assumed ONLY by this repository's main branch, and it can only
# call the one Claude model and the one guardrail the attack suite needs.
# ──────────────────────────────────────────────────────────────────────────────

# GitHub now puts the numeric owner and repository IDs into the OIDC "sub"
# claim, so the identity looks like:
#   repo:<owner>@<owner-id>/<repo>@<repo-id>:ref:refs/heads/main
# Matching on the IDs (not just the names) is the safer choice: if this repo were
# ever deleted and someone else created one with the same name, it would get new
# IDs and could NOT assume this role. Find the values in the "sub" line printed
# by the workflow's debug step, or in the repository's OIDC token claims.
variable "github_oidc_repo_subject" {
  description = "Repository part of the GitHub OIDC subject: owner@ownerId/repo@repoId."
  type        = string
  default     = "AmirithaGuru@149721694/soc-triage-guardrails@1433937637"

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+@[0-9]+/[A-Za-z0-9._-]+@[0-9]+$", var.github_oidc_repo_subject))
    error_message = "Use the form owner@123/repo@456 (names with their numeric IDs)."
  }
}

# One provider per AWS account for this URL.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "ci" {
  name                 = "${var.project_name}-ci-adversarial"
  description          = "Assumed by GitHub Actions (OIDC) to run the live attack suite."
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
            # Exact match, no wildcard: only this repository (by ID) on its main branch.
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_oidc_repo_subject}:ref:refs/heads/main"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "ci_bedrock" {
  name        = "${var.project_name}-ci-bedrock"
  description = "Let CI call the triage model and guardrail, nothing else."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowInvokeHaiku45"
        Effect = "Allow"
        Action = ["bedrock:InvokeModel"]
        Resource = [
          "arn:aws:bedrock:us-east-1:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0",
          "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
          "arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
          "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
        ]
      },
      {
        Sid      = "AllowApplyTriageGuardrail"
        Effect   = "Allow"
        Action   = ["bedrock:ApplyGuardrail"]
        Resource = [aws_bedrock_guardrail.triage.guardrail_arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ci_bedrock" {
  role       = aws_iam_role.ci.name
  policy_arn = aws_iam_policy.ci_bedrock.arn
}

output "ci_role_arn" {
  description = "Role ARN for GitHub Actions. Store it as the repository variable AWS_CI_ROLE_ARN."
  value       = aws_iam_role.ci.arn
}
