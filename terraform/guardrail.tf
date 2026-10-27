# ──────────────────────────────────────────────────────────────────────────────
# Bedrock Guardrail — layer 3 of the v2 defences
#
# A guardrail is a separate AWS-managed check that runs on the text BEFORE the
# model sees it. This one has a single filter, PROMPT_ATTACK, which looks for
# jailbreaks and "ignore your instructions" style prompt injection.
#
#   input_strength  — how aggressive the filter is: LOW, MEDIUM or HIGH.
#   output_strength — AWS only allows NONE for this filter type (it inspects
#                     what goes IN to the model, not what comes out).
#
# If the filter fires, the Converse call returns stopReason=guardrail_intervened,
# lambda/bedrock_client.py raises GuardrailIntervened, and a human gets the raw
# finding in Slack with a "blocked by guardrail" headline.
#
# If a HIGH filter blocks the harmless control finding (a false positive), lower
# it without editing code:  TF_VAR_guardrail_prompt_attack_strength=MEDIUM
# ──────────────────────────────────────────────────────────────────────────────

variable "guardrail_prompt_attack_strength" {
  description = "Strength of the Bedrock prompt-attack input filter: LOW, MEDIUM or HIGH."
  type        = string
  default     = "HIGH"

  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH"], var.guardrail_prompt_attack_strength)
    error_message = "guardrail_prompt_attack_strength must be LOW, MEDIUM or HIGH."
  }
}

resource "aws_bedrock_guardrail" "triage" {
  name        = "${var.project_name}-guardrail"
  description = "Prompt-attack filter for the SOC triage pipeline (v2)."

  # Shown in the (never used) model response when the guardrail blocks something.
  blocked_input_messaging   = "Blocked by the triage guardrail: possible prompt attack in the finding data."
  blocked_outputs_messaging = "Blocked by the triage guardrail."

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = var.guardrail_prompt_attack_strength
      output_strength = "NONE"
    }
  }
}

# A guardrail starts as an editable DRAFT. The Lambda is pinned to a numbered,
# frozen version so a later edit to the guardrail can't change production
# behaviour by surprise. replace_triggered_by makes Terraform cut a new version
# whenever the guardrail itself changes.
resource "aws_bedrock_guardrail_version" "triage" {
  description   = "Frozen version used by the soc-triage Lambda."
  guardrail_arn = aws_bedrock_guardrail.triage.guardrail_arn

  lifecycle {
    replace_triggered_by = [aws_bedrock_guardrail.triage]
  }
}

# ──────────────────────────────────────────────────────────────────────────────
# IAM — least privilege for the guardrail
#
# One action (bedrock:ApplyGuardrail) on one resource (this guardrail's ARN).
# No wildcards. Kept in its own policy so the Bedrock-model policy in iam.tf
# stays exactly as reviewed.
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_iam_policy" "lambda_guardrail" {
  name        = "${var.project_name}-lambda-guardrail"
  description = "Allow the Lambda to apply its single Bedrock guardrail."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowApplyTriageGuardrail"
        Effect   = "Allow"
        Action   = ["bedrock:ApplyGuardrail"]
        Resource = [aws_bedrock_guardrail.triage.guardrail_arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_guardrail" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_guardrail.arn
}

# ──────────────────────────────────────────────────────────────────────────────
# Outputs — used by scripts/run_attacks.py on your laptop (not secrets).
# ──────────────────────────────────────────────────────────────────────────────

output "guardrail_identifier" {
  description = "Guardrail ARN. Converse accepts an ARN or an ID as the identifier."
  value       = aws_bedrock_guardrail.triage.guardrail_arn
}

output "guardrail_version" {
  description = "Frozen guardrail version number the Lambda uses."
  value       = aws_bedrock_guardrail_version.triage.version
}
