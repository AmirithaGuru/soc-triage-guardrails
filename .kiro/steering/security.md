# Security rules (always follow)
- Never write secrets (Slack webhook, keys, account IDs) into code, steering, specs, or fixtures.
  Secrets come from Terraform sensitive variables or environment variables.
- IAM is least privilege: no "*" actions, resources scoped to specific ARNs. Explain every permission.
- NEVER run `terraform apply`, `terraform destroy`, or any command that changes AWS without asking me first
  and showing the plan.
- Never run commands that print credentials.
- Do not add AWS services that are not in SPEC.md without asking.
- Fail safe: if Bedrock, the guardrail, or output validation fails, escalate the raw finding to a human. Never drop an alert.
