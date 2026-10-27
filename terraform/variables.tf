variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short name used to prefix resource names."
  type        = string
  default     = "soc-triage"
}

variable "slack_webhook_url" {
  description = "Slack Incoming Webhook URL. Supply via TF_VAR_slack_webhook_url at apply time. Never commit this value."
  type        = string
  sensitive   = true

  # Catch blank or non-HTTPS values before any resource is created.
  validation {
    condition     = length(var.slack_webhook_url) > 0 && startswith(var.slack_webhook_url, "https://")
    error_message = "slack_webhook_url must be a non-empty HTTPS URL."
  }
}
