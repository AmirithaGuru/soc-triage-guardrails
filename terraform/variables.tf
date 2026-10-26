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
