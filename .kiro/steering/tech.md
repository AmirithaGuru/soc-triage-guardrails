# Tech constraints
- Region: us-east-1. Total AWS spend must stay under $10.
- Lambda: Python 3.12, standard library + boto3 only. Use urllib for the Slack webhook. No frameworks.
- Terraform with LOCAL state. Verify resource names against the current AWS provider docs.
- AI: Amazon Bedrock Converse API, Claude Haiku-tier model. Model IDs and inference-profile IDs change.
  ALWAYS look up the current ID from AWS docs or `aws bedrock list-inference-profiles --region us-east-1`.
  Never guess an ID.
- Output from the model is untrusted. Validate it in code.
- CI: GitHub Actions with OIDC to AWS. No long-lived AWS keys.
- AWS CLI uses an SSO profile. Terraform and scripts read credentials from the AWS_PROFILE environment variable.
