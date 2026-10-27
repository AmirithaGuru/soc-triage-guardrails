# Requirements Document

## Introduction

This spec covers Phases 5 and 6 of the SOC Triage Guardrails project: wiring the existing Lambda stub to Amazon Bedrock (Converse API, Claude Haiku 4.5 via cross-region inference profile) and posting the AI-generated triage summary to a Slack channel via an Incoming Webhook.

This is the **v1 deliberately naive implementation**. The prompt passes the entire raw GuardDuty finding JSON to the model with no field allowlisting, no Bedrock Guardrail, and no strict output validation. That is intentional — v1 exists to prove the prompt-injection vulnerability before v2 hardens it (Spec 3). The code is structured so v2 can be layered on without rewriting v1.

The pipeline data flow is: `handler` → `extract` → `prompts` → `bedrock_client` → `validate` → `slack`, matching SPEC.md section 7.

## Glossary

- **Handler**: the `lambda/handler.py` entry point; orchestrates the full pipeline.
- **Extractor**: the `lambda/extract.py` module; in v1 it passes the raw finding through with minimal transformation.
- **Prompt_Builder**: the `lambda/prompts.py` module; contains `PROMPT_V1`, the `PROMPT_VERSION` constant, and the `build_messages` function.
- **Bedrock_Client**: the `lambda/bedrock_client.py` module; calls the Bedrock Converse API and returns the model's text response.
- **Output_Validator**: the `lambda/validate.py` module; in v1 it attempts a best-effort JSON parse and returns the raw text on failure (strict validation is a v2 concern).
- **Slack_Poster**: the `lambda/slack.py` module; sends a formatted or fallback message to the Slack Incoming Webhook using `urllib`.
- **Inference_Profile**: the cross-region Bedrock inference profile `us.anthropic.claude-haiku-4-5-20251001-v1:0`; routes requests across us-east-1, us-east-2, and us-west-2 for resilience.
- **Output_Contract**: the fixed JSON schema the model is instructed to return (summary, severity, attack_technique_id, attack_technique_name, recommended_action, suspicious_input_detected).
- **Fail_Safe**: the escalation path taken when any pipeline stage fails; posts the raw finding to Slack and marks it "AI triage failed - needs human review".
- **Lambda_Role**: the IAM execution role `soc-triage-lambda-exec` that grants the Lambda exactly the permissions it needs and nothing more.
- **Severity_Band**: one of the four allowed model output values: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

---

## Requirements

### Requirement 1: Pipeline Orchestration

**User Story:** As a SOC analyst, I want the Lambda to automatically call Bedrock and post a triage summary whenever a GuardDuty finding arrives, so that I receive a plain-English alert in Slack without reading raw JSON.

#### Acceptance Criteria

1. WHEN a GuardDuty finding event arrives at the Lambda, THE Handler SHALL read the finding as `event.get("detail", {})` and invoke the Extractor, Prompt_Builder, Bedrock_Client, Output_Validator, and Slack_Poster in that order; a missing or malformed `detail` key results in an empty dict being passed to the pipeline, which the Extractor's input validation catches and routes to the Fail_Safe.
2. WHEN all five pipeline stages complete without raising an exception, THE Handler SHALL return `{"status": "ok"}` and log `PIPELINE_STATUS=ok` at INFO level.
3. IF any pipeline stage raises an exception, THEN THE Handler SHALL log `PIPELINE_STATUS=error REASON=<exception_type>` at ERROR level and invoke the Fail_Safe path.
4. THE Handler SHALL log the raw GuardDuty finding type at INFO level before any processing begins (checkpoint: `RAW_FINDING_TYPE=<value>`).
5. THE Handler SHALL log the `PROMPT_VERSION` environment variable at INFO level before calling the Prompt_Builder.
6. IF the `PROMPT_VERSION` environment variable is absent or empty, THEN THE Handler SHALL raise a `ValueError` before invoking the Prompt_Builder, so the Fail_Safe path receives a meaningful error rather than silently using an undefined prompt version.

---

### Requirement 2: Finding Extraction (v1 pass-through)

**User Story:** As a developer, I want the Extractor to prepare the finding for the prompt, so that the code is structured for the v2 allowlist to be added in one place without touching handler logic.

#### Acceptance Criteria

1. WHEN the Handler calls `extract_fields` with a non-empty GuardDuty finding dict, THE Extractor SHALL return a dict containing the original finding dict under the key `finding_json` and its JSON serialization (using `json.dumps`) under the key `finding_json_str`.
2. IF `extract_fields` is called with a value that is not a dict, or with an empty dict, THEN THE Extractor SHALL raise a `ValueError` with a message describing the invalid input.
3. IF `json.dumps` raises a `TypeError` during serialization (e.g., the finding contains a non-serializable type), THEN THE Extractor SHALL propagate the exception unchanged so the Handler can trigger the Fail_Safe.
4. THE Extractor SHALL log `EXTRACT_VERSION=v1` at DEBUG level so future traces distinguish v1 from v2 behavior.

---

### Requirement 3: Prompt Construction (v1 naive)

**User Story:** As a developer, I want the v1 prompt to be deliberately naive — no delimiters, no restrictions — so that injection payloads in Phase 8 have a realistic attack surface to exploit.

#### Acceptance Criteria

1. THE Prompt_Builder SHALL define a module-level string constant `PROMPT_V1` containing the full system prompt text for the naive version.
2. THE Prompt_Builder SHALL define a module-level string constant `PROMPT_VERSION` whose value is `"v1"`.
3. WHEN `build_messages` is called with extracted fields and version `"v1"`, THE Prompt_Builder SHALL return a two-element tuple `(system_prompt_str, messages_list)` where `system_prompt_str` is `PROMPT_V1` and `messages_list` contains exactly one dict `{"role": "user", "content": [{"text": fields["finding_json_str"]}]}` — content must be a list of content-block dicts as required by the Bedrock Converse API; a plain string is rejected by botocore.
4. THE `PROMPT_V1` system prompt SHALL instruct the model to act as a SOC analyst, summarize the GuardDuty finding, map it to a MITRE ATT&CK technique, rate its severity as one of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`, suggest a concrete remediation action, and return **only** valid JSON matching the Output_Contract with no prose outside the JSON block.
5. THE `PROMPT_V1` system prompt SHALL NOT include any instruction to treat the finding content as untrusted data, SHALL NOT use `<finding_data>` delimiters, and SHALL NOT include a Bedrock Guardrail — these omissions are deliberate so the v1 vulnerability is reproducible.
6. IF `build_messages` is called with an unrecognized version string (e.g., `"v99"`), THEN THE Prompt_Builder SHALL raise a `ValueError` whose message includes the unrecognized version string value.

---

### Requirement 4: Bedrock Converse API Call

**User Story:** As a developer, I want a single module responsible for calling Bedrock, so that the API details and error handling are isolated and easy to swap for v2.

#### Acceptance Criteria

1. WHEN `triage` is called with a non-empty system prompt string and a non-empty messages list, THE Bedrock_Client SHALL call `bedrock_runtime.converse` with `modelId` set to `us.anthropic.claude-haiku-4-5-20251001-v1:0`, `system` set to `[{"text": system_prompt}]`, and `messages` set to the provided list.
2. THE Bedrock_Client SHALL set `inferenceConfig` to `{"maxTokens": 600, "temperature": 0}` on every call.
3. WHEN the Converse API returns successfully, THE Bedrock_Client SHALL extract the model's text from `response["output"]["message"]["content"][0]["text"]` and return it as a string; IF a `KeyError` or `IndexError` is raised during extraction, THE Bedrock_Client SHALL re-raise it as a `ValueError` so the Handler can trigger the Fail_Safe.
4. WHEN the Converse API returns successfully, THE Bedrock_Client SHALL log `BEDROCK_STOP_REASON=<response["stopReason"]>` at INFO level.
5. IF the Bedrock Converse API raises a `ClientError` or `EndpointResolutionError`, THEN THE Bedrock_Client SHALL re-raise the exception so the Handler can trigger the Fail_Safe.
6. THE Bedrock_Client SHALL use a `boto3` client for `bedrock-runtime` in region `us-east-1`; the client SHALL be created once at module import time to reuse the Lambda execution environment's connection.
7. THE Bedrock_Client SHALL configure the boto3 client with `connect_timeout=3`, `read_timeout=8`, and `retries={"max_attempts": 2, "mode": "standard"}` so that a slow or failed Bedrock call completes (including one retry) within approximately 19 seconds — leaving at least 23 seconds for the Slack fail-safe post inside the 45-second Lambda timeout.

---

### Requirement 5: Output Parsing (v1 best-effort)

**User Story:** As a developer, I want the Output_Validator to attempt a JSON parse so the Slack message is structured when possible, while still triggering the Fail_Safe on a complete parse failure.

#### Acceptance Criteria

1. WHEN `parse_output` is called with a string that contains valid JSON, THE Output_Validator SHALL return a Python dict with key-value pairs equivalent to the JSON object.
2. WHEN the model wraps the JSON in a markdown code fence matching the pattern ` ```json\n…\n``` ` (with optional surrounding whitespace), THE Output_Validator SHALL strip the fence markers and parse the inner content.
3. IF `parse_output` is called with a string from which no valid JSON can be extracted (including cases where fences are stripped but the inner content is still invalid), THEN THE Output_Validator SHALL raise a `ValueError` so the Handler triggers the Fail_Safe.
4. IF `json.loads` returns a value whose type is not `dict` (e.g., a JSON array or scalar), THEN THE Output_Validator SHALL raise a `ValueError` so the Handler triggers the Fail_Safe.
5. THE Output_Validator SHALL NOT enforce the Output_Contract field schema in v1 — that enforcement is a v2 concern. It SHALL only verify that `json.loads` succeeds and returns a dict.

---

### Requirement 6: Slack Notification

**User Story:** As a SOC analyst, I want to receive the triage result in Slack so that I can act on it without logging into AWS.

#### Acceptance Criteria

1. WHEN `post_success` is called with a parsed triage dict and the original finding, THE Slack_Poster SHALL send a single POST request to the Slack Incoming Webhook URL using `urllib.request.urlopen` with a timeout of 10 seconds.
2. THE Slack_Poster SHALL format the Slack message body as a UTF-8-encoded JSON payload that includes all five of the following fields: the GuardDuty finding type, the AI summary truncated to a maximum of 500 characters, the MITRE ATT&CK technique ID and name, the severity, and the recommended action.
3. THE Slack_Poster SHALL read the webhook URL exclusively from the `SLACK_WEBHOOK_URL` environment variable; the URL SHALL NOT appear in source code, Terraform non-sensitive variables, test fixtures, or any file tracked by git.
4. WHEN `post_failure` is called with the original finding, THE Slack_Poster SHALL send a Slack message containing the finding title, type, GuardDuty severity, and finding ID, and SHALL include the text "AI triage failed - needs human review".
5. IF the Slack webhook POST returns an HTTP status code other than 200, THEN THE Slack_Poster SHALL log the status code and response body at ERROR level and raise an `IOError` so the caller can log the delivery failure.
6. THE Slack_Poster SHALL set the `Content-Type` header to `application/json` on all requests.
7. IF the `SLACK_WEBHOOK_URL` environment variable is absent or contains an empty string when `post_success` or `post_failure` is called, THEN THE Slack_Poster SHALL raise a `ValueError` with an error message indicating the missing configuration before attempting any network request.
8. IF the triage dict passed to `post_success` is missing one or more of the required fields (finding type, AI summary, MITRE ATT&CK technique ID, MITRE ATT&CK technique name, severity, or recommended action), THEN THE Slack_Poster SHALL raise a `KeyError` with an error message indicating which field is absent, without sending any HTTP request.

---

### Requirement 7: Fail-Safe Escalation

**User Story:** As a SOC analyst, I want to be notified even when the AI pipeline fails, so that no GuardDuty finding is silently dropped.

#### Acceptance Criteria

1. WHEN any stage of the pipeline — including the Bedrock_Client invocation, response parsing, and Slack success post — raises an exception, THE Handler SHALL call `post_failure` with the original finding dict and the caught exception.
2. WHEN the Fail_Safe path is taken, THE Handler SHALL log `PIPELINE_STATUS=fail_safe REASON=<exception_type>` at ERROR level before calling `post_failure`.
3. IF `post_failure` raises an exception, THEN THE Handler SHALL log `PIPELINE_STATUS=critical_error REASON=<exception_type>` at CRITICAL level and re-raise the exception, so the Lambda runtime marks the invocation as failed and EventBridge's automatic async retry gets another chance to deliver the alert.
4. WHEN `post_failure` completes without raising an exception during the Fail_Safe path, THE Handler SHALL return `{"status": "fail_safe"}`.
5. THE Handler SHALL only propagate an exception to the Lambda runtime when `post_failure` itself fails (the critical-error path); all other execution paths SHALL end in a `return` statement with a dict value.

---

### Requirement 8: IAM Permissions for Bedrock

**User Story:** As a security-conscious developer, I want the Lambda's IAM role to allow only the exact Bedrock calls it needs, so that a compromised function cannot call unrelated models or AWS services.

#### Acceptance Criteria

1. THE Lambda_Role SHALL be granted `bedrock:InvokeModel` on the inference-profile ARN `arn:aws:bedrock:us-east-1:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0` (the account ID is obtained from Terraform's `data "aws_caller_identity" "current"` data source and must never be hardcoded).
2. THE Lambda_Role SHALL be granted `bedrock:InvokeModel` on the foundation-model ARN `arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0`.
3. THE Lambda_Role SHALL be granted `bedrock:InvokeModel` on the foundation-model ARN `arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0`.
4. THE Lambda_Role SHALL be granted `bedrock:InvokeModel` on the foundation-model ARN `arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0`.
5. THE Bedrock IAM policy statement SHALL use `Effect = "Allow"` and SHALL list only `bedrock:InvokeModel` as the permitted action, with no wildcard (`*`) in either the action or the resource field.
6. THE `iam.tf` file SHALL include an inline comment on or immediately preceding each ARN that explains why it is required: the inference-profile ARN comment SHALL state that this is the ID passed as `modelId` in the Converse API call; each foundation-model ARN comment SHALL state that the cross-region profile resolves to this underlying model ARN at runtime and that IAM must permit it explicitly.

---

### Requirement 9: Slack Webhook Configuration

**User Story:** As a developer, I want the Slack webhook URL managed securely through Terraform, so that it never appears in code, git history, or logs.

#### Acceptance Criteria

1. THE Terraform configuration SHALL declare a `sensitive = true` variable named `slack_webhook_url` whose value is a non-empty string beginning with `https://` (validated at plan time to prevent silent misconfiguration from a blank or malformed URL).
2. THE Lambda function resource SHALL pass the webhook URL to the function as the environment variable `SLACK_WEBHOOK_URL` using the Terraform variable.
3. THE `variables.tf` file SHALL NOT include a `default` value for `slack_webhook_url`; the value SHALL be supplied via `TF_VAR_slack_webhook_url` at apply time.
4. THE `.gitignore` SHALL include entries for `*.tfvars`, `*.tfvars.json`, `terraform.tfstate`, and `terraform.tfstate.backup` to prevent accidental secret commits, since Terraform state files store the webhook URL in plaintext.

---

### Requirement 10: Lambda Timeout and Memory

**User Story:** As a developer, I want the Lambda timeout to be long enough for a Bedrock API call to complete, so that the function does not time out before the model responds.

#### Acceptance Criteria

1. THE Lambda function SHALL have a timeout of 45 seconds. Worst-case budget: Bedrock connect+read × 2 attempts = up to 22 seconds, then the Slack fail-safe runs after Bedrock fails (up to 10 seconds) — total up to 32 seconds. 45 seconds provides a safe margin and remains well within EventBridge's 300-second invocation limit.
2. THE Lambda function SHALL have a memory allocation of 256 MB; the function uses only Python stdlib and boto3 with no large data structures, so the default 128 MB is sufficient, but 256 MB is set to give the Lambda more CPU proportional to memory and reduce cold-start latency.
3. THE Terraform `aws_lambda_function` resource SHALL explicitly set both `timeout` and `memory_size` attributes so the values are visible in code review rather than relying on AWS defaults.

---

### Requirement 11: Lambda Deployment Package

**User Story:** As a developer, I want all Lambda source modules packaged together, so that `handler.py` can import `extract`, `prompts`, `bedrock_client`, `validate`, and `slack` without a dependency layer.

#### Acceptance Criteria

1. THE Terraform `archive_file` data source SHALL package all six Lambda modules (`handler.py`, `extract.py`, `prompts.py`, `bedrock_client.py`, `validate.py`, `slack.py`) from the `lambda/` directory into a single zip written to `terraform/build/lambda.zip`, not inside the `lambda/` directory; `.gitkeep` files SHALL be excluded from the archive.
2. WHEN any of the six source files changes, THE Terraform `source_code_hash` attribute SHALL detect the change and trigger a Lambda redeployment on the next `terraform apply`.
3. THE `archive_file` data source SHALL use `source_dir` (not `source_file`) since the package now contains multiple modules; the `output_path` SHALL point to `terraform/build/lambda.zip` and SHALL be the same path referenced by the Lambda function resource.
4. THE `terraform/build/` directory SHALL be listed in `.gitignore` so build artifacts are never committed to the repository.

---

### Requirement 12: Unit Tests

**User Story:** As a developer, I want automated unit tests that run without AWS credentials, so that every push is validated quickly in CI.

#### Acceptance Criteria

1. THE test suite in `tests/test_unit.py` SHALL cover: `extract` pass-through behavior, `build_messages` output shape for `"v1"`, Bedrock response parsing, Output_Validator JSON stripping for markdown fences, Slack message formatting for both the success and failure paths.
2. WHEN running `python -m pytest tests/test_unit.py`, THE test suite SHALL mock all `boto3` client calls and all `urllib.request.urlopen` calls so no network or AWS access is required.
3. THE test suite SHALL assert that calling `build_messages` with an unknown version raises `ValueError`.
4. THE test suite SHALL assert that the Fail_Safe path is taken when `Bedrock_Client` raises a `ClientError`.
5. THE test suite SHALL pass with zero failures before `terraform plan` is shown.

---

### Requirement 13: Lambda PROMPT_VERSION Environment Variable

**User Story:** As a developer, I want Terraform to set `PROMPT_VERSION` on the Lambda function so the handler always has a valid prompt version without relying on manual configuration.

#### Acceptance Criteria

1. THE Terraform `aws_lambda_function` resource SHALL set the environment variable `PROMPT_VERSION = "v1"` alongside `SLACK_WEBHOOK_URL` in the `environment { variables = { … } }` block.
2. THE `PROMPT_VERSION` variable SHALL NOT be marked `sensitive` in Terraform — it is not a secret.
3. THE `PROMPT_VERSION` value `"v1"` SHALL be a plain Terraform string literal (not a Terraform variable), since it corresponds directly to the code version being deployed; when the prompt version changes, both `prompts.py` and this literal are updated together.
