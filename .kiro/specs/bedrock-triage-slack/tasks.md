# Implementation Plan: Bedrock Triage → Slack (v1 Naive Pipeline)

## Overview

Wire the existing Lambda stub to Amazon Bedrock (Converse API, Claude Haiku 4.5 via
cross-region inference profile) and post AI-generated triage summaries to a Slack
channel via an Incoming Webhook. The implementation is the **v1 deliberately naive**
pipeline — no field allowlisting, no Bedrock Guardrail, and no strict output-schema
enforcement — so that the prompt-injection vulnerability can be demonstrated in Phase 8
before v2 hardens it.

The fail-safe principle underpins every task: if anything goes wrong at any stage the
raw GuardDuty finding is escalated to Slack with a "needs human review" flag. No alert
is ever silently dropped.

---

## Tasks

- [ ] 1. Update `.gitignore` with required secret-protection entries
  - Add `*.tfvars.json` if not already present (explicit companion to the existing `*.tfvars` entry).
  - Verify the file already contains `*.tfstate`, `*.tfstate.*`, and `*.tfvars`; add any that are missing.
  - Add `terraform/build/` so build artifacts (the Lambda zip) are never committed.
  - No secret values, URLs, or account IDs are written anywhere in this task.
  - _Requirements: 9.4, 11.4_

- [ ] 2. Create `lambda/extract.py` — v1 pass-through extractor
  - [ ] 2.1 Implement `extract_fields(finding: dict) -> dict`
    - Validate input: if `finding` is not a `dict`, or is an empty `dict`, raise
      `ValueError("extract_fields requires a non-empty dict")`.
    - Return `{"finding_json": finding, "finding_json_str": json.dumps(finding)}`.
    - Let any `TypeError` from `json.dumps` propagate unchanged so the handler can
      trigger the fail-safe.
    - Add `log.debug("EXTRACT_VERSION=v1")` — lets future traces distinguish v1 from v2.
    - Add type hints and a module-level docstring explaining the v1 vs v2 role.
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [ ]* 2.2 Write property test for `extract_fields`
    - **Property 2: extract_fields rejects all invalid inputs** — for any value that is
      not a non-empty dict (non-dict types, empty dict `{}`), `extract_fields` SHALL
      always raise `ValueError`.
    - **Validates: Requirements 2.2**
    - **Property 3: extract_fields output is a JSON round-trip of the input** — for any
      non-empty dict `d`, `result["finding_json"]` equals `d` and
      `json.loads(result["finding_json_str"])` equals `d`.
    - **Validates: Requirements 2.1**
    - Use `hypothesis` with `st.dictionaries(st.text(), st.text())` for valid inputs and
      `st.one_of(st.none(), st.integers(), st.text(), st.lists(st.integers()), st.just({}))`
      for invalid inputs. Minimum 100 examples (`@settings(max_examples=100)`).
    - Tag each property with `# Feature: bedrock-triage-slack, Property <N>: <text>`.

- [ ] 3. Create `lambda/prompts.py` — prompt constants and message builder
  - [ ] 3.1 Implement module-level constants and `build_messages`
    - Define `PROMPT_VERSION: str = "v1"`.
    - Define `PROMPT_V1: str` containing the full naive system prompt (instruct the
      model to act as a SOC analyst, return ONLY valid JSON matching the Output Contract,
      no prose, no markdown fences outside the JSON, severity must be one of
      `LOW|MEDIUM|HIGH|CRITICAL`, `suspicious_input_detected` must be `false`).
    - **Deliberate v1 omissions (document in a code comment):** `PROMPT_V1` contains no
      `<finding_data>` delimiters, no instruction to treat the finding as untrusted data,
      and no reference to a Bedrock Guardrail. These omissions are intentional so
      Phase 8 injection payloads have a realistic attack surface.
    - Implement `build_messages(fields: dict, version: str) -> tuple[str, list[dict]]`:
      - If `version == "v1"`: return
        `(PROMPT_V1, [{"role": "user", "content": fields["finding_json_str"]}])`.
      - Any other version string: raise
        `ValueError(f"Unknown prompt version: {version!r}")`.
    - Add type hints and module-level docstring.
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

  - [ ]* 3.2 Write property tests for `build_messages`
    - **Property 4: build_messages always raises ValueError for unrecognized versions** —
      for any string that is not `"v1"`, `build_messages(fields, version)` SHALL raise
      `ValueError`.
    - **Validates: Requirements 3.6**
    - **Property 5: build_messages v1 output shape is independent of finding content** —
      for any dict with a non-empty `finding_json_str`, the return value's first element
      is `PROMPT_V1` and the second is a list containing exactly one dict with
      `role="user"` and `content` equal to `fields["finding_json_str"]`.
    - **Validates: Requirements 3.3**
    - Use `st.text().filter(lambda s: s not in {"v1"})` for invalid versions and
      `st.text(min_size=1)` for `finding_json_str`. Minimum 100 examples.

- [ ] 4. Create `lambda/bedrock_client.py` — Bedrock Converse API wrapper
  - [ ] 4.1 Implement module-level client and `triage` function
    - Create `_client = boto3.client("bedrock-runtime", region_name="us-east-1")` at
      module level (reuses the Lambda execution environment's connection across warm
      invocations).
    - Define `MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"`.
    - Implement `triage(system_prompt: str, messages: list[dict]) -> str`:
      - Call `_client.converse(modelId=MODEL_ID, system=[{"text": system_prompt}], messages=messages, inferenceConfig={"maxTokens": 600, "temperature": 0})`.
      - Extract text from `response["output"]["message"]["content"][0]["text"]`; if
        `KeyError` or `IndexError` is raised, re-raise as
        `ValueError(f"Unexpected Bedrock response shape: {exc}")`.
      - Log `BEDROCK_STOP_REASON=<response.get("stopReason")>` at INFO.
      - Let `ClientError` and `EndpointResolutionError` propagate unchanged so the
        handler can trigger the fail-safe.
    - Add type hints and module-level docstring.
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

- [ ] 5. Create `lambda/validate.py` — best-effort output parser
  - [ ] 5.1 Implement `parse_output(text: str) -> dict`
    - Define `_FENCE_PATTERN = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.DOTALL | re.IGNORECASE)`.
    - Logic:
      1. Attempt to match `_FENCE_PATTERN`; if matched, use the captured group as the
         candidate string; otherwise use `text` as-is.
      2. Call `json.loads(candidate)`.
      3. If `json.JSONDecodeError`: raise `ValueError(f"Model output is not valid JSON: {candidate[:200]!r}")`.
      4. If the result is not a `dict`: raise `ValueError(f"Model output is not a JSON object: {type(result).__name__}")`.
      5. Return the parsed dict.
    - v1 does NOT enforce the Output Contract field schema — that is a v2 concern.
    - Add type hints and module-level docstring.
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [ ]* 5.2 Write property tests for `parse_output`
    - **Property 6: parse_output is a left-inverse of json.dumps for any dict** — for
      any dict `d`, `parse_output(json.dumps(d))` returns a dict equal to `d`; and
      `parse_output("```json\n" + json.dumps(d) + "\n```")` also returns a dict equal
      to `d`.
    - **Validates: Requirements 5.1, 5.2**
    - **Property 7: parse_output never returns a non-dict** — for any string that is
      not valid JSON or is valid JSON that does not decode to a dict, `parse_output`
      SHALL raise `ValueError`.
    - **Validates: Requirements 5.3, 5.4**
    - Use `st.dictionaries(st.text(), st.text())` for valid input and
      `st.one_of(st.lists(st.integers()), st.integers(), st.text().filter(lambda s: not _is_json_dict(s)))`
      for invalid input. Minimum 100 examples.

- [ ] 6. Create `lambda/slack.py` — Slack Incoming Webhook poster
  - [ ] 6.1 Implement `post_success(triage: dict, finding: dict) -> None`
    - Read `SLACK_WEBHOOK_URL` from `os.environ`; raise
      `ValueError("SLACK_WEBHOOK_URL is not configured")` if absent or empty — before
      any HTTP request.
    - Assert the following required fields exist in `triage`: `summary`, `severity`,
      `attack_technique_id`, `attack_technique_name`, `recommended_action`. Raise
      `KeyError(f"Missing required triage field: {field}")` for the first missing field
      — before any HTTP request.
    - Build the message body with all 5 required fields:
      - Finding type from `finding.get("type", "Unknown")`.
      - AI summary truncated to 500 characters: `triage["summary"][:500]`.
      - MITRE ATT&CK technique ID and name.
      - Severity.
      - Recommended action.
    - POST via `urllib.request.urlopen` with `Content-Type: application/json` header,
      10-second timeout, UTF-8-encoded body.
    - If HTTP status ≠ 200: log `SLACK_STATUS=<code>` at ERROR and raise
      `IOError(f"Slack webhook returned {code}")`.
    - _Requirements: 6.1, 6.2, 6.3, 6.5, 6.6, 6.7, 6.8_

  - [ ] 6.2 Implement `post_failure(finding: dict, exc: Exception) -> None`
    - Same `SLACK_WEBHOOK_URL` env var check (ValueError if absent/empty).
    - Build the escalation body including: finding title, type, GuardDuty severity,
      finding ID, error type, and the exact string `"AI triage failed - needs human review"`.
    - Same POST logic: timeout 10s, `Content-Type: application/json`, non-200 → `IOError`.
    - _Requirements: 6.4, 6.5, 6.6, 6.7_

  - [ ]* 6.3 Write property tests for `post_success` and `post_failure`
    - **Property 8: post_success message always contains all required triage fields** —
      for any valid triage dict (all 6 contract fields present) and any finding dict,
      the JSON payload POSTed SHALL contain finding type, AI summary (≤ 500 chars),
      ATT&CK ID, ATT&CK name, severity, and recommended action.
    - **Validates: Requirements 6.2**
    - **Property 9: post_success raises KeyError for any dict missing a required field** —
      for any triage dict missing at least one required field, `post_success` SHALL raise
      `KeyError` without making any HTTP request.
    - **Validates: Requirements 6.8**
    - **Property 10: post_failure message always contains finding metadata and escalation text** —
      for any finding dict with `title`, `type`, `severity`, and `id` fields, and any
      exception, the payload SHALL contain those four fields and the string
      `"AI triage failed"`.
    - **Validates: Requirements 6.4**
    - Mock `urllib.request.urlopen` and `os.environ` in all property tests. Minimum 100
      examples per property.

- [ ] 7. Update `lambda/handler.py` — replace Phase 1-3 stub with full pipeline
  - [ ] 7.1 Implement the orchestrator and fail-safe helper
    - Add imports: `os`, `extract_fields` from `extract`, `build_messages` from
      `prompts`, `triage` from `bedrock_client`, `parse_output` from `validate`,
      `post_success`/`post_failure` from `slack`.
    - `lambda_handler(event, context) -> dict`:
      1. Read `finding = event["detail"]`.
      2. Log `RAW_FINDING_TYPE=<finding.get("type")>` at INFO.
      3. Read `PROMPT_VERSION` env var; if absent or empty construct
         `ValueError("PROMPT_VERSION env var is absent or empty")` and call
         `_fail_safe(finding, exc)` directly — before the try block.
      4. Log `PROMPT_VERSION=<value>` at INFO.
      5. `try` block: call `extract_fields` → `build_messages` → `triage` →
         `parse_output` → `post_success` in order.
      6. On success: log `PIPELINE_STATUS=ok` at INFO, return `{"status": "ok"}`.
      7. `except Exception as exc`: call `_fail_safe(finding, exc)` and return its result.
    - `_fail_safe(finding, exc) -> dict`:
      1. Log `PIPELINE_STATUS=fail_safe REASON=<type(exc).__name__>` at ERROR.
      2. `try`: call `post_failure(finding, exc)` → return `{"status": "fail_safe"}`.
      3. `except Exception as inner`: log `PIPELINE_STATUS=critical_error REASON=<type(inner).__name__>` at CRITICAL → return `{"status": "critical_error"}`.
    - The handler MUST never propagate an unhandled exception to the Lambda runtime —
      every code path ends in a `return` statement.
    - Add type hints and update the module-level docstring to describe the full pipeline.
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 7.1, 7.2, 7.3, 7.4, 7.5_

  - [ ]* 7.2 Write property test for fail-safe guarantee
    - **Property 1: Fail-safe is always triggered on pipeline exceptions** — for any
      GuardDuty finding dict and any exception raised by any pipeline stage,
      `lambda_handler` SHALL always call `post_failure` and SHALL never propagate an
      unhandled exception; the return value is always a dict.
    - **Validates: Requirements 1.3, 7.1, 7.5**
    - Use `st.dictionaries(st.text(), st.text())` for finding, mock each pipeline stage
      to raise `st.from_type(Exception)`. Minimum 100 examples.

- [ ] 8. Checkpoint — ensure all Lambda modules are wired correctly
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Update `terraform/iam.tf` — add Bedrock IAM policy
  - [ ] 9.1 Add `aws_iam_policy.lambda_bedrock`
    - `Effect = "Allow"`, `Action = ["bedrock:InvokeModel"]` only — no wildcards in
      either action or resource.
    - The inference-profile ARN uses `data.aws_caller_identity.current.account_id` so it
      works in any AWS account without hardcoding. Add a `data "aws_caller_identity" "current" {}`
      block in `iam.tf` if not already present.
    - Resources list with inline comments explaining why each ARN is required:
      - `arn:aws:bedrock:us-east-1:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0`
        — comment: "This is the modelId passed to the Converse API call."
      - `arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0`
        — comment: "The cross-region profile resolves to this foundation-model ARN at runtime; IAM must permit it explicitly."
      - `arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0`
        — comment: "The cross-region profile resolves to this foundation-model ARN at runtime; IAM must permit it explicitly."
      - `arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0`
        — comment: "The cross-region profile resolves to this foundation-model ARN at runtime; IAM must permit it explicitly."
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [ ] 9.2 Add `aws_iam_role_policy_attachment.lambda_bedrock`
    - Attach `aws_iam_policy.lambda_bedrock.arn` to `aws_iam_role.lambda_exec.name`.
    - _Requirements: 8.1_

- [ ] 10. Update `terraform/variables.tf` — add Slack webhook variable
  - Add variable `slack_webhook_url`:
    - `type        = string`
    - `sensitive   = true`
    - `description` explaining it is supplied via `TF_VAR_slack_webhook_url` at apply
      time and must never be committed.
    - `validation` block: condition checks the value is non-empty and starts with
      `"https://"` — prevents silent misconfiguration from a blank or malformed URL.
    - **No `default` value** — the value must be supplied via `TF_VAR_slack_webhook_url`.
  - _Requirements: 9.1, 9.3_

- [ ] 11. Update `terraform/main.tf` — update Lambda function resource and deployment package
  - [ ] 11.1 Update `data "archive_file" "lambda_zip"`
    - Change from `source_file = ".../handler.py"` to
      `source_dir = "${path.module}/../lambda/"` so all six modules
      (`handler.py`, `extract.py`, `prompts.py`, `bedrock_client.py`, `validate.py`,
      `slack.py`) are included at the root of the zip archive.
    - Change `output_path` from inside `lambda/` to `"${path.module}/build/lambda.zip"`
      so the zip is written to `terraform/build/lambda.zip` and never nested inside
      the source directory (which would cause the zip to include itself).
    - Add `excludes = [".gitkeep"]` to the `archive_file` data source so the placeholder
      file is not included in the deployment package.
    - Create the `terraform/build/` directory (e.g. by adding a `.gitkeep` inside it
      locally) and ensure `terraform/build/` is listed in `.gitignore` (see task 1).
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [ ] 11.2 Update `aws_lambda_function "triage"`
    - Set `timeout     = 30` explicitly (not relying on AWS provider default).
    - Set `memory_size = 256` explicitly (not relying on AWS provider default).
    - Add `environment { variables = { SLACK_WEBHOOK_URL = var.slack_webhook_url, PROMPT_VERSION = "v1" } }`.
      `PROMPT_VERSION` is a plain string literal (not a Terraform variable and not sensitive).
    - Update `source_code_hash` to reference `data.archive_file.lambda_zip.output_base64sha256`
      (should already be correct; verify it matches the updated archive source).
    - Add `aws_iam_role_policy_attachment.lambda_bedrock` to the `depends_on` list.
    - Update the description string to reflect the full v1 pipeline.
    - _Requirements: 9.2, 10.1, 10.2, 10.3, 11.2, 11.3, 13.1, 13.2, 13.3_

- [ ] 12. Write `tests/test_unit.py` — full unit test suite
  - Write unit tests covering ALL of the following (mock all boto3 and urllib calls —
    no AWS credentials or network access required):

  - [ ] 12.1 Extract module tests
    - `test_extract_passthrough` — valid non-empty dict → `finding_json` and
      `finding_json_str` correct.
    - `test_extract_invalid_inputs` — parametrize over non-dict values and empty dict →
      each raises `ValueError`.
    - _Requirements: 2.1, 2.2_

  - [ ] 12.2 Prompts module tests
    - `test_build_messages_v1_shape` — returns tuple; first element is `PROMPT_V1`;
      second element is a list with one dict, `role="user"`,
      `content=fields["finding_json_str"]`.
    - `test_build_messages_unknown_version` — raises `ValueError`; message contains the
      unrecognized version string.
    - _Requirements: 3.3, 3.6_

  - [ ] 12.3 Bedrock client tests
    - `test_triage_happy_path` — mock `_client.converse` to return a well-formed
      response dict; assert `triage` returns the text string.
    - `test_triage_propagates_client_error` — mock `_client.converse` to raise
      `ClientError`; assert it propagates (is not swallowed).
    - `test_triage_malformed_response_raises_value_error` — mock response missing the
      expected keys; assert `ValueError` is raised.
    - _Requirements: 4.3, 4.5_

  - [ ] 12.4 Validate module tests
    - `test_parse_output_plain_json` — valid JSON dict string → returns dict.
    - `test_parse_output_fence_stripping` — markdown-fenced JSON → returns correct dict.
    - `test_parse_output_invalid_json` — non-JSON string → raises `ValueError`.
    - `test_parse_output_non_dict` — JSON array string → raises `ValueError`.
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [ ] 12.5 Slack module tests
    - `test_post_success_posts_correct_fields` — mock `urlopen`; assert payload
      (decoded JSON) contains finding type, summary, ATT&CK ID, ATT&CK name, severity,
      and recommended action.
    - `test_post_success_missing_field` — triage dict missing `severity` → raises
      `KeyError`; assert `urlopen` was NOT called.
    - `test_post_failure_contains_escalation_text` — mock `urlopen`; assert payload
      contains `"AI triage failed"`.
    - _Requirements: 6.2, 6.4, 6.8_

  - [ ] 12.6 Handler integration tests
    - `test_handler_ok_path` — mock all five pipeline modules to succeed → returns
      `{"status": "ok"}`.
    - `test_handler_bedrock_error_triggers_fail_safe` — mock `triage` to raise
      `ClientError`; mock `post_failure` to succeed → returns `{"status": "fail_safe"}`.
    - `test_handler_missing_prompt_version` — unset `PROMPT_VERSION` env var →
      returns `{"status": "fail_safe"}`.
    - `test_handler_critical_error` — mock `triage` to raise any exception, mock
      `post_failure` to also raise → returns `{"status": "critical_error"}`.
    - _Requirements: 1.2, 1.3, 1.6, 7.3, 7.4, 7.5, 12.1, 12.2, 12.3, 12.4_

- [ ] 13. Run unit tests — all must pass before Terraform
  - Run `python -m pytest tests/test_unit.py -v` and show the full output.
  - **All tests must pass with zero failures before proceeding.**
  - If any test fails, fix the failing code or test and re-run until all pass.
  - Do NOT proceed to task 14 (terraform validate/plan) until this task shows green.
  - _Requirements: 12.5_

- [ ] 14. Run `terraform validate` and `terraform plan`
  - First run `terraform validate` in the `terraform/` directory and confirm it exits
    clean.
  - Then run `terraform plan` (supplying `TF_VAR_slack_webhook_url` via the environment
    — never echo the value in output) and show the output verbatim, including the exact
    count of resources to be added, changed, and destroyed.
  - **STOP HERE. Do NOT run `terraform apply` automatically.**
  - Wait for explicit user approval before proceeding to task 15.
  - _Requirements: 12.5 (plan must not run while tests fail)_

- [ ] 15. Run `terraform apply` — ONLY after explicit user approval of task 14's plan
  - **This task MUST NOT be started until the user has reviewed and explicitly approved
    the `terraform plan` output from task 14.**
  - Run `terraform apply` with the same `TF_VAR_slack_webhook_url` env var (never echo
    the value).
  - Show any confirmation prompts and wait for the apply to complete.
  - Confirm the Lambda function name, IAM role, and Bedrock policy are visible in the
    Terraform output.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; all property
  tests fall into this category.
- Each task references specific requirements for traceability.
- Checkpoints ensure incremental validation before Terraform changes.
- **Secret discipline:** the Slack webhook URL (`SLACK_WEBHOOK_URL`) and any AWS account
  IDs must never appear in source code, test fixtures, Terraform non-sensitive variables,
  or any file tracked by git. They flow exclusively via `TF_VAR_slack_webhook_url` at
  apply time and `os.environ` at Lambda runtime. The inference-profile ARN in `iam.tf`
  uses `data.aws_caller_identity.current.account_id` — never a hardcoded account ID.
- Terraform `apply` (task 15) requires explicit human approval — per
  `steering/security.md`: "NEVER run `terraform apply` without asking me first and
  showing the plan."
- Property tests use [Hypothesis](https://hypothesis.readthedocs.io/) with a minimum of
  100 examples per property (`@settings(max_examples=100)`); install with
  `pip install hypothesis` before running the test suite.

---

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["2.1", "3.1", "4.1", "5.1", "6.1", "6.2"] },
    { "id": 1, "tasks": ["7.1", "2.2", "3.2", "5.2", "6.3"] },
    { "id": 2, "tasks": ["7.2", "9.1", "9.2", "10", "11.1"] },
    { "id": 3, "tasks": ["11.2", "12.1", "12.2", "12.3", "12.4", "12.5"] },
    { "id": 4, "tasks": ["12.6"] },
    { "id": 5, "tasks": ["13"] },
    { "id": 6, "tasks": ["14"] },
    { "id": 7, "tasks": ["15"] }
  ]
}
```
