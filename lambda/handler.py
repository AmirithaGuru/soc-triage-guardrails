"""handler.py — Lambda entry point.

Orchestrates the triage pipeline (version chosen by the PROMPT_VERSION env var):
    extract_fields → build_messages → triage → parse_output → apply_policy → post_success

v1 is the deliberately naive baseline. v2 adds the defences: field allowlist,
delimited prompt, Bedrock Guardrail, strict output validation, severity floor.

Fail-safe: any exception in the pipeline calls post_failure so the analyst
gets a raw-finding alert in Slack even when the AI step fails. If post_failure
itself raises (Slack is down), we log CRITICAL and re-raise — the Lambda
runtime marks the invocation failed and EventBridge's async retry policy fires,
giving another attempt to deliver the alert.

Every code path except that last-resort re-raise returns a dict.
"""

import json
import logging
import os

from bedrock_client import triage
from extract import SUPPORTED_VERSIONS, extract_fields
from policy import apply_policy
from prompts import build_messages
from slack import post_failure, post_success
from validate import parse_output

log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event: dict, context: object) -> dict:
    """Lambda entry point.

    Args:
        event:   EventBridge event dict; finding is under event["detail"].
        context: Lambda context object (unused).

    Returns:
        {"status": "ok"}        — pipeline succeeded.
        {"status": "fail_safe"} — pipeline failed, Slack escalation delivered.

    Raises:
        Exception: only when post_failure itself also raises (critical-error
                   path), so Lambda's async retry gets another attempt.
    """
    # event.get("detail", {}) — empty dict on a malformed event; the Extractor's
    # input validation raises ValueError which routes to the fail-safe.
    finding = event.get("detail", {})
    if not isinstance(finding, dict):
        # detail is not a dict (malformed event): use {} so extract_fields raises
        # ValueError and the fail-safe handles it.
        finding = {}

    log.info("RAW_FINDING_TYPE=%s", finding.get("type"))

    # Validate PROMPT_VERSION before entering the try block so the ValueError
    # is caught by _fail_safe and routed to Slack rather than crashing silently.
    prompt_version = os.environ.get("PROMPT_VERSION", "")
    if not prompt_version:
        return _fail_safe(finding, ValueError("PROMPT_VERSION env var is absent or empty"))
    if prompt_version not in SUPPORTED_VERSIONS:
        return _fail_safe(finding, ValueError(f"Unsupported PROMPT_VERSION: {prompt_version!r}"))
    log.info("PROMPT_VERSION=%s", prompt_version)

    try:
        fields = extract_fields(finding, prompt_version)
        system, messages = build_messages(fields, prompt_version)
        raw_text = triage(system, messages, prompt_version)
        parsed = parse_output(raw_text, prompt_version)
        parsed = apply_policy(parsed, finding, prompt_version)
        post_success(parsed, finding)
        log.info("PIPELINE_STATUS=ok")
        return {"status": "ok"}
    except Exception as exc:
        return _fail_safe(finding, exc)


def _fail_safe(finding: dict, exc: Exception) -> dict:
    """Attempt to deliver a raw-finding escalation to Slack.

    Returns:
        {"status": "fail_safe"} if Slack delivery succeeded.

    Raises:
        Exception: re-raises if post_failure itself fails, so Lambda's async
                   retry can try again.
    """
    log.error("PIPELINE_STATUS=fail_safe REASON=%s", type(exc).__name__)
    # The message helps debugging (the error TYPE alone hid the real cause once).
    # Newlines are removed and the length capped so it stays one log line.
    log.error("PIPELINE_ERROR_DETAIL=%s", " ".join(str(exc).split())[:300])
    try:
        post_failure(finding, exc)
        return {"status": "fail_safe"}
    except Exception as inner:
        # Both the pipeline and Slack delivery have failed.
        # Re-raise so the Lambda runtime marks this invocation failed and
        # EventBridge's async retry fires.
        log.critical("PIPELINE_STATUS=critical_error REASON=%s", type(inner).__name__)
        raise
