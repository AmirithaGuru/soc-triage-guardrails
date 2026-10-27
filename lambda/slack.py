"""slack.py — Slack Incoming Webhook poster.

Uses urllib.request only — no third-party packages needed, nothing to layer
into the Lambda deployment zip. The webhook URL comes from the SLACK_WEBHOOK_URL
environment variable set by Terraform. It never appears in source code.
"""

import json
import logging
import os
from urllib import request as urlrequest

log = logging.getLogger(__name__)

_TIMEOUT_S = 10  # seconds — keeps the Lambda well within its 30 s timeout

# Required fields in the triage dict for post_success.
_REQUIRED_FIELDS = (
    "summary",
    "severity",
    "attack_technique_id",
    "attack_technique_name",
    "recommended_action",
)


def _get_webhook_url() -> str:
    """Read SLACK_WEBHOOK_URL from env; raise ValueError if absent or empty."""
    url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not url:
        raise ValueError("SLACK_WEBHOOK_URL is not configured")
    return url


def _post(url: str, body: dict) -> None:
    """POST body as UTF-8 JSON to url; raise IOError on non-200 response."""
    payload = json.dumps(body).encode("utf-8")
    req = urlrequest.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlrequest.urlopen(req, timeout=_TIMEOUT_S) as resp:
        status = resp.status
        if status != 200:
            body_text = resp.read().decode("utf-8", errors="replace")
            log.error("SLACK_STATUS=%s BODY=%s", status, body_text[:200])
            raise IOError(f"Slack webhook returned {status}")


def post_success(triage: dict, finding: dict) -> None:
    """Post an AI triage summary to Slack.

    Args:
        triage:  Parsed output-contract dict from validate.parse_output.
        finding: Original GuardDuty finding dict (for the finding type header).

    Raises:
        ValueError: if SLACK_WEBHOOK_URL is not set.
        KeyError:   if triage is missing a required field (no HTTP request made).
        IOError:    if the webhook returns a non-200 status.
    """
    url = _get_webhook_url()

    # Validate required fields before making any network request.
    for field in _REQUIRED_FIELDS:
        if field not in triage:
            raise KeyError(f"Missing required triage field: {field!r}")

    body = {
        "text": (
            f"*GuardDuty Finding: {finding.get('type', 'Unknown')}*\n"
            f"*Severity:* {triage['severity']}\n"
            # Truncate summary to 500 chars — Slack has message size limits.
            f"*Summary:* {triage['summary'][:500]}\n"
            f"*ATT\u0026CK:* {triage['attack_technique_id']} \u2014 "
            f"{triage['attack_technique_name']}\n"
            f"*Action:* {triage['recommended_action']}"
        )
    }
    _post(url, body)


def post_failure(finding: dict, exc: Exception) -> None:
    """Post a fail-safe escalation message to Slack.

    Called when any pipeline stage fails. The finding's raw metadata (title,
    type, severity, id) lets the analyst act without waiting for AI triage.

    Args:
        finding: Original GuardDuty finding dict.
        exc:     The exception that caused the fail-safe path.

    Raises:
        ValueError: if SLACK_WEBHOOK_URL is not set.
        IOError:    if the webhook returns a non-200 status.
    """
    url = _get_webhook_url()

    body = {
        "text": (
            ":rotating_light: *AI triage failed \u2014 needs human review*\n"
            f"*Finding:* {finding.get('title', 'N/A')}\n"
            f"*Type:* {finding.get('type', 'N/A')}\n"
            f"*GuardDuty Severity:* {finding.get('severity', 'N/A')}\n"
            f"*Finding ID:* {finding.get('id', 'N/A')}\n"
            f"*Error:* {type(exc).__name__}"
        )
    }
    _post(url, body)
