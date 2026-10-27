"""slack.py — Slack Incoming Webhook poster.

Uses urllib.request only — no third-party packages needed, nothing to layer
into the Lambda deployment zip. The webhook URL comes from the SLACK_WEBHOOK_URL
environment variable set by Terraform. It never appears in source code.

Output handling (v2 defence): text that came from the model or from a finding is
passed through _clean() before it goes into Slack, so it cannot become a channel
@mention, a clickable link, or other Slack markup.
"""

import json
import logging
import os
import re
from urllib import request as urlrequest
from urllib.error import URLError  # noqa: F401 — kept for callers/tests

from errors import GuardrailIntervened

log = logging.getLogger(__name__)

_TIMEOUT_S = 10  # seconds — the fail-safe post must fit inside the Lambda timeout

# Required fields in the triage dict for post_success.
_REQUIRED_FIELDS = (
    "summary",
    "severity",
    "attack_technique_id",
    "attack_technique_name",
    "recommended_action",
)

_URL_SCHEME = re.compile(r"\b(https?)://", re.IGNORECASE)


def _clean(value) -> str:
    """Make text safe to show in Slack.

    1. Escape & < > exactly as Slack documents, so <!channel>, <@U123> and
       <https://x|label> are shown as plain characters and never act as markup.
    2. "Defang" web addresses (https:// -> hxxps://). Slack turns bare URLs into
       clickable links, and an analyst should never be one click from an
       attacker-chosen page. Defanging is standard practice in SOC reports.
    """
    text = str(value)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # "http" -> "hxxp", "https" -> "hxxps" (keeps the last letters, lower-cased).
    return _URL_SCHEME.sub(lambda m: "hxx" + m.group(1).lower()[3:] + "://", text)


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


def _notes(triage: dict) -> str:
    """Warning lines for analysts (v2 only; v1 dicts have none of these keys)."""
    lines = []
    if triage.get("suspicious_input_detected") is True:
        lines.append(
            ":warning: *Possible prompt injection:* the finding contains text that "
            "tries to instruct the reader. Verify manually.\n"
        )
    if triage.get("severity_floor_applied"):
        lines.append(
            f":arrow_up: AI rated this *{_clean(triage.get('model_severity'))}*, but "
            f"GuardDuty's score requires at least *{_clean(triage.get('guardduty_band'))}*. "
            "Severity raised automatically.\n"
        )
    if triage.get("severity_capped"):
        lines.append(
            f":arrow_down: AI rated this *{_clean(triage.get('model_severity'))}*, but "
            f"GuardDuty's score caps it at *{_clean(triage.get('guardduty_band'))}*. "
            "Severity held at GuardDuty's level; check the evidence.\n"
        )
    return "".join(lines)


def post_success(triage: dict, finding: dict) -> None:
    """Post an AI triage summary to Slack.

    Args:
        triage:  Parsed output-contract dict (after policy.apply_policy in v2).
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

    score = triage.get("guardduty_severity")
    severity_line = f"*Severity:* {_clean(triage['severity'])}"
    if score is not None:
        severity_line += f" _(GuardDuty score {_clean(score)})_"

    body = {
        "text": (
            f"*GuardDuty Finding: {_clean(finding.get('type', 'Unknown'))}*\n"
            f"{severity_line}\n"
            f"{_notes(triage)}"
            # Truncate summary to 500 chars — Slack has message size limits.
            f"*Summary:* {_clean(str(triage['summary'])[:500])}\n"
            f"*ATT&CK:* {_clean(triage['attack_technique_id'])} — "
            f"{_clean(triage['attack_technique_name'])}\n"
            f"*Action:* {_clean(triage['recommended_action'])}"
        )
    }
    _post(url, body)


def post_failure(finding: dict, exc: Exception) -> None:
    """Post a fail-safe escalation message to Slack.

    Called when any pipeline stage fails. The finding's raw metadata (title,
    type, severity, id) lets the analyst act without waiting for AI triage.
    A guardrail block gets its own headline because it is a security signal.

    Args:
        finding: Original GuardDuty finding dict.
        exc:     The exception that caused the fail-safe path.

    Raises:
        ValueError: if SLACK_WEBHOOK_URL is not set.
        IOError:    if the webhook returns a non-200 status.
    """
    url = _get_webhook_url()

    if isinstance(exc, GuardrailIntervened):
        headline = (
            ":shield: *AI triage blocked by guardrail — possible prompt injection "
            "— needs human review*\n"
        )
    else:
        headline = ":rotating_light: *AI triage failed — needs human review*\n"

    body = {
        "text": (
            f"{headline}"
            f"*Finding:* {_clean(finding.get('title', 'N/A'))}\n"
            f"*Type:* {_clean(finding.get('type', 'N/A'))}\n"
            f"*GuardDuty Severity:* {_clean(finding.get('severity', 'N/A'))}\n"
            f"*Finding ID:* {_clean(finding.get('id', 'N/A'))}\n"
            f"*Error:* {type(exc).__name__}"
        )
    }
    _post(url, body)
