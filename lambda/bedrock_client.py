"""bedrock_client.py — Bedrock Converse API wrapper.

Creating the boto3 client at module level means it is reused across warm
Lambda invocations, saving ~50-100 ms per call. The handler's except block
catches any exception that propagates out of triage() and triggers the
fail-safe Slack post.
"""

import logging
import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError  # noqa: F401 — re-exported for test mocking

from errors import GuardrailIntervened

log = logging.getLogger(__name__)

# Verified 2026-10-26 via:
#   aws bedrock get-inference-profile \
#     --inference-profile-identifier us.anthropic.claude-haiku-4-5-20251001-v1:0 \
#     --region us-east-1 --profile triage
# Status: ACTIVE. Routes to us-east-1, us-east-2, us-west-2.
MODEL_ID: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

# Timeout budget (must fit inside the 45s Lambda timeout):
#   connect_timeout=3s  — fail fast if Bedrock is unreachable
#   read_timeout=8s     — covers a typical Haiku response (2-8s)
#   max_attempts=2      — one retry on transient errors
#   worst-case: (3+8) × 2 = 22s for Bedrock, then up to 10s for the Slack fail-safe
#   (the fail-safe runs only after Bedrock fails): ~32s total, inside 45s.
_CONFIG = Config(
    connect_timeout=3,
    read_timeout=8,
    retries={"max_attempts": 2, "mode": "standard"},
)

# Module-level client — reused across warm invocations.
_client = boto3.client("bedrock-runtime", region_name="us-east-1", config=_CONFIG)


def _guardrail_config(version: str) -> dict | None:
    """Return the Converse guardrailConfig for v2, or None for v1.

    v2 FAILS CLOSED: if the guardrail settings are missing we raise instead of
    quietly calling the model without a guardrail.
    """
    if version == "v1":
        return None
    if version != "v2":
        raise ValueError(f"Unknown prompt version: {version!r}")
    identifier = os.environ.get("GUARDRAIL_IDENTIFIER", "")
    guardrail_version = os.environ.get("GUARDRAIL_VERSION", "")
    if not identifier or not guardrail_version:
        raise ValueError(
            "GUARDRAIL_IDENTIFIER and GUARDRAIL_VERSION must be set for prompt version v2"
        )
    return {
        "guardrailIdentifier": identifier,
        "guardrailVersion": guardrail_version,
        "trace": "enabled",
    }


def triage(system_prompt: str, messages: list[dict], version: str = "v1") -> str:
    """Call the Bedrock Converse API and return the model's raw text response.

    Args:
        system_prompt: System turn string (from prompts.build_messages).
        messages:      User-turn messages list (from prompts.build_messages).
                       Each message's content must be a list of content-block
                       dicts e.g. [{"text": "..."}] — not a plain string.
        version:       "v1" calls the model alone; "v2" also attaches the Bedrock
                       Guardrail (prompt-attack filter on the finding data).

    Returns:
        Raw text string from the model (not yet parsed as JSON).

    Raises:
        GuardrailIntervened:     the guardrail blocked the request (v2).
        ValueError:              unexpected response shape, or v2 without
                                 guardrail settings.
        ClientError:             propagated — handler triggers fail-safe.
        EndpointResolutionError: propagated — handler triggers fail-safe.
    """
    kwargs = {
        "modelId": MODEL_ID,
        "system": [{"text": system_prompt}],
        "messages": messages,
        "inferenceConfig": {"maxTokens": 600, "temperature": 0},
    }
    guardrail = _guardrail_config(version)
    if guardrail is not None:
        kwargs["guardrailConfig"] = guardrail

    response = _client.converse(**kwargs)

    # A guardrail block still returns HTTP 200: the model never answered and the
    # "output" is just the canned blocked-message. Never treat it as a triage.
    if response.get("stopReason") == "guardrail_intervened":
        log.warning("GUARDRAIL_INTERVENED=true")
        raise GuardrailIntervened("Bedrock guardrail blocked the request")

    # Extract the text content — re-raise structural errors as ValueError so
    # the handler's generic except block routes them to the fail-safe.
    try:
        text: str = response["output"]["message"]["content"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise ValueError(f"Unexpected Bedrock response shape: {exc}") from exc

    log.info("BEDROCK_STOP_REASON=%s", response.get("stopReason"))
    return text
