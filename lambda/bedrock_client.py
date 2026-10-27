"""bedrock_client.py — Bedrock Converse API wrapper.

Creating the boto3 client at module level means it is reused across warm
Lambda invocations, saving ~50-100 ms per call. The handler's except block
catches any exception that propagates out of triage() and triggers the
fail-safe Slack post.
"""

import logging

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError  # noqa: F401 — re-exported for test mocking

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
#   worst-case: (3+8) × 2 = 22s for Bedrock;
#   Slack fail-safe runs AFTER Bedrock fails, adding up to 10s → ~32s total,
#   leaving ≥13s margin inside the 45s Lambda timeout
_CONFIG = Config(
    connect_timeout=3,
    read_timeout=8,
    retries={"max_attempts": 2, "mode": "standard"},
)

# Module-level client — reused across warm invocations.
_client = boto3.client("bedrock-runtime", region_name="us-east-1", config=_CONFIG)


def triage(system_prompt: str, messages: list[dict]) -> str:
    """Call the Bedrock Converse API and return the model's raw text response.

    Args:
        system_prompt: System turn string (from prompts.build_messages).
        messages:      User-turn messages list (from prompts.build_messages).
                       Each message's content must be a list of content-block
                       dicts e.g. [{"text": "..."}] — not a plain string.

    Returns:
        Raw text string from the model (not yet parsed as JSON).

    Raises:
        ValueError:              if the response shape is unexpected.
        ClientError:             propagated — handler triggers fail-safe.
        EndpointResolutionError: propagated — handler triggers fail-safe.
    """
    response = _client.converse(
        modelId=MODEL_ID,
        system=[{"text": system_prompt}],
        messages=messages,
        inferenceConfig={"maxTokens": 600, "temperature": 0},
    )

    # Extract the text content — re-raise structural errors as ValueError so
    # the handler's generic except block routes them to the fail-safe.
    try:
        text: str = response["output"]["message"]["content"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise ValueError(f"Unexpected Bedrock response shape: {exc}") from exc

    log.info("BEDROCK_STOP_REASON=%s", response.get("stopReason"))
    return text
