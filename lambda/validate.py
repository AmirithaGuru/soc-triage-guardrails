"""validate.py — model output parser.

v1: best-effort JSON parse only. We strip markdown fences the model sometimes
adds even when told not to, then confirm we got a dict. Field-level schema
enforcement (enum values, ATT&CK ID regex, severity floor) is a v2 concern.
"""

import json
import re

# Matches ```json ... ``` or ``` ... ``` with optional surrounding whitespace.
_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.DOTALL | re.IGNORECASE)


def parse_output(text: str) -> dict:
    """Parse the model's raw text response into a dict.

    Args:
        text: Raw string returned by bedrock_client.triage.

    Returns:
        Parsed dict (keys not validated in v1).

    Raises:
        ValueError: if the text cannot be parsed as a JSON object (dict).
    """
    # Strip markdown fence if present.
    match = _FENCE_RE.search(text)
    candidate = match.group(1) if match else text

    try:
        result = json.loads(candidate)
    except json.JSONDecodeError:
        raise ValueError(
            f"Model output is not valid JSON: {candidate[:200]!r}"
        )

    # json.loads can return a list, int, str, etc. — we need a dict.
    if not isinstance(result, dict):
        raise ValueError(
            f"Model output is not a JSON object: {type(result).__name__}"
        )

    return result
