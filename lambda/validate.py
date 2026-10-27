"""validate.py — model output parser.

v1: best-effort JSON parse only. We strip markdown fences the model sometimes
adds even when told not to, then confirm we got a dict.

v2: STRICT contract on top of that. Anything off-contract raises ValueError and
the handler escalates the raw finding to a human instead of posting the answer.
  - exactly the six expected keys (extra keys are a warning sign, so rejected)
  - severity is exactly LOW / MEDIUM / HIGH / CRITICAL
  - ATT&CK id looks like T1234 or T1234.001
  - suspicious_input_detected is a real boolean
  - text fields are non-empty strings within length limits
Error messages name the field but never repeat the model's text.
"""

import json
import re

# Matches ```json ... ``` or ``` ... ``` with optional surrounding whitespace.
_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.DOTALL | re.IGNORECASE)

_V2_KEYS = frozenset({
    "summary", "severity", "attack_technique_id", "attack_technique_name",
    "recommended_action", "suspicious_input_detected",
})
_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_MAX_LEN = {
    "summary": 700,
    "attack_technique_name": 100,
    "recommended_action": 500,
}


def parse_output(text: str, version: str = "v1") -> dict:
    """Parse the model's raw text response into a dict.

    Args:
        text:    Raw string returned by bedrock_client.triage.
        version: "v1" (parse only) or "v2" (parse + strict contract).

    Returns:
        Parsed dict.

    Raises:
        ValueError: if the text is not a JSON object, or (v2) breaks the contract.
    """
    if version not in ("v1", "v2"):
        raise ValueError(f"Unknown validate version: {version!r}")

    # Strip markdown fence if present.
    match = _FENCE_RE.search(text)
    candidate = match.group(1) if match else text

    try:
        result = json.loads(candidate)
    except json.JSONDecodeError:
        if version == "v2":
            # v2 never echoes model text into errors (they end up in logs).
            raise ValueError("Model output is not valid JSON")
        raise ValueError(
            f"Model output is not valid JSON: {candidate[:200]!r}"
        )

    # json.loads can return a list, int, str, etc. — we need a dict.
    if not isinstance(result, dict):
        raise ValueError(
            f"Model output is not a JSON object: {type(result).__name__}"
        )

    if version == "v2":
        _check_contract(result)
    return result


def _check_contract(result: dict) -> None:
    keys = set(result)
    if keys != _V2_KEYS:
        missing = sorted(_V2_KEYS - keys)
        extra = sorted(keys - _V2_KEYS)
        raise ValueError(f"Output contract violated: missing={missing} extra={extra}")

    for field in ("summary", "attack_technique_name", "recommended_action"):
        value = result[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Output contract violated: {field} must be a non-empty string")
        if len(value) > _MAX_LEN[field]:
            raise ValueError(f"Output contract violated: {field} is too long")

    if result["severity"] not in _SEVERITIES:
        raise ValueError("Output contract violated: severity is not an allowed value")

    attack_id = result["attack_technique_id"]
    if not isinstance(attack_id, str) or not _ATTACK_ID_RE.match(attack_id):
        raise ValueError("Output contract violated: attack_technique_id is not a valid ATT&CK id")

    if not isinstance(result["suspicious_input_detected"], bool):
        raise ValueError("Output contract violated: suspicious_input_detected must be true or false")
