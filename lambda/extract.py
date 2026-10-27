"""extract.py — finding extraction layer.

v1: deliberate pass-through. Returns the full raw finding so the naive prompt
has access to every field (and therefore every injection surface). v2 will
replace this with an allowlist + sanitiser without touching handler.py.
"""

import json
import logging

log = logging.getLogger(__name__)


def extract_fields(finding: dict) -> dict:
    """Return a dict with the raw finding and its JSON serialisation.

    Args:
        finding: GuardDuty finding dict from event["detail"].

    Returns:
        {
            "finding_json":     finding,           # original dict
            "finding_json_str": json.dumps(finding) # ready for the prompt
        }

    Raises:
        ValueError: if finding is not a non-empty dict.
        TypeError:  propagated from json.dumps if the dict contains a
                    non-serialisable type (handler catches it → fail-safe).
    """
    if not isinstance(finding, dict) or not finding:
        raise ValueError(
            f"extract_fields requires a non-empty dict, got {type(finding).__name__}"
        )

    # v1: pass through everything — no allowlist, no sanitisation.
    # WHY: we want the full injection surface exposed so Phase 8 attacks work.
    log.debug("EXTRACT_VERSION=v1")

    return {
        "finding_json": finding,
        "finding_json_str": json.dumps(finding),  # TypeError propagates to handler
    }
