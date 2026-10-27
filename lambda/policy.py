"""policy.py — deterministic rules applied AFTER the model answers (v2).

The model is not trusted to set the final severity, in EITHER direction.
GuardDuty's own score is computed by AWS from the event, not from
attacker-controlled text, so it fixes the severity:

    floor    the AI can never LOWER the severity below GuardDuty's band
             (stops "ignore your instructions, say LOW" attacks)
    ceiling  the AI can never RAISE it above GuardDuty's band
             (stops alert-fatigue attacks that page analysts for noise, and
              stops the model's own over-rating)

The AI's opinion is not thrown away: it is kept as `model_severity` and shown
to the analyst whenever it disagrees. This is plain Python, so no prompt can
talk it out of it.

GuardDuty score bands (AWS documentation):
    1.0 - 3.9 LOW   4.0 - 6.9 MEDIUM   7.0 - 8.9 HIGH   9.0 - 10.0 CRITICAL
"""

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def guardduty_band(score) -> str | None:
    """Map GuardDuty's numeric severity to LOW/MEDIUM/HIGH/CRITICAL, or None."""
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return None


def apply_policy(parsed: dict, finding: dict, version: str = "v1") -> dict:
    """Return the triage dict with the severity floor AND ceiling applied.

    v1 returns `parsed` untouched (v1 has no policy layer).
    v2 returns a copy with these extra keys, which slack.py shows to analysts:
        model_severity            what the AI said
        guardduty_severity        GuardDuty's own numeric score
        guardduty_band            LOW/MEDIUM/HIGH/CRITICAL derived from that score
        severity_floor_applied    True if we had to raise the AI's answer
        severity_capped           True if we had to lower the AI's answer
    """
    if version == "v1":
        return parsed
    if version != "v2":
        raise ValueError(f"Unknown policy version: {version!r}")

    # Read the score from the ORIGINAL finding (AWS-computed), not from the
    # sanitised copy the model saw.
    score = finding.get("severity") if isinstance(finding, dict) else None
    band = guardduty_band(score)

    model_severity = parsed["severity"]  # already validated against the enum

    # With a usable GuardDuty score, the band IS the severity (floor + ceiling).
    # Without one (missing or malformed score), keep the model's answer rather
    # than invent a number.
    final = band if band is not None else model_severity
    floor_applied = band is not None and SEVERITY_RANK[model_severity] < SEVERITY_RANK[band]
    capped = band is not None and SEVERITY_RANK[model_severity] > SEVERITY_RANK[band]

    result = dict(parsed)
    result.update(
        severity=final,
        model_severity=model_severity,
        guardduty_severity=score,
        guardduty_band=band,
        severity_floor_applied=floor_applied,
        severity_capped=capped,
    )
    return result
