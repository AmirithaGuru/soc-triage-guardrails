"""extract.py — finding extraction layer.

v1: deliberate pass-through. Returns the full raw finding so the naive prompt has
access to every field (and therefore every injection surface).

v2: ALLOWLIST + SANITISER. Only fields named in _ALLOWLIST reach the model. Every
other field is dropped, including the free-text ones that outsiders can write:
EC2 tag values, user-agent strings, and network-owner (organisation / ISP) names.
Allowed strings are also cleaned and length-capped, so a payload has little room.
"""

import json
import logging
import re

log = logging.getLogger(__name__)

SUPPORTED_VERSIONS = ("v1", "v2")

# Allowlist: a dict means "look inside"; an int means "keep this value; if it is
# a string, cut it to at most that many characters". Anything not listed is
# dropped. Lists are never kept (tags live in lists, which is intentional).
_ALLOWLIST = {
    "type": 100,
    "title": 300,
    "description": 500,
    "severity": 0,          # number; 0 = no string limit needed
    "id": 64,
    "region": 32,
    "createdAt": 40,
    "updatedAt": 40,
    "resource": {
        "resourceType": 50,
        "instanceDetails": {"instanceId": 32, "instanceType": 32},
        # IAM user names are limited to 64 characters by AWS itself.
        "accessKeyDetails": {"userType": 32, "userName": 64},
    },
    "service": {
        "serviceName": 32,
        "count": 0,
        "eventFirstSeen": 40,
        "eventLastSeen": 40,
        "action": {
            "actionType": 40,
            "awsApiCallAction": {
                "api": 64,
                "serviceName": 64,
                "callerType": 32,
                "remoteIpDetails": {
                    "ipAddressV4": 45,
                    "country": {"countryName": 64},
                    # asn is a number-like id; the free-text org / isp / asnOrg
                    # names are deliberately NOT allowed.
                    "organization": {"asn": 16},
                },
            },
            "networkConnectionAction": {
                "connectionDirection": 16,
                "protocol": 16,
                "blocked": 0,
                "remoteIpDetails": {
                    "ipAddressV4": 45,
                    "country": {"countryName": 64},
                    "organization": {"asn": 16},
                },
                "localPortDetails": {"port": 0, "portName": 32},
                "remotePortDetails": {"port": 0, "portName": 32},
            },
            "portProbeAction": {"blocked": 0},
        },
    },
}

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_ANGLE_BRACKETS = re.compile(r"[<>]")
_SPACES = re.compile(r"\s+")


def _clean_string(value: str, limit: int) -> str:
    """Remove control chars and < >, collapse whitespace, cut to `limit`.

    Removing < and > means a value can never fake a closing </finding_data> tag
    or carry Slack markup such as <!channel> or <https://...|link>.
    """
    value = _CONTROL_CHARS.sub(" ", value)
    value = _ANGLE_BRACKETS.sub(" ", value)
    value = _SPACES.sub(" ", value).strip()
    return value[:limit] if limit else value


def _filter(node, allow):
    """Copy only the allowed parts of `node`. Returns a dict (maybe empty)."""
    out = {}
    if not isinstance(node, dict):
        return out
    for key, rule in allow.items():
        if key not in node:
            continue
        value = node[key]
        if isinstance(rule, dict):
            inner = _filter(value, rule)
            if inner:
                out[key] = inner
        elif isinstance(value, str):
            out[key] = _clean_string(value, rule)
        elif isinstance(value, (int, float)):   # bool is an int subclass: kept
            out[key] = value
        # lists, nulls and nested objects where a scalar is expected: dropped
    return out


def extract_fields(finding: dict, version: str = "v1") -> dict:
    """Return the finding for the prompt.

    Args:
        finding: GuardDuty finding dict from event["detail"].
        version: "v1" (pass-through) or "v2" (allowlist + sanitiser).

    Returns:
        {"finding_json": <dict>, "finding_json_str": <JSON string for the prompt>}

    Raises:
        ValueError: if finding is not a non-empty dict, the version is unknown,
                    or (v2) nothing survives the allowlist.
        TypeError:  from json.dumps on a non-serialisable value (handler catches).
    """
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unknown extract version: {version!r}")
    if not isinstance(finding, dict) or not finding:
        raise ValueError(
            f"extract_fields requires a non-empty dict, got {type(finding).__name__}"
        )

    if version == "v1":
        # v1: pass through everything, so the full injection surface is exposed.
        log.debug("EXTRACT_VERSION=v1")
        return {
            "finding_json": finding,
            "finding_json_str": json.dumps(finding),  # TypeError propagates
        }

    clean = _filter(finding, _ALLOWLIST)
    if not clean:
        raise ValueError("No allowlisted fields found in the finding")
    log.info("EXTRACT_VERSION=v2 KEPT_TOP_LEVEL_KEYS=%d", len(clean))
    return {
        "finding_json": clean,
        "finding_json_str": json.dumps(clean, sort_keys=True),
    }
