"""errors.py — small shared exception types.

Kept in its own module so slack.py can recognise a guardrail block without
importing bedrock_client (and therefore boto3).
"""


class GuardrailIntervened(Exception):
    """The Bedrock Guardrail blocked the request (stopReason=guardrail_intervened).

    Treated as a security signal, not just an error: the handler escalates the
    raw finding to a human and the Slack message says a guardrail fired.
    """
