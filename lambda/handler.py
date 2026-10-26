import json
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Phase 1-3 stub: log the incoming event and return ok.

    Later phases will replace this with extract → prompt → Bedrock → Slack.
    """
    log.info("EVENT=%s", json.dumps(event))
    return {"status": "ok"}
