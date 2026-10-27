"""test_unit.py — unit tests for the v1 triage pipeline.

All boto3 and urllib calls are mocked — no AWS credentials or network access
required. Run with:  python -m pytest tests/test_unit.py -v
"""

import json
import os
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

# conftest.py adds lambda/ to sys.path so these are plain imports.
import bedrock_client
import extract
import handler
import prompts
import slack
import validate


# ── Helpers ──────────────────────────────────────────────────────────────────

SAMPLE_FINDING = {
    "type": "UnauthorizedAccess:EC2/SSHBruteForce",
    "severity": 5.0,
    "title": "SSH brute-force attack",
    "id": "abc-123",
    "region": "us-east-1",
}

VALID_TRIAGE = {
    "summary": "An EC2 instance is being brute-forced over SSH.",
    "severity": "MEDIUM",
    "attack_technique_id": "T1110",
    "attack_technique_name": "Brute Force",
    "recommended_action": "Block the source IP in the security group.",
    "suspicious_input_detected": False,
}


# ── Task 12.1: extract module ─────────────────────────────────────────────────

class TestExtract:
    def test_extract_passthrough(self):
        result = extract.extract_fields(SAMPLE_FINDING)
        assert result["finding_json"] is SAMPLE_FINDING
        assert json.loads(result["finding_json_str"]) == SAMPLE_FINDING

    @pytest.mark.parametrize("bad", [
        None, 42, "string", [], {}, b"bytes",
    ])
    def test_extract_invalid_inputs(self, bad):
        with pytest.raises(ValueError):
            extract.extract_fields(bad)


# ── Task 12.2: prompts module ─────────────────────────────────────────────────

class TestPrompts:
    def test_build_messages_v1_shape(self):
        fields = extract.extract_fields(SAMPLE_FINDING)
        system, messages = prompts.build_messages(fields, "v1")
        assert system is prompts.PROMPT_V1
        assert len(messages) == 1
        msg = messages[0]
        assert msg["role"] == "user"
        # content must be a list of content-block dicts, not a plain string
        assert isinstance(msg["content"], list)
        assert msg["content"] == [{"text": fields["finding_json_str"]}]

    def test_build_messages_unknown_version(self):
        fields = extract.extract_fields(SAMPLE_FINDING)
        with pytest.raises(ValueError, match="v99"):
            prompts.build_messages(fields, "v99")


# ── Task 12.3: bedrock_client module ─────────────────────────────────────────

class TestBedrockClient:
    # Minimal valid Converse response shape
    _VALID_RESPONSE = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": json.dumps(VALID_TRIAGE)}],
            }
        },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 100, "outputTokens": 50, "totalTokens": 150},
        "metrics": {"latencyMs": 1234},
    }

    def test_triage_happy_path(self):
        with patch.object(bedrock_client._client, "converse",
                          return_value=self._VALID_RESPONSE):
            result = bedrock_client.triage("system", [{"role": "user", "content": [{"text": "hi"}]}])
        assert result == json.dumps(VALID_TRIAGE)

    def test_triage_propagates_client_error(self):
        err = ClientError({"Error": {"Code": "ThrottlingException", "Message": "rate"}}, "converse")
        with patch.object(bedrock_client._client, "converse", side_effect=err):
            with pytest.raises(ClientError):
                bedrock_client.triage("system", [{"role": "user", "content": [{"text": "hi"}]}])

    def test_triage_malformed_response_raises_value_error(self):
        bad = {"output": {}}   # missing message → KeyError → ValueError
        with patch.object(bedrock_client._client, "converse", return_value=bad):
            with pytest.raises(ValueError, match="Unexpected Bedrock response shape"):
                bedrock_client.triage("system", [{"role": "user", "content": [{"text": "hi"}]}])

    def test_triage_request_is_valid_for_converse(self):
        """Stubber validates the full request shape offline.

        A plain MagicMock accepts any arguments; botocore.stub.Stubber
        actually validates the request against the service model, so it
        catches wrong content-block formats (e.g. a plain string instead
        of [{"text": "..."}]) before any network call.
        """
        fields = extract.extract_fields(SAMPLE_FINDING)
        system, messages = prompts.build_messages(fields, "v1")

        with Stubber(bedrock_client._client) as stubber:
            stubber.add_response(
                "converse",
                expected_params={
                    "modelId": bedrock_client.MODEL_ID,
                    "system": [{"text": system}],
                    "messages": messages,
                    "inferenceConfig": {"maxTokens": 600, "temperature": 0},
                },
                service_response=self._VALID_RESPONSE,
            )
            result = bedrock_client.triage(system, messages)

        assert json.loads(result) == VALID_TRIAGE


# ── Task 12.4: validate module ────────────────────────────────────────────────

class TestValidate:
    def test_parse_output_plain_json(self):
        result = validate.parse_output(json.dumps(VALID_TRIAGE))
        assert result == VALID_TRIAGE

    def test_parse_output_fence_stripping(self):
        fenced = f"```json\n{json.dumps(VALID_TRIAGE)}\n```"
        assert validate.parse_output(fenced) == VALID_TRIAGE

    def test_parse_output_fence_no_lang(self):
        fenced = f"```\n{json.dumps(VALID_TRIAGE)}\n```"
        assert validate.parse_output(fenced) == VALID_TRIAGE

    def test_parse_output_invalid_json(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            validate.parse_output("this is not json")

    def test_parse_output_non_dict(self):
        with pytest.raises(ValueError, match="not a JSON object"):
            validate.parse_output(json.dumps([1, 2, 3]))


# ── Task 12.5: slack module ───────────────────────────────────────────────────

class TestSlack:
    def _mock_resp(self, status=200):
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.status = status
        resp.read.return_value = b"ok"
        return resp

    def test_post_success_posts_correct_fields(self):
        resp = self._mock_resp(200)
        with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"}):
            with patch("slack.urlrequest.urlopen", return_value=resp) as mock_open:
                slack.post_success(VALID_TRIAGE, SAMPLE_FINDING)

        call_args = mock_open.call_args
        req_obj = call_args[0][0]
        body = json.loads(req_obj.data.decode())
        text = body["text"]
        assert SAMPLE_FINDING["type"] in text
        assert VALID_TRIAGE["severity"] in text
        assert VALID_TRIAGE["summary"][:50] in text
        assert VALID_TRIAGE["attack_technique_id"] in text
        assert VALID_TRIAGE["attack_technique_name"] in text
        assert VALID_TRIAGE["recommended_action"] in text

    def test_post_success_missing_field_no_http(self):
        bad = {k: v for k, v in VALID_TRIAGE.items() if k != "severity"}
        with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"}):
            with patch("slack.urlrequest.urlopen") as mock_open:
                with pytest.raises(KeyError, match="severity"):
                    slack.post_success(bad, SAMPLE_FINDING)
        mock_open.assert_not_called()

    def test_post_failure_contains_escalation_text(self):
        resp = self._mock_resp(200)
        exc = ValueError("something broke")
        with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"}):
            with patch("slack.urlrequest.urlopen", return_value=resp) as mock_open:
                slack.post_failure(SAMPLE_FINDING, exc)

        body = json.loads(mock_open.call_args[0][0].data.decode())
        assert "AI triage failed" in body["text"]
        assert SAMPLE_FINDING["id"] in body["text"]

    def test_post_success_missing_webhook_raises(self):
        env = {k: v for k, v in os.environ.items() if k != "SLACK_WEBHOOK_URL"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="SLACK_WEBHOOK_URL"):
                slack.post_success(VALID_TRIAGE, SAMPLE_FINDING)

    def test_post_non_200_raises_ioerror(self):
        resp = self._mock_resp(400)
        with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"}):
            with patch("slack.urlrequest.urlopen", return_value=resp):
                with pytest.raises(IOError):
                    slack.post_success(VALID_TRIAGE, SAMPLE_FINDING)


# ── Task 12.6: handler integration ───────────────────────────────────────────

def _make_event(finding=None):
    if finding is None:
        finding = SAMPLE_FINDING
    return {"detail": finding}


class TestHandler:
    def test_handler_ok_path(self):
        with patch.dict(os.environ, {"PROMPT_VERSION": "v1", "SLACK_WEBHOOK_URL": "https://x"}):
            with patch("handler.extract_fields", return_value={"finding_json": SAMPLE_FINDING, "finding_json_str": "{}"}):
                with patch("handler.build_messages", return_value=("sys", [{"role": "user", "content": [{"text": "{}"}]}])):
                    with patch("handler.triage", return_value=json.dumps(VALID_TRIAGE)):
                        with patch("handler.parse_output", return_value=VALID_TRIAGE):
                            with patch("handler.post_success"):
                                result = handler.lambda_handler(_make_event(), None)
        assert result == {"status": "ok"}

    def test_handler_bedrock_error_triggers_fail_safe(self):
        err = ClientError({"Error": {"Code": "ThrottlingException", "Message": "rate"}}, "converse")
        with patch.dict(os.environ, {"PROMPT_VERSION": "v1", "SLACK_WEBHOOK_URL": "https://x"}):
            with patch("handler.extract_fields", return_value={"finding_json": SAMPLE_FINDING, "finding_json_str": "{}"}):
                with patch("handler.build_messages", return_value=("sys", [])):
                    with patch("handler.triage", side_effect=err):
                        with patch("handler.post_failure") as mock_pf:
                            result = handler.lambda_handler(_make_event(), None)
        assert result == {"status": "fail_safe"}
        mock_pf.assert_called_once()

    def test_handler_missing_prompt_version(self):
        env = {k: v for k, v in os.environ.items() if k != "PROMPT_VERSION"}
        env["SLACK_WEBHOOK_URL"] = "https://x"
        with patch.dict(os.environ, env, clear=True):
            with patch("handler.post_failure") as mock_pf:
                result = handler.lambda_handler(_make_event(), None)
        assert result == {"status": "fail_safe"}
        mock_pf.assert_called_once()

    def test_handler_malformed_event_no_detail(self):
        """Missing 'detail' key → empty finding → extract ValueError → fail_safe."""
        with patch.dict(os.environ, {"PROMPT_VERSION": "v1", "SLACK_WEBHOOK_URL": "https://x"}):
            with patch("handler.post_failure") as mock_pf:
                result = handler.lambda_handler({}, None)
        assert result == {"status": "fail_safe"}
        mock_pf.assert_called_once()

    def test_handler_detail_not_dict(self):
        """detail is a string → isinstance guard resets to {} → fail_safe."""
        with patch.dict(os.environ, {"PROMPT_VERSION": "v1", "SLACK_WEBHOOK_URL": "https://x"}):
            with patch("handler.post_failure") as mock_pf:
                result = handler.lambda_handler({"detail": "not-a-dict"}, None)
        assert result == {"status": "fail_safe"}
        mock_pf.assert_called_once()

    def test_handler_critical_error(self):
        """When post_failure also raises, the handler re-raises (does not return)."""
        err = RuntimeError("pipeline boom")
        with patch.dict(os.environ, {"PROMPT_VERSION": "v1", "SLACK_WEBHOOK_URL": "https://x"}):
            with patch("handler.extract_fields", side_effect=err):
                with patch("handler.post_failure", side_effect=IOError("slack down")):
                    with pytest.raises(IOError, match="slack down"):
                        handler.lambda_handler(_make_event(), None)
