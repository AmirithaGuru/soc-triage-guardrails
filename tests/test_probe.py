"""Offline tests for scripts/probe_guardrail.py. Botocore Stubber, no AWS."""
import sys
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import probe_guardrail as pg  # noqa: E402

GID = "arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123"


def _client():
    return boto3.client("bedrock-runtime", region_name="us-east-1",
                        aws_access_key_id="x", aws_secret_access_key="y")


def _reply(action):
    return {"usage": {"topicPolicyUnits": 0, "contentPolicyUnits": 1,
                      "wordPolicyUnits": 0, "sensitiveInformationPolicyUnits": 0,
                      "sensitiveInformationPolicyFreeUnits": 0,
                      "contextualGroundingPolicyUnits": 0},
            "action": action, "outputs": [], "assessments": []}


def _stubbed(actions):
    c = _client()
    s = Stubber(c)
    for a in actions:
        s.add_response("apply_guardrail", _reply(a))
    s.activate()
    return c, s


def test_every_probe_has_a_unique_id_and_a_known_kind():
    ids = [p[0] for p in pg.PROBES]
    assert len(ids) == len(set(ids))
    assert {p[1] for p in pg.PROBES} == {"attack", "control"}


def test_probe_one_true_only_when_guardrail_intervenes():
    c, s = _stubbed(["GUARDRAIL_INTERVENED", "NONE"])
    assert pg.probe_one(c, GID, "1", "x") is True
    assert pg.probe_one(c, GID, "1", "x") is False
    s.assert_no_pending_responses()


def test_run_marks_expected_and_unexpected():
    # attacks blocked, controls pass -> all as expected
    actions = ["GUARDRAIL_INTERVENED" if k == "attack" else "NONE" for _, k, _ in pg.PROBES]
    c, _ = _stubbed(actions)
    assert all(r["as_expected"] for r in pg.run(c, GID, "1"))

    # nothing blocked -> every attack row is unexpected, controls fine
    c, _ = _stubbed(["NONE"] * len(pg.PROBES))
    rows = pg.run(c, GID, "1")
    assert [r["as_expected"] for r in rows if r["kind"] == "attack"] == [False] * 4
    assert all(r["as_expected"] for r in rows if r["kind"] == "control")


def test_missing_env_returns_2_and_makes_no_call(monkeypatch, capsys):
    monkeypatch.delenv("GUARDRAIL_IDENTIFIER", raising=False)
    monkeypatch.delenv("GUARDRAIL_VERSION", raising=False)
    assert pg.main(["--yes"]) == 2
    assert "export GUARDRAIL_IDENTIFIER" in capsys.readouterr().out


def test_saved_file_does_not_contain_the_guardrail_id(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDRAIL_IDENTIFIER", GID)
    monkeypatch.setenv("GUARDRAIL_VERSION", "1")
    actions = ["GUARDRAIL_INTERVENED" if k == "attack" else "NONE" for _, k, _ in pg.PROBES]
    c, _ = _stubbed(actions)
    monkeypatch.setattr(pg, "make_client", lambda: c)
    out = tmp_path / "probe.json"
    assert pg.main(["--yes", "--out", str(out)]) == 0
    saved = out.read_text()
    assert "abc123" not in saved and "123456789012" not in saved
