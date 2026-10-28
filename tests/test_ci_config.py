"""Guard-rail tests for the CI setup. Plain text checks, no YAML library needed.

They stop a later edit from quietly weakening the pipeline's own security:
a live-AWS workflow that runs on every PR, stored AWS keys, or a broad role.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
LIVE = (ROOT / ".github" / "workflows" / "adversarial-live.yml").read_text()
OIDC = (ROOT / "terraform" / "github_oidc.tf").read_text()
ALL_WORKFLOWS = [CI, LIVE]


def test_offline_ci_has_read_only_permissions_and_no_aws():
    assert re.search(r"^permissions:\n  contents: read\n", CI, re.M)
    assert "id-token" not in CI
    assert "aws-actions" not in CI


def test_live_workflow_is_manual_only():
    triggers = LIVE.split("jobs:")[0]
    assert "workflow_dispatch:" in triggers
    for forbidden in ("pull_request", "push:", "schedule:"):
        assert forbidden not in triggers


def test_no_workflow_uses_pull_request_target_or_stored_aws_keys():
    for text in ALL_WORKFLOWS:
        assert "pull_request_target" not in text
        assert "AWS_ACCESS_KEY_ID" not in text
        assert "AWS_SECRET_ACCESS_KEY" not in text
        assert "secrets.AWS" not in text


def test_every_action_is_pinned_to_an_exact_version():
    for text in ALL_WORKFLOWS:
        for ref in re.findall(r"uses:\s*\S+@(\S+)", text):
            assert re.fullmatch(r"v\d+\.\d+\.\d+|[0-9a-f]{40}", ref), ref


def test_checkout_does_not_keep_credentials():
    for text in ALL_WORKFLOWS:
        assert text.count("actions/checkout") == text.count("persist-credentials: false")


def test_live_run_is_strict_so_a_successful_attack_fails_the_job():
    assert "--strict" in LIVE


def test_oidc_role_trust_is_exact_and_main_branch_only():
    assert ":sub" in OIDC and "StringEquals" in OIDC
    assert "StringLike" not in OIDC
    assert "ref:refs/heads/main" in OIDC
    assert '"*"' not in OIDC


def test_oidc_role_permissions_are_the_two_bedrock_actions_only():
    actions = re.findall(r'Action\s*=\s*\["(bedrock:[A-Za-z]+)"\]', OIDC)
    assert sorted(actions) == ["bedrock:ApplyGuardrail", "bedrock:InvokeModel"]


def test_oidc_subject_is_matched_by_numeric_ids_not_only_names():
    m = re.search(r'default\s*=\s*"([^"]+@\d+/[^"]+@\d+)"', OIDC)
    assert m, "the repo subject must include owner and repo IDs (owner@id/repo@id)"
    assert "var.github_oidc_repo_subject" in OIDC
    assert "var.github_repository" not in OIDC


def test_no_debug_step_that_reads_the_oidc_token_is_left_in_the_workflows():
    for text in ALL_WORKFLOWS:
        assert "ACTIONS_ID_TOKEN_REQUEST" not in text
        assert "Debug OIDC" not in text
