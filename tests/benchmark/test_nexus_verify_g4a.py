from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest

SCRIPT = Path("scripts/bench/nexus_verify_g4a.py")


@pytest.fixture(scope="module")
def gate():
    return runpy.run_path(str(SCRIPT), run_name="nexus_verify_g4a_test")


@pytest.fixture(scope="module")
def report(gate):
    return gate["score"]()


def test_g4a_internal_review_package_is_ready(report, gate):
    assert report["state"] == gate["READY_STATE"]
    assert report["claim_ceiling"] == "INTERNAL_PUBLIC_REVIEW_READINESS_ONLY"
    assert report["summary"]["failure_count"] == 0


def test_all_internal_checks_pass(report):
    assert report["summary"]["internal_check_count"] == 7
    assert report["summary"]["internal_checks_passed"] == 7
    assert all(row["ok"] for row in report["checks"].values())


def test_review_case_counts_are_exact(report):
    assert report["summary"]["positive_review_cases"] == 5
    assert report["summary"]["negative_review_cases"] == 3


def test_external_activation_is_explicitly_not_claimed(report):
    assert report["summary"]["external_activation_ready"] is False
    external = report["summary"]["external_activation_status"]
    assert external["stable_https_mcp_endpoint"] == "UNBOUND_EXTERNAL"
    assert external["publisher_identity_verification"] == "NOT_RUN"
    assert external["production_tool_scan"] == "NOT_RUN"
    assert external["portal_submission"] == "NOT_RUN"
    assert external["publication"] == "NOT_RUN"


def test_tool_contract_remains_single_read_only_public_outcome(gate):
    package = gate["_read_json"](gate["PACKAGE_PATH"])
    mcp = package["mcp"]
    assert mcp["tool_count"] == 1
    assert mcp["tool_name"] == "verify_code_change_evidence"
    assert mcp["auth_mode"] == "noauth"
    assert mcp["repository_scope"] == "PUBLIC_GITHUB_ONLY"
    assert mcp["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }


def test_public_policy_does_not_request_user_credentials(gate):
    package = gate["_read_json"](gate["PACKAGE_PATH"])
    assert package["mcp"]["user_oauth"] is False
    assert package["mcp"]["github_writes"] is False
    assert package["mcp"]["arbitrary_repository_execution"] is False
    privacy = Path("docs/nexus_verify/PRIVACY_POLICY_DRAFT.md").read_text(encoding="utf-8")
    assert "does not request passwords, API keys, access tokens, MFA/OTP codes" in privacy


def test_report_hash_recomputes(report, gate):
    body = {key: value for key, value in report.items() if key != "report_hash"}
    assert report["report_hash"] == gate["canonical_hash"](body)


def test_cli_writes_ready_report(tmp_path: Path, gate, capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "g4a-report.json"
    rc = gate["main"](["--report", str(out)])
    assert rc == 0
    emitted = json.loads(capsys.readouterr().out)
    persisted = json.loads(out.read_text(encoding="utf-8"))
    assert emitted == persisted
    assert persisted["state"] == gate["READY_STATE"]


def test_no_public_submission_side_effects_are_in_gate_source():
    source = SCRIPT.read_text(encoding="utf-8").lower()
    for forbidden in (
        "create_plugin(",
        "submit for review",
        "publish_plugin",
        "deploy_public",
        "domain_verification_challenge",
    ):
        assert forbidden not in source
