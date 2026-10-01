from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest

SCRIPT = Path("scripts/bench/nexus_verify_g2.py")


@pytest.fixture(scope="module")
def gate():
    return runpy.run_path(str(SCRIPT), run_name="nexus_verify_g2_test")


@pytest.fixture(scope="module")
def report(gate):
    return gate["run_experiment"](repetitions=3)


def test_g2_report_reaches_supported_terminal_state(report, gate):
    assert report["state"] == gate["SUPPORTED_STATE"]
    assert report["schema"] == gate["SCHEMA"]
    assert report["synthetic_controlled"] is True
    assert report["claim_ceiling"] == "CONTROLLED_COMPARATIVE_EVIDENCE_ONLY"


def test_all_ten_required_cases_are_present(report):
    assert [row["case_id"] for row in report["cases"]] == [
        "G2-01-FRESH-EXACT",
        "G2-02-OLDER-TARGET",
        "G2-03-HEAD-MOVES-DURING-READ",
        "G2-04-TAMPERED-RECEIPT",
        "G2-05-REQUIRED-VERIFIER-MISSING",
        "G2-06-SCOPE-MISMATCH",
        "G2-07-GREEN-CHECKS-NO-RECEIPT",
        "G2-08-INCOMPLETE-ACQUISITION",
        "G2-09-VALID-EVIDENCE-CHECK-CHURN",
        "G2-10-GITHUB-NATIVE-SUFFICIENT",
    ]


def test_no_false_green_or_false_block(report):
    summary = report["summary"]
    assert summary["false_green_count"] == 0
    assert summary["false_block_count"] == 0
    assert summary["expected_mismatch_cases"] == []
    assert summary["claim_ceiling_violations"] == []


def test_material_incremental_evidence_value_exceeds_threshold(report, gate):
    summary = report["summary"]
    assert summary["unique_value_case_count"] >= gate["MIN_UNIQUE_CASES"]
    assert set(summary["unique_value_cases"]) >= {
        "G2-01-FRESH-EXACT",
        "G2-02-OLDER-TARGET",
        "G2-04-TAMPERED-RECEIPT",
        "G2-05-REQUIRED-VERIFIER-MISSING",
        "G2-06-SCOPE-MISMATCH",
        "G2-09-VALID-EVIDENCE-CHECK-CHURN",
    }


def test_positive_controls_are_not_falsely_blocked(report):
    assert report["summary"]["positive_controls_accepted"] == [
        "G2-01-FRESH-EXACT",
        "G2-09-VALID-EVIDENCE-CHECK-CHURN",
    ]


def test_required_verifier_missing_is_valid_evidence_but_unverifiable(report):
    row = next(
        row for row in report["cases"] if row["case_id"] == "G2-05-REQUIRED-VERIFIER-MISSING"
    )
    assert row["assisted"]["receipt_integrity"] == "VALID"
    assert row["assisted"]["evidence_applicability"] == "APPLIES"
    assert row["assisted"]["core_verification"] == "UNVERIFIABLE"
    assert row["observed"]["accept"] is False
    assert row["observed"]["unique_value"] is True


def test_tampered_receipt_is_fail_closed(report):
    row = next(
        row for row in report["cases"] if row["case_id"] == "G2-04-TAMPERED-RECEIPT"
    )
    assert row["assisted"]["receipt_integrity"] == "INVALID"
    assert row["assisted"]["evidence_applicability"] == "TAMPERED"
    assert "RECEIPT_HASH_MISMATCH" in row["assisted"]["reason_codes"]
    assert row["observed"]["accept"] is False


def test_github_native_overlap_is_not_counted_as_nexus_value(report):
    assert report["summary"]["commodity_overlap_cases"] == [
        "G2-03-HEAD-MOVES-DURING-READ",
        "G2-08-INCOMPLETE-ACQUISITION",
        "G2-10-GITHUB-NATIVE-SUFFICIENT",
    ]
    rows = {row["case_id"]: row for row in report["cases"]}
    assert rows["G2-10-GITHUB-NATIVE-SUFFICIENT"]["observed"]["unique_value"] is False
    assert rows["G2-08-INCOMPLETE-ACQUISITION"]["observed"]["unique_value"] is False


def test_no_receipt_does_not_upgrade_green_github_state(report):
    row = next(
        row for row in report["cases"] if row["case_id"] == "G2-07-GREEN-CHECKS-NO-RECEIPT"
    )
    assert row["baseline"]["state"] == "GITHUB_REQUIRED_CHECKS_GREEN"
    assert row["assisted"]["receipt_integrity"] == "ABSENT"
    assert row["assisted"]["evidence_applicability"] == "EVIDENCE_NOT_SUPPLIED"
    assert row["assisted"]["core_verification"] == "NOT_AVAILABLE"
    assert row["observed"]["accept"] is False


def test_assisted_arm_preserves_claim_ceiling_and_double_read(report):
    for row in report["cases"]:
        assert row["observed"]["claim_ceiling_ok"] is True
        assert row["cost"]["baseline_logical_github_reads"] == 2
        assert row["cost"]["assisted_logical_github_reads"] == 2
        assert row["cost"]["baseline_median_ns"] > 0
        assert row["cost"]["assisted_median_ns"] > 0


def test_decision_hash_is_timing_independent_shape(report, gate):
    decision_basis = {
        "state": report["state"],
        "summary": {
            "unique_value_cases": report["summary"]["unique_value_cases"],
            "commodity_overlap_cases": report["summary"]["commodity_overlap_cases"],
            "false_green_count": report["summary"]["false_green_count"],
            "false_block_count": report["summary"]["false_block_count"],
            "expected_mismatch_cases": report["summary"]["expected_mismatch_cases"],
            "claim_ceiling_violations": report["summary"]["claim_ceiling_violations"],
            "positive_controls_accepted": report["summary"]["positive_controls_accepted"],
        },
        "cases": [
            {
                "case_id": row["case_id"],
                "baseline_state": row["baseline"]["state"],
                "assisted_receipt_integrity": row["assisted"]["receipt_integrity"],
                "assisted_applicability": row["assisted"]["evidence_applicability"],
                "assisted_core_verification": row["assisted"]["core_verification"],
                "expected": row["expected"],
                "observed": row["observed"],
            }
            for row in report["cases"]
        ],
    }
    assert report["decision_hash"] == gate["canonical_hash"](decision_basis)


def test_report_hash_recomputes(report, gate):
    body = {key: value for key, value in report.items() if key != "report_hash"}
    assert report["report_hash"] == gate["canonical_hash"](body)


def test_cli_writes_supported_report(tmp_path: Path, gate, capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "g2-report.json"
    rc = gate["main"](["--repetitions", "3", "--report", str(out)])
    assert rc == 0
    emitted = json.loads(capsys.readouterr().out)
    persisted = json.loads(out.read_text(encoding="utf-8"))
    assert emitted == persisted
    assert persisted["state"] == gate["SUPPORTED_STATE"]


def test_harness_has_no_network_client_or_public_deploy_surface():
    source = SCRIPT.read_text(encoding="utf-8").lower()
    for forbidden in (
        "urllib.request",
        "requests.get",
        "httpx",
        "aiohttp",
        "plugin submission",
        "merge_pull_request",
        "workflow_dispatch",
    ):
        assert forbidden not in source
