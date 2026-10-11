"""Repository-identity cutover tests for the extracted TG8 gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from product.protocol import compatibility_gate as gate


def _hashed(body: dict[str, Any], key: str) -> dict[str, Any]:
    return {**body, key: gate._digest(body)}


def _open_issues(repository: str, observed_at: str) -> dict[str, Any]:
    return _hashed(
        {
            "schema": gate.OPEN_ISSUES_SCHEMA,
            "repository": repository,
            "observed_at": observed_at,
            "query_manifest_hash": "sha256:" + "1" * 64,
            "raw_issue_ids": [],
            "severity_high_issue_ids": [],
            "classifications": {},
            "severity_high_count": 0,
        },
        "snapshot_hash",
    )


def test_repository_cutover_timestamp_is_exact() -> None:
    assert (
        gate._repository_for_observed_at("2026-09-05T23:38:17Z")
        == gate.LEGACY_ACCEPTANCE_REPOSITORY
    )
    assert (
        gate._repository_for_observed_at("2026-09-05T23:38:18Z")
        == gate.CANONICAL_REPOSITORY
    )


def test_post_cutover_thresholds_require_canonical_repository(tmp_path: Path) -> None:
    expected = tmp_path / "thresholds.sha256"
    expected.write_text("\n", encoding="utf-8")
    legacy = {
        "repository": gate.LEGACY_ACCEPTANCE_REPOSITORY,
        "observed_at": "2026-09-06T00:00:00Z",
    }
    current = {**legacy, "repository": gate.CANONICAL_REPOSITORY}

    assert "THRESHOLDS:REPOSITORY" in gate._validate_thresholds(legacy, expected)
    assert "THRESHOLDS:REPOSITORY" not in gate._validate_thresholds(current, expected)


def test_post_cutover_open_issue_snapshot_requires_canonical_repository() -> None:
    current = _open_issues(gate.CANONICAL_REPOSITORY, "2026-09-06T00:00:00Z")
    legacy = _open_issues(gate.LEGACY_ACCEPTANCE_REPOSITORY, "2026-09-06T00:00:00Z")

    assert gate._issues(current) == []
    assert "OPEN_ISSUES:SCHEMA" in gate._issues(legacy)


def test_pre_cutover_open_issue_snapshot_remains_replayable() -> None:
    historical = _open_issues(
        gate.LEGACY_ACCEPTANCE_REPOSITORY,
        "2026-09-05T23:38:17Z",
    )
    assert gate._issues(historical) == []


def test_historical_dependency_receipt_keeps_legacy_repository() -> None:
    body = {
        "schema": gate.TG4_ACCEPTANCE_SCHEMA,
        "repository": gate.LEGACY_ACCEPTANCE_REPOSITORY,
        "subject_commit": "1" * 40,
        "subject_tree": "2" * 40,
        "status": "ACCEPTED",
        "claim": "LOCAL_LEDGER_RECONCILIATION_VERIFIED",
        "authority_source": "historical-nexus-new-acceptance",
        "evidence_hashes": {"controller_receipt": "sha256:" + "3" * 64},
        "observed_at": "2026-09-05T05:10:00Z",
    }
    receipt = _hashed(body, "receipt_hash")
    dep = {
        "commit": receipt["subject_commit"],
        "tree": receipt["subject_tree"],
        "receipt_hash": receipt["receipt_hash"],
    }
    assert gate._binding(
        receipt,
        gate.TG4_ACCEPTANCE_SCHEMA,
        dep,
        "LOCAL_LEDGER_RECONCILIATION_VERIFIED",
    ) == []

    rewritten = dict(receipt)
    rewritten["repository"] = gate.CANONICAL_REPOSITORY
    rewritten.pop("receipt_hash")
    rewritten["receipt_hash"] = gate._digest(rewritten)
    dep["receipt_hash"] = rewritten["receipt_hash"]
    assert any(
        error.endswith(":REPOSITORY")
        for error in gate._binding(
            rewritten,
            gate.TG4_ACCEPTANCE_SCHEMA,
            dep,
            "LOCAL_LEDGER_RECONCILIATION_VERIFIED",
        )
    )


def test_gate_report_is_emitted_under_canonical_repository(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    report = gate._report(
        path,
        {
            "subject_commit": "a" * 40,
            "subject_tree": "b" * 40,
            "threshold_hash": "sha256:" + "4" * 64,
            "observed_at": "2026-09-06T00:00:00Z",
        },
        {},
        gate.RC_READY,
        ["RC_CONDITIONS_SATISFIED"],
        {},
        {},
        {},
        [],
        0,
        0,
    )
    claimed_hash = report["report_hash"]
    body = dict(report)
    body.pop("report_hash")
    assert report["repository"] == gate.CANONICAL_REPOSITORY
    assert claimed_hash == gate._digest(body)
    assert path.read_text(encoding="utf-8").endswith("\n")
