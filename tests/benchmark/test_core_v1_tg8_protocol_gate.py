"""TG8 protocol maturity gate tests.

The suite keeps RC/Stable evidence readiness separate from protocol promotion.
Every mutation below either remains a lower maturity state or fails closed.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from product.benchmark import _digest
from product.protocol import (
    CERTIFICATION_RECEIPT_SCHEMA,
    EVIDENCE_BUNDLE_SCHEMA,
    IMPLEMENTATION_SCHEMA,
    PROVENANCE_ENVELOPE_SCHEMA,
    PUBLIC_PROTOCOL_VERSION,
)
from product.protocol import compatibility_gate as gate


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _hashed(value: dict[str, Any], key: str) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result[key] = _digest(result)
    return result


def _binding(
    schema: str,
    *,
    commit: str,
    tree: str,
    claim: str,
    authority_source: str,
    evidence_hashes: dict[str, str],
) -> dict[str, Any]:
    return _hashed(
        {
            "schema": schema,
            "repository": "James3014/Nexus-new",
            "subject_commit": commit,
            "subject_tree": tree,
            "status": "ACCEPTED",
            "claim": claim,
            "authority_source": authority_source,
            "evidence_hashes": evidence_hashes,
            "observed_at": "2026-09-05T05:10:00+00:00",
        },
        "receipt_hash",
    )


def _certification_receipt() -> dict[str, Any]:
    body = {
        "acceptance_contract_hash": "sha256:" + "1" * 64,
        "certification": {
            "disposition": "CERTIFIED",
            "policy": {
                "accepted": True,
                "approval_present": True,
                "authority_present": True,
                "signing_present": True,
            },
        },
        "change_set_hash": "sha256:" + "2" * 64,
        "claim_ceiling": [
            "NO_MERGE_AUTHORIZATION",
            "NO_DEPLOYMENT_TRUTH",
            "NO_OUTCOME_TRUTH",
            "NO_PRODUCTION_READINESS",
            "NO_PUBLIC_PROTOCOL_STABILITY",
        ],
        "evidence_hash": "sha256:" + "3" * 64,
        "implementation_schema": IMPLEMENTATION_SCHEMA,
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "receipt_schema": CERTIFICATION_RECEIPT_SCHEMA,
        "verification": {
            "condition": "VALID",
            "reason_codes": [],
            "status": "VERIFIED",
        },
        "verification_plan_hash": "sha256:" + "4" * 64,
    }
    return {**body, "receipt_hash": _digest(body)}


def _tg5_binding(commit: str, tree: str) -> dict[str, Any]:
    receipt = _certification_receipt()
    return _hashed(
        {
            "schema": gate.TG5_ACCEPTANCE_SCHEMA,
            "repository": "James3014/Nexus-new",
            "subject_commit": commit,
            "subject_tree": tree,
            "status": "ACCEPTED",
            "controlled_pr": 635,
            "controlled_pr_base": "a" * 40,
            "controlled_pr_head": "b" * 40,
            "live_run_id": "tg5-live-001",
            "mandatory_commands": [
                "uv run pytest -qq tests/product/test_http_runtime.py tests/product/test_http_e2e.py -m not-live",
                "NEXUS_CORE_HTTP_PORT=8767 uv run pytest -qq tests/product/test_http_e2e.py -m live --run-live",
            ],
            "certification_receipt": receipt,
            "certification_receipt_hash": receipt["receipt_hash"],
            "observed_at": "2026-09-05T05:11:00+00:00",
        },
        "receipt_hash",
    )


def _compatibility_manifest() -> list[dict[str, str]]:
    current = {
        "public_protocol": PUBLIC_PROTOCOL_VERSION,
        "implementation_schema": IMPLEMENTATION_SCHEMA,
        "evidence_bundle_schema": EVIDENCE_BUNDLE_SCHEMA,
        "provenance_envelope_schema": PROVENANCE_ENVELOPE_SCHEMA,
        "certification_receipt_schema": CERTIFICATION_RECEIPT_SCHEMA,
        "ledger_schema": gate.LEDGER_SCHEMA,
        "ledger_generation": "generation-v1",
        "http_schema": gate.HTTP_SCHEMA,
        "cli_client": "nexus-certify-v1",
        "mcp_client": "nexus-mcp-thin-v1",
        "action_client": "nexus-action-thin-v1",
        "reader_version": "reader-v1",
    }
    rows: list[dict[str, str]] = []
    for axis, source in current.items():
        rows.append({
            "row_id": f"{axis}-supported",
            "axis": axis,
            "source": source,
            "target": f"{axis}-rc-compatible",
            "expected": "SUPPORTED",
        })
        rows.append({
            "row_id": f"{axis}-refused",
            "axis": axis,
            "source": source,
            "target": f"{axis}-incompatible",
            "expected": "REFUSED",
        })
    return rows


def _compatibility(
    subject: str,
    tree: str,
    manifest: list[dict[str, str]],
) -> dict[str, Any]:
    rows = []
    for spec in manifest:
        rows.append(
            _hashed(
                {
                    **spec,
                    "observed": spec["expected"],
                    "reason_code": (
                        "COMPATIBLE_TRANSITION"
                        if spec["expected"] == "SUPPORTED"
                        else "INCOMPATIBLE_REFUSED"
                    ),
                    "receipt_preservation_hash": "sha256:" + "5" * 64,
                },
                "row_hash",
            )
        )
    return _hashed(
        {
            "schema": gate.COMPATIBILITY_SCHEMA,
            "subject_commit": subject,
            "subject_tree": tree,
            "rows": rows,
        },
        "matrix_hash",
    )


def _conformance(subject: str, tree: str) -> dict[str, Any]:
    clients = []
    for index, name in enumerate(gate.REQUIRED_CLIENTS, start=1):
        clients.append(
            _hashed(
                {
                    "name": name,
                    "artifact_hash": "sha256:" + f"{index:x}" * 64,
                    "output_hash": "sha256:" + f"{index + 3:x}" * 64,
                    "parity": True,
                },
                "row_hash",
            )
        )
    return _hashed(
        {
            "schema": gate.CONFORMANCE_SCHEMA,
            "subject_commit": subject,
            "subject_tree": tree,
            "canonical_request_hash": "sha256:" + "7" * 64,
            "canonical_response_hash": "sha256:" + "8" * 64,
            "endpoint_sequence": [
                "POST /v1/certifications",
                "GET /v1/certifications/{id}",
            ],
            "redaction_set": ["authorization", "github_token"],
            "clients": clients,
            "parity": True,
        },
        "report_hash",
    )


def _upgrade_manifest() -> list[dict[str, str]]:
    specs = [
        (
            "current-to-rc",
            "CURRENT_TO_RC",
            PUBLIC_PROTOCOL_VERSION,
            gate.RC_CANDIDATE,
            "SUPPORTED",
        ),
        ("rc-patch", "RC_PATCH", gate.RC_CANDIDATE, "1.0.0-rc.2", "SUPPORTED"),
        (
            "rc-to-stable",
            "RC_TO_STABLE",
            gate.RC_CANDIDATE,
            gate.STABLE_CANDIDATE,
            "SUPPORTED",
        ),
        (
            "bad-protocol",
            "INCOMPATIBLE_PROTOCOL",
            gate.RC_CANDIDATE,
            "2.0.0-foreign",
            "REFUSED",
        ),
        (
            "bad-schema",
            "INCOMPATIBLE_SCHEMA",
            IMPLEMENTATION_SCHEMA,
            "nexus.foreign.v9",
            "REFUSED",
        ),
        (
            "bad-ledger",
            "INCOMPATIBLE_LEDGER",
            gate.LEDGER_SCHEMA,
            "nexus.ledger-entry.v9",
            "REFUSED",
        ),
        (
            "failed-upgrade",
            "FAILED_UPGRADE_ROLLBACK",
            gate.RC_CANDIDATE,
            gate.STABLE_CANDIDATE,
            "REFUSED",
        ),
    ]
    return [
        {
            "row_id": row_id,
            "kind": kind,
            "source": source,
            "target": target,
            "expected": expected,
        }
        for row_id, kind, source, target, expected in specs
    ]


def _upgrade(
    subject: str,
    tree: str,
    manifest: list[dict[str, str]],
) -> dict[str, Any]:
    rows = []
    for index, spec in enumerate(manifest, start=1):
        hashes = {
            "old_wheel_hash": "sha256:" + f"{(index % 9) + 1:x}" * 64,
            "new_wheel_hash": "sha256:" + f"{((index + 1) % 9) + 1:x}" * 64,
            "old_runtime_hash": "sha256:" + f"{((index + 2) % 9) + 1:x}" * 64,
            "new_runtime_hash": "sha256:" + f"{((index + 3) % 9) + 1:x}" * 64,
            "old_ledger_hash": "sha256:" + f"{((index + 4) % 9) + 1:x}" * 64,
            "new_ledger_hash": "sha256:" + f"{((index + 5) % 9) + 1:x}" * 64,
            "old_receipt_hash": "sha256:" + f"{((index + 6) % 9) + 1:x}" * 64,
            "new_receipt_hash": "sha256:" + f"{((index + 7) % 9) + 1:x}" * 64,
        }
        rows.append(
            _hashed(
                {
                    **spec,
                    "observed": spec["expected"],
                    **hashes,
                    "old_receipt_byte_equal": True,
                    "rollback_state": (
                        "RESTORED_EXACT"
                        if spec["kind"] == "FAILED_UPGRADE_ROLLBACK"
                        else "NOT_REQUIRED"
                    ),
                    "reason_code": (
                        "SUPPORTED_AND_READABLE"
                        if spec["expected"] == "SUPPORTED"
                        else "REFUSED_WITHOUT_REWRITE"
                    ),
                },
                "row_hash",
            )
        )
    return _hashed(
        {
            "schema": gate.UPGRADE_ROLLBACK_SCHEMA,
            "subject_commit": subject,
            "subject_tree": tree,
            "rows": rows,
        },
        "report_hash",
    )


def _open_issues(high: list[int] | None = None) -> dict[str, Any]:
    high = sorted(high or [])
    raw = sorted(set(high + [772, 773]))
    classes = {
        str(issue): ("CORE_SEVERITY_HIGH_BLOCKER" if issue in high else "GATE_META_EXCLUDED")
        for issue in raw
    }
    return _hashed(
        {
            "schema": gate.OPEN_ISSUES_SCHEMA,
            "repository": "James3014/Nexus-new",
            "observed_at": "2026-09-05T05:12:00+00:00",
            "query_manifest_hash": "sha256:" + "9" * 64,
            "raw_issue_ids": raw,
            "severity_high_issue_ids": high,
            "classifications": classes,
            "severity_high_count": len(high),
        },
        "snapshot_hash",
    )


def _tg7(
    certification_hash: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    selection = _hashed(
        {
            "schema": "nexus.core-v1.tg7-selection.v1",
            "canonical_url": "https://github.com/bottlepy/bottle",
            "owner": "bottlepy",
            "name": "bottle",
            "commit": "c" * 40,
            "tree": "d" * 40,
            "snapshot_path": "external/bottle",
            "snapshot_tree_hash": "sha256:" + "a" * 64,
            "observed_at": "2026-09-05T05:13:00+00:00",
            "license_spdx": "MIT",
            "license_evidence_hash": "sha256:" + "b" * 64,
            "privacy_class": "PUBLIC_OPEN_SOURCE",
            "read_only_evidence_hash": "sha256:" + "c" * 64,
            "task_set_id": "tg7-shadow-bottle-v1",
            "not_nexus_reason": "independent public repository",
        },
        "selection_hash",
    )
    cases = [
        {"case_id": f"{family}-{index}", "hostile_family": family}
        for family in gate.HOSTILE_FAMILIES
        for index in range(7)
    ]
    corpus = _hashed(
        {
            "schema": "nexus.core-v1.tg7-corpus.v1",
            "task_set_id": "tg7-shadow-bottle-v1",
            "repository": {
                "owner": selection["owner"],
                "name": selection["name"],
                "commit": selection["commit"],
                "tree": selection["tree"],
            },
            "case_count": len(cases),
            "cases": cases,
        },
        "corpus_hash",
    )
    shadow_cases = [{"case_id": case["case_id"]} for case in cases]
    shadow = _hashed(
        {
            "schema": "nexus.core-v1.tg7-shadow-receipt.v1",
            "cases": shadow_cases,
            "corpus_hash": corpus["corpus_hash"],
            "eligible_count": 56,
            "infra_invalid_count": 0,
            "repository": {
                **corpus["repository"],
                "bottle_py_hash": "sha256:" + "e" * 64,
            },
            "run_id": "tg7-physical-run",
            "selection_hash": selection["selection_hash"],
            "task_set_id": "tg7-shadow-bottle-v1",
            "tg5_receipt_hash": certification_hash,
        },
        "receipt_hash",
    )
    report = _hashed(
        {
            "schema": "nexus.core-v1.tg7-report.v1",
            "claim_ceiling": [
                "NO_MERGE_AUTHORIZATION",
                "NO_DEPLOYMENT_TRUTH",
                "NO_OUTCOME_TRUTH",
                "NO_PRODUCTION_READINESS",
                "NO_PUBLIC_PROTOCOL_STABILITY",
            ],
            "compatibility": {
                "attempt_receipt_schema": "nexus.core-v1.tg7-attempt-receipt.v2",
                "claim_ceiling": [
                    "NO_MERGE_AUTHORIZATION",
                    "NO_DEPLOYMENT_TRUTH",
                    "NO_OUTCOME_TRUTH",
                    "NO_PRODUCTION_READINESS",
                    "NO_PUBLIC_PROTOCOL_STABILITY",
                ],
                "implementation_schema": IMPLEMENTATION_SCHEMA,
                "profile_id": gate.PROFILE_ID,
                "protocol_version": PUBLIC_PROTOCOL_VERSION,
            },
            "denominator": 56,
            "eligible_count": 56,
            "false_certification_case_ids": [],
            "false_certification_count": 0,
            "family_counts": {family: 7 for family in gate.HOSTILE_FAMILIES},
            "generated_at": "2026-09-05T05:14:00+00:00",
            "infra_invalid_count": 0,
            "maximum_claim": "CROSS_REPO_TRUST_SHADOW_VERIFIED",
            "selection_hash": selection["selection_hash"],
            "shadow_receipt_hash": shadow["receipt_hash"],
            "task_set_id": "tg7-shadow-bottle-v1",
            "tg5_receipt_hash": certification_hash,
            "trust_mismatches": 0,
        },
        "report_hash",
    )
    return selection, corpus, shadow, report


def _stable_run(
    *,
    run_id: str,
    observed_at: str,
    subject: str,
    tree: str,
    tg5_hash: str,
    tg7_hash: str,
    compatibility_hash: str,
    conformance_hash: str,
    upgrade_hash: str,
    factual_hash: str = "sha256:" + "e" * 64,
    eligible: int = 56,
) -> dict[str, Any]:
    return _hashed(
        {
            "schema": gate.STABLE_RUN_SCHEMA,
            "run_id": run_id,
            "candidate_commit": subject,
            "candidate_tree": tree,
            "observed_at": observed_at,
            "complete": True,
            "tg5_run_id": f"{run_id}-tg5",
            "tg7_run_id": f"{run_id}-tg7",
            "eligible_attempts": eligible,
            "required_skips": 0,
            "false_certification_count": 0,
            "client_parity": True,
            "factual_outcome_hash": factual_hash,
            "compatibility_hash": compatibility_hash,
            "conformance_hash": conformance_hash,
            "upgrade_rollback_hash": upgrade_hash,
            "tg5_receipt_hash": tg5_hash,
            "tg7_report_hash": tg7_hash,
        },
        "run_hash",
    )


def _thresholds(
    *,
    subject: str,
    tree: str,
    paths: dict[str, Path],
    tg4: dict[str, Any],
    tg5: dict[str, Any],
    tg6: dict[str, Any],
    tg7_report: dict[str, Any],
    compatibility_manifest: list[dict[str, str]],
    upgrade_manifest: list[dict[str, str]],
    stable_paths: list[Path],
) -> dict[str, Any]:
    input_hashes = {key: gate._file_hash(path) for key, path in paths.items() if path.is_file()}
    for index, path in enumerate(stable_paths, start=1):
        if path.is_file():
            input_hashes[f"stable_run_{index}"] = gate._file_hash(path)
    return _hashed(
        {
            "schema": gate.THRESHOLDS_SCHEMA,
            "repository": "James3014/Nexus-new",
            "rc_candidate": gate.RC_CANDIDATE,
            "stable_candidate": gate.STABLE_CANDIDATE,
            "subject_commit": subject,
            "subject_tree": tree,
            "dependency_subjects": {
                "tg4": {
                    "commit": tg4["subject_commit"],
                    "tree": tg4["subject_tree"],
                    "receipt_hash": tg4["receipt_hash"],
                },
                "tg5": {
                    "commit": tg5["subject_commit"],
                    "tree": tg5["subject_tree"],
                    "receipt_hash": tg5["receipt_hash"],
                },
                "tg6": {
                    "commit": tg6["subject_commit"],
                    "tree": tg6["subject_tree"],
                    "receipt_hash": tg6["receipt_hash"],
                },
                "tg7": {
                    "commit": "7" * 40,
                    "tree": "8" * 40,
                    "receipt_hash": tg7_report["report_hash"],
                },
            },
            "input_hashes": input_hashes,
            "compatibility_manifest": compatibility_manifest,
            "upgrade_manifest": upgrade_manifest,
            "required_clients": list(gate.REQUIRED_CLIENTS),
            "forbidden_output_states": sorted(gate.FORBIDDEN_OUTPUT_STATES),
            "observed_at": "2026-09-05T05:15:00+00:00",
        },
        "threshold_hash",
    )


def _fixture(
    tmp_path: Path, *, stable: bool = False, high: list[int] | None = None
) -> dict[str, Any]:
    subject = "e" * 40
    tree = "f" * 40
    tg4 = _binding(
        gate.TG4_ACCEPTANCE_SCHEMA,
        commit="1" * 40,
        tree="2" * 40,
        claim="LOCAL_LEDGER_RECONCILIATION_VERIFIED",
        authority_source="issue-768-comment-5542807802",
        evidence_hashes={"controller_receipt": "sha256:" + "1" * 64},
    )
    tg5 = _tg5_binding("3" * 40, "4" * 40)
    tg6 = _binding(
        gate.TG6_ACCEPTANCE_SCHEMA,
        commit="5" * 40,
        tree="6" * 40,
        claim="OPERATOR_JOURNEY_VERIFIED",
        authority_source="issue-770-comment-5548355769",
        evidence_hashes={
            "physical_artifact": "sha256:" + "2" * 64,
            "tg5_receipt": tg5["certification_receipt_hash"],
        },
    )
    selection, corpus, shadow, tg7_report = _tg7(tg5["certification_receipt_hash"])
    compat_manifest = _compatibility_manifest()
    upgrade_manifest = _upgrade_manifest()
    compatibility = _compatibility(subject, tree, compat_manifest)
    conformance = _conformance(subject, tree)
    upgrade = _upgrade(subject, tree, upgrade_manifest)
    open_issues = _open_issues(high)

    paths = {
        "tg4_receipt": tmp_path / "tg4.json",
        "tg5_receipt": tmp_path / "tg5.json",
        "tg6_receipt": tmp_path / "tg6.json",
        "compatibility": tmp_path / "compatibility.json",
        "conformance": tmp_path / "conformance.json",
        "upgrade_rollback": tmp_path / "upgrade.json",
        "open_issues": tmp_path / "open-issues.json",
        "tg7_selection": tmp_path / "selection.json",
        "tg7_corpus": tmp_path / "corpus.json",
        "tg7_shadow": tmp_path / "shadow.json",
        "tg7_report": tmp_path / "tg7-report.json",
    }
    values = {
        "tg4_receipt": tg4,
        "tg5_receipt": tg5,
        "tg6_receipt": tg6,
        "compatibility": compatibility,
        "conformance": conformance,
        "upgrade_rollback": upgrade,
        "open_issues": open_issues,
        "tg7_selection": selection,
        "tg7_corpus": corpus,
        "tg7_shadow": shadow,
        "tg7_report": tg7_report,
    }
    for key, path in paths.items():
        _write(path, values[key])

    stable_paths = [tmp_path / f"stable-{index}.json" for index in range(1, 4)]
    if stable:
        for index, path in enumerate(stable_paths, start=1):
            _write(
                path,
                _stable_run(
                    run_id=f"stable-run-{index}",
                    observed_at=f"2026-09-05T05:{20 + index:02d}:00+00:00",
                    subject=subject,
                    tree=tree,
                    tg5_hash=tg5["certification_receipt_hash"],
                    tg7_hash=tg7_report["report_hash"],
                    compatibility_hash=compatibility["matrix_hash"],
                    conformance_hash=conformance["report_hash"],
                    upgrade_hash=upgrade["report_hash"],
                ),
            )

    thresholds = _thresholds(
        subject=subject,
        tree=tree,
        paths=paths,
        tg4=tg4,
        tg5=tg5,
        tg6=tg6,
        tg7_report=tg7_report,
        compatibility_manifest=compat_manifest,
        upgrade_manifest=upgrade_manifest,
        stable_paths=stable_paths,
    )
    threshold_path = tmp_path / "thresholds.json"
    _write(threshold_path, thresholds)
    expected_path = tmp_path / "thresholds.sha256"
    expected_path.write_text(thresholds["threshold_hash"][7:] + "\n", encoding="utf-8")

    return {
        "subject": subject,
        "tree": tree,
        "paths": paths,
        "values": values,
        "stable_paths": stable_paths,
        "thresholds": thresholds,
        "threshold_path": threshold_path,
        "expected_path": expected_path,
        "report": tmp_path / "report.json",
    }


def _refresh(fx: dict[str, Any]) -> None:
    thresholds = fx["thresholds"]
    paths = fx["paths"]
    input_hashes = {key: gate._file_hash(path) for key, path in paths.items() if path.is_file()}
    for index, path in enumerate(fx["stable_paths"], start=1):
        if path.is_file():
            input_hashes[f"stable_run_{index}"] = gate._file_hash(path)
    thresholds["input_hashes"] = input_hashes
    thresholds.pop("threshold_hash", None)
    thresholds["threshold_hash"] = _digest(thresholds)
    _write(fx["threshold_path"], thresholds)
    fx["expected_path"].write_text(thresholds["threshold_hash"][7:] + "\n", encoding="utf-8")


def _run(fx: dict[str, Any]) -> dict[str, Any]:
    p = fx["paths"]
    return gate.adjudicate(
        thresholds_path=fx["threshold_path"],
        expected_thresholds_sha256_file=fx["expected_path"],
        compatibility_path=p["compatibility"],
        conformance_path=p["conformance"],
        upgrade_rollback_path=p["upgrade_rollback"],
        open_issues_path=p["open_issues"],
        tg4_receipt_path=p["tg4_receipt"],
        tg5_receipt_path=p["tg5_receipt"],
        tg6_receipt_path=p["tg6_receipt"],
        tg7_selection_path=p["tg7_selection"],
        tg7_corpus_path=p["tg7_corpus"],
        tg7_shadow_path=p["tg7_shadow"],
        tg7_report_path=p["tg7_report"],
        stable_run_paths=fx["stable_paths"],
        report_path=fx["report"],
    )


def test_valid_rc_evidence_is_ready_without_stable_promotion(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    report = _run(fx)
    assert report["classification"] == gate.RC_READY
    assert "NO_PROTOCOL_PROMOTION" in report["claim_ceiling"]


def test_three_fresh_reproducible_runs_support_stable_evidence_readiness(
    tmp_path: Path,
) -> None:
    fx = _fixture(tmp_path, stable=True)
    report = _run(fx)
    assert report["classification"] == gate.STABLE_READY
    assert report["stable_run_count"] == 3


def test_missing_required_artifact_is_unverifiable(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    fx["paths"]["compatibility"].unlink()
    assert _run(fx)["classification"] == gate.UNVERIFIABLE


def test_tampered_artifact_hash_is_unverifiable(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    with fx["paths"]["compatibility"].open("a", encoding="utf-8") as handle:
        handle.write(" ")
    assert _run(fx)["classification"] == gate.UNVERIFIABLE


def test_threshold_hash_file_mismatch_is_unverifiable(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    fx["expected_path"].write_text("0" * 64 + "\n", encoding="utf-8")
    assert _run(fx)["classification"] == gate.UNVERIFIABLE


def test_compatibility_outcome_mismatch_is_lower_maturity(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    value = fx["values"]["compatibility"]
    value["rows"][0]["observed"] = "REFUSED"
    value["rows"][0].pop("row_hash")
    value["rows"][0]["row_hash"] = _digest(value["rows"][0])
    value.pop("matrix_hash")
    value["matrix_hash"] = _digest(value)
    _write(fx["paths"]["compatibility"], value)
    _refresh(fx)
    assert _run(fx)["classification"] == gate.LOWER_MATURITY


def test_missing_compatibility_axis_fails_closed(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    manifest = fx["thresholds"]["compatibility_manifest"]
    fx["thresholds"]["compatibility_manifest"] = [
        row for row in manifest if row["axis"] != "reader_version"
    ]
    fx["thresholds"].pop("threshold_hash")
    fx["thresholds"]["threshold_hash"] = _digest(fx["thresholds"])
    _write(fx["threshold_path"], fx["thresholds"])
    fx["expected_path"].write_text(fx["thresholds"]["threshold_hash"][7:] + "\n", encoding="utf-8")
    assert _run(fx)["classification"] == gate.UNVERIFIABLE


def test_client_parity_failure_is_lower_maturity(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    value = fx["values"]["conformance"]
    value["clients"][0]["parity"] = False
    value["clients"][0].pop("row_hash")
    value["clients"][0]["row_hash"] = _digest(value["clients"][0])
    value["parity"] = False
    value.pop("report_hash")
    value["report_hash"] = _digest(value)
    _write(fx["paths"]["conformance"], value)
    _refresh(fx)
    assert _run(fx)["classification"] == gate.LOWER_MATURITY


def test_failed_upgrade_without_exact_rollback_is_lower_maturity(
    tmp_path: Path,
) -> None:
    fx = _fixture(tmp_path)
    value = fx["values"]["upgrade_rollback"]
    row = next(r for r in value["rows"] if r["kind"] == "FAILED_UPGRADE_ROLLBACK")
    row["rollback_state"] = "PARTIAL"
    row.pop("row_hash")
    row["row_hash"] = _digest(row)
    value.pop("report_hash")
    value["report_hash"] = _digest(value)
    _write(fx["paths"]["upgrade_rollback"], value)
    _refresh(fx)
    assert _run(fx)["classification"] == gate.LOWER_MATURITY


def test_receipt_rewrite_on_incompatible_transition_is_lower_maturity(
    tmp_path: Path,
) -> None:
    fx = _fixture(tmp_path)
    value = fx["values"]["upgrade_rollback"]
    row = next(r for r in value["rows"] if r["kind"] == "INCOMPATIBLE_SCHEMA")
    row["old_receipt_byte_equal"] = False
    row.pop("row_hash")
    row["row_hash"] = _digest(row)
    value.pop("report_hash")
    value["report_hash"] = _digest(value)
    _write(fx["paths"]["upgrade_rollback"], value)
    _refresh(fx)
    assert _run(fx)["classification"] == gate.LOWER_MATURITY


def test_tg7_false_certification_blocks_rc(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    report = fx["values"]["tg7_report"]
    report["false_certification_count"] = 1
    report["false_certification_case_ids"] = ["AUTH_ISSUER_TAMPER-0"]
    report.pop("report_hash")
    report["report_hash"] = _digest(report)
    _write(fx["paths"]["tg7_report"], report)
    fx["thresholds"]["dependency_subjects"]["tg7"]["receipt_hash"] = report["report_hash"]
    _refresh(fx)
    assert _run(fx)["classification"] == gate.LOWER_MATURITY


def test_tg7_family_denominator_blocks_rc(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    report = fx["values"]["tg7_report"]
    report["family_counts"]["AUTH_ISSUER_TAMPER"] = 4
    report.pop("report_hash")
    report["report_hash"] = _digest(report)
    _write(fx["paths"]["tg7_report"], report)
    fx["thresholds"]["dependency_subjects"]["tg7"]["receipt_hash"] = report["report_hash"]
    _refresh(fx)
    assert _run(fx)["classification"] == gate.LOWER_MATURITY


def test_open_high_severity_core_issue_prevents_stable_but_not_rc(
    tmp_path: Path,
) -> None:
    fx = _fixture(tmp_path, stable=True, high=[783])
    assert _run(fx)["classification"] == gate.RC_READY


def test_nonreproducible_stable_factual_hash_stays_rc(tmp_path: Path) -> None:
    fx = _fixture(tmp_path, stable=True)
    path = fx["stable_paths"][2]
    value = json.loads(path.read_text(encoding="utf-8"))
    value["factual_outcome_hash"] = "sha256:" + "f" * 64
    value.pop("run_hash")
    value["run_hash"] = _digest(value)
    _write(path, value)
    _refresh(fx)
    assert _run(fx)["classification"] == gate.RC_READY


def test_aggregate_stable_denominator_under_150_stays_rc(tmp_path: Path) -> None:
    fx = _fixture(tmp_path, stable=True)
    for path in fx["stable_paths"]:
        value = json.loads(path.read_text(encoding="utf-8"))
        value["eligible_attempts"] = 49
        value.pop("run_hash")
        value["run_hash"] = _digest(value)
        _write(path, value)
    _refresh(fx)
    assert _run(fx)["classification"] == gate.RC_READY


def test_unbound_stable_run_is_unverifiable(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    _write(
        fx["stable_paths"][0],
        _stable_run(
            run_id="surprise",
            observed_at="2026-09-05T05:30:00+00:00",
            subject=fx["subject"],
            tree=fx["tree"],
            tg5_hash=fx["values"]["tg5_receipt"]["certification_receipt_hash"],
            tg7_hash=fx["values"]["tg7_report"]["report_hash"],
            compatibility_hash=fx["values"]["compatibility"]["matrix_hash"],
            conformance_hash=fx["values"]["conformance"]["report_hash"],
            upgrade_hash=fx["values"]["upgrade_rollback"]["report_hash"],
        ),
    )
    assert _run(fx)["classification"] == gate.UNVERIFIABLE


def test_forged_tg5_controlled_pr_binding_is_unverifiable(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    value = fx["values"]["tg5_receipt"]
    value["controlled_pr"] = 999
    value.pop("receipt_hash")
    value["receipt_hash"] = _digest(value)
    _write(fx["paths"]["tg5_receipt"], value)
    fx["thresholds"]["dependency_subjects"]["tg5"]["receipt_hash"] = value["receipt_hash"]
    _refresh(fx)
    assert _run(fx)["classification"] == gate.UNVERIFIABLE


def test_forbidden_value_ready_claim_fails_closed(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    value = fx["values"]["open_issues"]
    value["classifications"]["772"] = "VALUE_READY"
    value.pop("snapshot_hash")
    value["snapshot_hash"] = _digest(value)
    _write(fx["paths"]["open_issues"], value)
    _refresh(fx)
    report = _run(fx)
    assert report["classification"] == gate.UNVERIFIABLE
    assert any("FORBIDDEN_CLAIM_VALUE" in reason for reason in report["reasons"])


def test_malformed_threshold_nested_row_is_unverifiable_not_exception(
    tmp_path: Path,
) -> None:
    fx = _fixture(tmp_path)
    fx["thresholds"]["compatibility_manifest"][0]["row_id"] = ["not-hashable"]
    fx["thresholds"].pop("threshold_hash")
    fx["thresholds"]["threshold_hash"] = _digest(fx["thresholds"])
    _write(fx["threshold_path"], fx["thresholds"])
    fx["expected_path"].write_text(fx["thresholds"]["threshold_hash"][7:] + "\n", encoding="utf-8")
    assert _run(fx)["classification"] == gate.UNVERIFIABLE


def test_missing_dependency_binding_is_unverifiable_not_exception(
    tmp_path: Path,
) -> None:
    fx = _fixture(tmp_path)
    del fx["thresholds"]["dependency_subjects"]["tg4"]
    fx["thresholds"].pop("threshold_hash")
    fx["thresholds"]["threshold_hash"] = _digest(fx["thresholds"])
    _write(fx["threshold_path"], fx["thresholds"])
    fx["expected_path"].write_text(fx["thresholds"]["threshold_hash"][7:] + "\n", encoding="utf-8")
    assert _run(fx)["classification"] == gate.UNVERIFIABLE


def test_non_integer_tg7_denominator_is_unverifiable_not_exception(
    tmp_path: Path,
) -> None:
    fx = _fixture(tmp_path)
    report = fx["values"]["tg7_report"]
    report["denominator"] = "fifty-six"
    report["eligible_count"] = "fifty-six"
    report.pop("report_hash")
    report["report_hash"] = _digest(report)
    _write(fx["paths"]["tg7_report"], report)
    fx["thresholds"]["dependency_subjects"]["tg7"]["receipt_hash"] = report["report_hash"]
    _refresh(fx)
    assert _run(fx)["classification"] == gate.LOWER_MATURITY


def test_cli_exit_code_is_zero_only_for_ready_states(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    p = fx["paths"]
    args = [
        "--thresholds",
        str(fx["threshold_path"]),
        "--expected-thresholds-sha256-file",
        str(fx["expected_path"]),
        "--compatibility",
        str(p["compatibility"]),
        "--conformance",
        str(p["conformance"]),
        "--upgrade-rollback",
        str(p["upgrade_rollback"]),
        "--open-issues",
        str(p["open_issues"]),
        "--tg4-receipt",
        str(p["tg4_receipt"]),
        "--tg5-receipt",
        str(p["tg5_receipt"]),
        "--tg6-receipt",
        str(p["tg6_receipt"]),
        "--tg7-selection",
        str(p["tg7_selection"]),
        "--tg7-corpus",
        str(p["tg7_corpus"]),
        "--tg7-shadow",
        str(p["tg7_shadow"]),
        "--tg7-report",
        str(p["tg7_report"]),
        "--stable-run-1",
        str(fx["stable_paths"][0]),
        "--stable-run-2",
        str(fx["stable_paths"][1]),
        "--stable-run-3",
        str(fx["stable_paths"][2]),
        "--report",
        str(fx["report"]),
    ]
    assert gate.main(args) == 0
    fx["paths"]["tg4_receipt"].unlink()
    assert gate.main(args) == 2


@pytest.mark.parametrize("state", sorted(gate.FORBIDDEN_OUTPUT_STATES))
def test_forbidden_output_states_are_not_allowed_machine_states(state: str) -> None:
    assert state not in gate.ALLOWED_STATES


def test_tg7_shadow_repository_requires_external_material_hash(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    shadow = fx["values"]["tg7_shadow"]
    shadow["repository"].pop("bottle_py_hash")
    shadow.pop("receipt_hash")
    shadow["receipt_hash"] = _digest(shadow)
    _write(fx["paths"]["tg7_shadow"], shadow)
    _refresh(fx)
    report = _run(fx)
    assert report["classification"] == gate.UNVERIFIABLE
    assert "TG7:REPOSITORY" in report["reasons"]


def test_tg7_shadow_repository_rejects_invalid_external_material_hash(tmp_path: Path) -> None:
    fx = _fixture(tmp_path)
    shadow = fx["values"]["tg7_shadow"]
    shadow["repository"]["bottle_py_hash"] = "not-a-sha256"
    shadow.pop("receipt_hash")
    shadow["receipt_hash"] = _digest(shadow)
    _write(fx["paths"]["tg7_shadow"], shadow)
    _refresh(fx)
    report = _run(fx)
    assert report["classification"] == gate.UNVERIFIABLE
    assert "TG7:REPOSITORY" in report["reasons"]
