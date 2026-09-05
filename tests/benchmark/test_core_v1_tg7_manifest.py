"""Negative guards and controller-evidence readback for TG-7."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from product.benchmark import _canonical, _digest
from product.benchmark.tg7_shadow import (
    ALLOWED_LICENSES,
    ATTEMPT_RECEIPT_SCHEMA,
    HOSTILE_FAMILIES,
    MAXIMUM_CLAIM,
    PROFILE_ID,
    build_default_corpus,
    validate_attempt_receipt,
    validate_corpus,
    validate_report,
    validate_selection,
    validate_shadow_receipt,
    validate_tg5_receipt,
)
from product.protocol import IMPLEMENTATION_SCHEMA, PUBLIC_PROTOCOL_VERSION

EVIDENCE_DIR = Path("/private/tmp/nexus-core-v1-evidence/tg7")
SELECTION_PATH = EVIDENCE_DIR / "selection.json"
TG5_PATH = EVIDENCE_DIR / "tg5-receipt.json"
CORPUS_PATH = EVIDENCE_DIR / "corpus.json"
SHADOW_RECEIPT_PATH = EVIDENCE_DIR / "shadow-receipt.json"
REPORT_PATH = EVIDENCE_DIR / "report.json"
REPO_PATH = EVIDENCE_DIR / "repository"
ATTEMPTS_PATH = EVIDENCE_DIR / "attempts"
_PHYSICAL_ENV = "NEXUS_TG7_PHYSICAL_ACCEPTANCE"
_NON_ACCEPTANCE_REASON = "NON_ACCEPTANCE_PHYSICAL_DEPENDENCY_REQUIRED:TG7"

SELF_TEST_SYNTHETIC_SELECTION = {
    "schema": "nexus.core-v1.tg7-selection.v1",
    "canonical_url": "https://github.com/bottlepy/bottle",
    "owner": "bottlepy",
    "name": "bottle",
    "commit": "62d7e076e1f7d10ed4d9e13314df32c6a1e80173",
    "tree": "4142f8e43ed54bc57bd83306cddf467f4b82f0b8",
    "snapshot_path": "/private/tmp/nexus-core-v1-evidence/tg7/repository",
    "snapshot_tree_hash": "sha256:c2603ef6f90072e8f9330929d1ed794176dffee9031eeec3937c001d3ef1080b",
    "observed_at": "2026-09-05T06:27:00Z",
    "license_spdx": "MIT",
    "license_evidence_hash": "sha256:43afd5c761e9359d3111aaecf4b85a72558d5c9be035c097f8f243f4ee725c2f",
    "privacy_class": "PUBLIC_OPEN_SOURCE",
    "read_only_evidence_hash": "sha256:1870a1eba45d4e33dacbbbef9b1d87e5c46eacedfa3dbab4204ca00cbd94543c",
    "task_set_id": "tg7-shadow-bottle-v1",
    "not_nexus_reason": "External standalone Python WSGI micro-framework repository independent from Nexus-new",
    "selection_hash": "sha256:d744a17710cbce7b8ec3f339b13fd8739a909bc352f8a71bd277245e274db4c3",
}

SELF_TEST_SYNTHETIC_TG5 = {
    "acceptance_contract_hash": "sha256:18bb65e9224e58421c0bd57cc60ba8f1da5e2237a90d6d46567094e974247a56",
    "certification": {
        "disposition": "CERTIFIED",
        "policy": {
            "accepted": True,
            "approval_present": True,
            "authority_present": True,
            "signing_present": True,
        },
    },
    "change_set_hash": "sha256:18263cd15a306fcc58b9d7b0625b98d9b45166c01dd373d57849f9a25d7cd16b",
    "claim_ceiling": [
        "NO_MERGE_AUTHORIZATION",
        "NO_DEPLOYMENT_TRUTH",
        "NO_OUTCOME_TRUTH",
        "NO_PRODUCTION_READINESS",
        "NO_PUBLIC_PROTOCOL_STABILITY",
    ],
    "evidence_hash": "sha256:42a64047fd708624a4a8b821e7022070b38e824d78144042705d8612202bb6f6",
    "implementation_schema": "nexus.changeset_certification.v2",
    "protocol_version": "0.1.0-experimental",
    "receipt_hash": "sha256:c326b1678a2abaf0949a892ac45c7e9476ab928554e407fa5cbd43f571446d43",
    "receipt_schema": "nexus.certification_receipt.v1-experimental",
    "verification": {"condition": "VALID", "reason_codes": [], "status": "VERIFIED"},
    "verification_plan_hash": "sha256:913bf41a4af7377e9ed7cd47bc06ed1bfb0730b5eadbc89bb3a386db9bd73a61",
}


def _rehash(payload: dict[str, Any], hash_key: str) -> dict[str, Any]:
    body = {k: v for k, v in payload.items() if k != hash_key}
    return {**body, hash_key: _digest(body)}


@pytest.fixture(scope="module")
def self_test_selection() -> dict[str, Any]:
    return copy.deepcopy(SELF_TEST_SYNTHETIC_SELECTION)


@pytest.fixture(scope="module")
def self_test_tg5() -> dict[str, Any]:
    return copy.deepcopy(SELF_TEST_SYNTHETIC_TG5)


@pytest.fixture(scope="module")
def self_test_corpus(self_test_selection: dict[str, Any]) -> dict[str, Any]:
    return build_default_corpus(self_test_selection)


def _make_attempt(
    case: dict[str, Any],
    selection: dict[str, Any],
    tg5: dict[str, Any],
    *,
    material_hash: str = "sha256:" + "d" * 64,
) -> dict[str, Any]:
    attempt = {
        "schema": ATTEMPT_RECEIPT_SCHEMA,
        "issuer_id": "nexus.service.v1",
        "producer_id": "nexus.controller.v1",
        "attempt_id": f"att-{case['case_id']}",
        "execution_id": f"exec-{case['case_id']}",
        "case_id": case["case_id"],
        "case_hash": case["case_hash"],
        "hostile_family": case["hostile_family"],
        "repository_commit": selection["commit"],
        "repository_tree": selection["tree"],
        "external_material_hash": material_hash,
        "canonical_request_hash": case["canonical_request_hash"],
        "oracle_hash": case["oracle_hash"],
        "oracle_source": case["oracle_source"],
        "profile_id": PROFILE_ID,
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "implementation_schema": IMPLEMENTATION_SCHEMA,
        "tg5_receipt_hash": tg5["receipt_hash"],
        "actual_status": case["expected_status"],
        "actual_disposition": case["expected_disposition"],
        "evidence_hash": "sha256:" + "e" * 64,
        "runner_result_hash": "sha256:" + "f" * 64,
        "infra_invalid": False,
        "infra_invalid_reason": None,
        "observed_at": "2026-09-05T07:00:00Z",
    }
    attempt["attempt_hash"] = _digest(attempt)
    return attempt


def test_negative_forged_selection_and_missing_fields(self_test_selection: dict[str, Any]):
    mutated = copy.deepcopy(self_test_selection)
    del mutated["canonical_url"]
    assert validate_selection(mutated)
    tampered = copy.deepcopy(self_test_selection)
    tampered["selection_hash"] = "sha256:" + "0" * 64
    assert any("selection_hash" in error for error in validate_selection(tampered))
    extra = copy.deepcopy(self_test_selection)
    extra["malicious_extra"] = "payload"
    assert any("unknown keys" in error for error in validate_selection(extra))


def test_negative_illegal_license_rejected(self_test_selection: dict[str, Any]):
    for bad_license in ("GPL-3.0", "AGPL-3.0", "Proprietary", "UNKNOWN"):
        mutated = copy.deepcopy(self_test_selection)
        mutated["license_spdx"] = bad_license
        mutated = _rehash(mutated, "selection_hash")
        assert any("license_spdx" in error for error in validate_selection(mutated))


def test_negative_repository_tree_or_commit_tamper(
    self_test_selection: dict[str, Any], self_test_corpus: dict[str, Any]
):
    bad_commit = copy.deepcopy(self_test_selection)
    bad_commit["commit"] = "0" * 40
    bad_commit = _rehash(bad_commit, "selection_hash")
    assert any(
        "commit mismatch" in error for error in validate_corpus(self_test_corpus, bad_commit)
    )
    bad_tree = copy.deepcopy(self_test_selection)
    bad_tree["tree"] = "0" * 40
    bad_tree = _rehash(bad_tree, "selection_hash")
    assert any("tree mismatch" in error for error in validate_corpus(self_test_corpus, bad_tree))


def test_negative_missing_or_forged_oracle(
    self_test_selection: dict[str, Any], self_test_corpus: dict[str, Any]
):
    tampered = copy.deepcopy(self_test_corpus)
    tampered["cases"][0]["oracle_hash"] = "sha256:" + "f" * 64
    tampered["cases"][0]["case_hash"] = _digest({
        k: v for k, v in tampered["cases"][0].items() if k != "case_hash"
    })
    tampered = _rehash(tampered, "corpus_hash")
    assert any("oracle_hash" in error for error in validate_corpus(tampered, self_test_selection))


def test_negative_denominator_below_50_or_family_below_5(
    self_test_selection: dict[str, Any], self_test_corpus: dict[str, Any]
):
    truncated = copy.deepcopy(self_test_corpus)
    truncated["cases"] = truncated["cases"][:40]
    truncated["case_count"] = 40
    truncated = _rehash(truncated, "corpus_hash")
    assert any(">= 50" in error for error in validate_corpus(truncated, self_test_selection))
    skewed = copy.deepcopy(self_test_corpus)
    skewed["cases"] = [
        case for case in skewed["cases"] if case["hostile_family"] != "AUTH_ISSUER_TAMPER"
    ]
    skewed["case_count"] = len(skewed["cases"])
    skewed = _rehash(skewed, "corpus_hash")
    assert any(
        "AUTH_ISSUER_TAMPER" in error for error in validate_corpus(skewed, self_test_selection)
    )


def test_negative_attempt_receipt_cannot_self_assert_authority(
    self_test_selection: dict[str, Any],
    self_test_corpus: dict[str, Any],
    self_test_tg5: dict[str, Any],
):
    case = self_test_corpus["cases"][0]
    material_hash = "sha256:" + "d" * 64
    valid = _make_attempt(case, self_test_selection, self_test_tg5, material_hash=material_hash)
    assert (
        validate_attempt_receipt(
            valid,
            case=case,
            selection=self_test_selection,
            tg5_receipt=self_test_tg5,
            external_material_hash=material_hash,
        )
        == []
    )

    for field, bad_value in (
        ("issuer_id", "tg7.worker.local"),
        ("producer_id", "tg7.worker.local"),
        ("profile_id", "synthetic-profile"),
        ("tg5_receipt_hash", "sha256:" + "0" * 64),
        ("external_material_hash", "sha256:" + "1" * 64),
    ):
        tampered = copy.deepcopy(valid)
        tampered[field] = bad_value
        tampered = _rehash(tampered, "attempt_hash")
        errors = validate_attempt_receipt(
            tampered,
            case=case,
            selection=self_test_selection,
            tg5_receipt=self_test_tg5,
            external_material_hash=material_hash,
        )
        assert errors, f"attempt tamper {field} was accepted"

    forged_hash = copy.deepcopy(valid)
    forged_hash["attempt_hash"] = "sha256:" + "a" * 64
    assert any(
        "attempt_hash" in error
        for error in validate_attempt_receipt(
            forged_hash,
            case=case,
            selection=self_test_selection,
            tg5_receipt=self_test_tg5,
            external_material_hash=material_hash,
        )
    )


def test_negative_tg5_receipt_mismatch_or_stale(self_test_tg5: dict[str, Any]):
    bad_tg5 = copy.deepcopy(self_test_tg5)
    bad_tg5["verification"]["status"] = "UNVERIFIABLE"
    bad_tg5 = _rehash(bad_tg5, "receipt_hash")
    assert any("VERIFIED" in error for error in validate_tg5_receipt(bad_tg5))


def test_negative_forged_infra_invalid_reasons(
    self_test_selection: dict[str, Any],
    self_test_corpus: dict[str, Any],
    self_test_tg5: dict[str, Any],
):
    case = self_test_corpus["cases"][0]
    result = {
        "case_id": case["case_id"],
        "hostile_family": case["hostile_family"],
        "attempt_id": "att-1",
        "attempt_hash": "sha256:" + "a" * 64,
        "oracle_hash": case["oracle_hash"],
        "actual_status": "INFRA_INVALID",
        "actual_disposition": "BLOCKED",
        "evidence_hash": "sha256:" + "c" * 64,
        "infra_invalid": True,
        "infra_invalid_reason": "UNAUTHORIZED_FORGED_REASON",
    }
    result["result_hash"] = _digest({
        "case_id": result["case_id"],
        "attempt_hash": result["attempt_hash"],
        "oracle_hash": result["oracle_hash"],
        "actual_status": result["actual_status"],
        "actual_disposition": result["actual_disposition"],
    })
    shadow = {
        "schema": "nexus.core-v1.tg7-shadow-receipt.v1",
        "run_id": "self-test-run",
        "tg5_receipt_hash": self_test_tg5["receipt_hash"],
        "selection_hash": self_test_selection["selection_hash"],
        "corpus_hash": self_test_corpus["corpus_hash"],
        "task_set_id": "tg7-shadow-bottle-v1",
        "repository": {
            "owner": self_test_selection["owner"],
            "name": self_test_selection["name"],
            "commit": self_test_selection["commit"],
            "tree": self_test_selection["tree"],
        },
        "eligible_count": 55,
        "infra_invalid_count": 1,
        "cases": [result],
    }
    shadow["receipt_hash"] = _digest(shadow)
    errors = validate_shadow_receipt(
        shadow,
        corpus=self_test_corpus,
        tg5_receipt=self_test_tg5,
        selection=self_test_selection,
    )
    assert any("infra reason" in error for error in errors)


def test_negative_false_certification_detection_fails_closed(
    self_test_selection: dict[str, Any],
    self_test_corpus: dict[str, Any],
    self_test_tg5: dict[str, Any],
):
    report = {
        "schema": "nexus.core-v1.tg7-report.v1",
        "task_set_id": "tg7-shadow-bottle-v1",
        "shadow_receipt_hash": "sha256:" + "a" * 64,
        "selection_hash": self_test_selection["selection_hash"],
        "tg5_receipt_hash": self_test_tg5["receipt_hash"],
        "generated_at": "2026-09-05T06:45:00Z",
        "denominator": len(self_test_corpus["cases"]),
        "eligible_count": len(self_test_corpus["cases"]),
        "infra_invalid_count": 0,
        "family_counts": {family: 7 for family in HOSTILE_FAMILIES},
        "false_certification_count": 1,
        "false_certification_case_ids": [self_test_corpus["cases"][0]["case_id"]],
        "trust_mismatches": 0,
        "maximum_claim": MAXIMUM_CLAIM,
    }
    report = _rehash(report, "report_hash")
    assert any("HIGH RISK FALSE CERTIFICATION" in error for error in validate_report(report))


def test_negative_selection_cannot_be_nexus_new(self_test_selection: dict[str, Any]):
    bad_selection = copy.deepcopy(self_test_selection)
    bad_selection["name"] = "Nexus-new"
    bad_selection = _rehash(bad_selection, "selection_hash")
    assert any("Nexus-new" in error for error in validate_selection(bad_selection))


def _physical_evidence_paths() -> tuple[Path, ...]:
    return (
        SELECTION_PATH,
        TG5_PATH,
        CORPUS_PATH,
        SHADOW_RECEIPT_PATH,
        REPORT_PATH,
        REPO_PATH,
        ATTEMPTS_PATH,
    )


def _require_physical_evidence(request: pytest.FixtureRequest) -> bool:
    """Generic CI records NON_ACCEPTANCE; explicit physical mode fails on any gap."""
    if os.environ.get(_PHYSICAL_ENV) != "1":
        request.node.user_properties.append(("nexus_acceptance_mode", _NON_ACCEPTANCE_REASON))
        return False
    missing = [str(path) for path in _physical_evidence_paths() if not path.exists()]
    assert not missing, "TG7_PHYSICAL_ACCEPTANCE_DEPENDENCY_MISSING:" + ",".join(missing)
    request.node.user_properties.append(("nexus_acceptance_mode", "PHYSICAL_ACCEPTANCE"))
    return True


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_tg7_selection_manifest_conformance(request: pytest.FixtureRequest):
    if not _require_physical_evidence(request):
        return
    selection = _load_json(SELECTION_PATH)
    assert validate_selection(selection, repo_path=REPO_PATH) == []
    assert selection["license_spdx"] in ALLOWED_LICENSES
    assert selection["name"] == "bottle"
    assert selection["owner"] == "bottlepy"
    assert selection["privacy_class"] == "PUBLIC_OPEN_SOURCE"


def test_tg7_tg5_receipt_conformance(request: pytest.FixtureRequest):
    if not _require_physical_evidence(request):
        return
    tg5 = _load_json(TG5_PATH)
    assert validate_tg5_receipt(tg5) == []
    assert tg5["verification"]["status"] == "VERIFIED"
    assert tg5["certification"]["disposition"] == "CERTIFIED"


def test_tg7_corpus_manifest_conformance(request: pytest.FixtureRequest):
    if not _require_physical_evidence(request):
        return
    selection = _load_json(SELECTION_PATH)
    corpus = _load_json(CORPUS_PATH)
    assert validate_corpus(corpus, selection=selection) == []
    assert len(corpus["cases"]) >= 50
    for family in HOSTILE_FAMILIES:
        assert sum(case["hostile_family"] == family for case in corpus["cases"]) >= 5


def test_tg7_attempt_inventory_conformance(request: pytest.FixtureRequest):
    if not _require_physical_evidence(request):
        return
    selection = _load_json(SELECTION_PATH)
    corpus = _load_json(CORPUS_PATH)
    tg5 = _load_json(TG5_PATH)
    bottle_hash = "sha256:" + hashlib.sha256((REPO_PATH / "bottle.py").read_bytes()).hexdigest()
    assert ATTEMPTS_PATH.is_dir()
    assert not (ATTEMPTS_PATH.stat().st_mode & 0o222)
    expected_files = {f"{case['case_id']}.json" for case in corpus["cases"]}
    assert {path.name for path in ATTEMPTS_PATH.glob("*.json")} == expected_files
    for case in corpus["cases"]:
        path = ATTEMPTS_PATH / f"{case['case_id']}.json"
        assert not (path.stat().st_mode & 0o222)
        raw = path.read_bytes()
        attempt = json.loads(raw.decode("utf-8"))
        assert raw == (_canonical(attempt) + "\n").encode("utf-8")
        assert (
            validate_attempt_receipt(
                attempt,
                case=case,
                selection=selection,
                tg5_receipt=tg5,
                external_material_hash=bottle_hash,
            )
            == []
        )


def test_tg7_shadow_receipt_conformance(request: pytest.FixtureRequest):
    if not _require_physical_evidence(request):
        return
    selection = _load_json(SELECTION_PATH)
    corpus = _load_json(CORPUS_PATH)
    tg5 = _load_json(TG5_PATH)
    shadow = _load_json(SHADOW_RECEIPT_PATH)
    assert (
        validate_shadow_receipt(shadow, corpus=corpus, tg5_receipt=tg5, selection=selection) == []
    )
    assert shadow["eligible_count"] >= 50
    assert shadow["infra_invalid_count"] == 0
    assert len(shadow["cases"]) == len(corpus["cases"])


def test_tg7_report_conformance_and_zero_false_cert(request: pytest.FixtureRequest):
    if not _require_physical_evidence(request):
        return
    corpus = _load_json(CORPUS_PATH)
    shadow = _load_json(SHADOW_RECEIPT_PATH)
    report = _load_json(REPORT_PATH)
    assert validate_report(report, shadow_receipt=shadow, corpus=corpus) == []
    assert report["false_certification_count"] == 0
    assert report["false_certification_case_ids"] == []
    assert report["denominator"] >= 50
    assert report["maximum_claim"] == MAXIMUM_CLAIM
    assert sum(report["family_counts"].values()) == report["denominator"]
