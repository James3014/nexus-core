"""TG-7 representative corpus and second-repository shadow verifier.

The benchmark is deliberately not an execution or receipt authority.  A
controller materializes the selected public repository, the accepted TG-5
receipt, the immutable corpus, and one read-only TG-5 attempt receipt per case.
TG-7 validates and reduces those artifacts into a bounded shadow receipt and
report.  Missing, writable, synthetic, stale, or mismatched attempt evidence
fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from product.benchmark import _canonical, _digest
from product.certification.receipt import CLAIM_CEILING
from product.protocol import (
    CERTIFICATION_RECEIPT_SCHEMA,
    IMPLEMENTATION_SCHEMA,
    PUBLIC_PROTOCOL_VERSION,
)

SELECTION_SCHEMA = "nexus.core-v1.tg7-selection.v1"
CORPUS_SCHEMA = "nexus.core-v1.tg7-corpus.v1"
ATTEMPT_RECEIPT_SCHEMA = "nexus.core-v1.tg7-attempt-receipt.v2"
SHADOW_RECEIPT_SCHEMA = "nexus.core-v1.tg7-shadow-receipt.v1"
REPORT_SCHEMA = "nexus.core-v1.tg7-report.v1"

MAXIMUM_CLAIM = "CROSS_REPO_TRUST_SHADOW_VERIFIED"
PROFILE_ID = "python-oci-pytest-v1"
TASK_SET_ID = "tg7-shadow-bottle-v1"

HOSTILE_FAMILIES = (
    "AUTH_ISSUER_TAMPER",
    "PROVENANCE_HASH_TAMPER",
    "STALE_REVISION_GENERATION",
    "DUPLICATE_REPLAY_CONFLICT",
    "MALFORMED_PROTOCOL_SCHEMA",
    "MISSING_INADEQUATE_ORACLE",
    "PATH_SCOPE_ESCAPE",
    "CRASH_UNKNOWN_EFFECT",
)

ALLOWED_LICENSES = frozenset({"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC"})
INFRA_INVALID_REASONS = frozenset({
    "MATERIALIZATION_MISSING",
    "RUNNER_UNAVAILABLE_BEFORE_EXECUTION",
    "DEPENDENCY_ARTIFACT_MISSING",
    "TIMEOUT_BEFORE_EXECUTION",
    "CORRUPT_FIXTURE",
})

SELECTION_REQUIRED_KEYS = frozenset({
    "schema",
    "canonical_url",
    "owner",
    "name",
    "commit",
    "tree",
    "snapshot_path",
    "snapshot_tree_hash",
    "observed_at",
    "license_spdx",
    "license_evidence_hash",
    "privacy_class",
    "read_only_evidence_hash",
    "task_set_id",
    "not_nexus_reason",
    "selection_hash",
})
CORPUS_REQUIRED_KEYS = frozenset({
    "schema",
    "task_set_id",
    "repository",
    "case_count",
    "cases",
    "corpus_hash",
})
CORPUS_CASE_REQUIRED_KEYS = frozenset({
    "case_id",
    "hostile_family",
    "repository_commit",
    "repository_tree",
    "operation",
    "canonical_request_hash",
    "request_payload",
    "oracle_kind",
    "oracle_source",
    "oracle_hash",
    "expected_status",
    "expected_disposition",
    "expected_reason",
    "protocol_version",
    "implementation_schema",
    "profile_id",
    "task_set_id",
    "case_hash",
})
ATTEMPT_REQUIRED_KEYS = frozenset({
    "schema",
    "issuer_id",
    "producer_id",
    "attempt_id",
    "execution_id",
    "case_id",
    "case_hash",
    "hostile_family",
    "repository_commit",
    "repository_tree",
    "external_material_hash",
    "canonical_request_hash",
    "oracle_hash",
    "oracle_source",
    "profile_id",
    "protocol_version",
    "implementation_schema",
    "tg5_receipt_hash",
    "actual_status",
    "actual_disposition",
    "evidence_hash",
    "runner_result_hash",
    "infra_invalid",
    "infra_invalid_reason",
    "observed_at",
    "attempt_hash",
})
SHADOW_CASE_REQUIRED_KEYS = frozenset({
    "case_id",
    "hostile_family",
    "attempt_id",
    "attempt_hash",
    "oracle_hash",
    "result_hash",
    "actual_status",
    "actual_disposition",
    "evidence_hash",
    "infra_invalid",
    "infra_invalid_reason",
})


def _sha256_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(ch in "0123456789abcdef" for ch in value[7:])
    )


def _git_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _aware_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def validate_selection(
    selection: Mapping[str, Any], repo_path: Path | str | None = None
) -> list[str]:
    errors: list[str] = []
    if not isinstance(selection, Mapping):
        return ["selection must be a JSON object"]
    keys = set(selection)
    if keys != SELECTION_REQUIRED_KEYS:
        missing = SELECTION_REQUIRED_KEYS - keys
        extra = keys - SELECTION_REQUIRED_KEYS
        if missing:
            errors.append(f"selection missing keys: {sorted(missing)}")
        if extra:
            errors.append(f"selection unknown keys: {sorted(extra)}")
        return errors
    if selection.get("schema") != SELECTION_SCHEMA:
        errors.append(f"selection schema must be {SELECTION_SCHEMA}")
    body = {k: v for k, v in selection.items() if k != "selection_hash"}
    if selection.get("selection_hash") != _digest(body):
        errors.append("selection_hash does not match canonical digest of body")
    if selection.get("task_set_id") != TASK_SET_ID:
        errors.append(f"selection task_set_id must be {TASK_SET_ID}")
    if selection.get("privacy_class") != "PUBLIC_OPEN_SOURCE":
        errors.append("selection privacy_class must be PUBLIC_OPEN_SOURCE")
    if selection.get("license_spdx") not in ALLOWED_LICENSES:
        errors.append("selection license_spdx is not in the allowed public-license set")
    if selection.get("name") == "Nexus-new" or "Nexus-new" in str(selection.get("canonical_url")):
        errors.append("second repository selection cannot be Nexus-new")
    if not _git_sha(selection.get("commit")):
        errors.append("selection commit must be a full lowercase immutable SHA")
    if not _git_sha(selection.get("tree")):
        errors.append("selection tree must be a full lowercase immutable SHA")
    for key in ("snapshot_tree_hash", "license_evidence_hash", "read_only_evidence_hash"):
        if not _sha256_text(selection.get(key)):
            errors.append(f"selection {key} must be canonical sha256")
    if not _aware_timestamp(selection.get("observed_at")):
        errors.append("selection observed_at must be timezone-aware ISO-8601")

    if repo_path is not None:
        path = Path(repo_path)
        if not path.is_dir():
            errors.append(f"repository path does not exist: {path}")
            return errors
        try:
            actual_commit = subprocess.check_output(
                ["git", "-C", str(path), "rev-parse", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
            actual_tree = subprocess.check_output(
                ["git", "-C", str(path), "rev-parse", "HEAD^{tree}"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            errors.append(f"failed to read immutable repository identity: {exc}")
        else:
            if actual_commit != selection.get("commit"):
                errors.append("repository HEAD commit does not match selection")
            if actual_tree != selection.get("tree"):
                errors.append("repository HEAD tree does not match selection")
        if path.stat().st_mode & 0o222:
            errors.append("repository directory is not read-only")
    return errors


def validate_tg5_receipt(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(receipt, Mapping):
        return ["tg5-receipt must be a JSON object"]
    if receipt.get("receipt_schema") != CERTIFICATION_RECEIPT_SCHEMA:
        errors.append(f"tg5-receipt schema must be {CERTIFICATION_RECEIPT_SCHEMA}")
    if receipt.get("protocol_version") != PUBLIC_PROTOCOL_VERSION:
        errors.append(f"tg5-receipt protocol_version must be {PUBLIC_PROTOCOL_VERSION}")
    if receipt.get("implementation_schema") != IMPLEMENTATION_SCHEMA:
        errors.append(f"tg5-receipt implementation_schema must be {IMPLEMENTATION_SCHEMA}")
    body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
    if receipt.get("receipt_hash") != _digest(body):
        errors.append("tg5-receipt receipt_hash does not match canonical digest of body")
    verification = receipt.get("verification", {})
    if not isinstance(verification, Mapping) or verification.get("status") != "VERIFIED":
        errors.append("tg5-receipt verification.status must be VERIFIED")
    certification = receipt.get("certification", {})
    if not isinstance(certification, Mapping) or certification.get("disposition") != "CERTIFIED":
        errors.append("tg5-receipt certification.disposition must be CERTIFIED")
    return errors


def validate_corpus(
    corpus: Mapping[str, Any], selection: Mapping[str, Any] | None = None
) -> list[str]:
    errors: list[str] = []
    if not isinstance(corpus, Mapping):
        return ["corpus must be a JSON object"]
    keys = set(corpus)
    if keys != CORPUS_REQUIRED_KEYS:
        missing = CORPUS_REQUIRED_KEYS - keys
        extra = keys - CORPUS_REQUIRED_KEYS
        if missing:
            errors.append(f"corpus missing keys: {sorted(missing)}")
        if extra:
            errors.append(f"corpus unknown keys: {sorted(extra)}")
        return errors
    if corpus.get("schema") != CORPUS_SCHEMA:
        errors.append(f"corpus schema must be {CORPUS_SCHEMA}")
    body = {k: v for k, v in corpus.items() if k != "corpus_hash"}
    if corpus.get("corpus_hash") != _digest(body):
        errors.append("corpus_hash does not match canonical digest of body")
    if corpus.get("task_set_id") != TASK_SET_ID:
        errors.append(f"corpus task_set_id must be {TASK_SET_ID}")
    cases = corpus.get("cases")
    if not isinstance(cases, list):
        return [*errors, "corpus cases must be a list"]
    if corpus.get("case_count") != len(cases):
        errors.append("corpus case_count does not equal physical case count")
    if len(cases) < 50:
        errors.append(f"corpus eligible case denominator must be >= 50, found {len(cases)}")

    if selection is not None:
        repo = corpus.get("repository")
        expected_repo = {
            "owner": selection.get("owner"),
            "name": selection.get("name"),
            "commit": selection.get("commit"),
            "tree": selection.get("tree"),
        }
        if repo != expected_repo:
            errors.append("corpus repository identity does not match selection")

    seen: set[str] = set()
    ordered: list[str] = []
    family_counts = {family: 0 for family in HOSTILE_FAMILIES}
    for index, case in enumerate(cases):
        if not isinstance(case, Mapping):
            errors.append(f"case at index {index} must be a JSON object")
            continue
        case_keys = set(case)
        if case_keys != CORPUS_CASE_REQUIRED_KEYS:
            missing = CORPUS_CASE_REQUIRED_KEYS - case_keys
            extra = case_keys - CORPUS_CASE_REQUIRED_KEYS
            if missing:
                errors.append(f"case[{index}] missing keys: {sorted(missing)}")
            if extra:
                errors.append(f"case[{index}] unknown keys: {sorted(extra)}")
            continue
        cid = case.get("case_id")
        if not isinstance(cid, str) or not cid:
            errors.append(f"case[{index}] missing case_id")
            continue
        if cid in seen:
            errors.append(f"duplicate case_id: {cid}")
        seen.add(cid)
        ordered.append(cid)
        case_body = {k: v for k, v in case.items() if k != "case_hash"}
        if case.get("case_hash") != _digest(case_body):
            errors.append(f"case[{cid}] case_hash mismatch")
        family = case.get("hostile_family")
        if family not in HOSTILE_FAMILIES:
            errors.append(f"case[{cid}] invalid hostile_family: {family}")
        else:
            family_counts[str(family)] += 1
        if selection is not None:
            if case.get("repository_commit") != selection.get("commit"):
                errors.append(f"case[{cid}] repository_commit mismatch with selection")
            if case.get("repository_tree") != selection.get("tree"):
                errors.append(f"case[{cid}] repository_tree mismatch with selection")
        if case.get("canonical_request_hash") != _digest(case.get("request_payload")):
            errors.append(f"case[{cid}] canonical_request_hash mismatch")
        oracle_kind = case.get("oracle_kind")
        expected_oracle_hash = _digest({
            "source": case.get("oracle_source"),
            "kind": oracle_kind,
            "reason": case.get("expected_reason"),
        })
        if not isinstance(oracle_kind, str) or not oracle_kind:
            errors.append(f"case[{cid}] missing or empty oracle_kind")
        if case.get("oracle_hash") != expected_oracle_hash:
            errors.append(f"case[{cid}] oracle_hash mismatch with oracle source/kind/reason")
        if case.get("protocol_version") != PUBLIC_PROTOCOL_VERSION:
            errors.append(f"case[{cid}] protocol_version mismatch")
        if case.get("implementation_schema") != IMPLEMENTATION_SCHEMA:
            errors.append(f"case[{cid}] implementation_schema mismatch")
        if case.get("profile_id") != PROFILE_ID:
            errors.append(f"case[{cid}] profile_id mismatch")
        if case.get("task_set_id") != TASK_SET_ID:
            errors.append(f"case[{cid}] task_set_id mismatch")
    if ordered != sorted(ordered):
        errors.append("case_ids must be strictly in sorted order")
    for family, count in family_counts.items():
        if count < 5:
            errors.append(f"hostile family {family} has fewer than 5 cases: {count}")
    return errors


def validate_attempt_receipt(
    attempt: Mapping[str, Any],
    *,
    case: Mapping[str, Any],
    selection: Mapping[str, Any],
    tg5_receipt: Mapping[str, Any],
    external_material_hash: str,
) -> list[str]:
    """Validate one controller-staged TG-5 attempt; TG-7 never issues it."""
    errors: list[str] = []
    if not isinstance(attempt, Mapping):
        return ["attempt receipt must be a JSON object"]
    keys = set(attempt)
    if keys != ATTEMPT_REQUIRED_KEYS:
        missing = ATTEMPT_REQUIRED_KEYS - keys
        extra = keys - ATTEMPT_REQUIRED_KEYS
        if missing:
            errors.append(f"attempt missing keys: {sorted(missing)}")
        if extra:
            errors.append(f"attempt unknown keys: {sorted(extra)}")
        return errors
    body = {k: v for k, v in attempt.items() if k != "attempt_hash"}
    if attempt.get("attempt_hash") != _digest(body):
        errors.append("attempt_hash does not match canonical attempt body")
    if attempt.get("schema") != ATTEMPT_RECEIPT_SCHEMA:
        errors.append(f"attempt schema must be {ATTEMPT_RECEIPT_SCHEMA}")
    if attempt.get("issuer_id") != "nexus.service.v1":
        errors.append("attempt issuer_id must be nexus.service.v1")
    if attempt.get("producer_id") != "nexus.controller.v1":
        errors.append("attempt producer_id must be nexus.controller.v1")
    if not isinstance(attempt.get("attempt_id"), str) or not attempt.get("attempt_id"):
        errors.append("attempt_id must be non-empty")
    if not isinstance(attempt.get("execution_id"), str) or not attempt.get("execution_id"):
        errors.append("execution_id must be non-empty")
    binding_pairs = (
        ("case_id", case.get("case_id")),
        ("case_hash", case.get("case_hash")),
        ("hostile_family", case.get("hostile_family")),
        ("repository_commit", selection.get("commit")),
        ("repository_tree", selection.get("tree")),
        ("external_material_hash", external_material_hash),
        ("canonical_request_hash", case.get("canonical_request_hash")),
        ("oracle_hash", case.get("oracle_hash")),
        ("oracle_source", case.get("oracle_source")),
        ("profile_id", PROFILE_ID),
        ("protocol_version", PUBLIC_PROTOCOL_VERSION),
        ("implementation_schema", IMPLEMENTATION_SCHEMA),
        ("tg5_receipt_hash", tg5_receipt.get("receipt_hash")),
    )
    for key, expected in binding_pairs:
        if attempt.get(key) != expected:
            errors.append(f"attempt {key} binding mismatch")
    for key in ("external_material_hash", "evidence_hash", "runner_result_hash", "attempt_hash"):
        if not _sha256_text(attempt.get(key)):
            errors.append(f"attempt {key} must be canonical sha256")
    if not _aware_timestamp(attempt.get("observed_at")):
        errors.append("attempt observed_at must be timezone-aware ISO-8601")
    infra_invalid = attempt.get("infra_invalid")
    reason = attempt.get("infra_invalid_reason")
    if not isinstance(infra_invalid, bool):
        errors.append("attempt infra_invalid must be boolean")
    elif infra_invalid:
        if reason not in INFRA_INVALID_REASONS:
            errors.append("attempt infra_invalid_reason is outside the closed taxonomy")
        if attempt.get("actual_status") != "INFRA_INVALID":
            errors.append("infra-invalid attempt must use actual_status=INFRA_INVALID")
    else:
        if reason is not None:
            errors.append("eligible attempt must not carry infra_invalid_reason")
        if attempt.get("actual_status") == "INFRA_INVALID":
            errors.append("eligible attempt cannot use actual_status=INFRA_INVALID")
    if not isinstance(attempt.get("actual_status"), str) or not attempt.get("actual_status"):
        errors.append("attempt actual_status must be non-empty")
    if not isinstance(attempt.get("actual_disposition"), str) or not attempt.get(
        "actual_disposition"
    ):
        errors.append("attempt actual_disposition must be non-empty")
    return errors


def validate_shadow_receipt(
    shadow_receipt: Mapping[str, Any],
    corpus: Mapping[str, Any] | None = None,
    tg5_receipt: Mapping[str, Any] | None = None,
    selection: Mapping[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(shadow_receipt, Mapping):
        return ["shadow_receipt must be a JSON object"]
    if shadow_receipt.get("schema") != SHADOW_RECEIPT_SCHEMA:
        errors.append(f"shadow_receipt schema must be {SHADOW_RECEIPT_SCHEMA}")
    body = {k: v for k, v in shadow_receipt.items() if k != "receipt_hash"}
    if shadow_receipt.get("receipt_hash") != _digest(body):
        errors.append("shadow_receipt receipt_hash does not match canonical digest of body")
    if selection is not None and shadow_receipt.get("selection_hash") != selection.get(
        "selection_hash"
    ):
        errors.append("shadow_receipt selection_hash mismatch with selection.json")
    if tg5_receipt is not None and shadow_receipt.get("tg5_receipt_hash") != tg5_receipt.get(
        "receipt_hash"
    ):
        errors.append("shadow_receipt tg5_receipt_hash mismatch with tg5-receipt.json")
    if corpus is not None and shadow_receipt.get("corpus_hash") != corpus.get("corpus_hash"):
        errors.append("shadow_receipt corpus_hash mismatch with corpus.json")
    if shadow_receipt.get("task_set_id") != TASK_SET_ID:
        errors.append("shadow_receipt task_set_id mismatch")
    cases = shadow_receipt.get("cases")
    if not isinstance(cases, list):
        return [*errors, "shadow_receipt cases must be a list"]
    eligible = shadow_receipt.get("eligible_count")
    infra = shadow_receipt.get("infra_invalid_count")
    if not isinstance(eligible, int) or eligible < 50:
        errors.append(f"shadow_receipt eligible_count must be >= 50, found {eligible}")
    if not isinstance(infra, int) or infra < 0:
        errors.append("shadow_receipt infra_invalid_count must be non-negative integer")
    actual_infra = 0
    case_ids: list[str] = []
    for item in cases:
        if not isinstance(item, Mapping):
            errors.append("shadow_receipt case must be an object")
            continue
        if set(item) != SHADOW_CASE_REQUIRED_KEYS:
            errors.append(f"shadow_receipt case[{item.get('case_id')}] keys mismatch")
            continue
        case_ids.append(str(item.get("case_id")))
        if not _sha256_text(item.get("attempt_hash")):
            errors.append(f"case[{item.get('case_id')}] invalid attempt_hash")
        if not _sha256_text(item.get("evidence_hash")):
            errors.append(f"case[{item.get('case_id')}] invalid evidence_hash")
        expected_result_hash = _digest({
            "case_id": item.get("case_id"),
            "attempt_hash": item.get("attempt_hash"),
            "oracle_hash": item.get("oracle_hash"),
            "actual_status": item.get("actual_status"),
            "actual_disposition": item.get("actual_disposition"),
        })
        if item.get("result_hash") != expected_result_hash:
            errors.append(f"case[{item.get('case_id')}] result_hash mismatch")
        if item.get("infra_invalid") is True:
            actual_infra += 1
            if item.get("infra_invalid_reason") not in INFRA_INVALID_REASONS:
                errors.append(f"case[{item.get('case_id')}] invalid infra reason")
            if item.get("actual_status") != "INFRA_INVALID":
                errors.append(f"case[{item.get('case_id')}] infra status mismatch")
        elif item.get("infra_invalid_reason") is not None:
            errors.append(f"case[{item.get('case_id')}] eligible case carries infra reason")
    if isinstance(eligible, int) and isinstance(infra, int):
        if eligible + infra != len(cases):
            errors.append("shadow_receipt arithmetic mismatch")
        if infra != actual_infra:
            errors.append("shadow_receipt infra_invalid_count disagrees with case rows")
    if corpus is not None:
        expected_ids = [str(case.get("case_id")) for case in corpus.get("cases", [])]
        if case_ids != expected_ids:
            errors.append("shadow_receipt case order/identity does not exactly match corpus")
    return errors


def validate_report(
    report: Mapping[str, Any],
    shadow_receipt: Mapping[str, Any] | None = None,
    corpus: Mapping[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ["report must be a JSON object"]
    if report.get("schema") != REPORT_SCHEMA:
        errors.append(f"report schema must be {REPORT_SCHEMA}")
    body = {k: v for k, v in report.items() if k != "report_hash"}
    if report.get("report_hash") != _digest(body):
        errors.append("report_hash does not match canonical digest of body")
    if report.get("maximum_claim") not in {
        "TG7_REPAIR_READY_FOR_REVIEW",
        "CROSS_REPO_TRUST_SHADOW_VERIFIED",
    }:
        errors.append("report maximum_claim exceeds the TG-7 claim vocabulary")
    denominator = report.get("denominator")
    if not isinstance(denominator, int) or denominator < 50:
        errors.append(f"report denominator must be >= 50, found {denominator}")
    family_counts = report.get("family_counts")
    if not isinstance(family_counts, Mapping):
        errors.append("report family_counts must be an object")
    else:
        for family in HOSTILE_FAMILIES:
            if family_counts.get(family, 0) < 5:
                errors.append(f"report family_counts[{family}] must be >= 5")
        if isinstance(denominator, int) and sum(family_counts.values()) != denominator:
            errors.append("report family-count arithmetic mismatch")
    if (
        report.get("false_certification_count") != 0
        or report.get("false_certification_case_ids") != []
    ):
        errors.append("HIGH RISK FALSE CERTIFICATION reported")
    if shadow_receipt is not None:
        if report.get("shadow_receipt_hash") != shadow_receipt.get("receipt_hash"):
            errors.append("report shadow_receipt_hash mismatch")
        if denominator != shadow_receipt.get("eligible_count"):
            errors.append("report denominator differs from shadow receipt")
    if shadow_receipt is not None and corpus is not None:
        expected = {str(case.get("case_id")): case for case in corpus.get("cases", [])}
        recomputed: list[str] = []
        for row in shadow_receipt.get("cases", []):
            case = expected.get(str(row.get("case_id")))
            if case is None or row.get("infra_invalid") is True:
                continue
            if (
                case.get("expected_disposition") != "CERTIFIED"
                and row.get("actual_status") == "VERIFIED"
                and row.get("actual_disposition") == "CERTIFIED"
            ):
                recomputed.append(str(row.get("case_id")))
        if recomputed:
            errors.append(f"independent audit found false certifications: {sorted(recomputed)}")
    return errors


def build_default_corpus(selection: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic SELF_TEST corpus; it is never acceptance evidence."""
    family_contracts: dict[str, tuple[str, str, str, tuple[str, ...]]] = {
        "AUTH_ISSUER_TAMPER": (
            "product.protocol.auth",
            "UNVERIFIABLE",
            "BLOCKED",
            (
                "validate_bearer_token",
                "validate_bearer_header",
                "read_bearer_token",
                "verify_envelope_issuer",
                "validate_bearer_token_empty",
                "validate_issuer_mismatch",
                "validate_token_permissions",
            ),
        ),
        "PROVENANCE_HASH_TAMPER": (
            "product.evidence.provenance",
            "UNVERIFIABLE",
            "REJECTED",
            (
                "bundle_hash_tamper",
                "contract_hash_tamper",
                "plan_hash_tamper",
                "change_set_hash_tamper",
                "receipt_hash_tamper",
                "tree_hash_tamper",
                "runner_hash_tamper",
            ),
        ),
        "STALE_REVISION_GENERATION": (
            "product.protocol.freshness",
            "UNVERIFIABLE",
            "BLOCKED",
            (
                "stale_generation",
                "stale_base",
                "stale_head",
                "stale_slot",
                "stale_timestamp",
                "stale_tree",
                "stale_request_generation",
            ),
        ),
        "DUPLICATE_REPLAY_CONFLICT": (
            "product.protocol.idempotency",
            "UNVERIFIABLE",
            "BLOCKED",
            (
                "idempotency_payload_conflict",
                "idempotency_contract_conflict",
                "duplicate_verifier",
                "duplicate_observation",
                "duplicate_slot",
                "generation_replay",
                "concurrent_conflict",
            ),
        ),
        "MALFORMED_PROTOCOL_SCHEMA": (
            "product.protocol.schemas",
            "UNVERIFIABLE",
            "INPUT_REJECTED",
            (
                "bad_protocol",
                "bad_schema",
                "bad_profile",
                "null_repository",
                "bad_base_sha",
                "bad_head_sha",
                "bad_pr_number",
            ),
        ),
        "MISSING_INADEQUATE_ORACLE": (
            "product.evidence.oracle",
            "UNVERIFIABLE",
            "BLOCKED",
            (
                "missing_verifier",
                "empty_artifact",
                "empty_bundle",
                "plan_contract_mismatch",
                "profile_hash_mismatch",
                "missing_oracle",
                "oracle_hash_mismatch",
            ),
        ),
        "PATH_SCOPE_ESCAPE": (
            "product.evidence.scope",
            "FAILED_VERIFICATION",
            "REJECTED",
            (
                "parent_escape",
                "absolute_escape",
                "contract_scope_escape",
                "workflow_scope_escape",
                "changeset_escape",
                "dot_component_escape",
                "backslash_escape",
            ),
        ),
        "CRASH_UNKNOWN_EFFECT": (
            "product.execution.python_oci",
            "UNVERIFIABLE",
            "BLOCKED",
            (
                "runner_sigkill",
                "runner_timeout",
                "partial_ledger_write",
                "corrupt_runner_output",
                "readonly_mutation",
                "runner_oom",
                "db_lock_timeout",
            ),
        ),
    }
    cases: list[dict[str, Any]] = []
    for family in HOSTILE_FAMILIES:
        source, expected_status, expected_disposition, operations = family_contracts[family]
        slug = family.lower()
        for index, operation in enumerate(operations, start=1):
            case_id = f"tg7_{slug}_{index:03d}"
            payload = {
                "operation": operation,
                "variant": index,
                "repository_commit": selection["commit"],
                "repository_tree": selection["tree"],
            }
            reason = f"{family} deterministic hostile control {index} must fail closed"
            oracle_kind = "DETERMINISTIC_PROTOCOL_GUARD"
            case = {
                "case_id": case_id,
                "hostile_family": family,
                "repository_commit": selection["commit"],
                "repository_tree": selection["tree"],
                "operation": operation,
                "canonical_request_hash": _digest(payload),
                "request_payload": payload,
                "oracle_kind": oracle_kind,
                "oracle_source": source,
                "oracle_hash": _digest({"source": source, "kind": oracle_kind, "reason": reason}),
                "expected_status": expected_status,
                "expected_disposition": expected_disposition,
                "expected_reason": reason,
                "protocol_version": PUBLIC_PROTOCOL_VERSION,
                "implementation_schema": IMPLEMENTATION_SCHEMA,
                "profile_id": PROFILE_ID,
                "task_set_id": TASK_SET_ID,
            }
            case["case_hash"] = _digest(case)
            cases.append(case)
    cases.sort(key=lambda item: item["case_id"])
    corpus = {
        "schema": CORPUS_SCHEMA,
        "task_set_id": TASK_SET_ID,
        "repository": {
            "owner": selection["owner"],
            "name": selection["name"],
            "commit": selection["commit"],
            "tree": selection["tree"],
        },
        "case_count": len(cases),
        "cases": cases,
    }
    corpus["corpus_hash"] = _digest(corpus)
    return corpus


def _load_attempt_file(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"attempt receipt is not canonical JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"attempt receipt must be a JSON object: {path}")
    if raw != (_canonical(value) + "\n").encode("utf-8"):
        raise ValueError(f"attempt receipt bytes are not canonical: {path}")
    return value


def run_shadow(
    selection: Mapping[str, Any],
    repository_path: Path,
    corpus: Mapping[str, Any],
    tg5_receipt: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Consume immutable controller-staged attempts and reduce the TG-7 report."""
    repo_path = Path(repository_path)
    bottle_path = repo_path / "bottle.py"
    if not bottle_path.is_file():
        raise FileNotFoundError(f"external repository bottle.py missing: {bottle_path}")
    bottle_hash = "sha256:" + hashlib.sha256(bottle_path.read_bytes()).hexdigest()
    attempts_dir = repo_path.parent / "attempts"
    if not attempts_dir.is_dir():
        raise FileNotFoundError(f"controller-staged attempts directory missing: {attempts_dir}")
    if attempts_dir.stat().st_mode & 0o222:
        raise PermissionError("controller-staged attempts directory must be read-only")

    expected_files = {f"{case['case_id']}.json" for case in corpus["cases"]}
    physical_files = {path.name for path in attempts_dir.glob("*.json") if path.is_file()}
    if physical_files != expected_files:
        missing = sorted(expected_files - physical_files)
        extra = sorted(physical_files - expected_files)
        raise ValueError(f"attempt inventory mismatch; missing={missing}, extra={extra}")

    cases_results: list[dict[str, Any]] = []
    false_cert_ids: list[str] = []
    trust_mismatches = 0
    family_counts = {family: 0 for family in HOSTILE_FAMILIES}
    seen_attempt_ids: set[str] = set()
    seen_execution_ids: set[str] = set()
    observed_times: list[str] = []

    for case in corpus["cases"]:
        case_id = case["case_id"]
        family = case["hostile_family"]
        family_counts[family] += 1
        attempt_path = attempts_dir / f"{case_id}.json"
        if attempt_path.stat().st_mode & 0o222:
            raise PermissionError(f"attempt receipt must be read-only: {attempt_path}")
        attempt = _load_attempt_file(attempt_path)
        attempt_errors = validate_attempt_receipt(
            attempt,
            case=case,
            selection=selection,
            tg5_receipt=tg5_receipt,
            external_material_hash=bottle_hash,
        )
        if attempt_errors:
            raise ValueError(f"attempt[{case_id}] validation failed: {attempt_errors}")
        attempt_id = str(attempt["attempt_id"])
        execution_id = str(attempt["execution_id"])
        if attempt_id in seen_attempt_ids:
            raise ValueError(f"duplicate attempt_id across corpus: {attempt_id}")
        if execution_id in seen_execution_ids:
            raise ValueError(f"duplicate execution_id across corpus: {execution_id}")
        seen_attempt_ids.add(attempt_id)
        seen_execution_ids.add(execution_id)
        observed_times.append(str(attempt["observed_at"]))

        actual_status = str(attempt["actual_status"])
        actual_disposition = str(attempt["actual_disposition"])
        infra_invalid = bool(attempt["infra_invalid"])
        infra_reason = attempt["infra_invalid_reason"]
        if (
            not infra_invalid
            and case.get("expected_disposition") != "CERTIFIED"
            and actual_status == "VERIFIED"
            and actual_disposition == "CERTIFIED"
        ):
            false_cert_ids.append(case_id)
        if not infra_invalid and (
            actual_status != case.get("expected_status")
            or actual_disposition != case.get("expected_disposition")
        ):
            trust_mismatches += 1
        result_hash = _digest({
            "case_id": case_id,
            "attempt_hash": attempt["attempt_hash"],
            "oracle_hash": case["oracle_hash"],
            "actual_status": actual_status,
            "actual_disposition": actual_disposition,
        })
        cases_results.append({
            "case_id": case_id,
            "hostile_family": family,
            "attempt_id": attempt_id,
            "attempt_hash": attempt["attempt_hash"],
            "oracle_hash": case["oracle_hash"],
            "result_hash": result_hash,
            "actual_status": actual_status,
            "actual_disposition": actual_disposition,
            "evidence_hash": attempt["evidence_hash"],
            "infra_invalid": infra_invalid,
            "infra_invalid_reason": infra_reason,
        })

    eligible_count = sum(not row["infra_invalid"] for row in cases_results)
    infra_invalid_count = len(cases_results) - eligible_count
    run_id = (
        "tg7-run-"
        + _digest({
            "selection_hash": selection["selection_hash"],
            "corpus_hash": corpus["corpus_hash"],
            "tg5_receipt_hash": tg5_receipt["receipt_hash"],
            "attempt_hashes": [row["attempt_hash"] for row in cases_results],
        })[7:23]
    )
    generated_at = max(observed_times)
    shadow_receipt = {
        "schema": SHADOW_RECEIPT_SCHEMA,
        "run_id": run_id,
        "tg5_receipt_hash": tg5_receipt["receipt_hash"],
        "selection_hash": selection["selection_hash"],
        "corpus_hash": corpus["corpus_hash"],
        "task_set_id": TASK_SET_ID,
        "repository": {
            "owner": selection["owner"],
            "name": selection["name"],
            "commit": selection["commit"],
            "tree": selection["tree"],
            "bottle_py_hash": bottle_hash,
        },
        "eligible_count": eligible_count,
        "infra_invalid_count": infra_invalid_count,
        "cases": cases_results,
    }
    shadow_receipt["receipt_hash"] = _digest(shadow_receipt)
    report = {
        "schema": REPORT_SCHEMA,
        "task_set_id": TASK_SET_ID,
        "shadow_receipt_hash": shadow_receipt["receipt_hash"],
        "selection_hash": selection["selection_hash"],
        "tg5_receipt_hash": tg5_receipt["receipt_hash"],
        "generated_at": generated_at,
        "denominator": eligible_count,
        "eligible_count": eligible_count,
        "infra_invalid_count": infra_invalid_count,
        "family_counts": family_counts,
        "false_certification_count": len(false_cert_ids),
        "false_certification_case_ids": sorted(false_cert_ids),
        "trust_mismatches": trust_mismatches,
        "maximum_claim": MAXIMUM_CLAIM,
        "claim_ceiling": list(CLAIM_CEILING),
        "compatibility": {
            "protocol_version": PUBLIC_PROTOCOL_VERSION,
            "implementation_schema": IMPLEMENTATION_SCHEMA,
            "profile_id": PROFILE_ID,
            "claim_ceiling": list(CLAIM_CEILING),
            "attempt_receipt_schema": ATTEMPT_RECEIPT_SCHEMA,
        },
    }
    report["report_hash"] = _digest(report)
    return shadow_receipt, report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TG-7 Representative Corpus and Second-Repo Shadow Verifier"
    )
    parser.add_argument("--selection", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--manifest", "--corpus", dest="manifest", required=True)
    parser.add_argument("--generate-corpus", action="store_true", default=False)
    parser.add_argument("--tg5-receipt", required=True)
    parser.add_argument("--shadow-receipt", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    selection_path = Path(args.selection)
    if not selection_path.is_file():
        sys.exit(f"Selection file not found: {selection_path}")
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    repo_path = Path(args.repository)
    selection_errors = validate_selection(selection, repo_path=repo_path)
    if selection_errors:
        sys.exit(f"Selection validation failed: {selection_errors}")

    tg5_path = Path(args.tg5_receipt)
    if not tg5_path.is_file():
        sys.exit(f"TG-5 receipt file not found: {tg5_path}")
    tg5_receipt = json.loads(tg5_path.read_text(encoding="utf-8"))
    tg5_errors = validate_tg5_receipt(tg5_receipt)
    if tg5_errors:
        sys.exit(f"TG-5 receipt validation failed: {tg5_errors}")

    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        if not args.generate_corpus:
            sys.exit(f"Corpus manifest file not found (fail-closed): {manifest_path}")
        if os.environ.get("NEXUS_TG7_SELF_TEST") != "1":
            sys.exit("--generate-corpus is SELF_TEST-only and cannot satisfy physical acceptance")
        corpus = build_default_corpus(selection)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(_canonical(corpus) + "\n", encoding="utf-8")
    else:
        corpus = json.loads(manifest_path.read_text(encoding="utf-8"))
    corpus_errors = validate_corpus(corpus, selection=selection)
    if corpus_errors:
        sys.exit(f"Corpus validation failed (fail-closed): {corpus_errors}")

    try:
        shadow_receipt, report = run_shadow(selection, repo_path, corpus, tg5_receipt)
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        sys.exit(f"Shadow execution evidence unavailable or invalid: {exc}")
    shadow_errors = validate_shadow_receipt(
        shadow_receipt,
        corpus=corpus,
        tg5_receipt=tg5_receipt,
        selection=selection,
    )
    if shadow_errors:
        sys.exit(f"Shadow receipt verification failed: {shadow_errors}")
    report_errors = validate_report(report, shadow_receipt=shadow_receipt, corpus=corpus)
    if report_errors:
        sys.exit(f"Report verification failed: {report_errors}")

    shadow_path = Path(args.shadow_receipt)
    report_path = Path(args.report)
    shadow_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    shadow_path.write_text(_canonical(shadow_receipt) + "\n", encoding="utf-8")
    report_path.write_text(_canonical(report) + "\n", encoding="utf-8")
    print(
        f"[TG-7 READY-FOR-REVIEW] {report['denominator']} eligible cases; "
        f"false certifications={report['false_certification_count']}; "
        f"claim={report['maximum_claim']}"
    )


if __name__ == "__main__":
    main()
