"""Runtime facade for candidate acquisition (nexus-core-issue1312).

This module is the **only** production wiring point allowed to import from both:
- ``product.acquisition.candidate_materialization`` (acquire_and_verify_candidate, request/
  profile types, receipt validator, CandidateAcquisitionError)
- ``product.adapters.generic_verification`` (verify_generic_changeset)

It owns strict machine-request parsing, facade orchestration, and machine-result
normalization.  ``product.clients.cli`` must import only from this module (plus
``product.runtime.*``) and must never import ``product.acquisition`` directly.

Authority ceiling — this facade is:
- NOT acceptance authority
- NOT merge authority
- NOT release authority
- NOT deployment authority
- NOT routing/G2 adjudication authority
It records CORE_EVIDENCE_TRUST_COMPLETION_ONLY.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from product.acquisition.candidate_materialization import (
    CandidateAcquisitionError,
    CandidateAcquisitionRequest,
    CandidateAcquisitionResult,
    VerificationAcquisitionProfile,
    acquire_and_verify_candidate,
    validate_candidate_acquisition_receipt,
)
from product.adapters.generic_verification import verify_generic_changeset

# ---------------------------------------------------------------------------
# Machine-result schema ID
# ---------------------------------------------------------------------------

CLI_RESULT_SCHEMA = "nexus.core.candidate_acquisition_cli_result.v1"
CLI_ERROR_SCHEMA = "nexus.core.candidate_acquisition_cli_result.v1"

# Authority constant written into every result
_AUTHORITY = "CORE_EVIDENCE_TRUST_COMPLETION_ONLY"

# Claim ceiling — must never imply acceptance/merge/release/deploy
_CLAIM_CEILING = [
    "NO_ACCEPTANCE_AUTHORITY",
    "NO_MERGE_AUTHORIZATION",
    "NO_RELEASE_AUTHORITY",
    "NO_DEPLOYMENT_AUTHORITY",
    "NO_ROUTING_AUTHORITY",
]

# ---------------------------------------------------------------------------
# Strict request parsing
# ---------------------------------------------------------------------------

_TOP_LEVEL_KEYS = frozenset(
    {
        "candidate_head",
        "candidate_tree",
        "expected_source_identity",
        "acceptance_contract",
        "expected_contract_hash",
        "verification_profile",
        "expected_profile_hash",
        "expected_change_set_hash",
        "acquisition_request_id",
        "request_hash",
        "repo_path",
        "receipt_directory",
    }
)

_PROFILE_KEYS = frozenset(
    {
        "profile_id",
        "verifier_ids",
        "verifier_commands",
        "timeout_seconds",
        "profile_hash",
    }
)

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _require_str(value: Any, field: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            f"{field} must be a string, got {type(value).__name__}",
        )
    if nonempty and not value.strip():
        raise CandidateAcquisitionError("PARSE_ERROR", f"{field} must not be empty")
    return value


def _require_int_positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            f"{field} must be an integer, got {type(value).__name__}",
        )
    if value <= 0:
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            f"{field} must be > 0, got {value}",
        )
    return value


def _require_hash_shape(value: Any, field: str) -> str:
    s = _require_str(value, field)
    if not _SHA256_RE.fullmatch(s):
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            f"{field} must match sha256:<64hex>, got {s!r}",
        )
    return s


def _require_nonempty_list_of_nonempty_strings(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            f"{field} must be a non-empty list",
        )
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise CandidateAcquisitionError(
                "PARSE_ERROR",
                f"{field}[{i}] must be a non-empty string",
            )
    return [str(s) for s in value]


def parse_acquisition_request(doc: Any) -> CandidateAcquisitionRequest:
    """Parse and strictly validate a machine acquisition request document.

    Rejects:
    - unknown top-level or profile keys
    - wrong types, empty IDs/argvs, malformed hash shapes, invalid timeout
    - missing required fields

    Never infers verifier commands, fills missing fields, or transforms labels.
    """
    if not isinstance(doc, dict):
        raise CandidateAcquisitionError(
            "PARSE_ERROR", "request document must be a JSON object"
        )

    # Reject unknown top-level keys.
    unknown = set(doc.keys()) - _TOP_LEVEL_KEYS
    if unknown:
        raise CandidateAcquisitionError(
            "UNKNOWN_FIELDS",
            f"unknown top-level keys: {sorted(unknown)}",
        )

    # Check all required top-level keys are present.
    missing = _TOP_LEVEL_KEYS - set(doc.keys())
    if missing:
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            f"missing required fields: {sorted(missing)}",
        )

    candidate_head = _require_str(doc["candidate_head"], "candidate_head")
    candidate_tree = _require_str(doc["candidate_tree"], "candidate_tree")
    expected_source_identity = _require_str(
        doc["expected_source_identity"], "expected_source_identity"
    )
    acquisition_request_id = _require_str(
        doc["acquisition_request_id"], "acquisition_request_id"
    )
    request_hash = _require_hash_shape(doc["request_hash"], "request_hash")
    expected_contract_hash = _require_hash_shape(
        doc["expected_contract_hash"], "expected_contract_hash"
    )
    expected_profile_hash = _require_hash_shape(
        doc["expected_profile_hash"], "expected_profile_hash"
    )
    expected_change_set_hash = _require_hash_shape(
        doc["expected_change_set_hash"], "expected_change_set_hash"
    )

    # acceptance_contract must be a dict.
    acceptance_contract = doc["acceptance_contract"]
    if not isinstance(acceptance_contract, dict):
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            "acceptance_contract must be a JSON object",
        )

    repo_path_str = _require_str(doc["repo_path"], "repo_path")
    receipt_directory_str = _require_str(doc["receipt_directory"], "receipt_directory")

    # Parse verification_profile strictly.
    profile_doc = doc["verification_profile"]
    if not isinstance(profile_doc, dict):
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            "verification_profile must be a JSON object",
        )
    unknown_profile = set(profile_doc.keys()) - _PROFILE_KEYS
    if unknown_profile:
        raise CandidateAcquisitionError(
            "UNKNOWN_FIELDS",
            f"unknown verification_profile keys: {sorted(unknown_profile)}",
        )
    missing_profile = _PROFILE_KEYS - set(profile_doc.keys())
    if missing_profile:
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            f"verification_profile missing fields: {sorted(missing_profile)}",
        )

    profile_id = _require_str(profile_doc["profile_id"], "verification_profile.profile_id")
    profile_hash = _require_hash_shape(
        profile_doc["profile_hash"], "verification_profile.profile_hash"
    )
    timeout_seconds = _require_int_positive(
        profile_doc["timeout_seconds"], "verification_profile.timeout_seconds"
    )

    verifier_ids_raw = profile_doc["verifier_ids"]
    verifier_ids = _require_nonempty_list_of_nonempty_strings(
        verifier_ids_raw, "verification_profile.verifier_ids"
    )

    # verifier_commands: list of lists (argv arrays), positionally paired with verifier_ids.
    verifier_commands_raw = profile_doc["verifier_commands"]
    if not isinstance(verifier_commands_raw, list) or not verifier_commands_raw:
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            "verification_profile.verifier_commands must be a non-empty list",
        )
    verifier_commands: list[tuple[str, ...]] = []
    for i, cmd in enumerate(verifier_commands_raw):
        if not isinstance(cmd, list) or not cmd:
            raise CandidateAcquisitionError(
                "PARSE_ERROR",
                f"verification_profile.verifier_commands[{i}] must be a non-empty list (argv)",
            )
        argv: list[str] = []
        for j, arg in enumerate(cmd):
            if not isinstance(arg, str) or not arg:
                raise CandidateAcquisitionError(
                    "PARSE_ERROR",
                    f"verification_profile.verifier_commands[{i}][{j}] must be a non-empty string",
                )
            argv.append(arg)
        verifier_commands.append(tuple(argv))

    if len(verifier_ids) != len(verifier_commands):
        raise CandidateAcquisitionError(
            "PARSE_ERROR",
            "verification_profile.verifier_ids and verifier_commands must have the same length",
        )

    profile = VerificationAcquisitionProfile(
        profile_id=profile_id,
        verifier_ids=tuple(verifier_ids),
        verifier_commands=tuple(verifier_commands),
        timeout_seconds=timeout_seconds,
        profile_hash=profile_hash,
    )

    return CandidateAcquisitionRequest(
        candidate_head=candidate_head,
        candidate_tree=candidate_tree,
        expected_source_identity=expected_source_identity,
        acceptance_contract=acceptance_contract,
        expected_contract_hash=expected_contract_hash,
        profile=profile,
        expected_profile_hash=expected_profile_hash,
        expected_change_set_hash=expected_change_set_hash,
        acquisition_request_id=acquisition_request_id,
        request_hash=request_hash,
        repo_path=Path(repo_path_str),
        receipt_directory=Path(receipt_directory_str),
    )


# ---------------------------------------------------------------------------
# Machine-result builders
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _make_success_result(
    acq_result: CandidateAcquisitionResult,
    started_at: str,
    completed_at: str,
    runtime_ms: int,
) -> dict[str, Any]:
    """Build a stable machine success result from a CandidateAcquisitionResult."""
    receipt_path = acq_result.receipt_path
    # Validate receipt hash from the persisted file — never trust in-memory state.
    validation = validate_candidate_acquisition_receipt(receipt_path)
    if not validation["valid"]:
        # Fail closed: if the persisted receipt fails validation, treat as error.
        raise CandidateAcquisitionError(
            "RECEIPT_VALIDATION_FAILED",
            f"persisted receipt failed validation: {validation['reason_codes']}",
            receipt_path=receipt_path,
        )

    import json as _json

    receipt_data = _json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_hash = receipt_data.get("receipt_hash", "")

    return {
        "schema": CLI_RESULT_SCHEMA,
        "status": "OK",
        "core_verdict": acq_result.status,
        "core_reason_codes": acq_result.reason_codes,
        "acquisition_request_id": acq_result.request_id,
        "request_hash": acq_result.request_hash,
        "reason_codes": acq_result.reason_codes,
        "receipt_hash": receipt_hash,
        "receipt_path": str(receipt_path),
        "replayed": acq_result.replayed,
        "started_at": started_at,
        "completed_at": completed_at,
        "orchestration_runtime_ms": runtime_ms,
        "core_response": acq_result.core_response,
        "authority": _AUTHORITY,
        "claim_ceiling": _CLAIM_CEILING,
    }


def _make_error_result(
    reason_code: str,
    detail: str,
    *,
    started_at: str,
    completed_at: str,
    runtime_ms: int,
    receipt_path: Path | None = None,
    acquisition_request_id: str | None = None,
    request_hash: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": CLI_ERROR_SCHEMA,
        "status": "ERROR",
        "reason_code": reason_code,
        "detail": detail,
        "started_at": started_at,
        "completed_at": completed_at,
        "orchestration_runtime_ms": runtime_ms,
        "authority": _AUTHORITY,
        "claim_ceiling": _CLAIM_CEILING,
    }
    if receipt_path is not None:
        result["receipt_path"] = str(receipt_path)
    if acquisition_request_id is not None:
        result["acquisition_request_id"] = acquisition_request_id
    if request_hash is not None:
        result["request_hash"] = request_hash
    return result


def make_candidate_acquisition_input_error(
    reason_code: str,
    detail: str,
) -> dict[str, Any]:
    """Build the stable machine envelope for pre-request CLI/input failures.

    These failures happen before a CandidateAcquisitionRequest can be safely
    constructed, so they intentionally omit request identity and receipt
    fields while preserving the same authority/claim ceiling as all other
    candidate-acquisition results.
    """
    now = _now_iso()
    return _make_error_result(
        reason_code,
        detail,
        started_at=now,
        completed_at=now,
        runtime_ms=0,
    )


# ---------------------------------------------------------------------------
# Public facade entry point
# ---------------------------------------------------------------------------


def run_candidate_acquisition(
    doc: Any,
    *,
    stderr_diag: bool = True,
) -> tuple[dict[str, Any], int]:
    """Parse the request document, orchestrate acquisition, and return a machine result.

    Returns ``(result_dict, exit_code)`` where exit_code is 0 on success and
    non-zero on any error.  Callers should emit ``result_dict`` to stdout as a
    single JSON document and exit with ``exit_code``.

    Diagnostic text (non-JSON) may be written to stderr when ``stderr_diag`` is True;
    stdout always contains exactly one JSON document.
    """
    import time

    started_at = _now_iso()
    t0 = time.monotonic()

    request: CandidateAcquisitionRequest | None = None
    request_id_safe: str | None = None
    request_hash_safe: str | None = None

    try:
        request = parse_acquisition_request(doc)
        request_id_safe = request.acquisition_request_id
        request_hash_safe = request.request_hash

        acq_result = acquire_and_verify_candidate(request, verify_generic_changeset)

        completed_at = _now_iso()
        runtime_ms = int((time.monotonic() - t0) * 1000)

        result = _make_success_result(acq_result, started_at, completed_at, runtime_ms)
        return result, 0

    except CandidateAcquisitionError as exc:
        completed_at = _now_iso()
        runtime_ms = int((time.monotonic() - t0) * 1000)
        if stderr_diag:
            print(
                f"[nexus-certify acquire] {exc.reason_code}: {exc.detail}",
                file=sys.stderr,
            )
        result = _make_error_result(
            exc.reason_code,
            exc.detail,
            started_at=started_at,
            completed_at=completed_at,
            runtime_ms=runtime_ms,
            receipt_path=exc.receipt_path,
            acquisition_request_id=request_id_safe,
            request_hash=request_hash_safe,
        )
        return result, 1

    except Exception as exc:  # noqa: BLE001
        completed_at = _now_iso()
        runtime_ms = int((time.monotonic() - t0) * 1000)
        # Normalize unexpected errors without leaking secrets.
        if stderr_diag:
            print(
                f"[nexus-certify acquire] unexpected internal error: {type(exc).__name__}",
                file=sys.stderr,
            )
        result = _make_error_result(
            "INTERNAL_ERROR",
            f"unexpected internal error: {type(exc).__name__}",
            started_at=started_at,
            completed_at=completed_at,
            runtime_ms=runtime_ms,
            acquisition_request_id=request_id_safe,
            request_hash=request_hash_safe,
        )
        return result, 1


__all__ = [
    "CLI_RESULT_SCHEMA",
    "CandidateAcquisitionError",
    "make_candidate_acquisition_input_error",
    "parse_acquisition_request",
    "run_candidate_acquisition",
]
