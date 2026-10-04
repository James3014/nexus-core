"""Runtime and manual handoff readiness evidence validation (issue #83).

This module is part of the Evidence Trust Core. It validates that evidence
demonstrating runtime readiness for manual testing meets Core truth criteria:
- exact source tree and commit are bound and clean;
- runtime services are live, reachable, and identified by process identity;
- consumer-provided handoff verifier succeeded against the live runtime;
- explicit claim ceiling is strictly enforced.

It does NOT orchestrate processes, run browser tests, or grant release/merge authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from product.protocol.runtime_handoff import (
    HANDOFF_CLAIM_CEILING,
    HANDOFF_NON_CLAIMS,
    RUNTIME_HANDOFF_RECEIPT_KIND,
    RUNTIME_HANDOFF_SCHEMA_ID,
    is_git_commit_ref,
    is_git_tree_ref,
    is_sha256_hash,
    runtime_handoff_receipt_hash,
)


class HandoffVerdict(str, Enum):
    HANDOFF_READY = "HANDOFF_READY"
    HANDOFF_BLOCKED = "HANDOFF_BLOCKED"


@dataclass(frozen=True)
class ServiceIdentity:
    service_id: str
    endpoint: str
    pid: int | None
    process_start_time: str | None
    executable_path: str | None
    reachable: bool


@dataclass(frozen=True)
class SourceBinding:
    target_commit: str
    target_tree: str
    worktree_clean: bool


@dataclass(frozen=True)
class HandoffVerifierArtifact:
    command: tuple[str, ...]
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str
    duration_ms: int


def validate_handoff_evidence_envelope(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate structure, hashes, and truth invariants of a handoff receipt payload."""
    reasons: list[str] = []

    if not isinstance(payload, Mapping):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}

    if payload.get("schema") != RUNTIME_HANDOFF_SCHEMA_ID:
        reasons.append("INVALID_SCHEMA")
    if payload.get("receipt_kind") != RUNTIME_HANDOFF_RECEIPT_KIND:
        reasons.append("INVALID_RECEIPT_KIND")

    claim_ceiling = payload.get("claim_ceiling")
    if claim_ceiling != HANDOFF_CLAIM_CEILING:
        reasons.append("CLAIM_CEILING_MISMATCH")

    non_claims = payload.get("non_claims")
    if not isinstance(non_claims, list) or tuple(non_claims) != HANDOFF_NON_CLAIMS:
        reasons.append("NON_CLAIMS_MISMATCH")

    handoff_id = payload.get("handoff_id")
    if not isinstance(handoff_id, str) or not handoff_id.strip():
        reasons.append("HANDOFF_ID_MISSING")
    if not is_sha256_hash(payload.get("handoff_config_hash")):
        reasons.append("HANDOFF_CONFIG_HASH_INVALID")

    # Source binding validation
    source = payload.get("source_binding")
    if not isinstance(source, Mapping):
        reasons.append("SOURCE_BINDING_MISSING")
    else:
        if not is_git_commit_ref(source.get("target_commit")):
            reasons.append("INVALID_TARGET_COMMIT")
        if not is_git_tree_ref(source.get("target_tree")):
            reasons.append("INVALID_TARGET_TREE")
        if source.get("worktree_clean") is not True:
            reasons.append("WORKTREE_DIRTY")

    # Runtime binding validation
    runtime = payload.get("runtime_binding")
    if not isinstance(runtime, Mapping):
        reasons.append("RUNTIME_BINDING_MISSING")
    else:
        services = runtime.get("services")
        if not isinstance(services, list) or not services:
            reasons.append("NO_RUNTIME_SERVICES_DECLARED")
        else:
            for idx, svc in enumerate(services):
                if not isinstance(svc, Mapping):
                    reasons.append(f"SERVICE[{idx}]_MALFORMED")
                    continue
                if not isinstance(svc.get("service_id"), str) or not svc.get("service_id"):
                    reasons.append(f"SERVICE[{idx}]_ID_INVALID")
                if not isinstance(svc.get("endpoint"), str) or not svc.get("endpoint"):
                    reasons.append(f"SERVICE[{idx}]_ENDPOINT_INVALID")
                if svc.get("reachable") is not True:
                    reasons.append("RUNTIME_SERVICE_UNREACHABLE")
                pid = svc.get("pid")
                if pid is not None and (not isinstance(pid, int) or pid <= 0):
                    reasons.append("INVALID_PROCESS_IDENTITY")

    # Handoff verifier validation
    verifier = payload.get("handoff_verifier")
    if not isinstance(verifier, Mapping):
        reasons.append("HANDOFF_VERIFIER_MISSING")
    else:
        command = verifier.get("command")
        if not isinstance(command, list) or not command or any(not isinstance(c, str) for c in command):
            reasons.append("INVALID_VERIFIER_COMMAND")
        exit_code = verifier.get("exit_code")
        if not isinstance(exit_code, int) or exit_code != 0:
            reasons.append("HANDOFF_VERIFIER_FAILED")
        if not is_sha256_hash(verifier.get("stdout_sha256")):
            reasons.append("INVALID_STDOUT_HASH")
        if not is_sha256_hash(verifier.get("stderr_sha256")):
            reasons.append("INVALID_STDERR_HASH")

    # Receipt hash integrity
    receipt_hash = payload.get("receipt_hash")
    if not is_sha256_hash(receipt_hash):
        reasons.append("INVALID_RECEIPT_HASH")
    else:
        expected_hash = runtime_handoff_receipt_hash(payload)
        if receipt_hash != expected_hash:
            reasons.append("RECEIPT_HASH_MISMATCH")

    # Verdict check
    verdict = payload.get("verdict")
    expected_verdict = HandoffVerdict.HANDOFF_READY.value if not reasons else HandoffVerdict.HANDOFF_BLOCKED.value
    if verdict != expected_verdict and not (verdict == HandoffVerdict.HANDOFF_BLOCKED.value and reasons):
        reasons.append("VERDICT_MISMATCH")

    return {
        "valid": not reasons,
        "reason_codes": sorted(set(reasons)),
    }


__all__ = [
    "HandoffVerdict",
    "HandoffVerifierArtifact",
    "ServiceIdentity",
    "SourceBinding",
    "validate_handoff_evidence_envelope",
]
