"""Read-only ChatGPT/Codex-facing evidence verification tool contract.

This module is a thin carrying layer. It acquires the current GitHub pull-request
subject through an injected read port, validates an existing Nexus local
verification receipt, and compares the two identities. It does not execute code,
write GitHub state, make merge/release decisions, or create a second verification
authority.
"""

from __future__ import annotations

from typing import Any, Mapping

from product.clients.local_golden_path import validate_verification_receipt_payload
from product.runtime.nexus_verify import (
    read_current_pull_request_subject,
    validate_github_locator,
)

TOOL_NAME = "verify_code_change_evidence"
TOOL_DESCRIPTION = (
    "Verify whether supplied Nexus evidence is internally valid and still applies "
    "to the current exact GitHub pull-request state."
)

CLAIM_CEILING = (
    "VERIFIED_IS_NOT_MERGE_APPROVAL",
    "NO_RELEASE_AUTHORITY",
    "NO_DEPLOYMENT_AUTHORITY",
)

INPUT_SCHEMA: dict[str, Any] = {
    "$id": "nexus.verify-code-change-evidence.input.v1",
    "type": "object",
    "additionalProperties": False,
    "required": ["repository_owner", "repository_name", "pr_number"],
    "properties": {
        "repository_owner": {"type": "string", "minLength": 1, "maxLength": 100},
        "repository_name": {"type": "string", "minLength": 1, "maxLength": 100},
        "pr_number": {"type": "integer", "minimum": 1},
        "receipt": {
            "anyOf": [
                {"type": "object"},
                {"type": "null"},
            ]
        },
    },
}

_SUBJECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "repository_owner",
        "repository_name",
        "pr_number",
        "current_base_sha",
        "current_head_sha",
        "current_base_tree",
        "current_head_tree",
        "freshness_cas",
    ],
    "properties": {
        "repository_owner": {"type": "string"},
        "repository_name": {"type": "string"},
        "pr_number": {"type": "integer"},
        "current_base_sha": {"type": "string"},
        "current_head_sha": {"type": "string"},
        "current_base_tree": {"type": "string"},
        "current_head_tree": {"type": "string"},
        "freshness_cas": {"type": "string"},
    },
}

OUTPUT_SCHEMA: dict[str, Any] = {
    "$id": "nexus.verify-code-change-evidence.output.v1",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "subject",
        "receipt_integrity",
        "evidence_applicability",
        "core_verification",
        "reason_codes",
        "claim_ceiling",
    ],
    "properties": {
        "subject": {"anyOf": [_SUBJECT_SCHEMA, {"type": "null"}]},
        "receipt_integrity": {"enum": ["VALID", "INVALID", "ABSENT"]},
        "evidence_applicability": {
            "enum": [
                "APPLIES",
                "STALE_SOURCE",
                "STALE_TARGET",
                "SUBJECT_MISMATCH",
                "TAMPERED",
                "UNVERIFIABLE",
                "EVIDENCE_NOT_SUPPLIED",
            ]
        },
        "core_verification": {
            "enum": [
                "VERIFIED",
                "FAILED_VERIFICATION",
                "UNVERIFIABLE",
                "NOT_AVAILABLE",
            ]
        },
        "reason_codes": {
            "type": "array",
            "items": {"type": "string"},
            "uniqueItems": True,
        },
        "claim_ceiling": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": len(CLAIM_CEILING),
            "maxItems": len(CLAIM_CEILING),
        },
    },
}

TOOL_DEFINITION: dict[str, Any] = {
    "name": TOOL_NAME,
    "description": TOOL_DESCRIPTION,
    "inputSchema": INPUT_SCHEMA,
    "outputSchema": OUTPUT_SCHEMA,
    "annotations": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
}

_TAMPER_REASONS = frozenset(
    {
        "RECEIPT_HASH_MISMATCH",
        "CONFIG_HASH_MISMATCH",
        "VERIFIER_ARTIFACT_MISMATCH",
        "VERIFIER_OUTPUT_MISMATCH",
        "VERIFIER_STATUS_MISMATCH",
        "MANIFEST_HASH_MISMATCH",
        "CORE_RESPONSE_MISMATCH",
        "VERIFIER_BINDING_MISMATCH",
        "RECEIPT_BINDING_MISMATCH",
        "CONFIG_BINDING_MISMATCH",
        "OUTCOME_MISMATCH",
        "GIT_MANIFEST_MISMATCH",
    }
)


def _result(
    *,
    subject: dict[str, Any] | None,
    receipt_integrity: str,
    evidence_applicability: str,
    core_verification: str,
    reason_codes: tuple[str, ...] | list[str],
) -> dict[str, Any]:
    return {
        "subject": subject,
        "receipt_integrity": receipt_integrity,
        "evidence_applicability": evidence_applicability,
        "core_verification": core_verification,
        "reason_codes": sorted(set(reason_codes)),
        "claim_ceiling": list(CLAIM_CEILING),
    }


def _validate_arguments(arguments: Mapping[str, Any]) -> tuple[str, str, int, dict[str, Any] | None]:
    if not isinstance(arguments, Mapping):
        raise ValueError("arguments must be an object")
    values = dict(arguments)
    if not {"repository_owner", "repository_name", "pr_number"}.issubset(values):
        raise ValueError("repository_owner, repository_name and pr_number are required")
    if set(values) - {"repository_owner", "repository_name", "pr_number", "receipt"}:
        raise ValueError("unexpected tool arguments")
    owner, repository, pr_number = validate_github_locator(
        values["repository_owner"],
        values["repository_name"],
        values["pr_number"],
    )
    receipt = values.get("receipt")
    if receipt is not None and not isinstance(receipt, Mapping):
        raise ValueError("receipt must be an object or null")
    return owner, repository, pr_number, dict(receipt) if receipt is not None else None


def _public_subject(subject: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: subject[key]
        for key in (
            "repository_owner",
            "repository_name",
            "pr_number",
            "current_base_sha",
            "current_head_sha",
            "current_base_tree",
            "current_head_tree",
            "freshness_cas",
        )
    }


def _receipt_binding(receipt: Mapping[str, Any]) -> dict[str, Any] | None:
    try:
        inputs = receipt["inputs"]
        request = inputs["request"]
        change_set = request["change_set"]
        manifest = request["change_manifest"]
        paths = tuple(sorted(change_set["paths"]))
        deleted_paths = tuple(sorted(change_set["deleted_paths"]))
        return {
            "source_revision": receipt["source_revision"],
            "source_tree": receipt["source_tree"],
            "target_revision": receipt["target_revision"],
            "target_tree": receipt["target_tree"],
            "change_source_revision": change_set["source_revision"],
            "change_target_revision": change_set["target_revision"],
            "manifest_source_tree": manifest["source_tree"],
            "manifest_target_tree": manifest["target_tree"],
            "paths": paths,
            "deleted_paths": deleted_paths,
        }
    except (KeyError, TypeError):
        return None


def _core_status(receipt: Mapping[str, Any]) -> str:
    try:
        status = receipt["core_response"]["verification"]["status"]
    except (KeyError, TypeError):
        return "NOT_AVAILABLE"
    if status in {"VERIFIED", "FAILED_VERIFICATION", "UNVERIFIABLE"}:
        return status
    return "NOT_AVAILABLE"


def verify_code_change_evidence(
    arguments: Mapping[str, Any],
    *,
    github_port: Any,
) -> dict[str, Any]:
    """Verify supplied Nexus evidence against the current exact GitHub PR state.

    The GitHub port is injected by the host, which owns authentication and
    transport. This function is deterministic relative to the supplied port
    reads and receipt bytes; it performs no repository execution or mutation.
    """

    owner, repository, pr_number, receipt = _validate_arguments(arguments)

    if receipt is None:
        receipt_integrity = "ABSENT"
        receipt_reasons: tuple[str, ...] = ()
        core_verification = "NOT_AVAILABLE"
    else:
        try:
            validation = validate_verification_receipt_payload(receipt)
        except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
            validation = {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
        receipt_reasons = tuple(validation["reason_codes"])
        receipt_integrity = "VALID" if validation["valid"] else "INVALID"
        core_verification = _core_status(receipt) if validation["valid"] else "NOT_AVAILABLE"

    acquisition = read_current_pull_request_subject(
        owner,
        repository,
        pr_number,
        github_port=github_port,
    )
    if acquisition.get("status") != "OK" or not isinstance(acquisition.get("subject"), Mapping):
        reason = acquisition.get("reason_code")
        return _result(
            subject=None,
            receipt_integrity=receipt_integrity,
            evidence_applicability="UNVERIFIABLE",
            core_verification=core_verification,
            reason_codes=(
                *receipt_reasons,
                reason if isinstance(reason, str) else "GITHUB_ACQUISITION_INVALID",
            ),
        )

    acquired_subject = dict(acquisition["subject"])
    subject = _public_subject(acquired_subject)

    if receipt is None:
        return _result(
            subject=subject,
            receipt_integrity="ABSENT",
            evidence_applicability="EVIDENCE_NOT_SUPPLIED",
            core_verification="NOT_AVAILABLE",
            reason_codes=("NEXUS_RECEIPT_NOT_SUPPLIED",),
        )

    if receipt_integrity != "VALID":
        applicability = (
            "TAMPERED" if any(reason in _TAMPER_REASONS for reason in receipt_reasons) else "UNVERIFIABLE"
        )
        return _result(
            subject=subject,
            receipt_integrity="INVALID",
            evidence_applicability=applicability,
            core_verification="NOT_AVAILABLE",
            reason_codes=receipt_reasons,
        )

    binding = _receipt_binding(receipt)
    if binding is None:
        return _result(
            subject=subject,
            receipt_integrity="INVALID",
            evidence_applicability="UNVERIFIABLE",
            core_verification="NOT_AVAILABLE",
            reason_codes=("MALFORMED_RECEIPT_BINDING",),
        )

    expected_source_revision = f"git-commit:{acquired_subject['current_base_sha']}"
    expected_source_tree = f"git-tree:{acquired_subject['current_base_tree']}"
    expected_target_tree = f"git-tree:{acquired_subject['current_head_tree']}"

    if (
        binding["source_revision"] != expected_source_revision
        or binding["change_source_revision"] != expected_source_revision
        or binding["source_tree"] != expected_source_tree
        or binding["manifest_source_tree"] != expected_source_tree
    ):
        return _result(
            subject=subject,
            receipt_integrity="VALID",
            evidence_applicability="STALE_SOURCE",
            core_verification=core_verification,
            reason_codes=("RECEIPT_SOURCE_DOES_NOT_MATCH_CURRENT_PR",),
        )

    if (
        binding["target_revision"] != expected_target_tree
        or binding["change_target_revision"] != expected_target_tree
        or binding["target_tree"] != expected_target_tree
        or binding["manifest_target_tree"] != expected_target_tree
    ):
        return _result(
            subject=subject,
            receipt_integrity="VALID",
            evidence_applicability="STALE_TARGET",
            core_verification=core_verification,
            reason_codes=("RECEIPT_TARGET_DOES_NOT_MATCH_CURRENT_PR",),
        )

    if (
        binding["paths"] != tuple(acquired_subject["changed_paths"])
        or binding["deleted_paths"] != tuple(acquired_subject["deleted_paths"])
    ):
        return _result(
            subject=subject,
            receipt_integrity="VALID",
            evidence_applicability="SUBJECT_MISMATCH",
            core_verification=core_verification,
            reason_codes=("RECEIPT_PATH_SCOPE_DOES_NOT_MATCH_CURRENT_PR",),
        )

    return _result(
        subject=subject,
        receipt_integrity="VALID",
        evidence_applicability="APPLIES",
        core_verification=core_verification,
        reason_codes=(),
    )


__all__ = [
    "CLAIM_CEILING",
    "INPUT_SCHEMA",
    "OUTPUT_SCHEMA",
    "TOOL_DEFINITION",
    "TOOL_DESCRIPTION",
    "TOOL_NAME",
    "verify_code_change_evidence",
]
