# pyright: strict, reportUnnecessaryIsInstance=false, reportUnnecessaryComparison=false
"""Read-only ChatGPT/Codex-facing evidence verification tool contract.

This module is a thin carrying layer. It acquires the current GitHub pull-request
subject through an injected read port, validates an existing Nexus local
verification receipt, and compares the two identities. It does not execute code,
write GitHub state, make merge/release decisions, or create a second verification
authority.

``receipt_integrity`` means self-consistency (an unkeyed SHA-256 hash), not
authenticity. Since #231 a receipt is trusted only when it arrives with the Sigstore
bundle that CI produced for its exact bytes (``receipt_signature``) and that bundle
verifies against the expected GitHub Actions workflow identity of the subject
repository. Without an authenticated bundle the result is ``UNVERIFIABLE`` with
``RECEIPT_NOT_AUTHENTICATED`` (or ``RECEIPT_AUTHENTICATION_UNAVAILABLE`` when the
optional ``sigstore`` package or trust root is unavailable), never ``VERIFIED``.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Mapping, Sequence, cast

from product.clients.local_golden_path import validate_verification_receipt_payload
from product.clients.receipt_authentication import (
    NOT_AUTHENTICATED,
    UNAVAILABLE,
    ReceiptAuthentication,
    ReceiptAuthenticator,
    ReceiptSignerPolicy,
    SigstoreReceiptAuthenticator,
    github_workflow_signer_policy,
)
from product.runtime.nexus_verify import (
    read_current_pull_request_subject,
    validate_github_locator,
)

TOOL_NAME = "verify_code_change_evidence"
TOOL_DESCRIPTION = (
    "Verify whether supplied Nexus evidence is internally valid, authenticated by its "
    "Sigstore CI signature, and still applies to the current exact GitHub pull-request state."
)

RECEIPT_NOT_AUTHENTICATED = "RECEIPT_NOT_AUTHENTICATED"
RECEIPT_AUTHENTICATION_UNAVAILABLE = "RECEIPT_AUTHENTICATION_UNAVAILABLE"

_RECEIPT_SIGNATURE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["receipt_base64", "sigstore_bundle"],
    "properties": {
        "receipt_base64": {
            "type": "string",
            "minLength": 1,
            "description": "Base64 of the exact signed receipt file bytes (<receipt>.json).",
        },
        "sigstore_bundle": {
            "type": "object",
            "description": "The CI Sigstore bundle for those bytes (<receipt>.json.sigstore.json).",
        },
    },
}

CLAIM_CEILING = (
    "VERIFIED_IS_NOT_MERGE_APPROVAL",
    "NO_RELEASE_AUTHORITY",
    "NO_DEPLOYMENT_AUTHORITY",
)

INPUT_SCHEMA: dict[str, Any] = {
    "$id": "nexus.verify-code-change-evidence.input.v2",
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
        "receipt_signature": {
            "anyOf": [
                _RECEIPT_SIGNATURE_SCHEMA,
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
    "$id": "nexus.verify-code-change-evidence.output.v2",
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


def _validate_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, str, int, dict[str, Any] | None, dict[str, Any] | None]:
    if not isinstance(arguments, Mapping):
        raise ValueError("arguments must be an object")
    values = dict(arguments)
    if not {"repository_owner", "repository_name", "pr_number"}.issubset(values):
        raise ValueError("repository_owner, repository_name and pr_number are required")
    if set(values) - {
        "repository_owner",
        "repository_name",
        "pr_number",
        "receipt",
        "receipt_signature",
    }:
        raise ValueError("unexpected tool arguments")
    owner, repository, pr_number = validate_github_locator(
        values["repository_owner"],
        values["repository_name"],
        values["pr_number"],
    )
    receipt = values.get("receipt")
    if receipt is not None and not isinstance(receipt, Mapping):
        raise ValueError("receipt must be an object or null")
    signature = _validate_receipt_signature_shape(values.get("receipt_signature"))
    if signature is not None and receipt is None:
        raise ValueError("receipt_signature requires receipt")
    return (
        owner,
        repository,
        pr_number,
        dict(cast("Mapping[str, Any]", receipt)) if receipt is not None else None,
        signature,
    )


def _validate_receipt_signature_shape(value: object) -> dict[str, Any] | None:
    """Schema-level check of ``receipt_signature``; content is judged later."""

    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("receipt_signature must be an object or null")
    signature = dict(cast("Mapping[str, Any]", value))
    if set(signature) != {"receipt_base64", "sigstore_bundle"}:
        raise ValueError("receipt_signature needs exactly receipt_base64 and sigstore_bundle")
    if not isinstance(signature["receipt_base64"], str) or not signature["receipt_base64"]:
        raise ValueError("receipt_signature.receipt_base64 must be a non-empty string")
    if not isinstance(signature["sigstore_bundle"], Mapping):
        raise ValueError("receipt_signature.sigstore_bundle must be an object")
    return signature


def _bundle_shape_problem(bundle: Mapping[str, Any]) -> str | None:
    """Reject bundles that cannot be a Sigstore message-signature bundle.

    The authenticator does the cryptographic work; this keeps obviously wrong
    material (including DSSE envelopes, which sign a statement rather than the
    receipt bytes) from ever reaching it.
    """

    media_type = bundle.get("mediaType")
    if not isinstance(media_type, str) or not media_type.startswith(
        "application/vnd.dev.sigstore.bundle"
    ):
        return "bundle mediaType is not a Sigstore bundle"
    if not isinstance(bundle.get("verificationMaterial"), Mapping):
        return "bundle has no verificationMaterial"
    if "dsseEnvelope" in bundle or not isinstance(bundle.get("messageSignature"), Mapping):
        return "bundle is not a message signature over the receipt bytes"
    return None


def _canonical_json(value: object) -> str | None:
    # Type-exact comparison: ``True == 1`` and ``1 == 1.0`` in Python, not in JSON.
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return None


def authenticate_receipt(
    receipt: Mapping[str, Any],
    receipt_signature: Mapping[str, Any] | None,
    *,
    policy: ReceiptSignerPolicy,
    authenticator: ReceiptAuthenticator | None = None,
) -> ReceiptAuthentication:
    """Decide whether ``receipt`` is the exact payload signed by ``policy``'s workflow.

    Missing, malformed or mismatched signature material is ``NOT_AUTHENTICATED``.
    The signed bytes must decode to exactly the supplied receipt object, so a
    caller cannot pair a genuine bundle with an edited receipt.
    """

    if receipt_signature is None:
        return ReceiptAuthentication(NOT_AUTHENTICATED, "no receipt_signature supplied")
    signature = _validate_receipt_signature_shape(receipt_signature)
    assert signature is not None
    try:
        receipt_bytes = base64.b64decode(signature["receipt_base64"], validate=True)
    except (binascii.Error, ValueError):
        return ReceiptAuthentication(NOT_AUTHENTICATED, "receipt_base64 is not valid base64")
    try:
        signed_receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return ReceiptAuthentication(NOT_AUTHENTICATED, "signed bytes are not a JSON receipt")
    if _canonical_json(signed_receipt) != _canonical_json(dict(receipt)) or _canonical_json(
        signed_receipt
    ) is None:
        return ReceiptAuthentication(
            NOT_AUTHENTICATED, "signed bytes do not encode the supplied receipt"
        )
    bundle = cast("Mapping[str, Any]", signature["sigstore_bundle"])
    problem = _bundle_shape_problem(bundle)
    if problem is not None:
        return ReceiptAuthentication(NOT_AUTHENTICATED, problem)
    try:
        bundle_json = json.dumps(bundle, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return ReceiptAuthentication(NOT_AUTHENTICATED, "bundle is not serializable JSON")
    active = authenticator if authenticator is not None else SigstoreReceiptAuthenticator()
    try:
        outcome = active.authenticate(
            receipt_bytes=receipt_bytes, bundle_json=bundle_json, policy=policy
        )
    except Exception as exc:  # noqa: BLE001 - an authenticator crash never authenticates
        return ReceiptAuthentication(UNAVAILABLE, f"authenticator failed: {type(exc).__name__}")
    if not isinstance(outcome, ReceiptAuthentication):
        return ReceiptAuthentication(NOT_AUTHENTICATED, "authenticator returned no verdict")
    return outcome


def _authentication_reason(outcome: ReceiptAuthentication) -> str:
    return (
        RECEIPT_AUTHENTICATION_UNAVAILABLE
        if outcome.status == UNAVAILABLE
        else RECEIPT_NOT_AUTHENTICATED
    )


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


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")


def _normalize_subject_paths(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field} must be a path list")
    result = tuple(str(item) for item in cast("Sequence[object]", value))
    if len(result) != len(set(result)):
        raise ValueError(f"{field} contains duplicates")
    for path in result:
        if (
            not path
            or path != path.strip()
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise ValueError(f"{field} contains an invalid relative path")
    return tuple(sorted(result))


def _normalize_supplied_subject(subject: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(subject, Mapping):
        raise ValueError("subject must be an object")
    values = dict(subject)
    required = {
        "repository_owner",
        "repository_name",
        "pr_number",
        "current_base_sha",
        "current_head_sha",
        "current_base_tree",
        "current_head_tree",
        "changed_paths",
        "deleted_paths",
    }
    allowed = {*required, "freshness_cas"}
    if not required.issubset(values) or set(values) - allowed:
        raise ValueError("subject has an incomplete or substituted schema")
    owner, repository, pr_number = validate_github_locator(
        values["repository_owner"], values["repository_name"], values["pr_number"]
    )
    normalized: dict[str, Any] = {
        "repository_owner": owner,
        "repository_name": repository,
        "pr_number": pr_number,
    }
    for field in (
        "current_base_sha",
        "current_head_sha",
        "current_base_tree",
        "current_head_tree",
    ):
        value = values[field]
        if not isinstance(value, str) or _SHA40.fullmatch(value) is None:
            raise ValueError(f"{field} must be lowercase 40-hex SHA")
        normalized[field] = value
    if normalized["current_base_sha"] == normalized["current_head_sha"]:
        raise ValueError("current base and head SHA must differ")
    changed_paths = _normalize_subject_paths(values["changed_paths"], "changed_paths")
    deleted_paths = _normalize_subject_paths(values["deleted_paths"], "deleted_paths")
    if not set(deleted_paths).issubset(set(changed_paths)):
        raise ValueError("deleted_paths must be a subset of changed_paths")
    normalized["changed_paths"] = list(changed_paths)
    normalized["deleted_paths"] = list(deleted_paths)
    freshness_cas = values.get("freshness_cas")
    if freshness_cas is not None and not isinstance(freshness_cas, str):
        raise ValueError("freshness_cas must be a string when supplied")
    normalized["freshness_cas"] = freshness_cas
    return normalized


def _resolve_signer_policy(
    owner: str,
    repository: str,
    signer_policy: ReceiptSignerPolicy | None,
) -> ReceiptSignerPolicy:
    if signer_policy is None:
        return github_workflow_signer_policy(owner, repository)
    if not isinstance(signer_policy, ReceiptSignerPolicy):
        raise ValueError("signer_policy must be a ReceiptSignerPolicy")
    if signer_policy.repository != f"{owner}/{repository}":
        # A receipt signed by another repository's workflow never authenticates
        # evidence for this pull request.
        raise ValueError("signer_policy repository must be the subject repository")
    return signer_policy


def evaluate_code_change_evidence_subject(
    subject: Mapping[str, Any],
    receipt: Mapping[str, Any] | None,
    *,
    receipt_signature: Mapping[str, Any] | None = None,
    authenticator: ReceiptAuthenticator | None = None,
    signer_policy: ReceiptSignerPolicy | None = None,
) -> dict[str, Any]:
    """Apply canonical Core receipt/applicability semantics to one supplied PR subject.

    This reducer performs no GitHub acquisition.  A carrying surface may supply an
    already-observed exact subject; when no canonical acquisition freshness CAS is
    supplied, the public ``subject`` field stays null so the result cannot be
    mistaken for an independently acquired GitHub snapshot.

    A self-consistent receipt is evaluated further only when ``receipt_signature``
    authenticates its exact bytes as signed by ``signer_policy`` (default: the
    subject repository's ``nexus-core-issue-completion.yml`` on ``refs/heads/main``,
    issuer GitHub Actions). ``authenticator`` defaults to the optional Sigstore
    implementation; the caller of the tool never chooses the signer.
    """

    acquired_subject = _normalize_supplied_subject(subject)
    policy = _resolve_signer_policy(
        acquired_subject["repository_owner"],
        acquired_subject["repository_name"],
        signer_policy,
    )
    if receipt_signature is not None:
        _validate_receipt_signature_shape(receipt_signature)
        if receipt is None:
            raise ValueError("receipt_signature requires receipt")
    public_subject = (
        _public_subject(acquired_subject)
        if isinstance(acquired_subject.get("freshness_cas"), str)
        else None
    )

    if receipt is None:
        return _result(
            subject=public_subject,
            receipt_integrity="ABSENT",
            evidence_applicability="EVIDENCE_NOT_SUPPLIED",
            core_verification="NOT_AVAILABLE",
            reason_codes=("NEXUS_RECEIPT_NOT_SUPPLIED",),
        )
    if not isinstance(receipt, Mapping):
        raise ValueError("receipt must be an object or null")
    receipt = dict(receipt)
    validation: dict[str, Any]
    try:
        validation = validate_verification_receipt_payload(receipt)
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        validation = {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
    receipt_reasons = tuple(validation["reason_codes"])
    receipt_integrity = "VALID" if validation["valid"] else "INVALID"
    core_verification = _core_status(receipt) if validation["valid"] else "NOT_AVAILABLE"

    if receipt_integrity != "VALID":
        applicability = (
            "TAMPERED"
            if any(reason in _TAMPER_REASONS for reason in receipt_reasons)
            else "UNVERIFIABLE"
        )
        return _result(
            subject=public_subject,
            receipt_integrity="INVALID",
            evidence_applicability=applicability,
            core_verification="NOT_AVAILABLE",
            reason_codes=receipt_reasons,
        )

    authentication = authenticate_receipt(
        receipt, receipt_signature, policy=policy, authenticator=authenticator
    )
    if not authentication.authenticated:
        # Integrity is only an unkeyed self-hash: without an authenticated CI
        # signature nothing the receipt claims (config source, base, outcome)
        # is trusted, so the result can never be APPLIES/VERIFIED (#231).
        return _result(
            subject=public_subject,
            receipt_integrity="VALID",
            evidence_applicability="UNVERIFIABLE",
            core_verification="NOT_AVAILABLE",
            reason_codes=(_authentication_reason(authentication),),
        )

    binding = _receipt_binding(receipt)
    if binding is None:
        return _result(
            subject=public_subject,
            receipt_integrity="INVALID",
            evidence_applicability="UNVERIFIABLE",
            core_verification="NOT_AVAILABLE",
            reason_codes=("MALFORMED_RECEIPT_BINDING",),
        )

    config_source = receipt.get("config_source")
    if not (
        isinstance(config_source, Mapping)
        and config_source.get("kind") == "base-ref"  # pyright: ignore[reportUnknownMemberType]
    ):
        # The unkeyed receipt hash proves self-consistency only; evidence produced
        # from a worktree/candidate-controlled config is not trusted evidence.
        return _result(
            subject=public_subject,
            receipt_integrity="VALID",
            evidence_applicability="UNVERIFIABLE",
            core_verification="NOT_AVAILABLE",
            reason_codes=("RECEIPT_CONFIG_SOURCE_UNTRUSTED",),
        )

    expected_source_revision = f"git-commit:{acquired_subject['current_base_sha']}"
    expected_source_tree = f"git-tree:{acquired_subject['current_base_tree']}"
    expected_target_tree = f"git-tree:{acquired_subject['current_head_tree']}"
    config_commit: object = cast("Mapping[str, Any]", config_source).get("commit")

    if binding["source_revision"] == expected_source_revision:
        # Tip mode: the receipt's source is the current base tip itself.
        source_ok = (
            binding["change_source_revision"] == expected_source_revision
            and binding["source_tree"] == expected_source_tree
            and binding["manifest_source_tree"] == expected_source_tree
        )
    else:
        # Merge-base mode (#243): the producer took the source as the unique
        # merge-base of HEAD and the exact base tip it read the trusted config
        # from, so the source is an ancestor of that tip by construction. The
        # receipt applies only while that tip is still the current base tip; a
        # receipt made before the base tip (and so possibly its config) moved is
        # stale. The source must also be internally consistent.
        source_ok = (
            config_commit == acquired_subject["current_base_sha"]
            and binding["change_source_revision"] == binding["source_revision"]
            and binding["manifest_source_tree"] == binding["source_tree"]
        )
    if not source_ok:
        return _result(
            subject=public_subject,
            receipt_integrity="VALID",
            evidence_applicability="STALE_SOURCE",
            core_verification=core_verification,
            reason_codes=("RECEIPT_SOURCE_DOES_NOT_MATCH_CURRENT_PR",),
        )

    if config_commit != acquired_subject["current_base_sha"]:
        return _result(
            subject=public_subject,
            receipt_integrity="VALID",
            evidence_applicability="UNVERIFIABLE",
            core_verification="NOT_AVAILABLE",
            reason_codes=("RECEIPT_CONFIG_SOURCE_UNTRUSTED",),
        )

    if (
        binding["target_revision"] != expected_target_tree
        or binding["change_target_revision"] != expected_target_tree
        or binding["target_tree"] != expected_target_tree
        or binding["manifest_target_tree"] != expected_target_tree
    ):
        return _result(
            subject=public_subject,
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
            subject=public_subject,
            receipt_integrity="VALID",
            evidence_applicability="SUBJECT_MISMATCH",
            core_verification=core_verification,
            reason_codes=("RECEIPT_PATH_SCOPE_DOES_NOT_MATCH_CURRENT_PR",),
        )

    return _result(
        subject=public_subject,
        receipt_integrity="VALID",
        evidence_applicability="APPLIES",
        core_verification=core_verification,
        reason_codes=(),
    )


def verify_code_change_evidence(
    arguments: Mapping[str, Any],
    *,
    github_port: Any,
    authenticator: ReceiptAuthenticator | None = None,
    signer_policy: ReceiptSignerPolicy | None = None,
) -> dict[str, Any]:
    """Verify supplied Nexus evidence against the current exact GitHub PR state.

    ``authenticator`` and ``signer_policy`` are host-side injection points; tool
    arguments can supply signature material but never choose the trusted signer.
    """

    owner, repository, pr_number, receipt, receipt_signature = _validate_arguments(arguments)
    policy = _resolve_signer_policy(owner, repository, signer_policy)
    acquisition = read_current_pull_request_subject(
        owner,
        repository,
        pr_number,
        github_port=github_port,
    )
    if acquisition.get("status") != "OK" or not isinstance(acquisition.get("subject"), Mapping):
        reason = acquisition.get("reason_code")
        if receipt is None:
            receipt_integrity = "ABSENT"
            core_verification = "NOT_AVAILABLE"
            receipt_reasons: tuple[str, ...] = ()
        else:
            validation: dict[str, Any]
            try:
                validation = validate_verification_receipt_payload(receipt)
            except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
                validation = {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
            receipt_reasons = tuple(validation["reason_codes"])
            receipt_integrity = "VALID" if validation["valid"] else "INVALID"
            core_verification = _core_status(receipt) if validation["valid"] else "NOT_AVAILABLE"
            if validation["valid"]:
                authentication = authenticate_receipt(
                    receipt, receipt_signature, policy=policy, authenticator=authenticator
                )
                if not authentication.authenticated:
                    core_verification = "NOT_AVAILABLE"
                    receipt_reasons = (*receipt_reasons, _authentication_reason(authentication))
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
    return evaluate_code_change_evidence_subject(
        acquisition["subject"],
        receipt,
        receipt_signature=receipt_signature,
        authenticator=authenticator,
        signer_policy=policy,
    )


__all__ = [
    "CLAIM_CEILING",
    "INPUT_SCHEMA",
    "OUTPUT_SCHEMA",
    "RECEIPT_AUTHENTICATION_UNAVAILABLE",
    "RECEIPT_NOT_AUTHENTICATED",
    "TOOL_DEFINITION",
    "TOOL_DESCRIPTION",
    "TOOL_NAME",
    "authenticate_receipt",
    "evaluate_code_change_evidence_subject",
    "verify_code_change_evidence",
]
