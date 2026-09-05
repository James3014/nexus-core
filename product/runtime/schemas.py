"""Canonical schemas and validation functions for Core V1 HTTP runtime (TG-5)."""

from __future__ import annotations

import re
from typing import Any, Mapping

from product.certification.receipt import CLAIM_CEILING
from product.evidence import _hash
from product.protocol import (
    CERTIFICATION_RECEIPT_SCHEMA,
    IMPLEMENTATION_SCHEMA,
    PUBLIC_PROTOCOL_VERSION,
)

CERTIFICATION_REQUEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "nexus.core.certification-request.v1",
    "type": "object",
    "required": [
        "protocol_version",
        "implementation_schema",
        "repository",
        "acceptance_contract",
        "verification_plan",
        "profile_id",
        "idempotency_key",
        "expected_generation",
    ],
    "properties": {
        "protocol_version": {"type": "string", "const": PUBLIC_PROTOCOL_VERSION},
        "implementation_schema": {"type": "string", "const": IMPLEMENTATION_SCHEMA},
        "repository": {
            "type": "object",
            "required": [
                "owner",
                "name",
                "pr_number",
                "expected_base_sha",
                "expected_head_sha",
            ],
            "properties": {
                "owner": {"type": "string"},
                "name": {"type": "string"},
                "pr_number": {"type": "integer", "minimum": 1},
                "expected_base_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "expected_head_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            },
            "additionalProperties": False,
        },
        "acceptance_contract": {"type": "object"},
        "verification_plan": {"type": "object"},
        "profile_id": {"type": "string", "const": "python-oci-pytest-v1"},
        "idempotency_key": {"type": "string", "maxLength": 128},
        "expected_generation": {"type": "integer", "minimum": 0},
    },
    "additionalProperties": False,
}

HTTP_RESPONSE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "nexus.core.http-response.v1",
    "type": "object",
    "required": [
        "request_id",
        "state",
        "generation",
        "acquisition",
        "execution",
        "evidence",
        "verification",
        "disposition",
        "receipt",
        "claim_ceiling",
    ],
    "properties": {
        "request_id": {"type": "string"},
        "state": {
            "type": "string",
            "enum": ["PENDING", "RUNNING", "COMPLETED", "FAILED", "UNVERIFIABLE"],
        },
        "generation": {"type": "integer"},
        "acquisition": {"type": ["object", "null"]},
        "execution": {"type": ["object", "null"]},
        "evidence": {"type": ["object", "null"]},
        "verification": {"type": ["object", "null"]},
        "disposition": {
            "type": ["string", "null"],
            "enum": ["CERTIFIED", "REJECTED", "BLOCKED", None],
        },
        "receipt": {"type": ["object", "null"]},
        "claim_ceiling": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "additionalProperties": False,
}

HTTP_ERROR_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "nexus.core.http-error.v1",
    "type": "object",
    "required": ["code", "request_id", "message"],
    "properties": {
        "code": {"type": "string"},
        "request_id": {"type": ["string", "null"]},
        "message": {"type": "string"},
    },
    "additionalProperties": False,
}

RECEIPT_VERIFY_REQUEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "nexus.core.receipt-verify-request.v1",
    "type": "object",
    "required": ["receipt", "requested_scope", "original_inputs"],
    "properties": {
        "receipt": {"type": "object"},
        "requested_scope": {
            "type": "string",
            "enum": ["AUTO", "ENVELOPE_ONLY", "FULL"],
        },
        "original_inputs": {"type": ["object", "null"]},
    },
    "additionalProperties": False,
}

RECEIPT_VERIFY_RESPONSE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "nexus.core.receipt-verify-response.v1",
    "type": "object",
    "required": [
        "scope",
        "status",
        "reason_codes",
        "receipt_hash",
        "recomputed_hash",
        "claim_ceiling",
    ],
    "properties": {
        "scope": {
            "type": "string",
            "enum": ["ENVELOPE_ONLY", "FULL_RECOMPUTED"],
        },
        "status": {
            "type": "string",
            "enum": ["VALID", "INVALID", "UNVERIFIABLE"],
        },
        "reason_codes": {
            "type": "array",
            "items": {"type": "string"},
        },
        "receipt_hash": {"type": "string"},
        "recomputed_hash": {"type": ["string", "null"]},
        "claim_ceiling": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "additionalProperties": False,
}

SCHEMA_BUNDLE: dict[str, dict[str, Any]] = {
    "CERTIFICATION_REQUEST_SCHEMA": CERTIFICATION_REQUEST_SCHEMA,
    "HTTP_ERROR_SCHEMA": HTTP_ERROR_SCHEMA,
    "HTTP_RESPONSE_SCHEMA": HTTP_RESPONSE_SCHEMA,
    "RECEIPT_VERIFY_REQUEST_SCHEMA": RECEIPT_VERIFY_REQUEST_SCHEMA,
    "RECEIPT_VERIFY_RESPONSE_SCHEMA": RECEIPT_VERIFY_RESPONSE_SCHEMA,
}

SCHEMA_BUNDLE_HASH: str = _hash(SCHEMA_BUNDLE)

_SHA40_RE = re.compile(r"^[0-9a-f]{40}")
_REQUIRED_REQUEST_KEYS = frozenset(CERTIFICATION_REQUEST_SCHEMA["required"])
_REQUIRED_REPO_KEYS = frozenset(
    CERTIFICATION_REQUEST_SCHEMA["properties"]["repository"]["required"]
)


def validate_certification_request(payload: Any) -> tuple[str, ...]:
    """Validate incoming certification request payload against schema and semantic constraints.

    Returns empty tuple on success, or tuple of error descriptions.
    """
    if not isinstance(payload, dict):
        return ("payload must be a JSON object",)

    keys = set(payload.keys())
    if keys != _REQUIRED_REQUEST_KEYS:
        missing = _REQUIRED_REQUEST_KEYS - keys
        extra = keys - _REQUIRED_REQUEST_KEYS
        errs = []
        if missing:
            errs.append(f"missing required keys: {sorted(missing)}")
        if extra:
            errs.append(f"unknown keys rejected: {sorted(extra)}")
        return tuple(errs)

    # Check for forbidden nulls in top-level required fields
    for k in _REQUIRED_REQUEST_KEYS:
        if payload[k] is None:
            return (f"null value forbidden for key '{k}'",)

    # Check protocol version and implementation schema
    if payload["protocol_version"] != PUBLIC_PROTOCOL_VERSION:
        return (f"unsupported protocol_version '{payload['protocol_version']}'",)
    if payload["implementation_schema"] != IMPLEMENTATION_SCHEMA:
        return (f"unsupported implementation_schema '{payload['implementation_schema']}'",)
    if payload["profile_id"] != "python-oci-pytest-v1":
        return (f"unsupported profile_id '{payload['profile_id']}'",)

    # Validate repository sub-object
    repo = payload["repository"]
    if not isinstance(repo, dict):
        return ("repository must be a JSON object",)
    repo_keys = set(repo.keys())
    if repo_keys != _REQUIRED_REPO_KEYS:
        missing_repo = _REQUIRED_REPO_KEYS - repo_keys
        extra_repo = repo_keys - _REQUIRED_REPO_KEYS
        errs = []
        if missing_repo:
            errs.append(f"repository missing keys: {sorted(missing_repo)}")
        if extra_repo:
            errs.append(f"repository unknown keys rejected: {sorted(extra_repo)}")
        return tuple(errs)

    for rk in _REQUIRED_REPO_KEYS:
        if repo[rk] is None:
            return (f"null value forbidden in repository key '{rk}'",)

    if (
        not isinstance(repo["owner"], str)
        or not repo["owner"]
        or repo["owner"] != repo["owner"].strip()
    ):
        return ("repository.owner must be a non-empty normalized string",)
    if (
        not isinstance(repo["name"], str)
        or not repo["name"]
        or repo["name"] != repo["name"].strip()
    ):
        return ("repository.name must be a non-empty normalized string",)
    if (
        not isinstance(repo["pr_number"], int)
        or isinstance(repo["pr_number"], bool)
        or repo["pr_number"] <= 0
    ):
        return ("repository.pr_number must be a positive integer",)

    base_sha = repo["expected_base_sha"]
    head_sha = repo["expected_head_sha"]
    if (
        not isinstance(base_sha, str)
        or len(base_sha) != 40
        or not all(c in "0123456789abcdef" for c in base_sha)
    ):
        return ("repository.expected_base_sha must be a 40-character lowercase hex string",)
    if (
        not isinstance(head_sha, str)
        or len(head_sha) != 40
        or not all(c in "0123456789abcdef" for c in head_sha)
    ):
        return ("repository.expected_head_sha must be a 40-character lowercase hex string",)
    if base_sha == head_sha:
        return ("repository.expected_base_sha and expected_head_sha must differ",)

    # Validate acceptance_contract and verification_plan objects
    if not isinstance(payload["acceptance_contract"], dict):
        return ("acceptance_contract must be a JSON object",)
    if not isinstance(payload["verification_plan"], dict):
        return ("verification_plan must be a JSON object",)

    # Validate idempotency_key
    ikey = payload["idempotency_key"]
    if (
        not isinstance(ikey, str)
        or not ikey
        or ikey != ikey.strip()
        or len(ikey.encode("utf-8")) > 128
    ):
        return ("idempotency_key must be a non-empty normalized string with length <= 128 bytes",)

    # Validate expected_generation
    exp_gen = payload["expected_generation"]
    if not isinstance(exp_gen, int) or isinstance(exp_gen, bool) or exp_gen < 0:
        return ("expected_generation must be a non-negative integer",)

    return ()


def make_http_response(
    *,
    request_id: str,
    state: str,
    generation: int,
    acquisition: Mapping[str, Any] | None = None,
    execution: Mapping[str, Any] | None = None,
    evidence: Mapping[str, Any] | None = None,
    verification: Mapping[str, Any] | None = None,
    disposition: str | None = None,
    receipt: Mapping[str, Any] | None = None,
    claim_ceiling: tuple[str, ...] | list[str] = CLAIM_CEILING,
) -> dict[str, Any]:
    """Construct canonical nexus.core.http-response.v1 dict with exact required keys.

    Unavailable sections are explicitly None/null, never omitted.
    """
    return {
        "request_id": request_id,
        "state": state,
        "generation": generation,
        "acquisition": dict(acquisition) if acquisition is not None else None,
        "execution": dict(execution) if execution is not None else None,
        "evidence": dict(evidence) if evidence is not None else None,
        "verification": dict(verification) if verification is not None else None,
        "disposition": disposition,
        "receipt": dict(receipt) if receipt is not None else None,
        "claim_ceiling": list(claim_ceiling),
    }


def make_http_error(
    *,
    code: str,
    request_id: str | None,
    message: str,
) -> dict[str, Any]:
    """Construct canonical nexus.core.http-error.v1 dict with generic non-leaking message."""
    return {
        "code": code,
        "request_id": request_id,
        "message": message,
    }


def validate_receipt_verify_request(payload: Any) -> tuple[str, ...]:
    """Validate incoming receipt verification request against schema."""
    if not isinstance(payload, dict):
        return ("payload must be a JSON object",)
    req_keys = frozenset(RECEIPT_VERIFY_REQUEST_SCHEMA["required"])
    if set(payload.keys()) != req_keys:
        return (f"keys must match {sorted(req_keys)}",)

    receipt = payload.get("receipt")
    if not isinstance(receipt, dict):
        return ("receipt must be a JSON object",)
    if receipt.get("receipt_schema") != CERTIFICATION_RECEIPT_SCHEMA:
        return ("invalid receipt_schema in receipt",)

    scope = payload.get("requested_scope")
    if scope not in {"AUTO", "ENVELOPE_ONLY", "FULL"}:
        return ("requested_scope must be AUTO, ENVELOPE_ONLY, or FULL",)

    orig_inputs = payload.get("original_inputs")
    if orig_inputs is not None and not isinstance(orig_inputs, dict):
        return ("original_inputs must be a JSON object or null",)

    return ()


__all__ = [
    "CERTIFICATION_REQUEST_SCHEMA",
    "HTTP_RESPONSE_SCHEMA",
    "HTTP_ERROR_SCHEMA",
    "RECEIPT_VERIFY_REQUEST_SCHEMA",
    "RECEIPT_VERIFY_RESPONSE_SCHEMA",
    "SCHEMA_BUNDLE",
    "SCHEMA_BUNDLE_HASH",
    "validate_certification_request",
    "make_http_response",
    "make_http_error",
    "validate_receipt_verify_request",
]
