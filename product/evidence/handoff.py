"""Workflow/session handoff evidence verification (issue #59).

A bounded verification profile over a neutral, versioned handoff envelope. It
answers only whether handoff evidence is fresh, applicable, and untampered for
its stated exact source/attempt identity.

What this module does NOT do:

- it does not decide what task runs next;
- it does not resume execution, own a checkpoint, or hold a phase state machine;
- verification is not resume, merge, release, or deploy authority.

Freshness is derived from exact identity and content binding, never from chat
or wall-clock timestamps. Expected producer configuration can never fill a
missing observed identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from product.evidence import IntegrityStatus, _hash, _require_text

HANDOFF_SCHEMA = "nexus.core.workflow_handoff.v1"
HANDOFF_CLAIM_CEILING = "CORE_HANDOFF_EVIDENCE_VERIFICATION_ONLY"
SUPPORTED_HANDOFF_SCHEMAS = frozenset({HANDOFF_SCHEMA})


class HandoffVerdict(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    TAMPERED = "TAMPERED"
    STALE = "STALE"
    MISMATCHED = "MISMATCHED"


_FAIL_CLOSED = frozenset(
    {
        HandoffVerdict.INVALID,
        HandoffVerdict.TAMPERED,
        HandoffVerdict.STALE,
        HandoffVerdict.MISMATCHED,
    }
)


def is_trustworthy(verdict: HandoffVerdict) -> bool:
    """True only when evidence may be trusted for its stated exact identity."""
    return type(verdict) is HandoffVerdict and verdict is HandoffVerdict.VALID


class HandoffEvidenceError(ValueError):
    """Raised for structurally unusable handoff inputs during construction."""


def _text(value: Any, field: str) -> str:
    _require_text(value, field)
    return value


def _normalize_content_hash(value: str, field: str) -> str:
    """Accept bare 64-hex digests from foreign producers, return Core form."""
    text = value.strip()
    if text.startswith("sha256:"):
        return _require_sha256(text, field)
    if len(text) == 64 and all(c in "0123456789abcdef" for c in text):
        return "sha256:" + text
    raise HandoffEvidenceError(f"{field} must be a sha256 content hash")


def _require_sha256(value: Any, field: str) -> str:
    text = _text(value, field)
    if not text.startswith("sha256:"):
        raise HandoffEvidenceError(f"{field} must be a sha256 content hash")
    tail = text[len("sha256:") :]
    if len(tail) != 64 or any(c not in "0123456789abcdef" for c in tail):
        raise HandoffEvidenceError(f"{field} must be a sha256:<64 hex> content hash")
    return text


@dataclass(frozen=True)
class HandoffIdentity:
    """Exact physical identity a handoff claim applies to."""

    repository: str
    source_revision: str
    runtime_identity: str = ""
    target_revision: str = ""

    @classmethod
    def from_mapping(cls, data: Any) -> HandoffIdentity:
        if not isinstance(data, dict):
            raise HandoffEvidenceError("handoff identity must be an object")
        return cls(
            repository=_text(data.get("repository"), "repository"),
            source_revision=_text(data.get("source_revision"), "source_revision"),
            runtime_identity=str(data.get("runtime_identity") or "").strip(),
            target_revision=str(data.get("target_revision") or "").strip(),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "repository": self.repository,
            "source_revision": self.source_revision,
            "runtime_identity": self.runtime_identity,
            "target_revision": self.target_revision,
        }

    @property
    def binding_hash(self) -> str:
        return _hash(
            (
                self.repository,
                self.source_revision,
                self.runtime_identity,
                self.target_revision,
            )
        )


def identity_binding(value: Any) -> HandoffIdentity:
    if isinstance(value, HandoffIdentity):
        return value
    return HandoffIdentity.from_mapping(value)


@dataclass(frozen=True)
class HandoffVerification:
    """Deterministic, hash-bound verification result for one handoff envelope."""

    verdict: HandoffVerdict
    reason_codes: tuple[str, ...]
    integrity: IntegrityStatus
    input_binding_hash: str
    schema: str
    claim_ceiling: str

    def __post_init__(self) -> None:
        if type(self.verdict) is not HandoffVerdict:
            raise HandoffEvidenceError("verdict must be a HandoffVerdict")
        if type(self.reason_codes) is not tuple:
            raise HandoffEvidenceError("reason_codes must be a tuple")
        for code in self.reason_codes:
            if not isinstance(code, str) or not code or code != code.strip() or len(code) > 128:
                raise HandoffEvidenceError("reason_codes must be bounded nonblank strings")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise HandoffEvidenceError("reason_codes must be unique and sorted")
        if not isinstance(self.integrity, IntegrityStatus):
            raise HandoffEvidenceError("integrity must be an IntegrityStatus")
        _require_sha256(self.input_binding_hash, "input_binding_hash")
        if self.schema not in SUPPORTED_HANDOFF_SCHEMAS:
            raise HandoffEvidenceError("unsupported handoff schema")
        if self.claim_ceiling != HANDOFF_CLAIM_CEILING:
            raise HandoffEvidenceError("handoff claim ceiling mismatch")
        if self.verdict is HandoffVerdict.VALID and self.integrity is not IntegrityStatus.VALID:
            raise HandoffEvidenceError("a VALID verdict requires VALID integrity")

    @property
    def trustworthy(self) -> bool:
        return is_trustworthy(self.verdict)

    @property
    def hash(self) -> str:
        return _hash(
            (
                self.verdict.value,
                self.reason_codes,
                self.integrity.value,
                self.input_binding_hash,
                self.schema,
                self.claim_ceiling,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim_ceiling": self.claim_ceiling,
            "verdict": self.verdict.value,
            "trustworthy": self.trustworthy,
            "reason_codes": list(self.reason_codes),
            "integrity": self.integrity.value,
            "input_binding_hash": self.input_binding_hash,
            "verification_hash": self.hash,
            "authority_note": "verification_is_not_resume_merge_release_or_deploy_authority",
        }


def build_handoff_envelope(
    *,
    operation_id: str,
    attempt_id: str,
    identity: Any,
    checkpoint_content_hash: str,
    receipt_refs: tuple[str, ...] = (),
    asserted_phase: str = "",
    asserted_terminal: bool = False,
    checkpoint_status: str = "",
    producer_identity: str = "",
    body: Any = None,
    observed_identity: str = "",
) -> dict[str, Any]:
    """Build a neutral, hash-sealed handoff envelope.

    This is a construction helper only. Verdicts are produced by
    :func:`verify_handoff_evidence`, never here.
    """
    bound = identity_binding(identity)
    _text(operation_id, "operation_id")
    _text(attempt_id, "attempt_id")
    _require_sha256(checkpoint_content_hash, "checkpoint_content_hash")
    if type(asserted_terminal) is not bool:
        raise HandoffEvidenceError("asserted_terminal must be a bool")
    refs = tuple(dict.fromkeys(str(r).strip() for r in receipt_refs if str(r).strip()))
    envelope: dict[str, Any] = {
        "schema": HANDOFF_SCHEMA,
        "operation_id": operation_id.strip(),
        "attempt_id": attempt_id.strip(),
        "identity": bound.to_dict(),
        "identity_binding_hash": bound.binding_hash,
        "checkpoint": {
            "content_hash": checkpoint_content_hash,
            "status": str(checkpoint_status or "").strip(),
        },
        "receipt_refs": list(refs),
        "asserted_phase": str(asserted_phase or "").strip(),
        "asserted_terminal": asserted_terminal,
        "producer_identity": str(producer_identity or "").strip(),
        "observed_identity": str(observed_identity or "").strip(),
        "body": body if body is not None else {},
        "claim_ceiling": HANDOFF_CLAIM_CEILING,
    }
    # The body is always a neutral object; its content hash is always declared
    # and always recomputable, so an empty body is still bound explicitly.
    envelope["body_content_hash"] = _hash(envelope["body"])
    envelope["envelope_hash"] = _hash({k: v for k, v in envelope.items() if k != "envelope_hash"})
    return envelope


def _result(
    verdict: HandoffVerdict,
    reasons: list[str],
    *,
    input_binding_hash: str,
    integrity: IntegrityStatus,
) -> HandoffVerification:
    return HandoffVerification(
        verdict=verdict,
        reason_codes=tuple(sorted(set(reasons))),
        integrity=integrity,
        input_binding_hash=input_binding_hash,
        schema=HANDOFF_SCHEMA,
        claim_ceiling=HANDOFF_CLAIM_CEILING,
    )


def _empty_binding(reason: str) -> str:
    # A failed binding is bound to the failing reason so it never collides with
    # a real input binding.
    return _hash(("handoff-binding-unavailable", reason))


def verify_handoff_evidence(
    envelope: Any,
    *,
    current_identity: Any = None,
) -> HandoffVerification:
    """Verify one handoff envelope against exact current physical identity.

    Fail-closed precedence: structure, then tamper, then staleness, then
    internal mismatch. Freshness never uses a timestamp.
    """
    if not isinstance(envelope, dict):
        return _result(
            HandoffVerdict.INVALID,
            ["INVALID:envelope_not_object"],
            input_binding_hash=_empty_binding("not-object"),
            integrity=IntegrityStatus.MALFORMED,
        )
    schema = envelope.get("schema")
    if schema not in SUPPORTED_HANDOFF_SCHEMAS:
        return _result(
            HandoffVerdict.INVALID,
            ["INVALID:schema"],
            input_binding_hash=_empty_binding("schema"),
            integrity=IntegrityStatus.MALFORMED,
        )
    if envelope.get("claim_ceiling") != HANDOFF_CLAIM_CEILING:
        return _result(
            HandoffVerdict.INVALID,
            ["INVALID:claim_ceiling_escalation"],
            input_binding_hash=_empty_binding("ceiling"),
            integrity=IntegrityStatus.MALFORMED,
        )
    try:
        operation_id = _text(envelope.get("operation_id"), "operation_id")
        attempt_id = _text(envelope.get("attempt_id"), "attempt_id")
        identity = HandoffIdentity.from_mapping(envelope.get("identity"))
        checkpoint = envelope.get("checkpoint")
        if not isinstance(checkpoint, dict):
            raise HandoffEvidenceError("checkpoint must be an object")
        checkpoint_hash = _require_sha256(checkpoint.get("content_hash"), "checkpoint.content_hash")
        receipt_refs = envelope.get("receipt_refs")
        if not isinstance(receipt_refs, list) or any(
            not isinstance(item, str) or not item.strip() for item in receipt_refs
        ):
            raise HandoffEvidenceError("receipt_refs must be a list of non-empty strings")
        asserted_terminal = envelope.get("asserted_terminal")
        if type(asserted_terminal) is not bool:
            raise HandoffEvidenceError("asserted_terminal must be a bool")
    except (TypeError, ValueError) as exc:
        return _result(
            HandoffVerdict.INVALID,
            [f"INVALID:{type(exc).__name__}"],
            input_binding_hash=_empty_binding(str(exc)),
            integrity=IntegrityStatus.MALFORMED,
        )

    # Freshness is bound to exact inputs, never to a chat or wall-clock time.
    current = None
    if current_identity is not None:
        try:
            current = identity_binding(current_identity)
        except HandoffEvidenceError:
            return _result(
                HandoffVerdict.INVALID,
                ["INVALID:current_identity_unusable"],
                input_binding_hash=_empty_binding("current-identity"),
                integrity=IntegrityStatus.MALFORMED,
            )

    input_binding_hash = _hash(
        (
            schema,
            operation_id,
            attempt_id,
            identity.binding_hash,
            checkpoint_hash,
            tuple(receipt_refs),
            str(envelope.get("asserted_phase") or ""),
            asserted_terminal,
            str(envelope.get("producer_identity") or ""),
            str(envelope.get("observed_identity") or ""),
            current.binding_hash if current is not None else "",
        )
    )

    # --- Tamper: every declared hash must recompute exactly. ---
    tamper_reasons: list[str] = []
    declared_binding = envelope.get("identity_binding_hash")
    if not isinstance(declared_binding, str) or declared_binding != identity.binding_hash:
        tamper_reasons.append("TAMPERED:identity_binding_hash")
    body = envelope.get("body")
    if body is not None and not isinstance(body, dict):
        return _result(
            HandoffVerdict.INVALID,
            ["INVALID:body_not_object"],
            input_binding_hash=input_binding_hash,
            integrity=IntegrityStatus.MALFORMED,
        )
    declared_body_hash = envelope.get("body_content_hash")
    if isinstance(body, dict):
        recomputed_body_hash = _hash(body)
        if declared_body_hash != recomputed_body_hash:
            tamper_reasons.append("TAMPERED:body_content_hash")
    elif declared_body_hash not in (None, ""):
        tamper_reasons.append("TAMPERED:body_content_hash")
    recomputed_envelope_hash = _hash({k: v for k, v in envelope.items() if k != "envelope_hash"})
    if envelope.get("envelope_hash") != recomputed_envelope_hash:
        tamper_reasons.append("TAMPERED:envelope_hash")
    if tamper_reasons:
        return _result(
            HandoffVerdict.TAMPERED,
            tamper_reasons,
            input_binding_hash=input_binding_hash,
            integrity=IntegrityStatus.TAMPERED,
        )

    # --- Stale: exact identity binding, never a timestamp. ---
    if current is not None:
        stale_fields = [
            name
            for name in ("repository", "source_revision")
            if getattr(identity, name) != getattr(current, name)
        ]
        if identity.runtime_identity and current.runtime_identity:
            if identity.runtime_identity != current.runtime_identity:
                stale_fields.append("runtime_identity")
        if stale_fields:
            return _result(
                HandoffVerdict.STALE,
                [f"STALE:identity:{name}" for name in stale_fields],
                input_binding_hash=input_binding_hash,
                integrity=IntegrityStatus.STALE,
            )

    # --- Internal mismatch: the claim disagrees with itself. ---
    mismatch: list[str] = []
    if isinstance(body, dict) and declared_body_hash:
        if checkpoint_hash != declared_body_hash:
            mismatch.append("MISMATCHED:checkpoint_content_hash")
    checkpoint_status = str(checkpoint.get("status") or "").strip()
    if asserted_terminal and not checkpoint_status:
        mismatch.append("MISMATCHED:terminal_without_status")
    producer_identity = str(envelope.get("producer_identity") or "").strip()
    observed_identity = str(envelope.get("observed_identity") or "").strip()
    if producer_identity and not observed_identity:
        mismatch.append("MISMATCHED:observed_identity_missing")
    if mismatch:
        return _result(
            HandoffVerdict.MISMATCHED,
            mismatch,
            input_binding_hash=input_binding_hash,
            integrity=IntegrityStatus.CROSS_BOUND,
        )

    return _result(
        HandoffVerdict.VALID,
        ["VALID:exact_identity_and_content_bound"],
        input_binding_hash=input_binding_hash,
        integrity=IntegrityStatus.VALID,
    )


def project_workflow_checkpoint_envelope(
    checkpoint: Any,
    *,
    producer_identity: str = "",
    observed_identity: str = "",
) -> dict[str, Any]:
    """Project a nexus-runtime workflow checkpoint dict into this envelope.

    Compatibility adapter only: Core consumes a neutral shape and never holds a
    copy of the runtime state machine.
    """
    if not isinstance(checkpoint, dict):
        raise HandoffEvidenceError("checkpoint payload must be an object")
    status = str(checkpoint.get("status") or "").strip()
    terminal = status in {"COMPLETED", "FAILED"}
    receipts = list(checkpoint.get("evidence_refs") or [])
    for effect in checkpoint.get("completed_effects") or []:
        if isinstance(effect, dict) and str(effect.get("receipt_ref") or "").strip():
            receipts.append(str(effect["receipt_ref"]).strip())
    return build_handoff_envelope(
        operation_id=str(checkpoint.get("operation_id") or ""),
        attempt_id=str(checkpoint.get("attempt_id") or ""),
        identity=checkpoint.get("identity") or {},
        checkpoint_content_hash=_normalize_content_hash(
            str(checkpoint.get("checkpoint_hash") or ""), "checkpoint_hash"
        ),
        receipt_refs=tuple(receipts),
        asserted_phase=str(checkpoint.get("phase") or ""),
        asserted_terminal=terminal,
        checkpoint_status=status,
        producer_identity=producer_identity,
        observed_identity=observed_identity,
        body={k: v for k, v in checkpoint.items() if k != "checkpoint_hash"},
    )


__all__ = [
    "HANDOFF_CLAIM_CEILING",
    "HANDOFF_SCHEMA",
    "SUPPORTED_HANDOFF_SCHEMAS",
    "HandoffEvidenceError",
    "HandoffIdentity",
    "HandoffVerdict",
    "HandoffVerification",
    "build_handoff_envelope",
    "identity_binding",
    "is_trustworthy",
    "project_workflow_checkpoint_envelope",
    "verify_handoff_evidence",
]
