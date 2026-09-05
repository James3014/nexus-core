"""Trusted certification adapter over the Task-3 evidence authority."""

import hashlib
import weakref
from dataclasses import dataclass
from enum import Enum

import product.kernel as kernel
from product.evidence import _hash
from product.evidence.ingestion import (
    EvidenceIdentityEnvelope,  # noqa: F401
    EvidenceSubmission,  # noqa: F401
    ExternalEd25519VerifierPort,  # noqa: F401
    ExternalVerificationReceipt,  # noqa: F401
    IngestionResult,  # noqa: F401
    IngestionTrustStatus,  # noqa: F401
    IssuerGrant,  # noqa: F401
    TrustDecision,  # noqa: F401
    TrustedIngestionContext,  # noqa: F401
    TrustReference,  # noqa: F401
    TrustRole,  # noqa: F401
    _parse_time,  # noqa: F401
    classify_ingestion_result,  # noqa: F401
    ingest_evidence,  # noqa: F401
    is_trusted_ingestion_result,  # noqa: F401
    load_external_verification_receipt,  # noqa: F401
    load_identity_envelope,  # noqa: F401
    make_identity_envelope,  # noqa: F401
    serialize_identity_envelope,  # noqa: F401
    verify_external_ed25519,  # noqa: F401
    verify_external_ed25519_receipt,  # noqa: F401
    verify_trust_reference_signature,  # noqa: F401
)
from product.kernel import CertificationInput, CertificationResult

EXTERNAL_RECEIPT_EXPECTATION_SCHEMA = "nexus.external_receipt_expectation.v1-experimental"
_ROLES = (TrustRole.POLICY, TrustRole.AUTHORITY, TrustRole.APPROVAL, TrustRole.SIGNING)
_TRUSTED_EXPECTATIONS = weakref.WeakKeyDictionary()
_TRUSTED_PREREQUISITES = weakref.WeakKeyDictionary()
_TRUSTED_CERTIFICATIONS = weakref.WeakKeyDictionary()


@dataclass(frozen=True, init=False, eq=False)
class ExternalReceiptExpectation:
    context_hash: str
    subject_hash: str
    profile_hash: str
    role: TrustRole
    evidence_id: str
    issuer_id: str
    expected_payload_hash: str
    required_action: str
    verification_method: str
    external_verification_receipt_hash: str

    def __init__(self, *args, **kwargs):
        raise TypeError("ExternalReceiptExpectation construction is internal")

    @property
    def hash(self):
        return _hash((
            EXTERNAL_RECEIPT_EXPECTATION_SCHEMA,
            self.context_hash,
            self.subject_hash,
            self.profile_hash,
            self.role.value,
            self.evidence_id,
            self.issuer_id,
            self.expected_payload_hash,
            self.required_action,
            self.verification_method,
            self.external_verification_receipt_hash,
        ))


class PrerequisiteValidationStatus(str, Enum):
    VALIDATED = "VALIDATED"
    INVALID = "INVALID"


@dataclass(frozen=True)
class PrerequisiteValidationResult:
    status: PrerequisiteValidationStatus
    prerequisites: "ValidatedPrerequisites | None"
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, init=False, eq=False)
class ValidatedPrerequisites:
    subject_hash: str
    context_hash: str
    profile_hash: str
    ingestion_bundle_hash: str
    ingestion_receipt_hash: str
    observed_at: str
    policy_accepted: bool
    authority_present: bool
    approval_present: bool
    signing_present: bool
    reference_hashes: tuple[str, ...]
    expectation_hashes: tuple[str, ...]

    def __init__(self, *args, **kwargs):
        raise TypeError("ValidatedPrerequisites construction is internal")

    @property
    def hash(self):
        return _hash(
            ("nexus.validated_prerequisites.v1-experimental",)
            + tuple(getattr(self, f) for f in self.__dataclass_fields__)
        )


@dataclass(frozen=True, init=False, eq=False)
class TrustedCertificationResult:
    context_hash: str
    profile_hash: str
    ingestion_bundle_hash: str
    ingestion_receipt_hash: str
    prerequisite_subject_hash: str
    prerequisites_hash: str
    core_receipt_hash: str
    core_result: CertificationResult

    def __init__(self, *args, **kwargs):
        raise TypeError("TrustedCertificationResult construction is internal")

    @property
    def hash(self):
        return _hash((
            "nexus.trusted_certification_wrapper.v1-experimental",
            self.context_hash,
            self.profile_hash,
            self.ingestion_bundle_hash,
            self.ingestion_receipt_hash,
            self.prerequisite_subject_hash,
            self.prerequisites_hash,
            self.core_receipt_hash,
        ))


def _subject(context, ingestion):
    return _hash((
        "nexus.trusted_prerequisite_subject.v1-experimental",
        context.hash,
        ingestion.bundle.hash,
    ))


def _raw_hash(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _mint(cls, values):
    value = object.__new__(cls)
    for name, item in zip(cls.__dataclass_fields__, values):
        object.__setattr__(value, name, item)
    return value


def _role_map(values, expected_type):
    if type(values) is not tuple or len(values) != 4:
        return None
    if any(type(v) is not expected_type for v in values):
        return None
    try:
        roles = tuple(v.role for v in values)
    except (AttributeError, TypeError):
        return None
    if roles != _ROLES:
        return None
    return dict(zip(roles, values))


def _valid_reference(value):
    try:
        value.__post_init__()
        return True
    except ValueError as exc:
        # The submitted receipt digest is deliberately checked at the
        # role-level decision table so it cannot mask an earlier role reason.
        return str(exc) == "external verification receipt hash mismatch"
    except (TypeError, AttributeError):
        return False


def _valid_expectation(value, context, ingestion):
    try:
        binding = _TRUSTED_EXPECTATIONS[value]
        return binding[0]() is context and binding[1]() is ingestion and value.hash == binding[2]
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _registered_prerequisite(value, context, ingestion):
    try:
        binding = _TRUSTED_PREREQUISITES[value]
        if binding[0]() is not context or binding[1]() is not ingestion:
            return False
        for name in (
            "subject_hash",
            "context_hash",
            "profile_hash",
            "ingestion_bundle_hash",
            "ingestion_receipt_hash",
            "observed_at",
        ):
            if type(getattr(value, name)) is not str:
                return False
        if any(
            type(getattr(value, name)) is not bool
            for name in (
                "policy_accepted",
                "authority_present",
                "approval_present",
                "signing_present",
            )
        ):
            return False
        for name in ("reference_hashes", "expectation_hashes"):
            items = getattr(value, name)
            if (
                type(items) is not tuple
                or len(items) != 4
                or any(type(item) is not str for item in items)
            ):
                return False
        return (
            value.subject_hash == _subject(context, ingestion)
            and value.context_hash == context.hash
            and value.profile_hash == context.expected_profile_hash
            and value.ingestion_bundle_hash == ingestion.bundle.hash
            and value.ingestion_receipt_hash == ingestion.receipt.hash
            and value.observed_at == context.observed_at
            and value.hash == binding[2]
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _prerequisite_shape(value):
    try:
        for name in (
            "subject_hash",
            "context_hash",
            "profile_hash",
            "ingestion_bundle_hash",
            "ingestion_receipt_hash",
            "observed_at",
        ):
            if type(getattr(value, name)) is not str:
                return False
        if any(
            type(getattr(value, name)) is not bool
            for name in (
                "policy_accepted",
                "authority_present",
                "approval_present",
                "signing_present",
            )
        ):
            return False
        return all(
            type(items := getattr(value, name)) is tuple
            and len(items) == 4
            and all(type(item) is str for item in items)
            for name in ("reference_hashes", "expectation_hashes")
        )
    except (AttributeError, TypeError):
        return False


def _bootstrap_external_receipt_expectation(
    *,
    context: TrustedIngestionContext,
    ingestion: IngestionResult,
    role: TrustRole,
    expected_evidence_id: str,
    expected_issuer_id: str,
    expected_verification_method: str,
    independently_expected_receipt: bytes,
) -> ExternalReceiptExpectation:
    if not is_trusted_ingestion_result(context, ingestion):
        raise ValueError("UNTRUSTED_INGESTION")
    if type(role) is not TrustRole or type(independently_expected_receipt) is not bytes:
        raise ValueError(f"{getattr(role, 'value', role)}:ISSUER_GRANT_MISSING")
    try:
        grant = next(g for g in context.profile.issuers if g.issuer_id == expected_issuer_id)
    except (AttributeError, StopIteration):
        raise ValueError(f"{role.value}:ISSUER_GRANT_MISSING") from None
    if role not in grant.roles:
        raise ValueError(f"{role.value}:ISSUER_GRANT_MISSING")
    if (
        context.required_action not in grant.actions
        or expected_verification_method not in grant.verification_methods
    ):
        raise ValueError(f"{role.value}:ISSUER_GRANT_MISMATCH")
    roots = dict(context.prerequisite_payload_hashes)
    if role not in roots:
        raise ValueError("UNTRUSTED_CONTEXT")
    value = _mint(
        ExternalReceiptExpectation,
        (
            context.hash,
            _subject(context, ingestion),
            context.expected_profile_hash,
            role,
            expected_evidence_id,
            expected_issuer_id,
            roots[role],
            context.required_action,
            expected_verification_method,
            _raw_hash(independently_expected_receipt),
        ),
    )
    _TRUSTED_EXPECTATIONS[value] = (weakref.ref(context), weakref.ref(ingestion), value.hash)
    return value


def _invalid(reason):
    return PrerequisiteValidationResult(PrerequisiteValidationStatus.INVALID, None, (reason,))


def validate_prerequisites(
    context: TrustedIngestionContext,
    ingestion: IngestionResult,
    references: tuple[TrustReference, ...],
    receipt_expectations: tuple[ExternalReceiptExpectation, ...],
) -> PrerequisiteValidationResult:
    if type(context) is not TrustedIngestionContext:
        return _invalid("MALFORMED_INPUT")
    try:
        context.__post_init__()
    except (TypeError, ValueError, AttributeError):
        return _invalid("UNTRUSTED_CONTEXT")
    if len(context.prerequisite_payload_hashes) != len(_ROLES) or {
        role for role, _ in context.prerequisite_payload_hashes
    } != set(_ROLES):
        return _invalid("UNTRUSTED_CONTEXT")
    try:
        profile_matches = context.expected_profile_hash == context.profile.hash
    except (TypeError, ValueError, AttributeError):
        return _invalid("UNTRUSTED_CONTEXT")
    if not profile_matches:
        return _invalid("PROFILE_MISMATCH")
    state = classify_ingestion_result(context, ingestion)
    if state is IngestionTrustStatus.UNTRUSTED:
        return _invalid("UNTRUSTED_INGESTION")
    if state is IngestionTrustStatus.RECEIPT_INVALID:
        return _invalid("INGESTION_RECEIPT_INVALID")
    refmap = _role_map(references, TrustReference)
    if refmap is None:
        return _invalid("ROLE_SET_INVALID")
    expmap = _role_map(receipt_expectations, ExternalReceiptExpectation)
    if expmap is None or any(
        not _valid_expectation(value, context, ingestion) for value in receipt_expectations
    ):
        return _invalid("EXPECTATION_SET_INVALID")
    if any(not _valid_reference(value) for value in references):
        return _invalid("ROLE_SET_INVALID")
    subject = _subject(context, ingestion)
    roots = dict(context.prerequisite_payload_hashes)
    reasons = []
    for role in _ROLES:
        ref, exp = refmap[role], expmap[role]
        raw_hash = _raw_hash(ref.external_verification_receipt)
        raw_hash_mismatch = raw_hash != ref.external_verification_receipt_hash
        issued_at = _parse_time(ref.issued_at)
        expires_at = _parse_time(ref.expires_at)
        revoked_at = _parse_time(ref.revoked_at)
        observed_at = _parse_time(context.observed_at)
        checks = (
            (ref.subject_hash != subject, "SUBJECT_MISMATCH"),
            (
                any(
                    (getattr(exp, f) != expected)
                    for f, expected in (
                        ("context_hash", context.hash),
                        ("subject_hash", subject),
                        ("profile_hash", context.expected_profile_hash),
                        ("role", role),
                        ("evidence_id", ref.evidence_id),
                        ("issuer_id", ref.issuer_id),
                        ("required_action", context.required_action),
                        ("verification_method", ref.verification_method),
                        ("expected_payload_hash", roots.get(role)),
                        ("external_verification_receipt_hash", raw_hash),
                    )
                    if getattr(exp, f) != expected
                    and not (f == "external_verification_receipt_hash" and raw_hash_mismatch)
                ),
                "EXTERNAL_RECEIPT_EXPECTATION_MISMATCH",
            ),
            (ref.action != context.required_action, "ACTION_MISMATCH"),
            (ref.payload_hash != roots.get(role), "PAYLOAD_HASH_MISMATCH"),
            (ref.signed_payload_hash != roots.get(role), "SIGNED_PAYLOAD_HASH_MISMATCH"),
            (
                _parse_time(ref.issued_at) is None
                or _parse_time(ref.expires_at) is None
                or (ref.revoked_at is not None and _parse_time(ref.revoked_at) is None),
                "TIMESTAMP_MALFORMED",
            ),
            (
                issued_at is not None and observed_at is not None and issued_at > observed_at,
                "ISSUED_AFTER_OBSERVED_AT",
            ),
            (
                expires_at is not None and observed_at is not None and expires_at <= observed_at,
                "EXPIRED_AT_OBSERVED_AT",
            ),
            (
                revoked_at is not None and observed_at is not None and revoked_at <= observed_at,
                "REVOKED_AT_OBSERVED_AT",
            ),
            (raw_hash_mismatch, "EXTERNAL_RECEIPT_HASH_MISMATCH"),
        )
        for failed, code in checks:
            if failed:
                reasons.append(f"{role.value}:{code}")
                break
    if reasons:
        return PrerequisiteValidationResult(
            PrerequisiteValidationStatus.INVALID, None, tuple(reasons)
        )
    bundle = ingestion.bundle
    if bundle is None:
        return _invalid("INGESTION_RECEIPT_INVALID")
    flags = [refmap[r].decision is TrustDecision.ALLOW for r in _ROLES]
    prereq = _mint(
        ValidatedPrerequisites,
        (
            subject,
            context.hash,
            context.expected_profile_hash,
            bundle.hash,
            ingestion.receipt.hash,
            context.observed_at,
            *flags,
            tuple(refmap[r].hash for r in _ROLES),
            tuple(expmap[r].hash for r in _ROLES),
        ),
    )
    _TRUSTED_PREREQUISITES[prereq] = (weakref.ref(context), weakref.ref(ingestion), prereq.hash)
    return PrerequisiteValidationResult(PrerequisiteValidationStatus.VALIDATED, prereq, ())


def certify_ingested(
    context: TrustedIngestionContext,
    ingestion: IngestionResult,
    prerequisites: ValidatedPrerequisites,
) -> TrustedCertificationResult:
    if type(context) is not TrustedIngestionContext:
        raise ValueError("invalid_trusted_certification_input:UNTRUSTED_CONTEXT")
    try:
        context.__post_init__()
    except (TypeError, ValueError, AttributeError):
        raise ValueError("invalid_trusted_certification_input:UNTRUSTED_CONTEXT") from None
    try:
        profile_matches = context.expected_profile_hash == context.profile.hash
    except (TypeError, ValueError, AttributeError):
        raise ValueError("invalid_trusted_certification_input:UNTRUSTED_CONTEXT") from None
    if not profile_matches:
        raise ValueError("invalid_trusted_certification_input:PROFILE_MISMATCH")
    state = classify_ingestion_result(context, ingestion)
    if state is IngestionTrustStatus.UNTRUSTED:
        raise ValueError("invalid_trusted_certification_input:UNTRUSTED_INGESTION")
    if state is IngestionTrustStatus.RECEIPT_INVALID:
        raise ValueError("invalid_trusted_certification_input:INGESTION_RECEIPT_INVALID")
    bundle = ingestion.bundle
    if bundle is None:
        raise ValueError("invalid_trusted_certification_input:INGESTION_RECEIPT_INVALID")
    if type(prerequisites) is not ValidatedPrerequisites:
        raise ValueError("invalid_trusted_certification_input:UNTRUSTED_PREREQUISITES")
    if not _registered_prerequisite(prerequisites, context, ingestion):
        raise ValueError("invalid_trusted_certification_input:UNTRUSTED_PREREQUISITES")
    # Reserved defensive invariant: registration already proves this, but
    # retain the explicit subject boundary after full capability validation.
    if prerequisites.subject_hash != _subject(context, ingestion):
        raise ValueError("invalid_trusted_certification_input:SUBJECT_MISMATCH")
    if (
        prerequisites.context_hash != context.hash
        or prerequisites.ingestion_receipt_hash != ingestion.receipt.hash
    ):
        raise ValueError("invalid_trusted_certification_input:SUBJECT_MISMATCH")
    core = kernel.certify(
        CertificationInput(
            context.contract,
            context.change_set,
            context.plan,
            bundle,
            prerequisites.policy_accepted,
            prerequisites.authority_present,
            prerequisites.approval_present,
            prerequisites.signing_present,
        )
    )
    result = _mint(
        TrustedCertificationResult,
        (
            context.hash,
            context.expected_profile_hash,
            bundle.hash,
            ingestion.receipt.hash,
            prerequisites.subject_hash,
            prerequisites.hash,
            core.receipt.hash,
            core,
        ),
    )
    _TRUSTED_CERTIFICATIONS[result] = (
        weakref.ref(context),
        weakref.ref(ingestion),
        weakref.ref(prerequisites),
        result.hash,
    )
    return result


def is_trusted_certification_result(
    context: TrustedIngestionContext,
    ingestion: IngestionResult,
    prerequisites: ValidatedPrerequisites,
    result: TrustedCertificationResult,
) -> bool:
    try:
        if type(result) is not TrustedCertificationResult or result not in _TRUSTED_CERTIFICATIONS:
            return False
        binding = _TRUSTED_CERTIFICATIONS[result]
        if (
            binding[0]() is not context
            or binding[1]() is not ingestion
            or binding[2]() is not prerequisites
        ):
            return False
        if not is_trusted_ingestion_result(context, ingestion) or not _registered_prerequisite(
            prerequisites, context, ingestion
        ):
            return False
        bundle = ingestion.bundle
        if bundle is None:
            return False
        if not (
            result.hash == binding[3]
            and result.context_hash == context.hash
            and result.ingestion_bundle_hash == bundle.hash
            and result.ingestion_receipt_hash == ingestion.receipt.hash
            and result.prerequisites_hash == prerequisites.hash
            and result.core_result.receipt.hash == result.core_receipt_hash
        ):
            return False
        expected = kernel.certify(
            CertificationInput(
                context.contract,
                context.change_set,
                context.plan,
                bundle,
                prerequisites.policy_accepted,
                prerequisites.authority_present,
                prerequisites.approval_present,
                prerequisites.signing_present,
            )
        )
        return (
            type(result.core_result) is type(expected)
            and result.core_result.receipt.hash == expected.receipt.hash
            and result.core_result.verification == expected.verification
            and result.core_result.disposition is expected.disposition
        )
    except Exception:
        return False


__all__ = [
    "EvidenceIdentityEnvelope",
    "ExternalVerificationReceipt",
    "load_external_verification_receipt",
    "ExternalEd25519VerifierPort",
    "make_identity_envelope",
    "serialize_identity_envelope",
    "load_identity_envelope",
    "verify_external_ed25519",
    "verify_external_ed25519_receipt",
    "verify_trust_reference_signature",
    "ExternalReceiptExpectation",
    "PrerequisiteValidationStatus",
    "PrerequisiteValidationResult",
    "ValidatedPrerequisites",
    "TrustedCertificationResult",
    "validate_prerequisites",
    "certify_ingested",
    "is_trusted_certification_result",
    "EXTERNAL_RECEIPT_EXPECTATION_SCHEMA",
]
