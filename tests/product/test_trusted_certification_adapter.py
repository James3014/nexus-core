"""RED contract for the provider-neutral trusted certification adapter."""

import ast
import copy
import dataclasses
import gc
import hashlib
import importlib
import inspect
import sys
import weakref
from contextlib import contextmanager
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import get_type_hints

import pytest

from product.evidence import IntegrityStatus, _hash

TRUSTED_SOURCE = Path("product/adapters/trusted.py")
ROLE_NAMES = ("POLICY", "AUTHORITY", "APPROVAL", "SIGNING")


def _api():
    # Deferred so RED collection succeeds while the adapter is absent.
    from product.adapters import trusted

    return trusted


def _task3_fixture():
    from tests.product.test_trusted_evidence_ingestion import _fixture

    return _fixture()


def _at(seconds=0):
    return (
        datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    ).isoformat()


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _forge(value, **changes):
    clone = object.__new__(type(value))
    for name, item in vars(value).items():
        object.__setattr__(clone, name, changes.get(name, item))
    return clone


def _mutate(value, name, item):
    object.__setattr__(value, name, item)


def _subject(context, ingestion):
    return _hash((
        "nexus.trusted_prerequisite_subject.v1-experimental",
        context.hash,
        ingestion.bundle.hash,
    ))


def _four_role_fixture(*, decisions=None):
    api = _api()
    task3, context, submission, envelope = _task3_fixture()
    roles = tuple(task3.TrustRole)
    decisions = decisions or {}
    issuers = tuple(
        sorted(
            (
                task3.IssuerGrant(f"issuer-{role.value.lower()}", (role,), ("merge",), ("pytest",))
                for role in roles
            ),
            key=lambda grant: grant.issuer_id,
        )
    )
    profile = replace(context.profile, issuers=issuers)
    roots = tuple(
        sorted(
            ((role, _hash(f"independent-root-{role.value}")) for role in roles),
            key=lambda pair: pair[0].value,
        )
    )
    context = replace(
        context,
        profile=profile,
        expected_profile_hash=profile.hash,
        prerequisite_payload_hashes=roots,
    )
    ingestion = task3.ingest_evidence(context, (submission,))
    assert task3.classify_ingestion_result(context, ingestion) is task3.IngestionTrustStatus.TRUSTED
    receipt = b"independently pinned external receipt"
    references = tuple(
        task3.TrustReference(
            role,
            envelope.evidence_id,
            f"issuer-{role.value.lower()}",
            _subject(context, ingestion),
            context.required_action,
            decisions.get(role, task3.TrustDecision.ALLOW),
            _at(-20),
            _at(3500),
            None,
            dict(roots)[role],
            dict(roots)[role],
            "pytest",
            receipt,
            _sha(receipt),
        )
        for role in roles
    )
    expectations = tuple(
        api._bootstrap_external_receipt_expectation(
            context=context,
            ingestion=ingestion,
            role=role,
            expected_evidence_id=envelope.evidence_id,
            expected_issuer_id=f"issuer-{role.value.lower()}",
            expected_verification_method="pytest",
            independently_expected_receipt=receipt,
        )
        for role in roles
    )
    validation = api.validate_prerequisites(context, ingestion, references, expectations)
    assert validation.status is api.PrerequisiteValidationStatus.VALIDATED
    assert validation.prerequisites is not None
    result = api.certify_ingested(context, ingestion, validation.prerequisites)
    return api, context, ingestion, references, expectations, validation.prerequisites, result


def _assert_invalid(outcome, reasons):
    api = _api()
    assert outcome.status is api.PrerequisiteValidationStatus.INVALID
    assert outcome.prerequisites is None
    assert outcome.reason_codes == reasons


def _validate(context, ingestion, references, expectations):
    return _api().validate_prerequisites(context, ingestion, references, expectations)


def _import_targets(tree):
    """Normalize both import forms to their fully qualified imported targets."""
    targets = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            targets.extend(
                f"{module}.{alias.name}" if module else alias.name for alias in node.names
            )
    return tuple(targets)


def _dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


@contextmanager
def _adapter_with_core_spy(monkeypatch):
    """Patch public kernel before fresh adapter import and restore module isolation."""
    import product.adapters as adapters
    import product.kernel as kernel

    original = kernel.certify
    calls = []
    control = {"transform": None}

    def counted(value):
        calls.append(value)
        result = original(value)
        transform = control["transform"]
        return result if transform is None else transform(result)

    monkeypatch.setattr(kernel, "certify", counted)
    sys.modules.pop("product.adapters.trusted", None)
    if hasattr(adapters, "trusted"):
        delattr(adapters, "trusted")
    api = importlib.import_module("product.adapters.trusted")
    try:
        yield api, calls, control
    finally:
        sys.modules.pop("product.adapters.trusted", None)
        if hasattr(adapters, "trusted"):
            delattr(adapters, "trusted")
        monkeypatch.setattr(kernel, "certify", original)


def _trusted_variant(api, context, kind):
    """Mint a distinct exact context/ingestion for replay counterexamples."""
    _, _, submission, _ = _task3_fixture()
    if kind == "bundle":
        envelope = replace(submission.provenance, source_locator="tests/distinct.py")
        submission = replace(submission, provenance=envelope)
        requirement = replace(context.requirements[0], provenance_hash=envelope.hash)
        context = replace(context, requirements=(requirement,))
    elif kind == "payload":
        roots = dict(context.prerequisite_payload_hashes)
        roots[api.TrustRole.POLICY] = _hash("distinct-policy-root")
        context = replace(
            context,
            prerequisite_payload_hashes=tuple(
                sorted(roots.items(), key=lambda pair: (pair[0].value, pair[1]))
            ),
        )
    elif kind in {"action", "method"}:
        grants = tuple(
            replace(
                grant,
                actions=("promote",) if kind == "action" else grant.actions,
                verification_methods=("other-method",)
                if kind == "method"
                else grant.verification_methods,
            )
            if api.TrustRole.POLICY in grant.roles
            else grant
            for grant in context.profile.issuers
        )
        profile = replace(context.profile, issuers=grants)
        context = replace(
            context,
            profile=profile,
            expected_profile_hash=profile.hash,
            required_action="promote" if kind == "action" else context.required_action,
        )
    else:
        envelope = replace(submission.provenance, repository_id="repo-distinct")
        submission = replace(submission, provenance=envelope)
        requirement = replace(context.requirements[0], provenance_hash=envelope.hash)
        context = replace(
            context,
            repository_id="repo-distinct",
            requirements=(requirement,),
        )
    ingestion = api.ingest_evidence(context, (submission,))
    assert api.classify_ingestion_result(context, ingestion) is api.IngestionTrustStatus.TRUSTED
    return context, ingestion


def test_task3_exact_authority_reuse_and_no_parallel_types():
    """T4-1 / Architecture A / Architecture B: exact Task-3 authority reuse."""
    api = _api()
    from product.evidence import ingestion

    names = (
        "TrustRole",
        "TrustDecision",
        "IssuerGrant",
        "TrustReference",
        "TrustedIngestionContext",
        "EvidenceSubmission",
        "IngestionResult",
        "IngestionTrustStatus",
        "ingest_evidence",
        "classify_ingestion_result",
        "is_trusted_ingestion_result",
        "_parse_time",
    )
    for name in names:
        assert getattr(api, name) is getattr(ingestion, name)
    definitions = {
        node.name
        for node in ast.walk(ast.parse(TRUSTED_SOURCE.read_text()))
        if isinstance(node, (ast.ClassDef, ast.FunctionDef))
    }
    assert definitions.isdisjoint(set(names[:-4]))


def test_exact_shapes_hashes_and_constructor_boundaries():
    """T4-10, T4-20, T4-25 / Architecture C: exact sealed value surfaces."""
    api, context, ingestion, _, expectations, prerequisites, result = _four_role_fixture()
    expected = {
        "ExternalReceiptExpectation": (
            "context_hash",
            "subject_hash",
            "profile_hash",
            "role",
            "evidence_id",
            "issuer_id",
            "expected_payload_hash",
            "required_action",
            "verification_method",
            "external_verification_receipt_hash",
        ),
        "PrerequisiteValidationResult": ("status", "prerequisites", "reason_codes"),
        "ValidatedPrerequisites": (
            "subject_hash",
            "context_hash",
            "profile_hash",
            "ingestion_bundle_hash",
            "ingestion_receipt_hash",
            "observed_at",
            "policy_accepted",
            "authority_present",
            "approval_present",
            "signing_present",
            "reference_hashes",
            "expectation_hashes",
        ),
        "TrustedCertificationResult": (
            "context_hash",
            "profile_hash",
            "ingestion_bundle_hash",
            "ingestion_receipt_hash",
            "prerequisite_subject_hash",
            "prerequisites_hash",
            "core_receipt_hash",
            "core_result",
        ),
    }
    for name, names in expected.items():
        cls = getattr(api, name)
        assert tuple(field.name for field in fields(cls)) == names
        assert cls.__dataclass_params__.frozen
        if name != "PrerequisiteValidationResult":
            assert cls.__dataclass_params__.init is False
            assert cls.__dataclass_params__.eq is False
            with pytest.raises(TypeError):
                cls()
    expectation = expectations[0]
    assert expectation.hash == _hash((
        "nexus.external_receipt_expectation.v1-experimental",
        expectation.context_hash,
        expectation.subject_hash,
        expectation.profile_hash,
        expectation.role.value,
        expectation.evidence_id,
        expectation.issuer_id,
        expectation.expected_payload_hash,
        expectation.required_action,
        expectation.verification_method,
        expectation.external_verification_receipt_hash,
    ))
    assert prerequisites.hash == _hash(
        ("nexus.validated_prerequisites.v1-experimental",)
        + tuple(getattr(prerequisites, field.name) for field in fields(prerequisites))
    )
    assert result.hash == _hash((
        "nexus.trusted_certification_wrapper.v1-experimental",
        result.context_hash,
        result.profile_hash,
        result.ingestion_bundle_hash,
        result.ingestion_receipt_hash,
        result.prerequisite_subject_hash,
        result.prerequisites_hash,
        result.core_receipt_hash,
    ))
    assert expectation.subject_hash == _subject(context, ingestion)
    assert set(api.PrerequisiteValidationStatus.__members__) == {"VALIDATED", "INVALID"}
    assert "ExternalReceiptExpectation" in api.__all__
    assert "_bootstrap_external_receipt_expectation" not in api.__all__


def test_bootstrap_signature_and_every_derived_field():
    """T4-10A-B, T4-25: no raw hash/reference input; all roots are derived."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    signature = inspect.signature(api._bootstrap_external_receipt_expectation)
    assert tuple(signature.parameters) == (
        "context",
        "ingestion",
        "role",
        "expected_evidence_id",
        "expected_issuer_id",
        "expected_verification_method",
        "independently_expected_receipt",
    )
    assert all(
        value.kind is inspect.Parameter.KEYWORD_ONLY for value in signature.parameters.values()
    )
    assert not {"expected_hash", "reference", "payload_hash"} & set(signature.parameters)
    roots = dict(context.prerequisite_payload_hashes)
    for reference, expectation in zip(references, expectations, strict=True):
        assert expectation.context_hash == context.hash
        assert expectation.subject_hash == _subject(context, ingestion)
        assert expectation.profile_hash == context.expected_profile_hash
        assert expectation.role is reference.role
        assert expectation.evidence_id == reference.evidence_id
        assert expectation.issuer_id == reference.issuer_id
        assert expectation.expected_payload_hash == roots[reference.role]
        assert expectation.required_action == context.required_action
        assert expectation.verification_method == "pytest"
        assert expectation.external_verification_receipt_hash == _sha(
            reference.external_verification_receipt
        )


@pytest.mark.parametrize("role_name", ROLE_NAMES)
@pytest.mark.parametrize("kind", ("missing", "duplicate", "extra", "wrong_type"))
def test_full_reference_cardinality_matrix(role_name, kind):
    """T4-2: every role's missing/duplicate/extra/wrong-type reference is rejected."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    index = tuple(api.TrustRole).index(api.TrustRole[role_name])
    if kind == "missing":
        references = references[:index] + references[index + 1 :]
    elif kind == "duplicate":
        references += (references[index],)
    elif kind == "extra":
        references += (object(),)
    else:
        references = references[:index] + (object(),) + references[index + 1 :]
    _assert_invalid(_validate(context, ingestion, references, expectations), ("ROLE_SET_INVALID",))


@pytest.mark.parametrize("role_name", ROLE_NAMES)
@pytest.mark.parametrize("kind", ("missing", "duplicate", "extra", "wrong_type", "unregistered"))
def test_full_expectation_cardinality_and_registry_matrix(role_name, kind):
    """T4-2, T4-10C: only one registry-minted expectation per role is accepted."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    index = tuple(api.TrustRole).index(api.TrustRole[role_name])
    if kind == "missing":
        expectations = expectations[:index] + expectations[index + 1 :]
    elif kind == "duplicate":
        expectations += (expectations[index],)
    elif kind == "extra":
        expectations += (object(),)
    elif kind == "wrong_type":
        expectations = expectations[:index] + (object(),) + expectations[index + 1 :]
    else:
        expectations = (
            expectations[:index] + (_forge(expectations[index]),) + expectations[index + 1 :]
        )
    _assert_invalid(
        _validate(context, ingestion, references, expectations),
        ("EXPECTATION_SET_INVALID",),
    )


def test_cross_admission_between_reference_and_expectation_sets_is_bounded():
    """T4-2: valid opposite-set capabilities return set-invalid, never exceptions."""
    _, context, ingestion, references, expectations, *_ = _four_role_fixture()
    wrong_references = (expectations[0],) + references[1:]
    _assert_invalid(
        _validate(context, ingestion, wrong_references, expectations),
        ("ROLE_SET_INVALID",),
    )
    wrong_expectations = (references[0],) + expectations[1:]
    _assert_invalid(
        _validate(context, ingestion, references, wrong_expectations),
        ("EXPECTATION_SET_INVALID",),
    )


def test_exact_type_objects_missing_role_are_bounded_set_invalid():
    """T4-2: constructor-bypassed exact objects missing role never leak AttributeError."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    missing_reference_role = object.__new__(api.TrustReference)
    _assert_invalid(
        api.validate_prerequisites(
            context,
            ingestion,
            (missing_reference_role,) + references[1:],
            expectations,
        ),
        ("ROLE_SET_INVALID",),
    )
    missing_expectation_role = object.__new__(api.ExternalReceiptExpectation)
    _assert_invalid(
        api.validate_prerequisites(
            context,
            ingestion,
            references,
            (missing_expectation_role,) + expectations[1:],
        ),
        ("EXPECTATION_SET_INVALID",),
    )


@pytest.mark.parametrize("role_name", ROLE_NAMES)
@pytest.mark.parametrize(
    "change,expected_suffix",
    (
        ("missing", "ISSUER_GRANT_MISSING"),
        ("action", "ISSUER_GRANT_MISMATCH"),
        ("method", "ISSUER_GRANT_MISMATCH"),
        ("role", "ISSUER_GRANT_MISSING"),
    ),
)
def test_bootstrap_only_issuer_grant_missing_and_mismatch(role_name, change, expected_suffix):
    """T4-4, T4-6, T4-29: issuer denials are reachable only in private bootstrap."""
    api, context, _, *_ = _four_role_fixture()
    role = api.TrustRole[role_name]
    issuer_id = f"issuer-{role.value.lower()}"
    grants = list(context.profile.issuers)
    index = next(i for i, grant in enumerate(grants) if grant.issuer_id == issuer_id)
    if change == "missing":
        grants.pop(index)
    elif change == "action":
        grants[index] = replace(grants[index], actions=("release",))
    elif change == "method":
        grants[index] = replace(grants[index], verification_methods=("other",))
    else:
        other = (
            api.TrustRole.AUTHORITY if role is not api.TrustRole.AUTHORITY else api.TrustRole.POLICY
        )
        grants[index] = replace(grants[index], roles=(other,))
    profile = replace(
        context.profile, issuers=tuple(sorted(grants, key=lambda item: item.issuer_id))
    )
    changed_context = replace(context, profile=profile, expected_profile_hash=profile.hash)
    _, _, submission, _ = _task3_fixture()
    changed_ingestion = api.ingest_evidence(changed_context, (submission,))
    assert (
        api.classify_ingestion_result(changed_context, changed_ingestion)
        is api.IngestionTrustStatus.TRUSTED
    )
    with pytest.raises(ValueError, match=f"^{role_name}:{expected_suffix}$"):
        api._bootstrap_external_receipt_expectation(
            context=changed_context,
            ingestion=changed_ingestion,
            role=role,
            expected_evidence_id="evidence-1",
            expected_issuer_id=issuer_id,
            expected_verification_method="pytest",
            independently_expected_receipt=b"independently pinned external receipt",
        )


@pytest.mark.parametrize(
    "field,value,reason",
    (
        ("subject_hash", _hash("wrong-subject"), "SUBJECT_MISMATCH"),
        ("action", "release", "ACTION_MISMATCH"),
        ("payload_hash", _hash("wrong-payload"), "PAYLOAD_HASH_MISMATCH"),
        ("signed_payload_hash", _hash("wrong-signed"), "SIGNED_PAYLOAD_HASH_MISMATCH"),
    ),
)
def test_reference_subject_action_and_independent_payload_roots(field, value, reason):
    """T4-5, T4-7, T4-8, T4-11: submitted roots cannot replace context truth."""
    _, context, ingestion, references, expectations, *_ = _four_role_fixture()
    changed = (replace(references[0], **{field: value}),) + references[1:]
    _assert_invalid(_validate(context, ingestion, changed, expectations), (f"POLICY:{reason}",))


@pytest.mark.parametrize(
    "field,value",
    (
        ("verification_method", "other"),
        ("issuer_id", "other-issuer"),
        ("evidence_id", "other-evidence"),
    ),
)
def test_reference_identity_cannot_select_expectation_identity(field, value):
    """T4-6, T4-10B, T4-24: independently minted identity wins."""
    _, context, ingestion, references, expectations, *_ = _four_role_fixture()
    changed = (replace(references[0], **{field: value}),) + references[1:]
    _assert_invalid(
        _validate(context, ingestion, changed, expectations),
        ("POLICY:EXTERNAL_RECEIPT_EXPECTATION_MISMATCH",),
    )


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("external_verification_receipt", b"changed bytes"),
        ("external_verification_receipt_hash", _sha(b"changed digest")),
    ),
)
def test_receipt_bytes_and_submitted_hash_are_independently_recomputed(field, replacement):
    """T4-9: raw bytes and caller-recorded hash both fail closed."""
    _, context, ingestion, references, expectations, *_ = _four_role_fixture()
    valid_changed = replace(
        references[0],
        external_verification_receipt=b"valid changed bytes",
        external_verification_receipt_hash=_sha(b"valid changed bytes"),
    )
    valid_changed.__post_init__()
    hostile = _forge(references[0], **{field: replacement})
    changed = (hostile,) + references[1:]
    _assert_invalid(
        _validate(context, ingestion, changed, expectations),
        ("POLICY:EXTERNAL_RECEIPT_HASH_MISMATCH",),
    )


@pytest.mark.parametrize(
    "field,value,passes,reason",
    [
        ("issued_at", _at(), True, None),
        ("issued_at", _at(1), False, "ISSUED_AFTER_OBSERVED_AT"),
        ("issued_at", "2026-08-29 12:00:00+00:00", False, "TIMESTAMP_MALFORMED"),
        ("issued_at", "2026-08-29T12:00:00+01:00", False, "TIMESTAMP_MALFORMED"),
        ("expires_at", _at(1), True, None),
        ("expires_at", _at(), False, "EXPIRED_AT_OBSERVED_AT"),
        ("expires_at", _at(-1), False, "EXPIRED_AT_OBSERVED_AT"),
        ("expires_at", "2026-08-29T12:00:00+00:00:00", False, "TIMESTAMP_MALFORMED"),
        ("revoked_at", _at(1), True, None),
        ("revoked_at", _at(), False, "REVOKED_AT_OBSERVED_AT"),
        ("revoked_at", _at(-1), False, "REVOKED_AT_OBSERVED_AT"),
        ("revoked_at", "2026-08-29T12:00:00,1Z", False, "TIMESTAMP_MALFORMED"),
    ],
    ids=[
        "issued_at-equal-utc-ok",
        "issued_at-after-observed-fail",
        "issued_at-space-separator-malformed",
        "issued_at-non-utc-offset-malformed",
        "expires_at-after-observed-ok",
        "expires_at-equal-observed-fail",
        "expires_at-before-observed-fail",
        "expires_at-extra-colon-malformed",
        "revoked_at-after-observed-ok",
        "revoked_at-equal-observed-fail",
        "revoked_at-before-observed-fail",
        "revoked_at-comma-separator-malformed",
    ],
)
def test_rfc3339_issuance_expiry_revocation_cutoffs(field, value, passes, reason):
    """T4-12, T4-13, T4-14: exact equality and malformed/non-UTC boundaries."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    changed = (replace(references[0], **{field: value}),) + references[1:]
    outcome = _validate(context, ingestion, changed, expectations)
    if passes:
        assert outcome.status is api.PrerequisiteValidationStatus.VALIDATED
        assert outcome.reason_codes == ()
    else:
        _assert_invalid(outcome, (f"POLICY:{reason}",))


@pytest.mark.parametrize(
    "role_name,disposition,flags",
    (
        ("POLICY", "REJECTED", (False, True, True, True)),
        ("AUTHORITY", "BLOCKED", (True, False, True, True)),
        ("APPROVAL", "BLOCKED", (True, True, False, True)),
        ("SIGNING", "BLOCKED", (True, True, True, False)),
    ),
)
def test_each_deny_changes_only_its_existing_core_boolean(role_name, disposition, flags):
    """T4-15, T4-17: each validated DENY preserves unchanged reducer semantics."""
    api = _api()
    api, _, _, _, _, prerequisites, result = _four_role_fixture(
        decisions={api.TrustRole[role_name]: api.TrustDecision.DENY}
    )
    actual = (
        prerequisites.policy_accepted,
        prerequisites.authority_present,
        prerequisites.approval_present,
        prerequisites.signing_present,
    )
    assert actual == flags
    policy = result.core_result.receipt.policy
    assert (
        policy.accepted,
        policy.authority_present,
        policy.approval_present,
        policy.signing_present,
    ) == flags
    assert result.core_result.disposition.value == disposition


@pytest.mark.parametrize(
    "state,expected",
    (
        ("malformed", "MALFORMED_INPUT"),
        ("context", "UNTRUSTED_CONTEXT"),
        ("profile", "PROFILE_MISMATCH"),
        ("untrusted", "UNTRUSTED_INGESTION"),
        ("receipt", "INGESTION_RECEIPT_INVALID"),
        ("roles", "ROLE_SET_INVALID"),
        ("expectations", "EXPECTATION_SET_INVALID"),
    ),
)
def test_level_a_short_circuit_order_and_opaque_later_inputs(state, expected):
    """T4-16, T4-27, T4-28: earliest Level-A reason only; no role access/core."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    if state == "malformed":
        context = object()
    elif state == "context":
        context = replace(
            context, prerequisite_payload_hashes=context.prerequisite_payload_hashes[:-1]
        )
    elif state == "profile":
        context = replace(context, expected_profile_hash=_hash("other-profile"))
    elif state == "untrusted":
        ingestion = _forge(ingestion)
    elif state == "receipt":
        _mutate(ingestion, "reason_codes", ("TAMPERED:content_hash",))
    elif state == "roles":
        references = references[:-1]
    else:
        expectations = expectations[:-1]
    if state not in {"roles", "expectations"}:
        references, expectations = (object(),), (object(),)
    _assert_invalid(_validate(context, ingestion, references, expectations), (expected,))


@pytest.mark.parametrize(
    "mutations,reasons",
    (
        (
            {"POLICY": ("subject_hash", _hash("x")), "AUTHORITY": ("action", "release")},
            ("POLICY:SUBJECT_MISMATCH", "AUTHORITY:ACTION_MISMATCH"),
        ),
        (
            {
                "POLICY": ("payload_hash", _hash("x")),
                "AUTHORITY": ("signed_payload_hash", _hash("x")),
                "APPROVAL": ("expires_at", _at()),
                "SIGNING": ("issued_at", _at(1)),
            },
            (
                "POLICY:PAYLOAD_HASH_MISMATCH",
                "AUTHORITY:SIGNED_PAYLOAD_HASH_MISMATCH",
                "APPROVAL:EXPIRED_AT_OBSERVED_AT",
                "SIGNING:ISSUED_AFTER_OBSERVED_AT",
            ),
        ),
    ),
)
def test_level_b_first_check_and_deterministic_role_aggregation(mutations, reasons):
    """T4-30: at most one reason per role, in policy/authority/approval/signing order."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    changed = list(references)
    for role_name, (field, value) in mutations.items():
        index = tuple(api.TrustRole).index(api.TrustRole[role_name])
        kwargs = {field: value}
        primary = replace(changed[index], **kwargs)
        changed[index] = _forge(
            primary,
            external_verification_receipt_hash=_sha(b"later failure"),
        )
    _assert_invalid(_validate(context, ingestion, tuple(changed), expectations), reasons)


def test_level_b_excludes_bootstrap_only_and_removed_codes():
    """T4-29, T4-30: bootstrap grant errors and old speculative reasons are unreachable."""
    _, context, ingestion, references, expectations, *_ = _four_role_fixture()
    changed = (replace(references[0], verification_method="wrong"),) + references[1:]
    outcome = _validate(context, ingestion, changed, expectations)
    assert outcome.reason_codes == ("POLICY:EXTERNAL_RECEIPT_EXPECTATION_MISMATCH",)
    forbidden = {
        "ISSUER_GRANT_MISSING",
        "ISSUER_GRANT_MISMATCH",
        "EXTERNAL_RECEIPT_EXPECTATION_MISSING",
        "VERIFICATION_METHOD_MISMATCH",
        "SIGNED_PAYLOAD_UNVERIFIABLE",
    }
    assert all(reason.split(":", 1)[1] not in forbidden for reason in outcome.reason_codes)


@pytest.mark.parametrize(
    "state",
    ("malformed", "context", "profile", "untrusted", "receipt", "roles", "expectations"),
)
def test_every_level_a_invalid_case_calls_core_zero(state, monkeypatch):
    """T4-16, T4-27 / Architecture G: exhaustive Level-A core-zero spy."""
    with _adapter_with_core_spy(monkeypatch) as (api, calls, _):
        api, context, ingestion, references, expectations, *_ = _four_role_fixture()
        calls.clear()
        if state == "malformed":
            context = object()
        elif state == "context":
            context = replace(
                context,
                prerequisite_payload_hashes=context.prerequisite_payload_hashes[:-1],
            )
        elif state == "profile":
            context = replace(context, expected_profile_hash=_hash("wrong-profile"))
        elif state == "untrusted":
            ingestion = _forge(ingestion)
        elif state == "receipt":
            _mutate(ingestion, "reason_codes", ("TAMPERED:content_hash",))
        elif state == "roles":
            references = references[:-1]
        else:
            expectations = expectations[:-1]
        api.validate_prerequisites(context, ingestion, references, expectations)
        assert calls == []


@pytest.mark.parametrize("role_name", ROLE_NAMES)
@pytest.mark.parametrize(
    "failure",
    (
        "subject",
        "expectation",
        "action",
        "payload",
        "signed",
        "timestamp",
        "issued",
        "expired",
        "revoked",
        "receipt",
    ),
)
def test_every_level_b_invalid_case_calls_core_zero(role_name, failure, monkeypatch):
    """T4-16, T4-30 / Architecture G: full role/check matrix never invokes core."""
    with _adapter_with_core_spy(monkeypatch) as (api, calls, _):
        api, context, ingestion, references, expectations, *_ = _four_role_fixture()
        calls.clear()
        index = tuple(api.TrustRole).index(api.TrustRole[role_name])
        field, value = {
            "subject": ("subject_hash", _hash("wrong-subject")),
            "expectation": ("verification_method", "wrong-method"),
            "action": ("action", "wrong-action"),
            "payload": ("payload_hash", _hash("wrong-payload")),
            "signed": ("signed_payload_hash", _hash("wrong-signed")),
            "timestamp": ("issued_at", "2026-08-29 12:00:00+00:00"),
            "issued": ("issued_at", _at(1)),
            "expired": ("expires_at", _at()),
            "revoked": ("revoked_at", _at()),
            "receipt": (
                "external_verification_receipt_hash",
                _sha(b"hostile-recorded-hash"),
            ),
        }[failure]
        if failure == "receipt":
            hostile = _forge(references[index], **{field: value})
        else:
            hostile = replace(references[index], **{field: value})
        references = references[:index] + (hostile,) + references[index + 1 :]
        api.validate_prerequisites(context, ingestion, references, expectations)
        assert calls == []


@pytest.mark.parametrize("replay", ("context", "bundle", "payload", "action", "method"))
def test_cross_context_bundle_payload_action_method_replays_fail(replay):
    """T4-22, T4-23, T4-24: expectations are exact-context/root bound."""
    _, context, ingestion, references, expectations, *_ = _four_role_fixture()
    if replay == "context":
        _assert_invalid(
            _validate(replace(context), ingestion, references, expectations),
            ("UNTRUSTED_INGESTION",),
        )
        return
    if replay == "bundle":
        _mutate(ingestion, "bundle", _forge(ingestion.bundle, bundle_id="other-bundle"))
        _assert_invalid(
            _validate(context, ingestion, references, expectations),
            ("INGESTION_RECEIPT_INVALID",),
        )
        return
    field, value, reason = {
        "payload": ("payload_hash", _hash("other-root"), "PAYLOAD_HASH_MISMATCH"),
        "action": ("action", "other", "ACTION_MISMATCH"),
        "method": ("verification_method", "other", "EXTERNAL_RECEIPT_EXPECTATION_MISMATCH"),
    }[replay]
    changed = (replace(references[0], **{field: value}),) + references[1:]
    _assert_invalid(_validate(context, ingestion, changed, expectations), (f"POLICY:{reason}",))


@pytest.mark.parametrize("variant", ("context", "bundle"))
def test_registered_expectation_replayed_into_distinct_trusted_subject(variant):
    """T4-22, T4-23: real C2 trusted ingestion rejects old C1 expectation by role."""
    api, context, _, references, expectations, *_ = _four_role_fixture()
    context2, ingestion2 = _trusted_variant(api, context, variant)
    roots2 = dict(context2.prerequisite_payload_hashes)
    references2 = tuple(
        replace(
            reference,
            subject_hash=_subject(context2, ingestion2),
            payload_hash=roots2[reference.role],
            signed_payload_hash=roots2[reference.role],
        )
        for reference in references
    )
    c2_expectations = tuple(
        api._bootstrap_external_receipt_expectation(
            context=context2,
            ingestion=ingestion2,
            role=reference.role,
            expected_evidence_id=reference.evidence_id,
            expected_issuer_id=reference.issuer_id,
            expected_verification_method=reference.verification_method,
            independently_expected_receipt=reference.external_verification_receipt,
        )
        for reference in references2
    )
    replayed = (expectations[0],) + c2_expectations[1:]
    _assert_invalid(
        api.validate_prerequisites(context2, ingestion2, references2, replayed),
        ("EXPECTATION_SET_INVALID",),
    )


@pytest.mark.parametrize("variant", ("payload", "action", "method"))
def test_expectation_side_payload_action_method_replay(variant):
    """T4-24: a registered C2 expectation cannot authorize C1 reference/context."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    context2, ingestion2 = _trusted_variant(api, context, variant)
    method = "other-method" if variant == "method" else "pytest"
    c2_expectation = api._bootstrap_external_receipt_expectation(
        context=context2,
        ingestion=ingestion2,
        role=api.TrustRole.POLICY,
        expected_evidence_id=references[0].evidence_id,
        expected_issuer_id=references[0].issuer_id,
        expected_verification_method=method,
        independently_expected_receipt=references[0].external_verification_receipt,
    )
    replayed = (c2_expectation,) + expectations[1:]
    _assert_invalid(
        api.validate_prerequisites(context, ingestion, references, replayed),
        ("EXPECTATION_SET_INVALID",),
    )


@pytest.mark.parametrize(
    "classifier_state,expected",
    (
        ("wrong_type", "UNTRUSTED_INGESTION"),
        ("lookalike", "UNTRUSTED_INGESTION"),
        ("same_hash_context", "UNTRUSTED_INGESTION"),
        ("minted_non_success", "UNTRUSTED_INGESTION"),
        ("recognized_mutation", "INGESTION_RECEIPT_INVALID"),
    ),
)
def test_public_ingestion_classifier_mapping(classifier_state, expected):
    """T4-19, T4-28: exact Task-3 classifier distinguishes origin from corruption."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    if classifier_state == "wrong_type":
        ingestion = object()
    elif classifier_state == "lookalike":
        ingestion = _forge(ingestion)
    elif classifier_state == "same_hash_context":
        context = replace(context)
    elif classifier_state == "minted_non_success":
        context = replace(context, plan=replace(context.plan, change_set_hash=_hash("wrong")))
        _, _, submission, _ = _task3_fixture()
        ingestion = api.ingest_evidence(context, (submission,))
    else:
        _mutate(ingestion, "reason_codes", ("TAMPERED:content_hash",))
    _assert_invalid(_validate(context, ingestion, references, expectations), (expected,))


@pytest.mark.parametrize(
    "target,field",
    (
        ("result", "bundle"),
        ("result", "receipt"),
        ("result", "condition"),
        ("result", "reason_codes"),
        ("receipt", "context_hash"),
        ("receipt", "profile_hash"),
        ("receipt", "bundle_hash"),
        ("receipt", "raw_content_hashes"),
        ("receipt", "provenance_hashes"),
        ("receipt", "observations"),
        ("receipt", "freshness"),
        ("receipt", "machine_verified_artifact_ids"),
        ("receipt", "human_open_artifact_ids"),
        ("receipt", "human_open_reasons"),
        ("receipt", "missing_verifier_ids"),
        ("receipt", "reason_codes"),
        ("receipt", "receipt_hash"),
    ),
)
def test_task3_result_and_receipt_full_mutation_matrix(target, field):
    """T4-19, T4-34: every recognized successful capability mutation is receipt-invalid."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    replacements = {
        "bundle": _forge(ingestion.bundle, bundle_id="mutated-bundle"),
        "receipt": _forge(ingestion.receipt, receipt_hash=_hash("mutated-receipt")),
        "condition": IntegrityStatus.TAMPERED,
        "context_hash": _hash("other-context"),
        "profile_hash": _hash("other-profile"),
        "bundle_hash": _hash("other-bundle"),
        "raw_content_hashes": (_hash("other-content"),),
        "provenance_hashes": (_hash("other-provenance"),),
        "observations": (),
        "freshness": (),
        "machine_verified_artifact_ids": ("other-artifact",),
        "human_open_artifact_ids": ("other-open",),
        "human_open_reasons": (("other-open", "semantic_review_required"),),
        "missing_verifier_ids": ("other-verifier",),
        "reason_codes": ("TAMPERED:content_hash",),
        "receipt_hash": _hash("other-receipt"),
    }
    replacement = replacements[field]
    _mutate(ingestion if target == "result" else ingestion.receipt, field, replacement)
    assert (
        api.classify_ingestion_result(context, ingestion)
        is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    _assert_invalid(
        _validate(context, ingestion, references, expectations),
        ("INGESTION_RECEIPT_INVALID",),
    )


def test_context_root_and_forged_subject_fail_before_core(monkeypatch):
    """T4-3, T4-8, T4-11, T4-16 / Architecture G: invalid paths call core zero."""
    with _adapter_with_core_spy(monkeypatch) as (api, calls, _):
        api, context, ingestion, references, expectations, prerequisites, _ = _four_role_fixture()
        calls.clear()
        rootless = replace(
            context, prerequisite_payload_hashes=context.prerequisite_payload_hashes[:-1]
        )
        _assert_invalid(
            api.validate_prerequisites(rootless, ingestion, references, expectations),
            ("UNTRUSTED_CONTEXT",),
        )
        with pytest.raises(
            ValueError, match="^invalid_trusted_certification_input:UNTRUSTED_PREREQUISITES$"
        ):
            api.certify_ingested(
                context,
                ingestion,
                _forge(prerequisites, subject_hash=_hash("wrong-subject")),
            )
        assert calls == []


@pytest.mark.parametrize("attack", ("public", "object_new", "clone", "mutation", "lookalike"))
def test_forged_stale_or_mutated_prerequisites_never_reach_core(attack, monkeypatch):
    """T4-18, T4-34: only registered, fully recomputed prerequisites certify."""
    with _adapter_with_core_spy(monkeypatch) as (api, calls, _):
        api, context, ingestion, _, _, prerequisites, _ = _four_role_fixture()
        calls.clear()
        if attack == "public":
            with pytest.raises(TypeError):
                api.ValidatedPrerequisites()
            assert calls == []
            return
        if attack == "object_new":
            hostile = object.__new__(api.ValidatedPrerequisites)
        elif attack == "clone":
            hostile = _forge(prerequisites)
        elif attack == "mutation":
            _mutate(prerequisites, "authority_present", False)
            hostile = prerequisites
        else:
            hostile = object()
        with pytest.raises(
            ValueError, match="^invalid_trusted_certification_input:UNTRUSTED_PREREQUISITES$"
        ):
            api.certify_ingested(context, ingestion, hostile)
        assert calls == []


@pytest.mark.parametrize(
    "field",
    (
        "context_hash",
        "profile_hash",
        "ingestion_bundle_hash",
        "ingestion_receipt_hash",
        "prerequisite_subject_hash",
        "prerequisites_hash",
        "core_receipt_hash",
    ),
)
def test_wrapper_seven_root_tamper_matrix_and_field_identical_clone(field):
    """T4-20, T4-31, T4-34: wrapper hash fields and registry identity are recomputed."""
    api, context, ingestion, _, _, prerequisites, result = _four_role_fixture()
    _mutate(result, field, _hash(f"tampered-{field}"))
    assert not api.is_trusted_certification_result(context, ingestion, prerequisites, result)
    _, _, _, _, _, _, clean_result = _four_role_fixture()
    assert not api.is_trusted_certification_result(
        context, ingestion, prerequisites, _forge(clean_result)
    )
    assert not api.is_trusted_certification_result(context, ingestion, prerequisites, object())


@pytest.mark.parametrize("dependency", ("context", "ingestion", "prerequisites"))
def test_equal_looking_wrong_dependency_identity_is_false(dependency):
    """T4-32, T4-33: same fields/hash cannot substitute exact weak object identity."""
    api, context, ingestion, _, _, prerequisites, result = _four_role_fixture()
    args = [context, ingestion, prerequisites, result]
    originals = (context, ingestion, prerequisites)
    args[("context", "ingestion", "prerequisites").index(dependency)] = _forge(
        originals[("context", "ingestion", "prerequisites").index(dependency)]
    )
    assert not api.is_trusted_certification_result(*args)


def test_creation_and_each_independent_validation_call_core_once(monkeypatch):
    """T4-17, T4-35 / Architecture G: creation=1 and each validation=1."""
    with _adapter_with_core_spy(monkeypatch) as (api, calls, _):
        api, context, ingestion, references, expectations, prerequisites, _ = _four_role_fixture()
        calls.clear()
        result = api.certify_ingested(context, ingestion, prerequisites)
        assert len(calls) == 1
        assert calls[0].evidence is ingestion.bundle
        assert api.is_trusted_certification_result(context, ingestion, prerequisites, result)
        assert len(calls) == 2
        assert (
            api.validate_prerequisites(context, ingestion, references, expectations).prerequisites
            is not None
        )


def test_independent_recertification_detects_core_result_substitution(monkeypatch):
    """T4-35: fresh core receipt/verification/disposition comparison detects substitution."""
    with _adapter_with_core_spy(monkeypatch) as (api, calls, control):
        api, context, ingestion, _, _, prerequisites, result = _four_role_fixture()
        calls.clear()
        control["transform"] = lambda honest: _forge(
            honest, disposition=honest.disposition.__class__.BLOCKED
        )
        assert not api.is_trusted_certification_result(context, ingestion, prerequisites, result)
        assert len(calls) == 1


@pytest.mark.parametrize("substitution", ("receipt", "verification", "disposition"))
def test_independent_recertification_detects_each_core_surface(substitution, monkeypatch):
    """T4-20, T4-35: receipt, verification, and disposition are independently compared."""
    with _adapter_with_core_spy(monkeypatch) as (api, calls, control):
        api, context, ingestion, _, _, prerequisites, result = _four_role_fixture()
        calls.clear()

        def transform(honest):
            if substitution == "receipt":
                return _forge(
                    honest,
                    receipt=_forge(
                        honest.receipt,
                        acceptance_contract_hash=_hash("substituted-receipt"),
                    ),
                )
            if substitution == "verification":
                return _forge(honest, verification=object())
            return _forge(honest, disposition=honest.disposition.__class__.BLOCKED)

        control["transform"] = transform
        assert not api.is_trusted_certification_result(context, ingestion, prerequisites, result)
        assert len(calls) == 1


def test_positive_chain_binds_physical_wrapper_and_core_receipt():
    """T4-17: complete ALLOW chain binds exact references, expectations, and core result."""
    api, context, ingestion, references, expectations, prerequisites, result = _four_role_fixture()
    assert prerequisites.reference_hashes == tuple(item.hash for item in references)
    assert prerequisites.expectation_hashes == tuple(item.hash for item in expectations)
    assert result.context_hash == context.hash
    assert result.profile_hash == context.expected_profile_hash
    assert result.ingestion_bundle_hash == ingestion.bundle.hash
    assert result.ingestion_receipt_hash == ingestion.receipt.hash
    assert result.prerequisite_subject_hash == prerequisites.subject_hash
    assert result.prerequisites_hash == prerequisites.hash
    assert result.core_receipt_hash == result.core_result.receipt.hash
    assert result.core_result.disposition.value == "CERTIFIED"
    assert api.is_trusted_certification_result(context, ingestion, prerequisites, result)


def test_weak_dependency_and_result_gc_proves_no_strong_or_dead_identity_storage():
    """T4-33, T4-36 / Architecture C: dependencies and weak-key result are collectible."""
    _, context, ingestion, _, _, prerequisites, result = _four_role_fixture()
    context_ref = weakref.ref(context)
    ingestion_ref = weakref.ref(ingestion)
    prerequisite_ref = weakref.ref(prerequisites)
    result_ref = weakref.ref(result)
    del context, ingestion, prerequisites
    gc.collect()
    assert context_ref() is None
    assert ingestion_ref() is None
    assert prerequisite_ref() is None
    assert result_ref() is result
    del result
    gc.collect()
    assert result_ref() is None
    source = TRUSTED_SOURCE.read_text()
    tree = ast.parse(source)
    assert "WeakKeyDictionary" in source
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "id"
        for node in ast.walk(tree)
    )


def test_architecture_no_clock_crypto_transport_legacy_path_or_reducer_cycle():
    """Architecture D / Architecture E / Architecture F / Architecture H / Architecture I."""
    api = _api()
    from product.evidence import ingestion

    task3_fields = {
        "IngestionReceipt": (
            "context_hash",
            "profile_hash",
            "bundle_hash",
            "raw_content_hashes",
            "provenance_hashes",
            "observations",
            "freshness",
            "machine_verified_artifact_ids",
            "human_open_artifact_ids",
            "human_open_reasons",
            "missing_verifier_ids",
            "reason_codes",
            "receipt_hash",
        ),
        "IngestionResult": ("bundle", "receipt", "condition", "reason_codes"),
    }
    for name, expected_fields in task3_fields.items():
        cls = getattr(ingestion, name)
        assert cls.__dataclass_params__.frozen
        assert cls.__dataclass_params__.init is False
        assert cls.__dataclass_params__.eq is False
        assert tuple(field.name for field in fields(cls)) == expected_fields
    source = TRUSTED_SOURCE.read_text()
    tree = ast.parse(source)
    allowed_import_targets = {
        "dataclasses",
        "enum",
        "hashlib",
        "weakref",
        "product.evidence.ingestion",
        "product.kernel",
    }
    allowed_exact_evidence_imports = {"product.evidence._hash"}
    for target in _import_targets(tree):
        assert target in allowed_exact_evidence_imports or any(
            target == allowed or target.startswith(f"{allowed}.")
            for allowed in allowed_import_targets
        )
    assert api._parse_time is ingestion._parse_time
    assert "product.kernel" in source
    assert not any(
        target == "product.adapters.legacy" or target.startswith("product.adapters.legacy.")
        for target in _import_targets(tree)
    )
    assert "verify_signature" not in source

    forbidden_modules = ("product.verification", "product.certification")
    imported_aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith(forbidden_modules)
                if alias.name.startswith(forbidden_modules):
                    imported_aliases.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not module.startswith(forbidden_modules)
            for alias in node.names:
                qualified = f"{module}.{alias.name}" if module else alias.name
                assert not qualified.startswith(forbidden_modules)
                if qualified.startswith(forbidden_modules):
                    imported_aliases.add(alias.asname or alias.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = _dotted_name(node.func)
        assert not called.startswith(forbidden_modules)
        assert called.split(".", 1)[0] not in {
            "open",
            "exec",
            "eval",
            "compile",
            "system",
            "popen",
            "run",
            "Popen",
            "Path",
            "Client",
            "Session",
        }
        assert not any(
            called == alias or called.startswith(f"{alias}.") for alias in imported_aliases
        )
    assert not any(
        isinstance(node, ast.Name)
        and node.id.lower() in {"provider", "model", "mcp", "cloud", "key", "secret"}
        for node in ast.walk(tree)
    )

    local_reducer_names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.ClassDef, ast.FunctionDef))
        and (
            node.name in {"VerificationResult", "CertificationDisposition", "CertificationPolicy"}
            or node.name.lower() in {"verify", "reduce", "certify_result", "reducer"}
        )
    }
    assert local_reducer_names == set()
    kernel_aliases = set()
    kernel_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "product.kernel":
            for alias in node.names:
                assert alias.name in {"CertificationInput", "CertificationResult", "certify"}
                if alias.name == "certify":
                    kernel_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "product.kernel":
                    kernel_modules.add(alias.asname or "product.kernel")
    kernel_calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = _dotted_name(node.func)
            if called in kernel_aliases or any(
                called == f"{module}.certify" for module in kernel_modules
            ):
                kernel_calls.append(node)
    assert kernel_calls
    for path in (
        Path("product/kernel/__init__.py"),
        Path("product/verification/__init__.py"),
        Path("product/certification/__init__.py"),
    ):
        reducer_tree = ast.parse(path.read_text())
        assert not any(
            target == "product.adapters.trusted" or target.startswith("product.adapters.trusted.")
            for target in _import_targets(reducer_tree)
        )


def test_architecture_rejects_renamed_authority_enums_and_dataclasses():
    """Architecture A: no second authority can hide under a different class name."""
    api = _api()
    local_classes = {
        name
        for name, value in vars(api).items()
        if inspect.isclass(value) and value.__module__ == api.__name__
    }
    contract_classes = {
        "PrerequisiteValidationStatus",
        "ExternalReceiptExpectation",
        "PrerequisiteValidationResult",
        "ValidatedPrerequisites",
        "TrustedCertificationResult",
    }
    private_bindings = local_classes - contract_classes
    assert all(name.startswith("_") for name in private_bindings)
    authority_tokens = {
        "authority",
        "role",
        "decision",
        "issuer",
        "permission",
        "permissions",
        "allowed",
        "policy",
        "approval",
        "signing",
        "action",
        "method",
    }
    for name in private_bindings:
        value = getattr(api, name)
        assert dataclasses.is_dataclass(value)
        assert not issubclass(value, Enum)
        assert all(token not in name.strip("_").lower() for token in authority_tokens)
        field_names = {field.name.lower() for field in fields(value)}
        assert not field_names.intersection(authority_tokens)
        assert all(
            field.endswith("_ref")
            or "hash" in field
            or "fingerprint" in field
            or field.startswith("mint")
            for field in field_names
        )
    assert local_classes == contract_classes | private_bindings


def test_exact_public_signatures_and_no_bootstrap_export():
    """T4-10C, T4-25 / Architecture A-F: public boundary cannot mint."""
    api = _api()
    expected = {
        "validate_prerequisites": ("context", "ingestion", "references", "receipt_expectations"),
        "certify_ingested": ("context", "ingestion", "prerequisites"),
        "is_trusted_certification_result": ("context", "ingestion", "prerequisites", "result"),
    }
    for name, parameters in expected.items():
        assert tuple(inspect.signature(getattr(api, name)).parameters) == parameters
    assert "_bootstrap_external_receipt_expectation" not in api.__all__


def test_t4_21_and_t4_26_legacy_authority_is_owned_only_by_legacy_suite():
    """T4-21, T4-26 / Architecture H: trusted adapter exports no Legacy path."""
    api = _api()
    assert all("legacy" not in name.lower() for name in api.__all__)
    assert "adapt_legacy_evidence" not in TRUSTED_SOURCE.read_text()


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("subject_hash", _hash("other-subject")),
        ("context_hash", _hash("other-context")),
        ("profile_hash", _hash("other-profile")),
        ("ingestion_bundle_hash", _hash("other-bundle")),
        ("ingestion_receipt_hash", _hash("other-receipt")),
        ("observed_at", _at(1)),
        ("policy_accepted", False),
        ("authority_present", False),
        ("approval_present", False),
        ("signing_present", False),
        ("reference_hashes", (_hash("other-reference"),) * 4),
        ("expectation_hashes", (_hash("other-expectation"),) * 4),
    ),
)
def test_prerequisite_full_field_recomputation_matrix(field, replacement):
    """T4-3, T4-18, T4-34: every sealed prerequisite field is recomputed."""
    api, context, ingestion, _, _, prerequisites, result = _four_role_fixture()
    _mutate(prerequisites, field, replacement)
    assert not api.is_trusted_certification_result(context, ingestion, prerequisites, result)
    with pytest.raises(
        ValueError, match="^invalid_trusted_certification_input:UNTRUSTED_PREREQUISITES$"
    ):
        api.certify_ingested(context, ingestion, prerequisites)


def test_profile_mismatch_precedes_stale_ingestion_and_role_inputs():
    """T4-3, T4-27, T4-29: changed profile stops at earliest Level-A identity gate."""
    _, context, ingestion, _, _, *_ = _four_role_fixture()
    changed = replace(context, expected_profile_hash=_hash("changed-profile"))
    _assert_invalid(
        _validate(changed, ingestion, (object(),), (object(),)),
        ("PROFILE_MISMATCH",),
    )


def test_mutated_registered_expectation_hash_is_not_reinterpreted_as_role_evidence():
    """T4-9, T4-10C, T4-34: expectation mutation fails registry/set gate."""
    _, context, ingestion, references, expectations, *_ = _four_role_fixture()
    _mutate(
        expectations[0],
        "external_verification_receipt_hash",
        _sha(b"forged expected hash"),
    )
    _assert_invalid(
        _validate(context, ingestion, references, expectations),
        ("EXPECTATION_SET_INVALID",),
    )


def test_validation_and_certification_sources_cannot_call_private_bootstrap():
    """T4-10C, T4-25: no validator, certifier, or fallback can mint expectations."""
    api = _api()
    for function in (
        api.validate_prerequisites,
        api.certify_ingested,
        api.is_trusted_certification_result,
    ):
        tree = ast.parse(inspect.getsource(function))
        direct_aliases = set()
        module_aliases = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_aliases.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "_bootstrap_external_receipt_expectation":
                        direct_aliases.add(alias.asname or alias.name)
                    else:
                        module_aliases.add(alias.asname or alias.name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            called = _dotted_name(node.func)
            assert called != "_bootstrap_external_receipt_expectation"
            assert called not in direct_aliases
            assert not called.endswith("._bootstrap_external_receipt_expectation")
            assert not any(
                called == f"{alias}._bootstrap_external_receipt_expectation"
                for alias in module_aliases
            )


def test_registered_wrapper_core_result_and_receipt_substitution_is_false():
    """T4-20, T4-34, T4-35: physical core_result must match core_receipt_hash."""
    api, context, ingestion, _, _, prerequisites, result = _four_role_fixture()
    _mutate(result, "core_result", object())
    assert not api.is_trusted_certification_result(context, ingestion, prerequisites, result)


def test_external_expectation_registry_is_weak_and_returns_to_baseline_after_gc():
    """T4-10C, T4-25, T4-36 / Architecture C: expectation mint has weak lifecycle."""
    api, context, ingestion, _, expectations, _, _ = _four_role_fixture()
    weak_registries = [
        value for value in vars(api).values() if isinstance(value, weakref.WeakKeyDictionary)
    ]
    expectation = expectations[0]
    containing = [registry for registry in weak_registries if expectation in registry]
    assert len(containing) == 1
    registry = containing[0]
    baseline = len(registry)

    minted = api._bootstrap_external_receipt_expectation(
        context=context,
        ingestion=ingestion,
        role=expectation.role,
        expected_evidence_id=expectation.evidence_id,
        expected_issuer_id=expectation.issuer_id,
        expected_verification_method=expectation.verification_method,
        independently_expected_receipt=b"independent weak-lifecycle receipt",
    )
    assert minted in registry
    assert len(registry) == baseline + 1
    minted_ref = weakref.ref(minted)
    del minted
    gc.collect()
    assert minted_ref() is None
    assert len(registry) == baseline

    tree = ast.parse(TRUSTED_SOURCE.read_text())
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "id"
        for node in ast.walk(tree)
    )


def test_prerequisite_registry_gc_and_live_result_dependency_invalidation():
    """T4-33, T4-36 / Architecture C: prerequisite registry/dependency is weak."""
    api, context, ingestion, references, expectations, prerequisite, result = _four_role_fixture()
    registries = [
        value for value in vars(api).values() if isinstance(value, weakref.WeakKeyDictionary)
    ]
    containing = [registry for registry in registries if prerequisite in registry]
    assert len(containing) == 1
    registry = containing[0]
    baseline = len(registry)
    validation = api.validate_prerequisites(context, ingestion, references, expectations)
    transient = validation.prerequisites
    assert transient in registry and len(registry) == baseline + 1
    transient_ref = weakref.ref(transient)
    del transient, validation
    gc.collect()
    assert transient_ref() is None and len(registry) == baseline

    prerequisite_ref = weakref.ref(prerequisite)
    replacement = _forge(prerequisite)
    del prerequisite
    gc.collect()
    assert prerequisite_ref() is None
    assert not api.is_trusted_certification_result(context, ingestion, replacement, result)


def test_bootstrap_denial_never_changes_expectation_registry_count():
    """T4-4, T4-6, T4-29: grant denial has no expectation mint side effect."""
    api, context, _, _, expectations, *_ = _four_role_fixture()
    registries = [
        value for value in vars(api).values() if isinstance(value, weakref.WeakKeyDictionary)
    ]
    registry = next(value for value in registries if expectations[0] in value)
    baseline = len(registry)
    grants = tuple(
        grant for grant in context.profile.issuers if api.TrustRole.POLICY not in grant.roles
    )
    profile = replace(context.profile, issuers=grants)
    denied_context = replace(context, profile=profile, expected_profile_hash=profile.hash)
    _, _, submission, _ = _task3_fixture()
    denied_ingestion = api.ingest_evidence(denied_context, (submission,))
    assert (
        api.classify_ingestion_result(denied_context, denied_ingestion)
        is api.IngestionTrustStatus.TRUSTED
    )
    with pytest.raises(ValueError, match="^POLICY:ISSUER_GRANT_MISSING$"):
        api._bootstrap_external_receipt_expectation(
            context=denied_context,
            ingestion=denied_ingestion,
            role=api.TrustRole.POLICY,
            expected_evidence_id="evidence-1",
            expected_issuer_id="issuer-policy",
            expected_verification_method="pytest",
            independently_expected_receipt=b"must-not-mint",
        )
    gc.collect()
    assert len(registry) == baseline


def test_public_copy_replace_and_deepcopy_cannot_register_sealed_capabilities():
    """T4-10C, T4-18, T4-20, T4-31: public copying is never minting."""
    api, context, ingestion, references, expectations, prerequisite, result = _four_role_fixture()
    with pytest.raises(TypeError):
        replace(expectations[0])
    with pytest.raises(TypeError):
        replace(prerequisite)
    with pytest.raises(TypeError):
        replace(result)
    for copier in (copy.copy, copy.deepcopy):
        expectation_copy = copier(expectations[0])
        replaced = (expectation_copy,) + expectations[1:]
        _assert_invalid(
            api.validate_prerequisites(context, ingestion, references, replaced),
            ("EXPECTATION_SET_INVALID",),
        )
        prerequisite_copy = copier(prerequisite)
        with pytest.raises(
            ValueError,
            match="^invalid_trusted_certification_input:UNTRUSTED_PREREQUISITES$",
        ):
            api.certify_ingested(context, ingestion, prerequisite_copy)
        assert not api.is_trusted_certification_result(
            context, ingestion, prerequisite, copier(result)
        )


def test_collected_expectation_stale_identity_cannot_be_revived_by_allocations():
    """T4-33: collected weak identity stays invalid after replacement allocations."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    stale_clone = _forge(expectations[0])
    stale_ref = weakref.ref(expectations[0])
    expectations = expectations[1:]
    gc.collect()
    assert stale_ref() is None
    replacements = [object.__new__(api.ExternalReceiptExpectation) for _ in range(512)]
    assert replacements
    _assert_invalid(
        api.validate_prerequisites(
            context,
            ingestion,
            references,
            (stale_clone,) + expectations,
        ),
        ("EXPECTATION_SET_INVALID",),
    )


def test_registry_bindings_store_no_strong_capabilities_or_dead_identity_lists():
    """T4-33, T4-36 / Architecture C: all registry dependency storage is weak/immutable."""
    api, context, ingestion, _, expectations, prerequisite, result = _four_role_fixture()
    prohibited = (
        type(context),
        type(ingestion),
        type(expectations[0]),
        type(prerequisite),
        type(result),
    )

    def contains_strong(value):
        if isinstance(value, weakref.ReferenceType):
            return False
        if isinstance(value, prohibited):
            return True
        if type(value) in {tuple, frozenset}:
            return any(contains_strong(item) for item in value)
        if type(value) is dict:
            return any(contains_strong(item) for pair in value.items() for item in pair)
        return False

    registries = [
        value for value in vars(api).values() if isinstance(value, weakref.WeakKeyDictionary)
    ]
    assert len(registries) >= 3
    assert all(
        not contains_strong(binding) for registry in registries for binding in registry.values()
    )
    assert not any(
        type(value) is list and ("dead" in name.lower() or "stale" in name.lower())
        for name, value in vars(api).items()
    )


@pytest.mark.parametrize("foreign_decision", ("ALLOW", "FOREIGN_ENUM"))
def test_hostile_exact_reference_cannot_supply_non_task3_decision(foreign_decision):
    """T4-2, T4-15: string/foreign decision cannot silently become DENY or ALLOW."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()

    class ForeignDecision(str, Enum):
        ALLOW = "ALLOW"

    value = "ALLOW" if foreign_decision == "ALLOW" else ForeignDecision.ALLOW
    hostile = _forge(references[0], decision=value)
    outcome = api.validate_prerequisites(
        context,
        ingestion,
        (hostile,) + references[1:],
        expectations,
    )
    _assert_invalid(outcome, ("ROLE_SET_INVALID",))


def test_hostile_exact_reference_raw_shape_is_bounded_level_a_invalid():
    """T4-2, T4-16: constructor-bypassed raw field never leaks TypeError."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    hostile = _forge(references[0], external_verification_receipt="not-bytes")
    outcome = api.validate_prerequisites(
        context,
        ingestion,
        (hostile,) + references[1:],
        expectations,
    )
    _assert_invalid(outcome, ("ROLE_SET_INVALID",))


def test_same_hash_new_context_ingestion_rejects_old_registered_expectation():
    """T4-22, T4-29, T4-33: registry mint binds exact context+ingestion identities."""
    api, context, _, references, expectations, *_ = _four_role_fixture()
    context2 = replace(context)
    _, _, submission, _ = _task3_fixture()
    ingestion2 = api.ingest_evidence(context2, (submission,))
    assert context2.hash == context.hash and context2 is not context
    assert api.classify_ingestion_result(context2, ingestion2) is api.IngestionTrustStatus.TRUSTED
    _assert_invalid(
        api.validate_prerequisites(context2, ingestion2, references, expectations),
        ("EXPECTATION_SET_INVALID",),
    )


def test_same_hash_new_context_ingestion_rejects_old_registered_prerequisites():
    """T4-18, T4-32, T4-33: prerequisite registry binds exact dependencies."""
    api, context, _, _, _, prerequisites, _ = _four_role_fixture()
    context2 = replace(context)
    _, _, submission, _ = _task3_fixture()
    ingestion2 = api.ingest_evidence(context2, (submission,))
    assert context2.hash == context.hash
    with pytest.raises(
        ValueError,
        match="^invalid_trusted_certification_input:UNTRUSTED_PREREQUISITES$",
    ):
        api.certify_ingested(context2, ingestion2, prerequisites)


def test_certify_ingested_exact_error_mapping_and_order():
    """T4-18, T4-19, T4-28: exact certification input error taxonomy/order."""
    api, context, ingestion, _, _, prerequisites, _ = _four_role_fixture()

    def assert_code(given_context, given_ingestion, given_prerequisites, code):
        with pytest.raises(
            ValueError,
            match=f"^invalid_trusted_certification_input:{code}$",
        ):
            api.certify_ingested(given_context, given_ingestion, given_prerequisites)

    assert_code(object(), ingestion, prerequisites, "UNTRUSTED_CONTEXT")
    profile_mismatch = replace(context, expected_profile_hash=_hash("wrong-profile"))
    assert_code(profile_mismatch, ingestion, prerequisites, "PROFILE_MISMATCH")
    assert_code(context, object(), prerequisites, "UNTRUSTED_INGESTION")

    api2, context2, corrupted, _, _, prerequisite2, _ = _four_role_fixture()
    _mutate(corrupted, "reason_codes", ("TAMPERED:content_hash",))
    assert_code(context2, corrupted, prerequisite2, "INGESTION_RECEIPT_INVALID")
    assert_code(context, ingestion, _forge(prerequisites), "UNTRUSTED_PREREQUISITES")

    for field in ("subject_hash", "context_hash"):
        _, current_context, current_ingestion, _, _, current_prerequisite, _ = _four_role_fixture()
        _mutate(current_prerequisite, field, _hash(f"hostile-{field}"))
        assert_code(
            current_context,
            current_ingestion,
            current_prerequisite,
            "UNTRUSTED_PREREQUISITES",
        )

    source = inspect.getsource(api.certify_ingested)
    assert source.index("UNTRUSTED_PREREQUISITES") < source.index("SUBJECT_MISMATCH")


def test_exact_public_capability_annotations_are_not_object_erased():
    """T4-1, T4-20: public prerequisites and core result annotations are exact."""
    api = _api()
    from product.kernel import CertificationResult

    validation_annotations = get_type_hints(api.PrerequisiteValidationResult)
    wrapper_annotations = get_type_hints(api.TrustedCertificationResult)
    assert validation_annotations["prerequisites"] == api.ValidatedPrerequisites | None
    assert wrapper_annotations["core_result"] is CertificationResult


@pytest.mark.parametrize("nested_attack", ("profile_producers", "producer_methods"))
def test_nested_profile_hostile_shape_is_bounded_untrusted_context(nested_attack):
    """T4-3, T4-16: post-mint nested profile corruption never leaks raw errors."""
    api, context, ingestion, references, expectations, prerequisites, _ = _four_role_fixture()
    if nested_attack == "profile_producers":
        _mutate(context.profile, "producers", object())
    else:
        _mutate(context.profile.producers[0], "verification_methods", object())
    _assert_invalid(
        api.validate_prerequisites(context, ingestion, references, expectations),
        ("UNTRUSTED_CONTEXT",),
    )
    with pytest.raises(
        ValueError,
        match="^invalid_trusted_certification_input:UNTRUSTED_CONTEXT$",
    ):
        api.certify_ingested(context, ingestion, prerequisites)


def test_registered_prerequisite_hostile_reference_hash_shape_is_bounded():
    """T4-18, T4-34: malformed registered prerequisite maps to untrusted prerequisite."""
    api, context, ingestion, _, _, prerequisites, result = _four_role_fixture()
    _mutate(prerequisites, "reference_hashes", object())
    with pytest.raises(
        ValueError,
        match="^invalid_trusted_certification_input:UNTRUSTED_PREREQUISITES$",
    ):
        api.certify_ingested(context, ingestion, prerequisites)
    assert not api.is_trusted_certification_result(
        context,
        ingestion,
        prerequisites,
        result,
    )


@pytest.mark.parametrize("field", ("reference_hashes", "expectation_hashes"))
def test_canonical_equivalent_list_cannot_replace_exact_prerequisite_tuple(field):
    """T4-18, T4-34: equal canonical hash does not override exact tuple shape."""
    api, context, ingestion, _, _, prerequisites, result = _four_role_fixture()
    original_hash = prerequisites.hash
    _mutate(prerequisites, field, list(getattr(prerequisites, field)))
    assert prerequisites.hash == original_hash
    with pytest.raises(
        ValueError,
        match="^invalid_trusted_certification_input:UNTRUSTED_PREREQUISITES$",
    ):
        api.certify_ingested(context, ingestion, prerequisites)
    assert not api.is_trusted_certification_result(
        context,
        ingestion,
        prerequisites,
        result,
    )


def test_validated_prerequisite_exact_current_field_shape_matrix():
    """T4-18, T4-34: positive capability retains exact scalar/root field shapes."""
    api, _, _, _, _, prerequisites, _ = _four_role_fixture()
    for field in (
        "subject_hash",
        "context_hash",
        "profile_hash",
        "ingestion_bundle_hash",
        "ingestion_receipt_hash",
    ):
        value = getattr(prerequisites, field)
        assert type(value) is str
        assert value.startswith("sha256:") and len(value) == 71
    assert type(prerequisites.observed_at) is str
    assert api._parse_time(prerequisites.observed_at) is not None
    for field in (
        "policy_accepted",
        "authority_present",
        "approval_present",
        "signing_present",
    ):
        assert type(getattr(prerequisites, field)) is bool
    for field in ("reference_hashes", "expectation_hashes"):
        roots = getattr(prerequisites, field)
        assert type(roots) is tuple and len(roots) == 4
        assert all(
            type(value) is str and value.startswith("sha256:") and len(value) == 71
            for value in roots
        )


@pytest.mark.parametrize(
    "hostile_case",
    (
        "H2_stale_subject",
        "H4_authority_widening",
        "H5_approval_candidate_payload_replay",
        "H6_signing_payload_substitution",
        "H7_runtime_freshness_spoof",
        "H9_missing_evidence",
        "H10_unparseable_provenance_downgrade",
        "H11_type_confusion",
    ),
)
def test_task6_named_hostile_controls_preserve_no_trusted_prerequisites(hostile_case):
    """Task-6 H2-H7/H9-H11: prerequisite substitutions stay fail-closed."""
    api, context, ingestion, references, expectations, *_ = _four_role_fixture()
    expected = None
    if hostile_case == "H2_stale_subject":
        references = (replace(references[0], subject_hash=_hash("stale")),) + references[1:]
        expected = ("POLICY:SUBJECT_MISMATCH",)
    elif hostile_case == "H4_authority_widening":
        references = (replace(references[0], action="release"),) + references[1:]
        expected = ("POLICY:ACTION_MISMATCH",)
    elif hostile_case == "H5_approval_candidate_payload_replay":
        context_b, ingestion_b = _trusted_variant(api, context, "payload")
        roots_a = dict(context.prerequisite_payload_hashes)
        roots_b = dict(context_b.prerequisite_payload_hashes)
        roots_b[api.TrustRole.APPROVAL] = _hash("candidate-b-approval-root")
        context_b = replace(
            context_b,
            prerequisite_payload_hashes=tuple(
                sorted(roots_b.items(), key=lambda pair: (pair[0].value, pair[1]))
            ),
        )
        ingestion_b = api.ingest_evidence(context_b, (_task3_fixture()[2],))
        subject_b = _subject(context_b, ingestion_b)
        references_b = tuple(
            replace(
                reference,
                subject_hash=subject_b,
                payload_hash=roots_a[role] if role is api.TrustRole.APPROVAL else roots_b[role],
                signed_payload_hash=roots_b[role],
            )
            for role, reference in zip(api.TrustRole, references, strict=True)
        )
        expectations_b = tuple(
            api._bootstrap_external_receipt_expectation(
                context=context_b,
                ingestion=ingestion_b,
                role=role,
                expected_evidence_id=reference.evidence_id,
                expected_issuer_id=reference.issuer_id,
                expected_verification_method=reference.verification_method,
                independently_expected_receipt=reference.external_verification_receipt,
            )
            for role, reference in zip(api.TrustRole, references_b, strict=True)
        )
        outcome = _validate(context_b, ingestion_b, references_b, expectations_b)
        _assert_invalid(outcome, ("APPROVAL:PAYLOAD_HASH_MISMATCH",))
        return
    elif hostile_case == "H6_signing_payload_substitution":
        role = api.TrustRole.SIGNING
        index = tuple(api.TrustRole).index(role)
        references = (
            references[:index]
            + (replace(references[index], signed_payload_hash=_hash("substituted")),)
            + references[index + 1 :]
        )
        expected = ("SIGNING:SIGNED_PAYLOAD_HASH_MISMATCH",)
    elif hostile_case == "H7_runtime_freshness_spoof":
        context = replace(context, observed_at=_at(4000))
        expected = ("UNTRUSTED_INGESTION",)
    elif hostile_case == "H9_missing_evidence":
        ingestion = _forge(ingestion, bundle=None)
        expected = ("UNTRUSTED_INGESTION",)
    elif hostile_case == "H10_unparseable_provenance_downgrade":
        references = (replace(references[0], issued_at="not-a-timestamp"),) + references[1:]
        expected = ("POLICY:TIMESTAMP_MALFORMED",)
    elif hostile_case == "H11_type_confusion":
        expectations = list(expectations)
        expected = ("EXPECTATION_SET_INVALID",)
    else:  # pragma: no cover - parameter set is the explicit H2-H7/H9-H11 matrix
        raise AssertionError(f"unhandled hostile control: {hostile_case}")
    outcome = _validate(context, ingestion, references, expectations)
    _assert_invalid(outcome, expected)


def test_task6_h1_artifact_substitution_and_h8_legacy_escalation_are_explicit():
    """Task-6 H1/H8: artifact replacement and narrative PASS cannot certify."""
    _, context, submission, envelope = _task3_fixture()
    from product.evidence import ingestion as task3

    artifact = replace(envelope, artifact_id="different-artifact")
    tampered = task3.ingest_evidence(context, (replace(submission, provenance=artifact),))
    assert tampered.bundle is None
    from product.adapters import legacy

    narrative = legacy.adapt_legacy_evidence(context, "PASS")
    assert narrative.ingestion is None
    assert narrative.fallback_integrity is task3.IntegrityStatus.LEGACY_NON_CERTIFIABLE
