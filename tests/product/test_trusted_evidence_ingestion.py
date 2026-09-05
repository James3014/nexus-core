import gc
import hashlib
import itertools
import weakref
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone

import pytest

from product.evidence import (
    AcceptanceContract,
    ChangeSet,
    ObservationStatus,
    VerificationPlan,
    _hash,
)
from product.evidence.ingestion import _canon


def _api():
    from product.evidence import ingestion

    return ingestion


class OpaqueSubmission:
    """Sentinel proving plan gates run before submission inspection."""

    def __getattribute__(self, name):
        raise AssertionError(f"opaque submission inspected: {name}")


def _at(seconds=0):
    return (
        datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    ).isoformat()


def _runtime(api, **changes):
    values = dict(
        generation=api.EvidenceGeneration.RUNTIME,
        desired_source_revision="target-r2",
        loaded_source_revision="target-r2",
        desired_generation=7,
        observed_generation=7,
        observed_at=_at(-10),
        expires_at=_at(3500),
        expected_runtime_identity="runtime-1",
        observed_runtime_identity="runtime-1",
        readiness_status="READY",
    )
    values.update(changes)
    return api.RuntimeSourceObservation(**values)


def _fixture():
    api = _api()
    contract = AcceptanceContract("ac-1", _hash("requirements"), ("unit",), ("src/a.py",), "FORBID")
    change = ChangeSet("cs-1", "source-r1", "target-r2", _hash("diff"), ("src/a.py",))
    plan = VerificationPlan("plan-1", contract.hash, change.hash, ("unit",))
    producer = api.ProducerGrant(
        "producer-1", api.ProducerRole.VERIFIER, _hash("producer-software"), ("pytest",)
    )
    issuer = api.IssuerGrant("issuer-1", (api.TrustRole.AUTHORITY,), ("merge",), ("pytest",))
    profile = api.IngestionProfile("profile-1", (producer,), (issuer,), 3600)
    raw = b"unit passed\n"
    runtime = _runtime(api)
    envelope = api.ProvenanceEnvelope(
        "product.evidence.provenance.v1",
        "evidence-1",
        api.EvidenceType.VERIFIER_RESULT,
        "unit",
        "artifact-1",
        "producer-1",
        api.ProducerRole.VERIFIER,
        producer.software_hash,
        "repo-1",
        "source-r1",
        "tree-source",
        "target-r2",
        "tree-target",
        change.hash,
        change.diff_hash,
        _at(-10),
        "tests/test_a.py",
        "sha256:" + hashlib.sha256(raw).hexdigest(),
        "pytest",
        "exec-1",
        "attempt-1",
        _hash("environment"),
        api.EvidenceGeneration.RUNTIME,
        runtime,
    )
    submission = api.EvidenceSubmission(raw, ObservationStatus.PASS, envelope)
    requirement = api.EvidenceRequirement(
        "unit",
        "artifact-1",
        api.EvidenceType.VERIFIER_RESULT,
        api.EvidenceGeneration.RUNTIME,
        "producer-1",
        "exec-1",
        "attempt-1",
        _hash("environment"),
        "sha256:" + hashlib.sha256(raw).hexdigest(),
        envelope.hash,
        True,
        False,
        ObservationStatus.PASS,
    )
    reference = api.TrustReference(
        api.TrustRole.AUTHORITY,
        "evidence-1",
        "issuer-1",
        _hash("subject"),
        "merge",
        api.TrustDecision.ALLOW,
        _at(-20),
        _at(3500),
        None,
        _hash("payload"),
        _hash("signed-payload"),
        "pytest",
        b"external receipt",
        "sha256:" + hashlib.sha256(b"external receipt").hexdigest(),
    )
    context = api.TrustedIngestionContext(
        contract,
        change,
        plan,
        "repo-1",
        "tree-source",
        "tree-target",
        _at(),
        profile,
        profile.hash,
        (requirement,),
        "merge",
        ((api.TrustRole.AUTHORITY, reference.payload_hash),),
    )
    return api, context, submission, envelope


def test_public_api_and_exact_enum_members_are_frozen():
    api = _api()
    assert set(api.EvidenceType.__members__) == {
        "VERIFIER_RESULT",
        "CI_CHECK",
        "MANUAL_REVIEW",
        "RUNTIME_OBSERVATION",
        "LEGACY_RECORD",
    }
    assert set(api.ProducerRole.__members__) == {
        "VERIFIER",
        "CI",
        "REVIEWER",
        "OWNER",
        "SIGNER",
        "RUNTIME",
    }
    assert set(api.EvidenceGeneration.__members__) == {
        "SOURCE",
        "EXECUTION",
        "RUNTIME",
        "LEGACY_NARRATIVE",
    }
    assert set(api.FreshnessStatus.__members__) == {
        "SOURCE_ALIGNED",
        "SOURCE_AHEAD_OF_RUNTIME",
        "RUNTIME_IDENTITY_MISMATCH",
        "STALE_OBSERVATION",
        "READY_IDENTITY_BOUND",
        "CONVERGENCE_UNKNOWN",
    }
    assert set(api.TrustRole.__members__) == {"POLICY", "AUTHORITY", "APPROVAL", "SIGNING"}
    assert set(api.TrustDecision.__members__) == {"ALLOW", "DENY"}


def test_exact_dataclass_fields_and_order_are_frozen():
    api = _api()
    expected = {
        "ProducerGrant": ("producer_id", "role", "software_hash", "verification_methods"),
        "IssuerGrant": ("issuer_id", "roles", "actions", "verification_methods"),
        "IngestionProfile": ("profile_id", "producers", "issuers", "max_age_seconds"),
        "EvidenceRequirement": (
            "verifier_id",
            "artifact_id",
            "evidence_type",
            "generation",
            "producer_id",
            "execution_id",
            "attempt_id",
            "environment_hash",
            "content_hash",
            "provenance_hash",
            "runtime_ready_required",
            "human_semantic_review_required",
            "expected_status",
        ),
        "EvidenceSubmission": ("content", "status", "provenance"),
        "IngestionResult": ("bundle", "receipt", "condition", "reason_codes"),
    }
    for name, names in expected.items():
        assert tuple(field.name for field in fields(getattr(api, name))) == names
    assert tuple(field.name for field in fields(api.RuntimeSourceObservation)) == (
        "generation",
        "desired_source_revision",
        "loaded_source_revision",
        "expected_runtime_identity",
        "observed_runtime_identity",
        "desired_generation",
        "observed_generation",
        "observed_at",
        "expires_at",
        "readiness_status",
    )
    assert tuple(field.name for field in fields(api.ProvenanceEnvelope)) == (
        "schema",
        "evidence_id",
        "evidence_type",
        "verifier_id",
        "artifact_id",
        "producer_id",
        "producer_role",
        "producer_software_hash",
        "repository_id",
        "source_revision",
        "source_tree",
        "target_revision",
        "target_tree",
        "change_set_hash",
        "diff_hash",
        "generated_at",
        "source_locator",
        "content_hash",
        "verification_method",
        "execution_id",
        "attempt_id",
        "environment_hash",
        "generation",
        "runtime",
    )
    assert tuple(field.name for field in fields(api.TrustedIngestionContext)) == (
        "contract",
        "change_set",
        "plan",
        "repository_id",
        "source_tree",
        "target_tree",
        "observed_at",
        "profile",
        "expected_profile_hash",
        "requirements",
        "required_action",
        "prerequisite_payload_hashes",
    )
    assert tuple(field.name for field in fields(api.IngestionReceipt)) == (
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
    )
    assert tuple(field.name for field in fields(api.TrustReference)) == (
        "role",
        "evidence_id",
        "issuer_id",
        "subject_hash",
        "action",
        "decision",
        "issued_at",
        "expires_at",
        "revoked_at",
        "payload_hash",
        "signed_payload_hash",
        "verification_method",
        "external_verification_receipt",
        "external_verification_receipt_hash",
    )


def test_every_frozen_ingestion_contract_is_immutable():
    api = _api()
    names = (
        "ProducerGrant",
        "IssuerGrant",
        "IngestionProfile",
        "EvidenceRequirement",
        "RuntimeSourceObservation",
        "ProvenanceEnvelope",
        "EvidenceSubmission",
        "TrustReference",
        "TrustedIngestionContext",
        "IngestionReceipt",
        "IngestionResult",
    )
    assert all(getattr(api, name).__dataclass_params__.frozen for name in names)


def test_valid_ingestion_binds_raw_hash_and_provenance_envelope_hash():
    api, context, submission, envelope = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert result.bundle is not None
    assert result.condition is api.IntegrityStatus.VALID and result.reason_codes == ()
    assert result.receipt.observations[0].status is ObservationStatus.PASS
    assert result.receipt.observations[0].artifact_hash == envelope.hash
    assert result.receipt.raw_content_hashes == (envelope.content_hash,)
    assert result.receipt.provenance_hashes == (envelope.hash,)
    assert envelope.content_hash == "sha256:" + hashlib.sha256(submission.content).hexdigest()


def test_deterministic_hashes_and_sorted_reasons():
    api, context, submission, envelope = _fixture()
    assert envelope.hash == replace(envelope).hash
    assert (
        api.ingest_evidence(context, (submission,)).receipt.hash
        == api.ingest_evidence(context, (submission,)).receipt.hash
    )
    failed = api.ingest_evidence(context, (replace(submission, content=b"changed"), submission))
    assert tuple(sorted(set(failed.reason_codes))) == failed.reason_codes
    assert failed.bundle is None
    assert all("required_verifier=" not in reason for reason in failed.reason_codes)


@pytest.mark.parametrize(
    "changes", [{"observed_at": _at(4000)}, {"expires_at": _at(-1)}, {"observed_generation": 6}]
)
def test_future_expired_or_generation_stale_is_stale(changes):
    api, *_ = _fixture()
    assert api.derive_runtime_freshness(_runtime(api, **changes), _at()).name == "STALE_OBSERVATION"


@pytest.mark.parametrize(
    "changes", [{"observed_at": "not-utc"}, {"observed_at": "2026-08-29T12:00:00"}]
)
def test_missing_or_non_utc_time_is_unknown(changes):
    api, *_ = _fixture()
    assert (
        api.derive_runtime_freshness(_runtime(api, **changes), _at()).name == "CONVERGENCE_UNKNOWN"
    )


def test_freshness_truth_table_covers_source_runtime_and_ready_identity():
    api, *_ = _fixture()
    assert (
        api.derive_runtime_freshness(_runtime(api, loaded_source_revision="source-r1"), _at()).name
        == "SOURCE_AHEAD_OF_RUNTIME"
    )
    assert (
        api.derive_runtime_freshness(
            _runtime(api, observed_runtime_identity="runtime-2"), _at()
        ).name
        == "RUNTIME_IDENTITY_MISMATCH"
    )
    assert (
        api.derive_runtime_freshness(
            _runtime(
                api,
                generation=api.EvidenceGeneration.SOURCE,
                expected_runtime_identity=None,
                observed_runtime_identity=None,
                readiness_status=None,
            ),
            _at(),
        ).name
        == "SOURCE_ALIGNED"
    )
    assert (
        api.derive_runtime_freshness(_runtime(api, readiness_status="LIVE"), _at()).name
        == "CONVERGENCE_UNKNOWN"
    )
    assert api.derive_runtime_freshness(_runtime(api), _at()).name == "READY_IDENTITY_BOUND"


@pytest.mark.parametrize("generation", ["EXECUTION", "LEGACY_NARRATIVE"])
def test_non_runtime_generation_observation_is_rejected(generation):
    api, *_ = _fixture()
    with pytest.raises(ValueError):
        _runtime(api, generation=getattr(api.EvidenceGeneration, generation))


def test_condition_helper_has_closed_vocabulary_and_exact_precedence():
    api = _api()
    assert api.condition_for_ingestion_reasons(()) is api.IntegrityStatus.VALID
    ordered = [
        "TAMPERED:content_hash",
        "STALE:observation",
        "CROSS_BOUND:runtime",
        "DUPLICATE:artifact",
        "MALFORMED:submission",
        "MISSING:prerequisite",
    ]
    for index, reason in enumerate(ordered):
        assert api.condition_for_ingestion_reasons(tuple(ordered[index:])) is getattr(
            api.IntegrityStatus, reason.split(":")[0]
        )
    for invalid in (
        "UNKNOWN:reason",
        "MALFORMED:unknown",
        "CROSS_BOUND:unknown",
        "TAMPERED:unknown",
    ):
        with pytest.raises(ValueError):
            api.condition_for_ingestion_reasons((invalid,))
    for permutation in itertools.permutations(ordered):
        assert api.condition_for_ingestion_reasons(permutation) is api.IntegrityStatus.TAMPERED
    for index, higher in enumerate(ordered):
        for lower in ordered[index + 1 :]:
            assert api.condition_for_ingestion_reasons((lower, higher)) is getattr(
                api.IntegrityStatus, higher.split(":")[0]
            )


def test_content_and_envelope_hash_mutations_are_independently_tampered():
    api, context, submission, envelope = _fixture()
    content_result = api.ingest_evidence(context, (replace(submission, content=b"changed\n"),))
    envelope_result = api.ingest_evidence(
        context, (replace(submission, provenance=replace(envelope, content_hash=_hash("changed"))),)
    )
    assert (
        content_result.condition is api.IntegrityStatus.TAMPERED
        and "TAMPERED:content_hash" in content_result.reason_codes
    )
    assert (
        envelope_result.condition is api.IntegrityStatus.TAMPERED
        and "TAMPERED:provenance_hash" in envelope_result.reason_codes
    )


def test_requirement_content_and_provenance_trust_roots_are_independently_pinned():
    api, context, submission, _ = _fixture()
    content = replace(context.requirements[0], content_hash=_hash("wrong"))
    provenance = replace(context.requirements[0], provenance_hash=_hash("wrong"))
    content_result = api.ingest_evidence(replace(context, requirements=(content,)), (submission,))
    provenance_result = api.ingest_evidence(
        replace(context, requirements=(provenance,)), (submission,)
    )
    assert (
        content_result.condition is api.IntegrityStatus.TAMPERED
        and "TAMPERED:content_hash" in content_result.reason_codes
    )
    assert (
        provenance_result.condition is api.IntegrityStatus.TAMPERED
        and "TAMPERED:provenance_hash" in provenance_result.reason_codes
    )


def test_combined_raw_and_claimed_hash_attack_has_no_bundle():
    api, context, submission, envelope = _fixture()
    forged = replace(
        submission,
        content=b"forged",
        provenance=replace(
            envelope, content_hash="sha256:" + hashlib.sha256(b"forged").hexdigest()
        ),
    )
    result = api.ingest_evidence(context, (forged,))
    assert result.bundle is None and result.condition is api.IntegrityStatus.TAMPERED
    assert "TAMPERED:content_hash" in result.reason_codes


@pytest.mark.parametrize(
    "field, condition, reason",
    [
        ("artifact_id", "TAMPERED", "TAMPERED:provenance_hash"),
        ("target_revision", "TAMPERED", "TAMPERED:provenance_hash"),
        ("producer_id", "TAMPERED", "TAMPERED:provenance_hash"),
    ],
)
def test_h1_h2_h3_h9_h11_are_separate_fail_closed_cases(field, condition, reason):
    api, context, submission, envelope = _fixture()
    value = "other" if field != "evidence_type" else "VERIFIER_RESULT"
    result = api.ingest_evidence(
        context, (replace(submission, provenance=replace(envelope, **{field: value})),)
    )
    assert (
        result.condition is getattr(api.IntegrityStatus, condition)
        and reason in result.reason_codes
    )
    assert result.bundle is None


def test_h7_old_readiness_generation_is_stale():
    api, context, submission, envelope = _fixture()
    result = api.ingest_evidence(
        context,
        (
            replace(
                submission,
                provenance=replace(envelope, runtime=_runtime(api, observed_generation=6)),
            ),
        ),
    )
    assert (
        result.condition is api.IntegrityStatus.TAMPERED
        and "TAMPERED:provenance_hash" in result.reason_codes
    )
    assert result.bundle is None


@pytest.mark.parametrize(
    "field, value, reason",
    [
        ("producer_software_hash", _hash("other-software"), "CROSS_BOUND:producer"),
        ("producer_role", "CI", "CROSS_BOUND:producer"),
        ("verification_method", "other-method", "CROSS_BOUND:producer"),
        ("repository_id", "other-repo", "CROSS_BOUND:repository"),
        ("source_revision", "old-source", "STALE:subject"),
        ("target_revision", "old-target", "STALE:subject"),
        ("source_tree", "other-source-tree", "CROSS_BOUND:tree"),
        ("target_tree", "other-target-tree", "CROSS_BOUND:tree"),
        ("change_set_hash", _hash("other-change"), "CROSS_BOUND:changeset"),
        ("diff_hash", _hash("other-diff"), "CROSS_BOUND:changeset"),
        ("artifact_id", "other-artifact", "CROSS_BOUND:artifact"),
        ("execution_id", "other-execution", "CROSS_BOUND:execution"),
        ("attempt_id", "other-attempt", "CROSS_BOUND:execution"),
        ("environment_hash", _hash("other-environment"), "CROSS_BOUND:execution"),
        ("runtime", _runtime, "CROSS_BOUND:runtime"),
    ],
)
def test_updating_requirement_hash_cannot_bypass_semantic_binding(field, value, reason):
    api, context, submission, envelope = _fixture()
    if field == "producer_role":
        value = api.ProducerRole.CI
    if field == "runtime":
        value = value(api, observed_runtime_identity="runtime-2")
    mutated = replace(envelope, **{field: value})
    requirement = replace(
        context.requirements[0], content_hash=mutated.content_hash, provenance_hash=mutated.hash
    )
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=mutated),)
    )
    assert result.condition is getattr(api.IntegrityStatus, reason.split(":")[0])
    assert reason in result.reason_codes


@pytest.mark.parametrize(
    "field",
    [
        "schema",
        "evidence_id",
        "evidence_type",
        "verifier_id",
        "artifact_id",
        "producer_id",
        "producer_role",
        "producer_software_hash",
        "repository_id",
        "source_revision",
        "source_tree",
        "target_revision",
        "target_tree",
        "change_set_hash",
        "diff_hash",
        "generated_at",
        "source_locator",
        "content_hash",
        "verification_method",
        "execution_id",
        "attempt_id",
        "environment_hash",
        "generation",
        "runtime",
    ],
)
def test_every_provenance_field_mutation_is_rejected(field):
    api, context, submission, envelope = _fixture()
    value = (
        _hash("mutated")
        if field.endswith("_hash") or field == "content_hash"
        else (
            _at(-5)
            if field == "generated_at"
            else api.EvidenceGeneration.SOURCE
            if field == "generation"
            else _runtime(api, observed_generation=8)
            if field == "runtime"
            else api.EvidenceType.CI_CHECK
            if field == "evidence_type"
            else api.ProducerRole.CI
            if field == "producer_role"
            else "mutated"
        )
    )
    result = api.ingest_evidence(
        context, (replace(submission, provenance=replace(envelope, **{field: value})),)
    )
    assert result.condition is api.IntegrityStatus.TAMPERED
    assert "TAMPERED:provenance_hash" in result.reason_codes


def test_h12_identical_and_conflicting_duplicates_are_distinct():
    api, context, submission, envelope = _fixture()
    identical = api.ingest_evidence(context, (submission, submission))
    conflicting = api.ingest_evidence(
        context,
        (submission, replace(submission, provenance=replace(envelope, verifier_id="other"))),
    )
    assert (
        identical.condition is api.IntegrityStatus.DUPLICATE
        and "DUPLICATE:artifact" in identical.reason_codes
    )
    assert (
        conflicting.condition is api.IntegrityStatus.TAMPERED
        and "TAMPERED:provenance_hash" in conflicting.reason_codes
    )


def test_condition_precedence_is_tampered_over_lower_conditions():
    api, context, submission, *_ = _fixture()
    result = api.ingest_evidence(context, (replace(submission, content=b"changed\n"), submission))
    assert result.condition is api.IntegrityStatus.TAMPERED


def test_machine_and_human_semantic_review_accounting_are_separate():
    api, context, submission, *_ = _fixture()
    machine = api.ingest_evidence(context, (submission,))
    human_context = replace(
        context,
        requirements=(replace(context.requirements[0], human_semantic_review_required=True),),
    )
    human = api.ingest_evidence(human_context, (submission,))
    assert machine.receipt.machine_verified_count == 1 and machine.receipt.human_open_count == 0
    assert human.receipt.machine_verified_count == 1 and human.receipt.human_open_count == 1
    assert human.reason_codes == ()
    assert human.receipt.human_open_reasons == (("artifact-1", "semantic_review_required"),)


def test_evidence_requirement_schema_is_v2_and_status_is_hash_bound():
    api, context, _, envelope = _fixture()
    assert api.EVIDENCE_REQUIREMENT_SCHEMA == "nexus.evidence_requirement.v2-experimental"
    assert envelope.schema == "product.evidence.provenance.v1"
    assert "expected_status" not in tuple(field.name for field in fields(type(envelope)))
    assert (
        envelope.hash == "sha256:f3ab2ecf0856dadac9eced3662d21091d9ac0716c6cffa99217624745d496c41"
    )
    assert _canon(api.EvidenceType.VERIFIER_RESULT) == str(api.EvidenceType.VERIFIER_RESULT)
    assert _canon(api.EvidenceGeneration.RUNTIME) == str(api.EvidenceGeneration.RUNTIME)
    requirement = context.requirements[0]
    failed = replace(requirement, expected_status=ObservationStatus.FAIL)
    failed_context = replace(context, requirements=(failed,))
    envelope_hash = envelope.hash
    assert requirement.hash != failed.hash
    assert context.hash != failed_context.hash
    assert envelope.hash == envelope_hash


def test_expected_status_is_required_and_not_inferred_from_submission():
    api, context, submission, _ = _fixture()
    requirement = context.requirements[0]
    args = [getattr(requirement, field.name) for field in fields(requirement)][:-1]
    with pytest.raises(TypeError):
        api.EvidenceRequirement(*args)
    passed = api.ingest_evidence(context, (submission,))
    assert api.is_trusted_ingestion_result(context, passed) is True
    failed_submission = replace(submission, status=ObservationStatus.FAIL)
    mismatch = api.ingest_evidence(context, (failed_submission,))
    assert mismatch.bundle is None
    assert mismatch.condition is api.IntegrityStatus.CROSS_BOUND
    assert mismatch.reason_codes == ("CROSS_BOUND:observation_status",)
    assert mismatch.receipt.observations == ()
    assert mismatch.receipt.machine_verified_artifact_ids == ()
    assert mismatch.receipt.human_open_artifact_ids == ()
    assert mismatch.receipt.human_open_reasons == ()
    failed_requirement = replace(requirement, expected_status=ObservationStatus.FAIL)
    failed_context = replace(context, requirements=(failed_requirement,))
    accepted = api.ingest_evidence(failed_context, (failed_submission,))
    assert accepted.bundle is not None and accepted.condition is api.IntegrityStatus.VALID
    passed_mismatch = api.ingest_evidence(failed_context, (submission,))
    assert passed_mismatch.bundle is None
    assert passed_mismatch.condition is api.IntegrityStatus.CROSS_BOUND
    assert passed_mismatch.reason_codes == ("CROSS_BOUND:observation_status",)
    assert passed_mismatch.receipt.observations == ()
    assert passed_mismatch.receipt.machine_verified_artifact_ids == ()
    assert passed_mismatch.receipt.human_open_artifact_ids == ()
    assert passed_mismatch.receipt.human_open_reasons == ()


@pytest.mark.parametrize(
    "expected, submitted",
    [
        (ObservationStatus.PASS, ObservationStatus.FAIL),
        (ObservationStatus.FAIL, ObservationStatus.PASS),
    ],
)
def test_status_mismatch_never_creates_human_open_accounting(expected, submitted):
    api, context, submission, _ = _fixture()
    requirement = replace(
        context.requirements[0],
        expected_status=expected,
        human_semantic_review_required=True,
    )
    status_context = replace(context, requirements=(requirement,))
    result = api.ingest_evidence(status_context, (replace(submission, status=submitted),))
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.CROSS_BOUND
    assert result.reason_codes == ("CROSS_BOUND:observation_status",)
    assert result.receipt.observations == ()
    assert result.receipt.machine_verified_artifact_ids == ()
    assert result.receipt.human_open_artifact_ids == ()
    assert result.receipt.human_open_reasons == ()


@pytest.mark.parametrize("invalid", (None, "PASS", ObservationStatus.PASS.value))
def test_expected_status_rejects_non_exact_status_values(invalid):
    api, context, _, _ = _fixture()
    requirement = context.requirements[0]
    args = [getattr(requirement, field.name) for field in fields(requirement)][:-1]
    with pytest.raises((TypeError, ValueError)):
        api.EvidenceRequirement(*args, invalid)


def test_pass_and_fail_requirement_variants_have_independent_trusted_identities():
    api, context, submission, envelope = _fixture()
    passed = api.ingest_evidence(context, (submission,))
    failed_requirement = replace(context.requirements[0], expected_status=ObservationStatus.FAIL)
    failed_context = replace(context, requirements=(failed_requirement,))
    failed_submission = replace(submission, status=ObservationStatus.FAIL)
    failed = api.ingest_evidence(failed_context, (failed_submission,))
    assert passed.bundle is not None and failed.bundle is not None
    assert api.is_trusted_ingestion_result(context, passed) is True
    assert api.is_trusted_ingestion_result(failed_context, failed) is True
    assert context.requirements[0].hash != failed_requirement.hash
    assert context.hash != failed_context.hash
    assert passed.bundle.hash != failed.bundle.hash
    assert passed.receipt.receipt_hash != failed.receipt.receipt_hash
    assert passed.receipt is not failed.receipt
    assert envelope.hash == failed_submission.provenance.hash


def test_status_mismatch_and_tampered_content_keep_tamper_precedence():
    api, context, submission, _ = _fixture()
    forged = replace(submission, content=b"forged", status=ObservationStatus.FAIL)
    result = api.ingest_evidence(context, (forged,))
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.TAMPERED
    assert result.reason_codes == (
        "CROSS_BOUND:observation_status",
        "TAMPERED:content_hash",
    )


@pytest.mark.parametrize("subject", ("contract", "change_set", "plan"))
def test_outer_subject_subclasses_are_rejected_before_plan_or_submission(subject):
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert api.is_trusted_ingestion_result(context, result) is True
    originals = {
        "contract": context.contract,
        "change_set": context.change_set,
        "plan": context.plan,
    }
    base = originals[subject]
    subclass = type(
        f"Derived{type(base).__name__}",
        (type(base),),
        {},
    )
    derived = subclass(*[getattr(base, field.name) for field in fields(base)])
    object.__setattr__(context, subject, derived)
    assert (
        api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    assert api.is_trusted_ingestion_result(context, result) is False
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(context, (OpaqueSubmission(),))


def test_outer_subject_lookalike_wrong_type_is_rejected_before_plan_or_submission():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert api.is_trusted_ingestion_result(context, result) is True
    original = context.change_set
    lookalike = type("ChangeSetLookalike", (), {})()
    for field in fields(original):
        object.__setattr__(lookalike, field.name, getattr(original, field.name))
    object.__setattr__(context, "change_set", lookalike)
    assert (
        api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    assert api.is_trusted_ingestion_result(context, result) is False
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(context, (OpaqueSubmission(),))


def test_evidence_requirement_v2_hash_is_flat_and_enum_value_bound():
    api, context, _, _ = _fixture()
    requirement = context.requirements[0]
    expected = _hash((
        api.EVIDENCE_REQUIREMENT_SCHEMA,
        requirement.verifier_id,
        requirement.artifact_id,
        requirement.evidence_type.value,
        requirement.generation.value,
        requirement.producer_id,
        requirement.execution_id,
        requirement.attempt_id,
        requirement.environment_hash,
        requirement.content_hash,
        requirement.provenance_hash,
        requirement.runtime_ready_required,
        requirement.human_semantic_review_required,
        requirement.expected_status.value,
    ))
    assert requirement.hash == expected
    assert str(requirement.evidence_type) != requirement.evidence_type.value
    assert str(requirement.generation) != requirement.generation.value


def test_context_hash_consumes_requirement_hash_and_status_sensitivity():
    api, context, _, _ = _fixture()
    requirement = context.requirements[0]
    changed = replace(requirement, expected_status=ObservationStatus.FAIL)
    changed_context = replace(context, requirements=(changed,))
    repeated = replace(context, requirements=(changed,))
    assert changed.hash != requirement.hash
    assert changed_context.hash == repeated.hash
    assert changed_context.hash != context.hash


def test_constructor_type_bounds_sorted_and_duplicate_guards_fail_closed():
    api = _api()
    with pytest.raises((TypeError, ValueError)):
        api.IngestionProfile("p", [], (), 0)
    with pytest.raises((TypeError, ValueError)):
        api.ProducerGrant("p", api.ProducerRole.VERIFIER, _hash("x"), ("m", "m"))


def test_empty_locator_and_string_enum_are_rejected_by_the_envelope_constructor():
    api, _, _, envelope = _fixture()
    with pytest.raises((TypeError, ValueError)):
        replace(envelope, source_locator="")
    with pytest.raises((TypeError, ValueError)):
        replace(envelope, evidence_type="VERIFIER_RESULT")


def _hostile_envelope(envelope, **changes):
    forged = object.__new__(type(envelope))
    for field in fields(envelope):
        object.__setattr__(
            forged, field.name, changes.get(field.name, getattr(envelope, field.name))
        )
    return forged


def _hostile_runtime(runtime, **changes):
    forged = object.__new__(type(runtime))
    for field in fields(runtime):
        object.__setattr__(
            forged, field.name, changes.get(field.name, getattr(runtime, field.name))
        )
    return forged


def test_h9_forged_blank_locator_is_missing_at_admission():
    api, context, submission, envelope = _fixture()
    forged = _hostile_envelope(envelope, source_locator="")
    requirement = replace(context.requirements[0], provenance_hash=forged.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)),
        (api.EvidenceSubmission(submission.content, submission.status, forged),),
    )
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.MISSING
    assert "MISSING:source_locator" in result.reason_codes


def test_h11_forged_string_enum_is_malformed_before_hash_admission():
    api, context, submission, envelope = _fixture()
    forged = _hostile_envelope(envelope, evidence_type="VERIFIER_RESULT")
    result = api.ingest_evidence(
        context, (api.EvidenceSubmission(submission.content, submission.status, forged),)
    )
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.MALFORMED
    assert "MALFORMED:evidence_type" in result.reason_codes


def test_required_constructor_argument_cannot_be_omitted():
    api = _api()
    with pytest.raises(TypeError):
        api.EvidenceSubmission(b"content", ObservationStatus.PASS)


def test_closed_reason_vocabulary_is_exact_and_missing_verifiers_are_not_interpolated():
    api = _api()
    valid = (
        "TAMPERED:content_hash",
        "TAMPERED:provenance_hash",
        "STALE:subject",
        "STALE:generation",
        "STALE:observation",
        "CROSS_BOUND:producer",
        "CROSS_BOUND:repository",
        "CROSS_BOUND:tree",
        "CROSS_BOUND:changeset",
        "CROSS_BOUND:acceptance_contract",
        "CROSS_BOUND:artifact",
        "CROSS_BOUND:runtime",
        "CROSS_BOUND:observation_status",
        "DUPLICATE:artifact",
        "DUPLICATE:verifier",
        "MALFORMED:profile",
        "MALFORMED:requirement",
        "MALFORMED:submission",
        "MALFORMED:provenance",
        "MALFORMED:evidence_type",
        "MALFORMED:producer_role",
        "MALFORMED:generation",
        "MALFORMED:timestamp",
        "MALFORMED:runtime",
        "MALFORMED:trust_reference",
        "MISSING:required_verifier",
        "MISSING:source_locator",
        "MISSING:execution",
        "MISSING:runtime_identity",
        "MISSING:ready_identity",
        "MISSING:prerequisite",
    )
    for reason in valid:
        assert api.condition_for_ingestion_reasons((reason,)) is getattr(
            api.IntegrityStatus, reason.split(":")[0]
        )
    for invalid in (
        "UNKNOWN:reason",
        "UNKNOWN:",
        "",
        "TAMPERED:subject",
        "MISSING:verifier",
        "CROSS_BOUND:content_hash",
        "MALFORMED:unknown",
    ):
        with pytest.raises(ValueError):
            api.condition_for_ingestion_reasons((invalid,))


def test_receipt_freshness_is_artifact_status_pairs_and_only_admitted_artifacts_count():
    api, context, submission, envelope = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert result.receipt.freshness == (("artifact-1", api.FreshnessStatus.READY_IDENTITY_BOUND),)
    assert result.receipt.machine_verified_artifact_ids == ("artifact-1",)
    forged = replace(submission, content=b"tampered")
    rejected = api.ingest_evidence(context, (forged,))
    assert rejected.bundle is None and rejected.condition is api.IntegrityStatus.TAMPERED
    assert "TAMPERED:content_hash" in rejected.reason_codes
    assert rejected.receipt.machine_verified_artifact_ids == ()


def test_authoritative_verifier_requirements_reject_subsets_duplicates_and_missing_ids():
    api, context, submission, _ = _fixture()
    contract = replace(context.contract, required_verifier_ids=("unit", "lint"))
    plan = replace(
        context.plan,
        acceptance_contract_hash=contract.hash,
        required_verifier_ids=("unit", "lint"),
    )
    subset = replace(context, contract=contract, plan=plan)
    missing = api.ingest_evidence(subset, (submission,))
    assert missing.bundle is None and "MISSING:required_verifier" in missing.reason_codes
    assert missing.receipt.missing_verifier_ids == ("lint",)
    assert all("lint" not in reason for reason in missing.reason_codes)
    duplicate = replace(context, requirements=(context.requirements[0], context.requirements[0]))
    duplicate_result = api.ingest_evidence(duplicate, (submission,))
    assert (
        duplicate_result.condition is api.IntegrityStatus.DUPLICATE
        and "DUPLICATE:verifier" in duplicate_result.reason_codes
    )


def test_source_and_runtime_freshness_require_their_distinct_identity_contracts():
    api, *_ = _fixture()
    source = _runtime(
        api,
        generation=api.EvidenceGeneration.SOURCE,
        expected_runtime_identity=None,
        observed_runtime_identity=None,
        readiness_status=None,
    )
    assert api.derive_runtime_freshness(source, _at()).name == "SOURCE_ALIGNED"
    assert (
        api.derive_runtime_freshness(
            _runtime(
                api, generation=api.EvidenceGeneration.RUNTIME, expected_runtime_identity=None
            ),
            _at(),
        ).name
        == "CONVERGENCE_UNKNOWN"
    )
    assert (
        api.derive_runtime_freshness(
            _runtime(api, generation=api.EvidenceGeneration.RUNTIME, readiness_status=None), _at()
        ).name
        == "CONVERGENCE_UNKNOWN"
    )
    assert (
        api.derive_runtime_freshness(
            _runtime(
                api, generation=api.EvidenceGeneration.SOURCE, expected_runtime_identity="runtime-1"
            ),
            _at(),
        ).name
        == "CONVERGENCE_UNKNOWN"
    )
    assert (
        api.derive_runtime_freshness(
            _runtime(api, generation=api.EvidenceGeneration.SOURCE, readiness_status="READY"), _at()
        ).name
        == "CONVERGENCE_UNKNOWN"
    )


def test_generated_at_age_and_runtime_ready_requirement_are_fail_closed():
    api, context, submission, envelope = _fixture()
    stale = replace(submission, provenance=replace(envelope, generated_at=_at(-10000)))
    stale_context = replace(
        context,
        requirements=(replace(context.requirements[0], provenance_hash=stale.provenance.hash),),
    )
    stale_result = api.ingest_evidence(stale_context, (stale,))
    assert stale_result.bundle is None and "STALE:observation" in stale_result.reason_codes
    no_runtime = replace(context.requirements[0], runtime_ready_required=True)
    unknown_runtime = replace(envelope, runtime=None)
    unknown_submission = replace(submission, provenance=unknown_runtime)
    no_runtime = replace(no_runtime, provenance_hash=unknown_runtime.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(no_runtime,)), (unknown_submission,)
    )
    assert (
        result.bundle is None
        and result.condition is api.IntegrityStatus.MISSING
        and "MISSING:ready_identity" in result.reason_codes
    )
    profile = replace(context.profile, max_age_seconds=3600)
    for generated_at, expected in (
        (_at(-3600), api.IntegrityStatus.VALID),
        (_at(-3601), api.IntegrityStatus.STALE),
    ):
        aged_envelope = replace(envelope, generated_at=generated_at)
        aged_requirement = replace(context.requirements[0], provenance_hash=aged_envelope.hash)
        aged = api.ingest_evidence(
            replace(context, profile=profile, requirements=(aged_requirement,)),
            (replace(submission, provenance=aged_envelope),),
        )
        assert aged.condition is expected
        if expected is api.IntegrityStatus.STALE:
            assert aged.reason_codes == ("STALE:observation",)


def test_constructor_invariants_reject_bad_trust_reference_context_and_result_shapes():
    api, context, submission, _ = _fixture()
    valid = api.ingest_evidence(context, (submission,))
    with pytest.raises((TypeError, ValueError)):
        api.IngestionResult(None, valid.receipt, api.IntegrityStatus.VALID, ())
    with pytest.raises((TypeError, ValueError)):
        replace(
            valid.receipt,
            freshness=(
                ("z", api.FreshnessStatus.READY_IDENTITY_BOUND),
                ("a", api.FreshnessStatus.READY_IDENTITY_BOUND),
            ),
        )
    with pytest.raises((TypeError, ValueError)):
        api.TrustReference(
            api.TrustRole.AUTHORITY,
            "evidence-1",
            "issuer-1",
            _hash("subject"),
            "merge",
            api.TrustDecision.ALLOW,
            _at(-20),
            _at(3500),
            None,
            _hash("payload"),
            _hash("signed-payload"),
            "pytest",
            b"receipt",
            _hash("wrong"),
        )
    with pytest.raises((TypeError, ValueError)):
        api.TrustReference(
            "AUTHORITY",
            "evidence-1",
            "issuer-1",
            _hash("subject"),
            "merge",
            api.TrustDecision.ALLOW,
            _at(-20),
            _at(3500),
            None,
            _hash("payload"),
            _hash("signed-payload"),
            "pytest",
            b"receipt",
            "sha256:" + hashlib.sha256(b"receipt").hexdigest(),
        )
    with pytest.raises((TypeError, ValueError)):
        api.TrustedIngestionContext(
            context.contract,
            context.change_set,
            context.plan,
            "",
            context.source_tree,
            context.target_tree,
            context.observed_at,
            context.profile,
            context.expected_profile_hash,
            context.requirements,
            context.required_action,
            context.prerequisite_payload_hashes,
        )


def test_resealed_evidence_type_and_generation_mismatch_fail_closed():
    api, context, submission, envelope = _fixture()
    changed = replace(envelope, evidence_type=api.EvidenceType.CI_CHECK)
    requirement = replace(
        context.requirements[0],
        evidence_type=api.EvidenceType.VERIFIER_RESULT,
        provenance_hash=changed.hash,
    )
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=changed),)
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.CROSS_BOUND
    assert result.reason_codes == ("CROSS_BOUND:artifact",)
    source_requirement = replace(
        context.requirements[0],
        generation=api.EvidenceGeneration.SOURCE,
        runtime_ready_required=False,
    )
    source = replace(envelope, generation=api.EvidenceGeneration.SOURCE, runtime=_runtime(api))
    source_requirement = replace(source_requirement, provenance_hash=source.hash)
    generation_result = api.ingest_evidence(
        replace(context, requirements=(source_requirement,)),
        (replace(submission, provenance=source),),
    )
    assert generation_result.bundle is None
    assert generation_result.condition is api.IntegrityStatus.MALFORMED
    assert generation_result.reason_codes == ("MALFORMED:runtime",)


def test_receipt_and_result_integrity_contracts_reject_forged_hashes_and_mismatches():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    with pytest.raises((TypeError, ValueError)):
        replace(result.receipt, receipt_hash=_hash("wrong"))
    with pytest.raises((TypeError, ValueError)):
        api.IngestionResult(
            result.bundle, result.receipt, api.IntegrityStatus.VALID, ("MISSING:prerequisite",)
        )
    with pytest.raises((TypeError, ValueError)):
        api.IngestionResult(result.bundle, result.receipt, api.IntegrityStatus.TAMPERED, ())
    with pytest.raises((TypeError, ValueError)):
        api.IngestionResult(
            result.bundle,
            replace(result.receipt, bundle_hash=_hash("wrong")),
            result.condition,
            result.reason_codes,
        )


def test_invalid_profile_or_submission_returns_closed_no_bundle_result():
    api, context, submission, _ = _fixture()
    with pytest.raises((TypeError, ValueError)):
        replace(context.profile, max_age_seconds=-1)
    mismatch = api.ingest_evidence(
        replace(context, expected_profile_hash=_hash("wrong")), (submission,)
    )
    assert mismatch.bundle is None and mismatch.reason_codes == ("MALFORMED:profile",)
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(None, (submission,))
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(context, [submission])


_CLOSED_REASONS = {
    "TAMPERED:content_hash",
    "TAMPERED:provenance_hash",
    "CROSS_BOUND:acceptance_contract",
    "STALE:subject",
    "STALE:generation",
    "STALE:observation",
    "CROSS_BOUND:producer",
    "CROSS_BOUND:repository",
    "CROSS_BOUND:tree",
    "CROSS_BOUND:changeset",
    "CROSS_BOUND:artifact",
    "CROSS_BOUND:runtime",
    "CROSS_BOUND:observation_status",
    "DUPLICATE:artifact",
    "DUPLICATE:verifier",
    "MALFORMED:profile",
    "MALFORMED:requirement",
    "MALFORMED:submission",
    "MALFORMED:provenance",
    "MALFORMED:evidence_type",
    "MALFORMED:producer_role",
    "MALFORMED:generation",
    "MALFORMED:timestamp",
    "MALFORMED:runtime",
    "MALFORMED:trust_reference",
    "MISSING:required_verifier",
    "MISSING:source_locator",
    "MISSING:execution",
    "MISSING:runtime_identity",
    "MISSING:ready_identity",
    "MISSING:prerequisite",
}


def test_freshness_unknown_causes_map_to_exact_admission_reasons():
    api, context, submission, envelope = _fixture()
    cases = [
        (replace(envelope, runtime=_runtime(api, observed_at="not-utc")), "MALFORMED:timestamp"),
        (
            replace(
                envelope,
                runtime=_hostile_runtime(
                    _runtime(api), desired_source_revision="", loaded_source_revision=""
                ),
            ),
            "MISSING:source_locator",
        ),
        (
            replace(envelope, runtime=_runtime(api, expected_runtime_identity=None)),
            "MISSING:runtime_identity",
        ),
        (replace(envelope, runtime=_runtime(api, readiness_status=None)), "MISSING:ready_identity"),
    ]
    for changed, reason in cases:
        req = replace(context.requirements[0], provenance_hash=changed.hash)
        result = api.ingest_evidence(
            replace(context, requirements=(req,)), (replace(submission, provenance=changed),)
        )
        assert result.bundle is None and reason in result.reason_codes
    source_runtime = _runtime(
        api,
        generation=api.EvidenceGeneration.SOURCE,
        loaded_source_revision="source-r1",
        expected_runtime_identity=None,
        observed_runtime_identity=None,
        readiness_status=None,
    )
    source = replace(
        envelope,
        generation=api.EvidenceGeneration.SOURCE,
        runtime=source_runtime,
    )
    source_req = replace(
        context.requirements[0],
        generation=api.EvidenceGeneration.SOURCE,
        runtime_ready_required=False,
        provenance_hash=source.hash,
    )
    result = api.ingest_evidence(
        replace(context, requirements=(source_req,)), (replace(submission, provenance=source),)
    )
    assert result.bundle is None and "STALE:subject" in result.reason_codes


def test_freshness_age_boundaries_use_caller_time_without_wall_clock():
    api, context, submission, envelope = _fixture()
    boundary = replace(envelope, generated_at=context.observed_at)
    req = replace(context.requirements[0], provenance_hash=boundary.hash)
    valid = api.ingest_evidence(
        replace(context, requirements=(req,)), (replace(submission, provenance=boundary),)
    )
    assert valid.condition is api.IntegrityStatus.VALID
    malformed_context = replace(context, observed_at="not-utc")
    result = api.ingest_evidence(malformed_context, (submission,))
    assert result.bundle is None and "MALFORMED:timestamp" in result.reason_codes


def test_hostile_string_role_and_generation_are_malformed_not_hashed():
    api, context, submission, envelope = _fixture()
    role = _hostile_envelope(envelope, producer_role="VERIFIER")
    generation = _hostile_envelope(envelope, generation="RUNTIME")
    for forged, reason in ((role, "MALFORMED:producer_role"), (generation, "MALFORMED:generation")):
        result = api.ingest_evidence(
            context, (api.EvidenceSubmission(submission.content, submission.status, forged),)
        )
        assert result.bundle is None and reason in result.reason_codes


def test_canonical_constructors_reject_duplicate_or_unsorted_trust_inputs_and_empty_receipts():
    api, *_ = _fixture()
    with pytest.raises((TypeError, ValueError)):
        api.IssuerGrant(
            "i", (api.TrustRole.AUTHORITY, api.TrustRole.AUTHORITY), ("merge", "merge"), ("pytest",)
        )
    with pytest.raises((TypeError, ValueError)):
        api.TrustReference(
            api.TrustRole.AUTHORITY,
            "e",
            "i",
            _hash("s"),
            "merge",
            api.TrustDecision.ALLOW,
            _at(-1),
            _at(1),
            None,
            _hash("p"),
            _hash("sp"),
            "pytest",
            b"",
            "sha256:" + hashlib.sha256(b"").hexdigest(),
        )
    with pytest.raises((TypeError, ValueError)):
        api.IssuerGrant(
            "i", (api.TrustRole.APPROVAL, api.TrustRole.AUTHORITY), ("merge", "review"), ("pytest",)
        )
    with pytest.raises((TypeError, ValueError)):
        api.IngestionProfile(
            "p",
            (
                api.ProducerGrant("b", api.ProducerRole.VERIFIER, _hash("b"), ("z", "a")),
                api.ProducerGrant("a", api.ProducerRole.VERIFIER, _hash("a"), ("a",)),
            ),
            (),
            1,
        )


def test_fail_observation_remains_valid_machine_verified_evidence():
    api, context, submission, _ = _fixture()
    failed = replace(submission, status=ObservationStatus.FAIL)
    requirement = replace(context.requirements[0], expected_status=ObservationStatus.FAIL)
    failed_context = replace(context, requirements=(requirement,))
    result = api.ingest_evidence(failed_context, (failed,))
    assert result.bundle is not None
    assert result.condition is api.IntegrityStatus.VALID and result.reason_codes == ()
    assert result.receipt.observations[0].status is ObservationStatus.FAIL
    assert result.receipt.machine_verified_artifact_ids == ("artifact-1",)


def test_reversed_submission_order_has_canonical_receipt_and_bundle_hashes():
    api, context, submission, envelope = _fixture()
    second = replace(
        envelope,
        evidence_id="evidence-2",
        artifact_id="artifact-2",
        verifier_id="lint",
        content_hash="sha256:" + hashlib.sha256(b"second").hexdigest(),
    )
    requirement = replace(
        context.requirements[0],
        verifier_id="lint",
        artifact_id="artifact-2",
        provenance_hash=second.hash,
        content_hash=second.content_hash,
    )
    other = api.EvidenceSubmission(b"second", ObservationStatus.PASS, second)
    two_contract = replace(context.contract, required_verifier_ids=("unit", "lint"))
    two_plan = replace(
        context.plan,
        acceptance_contract_hash=two_contract.hash,
        required_verifier_ids=("unit", "lint"),
    )
    two_verifier_context = replace(
        context,
        contract=two_contract,
        plan=two_plan,
        requirements=(context.requirements[0], requirement),
    )
    left = api.ingest_evidence(two_verifier_context, (submission, other))
    right = api.ingest_evidence(
        replace(two_verifier_context, requirements=(requirement, context.requirements[0])),
        (other, submission),
    )
    assert left.bundle is not None and right.bundle is not None
    assert left.receipt.hash == right.receipt.hash and left.bundle.hash == right.bundle.hash


def test_public_receipt_rejects_unrecomputed_universal_placeholder_hash():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    with pytest.raises((TypeError, ValueError)):
        replace(result.receipt, receipt_hash=_hash("receipt-placeholder"))


def test_trusted_result_is_sealed_to_exact_context_and_minted_identity():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert api.is_trusted_ingestion_result(context, result) is True
    assert (
        api.is_trusted_ingestion_result(replace(context, required_action="other"), result) is False
    )
    lookalike = object.__new__(type(result))
    for field in fields(result):
        object.__setattr__(lookalike, field.name, getattr(result, field.name))
    assert api.is_trusted_ingestion_result(context, lookalike) is False
    with pytest.raises((TypeError, ValueError)):
        api.IngestionResult(result.bundle, result.receipt, result.condition, result.reason_codes)
    with pytest.raises((TypeError, ValueError)):
        api.IngestionReceipt(*[
            getattr(result.receipt, field.name) for field in fields(result.receipt)
        ])


def test_single_trusted_fingerprint_registry_is_the_only_registry():
    api, context, submission, _ = _fixture()
    assert isinstance(api._TRUSTED_FINGERPRINTS, weakref.WeakKeyDictionary)
    assert not hasattr(api, "_TRUSTED_RESULTS")
    result = api.ingest_evidence(context, (submission,))
    result_ref = weakref.ref(result)
    assert result in api._TRUSTED_FINGERPRINTS
    lookalike = object.__new__(type(result))
    for field in fields(result):
        object.__setattr__(lookalike, field.name, getattr(result, field.name))
    assert lookalike not in api._TRUSTED_FINGERPRINTS
    assert api.is_trusted_ingestion_result(context, result) is True
    del result
    gc.collect()
    assert result_ref() is None


def test_fingerprint_value_does_not_retain_context_after_context_is_dropped():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    context_ref = weakref.ref(context)
    assert result in api._TRUSTED_FINGERPRINTS
    del context
    gc.collect()
    assert context_ref() is None
    assert result in api._TRUSTED_FINGERPRINTS
    del result
    gc.collect()


def test_distinct_issuer_objects_must_be_sorted_by_issuer_id():
    api, _, *_ = _fixture()
    first = api.IssuerGrant("issuer-b", (api.TrustRole.AUTHORITY,), ("merge",), ("pytest",))
    second = api.IssuerGrant("issuer-a", (api.TrustRole.AUTHORITY,), ("merge",), ("pytest",))
    with pytest.raises((TypeError, ValueError)):
        api.IngestionProfile("profile", (), (first, second), 3600)


def test_duplicate_prerequisite_roles_are_rejected_even_with_distinct_hashes():
    api, context, *_ = _fixture()
    prerequisites = ((api.TrustRole.AUTHORITY, _hash("a")), (api.TrustRole.AUTHORITY, _hash("b")))
    with pytest.raises((TypeError, ValueError)):
        replace(context, prerequisite_payload_hashes=prerequisites)


def test_forged_receipt_post_init_rejects_placeholder_hash_and_arbitrary_fields():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    forged = object.__new__(type(result.receipt))
    for field in fields(result.receipt):
        object.__setattr__(forged, field.name, getattr(result.receipt, field.name))
    object.__setattr__(forged, "profile_hash", _hash("wrong"))
    object.__setattr__(forged, "reason_codes", ("MISSING:prerequisite",))
    object.__setattr__(forged, "receipt_hash", _hash("receipt-placeholder"))
    with pytest.raises((TypeError, ValueError)):
        forged.__post_init__()


def test_minted_result_fingerprint_rejects_each_authoritative_mutation():
    api, context, submission, _ = _fixture()
    first = api.ingest_evidence(context, (submission,))
    second = api.ingest_evidence(context, (submission,))
    assert api.is_trusted_ingestion_result(context, first) is True
    assert api.is_trusted_ingestion_result(context, second) is True
    mutations = (
        (first.receipt, "profile_hash", _hash("wrong")),
        (first.receipt, "reason_codes", ("MISSING:prerequisite",)),
        (first.receipt, "observations", ()),
        (first.receipt, "machine_verified_artifact_ids", ()),
        (first.receipt, "human_open_reasons", (("artifact-1", "changed"),)),
        (first, "condition", api.IntegrityStatus.TAMPERED),
        (first, "reason_codes", ("MISSING:prerequisite",)),
        (first, "bundle", None),
    )
    for target, field, value in mutations:
        object.__setattr__(target, field, value)
        assert api.is_trusted_ingestion_result(context, first) is False
        if target is first:
            object.__setattr__(target, field, getattr(second, field))
        else:
            object.__setattr__(target, field, getattr(second.receipt, field))


def test_same_verifier_different_artifacts_and_raw_contents_are_duplicate():
    api, context, submission, envelope = _fixture()
    second_envelope = replace(
        envelope,
        evidence_id="evidence-2",
        artifact_id="artifact-2",
        content_hash="sha256:" + hashlib.sha256(b"second").hexdigest(),
    )
    second = api.EvidenceSubmission(b"second", submission.status, second_envelope)
    req = replace(
        context.requirements[0],
        artifact_id="artifact-2",
        content_hash=second_envelope.content_hash,
        provenance_hash=second_envelope.hash,
    )
    result = api.ingest_evidence(
        replace(context, requirements=(context.requirements[0], req)), (submission, second)
    )
    assert result.bundle is None and result.reason_codes == ("DUPLICATE:verifier",)


def test_source_old_loaded_revision_is_source_ahead_before_admission():
    api, *_ = _fixture()
    observation = _hostile_runtime(
        _runtime(
            api,
            generation=api.EvidenceGeneration.SOURCE,
            expected_runtime_identity=None,
            observed_runtime_identity=None,
            readiness_status=None,
        ),
        loaded_source_revision="old",
    )
    assert api.derive_runtime_freshness(observation, _at()).name == "SOURCE_AHEAD_OF_RUNTIME"


def test_resealed_future_generated_at_is_stale_observation():
    api, context, submission, envelope = _fixture()
    future = replace(envelope, generated_at=_at(1))
    req = replace(context.requirements[0], provenance_hash=future.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(req,)), (replace(submission, provenance=future),)
    )
    assert result.bundle is None and result.reason_codes == ("STALE:observation",)


def test_combined_physical_reasons_are_retained_sorted_with_stale_precedence():
    api, context, submission, envelope = _fixture()
    contract = replace(context.contract, required_verifier_ids=("unit", "lint", "security"))
    plan = replace(
        context.plan,
        acceptance_contract_hash=contract.hash,
        required_verifier_ids=("unit", "lint", "security"),
    )
    stale = replace(envelope, verifier_id="lint", target_revision="stale")
    stale_req = replace(context.requirements[0], verifier_id="lint", provenance_hash=stale.hash)
    result = api.ingest_evidence(
        replace(
            context, contract=contract, plan=plan, requirements=(context.requirements[0], stale_req)
        ),
        (submission, replace(submission, provenance=stale), submission),
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.STALE
    assert result.reason_codes == (
        "DUPLICATE:artifact",
        "MISSING:required_verifier",
        "STALE:subject",
    )


def test_legacy_narrative_generation_never_enters_typed_pass_path():
    api, context, submission, envelope = _fixture()
    legacy = _hostile_envelope(envelope, generation=api.EvidenceGeneration.LEGACY_NARRATIVE)
    req = replace(
        context.requirements[0],
        generation=api.EvidenceGeneration.LEGACY_NARRATIVE,
        provenance_hash=legacy.hash,
    )
    result = api.ingest_evidence(
        replace(context, requirements=(req,)),
        (api.EvidenceSubmission(submission.content, ObservationStatus.PASS, legacy),),
    )
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.MALFORMED
    assert result.reason_codes == ("MALFORMED:generation",)


def test_context_requirements_and_prerequisites_respect_collection_bound():
    api, context, *_ = _fixture()
    requirements = tuple(context.requirements[0] for _ in range(api.MAX_COLLECTION_ITEMS + 1))
    prerequisites = tuple(
        (api.TrustRole.AUTHORITY, _hash(f"p{i}")) for i in range(api.MAX_COLLECTION_ITEMS + 1)
    )
    with pytest.raises((TypeError, ValueError)):
        replace(context, requirements=requirements)
    with pytest.raises((TypeError, ValueError)):
        replace(context, prerequisite_payload_hashes=prerequisites)


def test_receipt_and_result_are_sealed_init_false_non_equatable_dataclasses():
    api = _api()
    for cls in (api.IngestionReceipt, api.IngestionResult):
        params = cls.__dataclass_params__
        assert params.frozen is True and params.init is False and params.eq is False


def test_diagnostic_trust_classification_is_exact_and_matches_boolean_helper():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.TRUSTED
    assert api.is_trusted_ingestion_result(context, result) is True
    assert (
        api.classify_ingestion_result(replace(context, required_action="other"), result)
        is api.IngestionTrustStatus.UNTRUSTED
    )
    lookalike = object.__new__(type(result))
    for field in fields(result):
        object.__setattr__(lookalike, field.name, getattr(result, field.name))
    assert api.classify_ingestion_result(context, lookalike) is api.IngestionTrustStatus.UNTRUSTED
    object.__setattr__(result.receipt, "profile_hash", _hash("changed"))
    assert (
        api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    assert api.is_trusted_ingestion_result(context, result) is False
    assert set(api.IngestionTrustStatus.__members__) == {"UNTRUSTED", "RECEIPT_INVALID", "TRUSTED"}


def test_runtime_timestamp_types_are_rejected_but_malformed_strings_classify_unknown():
    api, *_ = _fixture()
    with pytest.raises(TypeError):
        _runtime(api, observed_at=1)
    with pytest.raises(TypeError):
        _runtime(api, expires_at=1)
    malformed = _runtime(api, observed_at="not-rfc3339")
    assert api.derive_runtime_freshness(malformed, _at()).name == "CONVERGENCE_UNKNOWN"


def test_hostile_source_blank_revisions_are_unknown():
    api, *_ = _fixture()
    source = _hostile_runtime(
        _runtime(
            api,
            generation=api.EvidenceGeneration.SOURCE,
            expected_runtime_identity=None,
            observed_runtime_identity=None,
            readiness_status=None,
        ),
        desired_source_revision="",
        loaded_source_revision="",
    )
    assert api.derive_runtime_freshness(source, _at()).name == "CONVERGENCE_UNKNOWN"


def test_under_submitted_duplicate_requirements_return_exact_duplicate_without_exception():
    api, context, submission, _ = _fixture()
    second = replace(
        context.requirements[0],
        artifact_id="artifact-2",
        provenance_hash=context.requirements[0].provenance_hash,
    )
    result = api.ingest_evidence(
        replace(context, requirements=(context.requirements[0], second)), (submission,)
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.DUPLICATE
    assert result.reason_codes == ("DUPLICATE:verifier",)


def test_plan_binding_mismatch_reports_only_plan_reason():
    api, context, submission, _ = _fixture()
    plan = replace(context.plan, change_set_hash=_hash("wrong"))
    result = api.ingest_evidence(replace(context, plan=plan), (submission,))
    assert result.bundle is None and result.condition is api.IntegrityStatus.CROSS_BOUND
    assert result.reason_codes == ("CROSS_BOUND:changeset",)


def test_plan_change_set_gate_precedes_opaque_submission_inspection():
    api, context, _, _ = _fixture()
    plan = replace(context.plan, change_set_hash=_hash("wrong"))
    gated_context = replace(context, plan=plan)
    result = api.ingest_evidence(gated_context, (OpaqueSubmission(),))
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.CROSS_BOUND
    assert result.reason_codes == ("CROSS_BOUND:changeset",)
    assert result.receipt.context_hash == gated_context.hash
    assert result.receipt.profile_hash == gated_context.profile.hash
    assert (
        api.classify_ingestion_result(gated_context, result) is api.IngestionTrustStatus.UNTRUSTED
    )
    assert api.is_trusted_ingestion_result(gated_context, result) is False


def test_plan_acceptance_contract_gate_precedes_opaque_submission_inspection():
    api, context, _, _ = _fixture()
    plan = replace(context.plan, acceptance_contract_hash=_hash("wrong"))
    object.__setattr__(context, "plan", plan)
    gated_context = context
    result = api.ingest_evidence(gated_context, (OpaqueSubmission(),))
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.CROSS_BOUND
    assert result.reason_codes == ("CROSS_BOUND:acceptance_contract",)
    assert result.receipt.context_hash == gated_context.hash
    assert result.receipt.profile_hash == gated_context.profile.hash
    assert (
        api.classify_ingestion_result(gated_context, result) is api.IngestionTrustStatus.UNTRUSTED
    )
    assert api.is_trusted_ingestion_result(gated_context, result) is False


def test_both_plan_subject_gates_precede_opaque_submission_with_sorted_reasons():
    api, context, _, _ = _fixture()
    plan = replace(
        context.plan,
        acceptance_contract_hash=_hash("wrong-contract"),
        change_set_hash=_hash("wrong-change"),
    )
    gated_context = replace(context, plan=plan)
    result = api.ingest_evidence(gated_context, (OpaqueSubmission(),))
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.CROSS_BOUND
    assert result.reason_codes == (
        "CROSS_BOUND:acceptance_contract",
        "CROSS_BOUND:changeset",
    )
    assert result.receipt.context_hash == gated_context.hash
    assert result.receipt.profile_hash == gated_context.profile.hash
    assert (
        api.classify_ingestion_result(gated_context, result) is api.IngestionTrustStatus.UNTRUSTED
    )
    assert api.is_trusted_ingestion_result(gated_context, result) is False


def test_outer_context_profile_validation_precedes_plan_and_submission_access():
    api, context, _, _ = _fixture()
    object.__setattr__(context.profile.producers[0], "verification_methods", ["pytest"])
    plan = replace(
        context.plan,
        acceptance_contract_hash=_hash("wrong-contract"),
        change_set_hash=_hash("wrong-change"),
    )
    object.__setattr__(context, "plan", plan)
    gated_context = context
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(gated_context, (OpaqueSubmission(),))


def test_outer_context_requirement_validation_precedes_plan_and_submission_access():
    api, context, _, _ = _fixture()
    object.__setattr__(context.requirements[0], "runtime_ready_required", 1)
    plan = replace(context.plan, change_set_hash=_hash("wrong-change"))
    object.__setattr__(context, "plan", plan)
    gated_context = context
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(gated_context, (OpaqueSubmission(),))


def test_reversed_valid_producer_collection_invalidates_profile_lifecycle_without_hash_drift():
    api, context, submission, _ = _fixture()
    producer_two = api.ProducerGrant(
        "producer-2", api.ProducerRole.RUNTIME, _hash("producer-two"), ("runtime",)
    )
    profile = replace(context.profile, producers=(context.profile.producers[0], producer_two))
    profiled = replace(context, profile=profile, expected_profile_hash=profile.hash)
    result = api.ingest_evidence(profiled, (submission,))
    assert result.bundle is not None
    assert api.is_trusted_ingestion_result(profiled, result) is True
    profile_hash = profiled.profile.hash
    context_hash = profiled.hash
    object.__setattr__(profiled.profile, "producers", tuple(reversed(profiled.profile.producers)))
    assert profiled.profile.hash == profile_hash and profiled.hash == context_hash
    assert (
        api.classify_ingestion_result(profiled, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    assert api.is_trusted_ingestion_result(profiled, result) is False
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(profiled, (submission,))


def test_reversed_valid_issuer_collection_invalidates_profile_lifecycle_without_hash_drift():
    api, context, submission, _ = _fixture()
    issuer_two = api.IssuerGrant("issuer-2", (api.TrustRole.AUTHORITY,), ("merge",), ("pytest",))
    profile = replace(context.profile, issuers=(context.profile.issuers[0], issuer_two))
    profiled = replace(context, profile=profile, expected_profile_hash=profile.hash)
    result = api.ingest_evidence(profiled, (submission,))
    assert result.bundle is not None
    assert api.is_trusted_ingestion_result(profiled, result) is True
    profile_hash = profiled.profile.hash
    context_hash = profiled.hash
    object.__setattr__(profiled.profile, "issuers", tuple(reversed(profiled.profile.issuers)))
    assert profiled.profile.hash == profile_hash and profiled.hash == context_hash
    assert (
        api.classify_ingestion_result(profiled, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    assert api.is_trusted_ingestion_result(profiled, result) is False
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(profiled, (submission,))


def test_outer_required_action_mutation_is_raw_shape_error_and_invalidates_prior_result():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert api.is_trusted_ingestion_result(context, result) is True
    object.__setattr__(context, "required_action", "")
    assert (
        api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    assert api.is_trusted_ingestion_result(context, result) is False
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(context, (submission,))


def test_reversed_sorted_prerequisites_preserve_hash_but_fail_outer_shape_validation():
    api, context, submission, _ = _fixture()
    prerequisites = (
        (api.TrustRole.APPROVAL, _hash("approval")),
        (api.TrustRole.AUTHORITY, _hash("authority")),
    )
    profiled = replace(context, prerequisite_payload_hashes=prerequisites)
    result = api.ingest_evidence(profiled, (submission,))
    assert api.is_trusted_ingestion_result(profiled, result) is True
    context_hash = profiled.hash
    object.__setattr__(profiled, "prerequisite_payload_hashes", tuple(reversed(prerequisites)))
    assert profiled.hash == context_hash
    assert (
        api.classify_ingestion_result(profiled, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    assert api.is_trusted_ingestion_result(profiled, result) is False
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(profiled, (submission,))


@pytest.mark.parametrize(
    "subject, field, value",
    [
        ("contract", "contract_id", ""),
        ("change_set", "source_revision", ""),
        ("plan", "required_verifier_ids", []),
    ],
)
def test_outer_subject_mutation_is_raw_shape_error_and_invalidates_prior_result(
    subject, field, value
):
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert api.is_trusted_ingestion_result(context, result) is True
    object.__setattr__(getattr(context, subject), field, value)
    assert (
        api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    assert api.is_trusted_ingestion_result(context, result) is False
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(context, (submission,))


def test_submission_tuple_collection_bound_is_checked_before_work():
    api, context, submission, _ = _fixture()
    with pytest.raises(ValueError):
        api.ingest_evidence(context, (submission,) * (api.MAX_COLLECTION_ITEMS + 1))


def test_under_submitted_duplicate_verifier_uses_distinct_resealed_provenance():
    api, context, submission, envelope = _fixture()
    second_envelope = replace(envelope, evidence_id="evidence-2", artifact_id="artifact-2")
    second_requirement = replace(
        context.requirements[0], artifact_id="artifact-2", provenance_hash=second_envelope.hash
    )
    result = api.ingest_evidence(
        replace(context, requirements=(context.requirements[0], second_requirement)), (submission,)
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.DUPLICATE
    assert result.reason_codes == ("DUPLICATE:verifier",)


def test_combined_reasons_retain_duplicate_and_stale_exactly_with_valid_plan():
    api, context, submission, envelope = _fixture()
    stale = replace(envelope, target_revision="stale")
    other = replace(envelope, verifier_id="other", target_revision="stale")
    stale_req = replace(context.requirements[0], verifier_id="unit", provenance_hash=stale.hash)
    other_req = replace(context.requirements[0], verifier_id="other", provenance_hash=other.hash)
    contract = replace(context.contract, required_verifier_ids=("unit", "other"))
    plan = replace(
        context.plan,
        acceptance_contract_hash=contract.hash,
        required_verifier_ids=("unit", "other"),
    )
    result = api.ingest_evidence(
        replace(context, contract=contract, plan=plan, requirements=(stale_req, other_req)),
        (replace(submission, provenance=stale), replace(submission, provenance=other)),
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.STALE
    assert result.reason_codes == ("DUPLICATE:artifact", "STALE:subject")


def test_contract_plan_binding_reports_only_plan_reason():
    api, context, submission, _ = _fixture()
    plan = replace(context.plan, acceptance_contract_hash=_hash("wrong"))
    result = api.ingest_evidence(replace(context, plan=plan), (submission,))
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.CROSS_BOUND
    assert result.reason_codes == ("CROSS_BOUND:acceptance_contract",)


def test_under_submitted_duplicate_artifact_reports_duplicate_and_missing_exactly():
    api, context, submission, envelope = _fixture()
    second_envelope = replace(envelope, evidence_id="evidence-2", verifier_id="lint")
    second_requirement = replace(
        context.requirements[0], verifier_id="lint", provenance_hash=second_envelope.hash
    )
    contract = replace(context.contract, required_verifier_ids=("unit", "lint"))
    plan = replace(
        context.plan, acceptance_contract_hash=contract.hash, required_verifier_ids=("unit", "lint")
    )
    result = api.ingest_evidence(
        replace(
            context,
            contract=contract,
            plan=plan,
            requirements=(context.requirements[0], second_requirement),
        ),
        (submission,),
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.DUPLICATE
    assert result.reason_codes == ("DUPLICATE:artifact", "MISSING:required_verifier")


@pytest.mark.parametrize("value", [" ", "bad\x00source", "x" * 4097, 1])
def test_hostile_runtime_source_revision_values_are_unknown(value):
    api, *_ = _fixture()
    runtime = _hostile_runtime(
        _runtime(api), desired_source_revision=value, loaded_source_revision=value
    )
    assert api.derive_runtime_freshness(runtime, _at()).name == "CONVERGENCE_UNKNOWN"


def test_hostile_source_revision_admission_maps_to_missing_source_locator():
    api, context, submission, envelope = _fixture()
    runtime = _hostile_runtime(
        _runtime(api), desired_source_revision=" ", loaded_source_revision=" "
    )
    changed = replace(envelope, runtime=runtime)
    requirement = replace(context.requirements[0], provenance_hash=changed.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=changed),)
    )
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.MISSING
    assert result.reason_codes == ("MISSING:source_locator",)


def test_hostile_source_locator_str_subclass_is_malformed_provenance():
    class SourceLocator(str):
        pass

    api, context, submission, envelope = _fixture()
    changed = _hostile_envelope(envelope, source_locator=SourceLocator("tests/test_a.py"))
    requirement = replace(context.requirements[0], provenance_hash=changed.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)),
        (api.EvidenceSubmission(submission.content, submission.status, changed),),
    )
    assert result.bundle is None and result.reason_codes == ("MALFORMED:provenance",)


def test_hostile_revision_types_are_malformed_provenance_after_resealing():
    class Revision(str):
        pass

    api, context, submission, envelope = _fixture()
    for field, value in (
        ("source_revision", 1),
        ("target_revision", 1),
        ("source_revision", Revision("source-r1")),
        ("target_revision", Revision("target-r2")),
    ):
        changed = _hostile_envelope(envelope, **{field: value})
        requirement = replace(context.requirements[0], provenance_hash=changed.hash)
        result = api.ingest_evidence(
            replace(context, requirements=(requirement,)),
            (api.EvidenceSubmission(submission.content, submission.status, changed),),
        )
        assert result.bundle is None and result.condition is api.IntegrityStatus.MALFORMED
        assert result.reason_codes == ("MALFORMED:provenance",)


def test_mint_history_cannot_upgrade_a_tampered_result_to_trusted():
    api, context, submission, _ = _fixture()
    tampered = api.ingest_evidence(context, (replace(submission, content=b"tampered"),))
    object.__setattr__(tampered, "condition", api.IntegrityStatus.VALID)
    object.__setattr__(tampered, "reason_codes", ())
    assert api.classify_ingestion_result(context, tampered) is api.IngestionTrustStatus.UNTRUSTED
    assert api.is_trusted_ingestion_result(context, tampered) is False


def test_successful_mint_mutated_condition_or_reasons_is_receipt_invalid():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.TRUSTED
    object.__setattr__(result, "condition", api.IntegrityStatus.TAMPERED)
    assert (
        api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    object.__setattr__(result, "condition", api.IntegrityStatus.VALID)
    object.__setattr__(result, "reason_codes", ("MISSING:prerequisite",))
    assert (
        api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )


def test_freshness_stale_generation_precedes_missing_source():
    api, *_ = _fixture()
    observation = _hostile_runtime(
        _runtime(api), desired_source_revision="", loaded_source_revision="", observed_generation=6
    )
    assert api.derive_runtime_freshness(observation, _at()).name == "STALE_OBSERVATION"


def test_source_generation_with_equal_runtime_identity_and_ready_is_unknown_and_malformed():
    api, context, submission, envelope = _fixture()
    runtime = _runtime(api, generation=api.EvidenceGeneration.RUNTIME)
    changed = replace(envelope, generation=api.EvidenceGeneration.SOURCE, runtime=runtime)
    requirement = replace(
        context.requirements[0],
        generation=api.EvidenceGeneration.SOURCE,
        runtime_ready_required=False,
        provenance_hash=changed.hash,
    )
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=changed),)
    )
    assert api.derive_runtime_freshness(runtime, _at()).name == "READY_IDENTITY_BOUND"
    assert result.bundle is None and result.reason_codes == ("MALFORMED:runtime",)


def test_runtime_generation_without_observation_is_missing_both_identity_reasons():
    api, context, submission, envelope = _fixture()
    changed = replace(envelope, runtime=None)
    requirement = replace(
        context.requirements[0], runtime_ready_required=False, provenance_hash=changed.hash
    )
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=changed),)
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.MISSING
    assert result.reason_codes == ("MISSING:ready_identity", "MISSING:runtime_identity")


@pytest.mark.parametrize(
    "field, value",
    [
        ("verifier_id", ""),
        ("artifact_id", ""),
        ("producer_id", ""),
        ("execution_id", ""),
        ("attempt_id", ""),
        ("evidence_type", "VERIFIER_RESULT"),
        ("generation", "RUNTIME"),
        ("environment_hash", "bad"),
        ("content_hash", "bad"),
        ("provenance_hash", "bad"),
        ("runtime_ready_required", "yes"),
        ("human_semantic_review_required", 1),
    ],
)
def test_trusted_context_revalidates_hostile_nested_requirement_fields(field, value):
    api, context, *_ = _fixture()
    requirement = object.__new__(type(context.requirements[0]))
    for item in fields(context.requirements[0]):
        object.__setattr__(requirement, item.name, getattr(context.requirements[0], item.name))
    object.__setattr__(requirement, field, value)
    with pytest.raises((TypeError, ValueError)):
        replace(context, requirements=(requirement,))


def test_source_aligned_evidence_cannot_satisfy_runtime_ready_requirement():
    api, context, submission, envelope = _fixture()
    source_runtime = _runtime(
        api,
        generation=api.EvidenceGeneration.SOURCE,
        expected_runtime_identity=None,
        observed_runtime_identity=None,
        readiness_status=None,
    )
    source = replace(envelope, generation=api.EvidenceGeneration.SOURCE, runtime=source_runtime)
    requirement = replace(
        context.requirements[0],
        generation=api.EvidenceGeneration.SOURCE,
        runtime_ready_required=True,
        provenance_hash=source.hash,
    )
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=source),)
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.MISSING
    assert result.reason_codes == ("MISSING:ready_identity",)


@pytest.mark.parametrize("bad_provenance", ["bad", None])
def test_ingest_revalidates_submission_provenance_without_attribute_error(bad_provenance):
    api, context, submission, _ = _fixture()
    object.__setattr__(submission, "provenance", bad_provenance)
    result = api.ingest_evidence(context, (submission,))
    assert result.bundle is None and result.condition is api.IntegrityStatus.MALFORMED
    assert result.reason_codes == ("MALFORMED:provenance", "MISSING:required_verifier")


@pytest.mark.parametrize("field, value", [("runtime_ready_required", 1), ("execution_id", "")])
def test_ingest_revalidates_nested_requirement_without_accepting_hostile_values(field, value):
    api, context, submission, _ = _fixture()
    requirement = context.requirements[0]
    object.__setattr__(requirement, field, value)
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(context, (submission,))


def test_opaque_submission_shape_is_malformed_with_missing_required_verifier():
    api, context, _, _ = _fixture()
    result = api.ingest_evidence(context, (object(),))
    assert result.bundle is None and result.condition is api.IntegrityStatus.MALFORMED
    assert result.reason_codes == ("MALFORMED:submission", "MISSING:required_verifier")


def test_opaque_and_tampered_submissions_preserve_tamper_precedence_and_both_reasons():
    api, context, submission, _ = _fixture()
    tampered = replace(submission, content=b"tampered")
    result = api.ingest_evidence(context, (object(), tampered))
    assert result.bundle is None and result.condition is api.IntegrityStatus.TAMPERED
    assert result.reason_codes == ("MALFORMED:submission", "TAMPERED:content_hash")


@pytest.mark.parametrize(
    "field, value",
    [
        ("source_revision", " "),
        ("target_revision", "bad\x00revision"),
        ("source_revision", "x" * 4097),
    ],
)
def test_hostile_normalized_revision_values_are_malformed_provenance(field, value):
    api, context, submission, envelope = _fixture()
    changed = _hostile_envelope(envelope, **{field: value})
    requirement = replace(context.requirements[0], provenance_hash=changed.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)),
        (api.EvidenceSubmission(submission.content, submission.status, changed),),
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.MALFORMED
    assert result.reason_codes == ("MALFORMED:provenance",)


@pytest.mark.parametrize(
    "grant_field, value",
    [("verification_methods", ["pytest"]), ("actions", ["merge"]), ("roles", None)],
)
def test_nested_profile_grant_mutation_invalidates_profile_without_hash_drift(grant_field, value):
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert api.is_trusted_ingestion_result(context, result) is True
    profile_hash = context.profile.hash
    context_hash = context.hash
    grant = (
        context.profile.producers[0]
        if grant_field == "verification_methods"
        else context.profile.issuers[0]
    )
    if grant_field == "roles":
        value = [api.TrustRole.AUTHORITY]
    object.__setattr__(grant, grant_field, value)
    assert context.profile.hash == profile_hash and context.hash == context_hash
    assert (
        api.classify_ingestion_result(context, result) is api.IngestionTrustStatus.RECEIPT_INVALID
    )
    assert api.is_trusted_ingestion_result(context, result) is False
    with pytest.raises((TypeError, ValueError)):
        api.ingest_evidence(context, (submission,))


def test_freshness_missing_source_and_generation_mismatch_preserve_both_reasons():
    api, context, submission, envelope = _fixture()
    runtime = _hostile_runtime(
        _runtime(api), desired_source_revision="", loaded_source_revision="", observed_generation=6
    )
    changed = replace(envelope, runtime=runtime)
    requirement = replace(context.requirements[0], provenance_hash=changed.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=changed),)
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.STALE
    assert result.reason_codes == ("MISSING:source_locator", "STALE:generation")


def test_source_runtime_identity_contamination_is_unknown_and_malformed_at_admission():
    api, context, submission, envelope = _fixture()
    runtime = _runtime(api, generation=api.EvidenceGeneration.RUNTIME)
    changed = replace(envelope, generation=api.EvidenceGeneration.SOURCE, runtime=runtime)
    requirement = replace(
        context.requirements[0],
        generation=api.EvidenceGeneration.SOURCE,
        runtime_ready_required=False,
        provenance_hash=changed.hash,
    )
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=changed),)
    )
    assert result.bundle is None and result.reason_codes == ("MALFORMED:runtime",)


def test_runtime_without_observation_is_missing_both_identity_and_readiness():
    api, context, submission, envelope = _fixture()
    changed = replace(envelope, runtime=None)
    requirement = replace(context.requirements[0], provenance_hash=changed.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=changed),)
    )
    assert result.bundle is None and result.condition is api.IntegrityStatus.MISSING
    assert result.reason_codes == ("MISSING:ready_identity", "MISSING:runtime_identity")


@pytest.mark.parametrize("value", ["", " ", "bad\x00timestamp", "x" * 4097])
def test_runtime_timestamp_constructor_rejects_empty_whitespace_nul_and_oversize(value):
    api, *_ = _fixture()
    with pytest.raises((TypeError, ValueError)):
        _runtime(api, observed_at=value)


def test_runtime_not_utc_string_remains_constructible_but_unknown():
    api, *_ = _fixture()
    observation = _runtime(api, observed_at="not-utc")
    assert api.derive_runtime_freshness(observation, _at()).name == "CONVERGENCE_UNKNOWN"


def test_hostile_runtime_blank_source_revisions_map_to_missing_source_locator():
    api, context, submission, envelope = _fixture()
    runtime = _hostile_runtime(_runtime(api), desired_source_revision="", loaded_source_revision="")
    assert api.derive_runtime_freshness(runtime, _at()).name == "CONVERGENCE_UNKNOWN"
    changed = replace(envelope, runtime=runtime)
    requirement = replace(context.requirements[0], provenance_hash=changed.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=changed),)
    )
    assert result.bundle is None and result.reason_codes == ("MISSING:source_locator",)


@pytest.mark.parametrize("locator", [" ", "bad\x00locator"])
def test_hostile_blank_or_nul_source_locator_is_missing_at_admission(locator):
    api, context, submission, envelope = _fixture()
    changed = _hostile_envelope(envelope, source_locator=locator)
    requirement = replace(context.requirements[0], provenance_hash=changed.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)),
        (api.EvidenceSubmission(submission.content, submission.status, changed),),
    )
    assert result.bundle is None and result.reason_codes == ("MISSING:source_locator",)


def test_same_hash_context_clone_is_not_the_minted_context_identity():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    clone = replace(context)
    assert clone == context and clone is not context
    assert api.classify_ingestion_result(clone, result) is api.IngestionTrustStatus.UNTRUSTED
    assert api.is_trusted_ingestion_result(clone, result) is False


def test_minted_tampered_result_is_untrusted_while_mutated_success_is_receipt_invalid():
    api, context, submission, _ = _fixture()
    tampered = api.ingest_evidence(context, (replace(submission, content=b"tampered"),))
    assert tampered.condition is not api.IntegrityStatus.VALID
    assert api.classify_ingestion_result(context, tampered) is api.IngestionTrustStatus.UNTRUSTED
    assert api.is_trusted_ingestion_result(context, tampered) is False
    valid = api.ingest_evidence(context, (submission,))
    object.__setattr__(valid.receipt, "profile_hash", _hash("changed"))
    assert api.classify_ingestion_result(context, valid) is api.IngestionTrustStatus.RECEIPT_INVALID


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-08-29 12:00:00+00:00",
        "2026-08-29T12:00:00+00:00:00",
        "2026-08-29T12:00:00,1+00:00",
        "2026-08-29T12:00:00+08:00",
    ],
)
def test_strict_rfc3339_utc_controls_reject_noncanonical_or_non_utc_times(timestamp):
    api, *_ = _fixture()
    observation = _runtime(api, observed_at=timestamp)
    assert api.derive_runtime_freshness(observation, _at()).name == "CONVERGENCE_UNKNOWN"


def test_rfc3339_z_and_explicit_utc_are_accepted_equivalently():
    api, *_ = _fixture()
    explicit = _runtime(
        api, observed_at="2026-08-29T11:59:50+00:00", expires_at="2026-08-29T13:00:00+00:00"
    )
    zulu = _runtime(api, observed_at="2026-08-29T11:59:50Z", expires_at="2026-08-29T13:00:00Z")
    assert api.derive_runtime_freshness(explicit, _at()).name == "READY_IDENTITY_BOUND"
    assert api.derive_runtime_freshness(zulu, _at()).name == "READY_IDENTITY_BOUND"


def test_trusted_fingerprint_registry_is_weak_keyed_and_releases_results():
    api, context, submission, _ = _fixture()
    assert isinstance(api._TRUSTED_FINGERPRINTS, weakref.WeakKeyDictionary)
    results = [api.ingest_evidence(context, (submission,)) for _ in range(3)]
    refs = [weakref.ref(result) for result in results]
    assert all(result in api._TRUSTED_FINGERPRINTS for result in results)
    results.clear()
    gc.collect()
    assert all(ref() is None for ref in refs)
    assert len(api._TRUSTED_FINGERPRINTS) == 0


def test_result_consistency_binds_reasons_condition_and_context_profile_bundle():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    for changes in (
        {"reason_codes": ("MISSING:prerequisite",)},
        {"condition": api.IntegrityStatus.TAMPERED},
    ):
        with pytest.raises((TypeError, ValueError)):
            api.IngestionResult(
                result.bundle,
                changes.get("receipt", result.receipt),
                changes.get("condition", result.condition),
                changes.get("reason_codes", result.reason_codes),
            )
    for field in ("context_hash", "profile_hash", "bundle_hash"):
        with pytest.raises((TypeError, ValueError)):
            api.IngestionResult(
                result.bundle,
                replace(result.receipt, **{field: _hash("wrong")}),
                result.condition,
                result.reason_codes,
            )
    assert api.condition_for_ingestion_reasons(result.reason_codes) is result.condition


def test_duplicate_verifier_and_artifact_conflicts_are_distinct_and_unbundled():
    api, context, submission, envelope = _fixture()
    second_envelope = replace(envelope, evidence_id="evidence-2", artifact_id="artifact-2")
    second_requirement = replace(
        context.requirements[0], artifact_id="artifact-2", provenance_hash=second_envelope.hash
    )
    second = api.EvidenceSubmission(submission.content, submission.status, second_envelope)
    duplicate_context = replace(
        context,
        contract=replace(context.contract, required_verifier_ids=("unit",)),
        plan=replace(context.plan, required_verifier_ids=("unit",)),
        requirements=(context.requirements[0], second_requirement),
    )
    verifier_duplicate = api.ingest_evidence(duplicate_context, (submission, second))
    artifact_envelope = replace(second_envelope, verifier_id="other", artifact_id="artifact-1")
    artifact_submission = api.EvidenceSubmission(
        submission.content, submission.status, artifact_envelope
    )
    artifact_contract = replace(context.contract, required_verifier_ids=("unit", "other"))
    artifact_plan = replace(
        context.plan,
        acceptance_contract_hash=artifact_contract.hash,
        required_verifier_ids=("unit", "other"),
    )
    artifact_context = replace(
        context,
        contract=artifact_contract,
        plan=artifact_plan,
        requirements=(
            context.requirements[0],
            replace(
                second_requirement,
                verifier_id="other",
                artifact_id="artifact-1",
                provenance_hash=artifact_envelope.hash,
            ),
        ),
    )
    artifact_duplicate = api.ingest_evidence(
        artifact_context,
        (submission, artifact_submission),
    )
    assert verifier_duplicate.bundle is None and verifier_duplicate.reason_codes == (
        "DUPLICATE:verifier",
    )
    assert artifact_duplicate.bundle is None and artifact_duplicate.reason_codes == (
        "DUPLICATE:artifact",
    )


def test_source_ahead_maps_to_stale_subject_for_source_and_runtime_admission():
    api, context, submission, envelope = _fixture()
    source_runtime = _hostile_runtime(
        _runtime(
            api,
            generation=api.EvidenceGeneration.SOURCE,
            expected_runtime_identity=None,
            observed_runtime_identity=None,
            readiness_status=None,
        ),
        loaded_source_revision="source-r1",
    )
    source = replace(envelope, generation=api.EvidenceGeneration.SOURCE, runtime=source_runtime)
    req = replace(
        context.requirements[0],
        generation=api.EvidenceGeneration.SOURCE,
        runtime_ready_required=False,
        provenance_hash=source.hash,
    )
    result = api.ingest_evidence(
        replace(context, requirements=(req,)), (replace(submission, provenance=source),)
    )
    assert result.bundle is None and result.reason_codes == ("STALE:subject",)


def test_runtime_source_ahead_maps_to_stale_subject_with_resealed_runtime_requirement():
    api, context, submission, envelope = _fixture()
    runtime = _runtime(api, loaded_source_revision="source-r1")
    changed = replace(envelope, runtime=runtime)
    requirement = replace(context.requirements[0], provenance_hash=changed.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)), (replace(submission, provenance=changed),)
    )
    assert result.bundle is None and result.reason_codes == ("STALE:subject",)


def test_ready_with_blank_runtime_identity_is_unknown_and_missing():
    api, context, submission, envelope = _fixture()
    runtime = _hostile_runtime(
        _runtime(api), expected_runtime_identity="", observed_runtime_identity=""
    )
    changed = replace(envelope, runtime=runtime)
    req = replace(context.requirements[0], provenance_hash=changed.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(req,)), (replace(submission, provenance=changed),)
    )
    assert result.bundle is None and result.reason_codes == ("MISSING:runtime_identity",)


def test_constructor_order_and_duplicate_guards_cover_all_canonical_inputs():
    api, context, *_ = _fixture()
    with pytest.raises((TypeError, ValueError)):
        api.ProducerGrant("p", api.ProducerRole.VERIFIER, _hash("p"), ("z", "a"))
    with pytest.raises((TypeError, ValueError)):
        api.IssuerGrant(
            "i", (api.TrustRole.AUTHORITY, api.TrustRole.AUTHORITY), ("merge",), ("pytest",)
        )
    issuer = api.IssuerGrant("i", (api.TrustRole.AUTHORITY,), ("merge",), ("pytest",))
    with pytest.raises((TypeError, ValueError)):
        api.IngestionProfile(
            "p",
            (api.ProducerGrant("p", api.ProducerRole.VERIFIER, _hash("p"), ("pytest",)),),
            (issuer, issuer),
            1,
        )
    with pytest.raises((TypeError, ValueError)):
        api.TrustedIngestionContext(
            context.contract,
            context.change_set,
            context.plan,
            context.repository_id,
            context.source_tree,
            context.target_tree,
            context.observed_at,
            context.profile,
            context.expected_profile_hash,
            context.requirements,
            context.required_action,
            (
                (api.TrustRole.SIGNING, _hash("s")),
                (api.TrustRole.AUTHORITY, _hash("a")),
            ),
        )


def test_extra_requirement_and_plan_subject_mismatches_fail_closed():
    api, context, submission, _ = _fixture()
    extra = replace(context.requirements[0], verifier_id="extra", artifact_id="extra")
    extra_result = api.ingest_evidence(
        replace(context, requirements=(context.requirements[0], extra)), (submission,)
    )
    assert extra_result.bundle is None and extra_result.condition is api.IntegrityStatus.MALFORMED
    assert extra_result.reason_codes == ("MALFORMED:requirement",)
    contract_mismatch = replace(context.plan, acceptance_contract_hash=_hash("wrong"))
    change_mismatch = replace(context.plan, change_set_hash=_hash("wrong"))
    for plan, reason in (
        (contract_mismatch, "CROSS_BOUND:acceptance_contract"),
        (change_mismatch, "CROSS_BOUND:changeset"),
    ):
        result = api.ingest_evidence(replace(context, plan=plan), (submission,))
        assert result.bundle is None
        assert result.condition is api.IntegrityStatus.CROSS_BOUND
        assert result.reason_codes == (reason,)


def test_bundle_integrity_cannot_disagree_with_successful_ingestion():
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (submission,))
    assert result.bundle is not None
    assert (
        result.bundle.integrity(context.contract, context.change_set, context.plan)
        is api.IntegrityStatus.VALID
    )


def test_runtime_generation_and_runtime_observation_combinations_fail_closed():
    api, context, submission, envelope = _fixture()
    execution = replace(
        envelope, generation=api.EvidenceGeneration.EXECUTION, runtime=_runtime(api)
    )
    runtime_source = replace(
        envelope,
        generation=api.EvidenceGeneration.RUNTIME,
        runtime=replace(_runtime(api), generation=api.EvidenceGeneration.SOURCE),
    )
    execution_req = replace(
        context.requirements[0],
        generation=api.EvidenceGeneration.EXECUTION,
        runtime_ready_required=False,
        provenance_hash=execution.hash,
    )
    runtime_source_req = replace(
        context.requirements[0],
        generation=api.EvidenceGeneration.RUNTIME,
        runtime_ready_required=False,
        provenance_hash=runtime_source.hash,
    )
    for changed, requirement, reason in (
        (execution, execution_req, "MALFORMED:runtime"),
        (runtime_source, runtime_source_req, "MALFORMED:generation"),
    ):
        result = api.ingest_evidence(
            replace(context, requirements=(requirement,)),
            (replace(submission, provenance=changed),),
        )
        assert result.bundle is None and result.reason_codes == (reason,)
    with pytest.raises((TypeError, ValueError)):
        _runtime(api, expected_runtime_identity=1)
    hostile_source = _hostile_envelope(envelope, source_locator=None)
    source_req = replace(context.requirements[0], provenance_hash=hostile_source.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(source_req,)),
        (api.EvidenceSubmission(submission.content, submission.status, hostile_source),),
    )
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.MALFORMED
    assert result.reason_codes == ("MALFORMED:provenance",)
    hostile_runtime = _hostile_envelope(envelope, runtime="bad")
    runtime_req = replace(context.requirements[0], provenance_hash=hostile_runtime.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(runtime_req,)),
        (api.EvidenceSubmission(submission.content, submission.status, hostile_runtime),),
    )
    assert result.bundle is None and result.reason_codes == ("MALFORMED:runtime",)


def test_public_bounded_length_constants_and_representative_limits():
    api, _, submission, envelope = _fixture()
    assert api.MAX_TEXT_LENGTH == 4096
    assert api.MAX_COLLECTION_ITEMS == 256
    assert api.MAX_CONTENT_BYTES == 1_048_576
    oversized_content = b"x" * (api.MAX_CONTENT_BYTES + 1)
    oversized_hash = "sha256:" + hashlib.sha256(oversized_content).hexdigest()
    with pytest.raises((TypeError, ValueError)):
        api.ProducerGrant(
            "p" * (api.MAX_TEXT_LENGTH + 1), api.ProducerRole.VERIFIER, _hash("p"), ("pytest",)
        )
    with pytest.raises((TypeError, ValueError)):
        api.ProducerGrant(
            "p",
            api.ProducerRole.VERIFIER,
            _hash("p"),
            tuple(f"m{i}" for i in range(api.MAX_COLLECTION_ITEMS + 1)),
        )
    with pytest.raises((TypeError, ValueError)):
        api.EvidenceSubmission(oversized_content, submission.status, envelope)
    with pytest.raises((TypeError, ValueError)):
        api.TrustReference(
            api.TrustRole.AUTHORITY,
            "e",
            "i",
            _hash("s"),
            "merge",
            api.TrustDecision.ALLOW,
            _at(-1),
            _at(1),
            None,
            _hash("p"),
            _hash("sp"),
            "pytest",
            oversized_content,
            oversized_hash,
        )


def test_multi_submission_attack_keeps_all_reason_codes_sorted_unique_and_top_condition():
    api, context, submission, envelope = _fixture()
    stale = replace(submission, provenance=replace(envelope, target_revision="stale"))
    forged = replace(submission, content=b"forged")
    result = api.ingest_evidence(context, (forged, stale, submission, submission))
    assert result.bundle is None and result.condition is api.IntegrityStatus.TAMPERED
    assert tuple(sorted(set(result.reason_codes))) == result.reason_codes


def test_task6_h1_same_artifact_locator_changed_raw_bytes_is_exact_content_tamper():
    """H1: same artifact/locator cannot carry different raw bytes."""
    api, context, submission, _ = _fixture()
    result = api.ingest_evidence(context, (replace(submission, content=b"different-content"),))
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.TAMPERED
    assert result.reason_codes == ("TAMPERED:content_hash",)


def test_task6_h3_resealed_producer_identity_is_exact_cross_bound_producer():
    """H3: resealing producer identity does not widen the trusted profile."""
    api, context, submission, envelope = _fixture()
    hostile = _hostile_envelope(envelope, producer_id="spoofed-producer")
    requirement = replace(context.requirements[0], provenance_hash=hostile.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)),
        (replace(submission, provenance=hostile),),
    )
    assert result.bundle is None
    assert result.reason_codes == ("CROSS_BOUND:producer",)


def test_task6_h7_old_runtime_generation_is_exact_stale_generation():
    """H7: a runtime observation cannot claim a newer desired generation."""
    api, context, submission, envelope = _fixture()
    hostile = _hostile_envelope(envelope, runtime=_runtime(api, observed_generation=6))
    requirement = replace(context.requirements[0], provenance_hash=hostile.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)),
        (replace(submission, provenance=hostile),),
    )
    assert result.bundle is None
    assert result.reason_codes == ("MISSING:ready_identity", "STALE:generation")


def test_task6_h9_missing_locator_is_exact_missing_without_bundle():
    """H9: missing physical source locator never defaults to trusted."""
    api, context, submission, envelope = _fixture()
    hostile = _hostile_envelope(envelope, source_locator="")
    requirement = replace(context.requirements[0], provenance_hash=hostile.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)),
        (replace(submission, provenance=hostile),),
    )
    assert result.bundle is None
    assert result.reason_codes == ("MISSING:source_locator",)


def test_task6_h11_string_producer_role_is_exact_malformed():
    """H11: string/enum confusion is malformed before trust admission."""
    api, context, submission, envelope = _fixture()
    hostile = _hostile_envelope(envelope, producer_role="VERIFIER")
    requirement = replace(context.requirements[0], provenance_hash=hostile.hash)
    result = api.ingest_evidence(
        replace(context, requirements=(requirement,)),
        (replace(submission, provenance=hostile),),
    )
    assert result.bundle is None
    assert result.reason_codes == ("MALFORMED:producer_role",)


def test_task6_h12_duplicate_conflicting_provenance_is_not_a_bundle():
    """Task-6 H12: duplicate evidence with conflicting provenance stays untrusted."""
    api, context, submission, envelope = _fixture()
    conflict = replace(submission, provenance=replace(envelope, execution_id="other-execution"))
    result = api.ingest_evidence(context, (submission, conflict))
    assert result.bundle is None
    assert result.condition is api.IntegrityStatus.TAMPERED
