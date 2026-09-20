import hashlib
from dataclasses import replace

from product.evidence import (
    AcceptanceContract,
    ChangeSet,
    EvidenceBundle,
    Observation,
    ObservationStatus,
    VerificationPlan,
    _hash,
)
from product.evidence.code_integrity import (
    PROFILE_HASH,
    VERIFIER_ID,
    CodeIntegrityRequirementV1,
    CodeIntegrityStatus,
    ImplementationTargetV1,
    ProducerExecutionState,
    analyze_code_integrity,
    observation_from_code_integrity,
)
from product.evidence.ingestion import (
    EvidenceGeneration,
    EvidenceRequirement,
    EvidenceSubmission,
    EvidenceType,
    IngestionProfile,
    ProducerGrant,
    ProducerRole,
    ProvenanceEnvelope,
    TrustedIngestionContext,
    ingest_evidence,
    is_trusted_ingestion_result,
)
from product.verification import VerificationStatus, verify

SOURCE_TREE = "1" * 40
TARGET_TREE = "2" * 40
OBSERVED_AT = "2026-09-20T12:00:00+00:00"
GENERATED_AT = "2026-09-20T11:59:00+00:00"


def _raw_hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _requirement() -> CodeIntegrityRequirementV1:
    return CodeIntegrityRequirementV1(
        implementation_targets=(ImplementationTargetV1("src/example.py", "work"),)
    )


def _change() -> ChangeSet:
    return ChangeSet(
        "ci-cs",
        "source-r1",
        "target-r2",
        _hash("ci-diff"),
        ("src/example.py",),
    )


def _analysis(source: bytes):
    requirement = _requirement()
    change = _change()
    return analyze_code_integrity(
        requirement,
        repository_id="James3014/nexus-core",
        change_set=change,
        source_tree=SOURCE_TREE,
        target_tree=TARGET_TREE,
        source_files={"src/example.py": source},
    )


def _core_subjects(required_ids=(VERIFIER_ID,)):
    change = _change()
    contract = AcceptanceContract(
        "ci-contract",
        _requirement().hash,
        required_ids,
        ("src/example.py",),
        "FORBID",
    )
    plan = VerificationPlan(
        "ci-plan",
        contract.hash,
        change.hash,
        required_ids,
    )
    return contract, change, plan


def _bundle(contract, change, plan, observations):
    return EvidenceBundle(
        "ci-bundle",
        contract.hash,
        change.hash,
        plan.hash,
        tuple(observations),
    )


def test_pass_report_projects_through_existing_core_reducer_to_verified():
    result = _analysis(b"def work():\n    return 1\n")
    assert result.execution_state is ProducerExecutionState.COMPLETED
    assert result.integrity_status is CodeIntegrityStatus.PASS
    observation = observation_from_code_integrity(result)
    assert observation is not None
    assert observation.status is ObservationStatus.PASS
    assert result.report is not None
    assert observation.artifact_hash == result.report.artifact_hash

    contract, change, plan = _core_subjects()
    evidence = _bundle(contract, change, plan, (observation,))
    reduced = verify(contract, change, plan, evidence)
    assert reduced.status is VerificationStatus.VERIFIED
    assert reduced.reason_codes == ()


def test_fail_report_projects_through_existing_core_reducer_to_failed_verification():
    result = _analysis(b"def work():\n    pass\n")
    assert result.integrity_status is CodeIntegrityStatus.FAIL
    observation = observation_from_code_integrity(result)
    assert observation is not None
    assert observation.status is ObservationStatus.FAIL

    contract, change, plan = _core_subjects()
    evidence = _bundle(contract, change, plan, (observation,))
    reduced = verify(contract, change, plan, evidence)
    assert reduced.status is VerificationStatus.FAILED_VERIFICATION
    assert reduced.reason_codes == ("VERIFIER_FAILED", VERIFIER_ID)


def test_unverifiable_report_mints_no_observation_and_required_evidence_fails_closed():
    requirement = _requirement()
    change = _change()
    result = analyze_code_integrity(
        requirement,
        repository_id="James3014/nexus-core",
        change_set=change,
        source_tree=SOURCE_TREE,
        target_tree=TARGET_TREE,
        source_files={},
    )
    assert result.integrity_status is CodeIntegrityStatus.UNVERIFIABLE
    assert observation_from_code_integrity(result) is None

    contract, change, plan = _core_subjects(("unit", VERIFIER_ID))
    unit = Observation("unit", "unit-artifact", _hash("unit"), ObservationStatus.PASS)
    evidence = _bundle(contract, change, plan, (unit,))
    reduced = verify(contract, change, plan, evidence)
    assert reduced.status is VerificationStatus.UNVERIFIABLE
    assert reduced.integrity.value == "MISSING"


def test_non_required_code_integrity_report_does_not_change_unrelated_verification():
    result = _analysis(b"def work():\n    pass\n")
    assert result.integrity_status is CodeIntegrityStatus.FAIL
    assert observation_from_code_integrity(result) is not None

    change = _change()
    contract = AcceptanceContract(
        "unit-only",
        _hash("unit-requirements"),
        ("unit",),
        ("src/example.py",),
        "FORBID",
    )
    plan = VerificationPlan("unit-plan", contract.hash, change.hash, ("unit",))
    unit = Observation("unit", "unit-artifact", _hash("unit"), ObservationStatus.PASS)
    evidence = _bundle(contract, change, plan, (unit,))
    reduced = verify(contract, change, plan, evidence)
    assert reduced.status is VerificationStatus.VERIFIED


def _trusted_ingestion_fixture(source: bytes):
    result = _analysis(source)
    assert result.report is not None
    observation = observation_from_code_integrity(result)
    assert observation is not None

    contract, change, plan = _core_subjects()
    producer = ProducerGrant(
        "code-integrity-producer",
        ProducerRole.VERIFIER,
        PROFILE_HASH,
        ("python-code-integrity-v1",),
    )
    profile = IngestionProfile("code-integrity-profile", (producer,), (), 3600)
    report = result.report
    envelope = ProvenanceEnvelope(
        "product.evidence.provenance.v1",
        "code-integrity-evidence",
        EvidenceType.VERIFIER_RESULT,
        VERIFIER_ID,
        report.artifact_id,
        producer.producer_id,
        ProducerRole.VERIFIER,
        producer.software_hash,
        "James3014/nexus-core",
        change.source_revision,
        SOURCE_TREE,
        change.target_revision,
        TARGET_TREE,
        change.hash,
        change.diff_hash,
        GENERATED_AT,
        "product/evidence/code_integrity.py",
        report.artifact_hash,
        "python-code-integrity-v1",
        "execution-code-integrity",
        "attempt-code-integrity",
        _hash("code-integrity-environment"),
        EvidenceGeneration.SOURCE,
        None,
    )
    requirement = EvidenceRequirement(
        VERIFIER_ID,
        report.artifact_id,
        EvidenceType.VERIFIER_RESULT,
        EvidenceGeneration.SOURCE,
        producer.producer_id,
        "execution-code-integrity",
        "attempt-code-integrity",
        _hash("code-integrity-environment"),
        report.artifact_hash,
        envelope.hash,
        False,
        False,
        observation.status,
    )
    context = TrustedIngestionContext(
        contract,
        change,
        plan,
        "James3014/nexus-core",
        SOURCE_TREE,
        TARGET_TREE,
        OBSERVED_AT,
        profile,
        profile.hash,
        (requirement,),
        "verify",
        (),
    )
    submission = EvidenceSubmission(
        report.canonical_bytes,
        observation.status,
        envelope,
    )
    return result, context, submission


def test_trusted_ingestion_binds_pass_report_then_existing_reducer_verifies():
    result, context, submission = _trusted_ingestion_fixture(b"def work():\n    return 1\n")
    ingested = ingest_evidence(context, (submission,))
    assert is_trusted_ingestion_result(context, ingested) is True
    assert ingested.bundle is not None
    assert result.report is not None
    assert ingested.receipt.raw_content_hashes == (result.report.artifact_hash,)
    assert ingested.bundle.observations[0].status is ObservationStatus.PASS
    assert ingested.bundle.observations[0].artifact_hash == submission.provenance.hash

    reduced = verify(
        context.contract,
        context.change_set,
        context.plan,
        ingested.bundle,
    )
    assert reduced.status is VerificationStatus.VERIFIED


def test_trusted_ingestion_binds_fail_report_then_existing_reducer_fails():
    result, context, submission = _trusted_ingestion_fixture(b"def work():\n    pass\n")
    assert result.integrity_status is CodeIntegrityStatus.FAIL
    ingested = ingest_evidence(context, (submission,))
    assert is_trusted_ingestion_result(context, ingested) is True
    assert ingested.bundle is not None
    assert ingested.bundle.observations[0].status is ObservationStatus.FAIL

    reduced = verify(
        context.contract,
        context.change_set,
        context.plan,
        ingested.bundle,
    )
    assert reduced.status is VerificationStatus.FAILED_VERIFICATION
    assert reduced.reason_codes == ("VERIFIER_FAILED", VERIFIER_ID)


def test_trusted_ingestion_rejects_report_content_tamper_before_reduction():
    _, context, submission = _trusted_ingestion_fixture(b"def work():\n    return 1\n")
    tampered = replace(submission, content=submission.content + b"\n")
    ingested = ingest_evidence(context, (tampered,))
    assert ingested.bundle is None
    assert ingested.condition.value == "TAMPERED"
    assert "TAMPERED:content_hash" in ingested.reason_codes


def test_trusted_ingestion_rejects_changeset_cross_binding():
    _, context, submission = _trusted_ingestion_fixture(b"def work():\n    return 1\n")
    wrong_envelope = replace(
        submission.provenance,
        change_set_hash=_hash("wrong-change-set"),
    )
    wrong_requirement = replace(
        context.requirements[0],
        provenance_hash=wrong_envelope.hash,
    )
    wrong_context = replace(context, requirements=(wrong_requirement,))
    wrong_submission = replace(submission, provenance=wrong_envelope)
    ingested = ingest_evidence(wrong_context, (wrong_submission,))
    assert ingested.bundle is None
    assert "CROSS_BOUND:changeset" in ingested.reason_codes
