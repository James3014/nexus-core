import pytest

from product.completion import (
    CompletionClaim,
    CompletionEvidenceAnalysis,
    EvidenceDisposition,
    analyze_completion_evidence,
    is_completion_evidence_analysis,
    validate_completion_evidence_analysis,
)
from product.evidence import (
    AcceptanceContract,
    ChangeSet,
    EvidenceBundle,
    IntegrityStatus,
    Observation,
    ObservationStatus,
    VerificationPlan,
    _hash,
)

_DIRTY = None


def _subjects():
    contract = AcceptanceContract(
        contract_id="ac-1",
        requirements_hash=_hash("requirements"),
        required_verifier_ids=("unit",),
        allowed_paths=("src/a.py",),
        deletion_policy="FORBID",
    )
    change_set = ChangeSet(
        change_set_id="cs-1",
        source_revision="git-commit:" + "a" * 40,
        target_revision="git-commit:" + "b" * 40,
        diff_hash=_hash("diff"),
        paths=("src/a.py",),
    )
    plan = VerificationPlan(
        plan_id="vp-1",
        acceptance_contract_hash=contract.hash,
        change_set_hash=change_set.hash,
        required_verifier_ids=("unit",),
    )
    return contract, change_set, plan


def _pass_evidence(change_set, plan, contract, artifact_id="artifact-1", artifact_hash=None):
    return EvidenceBundle(
        bundle_id="eb-1",
        acceptance_contract_hash=contract.hash,
        change_set_hash=change_set.hash,
        verification_plan_hash=plan.hash,
        observations=(
            Observation(
                verifier_id="unit",
                artifact_id=artifact_id,
                artifact_hash=artifact_hash or _hash("final-content"),
                status=ObservationStatus.PASS,
            ),
        ),
    )


def _claim(target_revision, *, claimed_complete=True, artifact_hash=None, artifact_id="artifact-1"):
    return CompletionClaim(
        claim_id="cl-1",
        target_revision=target_revision,
        content_hashes=(("src/a.py", artifact_hash or _hash("final-content")),),
        verified_artifacts=(("unit", artifact_id, "src/a.py"),),
        asserted_by="model:unit-test",
        claimed_complete=claimed_complete,
    )


def test_all_three_states_when_claim_bound_and_fresh():
    contract, change_set, plan = _subjects()
    evidence = _pass_evidence(change_set, plan, contract)
    claim = _claim(change_set.target_revision)
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert is_completion_evidence_analysis(analysis)
    assert analysis.claims_complete is True
    assert analysis.claims_verified is True
    assert analysis.verification_applies is True
    assert analysis.semantic_states == (
        "CLAIMS_COMPLETE",
        "CLAIMS_VERIFIED",
        "VERIFICATION_APPLIES",
    )
    assert analysis.integrity is IntegrityStatus.VALID
    assert validate_completion_evidence_analysis(
        analysis, claim, contract, change_set, plan, evidence
    )


def test_modify_pass_modify_again_marks_prior_verification_stale():
    contract, change_set, plan = _subjects()
    evidence = _pass_evidence(change_set, plan, contract, artifact_hash=_hash("content-v1"))
    claim = _claim(change_set.target_revision, artifact_hash=_hash("content-v2"))
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert analysis.verification_applies is False
    assert analysis.claims_verified is False
    assert analysis.dispositions[0].disposition is EvidenceDisposition.REJECTED_STALE
    assert analysis.dispositions[0].path == "src/a.py"
    assert analysis.dispositions[0].observed_artifact_hash == _hash("content-v1")
    assert analysis.dispositions[0].expected_content_hash == _hash("content-v2")


def test_equivalent_content_still_fresh_after_modify():
    contract, change_set, plan = _subjects()
    evidence = _pass_evidence(change_set, plan, contract, artifact_hash=_hash("content-v1"))
    claim = _claim(change_set.target_revision, artifact_hash=_hash("content-v1"))
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert analysis.verification_applies is True
    assert analysis.claims_verified is True
    assert analysis.dispositions[0].disposition is EvidenceDisposition.ACCEPTED


def test_irrelevant_verification_does_not_apply():
    contract, change_set, plan = _subjects()
    evidence = _pass_evidence(
        change_set, plan, contract, artifact_id="artifact-unrelated", artifact_hash=_hash("other")
    )
    claim = CompletionClaim(
        claim_id="cl-1",
        target_revision=change_set.target_revision,
        content_hashes=(("src/untouched.py", _hash("other")),),
        verified_artifacts=(("unit", "artifact-unrelated", "src/untouched.py"),),
        asserted_by="model:unit-test",
    )
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert analysis.verification_applies is False
    assert analysis.claims_verified is False
    assert analysis.dispositions[0].disposition is EvidenceDisposition.REJECTED_IRRELEVANT


def test_irrelevant_verification_bounds_unbound_artifact():
    contract, change_set, plan = _subjects()
    evidence = _pass_evidence(
        change_set,
        plan,
        contract,
        artifact_id="artifact-unbound",
        artifact_hash=_hash("final-content"),
    )
    claim = _claim(change_set.target_revision, artifact_id="artifact-1")
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert analysis.verification_applies is False
    assert analysis.dispositions[0].disposition is EvidenceDisposition.REJECTED_IRRELEVANT
    assert "IRRELEVANT" in analysis.dispositions[0].reason_codes[0]


def test_missing_applicable_verification_cannot_become_verified_from_assertion():
    contract, change_set, plan = _subjects()
    claim = CompletionClaim(
        claim_id="cl-asserted",
        target_revision=change_set.target_revision,
        content_hashes=(("src/a.py", _hash("final-content")),),
        verified_artifacts=(("unit", "artifact-1", "src/a.py"),),
        asserted_by="model:claims-passed",
        claimed_complete=True,
    )
    missing = EvidenceBundle(
        bundle_id="eb-no-observation",
        acceptance_contract_hash=contract.hash,
        change_set_hash=change_set.hash,
        verification_plan_hash=plan.hash,
        observations=(
            Observation(
                verifier_id="unit",
                artifact_id="artifact-other",
                artifact_hash=_hash("final-content"),
                status=ObservationStatus.PASS,
            ),
        ),
    )
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, missing)
    assert analysis.claims_verified is False
    assert analysis.dispositions[0].disposition is EvidenceDisposition.REJECTED_IRRELEVANT


def test_contradictory_evidence_visible_and_blocks_verified():
    contract, change_set, plan = _subjects()
    evidence = EvidenceBundle(
        bundle_id="eb-fail",
        acceptance_contract_hash=contract.hash,
        change_set_hash=change_set.hash,
        verification_plan_hash=plan.hash,
        observations=(
            Observation(
                verifier_id="unit",
                artifact_id="artifact-1",
                artifact_hash=_hash("final-content"),
                status=ObservationStatus.FAIL,
            ),
        ),
    )
    claim = _claim(change_set.target_revision)
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert analysis.claims_verified is False
    assert analysis.verification_applies is False
    assert analysis.dispositions[0].disposition is EvidenceDisposition.REJECTED_CONTRADICTORY
    assert "CONTRADICTORY" in analysis.dispositions[0].reason_codes[0]
    assert "CLAIMS_VERIFIED" not in analysis.semantic_states


def test_claim_revision_mismatch_blocks_complete():
    contract, change_set, plan = _subjects()
    evidence = _pass_evidence(change_set, plan, contract)
    claim = _claim("git-commit:" + "c" * 40)
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert analysis.claims_complete is False
    assert analysis.claims_verified is False
    assert "CLAIMS_COMPLETE" not in analysis.semantic_states
    assert "CLAIM:revision-mismatch" in analysis.reason_codes


def test_missing_claim_coverage_blocks_complete():
    contract = AcceptanceContract(
        contract_id="ac-1",
        requirements_hash=_hash("requirements"),
        required_verifier_ids=("unit",),
        allowed_paths=("src/a.py", "src/b.py"),
        deletion_policy="FORBID",
    )
    change_set = ChangeSet(
        change_set_id="cs-1",
        source_revision="git-commit:" + "a" * 40,
        target_revision="git-commit:" + "b" * 40,
        diff_hash=_hash("diff"),
        paths=("src/a.py", "src/b.py"),
    )
    plan = VerificationPlan(
        plan_id="vp-1",
        acceptance_contract_hash=contract.hash,
        change_set_hash=change_set.hash,
        required_verifier_ids=("unit",),
    )
    evidence = EvidenceBundle(
        bundle_id="eb-1",
        acceptance_contract_hash=contract.hash,
        change_set_hash=change_set.hash,
        verification_plan_hash=plan.hash,
        observations=(
            Observation(
                verifier_id="unit",
                artifact_id="artifact-1",
                artifact_hash=_hash("final-content"),
                status=ObservationStatus.PASS,
            ),
        ),
    )
    claim = CompletionClaim(
        claim_id="cl-partial",
        target_revision=change_set.target_revision,
        content_hashes=(("src/a.py", _hash("final-content")),),
        verified_artifacts=(("unit", "artifact-1", "src/a.py"),),
        asserted_by="model:unit-test",
    )
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert analysis.claims_complete is False
    assert "CLAIM:content-coverage-missing:path:src/b.py" in analysis.reason_codes


def test_claim_missing_is_not_complete():
    contract, change_set, plan = _subjects()
    evidence = _pass_evidence(change_set, plan, contract)
    analysis = analyze_completion_evidence(None, contract, change_set, plan, evidence)
    assert analysis.claims_complete is False
    assert analysis.claims_verified is False
    assert "CLAIM:missing" in analysis.reason_codes


def test_stale_evidence_binding_blocks_analysis_from_verify():
    contract, change_set, plan = _subjects()
    stale = EvidenceBundle(
        bundle_id="eb-stale",
        acceptance_contract_hash=contract.hash,
        change_set_hash=_hash("wrong-change-set"),
        verification_plan_hash=plan.hash,
        observations=(
            Observation(
                verifier_id="unit",
                artifact_id="artifact-1",
                artifact_hash=_hash("final-content"),
                status=ObservationStatus.PASS,
            ),
        ),
    )
    claim = _claim(change_set.target_revision)
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, stale)
    assert analysis.verification_applies is False
    assert analysis.claims_verified is False
    assert analysis.integrity is IntegrityStatus.STALE


def test_analysis_is_sealed():
    with pytest.raises(TypeError):
        CompletionEvidenceAnalysis(True, True, True, (), (), (), IntegrityStatus.VALID)


def test_validation_fails_on_tampered_reason_codes():
    contract, change_set, plan = _subjects()
    evidence = _pass_evidence(change_set, plan, contract)
    claim = _claim(change_set.target_revision)
    analysis = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert validate_completion_evidence_analysis(
        analysis, claim, contract, change_set, plan, evidence
    )
    forged = object.__new__(CompletionEvidenceAnalysis)
    object.__setattr__(forged, "claims_complete", analysis.claims_complete)
    object.__setattr__(forged, "claims_verified", analysis.claims_verified)
    object.__setattr__(forged, "verification_applies", analysis.verification_applies)
    object.__setattr__(forged, "semantic_states", analysis.semantic_states)
    object.__setattr__(forged, "dispositions", analysis.dispositions)
    object.__setattr__(forged, "reason_codes", ("TAMPERED",))
    object.__setattr__(forged, "integrity", analysis.integrity)
    assert not validate_completion_evidence_analysis(
        forged, claim, contract, change_set, plan, evidence
    )
    assert not is_completion_evidence_analysis(forged)


def test_to_dict_round_trips_and_hash_deterministic():
    contract, change_set, plan = _subjects()
    evidence = _pass_evidence(change_set, plan, contract)
    claim = _claim(change_set.target_revision)
    first = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    second = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
    assert first.hash == second.hash
    body = first.to_dict()
    assert body["claims_verified"] is True
    assert body["semantic_states"] == [
        "CLAIMS_COMPLETE",
        "CLAIMS_VERIFIED",
        "VERIFICATION_APPLIES",
    ]
    assert body["dispositions"][0]["disposition"] == "ACCEPTED"
    assert set({"verifier_id", "path", "status", "reason_codes"}) <= body["dispositions"][0].keys()