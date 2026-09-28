import pytest

from product.completion.sufficiency import (
    SUFFICIENCY_CLAIM_CEILING,
    EvidenceSufficiency,
    EvidenceSufficiencyAnalysis,
    SufficiencyRequest,
    analyze_evidence_sufficiency,
    is_evidence_sufficiency_analysis,
    validate_evidence_sufficiency_analysis,
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


def _subjects(required=("unit",)):
    contract = AcceptanceContract(
        contract_id="ac-1",
        requirements_hash=_hash("requirements"),
        required_verifier_ids=tuple(required),
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
        required_verifier_ids=tuple(required),
    )
    return contract, change_set, plan


def _req():
    return SufficiencyRequest(request_id="req-1", subject_scope="semantic-eligibility")


def _bundle(contract, change_set, plan, obs):
    return EvidenceBundle(
        bundle_id="eb-1",
        acceptance_contract_hash=contract.hash,
        change_set_hash=change_set.hash,
        verification_plan_hash=plan.hash,
        observations=tuple(obs),
    )


def _obs(vid="unit", status=ObservationStatus.PASS, h=None):
    return Observation(
        verifier_id=vid, artifact_id="art-1", artifact_hash=h or _hash("final"), status=status
    )


def test_sufficient_when_consistent():
    c, cs, p = _subjects()
    e = _bundle(c, cs, p, [_obs()])
    a = analyze_evidence_sufficiency(_req(), c, cs, p, e)
    assert a.sufficiency is EvidenceSufficiency.SUFFICIENT
    assert a.claim_ceiling == SUFFICIENCY_CLAIM_CEILING
    assert is_evidence_sufficiency_analysis(a)
    assert validate_evidence_sufficiency_analysis(a, _req(), c, cs, p, e)
    assert a.hash == analyze_evidence_sufficiency(_req(), c, cs, p, e).hash


def test_missing_observation_is_missing():
    c, cs, p = _subjects(required=("unit", "lint"))
    e = _bundle(c, cs, p, [_obs("unit")])
    a = analyze_evidence_sufficiency(_req(), c, cs, p, e)
    assert a.sufficiency is EvidenceSufficiency.MISSING
    assert any(r.sufficiency is EvidenceSufficiency.MISSING for r in a.subject_reports)


def test_fail_status_is_contradictory():
    c, cs, p = _subjects()
    e = _bundle(c, cs, p, [_obs(status=ObservationStatus.FAIL)])
    a = analyze_evidence_sufficiency(_req(), c, cs, p, e)
    assert a.sufficiency is EvidenceSufficiency.CONTRADICTORY


def test_expected_config_divergence_is_stale():
    c, cs, p = _subjects()
    e = _bundle(c, cs, p, [_obs(h=_hash("observed"))])
    a = analyze_evidence_sufficiency(
        _req(), c, cs, p, e, expected_by_verifier={"unit": _hash("expected")}
    )
    assert a.sufficiency is EvidenceSufficiency.STALE


def test_expected_config_cannot_fill_missing_gap():
    c, cs, p = _subjects(required=("unit", "lint"))
    e = _bundle(c, cs, p, [_obs("unit")])
    a = analyze_evidence_sufficiency(
        _req(), c, cs, p, e, expected_by_verifier={"unit": _hash("final")}
    )
    assert a.sufficiency is EvidenceSufficiency.MISSING


def test_stale_bundle_identity_is_stale():
    c, cs, p = _subjects()
    e = EvidenceBundle(
        bundle_id="eb-stale",
        acceptance_contract_hash=c.hash,
        change_set_hash=_hash("wrong"),
        verification_plan_hash=p.hash,
        observations=(_obs(),),
    )
    a = analyze_evidence_sufficiency(_req(), c, cs, p, e)
    assert a.sufficiency is EvidenceSufficiency.STALE
    assert a.integrity is IntegrityStatus.STALE


def test_foreign_contract_binding_fails_closed_as_stale():
    c, cs, p = _subjects()
    e = EvidenceBundle(
        bundle_id="eb-x",
        acceptance_contract_hash=_hash("wrong-contract"),
        change_set_hash=cs.hash,
        verification_plan_hash=p.hash,
        observations=(_obs(),),
    )
    a = analyze_evidence_sufficiency(_req(), c, cs, p, e)
    # Foreign contract binding can never satisfy sufficiency.
    assert a.sufficiency in (EvidenceSufficiency.STALE, EvidenceSufficiency.FAILED)
    assert a.sufficiency is not EvidenceSufficiency.SUFFICIENT


def test_duplicate_observations_fail_closed():
    c, cs, p = _subjects()
    e = _bundle(c, cs, p, [_obs(), _obs()])
    a = analyze_evidence_sufficiency(_req(), c, cs, p, e)
    assert a.sufficiency is EvidenceSufficiency.FAILED


def test_inapplicable_scope():
    c, cs, p = _subjects()
    e = _bundle(c, cs, p, [_obs()])
    req = SufficiencyRequest(request_id="r", subject_scope="s", applicable=False)
    a = analyze_evidence_sufficiency(req, c, cs, p, e)
    assert a.sufficiency is EvidenceSufficiency.INAPPLICABLE


def test_no_model_call_and_sealed():
    import inspect

    import product.completion.sufficiency as s

    src = inspect.getsource(s)
    assert "llm" not in src.lower() and "model" not in src.lower().replace("model_", "")
    with pytest.raises(TypeError):
        EvidenceSufficiencyAnalysis("x", (), (), IntegrityStatus.VALID, "s", "c")


def test_to_dict_round_trip():
    c, cs, p = _subjects()
    e = _bundle(c, cs, p, [_obs()])
    a = analyze_evidence_sufficiency(_req(), c, cs, p, e)
    body = a.to_dict()
    assert body["sufficiency"] == "SUFFICIENT"
    assert body["claim_ceiling"] == SUFFICIENCY_CLAIM_CEILING
