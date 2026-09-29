"""Independent regression witnesses for the #58 acceptance findings."""
from dataclasses import replace

from product.completion.sufficiency import (
    EvidenceSufficiency,
    SufficiencyRequest,
    analyze_evidence_sufficiency,
    validate_evidence_sufficiency_analysis,
)
from product.evidence import (
    AcceptanceContract,
    ChangeSet,
    EvidenceBundle,
    Observation,
    ObservationStatus,
    VerificationPlan,
    _hash,
)


def _inputs():
    request = SufficiencyRequest("r", "scope")
    contract = AcceptanceContract("c", _hash("requirements"), ("unit",), ("a.py",), "FORBID")
    change = ChangeSet("cs", "git-commit:" + "a" * 40, "git-commit:" + "b" * 40, _hash("diff"), ("a.py",))
    plan = VerificationPlan("p", contract.hash, change.hash, ("unit",))
    observation = Observation("unit", "artifact", _hash("bytes"), ObservationStatus.PASS)
    bundle = EvidenceBundle("e", contract.hash, change.hash, plan.hash, (observation,))
    return request, contract, change, plan, bundle


def test_request_scope_substitution_rejected():
    request, contract, change, plan, bundle = _inputs()
    analysis = analyze_evidence_sufficiency(request, contract, change, plan, bundle)
    for substituted in (replace(request, request_id="other"), replace(request, subject_scope="other")):
        assert not validate_evidence_sufficiency_analysis(analysis, substituted, contract, change, plan, bundle)


def test_different_valid_evidence_identity_not_interchangeable():
    request, contract, change, plan, bundle = _inputs()
    analysis = analyze_evidence_sufficiency(request, contract, change, plan, bundle)
    assert not validate_evidence_sufficiency_analysis(analysis, request, contract, change, plan, replace(bundle, bundle_id="other"))


def test_conflicting_observations_distinct_from_single_failure():
    request, contract, change, plan, bundle = _inputs()
    failed = replace(bundle.observations[0], status=ObservationStatus.FAIL)
    assert analyze_evidence_sufficiency(request, contract, change, plan, replace(bundle, observations=(failed,))).sufficiency is EvidenceSufficiency.FAILED
    conflict = replace(bundle, observations=(bundle.observations[0], failed))
    assert analyze_evidence_sufficiency(request, contract, change, plan, conflict).sufficiency is EvidenceSufficiency.CONTRADICTORY
