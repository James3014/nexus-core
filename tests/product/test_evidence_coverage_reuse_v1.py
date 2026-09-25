"""Evidence-coverage reuse (v1): universe observation binding repair."""
import pytest
from product.evidence import (AcceptanceContract, Applicability, ChangeSet, EvidenceBundle, ExpectedEvidenceSubject, IntegrityStatus, Observation, ObservationStatus, RequirementMode, canonical_json, derive_evidence_integrity)
from product.verification import (CoverageCategory, VerificationStatus, derive_coverage as verify_derive_coverage, derive_coverage, verify)
REQ_HASH = "sha256:" + "c" * 64
DIFF_HASH = "sha256:" + "d" * 64
ART_HASH = "sha256:" + "e" * 64
SRC = "git-commit:" + "a" * 40
TGT = "git-commit:" + "b" * 40
def _subject(sid, kind="unit-kind", mode=RequirementMode.REQUIRED, applicability=Applicability.APPLICABLE):
    return ExpectedEvidenceSubject(sid, kind, mode, applicability)
def _contract(subjects=(), required=("v1",), generation=1):
    subjects = tuple(subjects)
    return AcceptanceContract("ac-1", REQ_HASH, tuple(required), ("src/a.py",), "FORBID", subjects, generation if subjects else 0)
def _change_set():
    return ChangeSet("cs-1", SRC, TGT, DIFF_HASH, ("src/a.py",))
def _plan(contract, change_set, required=("v1",)):
    from product.evidence import VerificationPlan
    return VerificationPlan("vp-1", contract.hash, change_set.hash, tuple(required))
def _obs(verifier_id, sid=None, status=ObservationStatus.PASS, kind="unit-kind"):
    return Observation(verifier_id, "art-" + verifier_id + "-" + (sid or "unlabeled"), ART_HASH, status, sid, kind if sid is not None else None)
def _bundle(contract, change_set, plan, observations):
    return EvidenceBundle("eb-1", contract.hash, change_set.hash, plan.hash, tuple(observations))
def _verify(contract, observations, required=("v1",)):
    change_set = _change_set()
    plan = _plan(contract, change_set, required)
    bundle = _bundle(contract, change_set, plan, observations)
    return verify(contract, change_set, plan, bundle)
def test_legacy_parse_verify_unchanged():
    contract = _contract()
    result = _verify(contract, [_obs("v1")])
    assert result.status is VerificationStatus.VERIFIED
    assert result.integrity is IntegrityStatus.VALID
    assert result.reason_codes == ()
    assert result.coverage is None
    missing = _verify(contract, [_obs("other")])
    assert missing.status is VerificationStatus.UNVERIFIABLE
    assert missing.integrity is IntegrityStatus.MISSING
    assert missing.coverage is None
    failed = _verify(contract, [_obs("v1", status=ObservationStatus.FAIL)])
    assert failed.status is VerificationStatus.FAILED_VERIFICATION
    assert "VERIFIER_FAILED" in failed.reason_codes
    assert failed.coverage is None
def test_new_schema_parse_universe_subjects():
    subjects = [_subject("S1"), _subject("S2", mode=RequirementMode.CONDITIONALLY_REQUIRED)]
    contract = _contract(subjects, required=("v1", "v2"))
    assert contract.expected_subjects == tuple(subjects)
    assert contract.universe_generation == 1
    assert contract.universe_identity is not None
def test_malformed_declaration_rejected():
    with pytest.raises(ValueError):
        ExpectedEvidenceSubject("", "k", RequirementMode.REQUIRED)
    with pytest.raises(TypeError):
        ExpectedEvidenceSubject("S1", "k", "REQUIRED")
    with pytest.raises(ValueError):
        _contract([_subject("S1"), _subject("S1", kind="other-kind")])
    with pytest.raises(ValueError):
        AcceptanceContract("ac-1", REQ_HASH, ("v1",), ("src/a.py",), "FORBID", (), 3)
def test_canonical_hash_universe_mutation_changes_hash_key_order_does_not():
    left = _contract([_subject("S1"), _subject("S2")])
    right = _contract([_subject("S2"), _subject("S1")])
    assert left.hash == right.hash
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    mutated = _contract([_subject("S1"), _subject("S2-modified")])
    assert mutated.hash != left.hash
    assert left.universe_identity != mutated.universe_identity
def test_logical_identity_kind_mismatch_not_covered():
    subjects = [_subject("S1", kind="unit-kind")]
    matched = derive_coverage(tuple(subjects), [_obs("v1", "S1", kind="unit-kind")], universe_generation=1, universe_identity="id-1")
    assert matched.entries[0].category is CoverageCategory.COVERED
    mismatched = derive_coverage(tuple(subjects), [_obs("v1", "S1", kind="other-kind")], universe_generation=1, universe_identity="id-1")
    assert mismatched.entries[0].category is CoverageCategory.NOT_COVERED
    assert mismatched.entries[0].anomaly == "EVIDENCE_KIND_MISMATCH"
def test_w1_missing_subject_unverifiable_with_missing():
    subjects = [_subject("S1"), _subject("S2")]
    contract = _contract(subjects, required=("v1", "v2"))
    result = _verify(contract, [_obs("v1", "S1")], required=("v1", "v2"))
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.integrity is IntegrityStatus.MISSING
    assert "MISSING" in result.reason_codes
    assert result.coverage is not None
    by_sid = {e.logical_subject_id: e for e in result.coverage.entries}
    assert by_sid["S1"].category is CoverageCategory.COVERED
    assert by_sid["S2"].category is CoverageCategory.NOT_COVERED
def test_w2_contradictory_fail_status_failed_verification():
    subjects = [_subject("S1"), _subject("S2")]
    contract = _contract(subjects, required=("v1", "v2"))
    result = _verify(contract, [_obs("v1", "S1"), _obs("v2", "S2", status=ObservationStatus.FAIL)], required=("v1", "v2"))
    assert result.status is VerificationStatus.FAILED_VERIFICATION
    assert result.integrity is IntegrityStatus.VALID
    assert "MISSING" not in result.reason_codes
def test_w3_conditional_false_not_applicable_no_block():
    subjects = [_subject("S1"), _subject("S2", mode=RequirementMode.NOT_APPLICABLE, applicability=Applicability.NOT_APPLICABLE)]
    contract = _contract(subjects, required=("v1",))
    result = _verify(contract, [_obs("v1", "S1")])
    assert result.status is VerificationStatus.VERIFIED
    by_sid = {e.logical_subject_id: e for e in result.coverage.entries}
    assert by_sid["S2"].category is CoverageCategory.CONDITIONALLY_NOT_APPLICABLE
def test_w4_conditional_true_missing_non_pass():
    subjects = [_subject("S1"), _subject("S2", mode=RequirementMode.CONDITIONALLY_REQUIRED, applicability=Applicability.APPLICABLE)]
    contract = _contract(subjects, required=("v1",))
    result = _verify(contract, [_obs("v1", "S1")])
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.integrity is IntegrityStatus.MISSING
    assert "MISSING" in result.reason_codes
    assert result.status is not VerificationStatus.VERIFIED
    assert result.status is not VerificationStatus.FAILED_VERIFICATION
def test_w4b_coverage_unresolved_blocks():
    subjects = [_subject("S1", mode=RequirementMode.CONDITIONALLY_REQUIRED, applicability=Applicability.UNRESOLVED)]
    contract = _contract(subjects, required=("v1",))
    result = _verify(contract, [_obs("v1", "S1")])
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert "COVERAGE_UNRESOLVED" in result.reason_codes
def test_w5_duplicate_logical_subject_no_inflation_and_integrity_fails_closed():
    subjects = [_subject("S1")]
    projection = derive_coverage(tuple(subjects), [_obs("v1", "S1"), _obs("v2", "S1")], universe_generation=1, universe_identity="id-1")
    assert len(projection.entries) == 1
    assert projection.entries[0].category is CoverageCategory.COVERED
    contract = _contract(subjects, required=("v1", "v2"))
    change_set = _change_set()
    plan = _plan(contract, change_set, ("v1", "v2"))
    bundle = _bundle(contract, change_set, plan, [_obs("v1", "S1"), _obs("v2", "S1")])
    assert derive_evidence_integrity(contract, change_set, plan, bundle) is IntegrityStatus.DUPLICATE
    result = verify(contract, change_set, plan, bundle)
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.integrity is IntegrityStatus.DUPLICATE
def test_w6_byte_identical_payloads_different_sid_count_as_two():
    subjects = [_subject("S1"), _subject("S2")]
    contract = _contract(subjects, required=("v1", "v2"))
    first = _obs("v1", "S1")
    second = Observation("v2", "art-v2-S2", first.artifact_hash, ObservationStatus.PASS, "S2", "unit-kind")  # same payload bytes, distinct logical identity
    result = _verify(contract, [first, second], required=("v1", "v2"))
    assert result.status is VerificationStatus.VERIFIED
    assert result.coverage is not None
    assert len(result.coverage.entries) == 2
    assert all(e.category is CoverageCategory.COVERED for e in result.coverage.entries)
def test_w7_cross_generation_replay_detected():
    g1 = _contract([_subject("S1")], required=("v1",), generation=1)
    g2 = _contract([_subject("S1"), _subject("S2")], required=("v1", "v2"), generation=2)
    assert g1.universe_identity != g2.universe_identity
    assert g1.hash != g2.hash
    result = _verify(g2, [_obs("v1", "S1")], required=("v1", "v2"))
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.integrity is IntegrityStatus.MISSING
    assert result.coverage is not None
    assert result.coverage.universe_generation == 2
    assert result.coverage.universe_identity == g2.universe_identity
def test_w8_universe_mutation_replay_never_verified():
    old_contract = _contract([_subject("S1")], required=("v1",), generation=1)
    new_contract = _contract([_subject("S1"), _subject("S2")], required=("v1", "v2"), generation=2)
    old_change = _change_set()
    old_plan = _plan(old_contract, old_change)
    old_bundle = _bundle(old_contract, old_change, old_plan, [_obs("v1", "S1")])
    assert old_bundle.hash != new_contract.hash
    new_plan = _plan(new_contract, old_change, ("v1", "v2"))
    integrity = derive_evidence_integrity(new_contract, old_change, new_plan, old_bundle)
    assert integrity in (IntegrityStatus.CROSS_BOUND, IntegrityStatus.MISSING)
    result = verify(new_contract, old_change, new_plan, old_bundle)
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.status is not VerificationStatus.VERIFIED
def test_w10_legacy_coverage_none():
    contract = _contract()
    assert contract.expected_subjects == ()
    assert contract.universe_identity is None
    result = _verify(contract, [_obs("v1")])
    assert result.coverage is None
    assert result.status is VerificationStatus.VERIFIED
def test_w11_complete_labeled_universe_verified_with_coverage():
    subjects = [_subject("S1"), _subject("S2")]
    contract = _contract(subjects, required=("v1", "v2"))
    result = _verify(contract, [_obs("v1", "S1"), _obs("v2", "S2")], required=("v1", "v2"))
    assert result.status is VerificationStatus.VERIFIED
    assert result.integrity is IntegrityStatus.VALID
    assert result.coverage is not None
    assert [e.category for e in result.coverage.entries] == [CoverageCategory.COVERED, CoverageCategory.COVERED]
    assert result.coverage.universe_identity == contract.universe_identity
def test_w11_missing_required_verifier_is_not_rescued_by_coverage():
    subjects = [_subject("S1"), _subject("S2")]
    contract = _contract(subjects, required=("v1", "v2", "audit"))
    result = _verify(contract, [_obs("v1", "S1"), _obs("v2", "S2")], required=("v1", "v2", "audit"))
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.integrity is IntegrityStatus.MISSING
    assert "audit" in result.reason_codes
def test_w11_same_namespace_mismatch_fails_closed():
    subjects = [_subject("v1"), _subject("S2")]
    contract = _contract(subjects, required=("v1", "v2"))
    result = _verify(contract, [_obs("other", "v1"), _obs("v2", "S2")], required=("v1", "v2"))
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.integrity is IntegrityStatus.MALFORMED
def test_w11_namespaced_subject_ids_impose_no_coupling():
    subjects = [_subject("verifier/unit-tests")]
    contract = _contract(subjects, required=("v1",))
    result = _verify(contract, [_obs("v1", "verifier/unit-tests")])
    assert result.status is VerificationStatus.VERIFIED
def test_a1_extra_observed_subject_does_not_expand_universe():
    subjects = [_subject("S1")]
    contract = _contract(subjects, required=("v1",))
    result = _verify(contract, [_obs("v1", "S1"), _obs("extra", "S2")])
    assert result.status is VerificationStatus.VERIFIED
    assert result.coverage is not None
    assert [e.logical_subject_id for e in result.coverage.entries] == ["S1"]
    assert result.coverage.unexpected_subjects == (("S2", "unit-kind"),)
def test_a2_no_universe_observations_coverage_none():
    contract = _contract()
    result = _verify(contract, [_obs("v1"), _obs("extra")])
    assert result.status is VerificationStatus.UNVERIFIABLE
    assert result.coverage is None
def test_claim_ceiling_coverage_pass_carries_no_approval():
    subjects = [_subject("S1")]
    contract = _contract(subjects, required=("v1",))
    result = _verify(contract, [_obs("v1", "S1")])
    assert result.status is VerificationStatus.VERIFIED
    payload = result.to_dict()
    assert set(payload) == {"status", "reason_codes", "coverage"}
    assert not any(key in payload for key in ("approved", "approval", "authority", "signature"))
    assert verify_derive_coverage is derive_coverage
