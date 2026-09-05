import gc
import weakref

import pytest

import product.verification as verification_module
from product.certification import CertificationDisposition, CertificationPolicy, certify_result
from product.evidence import IntegrityStatus, ObservationStatus
from product.verification import VerificationResult, VerificationStatus, reduce_verification


@pytest.mark.parametrize(
    ("condition", "observations", "complete", "scope_escape", "status"),
    [
        (
            IntegrityStatus.VALID,
            (ObservationStatus.FAIL,),
            True,
            False,
            VerificationStatus.FAILED_VERIFICATION,
        ),
        (
            IntegrityStatus.VALID,
            (ObservationStatus.PASS,),
            True,
            True,
            VerificationStatus.FAILED_VERIFICATION,
        ),
        (
            IntegrityStatus.VALID,
            (ObservationStatus.PASS,),
            True,
            False,
            VerificationStatus.VERIFIED,
        ),
        (IntegrityStatus.MISSING, (), False, False, VerificationStatus.UNVERIFIABLE),
        (IntegrityStatus.STALE, (), False, False, VerificationStatus.UNVERIFIABLE),
        (IntegrityStatus.TAMPERED, (), False, False, VerificationStatus.UNVERIFIABLE),
        (IntegrityStatus.MALFORMED, (), False, False, VerificationStatus.UNVERIFIABLE),
        (IntegrityStatus.CROSS_BOUND, (), False, False, VerificationStatus.UNVERIFIABLE),
        (IntegrityStatus.DUPLICATE, (), False, False, VerificationStatus.UNVERIFIABLE),
        (IntegrityStatus.LEGACY_NON_CERTIFIABLE, (), False, False, VerificationStatus.UNVERIFIABLE),
    ],
)
def test_factual_reducer_matrix(condition, observations, complete, scope_escape, status):
    if scope_escape:
        condition = IntegrityStatus.SCOPE_ESCAPE
    result = reduce_verification(condition, observations)
    assert result.status is status


def test_reason_codes_are_sorted_unique_and_compatibly_exposed():
    result = reduce_verification(IntegrityStatus.MALFORMED, reasons=("a", "z"))
    assert result.reason_codes == ("a", "z")
    assert result.integrity is IntegrityStatus.MALFORMED
    assert result.failed_checks == result.reason_codes


def test_certification_reduces_only_from_factual_result():
    policy = CertificationPolicy(True, True, True, True)
    assert (
        certify_result(reduce_verification(IntegrityStatus.TAMPERED), policy)
        is CertificationDisposition.REJECTED
    )
    assert (
        certify_result(reduce_verification(IntegrityStatus.MISSING), policy)
        is CertificationDisposition.BLOCKED
    )
    assert (
        certify_result(
            reduce_verification(IntegrityStatus.VALID, (ObservationStatus.PASS,)), policy
        )
        is CertificationDisposition.CERTIFIED
    )


def test_direct_truth_and_caller_disposition_inputs_are_rejected():
    with pytest.raises(TypeError):
        VerificationResult(VerificationStatus.VERIFIED)
    with pytest.raises(TypeError):
        reduce_verification(IntegrityStatus.VALID, status=VerificationStatus.VERIFIED)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        reduce_verification(IntegrityStatus.VALID, disposition=CertificationDisposition.CERTIFIED)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        VerificationResult(VerificationStatus.VERIFIED, _token=object())
    with pytest.raises((ImportError, AttributeError)):
        exec("from product.verification import _INTERNAL_TOKEN", {})


@pytest.mark.parametrize("reasons", [[], {"x"}, "x", ("x", 1), ("x", "x"), (" x",)])
def test_reason_container_is_strictly_validated(reasons):
    with pytest.raises((TypeError, ValueError)):
        reduce_verification(IntegrityStatus.VALID, (ObservationStatus.PASS,), reasons)


def test_failed_results_have_canonical_reason_and_distinct_receipt_payload():
    failed = reduce_verification(IntegrityStatus.VALID, (ObservationStatus.FAIL,), ("unit",))
    scoped = reduce_verification(IntegrityStatus.SCOPE_ESCAPE)
    assert "VERIFIER_FAILED" in failed.reason_codes
    assert "unit" in failed.reason_codes
    assert "SCOPE_ESCAPE" in scoped.reason_codes
    assert failed != scoped


def test_reducer_registry_is_private_weak_and_forgery_does_not_pass():
    assert not hasattr(verification_module, "_REDUCED_RESULTS")
    assert not hasattr(verification_module, "_INTERNAL_TOKEN")
    assert not hasattr(verification_module, "_make_reducer")
    result = reduce_verification(IntegrityStatus.VALID, (ObservationStatus.PASS,))
    ref = weakref.ref(result)
    assert verification_module.is_reduced_result(result)
    del result
    gc.collect()
    assert ref() is None
    forged = object.__new__(VerificationResult)
    assert not verification_module.is_reduced_result(forged)


@pytest.mark.parametrize(
    "observations, condition, expected_condition, status, disposition",
    [
        (
            (ObservationStatus.PASS,),
            IntegrityStatus.VALID,
            IntegrityStatus.VALID,
            VerificationStatus.VERIFIED,
            CertificationDisposition.CERTIFIED,
        ),
        (
            (ObservationStatus.FAIL,),
            IntegrityStatus.VALID,
            IntegrityStatus.VALID,
            VerificationStatus.FAILED_VERIFICATION,
            CertificationDisposition.REJECTED,
        ),
        (
            (),
            IntegrityStatus.MISSING,
            IntegrityStatus.MISSING,
            VerificationStatus.UNVERIFIABLE,
            CertificationDisposition.BLOCKED,
        ),
        (
            ("PASS",),
            IntegrityStatus.VALID,
            IntegrityStatus.LEGACY_NON_CERTIFIABLE,
            VerificationStatus.UNVERIFIABLE,
            CertificationDisposition.BLOCKED,
        ),
        (
            ("FAIL",),
            IntegrityStatus.VALID,
            IntegrityStatus.LEGACY_NON_CERTIFIABLE,
            VerificationStatus.UNVERIFIABLE,
            CertificationDisposition.BLOCKED,
        ),
        (
            ("MAYBE",),
            IntegrityStatus.VALID,
            IntegrityStatus.MALFORMED,
            VerificationStatus.UNVERIFIABLE,
            CertificationDisposition.REJECTED,
        ),
        (
            (VerificationStatus.VERIFIED,),
            IntegrityStatus.VALID,
            IntegrityStatus.MALFORMED,
            VerificationStatus.UNVERIFIABLE,
            CertificationDisposition.REJECTED,
        ),
    ],
)
def test_named_compatibility_rows(observations, condition, expected_condition, status, disposition):
    result = reduce_verification(condition, observations)
    assert (result.status, result.integrity) == (status, expected_condition)
    assert certify_result(result, CertificationPolicy(True, True, True, True)) is disposition


@pytest.mark.parametrize(
    "condition, disposition",
    [
        (IntegrityStatus.SCOPE_ESCAPE, CertificationDisposition.REJECTED),
        (IntegrityStatus.MISSING, CertificationDisposition.BLOCKED),
        (IntegrityStatus.STALE, CertificationDisposition.BLOCKED),
        (IntegrityStatus.TAMPERED, CertificationDisposition.REJECTED),
        (IntegrityStatus.MALFORMED, CertificationDisposition.REJECTED),
        (IntegrityStatus.CROSS_BOUND, CertificationDisposition.REJECTED),
        (IntegrityStatus.DUPLICATE, CertificationDisposition.REJECTED),
        (IntegrityStatus.LEGACY_NON_CERTIFIABLE, CertificationDisposition.BLOCKED),
    ],
)
def test_condition_disposition_matrix(condition, disposition):
    result = reduce_verification(condition)
    assert result.status is (
        VerificationStatus.FAILED_VERIFICATION
        if condition is IntegrityStatus.SCOPE_ESCAPE
        else VerificationStatus.UNVERIFIABLE
    )
    assert certify_result(result, CertificationPolicy(True, True, True, True)) is disposition
