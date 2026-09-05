from dataclasses import dataclass
from enum import Enum

from product.evidence import IntegrityStatus
from product.verification import VerificationResult, VerificationStatus, is_reduced_result


class CertificationDisposition(str, Enum):
    CERTIFIED = "CERTIFIED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class CertificationPolicy:
    accepted: bool | None = None
    authority_present: bool | None = None
    approval_present: bool | None = None
    signing_present: bool | None = None


def certify_result(
    result: VerificationResult, policy: CertificationPolicy
) -> CertificationDisposition:
    if not isinstance(result, VerificationResult) or not is_reduced_result(result):
        return CertificationDisposition.BLOCKED
    if not isinstance(result.status, VerificationStatus):
        return CertificationDisposition.BLOCKED
    if not isinstance(result.integrity, IntegrityStatus):
        return CertificationDisposition.BLOCKED
    if (
        not isinstance(result.reason_codes, tuple)
        or any(
            not isinstance(check, str) or not check or check != check.strip()
            for check in result.reason_codes
        )
        or len(result.reason_codes) != len(set(result.reason_codes))
        or result.reason_codes != tuple(sorted(result.reason_codes))
    ):
        return CertificationDisposition.BLOCKED
    if result.status is VerificationStatus.VERIFIED and (
        result.integrity is not IntegrityStatus.VALID or result.reason_codes
    ):
        return CertificationDisposition.BLOCKED
    if (
        result.integrity is not IntegrityStatus.VALID
        and result.status is not VerificationStatus.UNVERIFIABLE
    ):
        return CertificationDisposition.BLOCKED
    if (
        result.status is VerificationStatus.FAILED_VERIFICATION
        or result.integrity is not None
        and result.integrity.value == "TAMPERED"
    ):
        return CertificationDisposition.REJECTED
    if result.status is VerificationStatus.UNVERIFIABLE:
        return (
            CertificationDisposition.REJECTED
            if result.integrity
            in {
                IntegrityStatus.TAMPERED,
                IntegrityStatus.MALFORMED,
                IntegrityStatus.CROSS_BOUND,
                IntegrityStatus.DUPLICATE,
            }
            else CertificationDisposition.BLOCKED
        )
    if policy.accepted is False:
        return CertificationDisposition.REJECTED
    if any(
        value is not True
        for value in (
            policy.accepted,
            policy.authority_present,
            policy.approval_present,
            policy.signing_present,
        )
    ):
        return CertificationDisposition.BLOCKED
    return CertificationDisposition.CERTIFIED


__all__ = ["CertificationDisposition", "CertificationPolicy", "certify_result"]
