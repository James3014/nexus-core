from dataclasses import dataclass
from enum import Enum
from weakref import WeakValueDictionary

from product.evidence import (
    IntegrityStatus,
    Observation,
    ObservationStatus,
    derive_evidence_integrity,
    validate_evidence_subjects,
)


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True, init=False)
class VerificationResult:
    status: VerificationStatus
    reason_codes: tuple[str, ...] = ()
    integrity: IntegrityStatus = IntegrityStatus.VALID

    def __init__(self, *args, **kwargs):
        raise TypeError("VerificationResult is created by reduce_verification")

    def __post_init__(self):
        if not isinstance(self.status, VerificationStatus):
            raise TypeError("status must be VerificationStatus")
        if not isinstance(self.integrity, IntegrityStatus):
            raise TypeError("integrity must be IntegrityStatus")
        if not isinstance(self.reason_codes, tuple):
            raise TypeError("reason_codes must be a tuple")
        if len(self.reason_codes) > 64:
            raise ValueError("reason_codes is bounded")
        for code in self.reason_codes:
            if not isinstance(code, str) or not code or code != code.strip() or len(code) > 128:
                raise ValueError("reason_codes must contain bounded nonblank strings")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("reason_codes must be unique and sorted")
        if self.status is VerificationStatus.VERIFIED and (
            self.integrity is not IntegrityStatus.VALID or self.reason_codes
        ):
            raise ValueError("VERIFIED requires valid integrity and no failed checks")
        if (
            self.integrity is not IntegrityStatus.VALID
            and self.status is not VerificationStatus.UNVERIFIABLE
        ):
            raise ValueError("non-valid integrity requires UNVERIFIABLE status")

    @property
    def failed_checks(self):
        return self.reason_codes

    def to_dict(self):
        return {
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
        }


def _validate_reasons(reasons):
    if not isinstance(reasons, tuple):
        raise TypeError("reasons must be a tuple")
    for reason in reasons:
        if (
            not isinstance(reason, str)
            or not reason
            or reason != reason.strip()
            or len(reason) > 128
        ):
            raise ValueError("reasons must contain bounded nonblank strings")
    if reasons != tuple(sorted(set(reasons))):
        raise ValueError("reasons must be unique and sorted")


def _make_reducer():
    registry = WeakValueDictionary()

    def reduce_verification(condition, observations=(), reasons=()):
        if not isinstance(condition, IntegrityStatus):
            raise TypeError("condition must be IntegrityStatus")
        _validate_reasons(reasons)
        if not isinstance(observations, tuple):
            raise TypeError("observations must be a tuple")
        codes = list(reasons)
        if condition is IntegrityStatus.SCOPE_ESCAPE:
            if not reasons:
                codes.append(condition.value)
            status, integrity = VerificationStatus.FAILED_VERIFICATION, IntegrityStatus.VALID
        elif condition is not IntegrityStatus.VALID:
            if not reasons:
                codes.append(condition.value)
            status, integrity = VerificationStatus.UNVERIFIABLE, condition
        elif not observations:
            status, integrity = VerificationStatus.UNVERIFIABLE, IntegrityStatus.MISSING
            codes.append(IntegrityStatus.MISSING.value)
        elif any(type(item) is str for item in observations) and all(
            item in {"PASS", "FAIL"} for item in observations
        ):
            status, integrity = (
                VerificationStatus.UNVERIFIABLE,
                IntegrityStatus.LEGACY_NON_CERTIFIABLE,
            )
            codes.append(IntegrityStatus.LEGACY_NON_CERTIFIABLE.value)
        elif any(type(item) is str for item in observations):
            status, integrity = VerificationStatus.UNVERIFIABLE, IntegrityStatus.MALFORMED
            codes.append(IntegrityStatus.MALFORMED.value)
        elif not all(isinstance(item, ObservationStatus) for item in observations):
            status, integrity = VerificationStatus.UNVERIFIABLE, IntegrityStatus.MALFORMED
            codes.append(IntegrityStatus.MALFORMED.value)
        elif any(item is ObservationStatus.FAIL for item in observations):
            status, integrity = VerificationStatus.FAILED_VERIFICATION, IntegrityStatus.VALID
            codes.append("VERIFIER_FAILED")
        else:
            status, integrity = VerificationStatus.VERIFIED, IntegrityStatus.VALID
        result = object.__new__(VerificationResult)
        object.__setattr__(result, "status", status)
        object.__setattr__(
            result,
            "reason_codes",
            tuple(sorted(set(codes))) if status is not VerificationStatus.VERIFIED else (),
        )
        object.__setattr__(result, "integrity", integrity)
        VerificationResult.__post_init__(result)
        registry[id(result)] = result
        return result

    def is_reduced_result(result):
        return isinstance(result, VerificationResult) and registry.get(id(result)) is result

    return reduce_verification, is_reduced_result


reduce_verification, is_reduced_result = _make_reducer()
del _make_reducer


def _make_verify(
    integrity_deriver,
    subject_validator,
    reducer,
    observation_type,
    observation_status,
    integrity_status,
):
    def verify(contract, change_set, plan, evidence):
        if subject_validator(contract, change_set, plan, evidence):
            return reducer(integrity_status.MALFORMED)
        integrity = integrity_deriver(contract, change_set, plan, evidence)
        if integrity is not integrity_status.VALID:
            return reducer(integrity)
        contract_data = vars(contract)
        change_data = vars(change_set)
        plan_data = vars(plan)
        evidence_data = vars(evidence)
        if set(change_data["paths"]) - set(contract_data["allowed_paths"]):
            return reducer(integrity_status.SCOPE_ESCAPE)
        if set(contract_data["required_verifier_ids"]) != set(plan_data["required_verifier_ids"]):
            return reducer(integrity_status.MISSING)
        observations = evidence_data["observations"]
        obs = {vars(o)["verifier_id"]: o for o in observations}
        observed_ids = set(obs)
        if observed_ids != set(plan_data["required_verifier_ids"]):
            return reducer(integrity_status.MISSING)
        if any(
            vars(o)["status"] not in {observation_status.PASS, observation_status.FAIL}
            for o in observations
        ):
            return reducer(integrity_status.MALFORMED)
        missing = tuple(
            sorted(
                x
                for x in contract_data["required_verifier_ids"]
                if x not in obs or x not in plan_data["required_verifier_ids"]
            )
        )
        if missing or not observations:
            return reducer(integrity_status.MISSING, reasons=missing)
        failed = tuple(
            sorted(
                x
                for x in contract_data["required_verifier_ids"]
                if vars(obs[x])["status"] is not observation_status.PASS
            )
        )
        return reducer(
            integrity_status.VALID,
            tuple(vars(obs[x])["status"] for x in contract_data["required_verifier_ids"]),
            failed,
        )

    return verify


verify = _make_verify(
    derive_evidence_integrity,
    validate_evidence_subjects,
    reduce_verification,
    Observation,
    ObservationStatus,
    IntegrityStatus,
)
