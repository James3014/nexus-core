from dataclasses import dataclass

from product.certification import CertificationPolicy, certify_result
from product.certification.receipt import (
    _SEALED_RECEIPT_CORE_HASH,
    CLAIM_CEILING,
    CertificationResult,
    Receipt,
    _create_certification_result,
    _create_receipt,
    _validate_receipt_envelope,
)
from product.evidence import (
    AcceptanceContract,
    ChangeSet,
    EvidenceBundle,
    VerificationPlan,
    validate_evidence_subjects,
)
from product.verification import verify


@dataclass(frozen=True)
class CertificationInput:
    contract: AcceptanceContract
    change_set: ChangeSet
    plan: VerificationPlan
    evidence: EvidenceBundle
    policy_accepted: bool | None = None
    authority_present: bool | None = None
    approval_present: bool | None = None
    signing_present: bool | None = None


def _make_policy_factory(policy_type):
    def create(accepted, authority_present, approval_present, signing_present):
        policy = object.__new__(policy_type)
        for name, value in (
            ("accepted", accepted),
            ("authority_present", authority_present),
            ("approval_present", approval_present),
            ("signing_present", signing_present),
        ):
            object.__setattr__(policy, name, value)
        return policy

    return create


_SEALED_POLICY_FACTORY = _make_policy_factory(CertificationPolicy)


def _make_kernel(
    certification_input_type,
    contract_type,
    change_set_type,
    plan_type,
    evidence_type,
    receipt_type,
    result_type,
    verify_fn,
    subject_validator,
    policy_type,
    result_certifier,
    receipt_envelope_validator,
    contract_hash,
    change_hash,
    plan_hash,
    evidence_hash,
    policy_factory,
    receipt_factory,
    result_factory,
):
    def validate_input(value):
        if type(value) is not certification_input_type:
            return ("MALFORMED:input",)
        data = vars(value)
        if set(data) != set(certification_input_type.__dataclass_fields__):
            return ("MALFORMED:input",)
        errors = subject_validator(
            data["contract"], data["change_set"], data["plan"], data["evidence"]
        )
        if type(data["contract"]) is not contract_type:
            errors += ("MALFORMED:contract",)
        if type(data["change_set"]) is not change_set_type:
            errors += ("MALFORMED:change_set",)
        if type(data["plan"]) is not plan_type:
            errors += ("MALFORMED:plan",)
        if type(data["evidence"]) is not evidence_type:
            errors += ("MALFORMED:evidence",)
        for field in (
            "policy_accepted",
            "authority_present",
            "approval_present",
            "signing_present",
        ):
            if data[field] is not None and type(data[field]) is not bool:
                errors += (f"MALFORMED:{field}",)
        return tuple(dict.fromkeys(errors))

    def certify(value):
        errors = validate_input(value)
        if errors:
            raise ValueError("invalid_certification_input:" + ",".join(errors))
        data = vars(value)
        result = verify_fn(data["contract"], data["change_set"], data["plan"], data["evidence"])
        policy = policy_factory(
            data["policy_accepted"],
            data["authority_present"],
            data["approval_present"],
            data["signing_present"],
        )
        disposition = result_certifier(result, policy)
        receipt = receipt_factory(
            contract_hash(data["contract"]),
            change_hash(data["change_set"]),
            plan_hash(data["plan"]),
            evidence_hash(data["evidence"]),
            result,
            disposition,
            policy,
        )
        return result_factory(result, disposition, receipt)

    def validate_receipt(receipt, value):
        if type(receipt) is not receipt_type or validate_input(value):
            return False
        expected = certify(value).receipt
        fields = vars(receipt)
        if set(fields) != set(receipt_type.__dataclass_fields__):
            return False
        claimed = fields["claimed_receipt_hash"]
        return _SEALED_RECEIPT_CORE_HASH(receipt) == _SEALED_RECEIPT_CORE_HASH(expected) and (
            claimed is None or claimed == _SEALED_RECEIPT_CORE_HASH(receipt)
        )

    def validate_serialized_receipt(payload, value):
        if validate_input(value):
            return ("MALFORMED:input",)
        return receipt_envelope_validator(payload, certify(value).receipt)

    return certify, validate_receipt, validate_serialized_receipt


certify, validate_receipt, validate_serialized_receipt = _make_kernel(
    CertificationInput,
    AcceptanceContract,
    ChangeSet,
    VerificationPlan,
    EvidenceBundle,
    Receipt,
    CertificationResult,
    verify,
    validate_evidence_subjects,
    CertificationPolicy,
    certify_result,
    _validate_receipt_envelope,
    AcceptanceContract.hash.fget,
    ChangeSet.hash.fget,
    VerificationPlan.hash.fget,
    EvidenceBundle.hash.fget,
    _SEALED_POLICY_FACTORY,
    _create_receipt,
    _create_certification_result,
)


__all__ = [
    "CLAIM_CEILING",
    "CertificationInput",
    "CertificationResult",
    "Receipt",
    "certify",
    "validate_receipt",
    "validate_serialized_receipt",
]
