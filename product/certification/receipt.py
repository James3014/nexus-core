from dataclasses import dataclass
from math import isfinite
from types import FunctionType

from product.certification import CertificationDisposition, CertificationPolicy, certify_result
from product.evidence import _hash, _require_hash
from product.protocol import (
    CERTIFICATION_RECEIPT_SCHEMA,
    IMPLEMENTATION_SCHEMA,
    PUBLIC_PROTOCOL_VERSION,
)
from product.verification import VerificationResult, is_reduced_result

_RECEIPT_HASH = _hash
_REQUIRE_HASH = _require_hash
_SEALED_RECEIPT_HASH = _RECEIPT_HASH
_SEALED_RECEIPT_REQUIRE_HASH = _REQUIRE_HASH
_VALIDATOR_RECEIPT_HASH = _SEALED_RECEIPT_HASH
_VALIDATOR_RECEIPT_REQUIRE_HASH = _SEALED_RECEIPT_REQUIRE_HASH


def _make_receipt_hash_property(hash_fn):
    def get_hash(self):
        return hash_fn(self)

    return property(get_hash)


CLAIM_CEILING = (
    "NO_MERGE_AUTHORIZATION",
    "NO_DEPLOYMENT_TRUTH",
    "NO_OUTCOME_TRUTH",
    "NO_PRODUCTION_READINESS",
    "NO_PUBLIC_PROTOCOL_STABILITY",
)
_VERIFICATION_STATUSES = {"VERIFIED", "FAILED_VERIFICATION", "UNVERIFIABLE"}
_INTEGRITY_STATUSES = {
    "VALID",
    "SCOPE_ESCAPE",
    "MISSING",
    "STALE",
    "TAMPERED",
    "MALFORMED",
    "CROSS_BOUND",
    "DUPLICATE",
    "LEGACY_NON_CERTIFIABLE",
}


def _make_strict_json(isfinite_fn):
    def strict_json(value):
        active = set()

        def visit(item):
            if item is None or type(item) in (str, bool, int):
                return
            if type(item) is float:
                if not isfinite_fn(item):
                    raise ValueError("non-finite value")
                return
            if type(item) in (list, tuple, dict):
                marker = id(item)
                if marker in active:
                    raise ValueError("cyclic value")
                active.add(marker)
                try:
                    if type(item) is dict:
                        for key, nested in item.items():
                            if type(key) is not str:
                                raise TypeError("object keys must be strings")
                            visit(nested)
                    else:
                        for nested in item:
                            visit(nested)
                finally:
                    active.remove(marker)
                return
            raise TypeError("unsupported value")

        visit(value)

    return strict_json


_strict_json = _make_strict_json(isfinite)


_VALIDATOR_STRICT_JSON = _strict_json


def _policy_valid(policy):
    return type(policy) is CertificationPolicy and all(
        value is None or type(value) is bool
        for value in (
            policy.accepted,
            policy.authority_present,
            policy.approval_present,
            policy.signing_present,
        )
    )


@dataclass(frozen=True, init=False)
class Receipt:
    acceptance_contract_hash: str
    change_set_hash: str
    verification_plan_hash: str
    evidence_hash: str
    verification: VerificationResult
    disposition: CertificationDisposition
    policy: CertificationPolicy
    claim_ceiling: tuple[str, ...] = CLAIM_CEILING
    protocol_version: str = PUBLIC_PROTOCOL_VERSION
    implementation_schema: str = IMPLEMENTATION_SCHEMA
    claimed_receipt_hash: str | None = None

    def __init__(self, *args, **kwargs):
        raise TypeError("Receipt construction is internal")

    def __post_init__(self):
        for field in (
            "acceptance_contract_hash",
            "change_set_hash",
            "verification_plan_hash",
            "evidence_hash",
        ):
            _SEALED_RECEIPT_REQUIRE_HASH(getattr(self, field), field)
        if type(self.verification) is not VerificationResult or not is_reduced_result(
            self.verification
        ):
            raise TypeError("verification must be reducer-produced VerificationResult")
        if type(self.disposition) is not CertificationDisposition:
            raise TypeError("disposition must be CertificationDisposition")
        if not _policy_valid(self.policy):
            raise TypeError("policy fields must be bool or None")
        if self.claim_ceiling != CLAIM_CEILING:
            raise ValueError("claim_ceiling must equal CLAIM_CEILING")
        if self.protocol_version != PUBLIC_PROTOCOL_VERSION:
            raise ValueError("protocol_version must equal PUBLIC_PROTOCOL_VERSION")
        if self.implementation_schema != IMPLEMENTATION_SCHEMA:
            raise ValueError("implementation_schema must equal IMPLEMENTATION_SCHEMA")
        if certify_result(self.verification, self.policy) is not self.disposition:
            raise ValueError("disposition must match reducer")
        if self.claimed_receipt_hash is not None:
            _SEALED_RECEIPT_REQUIRE_HASH(self.claimed_receipt_hash, "claimed_receipt_hash")

    @property
    def canonical_value(self):
        return {
            "receipt_schema": CERTIFICATION_RECEIPT_SCHEMA,
            "protocol_version": self.protocol_version,
            "implementation_schema": self.implementation_schema,
            "acceptance_contract_hash": self.acceptance_contract_hash,
            "change_set_hash": self.change_set_hash,
            "verification_plan_hash": self.verification_plan_hash,
            "evidence_hash": self.evidence_hash,
            "verification": {
                "status": self.verification.status.value,
                "condition": self.verification.integrity.value,
                "reason_codes": list(self.verification.reason_codes),
            },
            "certification": {
                "disposition": self.disposition.value,
                "policy": {
                    "accepted": self.policy.accepted,
                    "authority_present": self.policy.authority_present,
                    "approval_present": self.policy.approval_present,
                    "signing_present": self.policy.signing_present,
                },
            },
            "claim_ceiling": list(self.claim_ceiling),
        }

    @property
    def hash(self):
        return _SEALED_RECEIPT_HASH(self.canonical_value)

    def to_dict(self):
        _require_exact_receipt_fields(self)
        if self.claimed_receipt_hash is not None and self.claimed_receipt_hash != self.hash:
            raise ValueError("claimed_receipt_hash does not match computed hash")
        return {**self.canonical_value, "receipt_hash": self.hash}

    def validate(self):
        if not _has_exact_receipt_fields(self):
            return False
        return self.claimed_receipt_hash is None or self.claimed_receipt_hash == self.hash


@dataclass(frozen=True, init=False)
class CertificationResult:
    verification: VerificationResult
    disposition: CertificationDisposition
    receipt: Receipt

    def __init__(self, *args, **kwargs):
        raise TypeError("CertificationResult construction is internal")

    def __post_init__(self):
        if type(self.verification) is not VerificationResult or not is_reduced_result(
            self.verification
        ):
            raise TypeError("verification must be reducer-produced VerificationResult")
        if (
            type(self.disposition) is not CertificationDisposition
            or type(self.receipt) is not Receipt
        ):
            raise TypeError("invalid certification result types")
        if (
            self.receipt.verification != self.verification
            or self.receipt.disposition != self.disposition
        ):
            raise ValueError("certification result must match receipt")
        if certify_result(self.verification, self.receipt.policy) is not self.disposition:
            raise ValueError("disposition must match reducer")


_RECEIPT_FIELD_NAMES = frozenset(Receipt.__dataclass_fields__)


def _has_exact_receipt_fields(receipt):
    return set(vars(receipt)) == _RECEIPT_FIELD_NAMES


def _require_exact_receipt_fields(receipt):
    if not _has_exact_receipt_fields(receipt):
        raise ValueError("receipt fields do not match sealed fields")


def _make_sealed_receipt_body():
    def body(receipt):
        _require_exact_receipt_fields(receipt)
        fields = vars(receipt)
        verification = fields["verification"]
        policy = fields["policy"]
        return {
            "receipt_schema": CERTIFICATION_RECEIPT_SCHEMA,
            "protocol_version": fields["protocol_version"],
            "implementation_schema": fields["implementation_schema"],
            "acceptance_contract_hash": fields["acceptance_contract_hash"],
            "change_set_hash": fields["change_set_hash"],
            "verification_plan_hash": fields["verification_plan_hash"],
            "evidence_hash": fields["evidence_hash"],
            "verification": {
                "status": vars(verification)["status"].value,
                "condition": vars(verification)["integrity"].value,
                "reason_codes": list(vars(verification)["reason_codes"]),
            },
            "certification": {
                "disposition": fields["disposition"].value,
                "policy": {
                    name: vars(policy)[name]
                    for name in (
                        "accepted",
                        "authority_present",
                        "approval_present",
                        "signing_present",
                    )
                },
            },
            "claim_ceiling": list(fields["claim_ceiling"]),
        }

    return body


_SEALED_RECEIPT_BODY = _make_sealed_receipt_body()


def _make_receipt_serializer(body, hash_fn):
    def serialize(receipt):
        return {**body(receipt), "receipt_hash": hash_fn(body(receipt))}

    return serialize


def _make_receipt_core_hash(body, hash_fn):
    def compute(receipt):
        return hash_fn(body(receipt))

    return compute


_SEALED_RECEIPT_SERIALIZER = _make_receipt_serializer(_SEALED_RECEIPT_BODY, _SEALED_RECEIPT_HASH)
_SEALED_RECEIPT_CORE_HASH = _make_receipt_core_hash(_SEALED_RECEIPT_BODY, _SEALED_RECEIPT_HASH)


def _make_receipt_invariant(certifier, require_hash):
    def validate(receipt):
        _require_exact_receipt_fields(receipt)
        fields = vars(receipt)
        for field in (
            "acceptance_contract_hash",
            "change_set_hash",
            "verification_plan_hash",
            "evidence_hash",
        ):
            require_hash(fields[field], field)
        if type(fields["verification"]) is not VerificationResult or not is_reduced_result(
            fields["verification"]
        ):
            raise TypeError("verification must be reducer-produced VerificationResult")
        if type(fields["disposition"]) is not CertificationDisposition or not _policy_valid(
            fields["policy"]
        ):
            raise TypeError("invalid receipt certification fields")
        if (
            fields["claim_ceiling"] != CLAIM_CEILING
            or fields["protocol_version"] != PUBLIC_PROTOCOL_VERSION
            or fields["implementation_schema"] != IMPLEMENTATION_SCHEMA
        ):
            raise ValueError("receipt constants do not match")
        if certifier(fields["verification"], fields["policy"]) is not fields["disposition"]:
            raise ValueError("disposition must match reducer")
        if fields["claimed_receipt_hash"] is not None:
            require_hash(fields["claimed_receipt_hash"], "claimed_receipt_hash")

    return validate


_SEALED_RECEIPT_INVARIANT = _make_receipt_invariant(certify_result, _SEALED_RECEIPT_REQUIRE_HASH)


def _make_receipt_factory(
    receipt_type,
    invariant,
    ceiling,
    protocol_version,
    implementation_schema,
):
    field_names = tuple(receipt_type.__dataclass_fields__)

    def create_receipt(
        acceptance_contract_hash,
        change_set_hash,
        verification_plan_hash,
        evidence_hash,
        verification,
        disposition,
        policy,
        **options,
    ):
        claim_ceiling = options.pop("claim_ceiling", ceiling)
        receipt_protocol_version = options.pop("protocol_version", protocol_version)
        receipt_implementation_schema = options.pop("implementation_schema", implementation_schema)
        claimed_receipt_hash = options.pop("claimed_receipt_hash", None)
        if options:
            raise TypeError(f"unexpected receipt options: {', '.join(sorted(options))}")
        receipt = object.__new__(receipt_type)
        values = (
            acceptance_contract_hash,
            change_set_hash,
            verification_plan_hash,
            evidence_hash,
            verification,
            disposition,
            policy,
            claim_ceiling,
            receipt_protocol_version,
            receipt_implementation_schema,
            claimed_receipt_hash,
        )
        for name, value in zip(field_names, values):
            object.__setattr__(receipt, name, value)
        invariant(receipt)
        return receipt

    return create_receipt


_create_receipt = _make_receipt_factory(
    Receipt,
    _SEALED_RECEIPT_INVARIANT,
    CLAIM_CEILING,
    PUBLIC_PROTOCOL_VERSION,
    IMPLEMENTATION_SCHEMA,
)

Receipt.hash = _make_receipt_hash_property(  # pyright: ignore[reportAttributeAccessIssue]
    _SEALED_RECEIPT_CORE_HASH
)


def _validate_receipt_envelope(payload, expected_receipt):
    """Validate envelope structure against an already recomputed receipt.

    This is an internal structural check; callers must not treat a supplied
    Receipt as certification authority.  Kernel validation recomputes it.
    """
    if type(expected_receipt) is not Receipt:
        raise TypeError("expected_receipt must be Receipt")
    if type(payload) is not dict:
        return ("MALFORMED:payload",)

    errors = []
    try:
        _VALIDATOR_STRICT_JSON(payload)
        keys = set(_SEALED_RECEIPT_SERIALIZER(expected_receipt))
        if set(payload) != keys:
            errors.append("MALFORMED:keys")
        if isinstance(payload.get("receipt_hash"), str):
            try:
                _VALIDATOR_RECEIPT_REQUIRE_HASH(payload["receipt_hash"], "receipt_hash")
                body = {key: payload[key] for key in payload if key != "receipt_hash"}
                if payload["receipt_hash"] != _VALIDATOR_RECEIPT_HASH(body):
                    errors.append("TAMPERED:receipt_hash")
            except (TypeError, ValueError):
                errors.append("TAMPERED:receipt_hash")
        if payload.get("receipt_schema") != CERTIFICATION_RECEIPT_SCHEMA:
            errors.append("STALE:receipt_schema")
        if payload.get("protocol_version") != PUBLIC_PROTOCOL_VERSION:
            errors.append("STALE:protocol_version")
        if payload.get("implementation_schema") != IMPLEMENTATION_SCHEMA:
            errors.append("STALE:implementation_schema")
        for field in (
            "acceptance_contract_hash",
            "change_set_hash",
            "verification_plan_hash",
            "evidence_hash",
            "receipt_hash",
        ):
            if not isinstance(payload.get(field), str):
                errors.append(f"MALFORMED:{field}")
            elif field != "receipt_hash":
                try:
                    _VALIDATOR_RECEIPT_REQUIRE_HASH(payload[field], field)
                except (TypeError, ValueError):
                    errors.append(f"MALFORMED:{field}")
        verification = payload.get("verification")
        if not isinstance(verification, dict) or set(verification) != {
            "status",
            "condition",
            "reason_codes",
        }:
            errors.append("MALFORMED:verification")
        elif (
            verification.get("status") not in _VERIFICATION_STATUSES
            or verification.get("condition") not in _INTEGRITY_STATUSES
            or not isinstance(verification.get("reason_codes"), list)
            or any(type(code) is not str for code in verification["reason_codes"])
            or verification["reason_codes"] != sorted(set(verification["reason_codes"]))
        ):
            errors.append("MALFORMED:verification")
        certification = payload.get("certification")
        if not isinstance(certification, dict) or set(certification) != {"disposition", "policy"}:
            errors.append("MALFORMED:certification")
        else:
            if certification.get("disposition") not in {
                item.value for item in CertificationDisposition
            }:
                errors.append("MALFORMED:disposition")
            policy = certification.get("policy")
            if (
                not isinstance(policy, dict)
                or set(policy)
                != {"accepted", "authority_present", "approval_present", "signing_present"}
                or any(
                    value is not None and type(value) is not bool
                    for value in (policy.values() if isinstance(policy, dict) else ())
                )
            ):
                errors.append("MALFORMED:policy")
        if payload.get("claim_ceiling") != list(CLAIM_CEILING):
            errors.append("MALFORMED:claim_ceiling")
        if not errors and payload != _SEALED_RECEIPT_SERIALIZER(expected_receipt):
            errors.append("TAMPERED:fields")
        return tuple(dict.fromkeys(errors))
    except (TypeError, ValueError, RecursionError, OverflowError):
        return ("MALFORMED:payload",)


def _freeze_function_globals(function):
    frozen = FunctionType(
        function.__code__,
        dict(function.__globals__),
        function.__name__,
        function.__defaults__,
        function.__closure__,
    )
    frozen.__kwdefaults__ = (
        dict(function.__kwdefaults__) if function.__kwdefaults__ is not None else None
    )
    frozen.__annotations__ = dict(function.__annotations__)
    return frozen


# Freeze class invariant and envelope-validation dependencies. Receipt hashing
# itself is already a property closure over the sealed hash function.
Receipt.__post_init__ = _freeze_function_globals(Receipt.__post_init__)
Receipt.canonical_value = property(  # pyright: ignore[reportAttributeAccessIssue]
    _freeze_function_globals(Receipt.canonical_value.fget)
)
CertificationResult.__post_init__ = _freeze_function_globals(CertificationResult.__post_init__)
_validate_receipt_envelope = _freeze_function_globals(_validate_receipt_envelope)


def _make_certification_result_factory(result_type, receipt_type, certifier):
    def create_result(verification, disposition, receipt):
        if type(receipt) is not receipt_type:
            raise TypeError("receipt must be Receipt")
        receipt_fields = vars(receipt)
        if (
            receipt_fields["verification"] != verification
            or receipt_fields["disposition"] != disposition
        ):
            raise ValueError("certification result must match receipt")
        if certifier(verification, receipt_fields["policy"]) is not disposition:
            raise ValueError("disposition must match reducer")
        result = object.__new__(result_type)
        object.__setattr__(result, "verification", verification)
        object.__setattr__(result, "disposition", disposition)
        object.__setattr__(result, "receipt", receipt)
        return result

    return create_result


_create_certification_result = _make_certification_result_factory(
    CertificationResult, Receipt, certify_result
)
