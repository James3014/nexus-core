"""Deterministic false-completion benchmark with immutable execution specs."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, replace
from fractions import Fraction
from types import MappingProxyType
from typing import Any, Callable, Mapping, cast

from product.adapters.changeset_certification_v2 import certify_changeset
from product.certification import CertificationDisposition, CertificationPolicy
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
from product.kernel import CertificationInput, certify, validate_receipt
from product.protocol import IMPLEMENTATION_SCHEMA, PUBLIC_PROTOCOL_VERSION
from product.verification import reduce_verification

BENCHMARK_SCHEMA = "nexus.false_completion_benchmark.v1"
BENCHMARK_ID = "false-completion-fixed-local-v1"
CLAIM_CEILING = (
    "NO_MERGE_AUTHORIZATION",
    "NO_DEPLOYMENT_TRUTH",
    "NO_OUTCOME_TRUTH",
    "NO_PRODUCTION_READINESS",
    "NO_PUBLIC_PROTOCOL_STABILITY",
)
PUBLIC_CLAIM_GATE = "FAIL_CLOSED_EXPERIMENTAL"


def _canonical(value: Any, *, _isfinite=math.isfinite, _dumps=json.dumps) -> str:
    active: set[int] = set()

    def enc(v: Any) -> Any:
        if v is None or type(v) in (bool, int, str):
            return v
        if type(v) is float:
            if not _isfinite(v):
                raise ValueError("non-finite")
            return v
        if isinstance(v, Mapping):
            if any(type(k) is not str for k in v):
                raise TypeError("mapping key")
            if id(v) in active:
                raise ValueError("cycle")
            active.add(id(v))
            try:
                return {k: enc(v[k]) for k in sorted(v)}
            finally:
                active.remove(id(v))
        if isinstance(v, (list, tuple)):
            if id(v) in active:
                raise ValueError("cycle")
            active.add(id(v))
            try:
                return [enc(x) for x in v]
            finally:
                active.remove(id(v))
        raise TypeError(type(v).__name__)

    return _dumps(
        enc(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _digest(value: Any, *, _canonical_fn=_canonical, _sha256=hashlib.sha256) -> str:
    return "sha256:" + _sha256(_canonical_fn(value).encode()).hexdigest()


@dataclass(frozen=True)
class CaseOutcome:
    outcome_kind: str
    verification_status: str | None = None
    evidence_condition: str | None = None
    disposition: str | None = None

    def __post_init__(self) -> None:
        kinds = {
            "CERTIFICATION",
            "INPUT_REJECTED",
            "INPUT_ACCEPTED",
            "RECEIPT_INVALID",
            "RECEIPT_VALID",
            "INFRA_INVALID",
        }
        if type(self.outcome_kind) is not str or self.outcome_kind not in kinds:
            raise ValueError("invalid outcome kind")
        fields = (self.verification_status, self.evidence_condition, self.disposition)
        if self.outcome_kind == "CERTIFICATION":
            if any(type(x) is not str for x in fields):
                raise ValueError("certification fields required")
            if self.verification_status not in {"VERIFIED", "FAILED_VERIFICATION", "UNVERIFIABLE"}:
                raise ValueError("invalid verification status")
            if self.evidence_condition not in {
                "VALID",
                "MISSING",
                "DUPLICATE",
                "LEGACY_NON_CERTIFIABLE",
                "STALE",
                "TAMPERED",
                "MALFORMED",
                "CROSS_BOUND",
            }:
                raise ValueError("invalid evidence condition")
            if self.disposition not in {"CERTIFIED", "REJECTED", "BLOCKED"}:
                raise ValueError("invalid disposition")
            valid = {
                "VERIFIED": {"VALID": {"CERTIFIED", "REJECTED", "BLOCKED"}},
                "FAILED_VERIFICATION": {"VALID": {"REJECTED"}},
                "UNVERIFIABLE": {
                    "MISSING": {"BLOCKED"},
                    "STALE": {"BLOCKED"},
                    "LEGACY_NON_CERTIFIABLE": {"BLOCKED"},
                    "TAMPERED": {"REJECTED"},
                    "MALFORMED": {"REJECTED"},
                    "CROSS_BOUND": {"REJECTED"},
                    "DUPLICATE": {"REJECTED"},
                },
            }
            if self.evidence_condition not in valid.get(self.verification_status, {}):
                raise ValueError("invalid certification combination")
            if self.disposition not in valid[self.verification_status][self.evidence_condition]:
                raise ValueError("invalid certification combination")
        elif any(x is not None for x in fields):
            raise ValueError("non-certification fields must be null")

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome_kind": self.outcome_kind,
            "verification_status": self.verification_status,
            "evidence_condition": self.evidence_condition,
            "disposition": self.disposition,
        }


@dataclass(frozen=True)
class CaseDefinition:
    case_id: str
    hostile: bool
    expected: CaseOutcome
    operation: str
    params: Mapping[str, Any]

    def __post_init__(self) -> None:
        if type(self.case_id) is not str or not self.case_id.strip():
            raise ValueError("case_id")
        object.__setattr__(self, "case_id", self.case_id.strip())
        if type(self.hostile) is not bool:
            raise TypeError("hostile")
        if not isinstance(self.expected, CaseOutcome):
            raise TypeError("expected")
        if self.operation not in {"direct", "legacy", "reject", "receipt", "special"}:
            raise ValueError("operation")
        if not isinstance(self.params, Mapping) or any(type(k) is not str for k in self.params):
            raise TypeError("params")
        object.__setattr__(self, "params", MappingProxyType(_freeze(self.params)))


@dataclass(frozen=True)
class BenchmarkCaseResult:
    case_id: str
    expected: CaseOutcome
    actual: CaseOutcome
    detected: bool
    infra_invalid: bool = False
    error: str | None = None

    def __post_init__(self) -> None:
        if type(self.case_id) is not str or not self.case_id:
            raise ValueError("case_id")
        if type(self.expected) is not type(self.actual) or not hasattr(self.expected, "to_dict"):
            raise TypeError("outcome")
        if type(self.detected) is not bool or type(self.infra_invalid) is not bool:
            raise TypeError("result flags")
        if self.error is not None and type(self.error) is not str:
            raise TypeError("error")
        if self.infra_invalid and self.actual.outcome_kind != "INFRA_INVALID":
            raise ValueError("infra result must be INFRA_INVALID")
        if not self.infra_invalid and self.actual.outcome_kind == "INFRA_INVALID":
            raise ValueError("non-infra result cannot be INFRA_INVALID")

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "expected": self.expected.to_dict(),
            "actual": self.actual.to_dict(),
            "detected": self.detected,
            "infra_invalid": self.infra_invalid,
            "error": self.error,
        }

    @property
    def canonical_hash(self, *, _digest_fn=_digest) -> str:
        return _digest_fn(self.to_dict())


@dataclass(frozen=True)
class FalseCompletionReport:
    schema: str
    benchmark_id: str
    task_set_hash: str
    protocol_version: str
    implementation_schema: str
    case_ids: tuple[str, ...]
    eligible_count: int
    infra_invalid_count: int
    hostile_case_count: int
    detected_count: int
    false_completion_count: int
    false_completion_rate: float | None
    detection_rate: float | None
    trust_mismatch_count: int
    trust_mismatch_rate: float | None
    public_claim_gate: str
    claim_ceiling: tuple[str, ...]
    cases: tuple[BenchmarkCaseResult, ...]
    report_hash: str

    def __post_init__(self) -> None:
        if (
            type(self.schema) is not str
            or type(self.benchmark_id) is not str
            or type(self.task_set_hash) is not str
        ):
            raise TypeError("report identity")
        if type(self.eligible_count) is not int or type(self.infra_invalid_count) is not int:
            raise TypeError("report counts")
        if any(not hasattr(x, "to_dict") for x in self.cases):
            raise TypeError("cases")
        if type(self.case_ids) is not tuple or type(self.claim_ceiling) is not tuple:
            raise TypeError("report sequences")
        if any(type(x) is not str for x in self.case_ids + self.claim_ceiling):
            raise TypeError("report sequence values")

    def payload(self, *, include_hash: bool = True) -> dict[str, Any]:
        p = {
            "schema": self.schema,
            "benchmark_id": self.benchmark_id,
            "task_set_hash": self.task_set_hash,
            "protocol_version": self.protocol_version,
            "implementation_schema": self.implementation_schema,
            "case_ids": list(self.case_ids),
            "eligible_count": self.eligible_count,
            "infra_invalid_count": self.infra_invalid_count,
            "hostile_case_count": self.hostile_case_count,
            "detected_count": self.detected_count,
            "false_completion_count": self.false_completion_count,
            "false_completion_rate": self.false_completion_rate,
            "detection_rate": self.detection_rate,
            "trust_mismatch_count": self.trust_mismatch_count,
            "trust_mismatch_rate": self.trust_mismatch_rate,
            "public_claim_gate": self.public_claim_gate,
            "claim_ceiling": list(self.claim_ceiling),
            "cases": [x.to_dict() for x in self.cases],
        }
        if include_hash:
            p["report_hash"] = self.report_hash
        return p

    def canonical_json(self, *, _canonical_fn=_canonical) -> str:
        return _canonical_fn(self.payload())


def _input(
    *,
    observations=None,
    change_paths=("src/a.py",),
    contract_cls=AcceptanceContract,
    change_cls=ChangeSet,
    plan_cls=VerificationPlan,
    bundle_cls=EvidenceBundle,
    observation_cls=Observation,
    status_cls=ObservationStatus,
    hash_fn=_hash,
    certification_input_cls=CertificationInput,
    **flags: bool | None,
) -> CertificationInput:
    c = contract_cls(
        "bench-contract", hash_fn("requirements"), ("unit", "lint"), ("src/a.py",), "FORBID"
    )
    ch = change_cls("bench-change", "source", "target", hash_fn("diff"), tuple(change_paths))
    plan = plan_cls("bench-plan", c.hash, ch.hash, ("unit", "lint"))
    observations = observations or (
        observation_cls("unit", "artifact-unit", hash_fn("unit"), status_cls.PASS),
        observation_cls("lint", "artifact-lint", hash_fn("lint"), status_cls.PASS),
    )
    return certification_input_cls(
        c,
        ch,
        plan,
        bundle_cls("bench-evidence", c.hash, ch.hash, plan.hash, tuple(observations)),
        **flags,
    )


def _direct(
    *, certify_fn=certify, input_fn=_input, outcome_cls=CaseOutcome, **kw: Any
) -> CaseOutcome:
    r = certify_fn(input_fn(**kw))
    return outcome_cls(
        "CERTIFICATION",
        r.verification.status.value,
        r.verification.integrity.value,
        r.disposition.value,
    )


def _legacy(
    status: str, *, certify_fn=certify_changeset, outcome_cls=CaseOutcome, **extra: Any
) -> CaseOutcome:
    r = certify_fn(
        {"schema": "nexus.changeset_certification.v1", "version": 1, "status": status, **extra}
    )
    return outcome_cls(
        "CERTIFICATION",
        r.verification_result.status.value,
        r.verification_result.integrity.value,
        r.status.value,
    )


def _reject(
    kind: str,
    *,
    contract_cls=AcceptanceContract,
    observation_cls=Observation,
    certification_input_cls=CertificationInput,
    cast_fn=cast,
    input_fn=_input,
    hash_fn=_hash,
    outcome_cls=CaseOutcome,
) -> CaseOutcome:
    try:
        if kind == "traversal":
            contract_cls("x", hash_fn("r"), ("unit",), ("../escape",), "FORBID")
        elif kind == "status":
            observation_cls("unit", "a", hash_fn("a"), cast_fn(Any, "PASS"))
        else:
            certification_input_cls(
                **cast_fn(Any, input_fn().__dict__ | {"disposition": "CERTIFIED"})
            )
    except (TypeError, ValueError):
        return outcome_cls("INPUT_REJECTED")
    return outcome_cls("CERTIFICATION", disposition="INPUT_ACCEPTED")


def _receipt(
    kind: str,
    *,
    input_fn=_input,
    certify_fn=certify,
    validate_fn=validate_receipt,
    replace_fn=replace,
    disposition_cls=CertificationDisposition,
    policy_cls=CertificationPolicy,
    reduce_fn=reduce_verification,
    integrity_status=IntegrityStatus,
    observation_status=ObservationStatus,
    hash_fn=_hash,
    outcome_cls=CaseOutcome,
) -> CaseOutcome:
    s = input_fn(
        policy_accepted=True, authority_present=True, approval_present=True, signing_present=True
    )
    r = certify_fn(s)
    q = r.receipt
    try:
        if kind in ("tamper", "disposition"):
            q = replace_fn(q, disposition=disposition_cls.REJECTED)
        elif kind == "verification":
            q = replace_fn(
                q,
                verification=reduce_fn(
                    integrity_status.VALID, (observation_status.FAIL,), ("VERIFIER_FAILED",)
                ),
            )
        elif kind == "policy":
            q = replace_fn(q, policy=policy_cls(False, True, True, True))
        elif kind == "prerequisite":
            q = replace_fn(q, policy=policy_cls(True, None, True, True))
        elif kind == "claimed_hash":
            q = replace_fn(q, claimed_receipt_hash=hash_fn("tampered-receipt"))
    except (TypeError, ValueError):
        return outcome_cls("RECEIPT_INVALID")
    return outcome_cls("RECEIPT_INVALID" if not validate_fn(q, s) else "CERTIFICATION")


def _special(
    kind: str,
    *,
    input_fn=_input,
    replace_fn=replace,
    hash_fn=_hash,
    certify_fn=certify,
    outcome_cls=CaseOutcome,
) -> CaseOutcome:
    s = input_fn(
        policy_accepted=True, authority_present=True, approval_present=True, signing_present=True
    )
    s = replace_fn(
        s,
        evidence=replace_fn(
            s.evidence,
            **(
                {"change_set_hash": hash_fn("different-change-set")}
                if kind == "stale"
                else {"claimed_bundle_hash": hash_fn("tampered-evidence")}
            ),
        ),
    )
    r = certify_fn(s)
    return outcome_cls(
        "CERTIFICATION",
        r.verification.status.value,
        r.verification.integrity.value,
        r.disposition.value,
    )


def _expected(v: str) -> CaseOutcome:
    if v in ("INPUT_REJECTED", "RECEIPT_INVALID"):
        return CaseOutcome(v)
    sc, d = v.split(":")
    a = sc.split("|")
    return CaseOutcome(
        "CERTIFICATION",
        a[0],
        a[1] if len(a) > 1 else ("VALID" if a[0] != "UNVERIFIABLE" else "MISSING"),
        d,
    )


def _p(**x: Any) -> tuple[tuple[str, Any], ...]:
    return tuple(x.items())


_CASE_SPEC_LITERAL = (
    (
        "direct_happy_certified",
        False,
        "VERIFIED:CERTIFIED",
        "direct",
        _p(
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        ),
    ),
    (
        "direct_verifier_fail",
        True,
        "FAILED_VERIFICATION:REJECTED",
        "direct",
        _p(
            observations="fail",
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        ),
    ),
    (
        "direct_missing_required_verifier",
        True,
        "UNVERIFIABLE:BLOCKED",
        "direct",
        _p(
            observations="missing",
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        ),
    ),
    (
        "direct_scope_escape",
        True,
        "FAILED_VERIFICATION:REJECTED",
        "direct",
        _p(
            change_paths=("src/secret.py",),
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        ),
    ),
    (
        "direct_duplicate_verifier",
        True,
        "UNVERIFIABLE|DUPLICATE:REJECTED",
        "direct",
        _p(
            observations="duplicate_verifier",
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        ),
    ),
    (
        "direct_duplicate_artifact",
        True,
        "UNVERIFIABLE|DUPLICATE:REJECTED",
        "direct",
        _p(
            observations="duplicate_artifact",
            policy_accepted=True,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        ),
    ),
    (
        "direct_policy_false",
        True,
        "VERIFIED:REJECTED",
        "direct",
        _p(
            policy_accepted=False,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        ),
    ),
    (
        "direct_policy_missing",
        True,
        "VERIFIED:BLOCKED",
        "direct",
        _p(
            policy_accepted=None,
            authority_present=True,
            approval_present=True,
            signing_present=True,
        ),
    ),
)
for f in ("authority_present", "approval_present", "signing_present"):
    _CASE_SPEC_LITERAL += (
        (
            f"direct_missing_{f}",
            True,
            "VERIFIED:BLOCKED",
            "direct",
            _p(
                policy_accepted=True,
                authority_present=None if f == "authority_present" else True,
                approval_present=None if f == "approval_present" else True,
                signing_present=None if f == "signing_present" else True,
            ),
        ),
    )
_CASE_SPEC_LITERAL += (
    (
        "legacy_v1_raw_pass",
        True,
        "UNVERIFIABLE|LEGACY_NON_CERTIFIABLE:BLOCKED",
        "legacy",
        _p(status="PASS"),
    ),
    (
        "legacy_v1_raw_fail",
        True,
        "UNVERIFIABLE|LEGACY_NON_CERTIFIABLE:BLOCKED",
        "legacy",
        _p(status="FAIL"),
    ),
    (
        "legacy_caller_reason_cannot_override_fail",
        True,
        "UNVERIFIABLE|LEGACY_NON_CERTIFIABLE:BLOCKED",
        "legacy",
        _p(status="FAIL", disposition="CERTIFIED", reasons=[]),
    ),
    ("traversal_path_input_rejected", True, "INPUT_REJECTED", "reject", _p(kind="traversal")),
    ("malformed_status_input_rejected", True, "INPUT_REJECTED", "reject", _p(kind="status")),
    (
        "caller_claimed_disposition_rejected",
        True,
        "INPUT_REJECTED",
        "reject",
        _p(kind="disposition"),
    ),
    ("receipt_tamper_rejected", True, "RECEIPT_INVALID", "receipt", _p(kind="tamper")),
    (
        "stale_change_set_hash_mismatch",
        True,
        "UNVERIFIABLE|STALE:BLOCKED",
        "special",
        _p(kind="stale"),
    ),
    (
        "tampered_evidence_claimed_hash",
        True,
        "UNVERIFIABLE|TAMPERED:REJECTED",
        "special",
        _p(kind="tampered"),
    ),
)
for k in ("verification", "disposition", "policy", "prerequisite", "claimed_hash"):
    _CASE_SPEC_LITERAL += (
        (f"receipt_{k}_tamper_rejected", True, "RECEIPT_INVALID", "receipt", _p(kind=k)),
    )


def _spec_jsonable(v: Any) -> Any:
    if isinstance(v, CaseOutcome):
        return v.to_dict()
    if isinstance(v, Mapping):
        return {k: _spec_jsonable(x) for k, x in v.items()}
    if isinstance(v, (tuple, list)):
        return [_spec_jsonable(x) for x in v]
    return v


def _freeze(v: Any, _active: set[int] | None = None) -> Any:
    active = set() if _active is None else _active
    if isinstance(v, Mapping):
        if id(v) in active:
            raise ValueError("cycle")
        if any(type(k) is not str for k in v):
            raise TypeError("mapping key")
        active.add(id(v))
        try:
            return MappingProxyType({k: _freeze(x, active) for k, x in v.items()})
        finally:
            active.remove(id(v))
    if isinstance(v, (tuple, list)):
        if id(v) in active:
            raise ValueError("cycle")
        active.add(id(v))
        try:
            return tuple(_freeze(x, active) for x in v)
        finally:
            active.remove(id(v))
    if type(v) in (str, bool, int) or v is None:
        return v
    if type(v) is float:
        if not math.isfinite(v):
            raise ValueError("non-finite")
        return v
    raise TypeError(type(v).__name__)


def _make_specs() -> tuple[CaseDefinition, ...]:
    return tuple(
        CaseDefinition(i, h, _expected(e), op, MappingProxyType(dict(_freeze(p))))
        for i, h, e, op, p in _CASE_SPEC_LITERAL
    )


_AUTHORITATIVE_SPEC = _make_specs()
EXPECTED_CASE_IDS = tuple(x.case_id for x in _AUTHORITATIVE_SPEC)
CASE_SPEC = tuple(
    (x.case_id, x.hostile, x.expected, x.operation, x.params) for x in _AUTHORITATIVE_SPEC
)
CASES = _AUTHORITATIVE_SPEC
TASK_SET_HASH = "sha256:afa32ac1ed78076e9d00c16b707a94ba025bc64cae7f028a06cba7cfcd08703b"


def _make_dispatch() -> Callable[[str, Mapping[str, Any]], CaseOutcome]:
    direct_fn, legacy_fn, reject_fn, receipt_fn, special_fn = (
        _direct,
        _legacy,
        _reject,
        _receipt,
        _special,
    )
    observation, status, digest = Observation, ObservationStatus, _hash

    def dispatch(op: str, p: Mapping[str, Any]) -> CaseOutcome:
        q = dict(p)
        if op == "direct":
            o = q.get("observations")
            if o == "fail":
                q["observations"] = (
                    observation("unit", "artifact-unit", digest("unit"), status.FAIL),
                    observation("lint", "artifact-lint", digest("lint"), status.PASS),
                )
            elif o == "missing":
                q["observations"] = (observation("unit", "u", digest("u"), status.PASS),)
            elif o == "duplicate_verifier":
                q["observations"] = (
                    observation("unit", "u", digest("u"), status.PASS),
                    observation("unit", "l", digest("l"), status.PASS),
                )
            elif o == "duplicate_artifact":
                q["observations"] = (
                    observation("unit", "same", digest("u"), status.PASS),
                    observation("lint", "same", digest("l"), status.PASS),
                )
            return direct_fn(**q)
        if op == "legacy":
            return legacy_fn(**q)
        if op == "reject":
            return reject_fn(**q)
        if op == "receipt":
            return receipt_fn(**q)
        return special_fn(q["kind"])

    return dispatch


def _false(c: CaseDefinition, a: CaseOutcome) -> bool:
    return c.hostile and a.outcome_kind == "CERTIFICATION" and a.disposition == "CERTIFIED"


def _run(
    spec: tuple[CaseDefinition, ...],
    dispatch: Callable[[str, Mapping[str, Any]], CaseOutcome],
    *,
    false_predicate=_false,
    result_cls=BenchmarkCaseResult,
    outcome_cls=CaseOutcome,
) -> tuple[BenchmarkCaseResult, ...]:
    out = []
    for c in spec:
        try:
            a = dispatch(c.operation, c.params)
            out.append(
                result_cls(
                    c.case_id,
                    c.expected,
                    a,
                    c.hostile and a == c.expected and not false_predicate(c, a),
                )
            )
        except (TypeError, ValueError) as e:
            # Strict Receipt construction intentionally rejects contradictory
            # dataclass.replace mutations.  Those are benchmark assertions,
            # not infrastructure failures.
            if c.operation == "receipt":
                out.append(
                    result_cls(
                        c.case_id,
                        c.expected,
                        outcome_cls("RECEIPT_INVALID"),
                        c.hostile and outcome_cls("RECEIPT_INVALID") == c.expected,
                        False,
                        type(e).__name__,
                    )
                )
                continue
            out.append(
                result_cls(
                    c.case_id,
                    c.expected,
                    outcome_cls("INFRA_INVALID"),
                    False,
                    True,
                    type(e).__name__,
                )
            )
        except Exception as e:
            out.append(
                result_cls(
                    c.case_id,
                    c.expected,
                    outcome_cls("INFRA_INVALID"),
                    False,
                    True,
                    type(e).__name__,
                )
            )
    return tuple(out)


def _rate(n: int, d: int, *, fraction_cls=Fraction) -> float | None:
    return round(float(fraction_cls(n, d)), 12) if d else None


def _shape(p: Mapping[str, Any], *, isfinite=math.isfinite) -> list[str]:
    errors: list[str] = []

    def exact(path: str, value: Any, typ: type, nullable: bool = False) -> None:
        if nullable and value is None:
            return
        if type(value) is not typ:
            errors.append(path)

    for k in (
        "schema",
        "benchmark_id",
        "task_set_hash",
        "protocol_version",
        "implementation_schema",
        "public_claim_gate",
    ):
        exact(k, p[k], str)
    exact("case_ids", p["case_ids"], list)
    exact("claim_ceiling", p["claim_ceiling"], list)
    for k in (
        "eligible_count",
        "infra_invalid_count",
        "hostile_case_count",
        "detected_count",
        "false_completion_count",
        "trust_mismatch_count",
    ):
        if type(p[k]) is not int or p[k] < 0:
            errors.append(k)
    for k in ("false_completion_rate", "detection_rate", "trust_mismatch_rate"):
        if p[k] is not None and (type(p[k]) is not float or not isfinite(p[k])):
            errors.append(k)
    exact("cases", p["cases"], list)
    if type(p["cases"]) is list:
        ck = {"case_id", "expected", "actual", "detected", "infra_invalid", "error"}
        ok = {"outcome_kind", "verification_status", "evidence_condition", "disposition"}
        for i, c in enumerate(p["cases"]):
            path = f"cases[{i}]"
            if type(c) is not dict:
                errors.append(path)
                continue
            for k in c:
                if k not in ck:
                    errors.append(f"{path}.{k}")
            for k in ck:
                if k not in c:
                    errors.append(f"{path}.{k}")
            if "case_id" in c:
                exact(f"{path}.case_id", c["case_id"], str)
            if "detected" in c:
                exact(f"{path}.detected", c["detected"], bool)
            if "infra_invalid" in c:
                exact(f"{path}.infra_invalid", c["infra_invalid"], bool)
            if "error" in c:
                exact(f"{path}.error", c["error"], str, True)
            for name in ("expected", "actual"):
                q = c.get(name)
                qp = f"{path}.{name}"
                if type(q) is not dict:
                    errors.append(qp)
                    continue
                for k in q:
                    if k not in ok:
                        errors.append(f"{qp}.{k}")
                for k in ok:
                    if k not in q:
                        errors.append(f"{qp}.{k}")
                if "outcome_kind" in q:
                    exact(f"{qp}.outcome_kind", q["outcome_kind"], str)
                for k in ("verification_status", "evidence_condition", "disposition"):
                    if k in q:
                        exact(f"{qp}.{k}", q[k], str, True)
    return sorted(set(errors))


def _build(
    spec: tuple[CaseDefinition, ...],
    res: tuple[BenchmarkCaseResult, ...],
    *,
    false_predicate=_false,
    rate_fn=_rate,
    digest_fn=_digest,
    result_cls=BenchmarkCaseResult,
    report_cls=FalseCompletionReport,
    schema=BENCHMARK_SCHEMA,
    benchmark_id=BENCHMARK_ID,
    task_hash=TASK_SET_HASH,
    protocol_version=PUBLIC_PROTOCOL_VERSION,
    implementation_schema=IMPLEMENTATION_SCHEMA,
    claim_gate=PUBLIC_CLAIM_GATE,
    claim_ceiling=CLAIM_CEILING,
) -> FalseCompletionReport:
    good = tuple(r for r in res if not r.infra_invalid)
    hostile = sum(c.hostile for c, r in zip(spec, res) if not r.infra_invalid)
    false = sum(false_predicate(c, r.actual) for c, r in zip(spec, res) if not r.infra_invalid)
    detected = sum(r.detected for r in good)
    mismatch = sum(r.actual != r.expected for r in good)
    p = {
        "schema": schema,
        "benchmark_id": benchmark_id,
        "task_set_hash": task_hash,
        "protocol_version": protocol_version,
        "implementation_schema": implementation_schema,
        "case_ids": [r.case_id for r in res],
        "eligible_count": len(good),
        "infra_invalid_count": len(res) - len(good),
        "hostile_case_count": hostile,
        "detected_count": detected,
        "false_completion_count": false,
        "false_completion_rate": rate_fn(false, hostile),
        "detection_rate": rate_fn(detected, hostile),
        "trust_mismatch_count": mismatch,
        "trust_mismatch_rate": rate_fn(mismatch, len(good)),
        "public_claim_gate": claim_gate,
        "claim_ceiling": list(claim_ceiling),
        "cases": [r.to_dict() for r in res],
    }
    return report_cls(
        **{k: v for k, v in p.items() if k not in ("case_ids", "claim_ceiling", "cases")},
        case_ids=tuple(p["case_ids"]),
        claim_ceiling=claim_ceiling,
        cases=res,
        report_hash=digest_fn(p),
    )


def _make_public_api() -> tuple[
    Callable[[], FalseCompletionReport],
    Callable[[FalseCompletionReport | Mapping[str, Any]], tuple[str, ...]],
]:
    # Resolve every dependency once, then build two genuinely disjoint contexts.
    # This makes later mutation/rebinding of module globals irrelevant.
    product_classes = (
        AcceptanceContract,
        ChangeSet,
        EvidenceBundle,
        VerificationPlan,
        Observation,
        ObservationStatus,
        IntegrityStatus,
        CertificationInput,
        CertificationDisposition,
        CertificationPolicy,
    )
    product_fns = (
        certify,
        certify_changeset,
        validate_receipt,
        reduce_verification,
        replace,
        cast,
        _hash,
    )
    classes = (BenchmarkCaseResult, CaseOutcome, FalseCompletionReport)

    def _make_execution_context():
        (
            contract_cls,
            change_cls,
            bundle_cls,
            plan_cls,
            observation_cls,
            status_cls,
            observation_status_cls,
            certification_input_cls,
            disposition_cls,
            policy_cls,
        ) = product_classes
        certify_fn, legacy_certify_fn, validate_fn, reduce_fn, replace_fn, cast_fn, hash_fn = (
            product_fns
        )
        result_cls, outcome_cls, report_cls = classes

        def input_fn(*, observations=None, change_paths=("src/a.py",), **flags):
            c = contract_cls(
                "bench-contract", hash_fn("requirements"), ("unit", "lint"), ("src/a.py",), "FORBID"
            )
            ch = change_cls(
                "bench-change", "source", "target", hash_fn("diff"), tuple(change_paths)
            )
            plan = plan_cls("bench-plan", c.hash, ch.hash, ("unit", "lint"))
            obs = observations or (
                observation_cls("unit", "artifact-unit", hash_fn("unit"), status_cls.PASS),
                observation_cls("lint", "artifact-lint", hash_fn("lint"), status_cls.PASS),
            )
            return certification_input_cls(
                c,
                ch,
                plan,
                bundle_cls("bench-evidence", c.hash, ch.hash, plan.hash, tuple(obs)),
                **flags,
            )

        def direct_fn(**kw):
            r = certify_fn(input_fn(**kw))
            return outcome_cls(
                "CERTIFICATION",
                r.verification.status.value,
                r.verification.integrity.value,
                r.disposition.value,
            )

        def legacy_fn(status: str, **extra):
            r = legacy_certify_fn(
                {
                    "schema": "nexus.changeset_certification.v1",
                    "version": 1,
                    "status": status,
                    **extra,
                }
            )
            return outcome_cls(
                "CERTIFICATION",
                r.verification_result.status.value,
                r.verification_result.integrity.value,
                r.status.value,
            )

        def reject_fn(kind: str):
            try:
                if kind == "traversal":
                    contract_cls("x", hash_fn("r"), ("unit",), ("../escape",), "FORBID")
                elif kind == "status":
                    observation_cls("unit", "a", hash_fn("a"), cast_fn(Any, "PASS"))
                else:
                    certification_input_cls(
                        **cast_fn(Any, input_fn().__dict__ | {"disposition": "CERTIFIED"})
                    )
            except (TypeError, ValueError):
                return outcome_cls("INPUT_REJECTED")
            return outcome_cls("INPUT_ACCEPTED")

        def receipt_fn(kind: str):
            s = input_fn(
                policy_accepted=True,
                authority_present=True,
                approval_present=True,
                signing_present=True,
            )
            r = certify_fn(s)
            q = r.receipt
            try:
                if kind in ("tamper", "disposition"):
                    q = replace_fn(q, disposition=disposition_cls.REJECTED)
                elif kind == "verification":
                    q = replace_fn(
                        q,
                        verification=reduce_fn(
                            observation_status_cls.VALID, (status_cls.FAIL,), ("VERIFIER_FAILED",)
                        ),
                    )
                elif kind == "policy":
                    q = replace_fn(q, policy=policy_cls(False, True, True, True))
                elif kind == "prerequisite":
                    q = replace_fn(q, policy=policy_cls(True, None, True, True))
                elif kind == "claimed_hash":
                    q = replace_fn(q, claimed_receipt_hash=hash_fn("tampered-receipt"))
            except (TypeError, ValueError):
                return outcome_cls("RECEIPT_INVALID")
            return outcome_cls("RECEIPT_INVALID" if not validate_fn(q, s) else "RECEIPT_VALID")

        def special_fn(kind: str):
            s = input_fn(
                policy_accepted=True,
                authority_present=True,
                approval_present=True,
                signing_present=True,
            )
            evidence = replace_fn(
                s.evidence,
                **(
                    {"change_set_hash": hash_fn("different-change-set")}
                    if kind == "stale"
                    else {"claimed_bundle_hash": hash_fn("tampered-evidence")}
                ),
            )
            r = certify_fn(replace_fn(s, evidence=evidence))
            return outcome_cls(
                "CERTIFICATION",
                r.verification.status.value,
                r.verification.integrity.value,
                r.disposition.value,
            )

        def dispatch(op: str, params: Mapping[str, Any]):
            q = dict(params)
            marker = q.get("observations")
            if op == "direct":
                if marker == "fail":
                    q["observations"] = (
                        observation_cls("unit", "artifact-unit", hash_fn("unit"), status_cls.FAIL),
                        observation_cls("lint", "artifact-lint", hash_fn("lint"), status_cls.PASS),
                    )
                elif marker == "missing":
                    q["observations"] = (
                        observation_cls("unit", "u", hash_fn("u"), status_cls.PASS),
                    )
                elif marker == "duplicate_verifier":
                    q["observations"] = (
                        observation_cls("unit", "u", hash_fn("u"), status_cls.PASS),
                        observation_cls("unit", "l", hash_fn("l"), status_cls.PASS),
                    )
                elif marker == "duplicate_artifact":
                    q["observations"] = (
                        observation_cls("unit", "same", hash_fn("u"), status_cls.PASS),
                        observation_cls("lint", "same", hash_fn("l"), status_cls.PASS),
                    )
                return direct_fn(**q)
            if op == "legacy":
                return legacy_fn(**q)
            if op == "reject":
                return reject_fn(**q)
            if op == "receipt":
                return receipt_fn(**q)
            return special_fn(q["kind"])

        return dispatch

    def _make_hash_context():
        dumps, sha256, isfinite, fraction_cls = json.dumps, hashlib.sha256, math.isfinite, Fraction

        def canonical(value: Any) -> str:
            active: set[int] = set()

            def enc(v: Any) -> Any:
                if v is None or type(v) in (bool, int, str):
                    return v
                if type(v) is float:
                    if not isfinite(v):
                        raise ValueError("non-finite")
                    return v
                if isinstance(v, Mapping):
                    if any(type(k) is not str for k in v):
                        raise TypeError("mapping key")
                    if id(v) in active:
                        raise ValueError("cycle")
                    active.add(id(v))
                    try:
                        return {k: enc(v[k]) for k in sorted(v)}
                    finally:
                        active.remove(id(v))
                if isinstance(v, (list, tuple)):
                    if id(v) in active:
                        raise ValueError("cycle")
                    active.add(id(v))
                    try:
                        return [enc(x) for x in v]
                    finally:
                        active.remove(id(v))
                raise TypeError(type(v).__name__)

            return dumps(
                enc(value),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )

        def digest(value: Any) -> str:
            return "sha256:" + sha256(canonical(value).encode()).hexdigest()

        def rate(n: int, d: int) -> float | None:
            return round(float(fraction_cls(n, d)), 12) if d else None

        def false(c: CaseDefinition, a: CaseOutcome) -> bool:
            return c.hostile and a.outcome_kind == "CERTIFICATION" and a.disposition == "CERTIFIED"

        def shape(p: Mapping[str, Any]) -> list[str]:
            # Stable ordering is part of the verifier interface.
            errors: list[str] = []
            for key in sorted(p):
                if key not in _required:
                    errors.append(key)
            for key in sorted(_required):
                if key not in p:
                    errors.append(key)
            if errors:
                return sorted(set(errors))

            def exact(path: str, value: Any, typ: type, nullable: bool = False) -> None:
                if not (nullable and value is None) and type(value) is not typ:
                    errors.append(path)

            for key in (
                "schema",
                "benchmark_id",
                "task_set_hash",
                "protocol_version",
                "implementation_schema",
                "public_claim_gate",
            ):
                exact(key, p[key], str)
            for key in ("case_ids", "claim_ceiling", "cases"):
                exact(key, p[key], list)
            for key in (
                "eligible_count",
                "infra_invalid_count",
                "hostile_case_count",
                "detected_count",
                "false_completion_count",
                "trust_mismatch_count",
            ):
                if type(p[key]) is not int or p[key] < 0:
                    errors.append(key)
            for key in ("false_completion_rate", "detection_rate", "trust_mismatch_rate"):
                if p[key] is not None and (type(p[key]) is not float or not isfinite(p[key])):
                    errors.append(key)
            if type(p["cases"]) is list:
                allowed = {"case_id", "expected", "actual", "detected", "infra_invalid", "error"}
                outcome = {
                    "outcome_kind",
                    "verification_status",
                    "evidence_condition",
                    "disposition",
                }
                for i, case in enumerate(p["cases"]):
                    path = f"cases[{i}]"
                    if type(case) is not dict:
                        errors.append(path)
                        continue
                    errors.extend(f"{path}.{k}" for k in sorted(set(case) ^ allowed))
                    for k in sorted(allowed & set(case)):
                        if k in ("case_id",):
                            exact(f"{path}.{k}", case[k], str)
                        elif k in ("detected", "infra_invalid"):
                            exact(f"{path}.{k}", case[k], bool)
                        elif k == "error":
                            exact(f"{path}.{k}", case[k], str, True)
                    for k in sorted(allowed - set(case)):
                        errors.append(f"{path}.{k}")
                    for name in ("expected", "actual"):
                        qp = f"{path}.{name}"
                        q = case.get(name)
                        if type(q) is not dict:
                            errors.append(qp)
                            continue
                        errors.extend(f"{qp}.{k}" for k in sorted(set(q) ^ outcome))
                        for k in sorted(outcome - set(q)):
                            errors.append(f"{qp}.{k}")
                        for k in sorted(outcome & set(q)):
                            exact(f"{qp}.{k}", q[k], str, k != "outcome_kind")
            return sorted(set(errors))

        return canonical, digest, rate, shape, false

    run_spec, verify_spec = _make_specs(), _make_specs()
    run_dispatch, verify_dispatch = _make_execution_context(), _make_execution_context()
    _run_canonical, run_digest, run_rate, _run_shape, run_false = _make_hash_context()
    _verify_canonical, verify_digest, verify_rate, verify_shape, verify_false = _make_hash_context()
    task_hash = TASK_SET_HASH
    schema_const, benchmark_id_const = BENCHMARK_SCHEMA, BENCHMARK_ID
    protocol_const, implementation_const = PUBLIC_PROTOCOL_VERSION, IMPLEMENTATION_SCHEMA
    claim_gate_const, ceiling_const = PUBLIC_CLAIM_GATE, CLAIM_CEILING
    result_cls, outcome_cls, report_cls = classes
    false_predicate, rate, digest = run_false, run_rate, run_digest
    _required = frozenset(
        {
            "schema",
            "benchmark_id",
            "task_set_hash",
            "protocol_version",
            "implementation_schema",
            "case_ids",
            "eligible_count",
            "infra_invalid_count",
            "hostile_case_count",
            "detected_count",
            "false_completion_count",
            "false_completion_rate",
            "detection_rate",
            "trust_mismatch_count",
            "trust_mismatch_rate",
            "public_claim_gate",
            "claim_ceiling",
            "cases",
            "report_hash",
        }
    )

    def execute(spec, dispatch):
        rows = []
        for case in spec:
            try:
                actual = dispatch(case.operation, case.params)
                rows.append(
                    result_cls(
                        case.case_id,
                        case.expected,
                        actual,
                        case.hostile
                        and actual == case.expected
                        and not false_predicate(case, actual),
                    )
                )
            except (TypeError, ValueError) as exc:
                if case.operation == "receipt":
                    invalid = outcome_cls("RECEIPT_INVALID")
                    rows.append(
                        result_cls(
                            case.case_id,
                            case.expected,
                            invalid,
                            case.hostile and invalid == case.expected,
                            False,
                            type(exc).__name__,
                        )
                    )
                    continue
                rows.append(
                    result_cls(
                        case.case_id,
                        case.expected,
                        outcome_cls("INFRA_INVALID"),
                        False,
                        True,
                        type(exc).__name__,
                    )
                )
            except Exception as exc:
                rows.append(
                    result_cls(
                        case.case_id,
                        case.expected,
                        outcome_cls("INFRA_INVALID"),
                        False,
                        True,
                        type(exc).__name__,
                    )
                )
        return tuple(rows)

    def aggregate(spec, rows):
        eligible = tuple(r for r in rows if not r.infra_invalid)
        hostile = sum(c.hostile for c, r in zip(spec, rows) if not r.infra_invalid)
        false = sum(false_predicate(c, r.actual) for c, r in zip(spec, rows) if not r.infra_invalid)
        detected = sum(r.detected for r in eligible)
        mismatch = sum(r.actual != r.expected for r in eligible)
        payload = {
            "schema": schema_const,
            "benchmark_id": benchmark_id_const,
            "task_set_hash": task_hash,
            "protocol_version": protocol_const,
            "implementation_schema": implementation_const,
            "case_ids": [r.case_id for r in rows],
            "eligible_count": len(eligible),
            "infra_invalid_count": len(rows) - len(eligible),
            "hostile_case_count": hostile,
            "detected_count": detected,
            "false_completion_count": false,
            "false_completion_rate": rate(false, hostile),
            "detection_rate": rate(detected, hostile),
            "trust_mismatch_count": mismatch,
            "trust_mismatch_rate": rate(mismatch, len(eligible)),
            "public_claim_gate": claim_gate_const,
            "claim_ceiling": list(ceiling_const),
            "cases": [r.to_dict() for r in rows],
        }
        return report_cls(
            **{k: v for k, v in payload.items() if k not in ("case_ids", "claim_ceiling", "cases")},
            case_ids=tuple(payload["case_ids"]),
            claim_ceiling=ceiling_const,
            cases=rows,
            report_hash=digest(payload),
        )

    def produce():
        return aggregate(run_spec, execute(run_spec, run_dispatch))

    def check(report):
        try:
            false_predicate, rate, digest, shape = (
                verify_false,
                verify_rate,
                verify_digest,
                verify_shape,
            )
            payload = report.payload() if isinstance(report, report_cls) else dict(report)
            required = {
                "schema",
                "benchmark_id",
                "task_set_hash",
                "protocol_version",
                "implementation_schema",
                "case_ids",
                "eligible_count",
                "infra_invalid_count",
                "hostile_case_count",
                "detected_count",
                "false_completion_count",
                "false_completion_rate",
                "detection_rate",
                "trust_mismatch_count",
                "trust_mismatch_rate",
                "public_claim_gate",
                "claim_ceiling",
                "cases",
                "report_hash",
            }
            # Unknown keys precede missing keys, each in lexical order; this
            # remains stable across mapping insertion order and hash seeds.
            errors = sorted(k for k in payload if k not in required) + sorted(
                k for k in required if k not in payload
            )
            if errors:
                return tuple(errors)
            errors.extend(shape(payload))
            if errors:
                return tuple(dict.fromkeys(errors))
            if payload["report_hash"] != digest(
                {k: v for k, v in payload.items() if k != "report_hash"}
            ):
                errors.append("report_hash")
            # Independent verifier execution and aggregation; producer helpers are not used.
            rows = []
            for case in verify_spec:
                try:
                    actual = verify_dispatch(case.operation, case.params)
                    rows.append(
                        result_cls(
                            case.case_id,
                            case.expected,
                            actual,
                            case.hostile
                            and actual == case.expected
                            and not false_predicate(case, actual),
                        )
                    )
                except (TypeError, ValueError) as exc:
                    if case.operation == "receipt":
                        invalid = outcome_cls("RECEIPT_INVALID")
                        rows.append(
                            result_cls(
                                case.case_id,
                                case.expected,
                                invalid,
                                case.hostile and invalid == case.expected,
                                False,
                                type(exc).__name__,
                            )
                        )
                        continue
                    rows.append(
                        result_cls(
                            case.case_id,
                            case.expected,
                            outcome_cls("INFRA_INVALID"),
                            False,
                            True,
                            type(exc).__name__,
                        )
                    )
                except Exception as exc:
                    rows.append(
                        result_cls(
                            case.case_id,
                            case.expected,
                            outcome_cls("INFRA_INVALID"),
                            False,
                            True,
                            type(exc).__name__,
                        )
                    )
            eligible = tuple(r for r in rows if not r.infra_invalid)
            hostile = sum(c.hostile for c, r in zip(verify_spec, rows) if not r.infra_invalid)
            false = sum(
                false_predicate(c, r.actual)
                for c, r in zip(verify_spec, rows)
                if not r.infra_invalid
            )
            detected = sum(r.detected for r in eligible)
            mismatch = sum(r.actual != r.expected for r in eligible)
            expected = {
                "schema": schema_const,
                "benchmark_id": benchmark_id_const,
                "task_set_hash": task_hash,
                "protocol_version": protocol_const,
                "implementation_schema": implementation_const,
                "case_ids": [r.case_id for r in rows],
                "eligible_count": len(eligible),
                "infra_invalid_count": len(rows) - len(eligible),
                "hostile_case_count": hostile,
                "detected_count": detected,
                "false_completion_count": false,
                "false_completion_rate": rate(false, hostile),
                "detection_rate": rate(detected, hostile),
                "trust_mismatch_count": mismatch,
                "trust_mismatch_rate": rate(mismatch, len(eligible)),
                "public_claim_gate": claim_gate_const,
                "claim_ceiling": list(ceiling_const),
                "cases": [r.to_dict() for r in rows],
            }
            for key, value in expected.items():
                if payload[key] != value:
                    errors.append(key)
            return tuple(dict.fromkeys(errors))
        except Exception:
            return ("malformed_report",)

    return produce, check


run_benchmark, verify_report = _make_public_api()
__all__ = [
    "BENCHMARK_SCHEMA",
    "BENCHMARK_ID",
    "TASK_SET_HASH",
    "EXPECTED_CASE_IDS",
    "CASE_SPEC",
    "CASES",
    "CaseDefinition",
    "BenchmarkCaseResult",
    "FalseCompletionReport",
    "run_benchmark",
    "verify_report",
]
