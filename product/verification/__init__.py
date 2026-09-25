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


class CoverageCategory(str, Enum):
    COVERED = "COVERED"
    NOT_COVERED = "NOT_COVERED"
    CONDITIONALLY_NOT_APPLICABLE = "CONDITIONALLY_NOT_APPLICABLE"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class CoverageEntry:
    logical_subject_id: str
    evidence_kind: str
    requirement_mode: str
    applicability: str
    category: CoverageCategory
    observed_status: ObservationStatus | None = None
    anomaly: str | None = None

    def __post_init__(self):
        if type(self.logical_subject_id) is not str or not self.logical_subject_id:
            raise ValueError("logical_subject_id must be a nonblank string")
        if type(self.evidence_kind) is not str or not self.evidence_kind:
            raise ValueError("evidence_kind must be a nonblank string")
        if type(self.requirement_mode) is not str or not self.requirement_mode:
            raise ValueError("requirement_mode must be a nonblank string")
        if type(self.applicability) is not str or not self.applicability:
            raise ValueError("applicability must be a nonblank string")
        if type(self.category) is not CoverageCategory:
            raise TypeError("category must be CoverageCategory")
        if self.observed_status is not None and type(self.observed_status) is not ObservationStatus:
            raise TypeError("observed_status must be ObservationStatus when present")
        if self.anomaly is not None and (type(self.anomaly) is not str or not self.anomaly):
            raise ValueError("anomaly must be a nonblank string when present")

    def to_dict(self):
        value = {
            "logical_subject_id": self.logical_subject_id,
            "evidence_kind": self.evidence_kind,
            "requirement_mode": self.requirement_mode,
            "applicability": self.applicability,
            "category": self.category.value,
        }
        if self.observed_status is not None:
            value["observed_status"] = self.observed_status.value
        if self.anomaly is not None:
            value["anomaly"] = self.anomaly
        return value


@dataclass(frozen=True)
class CoverageProjection:
    universe_generation: int
    universe_identity: str | None
    entries: tuple[CoverageEntry, ...]
    unexpected_subjects: tuple[tuple[str, str], ...]

    def __post_init__(self):
        if type(self.universe_generation) is not int or self.universe_generation < 0:
            raise ValueError("universe_generation must be a non-negative int")
        if self.universe_identity is not None and (
            type(self.universe_identity) is not str or not self.universe_identity
        ):
            raise ValueError("universe_identity must be a nonblank string when present")
        if type(self.entries) is not tuple:
            raise TypeError("entries must be a tuple")
        if any(type(entry) is not CoverageEntry for entry in self.entries):
            raise TypeError("entries must contain CoverageEntry values")
        if type(self.unexpected_subjects) is not tuple:
            raise TypeError("unexpected_subjects must be a tuple")
        for subject in self.unexpected_subjects:
            if (
                type(subject) is not tuple
                or len(subject) != 2
                or any(type(part) is not str or not part for part in subject)
            ):
                raise ValueError("unexpected_subjects must contain (logical_subject_id, kind) pairs")
        if self.entries != tuple(sorted(self.entries, key=lambda e: e.logical_subject_id)):
            raise ValueError("entries must be sorted by logical_subject_id")

    @property
    def covered(self):
        return tuple(
            entry for entry in self.entries if entry.category is CoverageCategory.COVERED
        )

    @property
    def not_covered(self):
        return tuple(
            entry for entry in self.entries if entry.category is CoverageCategory.NOT_COVERED
        )

    @property
    def unresolved(self):
        return tuple(
            entry for entry in self.entries if entry.category is CoverageCategory.UNRESOLVED
        )

    @property
    def conditionally_not_applicable(self):
        return tuple(
            entry
            for entry in self.entries
            if entry.category is CoverageCategory.CONDITIONALLY_NOT_APPLICABLE
        )

    def to_dict(self):
        value = {
            "universe_generation": self.universe_generation,
            "universe_identity": self.universe_identity,
            "entries": [entry.to_dict() for entry in self.entries],
            "unexpected_subjects": [
                {"logical_subject_id": subject[0], "evidence_kind": subject[1]}
                for subject in self.unexpected_subjects
            ],
        }
        if self.universe_identity:
            value["universe_identity"] = self.universe_identity
        return value


def derive_coverage(
    expected_subjects, observations, *, universe_generation, universe_identity
):
    """Pure reconciliation of expected logical subjects against observed evidence.

    Deterministic over its immutable inputs; never mutates and never invents
    universe entries. Observed rows that match no expected subject are reported
    as unexpected (informational only) so discovery cannot force a failure.
    """
    seen = {}
    for observation in observations:
        sid = vars(observation).get("logical_subject_id")
        if sid is None:
            continue
        seen[(sid, vars(observation).get("evidence_kind"))] = observation
    universe_keys = {(s.logical_subject_id, s.evidence_kind) for s in expected_subjects}
    unexpected_subjects = tuple(sorted(seen.keys() - universe_keys))

    entries = []
    for subject in sorted(expected_subjects, key=lambda s: s.logical_subject_id):
        sv = vars(subject)
        key = (sv["logical_subject_id"], sv["evidence_kind"])
        observed = seen.get(key)
        anomaly = None
        if observed is None:
            for other_id, other_kind in seen:
                if other_id == sv["logical_subject_id"] and other_kind != sv["evidence_kind"]:
                    anomaly = "EVIDENCE_KIND_MISMATCH"
                    break
        if sv["applicability"].value == "UNRESOLVED":
            category = CoverageCategory.UNRESOLVED
        elif sv["applicability"].value == "NOT_APPLICABLE":
            category = CoverageCategory.CONDITIONALLY_NOT_APPLICABLE
        elif observed is None:
            category = CoverageCategory.NOT_COVERED
        else:
            category = CoverageCategory.COVERED
        entries.append(
            CoverageEntry(
                logical_subject_id=sv["logical_subject_id"],
                evidence_kind=sv["evidence_kind"],
                requirement_mode=sv["requirement_mode"].value,
                applicability=sv["applicability"].value,
                category=category,
                observed_status=vars(observed)["status"] if observed is not None else None,
                anomaly=anomaly,
            )
        )
    return CoverageProjection(
        universe_generation=universe_generation,
        universe_identity=universe_identity,
        entries=tuple(entries),
        unexpected_subjects=unexpected_subjects,
    )


@dataclass(frozen=True, init=False)
class VerificationResult:
    status: VerificationStatus
    reason_codes: tuple[str, ...] = ()
    integrity: IntegrityStatus = IntegrityStatus.VALID
    coverage: CoverageProjection | None = None

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
        if self.coverage is not None and not isinstance(self.coverage, CoverageProjection):
            raise TypeError("coverage must be CoverageProjection when present")
        if self.status is VerificationStatus.VERIFIED and (
            self.integrity is not IntegrityStatus.VALID or self.reason_codes
        ):
            raise ValueError("VERIFIED requires valid integrity and no failed checks")
        if (
            self.integrity is not IntegrityStatus.VALID
            and self.status is not VerificationStatus.UNVERIFIABLE
        ):
            raise ValueError("non-valid integrity requires UNVERIFIABLE status")
        if self.coverage is not None and any(
            entry.category is CoverageCategory.UNRESOLVED for entry in self.coverage.entries
        ):
            if (
                self.status is not VerificationStatus.UNVERIFIABLE
                or "COVERAGE_UNRESOLVED" not in self.reason_codes
            ):
                raise ValueError("UNRESOLVED coverage requires UNVERIFIABLE + COVERAGE_UNRESOLVED")
        if self.coverage is not None and any(
            entry.category is CoverageCategory.NOT_COVERED for entry in self.coverage.entries
        ):
            if (
                self.status is not VerificationStatus.UNVERIFIABLE
                or self.integrity is not IntegrityStatus.MISSING
                or "MISSING" not in self.reason_codes
            ):
                raise ValueError("NOT_COVERED coverage requires UNVERIFIABLE + MISSING integrity")

    @property
    def failed_checks(self):
        return self.reason_codes

    def to_dict(self):
        value = {
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
        }
        if self.coverage is not None:
            value["coverage"] = self.coverage.to_dict()
        return value


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

    def reduce_verification(condition, observations=(), reasons=(), coverage=None):
        if not isinstance(condition, IntegrityStatus):
            raise TypeError("condition must be IntegrityStatus")
        _validate_reasons(reasons)
        if not isinstance(observations, tuple):
            raise TypeError("observations must be a tuple")
        if coverage is not None and not isinstance(coverage, CoverageProjection):
            raise TypeError("coverage must be CoverageProjection when present")
        codes = list(reasons)
        if condition is IntegrityStatus.SCOPE_ESCAPE:
            if not reasons:
                codes.append(condition.value)
            status, integrity = VerificationStatus.FAILED_VERIFICATION, IntegrityStatus.VALID
        elif condition is not IntegrityStatus.VALID:
            if not reasons:
                codes.append(condition.value)
            status, integrity = VerificationStatus.UNVERIFIABLE, condition
        elif coverage is not None:
            if any(
                entry.category is CoverageCategory.UNRESOLVED for entry in coverage.entries
            ):
                codes.append("COVERAGE_UNRESOLVED")
                status, integrity = VerificationStatus.UNVERIFIABLE, IntegrityStatus.VALID
            else:
                uncovered = [
                    entry for entry in coverage.entries
                    if entry.category is CoverageCategory.NOT_COVERED
                ]
                failed_covered = [
                    entry for entry in coverage.entries
                    if entry.category is CoverageCategory.COVERED
                    and entry.observed_status is ObservationStatus.FAIL
                ]
                if uncovered:
                    codes.append(IntegrityStatus.MISSING.value)
                    codes.extend(sorted(entry.logical_subject_id for entry in uncovered))
                    status, integrity = (
                        VerificationStatus.UNVERIFIABLE,
                        IntegrityStatus.MISSING,
                    )
                elif failed_covered:
                    codes.append("EVIDENCE_CLAIM_FAILED")
                    status, integrity = VerificationStatus.FAILED_VERIFICATION, IntegrityStatus.VALID
                elif not observations:
                    codes.append(IntegrityStatus.MISSING.value)
                    status, integrity = (
                        VerificationStatus.UNVERIFIABLE,
                        IntegrityStatus.MISSING,
                    )
                elif any(item is ObservationStatus.FAIL for item in observations):
                    codes.append("VERIFIER_FAILED")
                    status, integrity = VerificationStatus.FAILED_VERIFICATION, IntegrityStatus.VALID
                else:
                    status, integrity = VerificationStatus.VERIFIED, IntegrityStatus.VALID
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
        object.__setattr__(result, "coverage", coverage)
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
        if contract_data["deletion_policy"] == "FORBID" and change_data["deleted_paths"]:
            return reducer(integrity_status.SCOPE_ESCAPE, reasons=("DELETION_FORBIDDEN",))
        if set(contract_data["required_verifier_ids"]) != set(plan_data["required_verifier_ids"]):
            return reducer(integrity_status.MISSING)
        observations = evidence_data["observations"]
        obs = {vars(o)["verifier_id"]: o for o in observations}
        observed_ids = set(obs)
        if any(
            vars(o)["status"] not in {observation_status.PASS, observation_status.FAIL}
            for o in observations
        ):
            return reducer(integrity_status.MALFORMED)
        universe = contract_data["expected_subjects"]
        if not universe:
            if observed_ids != set(plan_data["required_verifier_ids"]):
                return reducer(integrity_status.MISSING)
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
        # Universe branch: derive coverage FIRST (dedupe by logical identity via
        # derive_coverage last-wins; duplicates never inflate it, and DUPLICATE
        # integrity has already failed closed above). required_verifier_ids
        # remains the sole verifier authority: coverage never grants it.
        # §22 dual-representation guard (conservative, namespace-safe): only when
        # the universe explicitly claims the same verifier-id namespace -- i.e. an
        # expected logical_subject_id exactly equals a required_verifier_id -- is
        # that subject's observation required to carry the matching verifier_id.
        # Namespaced logical ids (e.g. "verifier/unit-tests" vs "v1") impose no
        # coupling. A same-namespace mismatch fails closed as MALFORMED.
        coverage = derive_coverage(
            universe,
            observations,
            universe_generation=contract_data["universe_generation"],
            universe_identity=contract.universe_identity,
        )
        namespace_overlap = {
            subject.logical_subject_id for subject in universe
        } & set(contract_data["required_verifier_ids"])
        if namespace_overlap:
            observed_by_subject = {}
            for observation in observations:
                subject_id = vars(observation)["logical_subject_id"]
                if subject_id in namespace_overlap:
                    observed_by_subject[subject_id] = vars(observation)["verifier_id"]
            for subject_id in sorted(namespace_overlap):
                if (
                    subject_id in observed_by_subject
                    and observed_by_subject[subject_id] != subject_id
                ):
                    # Fail closed without coverage: attaching a projection that
                    # may contain NOT_COVERED/UNRESOLVED entries would violate
                    # the VerificationResult coverage invariants (which bind
                    # those categories to MISSING/COVERAGE_UNRESOLVED outcomes).
                    return reducer(integrity_status.MALFORMED)
        observed_verifier_ids = {vars(o)["verifier_id"] for o in observations}
        missing_verifiers = tuple(
            sorted(
                verifier_id
                for verifier_id in contract_data["required_verifier_ids"]
                if verifier_id not in observed_verifier_ids
            )
        )
        if missing_verifiers:
            reasons = tuple(sorted(set(missing_verifiers) | {"MISSING"}))
            if any(
                entry.category is CoverageCategory.UNRESOLVED for entry in coverage.entries
            ):
                reasons = tuple(sorted(set(reasons) | {"COVERAGE_UNRESOLVED"}))
            return reducer(
                integrity_status.MISSING, reasons=reasons, coverage=coverage
            )
        required_statuses = tuple(
            vars(obs[x])["status"] for x in contract_data["required_verifier_ids"]
        )
        failed = tuple(
            sorted(
                x
                for x in contract_data["required_verifier_ids"]
                if vars(obs[x])["status"] is not observation_status.PASS
            )
        )
        return reducer(
            integrity_status.VALID,
            required_statuses,
            failed,
            coverage=coverage,
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