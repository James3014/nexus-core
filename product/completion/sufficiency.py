"""Deterministic evidence-sufficiency projection (nexus-core#58)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from weakref import WeakValueDictionary

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
from product.verification import verify

__all__ = [
    "SUFFICIENCY_SCHEMA",
    "SUFFICIENCY_CLAIM_CEILING",
    "EvidenceSufficiency",
    "SufficiencySubjectReport",
    "EvidenceSufficiencyAnalysis",
    "SufficiencyRequest",
    "analyze_evidence_sufficiency",
    "validate_evidence_sufficiency_analysis",
    "is_evidence_sufficiency_analysis",
]
SUFFICIENCY_SCHEMA = "nexus-core.evidence-sufficiency-projection.v1"
SUFFICIENCY_CLAIM_CEILING = "DETERMINISTIC_EVIDENCE_SUFFICIENCY_PROJECTION_ONLY"
_HASH_PREFIX = "sha256:"


class EvidenceSufficiency(str, Enum):
    SUFFICIENT = "SUFFICIENT"
    MISSING = "MISSING"
    STALE = "STALE"
    CONTRADICTORY = "CONTRADICTORY"
    FAILED = "FAILED"
    INAPPLICABLE = "INAPPLICABLE"


def _require_normalized_text(value, field):
    if type(value) is not str:
        raise TypeError(f"{field} must be a string")
    if not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{field} must be non-empty and normalized")
    return value


def _require_hash(value, field):
    text = _require_normalized_text(value, field)
    if not text.startswith(_HASH_PREFIX):
        raise ValueError(f"{field} must be a sha256:<hex> content hash")
    tail = text[len(_HASH_PREFIX) :]
    if len(tail) != 64 or any(c not in "0123456789abcdef" for c in tail):
        raise ValueError(f"{field} must be a sha256:<64 lowercase hex> content hash")
    return text


@dataclass(frozen=True)
class SufficiencySubjectReport:
    verifier_id: str
    artifact_id: str
    observed_artifact_hash: str
    expected_content_hash: str
    status: ObservationStatus
    sufficiency: EvidenceSufficiency
    reason_codes: tuple = ()

    def __post_init__(self):
        _require_normalized_text(self.verifier_id, "verifier_id")
        if type(self.artifact_id) is not str:
            raise TypeError("artifact_id must be a string")
        if type(self.observed_artifact_hash) is not str:
            raise TypeError("observed_artifact_hash must be a string")
        if type(self.expected_content_hash) is not str:
            raise TypeError("expected_content_hash must be a string")
        if type(self.status) is not ObservationStatus:
            raise TypeError("status must be ObservationStatus")
        if type(self.sufficiency) is not EvidenceSufficiency:
            raise TypeError("sufficiency must be EvidenceSufficiency")
        if type(self.reason_codes) is not tuple:
            raise TypeError("reason_codes must be a tuple")
        for code in self.reason_codes:
            if type(code) is not str or not code or code != code.strip() or len(code) > 128:
                raise ValueError("reason_codes must contain bounded nonblank strings")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("reason_codes must be unique and sorted")


@dataclass(frozen=True)
class SufficiencyRequest:
    request_id: str
    subject_scope: str
    applicable: bool = True

    def __post_init__(self):
        _require_normalized_text(self.request_id, "request_id")
        _require_normalized_text(self.subject_scope, "subject_scope")
        if type(self.applicable) is not bool:
            raise TypeError("applicable must be a bool")


def _project_subject(
    verifier_id: str, observation: Observation | None, expected_hash, core_integrity, stale_evidence
):
    if observation is None:
        return SufficiencySubjectReport(
            verifier_id=verifier_id,
            artifact_id="",
            observed_artifact_hash="",
            expected_content_hash=expected_hash,
            status=ObservationStatus.FAIL,
            sufficiency=EvidenceSufficiency.MISSING,
            reason_codes=(f"MISSING:verifier:{verifier_id}",),
        )
    if stale_evidence or core_integrity in (
        IntegrityStatus.STALE,
        IntegrityStatus.CROSS_BOUND,
        IntegrityStatus.CROSS_BINDING_INVALID,
    ):
        return SufficiencySubjectReport(
            verifier_id=observation.verifier_id,
            artifact_id=observation.artifact_id,
            observed_artifact_hash=observation.artifact_hash,
            expected_content_hash=expected_hash,
            status=observation.status,
            sufficiency=EvidenceSufficiency.STALE,
            reason_codes=(f"STALE:verifier:{verifier_id}",),
        )
    if core_integrity is IntegrityStatus.MISSING:
        return SufficiencySubjectReport(
            verifier_id=observation.verifier_id,
            artifact_id=observation.artifact_id,
            observed_artifact_hash=observation.artifact_hash,
            expected_content_hash=expected_hash,
            status=observation.status,
            sufficiency=EvidenceSufficiency.MISSING,
            reason_codes=(f"MISSING:verifier:{verifier_id}",),
        )
    if core_integrity is not IntegrityStatus.VALID:
        return SufficiencySubjectReport(
            verifier_id=observation.verifier_id,
            artifact_id=observation.artifact_id,
            observed_artifact_hash=observation.artifact_hash,
            expected_content_hash=expected_hash,
            status=observation.status,
            sufficiency=EvidenceSufficiency.FAILED,
            reason_codes=(f"FAILED:integrity:{core_integrity.value}",),
        )
    if expected_hash and observation.artifact_hash != expected_hash:
        return SufficiencySubjectReport(
            verifier_id=observation.verifier_id,
            artifact_id=observation.artifact_id,
            observed_artifact_hash=observation.artifact_hash,
            expected_content_hash=expected_hash,
            status=observation.status,
            sufficiency=EvidenceSufficiency.STALE,
            reason_codes=(f"STALE:verifier:{verifier_id}",),
        )
    if observation.status is not ObservationStatus.PASS:
        return SufficiencySubjectReport(
            verifier_id=observation.verifier_id,
            artifact_id=observation.artifact_id,
            observed_artifact_hash=observation.artifact_hash,
            expected_content_hash=expected_hash,
            status=observation.status,
            sufficiency=EvidenceSufficiency.CONTRADICTORY,
            reason_codes=(f"CONTRADICTORY:verifier:{verifier_id}",),
        )
    return SufficiencySubjectReport(
        verifier_id=observation.verifier_id,
        artifact_id=observation.artifact_id,
        observed_artifact_hash=observation.artifact_hash,
        expected_content_hash=expected_hash,
        status=observation.status,
        sufficiency=EvidenceSufficiency.SUFFICIENT,
        reason_codes=(),
    )


def _make_analyzer():
    registry = WeakValueDictionary()

    def analyze_evidence_sufficiency(
        request, contract, change_set, plan, evidence, expected_by_verifier=None
    ):
        if type(request) is not SufficiencyRequest:
            raise TypeError("request must be SufficiencyRequest")
        if type(contract) is not AcceptanceContract:
            raise TypeError("contract must be AcceptanceContract")
        if type(change_set) is not ChangeSet:
            raise TypeError("change_set must be ChangeSet")
        if type(plan) is not VerificationPlan:
            raise TypeError("plan must be VerificationPlan")
        if type(evidence) is not EvidenceBundle:
            raise TypeError("evidence must be EvidenceBundle")
        if expected_by_verifier is not None and not isinstance(expected_by_verifier, dict):
            raise TypeError("expected_by_verifier must be a dict or None")
        if not request.applicable:
            result = object.__new__(EvidenceSufficiencyAnalysis)
            object.__setattr__(result, "sufficiency", EvidenceSufficiency.INAPPLICABLE)
            object.__setattr__(result, "subject_reports", ())
            object.__setattr__(result, "reason_codes", ("SCOPE:inapplicable",))
            object.__setattr__(result, "integrity", IntegrityStatus.VALID)
            object.__setattr__(result, "schema", SUFFICIENCY_SCHEMA)
            object.__setattr__(result, "claim_ceiling", SUFFICIENCY_CLAIM_CEILING)
            EvidenceSufficiencyAnalysis.__post_init__(result)
            registry[id(result)] = result
            return result
        expected_map = {}
        if expected_by_verifier:
            for vid, ch in expected_by_verifier.items():
                _require_normalized_text(vid, "expected_by_verifier.verifier_id")
                _require_hash(ch, f"expected_by_verifier[{vid}]")
                if vid not in plan.required_verifier_ids:
                    raise ValueError(f"expected_by_verifier[{vid}] outside required plan")
                expected_map[vid] = ch
        core = verify(contract, change_set, plan, evidence)
        stale_evidence = core.integrity in (
            IntegrityStatus.STALE,
            IntegrityStatus.CROSS_BOUND,
            IntegrityStatus.CROSS_BINDING_INVALID,
        )
        observations = {obs.verifier_id: obs for obs in evidence.observations}
        reports = []
        for vid in sorted(plan.required_verifier_ids):
            reports.append(
                _project_subject(
                    vid,
                    observations.get(vid),
                    expected_map.get(vid, ""),
                    core.integrity,
                    stale_evidence,
                )
            )
        report_tuple = tuple(reports)
        reasons = []
        kinds = {r.sufficiency for r in report_tuple}
        if not report_tuple:
            overall = EvidenceSufficiency.MISSING
            reasons.append("MISSING:required-subjects:empty-plan")
        elif EvidenceSufficiency.CONTRADICTORY in kinds:
            overall = EvidenceSufficiency.CONTRADICTORY
        elif EvidenceSufficiency.STALE in kinds:
            overall = EvidenceSufficiency.STALE
        elif EvidenceSufficiency.FAILED in kinds:
            overall = EvidenceSufficiency.FAILED
        elif EvidenceSufficiency.MISSING in kinds:
            overall = EvidenceSufficiency.MISSING
        else:
            overall = EvidenceSufficiency.SUFFICIENT
        for r in report_tuple:
            reasons.extend(r.reason_codes)
        result = object.__new__(EvidenceSufficiencyAnalysis)
        object.__setattr__(result, "sufficiency", overall)
        object.__setattr__(result, "subject_reports", report_tuple)
        object.__setattr__(result, "reason_codes", tuple(sorted(set(reasons))))
        object.__setattr__(result, "integrity", core.integrity)
        object.__setattr__(result, "schema", SUFFICIENCY_SCHEMA)
        object.__setattr__(result, "claim_ceiling", SUFFICIENCY_CLAIM_CEILING)
        EvidenceSufficiencyAnalysis.__post_init__(result)
        registry[id(result)] = result
        return result

    return analyze_evidence_sufficiency, registry


analyze_evidence_sufficiency, _sufficiency_registry = _make_analyzer()
del _make_analyzer


@dataclass(frozen=True, init=False)
class EvidenceSufficiencyAnalysis:
    sufficiency: EvidenceSufficiency
    subject_reports: tuple
    reason_codes: tuple
    integrity: IntegrityStatus
    schema: str
    claim_ceiling: str

    def __init__(self, *args, **kwargs):
        raise TypeError("EvidenceSufficiencyAnalysis is created by analyze_evidence_sufficiency")

    def __post_init__(self):
        if type(self.sufficiency) is not EvidenceSufficiency:
            raise TypeError("sufficiency must be EvidenceSufficiency")
        if type(self.subject_reports) is not tuple or any(
            type(r) is not SufficiencySubjectReport for r in self.subject_reports
        ):
            raise TypeError("subject_reports must contain SufficiencySubjectReport values")
        if type(self.reason_codes) is not tuple:
            raise TypeError("reason_codes must be a tuple")
        for code in self.reason_codes:
            if type(code) is not str or not code or code != code.strip() or len(code) > 128:
                raise ValueError("reason_codes must contain bounded nonblank strings")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("reason_codes must be unique and sorted")
        if not isinstance(self.integrity, IntegrityStatus):
            raise TypeError("integrity must be IntegrityStatus")
        if self.schema != SUFFICIENCY_SCHEMA:
            raise ValueError("schema must be the sufficiency projection schema")
        if self.claim_ceiling != SUFFICIENCY_CLAIM_CEILING:
            raise ValueError("claim_ceiling must be the sufficiency projection ceiling")

    @property
    def hash(self):
        return _hash(
            (
                self.sufficiency.value,
                tuple(
                    (
                        r.verifier_id,
                        r.artifact_id,
                        r.observed_artifact_hash,
                        r.expected_content_hash,
                        r.status.value,
                        r.sufficiency.value,
                        r.reason_codes,
                    )
                    for r in self.subject_reports
                ),
                self.reason_codes,
                self.integrity.value,
                self.schema,
                self.claim_ceiling,
            )
        )

    def to_dict(self):
        return {
            "schema": self.schema,
            "claim_ceiling": self.claim_ceiling,
            "sufficiency": self.sufficiency.value,
            "subject_reports": [
                {
                    "verifier_id": r.verifier_id,
                    "artifact_id": r.artifact_id,
                    "observed_artifact_hash": r.observed_artifact_hash,
                    "expected_content_hash": r.expected_content_hash,
                    "status": r.status.value,
                    "sufficiency": r.sufficiency.value,
                    "reason_codes": list(r.reason_codes),
                }
                for r in self.subject_reports
            ],
            "reason_codes": list(self.reason_codes),
            "integrity": self.integrity.value,
        }


def is_evidence_sufficiency_analysis(analysis):
    return (
        isinstance(analysis, EvidenceSufficiencyAnalysis)
        and _sufficiency_registry.get(id(analysis)) is analysis
    )


def _make_analysis_validator():
    def validate_evidence_sufficiency_analysis(
        analysis, request, contract, change_set, plan, evidence, expected_by_verifier=None
    ):
        if not is_evidence_sufficiency_analysis(analysis):
            return False
        try:
            recomputed = analyze_evidence_sufficiency(
                request,
                contract,
                change_set,
                plan,
                evidence,
                expected_by_verifier=expected_by_verifier,
            )
        except (TypeError, ValueError):
            return False
        return recomputed.hash == analysis.hash

    return validate_evidence_sufficiency_analysis


validate_evidence_sufficiency_analysis = _make_analysis_validator()
del _make_analysis_validator
