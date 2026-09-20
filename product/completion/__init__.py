"""Completion Core - completion evidence applicability and freshness contract.

Deterministic, advisory analysis that binds a completion claim to the exact
changed content it claims, then decides whether verification evidence
actually applies to that final state. It never certifies anything: the
completion claim and any ``asserted_by`` identity are advisory inputs only,
and certification authority remains with :func:`product.kernel.certify`.

The contract answers three explicit semantic states:

- ``CLAIMS_COMPLETE`` - a completion claim is present, revision-bound to the
  change set, and covers every changed (non-deleted) path with a claimed
  final content hash.
- ``VERIFICATION_APPLIES`` - every required verifier has an evidence
  observation that is bound to a changed path, observes the claimed final
  content hash (freshness), and reports PASS. An observation that does not
  apply to the changed artifact is irrelevant even if it PASSed.
- ``CLAIMS_VERIFIED`` - the conjunction of the two states above together
  with the existing deterministic Core verification result
  (:func:`product.verification.verify`). A claim assertion can never
  substitute for the physical evidence an observation provides.

Evidence dispositions are explicit so consumers can explain exactly which
evidence was accepted, rejected (stale / irrelevant / failed), missing, or
contradictory. Freshness and execution ordering are derived from content
hash comparison rather than wall-clock timestamps: if the observed artifact
content hash differs from the claimed final content hash, the observation
predates a later mutation and is stale unless equivalence is proven by the
trusted content-hash machinery (i.e. the hashes are equal).

The package intentionally introduces no new dependency and does not modify
the public protocol schema, protocol version, or existing Core authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any
from weakref import WeakValueDictionary

from product.evidence import (
    AcceptanceContract,
    ChangeSet,
    EvidenceBundle,
    IntegrityStatus,
    ObservationStatus,
    VerificationPlan,
    _hash,
)
from product.verification import VerificationStatus, verify

__all__ = [
    "CompletionClaim",
    "EvidenceDisposition",
    "VerifierEvidenceReport",
    "CompletionEvidenceAnalysis",
    "analyze_completion_evidence",
    "validate_completion_evidence_analysis",
    "is_completion_evidence_analysis",
]

_HASH_RE_PREFIX = "sha256:"


class EvidenceDisposition(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED_STALE = "REJECTED_STALE"
    REJECTED_IRRELEVANT = "REJECTED_IRRELEVANT"
    REJECTED_MISSING = "REJECTED_MISSING"
    REJECTED_CONTRADICTORY = "REJECTED_CONTRADICTORY"
    REJECTED_FAILED = "REJECTED_FAILED"


def _require_normalized_text(value, field):
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{field} must be a non-empty normalized string")


def _require_hash(value, field):
    _require_normalized_text(value, field)
    if not value.startswith(_HASH_RE_PREFIX):
        raise ValueError(f"{field} must be a sha256:<hex> content hash")
    tail = value[len(_HASH_RE_PREFIX) :]
    if len(tail) != 64 or any(c not in "0123456789abcdef" for c in tail):
        raise ValueError(f"{field} must be a sha256:<64 lowercase hex> content hash")


def _sorted_paths(paths):
    return tuple(sorted(set(paths)))


@dataclass(frozen=True)
class CompletionClaim:
    """Deterministic, advisory representation of the requested completed work.

    This is intentionally *not* an evidence type: it carries an ``asserted_by``
    identity (a model / agent) and its observations are claims, not physical
    evidence. Nothing in this package can turn a claim into certification.
    """

    claim_id: str
    target_revision: str
    content_hashes: tuple[tuple[str, str], ...]
    verified_artifacts: tuple[tuple[str, str, str], ...]
    asserted_by: str
    claimed_complete: bool = True

    def __post_init__(self):
        _require_normalized_text(self.claim_id, "claim_id")
        _require_normalized_text(self.target_revision, "target_revision")
        _require_normalized_text(self.asserted_by, "asserted_by")
        if type(self.claimed_complete) is not bool:
            raise TypeError("claimed_complete must be a bool")
        if type(self.content_hashes) is not tuple or not self.content_hashes:
            raise ValueError("content_hashes must be a non-empty tuple")
        paths = []
        for index, (path, content_hash) in enumerate(self.content_hashes):
            _require_normalized_text(path, f"content_hashes[{index}].path")
            if (
                path.startswith("/")
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
            ):
                raise ValueError(f"content_hashes[{index}].path must be a relative path")
            _require_hash(content_hash, f"content_hashes[{index}].content_hash")
            paths.append(path)
        if len(paths) != len(set(paths)):
            raise ValueError("content_hashes must not contain duplicate paths")
        if tuple(paths) != _sorted_paths(paths):
            raise ValueError("content_hashes paths must be unique and sorted")
        if type(self.verified_artifacts) is not tuple:
            raise TypeError("verified_artifacts must be a tuple")
        bindings = []
        for index, (verifier_id, artifact_id, path) in enumerate(self.verified_artifacts):
            _require_normalized_text(verifier_id, f"verified_artifacts[{index}].verifier_id")
            _require_normalized_text(artifact_id, f"verified_artifacts[{index}].artifact_id")
            _require_normalized_text(path, f"verified_artifacts[{index}].path")
            bindings.append((verifier_id, artifact_id))
            if path not in paths:
                raise ValueError(
                    f"verified_artifacts[{index}] must bind a path listed in content_hashes"
                )
        if type(bindings) is not list:
            raise TypeError("bindings must be a list")
        if len(bindings) != len(set(bindings)):
            raise ValueError("verified_artifacts must not contain duplicate verifier/artifact pairs")
        if tuple(bindings) != tuple(sorted(bindings)):
            raise ValueError("verified_artifacts must be unique and sorted")

    @property
    def hash(self):
        return _hash(
            (
                self.claim_id,
                self.target_revision,
                tuple(self.content_hashes),
                tuple(self.verified_artifacts),
                self.asserted_by,
                self.claimed_complete,
            )
        )


@dataclass(frozen=True)
class VerifierEvidenceReport:
    verifier_id: str
    artifact_id: str
    path: str
    observed_artifact_hash: str
    expected_content_hash: str
    status: ObservationStatus
    disposition: EvidenceDisposition
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self):
        _require_normalized_text(self.verifier_id, "verifier_id")
        if not isinstance(self.disposition, EvidenceDisposition):
            raise TypeError("disposition must be EvidenceDisposition")
        if not isinstance(self.status, ObservationStatus):
            raise TypeError("status must be ObservationStatus")
        if not isinstance(self.reason_codes, tuple):
            raise TypeError("reason_codes must be a tuple")
        for code in self.reason_codes:
            if (
                not isinstance(code, str)
                or not code
                or code != code.strip()
                or len(code) > 128
            ):
                raise ValueError("reason_codes must contain bounded nonblank strings")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("reason_codes must be unique and sorted")


def _coverage_line(claim, change_set):
    """Return (revision_bound, missing_paths) for the claim against the change set."""
    if claim is None:
        return False, tuple(path for path in change_set.paths if path not in change_set.deleted_paths)
    revision_bound = claim.target_revision == change_set.target_revision
    claimed_paths = {path for path, _ in claim.content_hashes}
    changed = set(change_set.paths) - set(change_set.deleted_paths)
    missing = tuple(sorted(path for path in changed if path not in claimed_paths))
    return revision_bound, missing


def _dispositions_for(claim, change_set, plan, evidence):
    """Deterministic per-required-verifier evidence dispositions."""
    expected_by_path = (
        {path: content_hash for path, content_hash in claim.content_hashes}
        if claim is not None
        else {}
    )
    binding_by_artifact = (
        {
            artifact_id: path
            for _, artifact_id, path in claim.verified_artifacts
        }
        if claim is not None
        else {}
    )
    observations_by_verifier = {
        obs.verifier_id: obs for obs in evidence.observations
    }
    changed = set(change_set.paths) - set(change_set.deleted_paths)
    reports = []
    for verifier_id in sorted(plan.required_verifier_ids):
        observation = observations_by_verifier.get(verifier_id)
        if observation is None:
            reports.append(
                VerifierEvidenceReport(
                    verifier_id=verifier_id,
                    artifact_id="",
                    path="",
                    observed_artifact_hash="",
                    expected_content_hash="",
                    status=ObservationStatus.FAIL,
                    disposition=EvidenceDisposition.REJECTED_MISSING,
                    reason_codes=(f"MISSING:verifier:{verifier_id}",),
                )
            )
            continue
        path = binding_by_artifact.get(observation.artifact_id)
        if path is None or path not in changed:
            reports.append(
                VerifierEvidenceReport(
                    verifier_id=verifier_id,
                    artifact_id=observation.artifact_id,
                    path=path or "",
                    observed_artifact_hash=observation.artifact_hash,
                    expected_content_hash="",
                    status=observation.status,
                    disposition=EvidenceDisposition.REJECTED_IRRELEVANT,
                    reason_codes=(f"IRRELEVANT:verifier:{verifier_id}",),
                )
            )
            continue
        expected_hash = expected_by_path.get(path)
        if expected_hash is None:
            reports.append(
                VerifierEvidenceReport(
                    verifier_id=verifier_id,
                    artifact_id=observation.artifact_id,
                    path=path,
                    observed_artifact_hash=observation.artifact_hash,
                    expected_content_hash="",
                    status=observation.status,
                    disposition=EvidenceDisposition.REJECTED_MISSING,
                    reason_codes=(f"MISSING:content-hash:path:{path}",),
                )
            )
            continue
        if observation.artifact_hash != expected_hash:
            reports.append(
                VerifierEvidenceReport(
                    verifier_id=verifier_id,
                    artifact_id=observation.artifact_id,
                    path=path,
                    observed_artifact_hash=observation.artifact_hash,
                    expected_content_hash=expected_hash,
                    status=observation.status,
                    disposition=EvidenceDisposition.REJECTED_STALE,
                    reason_codes=(f"STALE:verifier:{verifier_id}:path:{path}",),
                )
            )
            continue
        if observation.status is not ObservationStatus.PASS:
            reports.append(
                VerifierEvidenceReport(
                    verifier_id=verifier_id,
                    artifact_id=observation.artifact_id,
                    path=path,
                    observed_artifact_hash=observation.artifact_hash,
                    expected_content_hash=expected_hash,
                    status=observation.status,
                    disposition=EvidenceDisposition.REJECTED_CONTRADICTORY,
                    reason_codes=(f"CONTRADICTORY:verifier:{verifier_id}",),
                )
            )
            continue
        reports.append(
            VerifierEvidenceReport(
                verifier_id=verifier_id,
                artifact_id=observation.artifact_id,
                path=path,
                observed_artifact_hash=observation.artifact_hash,
                expected_content_hash=expected_hash,
                status=observation.status,
                disposition=EvidenceDisposition.ACCEPTED,
            )
        )
    return tuple(reports)


def _make_analyzer():
    registry = WeakValueDictionary()

    def analyze_completion_evidence(
        claim: CompletionClaim | None,
        contract: AcceptanceContract,
        change_set: ChangeSet,
        plan: VerificationPlan,
        evidence: EvidenceBundle,
    ) -> CompletionEvidenceAnalysis:
        """Derive completion semantic states and per-verifier dispositions.

        The core verification result (``verify``) is preserved as the
        underlying authority: the analysis cannot mark evidence verified that
        the deterministic Core would not certify.
        """
        if claim is not None and type(claim) is not CompletionClaim:
            raise TypeError("claim must be CompletionClaim or None")
        if type(contract) is not AcceptanceContract:
            raise TypeError("contract must be AcceptanceContract")
        if type(change_set) is not ChangeSet:
            raise TypeError("change_set must be ChangeSet")
        if type(plan) is not VerificationPlan:
            raise TypeError("plan must be VerificationPlan")
        if type(evidence) is not EvidenceBundle:
            raise TypeError("evidence must be EvidenceBundle")

        core = verify(contract, change_set, plan, evidence)
        reports = _dispositions_for(claim, change_set, plan, evidence)

        revision_bound, coverage_missing = _coverage_line(claim, change_set)
        reasons = []
        if claim is None:
            reasons.append("CLAIM:missing")
        elif not revision_bound:
            reasons.append("CLAIM:revision-mismatch")
        reasons.extend(f"CLAIM:content-coverage-missing:path:{path}" for path in coverage_missing)

        core_valid = (
            core.status is VerificationStatus.VERIFIED
            and core.integrity is IntegrityStatus.VALID
        )
        claims_complete = (
            claim is not None and claim.claimed_complete and revision_bound and not coverage_missing
        )
        verification_applies = bool(reports) and core_valid and all(
            report.disposition is EvidenceDisposition.ACCEPTED
            and report.status is ObservationStatus.PASS
            for report in reports
        )
        claims_verified = claims_complete and verification_applies

        states = tuple(
            sorted(
                name
                for name, flag in (
                    ("CLAIMS_COMPLETE", claims_complete),
                    ("CLAIMS_VERIFIED", claims_verified),
                    ("VERIFICATION_APPLIES", verification_applies),
                )
                if flag
            )
        )

        result = object.__new__(CompletionEvidenceAnalysis)
        object.__setattr__(result, "claims_complete", claims_complete)
        object.__setattr__(result, "claims_verified", claims_verified)
        object.__setattr__(result, "verification_applies", verification_applies)
        object.__setattr__(result, "semantic_states", states)
        object.__setattr__(result, "dispositions", reports)
        object.__setattr__(result, "reason_codes", tuple(sorted(set(reasons))))
        object.__setattr__(result, "integrity", core.integrity)
        CompletionEvidenceAnalysis.__post_init__(result)
        registry[id(result)] = result
        return result

    return analyze_completion_evidence, registry


analyze_completion_evidence, _analysis_registry = _make_analyzer()
del _make_analyzer


@dataclass(frozen=True, init=False)
class CompletionEvidenceAnalysis:
    """Sealed result of :func:`analyze_completion_evidence`.

    Instances are only produced by the analyzer; construction elsewhere
    raises TypeError. The value is fully hash-bound: the verification helper
    recomputes the analysis from neutral inputs and compares hashes.
    """

    claims_complete: bool
    claims_verified: bool
    verification_applies: bool
    semantic_states: tuple[str, ...]
    dispositions: tuple[VerifierEvidenceReport, ...]
    reason_codes: tuple[str, ...]
    integrity: IntegrityStatus

    def __init__(self, *args, **kwargs):
        raise TypeError("CompletionEvidenceAnalysis is created by analyze_completion_evidence")

    def __post_init__(self):
        if type(self.claims_complete) is not bool:
            raise TypeError("claims_complete must be a bool")
        if type(self.claims_verified) is not bool:
            raise TypeError("claims_verified must be a bool")
        if type(self.verification_applies) is not bool:
            raise TypeError("verification_applies must be a bool")
        if not isinstance(self.integrity, IntegrityStatus):
            raise TypeError("integrity must be IntegrityStatus")
        if type(self.semantic_states) is not tuple:
            raise TypeError("semantic_states must be a tuple")
        allowed = {"CLAIMS_COMPLETE", "CLAIMS_VERIFIED", "VERIFICATION_APPLIES"}
        for state in self.semantic_states:
            if type(state) is not str or state not in allowed:
                raise ValueError("semantic_states must contain supported completion states")
        if self.semantic_states != tuple(sorted(set(self.semantic_states))):
            raise ValueError("semantic_states must be unique and sorted")
        if not isinstance(self.dispositions, tuple) or any(
            not isinstance(report, VerifierEvidenceReport) for report in self.dispositions
        ):
            raise TypeError("dispositions must contain VerifierEvidenceReport values")
        if not isinstance(self.reason_codes, tuple):
            raise TypeError("reason_codes must be a tuple")
        for code in self.reason_codes:
            if (
                not isinstance(code, str)
                or not code
                or code != code.strip()
                or len(code) > 128
            ):
                raise ValueError("reason_codes must contain bounded nonblank strings")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("reason_codes must be unique and sorted")
        has_complete = "CLAIMS_COMPLETE" in self.semantic_states
        has_verified = "CLAIMS_VERIFIED" in self.semantic_states
        has_applies = "VERIFICATION_APPLIES" in self.semantic_states
        if has_complete != self.claims_complete:
            raise ValueError("CLAIMS_COMPLETE state must match claims_complete")
        if has_verified != self.claims_verified:
            raise ValueError("CLAIMS_VERIFIED state must match claims_verified")
        if has_applies != self.verification_applies:
            raise ValueError("VERIFICATION_APPLIES state must match verification_applies")
        if self.claims_verified and not (self.claims_complete and self.verification_applies):
            raise ValueError("CLAIMS_VERIFIED requires CLAIMS_COMPLETE and VERIFICATION_APPLIES")
        if self.integrity is not IntegrityStatus.VALID and self.claims_verified:
            raise ValueError("CLAIMS_VERIFIED requires VALID evidence integrity")

    @property
    def hash(self):
        return _hash(
            (
                self.claims_complete,
                self.claims_verified,
                self.verification_applies,
                self.semantic_states,
                tuple(
                    (
                        report.verifier_id,
                        report.artifact_id,
                        report.path,
                        report.observed_artifact_hash,
                        report.expected_content_hash,
                        report.status.value,
                        report.disposition.value,
                        report.reason_codes,
                    )
                    for report in self.dispositions
                ),
                self.reason_codes,
                self.integrity.value,
            )
        )

    def to_dict(self):
        return {
            "claims_complete": self.claims_complete,
            "claims_verified": self.claims_verified,
            "verification_applies": self.verification_applies,
            "semantic_states": list(self.semantic_states),
            "dispositions": [
                {
                    "verifier_id": report.verifier_id,
                    "artifact_id": report.artifact_id,
                    "path": report.path,
                    "observed_artifact_hash": report.observed_artifact_hash,
                    "expected_content_hash": report.expected_content_hash,
                    "status": report.status.value,
                    "disposition": report.disposition.value,
                    "reason_codes": list(report.reason_codes),
                }
                for report in self.dispositions
            ],
            "reason_codes": list(self.reason_codes),
            "integrity": self.integrity.value,
        }


def is_completion_evidence_analysis(analysis: Any) -> bool:
    return (
        isinstance(analysis, CompletionEvidenceAnalysis)
        and _analysis_registry.get(id(analysis)) is analysis
    )


def _make_analysis_validator():
    def validate_completion_evidence_analysis(
        analysis: CompletionEvidenceAnalysis,
        claim: CompletionClaim | None,
        contract: AcceptanceContract,
        change_set: ChangeSet,
        plan: VerificationPlan,
        evidence: EvidenceBundle,
    ) -> bool:
        """Recompute the analysis from neutral inputs and hash-compare.

        Returns False if the supplied analysis is not the registered instance
        produced by the analyzer, does not hash-match a re-derivation, or any
        input is malformed. This mirrors the fail-closed recompute pattern used
        across Evidence Trust Core and the trusted certification adapter.
        """
        if not is_completion_evidence_analysis(analysis):
            return False
        try:
            recomputed = analyze_completion_evidence(claim, contract, change_set, plan, evidence)
        except (TypeError, ValueError):
            return False
        return recomputed.hash == analysis.hash

    return validate_completion_evidence_analysis


validate_completion_evidence_analysis = _make_analysis_validator()
del _make_analysis_validator