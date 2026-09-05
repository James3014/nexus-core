"""Provider-neutral v2 ChangeSet certification wire contract."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any, Mapping

from product.certification import CertificationDisposition, CertificationPolicy, certify_result
from product.evidence import EvidenceCondition, ObservationStatus, validate_normalized_paths
from product.protocol import IMPLEMENTATION_SCHEMA
from product.verification import VerificationResult, VerificationStatus, reduce_verification

LEGACY_CHANGESET_CERTIFICATION_SCHEMA = "nexus.changeset_certification.v1"
LEGACY_CHANGESET_CERTIFICATION_VERSION = 1
CHANGESET_CERTIFICATION_SCHEMA = "nexus.changeset_certification.v2"
CHANGESET_CERTIFICATION_VERSION = 2
CLAIM_CEILING = "LOCAL_CHANGESET_CERTIFICATION_V2_CONTRACT_CANDIDATE_ONLY"
assert CHANGESET_CERTIFICATION_SCHEMA == IMPLEMENTATION_SCHEMA
_STATUSES = frozenset({"CERTIFIED", "REJECTED", "BLOCKED"})
_VERIFIER_STATUSES = frozenset({"PASS", "FAIL"})
_HASH_LEN = 71
_MAX_REASONS = 16
_REASONS = frozenset(
    {
        "identity_missing",
        "identity_malformed",
        "evidence_missing",
        "evidence_malformed",
        "scope_missing",
        "scope_malformed",
        "candidate_missing",
        "candidate_malformed",
        "verifier_manifest_missing",
        "verifier_manifest_malformed",
        "verifier_missing",
        "verifier_failed",
        "verifier_artifact_missing",
        "verifier_artifact_malformed",
        "verifier_duplicate",
        "artifact_duplicate",
        "hash_mismatch",
        "manifest_hash_mismatch",
        "payload_hash_mismatch",
        "cross_binding_mismatch",
        "status_invalid",
        "reason_invalid",
        "schema_invalid",
        "unknown_field",
        "status_substitution",
        "change_set_missing",
        "identity_diff_hash_invalid",
        "evidence_0_invalid",
        "evidence_duplicate_id",
        "evidence_empty",
        "evidence_not_sequence",
        "canonical_hash_mismatch",
        "approval_missing",
        "authority_missing",
        "signing_missing",
        "policy_missing",
        "policy_disallowed",
        "scope_escape",
        "stale_changeset",
        "legacy_v1_reverification_required",
    }
)


CertificationStatus = CertificationDisposition


def _default_certification_status() -> CertificationStatus:
    factual = reduce_verification(EvidenceCondition.MISSING)
    return certify_result(factual, CertificationPolicy())


@dataclass(frozen=True)
class ChangeSetIdentity:
    change_set_id: str
    source_revision: str
    target_revision: str
    diff_hash: str


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    kind: str
    content_hash: str
    source: str


@dataclass(frozen=True, init=False)
class ChangeSetCertification:
    change_set: ChangeSetIdentity
    evidence: tuple[EvidenceRef, ...] = ()
    status: CertificationStatus = dataclass_field(
        default_factory=_default_certification_status, init=False
    )
    reason_codes: tuple[str, ...] = dataclass_field(default=(), init=False)
    envelope: Mapping[str, Any] | None = None
    schema: str = CHANGESET_CERTIFICATION_SCHEMA
    verification_result: VerificationResult = dataclass_field(
        default_factory=lambda: reduce_verification(EvidenceCondition.MISSING), init=False
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("ChangeSetCertification construction is internal")

    def to_dict(self) -> dict[str, Any]:
        # Compatibility dataclasses never emit the superseded legacy wire form.
        return _copy(self.envelope) if self.envelope is not None else _minimal(self)

    def canonical_json(self) -> str:
        return canonical_json(self.to_dict())

    def canonical_hash(self) -> str:
        return canonical_hash(self.to_dict())


def canonical_json(value: Any) -> str:
    return json.dumps(
        _normalize(value, ()),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _create_changeset_certification(
    change_set: ChangeSetIdentity,
    *,
    status: CertificationStatus,
    reason_codes: tuple[str, ...],
    envelope: Mapping[str, Any] | None = None,
    verification_result: VerificationResult,
) -> ChangeSetCertification:
    result = object.__new__(ChangeSetCertification)
    object.__setattr__(result, "change_set", change_set)
    object.__setattr__(result, "evidence", ())
    object.__setattr__(result, "status", status)
    object.__setattr__(result, "reason_codes", reason_codes)
    object.__setattr__(result, "envelope", envelope)
    object.__setattr__(result, "schema", CHANGESET_CERTIFICATION_SCHEMA)
    object.__setattr__(result, "verification_result", verification_result)
    return result


def canonical_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def derive_verification_result(
    payload: Mapping[str, Any], errors: tuple[str, ...] = ()
) -> VerificationResult:
    """Derive factual verifier truth without consulting caller disposition."""
    if "scope_escape" in errors:
        return reduce_verification(EvidenceCondition.SCOPE_ESCAPE, reasons=("scope_escape",))
    if errors or not isinstance(payload, Mapping):
        condition = _condition_for_errors(errors)
        return reduce_verification(condition, reasons=tuple(sorted(set(errors))))
    manifest = payload.get("verifier_manifest")
    if not isinstance(manifest, Mapping) or not _hashes_match(payload):
        reasons = _hash_errors(payload) if isinstance(manifest, Mapping) else ("evidence_missing",)
        condition = (
            EvidenceCondition.TAMPERED
            if isinstance(manifest, Mapping)
            else EvidenceCondition.MISSING
        )
        return reduce_verification(condition, reasons=reasons)
    verifiers = manifest.get("verifiers")
    if not isinstance(verifiers, list) or not verifiers:
        return reduce_verification(EvidenceCondition.MISSING, reasons=("verifier_missing",))
    if any(verifier.get("status") == "FAIL" for verifier in verifiers):
        return reduce_verification(
            EvidenceCondition.VALID, (ObservationStatus.FAIL,), ("verifier_failed",)
        )
    return reduce_verification(EvidenceCondition.VALID, (ObservationStatus.PASS,))


def _condition_for_errors(errors: tuple[str, ...]) -> EvidenceCondition:
    if "scope_escape" in errors:
        return EvidenceCondition.SCOPE_ESCAPE
    if "stale_changeset" in errors:
        return EvidenceCondition.STALE
    if any(
        reason in {"payload_hash_mismatch", "manifest_hash_mismatch", "hash_mismatch"}
        for reason in errors
    ):
        return EvidenceCondition.TAMPERED
    if any(reason in {"cross_binding_mismatch"} for reason in errors):
        return EvidenceCondition.CROSS_BOUND
    if any(reason in {"verifier_duplicate", "artifact_duplicate"} for reason in errors):
        return EvidenceCondition.DUPLICATE
    if any(reason == "legacy_v1_reverification_required" for reason in errors):
        return EvidenceCondition.LEGACY_NON_CERTIFIABLE
    if any(
        reason
        in {
            "identity_missing",
            "evidence_missing",
            "scope_missing",
            "candidate_missing",
            "verifier_manifest_missing",
            "verifier_missing",
            "verifier_artifact_missing",
        }
        for reason in errors
    ):
        return EvidenceCondition.MISSING
    return EvidenceCondition.MALFORMED


def _missing_prerequisites(payload: Mapping[str, Any]) -> tuple[str, ...]:
    missing = []
    for key in ("approval", "authority", "signing"):
        value = payload.get(key)
        complete = (
            isinstance(value, Mapping)
            and _exact(value, {"complete"})
            and value.get("complete") is True
        )
        if not complete:
            missing.append(f"{key}_missing")
    return tuple(missing)


def _policy_reasons(payload: Mapping[str, Any]) -> tuple[str, ...]:
    policy = payload.get("policy")
    if policy is None:
        return ("policy_missing",)
    if (
        not isinstance(policy, Mapping)
        or not _exact(policy, {"allowed"})
        or policy.get("allowed") is not True
    ):
        return ("policy_disallowed",)
    return ()


def _waiver_is_malformed(payload: Mapping[str, Any]) -> bool:
    waiver = payload.get("waiver")
    return waiver is not None and (
        not isinstance(waiver, Mapping)
        or not _exact(waiver, {"approved"})
        or not isinstance(waiver.get("approved"), bool)
    )


def certify_changeset(payload: Mapping[str, Any]) -> ChangeSetCertification:
    if not isinstance(payload, Mapping):
        return _blocked("identity_missing")
    try:
        if _contains_nonfinite(payload):
            return _blocked("identity_malformed")
        payload = _copy(payload)
    except (TypeError, ValueError, RecursionError):
        return _blocked("identity_malformed")
    if (
        payload.get("schema") == LEGACY_CHANGESET_CERTIFICATION_SCHEMA
        and payload.get("version") == LEGACY_CHANGESET_CERTIFICATION_VERSION
    ):
        return _blocked(
            "legacy_v1_reverification_required",
            _unverifiable(
                ("legacy_v1_reverification_required",), EvidenceCondition.LEGACY_NON_CERTIFIABLE
            ),
        )
    if "change_set" in payload:
        return _certify_compatibility_input(payload)
    if "verification_result" in payload:
        sanitized = _copy(payload)
        sanitized.pop("verification_result", None)
        sanitized["canonical_payload_hash"] = canonical_hash(_payload_input(sanitized))
        verification = derive_verification_result(sanitized)
        return _result(
            sanitized,
            ("unknown_field",),
            verification_result=verification,
        )
    if any(key not in payload for key in ("task", "repository", "base", "diff")):
        return _result(payload, reasons=("identity_missing",))
    errors = _validate(payload)
    if errors:
        if errors == ("cross_binding_mismatch",) and _candidate_binding_is_stale(payload):
            verification = _unverifiable(("stale_changeset",), EvidenceCondition.STALE)
            return _result(
                payload,
                ("stale_changeset",),
                verification_result=verification,
            )
        verification = derive_verification_result(payload, errors)
        return _result(
            payload,
            errors,
            verification_result=verification,
        )
    verification = derive_verification_result(payload)
    if verification.status is VerificationStatus.FAILED_VERIFICATION:
        return _result(
            payload,
            ("verifier_failed",),
            verification_result=verification,
        )
    if not _hashes_match(payload):
        tampered = _unverifiable(_hash_errors(payload), EvidenceCondition.TAMPERED)
        return _result(
            payload,
            _hash_errors(payload),
            verification_result=tampered,
        )
    if _waiver_is_malformed(payload):
        return _result(
            payload,
            ("reason_invalid",),
            verification_result=verification,
        )
    policy_reasons = _policy_reasons(payload)
    if policy_reasons:
        return _result(payload, policy_reasons, verification_result=verification)
    missing_prerequisites = _missing_prerequisites(payload)
    if missing_prerequisites:
        return _result(
            payload,
            missing_prerequisites,
            verification_result=verification,
        )
    return _result(
        payload,
        (),
        verification_result=verification,
    )


def _candidate_binding_is_stale(payload: Mapping[str, Any]) -> bool:
    task = _as_mapping(payload.get("task"))
    repository = _as_mapping(payload.get("repository"))
    base = _as_mapping(payload.get("base"))
    diff = _as_mapping(payload.get("diff"))
    candidate = _as_mapping(payload.get("candidate"))
    manifest = _as_mapping(payload.get("verifier_manifest"))
    if not all((task, repository, base, diff, candidate, manifest)):
        return False
    stable_bindings = (
        manifest.get("task_id") == task.get("task_id")
        and manifest.get("attempt_id") == task.get("attempt_id")
        and manifest.get("repository") == repository.get("repository")
        and manifest.get("source") == repository.get("source")
        and manifest.get("base_commit") == base.get("commit")
        and manifest.get("base_tree") == base.get("tree")
        and manifest.get("diff_hash") == diff.get("hash")
        and candidate.get("diff_hash") == diff.get("hash")
    )
    candidate_moved = manifest.get("candidate_commit") != candidate.get("commit") or manifest.get(
        "candidate_tree"
    ) != candidate.get("tree")
    return stable_bindings and candidate_moved


def build_changeset_certification(
    *,
    change_set: Mapping[str, Any],
    evidence: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] | None,
) -> dict[str, Any]:
    """Build a non-authorizing v2 envelope from the convenience API."""
    if (
        not isinstance(change_set, Mapping)
        or not _texts(change_set, ("change_set_id", "source_revision", "target_revision"))
        or not _hash(change_set.get("diff_hash"))
    ):
        return _minimal_invalid("identity_missing")
    if not isinstance(evidence, (list, tuple)) or not evidence:
        return _minimal_invalid("evidence_missing")
    paths = [f"changeset/{change_set['change_set_id']}"]
    verifiers: list[dict[str, Any]] = []
    verifier_ids: set[str] = set()
    for item in evidence:
        if (
            not isinstance(item, Mapping)
            or not _texts(item, ("evidence_id", "kind", "source"))
            or not _hash(item.get("content_hash"))
        ):
            return _minimal_invalid("verifier_artifact_malformed")
        if item["kind"] in verifier_ids:
            return _minimal_invalid("verifier_duplicate")
        verifier_ids.add(item["kind"])
        verifiers.append(
            {
                "verifier_id": item["kind"],
                "artifact_id": f"{item['kind']}:attempt-1",
                "artifact_hash": item["content_hash"],
                "status": "PASS",
            }
        )
    source = str(change_set["source_revision"])
    target = str(change_set["target_revision"])
    request = _new_envelope(
        task={"task_id": str(change_set["change_set_id"]), "attempt_id": "attempt-1"},
        repository={"repository": "local", "source": source},
        base={"commit": source, "tree": source},
        diff={"hash": change_set["diff_hash"], "paths": paths},
        allowed_scope={"paths": paths, "deletion_policy": "FORBID"},
        candidate={"commit": target, "tree": target, "diff_hash": change_set["diff_hash"]},
        verifiers=verifiers,
        disposition=certify_result(
            reduce_verification(EvidenceCondition.VALID, (ObservationStatus.PASS,)),
            CertificationPolicy(),
        ).value,
        reasons=["policy_missing"],
    )
    return certify_changeset(request).to_dict()


def _certify_compatibility_input(payload: Mapping[str, Any]) -> ChangeSetCertification:
    """Refuse to reinterpret the retired convenience/v1 input as v2 truth."""
    del payload
    return _blocked(
        "legacy_v1_reverification_required",
        _unverifiable(
            ("legacy_v1_reverification_required",), EvidenceCondition.LEGACY_NON_CERTIFIABLE
        ),
    )


def validate_changeset_certification(
    certification: ChangeSetCertification | Mapping[str, Any],
) -> tuple[str, ...]:
    try:
        payload = (
            certification.to_dict()
            if isinstance(certification, ChangeSetCertification)
            else _copy(certification)
        )
    except (TypeError, ValueError, RecursionError):
        return ("identity_malformed",)
    if not isinstance(payload, Mapping):
        return ("identity_malformed",)
    if (
        payload.get("schema") == CHANGESET_CERTIFICATION_SCHEMA
        and payload.get("version") == CHANGESET_CERTIFICATION_VERSION
        and "verification_result" not in payload
    ):
        return ("evidence_missing",)
    errors = _validate(payload, allow_verification_result=True)
    if errors:
        return errors
    if not _hashes_match(payload):
        return _hash_errors(payload)
    actual_reasons = tuple(payload["reasons"])
    structural_reasons = {"identity_missing", "identity_malformed", "evidence_missing"}
    if structural_reasons.intersection(actual_reasons):
        return (sorted(structural_reasons.intersection(actual_reasons))[0],)
    verification = derive_verification_result(payload)
    claimed_verification = payload.get("verification_result")
    if claimed_verification is not None and claimed_verification != _project_verification_result(
        verification
    ):
        return ("status_substitution",)
    policy_reasons = _policy_reasons(payload)
    missing_prerequisites = _missing_prerequisites(payload)
    expected_reasons = (
        ("verifier_failed",)
        if verification.status is VerificationStatus.FAILED_VERIFICATION
        else policy_reasons
        or missing_prerequisites
        or (
            ("reason_invalid",) if _waiver_is_malformed(payload) else _project_reasons(verification)
        )
        or ()
    )
    expected_policy = _effective_policy(payload, actual_reasons)
    expected_status = certify_result(verification, expected_policy).value
    if payload["disposition"] != expected_status or actual_reasons != expected_reasons:
        return ("status_substitution",)
    return ()


def _validate(
    payload: Mapping[str, Any], *, allow_verification_result: bool = False
) -> tuple[str, ...]:
    allowed = {
        "schema",
        "version",
        "task",
        "repository",
        "base",
        "diff",
        "allowed_scope",
        "candidate",
        "verifier_manifest",
        "disposition",
        "reasons",
        "claim_ceiling",
        "canonical_payload_hash",
        "approval",
        "authority",
        "signing",
        "policy",
        "waiver",
    }
    if allow_verification_result:
        allowed.add("verification_result")
    if set(payload) - allowed:
        return ("unknown_field",)
    if (
        payload.get("schema") != CHANGESET_CERTIFICATION_SCHEMA
        or payload.get("version") != CHANGESET_CERTIFICATION_VERSION
    ):
        return ("schema_invalid",)
    if allow_verification_result and "verification_result" in payload:
        factual = payload["verification_result"]
        if (
            not isinstance(factual, Mapping)
            or not _exact(factual, {"status", "reason_codes"})
            or factual.get("status") not in {item.value for item in VerificationStatus}
            or not isinstance(factual.get("reason_codes"), list)
            or len(factual["reason_codes"]) > _MAX_REASONS
            or len(set(factual["reason_codes"])) != len(factual["reason_codes"])
            or any(reason not in _REASONS for reason in factual["reason_codes"])
        ):
            return ("evidence_malformed",)
    task, repo, base, diff, scope = (
        payload.get(k) for k in ("task", "repository", "base", "diff", "allowed_scope")
    )
    if any(v is None for v in (task, repo, base, diff)):
        return ("identity_missing",)
    if (
        not isinstance(task, Mapping)
        or not _exact(task, {"task_id", "attempt_id"})
        or not _texts(task, ("task_id", "attempt_id"))
    ):
        return ("identity_malformed",)
    if (
        not isinstance(repo, Mapping)
        or not _exact(repo, {"repository", "source"})
        or not _texts(repo, ("repository", "source"))
    ):
        return ("identity_malformed",)
    if (
        not isinstance(base, Mapping)
        or not _exact(base, {"commit", "tree"})
        or not _texts(base, ("commit", "tree"))
    ):
        return ("identity_malformed",)
    if (
        not isinstance(diff, Mapping)
        or not _exact(diff, {"hash", "paths"})
        or not _hash(diff.get("hash"))
        or not _paths(diff.get("paths"))
    ):
        return ("identity_malformed",)
    if scope is None:
        return ("scope_missing",)
    if (
        not isinstance(scope, Mapping)
        or not _exact(scope, {"paths", "deletion_policy"})
        or not _paths(scope.get("paths"))
        or scope.get("deletion_policy") not in {"FORBID", "ALLOW"}
    ):
        return ("scope_malformed",)
    if not set(diff["paths"]).issubset(scope["paths"]):
        return ("scope_escape",)
    candidate = payload.get("candidate")
    if candidate is not None and (
        not isinstance(candidate, Mapping)
        or not _exact(candidate, {"commit", "tree", "diff_hash"})
        or not _texts(candidate, ("commit", "tree"))
        or not _hash(candidate.get("diff_hash"))
    ):
        return ("candidate_malformed",)
    if candidate is not None and candidate["diff_hash"] != diff["hash"]:
        return ("cross_binding_mismatch",)
    manifest = payload.get("verifier_manifest")
    if manifest is None:
        return ("verifier_manifest_missing",)
    mkeys = {
        "manifest_id",
        "task_id",
        "attempt_id",
        "repository",
        "source",
        "base_commit",
        "base_tree",
        "candidate_commit",
        "candidate_tree",
        "diff_hash",
        "verifiers",
        "manifest_hash",
    }
    if (
        not isinstance(manifest, Mapping)
        or not _exact(manifest, mkeys)
        or not _texts(
            manifest,
            (
                "manifest_id",
                "task_id",
                "attempt_id",
                "repository",
                "source",
                "base_commit",
                "base_tree",
                "candidate_commit",
                "candidate_tree",
            ),
        )
        or not _hash(manifest.get("diff_hash"))
        or not _hash(manifest.get("manifest_hash"))
    ):
        return ("verifier_manifest_malformed",)
    expected = candidate or {"commit": "none", "tree": "none"}
    bindings = (
        manifest["task_id"],
        manifest["attempt_id"],
        manifest["repository"],
        manifest["source"],
        manifest["base_commit"],
        manifest["base_tree"],
        manifest["candidate_commit"],
        manifest["candidate_tree"],
        manifest["diff_hash"],
    )
    actual = (
        task["task_id"],
        task["attempt_id"],
        repo["repository"],
        repo["source"],
        base["commit"],
        base["tree"],
        expected["commit"],
        expected["tree"],
        diff["hash"],
    )
    if bindings != actual:
        return ("cross_binding_mismatch",)
    verifiers = manifest.get("verifiers")
    if not isinstance(verifiers, list) or not verifiers:
        return ("verifier_missing",)
    verifier_ids: set[str] = set()
    artifact_ids: set[str] = set()
    for verifier in verifiers:
        if not isinstance(verifier, Mapping):
            return ("verifier_artifact_malformed",)
        if (
            not _exact(verifier, {"verifier_id", "artifact_id", "artifact_hash", "status"})
            or not _texts(verifier, ("verifier_id", "artifact_id"))
            or not _hash(verifier.get("artifact_hash"))
        ):
            return ("verifier_artifact_missing",)
        if verifier["verifier_id"] in verifier_ids:
            return ("verifier_duplicate",)
        if verifier["artifact_id"] in artifact_ids:
            return ("artifact_duplicate",)
        verifier_ids.add(verifier["verifier_id"])
        artifact_ids.add(verifier["artifact_id"])
        if verifier.get("status") not in _VERIFIER_STATUSES:
            return ("verifier_artifact_malformed",)
        if verifier["artifact_id"] != f"{verifier['verifier_id']}:{task['attempt_id']}":
            return ("cross_binding_mismatch",)
    reasons = payload.get("reasons")
    if not isinstance(reasons, list):
        return ("reason_invalid",)
    if len(reasons) > _MAX_REASONS or any(
        not isinstance(r, str) or r not in _REASONS for r in reasons
    ):
        return ("reason_invalid",)
    if len(set(reasons)) != len(reasons):
        return ("reason_invalid",)
    if payload.get("disposition") not in _STATUSES:
        return ("status_invalid",)
    if payload["disposition"] == "CERTIFIED" and candidate is None:
        return ("candidate_missing",)
    if payload["disposition"] == "REJECTED" and not reasons:
        return ("reason_invalid",)
    if payload.get("claim_ceiling") != CLAIM_CEILING:
        return ("cross_binding_mismatch",)
    if not _hash(payload.get("canonical_payload_hash")):
        return ("payload_hash_mismatch",)
    return ()


def _new_envelope(
    *,
    task: dict[str, Any],
    repository: dict[str, Any],
    base: dict[str, Any],
    diff: dict[str, Any],
    allowed_scope: dict[str, Any],
    candidate: dict[str, Any] | None,
    verifiers: list[dict[str, Any]],
    disposition: str,
    reasons: list[str],
) -> dict[str, Any]:
    candidate = candidate or {"commit": "none", "tree": "none"}
    manifest = {
        "manifest_id": f"manifest:{task['attempt_id']}",
        "task_id": task["task_id"],
        "attempt_id": task["attempt_id"],
        "repository": repository["repository"],
        "source": repository["source"],
        "base_commit": base["commit"],
        "base_tree": base["tree"],
        "candidate_commit": candidate["commit"],
        "candidate_tree": candidate["tree"],
        "diff_hash": diff["hash"],
        "verifiers": verifiers,
    }
    manifest["manifest_hash"] = canonical_hash(manifest)
    payload = {
        "schema": CHANGESET_CERTIFICATION_SCHEMA,
        "version": CHANGESET_CERTIFICATION_VERSION,
        "task": task,
        "repository": repository,
        "base": base,
        "diff": diff,
        "allowed_scope": allowed_scope,
        "candidate": None if candidate["commit"] == "none" else candidate,
        "verifier_manifest": manifest,
        "disposition": disposition,
        "reasons": reasons,
        "claim_ceiling": CLAIM_CEILING,
    }
    payload["canonical_payload_hash"] = canonical_hash(payload)
    return payload


def _result(
    payload: Mapping[str, Any],
    reasons: tuple[str, ...] = (),
    verification_result: VerificationResult | None = None,
) -> ChangeSetCertification:
    factual = verification_result or derive_verification_result(payload)
    policy = _effective_policy(payload, reasons)
    disposition = certify_result(factual, policy)
    result = _copy(payload)
    result["schema"] = CHANGESET_CERTIFICATION_SCHEMA
    result["version"] = CHANGESET_CERTIFICATION_VERSION
    result["disposition"] = disposition.value
    result["reasons"] = list(sorted(set(reasons)))
    result["verification_result"] = _project_verification_result(factual)
    if isinstance(result.get("verifier_manifest"), dict):
        result["verifier_manifest"]["manifest_hash"] = canonical_hash(
            _manifest_input(result["verifier_manifest"])
        )
    result["canonical_payload_hash"] = canonical_hash(_payload_input(result))
    task = _as_mapping(result.get("task"))
    base = _as_mapping(result.get("base"))
    candidate = _as_mapping(result.get("candidate"))
    diff = _as_mapping(result.get("diff"))
    identity = ChangeSetIdentity(
        str(task.get("task_id", "")),
        str(base.get("commit", "")),
        str(candidate.get("commit", "")),
        str(diff.get("hash", "")),
    )
    return _create_changeset_certification(
        identity,
        status=disposition,
        reason_codes=tuple(sorted(set(reasons))),
        envelope=result,
        verification_result=factual,
    )


def _policy(payload: Mapping[str, Any]) -> CertificationPolicy:
    policy = payload.get("policy")
    if "policy" not in payload or policy is None:
        return CertificationPolicy()
    if not isinstance(policy, Mapping):
        return CertificationPolicy(accepted=False)
    if set(policy) != {"allowed"} or not isinstance(policy.get("allowed"), bool):
        return CertificationPolicy(accepted=False)
    return CertificationPolicy(
        accepted=policy.get("allowed"),
        authority_present=_complete(payload.get("authority")),
        approval_present=_complete(payload.get("approval")),
        signing_present=_complete(payload.get("signing")),
    )


def _effective_policy(payload: Mapping[str, Any], reasons: tuple[str, ...]) -> CertificationPolicy:
    """Apply the same fail-closed policy semantics to result and validation."""
    malformed = (
        (isinstance(payload.get("policy"), Mapping) and set(payload["policy"]) != {"allowed"})
        or (isinstance(payload.get("waiver"), Mapping) and set(payload["waiver"]) != {"approved"})
        or any(
            reason
            in {
                "unknown_field",
                "reason_invalid",
                "status_substitution",
                "hash_mismatch",
                "payload_hash_mismatch",
                "manifest_hash_mismatch",
            }
            for reason in reasons
        )
    )
    if malformed:
        return CertificationPolicy(False, True, True, True)
    return _policy(payload)


_EXTERNAL_REASON_CODES = frozenset(_REASONS)
_INTERNAL_REASON_MAP = {
    "MISSING": "evidence_missing",
    "MALFORMED": "evidence_malformed",
    "TAMPERED": "hash_mismatch",
    "CROSS_BOUND": "cross_binding_mismatch",
    "DUPLICATE": "verifier_duplicate",
    "STALE": "stale_changeset",
    "LEGACY_NON_CERTIFIABLE": "legacy_v1_reverification_required",
    "VERIFIER_FAILED": "verifier_failed",
}


def _project_reasons(result: VerificationResult) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _INTERNAL_REASON_MAP.get(code, code)
                for code in result.reason_codes
                if _INTERNAL_REASON_MAP.get(code, code) in _EXTERNAL_REASON_CODES
            }
        )
    )


def _project_verification_result(result: VerificationResult) -> dict[str, Any]:
    return {"status": result.status.value, "reason_codes": list(_project_reasons(result))}


def _complete(value: Any) -> bool | None:
    if value is None:
        return None
    return (
        isinstance(value, Mapping) and value.get("complete") is True and set(value) == {"complete"}
    )


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _hashes_match(payload: Mapping[str, Any]) -> bool:
    manifest = payload.get("verifier_manifest")
    return (
        isinstance(manifest, Mapping)
        and payload.get("canonical_payload_hash") == canonical_hash(_payload_input(payload))
        and manifest.get("manifest_hash") == canonical_hash(_manifest_input(manifest))
    )


def _hash_errors(payload: Mapping[str, Any]) -> tuple[str, ...]:
    out = []
    manifest = payload.get("verifier_manifest")
    if not isinstance(manifest, Mapping) or manifest.get("manifest_hash") != canonical_hash(
        _manifest_input(manifest)
    ):
        out.append("manifest_hash_mismatch")
    if payload.get("canonical_payload_hash") != canonical_hash(_payload_input(payload)):
        out.append("payload_hash_mismatch")
    return tuple(out) or ("hash_mismatch",)


def _payload_input(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _copy(payload)
    value.pop("canonical_payload_hash", None)
    return value


def _manifest_input(manifest: Mapping[str, Any]) -> dict[str, Any]:
    value = _copy(manifest)
    value.pop("manifest_hash", None)
    return value


def _minimal(result: ChangeSetCertification) -> dict[str, Any]:
    payload = _minimal_invalid(
        result.reason_codes[0] if result.reason_codes else "identity_missing",
    )
    payload["verification_result"] = _project_verification_result(result.verification_result)
    payload["canonical_payload_hash"] = canonical_hash(_payload_input(payload))
    return payload


def _minimal_invalid(reason: str) -> dict[str, Any]:
    factual = reduce_verification(EvidenceCondition.MISSING, reasons=(reason,))
    disposition = certify_result(factual, CertificationPolicy()).value
    return _new_envelope(
        task={"task_id": "missing", "attempt_id": "missing"},
        repository={"repository": "missing", "source": "missing"},
        base={"commit": "missing", "tree": "missing"},
        diff={"hash": "sha256:" + "0" * 64, "paths": ["missing"]},
        allowed_scope={"paths": ["missing"], "deletion_policy": "FORBID"},
        candidate=None,
        verifiers=[
            {
                "verifier_id": "missing",
                "artifact_id": "missing:missing",
                "artifact_hash": "sha256:" + "0" * 64,
                "status": "FAIL",
            }
        ],
        disposition=disposition,
        reasons=[reason],
    )


def _blocked(
    reason: str,
    verification_result: VerificationResult | None = None,
) -> ChangeSetCertification:
    factual = verification_result or _unverifiable((reason,))
    disposition = certify_result(factual, CertificationPolicy())
    return _create_changeset_certification(
        ChangeSetIdentity("", "", "", ""),
        status=disposition,
        reason_codes=(reason,),
        verification_result=factual,
    )


def _unverifiable(
    reasons: tuple[str, ...], condition: EvidenceCondition = EvidenceCondition.MISSING
) -> VerificationResult:
    return reduce_verification(condition, reasons=tuple(sorted(set(reasons))))


def _texts(value: Mapping[str, Any], keys: tuple[str, ...]) -> bool:
    return all(
        isinstance(value.get(k), str)
        and bool(value[k])
        and value[k] == value[k].strip()
        and "\x00" not in value[k]
        for k in keys
    )


def _exact(value: Mapping[str, Any], expected: set[str]) -> bool:
    return set(value) == expected


def _hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _HASH_LEN
        and value.startswith("sha256:")
        and all(c in "0123456789abcdef" for c in value[7:])
    )


def _paths(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    try:
        validate_normalized_paths(tuple(value))
    except (TypeError, ValueError):
        return False
    return True


def _normalize(value: Any, path: tuple[str, ...]) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("canonical JSON values must be finite")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(k, str) for k in value):
            raise TypeError("canonical JSON keys must be strings")
        return {k: _normalize(value[k], path + (k,)) for k in sorted(value)}
    if isinstance(value, list):
        items = [_normalize(item, path) for item in value]
        return (
            sorted(items, key=canonical_json)
            if path and path[-1] in {"paths", "reasons", "reason_codes", "verifiers", "evidence"}
            else items
        )
    if isinstance(value, tuple):
        return _normalize(list(value), path)
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def _contains_nonfinite(value: Any) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, Mapping):
        return any(_contains_nonfinite(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_nonfinite(item) for item in value)
    if isinstance(value, tuple):
        return any(_contains_nonfinite(item) for item in value)
    return False


def _copy(value: Any) -> dict[str, Any]:
    # Validate recursively before JSON's encoder coerces non-string keys.
    normalized = _normalize(value, ())
    return json.loads(json.dumps(normalized, ensure_ascii=False, allow_nan=False))
