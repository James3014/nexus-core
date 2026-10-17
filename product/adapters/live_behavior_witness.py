# pyright: strict, reportUnnecessaryIsInstance=false, reportUnnecessaryComparison=false
"""Live-behavior witness consumer adapter (nexus-core#296, experimental).

A live-behavior witness is produced outside Core (Nexus-new#2453): a signed
record that a predeclared code path was actually exercised on an exact running
build. This carrying-layer adapter only *reads* such a witness and maps it onto
existing Core types and statuses; it adds no Core protocol field, no ledger
state and no truth authority (Owner decision G1 on #296, Option A).

Fail-closed mapping (G1):

* trust root is a Sigstore GitHub workflow identity, checked by an injected
  authenticator (normally the client layer's ``SigstoreReceiptAuthenticator``);
  missing or ``UNAVAILABLE`` -> MISSING
  (BLOCKED), anything else not ``AUTHENTICATED`` -> CROSS_BOUND (REJECTED);
* bundle digest differs from the witness bytes, or the artifacts digest is
  wrong -> TAMPERED;
* replay is bound to the promise's predeclared ``execution_id``/``attempt_id``
  (no Core-issued nonce) -> CROSS_BOUND;
* the contract must be for this promise: ``requirements_hash`` equals the
  promise's ``issue_contract_hash`` and the declared live subjects carry the
  promise digest in their evidence kind; otherwise CROSS_BOUND;
* change-set target revision or loaded source revision differs from the
  promised revision -> STALE; runtime/binary identity differs ->
  CROSS_BOUND; expired / too old / other generation -> STALE;
* ``UNKNOWN_INFRA`` or unknown convergence -> MISSING;
* raw output, secret-like or unknown fields -> MALFORMED;
* an authenticated ``ACTUAL_FAILED`` becomes a FAIL observation, so Core
  reports FAILED_VERIFICATION / EVIDENCE_CLAIM_FAILED (not a binding error);
* a probe that was not hit yields no observation, so the subject stays
  NOT_COVERED / MISSING; ``PARTIAL`` yields no observation at all (and is
  MALFORMED when every probe was hit); only ``PASS`` yields PASS.

The witness never supplies acceptance, authority, approval or signing policy
facts, and producer-supplied reviewer ids are ignored. A fully valid witness
can at most make the live subjects VERIFIED/COVERED; certification still needs
policy facts this adapter never produces (claim ceiling below).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, cast

from product.evidence import (
    AcceptanceContract,
    Applicability,
    ChangeSet,
    EvidenceBundle,
    ExpectedEvidenceSubject,
    IntegrityStatus,
    Observation,
    ObservationStatus,
    RequirementMode,
    VerificationPlan,
    canonical_json,
)
from product.evidence.ingestion import (
    EvidenceGeneration,
    FreshnessStatus,
    RuntimeSourceObservation,
    _parse_time,  # pyright: ignore[reportPrivateUsage]
    derive_runtime_freshness,
)
from product.verification import (
    CoverageCategory,
    VerificationResult,
    derive_coverage,
    reduce_verification,
    verify,
)

LIVE_BEHAVIOR_WITNESS_SCHEMA = "nexus.live-behavior-witness.v1-experimental"
LIVE_BEHAVIOR_EVIDENCE_KIND = "live-behavior-witness.v1"
LIVE_WITNESS_CLAIM_CEILING = "LIVE_BEHAVIOR_OBSERVATION_ONLY_NOT_CERTIFIED"
LIVE_SUBJECT_PREFIX = "live/"
MAX_WITNESS_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 64 * 1024
_MAX_REVIEWER_IDS = 32
_MAX_REVIEWER_ID_LENGTH = 128

_AUTHENTICATED = "AUTHENTICATED"
_UNAVAILABLE = "UNAVAILABLE"
_MAX_TEXT = 512
_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")

_RESULT_CLASSES = frozenset({"PASS", "ACTUAL_FAILED", "NOT_EXERCISED", "PARTIAL", "UNKNOWN_INFRA"})
_REQUIRED_FIELDS = frozenset(
    {
        "schema",
        "issue_ref",
        "issue_contract_hash",
        "promise_id",
        "promise_generation",
        "entry_id",
        "action_id",
        "input_digest",
        "execution_id",
        "attempt_id",
        "loaded_source_revision",
        "observed_runtime_identity",
        "readiness_status",
        "producer_software_hash",
        "probes",
        "result_class",
        "side_effects",
        "artifacts",
        "artifacts_digest",
        "started_at",
        "finished_at",
        "observed_at",
        "expires_at",
    }
)
# Accepted for producer convenience but ignored: reviewer ids never become
# approval or authority facts (G1 D7).
_IGNORED_FIELDS = frozenset({"reviewer_ids"})
_PROBE_FIELDS = frozenset({"probe_id", "hit"})
_ARTIFACT_FIELDS = frozenset({"id", "sha256"})
# Raw output and secret-bearing names: the witness must carry digests only.
_RAW_OR_SECRET_FIELDS = frozenset(
    {
        "stdout",
        "stderr",
        "output",
        "raw_output",
        "log",
        "logs",
        "content",
        "body",
        "env",
        "environment",
        "secret",
        "secrets",
        "token",
        "tokens",
        "password",
        "passwords",
        "credential",
        "credentials",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "cookies",
        "private_key",
    }
)


class _Reject(Exception):
    def __init__(self, condition: IntegrityStatus, reason: str) -> None:
        super().__init__(reason)
        self.condition = condition
        self.reason = reason


def _text(value: object, field: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value) > _MAX_TEXT
    ):
        raise ValueError(f"{field} must be normalized non-empty text")
    return value


def _sha(value: object, field: str) -> str:
    text = _text(value, field)
    if _HASH_RE.match(text) is None:
        raise ValueError(f"{field} must be sha256:<64 lowercase hex>")
    return text


def _ids(value: object, field: str, *, allow_empty: bool) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{field} must be a tuple")
    items = tuple(_text(v, field) for v in cast("tuple[object, ...]", value))
    if len(items) != len(set(items)):
        raise ValueError(f"{field} must not contain duplicates")
    if not items and not allow_empty:
        raise ValueError(f"{field} must be non-empty")
    return items


@dataclass(frozen=True)
class LiveBehaviorPromise:
    """What must be observed, frozen before execution (Nexus-new#2532 promise).

    Every field is authored upstream, never by the witness producer.
    ``signer_identity`` is the Sigstore workflow identity allowed to sign the
    witness; it must match the trust-root policy the caller loads from base-ref
    configuration.
    """

    issue_ref: str
    issue_contract_hash: str
    promise_id: str
    promise_generation: int
    entry_id: str
    action_id: str
    input_digest: str
    probe_ids: tuple[str, ...]
    desired_source_revision: str
    expected_runtime_identity: str
    execution_id: str
    attempt_id: str
    expected_side_effect_ids: tuple[str, ...]
    max_age_seconds: int
    signer_identity: str

    def __post_init__(self) -> None:
        for name in (
            "issue_ref",
            "promise_id",
            "entry_id",
            "action_id",
            "desired_source_revision",
            "expected_runtime_identity",
            "execution_id",
            "attempt_id",
            "signer_identity",
        ):
            _text(getattr(self, name), name)
        _sha(self.issue_contract_hash, "issue_contract_hash")
        _sha(self.input_digest, "input_digest")
        if "/" in self.promise_id:
            raise ValueError("promise_id must not contain '/'")
        if (
            type(self.promise_generation) is not int
            or isinstance(self.promise_generation, bool)
            or self.promise_generation < 0
        ):
            raise ValueError("promise_generation must be a non-negative int")
        _ids(self.probe_ids, "probe_ids", allow_empty=False)
        _ids(self.expected_side_effect_ids, "expected_side_effect_ids", allow_empty=True)
        if (
            type(self.max_age_seconds) is not int
            or isinstance(self.max_age_seconds, bool)
            or self.max_age_seconds <= 0
        ):
            raise ValueError("max_age_seconds must be a positive int")

    def subject_id(self, probe_id: str) -> str:
        return f"{LIVE_SUBJECT_PREFIX}{self.promise_id}/{probe_id}"

    @property
    def digest(self) -> str:
        """Canonical digest over every promise field."""
        value = {
            "schema": LIVE_BEHAVIOR_WITNESS_SCHEMA,
            "issue_ref": self.issue_ref,
            "issue_contract_hash": self.issue_contract_hash,
            "promise_id": self.promise_id,
            "promise_generation": self.promise_generation,
            "entry_id": self.entry_id,
            "action_id": self.action_id,
            "input_digest": self.input_digest,
            "probe_ids": list(self.probe_ids),
            "desired_source_revision": self.desired_source_revision,
            "expected_runtime_identity": self.expected_runtime_identity,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "expected_side_effect_ids": sorted(self.expected_side_effect_ids),
            "max_age_seconds": self.max_age_seconds,
            "signer_identity": self.signer_identity,
        }
        return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()

    @property
    def evidence_kind(self) -> str:
        """Evidence kind of this promise's subjects: ``live-behavior-witness.v1:<digest>``.

        Carrying the promise digest in the declared evidence kind binds the whole
        promise into ``AcceptanceContract.hash`` and ``universe_identity`` through
        fields Core already hashes, without a new protocol field.
        """
        return f"{LIVE_BEHAVIOR_EVIDENCE_KIND}:{self.digest}"

    @property
    def subject_ids(self) -> tuple[str, ...]:
        return tuple(self.subject_id(probe) for probe in self.probe_ids)

    @property
    def expected_subjects(self) -> tuple[ExpectedEvidenceSubject, ...]:
        """Universe entries the upstream contract must declare for this promise.

        Each subject's ``logical_subject_id`` doubles as its required verifier
        id, so the existing verifier-authority rule stays the only authority.
        """
        return tuple(
            ExpectedEvidenceSubject(
                sid,
                self.evidence_kind,
                RequirementMode.REQUIRED,
                Applicability.APPLICABLE,
            )
            for sid in self.subject_ids
        )


@dataclass(frozen=True)
class LiveWitnessVerification:
    """Outcome of consuming one witness; carries no policy facts."""

    result: VerificationResult
    evidence: EvidenceBundle | None
    observations: tuple[Observation, ...]
    witness_digest: str | None
    claim_ceiling: str = LIVE_WITNESS_CLAIM_CEILING


def live_witness_artifacts_digest(artifacts: object) -> str:
    """Canonical digest of the witness ``artifacts`` list (order-insensitive)."""
    if type(artifacts) is not list:
        raise TypeError("artifacts must be a list")
    rows: list[list[str]] = []
    for item in cast("list[object]", artifacts):
        if type(item) is not dict:
            raise TypeError("artifacts must contain objects")
        entry = cast("dict[str, object]", item)
        rows.append([_text(entry.get("id"), "artifact id"), _sha(entry.get("sha256"), "sha256")])
    rows.sort()
    return "sha256:" + hashlib.sha256(canonical_json(rows).encode()).hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise ValueError("non-finite number")


def _check_keys(obj: dict[str, Any], allowed: frozenset[str]) -> None:
    keys = set(obj)
    if keys & _RAW_OR_SECRET_FIELDS:
        raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:raw_output_field")
    if keys - allowed:
        raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:unknown_field")


def _parse_witness(witness_bytes: bytes) -> dict[str, Any]:
    malformed = _Reject(IntegrityStatus.MALFORMED, "MALFORMED:witness")
    try:
        raw: object = json.loads(
            witness_bytes.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise malformed from None
    if type(raw) is not dict:
        raise malformed
    witness = cast("dict[str, Any]", raw)
    if witness.get("schema") != LIVE_BEHAVIOR_WITNESS_SCHEMA:
        raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:schema")
    _check_keys(witness, _REQUIRED_FIELDS | _IGNORED_FIELDS)
    if not _REQUIRED_FIELDS <= set(witness):
        raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:missing_field")
    try:
        for name in (
            "issue_ref",
            "promise_id",
            "entry_id",
            "action_id",
            "execution_id",
            "attempt_id",
            "loaded_source_revision",
            "observed_runtime_identity",
            "readiness_status",
        ):
            _text(witness[name], name)
        for name in (
            "issue_contract_hash",
            "input_digest",
            "producer_software_hash",
            "artifacts_digest",
        ):
            _sha(witness[name], name)
        generation = witness["promise_generation"]
        if type(generation) is not int or generation < 0:
            raise ValueError("promise_generation")
        if witness["result_class"] not in _RESULT_CLASSES:
            raise ValueError("result_class")
        for name in ("started_at", "finished_at", "observed_at", "expires_at"):
            if _parse_time(witness[name]) is None:
                raise ValueError(name)
        side_effects = witness["side_effects"]
        if type(side_effects) is not list:
            raise ValueError("side_effects")
        _ids(tuple(cast("list[object]", side_effects)), "side_effects", allow_empty=True)
        reviewer_ids: object = witness.get("reviewer_ids", [])
        if type(reviewer_ids) is not list:
            raise ValueError("reviewer_ids")
        reviewer_list = cast("list[object]", reviewer_ids)
        if len(reviewer_list) > _MAX_REVIEWER_IDS:
            raise ValueError("reviewer_ids")
        for reviewer_id in reviewer_list:
            if len(_text(reviewer_id, "reviewer_ids")) > _MAX_REVIEWER_ID_LENGTH:
                raise ValueError("reviewer_ids")
        probes = witness["probes"]
        if type(probes) is not list or not probes:
            raise ValueError("probes")
        for probe in cast("list[object]", probes):
            if type(probe) is not dict:
                raise ValueError("probe")
            probe_obj = cast("dict[str, Any]", probe)
            _check_keys(probe_obj, _PROBE_FIELDS)
            _text(probe_obj.get("probe_id"), "probe_id")
            if type(probe_obj.get("hit")) is not bool:
                raise ValueError("hit")
        probe_ids = [cast("dict[str, Any]", p)["probe_id"] for p in cast("list[object]", probes)]
        if len(probe_ids) != len(set(probe_ids)):
            raise ValueError("duplicate probe")
        artifacts = witness["artifacts"]
        if type(artifacts) is not list:
            raise ValueError("artifacts")
        for item in cast("list[object]", artifacts):
            if type(item) is not dict:
                raise ValueError("artifact")
            _check_keys(cast("dict[str, Any]", item), _ARTIFACT_FIELDS)
        artifact_ids = [
            cast("dict[str, Any]", a).get("id") for a in cast("list[object]", artifacts)
        ]
        if len(artifact_ids) != len(set(map(str, artifact_ids))):
            raise ValueError("duplicate artifact")
        live_witness_artifacts_digest(cast(object, artifacts))
    except (TypeError, ValueError, KeyError):
        raise malformed from None
    times = [_parse_time(witness[n]) for n in ("started_at", "finished_at", "observed_at")]
    if not (times[0] and times[1] and times[2] and times[0] <= times[1] <= times[2]):
        raise malformed
    return witness


def _bundle_declares_other_digest(bundle_json: bytes, witness_bytes: bytes) -> bool:
    """True only when the bundle names a SHA2-256 digest that is not the witness's.

    A precise tamper signal; it never authenticates anything. Bundles without a
    readable message digest are left to the authenticator.
    """
    try:
        bundle: object = json.loads(bundle_json)
        if type(bundle) is not dict:
            return False
        signature = cast("dict[str, Any]", bundle).get("messageSignature")
        if type(signature) is not dict:
            return False
        digest = cast("dict[str, Any]", signature).get("messageDigest")
        if type(digest) is not dict:
            return False
        digest_obj = cast("dict[str, Any]", digest)
        if digest_obj.get("algorithm") != "SHA2_256" or type(digest_obj.get("digest")) is not str:
            return False
        declared = base64.b64decode(digest_obj["digest"], validate=True)
    except (ValueError, binascii.Error, UnicodeDecodeError, RecursionError):
        return False
    return declared != hashlib.sha256(witness_bytes).digest()


def _authenticate(
    authenticator: object, signer_policy: object, witness_bytes: bytes, bundle_json: object
) -> None:
    if authenticator is None or signer_policy is None or type(bundle_json) is not bytes:
        raise _Reject(IntegrityStatus.MISSING, "MISSING:witness_authentication")
    try:
        outcome = cast(Any, authenticator).authenticate(
            receipt_bytes=witness_bytes, bundle_json=bundle_json, policy=signer_policy
        )
        status = getattr(outcome, "status", None)
    except Exception:  # noqa: BLE001 - any authenticator fault is unknown infrastructure
        raise _Reject(
            IntegrityStatus.MISSING, "MISSING:witness_authentication_unavailable"
        ) from None
    if type(status) is str and status == _AUTHENTICATED:
        return
    if type(status) is str and status == _UNAVAILABLE:
        raise _Reject(IntegrityStatus.MISSING, "MISSING:witness_authentication_unavailable")
    raise _Reject(IntegrityStatus.CROSS_BOUND, "CROSS_BOUND:issuer")


def _check_promise_contract(
    promise: LiveBehaviorPromise,
    contract: AcceptanceContract,
    change_set: ChangeSet,
    plan: VerificationPlan,
) -> None:
    # The promise is for exactly this Issue contract: its issue_contract_hash is
    # the contract's requirements_hash, and its full digest is carried in the
    # declared subjects' evidence kind (covered by contract.hash).
    if contract.requirements_hash != promise.issue_contract_hash:
        raise _Reject(IntegrityStatus.CROSS_BOUND, "CROSS_BOUND:promise_contract")
    declared = {s.canonical_value for s in contract.expected_subjects}
    for subject in promise.expected_subjects:
        if (
            subject.canonical_value not in declared
            or subject.logical_subject_id not in contract.required_verifier_ids
            or subject.logical_subject_id not in plan.required_verifier_ids
        ):
            raise _Reject(IntegrityStatus.CROSS_BOUND, "CROSS_BOUND:promise_contract")
    if contract.universe_generation != promise.promise_generation:
        raise _Reject(IntegrityStatus.STALE, "STALE:generation")
    # merge HEAD under review == promised revision (G0 section 2); a source
    # mismatch is STALE per Owner decision D5.
    if change_set.target_revision != promise.desired_source_revision:
        raise _Reject(IntegrityStatus.STALE, "STALE:subject")


def _check_binding(promise: LiveBehaviorPromise, witness: dict[str, Any], now: str) -> None:
    if witness["artifacts_digest"] != live_witness_artifacts_digest(witness["artifacts"]):
        raise _Reject(IntegrityStatus.TAMPERED, "TAMPERED:artifacts_digest")
    for name in (
        "issue_ref",
        "issue_contract_hash",
        "promise_id",
        "entry_id",
        "action_id",
        "input_digest",
    ):
        if witness[name] != getattr(promise, name):
            raise _Reject(IntegrityStatus.CROSS_BOUND, "CROSS_BOUND:promise")
    if any(p["probe_id"] not in promise.probe_ids for p in witness["probes"]):
        raise _Reject(IntegrityStatus.CROSS_BOUND, "CROSS_BOUND:promise")
    if witness["promise_generation"] != promise.promise_generation:
        raise _Reject(IntegrityStatus.STALE, "STALE:generation")
    if (
        witness["execution_id"] != promise.execution_id
        or witness["attempt_id"] != promise.attempt_id
    ):
        raise _Reject(IntegrityStatus.CROSS_BOUND, "CROSS_BOUND:execution")
    observed_at = _parse_time(witness["observed_at"])
    current = _parse_time(now)
    if observed_at is None or current is None:
        raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:time")
    if (current - observed_at).total_seconds() > promise.max_age_seconds:
        raise _Reject(IntegrityStatus.STALE, "STALE:observation")
    runtime = RuntimeSourceObservation(
        generation=EvidenceGeneration.RUNTIME,
        desired_source_revision=promise.desired_source_revision,
        loaded_source_revision=witness["loaded_source_revision"],
        expected_runtime_identity=promise.expected_runtime_identity,
        observed_runtime_identity=witness["observed_runtime_identity"],
        desired_generation=promise.promise_generation,
        observed_generation=witness["promise_generation"],
        observed_at=witness["observed_at"],
        expires_at=witness["expires_at"],
        readiness_status=witness["readiness_status"],
    )
    freshness = derive_runtime_freshness(runtime, now)
    if freshness is FreshnessStatus.STALE_OBSERVATION:
        raise _Reject(IntegrityStatus.STALE, "STALE:observation")
    if freshness is FreshnessStatus.SOURCE_AHEAD_OF_RUNTIME:
        raise _Reject(IntegrityStatus.STALE, "STALE:subject")
    if freshness is FreshnessStatus.RUNTIME_IDENTITY_MISMATCH:
        raise _Reject(IntegrityStatus.CROSS_BOUND, "CROSS_BOUND:runtime")
    if freshness is not FreshnessStatus.READY_IDENTITY_BOUND:
        raise _Reject(IntegrityStatus.MISSING, "MISSING:runtime_identity")


def _live_observations(
    promise: LiveBehaviorPromise, witness: dict[str, Any], witness_digest: str
) -> tuple[Observation, ...]:
    result_class = witness["result_class"]
    hits = [p["probe_id"] for p in witness["probes"] if p["hit"] is True]
    if result_class == "UNKNOWN_INFRA":
        raise _Reject(IntegrityStatus.MISSING, "MISSING:unknown_infra")
    if result_class == "NOT_EXERCISED":
        if hits:
            raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:result_class")
        return ()
    if result_class == "PARTIAL":
        # A partial run asserts nothing positive: every live subject stays
        # NOT_COVERED (MISSING). Claiming PARTIAL with every probe hit is
        # self-contradictory.
        if set(hits) >= set(promise.probe_ids):
            raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:result_class")
        return ()
    side_effects_match = set(witness["side_effects"]) == set(promise.expected_side_effect_ids)
    status = (
        ObservationStatus.PASS
        if result_class == "PASS" and side_effects_match
        else ObservationStatus.FAIL
    )
    return tuple(
        Observation(
            verifier_id=promise.subject_id(probe),
            artifact_id=f"{promise.subject_id(probe)}@{promise.execution_id}",
            artifact_hash=witness_digest,
            status=status,
            logical_subject_id=promise.subject_id(probe),
            evidence_kind=promise.evidence_kind,
        )
        for probe in promise.probe_ids
        if probe in hits
    )


def _rejected(
    condition: IntegrityStatus, reason: str, digest: str | None
) -> LiveWitnessVerification:
    return LiveWitnessVerification(
        result=reduce_verification(condition, reasons=(reason,)),
        evidence=None,
        observations=(),
        witness_digest=digest,
    )


def verify_live_behavior_witness(
    *,
    promise: LiveBehaviorPromise,
    contract: AcceptanceContract,
    change_set: ChangeSet,
    plan: VerificationPlan,
    witness_bytes: bytes | None,
    bundle_json: bytes | None,
    authenticator: object,
    signer_policy: object,
    now: str,
    other_observations: tuple[Observation, ...] = (),
    bundle_id: str = "live-behavior-witness",
) -> LiveWitnessVerification:
    """Consume one witness and return Core's verdict over the whole contract.

    ``authenticator`` must implement ``authenticate(receipt_bytes=, bundle_json=,
    policy=)`` returning an object whose ``status`` is ``AUTHENTICATED`` /
    ``NOT_AUTHENTICATED`` / ``UNAVAILABLE`` (the client-layer
    ``SigstoreReceiptAuthenticator``). ``signer_policy`` is that layer's signer
    policy loaded from trusted base-ref configuration, never from the witness.
    ``other_observations`` are the contract's non-live observations; they may
    not carry evidence for the live subjects.
    """
    if type(promise) is not LiveBehaviorPromise:
        raise TypeError("promise must be LiveBehaviorPromise")
    if type(contract) is not AcceptanceContract:
        raise TypeError("contract must be AcceptanceContract")
    if type(change_set) is not ChangeSet:
        raise TypeError("change_set must be ChangeSet")
    if type(plan) is not VerificationPlan:
        raise TypeError("plan must be VerificationPlan")
    if type(other_observations) is not tuple or any(
        type(o) is not Observation for o in other_observations
    ):
        raise TypeError("other_observations must be a tuple of Observation")
    if _parse_time(now) is None:
        raise ValueError("now must be a UTC RFC 3339 timestamp")

    live_ids = set(promise.subject_ids)
    digest: str | None = None
    try:
        if any(
            o.verifier_id in live_ids
            or o.logical_subject_id in live_ids
            or (o.evidence_kind or "").startswith(LIVE_BEHAVIOR_EVIDENCE_KIND)
            for o in other_observations
        ):
            raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:other_observations_live_subject")
        _check_promise_contract(promise, contract, change_set, plan)
        live: tuple[Observation, ...] = ()
        if witness_bytes is not None:
            if type(witness_bytes) is not bytes or len(witness_bytes) > MAX_WITNESS_BYTES:
                raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:witness")
            digest = "sha256:" + hashlib.sha256(witness_bytes).hexdigest()
            if bundle_json is not None and (
                type(bundle_json) is not bytes or len(bundle_json) > MAX_BUNDLE_BYTES
            ):
                raise _Reject(IntegrityStatus.MALFORMED, "MALFORMED:bundle")
            if type(bundle_json) is bytes and _bundle_declares_other_digest(
                bundle_json, witness_bytes
            ):
                raise _Reject(IntegrityStatus.TAMPERED, "TAMPERED:witness_digest")
            witness = _parse_witness(witness_bytes)
            if signer_policy is not None and getattr(signer_policy, "identity", None) != (
                promise.signer_identity
            ):
                raise _Reject(IntegrityStatus.CROSS_BOUND, "CROSS_BOUND:signer_identity")
            _authenticate(authenticator, signer_policy, witness_bytes, bundle_json)
            _check_binding(promise, witness, now)
            live = _live_observations(promise, witness, digest)
    except _Reject as rejection:
        return _rejected(rejection.condition, rejection.reason, digest)

    observations = other_observations + live
    if not observations:
        coverage = derive_coverage(
            contract.expected_subjects,
            (),
            universe_generation=contract.universe_generation,
            universe_identity=contract.universe_identity,
        )
        reasons = {IntegrityStatus.MISSING.value, *promise.subject_ids}
        if any(e.category is CoverageCategory.UNRESOLVED for e in coverage.entries):
            reasons.add("COVERAGE_UNRESOLVED")
        return LiveWitnessVerification(
            result=reduce_verification(
                IntegrityStatus.MISSING, reasons=tuple(sorted(reasons)), coverage=coverage
            ),
            evidence=None,
            observations=(),
            witness_digest=digest,
        )
    evidence = EvidenceBundle(bundle_id, contract.hash, change_set.hash, plan.hash, observations)
    return LiveWitnessVerification(
        result=verify(contract, change_set, plan, evidence),
        evidence=evidence,
        observations=observations,
        witness_digest=digest,
    )


__all__ = [
    "LIVE_BEHAVIOR_EVIDENCE_KIND",
    "LIVE_BEHAVIOR_WITNESS_SCHEMA",
    "LIVE_SUBJECT_PREFIX",
    "LIVE_WITNESS_CLAIM_CEILING",
    "MAX_BUNDLE_BYTES",
    "MAX_WITNESS_BYTES",
    "LiveBehaviorPromise",
    "LiveWitnessVerification",
    "live_witness_artifacts_digest",
    "verify_live_behavior_witness",
]
