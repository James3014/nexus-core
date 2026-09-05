import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from types import FunctionType

from product.protocol import EVIDENCE_BUNDLE_SCHEMA


def _make_canonical_json(dumps):
    def canonical_json(value):
        active = set()

        def clean(v):
            if v is None or type(v) in (str, int, bool):
                return v
            if type(v) in (tuple, list):
                marker = id(v)
                if marker in active:
                    raise ValueError("cyclic canonical value")
                active.add(marker)
                result = [clean(x) for x in v]
                active.remove(marker)
                return result
            if type(v) is dict:
                marker = id(v)
                if marker in active:
                    raise ValueError("cyclic canonical value")
                active.add(marker)
                if any(not isinstance(k, str) for k in v):
                    raise TypeError("canonical object keys must be strings")
                result = {k: clean(v[k]) for k in sorted(v)}
                active.remove(marker)
                return result
            raise TypeError(f"unsupported canonical value: {type(v).__name__}")

        return dumps(clean(value), sort_keys=True, separators=(",", ":"), allow_nan=False)

    return canonical_json


canonical_json = _make_canonical_json(json.dumps)


def _make_hash(canonical, sha256):
    def hash_value(value):
        return "sha256:" + sha256(canonical(value).encode()).hexdigest()

    return hash_value


_hash = _make_hash(canonical_json, hashlib.sha256)


def _make_identity_property(hash_fn, value_fn):
    def identity(self):
        return hash_fn(value_fn(self))

    return property(identity)


class IntegrityStatus(str, Enum):
    VALID = "VALID"
    SCOPE_ESCAPE = "SCOPE_ESCAPE"
    MISSING = "MISSING"
    STALE = "STALE"
    TAMPERED = "TAMPERED"
    MALFORMED = "MALFORMED"
    CROSS_BOUND = "CROSS_BOUND"
    DUPLICATE = "DUPLICATE"
    LEGACY_NON_CERTIFIABLE = "LEGACY_NON_CERTIFIABLE"
    CROSS_BINDING_INVALID = "CROSS_BOUND"


EvidenceCondition = IntegrityStatus


class ObservationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SEALED_HASH_RE_FULLMATCH = _HASH_RE.fullmatch


def _require_text(value, field):
    if type(value) is not str:
        raise TypeError(f"{field} must be a string")
    if not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{field} must be non-empty and normalized")


def _make_require_hash(fullmatch):
    def require_hash(value, field):
        if type(value) is not str:
            raise TypeError(f"{field} must be a string")
        if not value or value != value.strip() or "\x00" in value:
            raise ValueError(f"{field} must be non-empty and normalized")
        if fullmatch(value) is None:
            raise ValueError(f"{field} must be sha256:<64 lowercase hex>")

    return require_hash


_require_hash = _make_require_hash(_SEALED_HASH_RE_FULLMATCH)


def _make_sealed_require_hash(require_text, fullmatch):
    def require_hash(value, field):
        require_text(value, field)
        if fullmatch(value) is None:
            raise ValueError(f"{field} must be sha256:<64 lowercase hex>")

    return require_hash


_VALIDATOR_REQUIRE_HASH = _make_sealed_require_hash(_require_text, _SEALED_HASH_RE_FULLMATCH)


def _make_sealed_require_ids(require_text):
    def require_ids(values, field):
        if type(values) is not tuple:
            raise TypeError(f"{field} must be a tuple")
        for value in values:
            require_text(value, field)
        if len(values) != len(set(values)):
            raise ValueError(f"{field} must not contain duplicates")
        if not values:
            raise ValueError(f"{field} must be non-empty")

    return require_ids


def _make_sealed_require_paths(require_ids):
    def require_paths(values, field):
        require_ids(values, field)
        for value in values:
            if (
                value.startswith("/")
                or "\\" in value
                or any(part in {"", ".", ".."} for part in value.split("/"))
            ):
                raise ValueError(f"{field} must contain relative paths")

    return require_paths


_VALIDATOR_REQUIRE_IDS = _make_sealed_require_ids(_require_text)
_VALIDATOR_REQUIRE_PATHS = _make_sealed_require_paths(_VALIDATOR_REQUIRE_IDS)


def _require_ids(values, field):
    if not isinstance(values, tuple):
        raise TypeError(f"{field} must be a tuple")
    for value in values:
        _require_text(value, field)
    if len(values) != len(set(values)):
        raise ValueError(f"{field} must not contain duplicates")
    if not values:
        raise ValueError(f"{field} must be non-empty")


def _require_paths(values, field):
    _require_ids(values, field)
    for value in values:
        if (
            value.startswith("/")
            or "\\" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise ValueError(f"{field} must contain relative paths")


def validate_normalized_paths(values, field="paths"):
    """Validate a normalized tuple of repository-relative POSIX paths."""
    _require_paths(values, field)
    return values


@dataclass(frozen=True)
class AcceptanceContract:
    contract_id: str
    requirements_hash: str
    required_verifier_ids: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    deletion_policy: str

    def __post_init__(self):
        _require_text(self.contract_id, "contract_id")
        _require_hash(self.requirements_hash, "requirements_hash")
        _require_ids(self.required_verifier_ids, "required_verifier_ids")
        _require_paths(self.allowed_paths, "allowed_paths")
        if type(self.deletion_policy) is not str or self.deletion_policy not in {"FORBID", "ALLOW"}:
            raise ValueError("deletion_policy must be FORBID or ALLOW")

    @property
    def hash(self):
        return _AC_HASH(
            (
                self.contract_id,
                self.requirements_hash,
                tuple(sorted(self.required_verifier_ids)),
                tuple(sorted(self.allowed_paths)),
                self.deletion_policy,
            )
        )


@dataclass(frozen=True)
class ChangeSet:
    change_set_id: str
    source_revision: str
    target_revision: str
    diff_hash: str
    paths: tuple[str, ...]

    def __post_init__(self):
        _require_text(self.change_set_id, "change_set_id")
        _require_text(self.source_revision, "source_revision")
        _require_text(self.target_revision, "target_revision")
        _require_hash(self.diff_hash, "diff_hash")
        _require_paths(self.paths, "paths")

    @property
    def hash(self):
        return _CS_HASH(
            (
                self.change_set_id,
                self.source_revision,
                self.target_revision,
                self.diff_hash,
                tuple(sorted(self.paths)),
            )
        )


@dataclass(frozen=True)
class VerificationPlan:
    plan_id: str
    acceptance_contract_hash: str
    change_set_hash: str
    required_verifier_ids: tuple[str, ...]

    def __post_init__(self):
        _require_text(self.plan_id, "plan_id")
        _require_hash(self.acceptance_contract_hash, "acceptance_contract_hash")
        _require_hash(self.change_set_hash, "change_set_hash")
        _require_ids(self.required_verifier_ids, "required_verifier_ids")

    @property
    def hash(self):
        return _VP_HASH(
            (
                self.plan_id,
                self.acceptance_contract_hash,
                self.change_set_hash,
                tuple(sorted(self.required_verifier_ids)),
            )
        )


@dataclass(frozen=True)
class Observation:
    verifier_id: str
    artifact_id: str
    artifact_hash: str
    status: ObservationStatus

    def __post_init__(self):
        _require_text(self.verifier_id, "verifier_id")
        _require_text(self.artifact_id, "artifact_id")
        _require_hash(self.artifact_hash, "artifact_hash")
        if type(self.status) is not ObservationStatus:
            raise TypeError("status must be ObservationStatus")


@dataclass(frozen=True)
class EvidenceBundle:
    bundle_id: str
    acceptance_contract_hash: str
    change_set_hash: str
    verification_plan_hash: str
    observations: tuple[Observation, ...]
    claimed_bundle_hash: str | None = None

    def __post_init__(self):
        _require_text(self.bundle_id, "bundle_id")
        _require_hash(self.acceptance_contract_hash, "acceptance_contract_hash")
        _require_hash(self.change_set_hash, "change_set_hash")
        _require_hash(self.verification_plan_hash, "verification_plan_hash")
        if type(self.observations) is not tuple or not self.observations:
            raise ValueError("observations must be non-empty tuple")
        if any(type(observation) is not Observation for observation in self.observations):
            raise TypeError("observations must contain Observation values")
        if self.claimed_bundle_hash is not None:
            _require_hash(self.claimed_bundle_hash, "claimed_bundle_hash")

    @property
    def canonical_value(self):
        return (
            self.bundle_id,
            self.acceptance_contract_hash,
            self.change_set_hash,
            self.verification_plan_hash,
            tuple(
                (o.verifier_id, o.artifact_id, o.artifact_hash, o.status.value)
                for o in sorted(self.observations, key=lambda x: (x.verifier_id, x.artifact_id))
            ),
        )

    @property
    def hash(self):
        return _EB_HASH(self.canonical_value)

    @property
    def envelope_hash(self):
        """Hash of the native serialized envelope (distinct from ``hash``)."""
        return self.to_dict()["bundle_hash"]

    def integrity(self, contract, change_set, plan):
        if self.claimed_bundle_hash is not None and self.claimed_bundle_hash != self.hash:
            return IntegrityStatus.TAMPERED
        if self.acceptance_contract_hash != contract.hash:
            return IntegrityStatus.CROSS_BOUND
        if self.change_set_hash != change_set.hash:
            return IntegrityStatus.STALE
        if (
            self.verification_plan_hash != plan.hash
            or plan.acceptance_contract_hash != contract.hash
            or plan.change_set_hash != change_set.hash
        ):
            return IntegrityStatus.CROSS_BINDING_INVALID
        verifier_ids = [o.verifier_id for o in self.observations]
        artifact_ids = [o.artifact_id for o in self.observations]
        if len(verifier_ids) != len(set(verifier_ids)) or len(artifact_ids) != len(
            set(artifact_ids)
        ):
            return IntegrityStatus.DUPLICATE
        return IntegrityStatus.VALID

    def to_dict(self):
        if self.claimed_bundle_hash is not None and self.claimed_bundle_hash != self.hash:
            raise ValueError("claimed_bundle_hash does not match computed hash")
        body = {
            "evidence_bundle_schema": EVIDENCE_BUNDLE_SCHEMA,
            "bundle_id": self.bundle_id,
            "acceptance_contract_hash": self.acceptance_contract_hash,
            "change_set_hash": self.change_set_hash,
            "verification_plan_hash": self.verification_plan_hash,
            "observations": [
                {
                    "verifier_id": o.verifier_id,
                    "artifact_id": o.artifact_id,
                    "artifact_hash": o.artifact_hash,
                    "status": o.status.value,
                }
                for o in sorted(self.observations, key=lambda x: (x.verifier_id, x.artifact_id))
            ],
        }
        body["bundle_hash"] = _EB_ENVELOPE_HASH(body)
        return body


_AC_HASH = _make_hash(canonical_json, hashlib.sha256)
_CS_HASH = _make_hash(canonical_json, hashlib.sha256)
_VP_HASH = _make_hash(canonical_json, hashlib.sha256)
_EB_HASH = _make_hash(canonical_json, hashlib.sha256)
_EB_ENVELOPE_HASH = _make_hash(canonical_json, hashlib.sha256)
_SEALED_EB_ENVELOPE_HASH = _EB_ENVELOPE_HASH
_VALIDATOR_EB_ENVELOPE_HASH = _SEALED_EB_ENVELOPE_HASH


def _make_bundle_core_serializer():
    def serialize(bundle):
        observations = tuple(
            (
                vars(o)["verifier_id"],
                vars(o)["artifact_id"],
                vars(o)["artifact_hash"],
                vars(o)["status"].value,
            )
            for o in sorted(
                vars(bundle)["observations"],
                key=lambda x: (vars(x)["verifier_id"], vars(x)["artifact_id"]),
            )
        )
        return (
            vars(bundle)["bundle_id"],
            vars(bundle)["acceptance_contract_hash"],
            vars(bundle)["change_set_hash"],
            vars(bundle)["verification_plan_hash"],
            observations,
        )

    return serialize


_SEALED_BUNDLE_CORE_SERIALIZER = _make_bundle_core_serializer()


def _make_bundle_core_hash(serializer, hash_fn):
    def compute(bundle):
        return hash_fn(serializer(bundle))

    return compute


_SEALED_BUNDLE_CORE_HASH = _make_bundle_core_hash(_SEALED_BUNDLE_CORE_SERIALIZER, _EB_HASH)


def _make_bundle_serializer(envelope_hash, schema, core_hash):
    def serialize(self):
        if self.claimed_bundle_hash is not None and self.claimed_bundle_hash != core_hash(self):
            raise ValueError("claimed_bundle_hash does not match computed hash")
        body = {
            "evidence_bundle_schema": schema,
            "bundle_id": self.bundle_id,
            "acceptance_contract_hash": self.acceptance_contract_hash,
            "change_set_hash": self.change_set_hash,
            "verification_plan_hash": self.verification_plan_hash,
            "observations": [
                {
                    "verifier_id": o.verifier_id,
                    "artifact_id": o.artifact_id,
                    "artifact_hash": o.artifact_hash,
                    "status": o.status.value,
                }
                for o in sorted(self.observations, key=lambda x: (x.verifier_id, x.artifact_id))
            ],
        }
        body["bundle_hash"] = envelope_hash(body)
        return body

    return serialize


_SEALED_BUNDLE_SERIALIZER = _make_bundle_serializer(
    _SEALED_EB_ENVELOPE_HASH, EVIDENCE_BUNDLE_SCHEMA, _SEALED_BUNDLE_CORE_HASH
)
EvidenceBundle.to_dict = _SEALED_BUNDLE_SERIALIZER


def _make_envelope_hash_property(serializer):
    def envelope_hash(self):
        return serializer(self)["bundle_hash"]

    return property(envelope_hash)


EvidenceBundle.envelope_hash = _make_envelope_hash_property(  # pyright: ignore[reportAttributeAccessIssue]
    _SEALED_BUNDLE_SERIALIZER
)

AcceptanceContract.hash = _make_identity_property(  # pyright: ignore[reportAttributeAccessIssue]
    _AC_HASH,
    lambda value: (
        value.contract_id,
        value.requirements_hash,
        tuple(sorted(value.required_verifier_ids)),
        tuple(sorted(value.allowed_paths)),
        value.deletion_policy,
    ),
)
ChangeSet.hash = _make_identity_property(  # pyright: ignore[reportAttributeAccessIssue]
    _CS_HASH,
    lambda value: (
        value.change_set_id,
        value.source_revision,
        value.target_revision,
        value.diff_hash,
        tuple(sorted(value.paths)),
    ),
)
VerificationPlan.hash = _make_identity_property(  # pyright: ignore[reportAttributeAccessIssue]
    _VP_HASH,
    lambda value: (
        value.plan_id,
        value.acceptance_contract_hash,
        value.change_set_hash,
        tuple(sorted(value.required_verifier_ids)),
    ),
)
EvidenceBundle.hash = _make_identity_property(  # pyright: ignore[reportAttributeAccessIssue]
    _SEALED_BUNDLE_CORE_HASH, lambda value: value
)


def _make_subject_validator(
    contract_type,
    change_set_type,
    plan_type,
    evidence_type,
    observation_type,
    observation_status_type,
    require_text,
    require_hash,
    require_ids,
    require_paths,
):
    """Build an input validator whose dependencies cannot be rebound later."""

    def validate(contract, change_set, plan, evidence):
        errors = []

        def check(expected, value, name):
            if type(value) is not expected:
                errors.append(f"MALFORMED:{name}")
                return False
            return True

        def fields(value, expected, name):
            if not check(expected, value, name):
                return None
            data = vars(value)
            if set(data) != set(expected.__dataclass_fields__):
                errors.append(f"MALFORMED:{name}")
                return None
            return data

        c = fields(contract, contract_type, "contract")
        cs = fields(change_set, change_set_type, "change_set")
        p = fields(plan, plan_type, "plan")
        e = fields(evidence, evidence_type, "evidence")

        def text(data, key, prefix):
            if data is not None:
                try:
                    require_text(data[key], key)
                except (TypeError, ValueError, KeyError):
                    errors.append(f"MALFORMED:{prefix}.{key}")

        def hash_value(data, key, prefix):
            if data is not None:
                try:
                    require_hash(data[key], key)
                except (TypeError, ValueError, KeyError):
                    errors.append(f"MALFORMED:{prefix}.{key}")

        if c is not None:
            text(c, "contract_id", "contract")
            hash_value(c, "requirements_hash", "contract")
            try:
                require_ids(c["required_verifier_ids"], "required_verifier_ids")
            except (TypeError, ValueError, KeyError):
                errors.append("MALFORMED:contract.required_verifier_ids")
            try:
                require_paths(c["allowed_paths"], "allowed_paths")
            except (TypeError, ValueError, KeyError):
                errors.append("MALFORMED:contract.allowed_paths")
            if type(c.get("deletion_policy")) is not str or c["deletion_policy"] not in {
                "FORBID",
                "ALLOW",
            }:
                errors.append("MALFORMED:contract.deletion_policy")
        if cs is not None:
            for key in ("change_set_id", "source_revision", "target_revision"):
                text(cs, key, "change_set")
            hash_value(cs, "diff_hash", "change_set")
            try:
                require_paths(cs["paths"], "paths")
            except (TypeError, ValueError, KeyError):
                errors.append("MALFORMED:change_set.paths")
        if p is not None:
            text(p, "plan_id", "plan")
            for key in ("acceptance_contract_hash", "change_set_hash"):
                hash_value(p, key, "plan")
            try:
                require_ids(p["required_verifier_ids"], "required_verifier_ids")
            except (TypeError, ValueError, KeyError):
                errors.append("MALFORMED:plan.required_verifier_ids")
        if e is not None:
            text(e, "bundle_id", "evidence")
            for key in ("acceptance_contract_hash", "change_set_hash", "verification_plan_hash"):
                hash_value(e, key, "evidence")
            if e.get("claimed_bundle_hash") is not None:
                hash_value(e, "claimed_bundle_hash", "evidence")
            observations = e.get("observations")
            if type(observations) is not tuple or not observations:
                errors.append("MALFORMED:evidence.observations")
            else:
                for index, observation in enumerate(observations):
                    od = fields(observation, observation_type, f"evidence.observations[{index}]")
                    if od is None:
                        continue
                    text(od, "verifier_id", f"evidence.observations[{index}]")
                    text(od, "artifact_id", f"evidence.observations[{index}]")
                    hash_value(od, "artifact_hash", f"evidence.observations[{index}]")
                    if type(od.get("status")) is not observation_status_type:
                        errors.append(f"MALFORMED:evidence.observations[{index}].status")
        return tuple(dict.fromkeys(errors))

    return validate


validate_evidence_subjects = _make_subject_validator(
    AcceptanceContract,
    ChangeSet,
    VerificationPlan,
    EvidenceBundle,
    Observation,
    ObservationStatus,
    _require_text,
    _VALIDATOR_REQUIRE_HASH,
    _VALIDATOR_REQUIRE_IDS,
    _VALIDATOR_REQUIRE_PATHS,
)


def _make_integrity_deriver(
    contract_type,
    change_set_type,
    plan_type,
    evidence_type,
    observation_type,
    status_type,
    hash_contract,
    hash_change_set,
    hash_plan,
    hash_evidence,
    subject_validator,
):
    def derive(contract, change_set, plan, evidence):
        if (
            type(contract) is not contract_type
            or type(change_set) is not change_set_type
            or type(plan) is not plan_type
            or type(evidence) is not evidence_type
        ):
            return status_type.MALFORMED
        if subject_validator(contract, change_set, plan, evidence):
            return status_type.MALFORMED
        c, cs, p, e = (vars(contract), vars(change_set), vars(plan), vars(evidence))
        contract_hash = hash_contract(
            (
                c["contract_id"],
                c["requirements_hash"],
                tuple(sorted(c["required_verifier_ids"])),
                tuple(sorted(c["allowed_paths"])),
                c["deletion_policy"],
            )
        )
        change_hash = hash_change_set(
            (
                cs["change_set_id"],
                cs["source_revision"],
                cs["target_revision"],
                cs["diff_hash"],
                tuple(sorted(cs["paths"])),
            )
        )
        plan_hash = hash_plan(
            (
                p["plan_id"],
                p["acceptance_contract_hash"],
                p["change_set_hash"],
                tuple(sorted(p["required_verifier_ids"])),
            )
        )
        observations = e["observations"]
        canonical = (
            e["bundle_id"],
            e["acceptance_contract_hash"],
            e["change_set_hash"],
            e["verification_plan_hash"],
            tuple(
                (
                    vars(o)["verifier_id"],
                    vars(o)["artifact_id"],
                    vars(o)["artifact_hash"],
                    vars(o)["status"].value,
                )
                for o in sorted(
                    observations, key=lambda x: (vars(x)["verifier_id"], vars(x)["artifact_id"])
                )
            ),
        )
        evidence_hash = hash_evidence(canonical)
        if e["claimed_bundle_hash"] is not None and e["claimed_bundle_hash"] != evidence_hash:
            return status_type.TAMPERED
        if e["acceptance_contract_hash"] != contract_hash:
            return status_type.CROSS_BOUND
        if e["change_set_hash"] != change_hash:
            return status_type.STALE
        if (
            e["verification_plan_hash"] != plan_hash
            or p["acceptance_contract_hash"] != contract_hash
            or p["change_set_hash"] != change_hash
        ):
            return status_type.CROSS_BINDING_INVALID
        verifier_ids = [vars(o)["verifier_id"] for o in observations]
        artifact_ids = [vars(o)["artifact_id"] for o in observations]
        if len(verifier_ids) != len(set(verifier_ids)) or len(artifact_ids) != len(
            set(artifact_ids)
        ):
            return status_type.DUPLICATE
        return status_type.VALID

    return derive


derive_evidence_integrity = _make_integrity_deriver(
    AcceptanceContract,
    ChangeSet,
    VerificationPlan,
    EvidenceBundle,
    Observation,
    IntegrityStatus,
    _AC_HASH,
    _CS_HASH,
    _VP_HASH,
    _EB_HASH,
    validate_evidence_subjects,
)


def validate_evidence_bundle_envelope(
    payload, contract, change_set, plan, *, expected_bundle=None, expected_envelope_hash=None
):
    if (expected_bundle is None) == (expected_envelope_hash is None):
        raise TypeError(
            "exactly one independently supplied expected bundle or envelope hash is required"
        )
    if expected_bundle is not None and type(expected_bundle) is not EvidenceBundle:
        raise TypeError("expected_bundle must be EvidenceBundle")
    if expected_bundle is not None and expected_bundle.claimed_bundle_hash is not None:
        if expected_bundle.claimed_bundle_hash != _SEALED_BUNDLE_CORE_HASH(expected_bundle):
            raise ValueError("expected_bundle claimed hash does not match computed hash")
    if expected_envelope_hash is not None:
        _VALIDATOR_REQUIRE_HASH(expected_envelope_hash, "expected_envelope_hash")
    if type(contract) is not AcceptanceContract:
        raise TypeError("contract must be AcceptanceContract")
    if type(change_set) is not ChangeSet:
        raise TypeError("change_set must be ChangeSet")
    if type(plan) is not VerificationPlan:
        raise TypeError("plan must be VerificationPlan")
    errors = []
    try:
        if type(payload) is not dict:
            return ("MALFORMED:payload",)
        expected_keys = {
            "evidence_bundle_schema",
            "bundle_id",
            "acceptance_contract_hash",
            "change_set_hash",
            "verification_plan_hash",
            "observations",
            "bundle_hash",
        }
        if set(payload) != expected_keys:
            errors.append("MALFORMED:keys")
        if payload.get("evidence_bundle_schema") != EVIDENCE_BUNDLE_SCHEMA:
            errors.append("STALE:evidence_bundle_schema")
        for field in (
            "bundle_id",
            "acceptance_contract_hash",
            "change_set_hash",
            "verification_plan_hash",
            "bundle_hash",
        ):
            if field not in payload or not isinstance(payload[field], str):
                errors.append(f"MALFORMED:{field}")
        if isinstance(payload.get("bundle_id"), str):
            _require_text(payload["bundle_id"], "bundle_id")
        for field in (
            "acceptance_contract_hash",
            "change_set_hash",
            "verification_plan_hash",
            "bundle_hash",
        ):
            if isinstance(payload.get(field), str):
                _VALIDATOR_REQUIRE_HASH(payload[field], field)
        observations = payload.get("observations")
        if not isinstance(observations, list) or not observations:
            errors.append("MALFORMED:observations")
        rows = []
        if type(observations) is list:
            for i, row in enumerate(observations):
                if type(row) is not dict or set(row) != {
                    "verifier_id",
                    "artifact_id",
                    "artifact_hash",
                    "status",
                }:
                    errors.append(f"MALFORMED:observations[{i}]")
                    continue
                if not all(
                    isinstance(row.get(k), str)
                    for k in ("verifier_id", "artifact_id", "artifact_hash", "status")
                ):
                    errors.append(f"MALFORMED:observations[{i}]")
                    continue
                if row["status"] not in {"PASS", "FAIL"}:
                    errors.append(f"MALFORMED:observations[{i}].status")
                try:
                    _require_text(row["verifier_id"], "verifier_id")
                    _require_text(row["artifact_id"], "artifact_id")
                    _VALIDATOR_REQUIRE_HASH(row["artifact_hash"], "artifact_hash")
                except (TypeError, ValueError):
                    errors.append(f"MALFORMED:observations[{i}]")
                rows.append(
                    (row["verifier_id"], row["artifact_id"], row["artifact_hash"], row["status"])
                )
        if len({r[0] for r in rows}) != len(rows) or len({r[1] for r in rows}) != len(rows):
            errors.append("DUPLICATE:observations")
        if rows != sorted(rows, key=lambda r: (r[0], r[1])):
            errors.append("MALFORMED:observation_order")
        body = {k: payload[k] for k in expected_keys - {"bundle_hash"} if k in payload}
        if not errors and payload.get("bundle_hash") != _VALIDATOR_EB_ENVELOPE_HASH(body):
            errors.append("TAMPERED:bundle_hash")
        if payload.get("acceptance_contract_hash") != contract.hash:
            errors.append("CROSS_BOUND:acceptance_contract_hash")
        if payload.get("change_set_hash") != change_set.hash:
            errors.append("STALE:change_set_hash")
        if (
            payload.get("verification_plan_hash") != plan.hash
            or plan.acceptance_contract_hash != contract.hash
            or plan.change_set_hash != change_set.hash
        ):
            errors.append("CROSS_BINDING_INVALID:verification_plan_hash")
        if not errors:
            if expected_bundle is not None:
                if payload != _SEALED_BUNDLE_SERIALIZER(expected_bundle):
                    errors.append("TAMPERED:fields")
            elif payload.get("bundle_hash") != expected_envelope_hash:
                errors.append("TAMPERED:fields")
    except (TypeError, ValueError, RecursionError, OverflowError):
        errors.append("MALFORMED:payload")
    return tuple(dict.fromkeys(errors))


def load_evidence_bundle_envelope(
    payload, contract, change_set, plan, *, expected_bundle=None, expected_envelope_hash=None
):
    errors = validate_evidence_bundle_envelope(
        payload,
        contract,
        change_set,
        plan,
        expected_bundle=expected_bundle,
        expected_envelope_hash=expected_envelope_hash,
    )
    if errors:
        return None
    return EvidenceBundle(
        payload["bundle_id"],
        payload["acceptance_contract_hash"],
        payload["change_set_hash"],
        payload["verification_plan_hash"],
        tuple(
            Observation(
                r["verifier_id"],
                r["artifact_id"],
                r["artifact_hash"],
                ObservationStatus(r["status"]),
            )
            for r in payload["observations"]
        ),
    )


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


# Snapshot validator dependencies after all authoritative types and sealed
# primitives exist. Later module-level rebinding cannot change these functions.
validate_evidence_bundle_envelope = _freeze_function_globals(validate_evidence_bundle_envelope)
load_evidence_bundle_envelope = _freeze_function_globals(load_evidence_bundle_envelope)
