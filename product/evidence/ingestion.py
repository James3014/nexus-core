"""Small, deterministic trust-boundary for verifier evidence submissions."""

import hashlib
import json
import re
import weakref
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping, Protocol, runtime_checkable

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
from product.protocol import EVIDENCE_REQUIREMENT_SCHEMA, PROVENANCE_ENVELOPE_SCHEMA

MAX_TEXT_LENGTH = 4096
MAX_COLLECTION_ITEMS = 256
MAX_CONTENT_BYTES = 1_048_576


_TRUSTED_FINGERPRINTS = weakref.WeakKeyDictionary()


class EvidenceType(str, Enum):
    VERIFIER_RESULT = "VERIFIER_RESULT"
    CI_CHECK = "CI_CHECK"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
    LEGACY_RECORD = "LEGACY_RECORD"


class ProducerRole(str, Enum):
    VERIFIER = "VERIFIER"
    CI = "CI"
    REVIEWER = "REVIEWER"
    OWNER = "OWNER"
    SIGNER = "SIGNER"
    RUNTIME = "RUNTIME"


class EvidenceGeneration(str, Enum):
    SOURCE = "SOURCE"
    EXECUTION = "EXECUTION"
    RUNTIME = "RUNTIME"
    LEGACY_NARRATIVE = "LEGACY_NARRATIVE"


class FreshnessStatus(str, Enum):
    SOURCE_ALIGNED = "SOURCE_ALIGNED"
    SOURCE_AHEAD_OF_RUNTIME = "SOURCE_AHEAD_OF_RUNTIME"
    RUNTIME_IDENTITY_MISMATCH = "RUNTIME_IDENTITY_MISMATCH"
    STALE_OBSERVATION = "STALE_OBSERVATION"
    READY_IDENTITY_BOUND = "READY_IDENTITY_BOUND"
    CONVERGENCE_UNKNOWN = "CONVERGENCE_UNKNOWN"


class IngestionTrustStatus(str, Enum):
    UNTRUSTED = "UNTRUSTED"
    RECEIPT_INVALID = "RECEIPT_INVALID"
    TRUSTED = "TRUSTED"


class TrustRole(str, Enum):
    POLICY = "POLICY"
    AUTHORITY = "AUTHORITY"
    APPROVAL = "APPROVAL"
    SIGNING = "SIGNING"


class TrustDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


IDENTITY_ENVELOPE_SCHEMA = "nexus.evidence.identity-envelope.v1"
EXTERNAL_VERIFICATION_STATUSES = frozenset({"VERIFIED", "INVALID", "REVOKED"})
EXTERNAL_SIGNATURE_PAYLOAD_SCHEMA = "nexus.external-signature-payload.v1"


def _native_sha(value: object, field: str, *, git: bool = False) -> None:
    if type(value) is not str:
        raise ValueError(f"{field} must be a string")
    if git:
        valid = len(value) == 40 and all(c in "0123456789abcdef" for c in value)
    else:
        valid = (
            value.startswith("sha256:")
            and len(value) == 71
            and all(c in "0123456789abcdef" for c in value[7:])
        )
    if not value or value != value.strip() or not valid:
        raise ValueError(f"{field} has an invalid digest")


def _native_text(value: object, field: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_CONTENT_BYTES
        or value != value.strip()
        or "\x00" in value
    ):
        raise ValueError(f"{field} must be a normalized string")


def _native_junit_counts(data: bytes, exit_code: int) -> tuple[int, int, int]:
    if not data or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ValueError("missing or unsafe junit oracle")
    try:
        root = ET.fromstring(data)
        suites = list(root) if root.tag == "testsuites" else [root]
        counts = tuple(
            sum(int(s.attrib.get(name, "0")) for s in suites)
            for name in ("tests", "failures", "errors")
        )
    except (ET.ParseError, TypeError, ValueError) as exc:
        raise ValueError("malformed junit oracle") from exc
    tests, failures, errors = counts
    if (
        tests <= 0
        or failures < 0
        or errors < 0
        or failures + errors > tests
        or (exit_code == 0 and failures + errors)
    ):
        raise ValueError("inadequate junit oracle")
    return counts


def _native_normalized_junit(data: bytes) -> object:
    root = ET.fromstring(data)

    def normalize(item):
        attrs = {
            k: v
            for k, v in sorted(item.attrib.items())
            if k not in {"timestamp", "hostname", "time"}
        }
        text = (item.text or "").replace("/private/tmp/", "<tmp>/").replace("/tmp/", "<tmp>/")
        return [item.tag, attrs, text.strip(), [normalize(child) for child in item]]

    return normalize(root)


@dataclass(frozen=True)
class GitHubAcquisitionReceipt:
    """Evidence-core-owned, portable TG1 receipt; no acquisition dependency."""

    repository_owner: str
    repository_name: str
    pr_number: int
    base_sha: str
    head_sha: str
    base_tree_sha: str
    head_tree_sha: str
    merge_base_policy: str
    diff_bytes: bytes
    diff_hash: str
    changed_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]
    checks: tuple[tuple[str, str], ...]
    pagination_complete: bool
    observed_at: str
    freshness_cas: str
    locator_hash: str

    def __post_init__(self) -> None:
        for name in ("repository_owner", "repository_name", "observed_at"):
            _native_text(getattr(self, name), name)
        if type(self.pr_number) is not int or self.pr_number <= 0:
            raise ValueError("pr_number must be positive")
        for name in ("base_sha", "head_sha", "base_tree_sha", "head_tree_sha"):
            _native_sha(getattr(self, name), name, git=True)
        if self.base_sha == self.head_sha or self.merge_base_policy != "base_sha_exact":
            raise ValueError("invalid acquisition identity")
        if type(self.diff_bytes) is not bytes or _raw_hash(self.diff_bytes) != self.diff_hash:
            raise ValueError("diff_hash does not match diff_bytes")
        _native_sha(self.diff_hash, "diff_hash")
        for name in ("changed_paths", "deleted_paths"):
            values = getattr(self, name)
            if (
                type(values) is not tuple
                or values != tuple(sorted(values))
                or len(values) != len(set(values))
            ):
                raise ValueError(f"{name} must be sorted unique tuple")
            if any(
                type(x) is not str
                or not x
                or x.startswith("/")
                or "\\" in x
                or any(part in {"", ".", ".."} for part in x.split("/"))
                for x in values
            ):
                raise ValueError(f"{name} contains invalid path")
        if not set(self.deleted_paths).issubset(self.changed_paths):
            raise ValueError("deleted paths must be changed paths")
        if (
            type(self.checks) is not tuple
            or self.checks != tuple(sorted(self.checks))
            or len({item[0] for item in self.checks if type(item) is tuple and len(item) == 2})
            != len(self.checks)
        ):
            raise ValueError("checks must be sorted tuple")
        for item in self.checks:
            if type(item) is not tuple or len(item) != 2:
                raise ValueError("checks must be identity/digest pairs")
            _native_text(item[0], "check identity")
            _native_sha(item[1], "check digest")
        if self.pagination_complete is not True:
            raise ValueError("pagination must be complete")
        try:
            parsed = datetime.fromisoformat(self.observed_at[:-1])
        except (TypeError, ValueError) as exc:
            raise ValueError("observed_at must be UTC RFC3339") from exc
        if not self.observed_at.endswith("Z") or parsed.tzinfo is not None:
            raise ValueError("observed_at must be UTC RFC3339")
        freshness_subject = {
            "repository_owner": self.repository_owner.lower(),
            "repository_name": self.repository_name.lower(),
            "pr_number": self.pr_number,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "base_tree_sha": self.base_tree_sha,
            "head_tree_sha": self.head_tree_sha,
            "merge_base_policy": self.merge_base_policy,
            "diff_hash": self.diff_hash,
            "changed_paths": list(self.changed_paths),
            "deleted_paths": list(self.deleted_paths),
            "checks": [list(item) for item in self.checks],
        }
        expected_cas = _raw_hash(
            json.dumps(freshness_subject, sort_keys=True, separators=(",", ":")).encode()
        )
        if self.freshness_cas != expected_cas:
            raise ValueError("freshness_cas does not match acquisition identity")
        expected_locator = _raw_hash(
            json.dumps(
                [self.repository_owner.lower(), self.repository_name.lower(), self.pr_number],
                separators=(",", ":"),
            ).encode()
        )
        if self.locator_hash != expected_locator:
            raise ValueError("locator_hash does not match acquisition identity")
        _native_sha(self.freshness_cas, "freshness_cas")
        _native_sha(self.locator_hash, "locator_hash")

    def to_dict(self) -> dict[str, object]:
        return {
            "repository_owner": self.repository_owner,
            "repository_name": self.repository_name,
            "pr_number": self.pr_number,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "base_tree_sha": self.base_tree_sha,
            "head_tree_sha": self.head_tree_sha,
            "merge_base_policy": self.merge_base_policy,
            "diff_bytes": self.diff_bytes.hex(),
            "diff_hash": self.diff_hash,
            "changed_paths": list(self.changed_paths),
            "deleted_paths": list(self.deleted_paths),
            "checks": [list(x) for x in self.checks],
            "pagination_complete": self.pagination_complete,
            "observed_at": self.observed_at,
            "freshness_cas": self.freshness_cas,
            "locator_hash": self.locator_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "GitHubAcquisitionReceipt":
        if type(value) is not dict:
            raise TypeError("acquisition receipt must be a dict")
        data = dict(value)
        try:
            data["diff_bytes"] = bytes.fromhex(data["diff_bytes"])
            data["changed_paths"] = tuple(data["changed_paths"])
            data["deleted_paths"] = tuple(data["deleted_paths"])
            data["checks"] = tuple(tuple(x) for x in data["checks"])
            return cls(**data)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("malformed acquisition receipt") from exc


@dataclass(frozen=True)
class PythonExecutionAttemptReceipt:
    attempt_id: str
    execution_id: str
    source_revision: str
    source_tree: str
    contract_hash: str
    plan_hash: str
    environment_hash: str
    argv: tuple[str, ...]
    stdout: bytes
    stderr: bytes
    exit_code: int
    junit: bytes
    artifact_hash: str
    junit_tests: int
    junit_failures: int
    junit_errors: int
    outcome_hash: str

    def __post_init__(self) -> None:
        for name in ("attempt_id", "execution_id"):
            _native_text(getattr(self, name), name)
        for name in ("source_revision", "source_tree"):
            _native_sha(getattr(self, name), name, git=True)
        for name in (
            "contract_hash",
            "plan_hash",
            "environment_hash",
            "artifact_hash",
            "outcome_hash",
        ):
            _native_sha(getattr(self, name), name)
        if (
            type(self.argv) is not tuple
            or not self.argv
            or any(type(x) is not str or not x for x in self.argv)
        ):
            raise ValueError("argv must be a non-empty tuple")
        if any(x in {"sh", "bash", "-c", "--command"} for x in self.argv):
            raise ValueError("shell invocation is forbidden")
        for name in ("stdout", "stderr", "junit"):
            if (
                type(getattr(self, name)) is not bytes
                or len(getattr(self, name)) > MAX_CONTENT_BYTES
            ):
                raise ValueError(f"{name} must be bytes")
        if type(self.exit_code) is not int or isinstance(self.exit_code, bool):
            raise ValueError("exit_code must be int")
        for name in ("junit_tests", "junit_failures", "junit_errors"):
            if (
                type(getattr(self, name)) is not int
                or isinstance(getattr(self, name), bool)
                or getattr(self, name) < 0
            ):
                raise ValueError(f"{name} must be a non-negative int")
        tests, failures, errors = _native_junit_counts(self.junit, self.exit_code)
        if (tests, failures, errors) != (self.junit_tests, self.junit_failures, self.junit_errors):
            raise ValueError("junit semantic counts do not match")

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "execution_id": self.execution_id,
            "source_revision": self.source_revision,
            "source_tree": self.source_tree,
            "contract_hash": self.contract_hash,
            "plan_hash": self.plan_hash,
            "environment_hash": self.environment_hash,
            "argv": list(self.argv),
            "stdout": self.stdout.hex(),
            "stderr": self.stderr.hex(),
            "exit_code": self.exit_code,
            "junit": self.junit.hex(),
            "artifact_hash": self.artifact_hash,
            "junit_tests": self.junit_tests,
            "junit_failures": self.junit_failures,
            "junit_errors": self.junit_errors,
            "outcome_hash": self.outcome_hash,
        }


@dataclass(frozen=True)
class PythonRunnerProfileReceipt:
    profile_id: str
    image: str
    image_digest: str
    lock_digest: str
    dependency_artifacts_hash: str
    network: str
    rootfs: str
    command: tuple[str, ...]
    timeout_seconds: int
    memory_bytes: int
    cpu_seconds: int

    def __post_init__(self) -> None:
        for name in ("profile_id", "image", "network", "rootfs"):
            _native_text(getattr(self, name), name)
        for name in ("image_digest", "lock_digest", "dependency_artifacts_hash"):
            _native_sha(getattr(self, name), name)
        if self.network != "none" or self.rootfs != "read-only":
            raise ValueError("runner profile must be offline/read-only")
        if (
            type(self.command) is not tuple
            or not self.command
            or any(type(x) is not str or not x for x in self.command)
        ):
            raise ValueError("profile command must be argv tuple")
        if any(x in {"sh", "bash", "-c", "--command"} for x in self.command):
            raise ValueError("shell invocation is forbidden")
        for name in ("timeout_seconds", "memory_bytes", "cpu_seconds"):
            if (
                type(getattr(self, name)) is not int
                or isinstance(getattr(self, name), bool)
                or getattr(self, name) <= 0
            ):
                raise ValueError(f"{name} must be positive")

    def to_dict(self) -> dict[str, object]:
        return {
            **{
                name: getattr(self, name)
                for name in (
                    "profile_id",
                    "image",
                    "image_digest",
                    "lock_digest",
                    "dependency_artifacts_hash",
                    "network",
                    "rootfs",
                    "timeout_seconds",
                    "memory_bytes",
                    "cpu_seconds",
                )
            },
            "command": list(self.command),
        }


@dataclass(frozen=True)
class PythonRunnerReceipt:
    """Evidence-core-owned, portable TG2 receipt; execution remains injected."""

    status: str
    reason_codes: tuple[str, ...]
    profile_hash: str
    attempt_ids: tuple[str, ...]
    artifact_hashes: tuple[str, ...]
    attempts: tuple[PythonExecutionAttemptReceipt, ...]
    profile: PythonRunnerProfileReceipt

    def __post_init__(self) -> None:
        if self.status not in {"VERIFIED", "FAILED_VERIFICATION", "UNVERIFIABLE"}:
            raise ValueError("invalid runner status")
        if type(self.reason_codes) is not tuple or any(
            type(x) is not str for x in self.reason_codes
        ):
            raise ValueError("reason_codes must be tuple[str,...]")
        _native_sha(self.profile_hash, "profile_hash")
        if type(self.profile) is not PythonRunnerProfileReceipt:
            raise TypeError("native runner profile is required")
        if self.profile_hash != _raw_hash(
            json.dumps(self.profile.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        ):
            raise ValueError("profile_hash does not match runner profile")
        if type(self.attempts) is not tuple or any(
            type(x) is not PythonExecutionAttemptReceipt for x in self.attempts
        ):
            raise TypeError("native execution attempts are required")
        if type(self.attempt_ids) is not tuple or type(self.artifact_hashes) is not tuple:
            raise ValueError("runner summaries must be tuples")
        for value in self.artifact_hashes:
            _native_sha(value, "artifact_hash")
        if self.status in {"VERIFIED", "FAILED_VERIFICATION"} and len(self.attempts) != 2:
            raise ValueError("runner receipt requires two attempts")
        if self.status == "VERIFIED" and self.reason_codes != ():
            raise ValueError("verified runner receipt must have empty reasons")
        if self.status == "FAILED_VERIFICATION" and self.reason_codes != ("TEST_FAILURE",):
            raise ValueError("failed runner receipt must have TEST_FAILURE reason")
        if self.status == "UNVERIFIABLE" and len(self.attempts) not in {0, 2}:
            raise ValueError("unverifiable runner receipt requires zero or two attempts")
        if self.status != "UNVERIFIABLE" and len({x.execution_id for x in self.attempts}) != len(
            self.attempts
        ):
            raise ValueError("duplicate execution identity")
        if len(self.attempts) == 2:
            same_outcome = self.attempts[0].outcome_hash == self.attempts[1].outcome_hash
            if self.status == "VERIFIED" and (
                not same_outcome
                or any(
                    a.exit_code != 0 or a.junit_failures + a.junit_errors != 0
                    for a in self.attempts
                )
            ):
                raise ValueError("verified runner truth table mismatch")
            if self.status == "FAILED_VERIFICATION" and (
                not same_outcome
                or any(
                    a.exit_code != 1 or a.junit_failures + a.junit_errors <= 0
                    for a in self.attempts
                )
            ):
                raise ValueError("failed runner truth table mismatch")
            if self.status == "UNVERIFIABLE":
                duplicate = self.attempts[0].execution_id == self.attempts[1].execution_id
                expected = (
                    ("DUPLICATE_EXECUTION_ID",)
                    if duplicate
                    else ("NONDETERMINISTIC",)
                    if not same_outcome
                    else ("UNKNOWN_EXECUTION_OUTCOME",)
                )
                if self.reason_codes != expected:
                    raise ValueError("unverifiable runner truth table mismatch")
        elif self.status == "UNVERIFIABLE" and self.reason_codes not in {
            ("MISSING_BINDING",),
            ("MALFORMED_REQUEST",),
            ("MALFORMED_OR_UNAVAILABLE",),
        }:
            raise ValueError("unverifiable zero-attempt reason is not allowed")
        for attempt in self.attempts:
            expected_identity = (
                json.dumps(
                    {
                        "source_revision": attempt.source_revision,
                        "source_tree": attempt.source_tree,
                        "contract_hash": attempt.contract_hash,
                        "plan_hash": attempt.plan_hash,
                        "environment_hash": attempt.environment_hash,
                        "profile_id": self.profile.profile_id,
                        "image": self.profile.image,
                        "image_digest": self.profile.image_digest,
                        "lock_digest": self.profile.lock_digest,
                        "network": self.profile.network,
                        "rootfs": self.profile.rootfs,
                        "timeout_seconds": self.profile.timeout_seconds,
                        "memory_bytes": self.profile.memory_bytes,
                        "cpu_seconds": self.profile.cpu_seconds,
                        "argv": list(attempt.argv),
                        "junit": [
                            attempt.junit_tests,
                            attempt.junit_failures,
                            attempt.junit_errors,
                        ],
                        "exit_code": attempt.exit_code,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + self.profile.dependency_artifacts_hash.encode()
            )
            expected_artifact = _raw_hash(
                b"\0".join((expected_identity, attempt.stdout, attempt.stderr, attempt.junit))
            )
            if expected_artifact != attempt.artifact_hash:
                raise ValueError("artifact_hash does not match runner evidence")
            expected_outcome = _raw_hash(
                json.dumps(
                    [
                        attempt.source_revision,
                        attempt.source_tree,
                        attempt.contract_hash,
                        attempt.plan_hash,
                        attempt.environment_hash,
                        list(attempt.argv),
                        attempt.exit_code,
                        _native_normalized_junit(attempt.junit),
                    ],
                    separators=(",", ":"),
                ).encode()
            )
            if expected_outcome != attempt.outcome_hash:
                raise ValueError("outcome_hash does not match runner evidence")
        if self.attempt_ids != tuple(
            x.attempt_id for x in self.attempts
        ) or self.artifact_hashes != tuple(x.artifact_hash for x in self.attempts):
            raise ValueError("runner summary does not match attempts")

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason_codes": list(self.reason_codes),
            "profile_hash": self.profile_hash,
            "attempt_ids": list(self.attempt_ids),
            "artifact_hashes": list(self.artifact_hashes),
            "attempts": [x.to_dict() for x in self.attempts],
            "profile": self.profile.to_dict(),
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, object], *, profile: Mapping[str, object] | None = None
    ) -> "PythonRunnerReceipt":
        if type(value) is not dict:
            raise TypeError("runner receipt must be a dict")
        try:
            required = {
                "status",
                "reason_codes",
                "profile_hash",
                "attempt_ids",
                "artifact_hashes",
                "attempts",
                "profile",
            }
            if set(value) != required:
                raise ValueError("runner receipt schema keys mismatch")
            profile_data = profile if profile is not None else value["profile"]
            if type(profile_data) is not dict or set(profile_data) != {
                "profile_id",
                "image",
                "image_digest",
                "lock_digest",
                "dependency_artifacts_hash",
                "network",
                "rootfs",
                "command",
                "timeout_seconds",
                "memory_bytes",
                "cpu_seconds",
            }:
                raise ValueError("runner profile schema keys mismatch")
            profile_obj = PythonRunnerProfileReceipt(**{
                **profile_data,
                "command": tuple(profile_data["command"]),
            })
            attempt_keys = {
                "attempt_id",
                "execution_id",
                "source_revision",
                "source_tree",
                "contract_hash",
                "plan_hash",
                "environment_hash",
                "argv",
                "stdout",
                "stderr",
                "exit_code",
                "junit",
                "artifact_hash",
                "junit_tests",
                "junit_failures",
                "junit_errors",
                "outcome_hash",
            }
            if type(value["attempts"]) is not list or any(
                type(item) is not dict or set(item) != attempt_keys for item in value["attempts"]
            ):
                raise ValueError("runner attempt schema keys mismatch")
            attempts = tuple(
                PythonExecutionAttemptReceipt(**{
                    **item,
                    "argv": tuple(item["argv"]),
                    "stdout": bytes.fromhex(item["stdout"]),
                    "stderr": bytes.fromhex(item["stderr"]),
                    "junit": bytes.fromhex(item["junit"]),
                })
                for item in value["attempts"]
            )
            return cls(
                value["status"],
                tuple(value["reason_codes"]),
                value["profile_hash"],
                tuple(value["attempt_ids"]),
                tuple(value["artifact_hashes"]),
                attempts,
                profile_obj,
            )
        except (KeyError, TypeError) as exc:
            raise ValueError("malformed runner receipt") from exc


@dataclass(frozen=True)
class EvidenceIdentityEnvelope:
    """Portable trust identity; it contains no live-object capability."""

    context_hash: str
    profile_hash: str
    bundle_hash: str
    ingestion_receipt_hash: str
    subject_hash: str
    execution_id: str
    attempt_id: str
    generation: str
    producer_id: str
    issuer_id: str
    acquisition_snapshot_hash: str
    runner_result_hash: str
    verification_receipt_hash: str
    external_receipt_hashes: tuple[str, ...]
    identity_hash: str

    def __post_init__(self):
        for name in (
            "context_hash",
            "profile_hash",
            "bundle_hash",
            "ingestion_receipt_hash",
            "subject_hash",
            "execution_id",
            "attempt_id",
            "generation",
            "producer_id",
            "issuer_id",
        ):
            _text(getattr(self, name), name)
        for name in (
            "context_hash",
            "profile_hash",
            "bundle_hash",
            "ingestion_receipt_hash",
            "subject_hash",
        ):
            _hash_value(getattr(self, name), name)
        for name in (
            "acquisition_snapshot_hash",
            "runner_result_hash",
            "verification_receipt_hash",
        ):
            _hash_value(getattr(self, name), name)
        _tuple_text(self.external_receipt_hashes, "external_receipt_hashes", nonempty=False)
        for value in self.external_receipt_hashes:
            _hash_value(value, "external_receipt_hash")
        _hash_value(self.identity_hash, "identity_hash")
        if self.identity_hash != _identity_hash(self):
            raise ValueError("identity_hash does not match envelope")

    @property
    def hash(self):
        return self.identity_hash

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": IDENTITY_ENVELOPE_SCHEMA,
            "context_hash": self.context_hash,
            "profile_hash": self.profile_hash,
            "bundle_hash": self.bundle_hash,
            "ingestion_receipt_hash": self.ingestion_receipt_hash,
            "subject_hash": self.subject_hash,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "generation": self.generation,
            "producer_id": self.producer_id,
            "issuer_id": self.issuer_id,
            "acquisition_snapshot_hash": self.acquisition_snapshot_hash,
            "runner_result_hash": self.runner_result_hash,
            "verification_receipt_hash": self.verification_receipt_hash,
            "external_receipt_hashes": list(self.external_receipt_hashes),
            "identity_hash": self.identity_hash,
        }


def _identity_hash(envelope: EvidenceIdentityEnvelope) -> str:
    body = {
        "schema": IDENTITY_ENVELOPE_SCHEMA,
        **{
            name: getattr(envelope, name)
            for name in EvidenceIdentityEnvelope.__dataclass_fields__
            if name not in {"identity_hash"}
        },
        "external_receipt_hashes": list(envelope.external_receipt_hashes),
    }
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def _native_receipt_hash(receipt: GitHubAcquisitionReceipt | PythonRunnerReceipt) -> str:
    return _raw_hash(json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":")).encode())


def make_identity_envelope(
    context: "TrustedIngestionContext",
    ingestion: "IngestionResult",
    *,
    acquisition_snapshot: object,
    runner_result: object,
    verification_receipt: object,
    trust_reference: object = None,
    verifier: object = None,
    payload: bytes | None = None,
    signature: bytes | None = None,
    observed_at: str | None = None,
    external_receipt_hashes: tuple[str, ...] = (),
) -> EvidenceIdentityEnvelope:
    """Build an identity using only accepted, exact upstream evidence."""
    if not is_trusted_ingestion_result(context, ingestion) or ingestion.bundle is None:
        raise ValueError("UNTRUSTED_INGESTION")
    if (
        type(acquisition_snapshot) is not GitHubAcquisitionReceipt
        or type(runner_result) is not PythonRunnerReceipt
    ):
        raise TypeError("TG1/TG2 receipt types are required")
    if runner_result.status != "VERIFIED" or len(runner_result.attempts) != 2:
        raise ValueError("TG2 receipt has no attempts")
    req = context.requirements[0] if len(context.requirements) == 1 else None
    if req is None:
        raise ValueError("identity requires one bound requirement")
    attempt = next((a for a in runner_result.attempts if a.attempt_id == req.attempt_id), None)
    if attempt is None:
        raise ValueError("TG2 attempt is not bound to requirement")
    if (
        acquisition_snapshot.base_sha != context.change_set.source_revision
        or acquisition_snapshot.head_sha != context.change_set.target_revision
        or acquisition_snapshot.base_tree_sha != context.source_tree
        or acquisition_snapshot.head_tree_sha != context.target_tree
        or acquisition_snapshot.diff_hash != context.change_set.diff_hash
        or acquisition_snapshot.repository_owner + "/" + acquisition_snapshot.repository_name
        != context.repository_id
        or acquisition_snapshot.changed_paths != context.change_set.paths
        or attempt.source_revision != context.change_set.target_revision
        or attempt.source_tree != context.target_tree
        or attempt.contract_hash != context.contract.hash
        or attempt.plan_hash != context.plan.hash
        or attempt.environment_hash != req.environment_hash
        or attempt.execution_id != req.execution_id
        or attempt.attempt_id != req.attempt_id
    ):
        raise ValueError("CROSS_BOUND:TG1_TG2")
    if req.producer_id not in {grant.producer_id for grant in context.profile.producers}:
        raise ValueError("CROSS_BOUND:producer")
    if type(verification_receipt) is not ExternalVerificationReceipt:
        raise TypeError("verified external receipt is required")
    verification_receipt.__post_init__()
    issuer_id = verification_receipt.issuer_id
    if verification_receipt.status != "VERIFIED" or verification_receipt.revoked:
        raise ValueError("UNTRUSTED_EXTERNAL_RECEIPT")
    if tuple(external_receipt_hashes) != (verification_receipt.external_receipt_hash,):
        raise ValueError("CROSS_BOUND:external_receipt")
    if (
        type(trust_reference) is not TrustReference
        or verifier is None
        or payload is None
        or signature is None
        or observed_at is None
    ):
        raise ValueError("EXTERNAL_REFERENCE_REQUIRED")
    if trust_reference.issuer_id != issuer_id or trust_reference.action != context.required_action:
        raise ValueError("CROSS_BOUND:issuer_action")
    grant = next((g for g in context.profile.issuers if g.issuer_id == issuer_id), None)
    if grant is None or trust_reference.role not in grant.roles:
        raise ValueError("CROSS_BOUND:issuer_role")
    if (
        context.required_action not in grant.actions
        or trust_reference.action != context.required_action
        or trust_reference.verification_method not in grant.verification_methods
    ):
        raise ValueError("CROSS_BOUND:issuer_action")
    if trust_reference.decision is not TrustDecision.ALLOW:
        raise ValueError("CROSS_BOUND:issuer_decision")
    expected_subject = _hash((
        "nexus.trusted_prerequisite_subject.v1-experimental",
        context.hash,
        ingestion.bundle.hash,
    ))
    if trust_reference.subject_hash != expected_subject:
        raise ValueError("CROSS_BOUND:issuer_subject")
    if trust_reference.payload_hash != dict(context.prerequisite_payload_hashes).get(
        trust_reference.role
    ):
        raise ValueError("CROSS_BOUND:issuer_payload")
    acquisition_hash = _native_receipt_hash(acquisition_snapshot)
    runner_hash = _native_receipt_hash(runner_result)
    try:
        signed_payload = parse_external_signature_payload(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("UNVERIFIED_EXTERNAL_RECEIPT") from exc
    if (
        signed_payload["acquisition_snapshot_hash"] != acquisition_hash
        or signed_payload["runner_result_hash"] != runner_hash
    ):
        raise ValueError("CROSS_BOUND:TG1_TG2")
    if not verify_trust_reference_signature(
        trust_reference,
        verifier,
        expected_issuer_id=issuer_id,
        key_id=verification_receipt.key_id,
        payload=payload,
        signature=signature,
        verification_receipt=verification_receipt,
        observed_at=observed_at,
    ):
        raise ValueError("UNVERIFIED_EXTERNAL_RECEIPT")
    execution_id, attempt_id, generation, producer_id = (
        attempt.execution_id,
        attempt.attempt_id,
        req.generation.value,
        req.producer_id,
    )
    _tuple_text(external_receipt_hashes, "external_receipt_hashes", nonempty=False)
    if external_receipt_hashes != tuple(sorted(external_receipt_hashes)):
        raise ValueError("external_receipt_hashes must be sorted")
    provisional = EvidenceIdentityEnvelope.__new__(EvidenceIdentityEnvelope)
    values = (
        context.hash,
        context.profile.hash,
        ingestion.bundle.hash,
        ingestion.receipt.hash,
        _hash(("nexus.evidence.identity-subject.v1", context.hash, ingestion.bundle.hash)),
        execution_id,
        attempt_id,
        generation,
        producer_id,
        issuer_id,
        acquisition_hash,
        runner_hash,
        verification_receipt.receipt_hash,
        tuple(sorted(external_receipt_hashes)),
        "sha256:" + "0" * 64,
    )
    for field, value in zip(EvidenceIdentityEnvelope.__dataclass_fields__, values):
        object.__setattr__(provisional, field, value)
    object.__setattr__(provisional, "identity_hash", _identity_hash(provisional))
    provisional.__post_init__()
    return provisional


def serialize_identity_envelope(envelope: EvidenceIdentityEnvelope) -> dict[str, object]:
    if type(envelope) is not EvidenceIdentityEnvelope:
        raise TypeError("envelope must be EvidenceIdentityEnvelope")
    envelope.__post_init__()
    return envelope.to_dict()


def load_identity_envelope(payload: Mapping[str, object]) -> EvidenceIdentityEnvelope:
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")
    required = {
        "schema",
        "context_hash",
        "profile_hash",
        "bundle_hash",
        "ingestion_receipt_hash",
        "subject_hash",
        "execution_id",
        "attempt_id",
        "generation",
        "producer_id",
        "issuer_id",
        "acquisition_snapshot_hash",
        "runner_result_hash",
        "verification_receipt_hash",
        "external_receipt_hashes",
        "identity_hash",
    }
    if set(payload) != required or payload.get("schema") != IDENTITY_ENVELOPE_SCHEMA:
        raise ValueError("malformed identity envelope")
    hashes = payload["external_receipt_hashes"]
    if type(hashes) is not list:
        raise ValueError("external_receipt_hashes must be a list")
    if hashes != sorted(hashes) or len(hashes) != len(set(hashes)):
        raise ValueError("external_receipt_hashes must be sorted and unique")
    return EvidenceIdentityEnvelope(**{
        key: (tuple(payload[key]) if key == "external_receipt_hashes" else payload[key])
        for key in required
        if key != "schema"
    })


@runtime_checkable
class ExternalEd25519VerifierPort(Protocol):
    """Injected verifier; implementations expose public verification only."""

    def verify(
        self, *, issuer_id: str, key_id: str, algorithm: str, payload: bytes, signature: bytes
    ) -> bool: ...


def build_external_signature_payload(
    *,
    issuer_id,
    key_id,
    evidence_id,
    subject_hash,
    action,
    decision,
    external_receipt_hash,
    acquisition_snapshot_hash,
    runner_result_hash,
):
    values = {
        "schema": EXTERNAL_SIGNATURE_PAYLOAD_SCHEMA,
        "issuer_id": issuer_id,
        "key_id": key_id,
        "evidence_id": evidence_id,
        "subject_hash": subject_hash,
        "action": action,
        "decision": decision,
        "external_receipt_hash": external_receipt_hash,
        "acquisition_snapshot_hash": acquisition_snapshot_hash,
        "runner_result_hash": runner_result_hash,
    }
    _text(issuer_id, "issuer_id")
    _text(key_id, "key_id")
    _text(evidence_id, "evidence_id")
    _hash_value(subject_hash, "subject_hash")
    _text(action, "action")
    _text(decision, "decision")
    _hash_value(external_receipt_hash, "external_receipt_hash")
    _hash_value(acquisition_snapshot_hash, "acquisition_snapshot_hash")
    _hash_value(runner_result_hash, "runner_result_hash")
    return json.dumps(values, sort_keys=True, separators=(",", ":")).encode()


def parse_external_signature_payload(payload: bytes) -> dict[str, str]:
    if type(payload) is not bytes:
        raise ValueError("payload must be bytes")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed external signature payload") from exc
    required = {
        "schema",
        "issuer_id",
        "key_id",
        "evidence_id",
        "subject_hash",
        "action",
        "decision",
        "external_receipt_hash",
        "acquisition_snapshot_hash",
        "runner_result_hash",
    }
    if (
        type(value) is not dict
        or set(value) != required
        or value.get("schema") != EXTERNAL_SIGNATURE_PAYLOAD_SCHEMA
    ):
        raise ValueError("external signature payload schema mismatch")
    canonical = build_external_signature_payload(**{k: value[k] for k in required if k != "schema"})
    if canonical != payload:
        raise ValueError("external signature payload is not canonical")
    return value


@dataclass(frozen=True)
class ExternalVerificationReceipt:
    issuer_id: str
    algorithm: str
    key_id: str
    payload_hash: str
    signature_hash: str
    external_receipt_hash: str
    revoked: bool
    status: str
    receipt_hash: str

    def __post_init__(self):
        for name in ("issuer_id", "algorithm", "key_id", "status"):
            _text(getattr(self, name), name)
        if self.algorithm != "Ed25519":
            raise ValueError("algorithm must be Ed25519")
        for name in ("payload_hash", "signature_hash", "external_receipt_hash", "receipt_hash"):
            _hash_value(getattr(self, name), name)
        if type(self.revoked) is not bool:
            raise TypeError("revoked must be bool")
        if self.status not in EXTERNAL_VERIFICATION_STATUSES:
            raise ValueError("invalid external verification status")
        if (self.revoked and self.status != "REVOKED") or (
            not self.revoked and self.status == "REVOKED"
        ):
            raise ValueError("revoked/status mismatch")
        expected = _hash((
            "nexus.external-verification-receipt.v1",
            self.issuer_id,
            self.algorithm,
            self.key_id,
            self.payload_hash,
            self.signature_hash,
            self.external_receipt_hash,
            self.revoked,
            self.status,
        ))
        if expected != self.receipt_hash:
            raise ValueError("receipt_hash does not match verification receipt")

    def to_dict(self):
        return {
            "schema": "nexus.external-verification-receipt.v1",
            **{f: getattr(self, f) for f in self.__dataclass_fields__},
        }


def load_external_verification_receipt(
    payload: Mapping[str, object],
) -> ExternalVerificationReceipt:
    if (
        not isinstance(payload, Mapping)
        or payload.get("schema") != "nexus.external-verification-receipt.v1"
    ):
        raise ValueError("malformed external verification receipt")
    fields = set(ExternalVerificationReceipt.__dataclass_fields__)
    if set(payload) != fields | {"schema"}:
        raise ValueError("malformed external verification receipt")
    return ExternalVerificationReceipt(**{key: payload[key] for key in fields})


def verify_external_ed25519(
    verifier: ExternalEd25519VerifierPort,
    *,
    issuer_id: str,
    key_id: str,
    payload: bytes,
    signature: bytes,
) -> bool:
    """Verify an issuer signature without importing keys or crypto transports."""
    if not isinstance(verifier, ExternalEd25519VerifierPort):
        raise TypeError("verifier must implement ExternalEd25519VerifierPort")
    if (
        type(payload) is not bytes
        or not payload
        or type(signature) is not bytes
        or len(signature) != 64
    ):
        return False
    try:
        _text(issuer_id, "issuer_id")
        _text(key_id, "key_id")
        return (
            verifier.verify(
                issuer_id=issuer_id,
                key_id=key_id,
                algorithm="Ed25519",
                payload=payload,
                signature=signature,
            )
            is True
        )
    except (TypeError, ValueError, OSError):
        return False


def verify_external_ed25519_receipt(
    verifier: ExternalEd25519VerifierPort,
    *,
    issuer_id: str,
    key_id: str,
    payload: bytes,
    signature: bytes,
    external_receipt: bytes,
    revoked: bool = False,
) -> ExternalVerificationReceipt:
    """Return a durable, hash-bound result for an injected Ed25519 check."""
    payload_hash = _raw_hash(payload) if type(payload) is bytes else "sha256:" + "0" * 64
    signature_hash = _raw_hash(signature) if type(signature) is bytes else "sha256:" + "0" * 64
    receipt_hash = (
        _raw_hash(external_receipt)
        if type(external_receipt) is bytes and external_receipt
        else "sha256:" + "0" * 64
    )
    valid_shape = (
        type(signature) is bytes
        and len(signature) == 64
        and type(external_receipt) is bytes
        and bool(external_receipt)
    )
    verified = (
        valid_shape
        and not revoked
        and verify_external_ed25519(
            verifier, issuer_id=issuer_id, key_id=key_id, payload=payload, signature=signature
        )
    )
    status = "REVOKED" if revoked else "VERIFIED" if verified else "INVALID"
    body = (
        "nexus.external-verification-receipt.v1",
        issuer_id,
        "Ed25519",
        key_id,
        payload_hash,
        signature_hash,
        receipt_hash,
        revoked,
        status,
    )
    return ExternalVerificationReceipt(
        issuer_id,
        "Ed25519",
        key_id,
        payload_hash,
        signature_hash,
        receipt_hash,
        revoked,
        status,
        _hash(body),
    )


def verify_trust_reference_signature(
    reference: "TrustReference",
    verifier: ExternalEd25519VerifierPort,
    *,
    expected_issuer_id: str,
    key_id: str,
    payload: bytes,
    signature: bytes,
    verification_receipt: ExternalVerificationReceipt | None = None,
    observed_at: str | None = None,
) -> bool:
    """Bind an external signature to a trusted reference before verifying it."""
    if type(reference) is not TrustReference:
        return False
    try:
        reference.__post_init__()
        signed = parse_external_signature_payload(payload)
        _text(expected_issuer_id, "expected_issuer_id")
        if reference.issuer_id != expected_issuer_id or reference.revoked_at is not None:
            return False
        if any(
            signed[k] != expected
            for k, expected in (
                ("issuer_id", reference.issuer_id),
                ("key_id", key_id),
                ("evidence_id", reference.evidence_id),
                ("subject_hash", reference.subject_hash),
                ("action", reference.action),
                ("decision", reference.decision.value),
                ("external_receipt_hash", reference.external_verification_receipt_hash),
            )
        ):
            return False
        if type(verification_receipt) is not ExternalVerificationReceipt:
            return False
        verification_receipt.__post_init__()
        if (
            verification_receipt.status != "VERIFIED"
            or verification_receipt.revoked
            or verification_receipt.issuer_id != reference.issuer_id
            or verification_receipt.key_id != key_id
            or verification_receipt.payload_hash != _raw_hash(payload)
            or verification_receipt.signature_hash != _raw_hash(signature)
            or verification_receipt.external_receipt_hash
            != reference.external_verification_receipt_hash
        ):
            return False
        if observed_at is None:
            return False
        if observed_at is not None:
            observed = _parse_time(observed_at)
            issued = _parse_time(reference.issued_at)
            expires = _parse_time(reference.expires_at)
            if (
                observed is None
                or issued is None
                or expires is None
                or not (issued <= observed < expires)
            ):
                return False
        if type(payload) is not bytes or not payload:
            return False
        payload_hash = _raw_hash(payload)
        if reference.signed_payload_hash != payload_hash:
            return False
        return verify_external_ed25519(
            verifier,
            issuer_id=expected_issuer_id,
            key_id=key_id,
            payload=payload,
            signature=signature,
        )
    except (TypeError, ValueError, AttributeError):
        return False


def _text(value, name):
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    if not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{name} must be non-empty and normalized")
    if len(value) > MAX_TEXT_LENGTH:
        raise ValueError(f"{name} exceeds maximum length")


def _runtime_timestamp(value):
    if type(value) is not str:
        raise TypeError("runtime timestamps must be strings")
    if not value or value != value.strip() or "\x00" in value or len(value) > MAX_TEXT_LENGTH:
        raise ValueError("runtime timestamps must be normalized")


def _hash_value(value, name):
    _text(value, name)
    if not (
        value.startswith("sha256:")
        and len(value) == 71
        and all(c in "0123456789abcdef" for c in value[7:])
    ):
        raise ValueError(f"{name} must be sha256:<64 lowercase hex>")


def _tuple_text(values, name, nonempty=True):
    if type(values) is not tuple:
        raise TypeError(f"{name} must be a tuple")
    for value in values:
        _text(value, name)
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must not contain duplicates")
    if len(values) > MAX_COLLECTION_ITEMS:
        raise ValueError(f"{name} exceeds maximum size")
    if nonempty and not values:
        raise ValueError(f"{name} must be non-empty")


def _canon(value):
    if isinstance(value, str):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return tuple(_canon(v) for v in value)
    if isinstance(value, list):
        return [_canon(v) for v in value]
    if isinstance(value, bytes):
        return "bytes:" + value.hex()
    if hasattr(value, "__dataclass_fields__"):
        return tuple(_canon(getattr(value, f)) for f in value.__dataclass_fields__)
    if type(value) is RuntimeSourceObservation:
        return tuple(_canon(getattr(value, f)) for f in value.__dataclass_fields__)
    if type(value) is ProvenanceEnvelope:
        return tuple(_canon(getattr(value, f)) for f in value.__dataclass_fields__)
    return value


@dataclass(frozen=True)
class ProducerGrant:
    producer_id: str
    role: ProducerRole
    software_hash: str
    verification_methods: tuple[str, ...]

    def __post_init__(self):
        _text(self.producer_id, "producer_id")
        _hash_value(self.software_hash, "software_hash")
        if type(self.role) is not ProducerRole:
            raise TypeError("role must be ProducerRole")
        _tuple_text(self.verification_methods, "verification_methods")
        if self.verification_methods != tuple(sorted(self.verification_methods)):
            raise ValueError("verification_methods must be sorted")


@dataclass(frozen=True)
class IssuerGrant:
    issuer_id: str
    roles: tuple[TrustRole, ...]
    actions: tuple[str, ...]
    verification_methods: tuple[str, ...]

    def __post_init__(self):
        _text(self.issuer_id, "issuer_id")
        if (
            type(self.roles) is not tuple
            or not self.roles
            or any(type(v) is not TrustRole for v in self.roles)
        ):
            raise TypeError("roles must be TrustRole tuple")
        if len(set(self.roles)) != len(self.roles):
            raise ValueError("roles must not contain duplicates")
        if self.roles != tuple(sorted(self.roles, key=lambda v: list(TrustRole).index(v))):
            raise ValueError("roles must be sorted")
        _tuple_text(self.actions, "actions")
        _tuple_text(self.verification_methods, "verification_methods")
        if self.actions != tuple(sorted(self.actions)) or self.verification_methods != tuple(
            sorted(self.verification_methods)
        ):
            raise ValueError("trust inputs must be sorted")


@dataclass(frozen=True)
class IngestionProfile:
    profile_id: str
    producers: tuple[ProducerGrant, ...]
    issuers: tuple[IssuerGrant, ...]
    max_age_seconds: int

    def __post_init__(self):
        _text(self.profile_id, "profile_id")
        if type(self.producers) is not tuple or any(
            type(v) is not ProducerGrant for v in self.producers
        ):
            raise TypeError("producers must be ProducerGrant tuple")
        if len(self.producers) > MAX_COLLECTION_ITEMS or len(self.issuers) > MAX_COLLECTION_ITEMS:
            raise ValueError("profile collections exceed maximum size")
        if len({v.producer_id for v in self.producers}) != len(self.producers):
            raise ValueError("producers must not contain duplicates")
        if self.producers != tuple(sorted(self.producers, key=lambda v: v.producer_id)):
            raise ValueError("producers must be sorted")
        if type(self.issuers) is not tuple or any(type(v) is not IssuerGrant for v in self.issuers):
            raise TypeError("issuers must be IssuerGrant tuple")
        if len({v.issuer_id for v in self.issuers}) != len(self.issuers):
            raise ValueError("issuers must not contain duplicates")
        if self.issuers != tuple(sorted(self.issuers, key=lambda v: v.issuer_id)):
            raise ValueError("issuers must be sorted")
        if type(self.max_age_seconds) is not int or self.max_age_seconds < 0:
            raise ValueError("max_age_seconds must be non-negative int")

    @property
    def hash(self):
        return _hash(
            _canon((
                self.profile_id,
                tuple(sorted((_canon(v) for v in self.producers))),
                tuple(sorted((_canon(v) for v in self.issuers))),
                self.max_age_seconds,
            ))
        )


@dataclass(frozen=True)
class EvidenceRequirement:
    verifier_id: str
    artifact_id: str
    evidence_type: EvidenceType
    generation: EvidenceGeneration
    producer_id: str
    execution_id: str
    attempt_id: str
    environment_hash: str
    content_hash: str
    provenance_hash: str
    runtime_ready_required: bool
    human_semantic_review_required: bool
    expected_status: ObservationStatus

    def __post_init__(self):
        for n in ("verifier_id", "artifact_id", "producer_id", "execution_id", "attempt_id"):
            _text(getattr(self, n), n)
        if (
            type(self.evidence_type) is not EvidenceType
            or type(self.generation) is not EvidenceGeneration
        ):
            raise TypeError("invalid enum")
        for n in ("environment_hash", "content_hash", "provenance_hash"):
            _hash_value(getattr(self, n), n)
        if (
            type(self.runtime_ready_required) is not bool
            or type(self.human_semantic_review_required) is not bool
        ):
            raise TypeError("review flags must be bool")
        if type(self.expected_status) is not ObservationStatus:
            raise TypeError("expected_status must be ObservationStatus")

    @property
    def hash(self):
        return _hash(
            _canon((
                EVIDENCE_REQUIREMENT_SCHEMA,
                self.verifier_id,
                self.artifact_id,
                self.evidence_type.value,
                self.generation.value,
                self.producer_id,
                self.execution_id,
                self.attempt_id,
                self.environment_hash,
                self.content_hash,
                self.provenance_hash,
                self.runtime_ready_required,
                self.human_semantic_review_required,
                self.expected_status.value,
            ))
        )


@dataclass(frozen=True)
class RuntimeSourceObservation:
    generation: EvidenceGeneration
    desired_source_revision: str
    loaded_source_revision: str
    expected_runtime_identity: str | None
    observed_runtime_identity: str | None
    desired_generation: int
    observed_generation: int
    observed_at: str
    expires_at: str
    readiness_status: str | None

    def __post_init__(self):
        if type(self.generation) is not EvidenceGeneration:
            raise TypeError("generation must be EvidenceGeneration")
        if self.generation in (EvidenceGeneration.EXECUTION, EvidenceGeneration.LEGACY_NARRATIVE):
            raise ValueError("unsupported generation")
        for n in ("desired_source_revision", "loaded_source_revision"):
            _text(getattr(self, n), n)
        if type(self.desired_generation) is not int or type(self.observed_generation) is not int:
            raise TypeError("generations must be int")
        _runtime_timestamp(self.observed_at)
        _runtime_timestamp(self.expires_at)
        for name in ("expected_runtime_identity", "observed_runtime_identity", "readiness_status"):
            value = getattr(self, name)
            if value is not None:
                _text(value, name)


@dataclass(frozen=True)
class ProvenanceEnvelope:
    schema: str
    evidence_id: str
    evidence_type: EvidenceType
    verifier_id: str
    artifact_id: str
    producer_id: str
    producer_role: ProducerRole
    producer_software_hash: str
    repository_id: str
    source_revision: str
    source_tree: str
    target_revision: str
    target_tree: str
    change_set_hash: str
    diff_hash: str
    generated_at: str
    source_locator: str
    content_hash: str
    verification_method: str
    execution_id: str
    attempt_id: str
    environment_hash: str
    generation: EvidenceGeneration
    runtime: RuntimeSourceObservation | None

    def __post_init__(self):
        _text(self.schema, "schema")
        _text(self.evidence_id, "evidence_id")
        _text(self.verifier_id, "verifier_id")
        _text(self.artifact_id, "artifact_id")
        _text(self.producer_id, "producer_id")
        _text(self.repository_id, "repository_id")
        _text(self.source_revision, "source_revision")
        _text(self.source_tree, "source_tree")
        _text(self.target_revision, "target_revision")
        _text(self.target_tree, "target_tree")
        _text(self.generated_at, "generated_at")
        _text(self.source_locator, "source_locator")
        _text(self.verification_method, "verification_method")
        _text(self.execution_id, "execution_id")
        _text(self.attempt_id, "attempt_id")
        if (
            type(self.evidence_type) is not EvidenceType
            or type(self.producer_role) is not ProducerRole
            or type(self.generation) is not EvidenceGeneration
        ):
            raise TypeError("invalid enum")
        for n in (
            "producer_software_hash",
            "change_set_hash",
            "diff_hash",
            "content_hash",
            "environment_hash",
        ):
            _hash_value(getattr(self, n), n)
        if type(self.runtime) is not RuntimeSourceObservation and self.runtime is not None:
            raise TypeError("runtime must be RuntimeSourceObservation")

    @property
    def hash(self):
        return _hash(_canon(tuple(getattr(self, f) for f in self.__dataclass_fields__)))


@dataclass(frozen=True)
class EvidenceSubmission:
    content: bytes
    status: ObservationStatus
    provenance: ProvenanceEnvelope

    def __post_init__(self):
        if type(self.content) is not bytes:
            raise TypeError("content must be bytes")
        if len(self.content) > MAX_CONTENT_BYTES:
            raise ValueError("content exceeds maximum size")
        if type(self.status) is not ObservationStatus:
            raise TypeError("status must be ObservationStatus")
        if type(self.provenance) is not ProvenanceEnvelope:
            raise TypeError("provenance must be ProvenanceEnvelope")


@dataclass(frozen=True)
class TrustReference:
    role: TrustRole
    evidence_id: str
    issuer_id: str
    subject_hash: str
    action: str
    decision: TrustDecision
    issued_at: str
    expires_at: str
    revoked_at: str | None
    payload_hash: str
    signed_payload_hash: str
    verification_method: str
    external_verification_receipt: bytes
    external_verification_receipt_hash: str

    def __post_init__(self):
        if type(self.role) is not TrustRole or type(self.decision) is not TrustDecision:
            raise TypeError("invalid trust enum")
        for name in (
            "evidence_id",
            "issuer_id",
            "action",
            "issued_at",
            "expires_at",
            "verification_method",
        ):
            _text(getattr(self, name), name)
        for name in (
            "subject_hash",
            "payload_hash",
            "signed_payload_hash",
            "external_verification_receipt_hash",
        ):
            _hash_value(getattr(self, name), name)
        if self.revoked_at is not None:
            _text(self.revoked_at, "revoked_at")
        if type(self.external_verification_receipt) is not bytes:
            raise TypeError("external_verification_receipt must be bytes")
        if not self.external_verification_receipt:
            raise ValueError("external_verification_receipt must be non-empty")
        if len(self.external_verification_receipt) > MAX_CONTENT_BYTES:
            raise ValueError("external_verification_receipt exceeds maximum size")
        if self.external_verification_receipt_hash != _raw_hash(self.external_verification_receipt):
            raise ValueError("external verification receipt hash mismatch")

    @property
    def hash(self):
        return _hash(_canon(tuple(getattr(self, f) for f in self.__dataclass_fields__)))


@dataclass(frozen=True)
class TrustedIngestionContext:
    contract: AcceptanceContract
    change_set: ChangeSet
    plan: VerificationPlan
    repository_id: str
    source_tree: str
    target_tree: str
    observed_at: str
    profile: IngestionProfile
    expected_profile_hash: str
    requirements: tuple[EvidenceRequirement, ...]
    required_action: str
    prerequisite_payload_hashes: tuple[tuple[TrustRole, str], ...]

    def __post_init__(self):
        if (
            type(self.contract) is not AcceptanceContract
            or type(self.change_set) is not ChangeSet
            or type(self.plan) is not VerificationPlan
        ):
            raise TypeError("invalid context subjects")
        if type(self.profile) is not IngestionProfile:
            raise TypeError("profile must be IngestionProfile")
        for name in (
            "repository_id",
            "source_tree",
            "target_tree",
            "observed_at",
            "required_action",
        ):
            _text(getattr(self, name), name)
        _hash_value(self.expected_profile_hash, "expected_profile_hash")
        if type(self.requirements) is not tuple or any(
            type(v) is not EvidenceRequirement for v in self.requirements
        ):
            raise TypeError("requirements must be EvidenceRequirement tuple")
        for requirement in self.requirements:
            requirement.__post_init__()
        if (
            len(self.requirements) > MAX_COLLECTION_ITEMS
            or len(self.prerequisite_payload_hashes) > MAX_COLLECTION_ITEMS
        ):
            raise ValueError("context collections exceed maximum size")
        if type(self.prerequisite_payload_hashes) is not tuple:
            raise TypeError("prerequisite_payload_hashes must be tuple")
        for role, value in self.prerequisite_payload_hashes:
            if type(role) is not TrustRole:
                raise TypeError("prerequisite role must be TrustRole")
            _hash_value(value, "prerequisite_payload_hash")
        if len({role for role, _ in self.prerequisite_payload_hashes}) != len(
            self.prerequisite_payload_hashes
        ):
            raise ValueError("prerequisite roles must be unique")
        if self.prerequisite_payload_hashes != tuple(
            sorted(self.prerequisite_payload_hashes, key=lambda v: (v[0].value, v[1]))
        ):
            raise ValueError("prerequisites must be sorted")

    @property
    def hash(self):
        return _hash(
            _canon((
                self.contract,
                self.change_set,
                self.plan,
                self.repository_id,
                self.source_tree,
                self.target_tree,
                self.observed_at,
                self.profile.hash,
                self.expected_profile_hash,
                tuple(sorted((requirement.hash for requirement in self.requirements))),
                self.required_action,
                tuple(sorted(self.prerequisite_payload_hashes, key=lambda v: (v[0].value, v[1]))),
            ))
        )


@dataclass(frozen=True, init=False, eq=False)
class IngestionReceipt:
    context_hash: str
    profile_hash: str
    bundle_hash: str | None
    raw_content_hashes: tuple[str, ...]
    provenance_hashes: tuple[str, ...]
    observations: tuple[Observation, ...]
    freshness: tuple[tuple[str, FreshnessStatus], ...]
    machine_verified_artifact_ids: tuple[str, ...]
    human_open_artifact_ids: tuple[str, ...]
    human_open_reasons: tuple[tuple[str, str], ...]
    missing_verifier_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    receipt_hash: str

    def __post_init__(self):
        for name in ("context_hash", "profile_hash"):
            _hash_value(getattr(self, name), name)
        if self.bundle_hash is not None:
            _hash_value(self.bundle_hash, "bundle_hash")
        if type(self.observations) is not tuple or any(
            type(v) is not Observation for v in self.observations
        ):
            raise TypeError("observations must be Observation tuple")
        if type(self.freshness) is not tuple or any(
            type(v) is not tuple
            or len(v) != 2
            or type(v[0]) is not str
            or type(v[1]) is not FreshnessStatus
            for v in self.freshness
        ):
            raise TypeError("freshness must be artifact/status pairs")
        if self.freshness != tuple(sorted(self.freshness, key=lambda v: v[0])):
            raise ValueError("freshness must be sorted")
        for name in (
            "raw_content_hashes",
            "provenance_hashes",
            "machine_verified_artifact_ids",
            "human_open_artifact_ids",
            "missing_verifier_ids",
            "reason_codes",
        ):
            if type(getattr(self, name)) is not tuple:
                raise TypeError(f"{name} must be tuple")
        if type(self.human_open_reasons) is not tuple:
            raise TypeError("human_open_reasons must be tuple")
        _hash_value(self.receipt_hash, "receipt_hash")
        expected = _hash(
            _canon(
                tuple(getattr(self, f) for f in self.__dataclass_fields__ if f != "receipt_hash")
            )
        )
        if self.receipt_hash != expected:
            raise ValueError("receipt_hash does not match receipt")

    @property
    def hash(self):
        return self.receipt_hash

    @property
    def machine_verified_count(self):
        return len(self.machine_verified_artifact_ids)

    @property
    def human_open_count(self):
        return len(self.human_open_artifact_ids)


@dataclass(frozen=True, init=False, eq=False)
class IngestionResult:
    bundle: EvidenceBundle | None
    receipt: IngestionReceipt
    condition: IntegrityStatus
    reason_codes: tuple[str, ...]

    def __post_init__(self):
        if (
            type(self.receipt) is not IngestionReceipt
            or type(self.condition) is not IntegrityStatus
        ):
            raise TypeError("invalid ingestion result")
        if type(self.reason_codes) is not tuple:
            raise TypeError("reason_codes must be tuple")
        if self.condition is IntegrityStatus.VALID and self.bundle is None:
            raise ValueError("VALID result requires bundle")
        if self.bundle is not None and type(self.bundle) is not EvidenceBundle:
            raise TypeError("bundle must be EvidenceBundle")
        if self.condition is IntegrityStatus.VALID and (self.reason_codes or self.bundle is None):
            raise ValueError("VALID result must have no reasons and a bundle")
        if self.condition is not IntegrityStatus.VALID and self.bundle is not None:
            raise ValueError("non-VALID result cannot have a bundle")
        if self.receipt.bundle_hash != (self.bundle.hash if self.bundle is not None else None):
            raise ValueError("receipt bundle hash mismatch")


_REASON_ORDER = ("TAMPERED", "STALE", "CROSS_BOUND", "DUPLICATE", "MALFORMED", "MISSING")
_REASONS = {"TAMPERED", "STALE", "CROSS_BOUND", "DUPLICATE", "MALFORMED", "MISSING"}
_REASON_CODES = {
    "TAMPERED": {"content_hash", "provenance_hash"},
    "STALE": {"subject", "generation", "observation"},
    "CROSS_BOUND": {
        "producer",
        "repository",
        "tree",
        "changeset",
        "acceptance_contract",
        "observation_status",
        "artifact",
        "runtime",
        "execution",
    },
    "DUPLICATE": {"artifact", "verifier"},
    "MALFORMED": {
        "profile",
        "requirement",
        "submission",
        "provenance",
        "evidence_type",
        "producer_role",
        "generation",
        "timestamp",
        "runtime",
        "trust_reference",
    },
    "MISSING": {
        "required_verifier",
        "source_locator",
        "execution",
        "runtime_identity",
        "ready_identity",
        "prerequisite",
    },
}


def condition_for_ingestion_reasons(reasons):
    for reason in reasons:
        if type(reason) is not str or ":" not in reason or reason.split(":", 1)[0] not in _REASONS:
            raise ValueError("unknown ingestion reason")
        kind, detail = reason.split(":", 1)
        if detail not in _REASON_CODES[kind]:
            raise ValueError("unknown ingestion reason")
    for kind in _REASON_ORDER:
        if any(r.startswith(kind + ":") for r in reasons):
            return IntegrityStatus[kind]
    return IntegrityStatus.VALID


def _parse_time(value):
    if type(value) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", value
    ):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        offset = dt.utcoffset()
        return (
            dt
            if dt.tzinfo is not None and offset is not None and offset.total_seconds() == 0
            else None
        )
    except (TypeError, ValueError, AttributeError):
        return None


def _valid_revision(value):
    return (
        type(value) is str
        and bool(value.strip())
        and value == value.strip()
        and "\x00" not in value
        and len(value) <= MAX_TEXT_LENGTH
    )


def derive_runtime_freshness(runtime, observed_at):
    if type(runtime) is not RuntimeSourceObservation:
        return FreshnessStatus.CONVERGENCE_UNKNOWN
    now, at, expiry = (
        _parse_time(observed_at),
        _parse_time(runtime.observed_at),
        _parse_time(runtime.expires_at),
    )
    if not now or not at or not expiry:
        return FreshnessStatus.CONVERGENCE_UNKNOWN
    if at > now or expiry < now or runtime.observed_generation != runtime.desired_generation:
        return FreshnessStatus.STALE_OBSERVATION
    if not _valid_revision(runtime.desired_source_revision) or not _valid_revision(
        runtime.loaded_source_revision
    ):
        return FreshnessStatus.CONVERGENCE_UNKNOWN
    if runtime.generation is EvidenceGeneration.SOURCE:
        if not runtime.desired_source_revision or not runtime.loaded_source_revision:
            return FreshnessStatus.CONVERGENCE_UNKNOWN
        if runtime.loaded_source_revision != runtime.desired_source_revision:
            return FreshnessStatus.SOURCE_AHEAD_OF_RUNTIME
        if (
            runtime.expected_runtime_identity is not None
            or runtime.observed_runtime_identity is not None
            or runtime.readiness_status is not None
        ):
            return FreshnessStatus.CONVERGENCE_UNKNOWN
        return FreshnessStatus.SOURCE_ALIGNED
    if runtime.loaded_source_revision != runtime.desired_source_revision:
        return FreshnessStatus.SOURCE_AHEAD_OF_RUNTIME
    if not runtime.expected_runtime_identity or not runtime.observed_runtime_identity:
        return FreshnessStatus.CONVERGENCE_UNKNOWN
    if runtime.expected_runtime_identity != runtime.observed_runtime_identity:
        return FreshnessStatus.RUNTIME_IDENTITY_MISMATCH
    if runtime.readiness_status != "READY":
        return FreshnessStatus.CONVERGENCE_UNKNOWN
    return FreshnessStatus.READY_IDENTITY_BOUND


def _raw_hash(content):
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _mint_receipt(values):
    body = tuple(values)
    receipt_hash = _hash(_canon(body))
    obj = object.__new__(IngestionReceipt)
    for field, value in zip(IngestionReceipt.__dataclass_fields__, body + (receipt_hash,)):
        object.__setattr__(obj, field, value)
    obj.__post_init__()
    return obj


def _mint_result(bundle, receipt, condition, reason_codes):
    obj = object.__new__(IngestionResult)
    for field, value in zip(
        IngestionResult.__dataclass_fields__, (bundle, receipt, condition, reason_codes)
    ):
        object.__setattr__(obj, field, value)
    obj.__post_init__()
    return obj


def _result_fingerprint(context, result):
    return _canon((
        context.hash,
        tuple(getattr(result, field) for field in IngestionResult.__dataclass_fields__),
    ))


def _validate_context_nested(context):
    try:
        if (
            type(context.contract) is not AcceptanceContract
            or type(context.change_set) is not ChangeSet
            or type(context.plan) is not VerificationPlan
        ):
            return False
        context.__post_init__()
        context.contract.__post_init__()
        context.change_set.__post_init__()
        context.plan.__post_init__()
        context.profile.__post_init__()
        for producer in context.profile.producers:
            producer.__post_init__()
        for issuer in context.profile.issuers:
            issuer.__post_init__()
        for requirement in context.requirements:
            requirement.__post_init__()
    except (TypeError, ValueError, AttributeError):
        return False
    return True


def _revalidate_context_or_raise(context):
    if (
        type(context.contract) is not AcceptanceContract
        or type(context.change_set) is not ChangeSet
        or type(context.plan) is not VerificationPlan
    ):
        raise TypeError("invalid context subjects")
    if type(context.profile) is not IngestionProfile:
        raise TypeError("profile must be IngestionProfile")
    context.contract.__post_init__()
    context.change_set.__post_init__()
    context.plan.__post_init__()
    for name in (
        "repository_id",
        "source_tree",
        "target_tree",
        "observed_at",
        "required_action",
    ):
        _text(getattr(context, name), name)
    _hash_value(context.expected_profile_hash, "expected_profile_hash")
    if type(context.requirements) is not tuple or any(
        type(value) is not EvidenceRequirement for value in context.requirements
    ):
        raise TypeError("requirements must be EvidenceRequirement tuple")
    if type(context.prerequisite_payload_hashes) is not tuple:
        raise TypeError("prerequisite_payload_hashes must be tuple")
    if (
        len(context.requirements) > MAX_COLLECTION_ITEMS
        or len(context.prerequisite_payload_hashes) > MAX_COLLECTION_ITEMS
    ):
        raise ValueError("context collections exceed maximum size")
    for role, value in context.prerequisite_payload_hashes:
        if type(role) is not TrustRole:
            raise TypeError("prerequisite role must be TrustRole")
        _hash_value(value, "prerequisite_payload_hash")
    if len({role for role, _ in context.prerequisite_payload_hashes}) != len(
        context.prerequisite_payload_hashes
    ):
        raise ValueError("prerequisite roles must be unique")
    if context.prerequisite_payload_hashes != tuple(
        sorted(context.prerequisite_payload_hashes, key=lambda value: (value[0].value, value[1]))
    ):
        raise ValueError("prerequisites must be sorted")
    context.profile.__post_init__()
    for grant in context.profile.producers:
        grant.__post_init__()
    for grant in context.profile.issuers:
        grant.__post_init__()
    for requirement in context.requirements:
        requirement.__post_init__()


def _mint_failure(context, reasons):
    receipt = _mint_receipt((
        context.hash,
        context.profile.hash,
        None,
        (),
        (),
        (),
        (),
        (),
        (),
        (),
        (),
        tuple(sorted(set(reasons))),
    ))
    result = _mint_result(None, receipt, condition_for_ingestion_reasons(reasons), reasons)
    _TRUSTED_FINGERPRINTS[result] = (
        weakref.ref(context),
        _result_fingerprint(context, result),
        False,
    )
    return result


def is_trusted_ingestion_result(context, result):
    if type(context) is not TrustedIngestionContext or type(result) is not IngestionResult:
        return False
    if not _validate_context_nested(context):
        return False
    binding = _TRUSTED_FINGERPRINTS.get(result)
    if binding is None or binding[0]() is not context:
        return False
    if not binding[2]:
        return False
    mint_fingerprint = binding[1]
    current_fingerprint = _result_fingerprint(context, result)
    if current_fingerprint != mint_fingerprint:
        return False
    receipt = result.receipt
    expected_receipt = _hash(
        _canon(
            tuple(getattr(receipt, f) for f in receipt.__dataclass_fields__ if f != "receipt_hash")
        )
    )
    if expected_receipt != receipt.receipt_hash or receipt.context_hash != context.hash:
        return False
    if result.condition is IntegrityStatus.VALID:
        return (
            result.bundle is not None
            and receipt.bundle_hash == result.bundle.hash
            and result.bundle.integrity(context.contract, context.change_set, context.plan)
            is IntegrityStatus.VALID
            and result.reason_codes == ()
        )
    return False


def classify_ingestion_result(context, result):
    if type(context) is not TrustedIngestionContext or type(result) is not IngestionResult:
        return IngestionTrustStatus.UNTRUSTED
    binding = _TRUSTED_FINGERPRINTS.get(result)
    if binding is None or binding[0]() is not context:
        return IngestionTrustStatus.UNTRUSTED
    if not binding[2]:
        return IngestionTrustStatus.UNTRUSTED
    if not _validate_context_nested(context):
        return IngestionTrustStatus.RECEIPT_INVALID
    if not is_trusted_ingestion_result(context, result):
        return IngestionTrustStatus.RECEIPT_INVALID
    return IngestionTrustStatus.TRUSTED


def ingest_evidence(context, submissions):
    if type(context) is not TrustedIngestionContext:
        raise TypeError("context must be TrustedIngestionContext")
    if type(submissions) is not tuple:
        raise TypeError("submissions must be tuple")
    if len(submissions) > MAX_COLLECTION_ITEMS:
        raise ValueError("submissions exceed maximum size")
    _revalidate_context_or_raise(context)
    gate_reasons = []
    if context.plan.acceptance_contract_hash != context.contract.hash:
        gate_reasons.append("CROSS_BOUND:acceptance_contract")
    if context.plan.change_set_hash != context.change_set.hash:
        gate_reasons.append("CROSS_BOUND:changeset")
    if gate_reasons:
        return _mint_failure(context, tuple(sorted(gate_reasons)))
    reasons = []
    observations = []
    raw_hashes = []
    provenance_hashes = []
    freshness = []
    machine = []
    human = []
    human_reasons = []
    missing = []
    valid_requirements = []
    invalid_requirement = False
    invalid_profile = False
    try:
        context.profile.__post_init__()
        for grant in context.profile.producers:
            grant.__post_init__()
        for grant in context.profile.issuers:
            grant.__post_init__()
    except (TypeError, ValueError, AttributeError):
        reasons.append("MALFORMED:profile")
        invalid_profile = True
    if context:
        for requirement in context.requirements:
            try:
                requirement.__post_init__()
            except (TypeError, ValueError, AttributeError):
                reasons.append("MALFORMED:requirement")
                invalid_requirement = True
            else:
                valid_requirements.append(requirement)
    reqs = {(r.verifier_id, r.artifact_id): r for r in valid_requirements}
    if len(reqs) != len(valid_requirements):
        reasons.append("DUPLICATE:verifier")
    if len({r.verifier_id for r in valid_requirements}) != len(valid_requirements):
        reasons.append("DUPLICATE:verifier")
    if len({r.artifact_id for r in valid_requirements}) != len(valid_requirements):
        reasons.append("DUPLICATE:artifact")
    if any(
        r.verifier_id not in set(context.contract.required_verifier_ids) for r in valid_requirements
    ):
        reasons.append("MALFORMED:requirement")
    seen_artifacts = set()
    seen_verifier_content = set()
    validated_provenance = []
    for submission in submissions:
        if type(submission) is not EvidenceSubmission:
            reasons.append("MALFORMED:submission")
            continue
        p = submission.provenance
        local_reason_start = len(reasons)
        if type(p) is not ProvenanceEnvelope:
            reasons.append("MALFORMED:provenance")
            continue
        validated_provenance.append(p)
        raw = _raw_hash(submission.content)
        raw_hashes.append(raw)
        provenance_hashes.append(p.hash)
        if p.schema != PROVENANCE_ENVELOPE_SCHEMA:
            reasons.append("TAMPERED:provenance_hash")
        if raw != p.content_hash:
            reasons.append("TAMPERED:content_hash")
        if (
            type(p.source_locator) is not str
            or not p.source_locator.strip()
            or p.source_locator != p.source_locator.strip()
            or "\x00" in p.source_locator
        ):
            if type(p.source_locator) is not str:
                reasons.append("MALFORMED:provenance")
            else:
                reasons.append("MISSING:source_locator")
        if type(p.evidence_type) is not EvidenceType:
            reasons.append("MALFORMED:evidence_type")
        if type(p.producer_role) is not ProducerRole:
            reasons.append("MALFORMED:producer_role")
        if type(p.generation) is not EvidenceGeneration:
            reasons.append("MALFORMED:generation")
        for field in ("source_revision", "target_revision"):
            if not _valid_revision(getattr(p, field)):
                reasons.append("MALFORMED:provenance")
        if type(p.evidence_type) is not EvidenceType:
            reasons.append("MALFORMED:evidence_type")
        # Recompute the sealed envelope from physical fields; hostile objects cannot lie about hash.
        if (
            p.hash != _hash(_canon(tuple(getattr(p, f) for f in p.__dataclass_fields__)))
            and type(p.evidence_type) is EvidenceType
            and type(p.producer_role) is ProducerRole
            and type(p.generation) is EvidenceGeneration
        ):
            reasons.append("TAMPERED:provenance_hash")
        req = reqs.get((p.verifier_id, p.artifact_id))
        if req is None:
            req = next(
                (
                    candidate
                    for (verifier_id, _), candidate in reqs.items()
                    if verifier_id == p.verifier_id
                ),
                None,
            )
        if req is None:
            reasons.extend(("MISSING:required_verifier", "TAMPERED:provenance_hash"))
        else:
            status_mismatch = submission.status is not req.expected_status
            if req.content_hash != p.content_hash or req.content_hash != raw:
                reasons.append("TAMPERED:content_hash")
            if status_mismatch:
                reasons.append("CROSS_BOUND:observation_status")
            if req.provenance_hash != p.hash and type(p.evidence_type) is EvidenceType:
                reasons.append("TAMPERED:provenance_hash")
            if p.artifact_id != req.artifact_id:
                reasons.append("CROSS_BOUND:artifact")
            if type(p.evidence_type) is EvidenceType and p.evidence_type is not req.evidence_type:
                reasons.append("CROSS_BOUND:artifact")
            if type(p.generation) is EvidenceGeneration and p.generation is not req.generation:
                reasons.append("MALFORMED:generation")
            if (
                p.generation is EvidenceGeneration.SOURCE
                and p.runtime is not None
                and p.runtime.generation is not EvidenceGeneration.SOURCE
            ):
                reasons.append("MALFORMED:runtime")
            if (
                p.generation is EvidenceGeneration.SOURCE
                and type(p.runtime) is RuntimeSourceObservation
                and (
                    p.runtime.expected_runtime_identity is not None
                    or p.runtime.observed_runtime_identity is not None
                    or p.runtime.readiness_status is not None
                )
            ):
                reasons.append("MALFORMED:runtime")
            producer = next(
                (g for g in context.profile.producers if g.producer_id == p.producer_id), None
            )
            if type(p.producer_role) is ProducerRole and (
                p.producer_id != req.producer_id
                or producer is None
                or p.producer_role is not producer.role
                or p.producer_software_hash != producer.software_hash
            ):
                reasons.append("CROSS_BOUND:producer")
            if p.repository_id != context.repository_id:
                reasons.append("CROSS_BOUND:repository")
            if p.source_tree != context.source_tree or p.target_tree != context.target_tree:
                reasons.append("CROSS_BOUND:tree")
            if (
                _valid_revision(p.source_revision)
                and _valid_revision(p.target_revision)
                and (
                    p.source_revision != context.change_set.source_revision
                    or p.target_revision != context.change_set.target_revision
                )
            ):
                reasons.append("STALE:subject")
            if (
                p.change_set_hash != context.change_set.hash
                or p.diff_hash != context.change_set.diff_hash
            ):
                reasons.append("CROSS_BOUND:changeset")
            if (
                p.execution_id != req.execution_id
                or p.attempt_id != req.attempt_id
                or p.environment_hash != req.environment_hash
            ):
                reasons.append("CROSS_BOUND:execution")
            if p.verification_method not in next(
                (
                    g.verification_methods
                    for g in context.profile.producers
                    if g.producer_id == p.producer_id
                ),
                (),
            ):
                reasons.append("CROSS_BOUND:producer")
            if p.generation != req.generation:
                reasons.append("TAMPERED:provenance_hash")
            if p.generation is EvidenceGeneration.LEGACY_NARRATIVE:
                reasons.append("MALFORMED:generation")
            if p.generation is EvidenceGeneration.EXECUTION and p.runtime is not None:
                reasons.append("MALFORMED:runtime")
                continue
            if (
                p.generation is EvidenceGeneration.RUNTIME
                and type(p.runtime) is RuntimeSourceObservation
                and p.runtime.generation is EvidenceGeneration.SOURCE
            ):
                reasons.append("MALFORMED:generation")
            if p.runtime is not None:
                if type(p.runtime) is not RuntimeSourceObservation:
                    reasons.append("MALFORMED:runtime")
                    continue
                if (
                    p.generation is EvidenceGeneration.SOURCE
                    and _valid_revision(p.runtime.loaded_source_revision)
                    and _valid_revision(p.runtime.desired_source_revision)
                    and p.runtime.loaded_source_revision != p.runtime.desired_source_revision
                ):
                    reasons.append("STALE:subject")
                if p.runtime.observed_generation != p.runtime.desired_generation:
                    reasons.append("STALE:generation")
                if not _valid_revision(p.runtime.desired_source_revision) or not _valid_revision(
                    p.runtime.loaded_source_revision
                ):
                    reasons.append("MISSING:source_locator")
                if (
                    _parse_time(p.runtime.observed_at) is None
                    or _parse_time(p.runtime.expires_at) is None
                ):
                    reasons.append("MALFORMED:timestamp")
                f = derive_runtime_freshness(p.runtime, context.observed_at)
                freshness.append((p.artifact_id, f))
                if f is FreshnessStatus.STALE_OBSERVATION:
                    reasons.append(
                        "STALE:generation"
                        if p.runtime.observed_generation != p.runtime.desired_generation
                        else "STALE:observation"
                    )
                elif f is FreshnessStatus.SOURCE_AHEAD_OF_RUNTIME:
                    reasons.append("STALE:subject")
                elif f is FreshnessStatus.RUNTIME_IDENTITY_MISMATCH:
                    reasons.append("CROSS_BOUND:runtime")
                elif f is FreshnessStatus.CONVERGENCE_UNKNOWN:
                    if (
                        _parse_time(p.runtime.observed_at) is not None
                        and _parse_time(p.runtime.expires_at) is not None
                        and _valid_revision(p.runtime.desired_source_revision)
                        and _valid_revision(p.runtime.loaded_source_revision)
                    ):
                        if (
                            not p.runtime.expected_runtime_identity
                            or not p.runtime.observed_runtime_identity
                        ):
                            reasons.append("MISSING:runtime_identity")
                        elif p.runtime.readiness_status != "READY":
                            reasons.append("MISSING:ready_identity")
                if (
                    req.runtime_ready_required
                    and f is not FreshnessStatus.READY_IDENTITY_BOUND
                    and f is not FreshnessStatus.SOURCE_AHEAD_OF_RUNTIME
                    and _valid_revision(p.runtime.desired_source_revision)
                    and _valid_revision(p.runtime.loaded_source_revision)
                    and p.runtime.expected_runtime_identity
                    and p.runtime.observed_runtime_identity
                ):
                    reasons.append("MISSING:ready_identity")
                if p.generation is EvidenceGeneration.SOURCE and req.runtime_ready_required:
                    reasons.append("MISSING:ready_identity")
            elif p.generation is EvidenceGeneration.RUNTIME or req.runtime_ready_required:
                reasons.append("MISSING:ready_identity")
            if p.generation is EvidenceGeneration.RUNTIME and p.runtime is None:
                reasons.append("MISSING:runtime_identity")
            generated = _parse_time(p.generated_at)
            observed = _parse_time(context.observed_at)
            if generated is None:
                reasons.append("MALFORMED:timestamp")
            elif observed is not None and (
                generated > observed
                or (observed - generated).total_seconds() > context.profile.max_age_seconds
            ):
                reasons.append("STALE:observation")
            if p.artifact_id in seen_artifacts:
                reasons.append("DUPLICATE:artifact")
            if p.artifact_id not in seen_artifacts and p.verifier_id in {
                verifier for verifier, _ in seen_verifier_content
            }:
                reasons.append("DUPLICATE:verifier")
            seen_artifacts.add(p.artifact_id)
            seen_verifier_content.add((p.verifier_id, raw))
            if not status_mismatch:
                observations.append(
                    Observation(p.verifier_id, p.artifact_id, p.hash, req.expected_status)
                )
                if len(reasons) == local_reason_start:
                    machine.append(p.artifact_id)
                if req.human_semantic_review_required:
                    human.append(p.artifact_id)
                    human_reasons.append((p.artifact_id, "semantic_review_required"))
    submitted_ids = {p.verifier_id for p in validated_provenance}
    required_ids = set(context.contract.required_verifier_ids) | set(
        context.plan.required_verifier_ids
    )
    for verifier in sorted(required_ids - submitted_ids):
        missing.append(verifier)
        reasons.append("MISSING:required_verifier")
    for verifier, artifact in reqs:
        if verifier not in {p.verifier_id for p in validated_provenance}:
            missing.append(verifier)
    if context:
        if context.expected_profile_hash != context.profile.hash:
            reasons.append("MALFORMED:profile")
        if _parse_time(context.observed_at) is None:
            reasons.append("MALFORMED:timestamp")
        if context.profile.producers and any(
            type(x) is not ProducerGrant for x in context.profile.producers
        ):
            reasons.append("MALFORMED:profile")
    if invalid_profile:
        reasons = ["MALFORMED:profile"]
    elif invalid_requirement:
        reasons = ["MALFORMED:requirement"]
    reasons = tuple(sorted(set(reasons)))
    condition = condition_for_ingestion_reasons(reasons)
    bundle = None
    if (
        not reasons
        and len(observations) == len(context.requirements)
        and len({(o.verifier_id, o.artifact_id) for o in observations}) == len(context.requirements)
    ):
        bundle = EvidenceBundle(
            "ingested",
            context.contract.hash,
            context.change_set.hash,
            context.plan.hash,
            tuple(sorted(observations, key=lambda o: (o.verifier_id, o.artifact_id))),
        )
    receipt_values = (
        context.hash if context else "",
        context.profile.hash if context else "",
        bundle.hash if bundle else None,
        tuple(sorted(set(raw_hashes))),
        tuple(sorted(set(provenance_hashes))),
        tuple(sorted(observations, key=lambda o: (o.verifier_id, o.artifact_id))),
        tuple(sorted(set(freshness), key=lambda x: x[0])),
        tuple(sorted(set(machine))),
        tuple(sorted(set(human))),
        tuple(sorted(set(human_reasons))),
        tuple(sorted(set(missing))),
        reasons,
    )
    receipt = _mint_receipt(receipt_values)
    result = _mint_result(bundle, receipt, condition, reasons)
    _TRUSTED_FINGERPRINTS[result] = (
        weakref.ref(context),
        _result_fingerprint(context, result),
        result.condition is IntegrityStatus.VALID,
    )
    return result
