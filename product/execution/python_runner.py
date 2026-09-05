"""Deterministic, dependency-free boundary for the Python OCI witness.

The product core does not start containers or acquire dependencies.  A
controller supplies an injected ``executor`` implementing that effect.  This
module validates its result, binds it to the exact request/profile, and runs
the same request twice before returning a certifiable result.
"""

import hashlib
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Optional

IMAGE = "python:3.12-alpine"
IMAGE_DIGEST = "sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31"
LOCK_DIGEST = "sha256:604c10c45cf64e2d00242e8c761ac9d1460aa7c6a81f7f9d14f0a8e9d4e7a076"
PROFILE_ID = "python-oci-pytest-v1"
MAX_OUTPUT_BYTES = 1_048_576
DEPENDENCY_ARTIFACTS = (
    (
        "iniconfig-2.3.0-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/cb/b1/3846dd7f199d53cb17f49cba7e651e9ce294d8497c8c150530ed11865bb8/iniconfig-2.3.0-py3-none-any.whl",
        "f631c04d2c48c52b84d0d0549c99ff3859c98df65b3101406327ecc7d53fbf12",
    ),
    (
        "packaging-26.0-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/b7/b9/c538f279a4e237a006a2c98387d081e9eb060d203d8ed34467cc0f0b9b53/packaging-26.0-py3-none-any.whl",
        "b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529",
    ),
    (
        "pluggy-1.6.0-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/54/20/4d324d65cc6d9205fabedc306948156824eb9f0ee1633355a8f7ec5c66bf/pluggy-1.6.0-py3-none-any.whl",
        "e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746",
    ),
    (
        "pygments-2.20.0-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/f4/7e/a72dd26f3b0f4f2bf1dd8923c85f7ceb43172af56d63c7383eb62b332364/pygments-2.20.0-py3-none-any.whl",
        "81a9e26dd42fd28a23a2d169d86d7ac03b46e2f8b59ed4698fb4785f946d0176",
    ),
    (
        "pytest-9.0.3-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/d4/24/a372aaf5c9b7208e7112038812994107bc65a84cd00e0354a88c2c77a617/pytest-9.0.3-py3-none-any.whl",
        "2c5efc453d45394fdd706ade797c0a81091eccd1d6e4bccfcd476e2b8e0ab5d9",
    ),
)
DEPENDENCY_ARTIFACTS_HASH = (
    "sha256:"
    + hashlib.sha256(json.dumps(DEPENDENCY_ARTIFACTS, separators=(",", ":")).encode()).hexdigest()
)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _text(value: str, field: str) -> None:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{field} must be a normalized non-empty string")


def _hash(value: str, field: str) -> None:
    _text(value, field)
    if (
        len(value) != 71
        or not value.startswith("sha256:")
        or any(c not in "0123456789abcdef" for c in value[7:])
    ):
        raise ValueError(f"{field} must be sha256:<64 lowercase hex>")


class RunnerStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    UNVERIFIABLE = "UNVERIFIABLE"


class ExecutionUnavailableError(RuntimeError):
    """Injected executor could not produce a physical witness."""


@dataclass(frozen=True)
class PythonOCIProfile:
    profile_id: str = PROFILE_ID
    image: str = IMAGE
    image_digest: str = IMAGE_DIGEST
    lock_digest: str = LOCK_DIGEST
    network: str = "none"
    rootfs: str = "read-only"
    command: tuple[str, ...] = ("python", "-m", "pytest", "--junitxml=/evidence/junit.xml")
    timeout_seconds: int = 300
    memory_bytes: int = 1_073_741_824
    cpu_seconds: int = 60
    dependency_artifacts_hash: str = DEPENDENCY_ARTIFACTS_HASH

    def __post_init__(self):
        _text(self.profile_id, "profile_id")
        _text(self.image, "image")
        _hash(self.image_digest, "image_digest")
        _hash(self.lock_digest, "lock_digest")
        if self.dependency_artifacts_hash != DEPENDENCY_ARTIFACTS_HASH:
            raise ValueError("dependency artifact manifest mismatch")
        if self.network != "none" or self.rootfs != "read-only":
            raise ValueError("profile must disable network and use a read-only rootfs")
        if (
            type(self.command) is not tuple
            or not self.command
            or any(type(part) is not str or not part for part in self.command)
        ):
            raise ValueError("command must be a non-empty argv tuple")
        if any(part in {"sh", "bash", "-c", "--command"} for part in self.command):
            raise ValueError("shell invocation is forbidden")
        if self.timeout_seconds <= 0 or self.memory_bytes <= 0 or self.cpu_seconds <= 0:
            raise ValueError("resource limits must be positive")

    @property
    def hash(self) -> str:
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        return _digest(body)

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "image": self.image,
            "image_digest": self.image_digest,
            "lock_digest": self.lock_digest,
            "network": self.network,
            "rootfs": self.rootfs,
            "command": list(self.command),
            "timeout_seconds": self.timeout_seconds,
            "memory_bytes": self.memory_bytes,
            "cpu_seconds": self.cpu_seconds,
            "dependency_artifacts_hash": self.dependency_artifacts_hash,
        }

    @classmethod
    def load(cls, manifest: Path, lock: Path, uv_lock: Optional[Path] = None) -> "PythonOCIProfile":
        data = json.loads(manifest.read_text())
        if set(data) != {
            "profile_id",
            "image",
            "image_digest",
            "lock_digest",
            "network",
            "rootfs",
            "command",
            "timeout_seconds",
            "memory_bytes",
            "cpu_seconds",
            "dependency_artifacts_hash",
        }:
            raise ValueError("manifest keys mismatch")
        locked = json.loads(lock.read_text())
        required = {
            "profile_id",
            "image",
            "image_digest",
            "uv_lock_sha256",
            "offline",
            "network",
            "dependency_artifacts",
        }
        if (
            set(locked) != required
            or locked["offline"] is not True
            or locked["network"] != "none"
            or tuple(tuple(x) for x in locked["dependency_artifacts"]) != DEPENDENCY_ARTIFACTS
        ):
            raise ValueError("profile lock keys or policy mismatch")
        actual = (
            _digest(uv_lock.read_bytes())[7:]
            if uv_lock is not None and uv_lock.exists()
            else LOCK_DIGEST[7:]
        )
        if locked["uv_lock_sha256"] != actual:
            raise ValueError("uv.lock digest mismatch")
        profile = cls(**{k: tuple(v) if k == "command" else v for k, v in data.items()})
        if (
            locked["profile_id"] != profile.profile_id
            or locked["image"] != profile.image
            or locked["image_digest"] != profile.image_digest
        ):
            raise ValueError("profile lock mismatch")
        if (
            profile.lock_digest != "sha256:" + locked["uv_lock_sha256"]
            or profile.lock_digest != LOCK_DIGEST
            or profile.dependency_artifacts_hash != DEPENDENCY_ARTIFACTS_HASH
        ):
            raise ValueError("frozen profile mismatch")
        return profile


@dataclass(frozen=True)
class ExecutionAttempt:
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
    junit_tests: int = 0
    junit_failures: int = 0
    junit_errors: int = 0
    outcome_hash: str = ""


@dataclass(frozen=True)
class RunnerResult:
    status: RunnerStatus
    reason_codes: tuple[str, ...]
    profile_hash: str
    attempt_ids: tuple[str, ...]
    artifact_hashes: tuple[str, ...]
    attempts: tuple[ExecutionAttempt, ...]

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "profile_hash": self.profile_hash,
            "attempt_ids": list(self.attempt_ids),
            "artifact_hashes": list(self.artifact_hashes),
            "attempts": [
                {
                    "attempt_id": a.attempt_id,
                    "execution_id": a.execution_id,
                    "source_revision": a.source_revision,
                    "source_tree": a.source_tree,
                    "contract_hash": a.contract_hash,
                    "plan_hash": a.plan_hash,
                    "environment_hash": a.environment_hash,
                    "argv": list(a.argv),
                    "stdout": a.stdout.hex(),
                    "stderr": a.stderr.hex(),
                    "exit_code": a.exit_code,
                    "junit": a.junit.hex(),
                    "artifact_hash": a.artifact_hash,
                    "outcome_hash": a.outcome_hash,
                }
                for a in self.attempts
            ],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "RunnerResult":
        if type(data) is not dict or type(data.get("reason_codes")) is not list:
            raise ValueError("malformed receipt")
        attempts = []
        profile = PythonOCIRunner().profile
        for item in data.get("attempts", ()):
            if type(item.get("exit_code")) is not int:
                raise ValueError("receipt exit code must be int")
            stdout, stderr, junit = (bytes.fromhex(item[k]) for k in ("stdout", "stderr", "junit"))
            if tuple(item["argv"]) != profile.command or any(
                len(x) > MAX_OUTPUT_BYTES for x in (stdout, stderr, junit)
            ):
                raise ValueError("receipt command or output limit mismatch")
            for field in ("source_revision", "source_tree"):
                if (
                    type(item[field]) is not str
                    or len(item[field]) != 40
                    or any(c not in "0123456789abcdef" for c in item[field])
                ):
                    raise ValueError("receipt git identity mismatch")
            for field in ("contract_hash", "plan_hash", "environment_hash"):
                _hash(item[field], field)
            _text(item["attempt_id"], "attempt_id")
            _text(item["execution_id"], "execution_id")
            tests, failures, errors = PythonOCIRunner._check_junit(junit, item["exit_code"])
            raw = dict(item)
            raw.update({
                "profile_id": PROFILE_ID,
                "image": IMAGE,
                "image_digest": IMAGE_DIGEST,
                "lock_digest": LOCK_DIGEST,
            })
            argv = tuple(item["argv"])
            identity = json.dumps(
                {
                    "source_revision": raw["source_revision"],
                    "source_tree": raw["source_tree"],
                    "contract_hash": raw["contract_hash"],
                    "plan_hash": raw["plan_hash"],
                    "environment_hash": raw["environment_hash"],
                    "profile_id": PROFILE_ID,
                    "image": IMAGE,
                    "image_digest": IMAGE_DIGEST,
                    "lock_digest": LOCK_DIGEST,
                    "network": "none",
                    "rootfs": "read-only",
                    "timeout_seconds": 300,
                    "memory_bytes": 1073741824,
                    "cpu_seconds": 60,
                    "argv": list(argv),
                    "junit": [tests, failures, errors],
                    "exit_code": item["exit_code"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            identity += DEPENDENCY_ARTIFACTS_HASH.encode()
            artifact = _digest(b"\0".join((identity, stdout, stderr, junit)))
            if artifact != item["artifact_hash"]:
                raise ValueError("artifact hash mismatch")
            outcome = _digest(
                json.dumps(
                    [
                        item["source_revision"],
                        item["source_tree"],
                        item["contract_hash"],
                        item["plan_hash"],
                        item["environment_hash"],
                        list(argv),
                        item["exit_code"],
                        PythonOCIRunner._normalized_junit(junit),
                    ],
                    separators=(",", ":"),
                ).encode()
            )
            if item.get("outcome_hash") != outcome:
                raise ValueError("outcome hash mismatch")
            attempts.append(
                ExecutionAttempt(
                    item["attempt_id"],
                    item["execution_id"],
                    item["source_revision"],
                    item["source_tree"],
                    item["contract_hash"],
                    item["plan_hash"],
                    item["environment_hash"],
                    argv,
                    stdout,
                    stderr,
                    item["exit_code"],
                    junit,
                    artifact,
                    tests,
                    failures,
                    errors,
                    outcome,
                )
            )
        if len(attempts) == 0:
            if data.get("status") != RunnerStatus.UNVERIFIABLE.value or tuple(
                data["reason_codes"]
            ) not in (("MISSING_BINDING",), ("MALFORMED_REQUEST",), ("MALFORMED_OR_UNAVAILABLE",)):
                raise ValueError("invalid zero-attempt receipt")
            if (
                data.get("profile_hash") != PythonOCIProfile().hash
                or data.get("attempt_ids") != []
                or data.get("artifact_hashes") != []
            ):
                raise ValueError("invalid zero-attempt summary")
            return cls(
                RunnerStatus.UNVERIFIABLE,
                tuple(data["reason_codes"]),
                data["profile_hash"],
                (),
                (),
                (),
            )
        if len(attempts) != 2:
            raise ValueError("receipt requires two distinct executions")
        duplicate = attempts[0].execution_id == attempts[1].execution_id
        status = (
            RunnerStatus.VERIFIED
            if attempts[0].exit_code == 0
            and attempts[0].junit_failures + attempts[0].junit_errors == 0
            else RunnerStatus.FAILED_VERIFICATION
            if attempts[0].exit_code == 1
            and attempts[0].junit_failures + attempts[0].junit_errors > 0
            else RunnerStatus.UNVERIFIABLE
        )
        same = PythonOCIRunner._same_outcome(attempts[0], attempts[1])
        if not same:
            status, reasons = (
                (RunnerStatus.UNVERIFIABLE, ("DUPLICATE_EXECUTION_ID",))
                if duplicate
                else (RunnerStatus.UNVERIFIABLE, ("NONDETERMINISTIC",))
            )
        elif duplicate:
            status, reasons = RunnerStatus.UNVERIFIABLE, ("DUPLICATE_EXECUTION_ID",)
        else:
            reasons = (
                ()
                if status is RunnerStatus.VERIFIED
                else ("TEST_FAILURE",)
                if status is RunnerStatus.FAILED_VERIFICATION
                else ("UNKNOWN_EXECUTION_OUTCOME",)
            )
        if tuple(data["reason_codes"]) != reasons or data["status"] != status.value:
            raise ValueError("receipt status/reasons mismatch")
        result = cls(
            status,
            reasons,
            data["profile_hash"],
            tuple(data["attempt_ids"]),
            tuple(data["artifact_hashes"]),
            tuple(attempts),
        )
        if (
            result.profile_hash != PythonOCIProfile().hash
            or result.attempt_ids != tuple(a.attempt_id for a in attempts)
            or result.artifact_hashes != tuple(a.artifact_hash for a in attempts)
        ):
            raise ValueError("receipt summary mismatch")
        return result


class PythonOCIRunner:
    """Validate two fresh injected OCI executions and protect exact replay."""

    def __init__(self, profile: Optional[PythonOCIProfile] = None):
        if profile is None:
            root = Path(__file__).parents[2]
            profile = PythonOCIProfile.load(
                root / "product/execution/profiles/python-oci-pytest-v1.json",
                root / "product/execution/profiles/python-oci-pytest-v1.lock",
                root / "uv.lock",
            )
        self.profile = profile
        self._replay: dict[str, RunnerResult] = {}

    def run(
        self, request: Mapping[str, object], executor: Callable[..., Mapping[str, object]]
    ) -> RunnerResult:
        required = (
            "source_revision",
            "source_tree",
            "contract_hash",
            "plan_hash",
            "environment_hash",
            "attempt_id",
        )
        if any(key not in request for key in required):
            return self._unknown(("MISSING_BINDING",))
        try:
            for key in required:
                if type(request[key]) is not str:
                    raise ValueError(f"{key} must be string")
                _text(request[key], key)
            for key in ("source_revision", "source_tree"):
                if len(request[key]) != 40 or any(
                    c not in "0123456789abcdef" for c in request[key]
                ):
                    raise ValueError(f"{key} must be lowercase git identity")
            for key in ("contract_hash", "plan_hash", "environment_hash"):
                _hash(request[key], key)
            key = self._request_key(request)
        except (TypeError, ValueError):
            return self._unknown(("MALFORMED_REQUEST",))
        if key in self._replay:
            return self._replay[key]
        attempts = []
        for index in (1, 2):
            try:
                raw = executor(self.profile, request, index)
                attempt = self._attempt(raw, request, index)
            except (
                TypeError,
                ValueError,
                KeyError,
                ET.ParseError,
                TimeoutError,
                OSError,
                RuntimeError,
            ):
                result = self._unknown(("MALFORMED_OR_UNAVAILABLE",))
                self._replay[key] = result
                return result
            attempts.append(attempt)
        if attempts[0].execution_id == attempts[1].execution_id:
            result = self._result(RunnerStatus.UNVERIFIABLE, ("DUPLICATE_EXECUTION_ID",), attempts)
        elif not self._same_outcome(attempts[0], attempts[1]):
            result = self._result(RunnerStatus.UNVERIFIABLE, ("NONDETERMINISTIC",), attempts)
        elif attempts[0].exit_code == 0:
            result = self._result(RunnerStatus.VERIFIED, (), attempts)
        elif (
            attempts[0].exit_code == 1 and attempts[0].junit_failures + attempts[0].junit_errors > 0
        ):
            result = self._result(RunnerStatus.FAILED_VERIFICATION, ("TEST_FAILURE",), attempts)
        else:
            result = self._result(
                RunnerStatus.UNVERIFIABLE, ("UNKNOWN_EXECUTION_OUTCOME",), attempts
            )
        self._replay[key] = result
        return result

    def _attempt(
        self, raw: Mapping[str, object], request: Mapping[str, object], index: int
    ) -> ExecutionAttempt:
        observed = (
            "source_revision",
            "source_tree",
            "contract_hash",
            "plan_hash",
            "environment_hash",
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
            "execution_id",
        )
        if any(key not in raw for key in observed):
            raise ValueError("missing observed execution identity")
        expected = {
            "source_revision": request["source_revision"],
            "source_tree": request["source_tree"],
            "contract_hash": request["contract_hash"],
            "plan_hash": request["plan_hash"],
            "environment_hash": request["environment_hash"],
            "profile_id": self.profile.profile_id,
            "image": self.profile.image,
            "image_digest": self.profile.image_digest,
            "lock_digest": self.profile.lock_digest,
            "dependency_artifacts_hash": self.profile.dependency_artifacts_hash,
            "network": self.profile.network,
            "rootfs": self.profile.rootfs,
            "timeout_seconds": self.profile.timeout_seconds,
            "memory_bytes": self.profile.memory_bytes,
            "cpu_seconds": self.profile.cpu_seconds,
        }
        if any(raw[key] != value for key, value in expected.items()):
            raise ValueError("observed execution identity mismatch")
        execution_id = raw["execution_id"]
        _text(execution_id, "execution_id")
        stdout = raw.get("stdout", b"")
        stderr = raw.get("stderr", b"")
        junit = raw.get("junit", b"")
        if not all(isinstance(value, bytes) for value in (stdout, stderr, junit)):
            raise ValueError("execution streams must be bytes")
        if any(len(value) > MAX_OUTPUT_BYTES for value in (stdout, stderr, junit)):
            raise ValueError("execution evidence exceeds size limit")
        argv = tuple(raw.get("argv", self.profile.command))
        if argv != self.profile.command:
            raise ValueError("unexpected argv")
        exit_code = raw.get("exit_code")
        if type(exit_code) is not int:
            raise ValueError("missing exit code")
        junit_tests, junit_failures, junit_errors = self._check_junit(junit, exit_code)
        attempt_id = str(request["attempt_id"]) + f"-{index}"
        # Physical execution_id proves freshness and is recorded separately;
        # content identity intentionally excludes it so two fresh identical
        # executions can converge on one artifact hash.
        identity = json.dumps(
            {
                "source_revision": raw["source_revision"],
                "source_tree": raw["source_tree"],
                "contract_hash": raw["contract_hash"],
                "plan_hash": raw["plan_hash"],
                "environment_hash": raw["environment_hash"],
                "profile_id": raw["profile_id"],
                "image": raw["image"],
                "image_digest": raw["image_digest"],
                "lock_digest": raw["lock_digest"],
                "network": raw["network"],
                "rootfs": raw["rootfs"],
                "timeout_seconds": raw["timeout_seconds"],
                "memory_bytes": raw["memory_bytes"],
                "cpu_seconds": raw["cpu_seconds"],
                "argv": list(argv),
                "junit": [junit_tests, junit_failures, junit_errors],
                "exit_code": exit_code,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        identity += self.profile.dependency_artifacts_hash.encode()
        artifact = _digest(b"\0".join((identity, stdout, stderr, junit)))
        attempt = ExecutionAttempt(
            attempt_id,
            execution_id,
            str(raw["source_revision"]),
            str(raw["source_tree"]),
            str(raw["contract_hash"]),
            str(raw["plan_hash"]),
            str(raw["environment_hash"]),
            argv,
            stdout,
            stderr,
            exit_code,
            junit,
            artifact,
        )
        outcome = _digest(
            json.dumps(
                [
                    attempt.source_revision,
                    attempt.source_tree,
                    attempt.contract_hash,
                    attempt.plan_hash,
                    attempt.environment_hash,
                    list(attempt.argv),
                    attempt.exit_code,
                    self._normalized_junit(junit),
                ],
                separators=(",", ":"),
            ).encode()
        )
        return ExecutionAttempt(
            attempt.attempt_id,
            attempt.execution_id,
            attempt.source_revision,
            attempt.source_tree,
            attempt.contract_hash,
            attempt.plan_hash,
            attempt.environment_hash,
            attempt.argv,
            attempt.stdout,
            attempt.stderr,
            attempt.exit_code,
            attempt.junit,
            attempt.artifact_hash,
            junit_tests,
            junit_failures,
            junit_errors,
            outcome,
        )

    @staticmethod
    def _check_junit(data: bytes, exit_code: int) -> tuple[int, int, int]:
        if not data:
            raise ValueError("missing junit oracle")
        if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
            raise ValueError("DTD/entity input forbidden")
        root = ET.fromstring(data)
        suites = list(root) if root.tag == "testsuites" else [root]
        try:
            tests = sum(int(s.attrib.get("tests", "0")) for s in suites)
            failures = sum(int(s.attrib.get("failures", "0")) for s in suites)
            errors = sum(int(s.attrib.get("errors", "0")) for s in suites)
        except (TypeError, ValueError):
            raise ValueError("malformed junit counts")
        if (
            tests <= 0
            or failures < 0
            or errors < 0
            or failures + errors > tests
            or (exit_code == 0 and failures + errors)
        ):
            raise ValueError("inadequate junit oracle")
        return tests, failures, errors

    @staticmethod
    def _same_outcome(a, b):
        return a.outcome_hash == b.outcome_hash

    @staticmethod
    def _normalized_junit(data):
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

    def _request_key(self, request: Mapping[str, object]) -> str:
        body = {
            key: str(request[key])
            for key in (
                "source_revision",
                "source_tree",
                "contract_hash",
                "plan_hash",
                "environment_hash",
                "attempt_id",
            )
        }
        return _digest(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())

    def _unknown(self, reasons: tuple[str, ...]) -> RunnerResult:
        return RunnerResult(
            RunnerStatus.UNVERIFIABLE, tuple(sorted(reasons)), self.profile.hash, (), (), ()
        )

    def _result(self, status, reasons, attempts):
        return RunnerResult(
            status,
            tuple(sorted(reasons)),
            self.profile.hash,
            tuple(a.attempt_id for a in attempts),
            tuple(a.artifact_hash for a in attempts),
            tuple(attempts),
        )
