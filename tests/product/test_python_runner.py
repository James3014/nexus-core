import json
from pathlib import Path

import pytest

from product.execution.python_runner import (
    PythonOCIProfile,
    PythonOCIRunner,
    RunnerResult,
    RunnerStatus,
)


def request():
    return {
        "source_revision": "a" * 40,
        "source_tree": "b" * 40,
        "contract_hash": "sha256:" + "a" * 64,
        "plan_hash": "sha256:" + "b" * 64,
        "environment_hash": "sha256:" + "c" * 64,
        "attempt_id": "attempt-a",
    }


def executor(profile, request, index):
    return {
        "source_revision": request["source_revision"],
        "source_tree": request["source_tree"],
        "contract_hash": request["contract_hash"],
        "plan_hash": request["plan_hash"],
        "environment_hash": request["environment_hash"],
        "profile_id": profile.profile_id,
        "image": profile.image,
        "image_digest": profile.image_digest,
        "lock_digest": profile.lock_digest,
        "dependency_artifacts_hash": profile.dependency_artifacts_hash,
        "network": profile.network,
        "rootfs": profile.rootfs,
        "timeout_seconds": profile.timeout_seconds,
        "memory_bytes": profile.memory_bytes,
        "cpu_seconds": profile.cpu_seconds,
        "execution_id": f"exec-{index}",
        "argv": profile.command,
        "stdout": b"ok",
        "stderr": b"",
        "exit_code": 0,
        "junit": b'<testsuite tests="1" failures="0" errors="0" />',
    }


def test_two_fresh_runs_bind_profile_and_artifacts():
    result = PythonOCIRunner().run(request(), executor)
    assert result.status is RunnerStatus.VERIFIED
    assert len(result.attempts) == 2
    assert result.artifact_hashes[0] == result.artifact_hashes[1]


def test_failure_and_inadequate_oracle_are_fail_closed():
    def failed(profile, request, index):
        result = executor(profile, request, index)
        return {
            **result,
            "stdout": b"fail",
            "exit_code": 1,
            "junit": b'<testsuite tests="1" failures="1" errors="0" />',
        }

    assert PythonOCIRunner().run(request(), failed).status is RunnerStatus.FAILED_VERIFICATION
    assert PythonOCIRunner().run(request(), lambda *_: {}).status is RunnerStatus.UNVERIFIABLE


def test_nondeterminism_and_exact_replay_are_safe():
    def varying(profile, request, index):
        result = executor(profile, request, index)
        return {
            **result,
            "junit": f'<testsuite tests="1" failures="0" errors="0"><testcase name="case-{index}" /></testsuite>'.encode(),
        }

    runner = PythonOCIRunner()
    result = runner.run(request(), varying)
    assert result.status is RunnerStatus.UNVERIFIABLE
    called = []
    replay = runner.run(request(), lambda *_: called.append(1))
    assert replay == result and not called


def test_profile_file_and_shell_free_contract():
    data = json.loads(
        (
            Path(__file__).parents[2] / "product/execution/profiles/python-oci-pytest-v1.json"
        ).read_text()
    )
    assert data["network"] == "none" and data["rootfs"] == "read-only"
    assert "sh" not in data["command"]


@pytest.mark.parametrize(
    "field",
    [
        "source_revision",
        "source_tree",
        "environment_hash",
        "profile_id",
        "image",
        "image_digest",
        "lock_digest",
        "argv",
    ],
)
def test_wrong_observed_binding_is_unverifiable(field):
    def hostile(profile, req, index):
        value = executor(profile, req, index)
        value[field] = (profile.command + ("wrong",)) if field == "argv" else "wrong"
        return value

    assert PythonOCIRunner().run(request(), hostile).status is RunnerStatus.UNVERIFIABLE


@pytest.mark.parametrize("exit_code", [2, 3, 4, 5])
def test_pytest_non_test_exit_codes_are_unknown(exit_code):
    def unavailable(profile, req, index):
        return {**executor(profile, req, index), "exit_code": exit_code}

    assert PythonOCIRunner().run(request(), unavailable).status is RunnerStatus.UNVERIFIABLE


def test_duplicate_physical_execution_id_and_exit_mismatch_are_unknown():
    def duplicate(profile, req, index):
        return {**executor(profile, req, index), "execution_id": "same"}

    assert "DUPLICATE_EXECUTION_ID" in PythonOCIRunner().run(request(), duplicate).reason_codes

    def mismatch(profile, req, index):
        return {
            **executor(profile, req, index),
            "exit_code": 0,
            "junit": b'<testsuite tests="1" failures="1" errors="0" />',
        }

    assert PythonOCIRunner().run(request(), mismatch).status is RunnerStatus.UNVERIFIABLE


def test_manifest_lock_reload_binds_actual_uv_lock():
    root = Path(__file__).parents[2]
    profile = PythonOCIProfile.load(
        root / "product/execution/profiles/python-oci-pytest-v1.json",
        root / "product/execution/profiles/python-oci-pytest-v1.lock",
        root / "uv.lock",
    )
    assert profile.profile_id == "python-oci-pytest-v1"


@pytest.mark.parametrize("mutation", ["missing", "extra", "reordered", "wrong-hash"])
def test_dependency_artifact_lock_attacks_are_rejected(tmp_path, mutation):
    root = Path(__file__).parents[2]
    lock = json.loads((root / "product/execution/profiles/python-oci-pytest-v1.lock").read_text())
    if mutation == "missing":
        lock["dependency_artifacts"] = lock["dependency_artifacts"][1:]
    if mutation == "extra":
        lock["dependency_artifacts"].append(["x.whl", "https://x", "0" * 64])
    if mutation == "reordered":
        lock["dependency_artifacts"].reverse()
    if mutation == "wrong-hash":
        lock["dependency_artifacts"][0][2] = "0" * 64
    lock_path = tmp_path / "lock.json"
    lock_path.write_text(json.dumps(lock))
    with pytest.raises(ValueError):
        PythonOCIProfile.load(
            root / "product/execution/profiles/python-oci-pytest-v1.json",
            lock_path,
            root / "uv.lock",
        )


def test_receipt_reload_recomputes_and_rejects_tamper():
    result = PythonOCIRunner().run(request(), executor)
    assert RunnerResult.from_dict(result.to_dict()) == result
    tampered = result.to_dict()
    tampered["attempts"][0]["stdout"] = "00"
    with pytest.raises(ValueError):
        RunnerResult.from_dict(tampered)


@pytest.mark.parametrize("request_value", [None, {"source_revision": 1}])
def test_fail_closed_zero_attempt_receipts_round_trip(request_value):
    result = PythonOCIRunner().run(request_value or {}, executor)
    assert result.status is RunnerStatus.UNVERIFIABLE
    assert RunnerResult.from_dict(result.to_dict()) == result


def test_tampered_receipt_summary_is_rejected():
    result = PythonOCIRunner().run(request(), executor)
    for field, value in (
        ("status", "FAILED_VERIFICATION"),
        ("reason_codes", ["TEST_FAILURE"]),
        ("profile_hash", "sha256:" + "0" * 64),
        ("attempt_ids", ["bad", "bad2"]),
    ):
        tampered = result.to_dict()
        tampered[field] = value
        with pytest.raises(ValueError):
            RunnerResult.from_dict(tampered)


def test_volatile_junit_pair_is_semantically_deterministic_and_reloadable():
    payloads = (
        b'<testsuites><testsuite timestamp="2026-01-01T00:00:00" hostname="a" time="0.01" tests="1" failures="0" errors="0"><testcase classname="T" name="ok" time="0.001" /></testsuite></testsuites>',
        b'<testsuites><testsuite timestamp="2026-02-02T00:00:00" hostname="b" time="9.99" tests="1" failures="0" errors="0"><testcase classname="T" name="ok" time="4.321" /></testsuite></testsuites>',
    )

    def volatile(profile, req, index):
        return {**executor(profile, req, index), "junit": payloads[index - 1]}

    result = PythonOCIRunner().run(request(), volatile)
    assert result.status is RunnerStatus.VERIFIED
    assert result.attempts[0].outcome_hash == result.attempts[1].outcome_hash
    assert result.artifact_hashes[0] != result.artifact_hashes[1]
    assert RunnerResult.from_dict(result.to_dict()) == result

    def changed(profile, req, index):
        value = {**executor(profile, req, index), "junit": payloads[index - 1]}
        if index == 2:
            value["junit"] = value["junit"].replace(b'name="ok"', b'name="changed"')
        return value

    assert PythonOCIRunner().run(request(), changed).status is RunnerStatus.UNVERIFIABLE


@pytest.mark.parametrize("error", [TimeoutError(), OSError(), RuntimeError()])
def test_executor_unavailability_is_fail_closed(error):
    def unavailable(*_):
        raise error

    result = PythonOCIRunner().run(request(), unavailable)
    assert result.status is RunnerStatus.UNVERIFIABLE
    assert result.reason_codes == ("MALFORMED_OR_UNAVAILABLE",)


def test_tampered_outcome_hash_is_rejected():
    result = PythonOCIRunner().run(request(), executor)
    tampered = result.to_dict()
    tampered["attempts"][0]["outcome_hash"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        RunnerResult.from_dict(tampered)


@pytest.mark.parametrize(
    "field", ["argv", "source_revision", "contract_hash", "attempt_id", "execution_id", "stdout"]
)
def test_receipt_loader_rejects_malformed_execution_fields(field):
    result = PythonOCIRunner().run(request(), executor)
    tampered = result.to_dict()
    values = {
        "argv": ["python", "-m", "pytest"],
        "source_revision": "bad",
        "contract_hash": "bad",
        "attempt_id": "",
        "execution_id": "",
        "stdout": "not-hex",
    }
    tampered["attempts"][0][field] = values[field]
    with pytest.raises((ValueError, TypeError)):
        RunnerResult.from_dict(tampered)


@pytest.mark.parametrize("exit_code", [0.0, True, "0"])
def test_receipt_loader_rejects_non_integer_exit_code(exit_code):
    result = PythonOCIRunner().run(request(), executor)
    tampered = result.to_dict()
    tampered["attempts"][0]["exit_code"] = exit_code
    with pytest.raises(ValueError):
        RunnerResult.from_dict(tampered)
