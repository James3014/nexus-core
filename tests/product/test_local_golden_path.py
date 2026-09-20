from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from product.adapters.generic_verification import verify_generic_changeset
from product.clients.cli import build_parser
from product.clients.local_golden_path import (
    LocalCheckError,
    check_repository,
    doctor_repository,
    init_repository,
    validate_verification_receipt,
)
from product.protocol.generic_verification import (
    acceptance_contract_hash,
    canonical_hash,
    evidence_bundle_hash,
    verification_plan_hash,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


@pytest.fixture
def external_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "external"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "external@example.test")
    _git(repo, "config", "user.name", "External User")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_value():\n    assert VALUE > 0\n", encoding="utf-8"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    return repo


def _init(
    repo: Path,
    *,
    patterns: tuple[str, ...] = ("*.py",),
    deletion: str = "FORBID",
    force: bool = False,
):
    return init_repository(
        repo,
        base_ref="main",
        allowed_patterns=patterns,
        deletion_policy=deletion,
        verifier_command=(sys.executable, "-m", "pytest", "-q"),
        force=force,
    )


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    receipt["receipt_hash"] = canonical_hash(
        {key: value for key, value in receipt.items() if key != "receipt_hash"}
    )
    path.write_text(json.dumps(receipt), encoding="utf-8")


def _recompute_request_and_result(receipt: dict[str, Any]) -> None:
    request = receipt["inputs"]["request"]
    contract_hash = acceptance_contract_hash(request["acceptance_contract"])
    request["verification_plan"]["acceptance_contract_hash"] = contract_hash
    request["evidence_bundle"]["acceptance_contract_hash"] = contract_hash
    request["evidence_bundle"]["verification_plan_hash"] = verification_plan_hash(
        request["verification_plan"]
    )
    request["evidence_bundle"]["claimed_bundle_hash"] = evidence_bundle_hash(
        request["evidence_bundle"]
    )
    status, response = verify_generic_changeset(request)
    assert status == 200
    receipt["core_response"] = response
    receipt["outcome"]["status"] = response["verification"]["status"]
    receipt["outcome"]["reason_codes"] = response["verification"]["reason_codes"]


def test_init_creates_minimal_config_and_refuses_overwrite(external_repo: Path):
    config_path = _init(external_repo)
    text = config_path.read_text(encoding="utf-8")
    assert "version = 1" in text
    assert 'base_ref = "main"' in text
    assert "executor" not in text.lower()

    with pytest.raises(LocalCheckError, match="CONFIG_EXISTS"):
        _init(external_repo)

    assert _init(external_repo, patterns=("src/**",), force=True) == config_path


def test_init_cli_preserves_verifier_argv_flags():
    args = build_parser().parse_args(
        ["init", "--base-ref", "main", "--verifier", "python", "-m", "pytest", "-q"]
    )
    assert args.verifier == ["python", "-m", "pytest", "-q"]


def test_doctor_is_read_only_and_reports_success_and_failure(external_repo: Path):
    before = _git(external_repo, "status", "--porcelain=v1", "--untracked-files=all")
    failed = doctor_repository(external_repo)
    assert failed["healthy"] is False
    assert "CONFIG_MISSING" in failed["reason_codes"]
    assert _git(external_repo, "status", "--porcelain=v1", "--untracked-files=all") == before

    _init(external_repo)
    healthy = doctor_repository(external_repo)
    assert healthy["healthy"] is True
    assert healthy["checks"]["git"] == "OK"
    assert healthy["checks"]["base_ref"] == "OK"
    assert healthy["checks"]["verifier"] == "OK"

    config = external_repo / ".nexus-core" / "config.toml"
    config.write_text(config.read_text().replace('base_ref = "main"', 'base_ref = "missing"'))
    unresolved = doctor_repository(external_repo)
    assert unresolved["healthy"] is False
    assert "BASE_REF_UNRESOLVED" in unresolved["reason_codes"]


def test_doctor_and_check_reject_base_ref_outside_head_ancestry(external_repo: Path):
    unrelated = _git(external_repo, "commit-tree", "HEAD^{tree}", "-m", "unrelated root")
    _git(external_repo, "update-ref", "refs/heads/unrelated", unrelated)
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    init_repository(
        external_repo,
        base_ref="unrelated",
        allowed_patterns=("*.py",),
        verifier_command=(sys.executable, "-m", "pytest", "-q"),
    )

    diagnosis = doctor_repository(external_repo)
    assert diagnosis["healthy"] is False
    assert diagnosis["checks"]["base_ref"] == "ERROR"
    assert "BASE_REF_NOT_ANCESTOR" in diagnosis["reason_codes"]

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)
    assert raised.value.reason_code == "BASE_REF_NOT_ANCESTOR"
    assert raised.value.receipt_path is not None


def test_committed_external_repo_check_is_verified_and_replayable(external_repo: Path):
    _git(external_repo, "checkout", "-b", "feature")
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(external_repo, "add", "app.py")
    _git(external_repo, "commit", "-m", "change")
    _init(external_repo)

    result = check_repository(external_repo)

    assert result["status"] == "VERIFIED"
    assert result["certification"] is None
    assert result["receipt_path"].is_file()
    receipt = json.loads(result["receipt_path"].read_text(encoding="utf-8"))
    assert receipt["kind"] == "NEXUS_CORE_LOCAL_VERIFICATION_RECEIPT"
    assert receipt["core_response"]["verification"]["status"] == "VERIFIED"
    assert receipt["core_response"]["certification"] is None
    assert "executor" not in json.dumps(receipt["inputs"]["request"]).lower()
    validation = validate_verification_receipt(result["receipt_path"], repo=external_repo)
    assert validation == {"valid": True, "reason_codes": []}


def test_dirty_check_preserves_head_index_and_worktree(external_repo: Path):
    _init(external_repo)
    (external_repo / "app.py").write_text("VALUE = 3\n", encoding="utf-8")
    (external_repo / "new.py").write_text("NEW = True\n", encoding="utf-8")
    head_before = _git(external_repo, "rev-parse", "HEAD")
    index_before = (external_repo / ".git" / "index").read_bytes()
    app_before = (external_repo / "app.py").read_bytes()

    result = check_repository(external_repo)

    assert result["status"] == "VERIFIED"
    assert _git(external_repo, "rev-parse", "HEAD") == head_before
    assert (external_repo / ".git" / "index").read_bytes() == index_before
    assert (external_repo / "app.py").read_bytes() == app_before
    assert (external_repo / "new.py").read_text(encoding="utf-8") == "NEW = True\n"


def test_verifier_fail_is_failed_verification_not_transport_error(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = -1\n", encoding="utf-8")
    _init(external_repo)

    result = check_repository(external_repo)

    assert result["status"] == "FAILED_VERIFICATION"
    assert "VERIFIER_FAILED" in result["reason_codes"]
    assert "local-command" in result["reason_codes"]
    assert result["transport_error"] is False


def test_verifier_unavailable_fails_closed_with_typed_reason(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    init_repository(
        external_repo,
        allowed_patterns=("*.py",),
        verifier_command=("nexus-core-verifier-that-does-not-exist",),
    )

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "VERIFIER_UNAVAILABLE"
    assert raised.value.receipt_path is not None


def test_verifier_timeout_fails_closed_with_typed_reason(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    init_repository(
        external_repo,
        allowed_patterns=("*.py",),
        verifier_command=(sys.executable, "-c", "import time; time.sleep(5)"),
        timeout_seconds=1,
    )

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "VERIFIER_TIMEOUT"
    assert raised.value.receipt_path is not None


@pytest.mark.parametrize(
    ("patterns", "delete", "reason"),
    [
        (("src/**",), False, "FORBIDDEN_PATH"),
        (("*.py",), True, "FORBIDDEN_DELETION"),
    ],
)
def test_policy_projection_fails_closed_with_typed_reason(
    external_repo: Path, patterns: tuple[str, ...], delete: bool, reason: str
):
    if delete:
        (external_repo / "app.py").unlink()
    else:
        (external_repo / "app.py").write_text("VALUE = 4\n", encoding="utf-8")
    _init(external_repo, patterns=patterns)

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == reason
    assert raised.value.receipt_path is not None


def test_check_fails_closed_when_there_are_no_changes(external_repo: Path):
    _init(external_repo)
    with pytest.raises(LocalCheckError, match="NO_CHANGES"):
        check_repository(external_repo)


def test_receipt_rejects_tampered_manifest_and_result(external_repo: Path, tmp_path: Path):
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    _init(external_repo)
    result = check_repository(external_repo)
    original = json.loads(result["receipt_path"].read_text(encoding="utf-8"))

    manifest_tamper = json.loads(json.dumps(original))
    manifest_tamper["inputs"]["request"]["change_manifest"]["entries"][0]["after_oid"] = "f" * 40
    manifest_path = tmp_path / "manifest-tamper.json"
    manifest_path.write_text(json.dumps(manifest_tamper), encoding="utf-8")
    manifest_validation = validate_verification_receipt(manifest_path, repo=external_repo)
    assert manifest_validation["valid"] is False
    assert "RECEIPT_HASH_MISMATCH" in manifest_validation["reason_codes"]
    assert "GIT_MANIFEST_MISMATCH" in manifest_validation["reason_codes"]

    result_tamper = json.loads(json.dumps(original))
    result_tamper["core_response"]["verification"]["status"] = "FAILED_VERIFICATION"
    result_path = tmp_path / "result-tamper.json"
    result_path.write_text(json.dumps(result_tamper), encoding="utf-8")
    result_validation = validate_verification_receipt(result_path, repo=external_repo)
    assert result_validation["valid"] is False
    assert "CORE_RESPONSE_MISMATCH" in result_validation["reason_codes"]


@pytest.fixture
def valid_receipt(external_repo: Path) -> dict[str, Any]:
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    _init(external_repo)
    result = check_repository(external_repo)
    return json.loads(result["receipt_path"].read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_revision", "git-commit:" + "a" * 40),
        ("source_tree", "git-tree:" + "b" * 40),
        ("target_revision", "git-tree:" + "c" * 40),
        ("target_tree", "git-tree:" + "d" * 40),
    ],
)
def test_receipt_rejects_rehashed_source_target_duplicate_tamper(
    valid_receipt: dict[str, Any], tmp_path: Path, field: str, value: str
):
    valid_receipt[field] = value
    path = tmp_path / f"tampered-{field}.json"
    _write_receipt(path, valid_receipt)

    validation = validate_verification_receipt(path)

    assert validation["valid"] is False
    assert "RECEIPT_BINDING_MISMATCH" in validation["reason_codes"]
    assert "RECEIPT_HASH_MISMATCH" not in validation["reason_codes"]


def test_receipt_rejects_rehashed_outcome_tamper(
    valid_receipt: dict[str, Any], tmp_path: Path
):
    valid_receipt["outcome"] = {
        "status": "FAILED_VERIFICATION",
        "reason_codes": ["REWRITTEN"],
        "transport_error": False,
    }
    path = tmp_path / "tampered-outcome.json"
    _write_receipt(path, valid_receipt)

    validation = validate_verification_receipt(path)

    assert validation["valid"] is False
    assert "OUTCOME_MISMATCH" in validation["reason_codes"]
    assert "RECEIPT_HASH_MISMATCH" not in validation["reason_codes"]


def test_receipt_rejects_rehashed_verifier_status_tamper(
    valid_receipt: dict[str, Any], tmp_path: Path
):
    verifier = valid_receipt["verifier"]
    assert isinstance(verifier, dict)
    verifier["status"] = "FAIL"
    verifier["artifact_hash"] = canonical_hash(
        {key: value for key, value in verifier.items() if key != "artifact_hash"}
    )
    request = valid_receipt["inputs"]["request"]
    request["evidence_bundle"]["observations"][0]["artifact_hash"] = verifier["artifact_hash"]
    request["evidence_bundle"]["observations"][0]["status"] = "FAIL"
    _recompute_request_and_result(valid_receipt)
    path = tmp_path / "tampered-verifier-status.json"
    _write_receipt(path, valid_receipt)

    validation = validate_verification_receipt(path)

    assert validation["valid"] is False
    assert "VERIFIER_STATUS_MISMATCH" in validation["reason_codes"]
    assert "RECEIPT_HASH_MISMATCH" not in validation["reason_codes"]


def test_receipt_rejects_rehashed_requirements_config_tamper(
    valid_receipt: dict[str, Any], tmp_path: Path
):
    request = valid_receipt["inputs"]["request"]
    request["acceptance_contract"]["requirements_hash"] = canonical_hash({"rewritten": True})
    _recompute_request_and_result(valid_receipt)
    path = tmp_path / "tampered-requirements.json"
    _write_receipt(path, valid_receipt)

    validation = validate_verification_receipt(path)

    assert validation["valid"] is False
    assert "CONFIG_BINDING_MISMATCH" in validation["reason_codes"]
    assert "RECEIPT_HASH_MISMATCH" not in validation["reason_codes"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "REWRITTEN_RECEIPT"),
        ("schema_version", 2),
        ("product", {"name": "rewritten-product", "version": "1.0"}),
        ("product", {"name": "nexus-core", "version": ""}),
    ],
)
def test_receipt_rejects_rehashed_structural_identity_tamper(
    valid_receipt: dict[str, Any], tmp_path: Path, field: str, value: Any
):
    valid_receipt[field] = value
    path = tmp_path / "tampered-identity.json"
    _write_receipt(path, valid_receipt)

    validation = validate_verification_receipt(path)

    assert validation["valid"] is False
    assert "UNSUPPORTED_RECEIPT" in validation["reason_codes"]
    assert "RECEIPT_HASH_MISMATCH" not in validation["reason_codes"]


def test_check_detects_target_changed_by_verifier(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 6\n", encoding="utf-8")
    script = external_repo / "mutate.py"
    script.write_text("from pathlib import Path\nPath('app.py').write_text('VALUE = 7\\n')\n", encoding="utf-8")
    init_repository(
        external_repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        deletion_policy="FORBID",
        verifier_command=(sys.executable, "mutate.py"),
    )

    with pytest.raises(LocalCheckError, match="GIT_MANIFEST_MISMATCH"):
        check_repository(external_repo)
