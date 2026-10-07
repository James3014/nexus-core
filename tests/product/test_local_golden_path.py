from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from product.adapters.generic_verification import verify_generic_changeset
from product.clients.cli import build_parser
from product.clients.cli import main as cli_main
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
    result = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
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


def test_receipt_check_cli_projects_canonical_validator_json(
    external_repo: Path, capsys: pytest.CaptureFixture[str]
):
    _init(external_repo)
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    result = check_repository(external_repo)

    exit_code = cli_main(
        [
            "receipt-check",
            "--receipt",
            str(result["receipt_path"]),
            "--repo",
            str(external_repo),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload == {"reason_codes": [], "valid": True}


def test_receipt_check_cli_fails_closed_on_tampered_receipt(
    external_repo: Path, capsys: pytest.CaptureFixture[str]
):
    _init(external_repo)
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    result = check_repository(external_repo)
    receipt_path = result["receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["outcome"]["status"] = "FAILED_VERIFICATION"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    exit_code = cli_main(
        [
            "receipt-check",
            "--receipt",
            str(receipt_path),
            "--repo",
            str(external_repo),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["valid"] is False
    assert "RECEIPT_HASH_MISMATCH" in payload["reason_codes"]
    assert "OUTCOME_MISMATCH" in payload["reason_codes"]


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


def test_check_fails_closed_on_ignored_out_of_scope_dist_residue(external_repo: Path):
    _init(external_repo, patterns=("*.py",))
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    (external_repo / "dist").mkdir()
    (external_repo / "dist" / ".gitignore").write_text("*\n", encoding="utf-8")
    (external_repo / "dist" / "secret.txt").write_text("secret\n", encoding="utf-8")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)
    assert raised.value.reason_code == "IGNORED_RESIDUE"
    assert "dist/secret.txt" in raised.value.detail or "dist/.gitignore" in raised.value.detail


def test_check_fails_closed_on_ordinary_ignored_build_residue(external_repo: Path):
    _init(external_repo, patterns=("*.py",))
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    (external_repo / ".gitignore").write_text("build/\n", encoding="utf-8")
    _git(external_repo, "add", ".gitignore")
    _git(external_repo, "commit", "-m", "add gitignore")
    (external_repo / "build").mkdir()
    (external_repo / "build" / "output.o").write_text("binary\n", encoding="utf-8")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)
    assert raised.value.reason_code == "IGNORED_RESIDUE"
    assert "build/output.o" in raised.value.detail


def test_check_allows_nexus_core_config_and_receipts(external_repo: Path):
    _init(external_repo, patterns=("*.py",))
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    (external_repo / ".gitignore").write_text(".nexus-core/\n", encoding="utf-8")
    _git(external_repo, "add", ".gitignore")
    _git(external_repo, "commit", "-m", "add gitignore")
    receipts_dir = external_repo / ".nexus-core" / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    (receipts_dir / "test.json").write_text("{}", encoding="utf-8")

    result = check_repository(external_repo)
    assert result["status"] == "VERIFIED"


def test_check_preserves_tracked_nexus_core_config_in_target_tree(external_repo: Path):
    config = _init(external_repo, patterns=("*.py",))
    _git(external_repo, "add", str(config.relative_to(external_repo)))
    _git(external_repo, "commit", "-m", "track nexus core config")
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")

    result = check_repository(external_repo)

    assert result["status"] == "VERIFIED"
    assert config.read_text(encoding="utf-8").startswith("version = 1\n")


def test_check_fails_closed_on_ignored_file_under_allowed_pattern(external_repo: Path):
    _init(external_repo, patterns=("*.py",))
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    (external_repo / ".gitignore").write_text("app_ignored.py\n", encoding="utf-8")
    _git(external_repo, "add", ".gitignore")
    _git(external_repo, "commit", "-m", "add gitignore")
    (external_repo / "app_ignored.py").write_text("VALUE = 0\n", encoding="utf-8")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)
    assert raised.value.reason_code == "IGNORED_RESIDUE"
    assert "app_ignored.py" in raised.value.detail


def test_ignored_residue_rejection_preserves_worktree_state(external_repo: Path):
    _init(external_repo, patterns=("*.py",))
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    (external_repo / "staged.py").write_text("VALUE = 5\n", encoding="utf-8")
    _git(external_repo, "add", "staged.py")
    (external_repo / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    _git(external_repo, "add", ".gitignore")
    _git(external_repo, "commit", "-m", "add gitignore")

    head_before = _git(external_repo, "rev-parse", "HEAD")
    status_before = _git(external_repo, "status", "--porcelain")

    (external_repo / "ignored.py").write_text("ignored\n", encoding="utf-8")

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)
    assert raised.value.reason_code == "IGNORED_RESIDUE"

    head_after = _git(external_repo, "rev-parse", "HEAD")
    status_after = _git(external_repo, "status", "--porcelain")

    assert head_after == head_before
    assert status_after == status_before


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


def test_receipt_rejects_rehashed_outcome_tamper(valid_receipt: dict[str, Any], tmp_path: Path):
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
    script.write_text(
        "from pathlib import Path\nPath('app.py').write_text('VALUE = 7\\n')\n", encoding="utf-8"
    )
    init_repository(
        external_repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        deletion_policy="FORBID",
        verifier_command=(sys.executable, "mutate.py"),
    )

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "VERIFIER_SUBJECT_MUTATED"


def test_check_allows_verifier_created_ignored_residue_in_isolated_subject(
    external_repo: Path,
):
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    script = external_repo / "mutate.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('dist').mkdir(exist_ok=True)\n"
        "Path('dist/.gitignore').write_text('*\\n')\n",
        encoding="utf-8",
    )
    init_repository(
        external_repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        deletion_policy="FORBID",
        verifier_command=(sys.executable, "mutate.py"),
    )

    result = check_repository(external_repo)

    assert result["status"] == "VERIFIED"
    assert not (external_repo / "dist").exists()
    receipt = json.loads(result["receipt_path"].read_text(encoding="utf-8"))
    assert receipt["verifier"]["execution_subject"]["mode"] == "isolated_shared_clone"
    assert receipt["verifier"]["execution_subject"]["target_tree"] == receipt["target_tree"]


def test_check_fails_closed_when_verifier_escapes_and_creates_ignored_residue(
    external_repo: Path,
):
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    escaped = external_repo / "dist" / ".gitignore"
    script = external_repo / "mutate.py"
    script.write_text(
        "from pathlib import Path\n"
        f"target = Path({str(escaped)!r})\n"
        "target.parent.mkdir(exist_ok=True)\n"
        "target.write_text('*\\n')\n",
        encoding="utf-8",
    )
    init_repository(
        external_repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        deletion_policy="FORBID",
        verifier_command=(sys.executable, "mutate.py"),
    )

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "IGNORED_RESIDUE"
    assert "dist/.gitignore" in raised.value.detail
    assert raised.value.receipt_path is not None
    receipt = json.loads(raised.value.receipt_path.read_text(encoding="utf-8"))
    assert receipt["verifier"] is not None
    assert receipt["verifier"]["status"] == "PASS"


def test_check_fails_closed_on_verifier_sandbox_cleanup_failure(
    external_repo: Path, monkeypatch: pytest.MonkeyPatch
):
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    _init(external_repo)

    def fail_cleanup(*args: Any, **kwargs: Any) -> None:
        raise OSError("cleanup blocked")

    monkeypatch.setattr(
        "product.clients.local_golden_path._cleanup_verifier_sandbox",
        fail_cleanup,
    )

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "VERIFIER_SANDBOX_CLEANUP_FAILED"


def test_check_allows_verifier_created_nexus_core_receipts(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")
    (external_repo / ".gitignore").write_text(".nexus-core/\n", encoding="utf-8")
    _git(external_repo, "add", ".gitignore")
    _git(external_repo, "commit", "-m", "add gitignore")

    script = external_repo / "mutate.py"
    script.write_text(
        "from pathlib import Path\n"
        "receipts = Path('.nexus-core/receipts')\n"
        "receipts.mkdir(parents=True, exist_ok=True)\n"
        "(receipts / 'test.json').write_text('{}')\n",
        encoding="utf-8",
    )
    init_repository(
        external_repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        deletion_policy="FORBID",
        verifier_command=(sys.executable, "mutate.py"),
    )

    result = check_repository(external_repo)
    assert result["status"] == "VERIFIED"


def test_tracked_config_unchanged_does_not_fail_forbidden_deletion(external_repo: Path):
    init_repository(
        external_repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        deletion_policy="FORBID",
    )
    _git(external_repo, "add", ".nexus-core/config.toml")
    _git(external_repo, "commit", "-m", "track config")

    base_tree = _git(external_repo, "rev-parse", "HEAD^{tree}")
    config_blob_base = _git(external_repo, "ls-tree", "HEAD", ".nexus-core/config.toml")

    (external_repo / "app.py").write_text("VALUE = 5\n", encoding="utf-8")

    result = check_repository(external_repo)
    assert result["status"] == "VERIFIED"
    assert "FORBIDDEN_DELETION" not in result["reason_codes"]

    receipt = json.loads(Path(result["receipt_path"]).read_text(encoding="utf-8"))
    source_tree = receipt["source_tree"].removeprefix("git-tree:")
    target_tree = receipt["target_tree"].removeprefix("git-tree:")

    assert source_tree == base_tree
    config_blob_target = _git(external_repo, "ls-tree", target_tree, ".nexus-core/config.toml")
    assert config_blob_target == config_blob_base

    validation = validate_verification_receipt(result["receipt_path"], repo=external_repo)
    assert validation["valid"] is True


def test_tracked_config_clean_repo_fails_with_no_changes_not_forbidden_deletion(
    external_repo: Path,
):
    init_repository(
        external_repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        deletion_policy="FORBID",
    )
    _git(external_repo, "add", ".nexus-core/config.toml")
    _git(external_repo, "commit", "-m", "track config")

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "NO_CHANGES"
    assert "FORBIDDEN_DELETION" != raised.value.reason_code

    receipt = json.loads(Path(raised.value.receipt_path).read_text(encoding="utf-8"))
    assert receipt["outcome"]["status"] == "FAILED_CLOSED"
    assert receipt["outcome"]["reason_codes"] == ["NO_CHANGES"]


def test_tracked_config_changed_candidate_tree_includes_unchanged_config(external_repo: Path):
    init_repository(
        external_repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        deletion_policy="FORBID",
    )
    _git(external_repo, "add", ".nexus-core/config.toml")
    _git(external_repo, "commit", "-m", "track config")

    base_tree = _git(external_repo, "rev-parse", "HEAD^{tree}")
    config_blob_base = _git(external_repo, "rev-parse", "HEAD:.nexus-core/config.toml")

    # Candidate stages a change to app.py
    (external_repo / "app.py").write_text("VALUE = 42\n", encoding="utf-8")
    _git(external_repo, "add", "app.py")

    result = check_repository(external_repo)
    assert result["status"] == "VERIFIED"

    receipt = json.loads(Path(result["receipt_path"]).read_text(encoding="utf-8"))
    target_tree = receipt["target_tree"].removeprefix("git-tree:")
    config_blob_target = _git(external_repo, "rev-parse", f"{target_tree}:.nexus-core/config.toml")

    assert config_blob_target == config_blob_base
    assert target_tree != base_tree


def test_tracked_config_legitimate_deletion_fails_closed_with_forbidden_deletion(
    external_repo: Path,
):
    init_repository(
        external_repo,
        base_ref="main",
        allowed_patterns=("*.py", ".nexus-core/**"),
        deletion_policy="FORBID",
    )
    _git(external_repo, "add", ".nexus-core/config.toml")
    _git(external_repo, "commit", "-m", "track config")

    # Candidate branch removes config.toml from git tree while keeping config on disk
    # so _load_config can still evaluate the policy
    _git(external_repo, "checkout", "-b", "candidate")
    _git(external_repo, "rm", "--cached", ".nexus-core/config.toml")
    (external_repo / "app.py").write_text("VALUE = 10\n", encoding="utf-8")
    _git(external_repo, "add", "app.py")
    _git(external_repo, "commit", "-m", "candidate branch deletes config from git")

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "FORBIDDEN_DELETION"
    assert ".nexus-core/config.toml" in raised.value.detail


def _write_multi_evidence_config(repo: Path, body: str) -> Path:
    config = repo / ".nexus-core" / "config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "\n".join(
            [
                "version = 2",
                'base_ref = "main"',
                'allowed_patterns = ["*.py"]',
                'deletion_policy = "FORBID"',
                "universe_generation = 1",
                body.strip(),
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config


def test_v2_multiple_required_evidence_subjects_are_covered(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _write_multi_evidence_config(
        external_repo,
        f"""
materials = []

[[verifiers]]
id = "behavior"
command = [{json.dumps(sys.executable)}, "-c", "import app; assert app.VALUE == 2"]
timeout_seconds = 30
logical_subject_id = "required/behavior"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"

[[verifiers]]
id = "regression"
command = [{json.dumps(sys.executable)}, "-c", "import app; assert app.VALUE > 0"]
timeout_seconds = 30
logical_subject_id = "required/regression"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
""",
    )

    result = check_repository(external_repo)

    assert result["status"] == "VERIFIED"
    receipt = json.loads(result["receipt_path"].read_text(encoding="utf-8"))
    assert receipt["schema_version"] == 2
    assert [row["producer_id"] for row in receipt["evidence_artifacts"]] == [
        "behavior",
        "regression",
    ]
    coverage = receipt["core_response"]["verification"]["coverage"]
    assert {row["logical_subject_id"]: row["category"] for row in coverage["entries"]} == {
        "required/behavior": "COVERED",
        "required/regression": "COVERED",
    }
    assert validate_verification_receipt(result["receipt_path"], repo=external_repo) == {
        "valid": True,
        "reason_codes": [],
    }


def test_v2_failed_required_verifier_cannot_false_green(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _write_multi_evidence_config(
        external_repo,
        f"""
materials = []

[[verifiers]]
id = "behavior"
command = [{json.dumps(sys.executable)}, "-c", "raise SystemExit(1)"]
timeout_seconds = 30
logical_subject_id = "required/behavior"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
""",
    )

    result = check_repository(external_repo)

    assert result["status"] == "FAILED_VERIFICATION"
    assert "behavior" in result["reason_codes"]


def test_v2_required_material_identity_mismatch_blocks_linked_verifier(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    expected = "git-commit:" + "b" * 40
    observed = "git-commit:" + "c" * 40
    marker = external_repo / "verifier-ran.txt"
    _write_multi_evidence_config(
        external_repo,
        f"""
[[materials]]
id = "learning-revision"
observe_command = [{json.dumps(sys.executable)}, "-c", "print({observed!r})"]
timeout_seconds = 30
logical_subject_id = "dependency/nexus-learning"
evidence_kind = "resolved-dependency"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
expected_identity = {json.dumps(expected)}

[[verifiers]]
id = "full-suite"
command = [{json.dumps(sys.executable)}, "-c", "from pathlib import Path; Path({str(marker)!r}).write_text('ran')"]
timeout_seconds = 30
logical_subject_id = "runtime/full-suite"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
required_material_ids = ["learning-revision"]
""",
    )

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "UNVERIFIABLE"
    assert not marker.exists()
    receipt = json.loads(raised.value.receipt_path.read_text(encoding="utf-8"))
    material = receipt["evidence_artifacts"][0]
    assert material["expected_identity"] == expected
    assert material["observed_identity"] == observed
    assert material["status"] == "FAIL"
    assert "full-suite" in receipt["outcome"]["reason_codes"]
    coverage = {
        row["logical_subject_id"]: row["category"]
        for row in receipt["core_response"]["verification"]["coverage"]["entries"]
    }
    assert coverage["dependency/nexus-learning"] == "COVERED"
    assert coverage["runtime/full-suite"] == "NOT_COVERED"


def test_v2_required_material_identity_match_is_linked_and_bound(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    identity = "git-commit:" + "b" * 40
    _write_multi_evidence_config(
        external_repo,
        f"""
[[materials]]
id = "learning-revision"
observe_command = [{json.dumps(sys.executable)}, "-c", "print({identity!r})"]
timeout_seconds = 30
logical_subject_id = "dependency/nexus-learning"
evidence_kind = "resolved-dependency"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
expected_identity = {json.dumps(identity)}

[[verifiers]]
id = "full-suite"
command = [{json.dumps(sys.executable)}, "-c", "raise SystemExit(0)"]
timeout_seconds = 30
logical_subject_id = "runtime/full-suite"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
required_material_ids = ["learning-revision"]
""",
    )

    result = check_repository(external_repo)

    assert result["status"] == "VERIFIED"
    receipt = json.loads(result["receipt_path"].read_text(encoding="utf-8"))
    assert receipt["evidence_artifacts"][0]["observed_identity"] == identity
    assert receipt["evidence_links"] == [
        {"verifier_id": "full-suite", "required_material_ids": ["learning-revision"]}
    ]
    assert validate_verification_receipt(result["receipt_path"], repo=external_repo)["valid"] is True


def test_v2_unresolved_conditional_subject_is_unverifiable(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _write_multi_evidence_config(
        external_repo,
        f"""
materials = []

[[verifiers]]
id = "required"
command = [{json.dumps(sys.executable)}, "-c", "raise SystemExit(0)"]
timeout_seconds = 30
logical_subject_id = "required/base"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"

[[verifiers]]
id = "conditional"
command = [{json.dumps(sys.executable)}, "-c", "raise SystemExit(0)"]
timeout_seconds = 30
logical_subject_id = "conditional/runtime"
evidence_kind = "test-result"
requirement_mode = "CONDITIONALLY_REQUIRED"
applicability = "UNRESOLVED"
""",
    )

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "UNVERIFIABLE"
    receipt = json.loads(raised.value.receipt_path.read_text(encoding="utf-8"))
    assert "COVERAGE_UNRESOLVED" in receipt["outcome"]["reason_codes"]


def test_v2_rehashed_material_identity_and_link_tamper_is_detected(
    external_repo: Path, tmp_path: Path
):
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    identity = "git-commit:" + "d" * 40
    _write_multi_evidence_config(
        external_repo,
        f"""
[[materials]]
id = "learning-revision"
observe_command = [{json.dumps(sys.executable)}, "-c", "print({identity!r})"]
timeout_seconds = 30
logical_subject_id = "dependency/nexus-learning"
evidence_kind = "resolved-dependency"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
expected_identity = {json.dumps(identity)}

[[verifiers]]
id = "full-suite"
command = [{json.dumps(sys.executable)}, "-c", "raise SystemExit(0)"]
timeout_seconds = 30
logical_subject_id = "runtime/full-suite"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
required_material_ids = ["learning-revision"]
""",
    )
    result = check_repository(external_repo)
    receipt = json.loads(result["receipt_path"].read_text(encoding="utf-8"))
    receipt["evidence_artifacts"][0]["observed_identity"] = "git-commit:" + "e" * 40
    receipt["evidence_artifacts"][0]["artifact_hash"] = canonical_hash(
        {
            key: value
            for key, value in receipt["evidence_artifacts"][0].items()
            if key != "artifact_hash"
        }
    )
    receipt["evidence_links"][0]["required_material_ids"] = []
    path = tmp_path / "material-tamper.json"
    _write_receipt(path, receipt)

    validation = validate_verification_receipt(path)

    assert validation["valid"] is False
    assert "MATERIAL_IDENTITY_MISMATCH" in validation["reason_codes"]
    assert "VERIFIER_BINDING_MISMATCH" in validation["reason_codes"]
    assert "EVIDENCE_LINK_MISMATCH" in validation["reason_codes"]


def test_v2_rejects_unknown_required_material_reference(external_repo: Path):
    (external_repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _write_multi_evidence_config(
        external_repo,
        f"""
materials = []

[[verifiers]]
id = "full-suite"
command = [{json.dumps(sys.executable)}, "-c", "raise SystemExit(0)"]
timeout_seconds = 30
logical_subject_id = "runtime/full-suite"
evidence_kind = "test-result"
requirement_mode = "REQUIRED"
applicability = "APPLICABLE"
required_material_ids = ["missing-material"]
""",
    )

    with pytest.raises(LocalCheckError) as raised:
        check_repository(external_repo)

    assert raised.value.reason_code == "INVALID_CONFIG"
    assert "required_material_ids" in raised.value.detail
