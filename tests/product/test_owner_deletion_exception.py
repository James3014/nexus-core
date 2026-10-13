from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from product.clients.local_golden_path import (
    LocalCheckError,
    check_repository,
    validate_verification_receipt,
)


def _ssh_keygen_usable() -> bool:
    """ssh-keygen exits 255 when the uid has no passwd entry (e.g. container sandboxes)."""

    if shutil.which("ssh-keygen") is None:
        return False
    with tempfile.TemporaryDirectory() as directory:
        probe = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(Path(directory) / "probe")],
            capture_output=True,
        )
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(
    not _ssh_keygen_usable(), reason="needs a usable ssh-keygen (uid with a passwd entry)"
)

NAMESPACE = "nexus-core-deletion@v1"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _keypair(directory: Path, name: str) -> tuple[Path, str]:
    key = directory / name
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)],
        check=True,
        capture_output=True,
    )
    public = (directory / f"{name}.pub").read_text(encoding="utf-8").split()
    return key, f"{public[0]} {public[1]}"


def _sign(key: Path, payload: bytes) -> bytes:
    result = subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", NAMESPACE],
        input=payload,
        check=True,
        capture_output=True,
    )
    return result.stdout


def _config(owner_public: str) -> str:
    return "\n".join(
        [
            "version = 2",
            'base_ref = "main"',
            'allowed_patterns = ["**"]',
            'deletion_policy = "FORBID"',
            "universe_generation = 1",
            "materials = []",
            "",
            "[deletion_exception]",
            'mode = "OWNER_SIGNED_ARCHIVE"',
            'manifest_dir = ".nexus-core/deletions"',
            f'signature_namespace = "{NAMESPACE}"',
            f'allowed_signers = ["owner {owner_public}"]',
            'protected_paths = [".github/workflows/core.yml"]',
            "",
            "[[verifiers]]",
            'id = "behavior"',
            f'command = [{json.dumps(sys.executable)}, "-c", "import app"]',
            "timeout_seconds = 30",
            'logical_subject_id = "required/behavior"',
            'evidence_kind = "test-result"',
            'requirement_mode = "REQUIRED"',
            'applicability = "APPLICABLE"',
            "",
        ]
    )


@pytest.fixture
def world(tmp_path: Path) -> dict[str, object]:
    keys = tmp_path / "keys"
    keys.mkdir()
    owner_key, owner_public = _keypair(keys, "owner")
    agent_key, agent_public = _keypair(keys, "agent")
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "owner@example.test")
    _git(repo, "config", "user.name", "Owner")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "old.txt").write_text("retired\n", encoding="utf-8")
    (repo / "ARCHIVED.md").write_text("# Archived\n", encoding="utf-8")
    (repo / ".nexus-core").mkdir()
    (repo / ".nexus-core" / "config.toml").write_text(_config(owner_public), encoding="utf-8")
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "core.yml").write_text("pin: a\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "branch", "archive/2026-10-13-test", base)
    _git(repo, "checkout", "-q", "-b", "deletion-pr")
    return {
        "repo": repo,
        "base": base,
        "owner_key": owner_key,
        "agent_key": agent_key,
        "agent_public": agent_public,
    }


def _stage_deletion(
    world: dict[str, object],
    *,
    key: Path,
    archive_commit: str | None = None,
    unrelated_change: bool = False,
) -> None:
    repo = world["repo"]
    assert isinstance(repo, Path)
    base = str(world["base"])
    ledger = "# Archived\n\n- old.txt deleted under manifest batch-1\n"
    (repo / "ARCHIVED.md").write_text(ledger, encoding="utf-8")
    manifest = {
        "schema": "nexus.core.deletion-manifest.v1",
        "id": "batch-1",
        "reason": "owner-approved retirement",
        "archive": {
            "ref": "refs/heads/archive/2026-10-13-test",
            "commit": archive_commit or base,
        },
        "deletions": [
            {
                "path": "old.txt",
                "before_oid": _git(repo, "rev-parse", f"{base}:old.txt"),
                "before_mode": "100644",
            }
        ],
        "companion_changes": [
            {
                "path": "ARCHIVED.md",
                "change_type": "MODIFY",
                "after_oid": _git(repo, "hash-object", "ARCHIVED.md"),
            }
        ],
    }
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    directory = repo / ".nexus-core" / "deletions"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "batch-1.json").write_bytes(payload)
    (directory / "batch-1.json.sig").write_bytes(_sign(key, payload))
    _git(repo, "rm", "-q", "old.txt")
    if unrelated_change:
        (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "governed deletion")


def test_unsigned_deletion_stays_forbidden(world: dict[str, object]) -> None:
    repo = world["repo"]
    assert isinstance(repo, Path)
    _git(repo, "rm", "-q", "old.txt")
    _git(repo, "commit", "-q", "-m", "plain deletion")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "FORBIDDEN_DELETION"


def test_owner_signed_dedicated_deletion_is_verified(world: dict[str, object]) -> None:
    repo = world["repo"]
    assert isinstance(repo, Path)
    _stage_deletion(world, key=world["owner_key"])  # type: ignore[arg-type]
    result = check_repository(repo, require_trusted_config=True)
    assert result["status"] == "VERIFIED"
    receipt = json.loads(Path(result["receipt_path"]).read_text(encoding="utf-8"))
    assert receipt["deletion_exception"]["principal"] == "owner"
    assert receipt["deletion_exception"]["deleted_paths"] == ["old.txt"]
    assert receipt["inputs"]["config"]["deletion_policy"] == "FORBID"
    assert receipt["inputs"]["request"]["acceptance_contract"]["deletion_policy"] == "ALLOW"
    assert validate_verification_receipt(result["receipt_path"], repo=repo)["valid"] is True

    receipt.pop("deletion_exception")
    stripped = Path(result["receipt_path"]).with_name("stripped.json")
    stripped.write_text(json.dumps(receipt), encoding="utf-8")
    validation = validate_verification_receipt(stripped, repo=repo)
    assert validation["valid"] is False
    assert "CONFIG_BINDING_MISMATCH" in validation["reason_codes"]


def test_agent_signed_manifest_is_rejected(world: dict[str, object]) -> None:
    repo = world["repo"]
    assert isinstance(repo, Path)
    _stage_deletion(world, key=world["agent_key"])  # type: ignore[arg-type]
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "DELETION_MANIFEST_SIGNATURE_INVALID"


def test_deletion_pr_must_be_dedicated(world: dict[str, object]) -> None:
    repo = world["repo"]
    assert isinstance(repo, Path)
    _stage_deletion(world, key=world["owner_key"], unrelated_change=True)  # type: ignore[arg-type]
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "DELETION_PR_NOT_DEDICATED"
    assert raised.value.detail == "app.py"


def test_unlisted_deletion_is_rejected(world: dict[str, object]) -> None:
    repo = world["repo"]
    assert isinstance(repo, Path)
    _git(repo, "rm", "-q", "app.py")
    _stage_deletion(world, key=world["owner_key"])  # type: ignore[arg-type]
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "DELETION_NOT_IN_MANIFEST"


def test_archive_must_be_in_base_history(world: dict[str, object]) -> None:
    repo = world["repo"]
    assert isinstance(repo, Path)
    _git(repo, "checkout", "-q", "--orphan", "detached-archive")
    _git(repo, "commit", "-q", "-m", "unrelated archive")
    orphan = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "deletion-pr")
    _stage_deletion(world, key=world["owner_key"], archive_commit=orphan)  # type: ignore[arg-type]
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "DELETION_ARCHIVE_NOT_PRESERVED"


@pytest.mark.parametrize("path", [".nexus-core/config.toml", ".github/workflows/core.yml"])
def test_protected_paths_require_owner_signature(world: dict[str, object], path: str) -> None:
    repo = world["repo"]
    assert isinstance(repo, Path)
    target = repo / path
    text = target.read_text(encoding="utf-8")
    if path.endswith("config.toml"):
        owner_line = text.split("allowed_signers = [", 1)[1].split("]", 1)[0]
        text = text.replace(owner_line, f'"agent {world["agent_public"]}"')
    else:
        text = "pin: b\n"
    target.write_text(text, encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "unsigned trust-root change")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "PROTECTED_PATH_REQUIRES_OWNER_SIGNATURE"
