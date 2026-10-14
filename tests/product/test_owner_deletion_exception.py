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


def _config(owner_public: str, enforcement: str | None = None) -> str:
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
            *([f'enforcement = "{enforcement}"'] if enforcement is not None else []),
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
    return _world(tmp_path)


@pytest.fixture
def advisory_world(tmp_path: Path) -> dict[str, object]:
    return _world(tmp_path, enforcement="ADVISORY")


def _world(tmp_path: Path, enforcement: str | None = None) -> dict[str, object]:
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
    (repo / ".nexus-core" / "config.toml").write_text(
        _config(owner_public, enforcement), encoding="utf-8"
    )
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


# --- [deletion_exception] enforcement = "ADVISORY" -------------------------------


def _edit_protected_workflow(repo: Path) -> None:
    (repo / ".github" / "workflows" / "core.yml").write_text("pin: b\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "unsigned workflow pin change")


def _receipt(result: dict[str, object]) -> dict[str, object]:
    return json.loads(Path(str(result["receipt_path"])).read_text(encoding="utf-8"))


def test_advisory_protected_path_without_signature_is_reported_not_failed(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _edit_protected_workflow(repo)
    result = check_repository(repo, require_trusted_config=True)
    assert result["status"] == "VERIFIED"
    advisory = result["owner_signature_advisory"]
    assert advisory["reason_code"] == "PROTECTED_PATH_REQUIRES_OWNER_SIGNATURE"
    assert advisory["protected_paths_touched"] == [".github/workflows/core.yml"]
    assert ".github/workflows/core.yml" in advisory["detail"]
    receipt = _receipt(result)
    assert receipt["owner_signature_advisory"] == advisory
    assert receipt["inputs"]["request"]["acceptance_contract"]["deletion_policy"] == "FORBID"
    assert "deletion_exception" not in receipt
    assert validate_verification_receipt(result["receipt_path"], repo=repo)["valid"] is True


def test_advisory_config_change_without_signature_is_reported_not_failed(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    config = repo / ".nexus-core" / "config.toml"
    config.write_text(config.read_text(encoding="utf-8") + "# note\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "unsigned config change")
    result = check_repository(repo, require_trusted_config=True)
    assert result["status"] == "VERIFIED"
    assert result["owner_signature_advisory"]["protected_paths_touched"] == [
        ".nexus-core/config.toml"
    ]


def test_advisory_unsigned_manifest_is_reported_not_failed(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    (repo / ".github" / "workflows" / "core.yml").write_text("pin: b\n", encoding="utf-8")
    _write_manifest(repo, "pin", str(advisory_world["base"]), ".github/workflows/core.yml")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "workflow change with unsigned manifest")
    result = check_repository(repo, require_trusted_config=True)
    assert result["status"] == "VERIFIED"
    advisory = result["owner_signature_advisory"]
    assert advisory["reason_code"] == "DELETION_MANIFEST_SIGNATURE_MISSING"
    assert advisory["manifest_paths_touched"] == [".nexus-core/deletions/pin.json"]
    assert advisory["protected_paths_touched"] == [".github/workflows/core.yml"]
    assert validate_verification_receipt(result["receipt_path"], repo=repo)["valid"] is True


def _write_manifest(repo: Path, name: str, base: str, companion: str) -> Path:
    manifest = {
        "schema": "nexus.core.deletion-manifest.v1",
        "id": name,
        "reason": "workflow pin",
        "archive": {"ref": "refs/heads/archive/2026-10-13-test", "commit": base},
        "deletions": [],
        "companion_changes": [
            {
                "path": companion,
                "change_type": "MODIFY",
                "after_oid": _git(repo, "hash-object", companion),
            }
        ],
    }
    directory = repo / ".nexus-core" / "deletions"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_advisory_rejects_a_malformed_unsigned_manifest(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    directory = repo / ".nexus-core" / "deletions"
    directory.mkdir(parents=True)
    (directory / "pin.json").write_text("{}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "malformed unsigned manifest")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "DELETION_MANIFEST_MALFORMED"


def test_advisory_reason_must_match_the_manifest_shape(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _edit_protected_workflow(repo)
    result = check_repository(repo, require_trusted_config=True)

    def swap(receipt: dict[str, object]) -> None:
        receipt["owner_signature_advisory"]["reason_code"] = (  # type: ignore[index]
            "DELETION_MANIFEST_SIGNATURE_MISSING"
        )

    validation = validate_verification_receipt(_rewrite(result, "s.json", swap), repo=repo)
    assert validation["valid"] is False
    assert "OWNER_SIGNATURE_ADVISORY_MALFORMED" in validation["reason_codes"]


def test_advisory_trust_root_recheck_against_the_repo(
    advisory_world: dict[str, object],
) -> None:
    """With the repository at hand, the validator re-runs the trust-root refusal."""

    from product.clients.local_golden_path import _advisory_trust_root_reasons

    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    config = repo / ".nexus-core" / "config.toml"
    config.write_text(config.read_text(encoding="utf-8") + "# note\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "harmless config edit")
    result = check_repository(repo, require_trusted_config=True)
    receipt = _receipt(result)
    trusted = receipt["inputs"]["config"]  # type: ignore[index]
    manifest = receipt["inputs"]["request"]["change_manifest"]  # type: ignore[index]
    assert _advisory_trust_root_reasons(repo, trusted, receipt, manifest) == []
    flipped = config.read_text(encoding="utf-8").replace(
        'deletion_policy = "FORBID"', 'deletion_policy = "ALLOW"'
    )
    flipped_oid = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=repo,
        input=flipped,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    for entry in manifest["entries"]:
        if entry["path"] == ".nexus-core/config.toml":
            entry["after_oid"] = flipped_oid
    assert _advisory_trust_root_reasons(repo, trusted, receipt, manifest) == [
        "OWNER_SIGNATURE_ADVISORY_UNAUTHORIZED"
    ]


def test_advisory_never_admits_an_unsigned_deletion(advisory_world: dict[str, object]) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _git(repo, "rm", "-q", "old.txt")
    _git(repo, "commit", "-q", "-m", "plain deletion")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "FORBIDDEN_DELETION"


def test_advisory_never_admits_a_deletion_with_protected_path_edit(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _git(repo, "rm", "-q", "old.txt")
    (repo / ".github" / "workflows" / "core.yml").write_text("pin: b\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "deletion plus workflow edit")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "FORBIDDEN_DELETION"


def test_advisory_never_admits_an_agent_signed_deletion(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _stage_deletion(advisory_world, key=advisory_world["agent_key"])  # type: ignore[arg-type]
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "DELETION_MANIFEST_SIGNATURE_INVALID"


def test_advisory_keeps_owner_signed_deletion_verified(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _stage_deletion(advisory_world, key=advisory_world["owner_key"])  # type: ignore[arg-type]
    result = check_repository(repo, require_trusted_config=True)
    assert result["status"] == "VERIFIED"
    assert "owner_signature_advisory" not in result
    assert validate_verification_receipt(result["receipt_path"], repo=repo)["valid"] is True


def test_candidate_cannot_switch_itself_to_advisory(world: dict[str, object]) -> None:
    repo = world["repo"]
    assert isinstance(repo, Path)
    config = repo / ".nexus-core" / "config.toml"
    text = config.read_text(encoding="utf-8").replace(
        'protected_paths = [".github/workflows/core.yml"]',
        'protected_paths = [".github/workflows/core.yml"]\nenforcement = "ADVISORY"',
    )
    config.write_text(text, encoding="utf-8")
    (repo / ".github" / "workflows" / "core.yml").write_text("pin: b\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "self-relaxing change")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "PROTECTED_PATH_REQUIRES_OWNER_SIGNATURE"


def test_advisory_record_is_rejected_under_enforced_config(world: dict[str, object]) -> None:
    from product.clients import owner_deletion_exception as ode
    from product.clients.local_golden_path import _receipt_hash

    repo = world["repo"]
    assert isinstance(repo, Path)
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "ordinary change")
    result = check_repository(repo, require_trusted_config=True)
    receipt = _receipt(result)
    receipt["owner_signature_advisory"] = {
        "schema": ode.ADVISORY_SCHEMA,
        "enforcement": "ADVISORY",
        "reason_code": "PROTECTED_PATH_REQUIRES_OWNER_SIGNATURE",
        "detail": "x",
        "protected_paths_touched": [],
        "manifest_paths_touched": [],
    }
    receipt["receipt_hash"] = _receipt_hash(receipt)
    forged = Path(str(result["receipt_path"])).with_name("forged.json")
    forged.write_text(json.dumps(receipt), encoding="utf-8")
    validation = validate_verification_receipt(forged, repo=repo)
    assert validation["valid"] is False
    assert "OWNER_SIGNATURE_ADVISORY_UNAUTHORIZED" in validation["reason_codes"]


def test_advisory_record_must_name_touched_protected_paths(
    advisory_world: dict[str, object],
) -> None:
    from product.clients.local_golden_path import _receipt_hash

    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _edit_protected_workflow(repo)
    result = check_repository(repo, require_trusted_config=True)
    receipt = _receipt(result)
    receipt["owner_signature_advisory"]["protected_paths_touched"] = []
    receipt["receipt_hash"] = _receipt_hash(receipt)
    hidden = Path(str(result["receipt_path"])).with_name("hidden.json")
    hidden.write_text(json.dumps(receipt), encoding="utf-8")
    validation = validate_verification_receipt(hidden, repo=repo)
    assert validation["valid"] is False
    assert "OWNER_SIGNATURE_ADVISORY_MALFORMED" in validation["reason_codes"]


def test_invalid_enforcement_value_is_rejected() -> None:
    from product.clients import owner_deletion_exception as ode

    section = {
        "mode": "OWNER_SIGNED_ARCHIVE",
        "manifest_dir": ".nexus-core/deletions",
        "signature_namespace": NAMESPACE,
        "allowed_signers": ["owner ssh-ed25519 AAAA"],
        "protected_paths": [],
        "enforcement": "OFF",
    }
    with pytest.raises(ode.DeletionExceptionError) as raised:
        ode.validate_section(section)
    assert raised.value.reason_code == "INVALID_CONFIG"
    section["enforcement"] = "ADVISORY"
    assert ode.validate_section(section)["enforcement"] == "ADVISORY"
    del section["enforcement"]
    assert ode.validate_section(section)["enforcement"] == "ENFORCED"


def test_advisory_annotation_cannot_inject_workflow_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from product.clients.cli import _print_owner_signature_advisory

    _print_owner_signature_advisory(
        {
            "owner_signature_advisory": {
                "reason_code": "PROTECTED_PATH_REQUIRES_OWNER_SIGNATURE",
                "detail": "a\n::error::forged\r\n##[error]x %0A",
                "protected_paths_touched": ["p\n::set-output name=x::y"],
                "manifest_paths_touched": [],
            }
        }
    )
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("owner signature: ADVISORY ")
    assert lines[1].startswith("::warning title=Nexus Core owner signature (advisory)::")
    assert "%250A" in lines[1]


@pytest.mark.parametrize(
    ("old", "new", "key"),
    [
        ('deletion_policy = "FORBID"', 'deletion_policy = "ALLOW"', "deletion_policy"),
        ('enforcement = "ADVISORY"', 'enforcement = "ENFORCED"', "deletion_exception"),
        (
            'protected_paths = [".github/workflows/core.yml"]',
            "protected_paths = []",
            "deletion_exception",
        ),
    ],
)
def test_advisory_never_covers_a_trust_root_edit(
    advisory_world: dict[str, object], old: str, new: str, key: str
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    config = repo / ".nexus-core" / "config.toml"
    text = config.read_text(encoding="utf-8")
    assert old in text
    config.write_text(text.replace(old, new), encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "unsigned trust-root edit")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "TRUST_ROOT_CHANGE_REQUIRES_OWNER_SIGNATURE"
    assert key in raised.value.detail
    assert "PROTECTED_PATH_REQUIRES_OWNER_SIGNATURE" in raised.value.detail


def test_advisory_never_covers_a_new_signer(advisory_world: dict[str, object]) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    config = repo / ".nexus-core" / "config.toml"
    text = config.read_text(encoding="utf-8")
    owner_line = text.split("allowed_signers = [", 1)[1].split("]", 1)[0]
    agent = f'"agent {advisory_world["agent_public"]}"'
    config.write_text(text.replace(owner_line, f"{owner_line}, {agent}"), encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "unsigned signer addition")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "TRUST_ROOT_CHANGE_REQUIRES_OWNER_SIGNATURE"


def test_advisory_never_covers_an_unparseable_config(advisory_world: dict[str, object]) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    (repo / ".nexus-core" / "config.toml").write_text("not = [toml\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "broken config")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code in {
        "TRUST_ROOT_CHANGE_REQUIRES_OWNER_SIGNATURE",
        "INVALID_CONFIG",
    }


def test_advisory_keeps_non_signature_manifest_failures(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    directory = repo / ".nexus-core" / "deletions"
    directory.mkdir(parents=True)
    (directory / "a.json").write_text("{}\n", encoding="utf-8")
    (directory / "b.json").write_text("{}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "two manifests")
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True)
    assert raised.value.reason_code == "DELETION_MANIFEST_COUNT_INVALID"


def _rewrite(result: dict[str, object], name: str, mutate) -> Path:  # type: ignore[no-untyped-def]
    from product.clients.local_golden_path import _receipt_hash

    receipt = _receipt(result)
    mutate(receipt)
    receipt["receipt_hash"] = _receipt_hash(receipt)
    path = Path(str(result["receipt_path"])).with_name(name)
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path


def test_advisory_record_cannot_be_stripped(advisory_world: dict[str, object]) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _edit_protected_workflow(repo)
    result = check_repository(repo, require_trusted_config=True)
    stripped = _rewrite(result, "stripped.json", lambda r: r.pop("owner_signature_advisory"))
    validation = validate_verification_receipt(stripped, repo=repo)
    assert validation["valid"] is False
    assert "OWNER_SIGNATURE_ADVISORY_MISSING" in validation["reason_codes"]


def test_advisory_record_reason_must_be_a_signature_code(
    advisory_world: dict[str, object],
) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _edit_protected_workflow(repo)
    result = check_repository(repo, require_trusted_config=True)

    def forge(receipt: dict[str, object]) -> None:
        receipt["owner_signature_advisory"]["reason_code"] = "ANYTHING"  # type: ignore[index]

    validation = validate_verification_receipt(_rewrite(result, "f.json", forge), repo=repo)
    assert validation["valid"] is False
    assert "OWNER_SIGNATURE_ADVISORY_MALFORMED" in validation["reason_codes"]


def test_advisory_record_must_name_a_touched_config(advisory_world: dict[str, object]) -> None:
    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    config = repo / ".nexus-core" / "config.toml"
    config.write_text(config.read_text(encoding="utf-8") + "# note\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "unsigned config comment")
    result = check_repository(repo, require_trusted_config=True)

    def hide(receipt: dict[str, object]) -> None:
        receipt["owner_signature_advisory"]["protected_paths_touched"] = []  # type: ignore[index]

    validation = validate_verification_receipt(_rewrite(result, "h.json", hide), repo=repo)
    assert validation["valid"] is False
    assert "OWNER_SIGNATURE_ADVISORY_MALFORMED" in validation["reason_codes"]


def test_cli_failure_detail_cannot_inject_workflow_commands(
    advisory_world: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    from product.clients.cli import main

    repo = advisory_world["repo"]
    assert isinstance(repo, Path)
    _git(repo, "checkout", "-q", "main")
    (repo / "evil\n::error::forged").write_text("x\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "evil path on main")
    _git(repo, "checkout", "-q", "-B", "deletion-pr", "main")
    _git(repo, "rm", "-q", "evil\n::error::forged")
    _git(repo, "commit", "-q", "-m", "delete evil path")
    code = main(["check", "--repo", str(repo), "--require-trusted-config"])
    assert code == 2
    err = capsys.readouterr().err
    assert all(not line.lstrip().startswith("::") for line in err.splitlines())
    assert "FORBIDDEN_DELETION" in err


def test_signed_record_replaces_advisory_only_for_its_own_manifest() -> None:
    from product.clients import owner_deletion_exception as ode

    section = ode.validate_section(
        {
            "mode": "OWNER_SIGNED_ARCHIVE",
            "manifest_dir": ".nexus-core/deletions",
            "signature_namespace": NAMESPACE,
            "allowed_signers": ["owner ssh-ed25519 AAAA"],
            "protected_paths": [".github/workflows/core.yml"],
            "enforcement": "ADVISORY",
        }
    )
    entries = [
        {"path": ".github/workflows/core.yml", "change_type": "MODIFY"},
        {"path": ".nexus-core/deletions/a.json", "change_type": "ADD"},
        {"path": ".nexus-core/deletions/a.json.sig", "change_type": "ADD"},
    ]
    own = {"manifest_path": ".nexus-core/deletions/a.json", "companion_paths": [entries[0]["path"]]}
    unrelated = {"manifest_path": ".nexus-core/deletions/old.json", "companion_paths": []}
    uncovered = {"manifest_path": ".nexus-core/deletions/a.json", "companion_paths": []}
    kwargs = {"exempt_paths": frozenset()}
    assert ode.advisory_binding_reasons(section, None, entries, deletion_record=own, **kwargs) == []
    for record in (unrelated, uncovered):
        assert ode.advisory_binding_reasons(
            section, None, entries, deletion_record=record, **kwargs
        ) == ["OWNER_SIGNATURE_ADVISORY_MISSING"]


def test_failed_run_still_prints_its_advisory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from product.clients.cli import _print_failed_run_advisory

    receipt = tmp_path / "r.json"
    receipt.write_text(
        json.dumps(
            {
                "owner_signature_advisory": {
                    "reason_code": "PROTECTED_PATH_REQUIRES_OWNER_SIGNATURE",
                    "detail": ".github/workflows/core.yml",
                    "protected_paths_touched": [".github/workflows/core.yml"],
                    "manifest_paths_touched": [],
                }
            }
        ),
        encoding="utf-8",
    )
    _print_failed_run_advisory(receipt)
    _print_failed_run_advisory(tmp_path / "missing.json")
    out = capsys.readouterr().out
    assert "::warning title=Nexus Core owner signature (advisory)::" in out
    assert ".github/workflows/core.yml" in out
