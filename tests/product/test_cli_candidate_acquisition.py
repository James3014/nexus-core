"""Focused tests for the candidate acquisition CLI/runtime seam (issue-1312).

Covers all required scenarios:
 1. Happy-path request through public CLI/runtime seam returns validated receipt hash.
 2. Stdin and file input behavior.
 3. Unknown top-level key rejected.
 4. Missing profile field rejected.
 5. Malformed/empty verifier argv rejected.
 6. Profile/contract hash tamper fails.
 7. Exact replay returns replayed=true and a counter proves verifier not rerun.
 8. Tampered matching receipt fails closed.
 9. Source/candidate mismatch fails closed.
10. Machine-readable non-zero error on stdout with correct schema.
11. Authority/claim fields cannot imply acceptance/merge/release/deploy.
12. Architecture conformance stays green without changes to architecture policy.
"""

from __future__ import annotations

import json
import subprocess
import sys
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from product.acquisition.candidate_materialization import (
    _compute_acquisition_request_hash,
    _receipt_hash_for,
)
from product.clients.cli import build_parser, cmd_acquire
from product.protocol.generic_verification import (
    acceptance_contract_hash,
    change_manifest_hash,
    change_set_hash,
)
from product.runtime.candidate_acquisition import (
    _AUTHORITY,
    _CLAIM_CEILING,
    CLI_RESULT_SCHEMA,
    parse_acquisition_request,
    run_candidate_acquisition,
)

# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=check,
        capture_output=True,
        text=True,
    )


def _git_out(repo: Path, *args: str) -> str:
    return _git(repo, *args).stdout.strip()


# ---------------------------------------------------------------------------
# Minimal git repo fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def base_repo(tmp_path: Path) -> Path:
    """Minimal git repo: base commit + candidate commit (modifies app.py)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.test")
    _git(repo, "config", "user.name", "Test User")

    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_ok():\n    assert VALUE == 1\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")

    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repo / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_ok():\n    assert VALUE == 2\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "candidate")
    return repo


# ---------------------------------------------------------------------------
# Request document builder helpers
# ---------------------------------------------------------------------------


def _compute_manifest(repo: Path, source_tree: str, target_tree: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--raw",
            "-r",
            "--no-renames",
            "-z",
            source_tree,
            target_tree,
        ],
        cwd=repo,
        capture_output=True,
        check=True,
    )
    chunks = result.stdout.split(b"\0")
    entries: list[dict[str, Any]] = []
    i = 0
    while i < len(chunks) and chunks[i]:
        header = chunks[i].decode("ascii")
        path = chunks[i + 1].decode("utf-8")
        i += 2
        fields = header.removeprefix(":").split()
        before_mode, after_mode, before_oid, after_oid, status = fields
        code = status[0]
        if code == "A":
            entries.append(
                {
                    "path": path,
                    "change_type": "ADD",
                    "before_oid": None,
                    "after_oid": after_oid,
                    "before_mode": None,
                    "after_mode": after_mode,
                }
            )
        elif code == "D":
            entries.append(
                {
                    "path": path,
                    "change_type": "DELETE",
                    "before_oid": before_oid,
                    "after_oid": None,
                    "before_mode": before_mode,
                    "after_mode": None,
                }
            )
        else:
            entries.append(
                {
                    "path": path,
                    "change_type": "MODIFY",
                    "before_oid": before_oid,
                    "after_oid": after_oid,
                    "before_mode": before_mode,
                    "after_mode": after_mode,
                }
            )
    return {
        "source_tree": f"git-tree:{source_tree}",
        "target_tree": f"git-tree:{target_tree}",
        "entries": sorted(entries, key=lambda e: e["path"]),
    }


def _make_correct_profile_hash(
    profile_id: str,
    verifier_ids: list[str],
    verifier_commands: list[list[str]],
    timeout_seconds: int,
) -> str:
    """Compute the canonical profile hash using the same algorithm as the module."""
    id_cmd_pairs = sorted(zip(verifier_ids, verifier_commands), key=lambda p: p[0])
    from product.protocol.generic_verification import canonical_hash

    canonical = {
        "profile_id": profile_id,
        "verifier_id_command_pairs": [[vid, list(cmd)] for vid, cmd in id_cmd_pairs],
        "timeout_seconds": timeout_seconds,
    }
    return canonical_hash(canonical)


def _build_request_doc(
    repo: Path,
    receipt_dir: Path,
    *,
    request_id: str = "req-cli-001",
    verifier_ids: list[str] | None = None,
    verifier_commands: list[list[str]] | None = None,
    timeout_seconds: int = 120,
    profile_id: str = "test-profile-cli",
    override_profile_hash: str | None = None,
    override_contract_hash: str | None = None,
    override_cs_hash: str | None = None,
    override_request_hash: str | None = None,
    override_unknown_top: dict[str, Any] | None = None,
    override_profile_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a complete, valid acquisition request document for the CLI seam."""
    source_commit = _git_out(repo, "rev-parse", "HEAD~1")
    candidate_commit = _git_out(repo, "rev-parse", "HEAD")
    candidate_tree = _git_out(repo, "rev-parse", "HEAD^{tree}")
    source_tree = _git_out(repo, "rev-parse", f"{source_commit}^{{tree}}")
    manifest = _compute_manifest(repo, source_tree, candidate_tree)

    _verifier_ids = verifier_ids or ["test-verifier-cli"]
    _verifier_commands = verifier_commands or [[sys.executable, "-m", "pytest", "-q"]]

    paths = [e["path"] for e in manifest["entries"]]
    deleted = [e["path"] for e in manifest["entries"] if e["change_type"] == "DELETE"]

    contract: dict[str, Any] = {
        "contract_id": "test-contract-cli-1",
        "requirements_hash": "sha256:" + "a" * 64,
        "required_verifier_ids": _verifier_ids,
        "allowed_paths": paths,
        "deletion_policy": "FORBID",
    }
    contract_hash = override_contract_hash or acceptance_contract_hash(contract)

    phash = override_profile_hash or _make_correct_profile_hash(
        profile_id, _verifier_ids, _verifier_commands, timeout_seconds
    )

    change_set_proto = {
        "change_set_id": f"acq-change-{request_id[:16]}",
        "source_revision": f"git-commit:{source_commit}",
        "target_revision": f"git-tree:{candidate_tree}",
        "diff_hash": change_manifest_hash(manifest),
        "paths": paths,
        "deleted_paths": deleted,
    }
    cs_hash = override_cs_hash or change_set_hash(change_set_proto)

    req_hash = override_request_hash or _compute_acquisition_request_hash(
        acquisition_request_id=request_id,
        candidate_head=candidate_commit,
        candidate_tree=candidate_tree,
        expected_source_identity=source_commit,
        expected_contract_hash=contract_hash,
        expected_profile_hash=phash,
        expected_change_set_hash=cs_hash,
    )

    profile_doc: dict[str, Any] = {
        "profile_id": profile_id,
        "verifier_ids": _verifier_ids,
        "verifier_commands": _verifier_commands,
        "timeout_seconds": timeout_seconds,
        "profile_hash": phash,
    }
    if override_profile_extra:
        profile_doc.update(override_profile_extra)

    doc: dict[str, Any] = {
        "candidate_head": candidate_commit,
        "candidate_tree": candidate_tree,
        "expected_source_identity": source_commit,
        "acceptance_contract": contract,
        "expected_contract_hash": contract_hash,
        "verification_profile": profile_doc,
        "expected_profile_hash": phash,
        "expected_change_set_hash": cs_hash,
        "acquisition_request_id": request_id,
        "request_hash": req_hash,
        "repo_path": str(repo),
        "receipt_directory": str(receipt_dir),
    }
    if override_unknown_top:
        doc.update(override_unknown_top)

    return doc


# ---------------------------------------------------------------------------
# Test 1: Happy-path — returns validated receipt hash
# ---------------------------------------------------------------------------


def test_happy_path_returns_validated_receipt_hash(base_repo: Path, tmp_path: Path) -> None:
    """Happy-path request through public CLI/runtime seam returns validated receipt hash."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir)

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code == 0, f"Expected exit 0, got {exit_code}; result={result}"
    assert result["schema"] == CLI_RESULT_SCHEMA
    assert result["status"] == "OK"
    assert result["core_verdict"] == result["core_response"]["verification"]["status"]
    assert result["core_reason_codes"] == result["reason_codes"]
    assert "receipt_hash" in result
    assert result["receipt_hash"].startswith("sha256:")
    assert result["replayed"] is False
    assert result["authority"] == _AUTHORITY
    assert result["claim_ceiling"] == _CLAIM_CEILING

    # Independently re-validate the receipt from the path in the result.
    receipt_path = Path(result["receipt_path"])
    assert receipt_path.is_file(), "receipt file must exist"
    receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
    # Re-derive the hash from the persisted receipt and check it matches.
    assert receipt_data["receipt_hash"] == _receipt_hash_for(receipt_data)
    # The result's receipt_hash must match the persisted one.
    assert result["receipt_hash"] == receipt_data["receipt_hash"]


# ---------------------------------------------------------------------------
# Test 2a: File input
# ---------------------------------------------------------------------------


def test_file_input_behavior(base_repo: Path, tmp_path: Path, capsys: Any) -> None:
    """File path input is loaded and processed correctly."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir, request_id="req-file-input")
    req_file = tmp_path / "request.json"
    req_file.write_text(json.dumps(doc), encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(["acquire", "--request", str(req_file)])
    rc = cmd_acquire(args)

    assert rc == 0
    captured = capsys.readouterr()
    out_doc = json.loads(captured.out)
    assert out_doc["status"] == "OK"
    assert out_doc["schema"] == CLI_RESULT_SCHEMA


# ---------------------------------------------------------------------------
# Test 2b: Stdin input
# ---------------------------------------------------------------------------


def test_stdin_input_behavior(base_repo: Path, tmp_path: Path, capsys: Any) -> None:
    """Stdin (request='-') is read and processed correctly."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir, request_id="req-stdin-input")

    parser = build_parser()
    args = parser.parse_args(["acquire"])  # No --request means stdin

    fake_stdin = StringIO(json.dumps(doc))
    with patch("sys.stdin", fake_stdin):
        rc = cmd_acquire(args)

    assert rc == 0
    captured = capsys.readouterr()
    out_doc = json.loads(captured.out)
    assert out_doc["status"] == "OK"


# ---------------------------------------------------------------------------
# Test 3: Unknown top-level key rejected
# ---------------------------------------------------------------------------


def test_unknown_top_level_key_rejected(base_repo: Path, tmp_path: Path) -> None:
    """A request document with an unknown top-level key must be rejected."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(
        base_repo,
        receipt_dir,
        override_unknown_top={"unexpected_field": "should_fail"},
    )

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["status"] == "ERROR"
    assert result["reason_code"] in ("UNKNOWN_FIELDS", "PARSE_ERROR")


# ---------------------------------------------------------------------------
# Test 4: Missing profile field rejected
# ---------------------------------------------------------------------------


def test_missing_profile_field_rejected(base_repo: Path, tmp_path: Path) -> None:
    """A verification_profile missing a required field must be rejected."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir)
    # Remove a required profile field
    del doc["verification_profile"]["timeout_seconds"]

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["status"] == "ERROR"
    assert result["reason_code"] == "PARSE_ERROR"


# ---------------------------------------------------------------------------
# Test 4b: Unknown profile field rejected
# ---------------------------------------------------------------------------


def test_unknown_profile_field_rejected(base_repo: Path, tmp_path: Path) -> None:
    """A verification_profile with an unknown key must be rejected."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(
        base_repo,
        receipt_dir,
        override_profile_extra={"extra_unknown_key": "bad"},
    )

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["status"] == "ERROR"
    assert result["reason_code"] in ("UNKNOWN_FIELDS", "PARSE_ERROR")


# ---------------------------------------------------------------------------
# Test 5: Malformed/empty verifier argv rejected
# ---------------------------------------------------------------------------


def test_empty_verifier_command_rejected(base_repo: Path, tmp_path: Path) -> None:
    """An empty verifier_commands entry (empty list) must be rejected."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir)
    # Override verifier_commands with an empty argv
    doc["verification_profile"]["verifier_commands"] = [[]]

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["status"] == "ERROR"
    assert result["reason_code"] == "PARSE_ERROR"


def test_nonempty_string_in_argv_required(base_repo: Path, tmp_path: Path) -> None:
    """An empty string element in a verifier argv must be rejected."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir)
    # Command with an empty string token
    doc["verification_profile"]["verifier_commands"] = [["python", "", "-m"]]

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["status"] == "ERROR"
    assert result["reason_code"] == "PARSE_ERROR"


def test_non_list_verifier_commands_rejected(base_repo: Path, tmp_path: Path) -> None:
    """verifier_commands must be a list of lists, not a list of strings."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir)
    # Instead of list-of-lists, pass a flat list of strings
    doc["verification_profile"]["verifier_commands"] = ["python", "-m", "pytest"]

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["status"] == "ERROR"
    assert result["reason_code"] == "PARSE_ERROR"


# ---------------------------------------------------------------------------
# Test 6a: Profile hash tamper fails
# ---------------------------------------------------------------------------


def test_profile_hash_tamper_fails(base_repo: Path, tmp_path: Path) -> None:
    """A tampered expected_profile_hash must fail closed."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir)
    doc["expected_profile_hash"] = "sha256:" + "f" * 64
    doc["verification_profile"]["profile_hash"] = "sha256:" + "f" * 64
    # Re-compute request hash with the tampered profile hash
    doc["request_hash"] = _compute_acquisition_request_hash(
        acquisition_request_id=doc["acquisition_request_id"],
        candidate_head=doc["candidate_head"],
        candidate_tree=doc["candidate_tree"],
        expected_source_identity=doc["expected_source_identity"],
        expected_contract_hash=doc["expected_contract_hash"],
        expected_profile_hash=doc["expected_profile_hash"],
        expected_change_set_hash=doc["expected_change_set_hash"],
    )

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["status"] == "ERROR"
    assert result["reason_code"] in ("PROFILE_HASH_MISMATCH", "PARSE_ERROR")


# ---------------------------------------------------------------------------
# Test 6b: Contract hash tamper fails
# ---------------------------------------------------------------------------


def test_contract_hash_tamper_fails(base_repo: Path, tmp_path: Path) -> None:
    """A tampered expected_contract_hash must fail closed."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir)
    tampered_contract_hash = "sha256:" + "e" * 64
    doc["expected_contract_hash"] = tampered_contract_hash
    # Recompute request_hash with the tampered contract hash
    doc["request_hash"] = _compute_acquisition_request_hash(
        acquisition_request_id=doc["acquisition_request_id"],
        candidate_head=doc["candidate_head"],
        candidate_tree=doc["candidate_tree"],
        expected_source_identity=doc["expected_source_identity"],
        expected_contract_hash=tampered_contract_hash,
        expected_profile_hash=doc["expected_profile_hash"],
        expected_change_set_hash=doc["expected_change_set_hash"],
    )

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["status"] == "ERROR"
    assert result["reason_code"] in ("CONTRACT_HASH_MISMATCH", "PARSE_ERROR")


# ---------------------------------------------------------------------------
# Test 7: Exact replay returns replayed=True and verifier not rerun
# ---------------------------------------------------------------------------


def test_exact_replay_returns_replayed_true_verifier_not_rerun(
    base_repo: Path, tmp_path: Path
) -> None:
    """Exact replay must return replayed=True and must not rerun verifier commands."""
    receipt_dir = tmp_path / "receipts"
    counter_file = tmp_path / "run_count.txt"
    counter_file.write_text("0", encoding="utf-8")

    # First run — perform acquisition and write receipt.
    doc = _build_request_doc(base_repo, receipt_dir, request_id="req-replay-007")
    result1, exit_code1 = run_candidate_acquisition(doc, stderr_diag=False)
    assert exit_code1 == 0, f"First run failed: {result1}"
    assert result1["replayed"] is False

    # Count how many receipts exist after first run.
    receipt_count_after_first = len(list(receipt_dir.glob("*.json")))
    assert receipt_count_after_first == 1

    # Second run — identical request → must replay without running verifiers.
    # We track subprocess.run calls to detect verifier re-execution.
    verifier_call_count = 0
    original_subprocess_run = subprocess.run

    def counting_subprocess_run(*args: Any, **kwargs: Any) -> Any:
        nonlocal verifier_call_count
        # Only count if it looks like a verifier (non-git) command.
        cmd = args[0] if args else kwargs.get("args", [])
        if isinstance(cmd, (list, tuple)) and cmd and cmd[0] != "git":
            verifier_call_count += 1
        return original_subprocess_run(*args, **kwargs)

    with patch("subprocess.run", side_effect=counting_subprocess_run):
        result2, exit_code2 = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code2 == 0, f"Replay run failed: {result2}"
    assert result2["replayed"] is True, "Second identical run must return replayed=True"
    assert result2["receipt_hash"] == result1["receipt_hash"], (
        "Replayed result must have the same receipt_hash as original"
    )
    # Critical: verifier must NOT have been invoked during replay.
    assert verifier_call_count == 0, (
        f"Verifier was invoked {verifier_call_count} time(s) during replay — must be 0"
    )
    # No additional receipt files created.
    receipt_count_after_replay = len(list(receipt_dir.glob("*.json")))
    assert receipt_count_after_replay == receipt_count_after_first


# ---------------------------------------------------------------------------
# Test 8: Tampered matching receipt fails closed
# ---------------------------------------------------------------------------


def test_tampered_receipt_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """A receipt whose stored receipt_hash does not match its re-derived hash must fail closed."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir, request_id="req-tamper-008")

    # First run to create the receipt.
    result1, exit_code1 = run_candidate_acquisition(doc, stderr_diag=False)
    assert exit_code1 == 0, f"Initial run failed: {result1}"

    # Tamper the persisted receipt.
    receipt_file = Path(result1["receipt_path"])
    data = json.loads(receipt_file.read_text(encoding="utf-8"))
    data["candidate_head"] = "0" * 40  # mutate a field
    # Leave receipt_hash unchanged so the stored hash no longer matches the content.
    receipt_file.write_text(json.dumps(data), encoding="utf-8")

    # Second run with the same request — must fail closed on tampered receipt.
    result2, exit_code2 = run_candidate_acquisition(doc, stderr_diag=False)
    assert exit_code2 != 0, "Expected non-zero exit on tampered receipt"
    assert result2["status"] == "ERROR"
    assert result2["reason_code"] == "TAMPERED_RECEIPT"


# ---------------------------------------------------------------------------
# Test 9: Source/candidate mismatch fails closed
# ---------------------------------------------------------------------------


def test_source_not_ancestor_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """expected_source_identity that is not an ancestor of candidate_head must fail closed."""
    receipt_dir = tmp_path / "receipts"
    # Use the candidate commit itself as the source (it cannot be its own ancestor in a non-trivial
    # sense without it being the parent). Use a valid-looking but wrong commit hash.
    doc = _build_request_doc(base_repo, receipt_dir)

    # Swap source identity to be the candidate itself (not its ancestor).
    # Use a non-existent SHA that won't resolve.
    doc["expected_source_identity"] = "a" * 40
    # Recompute request_hash with the new source identity.
    doc["request_hash"] = _compute_acquisition_request_hash(
        acquisition_request_id=doc["acquisition_request_id"],
        candidate_head=doc["candidate_head"],
        candidate_tree=doc["candidate_tree"],
        expected_source_identity="a" * 40,
        expected_contract_hash=doc["expected_contract_hash"],
        expected_profile_hash=doc["expected_profile_hash"],
        expected_change_set_hash=doc["expected_change_set_hash"],
    )

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["status"] == "ERROR"
    # source must fail to resolve or fail the ancestry check
    assert result["reason_code"] in ("SOURCE_IDENTITY_UNRESOLVABLE", "SOURCE_NOT_ANCESTOR",
                                     "CHANGE_SET_HASH_MISMATCH", "REQUEST_HASH_MISMATCH",
                                     "PARSE_ERROR")


# ---------------------------------------------------------------------------
# Test 10: Machine-readable non-zero error on stdout with correct schema
# ---------------------------------------------------------------------------


def test_machine_readable_error_on_stdout(base_repo: Path, tmp_path: Path, capsys: Any) -> None:
    """On error, exactly one JSON document is emitted to stdout with status=ERROR."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir)
    # Corrupt the request hash so it will fail.
    doc["request_hash"] = "sha256:" + "c" * 64

    parser = build_parser()
    args = parser.parse_args(["acquire"])
    fake_stdin = StringIO(json.dumps(doc))
    with patch("sys.stdin", fake_stdin):
        rc = cmd_acquire(args)

    captured = capsys.readouterr()
    # stdout must be exactly one valid JSON document.
    out_doc = json.loads(captured.out)
    assert rc != 0
    assert out_doc["status"] == "ERROR"
    assert out_doc["schema"] == CLI_RESULT_SCHEMA
    assert "reason_code" in out_doc


def test_machine_readable_error_on_unknown_key(
    base_repo: Path, tmp_path: Path, capsys: Any
) -> None:
    """Even a parse error must produce machine-readable JSON on stdout, non-zero exit."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(
        base_repo,
        receipt_dir,
        override_unknown_top={"rogue_key": 999},
    )

    parser = build_parser()
    args = parser.parse_args(["acquire"])
    fake_stdin = StringIO(json.dumps(doc))
    with patch("sys.stdin", fake_stdin):
        rc = cmd_acquire(args)

    captured = capsys.readouterr()
    out_doc = json.loads(captured.out)
    assert rc != 0
    assert out_doc["status"] == "ERROR"
    assert out_doc["schema"] == CLI_RESULT_SCHEMA


def test_malformed_json_input_is_machine_readable(capsys: Any) -> None:
    """JSON decode failures still emit one stable machine result on stdout."""
    parser = build_parser()
    args = parser.parse_args(["acquire"])

    with patch("sys.stdin", StringIO("{not-json")):
        rc = cmd_acquire(args)

    captured = capsys.readouterr()
    out_doc = json.loads(captured.out)
    assert rc == 2
    assert out_doc["schema"] == CLI_RESULT_SCHEMA
    assert out_doc["status"] == "ERROR"
    assert out_doc["reason_code"] == "JSON_PARSE_ERROR"
    assert out_doc["authority"] == _AUTHORITY
    assert out_doc["claim_ceiling"] == _CLAIM_CEILING


def test_missing_request_file_is_machine_readable(tmp_path: Path, capsys: Any) -> None:
    """Request-file lookup failures use the same machine envelope."""
    parser = build_parser()
    missing = tmp_path / "does-not-exist.json"
    args = parser.parse_args(["acquire", "--request", str(missing)])

    rc = cmd_acquire(args)

    captured = capsys.readouterr()
    out_doc = json.loads(captured.out)
    assert rc == 2
    assert out_doc["schema"] == CLI_RESULT_SCHEMA
    assert out_doc["status"] == "ERROR"
    assert out_doc["reason_code"] == "REQUEST_FILE_NOT_FOUND"
    assert out_doc["authority"] == _AUTHORITY
    assert out_doc["claim_ceiling"] == _CLAIM_CEILING


# ---------------------------------------------------------------------------
# Test 11: Authority/claim fields cannot imply acceptance/merge/release/deploy
# ---------------------------------------------------------------------------


def test_authority_field_is_correct(base_repo: Path, tmp_path: Path) -> None:
    """The authority field must equal CORE_EVIDENCE_TRUST_COMPLETION_ONLY."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir, request_id="req-authority-011")

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code == 0, f"Expected success, got: {result}"
    assert result["authority"] == "CORE_EVIDENCE_TRUST_COMPLETION_ONLY"


def test_claim_ceiling_excludes_acceptance_merge_release_deploy(
    base_repo: Path, tmp_path: Path
) -> None:
    """claim_ceiling must explicitly exclude acceptance, merge, release, and deploy."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir, request_id="req-ceiling-011b")

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)
    assert exit_code == 0, f"Expected success, got: {result}"

    ceiling = result.get("claim_ceiling", [])

    # Must NOT imply any of these authorities.
    forbidden_phrases = [
        "ACCEPT", "MERGE", "RELEASE", "DEPLOY",
    ]
    for phrase in forbidden_phrases:
        assert any(phrase in item.upper() for item in ceiling), (
            f"claim_ceiling must explicitly deny {phrase!r}; got {ceiling!r}"
        )

    # Must also contain NO_ prefix items (explicit exclusions).
    no_items = [item for item in ceiling if item.startswith("NO_")]
    assert no_items, "claim_ceiling must contain at least one NO_* explicit exclusion"

    # The authority field must not contain acceptance/merge/release/deploy.
    authority = result.get("authority", "").upper()
    for banned in ("ACCEPT", "MERGE_AUTH", "RELEASE", "DEPLOY"):
        assert banned not in authority, (
            f"authority field must not imply {banned!r}; got {authority!r}"
        )


def test_error_result_also_has_authority_and_ceiling(
    base_repo: Path, tmp_path: Path
) -> None:
    """Even error results must carry authority and claim_ceiling."""
    receipt_dir = tmp_path / "receipts"
    doc = _build_request_doc(base_repo, receipt_dir)
    # Force an error by corrupting request hash.
    doc["request_hash"] = "sha256:" + "d" * 64

    result, exit_code = run_candidate_acquisition(doc, stderr_diag=False)

    assert exit_code != 0
    assert result["authority"] == _AUTHORITY
    assert result["claim_ceiling"] == _CLAIM_CEILING


# ---------------------------------------------------------------------------
# Test 12: Architecture conformance stays green
# ---------------------------------------------------------------------------


def test_runtime_facade_does_not_exist_in_clients_package() -> None:
    """product.clients.cli must NOT directly import product.acquisition."""
    import ast
    from pathlib import Path as _Path

    cli_file = _Path(__file__).resolve().parent.parent.parent / "product" / "clients" / "cli.py"
    source = cli_file.read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("product.acquisition"), (
                    f"product.clients.cli must not import product.acquisition directly; "
                    f"found: import {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not module.startswith("product.acquisition"), (
                f"product.clients.cli must not import from product.acquisition directly; "
                f"found: from {module} import ..."
            )


def test_runtime_facade_imports_acquisition_and_adapters() -> None:
    """product.runtime.candidate_acquisition must import from both acquisition and adapters."""
    import ast
    from pathlib import Path as _Path

    facade_file = (
        _Path(__file__).resolve().parent.parent.parent
        / "product"
        / "runtime"
        / "candidate_acquisition.py"
    )
    source = facade_file.read_text(encoding="utf-8")
    tree = ast.parse(source)

    imports_acquisition = False
    imports_adapters = False

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith("product.acquisition"):
                imports_acquisition = True
            if module.startswith("product.adapters"):
                imports_adapters = True

    assert imports_acquisition, (
        "product.runtime.candidate_acquisition must import from product.acquisition"
    )
    assert imports_adapters, (
        "product.runtime.candidate_acquisition must import from product.adapters"
    )


def test_architecture_conformance_passes_with_new_facade() -> None:
    """Architecture conformance must pass without any changes to the policy allowlist."""
    from pathlib import Path as _Path

    from tests.architecture.conformance import (
        build_dependency_graph,
        verify_conformance,
    )

    repo_root = _Path(__file__).resolve().parent.parent.parent
    product_dir = repo_root / "product"
    graph = build_dependency_graph(product_dir, repo_root)
    violations = verify_conformance(graph)
    assert not violations, (
        "Architecture conformance violations detected after adding CLI/runtime facade:\n"
        + "\n".join(f"  - {v.format()}" for v in violations)
    )


# ---------------------------------------------------------------------------
# Additional parse-error matrix tests
# ---------------------------------------------------------------------------


def test_wrong_type_for_candidate_head_rejected() -> None:
    """candidate_head must be a string, not an integer."""
    from product.acquisition.candidate_materialization import CandidateAcquisitionError

    doc = {
        "candidate_head": 12345,  # wrong type
        "candidate_tree": "a" * 40,
        "expected_source_identity": "b" * 40,
        "acceptance_contract": {},
        "expected_contract_hash": "sha256:" + "a" * 64,
        "verification_profile": {
            "profile_id": "p",
            "verifier_ids": ["v"],
            "verifier_commands": [["cmd"]],
            "timeout_seconds": 60,
            "profile_hash": "sha256:" + "a" * 64,
        },
        "expected_profile_hash": "sha256:" + "a" * 64,
        "expected_change_set_hash": "sha256:" + "a" * 64,
        "acquisition_request_id": "req-1",
        "request_hash": "sha256:" + "a" * 64,
        "repo_path": "/tmp/repo",
        "receipt_directory": "/tmp/receipts",
    }
    with pytest.raises(CandidateAcquisitionError) as exc_info:
        parse_acquisition_request(doc)
    assert exc_info.value.reason_code == "PARSE_ERROR"


def test_malformed_hash_shape_rejected() -> None:
    """A hash field without sha256: prefix must be rejected."""
    from product.acquisition.candidate_materialization import CandidateAcquisitionError

    doc = {
        "candidate_head": "a" * 40,
        "candidate_tree": "b" * 40,
        "expected_source_identity": "c" * 40,
        "acceptance_contract": {"contract_id": "x"},
        "expected_contract_hash": "notahash",  # malformed
        "verification_profile": {
            "profile_id": "p",
            "verifier_ids": ["v"],
            "verifier_commands": [["cmd"]],
            "timeout_seconds": 60,
            "profile_hash": "sha256:" + "a" * 64,
        },
        "expected_profile_hash": "sha256:" + "a" * 64,
        "expected_change_set_hash": "sha256:" + "a" * 64,
        "acquisition_request_id": "req-2",
        "request_hash": "sha256:" + "a" * 64,
        "repo_path": "/tmp/repo",
        "receipt_directory": "/tmp/receipts",
    }
    with pytest.raises(CandidateAcquisitionError) as exc_info:
        parse_acquisition_request(doc)
    assert exc_info.value.reason_code == "PARSE_ERROR"


def test_zero_timeout_rejected() -> None:
    """timeout_seconds=0 must be rejected as invalid."""
    from product.acquisition.candidate_materialization import CandidateAcquisitionError

    doc = {
        "candidate_head": "a" * 40,
        "candidate_tree": "b" * 40,
        "expected_source_identity": "c" * 40,
        "acceptance_contract": {},
        "expected_contract_hash": "sha256:" + "a" * 64,
        "verification_profile": {
            "profile_id": "p",
            "verifier_ids": ["v"],
            "verifier_commands": [["cmd"]],
            "timeout_seconds": 0,  # invalid
            "profile_hash": "sha256:" + "a" * 64,
        },
        "expected_profile_hash": "sha256:" + "a" * 64,
        "expected_change_set_hash": "sha256:" + "a" * 64,
        "acquisition_request_id": "req-3",
        "request_hash": "sha256:" + "a" * 64,
        "repo_path": "/tmp/repo",
        "receipt_directory": "/tmp/receipts",
    }
    with pytest.raises(CandidateAcquisitionError) as exc_info:
        parse_acquisition_request(doc)
    assert exc_info.value.reason_code == "PARSE_ERROR"


def test_empty_acquisition_request_id_rejected() -> None:
    """An empty acquisition_request_id string must be rejected."""
    from product.acquisition.candidate_materialization import CandidateAcquisitionError

    doc = {
        "candidate_head": "a" * 40,
        "candidate_tree": "b" * 40,
        "expected_source_identity": "c" * 40,
        "acceptance_contract": {},
        "expected_contract_hash": "sha256:" + "a" * 64,
        "verification_profile": {
            "profile_id": "p",
            "verifier_ids": ["v"],
            "verifier_commands": [["cmd"]],
            "timeout_seconds": 60,
            "profile_hash": "sha256:" + "a" * 64,
        },
        "expected_profile_hash": "sha256:" + "a" * 64,
        "expected_change_set_hash": "sha256:" + "a" * 64,
        "acquisition_request_id": "",  # empty
        "request_hash": "sha256:" + "a" * 64,
        "repo_path": "/tmp/repo",
        "receipt_directory": "/tmp/receipts",
    }
    with pytest.raises(CandidateAcquisitionError) as exc_info:
        parse_acquisition_request(doc)
    assert exc_info.value.reason_code == "PARSE_ERROR"
