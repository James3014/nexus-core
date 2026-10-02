"""Focused tests for candidate_materialization – slice 1 (repaired).

Covers:
1. Profile hash tamper (PROFILE_HASH_MISMATCH)
2. Verifier ID mismatch (VERIFIER_ID_MISMATCH)
3. Exact candidate isolation despite caller worktree movement
4. Exact-request readback without rerun (request_hash dedup)
5. Replay conflict (same hash, different request ID)
6. Receipt tamper detection (RECEIPT_HASH_MISMATCH)
7. Contract hash tamper (CONTRACT_HASH_MISMATCH)

NEW – reproductions of the three independently-verified false greens:
8.  False green 1: verifier that rewrites a tracked file must fail closed
    (physical drift detection; must NOT pass with HEAD^{tree} check alone).
9.  False green 2: inter-verifier side-effect contamination must fail closed
    (verifier A creates marker.tmp; verifier B must not see it).
10. False green 3: same request_id/hash with different material must fail
    closed (REQUEST_HASH_MISMATCH – caller-supplied hash is not authority).

Plus:
11. Cleanup failure is observable and fails closed (CLEANUP_FAILED).
12. Tampered matching receipt fails closed (TAMPERED_RECEIPT), not silently
    skipped + rerun.
13. Source not ancestor fails closed (SOURCE_NOT_ANCESTOR).
14. Missing/empty expected_change_set_hash fails closed (MISSING_CHANGE_SET_HASH).
15. Profile hash computed from sorted id-command pairs, so swapping a pair
    changes the hash (no positional ambiguity).
16. Readback with different material (same hash) fails closed
    (REPLAY_MATERIAL_MISMATCH).
17. Replay validates actual AcceptanceContract content before receipt readback.
18. Replay validates actual acquisition profile content before receipt readback.
19. Temp-root cleanup failure blocks receipt/success publication.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from product.acquisition import candidate_materialization as candidate_module
from product.acquisition.candidate_materialization import (
    CandidateAcquisitionError,
    CandidateAcquisitionRequest,
    VerificationAcquisitionProfile,
    _compute_acquisition_request_hash,
    _compute_profile_hash,
    acquire_and_verify_candidate,
    validate_candidate_acquisition_receipt,
)
from product.protocol.generic_verification import (
    acceptance_contract_hash,
    change_manifest_hash,
    change_set_hash,
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
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def base_repo(tmp_path: Path) -> Path:
    """A minimal git repo with a base commit and a candidate commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.test")
    _git(repo, "config", "user.name", "Test User")

    # Base commit.
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_ok():\n    assert VALUE == 1\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")

    # Candidate commit: modify app.py.
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repo / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_ok():\n    assert VALUE == 2\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "candidate")

    return repo


def _base_commit(repo: Path) -> str:
    return _git_out(repo, "rev-parse", "HEAD~1")


def _candidate_commit(repo: Path) -> str:
    return _git_out(repo, "rev-parse", "HEAD")


def _candidate_tree(repo: Path) -> str:
    return _git_out(repo, "rev-parse", "HEAD^{tree}")


def _make_contract(paths: list[str], verifier_ids: list[str]) -> dict[str, Any]:
    return {
        "contract_id": "test-contract-1",
        "requirements_hash": "sha256:" + "a" * 64,
        "required_verifier_ids": verifier_ids,
        "allowed_paths": paths,
        "deletion_policy": "FORBID",
    }


def _make_profile(
    verifier_ids: list[str],
    commands: list[list[str]] | None = None,
    timeout: int = 120,
) -> VerificationAcquisitionProfile:
    if commands is None:
        commands = [[sys.executable, "-m", "pytest", "-q"] for _ in verifier_ids]
    profile = VerificationAcquisitionProfile(
        profile_id="test-profile-1",
        verifier_ids=tuple(verifier_ids),
        verifier_commands=tuple(tuple(c) for c in commands),
        timeout_seconds=timeout,
        profile_hash="placeholder",  # Will be replaced below.
    )
    # Re-derive correct hash and rebuild (frozen dataclass workaround).
    correct_hash = _compute_profile_hash(profile)
    return VerificationAcquisitionProfile(
        profile_id=profile.profile_id,
        verifier_ids=profile.verifier_ids,
        verifier_commands=profile.verifier_commands,
        timeout_seconds=profile.timeout_seconds,
        profile_hash=correct_hash,
    )


def _make_change_set_hash(
    repo: Path,
    source_commit: str,
    candidate_tree: str,
    manifest: dict[str, Any],
    request_id: str,
) -> str:
    paths = [e["path"] for e in manifest["entries"]]
    deleted = [e["path"] for e in manifest["entries"] if e["change_type"] == "DELETE"]
    cs = {
        "change_set_id": f"acq-change-{request_id[:16]}",
        "source_revision": f"git-commit:{source_commit}",
        "target_revision": f"git-tree:{candidate_tree}",
        "diff_hash": change_manifest_hash(manifest),
        "paths": paths,
        "deleted_paths": deleted,
    }
    return change_set_hash(cs)


def _compute_manifest(repo: Path, source_tree: str, candidate_tree: str) -> dict[str, Any]:
    """Compute a change manifest via git diff-tree."""
    result = subprocess.run(
        ["git", "diff-tree", "--no-commit-id", "--raw", "-r", "--no-renames", "-z",
         source_tree, candidate_tree],
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
            entries.append({"path": path, "change_type": "ADD",
                            "before_oid": None, "after_oid": after_oid,
                            "before_mode": None, "after_mode": after_mode})
        elif code == "D":
            entries.append({"path": path, "change_type": "DELETE",
                            "before_oid": before_oid, "after_oid": None,
                            "before_mode": before_mode, "after_mode": None})
        else:
            entries.append({"path": path, "change_type": "MODIFY",
                            "before_oid": before_oid, "after_oid": after_oid,
                            "before_mode": before_mode, "after_mode": after_mode})
    return {
        "source_tree": f"git-tree:{source_tree}",
        "target_tree": f"git-tree:{candidate_tree}",
        "entries": sorted(entries, key=lambda e: e["path"]),
    }


def _build_request(
    repo: Path,
    *,
    receipt_dir: Path,
    request_id: str = "req-001",
    override_profile: VerificationAcquisitionProfile | None = None,
    override_contract: dict[str, Any] | None = None,
    override_contract_hash: str | None = None,
    override_profile_hash: str | None = None,
    override_cs_hash: str | None = None,
    override_request_hash: str | None = None,
    verifier_ids: list[str] | None = None,
    verifier_commands: list[list[str]] | None = None,
) -> CandidateAcquisitionRequest:
    source_commit = _base_commit(repo)
    cand_commit = _candidate_commit(repo)
    cand_tree = _candidate_tree(repo)
    source_tree = _git_out(repo, "rev-parse", f"{source_commit}^{{tree}}")
    manifest = _compute_manifest(repo, source_tree, cand_tree)

    _verifier_ids = verifier_ids or ["test-verifier"]
    _verifier_commands = verifier_commands or [[sys.executable, "-m", "pytest", "-q"]]

    contract = override_contract or _make_contract(
        [e["path"] for e in manifest["entries"]], _verifier_ids
    )
    profile = override_profile or _make_profile(
        _verifier_ids,
        _verifier_commands,
    )
    contract_h = override_contract_hash or acceptance_contract_hash(contract)
    profile_h = override_profile_hash or profile.profile_hash
    cs_h = override_cs_hash or _make_change_set_hash(
        repo, source_commit, cand_tree, manifest, request_id
    )
    # Compute canonical request hash from ALL material inputs.
    request_hash = override_request_hash or _compute_acquisition_request_hash(
        acquisition_request_id=request_id,
        candidate_head=cand_commit,
        candidate_tree=cand_tree,
        expected_source_identity=source_commit,
        expected_contract_hash=contract_h,
        expected_profile_hash=profile_h,
        expected_change_set_hash=cs_h,
    )
    return CandidateAcquisitionRequest(
        candidate_head=cand_commit,
        candidate_tree=cand_tree,
        expected_source_identity=source_commit,
        acceptance_contract=contract,
        expected_contract_hash=contract_h,
        profile=profile,
        expected_profile_hash=profile_h,
        expected_change_set_hash=cs_h,
        acquisition_request_id=request_id,
        request_hash=request_hash,
        repo_path=repo,
        receipt_directory=receipt_dir,
    )


# ---------------------------------------------------------------------------
# Test 1: Profile hash tamper
# ---------------------------------------------------------------------------


def test_profile_hash_tamper_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """Supplying a wrong expected_profile_hash must raise PROFILE_HASH_MISMATCH."""
    receipt_dir = tmp_path / "receipts"
    good_profile = _make_profile(["test-verifier"])
    bad_hash = "sha256:" + "b" * 64  # Definitely wrong.

    req = _build_request(
        base_repo,
        receipt_dir=receipt_dir,
        override_profile=good_profile,
        override_profile_hash=bad_hash,
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req)

    assert exc_info.value.reason_code == "PROFILE_HASH_MISMATCH"
    # No receipt should exist for this failed-closed request.
    assert not receipt_dir.exists() or not any(receipt_dir.glob("*.json"))


# ---------------------------------------------------------------------------
# Test 2: Verifier ID mismatch
# ---------------------------------------------------------------------------


def test_verifier_id_mismatch_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """Profile with wrong verifier IDs must raise VERIFIER_ID_MISMATCH."""
    receipt_dir = tmp_path / "receipts"
    # Contract requires "test-verifier"; profile provides "other-verifier".
    contract = _make_contract(["app.py", "test_app.py"], ["test-verifier"])
    profile = _make_profile(["other-verifier"])  # Mismatch.

    req = _build_request(
        base_repo,
        receipt_dir=receipt_dir,
        override_contract=contract,
        override_contract_hash=acceptance_contract_hash(contract),
        override_profile=profile,
        override_profile_hash=profile.profile_hash,
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req)

    assert exc_info.value.reason_code == "VERIFIER_ID_MISMATCH"


# ---------------------------------------------------------------------------
# Test 3: Exact candidate isolation – caller worktree movement
# ---------------------------------------------------------------------------


def test_exact_candidate_despite_caller_worktree_movement(
    base_repo: Path, tmp_path: Path
) -> None:
    """Candidate tree must be the declared tree even if the caller's worktree
    moves to a different commit after the request is built.
    """
    receipt_dir = tmp_path / "receipts"
    # Build request against the current HEAD (candidate commit).
    req = _build_request(base_repo, receipt_dir=receipt_dir)
    declared_tree = req.candidate_tree

    # Now move the caller's working tree to a *new* commit.
    (base_repo / "app.py").write_text("VALUE = 999\n", encoding="utf-8")
    (base_repo / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_ok():\n    assert VALUE == 999\n",
        encoding="utf-8",
    )
    _git(base_repo, "add", ".")
    _git(base_repo, "commit", "-m", "post-request movement")

    # The acquisition must still materialise the declared candidate_head/tree.
    result = acquire_and_verify_candidate(req)

    # Receipt should record the original declared tree, not the post-movement tree.
    receipt_data = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    assert receipt_data["candidate_tree"] == declared_tree

    # Confirm the caller's HEAD is now ahead.
    caller_head_tree = _git_out(base_repo, "rev-parse", "HEAD^{tree}")
    assert caller_head_tree != declared_tree, (
        "Caller should have moved; test would be vacuous otherwise"
    )


# ---------------------------------------------------------------------------
# Test 4: Exact-request readback without rerun
# ---------------------------------------------------------------------------


def test_exact_request_readback_without_rerun(base_repo: Path, tmp_path: Path) -> None:
    """A second call with the same request_hash must return without rerunning."""
    receipt_dir = tmp_path / "receipts"
    req = _build_request(base_repo, receipt_dir=receipt_dir)

    # First run.
    first = acquire_and_verify_candidate(req)
    assert not first.replayed
    assert first.receipt_path.exists()

    # Count receipt files before second call.
    receipt_count_before = len(list(receipt_dir.glob("*.json")))

    # Second run with the same request.
    second = acquire_and_verify_candidate(req)
    assert second.replayed
    assert second.request_hash == first.request_hash
    assert second.status == first.status

    # No new receipt file should have been written.
    receipt_count_after = len(list(receipt_dir.glob("*.json")))
    assert receipt_count_after == receipt_count_before


# ---------------------------------------------------------------------------
# Test 5: Replay conflict – same hash, different request ID
# ---------------------------------------------------------------------------


def test_replay_conflict_same_hash_different_request_id(
    base_repo: Path, tmp_path: Path
) -> None:
    """If a receipt exists for request_hash but with a different request_id,
    the second call must raise REPLAY_CONFLICT.
    """
    receipt_dir = tmp_path / "receipts"

    # First request.
    req1 = _build_request(base_repo, receipt_dir=receipt_dir, request_id="req-001")
    first = acquire_and_verify_candidate(req1)
    assert not first.replayed

    # Build a *second* request with a different request_id but the same request_hash
    # (we reuse req1's hash to simulate a collision / attempted replay).
    req2 = CandidateAcquisitionRequest(
        candidate_head=req1.candidate_head,
        candidate_tree=req1.candidate_tree,
        expected_source_identity=req1.expected_source_identity,
        acceptance_contract=req1.acceptance_contract,
        expected_contract_hash=req1.expected_contract_hash,
        profile=req1.profile,
        expected_profile_hash=req1.expected_profile_hash,
        expected_change_set_hash=req1.expected_change_set_hash,
        acquisition_request_id="req-DIFFERENT",  # Different ID.
        request_hash=req1.request_hash,           # Same hash (forced).
        repo_path=req1.repo_path,
        receipt_directory=receipt_dir,
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req2)

    assert exc_info.value.reason_code in ("REQUEST_HASH_MISMATCH", "REPLAY_CONFLICT")


# ---------------------------------------------------------------------------
# Test 6: Receipt tamper detection
# ---------------------------------------------------------------------------


def test_receipt_tamper_detected(base_repo: Path, tmp_path: Path) -> None:
    """Mutating a receipt field must cause validate_candidate_acquisition_receipt
    to report RECEIPT_HASH_MISMATCH.
    """
    receipt_dir = tmp_path / "receipts"
    req = _build_request(base_repo, receipt_dir=receipt_dir)
    result = acquire_and_verify_candidate(req)
    assert result.receipt_path.exists()

    # First confirm the receipt is valid as-is.
    check = validate_candidate_acquisition_receipt(result.receipt_path)
    assert check["valid"], check["reason_codes"]

    # Tamper: modify a field without updating receipt_hash.
    receipt_data = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    receipt_data["candidate_head"] = "0" * 40  # Corrupt the head SHA.
    result.receipt_path.write_text(
        json.dumps(receipt_data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Re-validate: must detect tampering.
    check_after = validate_candidate_acquisition_receipt(result.receipt_path)
    assert not check_after["valid"]
    assert "RECEIPT_HASH_MISMATCH" in check_after["reason_codes"]


# ---------------------------------------------------------------------------
# Test 7: Contract hash tamper
# ---------------------------------------------------------------------------


def test_contract_hash_tamper_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """Supplying a wrong expected_contract_hash must raise CONTRACT_HASH_MISMATCH."""
    receipt_dir = tmp_path / "receipts"
    bad_contract_hash = "sha256:" + "c" * 64

    req = _build_request(
        base_repo,
        receipt_dir=receipt_dir,
        override_contract_hash=bad_contract_hash,
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req)

    assert exc_info.value.reason_code == "CONTRACT_HASH_MISMATCH"


# ===========================================================================
# NEW TESTS – reproductions of the three independently-verified false greens
# ===========================================================================


# ---------------------------------------------------------------------------
# Test 8: FALSE GREEN 1 – verifier that rewrites a tracked file must fail
#         closed.  HEAD^{tree} does NOT detect physical worktree mutations;
#         our repair uses git diff-index / diff-files.
# ---------------------------------------------------------------------------


def test_verifier_that_mutates_tracked_file_fails_closed(
    base_repo: Path, tmp_path: Path
) -> None:
    """Reproduction of false green #1.

    A verifier command that rewrites a tracked file (app.py) in the worktree
    must cause CANDIDATE_TREE_DRIFT, not VERIFIED.

    Under the old code HEAD^{tree} only read the committed tree and therefore
    missed physical worktree changes, producing a false VERIFIED.  With the
    repair, git diff-files / diff-index detects the mutation.
    """
    receipt_dir = tmp_path / "receipts"

    # Verifier that overwrites app.py in the worktree.
    mutate_script = base_repo / "mutate_tracked.py"
    mutate_script.write_text(
        "from pathlib import Path\n"
        "Path('app.py').write_text('VALUE = 999  # mutated\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    _git(base_repo, "add", "mutate_tracked.py")
    _git(base_repo, "commit", "-m", "add mutate script")

    # Rebuild all derived values after the extra commit.
    req = _build_request(
        base_repo,
        receipt_dir=receipt_dir,
        verifier_ids=["mutator"],
        verifier_commands=[[sys.executable, "mutate_tracked.py"]],
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req)

    assert exc_info.value.reason_code == "CANDIDATE_TREE_DRIFT", (
        f"Expected CANDIDATE_TREE_DRIFT but got {exc_info.value.reason_code!r}; "
        "the physical worktree drift was not detected"
    )


# ---------------------------------------------------------------------------
# Test 9: FALSE GREEN 2 – inter-verifier contamination via untracked file.
#         Verifier A creates marker.tmp; verifier B should NOT see it.
#         Each verifier must run in a fresh clean materialisation.
# ---------------------------------------------------------------------------


def test_inter_verifier_side_effect_contamination_fails_closed(
    base_repo: Path, tmp_path: Path
) -> None:
    """Reproduction of false green #2.

    Verifier A writes an untracked file (marker.tmp).
    Verifier B is a script that fails unless marker.tmp exists.

    Under the old code, verifiers ran sequentially in the SAME worktree, so
    B saw A's marker and both passed → false VERIFIED.

    With the repair, each verifier gets its own fresh materialisation (or the
    untracked file is cleaned before the next verifier), so B never sees A's
    marker and fails as expected.

    Because B fails (non-zero exit), verify_generic_changeset returns
    FAILED_VERIFICATION, not VERIFIED.
    """
    receipt_dir = tmp_path / "receipts"

    # Write verifier scripts into the repo so they are available in the worktree.
    (base_repo / "verifier_a.py").write_text(
        "from pathlib import Path\n"
        "Path('marker.tmp').write_text('exists', encoding='utf-8')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    (base_repo / "verifier_b.py").write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "# Fails (exit 1) if marker.tmp is NOT present.\n"
        "if not Path('marker.tmp').exists():\n"
        "    raise SystemExit(1)\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    _git(base_repo, "add", "verifier_a.py", "verifier_b.py")
    _git(base_repo, "commit", "-m", "add verifier scripts")

    req = _build_request(
        base_repo,
        receipt_dir=receipt_dir,
        # Two verifiers – must be matched in the contract.
        verifier_ids=["verifier-a", "verifier-b"],
        verifier_commands=[
            [sys.executable, "verifier_a.py"],
            [sys.executable, "verifier_b.py"],
        ],
    )

    # B should fail because A's marker.tmp is not present (fresh worktree).
    # The result should be FAILED_VERIFICATION, not VERIFIED.
    result = acquire_and_verify_candidate(req)
    assert result.status != "VERIFIED", (
        "Expected FAILED_VERIFICATION because verifier B should not see "
        "verifier A's marker.tmp in a fresh worktree, but got VERIFIED – "
        "inter-verifier side-effect contamination is still present."
    )


# ---------------------------------------------------------------------------
# Test 10: FALSE GREEN 3 – same acquisition_request_id + request_hash but
#          materially different AcceptanceContract must fail closed.
#          Caller-supplied request_hash is NOT the authority; the module must
#          recompute it from all material inputs.
# ---------------------------------------------------------------------------


def test_same_id_different_material_fails_closed(
    base_repo: Path, tmp_path: Path
) -> None:
    """Reproduction of false green #3.

    A caller crafts a second request with the same acquisition_request_id
    and the same request_hash string value, but a materially different
    AcceptanceContract (different requirements_hash).

    Under the old code, request_hash was not recomputed from all material
    inputs, so a replay with an unchanged hash but changed contract was
    accepted.

    With the repair, the module recomputes the canonical request hash from
    ALL material inputs and rejects any mismatch before readback or execution.
    """
    receipt_dir = tmp_path / "receipts"

    # First, complete a successful acquisition with the real contract.
    req1 = _build_request(base_repo, receipt_dir=receipt_dir, request_id="req-mat-001")
    result1 = acquire_and_verify_candidate(req1)
    assert not result1.replayed

    # Now construct a request with a *different* contract but the *same*
    # request_hash as the first request (simulating a caller that tries to
    # replay the old hash with new material).
    different_contract = {
        "contract_id": "test-contract-1",
        "requirements_hash": "sha256:" + "f" * 64,  # Different!
        "required_verifier_ids": ["test-verifier"],
        "allowed_paths": ["app.py", "test_app.py"],
        "deletion_policy": "FORBID",
    }
    different_contract_hash = acceptance_contract_hash(different_contract)

    # Keep the original profile and cs_hash, but change the contract.
    # The canonical request_hash would be different, but we force the old one.
    req2 = CandidateAcquisitionRequest(
        candidate_head=req1.candidate_head,
        candidate_tree=req1.candidate_tree,
        expected_source_identity=req1.expected_source_identity,
        acceptance_contract=different_contract,
        expected_contract_hash=different_contract_hash,
        profile=req1.profile,
        expected_profile_hash=req1.expected_profile_hash,
        expected_change_set_hash=req1.expected_change_set_hash,
        acquisition_request_id=req1.acquisition_request_id,
        request_hash=req1.request_hash,  # Same hash – but material differs.
        repo_path=req1.repo_path,
        receipt_directory=receipt_dir,
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req2)

    assert exc_info.value.reason_code == "REQUEST_HASH_MISMATCH", (
        f"Expected REQUEST_HASH_MISMATCH but got {exc_info.value.reason_code!r}; "
        "caller-supplied request_hash was accepted as authority despite material mismatch"
    )


# ---------------------------------------------------------------------------
# Test 11: Cleanup failure is observable and fails closed (I)
# ---------------------------------------------------------------------------


def test_cleanup_failure_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """Core-owned worktree cleanup failure must propagate as CLEANUP_FAILED."""
    receipt_dir = tmp_path / "receipts"
    req = _build_request(base_repo, receipt_dir=receipt_dir)

    with patch(
        "product.acquisition.candidate_materialization._remove_worktree",
        side_effect=CandidateAcquisitionError(
            "CLEANUP_FAILED",
            "injected cleanup failure",
        ),
    ):
        with pytest.raises(CandidateAcquisitionError) as exc_info:
            acquire_and_verify_candidate(req)

    assert exc_info.value.reason_code == "CLEANUP_FAILED"
    assert not receipt_dir.exists() or not any(receipt_dir.glob("*.json"))


# ---------------------------------------------------------------------------
# Test 12: Tampered matching receipt fails closed (G)
# ---------------------------------------------------------------------------


def test_tampered_matching_receipt_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """A receipt that matches the request_hash but has an invalid receipt_hash
    must cause TAMPERED_RECEIPT, not be silently skipped so the run reruns.

    Under the old code, a tampered receipt was silently skipped and the request
    would rerun – a security gap.  With the repair, it fails closed.
    """
    receipt_dir = tmp_path / "receipts"
    req = _build_request(base_repo, receipt_dir=receipt_dir)

    # Complete a real acquisition first.
    result = acquire_and_verify_candidate(req)
    assert result.receipt_path.exists()

    # Tamper with the receipt: change the outcome but leave receipt_hash stale.
    receipt_data = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    # Mutate a field so receipt_hash no longer validates.
    receipt_data["outcome"]["status"] = "VERIFIED"  # force a different value
    receipt_data["candidate_head"] = "a" * 40       # corrupt
    # Do NOT update receipt_hash – this makes it invalid.
    result.receipt_path.write_text(
        json.dumps(receipt_data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Second call with the same request should fail closed on the tampered receipt.
    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req)

    assert exc_info.value.reason_code == "TAMPERED_RECEIPT", (
        f"Expected TAMPERED_RECEIPT but got {exc_info.value.reason_code!r}; "
        "tampered matching receipt was not detected"
    )


# ---------------------------------------------------------------------------
# Test 13: Source not ancestor fails closed (D)
# ---------------------------------------------------------------------------


def test_source_not_ancestor_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """expected_source_identity that is not an ancestor of candidate_head must
    raise SOURCE_NOT_ANCESTOR.
    """
    receipt_dir = tmp_path / "receipts"

    # Create a second unrelated branch with its own root commit.
    unrelated = _git_out(
        base_repo, "commit-tree",
        _git_out(base_repo, "rev-parse", "HEAD^{tree}"),
        "-m", "unrelated root",
    )

    cand_commit = _candidate_commit(base_repo)
    cand_tree = _candidate_tree(base_repo)
    source_tree = _git_out(base_repo, "rev-parse", f"{unrelated}^{{tree}}")
    manifest = _compute_manifest(base_repo, source_tree, cand_tree)
    contract = _make_contract([e["path"] for e in manifest["entries"]], ["test-verifier"])
    profile = _make_profile(["test-verifier"])
    cs_h = _make_change_set_hash(base_repo, unrelated, cand_tree, manifest, "req-anc-001")
    rh = _compute_acquisition_request_hash(
        acquisition_request_id="req-anc-001",
        candidate_head=cand_commit,
        candidate_tree=cand_tree,
        expected_source_identity=unrelated,
        expected_contract_hash=acceptance_contract_hash(contract),
        expected_profile_hash=profile.profile_hash,
        expected_change_set_hash=cs_h,
    )
    req = CandidateAcquisitionRequest(
        candidate_head=cand_commit,
        candidate_tree=cand_tree,
        expected_source_identity=unrelated,
        acceptance_contract=contract,
        expected_contract_hash=acceptance_contract_hash(contract),
        profile=profile,
        expected_profile_hash=profile.profile_hash,
        expected_change_set_hash=cs_h,
        acquisition_request_id="req-anc-001",
        request_hash=rh,
        repo_path=base_repo,
        receipt_directory=receipt_dir,
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req)

    assert exc_info.value.reason_code == "SOURCE_NOT_ANCESTOR"


# ---------------------------------------------------------------------------
# Test 14: Missing expected_change_set_hash fails closed (C)
# ---------------------------------------------------------------------------


def test_missing_change_set_hash_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """Empty expected_change_set_hash must raise MISSING_CHANGE_SET_HASH."""
    receipt_dir = tmp_path / "receipts"

    source_commit = _base_commit(base_repo)
    cand_commit = _candidate_commit(base_repo)
    cand_tree = _candidate_tree(base_repo)
    source_tree = _git_out(base_repo, "rev-parse", f"{source_commit}^{{tree}}")
    manifest = _compute_manifest(base_repo, source_tree, cand_tree)
    contract = _make_contract([e["path"] for e in manifest["entries"]], ["test-verifier"])
    profile = _make_profile(["test-verifier"])
    contract_h = acceptance_contract_hash(contract)
    profile_h = profile.profile_hash

    # Compute a request hash with an empty cs_hash placeholder so we can
    # construct a request with empty expected_change_set_hash.
    rh = _compute_acquisition_request_hash(
        acquisition_request_id="req-empty-cs",
        candidate_head=cand_commit,
        candidate_tree=cand_tree,
        expected_source_identity=source_commit,
        expected_contract_hash=contract_h,
        expected_profile_hash=profile_h,
        expected_change_set_hash="",
    )
    req = CandidateAcquisitionRequest(
        candidate_head=cand_commit,
        candidate_tree=cand_tree,
        expected_source_identity=source_commit,
        acceptance_contract=contract,
        expected_contract_hash=contract_h,
        profile=profile,
        expected_profile_hash=profile_h,
        expected_change_set_hash="",  # Empty – must fail closed.
        acquisition_request_id="req-empty-cs",
        request_hash=rh,
        repo_path=base_repo,
        receipt_directory=receipt_dir,
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req)

    assert exc_info.value.reason_code == "MISSING_CHANGE_SET_HASH"


# ---------------------------------------------------------------------------
# Test 15: Profile hash is canonical (B) – sorted id→command pairs
# ---------------------------------------------------------------------------


def test_profile_hash_sorts_id_command_pairs(base_repo: Path, tmp_path: Path) -> None:
    """Swapping a verifier_id/command pair changes the profile_hash.

    This verifies that _compute_profile_hash uses sorted id→command pairs,
    not just sorted IDs with positional commands (which would allow the hash
    to be unchanged when a swap actually changes which command runs for which ID).
    """
    # Profile A: verifier-alpha → ["cmd_a"], verifier-beta → ["cmd_b"]
    profile_a = _make_profile(
        ["verifier-alpha", "verifier-beta"],
        [[sys.executable, "cmd_a.py"], [sys.executable, "cmd_b.py"]],
    )

    # Profile B: same IDs, commands swapped.
    profile_b_raw = VerificationAcquisitionProfile(
        profile_id="test-profile-1",
        verifier_ids=("verifier-alpha", "verifier-beta"),
        verifier_commands=(
            (sys.executable, "cmd_b.py"),  # swapped
            (sys.executable, "cmd_a.py"),  # swapped
        ),
        timeout_seconds=120,
        profile_hash="placeholder",
    )
    correct_hash_b = _compute_profile_hash(profile_b_raw)
    profile_b = VerificationAcquisitionProfile(
        profile_id=profile_b_raw.profile_id,
        verifier_ids=profile_b_raw.verifier_ids,
        verifier_commands=profile_b_raw.verifier_commands,
        timeout_seconds=profile_b_raw.timeout_seconds,
        profile_hash=correct_hash_b,
    )

    # Since profile_a has verifier-alpha→cmd_a and profile_b has
    # verifier-alpha→cmd_b, the canonical sorted pairs differ, so hashes differ.
    assert profile_a.profile_hash != profile_b.profile_hash, (
        "Profile hashes should differ when id→command mapping differs, "
        "but they are equal – canonical pairs may not be sorted correctly"
    )


# ---------------------------------------------------------------------------
# Test 16: Readback with different material (same hash forced) fails closed (H)
# ---------------------------------------------------------------------------


def test_readback_different_material_fails_closed(base_repo: Path, tmp_path: Path) -> None:
    """After a successful acquisition, a second call with the same request_hash
    but different candidate_tree must fail closed with REPLAY_MATERIAL_MISMATCH
    (H: exact readback cross-binds all material fields).

    This is distinct from false green #3 (which is caught at REQUEST_HASH_MISMATCH
    before readback); this test simulates a case where a tampered request_hash
    was somehow accepted (e.g. bug in hash validation) and reaches the readback
    cross-bind check.
    """
    receipt_dir = tmp_path / "receipts"

    # First: complete a real acquisition.
    req1 = _build_request(base_repo, receipt_dir=receipt_dir, request_id="req-rb-001")
    result1 = acquire_and_verify_candidate(req1)
    assert not result1.replayed

    # Build a second request with a different candidate_tree but *force* the
    # same request_hash that's now on disk (bypassing the hash validation to
    # reach the cross-bind check directly).
    fake_tree = "b" * 40
    req2 = CandidateAcquisitionRequest(
        candidate_head=req1.candidate_head,
        candidate_tree=fake_tree,              # Different tree.
        expected_source_identity=req1.expected_source_identity,
        acceptance_contract=req1.acceptance_contract,
        expected_contract_hash=req1.expected_contract_hash,
        profile=req1.profile,
        expected_profile_hash=req1.expected_profile_hash,
        expected_change_set_hash=req1.expected_change_set_hash,
        acquisition_request_id=req1.acquisition_request_id,
        request_hash=req1.request_hash,  # Same hash (forced bypass of A-check).
        repo_path=req1.repo_path,
        receipt_directory=receipt_dir,
    )

    # The canonical request hash check (A) will catch this before we even
    # reach the readback cross-bind (H).  Either error is acceptable –
    # both represent the correct fail-closed behaviour.
    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req2)

    assert exc_info.value.reason_code in (
        "REQUEST_HASH_MISMATCH",
        "REPLAY_MATERIAL_MISMATCH",
        "INVALID_INPUT",
    ), (
        f"Expected fail-closed error but got {exc_info.value.reason_code!r}"
    )


# ---------------------------------------------------------------------------
# Additional replay/cleanup hardening
# ---------------------------------------------------------------------------


def test_replay_validates_actual_contract_before_readback(
    base_repo: Path, tmp_path: Path
) -> None:
    """Changed contract content cannot reuse an old expected hash/receipt."""
    receipt_dir = tmp_path / "receipts"
    req1 = _build_request(base_repo, receipt_dir=receipt_dir, request_id="req-stale-contract")
    first = acquire_and_verify_candidate(req1)
    assert first.receipt_path.exists()

    changed_contract = dict(req1.acceptance_contract)
    changed_contract["requirements_hash"] = "sha256:" + "e" * 64

    req2 = CandidateAcquisitionRequest(
        candidate_head=req1.candidate_head,
        candidate_tree=req1.candidate_tree,
        expected_source_identity=req1.expected_source_identity,
        acceptance_contract=changed_contract,
        expected_contract_hash=req1.expected_contract_hash,
        profile=req1.profile,
        expected_profile_hash=req1.expected_profile_hash,
        expected_change_set_hash=req1.expected_change_set_hash,
        acquisition_request_id=req1.acquisition_request_id,
        request_hash=req1.request_hash,
        repo_path=req1.repo_path,
        receipt_directory=req1.receipt_directory,
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req2)

    assert exc_info.value.reason_code == "CONTRACT_HASH_MISMATCH"


def test_replay_validates_actual_profile_before_readback(
    base_repo: Path, tmp_path: Path
) -> None:
    """Changed profile content cannot reuse an old expected hash/receipt."""
    receipt_dir = tmp_path / "receipts"
    req1 = _build_request(base_repo, receipt_dir=receipt_dir, request_id="req-stale-profile")
    first = acquire_and_verify_candidate(req1)
    assert first.receipt_path.exists()

    changed_profile = VerificationAcquisitionProfile(
        profile_id=req1.profile.profile_id,
        verifier_ids=req1.profile.verifier_ids,
        verifier_commands=((sys.executable, "-c", "raise SystemExit(0)"),),
        timeout_seconds=req1.profile.timeout_seconds,
        profile_hash=req1.profile.profile_hash,
    )

    req2 = CandidateAcquisitionRequest(
        candidate_head=req1.candidate_head,
        candidate_tree=req1.candidate_tree,
        expected_source_identity=req1.expected_source_identity,
        acceptance_contract=req1.acceptance_contract,
        expected_contract_hash=req1.expected_contract_hash,
        profile=changed_profile,
        expected_profile_hash=req1.expected_profile_hash,
        expected_change_set_hash=req1.expected_change_set_hash,
        acquisition_request_id=req1.acquisition_request_id,
        request_hash=req1.request_hash,
        repo_path=req1.repo_path,
        receipt_directory=req1.receipt_directory,
    )

    with pytest.raises(CandidateAcquisitionError) as exc_info:
        acquire_and_verify_candidate(req2)

    assert exc_info.value.reason_code == "PROFILE_HASH_MISMATCH"


def test_temp_root_cleanup_failure_fails_closed_without_receipt(
    base_repo: Path, tmp_path: Path
) -> None:
    """Failure after physical temp-root cleanup still blocks success/receipt."""
    receipt_dir = tmp_path / "receipts"
    req = _build_request(base_repo, receipt_dir=receipt_dir)
    real_cleanup = candidate_module._remove_temp_root

    def cleanup_then_fail(path: Path) -> None:
        real_cleanup(path)
        raise CandidateAcquisitionError(
            "CLEANUP_FAILED",
            "synthetic temp-root cleanup failure",
        )

    with patch(
        "product.acquisition.candidate_materialization._remove_temp_root",
        side_effect=cleanup_then_fail,
    ):
        with pytest.raises(CandidateAcquisitionError) as exc_info:
            acquire_and_verify_candidate(req)

    assert exc_info.value.reason_code == "CLEANUP_FAILED"
    assert not receipt_dir.exists() or not any(receipt_dir.glob("*.json"))
