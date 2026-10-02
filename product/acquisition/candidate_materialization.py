"""Internal experimental candidate-bound acquisition module.

This module materialises an *exact* candidate commit/tree in a private detached
Git worktree, executes a set of pre-bound verifier commands, builds the
canonical VerificationPlan/EvidenceBundle structures, calls
:func:`verify_generic_changeset`, and writes a hash-bound Core-owned receipt.

Design constraints (slice-1):
* Fails closed when any supplied hash mismatches the re-computed value.
* Fails closed when profile ``verifier_ids`` do not *exactly equal*
  ``required_verifier_ids`` from the contract.
* Materialises into an isolated detached worktree; the caller's working tree
  is never touched.
* Each verifier runs from a fresh clean materialisation of the same immutable
  candidate so no verifier side-effect can leak to another verifier.
* Physical worktree drift is detected via a full worktree scan (not HEAD^{tree})
  after each verifier run; any tracked mutation fails closed.
* Supports exact readback/reconciliation by ``request_hash`` so a completed
  request is returned without rerunning.  Readback cross-binds all material
  fields and fails closed on any mismatch.
* A tampered receipt (valid hash but matching request_hash) fails closed rather
  than being silently skipped and rerun.
* No routing, no acceptance authority, no G2 adjudication.
* Local Golden Path compatible (imports only public product layers).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from product.adapters.generic_verification import verify_generic_changeset
from product.protocol import PUBLIC_PROTOCOL_VERSION
from product.protocol.generic_verification import (
    GENERIC_VERIFICATION_REQUEST_SCHEMA_ID,
    acceptance_contract_hash,
    canonical_hash,
    change_manifest_hash,
    change_set_hash,
    evidence_bundle_hash,
    verification_plan_hash,
)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

ACQUISITION_RECEIPT_KIND = "NEXUS_CORE_CANDIDATE_ACQUISITION_RECEIPT"
ACQUISITION_RECEIPT_SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Public error type
# ---------------------------------------------------------------------------


class CandidateAcquisitionError(Exception):
    """Fail-closed typed error for candidate acquisition."""

    def __init__(
        self,
        reason_code: str,
        detail: str = "",
        *,
        receipt_path: Path | None = None,
    ) -> None:
        self.reason_code = reason_code
        self.detail = detail
        self.receipt_path = receipt_path
        super().__init__(f"{reason_code}{': ' + detail if detail else ''}")


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationAcquisitionProfile:
    """Hash-bound specification of which verifiers to run and how.

    ``profile_hash`` binds the entire profile; it is verified on every call
    and must match the caller's ``expected_profile_hash``.

    ``verifier_ids`` must be an exact (order-independent) set match against
    ``acceptance_contract["required_verifier_ids"]``; any mismatch is a
    fail-closed error.

    The canonical id→command mapping is sorted by verifier_id so the hash
    is unambiguous regardless of the caller-supplied tuple order.
    """

    profile_id: str
    verifier_ids: tuple[str, ...]
    # One command list per verifier_id, same positional order as verifier_ids.
    verifier_commands: tuple[tuple[str, ...], ...]
    timeout_seconds: int
    profile_hash: str

    def __post_init__(self) -> None:
        if len(self.verifier_ids) != len(self.verifier_commands):
            raise CandidateAcquisitionError(
                "PROFILE_INVALID",
                "verifier_ids and verifier_commands length mismatch",
            )
        if len(set(self.verifier_ids)) != len(self.verifier_ids):
            raise CandidateAcquisitionError(
                "PROFILE_INVALID",
                "verifier_ids must be unique",
            )


@dataclass(frozen=True)
class CandidateAcquisitionRequest:
    """All caller-supplied parameters for one acquisition run.

    The caller is responsible for computing and passing the hashes; this
    module re-derives them and fails closed if they do not match.
    """

    # Git identity for the candidate.
    candidate_head: str  # 40-hex commit SHA
    candidate_tree: str  # 40-hex tree SHA

    # Expected source identity (parent / base commit SHA, 40-hex).
    expected_source_identity: str

    # AcceptanceContract dict + caller-supplied hash.
    acceptance_contract: dict[str, Any]
    expected_contract_hash: str

    # VerificationAcquisitionProfile + caller-supplied hash.
    profile: VerificationAcquisitionProfile
    expected_profile_hash: str

    # Change-set hash (mandatory; re-derived and verified internally).
    expected_change_set_hash: str

    # Unique request identity + hash bound.
    acquisition_request_id: str
    request_hash: str

    # Filesystem locations.
    repo_path: Path
    receipt_directory: Path


@dataclass
class CandidateAcquisitionResult:
    """Completed acquisition result, including the receipt path."""

    request_id: str
    request_hash: str
    status: str
    reason_codes: list[str]
    core_response: dict[str, Any]
    receipt_path: Path
    replayed: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _validate_hash_shape(value: str, label: str) -> None:
    """Fail closed if ``value`` is not a valid sha256: prefixed hex hash."""
    import re as _re
    if not (
        isinstance(value, str)
        and _re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    ):
        raise CandidateAcquisitionError(
            "INVALID_HASH_SHAPE",
            f"{label} must match sha256:<64hex>, got {value!r}",
        )


def _run_git(
    cwd: Path,
    *args: str,
    env: Mapping[str, str] | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess[Any]:
    cmd_env = os.environ.copy()
    if env:
        cmd_env.update(env)
    try:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            env=cmd_env,
            capture_output=True,
            text=text,
            check=False,
        )
    except OSError as exc:
        raise CandidateAcquisitionError("GIT_UNAVAILABLE", str(exc)) from exc


def _git_stdout(cwd: Path, *args: str, env: Mapping[str, str] | None = None) -> str:
    result = _run_git(cwd, *args, env=env)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise CandidateAcquisitionError("GIT_COMMAND_FAILED", detail)
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Canonical profile hash (B: sort by verifier_id, pair ids with commands)
# ---------------------------------------------------------------------------


def _compute_profile_hash(profile: VerificationAcquisitionProfile) -> str:
    """Re-derive the canonical profile hash from its mutable-free content.

    The id→command mapping is sorted by verifier_id to produce an unambiguous
    canonical form regardless of the caller-supplied tuple order.  Sorting IDs
    alone (while leaving commands in positional order) would be ambiguous when
    two IDs are swapped; here we sort pairs so the command is always bound to
    its verifier_id.
    """
    id_cmd_pairs = sorted(
        zip(profile.verifier_ids, profile.verifier_commands),
        key=lambda p: p[0],
    )
    canonical = {
        "profile_id": profile.profile_id,
        "verifier_id_command_pairs": [
            [vid, list(cmd)] for vid, cmd in id_cmd_pairs
        ],
        "timeout_seconds": profile.timeout_seconds,
    }
    return canonical_hash(canonical)


# ---------------------------------------------------------------------------
# Canonical acquisition request hash (A: all material immutable inputs)
# ---------------------------------------------------------------------------


def _compute_acquisition_request_hash(
    *,
    acquisition_request_id: str,
    candidate_head: str,
    candidate_tree: str,
    expected_source_identity: str,
    expected_contract_hash: str,
    expected_profile_hash: str,
    expected_change_set_hash: str,
) -> str:
    """Compute the canonical acquisition request hash from all material inputs.

    This hash binds every immutable input that determines the effect of a
    candidate acquisition run.  Caller-supplied ``request_hash`` is validated
    against this re-derived value before any readback or execution.
    """
    return canonical_hash({
        "acquisition_request_id": acquisition_request_id,
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
        "expected_source_identity": expected_source_identity,
        "expected_contract_hash": expected_contract_hash,
        "expected_profile_hash": expected_profile_hash,
        "expected_change_set_hash": expected_change_set_hash,
    })


def _validate_request_hash(request: CandidateAcquisitionRequest) -> None:
    """Validate the caller-supplied request_hash matches the re-derived hash."""
    actual = _compute_acquisition_request_hash(
        acquisition_request_id=request.acquisition_request_id,
        candidate_head=request.candidate_head,
        candidate_tree=request.candidate_tree,
        expected_source_identity=request.expected_source_identity,
        expected_contract_hash=request.expected_contract_hash,
        expected_profile_hash=request.expected_profile_hash,
        expected_change_set_hash=request.expected_change_set_hash,
    )
    if actual != request.request_hash:
        raise CandidateAcquisitionError(
            "REQUEST_HASH_MISMATCH",
            f"caller request_hash {request.request_hash!r} does not match "
            f"re-derived {actual!r}",
        )


# ---------------------------------------------------------------------------
# Change manifest helpers
# ---------------------------------------------------------------------------


def _manifest_from_trees(
    repo: Path, source_tree: str, target_tree: str
) -> dict[str, Any]:
    """Compute a change manifest between two git tree SHAs."""
    result = _run_git(
        repo,
        "diff-tree",
        "--no-commit-id",
        "--raw",
        "-r",
        "--no-renames",
        "-z",
        source_tree,
        target_tree,
        text=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise CandidateAcquisitionError("GIT_MANIFEST_FAILED", detail)
    chunks = result.stdout.split(b"\0")
    entries: list[dict[str, Any]] = []
    index = 0
    while index < len(chunks) and chunks[index]:
        header = chunks[index]
        index += 1
        if index >= len(chunks):
            raise CandidateAcquisitionError("GIT_MANIFEST_MALFORMED", "missing path")
        path_bytes = chunks[index]
        index += 1
        try:
            metadata = header.decode("ascii")
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CandidateAcquisitionError(
                "GIT_MANIFEST_MALFORMED", "non-UTF-8 path"
            ) from exc
        fields = metadata.removeprefix(":").split()
        if len(fields) != 5:
            raise CandidateAcquisitionError("GIT_MANIFEST_MALFORMED", metadata)
        before_mode, after_mode, before_oid, after_oid, status = fields
        code = status[0]
        if code == "A":
            change_type = "ADD"
            before_oid_val: str | None = None
            before_mode_val: str | None = None
        elif code == "D":
            change_type = "DELETE"
            after_oid = ""
            after_mode = ""
            before_oid_val = before_oid
            before_mode_val = before_mode
        else:
            change_type = "MODIFY"
            before_oid_val = before_oid
            before_mode_val = before_mode
        entries.append(
            {
                "path": path,
                "change_type": change_type,
                "before_oid": before_oid_val,
                "after_oid": after_oid or None,
                "before_mode": before_mode_val,
                "after_mode": after_mode or None,
            }
        )
    return {
        "source_tree": f"git-tree:{source_tree}",
        "target_tree": f"git-tree:{target_tree}",
        "entries": sorted(entries, key=lambda e: e["path"]),
    }


# ---------------------------------------------------------------------------
# Verifier artifact builder
# ---------------------------------------------------------------------------


def _verifier_artifact(
    verifier_id: str,
    command: Sequence[str],
    returncode: int,
    stdout: bytes,
    stderr: bytes,
) -> dict[str, Any]:
    """Build a verifier artifact dict matching local Golden Path semantics."""
    output_hash = canonical_hash(
        {
            "stdout_sha256": _sha256_bytes(stdout),
            "stderr_sha256": _sha256_bytes(stderr),
        }
    )
    artifact: dict[str, Any] = {
        "verifier_id": verifier_id,
        "command": list(command),
        "exit_code": returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "stdout_hash": _sha256_bytes(stdout),
        "stderr_hash": _sha256_bytes(stderr),
        "output_hash": output_hash,
        "status": "PASS" if returncode == 0 else "FAIL",
    }
    artifact["artifact_hash"] = canonical_hash(
        {k: v for k, v in artifact.items() if k != "artifact_hash"}
    )
    return artifact


# ---------------------------------------------------------------------------
# Generic verification request builder
# ---------------------------------------------------------------------------


def _build_generic_request(
    contract: dict[str, Any],
    source_commit: str,
    source_tree: str,
    target_tree: str,
    manifest: dict[str, Any],
    artifacts: list[dict[str, Any]],
    request_id: str,
) -> dict[str, Any]:
    """Assemble the full generic verification request payload."""
    paths = [e["path"] for e in manifest["entries"]]
    deleted = [e["path"] for e in manifest["entries"] if e["change_type"] == "DELETE"]

    change_set = {
        "change_set_id": f"acq-change-{request_id[:16]}",
        "source_revision": f"git-commit:{source_commit}",
        "target_revision": f"git-tree:{target_tree}",
        "diff_hash": change_manifest_hash(manifest),
        "paths": paths,
        "deleted_paths": deleted,
    }
    plan = {
        "plan_id": f"acq-plan-{request_id[:16]}",
        "acceptance_contract_hash": acceptance_contract_hash(contract),
        "change_set_hash": change_set_hash(change_set),
        "required_verifier_ids": list(contract["required_verifier_ids"]),
    }
    observations = [
        {
            "verifier_id": art["verifier_id"],
            "artifact_id": f"acq-art-{art['verifier_id']}-{art['artifact_hash'].removeprefix('sha256:')[:16]}",
            "artifact_hash": art["artifact_hash"],
            "status": art["status"],
        }
        for art in artifacts
    ]
    evidence = {
        "bundle_id": f"acq-evidence-{request_id[:16]}",
        "acceptance_contract_hash": acceptance_contract_hash(contract),
        "change_set_hash": change_set_hash(change_set),
        "verification_plan_hash": verification_plan_hash(plan),
        "observations": observations,
        "claimed_bundle_hash": None,
    }
    evidence["claimed_bundle_hash"] = evidence_bundle_hash(evidence)
    return {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "schema": GENERIC_VERIFICATION_REQUEST_SCHEMA_ID,
        "acceptance_contract": contract,
        "change_set": change_set,
        "change_manifest": manifest,
        "verification_plan": plan,
        "evidence_bundle": evidence,
        "certification_policy": None,
    }


# ---------------------------------------------------------------------------
# Receipt helpers
# ---------------------------------------------------------------------------


def _receipt_hash_for(receipt: Mapping[str, Any]) -> str:
    return canonical_hash({k: v for k, v in receipt.items() if k != "receipt_hash"})


def _write_receipt(
    receipt_directory: Path,
    receipt: dict[str, Any],
) -> Path:
    receipt_directory.mkdir(parents=True, exist_ok=True)
    receipt["receipt_hash"] = _receipt_hash_for(receipt)
    stamp = (
        receipt["timestamp"]
        .replace("-", "")
        .replace(":", "")
        .replace("+00:00", "Z")
    )
    path = receipt_directory / f"{stamp}-{receipt['receipt_hash'][-12:]}.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Receipt readback / reconciliation
# ---------------------------------------------------------------------------


def _find_receipt_by_request_hash(
    receipt_directory: Path,
    request_hash: str,
) -> dict[str, Any] | None:
    """Return a previously written receipt matching ``request_hash``, or None.

    G: A receipt whose stored receipt_hash does NOT match the re-derived hash
    (tampered) for the *exact* request_hash is a fail-closed error rather than
    a silently skipped candidate for rerun.
    """
    if not receipt_directory.is_dir():
        return None
    for p in receipt_directory.glob("*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get("kind") != ACQUISITION_RECEIPT_KIND:
            continue
        if data.get("acquisition_request_hash") != request_hash:
            continue
        # G: Receipt hash matches the stored request_hash – integrity check is
        # mandatory.  A tampered receipt must fail closed, not be silently
        # skipped so the request reruns (which would be a false clean).
        stored_hash = data.get("receipt_hash")
        if stored_hash != _receipt_hash_for(data):
            raise CandidateAcquisitionError(
                "TAMPERED_RECEIPT",
                f"receipt at {p} matches request_hash but has invalid integrity",
                receipt_path=p,
            )
        return data
    return None


# ---------------------------------------------------------------------------
# Fail-closed validation helpers
# ---------------------------------------------------------------------------


def _validate_sha40(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or not all(c in "0123456789abcdef" for c in value)
    ):
        raise CandidateAcquisitionError(
            "INVALID_INPUT", f"{label} must be a 40-hex lowercase SHA"
        )


def _validate_contract_hash(
    contract: dict[str, Any], expected: str
) -> None:
    actual = acceptance_contract_hash(contract)
    if actual != expected:
        raise CandidateAcquisitionError(
            "CONTRACT_HASH_MISMATCH",
            f"expected {expected}, got {actual}",
        )


def _validate_profile_hash(
    profile: VerificationAcquisitionProfile, expected: str
) -> None:
    # B: validate that profile.profile_hash itself equals the recomputed hash
    # and that it equals expected_profile_hash.
    recomputed = _compute_profile_hash(profile)
    if profile.profile_hash != recomputed:
        raise CandidateAcquisitionError(
            "PROFILE_HASH_MISMATCH",
            f"profile.profile_hash {profile.profile_hash!r} does not match "
            f"re-derived {recomputed!r}",
        )
    if recomputed != expected:
        raise CandidateAcquisitionError(
            "PROFILE_HASH_MISMATCH",
            f"expected {expected}, got {recomputed}",
        )


def _validate_verifier_ids_exact(
    profile: VerificationAcquisitionProfile,
    contract: dict[str, Any],
) -> None:
    required = set(contract.get("required_verifier_ids", []))
    provided = set(profile.verifier_ids)
    if provided != required:
        raise CandidateAcquisitionError(
            "VERIFIER_ID_MISMATCH",
            f"profile verifier_ids {sorted(provided)} != "
            f"required_verifier_ids {sorted(required)}",
        )


# ---------------------------------------------------------------------------
# Worktree materialisation
# ---------------------------------------------------------------------------


def _materialize_detached_worktree(
    repo: Path,
    candidate_head: str,
    worktree_root: Path,
    suffix: str = "",
) -> Path:
    """Checkout ``candidate_head`` into an isolated detached worktree.

    Returns the worktree path.  The caller is responsible for cleanup.
    """
    label = f"candidate-{candidate_head[:12]}{suffix}"
    wt_path = worktree_root / label
    result = _run_git(
        repo,
        "worktree",
        "add",
        "--detach",
        str(wt_path),
        candidate_head,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise CandidateAcquisitionError(
            "WORKTREE_MATERIALIZATION_FAILED", detail
        )
    return wt_path


def _remove_worktree(repo: Path, wt_path: Path) -> None:
    """Remove a git worktree and its directory, raising on failure."""
    result = _run_git(repo, "worktree", "remove", "--force", str(wt_path))
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise CandidateAcquisitionError("CLEANUP_FAILED", detail)
    # Belt-and-suspenders: also remove the directory if still present.
    if wt_path.exists():
        try:
            shutil.rmtree(wt_path)
        except OSError as exc:
            raise CandidateAcquisitionError(
                "CLEANUP_FAILED",
                f"failed to remove worktree directory {wt_path}: {exc}",
            ) from exc


def _remove_temp_root(tmp_dir: Path) -> None:
    """Remove the now-empty acquisition temp root, failing closed on residue."""
    try:
        tmp_dir.rmdir()
    except OSError as exc:
        raise CandidateAcquisitionError(
            "CLEANUP_FAILED",
            f"failed to remove acquisition temp root {tmp_dir}: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# Worktree drift detection (F: physical scan, NOT HEAD^{tree})
# ---------------------------------------------------------------------------


def _check_physical_worktree_clean(wt_path: Path, candidate_tree: str) -> None:
    """Fail closed if the physical worktree has drifted from candidate_tree.

    Uses ``git diff-index --cached HEAD`` to detect staged changes, and
    ``git diff-files`` to detect unstaged tracked changes.  Untracked files
    are explicitly removed to prevent contamination of subsequent verifiers
    (they cannot alter the tree hash but could influence verifier behaviour).

    Intentionally does NOT use ``HEAD^{tree}`` which only reads the committed
    tree and cannot observe worktree file mutations.
    """
    # Check for tracked modifications (staged or unstaged).
    staged = _run_git(wt_path, "diff-index", "--cached", "--name-only", "HEAD")
    if staged.returncode != 0:
        raise CandidateAcquisitionError(
            "CANDIDATE_TREE_DRIFT",
            f"git diff-index failed: {staged.stderr.strip()}",
        )
    if staged.stdout.strip():
        raise CandidateAcquisitionError(
            "CANDIDATE_TREE_DRIFT",
            f"tracked staged changes detected: {staged.stdout.strip()!r}",
        )

    unstaged = _run_git(wt_path, "diff-files", "--name-only")
    if unstaged.returncode != 0:
        raise CandidateAcquisitionError(
            "CANDIDATE_TREE_DRIFT",
            f"git diff-files failed: {unstaged.stderr.strip()}",
        )
    if unstaged.stdout.strip():
        raise CandidateAcquisitionError(
            "CANDIDATE_TREE_DRIFT",
            f"tracked file modifications detected: {unstaged.stdout.strip()!r}",
        )

    # Remove untracked files before this isolated verifier worktree is
    # destroyed.  Treat cleanup failure as material rather than silently
    # claiming the isolation boundary was cleaned.
    cleaned = _run_git(wt_path, "clean", "-fdx", "--quiet")
    if cleaned.returncode != 0:
        detail = (cleaned.stderr or cleaned.stdout).strip()
        raise CandidateAcquisitionError("CLEANUP_FAILED", detail)


# ---------------------------------------------------------------------------
# Source lineage validation (D)
# ---------------------------------------------------------------------------


def _validate_source_lineage(
    repo: Path, source_commit: str, candidate_head: str
) -> None:
    """Fail closed unless ``source_commit`` is an ancestor of ``candidate_head``."""
    result = _run_git(
        repo,
        "merge-base",
        "--is-ancestor",
        source_commit,
        candidate_head,
    )
    if result.returncode != 0:
        raise CandidateAcquisitionError(
            "SOURCE_NOT_ANCESTOR",
            f"{source_commit} is not an ancestor of {candidate_head}",
        )


# ---------------------------------------------------------------------------
# Readback material cross-bind (H)
# ---------------------------------------------------------------------------


def _validate_receipt_material_crossbind(
    receipt: dict[str, Any], request: CandidateAcquisitionRequest
) -> None:
    """Cross-bind all material fields between a replayed receipt and the request.

    Checks: request_id, candidate_head, candidate_tree, source_identity,
    contract_hash, profile_hash, change_set_hash.  Any mismatch fails closed
    with REPLAY_MATERIAL_MISMATCH even though the receipt_hash is valid.
    """
    mismatches: list[str] = []

    def _check(field: str, stored: Any, current: Any) -> None:
        if stored != current:
            mismatches.append(
                f"{field}: stored={stored!r} != current={current!r}"
            )

    _check("acquisition_request_id",
           receipt.get("acquisition_request_id"),
           request.acquisition_request_id)
    _check("candidate_head",
           receipt.get("candidate_head"),
           request.candidate_head)
    _check("candidate_tree",
           receipt.get("candidate_tree"),
           request.candidate_tree)
    _check("source_identity",
           receipt.get("source_identity"),
           request.expected_source_identity)
    _check("contract_hash",
           receipt.get("contract_hash"),
           request.expected_contract_hash)
    _check("profile_hash",
           receipt.get("profile_hash"),
           request.expected_profile_hash)
    _check("change_set_hash",
           receipt.get("change_set_hash"),
           request.expected_change_set_hash)

    if mismatches:
        raise CandidateAcquisitionError(
            "REPLAY_MATERIAL_MISMATCH",
            "; ".join(mismatches),
        )


# ---------------------------------------------------------------------------
# Primary public API
# ---------------------------------------------------------------------------


def acquire_and_verify_candidate(
    request: CandidateAcquisitionRequest,
) -> CandidateAcquisitionResult:
    """Materialise, verify, and receipt an exact candidate.

    Fail-closed contract:
    A. Re-derive and validate request_hash from all material inputs BEFORE
       any readback or execution.  Same ID/hash with different material fails.
    B. Re-derive profile hash; confirm profile.profile_hash == recomputed ==
       expected_profile_hash.
    C. expected_change_set_hash is mandatory; validate hash shape.
    D. Validate source lineage: expected_source_identity must be ancestor of
       candidate_head.
    E. Each verifier runs in a fresh clean materialisation of the same
       candidate so no side-effect leaks between verifiers.
    F. After each verifier detect physical worktree drift via full worktree
       scan, NOT HEAD^{tree}.  Untracked artifacts are cleaned so they cannot
       contaminate subsequent verifiers.
    G. A tampered matching receipt (valid request_hash but bad receipt_hash)
       fails closed rather than being silently skipped.
    H. Readback cross-binds all receipt material to the current request before
       returning.
    I. Cleanup failure is propagated as CLEANUP_FAILED, not silently swallowed.

    If a completed receipt already exists for the same ``request_hash``,
    return it without rerunning (exact readback) after cross-binding.
    """
    # -----------------------------------------------------------------------
    # A. Validate hash shapes up front before any other work.
    # -----------------------------------------------------------------------
    _validate_hash_shape(request.expected_contract_hash, "expected_contract_hash")
    _validate_hash_shape(request.expected_profile_hash, "expected_profile_hash")
    # C: expected_change_set_hash is mandatory; validate shape.
    if not request.expected_change_set_hash:
        raise CandidateAcquisitionError(
            "MISSING_CHANGE_SET_HASH",
            "expected_change_set_hash is mandatory",
        )
    _validate_hash_shape(request.expected_change_set_hash, "expected_change_set_hash")

    # A: Validate caller-bound request identity and the physical request
    # material BEFORE any readback.  Expected hashes are not authority by
    # themselves: the actual contract/profile contents must match them first.
    _validate_request_hash(request)
    _validate_sha40(request.candidate_head, "candidate_head")
    _validate_sha40(request.candidate_tree, "candidate_tree")
    _validate_sha40(request.expected_source_identity, "expected_source_identity")
    _validate_contract_hash(request.acceptance_contract, request.expected_contract_hash)
    _validate_profile_hash(request.profile, request.expected_profile_hash)
    _validate_verifier_ids_exact(request.profile, request.acceptance_contract)

    # -----------------------------------------------------------------------
    # G+H: Exact readback only after all caller-supplied request material has
    # been validated against its bound hashes.
    # -----------------------------------------------------------------------
    existing = _find_receipt_by_request_hash(
        request.receipt_directory, request.request_hash
    )
    if existing is not None:
        stored_rid = existing.get("acquisition_request_id", "")
        if stored_rid != request.acquisition_request_id:
            raise CandidateAcquisitionError(
                "REPLAY_CONFLICT",
                f"request_hash {request.request_hash!r} is bound to "
                f"request_id {stored_rid!r}, not {request.acquisition_request_id!r}",
            )
        _validate_receipt_material_crossbind(existing, request)
        core_resp = existing.get("core_response") or {}
        verif = core_resp.get("verification") or {}
        return CandidateAcquisitionResult(
            request_id=request.acquisition_request_id,
            request_hash=request.request_hash,
            status=verif.get("status", "UNKNOWN"),
            reason_codes=list(verif.get("reason_codes", [])),
            core_response=core_resp,
            receipt_path=request.receipt_directory
            / _receipt_path_for(existing),
            replayed=True,
        )

    repo = request.repo_path.resolve()

    # -----------------------------------------------------------------------
    # 4. Determine source tree from the expected_source_identity commit.
    # -----------------------------------------------------------------------
    source_tree_result = _run_git(
        repo, "rev-parse", f"{request.expected_source_identity}^{{tree}}"
    )
    if source_tree_result.returncode != 0:
        raise CandidateAcquisitionError(
            "SOURCE_IDENTITY_UNRESOLVABLE",
            f"cannot resolve tree for {request.expected_source_identity}",
        )
    source_tree = source_tree_result.stdout.strip()

    # D: Validate source lineage.
    _validate_source_lineage(repo, request.expected_source_identity, request.candidate_head)

    # -----------------------------------------------------------------------
    # 5. Build change manifest (before worktree materialisation so we can
    #    validate change_set_hash early).
    # -----------------------------------------------------------------------
    manifest = _manifest_from_trees(repo, source_tree, request.candidate_tree)

    # C: Validate change-set hash (mandatory).
    paths = [e["path"] for e in manifest["entries"]]
    deleted = [e["path"] for e in manifest["entries"] if e["change_type"] == "DELETE"]
    change_set_proto = {
        "change_set_id": f"acq-change-{request.acquisition_request_id[:16]}",
        "source_revision": f"git-commit:{request.expected_source_identity}",
        "target_revision": f"git-tree:{request.candidate_tree}",
        "diff_hash": change_manifest_hash(manifest),
        "paths": paths,
        "deleted_paths": deleted,
    }
    actual_cs_hash = change_set_hash(change_set_proto)
    if actual_cs_hash != request.expected_change_set_hash:
        raise CandidateAcquisitionError(
            "CHANGE_SET_HASH_MISMATCH",
            f"expected {request.expected_change_set_hash}, got {actual_cs_hash}",
        )

    # -----------------------------------------------------------------------
    # 6. Execute each verifier in a fresh isolated worktree (E).
    # -----------------------------------------------------------------------
    # Build the sorted id→command mapping (B: canonical order).
    id_cmd_pairs = sorted(
        zip(request.profile.verifier_ids, request.profile.verifier_commands),
        key=lambda p: p[0],
    )

    artifacts: list[dict[str, Any]] = []
    verifier_env = os.environ.copy()
    verifier_env.setdefault("PYTHONDONTWRITEBYTECODE", "1")

    tmp_dir = tempfile.mkdtemp(prefix="nexus-core-candidate-acq-")
    try:
        for idx, (verifier_id, command) in enumerate(id_cmd_pairs):
            # E: Fresh materialisation per verifier.
            wt_path = _materialize_detached_worktree(
                repo,
                request.candidate_head,
                Path(tmp_dir),
                suffix=f"-v{idx}",
            )
            try:
                # Confirm the checked-out tree SHA matches the declared candidate_tree.
                # Use write-tree (indexes the worktree) rather than HEAD^{tree}.
                actual_tree = _git_stdout(wt_path, "rev-parse", "HEAD^{tree}")
                if actual_tree != request.candidate_tree:
                    raise CandidateAcquisitionError(
                        "CANDIDATE_TREE_MISMATCH",
                        f"expected tree {request.candidate_tree}, got {actual_tree}",
                    )

                cmd = list(command)
                local_env = dict(verifier_env)
                if cmd[:3] == [cmd[0], "-m", "pytest"]:
                    existing_opts = local_env.get("PYTEST_ADDOPTS", "")
                    local_env["PYTEST_ADDOPTS"] = (
                        existing_opts + " -p no:cacheprovider"
                    ).strip()
                try:
                    executed = subprocess.run(
                        cmd,
                        cwd=wt_path,
                        env=local_env,
                        capture_output=True,
                        timeout=request.profile.timeout_seconds,
                        check=False,
                    )
                except subprocess.TimeoutExpired as exc:
                    raise CandidateAcquisitionError(
                        "VERIFIER_TIMEOUT",
                        f"{verifier_id}: {exc}",
                    ) from exc
                except OSError as exc:
                    raise CandidateAcquisitionError(
                        "VERIFIER_EXECUTION_FAILED",
                        f"{verifier_id}: {exc}",
                    ) from exc

                # F: Detect physical worktree drift after this verifier.
                # Untracked artifacts are also cleaned so they cannot
                # contaminate the next verifier's fresh materialisation.
                _check_physical_worktree_clean(wt_path, request.candidate_tree)

                artifacts.append(
                    _verifier_artifact(
                        verifier_id,
                        cmd,
                        executed.returncode,
                        executed.stdout,
                        executed.stderr,
                    )
                )
            finally:
                # I: Cleanup is always Core-owned here; callers cannot replace
                # it with a no-op hook.  Failures propagate as CLEANUP_FAILED.
                _remove_worktree(repo, wt_path)

    finally:
        _remove_temp_root(Path(tmp_dir))

    # -----------------------------------------------------------------------
    # 7. Build generic verification request and call Core.
    # -----------------------------------------------------------------------
    generic_request = _build_generic_request(
        contract=request.acceptance_contract,
        source_commit=request.expected_source_identity,
        source_tree=source_tree,
        target_tree=request.candidate_tree,
        manifest=manifest,
        artifacts=artifacts,
        request_id=request.acquisition_request_id,
    )
    http_status, core_response = verify_generic_changeset(generic_request)

    # -----------------------------------------------------------------------
    # 8. Write hash-bound Core-owned receipt.
    # -----------------------------------------------------------------------
    timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    outcome_status: str
    reason_codes: list[str]
    if http_status != 200:
        outcome_status = "FAILED_CLOSED"
        reason_codes = [
            core_response.get("error", {}).get("code", "CORE_REQUEST_REJECTED")
        ]
    else:
        verif = core_response["verification"]
        outcome_status = verif["status"]
        reason_codes = list(verif["reason_codes"])

    receipt: dict[str, Any] = {
        "schema_version": ACQUISITION_RECEIPT_SCHEMA_VERSION,
        "kind": ACQUISITION_RECEIPT_KIND,
        "timestamp": timestamp,
        "acquisition_request_id": request.acquisition_request_id,
        "acquisition_request_hash": request.request_hash,
        "candidate_head": request.candidate_head,
        "candidate_tree": request.candidate_tree,
        "source_identity": request.expected_source_identity,
        "contract_hash": request.expected_contract_hash,
        "profile_hash": request.expected_profile_hash,
        "change_set_hash": actual_cs_hash,
        "change_manifest_hash": change_manifest_hash(manifest),
        "core_response": core_response,
        "outcome": {
            "status": outcome_status,
            "reason_codes": reason_codes,
        },
    }
    receipt_path = _write_receipt(request.receipt_directory, receipt)

    return CandidateAcquisitionResult(
        request_id=request.acquisition_request_id,
        request_hash=request.request_hash,
        status=outcome_status,
        reason_codes=reason_codes,
        core_response=core_response,
        receipt_path=receipt_path,
        replayed=False,
    )


# ---------------------------------------------------------------------------
# Receipt validation
# ---------------------------------------------------------------------------


def validate_candidate_acquisition_receipt(
    receipt_path: str | Path,
) -> dict[str, Any]:
    """Independently validate a candidate acquisition receipt.

    Checks:
    * ``kind`` and ``schema_version`` are correct.
    * ``receipt_hash`` matches re-derived hash (tamper detection).

    Returns ``{"valid": bool, "reason_codes": [...]}``
    """
    reasons: list[str] = []
    try:
        data = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
    if not isinstance(data, dict):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
    if (
        data.get("kind") != ACQUISITION_RECEIPT_KIND
        or data.get("schema_version") != ACQUISITION_RECEIPT_SCHEMA_VERSION
    ):
        reasons.append("UNSUPPORTED_RECEIPT")
    stored_hash = data.get("receipt_hash")
    if stored_hash != _receipt_hash_for(data):
        reasons.append("RECEIPT_HASH_MISMATCH")
    return {"valid": not reasons, "reason_codes": sorted(set(reasons))}


# ---------------------------------------------------------------------------
# Internal helper used by readback
# ---------------------------------------------------------------------------


def _receipt_path_for(receipt: dict[str, Any]) -> str:
    """Reconstruct the receipt filename from a parsed receipt dict."""
    stamp = (
        receipt.get("timestamp", "")
        .replace("-", "")
        .replace(":", "")
        .replace("+00:00", "Z")
    )
    rh = receipt.get("receipt_hash", "")
    return f"{stamp}-{rh[-12:]}.json"


__all__ = [
    "ACQUISITION_RECEIPT_KIND",
    "ACQUISITION_RECEIPT_SCHEMA_VERSION",
    "CandidateAcquisitionError",
    "CandidateAcquisitionRequest",
    "CandidateAcquisitionResult",
    "VerificationAcquisitionProfile",
    "acquire_and_verify_candidate",
    "validate_candidate_acquisition_receipt",
]
