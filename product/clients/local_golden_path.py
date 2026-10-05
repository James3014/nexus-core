"""Local-first product shell over the canonical generic verification adapter.

This module acquires Git identity and verifier evidence. It deliberately delegates
the factual verdict to :func:`verify_generic_changeset`; it is not a second
verification, receipt, policy, execution-routing, or certification authority.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
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

CONFIG_DIRECTORY = ".nexus-core"
CONFIG_FILENAME = "config.toml"
RECEIPT_KIND = "NEXUS_CORE_LOCAL_VERIFICATION_RECEIPT"
RECEIPT_SCHEMA_VERSION = 1
CONFIG_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 300
_CONFIG_KEYS = {
    "version",
    "base_ref",
    "allowed_patterns",
    "deletion_policy",
    "verifier_command",
    "timeout_seconds",
}


class LocalCheckError(Exception):
    """Typed fail-closed product-shell error."""

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


@dataclass(frozen=True)
class _GitSnapshot:
    source_commit: str
    source_tree: str
    target_tree: str
    manifest: dict[str, Any]


def _product_version() -> str:
    try:
        return version("nexus-certify")
    except PackageNotFoundError:
        return "0+unknown"


def _run_git(
    repo: Path,
    *args: str,
    env: Mapping[str, str] | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess[Any]:
    command_env = os.environ.copy()
    if env:
        command_env.update(env)
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            env=command_env,
            capture_output=True,
            text=text,
            check=False,
        )
    except OSError as exc:
        raise LocalCheckError("GIT_UNAVAILABLE", str(exc)) from exc


def _git_stdout(repo: Path, *args: str, env: Mapping[str, str] | None = None) -> str:
    result = _run_git(repo, *args, env=env)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise LocalCheckError("GIT_COMMAND_FAILED", detail)
    return result.stdout.strip()


def _repo_root(path: str | Path) -> Path:
    candidate = Path(path).resolve()
    result = _run_git(candidate, "rev-parse", "--show-toplevel")
    if result.returncode != 0:
        raise LocalCheckError("NOT_A_GIT_REPOSITORY", (result.stderr or "").strip())
    return Path(result.stdout.strip()).resolve()


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _toml_array(values: Sequence[str]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def init_repository(
    path: str | Path = ".",
    *,
    base_ref: str = "main",
    allowed_patterns: Sequence[str] = ("**",),
    deletion_policy: str = "FORBID",
    verifier_command: Sequence[str] = ("python", "-m", "pytest", "-q"),
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    force: bool = False,
) -> Path:
    """Create the minimal versioned local-product config."""

    repo = _repo_root(path)
    config_path = repo / CONFIG_DIRECTORY / CONFIG_FILENAME
    if config_path.exists() and not force:
        raise LocalCheckError("CONFIG_EXISTS", str(config_path))
    config = {
        "version": CONFIG_VERSION,
        "base_ref": base_ref,
        "allowed_patterns": list(allowed_patterns),
        "deletion_policy": deletion_policy,
        "verifier_command": list(verifier_command),
        "timeout_seconds": timeout_seconds,
    }
    _validate_config(config)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(
        (
            f"version = {CONFIG_VERSION}",
            f"base_ref = {_toml_string(base_ref)}",
            f"allowed_patterns = {_toml_array(tuple(allowed_patterns))}",
            f"deletion_policy = {_toml_string(deletion_policy)}",
            f"verifier_command = {_toml_array(tuple(verifier_command))}",
            f"timeout_seconds = {timeout_seconds}",
            "",
        )
    )
    config_path.write_text(content, encoding="utf-8")
    return config_path


def _validate_config(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _CONFIG_KEYS:
        raise LocalCheckError("INVALID_CONFIG", "unexpected or missing config keys")
    if value["version"] != CONFIG_VERSION:
        raise LocalCheckError("INVALID_CONFIG", "unsupported config version")
    if not isinstance(value["base_ref"], str) or not value["base_ref"].strip():
        raise LocalCheckError("INVALID_CONFIG", "base_ref must be non-empty")
    patterns = value["allowed_patterns"]
    if (
        not isinstance(patterns, list)
        or not patterns
        or any(
            not isinstance(item, str)
            or not item
            or item.startswith("/")
            or "\\" in item
            or "\x00" in item
            for item in patterns
        )
    ):
        raise LocalCheckError("INVALID_CONFIG", "allowed_patterns must be relative globs")
    if value["deletion_policy"] not in {"FORBID", "ALLOW"}:
        raise LocalCheckError("INVALID_CONFIG", "deletion_policy must be FORBID or ALLOW")
    command = value["verifier_command"]
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(item, str) or not item or "\x00" in item for item in command)
    ):
        raise LocalCheckError("INVALID_CONFIG", "verifier_command must be a non-empty array")
    timeout = value["timeout_seconds"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1 or timeout > 3600:
        raise LocalCheckError("INVALID_CONFIG", "timeout_seconds must be between 1 and 3600")
    return value


def _load_config(repo: Path) -> dict[str, Any]:
    path = repo / CONFIG_DIRECTORY / CONFIG_FILENAME
    if not path.is_file():
        raise LocalCheckError("CONFIG_MISSING", str(path))
    try:
        with path.open("rb") as handle:
            return _validate_config(tomllib.load(handle))
    except LocalCheckError:
        raise
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise LocalCheckError("INVALID_CONFIG", str(exc)) from exc


def _command_available(repo: Path, command: Sequence[str]) -> bool:
    executable = command[0]
    if "/" in executable:
        target = Path(executable)
        if not target.is_absolute():
            target = repo / target
        return target.is_file() and os.access(target, os.X_OK)
    return shutil.which(executable) is not None


def _resolve_base_and_head(repo: Path, base_ref: str) -> tuple[str, str]:
    base = _run_git(repo, "rev-parse", "--verify", f"{base_ref}^{{commit}}")
    if base.returncode != 0:
        raise LocalCheckError("BASE_REF_UNRESOLVED", base_ref)
    source_commit = base.stdout.strip()
    head = _git_stdout(repo, "rev-parse", "HEAD^{commit}")
    ancestor = _run_git(repo, "merge-base", "--is-ancestor", source_commit, head)
    if ancestor.returncode == 1:
        raise LocalCheckError("BASE_REF_NOT_ANCESTOR", base_ref)
    if ancestor.returncode != 0:
        detail = (ancestor.stderr or ancestor.stdout).strip()
        raise LocalCheckError("GIT_COMMAND_FAILED", detail)
    return source_commit, head


def doctor_repository(path: str | Path = ".") -> dict[str, Any]:
    """Read-only diagnosis for the local Golden Path."""

    checks: dict[str, str] = {}
    reasons: list[str] = []
    try:
        repo = _repo_root(path)
        checks["git"] = "OK"
    except LocalCheckError as exc:
        return {
            "healthy": False,
            "checks": {"git": "ERROR"},
            "reason_codes": [exc.reason_code],
        }
    try:
        config = _load_config(repo)
        checks["config"] = "OK"
    except LocalCheckError as exc:
        checks["config"] = "ERROR"
        reasons.append(exc.reason_code)
        return {"healthy": False, "checks": checks, "reason_codes": reasons}

    try:
        _resolve_base_and_head(repo, config["base_ref"])
        checks["base_ref"] = "OK"
    except LocalCheckError as exc:
        checks["base_ref"] = "ERROR"
        reasons.append(exc.reason_code)
    if _command_available(repo, config["verifier_command"]):
        checks["verifier"] = "OK"
    else:
        checks["verifier"] = "ERROR"
        reasons.append("VERIFIER_UNAVAILABLE")
    checks["python"] = "OK" if shutil.which("python") or shutil.which("python3") else "ERROR"
    if checks["python"] == "ERROR":
        reasons.append("PYTHON_UNAVAILABLE")
    status = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    checks["change_discovery"] = "OK" if status.returncode == 0 else "ERROR"
    if status.returncode != 0:
        reasons.append("CHANGES_UNDISCOVERABLE")
    checks["cleanliness"] = "DIRTY" if status.stdout.strip() else "CLEAN"
    return {"healthy": not reasons, "checks": checks, "reason_codes": sorted(set(reasons))}


def _materialize_target_tree(repo: Path, head: str) -> str:
    with tempfile.TemporaryDirectory(prefix="nexus-core-index-") as directory:
        index_path = Path(directory) / "index"
        env = {"GIT_INDEX_FILE": str(index_path)}
        _git_stdout(repo, "read-tree", head, env=env)
        add = _run_git(repo, "add", "-A", "--", ".", env=env)
        if add.returncode != 0:
            raise LocalCheckError("GIT_TARGET_MATERIALIZATION_FAILED", add.stderr.strip())

        restore_control_state = _run_git(
            repo,
            "reset",
            "--quiet",
            head,
            "--",
            CONFIG_DIRECTORY,
            env=env,
        )
        if restore_control_state.returncode != 0:
            raise LocalCheckError(
                "GIT_TARGET_MATERIALIZATION_FAILED",
                restore_control_state.stderr.strip(),
            )
        return _git_stdout(repo, "write-tree", env=env)


def _manifest_from_trees(repo: Path, source_tree: str, target_tree: str) -> dict[str, Any]:
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
        raise LocalCheckError("GIT_MANIFEST_FAILED", detail)
    chunks = result.stdout.split(b"\0")
    entries: list[dict[str, Any]] = []
    index = 0
    while index < len(chunks) and chunks[index]:
        header = chunks[index]
        index += 1
        if index >= len(chunks):
            raise LocalCheckError("GIT_MANIFEST_MALFORMED", "missing path")
        path_bytes = chunks[index]
        index += 1
        try:
            metadata = header.decode("ascii")
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LocalCheckError("GIT_MANIFEST_MALFORMED", "non-UTF-8 path") from exc
        fields = metadata.removeprefix(":").split()
        if len(fields) != 5:
            raise LocalCheckError("GIT_MANIFEST_MALFORMED", metadata)
        before_mode, after_mode, before_oid, after_oid, status = fields
        code = status[0]
        if code == "A":
            change_type = "ADD"
            before_oid_value = None
            before_mode_value = None
        elif code == "D":
            change_type = "DELETE"
            after_oid = ""
            after_mode = ""
            before_oid_value = before_oid
            before_mode_value = before_mode
        else:
            change_type = "MODIFY"
            before_oid_value = before_oid
            before_mode_value = before_mode
        entries.append(
            {
                "path": path,
                "change_type": change_type,
                "before_oid": before_oid_value,
                "after_oid": after_oid or None,
                "before_mode": before_mode_value,
                "after_mode": after_mode or None,
            }
        )
    return {
        "source_tree": f"git-tree:{source_tree}",
        "target_tree": f"git-tree:{target_tree}",
        "entries": sorted(entries, key=lambda item: item["path"]),
    }


def _check_ignored_residue(repo: Path) -> None:
    ignored = _run_git(
        repo,
        "ls-files",
        "--others",
        "--ignored",
        "--exclude-standard",
        "-z",
        text=False,
    )
    if ignored.returncode != 0:
        raise LocalCheckError("GIT_COMMAND_FAILED", "failed to list ignored files")

    ignored_paths = []
    if ignored.stdout:
        for p in ignored.stdout.split(b"\0"):
            if not p:
                continue
            try:
                path_str = p.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise LocalCheckError("IGNORED_RESIDUE", "non-UTF-8 path") from exc
            if path_str == CONFIG_DIRECTORY or path_str.startswith(f"{CONFIG_DIRECTORY}/"):
                continue
            ignored_paths.append(path_str)

    if ignored_paths:
        raise LocalCheckError("IGNORED_RESIDUE", ", ".join(ignored_paths))


def _snapshot(repo: Path, base_ref: str) -> _GitSnapshot:
    source_commit, head = _resolve_base_and_head(repo, base_ref)

    _check_ignored_residue(repo)

    source_tree = _git_stdout(repo, "rev-parse", f"{source_commit}^{{tree}}")
    target_tree = _materialize_target_tree(repo, head)
    manifest = _manifest_from_trees(repo, source_tree, target_tree)
    if not manifest["entries"]:
        raise LocalCheckError("NO_CHANGES", f"no changes from {base_ref}")
    return _GitSnapshot(source_commit, source_tree, target_tree, manifest)


def _path_allowed(path: str, patterns: Sequence[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(path, pattern)
        or (pattern.endswith("/**") and path == pattern.removesuffix("/**"))
        for pattern in patterns
    )


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _verifier_artifact(
    command: Sequence[str],
    returncode: int,
    stdout: bytes,
    stderr: bytes,
    *,
    execution_subject: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    output_hash = canonical_hash(
        {
            "stdout_sha256": _sha256_bytes(stdout),
            "stderr_sha256": _sha256_bytes(stderr),
        }
    )
    artifact = {
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
    if execution_subject is not None:
        artifact["execution_subject"] = dict(execution_subject)
    artifact["artifact_hash"] = canonical_hash(artifact)
    return artifact


def _cleanup_verifier_sandbox(path: Path) -> None:
    shutil.rmtree(path)


def _run_verifier_isolated(
    repo: Path,
    snapshot: _GitSnapshot,
    command: Sequence[str],
    verifier_env: Mapping[str, str],
    timeout_seconds: int,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any], str | None]:
    """Run the verifier against an isolated exact-target Git subject.

    The clone has independent refs/index/worktree state while sharing immutable
    object storage with the source repository. The original repository remains
    the canonical ChangeSet subject and is re-read after verifier completion.
    """

    source_head = _git_stdout(repo, "rev-parse", "HEAD^{commit}")
    execution_subject = {
        "mode": "isolated_shared_clone",
        "source_head": f"git-commit:{source_head}",
        "target_tree": f"git-tree:{snapshot.target_tree}",
    }
    parent = Path(tempfile.mkdtemp(prefix="nexus-core-verifier-"))
    verifier_repo = parent / "repo"
    executed: subprocess.CompletedProcess[bytes] | None = None
    execution_error: subprocess.TimeoutExpired | OSError | None = None
    mutation_detail: str | None = None
    cleanup_error: str | None = None

    try:
        clone = _run_git(
            repo,
            "clone",
            "--no-checkout",
            "--shared",
            "--quiet",
            str(repo),
            str(verifier_repo),
        )
        if clone.returncode != 0:
            detail = (clone.stderr or clone.stdout).strip()
            raise LocalCheckError("VERIFIER_SANDBOX_PREPARE_FAILED", detail)

        checkout = _run_git(
            verifier_repo,
            "checkout",
            "--detach",
            "--quiet",
            source_head,
        )
        if checkout.returncode != 0:
            detail = (checkout.stderr or checkout.stdout).strip()
            raise LocalCheckError("VERIFIER_SANDBOX_PREPARE_FAILED", detail)

        materialize = _run_git(
            verifier_repo,
            "read-tree",
            "--reset",
            "-u",
            snapshot.target_tree,
        )
        if materialize.returncode != 0:
            detail = (materialize.stderr or materialize.stdout).strip()
            raise LocalCheckError("VERIFIER_SANDBOX_PREPARE_FAILED", detail)
        if _git_stdout(verifier_repo, "write-tree") != snapshot.target_tree:
            raise LocalCheckError(
                "VERIFIER_SANDBOX_PREPARE_FAILED",
                "isolated verifier index does not match target tree",
            )

        try:
            executed = subprocess.run(
                command,
                cwd=verifier_repo,
                env=dict(verifier_env),
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            execution_error = exc

        if execution_error is None:
            problems: list[str] = []
            post_head = _git_stdout(verifier_repo, "rev-parse", "HEAD^{commit}")
            if post_head != source_head:
                problems.append("verifier changed isolated HEAD")
            post_index = _git_stdout(verifier_repo, "write-tree")
            if post_index != snapshot.target_tree:
                problems.append("verifier changed isolated index")

            worktree_diff = _run_git(verifier_repo, "diff", "--quiet", "--")
            if worktree_diff.returncode == 1:
                problems.append("verifier changed tracked target bytes")
            elif worktree_diff.returncode != 0:
                detail = (worktree_diff.stderr or worktree_diff.stdout).strip()
                raise LocalCheckError("VERIFIER_SANDBOX_INSPECTION_FAILED", detail)

            untracked = _run_git(
                verifier_repo,
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                text=False,
            )
            if untracked.returncode != 0:
                detail = untracked.stderr.decode("utf-8", errors="replace").strip()
                raise LocalCheckError("VERIFIER_SANDBOX_INSPECTION_FAILED", detail)
            untracked_paths = [
                value.decode("utf-8", errors="replace")
                for value in untracked.stdout.split(b"\0")
                if value
            ]
            untracked_paths = [
                path
                for path in untracked_paths
                if path != CONFIG_DIRECTORY
                and not path.startswith(f"{CONFIG_DIRECTORY}/")
            ]
            if untracked_paths:
                problems.append(
                    "verifier created non-ignored files: " + ", ".join(untracked_paths[:20])
                )

            if problems:
                mutation_detail = "; ".join(problems)
    finally:
        try:
            _cleanup_verifier_sandbox(parent)
        except OSError as exc:
            cleanup_error = str(exc)

    if cleanup_error is not None:
        raise LocalCheckError("VERIFIER_SANDBOX_CLEANUP_FAILED", cleanup_error)
    if execution_error is not None:
        raise execution_error
    if executed is None:
        raise LocalCheckError("VERIFIER_EXECUTION_FAILED", "verifier did not execute")
    return executed, execution_subject, mutation_detail


def _build_request(
    config: Mapping[str, Any],
    config_hash: str,
    snapshot: _GitSnapshot,
    verifier: Mapping[str, Any],
    *,
    requirements_hash: str | None = None,
) -> dict[str, Any]:
    paths = [entry["path"] for entry in snapshot.manifest["entries"]]
    deleted = [
        entry["path"] for entry in snapshot.manifest["entries"] if entry["change_type"] == "DELETE"
    ]
    contract = {
        "contract_id": f"local-contract-{config_hash.removeprefix('sha256:')[:16]}",
        "requirements_hash": requirements_hash or config_hash,
        "required_verifier_ids": ["local-command"],
        "allowed_paths": paths,
        "deletion_policy": config["deletion_policy"],
    }
    change_set = {
        "change_set_id": f"local-change-{snapshot.target_tree[:16]}",
        "source_revision": f"git-commit:{snapshot.source_commit}",
        "target_revision": f"git-tree:{snapshot.target_tree}",
        "diff_hash": change_manifest_hash(snapshot.manifest),
        "paths": paths,
        "deleted_paths": deleted,
    }
    plan = {
        "plan_id": f"local-plan-{snapshot.target_tree[:16]}",
        "acceptance_contract_hash": acceptance_contract_hash(contract),
        "change_set_hash": change_set_hash(change_set),
        "required_verifier_ids": ["local-command"],
    }
    evidence = {
        "bundle_id": f"local-evidence-{snapshot.target_tree[:16]}",
        "acceptance_contract_hash": plan["acceptance_contract_hash"],
        "change_set_hash": plan["change_set_hash"],
        "verification_plan_hash": verification_plan_hash(plan),
        "observations": [
            {
                "verifier_id": "local-command",
                "artifact_id": f"local-command-{verifier['artifact_hash'].removeprefix('sha256:')[:16]}",
                "artifact_hash": verifier["artifact_hash"],
                "status": verifier["status"],
            }
        ],
        "claimed_bundle_hash": None,
    }
    evidence["claimed_bundle_hash"] = evidence_bundle_hash(evidence)
    return {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "schema": GENERIC_VERIFICATION_REQUEST_SCHEMA_ID,
        "acceptance_contract": contract,
        "change_set": change_set,
        "change_manifest": snapshot.manifest,
        "verification_plan": plan,
        "evidence_bundle": evidence,
        "certification_policy": None,
    }


def _receipt_hash(receipt: Mapping[str, Any]) -> str:
    return canonical_hash({key: value for key, value in receipt.items() if key != "receipt_hash"})


def _write_receipt(repo: Path, receipt: dict[str, Any]) -> Path:
    receipt["receipt_hash"] = _receipt_hash(receipt)
    receipts = repo / CONFIG_DIRECTORY / "receipts"
    receipts.mkdir(parents=True, exist_ok=True)
    stamp = receipt["timestamp"].replace("-", "").replace(":", "").replace("+00:00", "Z")
    path = receipts / f"{stamp}-{receipt['receipt_hash'][-12:]}.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _base_receipt(
    *,
    config: Mapping[str, Any] | None,
    config_hash: str | None,
    snapshot: _GitSnapshot | None,
    verifier: Mapping[str, Any] | None,
    request: Mapping[str, Any] | None,
    response: Mapping[str, Any] | None,
    status: str,
    reasons: Sequence[str],
    requirements_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "product": {"name": "nexus-core", "version": _product_version()},
        "source_revision": f"git-commit:{snapshot.source_commit}" if snapshot else None,
        "source_tree": f"git-tree:{snapshot.source_tree}" if snapshot else None,
        "target_revision": f"git-tree:{snapshot.target_tree}" if snapshot else None,
        "target_tree": f"git-tree:{snapshot.target_tree}" if snapshot else None,
        "manifest_hash": change_manifest_hash(snapshot.manifest) if snapshot else None,
        "config_hash": config_hash,
        "verifier": verifier,
        "inputs": {
            "config": config,
            "requirements_context": dict(requirements_context) if requirements_context else None,
            "request": request,
        },
        "core_response": response,
        "outcome": {
            "status": status,
            "reason_codes": list(reasons),
            "transport_error": False,
        },
    }


def _raise_with_receipt(
    repo: Path,
    reason: str,
    detail: str,
    *,
    config: Mapping[str, Any] | None = None,
    config_hash: str | None = None,
    snapshot: _GitSnapshot | None = None,
    verifier: Mapping[str, Any] | None = None,
    requirements_context: Mapping[str, Any] | None = None,
) -> None:
    receipt = _base_receipt(
        config=config,
        config_hash=config_hash,
        snapshot=snapshot,
        verifier=verifier,
        request=None,
        response=None,
        status="FAILED_CLOSED",
        reasons=[reason],
        requirements_context=requirements_context,
    )
    path = _write_receipt(repo, receipt)
    raise LocalCheckError(reason, detail, receipt_path=path)


def check_repository(
    path: str | Path = ".",
    *,
    requirements_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the local Golden Path and return the canonical Core verdict.

    ``requirements_context`` is an optional evidence-binding projection for a
    higher-level consumer such as the Issue Golden Path. It participates only in
    the AcceptanceContract requirements hash; it does not grant execution,
    approval, merge, release, or deployment authority.
    """

    repo = _repo_root(path)
    config = _load_config(repo)
    config_hash = canonical_hash(config)
    requirements_hash = (
        config_hash
        if requirements_context is None
        else canonical_hash({"config_hash": config_hash, "context": dict(requirements_context)})
    )
    if not _command_available(repo, config["verifier_command"]):
        _raise_with_receipt(
            repo,
            "VERIFIER_UNAVAILABLE",
            config["verifier_command"][0],
            config=config,
            config_hash=config_hash,
            requirements_context=requirements_context,
        )
    try:
        snapshot = _snapshot(repo, config["base_ref"])
    except LocalCheckError as exc:
        _raise_with_receipt(
            repo,
            exc.reason_code,
            exc.detail,
            config=config,
            config_hash=config_hash,
            requirements_context=requirements_context,
        )

    forbidden = [
        entry["path"]
        for entry in snapshot.manifest["entries"]
        if not _path_allowed(entry["path"], config["allowed_patterns"])
    ]
    if forbidden:
        _raise_with_receipt(
            repo,
            "FORBIDDEN_PATH",
            ", ".join(forbidden),
            config=config,
            config_hash=config_hash,
            snapshot=snapshot,
            requirements_context=requirements_context,
        )
    deleted = [
        entry["path"] for entry in snapshot.manifest["entries"] if entry["change_type"] == "DELETE"
    ]
    if deleted and config["deletion_policy"] == "FORBID":
        _raise_with_receipt(
            repo,
            "FORBIDDEN_DELETION",
            ", ".join(deleted),
            config=config,
            config_hash=config_hash,
            snapshot=snapshot,
            requirements_context=requirements_context,
        )

    verifier_env = os.environ.copy()
    verifier_env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    if config["verifier_command"][:3] == [config["verifier_command"][0], "-m", "pytest"]:
        existing = verifier_env.get("PYTEST_ADDOPTS", "")
        verifier_env["PYTEST_ADDOPTS"] = (existing + " -p no:cacheprovider").strip()
    try:
        executed, verifier_subject, verifier_mutation = _run_verifier_isolated(
            repo,
            snapshot,
            config["verifier_command"],
            verifier_env,
            config["timeout_seconds"],
        )
    except LocalCheckError as exc:
        _raise_with_receipt(
            repo,
            exc.reason_code,
            exc.detail,
            config=config,
            config_hash=config_hash,
            snapshot=snapshot,
            requirements_context=requirements_context,
        )
    except subprocess.TimeoutExpired as exc:
        _raise_with_receipt(
            repo,
            "VERIFIER_TIMEOUT",
            str(exc),
            config=config,
            config_hash=config_hash,
            snapshot=snapshot,
            requirements_context=requirements_context,
        )
    except OSError as exc:
        _raise_with_receipt(
            repo,
            "VERIFIER_EXECUTION_FAILED",
            str(exc),
            config=config,
            config_hash=config_hash,
            snapshot=snapshot,
            requirements_context=requirements_context,
        )
    verifier = _verifier_artifact(
        config["verifier_command"],
        executed.returncode,
        executed.stdout,
        executed.stderr,
        execution_subject=verifier_subject,
    )
    if verifier_mutation is not None:
        _raise_with_receipt(
            repo,
            "VERIFIER_SUBJECT_MUTATED",
            verifier_mutation,
            config=config,
            config_hash=config_hash,
            snapshot=snapshot,
            verifier=verifier,
            requirements_context=requirements_context,
        )

    try:
        _check_ignored_residue(repo)
    except LocalCheckError as exc:
        _raise_with_receipt(
            repo,
            exc.reason_code,
            exc.detail,
            config=config,
            config_hash=config_hash,
            snapshot=snapshot,
            verifier=verifier,
            requirements_context=requirements_context,
        )

    post_tree = _materialize_target_tree(repo, _git_stdout(repo, "rev-parse", "HEAD^{commit}"))
    if post_tree != snapshot.target_tree:
        _raise_with_receipt(
            repo,
            "GIT_MANIFEST_MISMATCH",
            "repository target changed while verifier executed",
            config=config,
            config_hash=config_hash,
            snapshot=snapshot,
            verifier=verifier,
            requirements_context=requirements_context,
        )

    request = _build_request(
        config,
        config_hash,
        snapshot,
        verifier,
        requirements_hash=requirements_hash,
    )
    http_status, response = verify_generic_changeset(request)
    if http_status != 200:
        reason = response.get("error", {}).get("code", "CORE_REQUEST_REJECTED")
        receipt = _base_receipt(
            config=config,
            config_hash=config_hash,
            snapshot=snapshot,
            verifier=verifier,
            request=request,
            response=response,
            status="FAILED_CLOSED",
            reasons=[reason],
            requirements_context=requirements_context,
        )
        path_out = _write_receipt(repo, receipt)
        raise LocalCheckError(reason, "canonical Core rejected request", receipt_path=path_out)

    status = response["verification"]["status"]
    reasons = response["verification"]["reason_codes"]
    receipt = _base_receipt(
        config=config,
        config_hash=config_hash,
        snapshot=snapshot,
        verifier=verifier,
        requirements_context=requirements_context,
        request=request,
        response=response,
        status=status,
        reasons=reasons,
    )
    receipt_path = _write_receipt(repo, receipt)
    if status not in {"VERIFIED", "FAILED_VERIFICATION"}:
        raise LocalCheckError(status, ", ".join(reasons), receipt_path=receipt_path)
    return {
        "status": status,
        "reason_codes": reasons,
        "certification": response["certification"],
        "transport_error": False,
        "receipt_path": receipt_path,
    }


def validate_verification_receipt_payload(
    payload: Mapping[str, Any], *, repo: str | Path | None = None
) -> dict[str, Any]:
    """Independently recompute a local verification receipt payload.

    This is the transport-neutral validation seam used by file-based local
    readback and read-only remote adapters. It performs no network access and
    does not execute repository verifier commands.
    """

    if not isinstance(payload, Mapping):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
    payload = dict(payload)
    reasons: list[str] = []
    product = payload.get("product")
    if (
        payload.get("kind") != RECEIPT_KIND
        or payload.get("schema_version") != RECEIPT_SCHEMA_VERSION
        or not isinstance(product, dict)
        or set(product) != {"name", "version"}
        or product.get("name") != "nexus-core"
        or not isinstance(product.get("version"), str)
        or not product["version"].strip()
    ):
        reasons.append("UNSUPPORTED_RECEIPT")
    if payload.get("receipt_hash") != _receipt_hash(payload):
        reasons.append("RECEIPT_HASH_MISMATCH")
    inputs = payload.get("inputs")
    if not isinstance(inputs, dict):
        reasons.append("MALFORMED_RECEIPT")
        return {"valid": False, "reason_codes": sorted(set(reasons))}
    config = inputs.get("config")
    requirements_context = inputs.get("requirements_context")
    request = inputs.get("request")
    config_hash = canonical_hash(config) if isinstance(config, dict) else None
    if config_hash is None or payload.get("config_hash") != config_hash:
        reasons.append("CONFIG_HASH_MISMATCH")
    verifier = payload.get("verifier")
    if isinstance(verifier, dict):
        verifier_body = {key: value for key, value in verifier.items() if key != "artifact_hash"}
        if verifier.get("artifact_hash") != canonical_hash(verifier_body):
            reasons.append("VERIFIER_ARTIFACT_MISMATCH")
        try:
            stdout = base64.b64decode(verifier["stdout_base64"], validate=True)
            stderr = base64.b64decode(verifier["stderr_base64"], validate=True)
        except (KeyError, TypeError, ValueError):
            stdout = stderr = b""
            reasons.append("VERIFIER_OUTPUT_MISMATCH")
        if (
            verifier.get("stdout_hash") != _sha256_bytes(stdout)
            or verifier.get("stderr_hash") != _sha256_bytes(stderr)
            or verifier.get("output_hash")
            != canonical_hash(
                {
                    "stdout_sha256": _sha256_bytes(stdout),
                    "stderr_sha256": _sha256_bytes(stderr),
                }
            )
            or verifier.get("stdout") != stdout.decode("utf-8", errors="replace")
            or verifier.get("stderr") != stderr.decode("utf-8", errors="replace")
        ):
            reasons.append("VERIFIER_OUTPUT_MISMATCH")
        exit_code = verifier.get("exit_code")
        expected_status = (
            "PASS"
            if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code == 0
            else "FAIL"
        )
        if (
            not isinstance(exit_code, int)
            or isinstance(exit_code, bool)
            or verifier.get("status") != expected_status
        ):
            reasons.append("VERIFIER_STATUS_MISMATCH")
    else:
        reasons.append("VERIFIER_ARTIFACT_MISMATCH")

    if isinstance(request, dict):
        manifest = request.get("change_manifest")
        manifest_hash = change_manifest_hash(manifest) if isinstance(manifest, dict) else None
        if manifest_hash is None or payload.get("manifest_hash") != manifest_hash:
            reasons.append("MANIFEST_HASH_MISMATCH")
        status, recomputed = verify_generic_changeset(request)
        if status != 200 or recomputed != payload.get("core_response"):
            reasons.append("CORE_RESPONSE_MISMATCH")
        try:
            observations = request["evidence_bundle"]["observations"]
            observation = observations[0]
            if (
                len(observations) != 1
                or not isinstance(verifier, dict)
                or observation["artifact_hash"] != verifier.get("artifact_hash")
                or observation["status"] != verifier.get("status")
            ):
                reasons.append("VERIFIER_BINDING_MISMATCH")
        except (KeyError, IndexError, TypeError):
            reasons.append("VERIFIER_BINDING_MISMATCH")
        try:
            if (
                payload.get("source_revision") != request["change_set"]["source_revision"]
                or payload.get("source_tree") != request["change_manifest"]["source_tree"]
                or payload.get("target_revision") != request["change_set"]["target_revision"]
                or payload.get("target_tree") != request["change_manifest"]["target_tree"]
            ):
                reasons.append("RECEIPT_BINDING_MISMATCH")
            expected_requirements_hash = (
                config_hash
                if requirements_context is None
                else canonical_hash(
                    {"config_hash": config_hash, "context": requirements_context}
                )
            )
            if request["acceptance_contract"]["requirements_hash"] != expected_requirements_hash:
                reasons.append("CONFIG_BINDING_MISMATCH")
        except (KeyError, TypeError):
            reasons.append("RECEIPT_BINDING_MISMATCH")
            reasons.append("CONFIG_BINDING_MISMATCH")
        if status == 200:
            try:
                outcome = payload["outcome"]
                verification = recomputed["verification"]
                if (
                    outcome["status"] != verification["status"]
                    or outcome["reason_codes"] != verification["reason_codes"]
                ):
                    reasons.append("OUTCOME_MISMATCH")
            except (KeyError, TypeError):
                reasons.append("OUTCOME_MISMATCH")
        if repo is not None and isinstance(manifest, dict):
            try:
                repo_root = _repo_root(repo)
                source_tree = str(manifest["source_tree"]).removeprefix("git-tree:")
                target_tree = str(manifest["target_tree"]).removeprefix("git-tree:")
                physical = _manifest_from_trees(repo_root, source_tree, target_tree)
                if physical != manifest:
                    reasons.append("GIT_MANIFEST_MISMATCH")
            except (LocalCheckError, KeyError, TypeError):
                reasons.append("GIT_MANIFEST_MISMATCH")
    else:
        reasons.append("MALFORMED_RECEIPT")
    return {"valid": not reasons, "reason_codes": sorted(set(reasons))}


def validate_verification_receipt(
    receipt_path: str | Path, *, repo: str | Path | None = None
) -> dict[str, Any]:
    """Independently recompute a local verification receipt from preserved inputs."""

    try:
        payload = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
    if not isinstance(payload, dict):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
    return validate_verification_receipt_payload(payload, repo=repo)


__all__ = [
    "CONFIG_DIRECTORY",
    "LocalCheckError",
    "check_repository",
    "doctor_repository",
    "init_repository",
    "validate_verification_receipt",
    "validate_verification_receipt_payload",
]
