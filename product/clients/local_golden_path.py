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
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import tomllib
import uuid
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
RECEIPT_SCHEMA_VERSION = 2
LEGACY_RECEIPT_SCHEMA_VERSION = 1
CONFIG_VERSION = 1
CONFIG_VERSION_MULTI_EVIDENCE = 2
DEFAULT_TIMEOUT_SECONDS = 300
_CONFIG_V1_KEYS = {
    "version",
    "base_ref",
    "allowed_patterns",
    "deletion_policy",
    "verifier_command",
    "timeout_seconds",
}
_CONFIG_V2_KEYS = {
    "version",
    "base_ref",
    "allowed_patterns",
    "deletion_policy",
    "universe_generation",
    "verifiers",
    "materials",
}
_CONFIG_V2_OPTIONAL_KEYS = {"env_passthrough", "isolation"}
CONTAINER_IMAGE_PULL_TIMEOUT_SECONDS = 900
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_HEX40_RE = re.compile(r"[0-9a-f]{40}")
_IMAGE_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_ISOLATION_KEYS = {"mode", "image", "network"}
_REQUIREMENT_MODES = {"REQUIRED", "CONDITIONALLY_REQUIRED", "NOT_APPLICABLE"}
_APPLICABILITY = {"APPLICABLE", "NOT_APPLICABLE", "UNRESOLVED"}


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


def _validate_command(value: Any, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item or "\x00" in item for item in value)
    ):
        raise LocalCheckError("INVALID_CONFIG", f"{field} must be a non-empty array")
    return value


def _validate_timeout(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 3600:
        raise LocalCheckError("INVALID_CONFIG", f"{field} must be between 1 and 3600")
    return value


def _validate_subject_fields(item: Mapping[str, Any], field: str) -> None:
    for key in ("id", "logical_subject_id", "evidence_kind"):
        value = item.get(key)
        if (
            not isinstance(value, str)
            or not value.strip()
            or value != value.strip()
            or "\x00" in value
        ):
            raise LocalCheckError("INVALID_CONFIG", f"{field}.{key} must be normalized text")
    mode = item.get("requirement_mode", "REQUIRED")
    applicability = item.get("applicability", "APPLICABLE")
    if mode not in _REQUIREMENT_MODES:
        raise LocalCheckError("INVALID_CONFIG", f"{field}.requirement_mode is invalid")
    if applicability not in _APPLICABILITY:
        raise LocalCheckError("INVALID_CONFIG", f"{field}.applicability is invalid")
    if mode == "REQUIRED" and applicability != "APPLICABLE":
        raise LocalCheckError(
            "INVALID_CONFIG", f"{field}: REQUIRED subjects require APPLICABLE applicability"
        )
    if mode == "NOT_APPLICABLE" and applicability != "NOT_APPLICABLE":
        raise LocalCheckError(
            "INVALID_CONFIG", f"{field}: NOT_APPLICABLE subjects require NOT_APPLICABLE applicability"
        )


def _validate_env_passthrough(value: Any) -> None:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not _ENV_NAME_RE.match(item) for item in value)
        or len(value) != len(set(value))
    ):
        raise LocalCheckError(
            "INVALID_CONFIG", "env_passthrough must be unique names matching ^[A-Z_][A-Z0-9_]*$"
        )


def _validate_isolation(value: Any) -> None:
    if not isinstance(value, dict) or not set(value) <= _ISOLATION_KEYS:
        raise LocalCheckError("INVALID_CONFIG", "isolation has unexpected fields")
    mode = value.get("mode", "process")
    network = value.get("network", "bridge")
    if mode not in {"process", "container"}:
        raise LocalCheckError("INVALID_CONFIG", "isolation.mode must be process or container")
    if network not in {"bridge", "none"}:
        raise LocalCheckError("INVALID_CONFIG", "isolation.network must be bridge or none")
    image = value.get("image")
    if mode == "container":
        if not isinstance(image, str) or not _IMAGE_DIGEST_RE.search(image) or "\x00" in image:
            raise LocalCheckError(
                "INVALID_CONFIG", "isolation.image must be digest-pinned (@sha256:<64 hex>)"
            )
    elif image is not None:
        raise LocalCheckError("INVALID_CONFIG", "isolation.image requires mode = container")


def _validate_config(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise LocalCheckError("INVALID_CONFIG", "config must be a table")
    version_value = value.get("version")
    if version_value == CONFIG_VERSION:
        if set(value) != _CONFIG_V1_KEYS:
            raise LocalCheckError("INVALID_CONFIG", "unexpected or missing config keys")
    elif version_value == CONFIG_VERSION_MULTI_EVIDENCE:
        keys = set(value)
        if not _CONFIG_V2_KEYS <= keys or not keys <= (_CONFIG_V2_KEYS | _CONFIG_V2_OPTIONAL_KEYS):
            raise LocalCheckError("INVALID_CONFIG", "unexpected or missing config keys")
    else:
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

    if version_value == CONFIG_VERSION:
        _validate_command(value["verifier_command"], "verifier_command")
        _validate_timeout(value["timeout_seconds"], "timeout_seconds")
        return value

    _validate_env_passthrough(value.get("env_passthrough", []))
    if "isolation" in value:
        _validate_isolation(value["isolation"])
    generation = value["universe_generation"]
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise LocalCheckError("INVALID_CONFIG", "universe_generation must be a positive integer")

    verifiers = value["verifiers"]
    materials = value["materials"]
    if not isinstance(verifiers, list) or not isinstance(materials, list) or not (verifiers or materials):
        raise LocalCheckError("INVALID_CONFIG", "version 2 requires verifiers and/or materials")

    allowed_verifier_keys = {
        "id",
        "command",
        "timeout_seconds",
        "logical_subject_id",
        "evidence_kind",
        "requirement_mode",
        "applicability",
        "required_material_ids",
    }
    allowed_material_keys = {
        "id",
        "observe_command",
        "timeout_seconds",
        "logical_subject_id",
        "evidence_kind",
        "requirement_mode",
        "applicability",
        "expected_identity",
    }
    producer_ids: list[str] = []
    subject_ids: list[str] = []
    material_ids: list[str] = []
    for index, item in enumerate(materials):
        field = f"materials[{index}]"
        if not isinstance(item, dict) or not set(item).issubset(allowed_material_keys):
            raise LocalCheckError("INVALID_CONFIG", f"{field} has unexpected fields")
        required = {
            "id",
            "observe_command",
            "timeout_seconds",
            "logical_subject_id",
            "evidence_kind",
            "expected_identity",
        }
        if not required.issubset(item):
            raise LocalCheckError("INVALID_CONFIG", f"{field} is missing required fields")
        _validate_subject_fields(item, field)
        _validate_command(item["observe_command"], f"{field}.observe_command")
        _validate_timeout(item["timeout_seconds"], f"{field}.timeout_seconds")
        expected = item["expected_identity"]
        if (
            not isinstance(expected, str)
            or not expected.strip()
            or expected != expected.strip()
            or "\x00" in expected
        ):
            raise LocalCheckError(
                "INVALID_CONFIG", f"{field}.expected_identity must be normalized text"
            )
        producer_ids.append(item["id"])
        subject_ids.append(item["logical_subject_id"])
        material_ids.append(item["id"])

    material_id_set = set(material_ids)
    for index, item in enumerate(verifiers):
        field = f"verifiers[{index}]"
        if not isinstance(item, dict) or not set(item).issubset(allowed_verifier_keys):
            raise LocalCheckError("INVALID_CONFIG", f"{field} has unexpected fields")
        required = {"id", "command", "timeout_seconds", "logical_subject_id", "evidence_kind"}
        if not required.issubset(item):
            raise LocalCheckError("INVALID_CONFIG", f"{field} is missing required fields")
        _validate_subject_fields(item, field)
        _validate_command(item["command"], f"{field}.command")
        _validate_timeout(item["timeout_seconds"], f"{field}.timeout_seconds")
        required_material_ids = item.get("required_material_ids", [])
        if (
            not isinstance(required_material_ids, list)
            or any(
                not isinstance(material_id, str)
                or not material_id
                or material_id not in material_id_set
                for material_id in required_material_ids
            )
            or len(required_material_ids) != len(set(required_material_ids))
        ):
            raise LocalCheckError(
                "INVALID_CONFIG",
                f"{field}.required_material_ids must reference unique declared materials",
            )
        producer_ids.append(item["id"])
        subject_ids.append(item["logical_subject_id"])

    if len(producer_ids) != len(set(producer_ids)):
        raise LocalCheckError("INVALID_CONFIG", "evidence producer ids must be unique")
    if len(subject_ids) != len(set(subject_ids)):
        raise LocalCheckError("INVALID_CONFIG", "logical_subject_id values must be unique")
    if not any(
        item.get("requirement_mode", "REQUIRED") == "REQUIRED"
        for item in [*verifiers, *materials]
    ):
        raise LocalCheckError("INVALID_CONFIG", "version 2 requires at least one REQUIRED producer")
    return value


def _v2_producers(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    producers: list[dict[str, Any]] = []
    for item in config.get("materials", []):
        producers.append(
            {
                **item,
                "kind": "material",
                "command": item["observe_command"],
                "requirement_mode": item.get("requirement_mode", "REQUIRED"),
                "applicability": item.get("applicability", "APPLICABLE"),
                "required_material_ids": [],
            }
        )
    for item in config.get("verifiers", []):
        producers.append(
            {
                **item,
                "kind": "verifier",
                "command": item["command"],
                "requirement_mode": item.get("requirement_mode", "REQUIRED"),
                "applicability": item.get("applicability", "APPLICABLE"),
                "required_material_ids": list(item.get("required_material_ids", [])),
            }
        )
    return producers


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


def _load_effective_config(
    repo: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Return (effective config, config_source, worktree config).

    The worktree config only names ``base_ref``; when that ref's commit carries
    ``.nexus-core/config.toml`` the committed (trusted) config is authoritative.
    """

    worktree_config = _load_config(repo)
    worktree_hash = canonical_hash(worktree_config)
    base_ref = worktree_config["base_ref"]
    config_rel = f"{CONFIG_DIRECTORY}/{CONFIG_FILENAME}"
    resolved = _run_git(repo, "rev-parse", "--verify", f"{base_ref}^{{commit}}")
    effective = worktree_config
    source: dict[str, Any] = {"kind": "worktree"}
    if resolved.returncode == 0:
        commit = resolved.stdout.strip()
        shown = _run_git(repo, "show", f"{commit}:{config_rel}", text=False)
        if shown.returncode == 0:
            try:
                base_config = _validate_config(tomllib.loads(shown.stdout.decode("utf-8")))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                raise LocalCheckError("INVALID_CONFIG", f"base-ref config: {exc}") from exc
            if base_config["base_ref"] != base_ref:
                raise LocalCheckError(
                    "CONFIG_BASE_REF_MISMATCH",
                    f"worktree base_ref {base_ref!r} != base-ref config {base_config['base_ref']!r}",
                )
            effective = base_config
            source = {
                "kind": "base-ref",
                "ref": base_ref,
                "commit": commit,
                "blob": _git_stdout(repo, "rev-parse", f"{commit}:{config_rel}"),
            }
    full_source = {
        "kind": source["kind"],
        "ref": source.get("ref"),
        "commit": source.get("commit"),
        "blob": source.get("blob"),
        "worktree_config_hash": worktree_hash,
        "config_drift": worktree_hash != canonical_hash(effective),
    }
    return effective, full_source, worktree_config


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
        _effective, doctor_source, _wt = _load_effective_config(repo)
        checks["config_source"] = "TRUSTED" if doctor_source["kind"] == "base-ref" else "UNTRACKED"
    except LocalCheckError as exc:
        checks["config_source"] = "ERROR"
        reasons.append(exc.reason_code)

    try:
        checks["ignored_residue"] = f"{len(_list_ignored_residue(repo))} paths (informational)"
    except LocalCheckError:
        checks["ignored_residue"] = "unknown (informational)"

    try:
        _resolve_base_and_head(repo, config["base_ref"])
        checks["base_ref"] = "OK"
    except LocalCheckError as exc:
        checks["base_ref"] = "ERROR"
        reasons.append(exc.reason_code)
    if config["version"] == CONFIG_VERSION:
        if _command_available(repo, config["verifier_command"]):
            checks["verifier"] = "OK"
        else:
            checks["verifier"] = "ERROR"
            reasons.append("VERIFIER_UNAVAILABLE")
    else:
        unavailable = [
            producer["id"]
            for producer in _v2_producers(config)
            if producer["applicability"] == "APPLICABLE"
            and not _command_available(repo, producer["command"])
        ]
        checks["verifier"] = "OK" if not unavailable else "ERROR"
        checks["evidence_producers"] = "OK" if not unavailable else "ERROR"
        if unavailable:
            reasons.append("EVIDENCE_PRODUCER_UNAVAILABLE")
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

        head_control_paths = _git_stdout(repo, "ls-files", "-z", "--", CONFIG_DIRECTORY, env=env)
        tracked_control_paths = set(p for p in head_control_paths.split("\0") if p)

        add = _run_git(repo, "add", "-A", "--", ".", env=env)
        if add.returncode != 0:
            raise LocalCheckError("GIT_TARGET_MATERIALIZATION_FAILED", add.stderr.strip())

        current_control_paths = _git_stdout(repo, "ls-files", "-z", "--", CONFIG_DIRECTORY, env=env)
        current_paths = set(p for p in current_control_paths.split("\0") if p)
        untracked_to_remove = sorted(current_paths - tracked_control_paths)
        if untracked_to_remove:
            remove_untracked = _run_git(
                repo,
                "rm",
                "--cached",
                "--quiet",
                "--",
                *untracked_to_remove,
                env=env,
            )
            if remove_untracked.returncode != 0:
                raise LocalCheckError(
                    "GIT_TARGET_MATERIALIZATION_FAILED",
                    remove_untracked.stderr.strip(),
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


RESIDUE_POLICY = "sandbox-only"


def _check_ignored_residue(repo: Path) -> None:
    ignored_paths = _list_ignored_residue(repo)
    if ignored_paths:
        raise LocalCheckError("IGNORED_RESIDUE", ", ".join(ignored_paths))


def _list_ignored_residue(repo: Path) -> list[str]:
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
    return ignored_paths


def _snapshot(repo: Path, base_ref: str) -> _GitSnapshot:
    source_commit, head = _resolve_base_and_head(repo, base_ref)

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


def _v2_artifact(
    producer: Mapping[str, Any],
    returncode: int,
    stdout: bytes,
    stderr: bytes,
    *,
    execution_subject: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    artifact = _verifier_artifact(
        producer["command"],
        returncode,
        stdout,
        stderr,
        execution_subject=execution_subject,
    )
    artifact.pop("artifact_hash", None)
    artifact.update(
        {
            "producer_id": producer["id"],
            "producer_kind": producer["kind"],
            "logical_subject_id": producer["logical_subject_id"],
            "evidence_kind": producer["evidence_kind"],
            "requirement_mode": producer["requirement_mode"],
            "applicability": producer["applicability"],
            "required_material_ids": list(producer.get("required_material_ids", [])),
        }
    )
    if producer["kind"] == "material":
        observed_identity = stdout.decode("utf-8", errors="replace").strip()
        artifact["expected_identity"] = producer["expected_identity"]
        artifact["observed_identity"] = observed_identity
        artifact["status"] = (
            "PASS"
            if returncode == 0 and observed_identity == producer["expected_identity"]
            else "FAIL"
        )
    artifact["artifact_hash"] = canonical_hash(artifact)
    return artifact


def _artifact_observation(artifact: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "verifier_id": artifact["producer_id"],
        "artifact_id": (
            f"{artifact['producer_id']}-"
            f"{artifact['artifact_hash'].removeprefix('sha256:')[:16]}"
        ),
        "artifact_hash": artifact["artifact_hash"],
        "status": artifact["status"],
        "logical_subject_id": artifact["logical_subject_id"],
        "evidence_kind": artifact["evidence_kind"],
    }


def _cleanup_verifier_sandbox(path: Path) -> None:
    shutil.rmtree(path)


def _isolation_settings(config: Mapping[str, Any]) -> dict[str, Any]:
    raw = config.get("isolation") or {}
    mode = raw.get("mode", "process")
    settings: dict[str, Any] = {"mode": mode}
    if mode == "container":
        settings["image"] = raw["image"]
        settings["network"] = raw.get("network", "bridge")
    return settings


def _passthrough_names(config: Mapping[str, Any]) -> list[str]:
    return [name for name in config.get("env_passthrough", []) if name in os.environ]


def _verifier_environment(
    config: Mapping[str, Any],
    sandbox_home: str,
    sandbox_tmp: str,
    command: Sequence[str] = (),
) -> dict[str, str]:
    """Allowlisted verifier environment; nothing is inherited implicitly."""

    env: dict[str, str] = {}
    if "PATH" in os.environ:
        env["PATH"] = os.environ["PATH"]
    for name in ("LANG", "LC_ALL"):
        if name in os.environ:
            env[name] = os.environ[name]
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HOME"] = str(sandbox_home)
    env["TMPDIR"] = str(sandbox_tmp)
    for name in _passthrough_names(config):
        env[name] = os.environ[name]
    if len(command) >= 3 and list(command[1:3]) == ["-m", "pytest"]:
        existing = env.get("PYTEST_ADDOPTS", "")
        env["PYTEST_ADDOPTS"] = (existing + " -p no:cacheprovider").strip()
    return env


def _container_argv(
    image: str,
    network: str,
    sandbox_repo: str | Path,
    env: Mapping[str, str],
    command: Sequence[str],
    uid: int,
    gid: int,
    *,
    name: str | None = None,
) -> list[str]:
    """Docker argv exposing only the sandbox parent directory at /sandbox."""

    sandbox_parent = Path(sandbox_repo).parent
    argv = ["docker", "run", "--rm"]
    if name is not None:
        argv += ["--name", name]
    argv += [
        "--network",
        network,
        "--user",
        f"{uid}:{gid}",
        "-v",
        f"{sandbox_parent}:/sandbox",
        "-w",
        "/sandbox/repo",
    ]
    for key, value in env.items():
        argv += ["-e", f"{key}={value}"]
    return [*argv, image, *command]


def _kill_group(proc: "subprocess.Popen[bytes]") -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _run_in_new_session(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int,
    on_timeout: Any = None,
) -> subprocess.CompletedProcess[bytes]:
    with subprocess.Popen(
        list(argv),
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as proc:
        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            if on_timeout is not None:
                on_timeout()
            proc.communicate()
            raise
        except BaseException:
            _kill_group(proc)
            raise
        _kill_group(proc)  # reap any backgrounded grandchildren
        return subprocess.CompletedProcess(list(argv), proc.returncode, stdout, stderr)


def _ensure_container_image(image: str) -> bool:
    """Pull the image if absent, outside the verifier timeout. Returns whether it pulled."""

    try:
        present = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True,
            check=False,
            timeout=60,
        )
        if present.returncode == 0:
            return False
        pulled = subprocess.run(
            ["docker", "pull", "--quiet", image],
            capture_output=True,
            check=False,
            timeout=CONTAINER_IMAGE_PULL_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise LocalCheckError("ISOLATION_IMAGE_UNAVAILABLE", f"{image}: {exc}") from exc
    if pulled.returncode != 0:
        tail = pulled.stderr.decode("utf-8", errors="replace").strip()[-500:]
        raise LocalCheckError("ISOLATION_IMAGE_UNAVAILABLE", f"{image}: {tail}")
    return True


def _probe_container_mount(parent: Path, image: str) -> None:
    nonce = uuid.uuid4().hex
    probe = parent / ".nexus-mount-probe"
    detail = (
        f"{parent} is not visible inside the container "
        "(check Docker file sharing / NEXUS_CERTIFY_SANDBOX_ROOT)"
    )
    probe.write_text(nonce, encoding="utf-8")
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{parent}:/sandbox",
                image, "cat", "/sandbox/.nexus-mount-probe",
            ],  # fmt: skip
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise LocalCheckError("ISOLATION_MOUNT_UNAVAILABLE", f"{detail}: {exc}") from exc
    finally:
        probe.unlink(missing_ok=True)
    if result.returncode != 0 or result.stdout.decode("utf-8", errors="replace").strip() != nonce:
        raise LocalCheckError("ISOLATION_MOUNT_UNAVAILABLE", detail)


def _run_verifier_isolated(
    repo: Path,
    snapshot: _GitSnapshot,
    command: Sequence[str],
    config: Mapping[str, Any],
    timeout_seconds: int,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any], str | None]:
    """Run the verifier against an isolated exact-target Git subject.

    The clone has independent refs/index/worktree state, no remote and no
    alternates, so the verifier cannot reach the source repository through Git.
    The original repository remains the canonical ChangeSet subject and is
    re-read after verifier completion.
    """

    isolation = _isolation_settings(config)
    if isolation["mode"] == "container" and shutil.which("docker") is None:
        raise LocalCheckError("ISOLATION_UNAVAILABLE", "docker is not installed")
    if isolation["mode"] == "container":
        isolation["image_pulled"] = _ensure_container_image(isolation["image"])

    source_head = _git_stdout(repo, "rev-parse", "HEAD^{commit}")
    execution_subject = {
        "mode": "isolated_detached_clone",
        "source_head": f"git-commit:{source_head}",
        "target_tree": f"git-tree:{snapshot.target_tree}",
        "isolation": isolation,
        "env_passthrough": _passthrough_names(config),
    }
    sandbox_root = os.environ.get("NEXUS_CERTIFY_SANDBOX_ROOT")
    if isolation["mode"] == "container":
        # NEXUS_CERTIFY_SANDBOX_ROOT: host directory for container sandboxes; it must
        # be shared with the Docker VM. macOS defaults to ~/.cache/nexus-certify/sandbox
        # because $TMPDIR (/var/folders) and /tmp are not shared by every VM
        # (Docker Desktop shares /Users; colima shares $HOME).
        if not sandbox_root and sys.platform == "darwin":
            default_root = Path.home() / ".cache" / "nexus-certify" / "sandbox"
            default_root.mkdir(parents=True, exist_ok=True)
            sandbox_root = str(default_root)
    else:
        sandbox_root = None
    parent = Path(tempfile.mkdtemp(prefix="nexus-core-verifier-", dir=sandbox_root or None))
    if isolation["mode"] == "container":
        parent = parent.resolve()
    verifier_repo = parent / "repo"
    executed: subprocess.CompletedProcess[bytes] | None = None
    execution_error: subprocess.TimeoutExpired | OSError | None = None
    mutation_detail: str | None = None
    cleanup_error: str | None = None

    try:
        clone = _run_git(
            repo,
            "clone",
            "--no-hardlinks",
            "--no-checkout",
            "--quiet",
            str(repo),
            str(verifier_repo),
        )
        if clone.returncode != 0:
            detail = (clone.stderr or clone.stdout).strip()
            raise LocalCheckError("VERIFIER_SANDBOX_PREPARE_FAILED", detail)

        remove_origin = _run_git(verifier_repo, "remote", "remove", "origin")
        if remove_origin.returncode != 0:
            detail = (remove_origin.stderr or remove_origin.stdout).strip()
            raise LocalCheckError("VERIFIER_SANDBOX_PREPARE_FAILED", detail)
        if (verifier_repo / ".git" / "objects" / "info" / "alternates").exists():
            raise LocalCheckError(
                "VERIFIER_SANDBOX_PREPARE_FAILED", "isolated clone has object alternates"
            )

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

        sandbox_home = parent / "home"
        sandbox_tmp = parent / "tmp"
        sandbox_home.mkdir()
        sandbox_tmp.mkdir()
        if isolation["mode"] == "container":
            _probe_container_mount(parent, isolation["image"])
            isolation["mount_probe"] = "PASS"
        try:
            if isolation["mode"] == "container":
                env = _verifier_environment(
                    config, "/sandbox/home", "/sandbox/tmp", command
                )
                name = f"nexus-verifier-{uuid.uuid4().hex[:16]}"
                argv = _container_argv(
                    isolation["image"],
                    isolation["network"],
                    verifier_repo,
                    env,
                    command,
                    os.getuid(),
                    os.getgid(),
                    name=name,
                )

                def _remove_container() -> None:
                    subprocess.run(
                        ["docker", "rm", "-f", name],
                        capture_output=True,
                        check=False,
                        timeout=30,
                    )

                executed = _run_in_new_session(
                    argv,
                    cwd=verifier_repo,
                    env=os.environ,
                    timeout_seconds=timeout_seconds,
                    on_timeout=_remove_container,
                )
            else:
                env = _verifier_environment(
                    config, str(sandbox_home), str(sandbox_tmp), command
                )
                executed = _run_in_new_session(
                    command,
                    cwd=verifier_repo,
                    env=env,
                    timeout_seconds=timeout_seconds,
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
                if path != CONFIG_DIRECTORY and not path.startswith(f"{CONFIG_DIRECTORY}/")
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
    artifacts: Sequence[Mapping[str, Any]],
    *,
    requirements_hash: str | None = None,
) -> dict[str, Any]:
    paths = [entry["path"] for entry in snapshot.manifest["entries"]]
    deleted = [
        entry["path"] for entry in snapshot.manifest["entries"] if entry["change_type"] == "DELETE"
    ]
    if config["version"] == CONFIG_VERSION:
        if len(artifacts) != 1:
            raise LocalCheckError("INTERNAL_EVIDENCE_MISMATCH", "legacy config requires one artifact")
        verifier = artifacts[0]
        required_verifier_ids = ["local-command"]
        expected_subjects = None
        observations = [
            {
                "verifier_id": "local-command",
                "artifact_id": (
                    f"local-command-{verifier['artifact_hash'].removeprefix('sha256:')[:16]}"
                ),
                "artifact_hash": verifier["artifact_hash"],
                "status": verifier["status"],
            }
        ]
    else:
        producers = _v2_producers(config)
        required_verifier_ids = [
            producer["id"]
            for producer in producers
            if producer["requirement_mode"] == "REQUIRED"
        ]
        expected_subjects = [
            {
                "logical_subject_id": producer["logical_subject_id"],
                "evidence_kind": producer["evidence_kind"],
                "requirement_mode": producer["requirement_mode"],
                "applicability": producer["applicability"],
            }
            for producer in producers
        ]
        observations = [_artifact_observation(artifact) for artifact in artifacts]

    contract = {
        "contract_id": f"local-contract-{config_hash.removeprefix('sha256:')[:16]}",
        "requirements_hash": requirements_hash or config_hash,
        "required_verifier_ids": required_verifier_ids,
        "allowed_paths": paths,
        "deletion_policy": config["deletion_policy"],
    }
    if expected_subjects is not None:
        contract["expected_subjects"] = expected_subjects
        contract["universe_generation"] = config["universe_generation"]

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
        "required_verifier_ids": required_verifier_ids,
    }
    evidence = {
        "bundle_id": f"local-evidence-{snapshot.target_tree[:16]}",
        "acceptance_contract_hash": plan["acceptance_contract_hash"],
        "change_set_hash": plan["change_set_hash"],
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


def _subject_fields(repo: Path | None, snapshot: _GitSnapshot | None) -> dict[str, Any]:
    """Bind the receipt to the exact HEAD commit/tree it was produced against."""

    if repo is None:
        return {}
    head = _run_git(repo, "rev-parse", "--verify", "HEAD^{commit}")
    if head.returncode != 0 or not _HEX40_RE.fullmatch(head.stdout.strip()):
        return {}
    head_sha = head.stdout.strip()
    tree = _run_git(repo, "rev-parse", "--verify", f"{head_sha}^{{tree}}")
    if tree.returncode != 0 or not _HEX40_RE.fullmatch(tree.stdout.strip()):
        return {}
    tree_sha = tree.stdout.strip()
    return {
        "subject_head": f"git-commit:{head_sha}",
        "subject_head_tree": f"git-tree:{tree_sha}",
        "subject_clean": (snapshot.target_tree == tree_sha) if snapshot else None,
    }


def _base_receipt(
    *,
    repo: Path | None = None,
    config: Mapping[str, Any] | None,
    config_hash: str | None,
    snapshot: _GitSnapshot | None,
    artifacts: Sequence[Mapping[str, Any]] = (),
    request: Mapping[str, Any] | None,
    response: Mapping[str, Any] | None,
    status: str,
    reasons: Sequence[str],
    requirements_context: Mapping[str, Any] | None = None,
    config_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    config_version = config.get("version") if isinstance(config, Mapping) else None
    receipt: dict[str, Any] = {
        "schema_version": (
            LEGACY_RECEIPT_SCHEMA_VERSION
            if config_version in {None, CONFIG_VERSION}
            else RECEIPT_SCHEMA_VERSION
        ),
        "kind": RECEIPT_KIND,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "product": {"name": "nexus-core", "version": _product_version()},
        "source_revision": f"git-commit:{snapshot.source_commit}" if snapshot else None,
        "source_tree": f"git-tree:{snapshot.source_tree}" if snapshot else None,
        "target_revision": f"git-tree:{snapshot.target_tree}" if snapshot else None,
        "target_tree": f"git-tree:{snapshot.target_tree}" if snapshot else None,
        "manifest_hash": change_manifest_hash(snapshot.manifest) if snapshot else None,
        "config_hash": config_hash,
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
    receipt.update(_subject_fields(repo, snapshot))
    if config_source is not None:
        receipt["config_source"] = dict(config_source)
        receipt["residue_policy"] = RESIDUE_POLICY
    if config_version in {None, CONFIG_VERSION}:
        receipt["verifier"] = dict(artifacts[0]) if artifacts else None
    else:
        assert config is not None
        receipt["evidence_artifacts"] = [dict(artifact) for artifact in artifacts]
        receipt["evidence_links"] = [
            {
                "verifier_id": producer["id"],
                "required_material_ids": list(producer.get("required_material_ids", [])),
            }
            for producer in _v2_producers(config)
            if producer["kind"] == "verifier"
        ]
        if request is not None:
            contract = request.get("acceptance_contract", {})
            receipt["evidence_universe"] = {
                "universe_generation": contract.get("universe_generation"),
                "expected_subjects": contract.get("expected_subjects", []),
                "required_verifier_ids": contract.get("required_verifier_ids", []),
            }
        else:
            receipt["evidence_universe"] = {
                "universe_generation": config.get("universe_generation"),
                "expected_subjects": [
                    {
                        "logical_subject_id": producer["logical_subject_id"],
                        "evidence_kind": producer["evidence_kind"],
                        "requirement_mode": producer["requirement_mode"],
                        "applicability": producer["applicability"],
                    }
                    for producer in _v2_producers(config)
                ],
                "required_verifier_ids": [
                    producer["id"]
                    for producer in _v2_producers(config)
                    if producer["requirement_mode"] == "REQUIRED"
                ],
            }
    return receipt


def _raise_with_receipt(
    repo: Path,
    reason: str,
    detail: str,
    *,
    config: Mapping[str, Any] | None = None,
    config_hash: str | None = None,
    snapshot: _GitSnapshot | None = None,
    artifacts: Sequence[Mapping[str, Any]] = (),
    requirements_context: Mapping[str, Any] | None = None,
    config_source: Mapping[str, Any] | None = None,
) -> None:
    receipt = _base_receipt(
        repo=repo,
        config=config,
        config_hash=config_hash,
        snapshot=snapshot,
        artifacts=artifacts,
        request=None,
        response=None,
        status="FAILED_CLOSED",
        reasons=[reason],
        requirements_context=requirements_context,
        config_source=config_source,
    )
    path = _write_receipt(repo, receipt)
    raise LocalCheckError(reason, detail, receipt_path=path)


def check_repository(
    path: str | Path = ".",
    *,
    requirements_context: Mapping[str, Any] | None = None,
    require_trusted_config: bool = False,
) -> dict[str, Any]:
    """Run the local Golden Path and return the canonical Core verdict."""

    repo = _repo_root(path)
    config, config_source, _worktree_config = _load_effective_config(repo)
    config_hash = canonical_hash(config)
    requirements_hash = (
        config_hash
        if requirements_context is None
        else canonical_hash({"config_hash": config_hash, "context": dict(requirements_context)})
    )

    if require_trusted_config and config_source["kind"] != "base-ref":
        _raise_with_receipt(
            repo,
            "CONFIG_UNTRUSTED",
            f"no {CONFIG_DIRECTORY}/{CONFIG_FILENAME} committed on {config['base_ref']}",
            config=config,
            config_hash=config_hash,
            config_source=config_source,
            requirements_context=requirements_context,
        )

    if config["version"] == CONFIG_VERSION:
        producers = [
            {
                "id": "local-command",
                "kind": "verifier",
                "command": config["verifier_command"],
                "timeout_seconds": config["timeout_seconds"],
                "requirement_mode": "REQUIRED",
                "applicability": "APPLICABLE",
                "required_material_ids": [],
            }
        ]
    else:
        producers = _v2_producers(config)

    for producer in producers:
        if producer["applicability"] != "APPLICABLE":
            continue
        if (
            config.get("isolation", {}).get("mode", "process") != "container"
            and not _command_available(repo, producer["command"])
        ):
            _raise_with_receipt(
                repo,
                (
                    "VERIFIER_UNAVAILABLE"
                    if config["version"] == CONFIG_VERSION
                    else "EVIDENCE_PRODUCER_UNAVAILABLE"
                ),
                producer["id"],
                config=config,
                config_hash=config_hash,
                config_source=config_source,
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
            config_source=config_source,
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
            config_source=config_source,
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
            config_source=config_source,
            snapshot=snapshot,
            requirements_context=requirements_context,
        )

    artifacts: list[dict[str, Any]] = []
    material_status: dict[str, str] = {}
    for producer in producers:
        if producer["applicability"] != "APPLICABLE":
            continue
        if producer["kind"] == "verifier":
            failed_materials = [
                material_id
                for material_id in producer.get("required_material_ids", [])
                if material_status.get(material_id) != "PASS"
            ]
            if failed_materials:
                # Execution admission is not verification truth. Do not run a
                # verifier whose declared material prerequisites are unsatisfied,
                # but let the canonical Core reducer observe the failed material
                # plus the missing verifier evidence and return UNVERIFIABLE.
                continue

        command = producer["command"]
        try:
            executed, verifier_subject, verifier_mutation = _run_verifier_isolated(
                repo,
                snapshot,
                command,
                config,
                producer["timeout_seconds"],
            )
        except LocalCheckError as exc:
            _raise_with_receipt(
                repo,
                exc.reason_code,
                f"{producer['id']}: {exc.detail}",
                config=config,
                config_hash=config_hash,
                config_source=config_source,
                snapshot=snapshot,
                artifacts=artifacts,
                requirements_context=requirements_context,
            )
        except subprocess.TimeoutExpired as exc:
            _raise_with_receipt(
                repo,
                "VERIFIER_TIMEOUT",
                f"{producer['id']}: {exc}",
                config=config,
                config_hash=config_hash,
                config_source=config_source,
                snapshot=snapshot,
                artifacts=artifacts,
                requirements_context=requirements_context,
            )
        except OSError as exc:
            _raise_with_receipt(
                repo,
                "VERIFIER_EXECUTION_FAILED",
                f"{producer['id']}: {exc}",
                config=config,
                config_hash=config_hash,
                config_source=config_source,
                snapshot=snapshot,
                artifacts=artifacts,
                requirements_context=requirements_context,
            )

        if config["version"] == CONFIG_VERSION:
            artifact = _verifier_artifact(
                command,
                executed.returncode,
                executed.stdout,
                executed.stderr,
                execution_subject=verifier_subject,
            )
        else:
            artifact = _v2_artifact(
                producer,
                executed.returncode,
                executed.stdout,
                executed.stderr,
                execution_subject=verifier_subject,
            )
        artifacts.append(artifact)
        if producer["kind"] == "material":
            material_status[producer["id"]] = artifact["status"]

        if verifier_mutation is not None:
            _raise_with_receipt(
                repo,
                "VERIFIER_SUBJECT_MUTATED",
                f"{producer['id']}: {verifier_mutation}",
                config=config,
                config_hash=config_hash,
                config_source=config_source,
                snapshot=snapshot,
                artifacts=artifacts,
                requirements_context=requirements_context,
            )

    post_tree = _materialize_target_tree(repo, _git_stdout(repo, "rev-parse", "HEAD^{commit}"))
    if post_tree != snapshot.target_tree:
        _raise_with_receipt(
            repo,
            "GIT_MANIFEST_MISMATCH",
            "repository target changed while evidence producers executed",
            config=config,
            config_hash=config_hash,
            config_source=config_source,
            snapshot=snapshot,
            artifacts=artifacts,
            requirements_context=requirements_context,
        )

    request = _build_request(
        config,
        config_hash,
        snapshot,
        artifacts,
        requirements_hash=requirements_hash,
    )
    http_status, response = verify_generic_changeset(request)
    if http_status != 200:
        reason = response.get("error", {}).get("code", "CORE_REQUEST_REJECTED")
        receipt = _base_receipt(
            repo=repo,
            config=config,
            config_hash=config_hash,
            config_source=config_source,
            snapshot=snapshot,
            artifacts=artifacts,
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
        repo=repo,
        config=config,
        config_hash=config_hash,
        config_source=config_source,
        snapshot=snapshot,
        artifacts=artifacts,
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
        "config_source": config_source,
        "base_ref": config["base_ref"],
        "subject_head": receipt.get("subject_head"),
        "subject_head_tree": receipt.get("subject_head_tree"),
        "subject_clean": receipt.get("subject_clean"),
    }


def _validate_artifact_payload(
    artifact: Any,
    *,
    producer: Mapping[str, Any] | None = None,
) -> list[str]:
    reasons: list[str] = []
    if not isinstance(artifact, dict):
        return ["VERIFIER_ARTIFACT_MISMATCH"]
    artifact_body = {key: value for key, value in artifact.items() if key != "artifact_hash"}
    if artifact.get("artifact_hash") != canonical_hash(artifact_body):
        reasons.append("VERIFIER_ARTIFACT_MISMATCH")
    try:
        stdout = base64.b64decode(artifact["stdout_base64"], validate=True)
        stderr = base64.b64decode(artifact["stderr_base64"], validate=True)
    except (KeyError, TypeError, ValueError):
        stdout = stderr = b""
        reasons.append("VERIFIER_OUTPUT_MISMATCH")
    if (
        artifact.get("stdout_hash") != _sha256_bytes(stdout)
        or artifact.get("stderr_hash") != _sha256_bytes(stderr)
        or artifact.get("output_hash")
        != canonical_hash(
            {
                "stdout_sha256": _sha256_bytes(stdout),
                "stderr_sha256": _sha256_bytes(stderr),
            }
        )
        or artifact.get("stdout") != stdout.decode("utf-8", errors="replace")
        or artifact.get("stderr") != stderr.decode("utf-8", errors="replace")
    ):
        reasons.append("VERIFIER_OUTPUT_MISMATCH")
    exit_code = artifact.get("exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        reasons.append("VERIFIER_STATUS_MISMATCH")
        return reasons

    expected_status = "PASS" if exit_code == 0 else "FAIL"
    if producer is not None:
        if (
            artifact.get("producer_id") != producer["id"]
            or artifact.get("producer_kind") != producer["kind"]
            or artifact.get("logical_subject_id") != producer["logical_subject_id"]
            or artifact.get("evidence_kind") != producer["evidence_kind"]
            or artifact.get("requirement_mode") != producer["requirement_mode"]
            or artifact.get("applicability") != producer["applicability"]
            or artifact.get("required_material_ids")
            != list(producer.get("required_material_ids", []))
            or artifact.get("command") != producer["command"]
        ):
            reasons.append("VERIFIER_BINDING_MISMATCH")
        if producer["kind"] == "material":
            observed = stdout.decode("utf-8", errors="replace").strip()
            if (
                artifact.get("expected_identity") != producer["expected_identity"]
                or artifact.get("observed_identity") != observed
            ):
                reasons.append("MATERIAL_IDENTITY_MISMATCH")
            expected_status = (
                "PASS"
                if exit_code == 0 and observed == producer["expected_identity"]
                else "FAIL"
            )
    if artifact.get("status") != expected_status:
        reasons.append("VERIFIER_STATUS_MISMATCH")
    return reasons


def _valid_subject_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and _HEX40_RE.fullmatch(value[len(prefix) :]) is not None
    )


def evaluate_receipt_expectations(
    payload: Mapping[str, Any],
    *,
    expect_status: str | None = None,
    expect_subject_head: str | None = None,
    expect_target_tree: str | None = None,
    expect_config_commit: str | None = None,
    expect_issue: int | None = None,
    expect_github_repository: str | None = None,
    require_clean_subject: bool = False,
    require_trusted_config: bool = False,
) -> dict[str, Any]:
    """Fail-closed consumer expectations over a receipt payload (pure)."""

    if not isinstance(payload, Mapping):
        payload = {}
    outcome = payload.get("outcome")
    source = payload.get("config_source")
    source = source if isinstance(source, Mapping) else {}
    inputs = payload.get("inputs")
    context = inputs.get("requirements_context") if isinstance(inputs, Mapping) else None
    context = context if isinstance(context, Mapping) else {}
    expectations: dict[str, str] = {}
    reasons: list[str] = []

    def record(flag: str, code: str, ok: bool) -> None:
        expectations[flag] = "PASS" if ok else "FAIL"
        if not ok and code not in reasons:
            reasons.append(code)

    if expect_status is not None:
        status = outcome.get("status") if isinstance(outcome, Mapping) else None
        record("expect-status", "STATUS_MISMATCH", status == expect_status)
    if expect_subject_head is not None:
        record(
            "expect-subject-head",
            "SUBJECT_HEAD_MISMATCH",
            payload.get("subject_head") == f"git-commit:{expect_subject_head}",
        )
    if expect_target_tree is not None:
        record(
            "expect-target-tree",
            "TARGET_TREE_MISMATCH",
            payload.get("target_tree") == f"git-tree:{expect_target_tree}",
        )
    if expect_config_commit is not None:
        record(
            "expect-config-commit",
            "CONFIG_SOURCE_MISMATCH",
            source.get("kind") == "base-ref" and source.get("commit") == expect_config_commit,
        )
    if expect_issue is not None:
        number = context.get("issue_number")
        record(
            "expect-issue",
            "ISSUE_BINDING_MISMATCH",
            context.get("schema") == "nexus.core.issue-binding-context.v2"
            and isinstance(number, int)
            and not isinstance(number, bool)
            and number == expect_issue,
        )
    if expect_github_repository is not None:
        record(
            "expect-github-repository",
            "ISSUE_BINDING_MISMATCH",
            context.get("github_repository") == expect_github_repository,
        )
    if require_clean_subject:
        record(
            "require-clean-subject",
            "SUBJECT_NOT_CLEAN",
            payload.get("subject_clean") is True,
        )
    if require_trusted_config:
        record("require-trusted-config", "CONFIG_UNTRUSTED", source.get("kind") == "base-ref")
    return {
        "passed": not reasons,
        "expectations": expectations,
        "reason_codes": reasons,
    }


def validate_verification_receipt_payload(
    payload: Mapping[str, Any], *, repo: str | Path | None = None
) -> dict[str, Any]:
    """Independently recompute a local verification receipt payload."""

    if not isinstance(payload, Mapping):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
    payload = dict(payload)
    reasons: list[str] = []
    product = payload.get("product")
    inputs = payload.get("inputs")
    if not isinstance(inputs, dict):
        reasons.append("MALFORMED_RECEIPT")
        return {"valid": False, "reason_codes": sorted(set(reasons))}
    config = inputs.get("config")
    requirements_context = inputs.get("requirements_context")
    request = inputs.get("request")
    config_version = config.get("version") if isinstance(config, dict) else None
    v2_config: Mapping[str, Any] | None = config if isinstance(config, dict) else None
    expected_schema_version = (
        LEGACY_RECEIPT_SCHEMA_VERSION
        if config_version == CONFIG_VERSION
        else RECEIPT_SCHEMA_VERSION
        if config_version == CONFIG_VERSION_MULTI_EVIDENCE
        else None
    )
    if (
        payload.get("kind") != RECEIPT_KIND
        or expected_schema_version is None
        or payload.get("schema_version") != expected_schema_version
        or not isinstance(product, dict)
        or set(product) != {"name", "version"}
        or product.get("name") != "nexus-core"
        or not isinstance(product.get("version"), str)
        or not product["version"].strip()
    ):
        reasons.append("UNSUPPORTED_RECEIPT")
    if payload.get("receipt_hash") != _receipt_hash(payload):
        reasons.append("RECEIPT_HASH_MISMATCH")
    if "subject_head" in payload and not _valid_subject_ref(payload["subject_head"], "git-commit:"):
        reasons.append("MALFORMED_RECEIPT")
    if "subject_head_tree" in payload and not _valid_subject_ref(
        payload["subject_head_tree"], "git-tree:"
    ):
        reasons.append("MALFORMED_RECEIPT")
    if "subject_clean" in payload and not (
        payload["subject_clean"] is None or isinstance(payload["subject_clean"], bool)
    ):
        reasons.append("MALFORMED_RECEIPT")
    if "residue_policy" in payload and payload["residue_policy"] != RESIDUE_POLICY:
        reasons.append("MALFORMED_RECEIPT")
    if "config_source" in payload:
        source = payload["config_source"]
        if (
            not isinstance(source, dict)
            or source.get("kind") not in {"base-ref", "worktree"}
            or not isinstance(source.get("config_drift"), bool)
        ):
            reasons.append("MALFORMED_RECEIPT")

    config_hash = canonical_hash(config) if isinstance(config, dict) else None
    if config_hash is None or payload.get("config_hash") != config_hash:
        reasons.append("CONFIG_HASH_MISMATCH")

    artifacts: list[dict[str, Any]] = []
    if config_version == CONFIG_VERSION:
        verifier = payload.get("verifier")
        reasons.extend(_validate_artifact_payload(verifier))
        if isinstance(verifier, dict):
            artifacts = [verifier]
    elif config_version == CONFIG_VERSION_MULTI_EVIDENCE and v2_config is not None:
        try:
            validated_config = _validate_config(dict(v2_config))
            producers = _v2_producers(validated_config)
            producers_by_id = {producer["id"]: producer for producer in producers}
        except LocalCheckError:
            reasons.append("CONFIG_BINDING_MISMATCH")
            producers = []
            producers_by_id = {}
        raw_artifacts = payload.get("evidence_artifacts")
        if not isinstance(raw_artifacts, list):
            reasons.append("VERIFIER_ARTIFACT_MISMATCH")
            raw_artifacts = []
        seen_ids: set[str] = set()
        for artifact in raw_artifacts:
            producer_id = artifact.get("producer_id") if isinstance(artifact, dict) else None
            producer = producers_by_id.get(producer_id) if isinstance(producer_id, str) else None
            if producer is None:
                reasons.append("VERIFIER_BINDING_MISMATCH")
            else:
                assert isinstance(producer_id, str)
                if producer_id in seen_ids:
                    reasons.append("VERIFIER_BINDING_MISMATCH")
                seen_ids.add(producer_id)
            reasons.extend(_validate_artifact_payload(artifact, producer=producer))
            if isinstance(artifact, dict):
                artifacts.append(artifact)
        expected_links = [
            {
                "verifier_id": producer["id"],
                "required_material_ids": list(producer.get("required_material_ids", [])),
            }
            for producer in producers
            if producer["kind"] == "verifier"
        ]
        if payload.get("evidence_links") != expected_links:
            reasons.append("EVIDENCE_LINK_MISMATCH")
    else:
        reasons.append("CONFIG_BINDING_MISMATCH")

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
            if config_version == CONFIG_VERSION:
                verifier = artifacts[0] if len(artifacts) == 1 else None
                observation = observations[0]
                if (
                    len(observations) != 1
                    or verifier is None
                    or observation["artifact_hash"] != verifier.get("artifact_hash")
                    or observation["status"] != verifier.get("status")
                ):
                    reasons.append("VERIFIER_BINDING_MISMATCH")
            elif config_version == CONFIG_VERSION_MULTI_EVIDENCE:
                artifacts_by_id = {
                    artifact.get("producer_id"): artifact
                    for artifact in artifacts
                    if isinstance(artifact.get("producer_id"), str)
                }
                if len(observations) != len(artifacts_by_id):
                    reasons.append("VERIFIER_BINDING_MISMATCH")
                for observation in observations:
                    artifact = artifacts_by_id.get(observation.get("verifier_id"))
                    if (
                        artifact is None
                        or observation.get("artifact_hash") != artifact.get("artifact_hash")
                        or observation.get("status") != artifact.get("status")
                        or observation.get("logical_subject_id") != artifact.get("logical_subject_id")
                        or observation.get("evidence_kind") != artifact.get("evidence_kind")
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
                else canonical_hash({"config_hash": config_hash, "context": requirements_context})
            )
            if request["acceptance_contract"]["requirements_hash"] != expected_requirements_hash:
                reasons.append("CONFIG_BINDING_MISMATCH")
            if config_version == CONFIG_VERSION_MULTI_EVIDENCE and v2_config is not None:
                contract = request["acceptance_contract"]
                expected_universe = {
                    "universe_generation": contract.get("universe_generation"),
                    "expected_subjects": contract.get("expected_subjects", []),
                    "required_verifier_ids": contract.get("required_verifier_ids", []),
                }
                if payload.get("evidence_universe") != expected_universe:
                    reasons.append("EVIDENCE_UNIVERSE_MISMATCH")
                expected_subjects = [
                    {
                        "logical_subject_id": producer["logical_subject_id"],
                        "evidence_kind": producer["evidence_kind"],
                        "requirement_mode": producer["requirement_mode"],
                        "applicability": producer["applicability"],
                    }
                    for producer in _v2_producers(v2_config)
                ]
                required_ids = [
                    producer["id"]
                    for producer in _v2_producers(v2_config)
                    if producer["requirement_mode"] == "REQUIRED"
                ]
                if (
                    contract.get("universe_generation") != v2_config["universe_generation"]
                    or contract.get("expected_subjects") != expected_subjects
                    or contract.get("required_verifier_ids") != required_ids
                ):
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
    "evaluate_receipt_expectations",
    "init_repository",
    "validate_verification_receipt",
    "validate_verification_receipt_payload",
]
