"""Client shell for runtime and manual handoff readiness (issue #83).

This module manages handoff configuration, service probing, verifier execution,
and fail-closed freshness checks. It emits sealed NEXUS_CORE_RUNTIME_HANDOFF_RECEIPTs
with claim ceiling MANUAL_TEST_HANDOFF_READY_NOT_RELEASED.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import tomllib
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from product.clients.local_golden_path import (
    CONFIG_DIRECTORY,
    LocalCheckError,
    _check_ignored_residue,
    _materialize_target_tree,
    _repo_root,
    _run_git,
    _sha256_bytes,
    validate_verification_receipt,
)
from product.protocol import PUBLIC_PROTOCOL_VERSION
from product.protocol.runtime_handoff import (
    HANDOFF_CLAIM_CEILING,
    HANDOFF_NON_CLAIMS,
    RUNTIME_HANDOFF_RECEIPT_KIND,
    RUNTIME_HANDOFF_SCHEMA_ID,
    canonical_hash,
    runtime_handoff_receipt_hash,
)
from product.runtime.runtime_handoff import validate_runtime_handoff_payload

HANDOFF_CONFIG_FILENAME = "handoff.toml"
HANDOFF_RECEIPT_DIRECTORY = "handoff-receipts"
HANDOFF_LATEST_POINTER_FILENAME = "latest.json"
HANDOFF_CONFIG_VERSION = 1
HANDOFF_LATEST_POINTER_VERSION = 1

_CONFIG_KEYS = {
    "version",
    "handoff_id",
    "services",
    "verifier_command",
    "timeout_seconds",
}

_SERVICE_KEYS = {
    "service_id",
    "endpoint",
    "port",
    "pid_file",
}




def _resolve_commit(repo: Path, ref: str, reason: str) -> str:
    result = _run_git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if result.returncode != 0:
        raise LocalCheckError(reason, ref)
    return result.stdout.strip()


def _non_management_dirty(repo: Path) -> list[str]:
    result = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if result.returncode != 0:
        raise LocalCheckError("CHANGES_UNDISCOVERABLE", result.stderr.strip())
    dirty: list[str] = []
    for line in result.stdout.splitlines():
        if len(line) < 4:
            continue
        candidate = line[3:]
        if " -> " in candidate:
            candidate = candidate.split(" -> ", 1)[1]
        if candidate == CONFIG_DIRECTORY or candidate.startswith(f"{CONFIG_DIRECTORY}/"):
            continue
        dirty.append(candidate)
    return dirty


def _product_tree(repo: Path, head_commit: str) -> str:
    return _materialize_target_tree(repo, head_commit)


def _handoff_config_path(repo: Path) -> Path:
    return repo / CONFIG_DIRECTORY / HANDOFF_CONFIG_FILENAME


def _handoff_receipt_dir(repo: Path) -> Path:
    return repo / CONFIG_DIRECTORY / HANDOFF_RECEIPT_DIRECTORY


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _toml_array(values: Sequence[str]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _validate_handoff_config(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _CONFIG_KEYS:
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "unexpected or missing config keys")
    if value.get("version") != HANDOFF_CONFIG_VERSION:
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "unsupported version")
    if not isinstance(value.get("handoff_id"), str) or not value["handoff_id"].strip():
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "handoff_id must be non-empty")
    command = value.get("verifier_command")
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(item, str) or not item or "\x00" in item for item in command)
    ):
        raise LocalCheckError(
            "INVALID_HANDOFF_CONFIG", "verifier_command must be a non-empty string array"
        )
    timeout = value.get("timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1 or timeout > 3600:
        raise LocalCheckError(
            "INVALID_HANDOFF_CONFIG", "timeout_seconds must be between 1 and 3600"
        )
    services = value.get("services")
    if not isinstance(services, list) or not services:
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "at least one service must be defined")
    seen_ids: set[str] = set()
    for svc in services:
        if type(svc) is not dict or not {"service_id", "endpoint"}.issubset(set(svc)):
            raise LocalCheckError(
                "INVALID_HANDOFF_CONFIG", "service missing service_id or endpoint"
            )
        if set(svc) - _SERVICE_KEYS:
            raise LocalCheckError("INVALID_HANDOFF_CONFIG", "unexpected service config keys")
        service_id = svc.get("service_id")
        endpoint = svc.get("endpoint")
        if not isinstance(service_id, str) or not service_id.strip() or "\x00" in service_id:
            raise LocalCheckError("INVALID_HANDOFF_CONFIG", "service_id must be non-empty")
        if service_id in seen_ids:
            raise LocalCheckError("INVALID_HANDOFF_CONFIG", "service_id values must be unique")
        seen_ids.add(service_id)
        if not isinstance(endpoint, str) or not endpoint.strip() or "\x00" in endpoint:
            raise LocalCheckError("INVALID_HANDOFF_CONFIG", "endpoint must be non-empty")
        port = svc.get("port")
        if port is not None and (
            not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535
        ):
            raise LocalCheckError("INVALID_HANDOFF_CONFIG", "service port must be 1..65535")
        pid_file = svc.get("pid_file")
        if pid_file is not None and (
            not isinstance(pid_file, str) or not pid_file.strip() or "\x00" in pid_file
        ):
            raise LocalCheckError("INVALID_HANDOFF_CONFIG", "pid_file must be a non-empty path")
    return value


def init_handoff(
    path: str | Path,
    *,
    handoff_id: str,
    services: Sequence[Mapping[str, Any]],
    verifier_command: Sequence[str],
    timeout_seconds: int = 300,
    force: bool = False,
) -> Path:
    """Initialize .nexus-core/handoff.toml with service definitions and verifier command."""
    repo = _repo_root(path)
    config_path = _handoff_config_path(repo)
    if config_path.exists() and not force:
        raise LocalCheckError("HANDOFF_CONFIG_EXISTS", str(config_path))

    normalized = {
        "version": HANDOFF_CONFIG_VERSION,
        "handoff_id": handoff_id,
        "services": [dict(service) if isinstance(service, Mapping) else service for service in services],
        "verifier_command": list(verifier_command),
        "timeout_seconds": timeout_seconds,
    }
    config = _validate_handoff_config(normalized)

    lines = [
        f"version = {HANDOFF_CONFIG_VERSION}",
        f"handoff_id = {_toml_string(config['handoff_id'])}",
        f"verifier_command = {_toml_array(config['verifier_command'])}",
        f"timeout_seconds = {config['timeout_seconds']}",
        "",
    ]

    for svc in services:
        lines.append("[[services]]")
        lines.append(f"service_id = {_toml_string(str(svc['service_id']))}")
        lines.append(f"endpoint = {_toml_string(str(svc['endpoint']))}")
        if "port" in svc and svc["port"] is not None:
            lines.append(f"port = {int(svc['port'])}")
        if "pid_file" in svc and svc["pid_file"]:
            lines.append(f"pid_file = {_toml_string(str(svc['pid_file']))}")
        lines.append("")

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("\n".join(lines), encoding="utf-8")
    return config_path


def _load_handoff_config(repo: Path) -> dict[str, Any]:
    path = _handoff_config_path(repo)
    if not path.is_file():
        raise LocalCheckError("HANDOFF_CONFIG_MISSING", str(path))
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", str(exc)) from exc

    return _validate_handoff_config(value)


def _parse_proc_net_tcp_listen_inodes(text: str, port: int) -> set[int]:
    """Socket inodes of LISTEN rows (state 0A) bound to ``port`` in /proc/net/tcp[6] text."""
    inodes: set[int] = set()
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or fields[3] != "0A":
            continue
        try:
            local_port = int(fields[1].rsplit(":", 1)[1], 16)
            inode = int(fields[9])
        except (IndexError, ValueError):
            continue
        if local_port == port and inode != 0:
            inodes.add(inode)
    return inodes


def _find_pid_for_port_procfs(port: int) -> int | None:
    """Linux fallback for hosts without lsof: map listening inodes to the lowest owning PID."""
    inodes: set[int] = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            inodes |= _parse_proc_net_tcp_listen_inodes(Path(table).read_text(), port)
        except OSError:
            continue
    if not inodes:
        return None
    targets = {f"socket:[{inode}]" for inode in inodes}
    try:
        pids = sorted(int(name) for name in os.listdir("/proc") if name.isdigit())
    except OSError:
        return None
    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            entries = os.listdir(fd_dir)
        except OSError:
            continue
        for entry in entries:
            try:
                if os.readlink(f"{fd_dir}/{entry}") in targets:
                    return pid
            except OSError:
                continue
    return None


def _find_pid_for_port(port: int) -> int | None:
    """Return the unique local PID that owns a listening TCP port."""
    if shutil.which("lsof") is not None:
        try:
            result = subprocess.run(
                ["lsof", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                pids = sorted(
                    {int(value.strip()) for value in result.stdout.splitlines() if value.strip()}
                )
                if len(pids) == 1:
                    return pids[0]
            return None
        except subprocess.TimeoutExpired:
            return None
        except (subprocess.SubprocessError, ValueError):
            return None
        except OSError:
            pass  # lsof failed to launch; fall through to procfs on Linux
    if sys.platform.startswith("linux"):
        return _find_pid_for_port_procfs(port)
    return None


def _get_process_start_time(pid: int) -> str | None:
    """Retrieve process start timestamp using ps, or /proc starttime ticks on Linux."""
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "lstart="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            # comm may contain spaces/parens; fields resume after the last ")".
            starttime = stat.rsplit(")", 1)[1].split()[19]
            return f"procfs-starttime-ticks:{int(starttime)}"
        except (OSError, IndexError, ValueError):
            pass
    return None


def _get_process_executable(pid: int) -> str | None:
    """Retrieve process command / executable using ps, or /proc on Linux."""
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except OSError:
            pass
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
            return comm or None
        except OSError:
            pass
    return None


def probe_service(repo: Path, svc_config: Mapping[str, Any]) -> dict[str, Any]:
    """Probe reachability and bind the process that actually owns the declared port."""
    service_id = str(svc_config["service_id"])
    endpoint = str(svc_config["endpoint"])
    port = svc_config.get("port")
    pid_file = svc_config.get("pid_file")

    parsed = urllib.parse.urlparse(endpoint)
    host = parsed.hostname or "127.0.0.1"
    if port is None:
        port = parsed.port

    reachable = False
    listener_pid: int | None = None
    if port is not None:
        try:
            with socket.create_connection((host, int(port)), timeout=2.0):
                reachable = True
        except (OSError, ValueError):
            reachable = False
        listener_pid = _find_pid_for_port(int(port))

    configured_pid: int | None = None
    if pid_file:
        pid_path = Path(pid_file)
        if not pid_path.is_absolute():
            pid_path = repo / pid_path
        if pid_path.is_file():
            try:
                configured_pid = int(pid_path.read_text(encoding="utf-8").strip())
            except (ValueError, OSError):
                configured_pid = None

    pid = configured_pid if pid_file else listener_pid
    start_time: str | None = None
    executable: str | None = None
    if pid is not None:
        try:
            os.kill(pid, 0)
            start_time = _get_process_start_time(pid)
            executable = _get_process_executable(pid)
        except OSError:
            pid = None

    identity_matches_endpoint = (
        pid is not None
        and listener_pid is not None
        and pid == listener_pid
    )
    process_identity_bound = identity_matches_endpoint and bool(start_time)

    return {
        "service_id": service_id,
        "endpoint": endpoint,
        "pid": pid,
        "listener_pid": listener_pid,
        "process_start_time": start_time,
        "executable_path": executable,
        "reachable": reachable,
        "identity_matches_endpoint": identity_matches_endpoint,
        "process_identity_bound": process_identity_bound,
    }


def _latest_timestamped_receipt(directory: Path) -> Path | None:
    if not directory.is_dir():
        return None
    receipts = sorted(
        path
        for path in directory.glob("*.json")
        if path.name != HANDOFF_LATEST_POINTER_FILENAME
    )
    return receipts[-1] if receipts else None


def _handoff_latest_pointer_path(repo: Path) -> Path:
    return _handoff_receipt_dir(repo) / HANDOFF_LATEST_POINTER_FILENAME


def _read_latest_pointer(repo: Path) -> dict[str, Any] | None:
    pointer_path = _handoff_latest_pointer_path(repo)
    if not pointer_path.is_file():
        return None
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalCheckError("HANDOFF_LATEST_POINTER_INVALID", str(exc)) from exc
    if not isinstance(pointer, dict):
        raise LocalCheckError("HANDOFF_LATEST_POINTER_INVALID", "pointer must be an object")
    pointer_hash = pointer.get("pointer_hash")
    pointer_body = {key: value for key, value in pointer.items() if key != "pointer_hash"}
    if (
        pointer.get("version") != HANDOFF_LATEST_POINTER_VERSION
        or pointer_hash != canonical_hash(pointer_body)
    ):
        raise LocalCheckError(
            "HANDOFF_LATEST_POINTER_INVALID", "latest pointer integrity check failed"
        )
    return pointer


def _latest_handoff_receipt(repo: Path) -> Path | None:
    receipt_dir = _handoff_receipt_dir(repo)
    pointer = _read_latest_pointer(repo)
    if pointer is None:
        return _latest_timestamped_receipt(receipt_dir)
    if pointer.get("state") == "IN_PROGRESS":
        raise LocalCheckError("HANDOFF_CHECK_IN_PROGRESS", "handoff verification did not finish")
    if (
        pointer.get("state") != "RECEIPT"
        or set(pointer) != {
            "version",
            "state",
            "receipt_file",
            "receipt_hash",
            "pointer_hash",
        }
        or not isinstance(pointer.get("receipt_file"), str)
        or Path(pointer["receipt_file"]).name != pointer["receipt_file"]
    ):
        raise LocalCheckError(
            "HANDOFF_LATEST_POINTER_INVALID", "unexpected latest pointer shape"
        )

    target = receipt_dir / pointer["receipt_file"]
    if not target.is_file():
        raise LocalCheckError(
            "HANDOFF_LATEST_POINTER_INVALID", "latest receipt target is missing"
        )
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalCheckError("HANDOFF_LATEST_POINTER_INVALID", str(exc)) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("receipt_hash") != pointer["receipt_hash"]
        or runtime_handoff_receipt_hash(payload) != pointer["receipt_hash"]
    ):
        raise LocalCheckError(
            "HANDOFF_LATEST_POINTER_INVALID", "latest receipt hash mismatch"
        )
    return target


def _write_latest_pointer(repo: Path, body: Mapping[str, Any]) -> None:
    receipt_dir = _handoff_receipt_dir(repo)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    pointer_body = {"version": HANDOFF_LATEST_POINTER_VERSION, **dict(body)}
    pointer = {**pointer_body, "pointer_hash": canonical_hash(pointer_body)}
    pointer_path = _handoff_latest_pointer_path(repo)
    pointer_tmp = pointer_path.with_suffix(".tmp")
    pointer_tmp.write_text(json.dumps(pointer, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(pointer_tmp, pointer_path)


def _mark_handoff_in_progress(repo: Path) -> None:
    _write_latest_pointer(
        repo,
        {
            "state": "IN_PROGRESS",
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
    )


def _write_handoff_receipt(repo: Path, payload: dict[str, Any]) -> Path:
    receipt_dir = _handoff_receipt_dir(repo)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    receipt_hash = runtime_handoff_receipt_hash(payload)
    payload["receipt_hash"] = receipt_hash
    short_hash = receipt_hash.removeprefix("sha256:")[:12]
    filename = f"{stamp}-{short_hash}.json"
    path = receipt_dir / filename
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    _write_latest_pointer(
        repo,
        {
            "state": "RECEIPT",
            "receipt_file": filename,
            "receipt_hash": receipt_hash,
        },
    )
    return path


def _write_attempt_marker(repo: Path, reason_code: str) -> Path:
    payload = {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "schema": RUNTIME_HANDOFF_SCHEMA_ID,
        "receipt_kind": RUNTIME_HANDOFF_RECEIPT_KIND,
        "claim_ceiling": HANDOFF_CLAIM_CEILING,
        "non_claims": list(HANDOFF_NON_CLAIMS),
        "handoff_id": "UNRESOLVED",
        "handoff_config_hash": canonical_hash({"state": "unresolved"}),
        "verdict": "HANDOFF_BLOCKED",
        "reason_codes": [reason_code],
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "source_binding": {
            "target_commit": "git-commit:" + "0" * 40,
            "target_tree": "git-tree:" + "0" * 40,
            "worktree_clean": False,
        },
        "prerequisite_repository": {},
        "runtime_binding": {"services": []},
        "handoff_verifier": {
            "command": ["<not-run>"],
            "exit_code": 1,
            "stdout_sha256": "sha256:" + "0" * 64,
            "stderr_sha256": "sha256:" + "0" * 64,
            "duration_ms": 0,
        },
    }
    return _write_handoff_receipt(repo, payload)


def _repository_verification_reasons(
    repo: Path,
    target_tree: str,
) -> tuple[list[str], Path | None]:
    latest = _latest_timestamped_receipt(repo / CONFIG_DIRECTORY / "receipts")
    if latest is None:
        return ["PREREQUISITE_REPOSITORY_NOT_VERIFIED"], None
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ["PREREQUISITE_REPOSITORY_NOT_VERIFIED"], latest
    if not isinstance(payload, dict):
        return ["PREREQUISITE_REPOSITORY_NOT_VERIFIED"], latest

    reasons: list[str] = []
    validation = validate_verification_receipt(latest, repo=repo)
    if not validation["valid"]:
        reasons.extend(validation["reason_codes"])
    status = payload.get("outcome", {}).get("status") or payload.get("core_response", {}).get(
        "verification", {}
    ).get("status")
    if status != "VERIFIED":
        reasons.append("REPOSITORY_RECEIPT_NOT_VERIFIED")
    if payload.get("target_tree") != target_tree:
        reasons.append("REPOSITORY_RECEIPT_STALE")
    if reasons:
        reasons.append("PREREQUISITE_REPOSITORY_NOT_VERIFIED")
    return sorted(set(reasons)), latest


def _prerequisite_binding_reasons(
    repo: Path,
    payload: Mapping[str, Any],
    target_tree: str,
) -> list[str]:
    binding = payload.get("prerequisite_repository")
    if not isinstance(binding, Mapping):
        return ["PREREQUISITE_REPOSITORY_BINDING_MISSING"]
    receipt_file = binding.get("receipt_file")
    if (
        not isinstance(receipt_file, str)
        or not receipt_file
        or Path(receipt_file).name != receipt_file
    ):
        return ["PREREQUISITE_REPOSITORY_BINDING_INVALID"]
    receipt_path = repo / CONFIG_DIRECTORY / "receipts" / receipt_file
    if not receipt_path.is_file():
        return ["PREREQUISITE_REPOSITORY_RECEIPT_MISSING"]
    try:
        bound_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ["PREREQUISITE_REPOSITORY_RECEIPT_INVALID"]
    if not isinstance(bound_payload, dict):
        return ["PREREQUISITE_REPOSITORY_RECEIPT_INVALID"]

    reasons: list[str] = []
    if bound_payload.get("receipt_hash") != binding.get("receipt_hash"):
        reasons.append("PREREQUISITE_REPOSITORY_RECEIPT_CHANGED")
    if bound_payload.get("target_tree") != target_tree or binding.get("target_tree") != target_tree:
        reasons.append("PREREQUISITE_REPOSITORY_RECEIPT_STALE")
    validation = validate_verification_receipt(receipt_path, repo=repo)
    if not validation["valid"]:
        reasons.extend(validation["reason_codes"])
        reasons.append("PREREQUISITE_REPOSITORY_RECEIPT_INVALID")
    status = bound_payload.get("outcome", {}).get("status") or bound_payload.get(
        "core_response", {}
    ).get("verification", {}).get("status")
    if status != "VERIFIED":
        reasons.append("PREREQUISITE_REPOSITORY_RECEIPT_NOT_VERIFIED")
    return sorted(set(reasons))


def _source_freshness_reasons(
    repo: Path,
    payload: Mapping[str, Any],
) -> list[str]:
    reasons: list[str] = []
    try:
        _check_ignored_residue(repo)
    except LocalCheckError as exc:
        reasons.append(exc.reason_code)

    try:
        dirty = _non_management_dirty(repo)
        if dirty:
            reasons.append("WORKTREE_DIRTY")
        head = _resolve_commit(repo, "HEAD", "HEAD_UNRESOLVED")
        tree = _product_tree(repo, head)
        source = payload.get("source_binding", {})
        if source.get("target_commit") != f"git-commit:{head}":
            reasons.append("SOURCE_HEAD_CHANGED")
        if source.get("target_tree") != f"git-tree:{tree}":
            reasons.append("SOURCE_TREE_DRIFT")
        current_tree = f"git-tree:{tree}"
        prerequisite_reasons, _ = _repository_verification_reasons(repo, current_tree)
        reasons.extend(prerequisite_reasons)
        reasons.extend(_prerequisite_binding_reasons(repo, payload, current_tree))
    except LocalCheckError as exc:
        reasons.append(exc.reason_code)
        reasons.append("SOURCE_FRESHNESS_CHECK_FAILED")
    return sorted(set(reasons))


def check_handoff(path: str | Path = ".") -> dict[str, Any]:
    """Execute runtime and manual handoff readiness verification.

    Binds pre/post Git HEAD, validates live services, executes handoff verifier,
    and writes a sealed NEXUS_CORE_RUNTIME_HANDOFF_RECEIPT.
    If any check fails, a fail-closed HANDOFF_BLOCKED receipt is written to supersede
    any earlier PASS receipt.
    """
    repo = _repo_root(path)
    _mark_handoff_in_progress(repo)
    try:
        config = _load_handoff_config(repo)
    except LocalCheckError as exc:
        rpath = _write_attempt_marker(repo, exc.reason_code)
        raise LocalCheckError(exc.reason_code, exc.detail, receipt_path=rpath) from exc
    now_iso = datetime.now(timezone.utc).isoformat()
    current_prerequisite_bind: dict[str, Any] = {}

    def make_blocked_receipt(
        reason_codes: list[str],
        *,
        source_binding: Mapping[str, Any] | None = None,
        prerequisite_repository: Mapping[str, Any] | None = None,
        runtime_binding: Mapping[str, Any] | None = None,
        handoff_verifier: Mapping[str, Any] | None = None,
    ) -> Path:
        payload = {
            "protocol_version": PUBLIC_PROTOCOL_VERSION,
            "schema": RUNTIME_HANDOFF_SCHEMA_ID,
            "receipt_kind": RUNTIME_HANDOFF_RECEIPT_KIND,
            "claim_ceiling": HANDOFF_CLAIM_CEILING,
            "non_claims": list(HANDOFF_NON_CLAIMS),
            "handoff_id": config["handoff_id"],
            "handoff_config_hash": canonical_hash(config),
            "verdict": "HANDOFF_BLOCKED",
            "reason_codes": sorted(set(reason_codes)),
            "verified_at": now_iso,
            "source_binding": dict(source_binding or {}),
            "prerequisite_repository": dict(
                current_prerequisite_bind
                if prerequisite_repository is None
                else prerequisite_repository
            ),
            "runtime_binding": dict(runtime_binding or {"services": []}),
            "handoff_verifier": dict(
                handoff_verifier
                or {
                    "command": config["verifier_command"],
                    "exit_code": 1,
                    "stdout_sha256": "sha256:" + "0" * 64,
                    "stderr_sha256": "sha256:" + "0" * 64,
                    "duration_ms": 0,
                }
            ),
        }
        return _write_handoff_receipt(repo, payload)

    # 1. Bind exact clean source state before trusting prerequisite evidence.
    try:
        _check_ignored_residue(repo)
        dirty = _non_management_dirty(repo)
        head_commit = _resolve_commit(repo, "HEAD", "HEAD_UNRESOLVED")
        product_tree = _product_tree(repo, head_commit)
    except LocalCheckError as exc:
        rpath = make_blocked_receipt([exc.reason_code])
        raise LocalCheckError(exc.reason_code, exc.detail, receipt_path=rpath) from exc

    source_bind = {
        "target_commit": f"git-commit:{head_commit}",
        "target_tree": f"git-tree:{product_tree}",
        "worktree_clean": not bool(dirty),
    }
    if dirty:
        rpath = make_blocked_receipt(["WORKTREE_DIRTY"], source_binding=source_bind)
        raise LocalCheckError("WORKTREE_DIRTY", ", ".join(dirty), receipt_path=rpath)

    # 2. Level 2 always requires a current valid Level 1 repository verification.
    prerequisite_reasons, latest_repo_receipt = _repository_verification_reasons(
        repo, source_bind["target_tree"]
    )
    if prerequisite_reasons or latest_repo_receipt is None:
        rpath = make_blocked_receipt(
            prerequisite_reasons or ["PREREQUISITE_REPOSITORY_NOT_VERIFIED"],
            source_binding=source_bind,
        )
        raise LocalCheckError(
            "PREREQUISITE_REPOSITORY_NOT_VERIFIED",
            ", ".join(prerequisite_reasons) or "repository verification receipt missing",
            receipt_path=rpath,
        )
    repo_payload = json.loads(latest_repo_receipt.read_text(encoding="utf-8"))
    prerequisite_bind = {
        "receipt_file": latest_repo_receipt.name,
        "receipt_hash": repo_payload["receipt_hash"],
        "target_tree": repo_payload["target_tree"],
    }
    current_prerequisite_bind = prerequisite_bind

    # 3. Pre-test service probe
    pre_services = [probe_service(repo, svc) for svc in config["services"]]
    runtime_bind = {"services": pre_services}
    unreachable = [s["service_id"] for s in pre_services if not s["reachable"]]
    if unreachable:
        rpath = make_blocked_receipt(
            ["RUNTIME_SERVICE_UNREACHABLE"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
        )
        raise LocalCheckError(
            "RUNTIME_SERVICE_UNREACHABLE",
            f"services unreachable: {', '.join(unreachable)}",
            receipt_path=rpath,
        )

    endpoint_mismatch = [
        svc["service_id"]
        for svc in pre_services
        if svc["pid"] is not None and not svc["identity_matches_endpoint"]
    ]
    if endpoint_mismatch:
        rpath = make_blocked_receipt(
            ["RUNTIME_PROCESS_ENDPOINT_MISMATCH"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
        )
        raise LocalCheckError(
            "RUNTIME_PROCESS_ENDPOINT_MISMATCH",
            f"services whose PID does not own the endpoint: {', '.join(endpoint_mismatch)}",
            receipt_path=rpath,
        )

    missing_identity = [
        svc["service_id"] for svc in pre_services if not svc["process_identity_bound"]
    ]
    if missing_identity:
        rpath = make_blocked_receipt(
            ["RUNTIME_PROCESS_IDENTITY_UNAVAILABLE"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
        )
        raise LocalCheckError(
            "RUNTIME_PROCESS_IDENTITY_UNAVAILABLE",
            f"services missing required process identity: {', '.join(missing_identity)}",
            receipt_path=rpath,
        )

    # 4. Verifier execution
    env = os.environ.copy()
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    start_time = time.monotonic()
    try:
        executed = subprocess.run(
            config["verifier_command"],
            cwd=repo,
            env=env,
            capture_output=True,
            timeout=config.get("timeout_seconds", 300),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        verifier_art = {
            "command": config["verifier_command"],
            "exit_code": 124,
            "stdout_sha256": _sha256_bytes(exc.stdout or b""),
            "stderr_sha256": _sha256_bytes(exc.stderr or b""),
            "duration_ms": duration_ms,
        }
        rpath = make_blocked_receipt(
            ["VERIFIER_TIMEOUT"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
            handoff_verifier=verifier_art,
        )
        raise LocalCheckError("VERIFIER_TIMEOUT", str(exc), receipt_path=rpath) from exc
    except OSError as exc:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        verifier_art = {
            "command": config["verifier_command"],
            "exit_code": 127,
            "stdout_sha256": "sha256:" + "0" * 64,
            "stderr_sha256": "sha256:" + "0" * 64,
            "duration_ms": duration_ms,
        }
        rpath = make_blocked_receipt(
            ["VERIFIER_EXECUTION_FAILED"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
            handoff_verifier=verifier_art,
        )
        raise LocalCheckError("VERIFIER_EXECUTION_FAILED", str(exc), receipt_path=rpath) from exc

    duration_ms = int((time.monotonic() - start_time) * 1000)
    verifier_art = {
        "command": config["verifier_command"],
        "exit_code": executed.returncode,
        "stdout_sha256": _sha256_bytes(executed.stdout),
        "stderr_sha256": _sha256_bytes(executed.stderr),
        "duration_ms": duration_ms,
    }

    # 5. Post-test source, config, and prerequisite evidence must remain identical/current.
    try:
        _check_ignored_residue(repo)
        post_config = _load_handoff_config(repo)
        post_head = _resolve_commit(repo, "HEAD", "HEAD_UNRESOLVED")
        post_tree = _product_tree(repo, post_head)
        post_dirty = _non_management_dirty(repo)
    except LocalCheckError as exc:
        rpath = make_blocked_receipt(
            [exc.reason_code],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
            handoff_verifier=verifier_art,
        )
        raise LocalCheckError(exc.reason_code, exc.detail, receipt_path=rpath) from exc

    if canonical_hash(post_config) != canonical_hash(config):
        rpath = make_blocked_receipt(
            ["HANDOFF_CONFIG_CHANGED"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
            handoff_verifier=verifier_art,
        )
        raise LocalCheckError(
            "HANDOFF_CONFIG_CHANGED",
            "handoff configuration changed during verification",
            receipt_path=rpath,
        )
    if post_head != head_commit:
        rpath = make_blocked_receipt(
            ["GIT_MANIFEST_MISMATCH", "SOURCE_HEAD_CHANGED"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
            handoff_verifier=verifier_art,
        )
        raise LocalCheckError(
            "GIT_MANIFEST_MISMATCH",
            "HEAD commit changed during handoff verification",
            receipt_path=rpath,
        )
    if post_dirty:
        rpath = make_blocked_receipt(
            ["GIT_MANIFEST_MISMATCH", "WORKTREE_DIRTY"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
            handoff_verifier=verifier_art,
        )
        raise LocalCheckError(
            "GIT_MANIFEST_MISMATCH",
            f"working tree became dirty: {', '.join(post_dirty)}",
            receipt_path=rpath,
        )
    if post_tree != product_tree:
        rpath = make_blocked_receipt(
            ["GIT_MANIFEST_MISMATCH", "SOURCE_TREE_DRIFT"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
            handoff_verifier=verifier_art,
        )
        raise LocalCheckError(
            "GIT_MANIFEST_MISMATCH",
            "repository product tree changed during handoff verification",
            receipt_path=rpath,
        )

    post_prerequisite_reasons, post_repo_receipt = _repository_verification_reasons(
        repo, source_bind["target_tree"]
    )
    if post_prerequisite_reasons or post_repo_receipt is None:
        rpath = make_blocked_receipt(
            post_prerequisite_reasons or ["PREREQUISITE_REPOSITORY_NOT_VERIFIED"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
            handoff_verifier=verifier_art,
        )
        raise LocalCheckError(
            "PREREQUISITE_REPOSITORY_NOT_VERIFIED",
            ", ".join(post_prerequisite_reasons),
            receipt_path=rpath,
        )
    post_repo_payload = json.loads(post_repo_receipt.read_text(encoding="utf-8"))
    current_prerequisite_bind = {
        "receipt_file": post_repo_receipt.name,
        "receipt_hash": post_repo_payload["receipt_hash"],
        "target_tree": post_repo_payload["target_tree"],
    }

    # 6. Post-test service probe & PID identity invariant check
    post_services = [probe_service(repo, svc) for svc in config["services"]]
    runtime_bind = {"services": post_services}
    for pre, post in zip(pre_services, post_services):
        if not post["reachable"]:
            rpath = make_blocked_receipt(
                ["RUNTIME_SERVICE_UNREACHABLE"],
                source_binding=source_bind,
                runtime_binding=runtime_bind,
                handoff_verifier=verifier_art,
            )
            raise LocalCheckError(
                "RUNTIME_SERVICE_UNREACHABLE",
                f"service {post['service_id']} went down during verification",
                receipt_path=rpath,
            )
        if post["pid"] is not None and not post["identity_matches_endpoint"]:
            rpath = make_blocked_receipt(
                ["RUNTIME_PROCESS_ENDPOINT_MISMATCH"],
                source_binding=source_bind,
                runtime_binding=runtime_bind,
                handoff_verifier=verifier_art,
            )
            raise LocalCheckError(
                "RUNTIME_PROCESS_ENDPOINT_MISMATCH",
                f"service {post['service_id']} PID no longer owns the endpoint",
                receipt_path=rpath,
            )
        if not post["process_identity_bound"]:
            rpath = make_blocked_receipt(
                ["RUNTIME_PROCESS_IDENTITY_UNAVAILABLE"],
                source_binding=source_bind,
                runtime_binding=runtime_bind,
                handoff_verifier=verifier_art,
            )
            raise LocalCheckError(
                "RUNTIME_PROCESS_IDENTITY_UNAVAILABLE",
                f"service {post['service_id']} has no verifiable process identity",
                receipt_path=rpath,
            )
        if (
            post["pid"] != pre["pid"]
            or post["listener_pid"] != pre["listener_pid"]
            or post["process_start_time"] != pre["process_start_time"]
        ):
            rpath = make_blocked_receipt(
                ["RUNTIME_PROCESS_IDENTITY_CHANGED"],
                source_binding=source_bind,
                runtime_binding=runtime_bind,
                handoff_verifier=verifier_art,
            )
            raise LocalCheckError(
                "RUNTIME_PROCESS_IDENTITY_CHANGED",
                f"service {post['service_id']} PID or start time changed during verification",
                receipt_path=rpath,
            )

    # 7. Verifier exit code check
    if executed.returncode != 0:
        rpath = make_blocked_receipt(
            ["HANDOFF_VERIFIER_FAILED"],
            source_binding=source_bind,
            runtime_binding=runtime_bind,
            handoff_verifier=verifier_art,
        )
        raise LocalCheckError(
            "HANDOFF_VERIFIER_FAILED",
            f"verifier exited with code {executed.returncode}",
            receipt_path=rpath,
        )

    # 8. All checks passed: seal HANDOFF_READY receipt
    receipt_payload = {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "schema": RUNTIME_HANDOFF_SCHEMA_ID,
        "receipt_kind": RUNTIME_HANDOFF_RECEIPT_KIND,
        "claim_ceiling": HANDOFF_CLAIM_CEILING,
        "non_claims": list(HANDOFF_NON_CLAIMS),
        "handoff_id": config["handoff_id"],
        "handoff_config_hash": canonical_hash(config),
        "verdict": "HANDOFF_READY",
        "reason_codes": [],
        "verified_at": now_iso,
        "source_binding": source_bind,
        "prerequisite_repository": current_prerequisite_bind,
        "runtime_binding": runtime_bind,
        "handoff_verifier": verifier_art,
    }
    receipt_path = _write_handoff_receipt(repo, receipt_payload)
    return {
        "status": "HANDOFF_READY",
        "claim_ceiling": HANDOFF_CLAIM_CEILING,
        "reason_codes": [],
        "receipt_path": receipt_path,
        "services": post_services,
    }


def _runtime_freshness_reasons(
    repo: Path,
    payload: Mapping[str, Any],
    config: Mapping[str, Any],
) -> list[str]:
    reasons: list[str] = []
    config_services = {
        service["service_id"]: service for service in config.get("services", [])
    }
    services = payload.get("runtime_binding", {}).get("services", [])
    if not isinstance(services, list) or not services:
        return ["NO_RUNTIME_SERVICES_DECLARED"]

    for service in services:
        if not isinstance(service, Mapping):
            reasons.append("RUNTIME_SERVICE_BINDING_INVALID")
            continue
        service_id = service.get("service_id")
        service_config = config_services.get(service_id)
        if service_config is None:
            reasons.append("HANDOFF_CONFIG_CHANGED")
            continue
        probed = probe_service(repo, service_config)
        if not probed["reachable"]:
            reasons.append("RUNTIME_SERVICE_UNREACHABLE")
        if probed["pid"] is not None and not probed["identity_matches_endpoint"]:
            reasons.append("RUNTIME_PROCESS_ENDPOINT_MISMATCH")
        if not probed["process_identity_bound"]:
            reasons.append("RUNTIME_PROCESS_IDENTITY_UNAVAILABLE")
        if (
            probed["pid"] != service.get("pid")
            or probed["listener_pid"] != service.get("listener_pid")
            or probed["process_start_time"] != service.get("process_start_time")
        ):
            reasons.append("RUNTIME_PROCESS_IDENTITY_CHANGED")
    return sorted(set(reasons))


def handoff_status(path: str | Path = ".") -> dict[str, Any]:
    """Read-only freshness and validity check of the current handoff attempt."""
    repo = _repo_root(path)
    try:
        latest = _latest_handoff_receipt(repo)
    except LocalCheckError as exc:
        return {
            "status": "BLOCKED",
            "fresh": False,
            "claim_ceiling": HANDOFF_CLAIM_CEILING,
            "reason_codes": [exc.reason_code],
            "receipt_path": None,
        }
    if latest is None:
        return {
            "status": "MISSING",
            "fresh": False,
            "claim_ceiling": HANDOFF_CLAIM_CEILING,
            "reason_codes": ["HANDOFF_RECEIPT_MISSING"],
            "receipt_path": None,
        }

    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "status": "BLOCKED",
            "fresh": False,
            "claim_ceiling": HANDOFF_CLAIM_CEILING,
            "reason_codes": ["MALFORMED_RECEIPT"],
            "receipt_path": latest,
        }
    if not isinstance(payload, dict):
        return {
            "status": "BLOCKED",
            "fresh": False,
            "claim_ceiling": HANDOFF_CLAIM_CEILING,
            "reason_codes": ["MALFORMED_RECEIPT"],
            "receipt_path": latest,
        }

    validation = validate_runtime_handoff_payload(payload)
    reasons = list(validation["reason_codes"])
    if payload.get("verdict") != "HANDOFF_READY":
        reasons.append("HANDOFF_NOT_READY")

    reasons.extend(_source_freshness_reasons(repo, payload))
    try:
        config = _load_handoff_config(repo)
        if payload.get("handoff_config_hash") != canonical_hash(config):
            reasons.append("HANDOFF_CONFIG_CHANGED")
        if payload.get("handoff_id") != config.get("handoff_id"):
            reasons.append("HANDOFF_CONFIG_CHANGED")
        reasons.extend(_runtime_freshness_reasons(repo, payload, config))
    except LocalCheckError as exc:
        reasons.extend(["HANDOFF_CONFIG_INVALID", exc.reason_code])

    fresh = not reasons
    return {
        "status": "HANDOFF_READY" if fresh else "BLOCKED",
        "fresh": fresh,
        "claim_ceiling": HANDOFF_CLAIM_CEILING,
        "reason_codes": sorted(set(reasons)),
        "receipt_path": latest,
    }


def validate_handoff_receipt(
    receipt_path: str | Path,
    *,
    repo: str | Path | None = None,
) -> dict[str, Any]:
    """Validate a receipt envelope and, with repo, its current handoff applicability."""
    receipt = Path(receipt_path)
    try:
        payload = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
    if not isinstance(payload, dict):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}

    res = validate_runtime_handoff_payload(payload)
    reasons = list(res["reason_codes"])
    if payload.get("verdict") != "HANDOFF_READY":
        reasons.append("HANDOFF_NOT_READY")

    if repo is not None:
        repo_root = _repo_root(repo)
        try:
            latest = _latest_handoff_receipt(repo_root)
            if latest is None or latest.resolve() != receipt.resolve():
                reasons.append("SUPERSEDED_HANDOFF_RECEIPT")
        except LocalCheckError as exc:
            reasons.append(exc.reason_code)

        reasons.extend(_source_freshness_reasons(repo_root, payload))
        try:
            config = _load_handoff_config(repo_root)
            if payload.get("handoff_config_hash") != canonical_hash(config):
                reasons.append("HANDOFF_CONFIG_CHANGED")
            if payload.get("handoff_id") != config.get("handoff_id"):
                reasons.append("HANDOFF_CONFIG_CHANGED")
            reasons.extend(_runtime_freshness_reasons(repo_root, payload, config))
        except LocalCheckError as exc:
            reasons.extend(["HANDOFF_CONFIG_INVALID", exc.reason_code])

    return {"valid": not reasons, "reason_codes": sorted(set(reasons))}


__all__ = [
    "HANDOFF_CLAIM_CEILING",
    "HANDOFF_CONFIG_FILENAME",
    "HANDOFF_CONFIG_VERSION",
    "HANDOFF_RECEIPT_DIRECTORY",
    "check_handoff",
    "handoff_status",
    "init_handoff",
    "probe_service",
    "validate_handoff_receipt",
]
