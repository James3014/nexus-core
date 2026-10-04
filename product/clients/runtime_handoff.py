"""Client shell for runtime and manual handoff readiness (issue #83).

This module manages handoff configuration, service probing, verifier execution,
and fail-closed freshness checks. It emits sealed NEXUS_CORE_RUNTIME_HANDOFF_RECEIPTs
with claim ceiling MANUAL_TEST_HANDOFF_READY_NOT_RELEASED.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import tomllib
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from product.clients.local_golden_path import (
    CONFIG_DIRECTORY,
    LocalCheckError,
    _materialize_target_tree,
    _repo_root,
    _run_git,
    _sha256_bytes,
)
from product.protocol import PUBLIC_PROTOCOL_VERSION
from product.protocol.runtime_handoff import (
    HANDOFF_CLAIM_CEILING,
    HANDOFF_NON_CLAIMS,
    RUNTIME_HANDOFF_RECEIPT_KIND,
    RUNTIME_HANDOFF_SCHEMA_ID,
    runtime_handoff_receipt_hash,
)
from product.runtime.runtime_handoff import validate_runtime_handoff_payload

HANDOFF_CONFIG_FILENAME = "handoff.toml"
HANDOFF_RECEIPT_DIRECTORY = "handoff-receipts"
HANDOFF_CONFIG_VERSION = 1

_CONFIG_KEYS = {
    "version",
    "handoff_id",
    "services",
    "verifier_command",
    "timeout_seconds",
    "require_prerequisite_repo_check",
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


def init_handoff(
    path: str | Path,
    *,
    handoff_id: str,
    services: Sequence[Mapping[str, Any]],
    verifier_command: Sequence[str],
    timeout_seconds: int = 300,
    require_prerequisite_repo_check: bool = True,
    force: bool = False,
) -> Path:
    """Initialize .nexus-core/handoff.toml with service definitions and verifier command."""
    repo = _repo_root(path)
    config_path = _handoff_config_path(repo)
    if config_path.exists() and not force:
        raise LocalCheckError("HANDOFF_CONFIG_EXISTS", str(config_path))

    if not isinstance(handoff_id, str) or not handoff_id.strip():
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "handoff_id must be non-empty")
    if not isinstance(verifier_command, (list, tuple)) or not verifier_command:
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "verifier_command must be non-empty")
    if not isinstance(services, (list, tuple)) or not services:
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "services must be non-empty")

    lines = [
        f"version = {HANDOFF_CONFIG_VERSION}",
        f"handoff_id = {_toml_string(handoff_id)}",
        f"verifier_command = {_toml_array(verifier_command)}",
        f"timeout_seconds = {int(timeout_seconds)}",
        f"require_prerequisite_repo_check = {'true' if require_prerequisite_repo_check else 'false'}",
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

    if type(value) is not dict or not _CONFIG_KEYS.issuperset(set(value)):
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "unexpected or missing config keys")
    if value.get("version") != HANDOFF_CONFIG_VERSION:
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "unsupported version")
    if not isinstance(value.get("handoff_id"), str) or not value.get("handoff_id"):
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "handoff_id must be non-empty")
    if not isinstance(value.get("verifier_command"), list) or not value.get("verifier_command"):
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "verifier_command must be non-empty")
    services = value.get("services")
    if not isinstance(services, list) or not services:
        raise LocalCheckError("INVALID_HANDOFF_CONFIG", "at least one service must be defined")
    for svc in services:
        if not isinstance(svc, dict) or not {"service_id", "endpoint"}.issubset(set(svc)):
            raise LocalCheckError("INVALID_HANDOFF_CONFIG", "service missing service_id or endpoint")
    return value


def _find_pid_for_port(port: int) -> int | None:
    """Attempt to locate listening PID for a TCP port using lsof."""
    try:
        result = subprocess.run(
            ["lsof", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().splitlines()
            if pids:
                return int(pids[0].strip())
    except (subprocess.SubprocessError, ValueError, OSError):
        pass
    return None


def _get_process_start_time(pid: int) -> str | None:
    """Retrieve process start timestamp using ps."""
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
    return None


def _get_process_executable(pid: int) -> str | None:
    """Retrieve process command / executable using ps."""
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
    return None


def probe_service(repo: Path, svc_config: Mapping[str, Any]) -> dict[str, Any]:
    """Probe a single service for network reachability and process identity."""
    service_id = str(svc_config["service_id"])
    endpoint = str(svc_config["endpoint"])
    port = svc_config.get("port")
    pid_file = svc_config.get("pid_file")

    parsed = urllib.parse.urlparse(endpoint)
    host = parsed.hostname or "127.0.0.1"
    if port is None:
        port = parsed.port

    reachable = False
    if port is not None:
        try:
            with socket.create_connection((host, int(port)), timeout=2.0):
                reachable = True
        except (OSError, ValueError):
            reachable = False
    else:
        # Fallback for paths / raw endpoints
        reachable = False

    pid: int | None = None
    if pid_file:
        pid_path = Path(pid_file)
        if not pid_path.is_absolute():
            pid_path = repo / pid_path
        if pid_path.is_file():
            try:
                pid = int(pid_path.read_text(encoding="utf-8").strip())
            except (ValueError, OSError):
                pid = None
        else:
            pid = None

    if pid is None and not pid_file and port is not None:
        pid = _find_pid_for_port(int(port))

    start_time: str | None = None
    executable: str | None = None
    if pid is not None:
        try:
            os.kill(pid, 0)
            start_time = _get_process_start_time(pid)
            executable = _get_process_executable(pid)
        except OSError:
            # Process does not exist
            pid = None

    return {
        "service_id": service_id,
        "endpoint": endpoint,
        "pid": pid,
        "process_start_time": start_time,
        "executable_path": executable,
        "reachable": reachable,
    }


def _latest_receipt(directory: Path) -> Path | None:
    if not directory.is_dir():
        return None
    receipts = sorted(directory.glob("*.json"))
    return receipts[-1] if receipts else None


def _write_handoff_receipt(repo: Path, payload: dict[str, Any]) -> Path:
    receipt_dir = _handoff_receipt_dir(repo)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    receipt_hash = runtime_handoff_receipt_hash(payload)
    payload["receipt_hash"] = receipt_hash
    short_hash = receipt_hash.removeprefix("sha256:")[:12]
    filename = f"{stamp}-{short_hash}.json"
    path = receipt_dir / filename
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def check_handoff(path: str | Path = ".") -> dict[str, Any]:
    """Execute runtime and manual handoff readiness verification.

    Binds pre/post Git HEAD, validates live services, executes handoff verifier,
    and writes a sealed NEXUS_CORE_RUNTIME_HANDOFF_RECEIPT.
    If any check fails, a fail-closed HANDOFF_BLOCKED receipt is written to supersede
    any earlier PASS receipt.
    """
    repo = _repo_root(path)
    config = _load_handoff_config(repo)
    now_iso = datetime.now(timezone.utc).isoformat()

    def make_blocked_receipt(
        reason_codes: list[str],
        *,
        source_binding: Mapping[str, Any] | None = None,
        runtime_binding: Mapping[str, Any] | None = None,
        handoff_verifier: Mapping[str, Any] | None = None,
    ) -> Path:
        payload = {
            "protocol_version": PUBLIC_PROTOCOL_VERSION,
            "schema": RUNTIME_HANDOFF_SCHEMA_ID,
            "receipt_kind": RUNTIME_HANDOFF_RECEIPT_KIND,
            "claim_ceiling": HANDOFF_CLAIM_CEILING,
            "non_claims": list(HANDOFF_NON_CLAIMS),
            "verdict": "HANDOFF_BLOCKED",
            "reason_codes": sorted(set(reason_codes)),
            "verified_at": now_iso,
            "source_binding": dict(source_binding or {}),
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

    # 1. Prerequisite repository verification check
    repo_receipts_dir = repo / CONFIG_DIRECTORY / "receipts"
    latest_repo_receipt = _latest_receipt(repo_receipts_dir)
    if config.get("require_prerequisite_repo_check", True):
        if latest_repo_receipt is None:
            rpath = make_blocked_receipt(["PREREQUISITE_REPOSITORY_NOT_VERIFIED"])
            raise LocalCheckError(
                "PREREQUISITE_REPOSITORY_NOT_VERIFIED",
                "repository verification receipt missing",
                receipt_path=rpath,
            )
        try:
            repo_payload = json.loads(latest_repo_receipt.read_text(encoding="utf-8"))
            repo_status = repo_payload.get("outcome", {}).get(
                "status"
            ) or repo_payload.get("core_response", {}).get("verification", {}).get(
                "status"
            )
            if repo_status != "VERIFIED":
                rpath = make_blocked_receipt(["PREREQUISITE_REPOSITORY_NOT_VERIFIED"])
                raise LocalCheckError(
                    "PREREQUISITE_REPOSITORY_NOT_VERIFIED",
                    "latest repository receipt is not VERIFIED",
                    receipt_path=rpath,
                )
        except (OSError, json.JSONDecodeError) as exc:
            rpath = make_blocked_receipt(["PREREQUISITE_REPOSITORY_NOT_VERIFIED"])
            raise LocalCheckError(
                "PREREQUISITE_REPOSITORY_NOT_VERIFIED",
                f"unreadable repository receipt: {exc}",
                receipt_path=rpath,
            ) from exc

    # 2. Source working tree clean check
    dirty = _non_management_dirty(repo)
    head_commit = _resolve_commit(repo, "HEAD", "HEAD_UNRESOLVED")
    product_tree = _product_tree(repo, head_commit)
    source_bind = {
        "target_commit": f"git-commit:{head_commit}",
        "target_tree": f"git-tree:{product_tree}",
        "worktree_clean": not bool(dirty),
    }

    if dirty:
        rpath = make_blocked_receipt(["WORKTREE_DIRTY"], source_binding=source_bind)
        raise LocalCheckError("WORKTREE_DIRTY", ", ".join(dirty), receipt_path=rpath)

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

    # 5. Post-test Git check
    post_head = _resolve_commit(repo, "HEAD", "HEAD_UNRESOLVED")
    post_tree = _product_tree(repo, post_head)
    post_dirty = _non_management_dirty(repo)
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
        if pre["pid"] is not None and (
            post["pid"] != pre["pid"] or post["process_start_time"] != pre["process_start_time"]
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
        "verdict": "HANDOFF_READY",
        "reason_codes": [],
        "verified_at": now_iso,
        "source_binding": source_bind,
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


def handoff_status(path: str | Path = ".") -> dict[str, Any]:
    """Read-only freshness and validity check of the latest handoff receipt."""
    repo = _repo_root(path)
    latest = _latest_receipt(_handoff_receipt_dir(repo))
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
            "status": "INVALID",
            "fresh": False,
            "claim_ceiling": HANDOFF_CLAIM_CEILING,
            "reason_codes": ["MALFORMED_RECEIPT"],
            "receipt_path": latest,
        }

    # Core validation
    validation = validate_runtime_handoff_payload(payload)
    reasons = list(validation["reason_codes"])

    # If the latest receipt itself was BLOCKED/FAILED, it remains BLOCKED (fail-closed)
    if payload.get("verdict") != "HANDOFF_READY":
        reasons.append("HANDOFF_NOT_READY")

    # Source freshness checks
    try:
        head_commit = _resolve_commit(repo, "HEAD", "HEAD_UNRESOLVED")
        product_tree = _product_tree(repo, head_commit)
        expected_commit = payload.get("source_binding", {}).get("target_commit")
        expected_tree = payload.get("source_binding", {}).get("target_tree")

        if expected_commit != f"git-commit:{head_commit}":
            reasons.append("SOURCE_HEAD_CHANGED")
        if expected_tree != f"git-tree:{product_tree}":
            reasons.append("SOURCE_TREE_DRIFT")

        dirty = _non_management_dirty(repo)
        if dirty:
            reasons.append("WORKTREE_DIRTY")
    except (KeyError, TypeError, LocalCheckError):
        reasons.append("SOURCE_FRESHNESS_CHECK_FAILED")

    # Live runtime freshness checks
    try:
        config = _load_handoff_config(repo)
        config_services = {s["service_id"]: s for s in config.get("services", [])}
    except LocalCheckError:
        config_services = {}

    services = payload.get("runtime_binding", {}).get("services", [])
    for svc in services:
        svc_cfg = config_services.get(svc.get("service_id")) or svc
        probed = probe_service(repo, svc_cfg)
        if not probed["reachable"]:
            reasons.append("RUNTIME_SERVICE_UNREACHABLE")
        if svc.get("pid") is not None and (
            probed["pid"] != svc.get("pid")
            or probed["process_start_time"] != svc.get("process_start_time")
        ):
            reasons.append("RUNTIME_PROCESS_IDENTITY_CHANGED")

    fresh = not reasons
    status = "HANDOFF_READY" if fresh else "BLOCKED"
    return {
        "status": status,
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
    """Validate a handoff receipt file against Core truth criteria."""
    try:
        payload = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}
    if not isinstance(payload, dict):
        return {"valid": False, "reason_codes": ["MALFORMED_RECEIPT"]}

    res = validate_runtime_handoff_payload(payload)
    reasons = list(res["reason_codes"])

    if repo is not None:
        repo_root = _repo_root(repo)
        try:
            head = _resolve_commit(repo_root, "HEAD", "HEAD_UNRESOLVED")
            expected_commit = payload.get("source_binding", {}).get("target_commit")
            if expected_commit != f"git-commit:{head}":
                reasons.append("SOURCE_HEAD_CHANGED")
        except LocalCheckError:
            reasons.append("SOURCE_HEAD_CHANGED")

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
