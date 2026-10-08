"""Issue-bound Golden Path over the existing local repository verifier."""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from product.clients.local_golden_path import (
    CONFIG_DIRECTORY,
    CONFIG_FILENAME,
    ISSUE_CEILING_UNBOUND,
    ISSUE_EVIDENCE_STALE_REASON,
    ISSUE_EVIDENCE_UNBOUND_REASON,  # noqa: F401
    LocalCheckError,
    _load_effective_config,
    check_repository,
)
from product.protocol.generic_verification import canonical_hash

LEGACY_ISSUE_BINDING_SCHEMA = "nexus.core.issue-binding.v1"
ISSUE_BINDING_SCHEMA = "nexus.core.issue-binding.v2"
ISSUE_CONTEXT_SCHEMA = "nexus.core.issue-binding-context.v2"
ISSUE_EVIDENCE_SUFFICIENCY_SCHEMA = "nexus.core.issue-evidence-sufficiency.v1"
ISSUE_EVIDENCE_MARKER_PREFIX = "<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: "
ISSUE_EVIDENCE_MARKER_SUFFIX = " -->"
ISSUE_RATE_LIMIT_RETRIES = 2
ISSUE_RATE_LIMIT_MAX_WAIT_SECONDS = 60.0
ISSUE_RATE_LIMIT_FALLBACK_WAIT_SECONDS = 1.0
IssueReader = Callable[[str, int], Mapping[str, Any]]


def _rate_limit_retry_delay(
    exc: urllib.error.HTTPError,
    detail: str,
) -> float | None:
    if exc.code not in {403, 429}:
        return None
    headers = exc.headers or {}
    remaining = str(headers.get("X-RateLimit-Remaining") or "").strip()
    normalized = detail.casefold()
    rate_limited = (
        exc.code == 429
        or remaining == "0"
        or "rate limit exceeded" in normalized
        or "secondary rate limit" in normalized
    )
    if not rate_limited:
        return None

    retry_after = str(headers.get("Retry-After") or "").strip()
    if retry_after:
        try:
            value = float(retry_after)
            if value >= 0:
                return value
        except ValueError:
            pass

    reset = str(headers.get("X-RateLimit-Reset") or "").strip()
    if reset:
        try:
            return max(0.0, float(reset) - time.time() + 1.0)
        except ValueError:
            pass

    return ISSUE_RATE_LIMIT_FALLBACK_WAIT_SECONDS


def _repo_root(path: str | Path) -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=Path(path).resolve(),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise LocalCheckError("NOT_A_GIT_REPOSITORY", (result.stderr or "").strip())
    return Path(result.stdout.strip()).resolve()


def _origin_github_repo(repo: Path) -> str | None:
    result = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    if value.startswith("git@github.com:"):
        value = value.removeprefix("git@github.com:")
    elif value.startswith("ssh://git@github.com/"):
        value = value.removeprefix("ssh://git@github.com/")
    else:
        parsed = urllib.parse.urlparse(value)
        if parsed.hostname != "github.com":
            return None
        value = parsed.path.lstrip("/")
    value = value.removesuffix(".git")
    parts = value.split("/")
    return f"{parts[0]}/{parts[1]}" if len(parts) == 2 and all(parts) else None


def _resolve_github_repo(repo: Path, explicit: str | None) -> str:
    observed = _origin_github_repo(repo)
    if explicit is None:
        if observed is None:
            raise LocalCheckError(
                "GITHUB_REPOSITORY_REQUIRED",
                "cannot derive owner/name from origin; pass --github-repo",
            )
        return observed
    parts = explicit.strip().split("/")
    if len(parts) != 2 or not all(parts):
        raise LocalCheckError("INVALID_GITHUB_REPOSITORY", explicit)
    requested = f"{parts[0]}/{parts[1]}"
    if observed and observed.lower() != requested.lower():
        raise LocalCheckError(
            "GITHUB_REPOSITORY_MISMATCH",
            f"origin={observed}, requested={requested}",
        )
    return requested


def _default_issue_reader(github_repo: str, issue_number: int) -> Mapping[str, Any]:
    url = f"https://api.github.com/repos/{github_repo}/issues/{issue_number}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "nexus-certify",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    payload: Any = None
    for attempt in range(ISSUE_RATE_LIMIT_RETRIES + 1):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=15
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            detail = exc.read(8192).decode("utf-8", errors="replace").strip()
            retry_delay = _rate_limit_retry_delay(exc, detail)
            if retry_delay is not None:
                if (
                    attempt >= ISSUE_RATE_LIMIT_RETRIES
                    or retry_delay > ISSUE_RATE_LIMIT_MAX_WAIT_SECONDS
                ):
                    raise LocalCheckError(
                        "ISSUE_RATE_LIMIT_EXHAUSTED",
                        (
                            f"{github_repo}#{issue_number}; "
                            f"retry_after_seconds={retry_delay:.3f}"
                        ),
                    ) from exc
                time.sleep(retry_delay)
                continue
            code = "ISSUE_NOT_FOUND" if exc.code == 404 else (
                "ISSUE_ACCESS_DENIED" if exc.code in {401, 403} else "ISSUE_FETCH_FAILED"
            )
            raise LocalCheckError(code, f"{github_repo}#{issue_number}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise LocalCheckError("ISSUE_FETCH_FAILED", str(exc)) from exc
    if not isinstance(payload, dict) or "pull_request" in payload:
        raise LocalCheckError("ISSUE_REQUIRED", f"{github_repo}#{issue_number}")
    return payload


def _issue_contract(github_repo: str, issue_number: int, raw: Mapping[str, Any]) -> dict[str, Any]:
    title, body, state, number = (
        raw.get("title"),
        raw.get("body"),
        raw.get("state"),
        raw.get("number"),
    )
    if number != issue_number or not isinstance(title, str) or state not in {"open", "closed"}:
        raise LocalCheckError("ISSUE_MALFORMED", f"{github_repo}#{issue_number}")
    if body is not None and not isinstance(body, str):
        raise LocalCheckError("ISSUE_MALFORMED", f"{github_repo}#{issue_number}")
    return {
        "github_repository": github_repo,
        "issue_number": issue_number,
        "title": title,
        "body": body or "",
        "state": state,
    }


def _path(repo: Path, issue_number: int) -> Path:
    return repo / CONFIG_DIRECTORY / "issues" / f"{issue_number}.json"


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _verification_contract_identity(repo: Path) -> dict[str, Any]:
    try:
        config, _source, _worktree = _load_effective_config(repo)
    except LocalCheckError as exc:
        if exc.reason_code == "CONFIG_MISSING":
            raise LocalCheckError("CONFIG_MISSING", "run nexus-certify init first") from exc
        raise
    return {
        "schema": ISSUE_EVIDENCE_SUFFICIENCY_SCHEMA,
        "config_path": f"{CONFIG_DIRECTORY}/{CONFIG_FILENAME}",
        "config_hash": canonical_hash(config),
    }


def _issue_evidence_universe_marker(contract: Mapping[str, Any]) -> str | None:
    body = contract.get("body")
    if not isinstance(body, str):
        raise LocalCheckError("ISSUE_MALFORMED", "Issue body must be text")
    matches: list[str] = []
    malformed = False
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped.startswith("<!--") or "NEXUS_CORE_EVIDENCE_UNIVERSE" not in stripped:
            continue
        if not (
            stripped.startswith(ISSUE_EVIDENCE_MARKER_PREFIX)
            and stripped.endswith(ISSUE_EVIDENCE_MARKER_SUFFIX)
        ):
            malformed = True
            continue
        value = stripped[
            len(ISSUE_EVIDENCE_MARKER_PREFIX) : -len(ISSUE_EVIDENCE_MARKER_SUFFIX)
        ]
        if not _is_sha256(value):
            malformed = True
            continue
        matches.append(value)
    if malformed or len(matches) > 1:
        raise LocalCheckError(
            "ISSUE_EVIDENCE_UNIVERSE_BINDING_MALFORMED",
            "expected at most one exact NEXUS_CORE_EVIDENCE_UNIVERSE marker",
        )
    return matches[0] if matches else None


def _evidence_sufficiency_binding(
    repo: Path,
    issue_contract_hash: str,
    *,
    declared_config_identity: str,
) -> dict[str, Any]:
    identity = _verification_contract_identity(repo)
    if identity["config_hash"] != declared_config_identity:
        raise LocalCheckError(
            ISSUE_EVIDENCE_STALE_REASON,
            "Issue evidence-universe marker does not match current verification contract",
        )
    return {
        **identity,
        "source": "issue-contract-marker",
        "issue_contract_hash": issue_contract_hash,
    }


def _hash_without_binding(payload: Mapping[str, Any]) -> str:
    return canonical_hash({key: value for key, value in payload.items() if key != "binding_hash"})


def _validate_evidence_sufficiency(
    value: Any,
    *,
    issue_contract_hash: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    required = {
        "schema",
        "config_path",
        "config_hash",
        "source",
        "issue_contract_hash",
    }
    if type(value) is not dict or set(value) != required:
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "invalid evidence sufficiency binding")
    if value.get("schema") != ISSUE_EVIDENCE_SUFFICIENCY_SCHEMA:
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "unsupported evidence sufficiency binding")
    if value.get("config_path") != f"{CONFIG_DIRECTORY}/{CONFIG_FILENAME}":
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "unexpected verification config path")
    if value.get("source") != "issue-contract-marker":
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "invalid evidence sufficiency source")
    if value.get("issue_contract_hash") != issue_contract_hash:
        raise LocalCheckError(
            "ISSUE_BINDING_TAMPERED",
            "evidence sufficiency issue contract hash mismatch",
        )
    if not _is_sha256(value.get("config_hash")):
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "invalid verification contract hash")
    return value


def _validate_binding(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema") not in {
        LEGACY_ISSUE_BINDING_SCHEMA,
        ISSUE_BINDING_SCHEMA,
    }:
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "unsupported binding")
    if payload.get("schema") == LEGACY_ISSUE_BINDING_SCHEMA:
        if payload.get("version") != 1:
            raise LocalCheckError("ISSUE_BINDING_MALFORMED", "invalid legacy binding version")
    else:
        if payload.get("version") != 2 or "evidence_sufficiency" not in payload:
            raise LocalCheckError("ISSUE_BINDING_MALFORMED", "invalid binding version")
    contract = payload.get("issue_contract")
    if not isinstance(contract, dict):
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "missing issue contract")
    issue_contract_hash = payload.get("issue_contract_hash")
    if (
        not isinstance(issue_contract_hash, str)
        or issue_contract_hash != canonical_hash(contract)
    ):
        raise LocalCheckError("ISSUE_BINDING_TAMPERED", "issue contract hash mismatch")
    if payload.get("schema") == ISSUE_BINDING_SCHEMA:
        _validate_evidence_sufficiency(
            payload.get("evidence_sufficiency"),
            issue_contract_hash=issue_contract_hash,
        )
    if payload.get("binding_hash") != _hash_without_binding(payload):
        raise LocalCheckError("ISSUE_BINDING_TAMPERED", "binding hash mismatch")
    return payload


def init_issue_binding(
    path: str | Path = ".",
    *,
    issue_number: int,
    github_repo: str | None = None,
    force: bool = False,
    issue_reader: IssueReader | None = None,
) -> Path:
    if issue_number < 1:
        raise LocalCheckError("INVALID_ISSUE_NUMBER", str(issue_number))
    repo = _repo_root(path)
    config = repo / CONFIG_DIRECTORY / "config.toml"
    if not config.is_file():
        raise LocalCheckError("CONFIG_MISSING", "run nexus-certify init first")
    resolved = _resolve_github_repo(repo, github_repo)
    raw = (issue_reader or _default_issue_reader)(resolved, issue_number)
    contract = _issue_contract(resolved, issue_number, raw)
    if contract["state"] != "open":
        raise LocalCheckError("ISSUE_NOT_OPEN", f"{resolved}#{issue_number}")
    target = _path(repo, issue_number)
    if target.exists() and not force:
        raise LocalCheckError("ISSUE_BINDING_EXISTS", str(target))
    issue_contract_hash = canonical_hash(contract)
    declared_config_identity = _issue_evidence_universe_marker(contract)
    payload = {
        "schema": ISSUE_BINDING_SCHEMA,
        "version": 2,
        "bound_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "github_repository": resolved,
        "issue_number": issue_number,
        "issue_contract": contract,
        "issue_contract_hash": issue_contract_hash,
        "github_updated_at": raw.get("updated_at"),
        "evidence_sufficiency": (
            _evidence_sufficiency_binding(
                repo,
                issue_contract_hash,
                declared_config_identity=declared_config_identity,
            )
            if declared_config_identity is not None
            else None
        ),
        "binding_hash": None,
    }
    payload["binding_hash"] = _hash_without_binding(payload)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def load_issue_binding(path: str | Path, issue_number: int) -> dict[str, Any]:
    target = _path(_repo_root(path), issue_number)
    if not target.is_file():
        raise LocalCheckError("ISSUE_BINDING_MISSING", str(target))
    try:
        return _validate_binding(json.loads(target.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", str(exc)) from exc


def check_issue(
    path: str | Path = ".",
    *,
    issue_number: int,
    issue_reader: IssueReader | None = None,
    require_trusted_config: bool = False,
) -> dict[str, Any]:
    repo = _repo_root(path)
    binding = load_issue_binding(repo, issue_number)
    github_repo = binding["github_repository"]
    raw = (issue_reader or _default_issue_reader)(github_repo, issue_number)
    current = _issue_contract(github_repo, issue_number, raw)
    if current["state"] != "open":
        raise LocalCheckError("ISSUE_NOT_OPEN", f"{github_repo}#{issue_number}")
    if canonical_hash(current) != binding["issue_contract_hash"]:
        raise LocalCheckError(
            "ISSUE_REBIND_REQUIRED",
            f"{github_repo}#{issue_number} contract changed since binding",
        )
    declared_config_identity = _issue_evidence_universe_marker(current)
    sufficiency = (
        binding.get("evidence_sufficiency")
        if binding.get("schema") == ISSUE_BINDING_SCHEMA
        else None
    )
    sufficiency_status = "UNBOUND"
    stale_detail: str | None = None
    if sufficiency is not None:
        if declared_config_identity != sufficiency["config_hash"]:
            raise LocalCheckError(
                "ISSUE_BINDING_TAMPERED",
                "bound evidence universe does not match the current Issue declaration",
            )
        current_verification_contract = _verification_contract_identity(repo)
        if sufficiency["config_hash"] != current_verification_contract["config_hash"]:
            sufficiency_status = "STALE"
            stale_detail = "verification contract changed since Issue evidence sufficiency was bound"
        else:
            sufficiency_status = "BOUND"

    context = {
        "schema": ISSUE_CONTEXT_SCHEMA,
        "github_repository": github_repo,
        "issue_number": issue_number,
        "issue_contract_hash": binding["issue_contract_hash"],
        "binding_hash": binding["binding_hash"],
        "evidence_sufficiency": {
            "status": "BOUND" if sufficiency_status == "STALE" else sufficiency_status,
            "config_hash": sufficiency["config_hash"] if sufficiency is not None else None,
        },
    }
    result = check_repository(
        repo,
        requirements_context=context,
        require_trusted_config=require_trusted_config,
        issue_verification={
            "issue_number": issue_number,
            "github_repository": github_repo,
            "issue_contract_hash": binding["issue_contract_hash"],
            "evidence_universe": sufficiency_status,
            "claim_ceiling": (
                "ISSUE_VERIFIED_NOT_RELEASED"
                if sufficiency_status == "BOUND"
                else ISSUE_CEILING_UNBOUND
            ),
        },
    )
    if stale_detail is not None:
        raise LocalCheckError(
            ISSUE_EVIDENCE_STALE_REASON,
            stale_detail,
            receipt_path=result["receipt_path"],
        )
    verdict = result["issue_verification"]
    return {
        **result,
        "github_repository": github_repo,
        "issue_number": issue_number,
        "issue_contract_hash": binding["issue_contract_hash"],
        "binding_hash": binding["binding_hash"],
        "issue_evidence_sufficiency_status": sufficiency_status,
        "repository_evidence_status": result["status"],
        "status": verdict["status"],
        "reason_codes": verdict["reason_codes"],
        "claim_ceiling": verdict["claim_ceiling"],
    }
