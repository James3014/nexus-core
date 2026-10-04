"""Issue-bound Golden Path over the existing local repository verifier."""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from product.clients.local_golden_path import CONFIG_DIRECTORY, LocalCheckError, check_repository
from product.protocol.generic_verification import canonical_hash

ISSUE_BINDING_SCHEMA = "nexus.core.issue-binding.v1"
ISSUE_CONTEXT_SCHEMA = "nexus.core.issue-binding-context.v1"
IssueReader = Callable[[str, int], Mapping[str, Any]]


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
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers=headers), timeout=15
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
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


def _hash_without_binding(payload: Mapping[str, Any]) -> str:
    return canonical_hash({key: value for key, value in payload.items() if key != "binding_hash"})


def _validate_binding(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema") != ISSUE_BINDING_SCHEMA:
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "unsupported binding")
    contract = payload.get("issue_contract")
    if not isinstance(contract, dict):
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "missing issue contract")
    if payload.get("issue_contract_hash") != canonical_hash(contract):
        raise LocalCheckError("ISSUE_BINDING_TAMPERED", "issue contract hash mismatch")
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
    payload = {
        "schema": ISSUE_BINDING_SCHEMA,
        "version": 1,
        "bound_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "github_repository": resolved,
        "issue_number": issue_number,
        "issue_contract": contract,
        "issue_contract_hash": canonical_hash(contract),
        "github_updated_at": raw.get("updated_at"),
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
    context = {
        "schema": ISSUE_CONTEXT_SCHEMA,
        "github_repository": github_repo,
        "issue_number": issue_number,
        "issue_contract_hash": binding["issue_contract_hash"],
        "binding_hash": binding["binding_hash"],
    }
    result = check_repository(repo, requirements_context=context)
    return {
        **result,
        "github_repository": github_repo,
        "issue_number": issue_number,
        "issue_contract_hash": binding["issue_contract_hash"],
        "binding_hash": binding["binding_hash"],
        "claim_ceiling": "ISSUE_VERIFIED_NOT_RELEASED",
    }
