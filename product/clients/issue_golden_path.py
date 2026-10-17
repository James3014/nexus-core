# pyright: strict, reportUnnecessaryIsInstance=false, reportUnnecessaryComparison=false
"""Issue-bound Golden Path over the existing local repository verifier."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, cast

from product.clients import gate_diagnostics
from product.clients.local_golden_path import (
    _MATERIAL_IDENTITY_RE,  # pyright: ignore[reportPrivateUsage]
    CONFIG_DIRECTORY,
    CONFIG_FILENAME,
    ISSUE_CEILING_UNBOUND,
    ISSUE_EVIDENCE_STALE_REASON,
    ISSUE_EVIDENCE_UNBOUND_REASON,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    MATERIAL_TRANSITION_AUTHORIZED_ASSOCIATIONS,
    LocalCheckError,
    _load_effective_config,  # pyright: ignore[reportPrivateUsage]
    _raise_with_receipt,  # pyright: ignore[reportPrivateUsage]
    check_repository,
)
from product.protocol.generic_verification import canonical_hash

LEGACY_ISSUE_BINDING_SCHEMA = "nexus.core.issue-binding.v1"
ISSUE_BINDING_SCHEMA = "nexus.core.issue-binding.v2"
ISSUE_CONTEXT_SCHEMA = "nexus.core.issue-binding-context.v2"
ISSUE_EVIDENCE_SUFFICIENCY_SCHEMA = "nexus.core.issue-evidence-sufficiency.v1"
ISSUE_EVIDENCE_MARKER_PREFIX = gate_diagnostics.EVIDENCE_MARKER_PREFIX
ISSUE_EVIDENCE_MARKER_SUFFIX = gate_diagnostics.EVIDENCE_MARKER_SUFFIX
ISSUE_MATERIAL_TRANSITION_TOKEN = "NEXUS_CORE_MATERIAL_TRANSITION"
ISSUE_MATERIAL_TRANSITION_SOURCE = "issue-contract-marker"
EVIDENCE_UNIVERSE_SOURCE_MARKER = "issue-contract-marker"
EVIDENCE_UNIVERSE_SOURCE_TRUSTED_CONFIG = "trusted-base-config"
EVIDENCE_UNIVERSE_MODES = ("issue-marker", "trusted-config")
_MATERIAL_TRANSITION_RE = re.compile(
    r"<!-- NEXUS_CORE_MATERIAL_TRANSITION: (\S+) (\S+) -> (\S+) -->"
)
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
    return cast("dict[str, Any]", payload)


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
    contract: dict[str, Any] = {
        "github_repository": github_repo,
        "issue_number": issue_number,
        "title": title,
        "body": body or "",
        "state": state,
    }
    # Authorship is part of the frozen contract so a transition marker cannot be
    # re-attributed. Keys are only added when the reader supplies them, which keeps
    # contract hashes stable for readers that do not (such Issues cannot authorize).
    association = raw.get("author_association")
    if isinstance(association, str):
        contract["author_association"] = association
    user = raw.get("user")
    login = cast("Mapping[str, Any]", user).get("login") if isinstance(user, Mapping) else None
    if isinstance(login, str) and login:
        contract["author_login"] = login
    return contract


# --- KEEP_OPEN intent items (#276) ---------------------------------------------
# The PR body may carry NEXUS_ISSUE_INTENT_V1 = JSON list of
#   {"issue": N, "on_merge": "KEEP_OPEN", "items": ["3"], "split": {"4": 2314}}.
# `items` names the Issue items this PR completes; `split` maps an item to the
# Issue it moved to. Both are optional and display-only: they never change the
# verdict, only the receipt's `issue_verification` and the check-run summary.
# Absent fields (or no PR body) leave behaviour and receipts exactly as before.
#
# Item list parser (deliberately small): code fences are skipped. Under the
# headings `## Problem`, `## Proposal`, `## Done when` and `## Change` (case-insensitive,
# until the next `## ` heading) each numbered line `1.` / `2)` is an item whose
# id is that number. If there are none, every `- [ ]` / `- [x]` checklist line
# in the body is an item whose id is its 1-based position.
ISSUE_ITEMS_MALFORMED = "ISSUE_ITEMS_MALFORMED"
ISSUE_ITEMS_UNKNOWN = "ISSUE_ITEMS_UNKNOWN"
ISSUE_ITEMS_REQUIRE_KEEP_OPEN = "ISSUE_ITEMS_REQUIRE_KEEP_OPEN"
_INTENT_BLOCK_RE = re.compile(
    r"<!--\s*NEXUS_ISSUE_INTENT_V1\s*(.*?)\s*NEXUS_ISSUE_INTENT_V1\s*-->", re.DOTALL
)
_ITEM_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
_ITEM_SECTIONS = {"problem", "proposal", "done when", "change"}
_NUMBERED_RE = re.compile(r"\s{0,3}(\d{1,4})[.)]\s+\S")
_CHECKLIST_RE = re.compile(r"\s{0,3}[-*]\s+\[[ xX]\]\s+\S")
_HEADING_RE = re.compile(r"\s{0,3}##\s+(.*?)\s*#*\s*$")
INTENT_BODY_MAX_BYTES = 65536


def parse_issue_items(body: str) -> list[str]:
    """Return the ordered, de-duplicated item ids of an Issue body (see above)."""

    numbered: list[str] = []
    checklist: list[str] = []
    fence: str | None = None
    in_section = False
    for line in (body or "").splitlines():
        lead = line.lstrip()
        if lead.startswith(("```", "~~~")):
            marker = lead[:3]
            fence = None if fence == marker else (fence or marker)
            continue
        if fence is not None:
            continue
        heading = _HEADING_RE.fullmatch(line)
        if heading is not None:
            in_section = heading.group(1).strip().casefold() in _ITEM_SECTIONS
            continue
        if in_section:
            match = _NUMBERED_RE.match(line)
            if match is not None and match.group(1) not in numbered:
                numbered.append(match.group(1))
        if _CHECKLIST_RE.match(line):
            checklist.append(str(len(checklist) + 1))
    return numbered or checklist


def _intent_for_issue(pr_body: str, issue_number: int) -> dict[str, Any] | None:
    """The one intent entry naming `issue_number` that uses items/split, else None.

    Unreadable intent blocks are ignored: their form is enforced elsewhere and
    this reads only the optional, display-only fields.
    """

    found: list[dict[str, Any]] = []
    for block in _INTENT_BLOCK_RE.findall(pr_body[:INTENT_BODY_MAX_BYTES]):
        try:
            data = json.loads(block)
        except (ValueError, RecursionError):
            continue
        if not isinstance(data, list):
            continue
        for entry in cast("list[Any]", data):
            if (
                isinstance(entry, dict)
                and cast("dict[str, Any]", entry).get("issue") == issue_number
                and ("items" in cast("dict[str, Any]", entry) or "split" in cast("dict[str, Any]", entry))
            ):
                found.append(cast("dict[str, Any]", entry))
    if len(found) > 1:
        raise LocalCheckError(ISSUE_ITEMS_MALFORMED, "more than one intent entry carries items")
    return found[0] if found else None


def resolve_intent_items(
    pr_body: str | None, issue_number: int, issue_body: str
) -> dict[str, Any]:
    """Validated {claimed_items, remaining_items, split} for the receipt, or {}."""

    if not pr_body:
        return {}
    entry = _intent_for_issue(pr_body, issue_number)
    if entry is None:
        return {}
    if entry.get("on_merge") != "KEEP_OPEN":
        raise LocalCheckError(
            ISSUE_ITEMS_REQUIRE_KEEP_OPEN, "items/split are only allowed with on_merge KEEP_OPEN"
        )
    raw_items: Any = entry.get("items", [])
    if (
        not isinstance(raw_items, list)
        or len(cast("list[Any]", raw_items)) > 64
        or not all(
            isinstance(i, str) and _ITEM_ID_RE.fullmatch(i) for i in cast("list[Any]", raw_items)
        )
        or len(set(cast("list[str]", raw_items))) != len(cast("list[Any]", raw_items))
    ):
        raise LocalCheckError(ISSUE_ITEMS_MALFORMED, "items must be a list of unique item ids")
    items = cast("list[str]", raw_items)
    raw_split: Any = entry.get("split", {})
    if not isinstance(raw_split, dict) or len(cast("dict[Any, Any]", raw_split)) > 64:
        raise LocalCheckError(ISSUE_ITEMS_MALFORMED, "split must map item ids to Issue numbers")
    split: dict[str, int] = {}
    for key, value in cast("dict[Any, Any]", raw_split).items():
        if (
            not isinstance(key, str)
            or not _ITEM_ID_RE.fullmatch(key)
            or type(value) is not int
            or value < 1
            or value == issue_number
        ):
            raise LocalCheckError(ISSUE_ITEMS_MALFORMED, "split must map item ids to Issue numbers")
        split[key] = value
    if not items and not split:
        raise LocalCheckError(ISSUE_ITEMS_MALFORMED, "items/split present but empty")
    if set(items) & set(split):
        raise LocalCheckError(ISSUE_ITEMS_MALFORMED, "an item cannot be both claimed and split")
    known = parse_issue_items(issue_body or "")
    unknown = [i for i in [*items, *split] if i not in known]
    if unknown:
        raise LocalCheckError(
            ISSUE_ITEMS_UNKNOWN,
            f"item ids {', '.join(unknown)} not in the Issue item list "
            f"({', '.join(known) if known else 'no items found'})",
        )
    remaining = [i for i in known if i not in items and i not in split]
    out: dict[str, Any] = {"claimed_items": items, "remaining_items": remaining}
    if split:
        out["split"] = split
    return out


ISSUE_ITEMS_COMPLETE = "ISSUE_ITEMS_COMPLETE"
ISSUE_ITEMS_INCOMPLETE = "ISSUE_ITEMS_INCOMPLETE"
ISSUE_ITEMS_SOURCE_UNAVAILABLE = "ISSUE_ITEMS_SOURCE_UNAVAILABLE"
TIMELINE_MAX_PAGES = 5

# --- ISSUE_ITEMS_COMPLETE (#294) -------------------------------------------------
# Display-only aggregation. Canonical source of "which merged PR claimed which
# item": the NEXUS_ISSUE_INTENT_V1 `items` of PRs that GitHub's own Issue timeline
# lists as cross-referencing this Issue AND as merged in this same repository. The
# claim text is author-written, so ISSUE_ITEMS_COMPLETE only means "every Issue item
# is claimed"; it never changes the verdict or ceiling and is not acceptance. If
# the source cannot be read completely the status is SOURCE_UNAVAILABLE.
MergedClaimsReader = Callable[[str, int], "Sequence[Mapping[str, Any]] | None"]


def merged_prs_from_timeline(
    github_repo: str, events: Sequence[Any]
) -> list[dict[str, Any]]:
    """Merged same-repository PRs (number, body) found in Issue timeline events."""

    prs: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        event = cast("Mapping[str, Any]", event)
        source = event.get("source")
        if event.get("event") != "cross-referenced" or not isinstance(source, Mapping):
            continue
        issue = cast("Mapping[str, Any]", source).get("issue")
        if not isinstance(issue, Mapping):
            continue
        issue = cast("Mapping[str, Any]", issue)
        pull = issue.get("pull_request")
        repo = issue.get("repository")
        name = cast("Mapping[str, Any]", repo).get("full_name") if isinstance(repo, Mapping) else None
        if (
            not isinstance(pull, Mapping)
            or not cast("Mapping[str, Any]", pull).get("merged_at")
            or not isinstance(name, str)
            or name.lower() != github_repo.lower()
            or type(issue.get("number")) is not int
        ):
            continue
        body = issue.get("body")
        prs.append({"number": issue["number"], "body": body if isinstance(body, str) else ""})
    return prs


def _default_merged_claims_reader(
    github_repo: str, issue_number: int
) -> list[dict[str, Any]] | None:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "nexus-certify",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    events: list[Any] = []
    for page in range(1, TIMELINE_MAX_PAGES + 1):
        url = (
            f"https://api.github.com/repos/{github_repo}/issues/{issue_number}"
            f"/timeline?per_page=100&page={page}"
        )
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=15
            ) as response:
                batch: Any = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None
        if not isinstance(batch, list):
            return None
        events.extend(cast("list[Any]", batch))
        if len(cast("list[Any]", batch)) < 100:
            return merged_prs_from_timeline(github_repo, events)
    return None  # more pages than we read: the list is not provably complete


def _merged_claimed_items(
    prs: Sequence[Any], issue_number: int, known: Sequence[str]
) -> tuple[list[str], list[str]]:
    """(items claimed, items split out) by the merged PRs; both in Issue order."""

    claimed: set[str] = set()
    split: dict[str, int] = {}
    for pr in prs:
        if not isinstance(pr, Mapping):
            continue
        pr = cast("Mapping[str, Any]", pr)
        body = pr.get("body")
        if type(pr.get("number")) is not int or not isinstance(body, str):
            continue
        for block in _INTENT_BLOCK_RE.findall(body[:INTENT_BODY_MAX_BYTES]):
            try:
                data = json.loads(block)
            except (ValueError, RecursionError):
                continue
            if not isinstance(data, list):
                continue
            for entry in cast("list[Any]", data):
                if not isinstance(entry, dict):
                    continue
                entry = cast("dict[str, Any]", entry)
                items = entry.get("items")
                if (
                    entry.get("issue") == issue_number
                    and entry.get("on_merge") == "KEEP_OPEN"
                    and isinstance(items, list)
                ):
                    claimed.update(
                        i for i in cast("list[Any]", items) if isinstance(i, str) and i in known
                    )
                raw_split = entry.get("split")
                if entry.get("issue") == issue_number and entry.get("on_merge") == "KEEP_OPEN" and isinstance(raw_split, dict):
                    split.update(
                        {
                            k: v
                            for k, v in cast("dict[Any, Any]", raw_split).items()
                            if isinstance(k, str) and k in known and type(v) is int and v != issue_number
                        }
                    )
    return [i for i in known if i in claimed], [i for i in known if i in split and i not in claimed]


def resolve_items_status(
    github_repo: str,
    issue_number: int,
    issue_body: str,
    verdict_items: Mapping[str, Any],
    reader: MergedClaimsReader | None,
) -> dict[str, Any]:
    """{items_status[, merged_claimed_items]} for a PR that carries items, else {}."""

    if "claimed_items" not in verdict_items:
        return {}
    try:
        prs = reader(github_repo, issue_number) if reader is not None else None
    except Exception:  # noqa: BLE001 - any source failure means "unknown", never a claim
        prs = None
    if not isinstance(prs, (list, tuple)):
        return {"items_status": ISSUE_ITEMS_SOURCE_UNAVAILABLE}
    try:
        known = parse_issue_items(issue_body or "")
        merged, merged_split = _merged_claimed_items(
            cast("Sequence[Any]", prs), issue_number, known
        )
        # Same accounting as #295's remaining_items: an item is accounted for when it is
        # claimed or split out to another Issue (by a merged PR or by this PR).
        covered = (
            set(merged)
            | set(merged_split)
            | set(cast("list[str]", verdict_items["claimed_items"]))
            | set(cast("dict[str, int]", verdict_items.get("split", {})))
        )
        complete = bool(known) and all(i in covered for i in known)
    except Exception:  # noqa: BLE001 - display-only: never let aggregation break the check
        return {"items_status": ISSUE_ITEMS_SOURCE_UNAVAILABLE}
    return {
        "items_status": ISSUE_ITEMS_COMPLETE if complete else ISSUE_ITEMS_INCOMPLETE,
        "merged_claimed_items": merged,
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


def _issue_material_transitions(contract: Mapping[str, Any]) -> list[dict[str, str]]:
    """Parse exact NEXUS_CORE_MATERIAL_TRANSITION markers from the Issue contract."""

    body = contract.get("body")
    if not isinstance(body, str):
        raise LocalCheckError("ISSUE_MALFORMED", "Issue body must be text")
    transitions: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped.startswith("<!--") or ISSUE_MATERIAL_TRANSITION_TOKEN not in stripped:
            continue
        match = _MATERIAL_TRANSITION_RE.fullmatch(stripped)
        if match is None:
            raise LocalCheckError(
                "ISSUE_MATERIAL_TRANSITION_MALFORMED",
                "expected <!-- NEXUS_CORE_MATERIAL_TRANSITION: <id> <from> -> <to> -->",
            )
        material_id, from_identity, to_identity = match.groups()
        if not all(_MATERIAL_IDENTITY_RE.fullmatch(v) for v in (from_identity, to_identity)):
            raise LocalCheckError(
                "ISSUE_MATERIAL_TRANSITION_MALFORMED",
                "identities must look like <scheme>:<value> without whitespace",
            )
        if material_id in seen or from_identity == to_identity:
            raise LocalCheckError(
                "ISSUE_MATERIAL_TRANSITION_MALFORMED",
                f"duplicate or no-op transition for material {material_id}",
            )
        seen.add(material_id)
        transitions.append(
            {
                "material_id": material_id,
                "from_identity": from_identity,
                "to_identity": to_identity,
                "source": ISSUE_MATERIAL_TRANSITION_SOURCE,
            }
        )
    return transitions


def _evidence_sufficiency_binding(
    repo: Path,
    issue_contract_hash: str,
    *,
    declared_config_identity: str,
    issue_number: int,
) -> dict[str, Any]:
    identity = _verification_contract_identity(repo)
    if identity["config_hash"] != declared_config_identity:
        expected = gate_diagnostics.evidence_marker_line(identity["config_hash"])
        raise LocalCheckError(
            ISSUE_EVIDENCE_STALE_REASON,
            "Issue evidence-universe marker does not match current verification contract; "
            f"expected Issue body line: {expected}",
            remediation=gate_diagnostics.stale_evidence_universe(
                issue_number, identity["config_hash"]
            ),
        )
    return {
        **identity,
        "source": "issue-contract-marker",
        "issue_contract_hash": issue_contract_hash,
    }


def _trusted_config_evidence_binding(repo: Path, issue_contract_hash: str) -> dict[str, Any]:
    return {
        **_verification_contract_identity(repo),
        "source": EVIDENCE_UNIVERSE_SOURCE_TRUSTED_CONFIG,
        "issue_contract_hash": issue_contract_hash,
    }


def _check_evidence_universe_mode(mode: str) -> None:
    if mode not in EVIDENCE_UNIVERSE_MODES:
        raise LocalCheckError("INVALID_EVIDENCE_UNIVERSE_MODE", str(mode))


def _require_base_ref_config(repo: Path) -> None:
    """Trusted-config mode only binds a config committed on the base ref (never the worktree)."""

    _config, source, _worktree = _load_effective_config(repo)
    if source["kind"] != "base-ref":
        raise LocalCheckError(
            "CONFIG_UNTRUSTED",
            f"trusted-config evidence universe needs {CONFIG_DIRECTORY}/{CONFIG_FILENAME} "
            "committed on the base ref (a plain branch name, not a revision expression)",
        )


def _advisory_marker_warning(contract: Mapping[str, Any], current_hash: str) -> str | None:
    """In trusted-config mode a bad or stale marker is advisory only (never an error)."""

    try:
        declared = _issue_evidence_universe_marker(contract)
    except LocalCheckError as exc:
        return f"ignoring malformed NEXUS_CORE_EVIDENCE_UNIVERSE marker ({exc.detail})"
    if declared is not None and declared != current_hash:
        return "ignoring stale NEXUS_CORE_EVIDENCE_UNIVERSE marker (not used in trusted-config mode)"
    return None


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
    if type(value) is not dict or set(cast("dict[str, Any]", value)) != required:
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "invalid evidence sufficiency binding")
    value = cast("dict[str, Any]", value)
    if value.get("schema") != ISSUE_EVIDENCE_SUFFICIENCY_SCHEMA:
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "unsupported evidence sufficiency binding")
    if value.get("config_path") != f"{CONFIG_DIRECTORY}/{CONFIG_FILENAME}":
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "unexpected verification config path")
    if value.get("source") not in {
        EVIDENCE_UNIVERSE_SOURCE_MARKER,
        EVIDENCE_UNIVERSE_SOURCE_TRUSTED_CONFIG,
    }:
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
    if not isinstance(payload, dict) or cast("dict[str, Any]", payload).get("schema") not in {
        LEGACY_ISSUE_BINDING_SCHEMA,
        ISSUE_BINDING_SCHEMA,
    }:
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "unsupported binding")
    payload = cast("dict[str, Any]", payload)
    if payload.get("schema") == LEGACY_ISSUE_BINDING_SCHEMA:
        if payload.get("version") != 1:
            raise LocalCheckError("ISSUE_BINDING_MALFORMED", "invalid legacy binding version")
    else:
        if payload.get("version") != 2 or "evidence_sufficiency" not in payload:
            raise LocalCheckError("ISSUE_BINDING_MALFORMED", "invalid binding version")
    contract = payload.get("issue_contract")
    if not isinstance(contract, dict):
        raise LocalCheckError("ISSUE_BINDING_MALFORMED", "missing issue contract")
    contract = cast("dict[str, Any]", contract)
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
    evidence_universe: str = "issue-marker",
) -> Path:
    _check_evidence_universe_mode(evidence_universe)
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
    trusted = evidence_universe == "trusted-config"
    declared_config_identity: str | None = None
    if trusted:
        _require_base_ref_config(repo)
        warning = _advisory_marker_warning(
            contract, _verification_contract_identity(repo)["config_hash"]
        )
        if warning is not None:
            print(f"warning: {warning}", file=sys.stderr)
    else:
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
            _trusted_config_evidence_binding(repo, issue_contract_hash)
            if trusted
            else _evidence_sufficiency_binding(
                repo,
                issue_contract_hash,
                declared_config_identity=declared_config_identity,
                issue_number=issue_number,
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
    expect_config_commit: str | None = None,
    evidence_universe: str = "issue-marker",
    pr_body: str | None = None,
    merged_claims_reader: MergedClaimsReader | None = None,
) -> dict[str, Any]:
    _check_evidence_universe_mode(evidence_universe)
    trusted = evidence_universe == "trusted-config"
    if trusted and not require_trusted_config:
        # Fail closed (not force): the caller must say it, so a receipt can never be
        # produced from a worktree config while claiming trusted-base-config.
        raise LocalCheckError(
            "EVIDENCE_UNIVERSE_REQUIRES_TRUSTED_CONFIG",
            "--evidence-universe trusted-config requires --require-trusted-config",
        )
    repo = _repo_root(path)
    binding = load_issue_binding(repo, issue_number)
    github_repo = _resolve_github_repo(repo, binding["github_repository"])
    raw = (issue_reader or _default_issue_reader)(github_repo, issue_number)
    current = _issue_contract(github_repo, issue_number, raw)
    if current["state"] != "open":
        raise LocalCheckError("ISSUE_NOT_OPEN", f"{github_repo}#{issue_number}")
    if canonical_hash(current) != binding["issue_contract_hash"]:
        raise LocalCheckError(
            "ISSUE_REBIND_REQUIRED",
            f"{github_repo}#{issue_number} contract changed since binding",
        )
    sufficiency = (
        binding.get("evidence_sufficiency")
        if binding.get("schema") == ISSUE_BINDING_SCHEMA
        else None
    )
    bound_source = sufficiency["source"] if sufficiency is not None else None
    if trusted:
        if sufficiency is not None and bound_source != EVIDENCE_UNIVERSE_SOURCE_TRUSTED_CONFIG:
            raise LocalCheckError(
                "ISSUE_EVIDENCE_UNIVERSE_MODE_MISMATCH",
                "binding was created in issue-marker mode; re-run issue-init --force "
                "with --evidence-universe trusted-config",
            )
        declared_config_identity = sufficiency["config_hash"] if sufficiency is not None else None
        warning = _advisory_marker_warning(
            current, _verification_contract_identity(repo)["config_hash"]
        )
        if warning is not None:
            print(f"warning: {warning}", file=sys.stderr)
    else:
        if bound_source == EVIDENCE_UNIVERSE_SOURCE_TRUSTED_CONFIG:
            raise LocalCheckError(
                "ISSUE_EVIDENCE_UNIVERSE_MODE_MISMATCH",
                "binding was created in trusted-config mode; "
                "pass --evidence-universe trusted-config",
            )
        declared_config_identity = _issue_evidence_universe_marker(current)
    sufficiency_status = "UNBOUND"
    stale_detail: str | None = None
    stale_remediation: str | None = None
    if sufficiency is not None:
        if declared_config_identity != sufficiency["config_hash"]:
            raise LocalCheckError(
                "ISSUE_BINDING_TAMPERED",
                "bound evidence universe does not match the current Issue declaration",
            )
        current_verification_contract = _verification_contract_identity(repo)
        if sufficiency["config_hash"] != current_verification_contract["config_hash"]:
            sufficiency_status = "STALE"
            current_hash = current_verification_contract["config_hash"]
            if trusted:
                stale_detail = (
                    "verification contract changed since the trusted-config evidence "
                    "universe was bound; re-run issue-init --force "
                    "--evidence-universe trusted-config"
                )
                stale_remediation = gate_diagnostics.stale_trusted_config_universe(issue_number)
            else:
                stale_detail = (
                    "verification contract changed since Issue evidence sufficiency was bound; "
                    "expected Issue body line: "
                    f"{gate_diagnostics.evidence_marker_line(current_hash)}"
                )
                stale_remediation = gate_diagnostics.stale_evidence_universe(
                    issue_number, current_hash
                )
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
    issue_verification: dict[str, Any] = {
        "issue_number": issue_number,
        "github_repository": github_repo,
        "issue_contract_hash": binding["issue_contract_hash"],
        "evidence_universe": sufficiency_status,
        **({"evidence_universe_source": bound_source} if trusted and bound_source else {}),
        "claim_ceiling": (
            "ISSUE_VERIFIED_NOT_RELEASED"
            if sufficiency_status == "BOUND"
            else ISSUE_CEILING_UNBOUND
        ),
    }
    try:
        issue_verification.update(resolve_intent_items(pr_body, issue_number, current["body"]))
        issue_verification.update(
            resolve_items_status(
                github_repo,
                issue_number,
                current["body"],
                issue_verification,
                merged_claims_reader
                or (_default_merged_claims_reader if issue_reader is None else None),
            )
        )
    except LocalCheckError as exc:
        effective_config, config_source, _worktree = _load_effective_config(repo)
        _raise_with_receipt(
            repo,
            exc.reason_code,
            exc.detail,
            config=effective_config,
            config_hash=canonical_hash(effective_config),
            config_source=config_source,
            requirements_context=context,
            issue_verification=issue_verification,
        )
    try:
        transitions = _issue_material_transitions(current)
    except LocalCheckError as exc:
        effective_config, config_source, _worktree = _load_effective_config(repo)
        _raise_with_receipt(
            repo,
            exc.reason_code,
            exc.detail,
            config=effective_config,
            config_hash=canonical_hash(effective_config),
            config_source=config_source,
            requirements_context=context,
            issue_verification=issue_verification,
        )
    if transitions:
        association = current.get("author_association")
        login = current.get("author_login")
        if association not in MATERIAL_TRANSITION_AUTHORIZED_ASSOCIATIONS or not login:
            effective_config, config_source, _worktree = _load_effective_config(repo)
            _raise_with_receipt(
                repo,
                "MATERIAL_TRANSITION_UNAUTHORIZED_AUTHOR",
                f"Issue author association {association!r} cannot authorize material transitions",
                config=effective_config,
                config_hash=canonical_hash(effective_config),
                config_source=config_source,
                requirements_context=context,
                issue_verification=issue_verification,
            )
        authorized_by = {"login": login, "author_association": association}
        transitions = [{**item, "authorized_by": dict(authorized_by)} for item in transitions]
        issue_verification["material_transitions"] = transitions
    result = check_repository(
        repo,
        requirements_context=context,
        require_trusted_config=require_trusted_config,
        expect_config_commit=expect_config_commit,
        issue_verification=issue_verification,
        material_transitions=transitions,
    )
    if stale_detail is not None:
        raise LocalCheckError(
            ISSUE_EVIDENCE_STALE_REASON,
            stale_detail,
            receipt_path=result["receipt_path"],
            remediation=stale_remediation,
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
        **{
            key: verdict[key]
            for key in (
                "claimed_items",
                "remaining_items",
                "split",
                "items_status",
                "merged_claimed_items",
            )
            if key in verdict
        },
    }
