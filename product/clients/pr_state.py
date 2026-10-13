# pyright: strict, reportUnnecessaryIsInstance=false, reportUnnecessaryComparison=false
"""Live pull-request state preflight for the issue gate (#250).

A queued or retried gate run can start after its PR merged and auto-closed the bound
Issue. Binding that Issue then fails ``ISSUE_NOT_OPEN``, which is noise: the PR is
already merged. This module reads the *live PR* (never the Issue) and lets the gate
emit a neutral ``PR_ALREADY_CLOSED_SKIPPED`` record instead.

The record is not evidence. It carries ``evidence_status: NOT_EVALUATED`` and never a
``VERIFIED`` status. ``receipt-verify`` re-reads the live PR itself and accepts the
skip only when the PR is merged at exactly the run's head; a closed-unmerged PR, an
open PR or a head mismatch is rejected. Any API or payload problem fails closed.
A closed Issue on its own is never treated as success: anyone can close an Issue.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, cast

from product.clients.issue_golden_path import (
    ISSUE_RATE_LIMIT_MAX_WAIT_SECONDS,
    ISSUE_RATE_LIMIT_RETRIES,
    _rate_limit_retry_delay,  # pyright: ignore[reportPrivateUsage]
)
from product.clients.local_golden_path import LocalCheckError

PR_STATE_SCHEMA = "nexus.core.pr-state-preflight.v1"
PROCEED = "PROCEED"
PR_ALREADY_CLOSED_SKIPPED = "PR_ALREADY_CLOSED_SKIPPED"
EVIDENCE_NOT_EVALUATED = "NOT_EVALUATED"
PullRequestReader = Callable[[str, int], Any]

_HEX40 = re.compile(r"[0-9a-f]{40}")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def _default_pull_request_reader(github_repo: str, number: int) -> Any:
    url = f"https://api.github.com/repos/{github_repo}/pulls/{number}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "nexus-certify",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    target = f"{github_repo}#{number}"
    for attempt in range(ISSUE_RATE_LIMIT_RETRIES + 1):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=15
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read(8192).decode("utf-8", errors="replace").strip()
            delay = _rate_limit_retry_delay(exc, detail)
            if delay is not None:
                if attempt >= ISSUE_RATE_LIMIT_RETRIES or delay > ISSUE_RATE_LIMIT_MAX_WAIT_SECONDS:
                    raise LocalCheckError(
                        "PR_STATE_RATE_LIMIT_EXHAUSTED",
                        f"{target}; retry_after_seconds={delay:.3f}",
                    ) from exc
                time.sleep(delay)
                continue
            code = "PR_STATE_NOT_FOUND" if exc.code == 404 else (
                "PR_STATE_ACCESS_DENIED" if exc.code in {401, 403} else "PR_STATE_FETCH_FAILED"
            )
            raise LocalCheckError(code, target) from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise LocalCheckError("PR_STATE_FETCH_FAILED", f"{target}: {exc}") from exc
    raise LocalCheckError("PR_STATE_FETCH_FAILED", target)  # pragma: no cover


def _observe(
    github_repo: str,
    number: int,
    expected_head: str,
    reader: PullRequestReader | None,
) -> dict[str, Any]:
    if (
        not isinstance(github_repo, str)
        or not _REPO.fullmatch(github_repo)
        or type(number) is not int
        or number < 1
        or not isinstance(expected_head, str)
        or not _HEX40.fullmatch(expected_head)
    ):
        raise LocalCheckError(
            "PR_STATE_INPUT_INVALID",
            "need owner/name, a positive PR number and a 40-hex expected head",
        )
    raw = (reader or _default_pull_request_reader)(github_repo, number)
    target = f"{github_repo}#{number}"
    if not isinstance(raw, Mapping):
        raise LocalCheckError("PR_STATE_MALFORMED", f"{target}: payload is not an object")
    payload = cast("Mapping[str, Any]", raw)
    state, merged, head = payload.get("state"), payload.get("merged"), payload.get("head")
    head_sha = cast("Mapping[str, Any]", head).get("sha") if isinstance(head, Mapping) else None
    merge_commit = payload.get("merge_commit_sha")
    if (
        payload.get("number") != number
        or state not in {"open", "closed"}
        or type(merged) is not bool
        or (merged and state != "closed")
        or not isinstance(head_sha, str)
        or not _HEX40.fullmatch(head_sha)
        or (merged and not (isinstance(merge_commit, str) and _HEX40.fullmatch(merge_commit)))
    ):
        raise LocalCheckError("PR_STATE_MALFORMED", f"{target}: unexpected pull request payload")
    observed = "open" if state == "open" else ("merged" if merged else "closed_unmerged")
    return {
        "schema": PR_STATE_SCHEMA,
        "github_repository": github_repo,
        "pull_request_number": number,
        "expected_head_sha": expected_head,
        "observed_state": observed,
        "observed_head_sha": head_sha,
        "head_matches": head_sha == expected_head,
        "merge_commit_sha": merge_commit if merged else None,
        "merged_at": payload.get("merged_at") if merged else None,
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        # This record never speaks for the evidence; only a signed receipt does.
        "evidence_status": EVIDENCE_NOT_EVALUATED,
    }


def gate_preflight(
    github_repo: str,
    number: int,
    expected_head: str,
    *,
    reader: PullRequestReader | None = None,
) -> dict[str, Any]:
    """Return ``PROCEED`` for an open PR, else the neutral ``PR_ALREADY_CLOSED_SKIPPED``."""
    record = _observe(github_repo, number, expected_head, reader)
    record["outcome"] = PROCEED if record["observed_state"] == "open" else PR_ALREADY_CLOSED_SKIPPED
    return record


def verify_skip(
    github_repo: str,
    number: int,
    expected_head: str,
    *,
    reader: PullRequestReader | None = None,
) -> dict[str, Any]:
    """Accept a declared skip only for a PR merged at exactly ``expected_head``."""
    record = _observe(github_repo, number, expected_head, reader)
    target = f"{github_repo}#{number}"
    if record["observed_state"] != "merged":
        raise LocalCheckError(
            "PR_SKIP_REJECTED_NOT_MERGED",
            f"{target} is {record['observed_state']}; a skip is accepted only for a merged PR",
        )
    if not record["head_matches"]:
        raise LocalCheckError(
            "PR_SKIP_REJECTED_HEAD_MISMATCH",
            f"{target} merged at head {record['observed_head_sha']}, "
            f"this run is for {expected_head}",
        )
    record["outcome"] = PR_ALREADY_CLOSED_SKIPPED
    record["skip_accepted"] = True
    return record
