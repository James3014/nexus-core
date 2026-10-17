"""#288: every required check must also report on merge queue (merge_group) commits.

With a merge queue on ``main``, GitHub tests each queued pull request on a new merge
group commit and waits for every required check on that commit. A workflow without a
``merge_group`` trigger never reports there, and the queue stalls until it times out.

Required on ``main`` (ruleset "Canonical Main Protection v1"):
- ``test`` from ``ci.yml``;
- ``Review record present (advisory)`` and ``Bindings preflight (default branch)``,
  commit statuses published by ``sibling-merge-checks.yml``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
SIBLING = ROOT / ".github" / "workflows" / "sibling-merge-checks.yml"
STATUS_CONTEXTS = ("Review record present (advisory)", "Bindings preflight (default branch)")
MERGE_GROUP_IF = "github.event_name == 'merge_group'"
CHECKS_IF = (
    "github.event_name == 'pull_request_target' || "
    "(github.event_name == 'issue_comment' && github.event.issue.pull_request)"
)


def _on_block(text: str) -> str:
    match = re.search(r"(?ms)^on:\n(.*?)(?=^\S)", text)
    assert match, "workflow has no top-level on: block"
    return match.group(1)


def _job(text: str, job_id: str) -> str:
    match = re.search(rf"(?ms)^  {re.escape(job_id)}:\n(.*?)(?=^  [A-Za-z_-]+:\n|\Z)", text)
    return match.group(1) if match else ""


def _uncommented(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _job_if(job: str) -> str | None:
    match = re.search(r"(?m)^    if:\s*(.+?)\s*$", job)
    return match.group(1) if match else None


def merge_group_trigger_violations(text: str) -> list[str]:
    on_block = _uncommented(_on_block(text))
    if not re.search(r"(?m)^  merge_group:\s*$", on_block):
        return ["merge_group: workflow must trigger on merge_group"]
    if not re.search(r"(?m)^    types:\s*\[\s*checks_requested\s*\]\s*$", on_block):
        return ["merge_group: trigger must use types: [checks_requested]"]
    return []


def sibling_violations(text: str) -> list[str]:
    violations = merge_group_trigger_violations(text)
    checks = _job(text, "checks")
    if _job_if(checks) != CHECKS_IF:
        violations.append(
            f"checks: the reusable PR checks must run only for PRs and PR comments ({CHECKS_IF})"
        )
    job = _job(text, "merge-group")
    if not job:
        return [*violations, "merge-group: job is missing"]
    if _job_if(job) != MERGE_GROUP_IF:
        violations.append(f"merge-group: job must run only on {MERGE_GROUP_IF}")
    body = _uncommented(job)
    loop = re.search(r"(?m)^\s*contexts=\((.+)\)\s*$", body)
    contexts = tuple(re.findall(r'"([^"]+)"', loop.group(1))) if loop else ()
    if contexts != STATUS_CONTEXTS:
        violations.append(f"merge-group: must publish exactly {STATUS_CONTEXTS}, found {contexts}")
    for needle in (
        "repos/${REPO}/statuses/${GROUP_SHA}",
        'creator") or {}).get("login")=="github-actions[bot]"',
        's[0].get("state")=="success"',
        "gh-readonly-queue/main/pr-([0-9]+)-[0-9a-f]{40}$",
        '[ "$state" = success ] || rc=1',
        "trap '[ \"$posted\" = 1 ] || fail_all' EXIT",
        "gh api --paginate",
        'exit "$rc"',
    ):
        if needle not in body:
            violations.append(f"merge-group: missing fail-closed element {needle!r}")
    if re.search(r"(?m)^\s*(-\s+)?uses:", body):
        violations.append("merge-group: job must not run actions (no PR code checkout)")
    return violations


def test_ci_test_job_reports_on_merge_group() -> None:
    assert merge_group_trigger_violations(CI.read_text(encoding="utf-8")) == []


def test_sibling_statuses_are_published_on_merge_group() -> None:
    assert sibling_violations(SIBLING.read_text(encoding="utf-8")) == []


def test_negative_control_missing_merge_group_trigger_is_detected() -> None:
    for path in (CI, SIBLING):
        text = path.read_text(encoding="utf-8")
        mutated = re.sub(r"(?m)^  merge_group:\n    types: \[checks_requested\]\n", "", text)
        assert mutated != text
        assert merge_group_trigger_violations(mutated)
        commented = text.replace("  merge_group:\n", "  # merge_group:\n", 1)
        assert merge_group_trigger_violations(commented)


def test_negative_control_sibling_merge_group_job_mutations_are_detected() -> None:
    text = SIBLING.read_text(encoding="utf-8")
    mutations = (
        text.replace(f"    if: {MERGE_GROUP_IF}\n", "    if: always()\n", 1),
        text.replace(f"    if: {CHECKS_IF}\n", "    if: github.event_name != 'issue_comment'\n", 1),
        text.replace(' "Bindings preflight (default branch)")', ")", 1),
        text.replace("  trap '[", "  # trap '[", 1),
        text.replace('[ "$state" = success ] || rc=1', "true", 1),
        text.replace('s[0].get("state")=="success"', "True", 1),
        text.replace("  merge-group:\n", "  merge-group-renamed:\n", 1),
        text.replace(
            "      - name: Copy the PR-head statuses",
            "      - uses: actions/checkout@0000000000000000000000000000000000000000\n"
            "      - name: Copy the PR-head statuses",
            1,
        ),
    )
    for mutated in mutations:
        assert mutated != text
        assert sibling_violations(mutated), mutated[-400:]


# --------------------------------------------------------------------------- behaviour
# Codex review r1 (#288): the text checks above cannot see a forced `state=success`, so
# the real step script is also run against a fake `gh` that serves fixture JSON.

_FAKE_GH = """#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *"-X POST"*)
    printf '%s\\n' "$*" >> "$FAKE_LOG"
    n=$(wc -l < "$FAKE_LOG")
    [ -z "${FAKE_POST_FAIL:-}" ] || [ "$FAKE_POST_FAIL" != "$((n))" ] || exit 1 ;;
  *"/pulls/"*) cat "$FAKE_PR" ;;
  *"/statuses?"*) cat "$FAKE_STATUSES" ;;
  *) echo "unexpected gh call: $*" >&2; exit 2 ;;
esac
"""
_GROUP = "b" * 40
_HEAD = "a" * 40
_REPO = "James3014/nexus-core"


def _step_script() -> str:
    job = _job(SIBLING.read_text(encoding="utf-8"), "merge-group")
    block = job.split("        run: |\n", 1)[1]
    return "\n".join(line[10:] for line in block.splitlines()) + "\n"


def _status(context: str, state: str, login: str = "github-actions[bot]") -> str:
    return json.dumps({"context": context, "state": state, "creator": {"login": login}})


def _run(
    tmp_path: Path,
    statuses: list[str],
    *,
    pr: dict | None = None,
    ref: str = f"refs/heads/gh-readonly-queue/main/pr-12-{_GROUP}",
    post_fail: int = 0,
) -> tuple[int, list[str]]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "gh"
    fake.write_text(_FAKE_GH, encoding="utf-8")
    fake.chmod(0o755)
    script = tmp_path / "step.sh"
    script.write_text(_step_script(), encoding="utf-8")
    pr_json = tmp_path / "pr.json"
    pr_json.write_text(
        json.dumps(
            pr
            if pr is not None
            else {
                "state": "open",
                "base": {"ref": "main"},
                "head": {"sha": _HEAD, "repo": {"full_name": _REPO}},
            }
        ),
        encoding="utf-8",
    )
    statuses_file = tmp_path / "statuses.jsonl"
    statuses_file.write_text("".join(f"{line}\n" for line in statuses), encoding="utf-8")
    log = tmp_path / "posts.log"
    runner_temp = tmp_path / "rt"
    runner_temp.mkdir()
    env = {
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_LOG": str(log),
        "FAKE_PR": str(pr_json),
        "FAKE_STATUSES": str(statuses_file),
        "RUNNER_TEMP": str(runner_temp),
        "REPO": _REPO,
        "GROUP_SHA": _GROUP,
        "GROUP_REF": ref,
        "RUN_URL": "https://example.invalid/run",
    }
    if post_fail:
        env["FAKE_POST_FAIL"] = str(post_fail)
    result = subprocess.run(
        ["bash", "-e", str(script)], env=env, capture_output=True, text=True, check=False
    )
    posts = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result.returncode, posts


def _posted(posts: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in posts:
        assert f"repos/{_REPO}/statuses/{_GROUP}" in line
        state = re.search(r"-f state=(\w+)", line)
        context = re.search(r"-f context=(.+?) -f target_url=", line)
        assert state and context
        out[context.group(1)] = state.group(1)
    return out


_ALL_GREEN = [_status(c, "success") for c in STATUS_CONTEXTS]
_BASH = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


@_BASH
def test_merge_group_copy_posts_success_when_pr_head_is_green(tmp_path: Path) -> None:
    older_failure = [_status(c, "failure") for c in STATUS_CONTEXTS]
    rc, posts = _run(tmp_path, [*_ALL_GREEN, *older_failure])
    assert rc == 0
    assert _posted(posts) == dict.fromkeys(STATUS_CONTEXTS, "success")


@_BASH
@pytest.mark.parametrize(
    "statuses",
    [
        pytest.param([_status(STATUS_CONTEXTS[0], "success")], id="missing-context"),
        pytest.param([_status(STATUS_CONTEXTS[0], "failure"), *_ALL_GREEN], id="latest-is-failure"),
        pytest.param([_status(STATUS_CONTEXTS[1], "pending"), *_ALL_GREEN], id="latest-is-pending"),
        pytest.param(
            [_status(STATUS_CONTEXTS[0], "success", "someone"), *_ALL_GREEN[1:]],
            id="foreign-creator",
        ),
    ],
)
def test_merge_group_copy_fails_closed_on_pr_head_statuses(
    tmp_path: Path, statuses: list[str]
) -> None:
    rc, posts = _run(tmp_path, statuses)
    assert rc != 0
    posted = _posted(posts)
    assert set(posted) == set(STATUS_CONTEXTS)
    assert "failure" in posted.values()


@_BASH
@pytest.mark.parametrize(
    ("pr", "ref"),
    [
        pytest.param(None, f"refs/heads/main-{_GROUP}", id="bad-ref"),
        pytest.param(None, f"refs/heads/gh-readonly-queue/dev/pr-12-{_GROUP}", id="other-base"),
        pytest.param(
            {
                "state": "closed",
                "base": {"ref": "main"},
                "head": {"sha": _HEAD, "repo": {"full_name": _REPO}},
            },
            f"refs/heads/gh-readonly-queue/main/pr-12-{_GROUP}",
            id="closed-pr",
        ),
        pytest.param(
            {"state": "open", "base": {"ref": "main"}, "head": {"sha": _HEAD, "repo": None}},
            f"refs/heads/gh-readonly-queue/main/pr-12-{_GROUP}",
            id="deleted-head-repo",
        ),
    ],
)
def test_merge_group_copy_early_exit_posts_failure_for_both(
    tmp_path: Path, pr: dict | None, ref: str
) -> None:
    rc, posts = _run(tmp_path, _ALL_GREEN, pr=pr, ref=ref)
    assert rc != 0
    assert _posted(posts) == dict.fromkeys(STATUS_CONTEXTS, "failure")


@_BASH
@pytest.mark.parametrize("nth", [1, 2])
def test_merge_group_copy_post_error_marks_both_failure(tmp_path: Path, nth: int) -> None:
    # The nth POST fails (first context, or second after the first went out as
    # success): the script exits non-zero and the EXIT trap posts failure for both.
    rc, posts = _run(tmp_path, _ALL_GREEN, post_fail=nth)
    assert rc != 0
    assert _posted(posts[nth:]) == dict.fromkeys(STATUS_CONTEXTS, "failure")


@_BASH
def test_merge_group_copy_malformed_status_line_fails_closed(tmp_path: Path) -> None:
    rc, posts = _run(tmp_path, [*_ALL_GREEN, "{not json"])
    assert rc != 0
    assert _posted(posts) == dict.fromkeys(STATUS_CONTEXTS, "failure")
