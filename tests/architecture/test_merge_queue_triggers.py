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

import re
from pathlib import Path

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
    loop = re.search(r"(?m)^\s*for context in (.+); do\s*$", body)
    contexts = tuple(re.findall(r'"([^"]+)"', loop.group(1))) if loop else ()
    if contexts != STATUS_CONTEXTS:
        violations.append(f"merge-group: must publish exactly {STATUS_CONTEXTS}, found {contexts}")
    for needle in (
        "repos/${REPO}/statuses/${GROUP_SHA}",
        'creator") or {}).get("login")=="github-actions[bot]"',
        's[0].get("state")=="success"',
        "gh-readonly-queue/main/pr-([0-9]+)-[0-9a-f]{40}$",
        '[ "$state" = success ] || rc=1',
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
        text.replace(' "Bindings preflight (default branch)"; do', "; do", 1),
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
