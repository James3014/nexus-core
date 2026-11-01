"""issue-gate pull-request mode requires the base to be the default branch.

Dispatch mode already requires its run ref to be the default branch; pull-request
mode takes the base from the pull request, so it must require the same of the pull
request's base ref. The default branch comes from trusted event data
(``github.event.repository.default_branch``). These tests run the real
"Resolve gate target" step script from the action and, when it resolves a target,
the real "Verify exact Issue-bound candidate" step against it (see
test_issue_gate_config_pin). Every verifier is a harmless ``echo``/``false`` fixture.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.architecture.test_issue_gate_config_pin import (
    CANDIDATE_REF,
    _ci_candidate,  # pyright: ignore[reportPrivateUsage]
    _config,  # pyright: ignore[reportPrivateUsage]
    _git,  # pyright: ignore[reportPrivateUsage]
    _run_check_step,  # pyright: ignore[reportPrivateUsage]
)
from tests.architecture.test_receipt_artifact_lineage import (
    ISSUE_GATE,
    StepResult,
    _run_step,  # pyright: ignore[reportPrivateUsage]
    _step,  # pyright: ignore[reportPrivateUsage]
)

PR_EVENTS = ["pull_request", "pull_request_target"]


def _target_context(
    *, event: str, head: str, base: str, base_ref: str, default_branch: str
) -> dict[str, Any]:
    return {
        "github": {
            "event_name": event,
            "sha": "f" * 40,
            "ref": "refs/pull/1/merge",
            "ref_name": "1/merge",
            "event": {
                "pull_request": {
                    "head": {"sha": head},
                    "base": {"sha": base, "ref": base_ref},
                },
                "repository": {"default_branch": default_branch},
            },
        },
        "inputs": {"head-sha": "", "issue-number": "1"},
    }


def _run_target_step(tmp_path: Path, **context: str) -> StepResult:
    run_dir = tmp_path / "target-run"
    run_dir.mkdir(exist_ok=True)
    return _run_step(_step(ISSUE_GATE, "target"), _target_context(**context), run_dir)


def _gate(
    tmp_path: Path, cand: Path, *, event: str, base: str, base_ref: str, default_branch: str
) -> tuple[StepResult, StepResult | None]:
    """Run the target step; when it resolves a target, run the check step on it."""

    head = _git(cand, "rev-parse", CANDIDATE_REF)
    target = _run_target_step(
        tmp_path,
        event=event,
        head=head,
        base=base,
        base_ref=base_ref,
        default_branch=default_branch,
    )
    if target.returncode != 0:
        return target, None
    check, _calls = _run_check_step(tmp_path, cand, target.outputs["base-sha"])
    return target, check


def _non_default_base_candidate(tmp_path: Path) -> tuple[Path, str]:
    """Candidate whose pull request base is a non-default branch with its own config.

    The default branch's verifier fails, so VERIFIED can only come from the config on
    the non-default base branch.
    """

    src = tmp_path / "src"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    _git(src, "config", "user.email", "t@example.test")
    _git(src, "config", "user.name", "T")
    (src / "app.txt").write_text("1\n", encoding="utf-8")
    (src / ".nexus-core").mkdir()
    (src / ".nexus-core" / "config.toml").write_text(
        _config("origin/main", ["false"]), encoding="utf-8"
    )
    _git(src, "add", ".")
    _git(src, "commit", "-qm", "main")
    _git(src, "checkout", "-q", "-b", "other")
    (src / ".nexus-core" / "config.toml").write_text(
        _config("origin/other", ["echo", "other"]), encoding="utf-8"
    )
    _git(src, "commit", "-qam", "other config")
    base = _git(src, "rev-parse", "HEAD")
    _git(src, "checkout", "-q", "-b", "feature")
    (src / "app.txt").write_text("2\n", encoding="utf-8")
    _git(src, "commit", "-qam", "change")
    head = _git(src, "rev-parse", "HEAD")

    cand = tmp_path / "candidate"
    _git(tmp_path, "init", "-q", str(cand))
    _git(cand, "remote", "add", "origin", str(src))
    _git(
        cand,
        "fetch",
        "-q",
        "--no-tags",
        "origin",
        f"+{head}:{CANDIDATE_REF}",
        f"+{base}:refs/remotes/origin/other",
    )
    _git(cand, "checkout", "-q", "--detach", head)
    return cand, base


@pytest.mark.parametrize("event", PR_EVENTS)
def test_pr_mode_refuses_a_base_that_is_not_the_default_branch(tmp_path: Path, event: str) -> None:
    cand, base = _non_default_base_candidate(tmp_path)
    target, check = _gate(
        tmp_path, cand, event=event, base=base, base_ref="other", default_branch="main"
    )
    assert check is None, check.stderr if check else ""
    assert target.returncode != 0
    assert "NEXUS_CORE_GATE_TARGET_INVALID" in target.stderr
    assert "pull request base must be the default branch main" in target.stderr
    assert target.outputs == {}


@pytest.mark.parametrize("event", PR_EVENTS)
def test_pr_mode_on_the_default_branch_still_verifies_an_honest_candidate(
    tmp_path: Path, event: str
) -> None:
    """Positive control: a pull request based on the default branch passes unchanged."""

    cand, base = _ci_candidate(tmp_path, base_command=["echo", "base"], candidate_base_ref=None)
    target, check = _gate(
        tmp_path, cand, event=event, base=base, base_ref="main", default_branch="main"
    )
    assert target.returncode == 0, target.stderr
    assert target.outputs["base-ref"] == "main"
    assert target.outputs["base-sha"] == base
    assert target.outputs["mode"] == "pull_request"
    assert check is not None
    assert check.returncode == 0, check.stderr
    assert "verification: VERIFIED" in check.stderr
    assert f"config: trusted (origin/main@{base[:12]}, pinned)" in check.stderr


@pytest.mark.parametrize("base_ref", ["main2", "Main", "refs/heads/main", "trunk", "main/x"])
def test_pr_mode_compares_the_base_ref_exactly(tmp_path: Path, base_ref: str) -> None:
    result = _run_target_step(
        tmp_path,
        event="pull_request_target",
        head="1" * 40,
        base="2" * 40,
        base_ref=base_ref,
        default_branch="main",
    )
    assert result.returncode != 0
    assert "NEXUS_CORE_GATE_TARGET_INVALID" in result.stderr
    assert result.outputs == {}


@pytest.mark.parametrize("default_branch", ["", "ma in", "main;x"])
def test_pr_mode_fails_closed_when_the_default_branch_is_unresolved(
    tmp_path: Path, default_branch: str
) -> None:
    result = _run_target_step(
        tmp_path,
        event="pull_request",
        head="1" * 40,
        base="2" * 40,
        base_ref=default_branch,
        default_branch=default_branch,
    )
    assert result.returncode != 0
    assert "NEXUS_CORE_GATE_TARGET_INVALID: default branch unresolved" in result.stderr
    assert result.outputs == {}


def test_target_step_reads_the_default_branch_from_trusted_event_data() -> None:
    env = _step(ISSUE_GATE, "target")["env"]
    assert env["DEFAULT_BRANCH"] == "${{ github.event.repository.default_branch }}"
    assert env["PR_BASE_REF"] == "${{ github.event.pull_request.base.ref }}"
