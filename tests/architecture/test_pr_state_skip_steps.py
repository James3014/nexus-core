"""Execute the #250 PR-state steps of issue-gate and receipt-verify with a fake tool.

The real ``nexus-certify`` is replaced by a script on PATH that records its argv and
prints a chosen record, so these tests pin what the composite steps themselves do:
which outcomes they accept, and that the PR number, head and repository reach the
tool only from trusted event fields or trusted inputs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.architecture.test_receipt_artifact_lineage import (
    HEAD,
    ISSUE_GATE,
    RECEIPT_VERIFY,
    REPOSITORY,
    _github,  # pyright: ignore[reportPrivateUsage]
    _run_step,  # pyright: ignore[reportPrivateUsage]
    _step,  # pyright: ignore[reportPrivateUsage]
)

PR_NUMBER = 41
ATTACKER_HEAD = "9" * 40


def _fake_tool(tmp_path: Path, *, stdout: str, exit_code: int = 0) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    argv_log = tmp_path / "argv.json"
    tool = bindir / "nexus-certify"
    tool.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        f"open({str(argv_log)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
        f"sys.stdout.write({stdout!r})\n"
        f"raise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    return argv_log


def _context(**inputs: str) -> dict[str, Any]:
    context = _github("https://api.github.test", run_attempt=1)
    context["github"]["event"]["pull_request"]["number"] = str(PR_NUMBER)
    # A PR body (attacker-controlled) never feeds the PR-state steps.
    context["github"]["event"]["pull_request"]["body"] = f"head {ATTACKER_HEAD} pr 1"
    context["inputs"] = inputs
    return context


def _flag(argv: list[str], name: str) -> str:
    return argv[argv.index(name) + 1]


# --------------------------------------------------------------------------- issue-gate


@pytest.mark.parametrize("outcome", ["PROCEED", "PR_ALREADY_CLOSED_SKIPPED"])
def test_gate_step_passes_through_known_outcomes(tmp_path: Path, outcome: str) -> None:
    argv_log = _fake_tool(tmp_path, stdout=json.dumps({"outcome": outcome}))
    result = _run_step(_step(ISSUE_GATE, "prstate"), _context(), tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.outputs == {"outcome": outcome}
    argv = json.loads(argv_log.read_text(encoding="utf-8"))
    assert argv[:3] == ["pr-state", "--mode", "gate"]


@pytest.mark.parametrize(
    "stdout",
    [
        json.dumps({"outcome": "VERIFIED"}),
        json.dumps({"outcome": "PASS"}),
        json.dumps({"outcome": ""}),
        json.dumps({"outcome": "PROCEED\noutcome=VERIFIED"}),
        json.dumps({}),
        "not json",
    ],
)
def test_gate_step_rejects_any_other_outcome(tmp_path: Path, stdout: str) -> None:
    _fake_tool(tmp_path, stdout=stdout)
    result = _run_step(_step(ISSUE_GATE, "prstate"), _context(), tmp_path)
    assert result.returncode != 0
    assert "outcome" not in result.outputs


def test_gate_step_fails_closed_when_the_tool_fails(tmp_path: Path) -> None:
    _fake_tool(tmp_path, stdout="", exit_code=2)
    result = _run_step(_step(ISSUE_GATE, "prstate"), _context(), tmp_path)
    assert result.returncode != 0
    assert result.outputs == {}


def test_gate_step_reads_pr_head_and_repo_from_trusted_event_fields(tmp_path: Path) -> None:
    step = _step(ISSUE_GATE, "prstate")
    assert step["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert step["env"]["PR_NUMBER"] == "${{ github.event.pull_request.number }}"
    assert step["env"]["REPO"] == "${{ github.repository }}"
    assert step["env"]["GITHUB_API_URL"] == "${{ github.api_url }}"
    assert not any("inputs." in value or "body" in value for value in step["env"].values())

    argv_log = _fake_tool(tmp_path, stdout=json.dumps({"outcome": "PROCEED"}))
    result = _run_step(step, _context(), tmp_path)
    assert result.returncode == 0, result.stderr
    argv = json.loads(argv_log.read_text(encoding="utf-8"))
    assert _flag(argv, "--expect-head") == HEAD
    assert _flag(argv, "--pr") == str(PR_NUMBER)
    assert _flag(argv, "--github-repo") == REPOSITORY


def test_gate_step_rejects_non_numeric_pr_number(tmp_path: Path) -> None:
    _fake_tool(tmp_path, stdout=json.dumps({"outcome": "PROCEED"}))
    context = _context()
    context["github"]["event"]["pull_request"]["number"] = "41; echo outcome=VERIFIED"
    result = _run_step(_step(ISSUE_GATE, "prstate"), context, tmp_path)
    assert result.returncode != 0
    assert not (tmp_path / "argv.json").exists()


# ------------------------------------------------------------------------ receipt-verify


def _verify_inputs(**overrides: str) -> dict[str, str]:
    return {
        "github-repository": REPOSITORY,
        "head-sha": HEAD,
        "pull-request-number": "",
        "gate-outcome": "PR_ALREADY_CLOSED_SKIPPED",
        **overrides,
    }


def test_verify_skip_step_pins_pr_number_and_head_to_trusted_sources() -> None:
    step = _step(RECEIPT_VERIFY, "skip")
    assert step["if"] == "inputs.gate-outcome == 'PR_ALREADY_CLOSED_SKIPPED'"
    assert step["env"]["PR_NUMBER"] == (
        "${{ inputs.pull-request-number || github.event.pull_request.number }}"
    )
    assert step["env"]["HEAD_SHA"] == "${{ inputs.head-sha }}"
    assert step["env"]["REPO"] == "${{ inputs.github-repository }}"
    assert step["env"]["GITHUB_API_URL"] == "${{ github.api_url }}"


@pytest.mark.parametrize(
    ("explicit", "expected"),
    [("", str(PR_NUMBER)), ("77", "77")],
)
def test_verify_skip_step_uses_trusted_pr_number_and_head(
    tmp_path: Path, explicit: str, expected: str
) -> None:
    argv_log = _fake_tool(tmp_path, stdout=json.dumps({"skip_accepted": True}))
    context = _context(**_verify_inputs(**{"pull-request-number": explicit}))
    result = _run_step(_step(RECEIPT_VERIFY, "skip"), context, tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.outputs == {"outcome": "PR_ALREADY_CLOSED_SKIPPED"}
    assert "verified" not in result.outputs
    argv = json.loads(argv_log.read_text(encoding="utf-8"))
    assert argv[:3] == ["pr-state", "--mode", "verify-skip"]
    assert _flag(argv, "--pr") == expected
    assert _flag(argv, "--expect-head") == HEAD
    assert _flag(argv, "--github-repo") == REPOSITORY


def test_verify_skip_step_fails_when_the_live_check_rejects(tmp_path: Path) -> None:
    _fake_tool(tmp_path, stdout="", exit_code=2)
    context = _context(**_verify_inputs())
    result = _run_step(_step(RECEIPT_VERIFY, "skip"), context, tmp_path)
    assert result.returncode != 0
    assert result.outputs == {}


def test_verify_skip_step_rejects_non_numeric_pr_number(tmp_path: Path) -> None:
    _fake_tool(tmp_path, stdout="{}")
    context = _context(**_verify_inputs(**{"pull-request-number": "7 --mode gate"}))
    result = _run_step(_step(RECEIPT_VERIFY, "skip"), context, tmp_path)
    assert result.returncode != 0
    assert not (tmp_path / "argv.json").exists()
