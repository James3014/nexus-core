"""#302/#303 variant: the consumer example must pin an issue-gate that binds trusted config
to the base commit.

The README "Add the two-job workflow" example pins issue-gate to a nexus-core commit. If that
commit predates #303, a consumer copying it runs ``issue-check --require-trusted-config``
without ``--expect-config-commit``.
"""

from __future__ import annotations

import os
import re
import subprocess

import pytest

from tests.architecture.test_receipt_artifact_lineage import REPO_ROOT

EXAMPLE = REPO_ROOT / "docs" / "examples" / "github-repository-check.yml"
PIN_RE = re.compile(r"James3014/nexus-core/\.github/actions/issue-gate@([0-9a-f]{40})")
ACTION_PATH = ".github/actions/issue-gate/action.yml"


def _git_show(sha: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "show", f"{sha}:{ACTION_PATH}"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def _action_text_at(sha: str) -> str:
    result = _git_show(sha)
    if result.returncode != 0:
        # Shallow CI clones may lack the pinned commit: fetch just that commit.
        subprocess.run(
            ["git", "fetch", "--depth=1", "origin", sha],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        result = _git_show(sha)
    if result.returncode != 0:
        message = f"pinned commit {sha} not obtainable: {result.stderr.strip()}"
        if os.environ.get("CI"):
            pytest.fail(message)
        pytest.skip(message)
    return result.stdout


def _issue_check_lines_at(sha: str) -> list[str]:
    return [
        line.strip()
        for line in _action_text_at(sha).splitlines()
        if "nexus-certify issue-check" in line and not line.strip().startswith("#")
    ]


def test_consumer_example_pins_an_issue_gate_that_binds_config_to_base_commit() -> None:
    pins = set(PIN_RE.findall(EXAMPLE.read_text(encoding="utf-8")))
    assert len(pins) == 1, pins
    (sha,) = pins
    calls = _issue_check_lines_at(sha)
    assert calls, f"no issue-check call in issue-gate@{sha}"
    for call in calls:
        assert "--require-trusted-config" in call.split(), call
        assert '--expect-config-commit "$BASE_SHA"' in call, f"issue-gate@{sha[:12]}: {call}"
