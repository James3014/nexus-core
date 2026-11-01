"""issue-gate binds the trusted config to the base commit it resolved.

The candidate fetch stores the head under a fixed remote-tracking ref name. A named
ref is advisory only (SECURITY.md "Governance config source"), so the trusted config
must be pinned to the base commit with ``--expect-config-commit``. These tests run the
real "Verify exact Issue-bound candidate" step script from the action against a
candidate laid out exactly as the candidate fetch lays it out, with a stand-in
``nexus-certify`` that forwards the step's trust flags to Core's real ``check``
(the Issue-specific flags need GitHub and are dropped). Every verifier is a harmless
``echo``/``false`` fixture.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.architecture.test_receipt_artifact_lineage import (
    ISSUE_GATE,
    REPO_ROOT,
    _run_step,  # pyright: ignore[reportPrivateUsage]
    _step,  # pyright: ignore[reportPrivateUsage]
)

CANDIDATE_REF = "refs/remotes/origin/nexus-core-candidate"
PIN_FLAG = '--expect-config-commit "$BASE_SHA"'

# Stand-in for the installed tool: forwards --repo and the trust flags of the step's
# issue-check call to Core's real `check`; records every call.
SHIM = """#!{python}
import sys
sys.path.insert(0, {root!r})
with open({log!r}, "a", encoding="utf-8") as log:
    log.write(" ".join(sys.argv[1:]) + "\\n")
from product.clients.cli import main
args = sys.argv[1:]
assert args[0] == "issue-check", args
keep = []
rest = iter(args[1:])
for arg in rest:
    if arg in ("--repo", "--expect-config-commit"):
        keep += [arg, next(rest)]
    elif arg == "--require-trusted-config":
        keep.append(arg)
    elif arg in ("--issue", "--evidence-universe", "--pr-body-file", "--receipt-path-out"):
        next(rest)
    else:
        raise SystemExit("unexpected issue-check argument: " + arg)
raise SystemExit(main(["check", *keep]))
"""


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _config(base_ref: str, command: list[str]) -> str:
    return "\n".join(
        [
            "version = 2",
            f'base_ref = "{base_ref}"',
            'allowed_patterns = ["**"]',
            'deletion_policy = "FORBID"',
            "universe_generation = 1",
            "materials = []",
            "[[verifiers]]",
            'id = "v"',
            f"command = {json.dumps(command)}",
            "timeout_seconds = 30",
            'logical_subject_id = "required/v"',
            'evidence_kind = "test-result"',
            "",
        ]
    )


def _ci_candidate(
    tmp_path: Path, *, base_command: list[str], candidate_base_ref: str | None
) -> tuple[Path, str]:
    """Return (candidate checkout, base sha) in the candidate-fetch layout.

    ``candidate_base_ref`` None leaves the base config untouched (honest candidate);
    otherwise the candidate commits its own config naming that ref, with an ``echo``
    verifier.
    """

    src = tmp_path / "src"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    _git(src, "config", "user.email", "t@example.test")
    _git(src, "config", "user.name", "T")
    (src / "app.txt").write_text("1\n", encoding="utf-8")
    (src / ".nexus-core").mkdir()
    (src / ".nexus-core" / "config.toml").write_text(
        _config("origin/main", base_command), encoding="utf-8"
    )
    _git(src, "add", ".")
    _git(src, "commit", "-qm", "base")
    base = _git(src, "rev-parse", "HEAD")
    _git(src, "checkout", "-q", "-b", "feature")
    if candidate_base_ref is not None:
        (src / ".nexus-core" / "config.toml").write_text(
            _config(candidate_base_ref, ["echo", "candidate"]), encoding="utf-8"
        )
    (src / "app.txt").write_text("2\n", encoding="utf-8")
    _git(src, "commit", "-qam", "candidate")
    head = _git(src, "rev-parse", "HEAD")

    # Same refspecs as "Acquire candidate head with plain Git (no submodule handling)".
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
        f"+{base}:refs/remotes/origin/main",
    )
    _git(cand, "checkout", "-q", "--detach", head)
    if candidate_base_ref is not None:
        # A change set that is not empty relative to the candidate ref itself.
        (cand / "app.txt").write_text("3\n", encoding="utf-8")
    return cand, base


def _run_check_step(
    tmp_path: Path, cand: Path, base_sha: str, *, step: dict[str, Any] | None = None
):
    run_dir = tmp_path / "run"
    bindir = run_dir / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "certify-calls.log"
    shim = bindir / "nexus-certify"
    shim.write_text(
        SHIM.format(python=sys.executable, root=str(REPO_ROOT), log=str(log)), encoding="utf-8"
    )
    shim.chmod(0o755)
    temp = tmp_path / "rtemp"
    temp.mkdir(exist_ok=True)
    context = {
        "github": {
            "token": "ghs_test_token",
            "event": {"pull_request": {"body": "body"}},
        },
        "inputs": {"candidate-path": str(cand), "evidence-universe": "trusted-config"},
        "runner": {"temp": str(temp)},
        "steps": {
            "resolve": {"outputs": {"issue-number": "1"}},
            "target": {"outputs": {"base-sha": base_sha}},
        },
    }
    result = _run_step(step or _step(ISSUE_GATE, "check"), context, run_dir)
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls


def _unpinned_step() -> dict[str, Any]:
    step = dict(_step(ISSUE_GATE, "check"))
    assert f" {PIN_FLAG} " in step["run"]
    step["run"] = step["run"].replace(f" {PIN_FLAG} ", " ", 1)
    return step


@pytest.fixture
def fixed_ref_candidate(tmp_path: Path) -> tuple[Path, str]:
    # The base verifier fails, so VERIFIED can only come from the candidate's config.
    return _ci_candidate(
        tmp_path, base_command=["false"], candidate_base_ref="origin/nexus-core-candidate"
    )


def test_check_step_pins_config_to_base_commit_and_rejects_fixed_candidate_ref(
    tmp_path: Path, fixed_ref_candidate: tuple[Path, str]
) -> None:
    cand, base = fixed_ref_candidate
    result, calls = _run_check_step(tmp_path, cand, base)
    assert result.returncode != 0, result.stderr
    assert "CONFIG_SOURCE_MISMATCH" in result.stderr
    assert "verification: VERIFIED" not in result.stderr
    assert len(calls) == 1 and f"--expect-config-commit {base}" in calls[0]


def test_without_the_pin_the_fixed_candidate_ref_is_trusted(
    tmp_path: Path, fixed_ref_candidate: tuple[Path, str]
) -> None:
    """Control: only the pin separates the two outcomes."""

    cand, base = fixed_ref_candidate
    result, _calls = _run_check_step(tmp_path, cand, base, step=_unpinned_step())
    assert result.returncode == 0, result.stderr
    assert "verification: VERIFIED" in result.stderr


def test_check_step_verifies_an_honest_candidate_under_the_pinned_base_config(
    tmp_path: Path,
) -> None:
    cand, base = _ci_candidate(tmp_path, base_command=["echo", "base"], candidate_base_ref=None)
    result, calls = _run_check_step(tmp_path, cand, base)
    assert result.returncode == 0, result.stderr
    assert "verification: VERIFIED" in result.stderr
    assert f"config: trusted (origin/main@{base[:12]}, pinned)" in result.stderr
    assert len(calls) == 1


@pytest.mark.parametrize("value", ["", "main", "A" * 40, "0" * 39])
def test_check_step_fails_closed_on_missing_or_malformed_base_sha(
    tmp_path: Path, fixed_ref_candidate: tuple[Path, str], value: str
) -> None:
    cand, _base = fixed_ref_candidate
    result, calls = _run_check_step(tmp_path, cand, value)
    assert result.returncode != 0
    assert "NEXUS_CORE_GATE_BASE_SHA_INVALID" in result.stderr
    assert calls == []


def test_check_step_binds_base_sha_from_the_resolved_target() -> None:
    step = _step(ISSUE_GATE, "check")
    assert step["env"]["BASE_SHA"] == "${{ steps.target.outputs.base-sha }}"
    run = step["run"]
    guard = run.index('[[ "$BASE_SHA" =~ ^[0-9a-f]{40}$ ]]')
    assert guard < run.index("nexus-certify issue-check")
