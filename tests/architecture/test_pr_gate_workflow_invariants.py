"""PR gate workflow invariants (Golden findings NCGF-004 and NCGF-005).

SECURITY.md "PR gate" and docs/GITHUB_REPOSITORY_CHECK.md make claims about the
structure of ``.github/workflows/nexus-core-issue-completion.yml`` and the composite
actions it calls. These tests turn those claims into checks over the real files.

The repository does not depend on a YAML library, so the files are read with small,
layout-specific text parsers: the workflow is split into its top-level ``on:`` block
and per-job blocks, and composite actions into their ``runs.steps`` items. Any layout
the parsers do not understand fails loudly instead of passing silently.

Each checker returns a list of violations naming the invariant it guards, so the
negative controls feed mutated copies of the real text to the same checkers.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "nexus-core-issue-completion.yml"
ISSUE_GATE = REPO_ROOT / ".github" / "actions" / "issue-gate" / "action.yml"
RECEIPT_VERIFY = REPO_ROOT / ".github" / "actions" / "receipt-verify" / "action.yml"

SAME_REPO_GUARD = "github.event.pull_request.head.repo.full_name == github.repository"
GATED_JOBS = ("run", "verify")
EXPECTED_IDENTITY = (
    "https://github.com/James3014/nexus-core/.github/workflows/"
    "nexus-core-issue-completion.yml@refs/heads/main"
)
RECEIPT_CHECK_EXPECTATIONS = (
    "--expect-status VERIFIED",
    "--expect-subject-head",
    "--expect-target-tree",
    "--expect-config-commit",
    "--expect-issue",
    "--expect-github-repository",
    "--require-clean-subject",
    "--require-trusted-config",
)

# NCGF-005: the documented token exposure (SECURITY.md "PR gate"). Step names are the
# exact ``- name:`` values; changing which steps see the token must update SECURITY.md.
TOKEN_STEPS = {
    ISSUE_GATE: {
        "Acquire candidate head with plain Git (no submodule handling)",
        "Bind exact Issue contract",
        "Verify exact Issue-bound candidate",
    },
    RECEIPT_VERIFY: {
        "Resolve exact producer artifact",
        "Resolve expected head tree",
    },
}
_TOKEN_REFERENCE = re.compile(r"github\.token|GITHUB_TOKEN|GH_TOKEN|secrets\.")


# --------------------------------------------------------------------------- parsers


def _top_level_block(text: str, key: str) -> str:
    """Return the body of a column-0 ``key:`` block (until the next column-0 key)."""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line == f"{key}:")
    except StopIteration:
        return ""
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        body.append(line)
    return "\n".join(body)


def _jobs(text: str) -> dict[str, str]:
    """Split the ``jobs:`` block into ``{job_id: job_text}`` (two-space job keys)."""
    jobs: dict[str, str] = {}
    current: str | None = None
    for line in _top_level_block(text, "jobs").splitlines():
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
        if match:
            current = match.group(1)
            jobs[current] = ""
        elif current is not None:
            jobs[current] += line + "\n"
    return jobs


def _job_if(job_text: str) -> str | None:
    """The job-level ``if:`` expression (four-space key), comments ignored."""
    for line in job_text.splitlines():
        match = re.fullmatch(r"    if:\s*(.+?)\s*", line)
        if match:
            return match.group(1)
    return None


def _steps(text: str) -> list[dict[str, str]]:
    """Split a composite action's ``runs.steps`` into items with ``name`` and raw ``text``."""
    lines = text.splitlines()
    if "  steps:" not in lines:
        raise AssertionError("composite action has no '  steps:' block")
    steps: list[dict[str, str]] = []
    for line in lines[lines.index("  steps:") + 1 :]:
        if line.startswith("    - "):
            steps.append({"name": "", "text": ""})
        elif line and not line.startswith("      ") and line.strip():
            raise AssertionError(f"unparsed step line: {line!r}")
        if not steps:
            continue
        steps[-1]["text"] += line + "\n"
        match = re.fullmatch(r"    (?:- |  )name:\s*(.+?)\s*", line)
        if match and not steps[-1]["name"]:
            steps[-1]["name"] = match.group(1)
    for step in steps:
        if not step["name"]:
            raise AssertionError(f"composite step without a name:\n{step['text']}")
    return steps


def _uncommented(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


# --------------------------------------------------------------------------- checkers


def workflow_violations(text: str) -> list[str]:
    """Invariants of nexus-core-issue-completion.yml (NCGF-004)."""
    violations: list[str] = []
    on_block = _top_level_block(text, "on")
    triggers = set(re.findall(r"^  ([A-Za-z_]+):", on_block, flags=re.MULTILINE))
    if triggers != {"pull_request_target"}:
        violations.append(
            "trigger: workflow must run only on pull_request_target (base-ref workflow "
            f"and config), found {sorted(triggers)}"
        )
    jobs = _jobs(text)
    for job_id in GATED_JOBS:
        if job_id not in jobs:
            violations.append(f"fork guard: job {job_id!r} is missing")
            continue
        condition = _job_if(jobs[job_id])
        if condition is None or SAME_REPO_GUARD not in condition:
            violations.append(
                f"fork guard: job {job_id!r} must carry the same-repository guard "
                f"'{SAME_REPO_GUARD}' in its if:"
            )
        if condition is not None and "head.repo.fork" in condition:
            violations.append(
                f"fork guard: job {job_id!r} must not rely on head.repo.fork (true for every "
                "branch when the repository is itself a fork)"
            )
        if condition is not None and re.search(r"\|\|", condition):
            violations.append(f"fork guard: job {job_id!r} if: must not be widened with '||'")
    verify = jobs.get("verify", "")
    identities = re.findall(r"^\s+expected-identity:\s*(\S+)\s*$", verify, flags=re.MULTILINE)
    if identities != [EXPECTED_IDENTITY]:
        violations.append(
            "sigstore identity: verify job must pin expected-identity to this workflow on "
            f"refs/heads/main ({EXPECTED_IDENTITY}), found {identities}"
        )
    if "./trusted/.github/actions/receipt-verify" not in _uncommented(verify):
        violations.append(
            "receipt authority: verify job must use the trusted receipt-verify action"
        )
    if "./trusted/.github/actions/issue-gate" not in _uncommented(jobs.get("run", "")):
        violations.append("run job must use the trusted issue-gate action")
    return violations


def issue_gate_violations(text: str) -> list[str]:
    """issue-check must be invoked with --require-trusted-config (NCGF-004)."""
    calls = [
        line.strip()
        for step in _steps(text)
        for line in _uncommented(step["text"]).splitlines()
        if "nexus-certify issue-check" in line
    ]
    if not calls:
        return ["trusted config: issue-gate must invoke 'nexus-certify issue-check'"]
    return [
        f"trusted config: issue-check must pass --require-trusted-config: {call!r}"
        for call in calls
        if "--require-trusted-config" not in call.split()
    ]


def _shell_command(run_text: str, needle: str) -> str | None:
    """Join the backslash-continued shell command that starts with ``needle``."""
    lines = _uncommented(run_text).splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith(needle):
            parts = [line.strip()]
            while parts[-1].endswith("\\") and index + 1 < len(lines):
                index += 1
                parts[-1] = parts[-1][:-1].rstrip()
                parts.append(lines[index].strip())
            return " ".join(parts)
    return None


def receipt_verify_violations(text: str) -> list[str]:
    """receipt-check must carry all eight expectations (NCGF-004)."""
    commands = [
        command
        for step in _steps(text)
        if (command := _shell_command(step["text"], "nexus-certify receipt-check")) is not None
    ]
    if len(commands) != 1:
        return [
            f"receipt expectations: expected exactly one receipt-check call, found {len(commands)}"
        ]
    command = " " + re.sub(r"\s+", " ", commands[0]) + " "
    return [
        f"receipt expectations: receipt-check must pass {flag}"
        for flag in RECEIPT_CHECK_EXPECTATIONS
        if f" {flag} " not in command
    ]


def token_steps(text: str) -> set[str]:
    """Names of composite steps whose text references the GitHub token (NCGF-005)."""
    return {
        step["name"] for step in _steps(text) if _TOKEN_REFERENCE.search(_uncommented(step["text"]))
    }


def token_violations(path: Path, text: str) -> list[str]:
    violations: list[str] = []
    steps_text = text.split("\n  steps:\n", 1)
    if len(steps_text) != 2 or _TOKEN_REFERENCE.search(_uncommented(steps_text[0])):
        violations.append(f"token scope: {path.name} references the token outside runs.steps")
    found = token_steps(text)
    if found != TOKEN_STEPS[path]:
        violations.append(
            f"token scope: {path.name} steps seeing the token {sorted(found)} != documented "
            f"{sorted(TOKEN_STEPS[path])} (update SECURITY.md 'PR gate' with any change)"
        )
    return violations


# --------------------------------------------------------------------------- tests


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_pr_gate_workflow_trigger_fork_guard_and_identity() -> None:
    assert workflow_violations(_read(WORKFLOW)) == []


def test_issue_gate_runs_issue_check_with_trusted_config() -> None:
    assert issue_gate_violations(_read(ISSUE_GATE)) == []


def test_receipt_verify_passes_all_eight_expectations() -> None:
    assert receipt_verify_violations(_read(RECEIPT_VERIFY)) == []


def test_token_exposure_matches_security_documentation() -> None:
    for path in TOKEN_STEPS:
        assert token_violations(path, _read(path)) == []


def test_candidate_fetch_token_is_env_scoped_and_never_persisted() -> None:
    """SECURITY.md 'PR gate': FETCH_TOKEN reaches git only via env-scoped http.extraheader."""
    (step,) = [
        s for s in _steps(_read(ISSUE_GATE)) if s["name"].startswith("Acquire candidate head")
    ]
    body = _uncommented(step["text"])
    assert "FETCH_TOKEN: ${{ github.token }}" in body
    assert "GIT_CONFIG_KEY_0=http.extraheader" in body
    assert not re.search(r"git\b[^\n]*\bconfig\b(?![^\n]*--get)", body), (
        "token must not be written by git config"
    )
    assert 'test -z "$(git -C "$CANDIDATE" config --get http.extraheader || true)"' in body
    # The verifier steps never receive FETCH_TOKEN (step env is step-scoped).
    for other in _steps(_read(ISSUE_GATE)):
        if other["name"] != step["name"]:
            assert "FETCH_TOKEN" not in other["text"], other["name"]


def test_security_md_pr_gate_row_documents_token_steps() -> None:
    row = next(
        line
        for line in _read(REPO_ROOT / "SECURITY.md").splitlines()
        if line.startswith("| **PR gate**")
    )
    assert "`GITHUB_TOKEN` is set only on the `issue-init`/`issue-check` steps" not in row
    for needle in (
        "FETCH_TOKEN",
        "http.extraheader",
        "issue-init",
        "issue-check",
        "receipt-verify",
    ):
        assert needle in row, needle


# --------------------------------------------------------------------------- negative controls


def test_negative_control_removed_fork_guard_is_detected() -> None:
    text = _read(WORKFLOW)
    mutated = text.replace(f"if: always() && {SAME_REPO_GUARD}", "if: always()", 1)
    assert mutated != text
    violations = workflow_violations(mutated)
    assert any("fork guard" in v and "'verify'" in v for v in violations), violations

    mutated = text.replace(
        f"if: {SAME_REPO_GUARD}", "if: github.event.pull_request.head.repo.fork == false", 1
    )
    assert mutated != text
    violations = workflow_violations(mutated)
    assert any("'run'" in v and "same-repository guard" in v for v in violations), violations
    assert any("'run'" in v and "head.repo.fork" in v for v in violations), violations


def test_negative_control_trigger_and_identity_mutations_are_detected() -> None:
    text = _read(WORKFLOW)
    mutated = text.replace("  pull_request_target:\n", "  pull_request:\n", 1)
    assert any(v.startswith("trigger:") for v in workflow_violations(mutated))
    mutated = text.replace("@refs/heads/main", "@refs/heads/feature", 1)
    assert any(v.startswith("sigstore identity:") for v in workflow_violations(mutated))


def test_negative_control_missing_expectations_are_detected() -> None:
    issue_gate = _read(ISSUE_GATE)
    mutated = issue_gate.replace(" --require-trusted-config\n", "\n", 1)
    assert mutated != issue_gate
    assert issue_gate_violations(mutated)

    receipt_verify = _read(RECEIPT_VERIFY)
    for flag in RECEIPT_CHECK_EXPECTATIONS:
        line = f"          {flag}"
        mutated = re.sub(rf"\n{re.escape(line)}( \S+)? \\\n", "\n", receipt_verify, count=1)
        if mutated == receipt_verify:  # the last flag has no trailing backslash
            mutated = re.sub(rf" \\\n{re.escape(line)}\n", "\n", receipt_verify, count=1)
        assert mutated != receipt_verify, flag
        assert receipt_verify_violations(mutated) == [
            f"receipt expectations: receipt-check must pass {flag}"
        ], flag


def test_negative_control_token_drift_is_detected() -> None:
    text = _read(ISSUE_GATE)
    mutated = text.replace(
        "        IN_PYTHON: ${{ inputs.python-version }}\n        UV_TOOL_DIR",
        "        IN_PYTHON: ${{ inputs.python-version }}\n        GH_TOKEN: ${{ github.token }}\n        UV_TOOL_DIR",
        1,
    )
    assert mutated != text
    assert token_violations(ISSUE_GATE, mutated)
