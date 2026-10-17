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

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "nexus-core-issue-completion.yml"
ISSUE_GATE = REPO_ROOT / ".github" / "actions" / "issue-gate" / "action.yml"
RECEIPT_VERIFY = REPO_ROOT / ".github" / "actions" / "receipt-verify" / "action.yml"
# Issue #255: the repository_dispatch-enabled consumer layout. It is an example (never run
# in this repository).
CONSUMER_EXAMPLE = REPO_ROOT / "docs" / "examples" / "nexus-core-issue-completion.consumer.yml"

REPOSITORY_CHECK_EXAMPLE = REPO_ROOT / "docs" / "examples" / "github-repository-check.yml"
SAME_REPO_GUARD = "github.event.pull_request.head.repo.full_name == github.repository"
GATED_JOBS = ("run",)
# #287: the evidence-universe mode nexus-core's own gate must run with.
EXPECTED_EVIDENCE_UNIVERSE = "trusted-config"
CONSUMER_GATED_JOBS = ("run",)
CONSUMER_PIN = "0" * 40
CONSUMER_IDENTITY = (
    "https://github.com/OWNER/REPO/.github/workflows/"
    "nexus-core-issue-completion.yml@refs/heads/main"
)


def _consumer_action(name: str) -> str:
    return f"James3014/nexus-core/.github/actions/{name}@{CONSUMER_PIN}"


# Issue #255: the only early-run trigger. It must stay a single audited constant.
DISPATCH_TRIGGER = "repository_dispatch"
DISPATCH_TYPES = "[nexus-core-precheck]"
PR_EVENT = "github.event_name == 'pull_request_target'"
DISPATCH_GUARD = (
    f"github.event_name == '{DISPATCH_TRIGGER}' && github.ref == "
    "format('refs/heads/{0}', github.event.repository.default_branch)"
)
# Exact job conditions: any widening (an extra '||' arm, a dropped guard) is drift.
EXPECTED_JOB_IFS = {
    "run": f"({PR_EVENT} && {SAME_REPO_GUARD}) || ({DISPATCH_GUARD})",
}
# #265: a skipped required check counts as success, so the consumer verify job is never
# skipped: its if: is exactly always() and the first step fails closed.
CONSUMER_VERIFY_IF = "always()"
GUARD_STEP_NAME = "Fail closed on untrusted source or unsuccessful issuer"
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
        "Read live pull request state",
        "Acquire candidate head with plain Git (no submodule handling)",
        "Bind exact Issue contract",
        "Verify exact Issue-bound candidate",
    },
    RECEIPT_VERIFY: {
        "Resolve exact producer artifact",
        "Confirm skipped PR merged at this head",
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


def _workflow_step(job_text: str, name: str) -> str:
    """The text of the ``- name: <name>`` step of a job (six-space step items)."""
    chunks = re.split(r"(?m)^      - ", job_text)
    found = [chunk for chunk in chunks[1:] if chunk.startswith(f"name: {name}\n")]
    if len(found) != 1:
        raise AssertionError(f"expected exactly one workflow step {name!r}, found {len(found)}")
    return found[0]


def _step_if(step_text: str) -> str | None:
    for line in step_text.splitlines():
        match = re.fullmatch(r"        if:\s*(.+?)\s*", line)
        if match:
            return match.group(1)
    return None


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
    violations.extend(_consumer_verify_guard_violations(verify))
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
    # #287: nexus-core's own gate derives the evidence universe from the trusted base
    # config, like Nexus-new and the consumers, so Issues need no body marker.
    modes = re.findall(
        r"^\s+evidence-universe:\s*(\S+)\s*$",
        _uncommented(jobs.get("run", "")),
        flags=re.MULTILINE,
    )
    if modes != [EXPECTED_EVIDENCE_UNIVERSE]:
        violations.append(
            "evidence universe: run job must pass exactly one "
            f"'evidence-universe: {EXPECTED_EVIDENCE_UNIVERSE}' to issue-gate, found {modes}"
        )
    elif not _issue_gate_with_sets_evidence_universe(jobs.get("run", "")):
        violations.append(
            "evidence universe: 'evidence-universe: trusted-config' must sit in the with: "
            "block of the issue-gate step (anywhere else the action uses its issue-marker default)"
        )
    # #287 (Codex review): the gate trusts the checked-out base.sha, so only PRs into the
    # reviewed default branch may produce completion evidence.
    if not re.search(r"(?m)^    branches:\s*\[\s*main\s*\]\s*$", _uncommented(on_block)):
        violations.append("trigger: pull_request_target must be restricted to branches: [main]")
    return violations


def _issue_gate_with_sets_evidence_universe(run_job: str) -> bool:
    steps = [
        chunk
        for chunk in re.split(r"(?m)^      - ", run_job)[1:]
        if re.search(r"(?m)^        uses: \./trusted/\.github/actions/issue-gate\s*$", chunk)
    ]
    if len(steps) != 1:
        return False
    match = re.search(r"(?ms)^        with:\n((?:^          .*\n?)*)", steps[0])
    if match is None:
        return False
    with_block = _uncommented(match.group(1))
    return (
        re.search(
            rf"(?m)^          evidence-universe:\s*{EXPECTED_EVIDENCE_UNIVERSE}\s*$", with_block
        )
        is not None
    )


def _first_workflow_step(job_text: str) -> str | None:
    chunks = re.split(r"(?m)^      - ", job_text)
    return chunks[1] if len(chunks) > 1 else None


def _consumer_verify_guard_violations(verify: str) -> list[str]:
    """#265: verify is never skipped (if: always()) and its first step fails closed."""
    violations: list[str] = []
    condition = _job_if(verify)
    if condition != CONSUMER_VERIFY_IF:
        violations.append(
            f"job condition: job 'verify' if: must be exactly {CONSUMER_VERIFY_IF!r} (a skipped "
            f"required check counts as passed), found {condition!r}"
        )
    first = _first_workflow_step(verify)
    if first is None or not first.startswith(f"name: {GUARD_STEP_NAME}\n"):
        violations.append(f"fork guard: the first step of job 'verify' must be {GUARD_STEP_NAME!r}")
        return violations
    body = _uncommented(first)
    for code in ("NEXUS_CORE_UNTRUSTED_PR_SOURCE", "NEXUS_CORE_ISSUER_NOT_SUCCESSFUL"):
        if code not in body:
            violations.append(f"fork guard: the guard step must reference {code}")
    if "head.repo.fork" in body:
        violations.append("fork guard: the guard step must not rely on head.repo.fork")
    env_match = re.search(r"(?ms)^        env:\n(.*?)^        run:", first)
    env_text = env_match.group(1) if env_match else ""
    for needle in (
        "github.event.pull_request.head.repo.full_name",
        "github.repository",
        "needs.run.result",
    ):
        if needle not in env_text:
            violations.append(f"fork guard: the guard step must read {needle} through env:")
    run_match = re.search(r"(?ms)^        run: \|\n(.*)", first)
    if run_match and "${{" in run_match.group(1):
        violations.append("fork guard: the guard script must not inline ${{ }} expressions")
    return violations


def consumer_workflow_violations(text: str) -> list[str]:
    """Invariants of the dispatch-enabled consumer example (Issue #255)."""
    violations: list[str] = []
    on_block = _top_level_block(text, "on")
    triggers = set(re.findall(r"^  ([A-Za-z_]+):", on_block, flags=re.MULTILINE))
    if triggers != {"pull_request_target", DISPATCH_TRIGGER}:
        violations.append(
            "trigger: workflow must run only on pull_request_target (base-ref workflow "
            f"and config) and {DISPATCH_TRIGGER} (default-branch precheck), found "
            f"{sorted(triggers)}"
        )
    dispatch_types = re.findall(
        rf"^  {DISPATCH_TRIGGER}:\n    types:\s*(\S.*?)\s*$", on_block, flags=re.MULTILINE
    )
    if dispatch_types != [DISPATCH_TYPES]:
        violations.append(
            f"trigger: {DISPATCH_TRIGGER} must be limited to types {DISPATCH_TYPES}, "
            f"found {dispatch_types}"
        )
    jobs = _jobs(text)
    for job_id in CONSUMER_GATED_JOBS:
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
        if condition != EXPECTED_JOB_IFS[job_id]:
            violations.append(
                f"job condition: job {job_id!r} if: must be exactly "
                f"{EXPECTED_JOB_IFS[job_id]!r}, found {condition!r}"
            )
    verify = jobs.get("verify", "")
    violations.extend(_consumer_verify_guard_violations(verify))
    verify = jobs.get("verify", "")
    identities = re.findall(r"^\s+expected-identity:\s*(\S+)\s*$", verify, flags=re.MULTILINE)
    if identities != [CONSUMER_IDENTITY]:
        violations.append(
            "sigstore identity: verify job must pin expected-identity to this workflow on "
            f"refs/heads/main ({CONSUMER_IDENTITY}), found {identities}"
        )
    if _consumer_action("receipt-verify") not in _uncommented(verify):
        violations.append(
            "receipt authority: verify job must use the trusted receipt-verify action"
        )
    if _consumer_action("issue-gate") not in _uncommented(jobs.get("run", "")):
        violations.append("run job must use the trusted issue-gate action")
    if not re.search(r"(?m)^    needs: run\s*$", verify):
        violations.append("receipt authority: verify job must need exactly run")
    try:
        decide = _workflow_step(verify, "Decide required check")
    except AssertionError as error:
        violations.append(f"receipt authority: {error}")
    else:
        if _step_if(decide) != "always()":
            violations.append("receipt authority: the final decision step must run always()")
    return violations


def repository_check_example_violations(text: str) -> list[str]:
    """#265: docs/examples/github-repository-check.yml (the primary consumer example)."""
    violations: list[str] = []
    on_block = _top_level_block(text, "on")
    triggers = set(re.findall(r"^  ([A-Za-z_]+):", on_block, flags=re.MULTILINE))
    if triggers != {"pull_request_target"}:
        violations.append(
            f"trigger: example must run only on pull_request_target, found {sorted(triggers)}"
        )
    jobs = _jobs(text)
    run = jobs.get("run", "")
    if _job_if(run) != SAME_REPO_GUARD:
        violations.append(f"fork guard: job 'run' if: must be exactly {SAME_REPO_GUARD!r}")
    violations.extend(_consumer_verify_guard_violations(jobs.get("verify", "")))
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
    """Join the backslash-continued shell command whose first line contains ``needle``."""
    lines = _uncommented(run_text).splitlines()
    for index, line in enumerate(lines):
        if needle in line:
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
    # A trailing '; then' (command used as an if condition) is not part of the flags.
    command = " " + re.sub(r"\s+", " ", re.sub(r";\s*then\s*$", "", commands[0])) + " "
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


def test_consumer_example_trigger_fork_guard_conditions_and_identity() -> None:
    assert consumer_workflow_violations(_read(CONSUMER_EXAMPLE)) == []


def test_repository_check_example_verify_fails_closed_instead_of_skipping() -> None:
    assert repository_check_example_violations(_read(REPOSITORY_CHECK_EXAMPLE)) == []


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
    guard = _guard_step_text(text)
    mutated = text.replace(guard + "\n", "", 1)
    assert mutated != text
    violations = workflow_violations(mutated)
    assert any("fork guard" in v and "'verify'" in v for v in violations), violations
    # a skippable verify job (job-level same-repository condition) is a violation
    mutated = text.replace(
        "    if: always()\n    runs-on: ubuntu-latest\n    timeout-minutes: 15",
        f"    if: always() && {SAME_REPO_GUARD}\n    runs-on: ubuntu-latest\n    timeout-minutes: 15",
        1,
    )
    assert mutated != text
    assert any(v.startswith("job condition:") for v in workflow_violations(mutated))
    # guard step without the issuer check
    mutated = text.replace(guard, guard.replace("NEXUS_CORE_ISSUER_NOT_SUCCESSFUL", "X"), 1)
    assert any("NEXUS_CORE_ISSUER_NOT_SUCCESSFUL" in v for v in workflow_violations(mutated))

    mutated = text.replace(
        f"if: {SAME_REPO_GUARD}", "if: github.event.pull_request.head.repo.fork == false", 1
    )
    assert mutated != text
    violations = workflow_violations(mutated)
    assert any("'run'" in v and "same-repository guard" in v for v in violations), violations
    assert any("'run'" in v and "head.repo.fork" in v for v in violations), violations


def test_negative_control_repository_check_example_mutations_are_detected() -> None:
    text = _read(REPOSITORY_CHECK_EXAMPLE)
    guard = _guard_step_text(text)
    mutated = text.replace(guard + "\n", "", 1)
    assert mutated != text
    assert any("first step" in v for v in repository_check_example_violations(mutated))
    mutated = text.replace(
        "    if: always()\n    runs-on: ubuntu-latest\n    timeout-minutes: 15",
        f"    if: always() && {SAME_REPO_GUARD}\n    runs-on: ubuntu-latest\n    timeout-minutes: 15",
        1,
    )
    assert mutated != text
    assert any(v.startswith("job condition:") for v in repository_check_example_violations(mutated))
    mutated = text.replace(
        guard, guard.replace('"$HEAD_REPO" != "$REPOSITORY"', "head.repo.fork"), 1
    )
    assert any("head.repo.fork" in v for v in repository_check_example_violations(mutated))
    mutated = text.replace(guard, guard.replace("NEXUS_CORE_ISSUER_NOT_SUCCESSFUL", "X"), 1)
    assert any("ISSUER" in v for v in repository_check_example_violations(mutated))


def test_negative_control_trigger_and_identity_mutations_are_detected() -> None:
    text = _read(WORKFLOW)
    mutated = text.replace("  pull_request_target:\n", "  pull_request:\n", 1)
    assert any(v.startswith("trigger:") for v in workflow_violations(mutated))
    mutated = text.replace("@refs/heads/main", "@refs/heads/feature", 1)
    assert any(v.startswith("sigstore identity:") for v in workflow_violations(mutated))


def test_pr_gate_workflow_pins_trusted_config_evidence_universe() -> None:
    """#287: an Issue without a NEXUS_CORE_EVIDENCE_UNIVERSE marker must still verify."""
    text = _read(WORKFLOW)
    assert "evidence-universe: trusted-config" in _uncommented(_jobs(text)["run"])
    assert not any(v.startswith("evidence universe:") for v in workflow_violations(text))


def test_negative_control_evidence_universe_mutations_are_detected() -> None:
    text = _read(WORKFLOW)
    line = "          evidence-universe: trusted-config\n"
    assert text.count(line) == 1
    for mutated in (
        text.replace(line, "", 1),
        text.replace(line, "          # evidence-universe: trusted-config\n", 1),
        text.replace(line, "          evidence-universe: issue-marker\n", 1),
        text.replace(line, line + line, 1),
        # Relocated out of the issue-gate with: block (Codex r1): the action would fall
        # back to its issue-marker default.
        text.replace(line, "", 1).replace(
            "          persist-credentials: false\n",
            "          persist-credentials: false\n" + line,
            1,
        ),
    ):
        assert mutated != text
        assert any(v.startswith("evidence universe:") for v in workflow_violations(mutated))


def test_negative_control_unrestricted_target_branch_is_detected() -> None:
    text = _read(WORKFLOW)
    branches = "    branches: [main]\n"
    assert text.count(branches) == 1
    mutated = text.replace(branches, "", 1)
    assert any("branches: [main]" in v for v in workflow_violations(mutated))


def _guard_step_text(text: str) -> str:
    verify = _jobs(text)["verify"]
    first = _first_workflow_step(verify)
    assert first is not None
    return "      - " + first.split("\n      - ", 1)[0].rstrip("\n") + "\n"


def test_negative_control_consumer_removed_fork_guard_is_detected() -> None:
    text = _read(CONSUMER_EXAMPLE)
    guard = _guard_step_text(text)
    assert guard in text
    mutated = text.replace(guard + "\n", "", 1)
    assert mutated != text
    violations = consumer_workflow_violations(mutated)
    assert any("fork guard" in v and "first step" in v for v in violations), violations

    run_if = f"    if: {EXPECTED_JOB_IFS['run']}\n"
    mutated = text.replace(
        run_if,
        run_if.replace(SAME_REPO_GUARD, "github.event.pull_request.head.repo.fork == false"),
        1,
    )
    assert mutated != text
    violations = consumer_workflow_violations(mutated)
    assert any("'run'" in v and "same-repository guard" in v for v in violations), violations
    assert any("'run'" in v and "head.repo.fork" in v for v in violations), violations


def test_negative_control_consumer_guard_step_mutations_are_detected() -> None:
    text = _read(CONSUMER_EXAMPLE)
    guard = _guard_step_text(text)
    # head.repo.fork used instead of the full_name comparison
    mutated = text.replace(
        guard,
        guard.replace('"$HEAD_REPO" != "$REPOSITORY"', "github.event.pull_request.head.repo.fork"),
        1,
    )
    assert mutated != text
    assert any("head.repo.fork" in v for v in consumer_workflow_violations(mutated))
    # issuer check missing
    mutated = text.replace(guard, guard.replace("NEXUS_CORE_ISSUER_NOT_SUCCESSFUL", "X"), 1)
    assert mutated != text
    assert any(
        "NEXUS_CORE_ISSUER_NOT_SUCCESSFUL" in v for v in consumer_workflow_violations(mutated)
    )
    # source code missing
    mutated = text.replace(guard, guard.replace("NEXUS_CORE_UNTRUSTED_PR_SOURCE", "X"), 1)
    assert any("NEXUS_CORE_UNTRUSTED_PR_SOURCE" in v for v in consumer_workflow_violations(mutated))
    # head repo not passed through env
    mutated = text.replace(
        guard,
        guard.replace(
            "          HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}\n", ""
        ),
        1,
    )
    assert mutated != text
    assert any("through env" in v for v in consumer_workflow_violations(mutated))
    # skippable verify job (job-level same-repo condition)
    mutated = text.replace(
        "    if: always()\n    runs-on: ubuntu-latest\n    timeout-minutes: 15",
        f"    if: always() && {SAME_REPO_GUARD}\n    runs-on: ubuntu-latest\n    timeout-minutes: 15",
        1,
    )
    assert mutated != text
    violations = consumer_workflow_violations(mutated)
    assert any(v.startswith("job condition:") and "'verify'" in v for v in violations), violations


def _guard_script(text: str) -> str:
    guard = _guard_step_text(text)
    match = re.search(r"(?ms)^        run: \|\n(.*)", guard)
    assert match
    return (
        "\n".join(
            line[10:] if line.startswith(" " * 10) else line for line in match.group(1).splitlines()
        )
        + "\n"
    )


GUARD_CASES = (
    (
        "pr_same_repo_ok",
        "pull_request_target",
        "o/r",
        "o/r",
        "refs/pull/1/merge",
        "main",
        "success",
        0,
        "",
    ),
    (
        "pr_fork",
        "pull_request_target",
        "evil/r",
        "o/r",
        "refs/pull/1/merge",
        "main",
        "skipped",
        1,
        "NEXUS_CORE_UNTRUSTED_PR_SOURCE",
    ),
    (
        "pr_no_head_repo",
        "pull_request_target",
        "",
        "o/r",
        "refs/pull/1/merge",
        "main",
        "success",
        1,
        "NEXUS_CORE_UNTRUSTED_PR_SOURCE",
    ),
    (
        "pr_run_failed",
        "pull_request_target",
        "o/r",
        "o/r",
        "refs/pull/1/merge",
        "main",
        "failure",
        1,
        "NEXUS_CORE_ISSUER_NOT_SUCCESSFUL",
    ),
    (
        "pr_run_skipped",
        "pull_request_target",
        "o/r",
        "o/r",
        "refs/pull/1/merge",
        "main",
        "skipped",
        1,
        "NEXUS_CORE_ISSUER_NOT_SUCCESSFUL",
    ),
    (
        "dispatch_main_ok",
        "repository_dispatch",
        "",
        "o/r",
        "refs/heads/main",
        "main",
        "success",
        0,
        "",
    ),
    (
        "dispatch_other_ref",
        "repository_dispatch",
        "",
        "o/r",
        "refs/heads/feature",
        "main",
        "success",
        1,
        "NEXUS_CORE_UNTRUSTED_DISPATCH_REF",
    ),
    (
        "dispatch_run_failed",
        "repository_dispatch",
        "",
        "o/r",
        "refs/heads/main",
        "main",
        "failure",
        1,
        "NEXUS_CORE_ISSUER_NOT_SUCCESSFUL",
    ),
    (
        "other_event",
        "workflow_dispatch",
        "",
        "o/r",
        "refs/heads/main",
        "main",
        "success",
        1,
        "NEXUS_CORE_UNTRUSTED_EVENT: workflow_dispatch",
    ),
)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")
@pytest.mark.parametrize(
    ("case", "event", "head", "repo", "ref", "default", "result", "code", "reason"),
    GUARD_CASES,
    ids=[c[0] for c in GUARD_CASES],
)
def test_consumer_guard_script_fails_closed(
    case: str,
    event: str,
    head: str,
    repo: str,
    ref: str,
    default: str,
    result: str,
    code: int,
    reason: str,
) -> None:
    script = _guard_script(_read(CONSUMER_EXAMPLE))
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "EVENT_NAME": event,
        "HEAD_REPO": head,
        "REPOSITORY": repo,
        "REF": ref,
        "DEFAULT_BRANCH": default,
        "RUN_RESULT": result,
    }
    proc = subprocess.run(
        ["bash", "-c", script], env=env, capture_output=True, text=True, check=False
    )
    assert proc.returncode == code, (case, proc.stderr)
    if reason:
        assert reason in proc.stderr, (case, proc.stderr)


def test_negative_control_consumer_widened_conditions_are_detected() -> None:
    text = _read(CONSUMER_EXAMPLE)
    verify_if = "    if: always()\n    runs-on: ubuntu-latest\n    timeout-minutes: 15"
    mutated = text.replace(verify_if, verify_if.replace("always()", "always() && true", 1), 1)
    assert mutated != text
    assert any(
        v.startswith("job condition:") and "'verify'" in v
        for v in consumer_workflow_violations(mutated)
    )
    run_if = f"    if: {EXPECTED_JOB_IFS['run']}\n"
    mutated = text.replace(run_if, run_if.rstrip("\n") + " || true\n", 1)
    assert mutated != text
    assert any(
        v.startswith("job condition:") and "'run'" in v
        for v in consumer_workflow_violations(mutated)
    )
    mutated = text.replace("    needs: run\n", "", 1)
    assert mutated != text
    assert any(
        "verify job must need exactly run" in v for v in consumer_workflow_violations(mutated)
    )


def test_negative_control_consumer_trigger_and_identity_mutations_are_detected() -> None:
    text = _read(CONSUMER_EXAMPLE)
    mutated = text.replace("  pull_request_target:\n", "  pull_request:\n", 1)
    assert any(v.startswith("trigger:") for v in consumer_workflow_violations(mutated))
    mutated = text.replace(f"  {DISPATCH_TRIGGER}:\n", "  workflow_dispatch:\n", 1)
    assert mutated != text
    assert any(v.startswith("trigger:") for v in consumer_workflow_violations(mutated))
    mutated = text.replace(DISPATCH_TYPES, "[nexus-core-precheck, other]", 1)
    assert mutated != text
    assert any(v.startswith("trigger:") for v in consumer_workflow_violations(mutated))
    mutated = text.replace("@refs/heads/main", "@refs/heads/feature", 1)
    assert any(v.startswith("sigstore identity:") for v in consumer_workflow_violations(mutated))


def test_negative_control_missing_expectations_are_detected() -> None:
    issue_gate = _read(ISSUE_GATE)
    mutated = issue_gate.replace(" --require-trusted-config\n", "\n", 1)
    assert mutated != issue_gate
    assert issue_gate_violations(mutated)

    for action in (RECEIPT_VERIFY,):
        original = _read(action)
        for flag in RECEIPT_CHECK_EXPECTATIONS:
            line = f"          {flag}"
            mutated = re.sub(rf"\n{re.escape(line)}( \S+)? \\\n", "\n", original, count=1)
            if mutated == original:  # the last flag has no trailing backslash
                mutated = re.sub(rf" \\\n{re.escape(line)}(;[^\n]*)?\n", r"\1\n", original, count=1)
            assert mutated != original, (action.name, flag)
            assert receipt_verify_violations(mutated) == [
                f"receipt expectations: receipt-check must pass {flag}"
            ], (action.name, flag)


def test_negative_control_token_drift_is_detected() -> None:
    text = _read(ISSUE_GATE)
    mutated = text.replace(
        "        IN_PYTHON: ${{ inputs.python-version }}\n        UV_TOOL_DIR",
        "        IN_PYTHON: ${{ inputs.python-version }}\n        GH_TOKEN: ${{ github.token }}\n        UV_TOOL_DIR",
        1,
    )
    assert mutated != text
    assert token_violations(ISSUE_GATE, mutated)


# --------------------------------------------------------------------------- #250 skip wiring

SKIP_OUTCOME = "PR_ALREADY_CLOSED_SKIPPED"


def pr_state_skip_violations(gate_text: str, verify_text: str) -> list[str]:
    """#250: the closed-PR skip is neutral, live-checked on both sides, and never VERIFIED."""
    violations: list[str] = []
    gate_steps = _steps(gate_text)
    names = [step["name"] for step in gate_steps]
    preflight = [s for s in gate_steps if "nexus-certify pr-state" in _uncommented(s["text"])]
    if len(preflight) != 1 or "--mode gate" not in preflight[0]["text"]:
        violations.append(
            "gate preflight: issue-gate must call 'nexus-certify pr-state --mode gate' once"
        )
    else:
        index = names.index(preflight[0]["name"])
        for guarded in (
            "Acquire candidate head with plain Git (no submodule handling)",
            "Bind exact Issue contract",
            "Verify exact Issue-bound candidate",
        ):
            if guarded not in names or names.index(guarded) < index:
                violations.append(f"gate preflight: {guarded!r} must run after the preflight")
                continue
            step = gate_steps[names.index(guarded)]
            if "steps.prstate.outputs.outcome == 'PROCEED'" not in step["text"]:
                violations.append(
                    f"gate preflight: {guarded!r} must run only when the preflight said PROCEED"
                )
    verify_steps = _steps(verify_text)
    skip_checks = [s for s in verify_steps if "nexus-certify pr-state" in _uncommented(s["text"])]
    if len(skip_checks) != 1 or "--mode verify-skip" not in skip_checks[0]["text"]:
        violations.append(
            "verify skip: receipt-verify must re-read the live PR with "
            "'nexus-certify pr-state --mode verify-skip' exactly once"
        )
    elif f"inputs.gate-outcome == '{SKIP_OUTCOME}'" not in skip_checks[0]["text"]:
        violations.append("verify skip: the live check must run only for a declared skip")
    else:
        skip_text = _uncommented(skip_checks[0]["text"])
        if "verified=true" in skip_text:
            violations.append("verify skip: a skip must never set verified=true")
    for step in verify_steps:
        text = _uncommented(step["text"])
        if "nexus-certify receipt-check" in text or "verified=true" in text:
            if f"inputs.gate-outcome != '{SKIP_OUTCOME}'" not in step["text"]:
                violations.append(f"verify skip: {step['name']!r} must not run for a declared skip")
    return violations


def test_closed_pr_skip_is_live_checked_and_never_verified() -> None:
    assert pr_state_skip_violations(_read(ISSUE_GATE), _read(RECEIPT_VERIFY)) == []


def test_negative_control_skip_wiring_mutations_are_detected() -> None:
    gate, verify = _read(ISSUE_GATE), _read(RECEIPT_VERIFY)
    mutated = gate.replace("steps.prstate.outputs.outcome == 'PROCEED'", "always()", 1)
    assert mutated != gate
    assert pr_state_skip_violations(mutated, verify)
    mutated = verify.replace("--mode verify-skip", "--mode gate", 1)
    assert mutated != verify
    assert pr_state_skip_violations(gate, mutated)
    mutated = verify.replace(f"inputs.gate-outcome != '{SKIP_OUTCOME}'", "always()")
    assert mutated != verify
    assert pr_state_skip_violations(gate, mutated)
