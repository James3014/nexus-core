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
RECEIPT_REUSE = REPO_ROOT / ".github" / "actions" / "receipt-reuse" / "action.yml"
# Issue #255: the reuse-enabled consumer layout. It is an example (never run in this
# repository); nexus-core's own gate keeps the two-job layout above.
CONSUMER_EXAMPLE = REPO_ROOT / "docs" / "examples" / "nexus-core-issue-completion.consumer.yml"

SAME_REPO_GUARD = "github.event.pull_request.head.repo.full_name == github.repository"
GATED_JOBS = ("run", "verify")
CONSUMER_GATED_JOBS = ("reuse", "run", "verify")
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
REUSED_OK = "needs.reuse.result == 'success' && needs.reuse.outputs.reused == 'true'"
# Exact job conditions: any widening (an extra '||' arm, a dropped guard) is drift.
EXPECTED_JOB_IFS = {
    "reuse": f"{PR_EVENT} && {SAME_REPO_GUARD}",
    "run": (
        f"(!cancelled()) && (({PR_EVENT} && {SAME_REPO_GUARD} && !({REUSED_OK})) "
        f"|| ({DISPATCH_GUARD}))"
    ),
    "verify": f"always() && (({PR_EVENT} && {SAME_REPO_GUARD}) || ({DISPATCH_GUARD}))",
}
# receipt-verify is skipped only when the reuse job succeeded with reused == 'true'.
VERIFY_STEP_IF = (
    f"github.event_name == '{DISPATCH_TRIGGER}' || needs.reuse.result != 'success' "
    "|| needs.reuse.outputs.reused != 'true'"
)
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
    RECEIPT_REUSE: {
        "Find prior signed receipt for this head",
        "Check config lineage and trust-file equivalence",
        "Check Issue is still open",
        "Download prior receipt artifact",
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


def consumer_workflow_violations(text: str) -> list[str]:
    """Invariants of the reuse-enabled consumer example (Issue #255)."""
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
    if _consumer_action("receipt-reuse") not in _uncommented(jobs.get("reuse", "")):
        violations.append("reuse job must use the trusted receipt-reuse action")
    if not re.search(r"(?m)^    needs: \[reuse, run\]\s*$", verify):
        violations.append("receipt authority: verify job must need exactly [reuse, run]")
    if not re.search(r"(?m)^    needs: reuse\s*$", jobs.get("run", "")):
        violations.append("run job must need reuse")
    try:
        verify_if = _step_if(_workflow_step(verify, "Verify signed receipt"))
        decide = _workflow_step(verify, "Decide required check")
    except AssertionError as error:
        violations.append(f"receipt authority: {error}")
    else:
        if verify_if != VERIFY_STEP_IF:
            violations.append(
                "receipt authority: receipt-verify may be skipped only when reuse succeeded "
                f"with reused == 'true' (if: {VERIFY_STEP_IF!r}), found {verify_if!r}"
            )
        if _step_if(decide) != "always()":
            violations.append("receipt authority: the final decision step must run always()")
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


def test_issue_gate_runs_issue_check_with_trusted_config() -> None:
    assert issue_gate_violations(_read(ISSUE_GATE)) == []


def test_receipt_verify_passes_all_eight_expectations() -> None:
    assert receipt_verify_violations(_read(RECEIPT_VERIFY)) == []


def test_receipt_reuse_passes_all_eight_expectations() -> None:
    assert receipt_verify_violations(_read(RECEIPT_REUSE)) == []


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


def test_negative_control_consumer_removed_fork_guard_is_detected() -> None:
    text = _read(CONSUMER_EXAMPLE)
    verify_if = f"    if: {EXPECTED_JOB_IFS['verify']}\n"
    mutated = text.replace(verify_if, verify_if.replace(f" && {SAME_REPO_GUARD}", ""), 1)
    assert mutated != text
    violations = consumer_workflow_violations(mutated)
    assert any("fork guard" in v and "'verify'" in v for v in violations), violations

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

    reuse_if = f"    if: {EXPECTED_JOB_IFS['reuse']}\n"
    mutated = text.replace(reuse_if, reuse_if.replace(f" && {SAME_REPO_GUARD}", ""), 1)
    assert mutated != text
    violations = consumer_workflow_violations(mutated)
    assert any("'reuse'" in v and "same-repository guard" in v for v in violations), violations


def test_negative_control_consumer_widened_or_reuse_bypass_conditions_are_detected() -> None:
    text = _read(CONSUMER_EXAMPLE)
    verify_if = f"    if: {EXPECTED_JOB_IFS['verify']}\n"
    mutated = text.replace(verify_if, verify_if.rstrip("\n") + " || true\n", 1)
    assert any(v.startswith("job condition:") and "'verify'" in v for v in consumer_workflow_violations(mutated))
    # Running 'run' even when reused, or skipping it whenever reuse merely produced output.
    run_if = f"    if: {EXPECTED_JOB_IFS['run']}\n"
    mutated = text.replace(run_if, run_if.replace("needs.reuse.result == 'success' && ", ""), 1)
    assert any(v.startswith("job condition:") and "'run'" in v for v in consumer_workflow_violations(mutated))
    # Skipping receipt-verify without requiring the reuse job to have succeeded.
    mutated = text.replace(
        f"        if: {VERIFY_STEP_IF}\n        uses: James3014/nexus-core/.github/actions/receipt-verify@",
        "        if: needs.reuse.outputs.reused != 'true'\n        uses: James3014/nexus-core/.github/actions/receipt-verify@",
        1,
    )
    assert mutated != text
    assert any("receipt-verify may be skipped" in v for v in consumer_workflow_violations(mutated))


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

    for action in (RECEIPT_VERIFY, RECEIPT_REUSE):
        original = _read(action)
        for flag in RECEIPT_CHECK_EXPECTATIONS:
            line = f"          {flag}"
            mutated = re.sub(rf"\n{re.escape(line)}( \S+)? \\\n", "\n", original, count=1)
            if mutated == original:  # the last flag has no trailing backslash
                mutated = re.sub(
                    rf" \\\n{re.escape(line)}(;[^\n]*)?\n", r"\1\n", original, count=1
                )
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
