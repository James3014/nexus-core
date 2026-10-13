"""Issue #255: dispatch-mode issue gate and the PR-time receipt reuse fast path.

The heavy Core run may happen early, through a ``repository_dispatch`` run of the
consumer workflow on the default branch. On a pull request the ``receipt-reuse``
action may accept that signed receipt instead of re-running, but only when it is
provably equivalent; every other outcome must fall back to the full run, and no error
path may produce a pass.

Structural invariants are checked over the real files with the layout-specific parsers
of ``test_pr_gate_workflow_invariants``; behavioural invariants execute the real
``run:`` scripts (target resolution, path validation, prior-run lookup against a fake
REST API, lineage/equivalence against real Git repositories, and both final decision
steps). Negative controls feed mutated copies to the same checkers.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.architecture.test_pr_gate_workflow_invariants import (
    CONSUMER_EXAMPLE,
    DISPATCH_TRIGGER,
    ISSUE_GATE,
    RECEIPT_REUSE,
    _jobs,
    _shell_command,
    _steps,
    _uncommented,
    _workflow_step,
)

REPOSITORY = "James3014/nexus-core"
WORKFLOW_PATH = ".github/workflows/nexus-core-issue-completion.yml"
HEAD = "ab" * 20
BASE = "2" * 40
RUN_SHA = "3" * 40


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _run_block(step_text: str) -> str:
    """The ``run: |`` script of a step, de-indented (works for actions and workflows)."""
    lines = step_text.splitlines()
    index = next(i for i, line in enumerate(lines) if line.strip() == "run: |")
    indent = len(lines[index]) - len(lines[index].lstrip()) + 2
    body: list[str] = []
    for line in lines[index + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:])
    return "\n".join(body) + "\n"


def _action_step(path: Path, name: str, text: str | None = None) -> dict[str, str]:
    found = [step for step in _steps(text if text is not None else _read(path)) if step["name"] == name]
    assert len(found) == 1, (path.name, name)
    return found[0]


def _bash(script: str, env: dict[str, str], tmp_path: Path) -> tuple[int, dict[str, str], str]:
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    full = {"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(output), **env}
    result = subprocess.run(
        ["bash", "-c", script], env=full, capture_output=True, text=True, timeout=120
    )
    outputs: dict[str, str] = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        outputs[key] = value
    return result.returncode, outputs, result.stdout + result.stderr


# ------------------------------------------------------------------ issue-gate dispatch mode

TARGET_STEP = "Resolve gate target (head, base, base ref)"


def _target_env(**overrides: str) -> dict[str, str]:
    env = {
        "EVENT_NAME": "pull_request_target",
        "IN_HEAD": "",
        "IN_ISSUE": "",
        "PR_HEAD_SHA": HEAD,
        "PR_BASE_SHA": BASE,
        "PR_BASE_REF": "main",
        "RUN_SHA": RUN_SHA,
        "RUN_REF": "refs/heads/main",
        "RUN_REF_NAME": "main",
        "DEFAULT_BRANCH": "main",
    }
    env.update(overrides)
    return env


def _target(tmp_path: Path, **overrides: str) -> tuple[int, dict[str, str], str]:
    script = _run_block(_action_step(ISSUE_GATE, TARGET_STEP)["text"])
    return _bash(script, _target_env(**overrides), tmp_path)


@pytest.mark.parametrize("event", ["pull_request_target", "pull_request"])
def test_issue_gate_pull_request_target_is_the_pull_request(tmp_path: Path, event: str) -> None:
    code, outputs, log = _target(tmp_path, EVENT_NAME=event)
    assert code == 0, log
    assert outputs == {"head-sha": HEAD, "base-sha": BASE, "base-ref": "main", "mode": "pull_request"}
    code, outputs, log = _target(tmp_path, EVENT_NAME=event, IN_HEAD=HEAD)
    assert code == 0, log
    assert outputs["head-sha"] == HEAD


def test_issue_gate_pull_request_rejects_a_different_head_input(tmp_path: Path) -> None:
    code, outputs, log = _target(tmp_path, IN_HEAD="4" * 40)
    assert code != 0 and outputs == {}
    assert "NEXUS_CORE_GATE_TARGET_INVALID" in log


def test_issue_gate_dispatch_mode_uses_the_default_branch_tip_as_base(tmp_path: Path) -> None:
    code, outputs, log = _target(
        tmp_path, EVENT_NAME=DISPATCH_TRIGGER, IN_HEAD=HEAD, IN_ISSUE="7", PR_HEAD_SHA="",
        PR_BASE_SHA="", PR_BASE_REF="",
    )
    assert code == 0, log
    assert outputs == {"head-sha": HEAD, "base-sha": RUN_SHA, "base-ref": "main", "mode": "dispatch"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"IN_HEAD": ""},
        {"IN_HEAD": "ABC"},
        {"IN_HEAD": HEAD.upper()},
        {"IN_HEAD": HEAD + "\nbase-sha=" + BASE},
        {"IN_ISSUE": ""},
        {"IN_ISSUE": "0"},
        {"IN_ISSUE": "7 "},
        {"IN_ISSUE": "-1"},
        {"RUN_REF": "refs/heads/feature", "RUN_REF_NAME": "feature"},
        {"RUN_REF": "refs/tags/main"},
        {"RUN_REF_NAME": "feature"},
        {"DEFAULT_BRANCH": ""},
        {"RUN_SHA": ""},
    ],
)
def test_issue_gate_dispatch_mode_fails_closed(tmp_path: Path, overrides: dict[str, str]) -> None:
    env = {"EVENT_NAME": DISPATCH_TRIGGER, "IN_HEAD": HEAD, "IN_ISSUE": "7", **overrides}
    code, outputs, _ = _target(tmp_path, **env)
    assert code != 0
    assert outputs == {}


@pytest.mark.parametrize(
    "event", ["workflow_dispatch", "push", "schedule", "pull_request_review", "issue_comment", ""]
)
def test_issue_gate_any_other_event_fails_closed(tmp_path: Path, event: str) -> None:
    code, outputs, log = _target(tmp_path, EVENT_NAME=event, IN_HEAD=HEAD, IN_ISSUE="7")
    assert code != 0 and outputs == {}
    assert "unsupported event" in log


def issue_gate_dispatch_violations(text: str) -> list[str]:
    violations: list[str] = []
    steps = _steps(text)
    names = [step["name"] for step in steps]
    if not names or names[0] != TARGET_STEP:
        violations.append("target: head/base/base-ref must be resolved in the first step")
    body = "".join(_uncommented(step["text"]) for step in steps)
    if body.count(DISPATCH_TRIGGER) != 1 or f'readonly DISPATCH_EVENT="{DISPATCH_TRIGGER}"' not in body:
        violations.append(f"trigger: {DISPATCH_TRIGGER} must appear once, as the DISPATCH_EVENT constant")
    for step in steps[1:]:
        for field in ("head.sha", "base.sha", "base.ref"):
            if f"github.event.pull_request.{field}" in step["text"]:
                violations.append(
                    f"target: step {step['name']!r} reads pull_request.{field} instead of "
                    "the resolved target"
                )
    acquire = next((s for s in steps if s["name"].startswith("Acquire candidate head")), None)
    names_step = next((s for s in steps if s["name"] == "Name receipt artifact"), None)
    for step, needles in (
        (acquire, ("HEAD_SHA: ${{ steps.target.outputs.head-sha }}",
                   "BASE_SHA: ${{ steps.target.outputs.base-sha }}",
                   "BASE_REF: ${{ steps.target.outputs.base-ref }}")),
        (names_step, ("HEAD_SHA: ${{ steps.target.outputs.head-sha }}",)),
    ):
        if step is None or any(needle not in step["text"] for needle in needles):
            violations.append("target: candidate fetch and artifact name must use the resolved target")
    install = next((i for i, n in enumerate(names) if n.startswith("Install pinned nexus-certify")), -1)
    fetch = next((i for i, n in enumerate(names) if n.startswith("Acquire candidate head")), -1)
    if not 0 <= install < fetch:
        violations.append("ordering: the pinned tool must be installed before the candidate exists")
    return violations


def test_issue_gate_dispatch_mode_structure() -> None:
    assert issue_gate_dispatch_violations(_read(ISSUE_GATE)) == []


BRANCH_TIP_CHECK = "NEXUS_CORE_GATE_DISPATCH_HEAD_NOT_A_BRANCH_TIP"


def dispatch_branch_tip_violations(text: str) -> list[str]:
    steps = _steps(text)
    acquire = next((s for s in steps if s["name"].startswith("Acquire candidate head")), None)
    if acquire is None:
        return ["acquire step missing"]
    body = _uncommented(acquire["text"])
    violations = []
    if "TARGET_MODE: ${{ steps.target.outputs.mode }}" not in body:
        violations.append("dispatch head check must key on the resolved target mode")
    guard = body.find('if [ "$TARGET_MODE" = "dispatch" ]; then')
    lsremote = body.find("ls-remote --heads origin")
    refusal = body.find(BRANCH_TIP_CHECK)
    fetch = body.find("fetch --no-tags origin")
    if not (0 <= guard < lsremote < refusal < fetch):
        violations.append("dispatch head must be proven a branch tip (ls-remote --heads) before the candidate fetch")
    if "refs\\/heads\\/" not in body:
        violations.append("branch-tip match must be limited to refs/heads/")
    return violations


def test_dispatch_head_must_be_a_branch_tip() -> None:
    assert dispatch_branch_tip_violations(_read(ISSUE_GATE)) == []


def test_negative_control_dispatch_branch_tip_check_removed_is_detected() -> None:
    text = _read(ISSUE_GATE)
    mutated = text.replace("ls-remote --heads origin", "ls-remote origin", 1)
    assert mutated != text
    assert dispatch_branch_tip_violations(mutated)
    guard = 'if [ "$TARGET_MODE" = "dispatch" ]; then\n          # Dispatch mode: the head must'
    assert guard in text
    mutated = text.replace(guard, guard.replace('[ "$TARGET_MODE" = "dispatch" ]', "false"), 1)
    assert mutated != text
    assert dispatch_branch_tip_violations(mutated)


def test_negative_control_issue_gate_dispatch_drift_is_detected() -> None:
    text = _read(ISSUE_GATE)
    mutations = [
        text.replace(
            "        HEAD_SHA: ${{ steps.target.outputs.head-sha }}\n        BASE_SHA",
            "        HEAD_SHA: ${{ github.event.pull_request.head.sha }}\n        BASE_SHA",
            1,
        ),
        text.replace('readonly DISPATCH_EVENT="repository_dispatch"', 'readonly DISPATCH_EVENT="workflow_dispatch"', 1),
        text.replace('"$DISPATCH_EVENT")', '"$DISPATCH_EVENT"|repository_dispatch)', 1),
    ]
    for mutated in mutations:
        assert mutated != text
        assert issue_gate_dispatch_violations(mutated)


# ------------------------------------------------------------------ receipt-reuse structure

CHECK_STEPS = (
    "Find prior signed receipt for this head",
    "Check config lineage and trust-file equivalence",
    "Check Issue is still open",
    "Download prior receipt artifact",
    "Locate exactly one receipt and bundle",
    "Install pinned nexus-certify",
    "Verify Sigstore signature, workflow identity, trigger and commit",
    "Check receipt against every expectation",
)


def receipt_reuse_violations(text: str) -> list[str]:
    violations: list[str] = []
    steps = _steps(text)
    body = "".join(_uncommented(step["text"]) for step in steps)
    if "actions/checkout" in body or re.search(r"\bgit\b[^\n]*\b(checkout|switch|worktree)\b", body):
        violations.append("candidate: receipt-reuse must never check out code")
    if re.search(r"\buv (sync|run|build)\b|\bpip install\b|\bmake\b", body):
        violations.append("candidate: receipt-reuse must never execute repository code")
    if "git init -q --bare" not in body:
        violations.append("candidate: Git objects must be fetched into a bare repository")
    if body.count(DISPATCH_TRIGGER) != 1 or f'readonly PRODUCER_EVENT="{DISPATCH_TRIGGER}"' not in body:
        violations.append(f"trigger: {DISPATCH_TRIGGER} must appear once, as the PRODUCER_EVENT constant")
    # Equivalence always covers the config and the workflow file.
    validate = next((s for s in steps if s["name"] == "Validate inputs"), None)
    if validate is None or 'paths=(".nexus-core/config.toml" "$IN_WORKFLOW")' not in validate["text"]:
        violations.append("equivalence: .nexus-core/config.toml and workflow-path must always be included")
    lineage = next((s for s in steps if s["name"] == CHECK_STEPS[1]), {"text": ""})
    for needle in (
        'merge-base --is-ancestor "$CONFIG_COMMIT" "$BASE_SHA"',
        '[ "$at_config" = "$at_base" ]',
        "CONFIG_COMMIT: ${{ steps.find.outputs.config-commit }}",
    ):
        if needle not in _uncommented(lineage["text"]):
            violations.append(f"lineage: missing {needle!r}")
    find = next((s for s in steps if s["name"] == CHECK_STEPS[0]), {"text": ""})
    for needle in (
        '"event": trigger',
        'run.get("event") != trigger',
        'run.get("path") != workflow',
        'run.get("head_branch") != branch',
        'run.get("conclusion") != "success"',
        'repository.get("full_name") != repo',
        'int(suffix) > run["run_attempt"]',
        'artifact.get("expired") is False',
        "len(matches) != 1",
    ):
        if needle not in find["text"]:
            violations.append(f"lookup: missing {needle!r}")
    signature = next((s for s in steps if s["name"] == CHECK_STEPS[6]), {"text": ""})
    command = _shell_command(signature["text"], "sigstore verify github") or ""
    command = " " + re.sub(r"\s+", " ", command) + " "
    for flag in (
        '--cert-identity "$IDENTITY"',
        '--repository "$REPO"',
        '--trigger "$TRIGGER"',
        '--sha "$CONFIG_COMMIT"',
        '--ref "refs/heads/${DEFAULT_BRANCH}"',
        '--bundle "$BUNDLE"',
    ):
        if f" {flag} " not in command:
            violations.append(f"sigstore: verify must pass {flag}")
    for needle in (
        "TRIGGER: ${{ steps.validate.outputs.trigger }}",
        "IDENTITY: ${{ steps.validate.outputs.identity }}",
        "CONFIG_COMMIT: ${{ steps.find.outputs.config-commit }}",
    ):
        if needle not in signature["text"]:
            violations.append(f"sigstore: missing {needle!r}")
    if (
        validate is None
        or 'echo "identity=https://github.com/${IN_REPO}/${IN_WORKFLOW}@refs/heads/${IN_DEFAULT}"'
        not in validate["text"]
    ):
        violations.append("sigstore: identity must be the consumer workflow on refs/heads/<default>")
    issue_step = next((s for s in steps if s["name"] == CHECK_STEPS[2]), {"text": ""})
    for needle in (
        "RUN_CREATED_AT: ${{ steps.find.outputs.run-created-at }}",
        'issue.get("updated_at")',
        "updated is None or created is None or updated > created",
        "REUSE_ISSUE_CHANGED_AFTER_PRECHECK",
    ):
        if needle not in _uncommented(issue_step["text"]):
            violations.append(f"issue freshness: missing {needle!r}")
    if '"run-created-at": run["created_at"]' not in find["text"]:
        violations.append("issue freshness: the lookup must emit the producing run's created_at")
    check = next((s for s in steps if s["name"] == CHECK_STEPS[7]), {"text": ""})
    if "CONFIG_COMMIT: ${{ steps.find.outputs.config-commit }}" not in check["text"] or (
        '--expect-config-commit "$CONFIG_COMMIT"' not in check["text"]
    ):
        violations.append("receipt-check: --expect-config-commit must be the producing commit R")
    # Soft checks: a failure declines reuse, never fails the PR by itself.
    for name in CHECK_STEPS:
        step = next((s for s in steps if s["name"] == name), None)
        if step is None or "continue-on-error: true" not in step["text"]:
            violations.append(f"fallback: check step {name!r} must be continue-on-error")
    # reused=true is decided only by the final always() step.
    if not steps or steps[-1]["name"] != "Decide reuse" or "if: always()" not in steps[-1]["text"]:
        violations.append("decision: the last step must be 'Decide reuse' with if: always()")
    for step in steps[:-1]:
        if re.search(r"\breused\b", _uncommented(step["text"])):
            violations.append(f"decision: step {step['name']!r} must not touch 'reused'")
    if "value: ${{ steps.decide.outputs.reused }}" not in text.split("\nruns:\n", 1)[0]:
        violations.append("decision: output 'reused' must come from the decide step")
    return violations


def test_receipt_reuse_structure() -> None:
    assert receipt_reuse_violations(_read(RECEIPT_REUSE)) == []


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('          --trigger "$TRIGGER" \\\n', ""),
        ('          --sha "$CONFIG_COMMIT" \\\n', ""),
        ('          --ref "refs/heads/${DEFAULT_BRANCH}" \\\n', ""),
        ('readonly PRODUCER_EVENT="repository_dispatch"', 'readonly PRODUCER_EVENT="workflow_dispatch"'),
        ('paths=(".nexus-core/config.toml" "$IN_WORKFLOW")', 'paths=("$IN_WORKFLOW")'),
        ('merge-base --is-ancestor "$CONFIG_COMMIT" "$BASE_SHA"', "true"),
        ('[ "$at_config" = "$at_base" ]', "true"),
        ('--expect-config-commit "$CONFIG_COMMIT"', '--expect-config-commit "$BASE_SHA"'),
        ('run.get("path") != workflow', "False"),
        ('int(suffix) > run["run_attempt"]', "False"),
        ("git init -q --bare", "git init -q"),
        ('        echo "ok=true" >> "$GITHUB_OUTPUT"\n\n    - name: Check receipt',
         '        echo "reused=true" >> "$GITHUB_OUTPUT"\n\n    - name: Check receipt'),
        ("    - name: Check Issue is still open\n      id: issue\n      if: steps.lineage.outputs.ok == 'true'\n      continue-on-error: true\n",
         "    - name: Check Issue is still open\n      id: issue\n      if: steps.lineage.outputs.ok == 'true'\n"),
        ("value: ${{ steps.decide.outputs.reused }}", "value: ${{ steps.check.outputs.ok }}"),
        ("updated is None or created is None or updated > created", "updated is None"),
        ("RUN_CREATED_AT: ${{ steps.find.outputs.run-created-at }}", "RUN_CREATED_AT: ''"),
    ],
)
def test_negative_control_receipt_reuse_drift_is_detected(old: str, new: str) -> None:
    text = _read(RECEIPT_REUSE)
    assert old in text, old
    assert receipt_reuse_violations(text.replace(old, new, 1))


def test_negative_control_candidate_checkout_in_reuse_is_detected() -> None:
    text = _read(RECEIPT_REUSE)
    mutated = text.replace(
        "    - name: Set up uv\n",
        "    - name: Checkout\n      uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n\n"
        "    - name: Set up uv\n",
        1,
    )
    assert mutated != text
    assert any(v.startswith("candidate:") for v in receipt_reuse_violations(mutated))


# ------------------------------------------------------------------ receipt-reuse validate


def _validate(tmp_path: Path, **overrides: str) -> tuple[int, dict[str, str], str]:
    env = {
        "IN_WORKFLOW": WORKFLOW_PATH,
        "IN_REPO": REPOSITORY,
        "IN_HEAD": HEAD,
        "IN_BASE": BASE,
        "IN_ISSUE": "",
        "IN_DEFAULT": "main",
        "IN_PATHS": "",
        "IN_SOURCE": "ref",
        "IN_REF": "4" * 40,
        "IN_PATH": "",
        "IN_PYTHON": "3.11",
        "IN_SIGSTORE": "4.5.0",
        "PR_BODY": "Closes #9\n<!-- NEXUS_CORE_ISSUE: 9 -->",
    }
    env.update(overrides)
    script = _run_block(_action_step(RECEIPT_REUSE, "Validate inputs")["text"])
    return _bash(script, env, tmp_path)


def test_reuse_equivalence_always_includes_config_and_workflow(tmp_path: Path) -> None:
    code, outputs, log = _validate(tmp_path)
    assert code == 0, log
    assert outputs["paths"].split() == sorted([".nexus-core/config.toml", WORKFLOW_PATH])
    assert outputs["trigger"] == DISPATCH_TRIGGER
    assert outputs["issue-number"] == "9"
    assert outputs["identity"] == (
        f"https://github.com/{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
    )
    code, outputs, log = _validate(
        tmp_path, IN_PATHS="  uv.lock\n\n.github/actions/issue-gate/action.yml\n.nexus-core/config.toml\n",
        IN_ISSUE="12",
    )
    assert code == 0, log
    assert set(outputs["paths"].split()) == {
        ".nexus-core/config.toml", WORKFLOW_PATH, "uv.lock", ".github/actions/issue-gate/action.yml",
    }
    assert outputs["issue-number"] == "12"


def test_reuse_unresolved_issue_binding_declines_instead_of_guessing(tmp_path: Path) -> None:
    for body in ("", "<!-- NEXUS_CORE_ISSUE: 1 --><!-- NEXUS_CORE_ISSUE: 2 -->"):
        code, outputs, log = _validate(tmp_path, PR_BODY=body)
        assert code == 0, log
        assert outputs["issue-number"] == ""


@pytest.mark.parametrize(
    "overrides",
    [
        {"IN_WORKFLOW": "../x.yml"},
        {"IN_WORKFLOW": ".github/actions/x/action.yml"},
        {"IN_PATHS": "../secret"},
        {"IN_PATHS": "/etc/passwd"},
        {"IN_PATHS": "a b"},
        {"IN_HEAD": "x"},
        {"IN_BASE": ""},
        {"IN_REPO": "owner"},
        {"IN_DEFAULT": "a..b"},
        {"IN_ISSUE": "0"},
        {"IN_SOURCE": "pip"},
    ],
)
def test_reuse_invalid_inputs_fail_closed(tmp_path: Path, overrides: dict[str, str]) -> None:
    code, outputs, _ = _validate(tmp_path, **overrides)
    assert code != 0
    assert "paths" not in outputs


# ------------------------------------------------------------------ prior-run lookup


@pytest.fixture
def api() -> Iterator[tuple[dict[str, Any], str]]:
    state: dict[str, Any] = {"runs": [], "artifacts": {}, "requests": [], "raw": None, "issue": None}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # pragma: no cover - silence
            return

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            url = urlsplit(self.path)
            state["requests"].append((url.path, {k: v[0] for k, v in parse_qs(url.query).items()}))
            runs = re.fullmatch(rf"/repos/{REPOSITORY}/actions/workflows/([^/]+)/runs", url.path)
            arts = re.fullmatch(rf"/repos/{REPOSITORY}/actions/runs/(\d+)/artifacts", url.path)
            issue = re.fullmatch(rf"/repos/{REPOSITORY}/issues/7", url.path)
            if issue and state["issue"] is not None:
                payload = state["issue"]
            elif runs:
                payload: Any = state["raw"] if state["raw"] is not None else {"total_count": len(state["runs"]), "workflow_runs": state["runs"]}
            elif arts:
                items = state["artifacts"].get(int(arts.group(1)), [])
                payload = {"total_count": len(items), "artifacts": items}
            else:
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _run(run_id: int, *, created: str, attempt: int = 1, **overrides: Any) -> dict[str, Any]:
    run = {
        "id": run_id,
        "run_attempt": attempt,
        "path": WORKFLOW_PATH,
        "head_branch": "main",
        "event": DISPATCH_TRIGGER,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": REPOSITORY},
        "head_sha": f"{run_id % 10}" * 40,
        "created_at": created,
    }
    run.update(overrides)
    return run


def _artifact(run_id: int, attempt: int, artifact_id: int, *, head: str = HEAD, expired: bool = False) -> dict[str, Any]:
    return {
        "id": artifact_id,
        "name": f"nexus-core-receipts-{head}-run{run_id}-attempt{attempt}",
        "expired": expired,
        "workflow_run": {"id": run_id},
    }


def _find(
    tmp_path: Path, api_url: str, issue: str = "7", pr_base_ref: str = "main"
) -> tuple[int, dict[str, str], str]:
    env = {
        "API_URL": api_url,
        "REPO": REPOSITORY,
        "WORKFLOW": WORKFLOW_PATH,
        "DEFAULT_BRANCH": "main",
        "PR_BASE_REF": pr_base_ref,
        "HEAD_SHA": HEAD,
        "ISSUE": issue,
        "TRIGGER": DISPATCH_TRIGGER,
        "GITHUB_TOKEN": "ghs_test",
    }
    script = _run_block(_action_step(RECEIPT_REUSE, "Find prior signed receipt for this head")["text"])
    return _bash(script, env, tmp_path)


def test_lookup_declines_pull_request_not_targeting_default_branch(tmp_path: Path, api) -> None:
    _, api_url = api
    for base_ref in ("release", ""):
        code, out, _ = _find(tmp_path, api_url, pr_base_ref=base_ref)
        assert code == 0
        assert out == {"ok": "false", "reason": "REUSE_BASE_NOT_DEFAULT_BRANCH"}


def test_lookup_takes_newest_qualifying_dispatch_run(tmp_path: Path, api) -> None:
    state, api_url = api
    state["runs"] = [
        # Newer runs that must be rejected, each for one reason.
        _run(9001, created="2026-10-13T09:00:00Z", path=".github/workflows/other.yml"),
        _run(9002, created="2026-10-13T09:00:00Z", head_branch="feature"),
        _run(9003, created="2026-10-13T09:00:00Z", event="workflow_dispatch"),
        _run(9004, created="2026-10-13T09:00:00Z", conclusion="failure"),
        _run(9005, created="2026-10-13T09:00:00Z", repository={"full_name": "evil/nexus-core"}),
        _run(9006, created="2026-10-13T09:00:00Z"),  # artifact for another head only
        _run(9007, created="2026-10-13T09:00:00Z", attempt=1),  # artifact from attempt 2 > run_attempt
        _run(9008, created="2026-10-13T09:00:00Z"),  # expired artifact
        _run(9009, created="2026-10-13T09:00:00Z", attempt=2),  # ambiguous: two artifacts
        _run(9010, created="2026-10-13 09:00:00"),  # creation time not a strict UTC stamp
        _run(8001, created="2026-10-13T08:00:00Z", attempt=2),  # the newest qualifying run
        _run(7001, created="2026-10-13T07:00:00Z"),
    ]
    for run_id in (9001, 9002, 9003, 9004, 9005, 9010, 7001):
        state["artifacts"][run_id] = [_artifact(run_id, 1, run_id * 10)]
    state["artifacts"][9006] = [_artifact(9006, 1, 90060, head="5" * 40)]
    state["artifacts"][9007] = [_artifact(9007, 2, 90070)]
    state["artifacts"][9008] = [_artifact(9008, 1, 90080, expired=True)]
    state["artifacts"][9009] = [_artifact(9009, 1, 90090), _artifact(9009, 2, 90091)]
    state["artifacts"][8001] = [_artifact(8001, 2, 80010), _artifact(8001, 1, 80011, head="5" * 40)]

    code, outputs, log = _find(tmp_path, api_url)
    assert code == 0, log
    assert outputs == {
        "ok": "true",
        "run-id": "8001",
        "artifact-id": "80010",
        "artifact-name": f"nexus-core-receipts-{HEAD}-run8001-attempt2",
        "config-commit": "1" * 40,
        "run-created-at": "2026-10-13T08:00:00Z",
    }
    path, query = state["requests"][0]
    assert path.endswith("/actions/workflows/nexus-core-issue-completion.yml/runs")
    assert query["event"] == DISPATCH_TRIGGER and query["branch"] == "main"
    assert query["status"] == "success"


def test_lookup_without_receipt_declines(tmp_path: Path, api) -> None:
    state, api_url = api
    state["runs"] = [_run(9001, created="2026-10-13T09:00:00Z")]
    code, outputs, log = _find(tmp_path, api_url)
    assert code == 0, log
    assert outputs == {"ok": "false", "reason": "NO_PRIOR_RECEIPT"}


@pytest.mark.parametrize("raw", [[], {"workflow_runs": "x"}, {"workflow_runs": None}])
def test_lookup_malformed_api_declines(tmp_path: Path, api, raw: Any) -> None:
    state, api_url = api
    state["raw"] = raw
    code, outputs, _ = _find(tmp_path, api_url)
    assert code == 0
    assert outputs == {"ok": "false", "reason": "REUSE_PRIOR_RUN_LOOKUP_FAILED"}


def test_lookup_unreachable_api_and_missing_issue_decline(tmp_path: Path) -> None:
    code, outputs, _ = _find(tmp_path, "http://127.0.0.1:9")
    assert code == 0 and outputs == {"ok": "false", "reason": "REUSE_PRIOR_RUN_LOOKUP_FAILED"}
    code, outputs, _ = _find(tmp_path, "http://127.0.0.1:9", issue="")
    assert code == 0 and outputs == {"ok": "false", "reason": "REUSE_ISSUE_BINDING_UNRESOLVED"}


# ------------------------------------------------------------------ Issue open and unchanged

PRECHECK_CREATED = "2026-10-13T08:00:00Z"


def _issue_check(tmp_path: Path, api_url: str, created: str = PRECHECK_CREATED) -> tuple[int, dict[str, str], str]:
    env = {
        "API_URL": api_url,
        "REPO": REPOSITORY,
        "ISSUE": "7",
        "RUN_CREATED_AT": created,
        "GITHUB_TOKEN": "ghs_test",
    }
    script = _run_block(_action_step(RECEIPT_REUSE, "Check Issue is still open")["text"])
    return _bash(script, env, tmp_path)


@pytest.mark.parametrize("updated", ["2026-10-13T07:59:59Z", PRECHECK_CREATED])
def test_issue_unchanged_since_precheck_allows_reuse(tmp_path: Path, api, updated: str) -> None:
    state, api_url = api
    state["issue"] = {"number": 7, "state": "open", "updated_at": updated}
    code, outputs, log = _issue_check(tmp_path, api_url)
    assert code == 0, log
    assert outputs == {"ok": "true"}


@pytest.mark.parametrize(
    ("issue", "created", "reason"),
    [
        # Body/title/marker edit or new comment after the precheck run was created.
        ({"state": "open", "updated_at": "2026-10-13T08:00:01Z"}, PRECHECK_CREATED,
         "REUSE_ISSUE_CHANGED_AFTER_PRECHECK"),
        ({"state": "open"}, PRECHECK_CREATED, "REUSE_ISSUE_CHANGED_AFTER_PRECHECK"),
        ({"state": "open", "updated_at": None}, PRECHECK_CREATED, "REUSE_ISSUE_CHANGED_AFTER_PRECHECK"),
        ({"state": "open", "updated_at": "2026-10-13T07:00:00+00:00"}, PRECHECK_CREATED,
         "REUSE_ISSUE_CHANGED_AFTER_PRECHECK"),
        ({"state": "open", "updated_at": "2026-10-13T07:00:00Z"}, "", "REUSE_ISSUE_CHANGED_AFTER_PRECHECK"),
        ({"state": "open", "updated_at": "2026-10-13T07:00:00Z"}, "yesterday",
         "REUSE_ISSUE_CHANGED_AFTER_PRECHECK"),
        ({"state": "closed", "updated_at": "2026-10-13T07:00:00Z"}, PRECHECK_CREATED, "REUSE_ISSUE_NOT_OPEN"),
        ({"state": "open", "updated_at": "2026-10-13T07:00:00Z", "pull_request": {}}, PRECHECK_CREATED,
         "REUSE_ISSUE_NOT_OPEN"),
    ],
)
def test_issue_changed_or_not_open_declines(
    tmp_path: Path, api, issue: dict[str, Any], created: str, reason: str
) -> None:
    state, api_url = api
    state["issue"] = {"number": 7, **issue}
    code, outputs, log = _issue_check(tmp_path, api_url, created)
    assert code == 0, log
    assert outputs == {"ok": "false", "reason": reason}


def test_issue_lookup_failure_declines(tmp_path: Path) -> None:
    code, outputs, _ = _issue_check(tmp_path, "http://127.0.0.1:9")
    assert code == 0
    assert outputs == {"ok": "false", "reason": "REUSE_ISSUE_LOOKUP_FAILED"}


def test_negative_control_dropped_issue_freshness_check_is_detected(tmp_path: Path, api) -> None:
    state, api_url = api
    state["issue"] = {"number": 7, "state": "open", "updated_at": "2026-10-13T09:00:00Z"}
    text = _read(RECEIPT_REUSE)
    needle = "updated is None or created is None or updated > created"
    mutated = text.replace(needle, "False", 1)
    assert mutated != text and receipt_reuse_violations(mutated)
    script = _run_block(_action_step(RECEIPT_REUSE, "Check Issue is still open", mutated)["text"])
    env = {"API_URL": api_url, "REPO": REPOSITORY, "ISSUE": "7",
           "RUN_CREATED_AT": PRECHECK_CREATED, "GITHUB_TOKEN": "ghs_test"}
    assert _bash(script, env, tmp_path)[1] == {"ok": "true"}  # the mutation would reuse ...
    assert _issue_check(tmp_path, api_url)[1]["reason"] == "REUSE_ISSUE_CHANGED_AFTER_PRECHECK"  # ... the real step declines


# ------------------------------------------------------------------ lineage and equivalence


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args], env=env, check=True, capture_output=True, text=True
    ).stdout.strip()


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def origin(tmp_path: Path) -> dict[str, Any]:
    work = tmp_path / "src"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    files = {".nexus-core/config.toml": "version = 2\n", WORKFLOW_PATH: "on: {}\n", "a.txt": "1\n"}
    r = _commit(work, files, "R")
    base_same = _commit(work, {"a.txt": "2\n"}, "base, trust files unchanged")
    base_config = _commit(work, {".nexus-core/config.toml": "version = 3\n"}, "config changed")
    _git(work, "checkout", "-q", "-b", "wf", base_same)
    base_workflow = _commit(work, {WORKFLOW_PATH: "on: {push: {}}\n"}, "workflow changed")
    _git(work, "checkout", "-q", "-b", "extra", base_same)
    _git(work, "rm", "-q", "a.txt")
    _git(work, "commit", "-q", "-m", "a.txt removed")
    base_missing = _git(work, "rev-parse", "HEAD")
    _git(work, "checkout", "-q", "-b", "head", r)
    head = _commit(work, {"feature.txt": "x\n"}, "candidate head")
    server = tmp_path / "srv"
    (server / "o").mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "-q", "--bare", str(work), str(server / "o" / "r.git")],
        check=True, capture_output=True,
    )
    _git(server / "o" / "r.git", "config", "uploadpack.allowAnySHA1InWant", "true")
    return {
        "server": f"file://{server}", "R": r, "base_same": base_same, "base_config": base_config,
        "base_workflow": base_workflow, "base_missing": base_missing, "head": head,
        "head_tree": _git(work, "rev-parse", f"{head}^{{tree}}"),
    }


def _lineage(tmp_path: Path, origin: dict[str, Any], *, config: str, base: str,
             paths: str = f".nexus-core/config.toml {WORKFLOW_PATH}") -> tuple[int, dict[str, str], str]:
    env = {
        "REPO": "o/r",
        "SERVER": origin["server"],
        "CONFIG_COMMIT": config,
        "BASE_SHA": base,
        "HEAD_SHA": origin["head"],
        "PATHS": paths,
        "WORK": str(tmp_path / "lineage-git"),
        "FETCH_TOKEN": "ghs_test",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ALLOW_PROTOCOL": "file",
    }
    script = _run_block(_action_step(RECEIPT_REUSE, "Check config lineage and trust-file equivalence")["text"])
    return _bash(script, env, tmp_path)


def test_lineage_accepts_ancestor_with_identical_trust_files(tmp_path: Path, origin) -> None:
    code, outputs, log = _lineage(tmp_path, origin, config=origin["R"], base=origin["base_same"])
    assert code == 0, log
    assert outputs == {"tree": origin["head_tree"], "ok": "true"}
    # Same commit as base is trivially equivalent.
    code, outputs, log = _lineage(tmp_path, origin, config=origin["R"], base=origin["R"])
    assert outputs.get("ok") == "true", log


@pytest.mark.parametrize(
    ("config", "base", "paths", "reason"),
    [
        ("base_same", "R", None, "REUSE_CONFIG_COMMIT_NOT_ANCESTOR"),
        ("R", "base_config", None, "REUSE_EQUIVALENCE_PATH_CHANGED"),
        ("R", "base_workflow", None, "REUSE_EQUIVALENCE_PATH_CHANGED"),
        ("R", "base_missing", f".nexus-core/config.toml {WORKFLOW_PATH} a.txt", "REUSE_EQUIVALENCE_PATH_MISSING"),
        ("R", "base_same", f".nexus-core/config.toml {WORKFLOW_PATH} absent.txt", "REUSE_EQUIVALENCE_PATH_MISSING"),
        ("R", "base_same", f".nexus-core/config.toml {WORKFLOW_PATH} a.txt", "REUSE_EQUIVALENCE_PATH_CHANGED"),
        ("R", "base_same", ".nexus-core/config.toml", "REUSE_EQUIVALENCE_PATHS_MISSING"),
    ],
)
def test_lineage_declines_unproven_equivalence(
    tmp_path: Path, origin, config: str, base: str, paths: str | None, reason: str
) -> None:
    kwargs = {} if paths is None else {"paths": paths}
    code, outputs, log = _lineage(tmp_path, origin, config=origin[config], base=origin[base], **kwargs)
    assert code == 0, log
    assert outputs == {"ok": "false", "reason": reason}, log


def test_lineage_unknown_commit_declines(tmp_path: Path, origin) -> None:
    code, outputs, _ = _lineage(tmp_path, origin, config="9" * 40, base=origin["base_same"])
    assert code == 0
    assert outputs == {"ok": "false", "reason": "REUSE_GIT_FETCH_FAILED"}
    code, outputs, _ = _lineage(tmp_path, origin, config="not-a-sha", base=origin["base_same"])
    assert outputs == {"ok": "false", "reason": "REUSE_CONFIG_COMMIT_INVALID"}


# ------------------------------------------------------------------ decision steps

STEP_KEYS = ("FIND", "LINEAGE", "ISSUE", "DOWNLOAD", "LOCATE", "INSTALL", "SIGNATURE", "CHECK")


def _all_passed() -> dict[str, str]:
    env = {"RUN_ID": "8001", "RECEIPT_SHA256": "a" * 64}
    for key in STEP_KEYS:
        env[f"{key}_OUTCOME"] = "success"
        if key != "DOWNLOAD":
            env[f"{key}_OK"] = "true"
            env[f"{key}_REASON"] = ""
    return env


def _decide(tmp_path: Path, env: dict[str, str], text: str | None = None) -> dict[str, str]:
    script = _run_block(_action_step(RECEIPT_REUSE, "Decide reuse", text)["text"])
    code, outputs, log = _bash(script, env, tmp_path)
    assert code == 0, log
    return outputs


def test_decide_reuses_only_when_every_check_passed(tmp_path: Path) -> None:
    outputs = _decide(tmp_path, _all_passed())
    assert outputs == {
        "reason": "REUSED", "producer-run-id": "8001", "receipt-sha256": "a" * 64, "reused": "true",
    }


def _failure_cases() -> list[tuple[str, dict[str, str]]]:
    cases: list[tuple[str, dict[str, str]]] = []
    for key in STEP_KEYS:
        for outcome in ("failure", "skipped", "cancelled", ""):
            cases.append((f"{key}-{outcome or 'missing'}", {f"{key}_OUTCOME": outcome}))
        if key != "DOWNLOAD":
            for ok in ("false", "", "TRUE", "true\n"):
                cases.append((f"{key}-ok-{ok!r}", {f"{key}_OK": ok}))
            # A step that errored after writing ok=true must still decline.
            cases.append((f"{key}-errored-after-ok", {f"{key}_OUTCOME": "failure"}))
    cases += [
        ("no-run-id", {"RUN_ID": ""}),
        ("bad-run-id", {"RUN_ID": "0"}),
        ("no-sha", {"RECEIPT_SHA256": ""}),
        ("bad-sha", {"RECEIPT_SHA256": "A" * 64}),
    ]
    return cases


@pytest.mark.parametrize(("case", "override"), _failure_cases(), ids=[c[0] for c in _failure_cases()])
def test_decide_never_reuses_after_any_failure(tmp_path: Path, case: str, override: dict[str, str]) -> None:
    env = {**_all_passed(), **override}
    outputs = _decide(tmp_path, env)
    assert outputs["reused"] == "false", case
    assert outputs["reason"] not in ("", "REUSED"), case
    assert outputs["producer-run-id"] == "" and outputs["receipt-sha256"] == ""


def test_decide_reports_the_first_failing_reason(tmp_path: Path) -> None:
    env = {**_all_passed(), "FIND_OK": "false", "FIND_REASON": "NO_PRIOR_RECEIPT",
           "LINEAGE_OUTCOME": "skipped", "LINEAGE_OK": ""}
    assert _decide(tmp_path, env)["reason"] == "NO_PRIOR_RECEIPT"
    env = {**_all_passed(), "SIGNATURE_OK": "false", "SIGNATURE_REASON": "REUSE_SIGNATURE_INVALID"}
    assert _decide(tmp_path, env)["reason"] == "REUSE_SIGNATURE_INVALID"
    env = {**_all_passed(), "CHECK_OUTCOME": "failure", "CHECK_OK": ""}
    assert _decide(tmp_path, env)["reason"] == "REUSE_RECEIPT_CHECK_ERROR"


def test_negative_control_dropped_decision_gate_is_detected(tmp_path: Path) -> None:
    text = _read(RECEIPT_REUSE)
    gate = '        gate "$SIGNATURE_OUTCOME" "$SIGNATURE_OK" "$SIGNATURE_REASON" REUSE_SIGNATURE_ERROR\n'
    assert gate in text
    mutated = text.replace(gate, "", 1)
    env = {**_all_passed(), "SIGNATURE_OUTCOME": "failure", "SIGNATURE_OK": ""}
    assert _decide(tmp_path, env, mutated)["reused"] == "true"  # the mutation would pass ...
    assert _decide(tmp_path, env)["reused"] == "false"  # ... the real step declines


# ------------------------------------------------------------------ consumer workflow decision (example layout)


def _verify_decide(tmp_path: Path, env: dict[str, str], text: str | None = None) -> int:
    verify = _jobs(text if text is not None else _read(CONSUMER_EXAMPLE))["verify"]
    script = _run_block(_workflow_step(verify, "Decide required check"))
    code, _, _ = _bash(script, {"VERIFY_RESULT": "", **env}, tmp_path)
    return code


PASSING = [
    # Pull request, reused.
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "success", "REUSED": "true",
     "VERIFY_OUTCOME": "skipped", "VERIFIED": ""},
    # Pull request, full run verified.
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "success", "REUSED": "false",
     "VERIFY_OUTCOME": "success", "VERIFIED": "true"},
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "failure", "REUSED": "",
     "VERIFY_OUTCOME": "success", "VERIFIED": "true"},
    # Dispatch, verified.
    {"EVENT_NAME": DISPATCH_TRIGGER, "REUSE_RESULT": "skipped", "REUSED": "",
     "VERIFY_OUTCOME": "success", "VERIFIED": "true"},
    # Pull request merged at this head before the gate ran: receipt-verify confirmed
    # the neutral #250 skip (verified stays 'false').
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "success", "REUSED": "false",
     "VERIFY_OUTCOME": "success", "VERIFIED": "false", "VERIFY_RESULT": "PR_ALREADY_CLOSED_SKIPPED"},
]
FAILING = [
    # Reuse errored and the run was skipped / failed: receipt-verify fails or is absent.
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "failure", "REUSED": "",
     "VERIFY_OUTCOME": "failure", "VERIFIED": "false"},
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "failure", "REUSED": "",
     "VERIFY_OUTCOME": "skipped", "VERIFIED": ""},
    # Reuse output 'true' from a job that did not succeed is not trusted.
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "failure", "REUSED": "true",
     "VERIFY_OUTCOME": "skipped", "VERIFIED": ""},
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "cancelled", "REUSED": "true",
     "VERIFY_OUTCOME": "skipped", "VERIFIED": ""},
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "success", "REUSED": "false",
     "VERIFY_OUTCOME": "skipped", "VERIFIED": ""},
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "skipped", "REUSED": "",
     "VERIFY_OUTCOME": "skipped", "VERIFIED": ""},
    # Verify step outputs without a successful outcome are not trusted.
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "success", "REUSED": "false",
     "VERIFY_OUTCOME": "failure", "VERIFIED": "true"},
    # Dispatch never passes on reuse.
    {"EVENT_NAME": DISPATCH_TRIGGER, "REUSE_RESULT": "success", "REUSED": "true",
     "VERIFY_OUTCOME": "skipped", "VERIFIED": ""},
    {"EVENT_NAME": DISPATCH_TRIGGER, "REUSE_RESULT": "skipped", "REUSED": "",
     "VERIFY_OUTCOME": "failure", "VERIFIED": "false"},
    # A skip never passes on dispatch, and never without a successful receipt-verify.
    {"EVENT_NAME": DISPATCH_TRIGGER, "REUSE_RESULT": "skipped", "REUSED": "",
     "VERIFY_OUTCOME": "success", "VERIFIED": "false", "VERIFY_RESULT": "PR_ALREADY_CLOSED_SKIPPED"},
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "success", "REUSED": "false",
     "VERIFY_OUTCOME": "failure", "VERIFIED": "false", "VERIFY_RESULT": "PR_ALREADY_CLOSED_SKIPPED"},
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "success", "REUSED": "false",
     "VERIFY_OUTCOME": "skipped", "VERIFIED": "", "VERIFY_RESULT": "PR_ALREADY_CLOSED_SKIPPED"},
    {"EVENT_NAME": "pull_request_target", "REUSE_RESULT": "success", "REUSED": "false",
     "VERIFY_OUTCOME": "success", "VERIFIED": "false", "VERIFY_RESULT": "VERIFIED"},
]


@pytest.mark.parametrize("env", PASSING)
def test_consumer_verify_passes_on_reuse_or_verified_receipt(tmp_path: Path, env: dict[str, str]) -> None:
    assert _verify_decide(tmp_path, env) == 0


@pytest.mark.parametrize("env", FAILING)
def test_consumer_verify_fails_closed(tmp_path: Path, env: dict[str, str]) -> None:
    assert _verify_decide(tmp_path, env) != 0


def test_negative_control_consumer_decision_ignoring_reuse_result_is_detected(tmp_path: Path) -> None:
    text = _read(CONSUMER_EXAMPLE)
    needle = '[ "$REUSE_RESULT" = "success" ] && '
    assert needle in text
    mutated = text.replace(needle, "", 1)
    env = FAILING[2]
    assert _verify_decide(tmp_path, env, mutated) == 0
    assert _verify_decide(tmp_path, env) != 0


def test_negative_control_consumer_skip_accepted_on_dispatch_is_detected(tmp_path: Path) -> None:
    text = _read(CONSUMER_EXAMPLE)
    needle = '[ "$EVENT_NAME" = "pull_request_target" ] && [ "$VERIFY_OUTCOME" = "success" ] && [ "$VERIFY_RESULT"'
    assert needle in text
    mutated = text.replace(needle, needle.replace('[ "$EVENT_NAME" = "pull_request_target" ] && ', ""), 1)
    env = {"EVENT_NAME": DISPATCH_TRIGGER, "REUSE_RESULT": "skipped", "REUSED": "",
           "VERIFY_OUTCOME": "success", "VERIFIED": "false", "VERIFY_RESULT": "PR_ALREADY_CLOSED_SKIPPED"}
    assert _verify_decide(tmp_path, env, mutated) == 0
    assert _verify_decide(tmp_path, env) != 0


def test_consumer_example_passes_the_gate_outcome_to_receipt_verify() -> None:
    jobs = _jobs(_read(CONSUMER_EXAMPLE))
    assert "      outcome: ${{ steps.gate.outputs.outcome }}\n" in jobs["run"]
    step = _workflow_step(jobs["verify"], "Verify signed receipt")
    assert "          gate-outcome: ${{ needs.run.outputs.outcome }}\n" in step
    assert "      pull-requests: read" in jobs["verify"]
