from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

HEX_40_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
DOCKER_DIGEST_PATTERN = re.compile(r"^docker://.+@sha256:[0-9a-fA-F]{64}$")
USES_LINE_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)


@dataclass(frozen=True)
class WorkflowPinViolation:
    workflow_path: str
    lineno: int
    raw_action_ref: str
    action_name: str
    action_ref: str
    message: str

    def format(self) -> str:
        return f"{self.workflow_path}:{self.lineno}: {self.message}"


def check_workflow_content_for_unpinned_actions(
    content: str, workflow_rel_path: str
) -> list[WorkflowPinViolation]:
    violations: list[WorkflowPinViolation] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        match = USES_LINE_PATTERN.match(line)
        if not match:
            continue

        raw_target = match.group(1).strip().strip("\"'")

        if raw_target.startswith("./"):
            continue

        if raw_target.startswith("docker://"):
            if not DOCKER_DIGEST_PATTERN.match(raw_target):
                violations.append(
                    WorkflowPinViolation(
                        workflow_path=workflow_rel_path,
                        lineno=idx,
                        raw_action_ref=raw_target,
                        action_name=raw_target,
                        action_ref="",
                        message=(
                            f"Docker action '{raw_target}' is not pinned to an immutable "
                            "sha256 image digest."
                        ),
                    )
                )
            continue

        if "@" not in raw_target:
            violations.append(
                WorkflowPinViolation(
                    workflow_path=workflow_rel_path,
                    lineno=idx,
                    raw_action_ref=raw_target,
                    action_name=raw_target,
                    action_ref="",
                    message=f"External action '{raw_target}' is missing an immutable ref (@<commit-sha>)",
                )
            )
            continue

        action_name, _, ref = raw_target.partition("@")
        if not HEX_40_PATTERN.match(ref):
            violations.append(
                WorkflowPinViolation(
                    workflow_path=workflow_rel_path,
                    lineno=idx,
                    raw_action_ref=raw_target,
                    action_name=action_name,
                    action_ref=ref,
                    message=(
                        f"External action '{action_name}' uses movable ref '@{ref}'. "
                        "Supply chain policy requires a full 40-character commit SHA."
                    ),
                )
            )

    return violations


def test_production_github_workflows_are_pinned_to_immutable_shas():
    repo_root = Path(__file__).resolve().parent.parent.parent
    workflows_dir = repo_root / ".github" / "workflows"
    assert workflows_dir.is_dir(), f"Workflows directory not found at {workflows_dir}"

    workflow_files = sorted(list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml")))
    assert workflow_files, "No workflow files discovered in .github/workflows"

    all_violations: list[WorkflowPinViolation] = []
    for wf in workflow_files:
        content = wf.read_text(encoding="utf-8")
        rel_path = str(wf.relative_to(repo_root))
        violations = check_workflow_content_for_unpinned_actions(content, rel_path)
        all_violations.extend(violations)

    assert not all_violations, (
        "Discovered unpinned movable GitHub Action dependencies in workflows:\n"
        + "\n".join(f"  - {v.format()}" for v in all_violations)
    )


def test_negative_control_movable_tag_rejected():
    sample = (
        "name: CI\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    violations = check_workflow_content_for_unpinned_actions(
        sample, ".github/workflows/fake_ci.yml"
    )
    assert len(violations) == 1
    v = violations[0]
    assert v.lineno == 5
    assert v.action_name == "actions/checkout"
    assert v.action_ref == "v4"
    assert "uses movable ref '@v4'" in v.message


def test_negative_control_movable_branch_rejected():
    sample = (
        "name: Build\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: astral-sh/setup-uv@main\n"
    )
    violations = check_workflow_content_for_unpinned_actions(
        sample, ".github/workflows/build.yml"
    )
    assert len(violations) == 1
    v = violations[0]
    assert v.lineno == 5
    assert v.action_ref == "main"
    assert "uses movable ref '@main'" in v.message


def test_negative_control_mutable_docker_tag_rejected():
    sample = (
        "name: Docker\n"
        "jobs:\n"
        "  run:\n"
        "    steps:\n"
        "      - uses: docker://alpine:latest\n"
    )
    violations = check_workflow_content_for_unpinned_actions(
        sample, ".github/workflows/docker.yml"
    )
    assert len(violations) == 1
    assert "not pinned to an immutable sha256 image digest" in violations[0].message


def test_local_actions_and_immutable_refs_accepted():
    docker_digest = "a" * 64
    sample = (
        "name: Valid\n"
        "jobs:\n"
        "  check:\n"
        "    steps:\n"
        "      - uses: ./.github/actions/local-setup\n"
        "      - uses: \"actions/checkout@11d5960a326750d5838078e36cf38b85af677262\"\n"
        f"      - uses: docker://alpine@sha256:{docker_digest}\n"
    )
    violations = check_workflow_content_for_unpinned_actions(
        sample, ".github/workflows/valid.yml"
    )
    assert not violations
