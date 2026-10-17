"""Guard the required GitHub checks documented for nexus-core main."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Live ruleset 22367671 since 2026-10-16 (Nexus-new#2385); updated with #288.
REQUIRED_CONTEXTS = (
    "test",
    "Review record present (advisory)",
    "Bindings preflight (default branch)",
)


def _documented_contexts(text: str, heading: str) -> tuple[str, ...]:
    assert text.count(heading) == 1, f"missing or duplicate heading: {heading}"
    section = text.split(heading, 1)[1].split("\n## ", 1)[0]
    return tuple(re.findall(r"(?m)^[ \t]*-[ \t]+`([^`]+)`[ \t]+—[ \t]+", section))


def test_required_status_check_documentation_agrees() -> None:
    governance = (ROOT / "docs/governance/CANONICAL_REPOSITORY_PROTECTION.md").read_text(
        encoding="utf-8"
    )
    english = (ROOT / "README.md").read_text(encoding="utf-8")
    traditional_chinese = (ROOT / "README.zh-TW.md").read_text(encoding="utf-8")

    assert _documented_contexts(governance, "## Repository Required Checks") == REQUIRED_CONTEXTS
    assert _documented_contexts(english, "### 5. Require the checks") == REQUIRED_CONTEXTS
    assert _documented_contexts(traditional_chinese, "### 5. 設為必要檢查") == REQUIRED_CONTEXTS

    assert tuple(re.findall(r'\{"context": "([^"]+)"\}', governance)) == REQUIRED_CONTEXTS


def test_documented_contexts_have_corresponding_workflow_jobs() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    core = (ROOT / ".github/workflows/nexus-core-issue-completion.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^  test:\s*$", ci)
    assert re.search(r"(?m)^    name: Nexus Core issue completion\s*$", core)
    sibling = (ROOT / ".github/workflows/sibling-merge-checks.yml").read_text(encoding="utf-8")
    for context in REQUIRED_CONTEXTS[1:]:
        assert f'"{context}"' in sibling, context
