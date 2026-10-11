from __future__ import annotations

import re
from pathlib import Path

SETUP_UV_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*astral-sh/setup-uv@")
VERSION_PATTERN = re.compile(r"^\s*version:\s*[\"']?([^\"'\s#]+)[\"']?")
EXACT_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


def _setup_uv_versions(content: str) -> list[tuple[int, str | None]]:
    """Return (line number, pinned uv version) for each setup-uv step.

    The version is the first ``version:`` key that appears after the ``uses:``
    line and before the next step, or None if the step does not set one.
    """
    lines = content.splitlines()
    found: list[tuple[int, str | None]] = []
    for idx, line in enumerate(lines):
        if not SETUP_UV_PATTERN.match(line):
            continue
        version: str | None = None
        for follow in lines[idx + 1 :]:
            if re.match(r"^\s*-\s", follow):
                break
            match = VERSION_PATTERN.match(follow)
            if match:
                version = match.group(1)
                break
        found.append((idx + 1, version))
    return found


def _workflow_versions(repo_root: Path) -> dict[str, list[tuple[int, str | None]]]:
    workflows_dir = repo_root / ".github" / "workflows"
    result: dict[str, list[tuple[int, str | None]]] = {}
    for wf in sorted(workflows_dir.glob("*.yml")):
        rel = str(wf.relative_to(repo_root))
        found = _setup_uv_versions(wf.read_text(encoding="utf-8"))
        if found:
            result[rel] = found
    return result


def test_every_setup_uv_step_pins_an_exact_uv_version():
    repo_root = Path(__file__).resolve().parent.parent.parent
    versions = _workflow_versions(repo_root)
    assert versions, "expected at least one setup-uv step under .github/workflows"

    problems = [
        f"{rel}:{lineno}: setup-uv version {version!r} is not an exact x.y.z pin"
        for rel, found in versions.items()
        for lineno, version in found
        if version is None or not EXACT_VERSION_PATTERN.match(version)
    ]
    assert not problems, "\n".join(problems)


def test_setup_uv_version_matches_publish_workflow():
    repo_root = Path(__file__).resolve().parent.parent.parent
    versions = _workflow_versions(repo_root)
    publish_found = versions.get(".github/workflows/publish.yml")
    assert publish_found, "publish.yml must declare the reference setup-uv version"
    reference = publish_found[0][1]
    assert reference and EXACT_VERSION_PATTERN.match(reference)

    mismatches = [
        f"{rel}:{lineno}: setup-uv version {version!r} != publish.yml {reference!r}"
        for rel, found in versions.items()
        for lineno, version in found
        if version != reference
    ]
    assert not mismatches, "\n".join(mismatches)


def test_negative_control_latest_is_rejected():
    sample = (
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: astral-sh/setup-uv@d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86  # v5.4.1\n"
        "        with:\n"
        "          version: \"latest\"\n"
        "      - name: Next\n"
    )
    assert _setup_uv_versions(sample) == [(4, "latest")]


def test_negative_control_missing_version_is_reported_as_none():
    sample = (
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: astral-sh/setup-uv@d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86\n"
        "      - name: Next\n"
        "        run: echo hi\n"
    )
    assert _setup_uv_versions(sample) == [(4, None)]
