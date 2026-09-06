from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Iterator

import pytest

from product.benchmark import _digest
from product.benchmark.tg7_shadow import validate_selection


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        stderr=subprocess.DEVNULL,
        text=True,
    ).strip()


def _selection(repo: Path) -> dict[str, object]:
    body: dict[str, object] = {
        "schema": "nexus.core-v1.tg7-selection.v1",
        "canonical_url": "https://github.com/bottlepy/bottle",
        "owner": "bottlepy",
        "name": "bottle",
        "commit": _git(repo, "rev-parse", "HEAD"),
        "tree": _git(repo, "rev-parse", "HEAD^{tree}"),
        "snapshot_path": str(repo),
        "snapshot_tree_hash": "sha256:" + "1" * 64,
        "observed_at": "2026-09-06T01:00:00Z",
        "license_spdx": "MIT",
        "license_evidence_hash": "sha256:" + "2" * 64,
        "privacy_class": "PUBLIC_OPEN_SOURCE",
        "read_only_evidence_hash": "sha256:" + "3" * 64,
        "task_set_id": "tg7-shadow-bottle-v1",
        "not_nexus_reason": "independent public repository",
    }
    return {**body, "selection_hash": _digest(body)}


@pytest.fixture
def readonly_repo(tmp_path: Path) -> Iterator[tuple[Path, Path, dict[str, object]]]:
    repo = tmp_path / "external"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "tg7@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "TG7 Test"], check=True)

    bottle = repo / "bottle.py"
    bottle.write_text("print('bottle')\n", encoding="utf-8")
    bottle.chmod(0o755)
    subprocess.run(["git", "-C", str(repo), "add", "bottle.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "fixture"], check=True)

    selection = _selection(repo)
    bottle.chmod(0o444)
    repo.chmod(0o555)
    try:
        yield repo, bottle, selection
    finally:
        repo.chmod(0o755)
        if bottle.exists():
            bottle.chmod(0o644)
        for path in repo.rglob("*"):
            try:
                path.chmod(path.stat().st_mode | 0o700)
            except OSError:
                pass


def test_readonly_mode_only_materialization_remains_valid(readonly_repo) -> None:
    repo, bottle, selection = readonly_repo
    head_before = _git(repo, "rev-parse", "HEAD")
    bytes_before = bottle.read_bytes()

    assert validate_selection(selection, repo_path=repo) == []

    assert _git(repo, "rev-parse", "HEAD") == head_before
    assert bottle.read_bytes() == bytes_before
    assert not (repo.stat().st_mode & 0o222)
    assert not (bottle.stat().st_mode & 0o222)


def test_tracked_content_tamper_is_rejected(readonly_repo) -> None:
    repo, bottle, selection = readonly_repo
    bottle.chmod(0o644)
    bottle.write_text("print('tampered')\n", encoding="utf-8")
    bottle.chmod(0o444)

    errors = validate_selection(selection, repo_path=repo)

    assert any("worktree content/index/untracked state" in error for error in errors)


def test_tracked_deletion_is_rejected(readonly_repo) -> None:
    repo, bottle, selection = readonly_repo
    repo.chmod(0o755)
    bottle.unlink()
    repo.chmod(0o555)

    errors = validate_selection(selection, repo_path=repo)

    assert any("worktree content/index/untracked state" in error for error in errors)


def test_untracked_file_is_rejected(readonly_repo) -> None:
    repo, _bottle, selection = readonly_repo
    repo.chmod(0o755)
    rogue = repo / "rogue.txt"
    rogue.write_text("unexpected\n", encoding="utf-8")
    rogue.chmod(0o444)
    repo.chmod(0o555)

    errors = validate_selection(selection, repo_path=repo)

    assert any("worktree content/index/untracked state" in error for error in errors)


def test_existing_commit_tree_binding_still_fails_closed(readonly_repo) -> None:
    repo, _bottle, selection = readonly_repo
    bad = dict(selection)
    bad["commit"] = "0" * 40
    body = {key: value for key, value in bad.items() if key != "selection_hash"}
    bad["selection_hash"] = _digest(body)

    errors = validate_selection(bad, repo_path=repo)

    assert "repository HEAD commit does not match selection" in errors


def test_validator_does_not_mutate_git_evidence(readonly_repo) -> None:
    repo, bottle, selection = readonly_repo
    before_head = _git(repo, "rev-parse", "HEAD")
    before_tree = _git(repo, "rev-parse", "HEAD^{tree}")
    before_index = (repo / ".git" / "index").read_bytes()
    before_file = bottle.read_bytes()
    before_mode = os.stat(bottle).st_mode

    assert validate_selection(selection, repo_path=repo) == []

    assert _git(repo, "rev-parse", "HEAD") == before_head
    assert _git(repo, "rev-parse", "HEAD^{tree}") == before_tree
    assert (repo / ".git" / "index").read_bytes() == before_index
    assert bottle.read_bytes() == before_file
    assert os.stat(bottle).st_mode == before_mode
