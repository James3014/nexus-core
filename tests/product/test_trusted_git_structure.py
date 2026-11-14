from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from product.clients import local_golden_path as lgp
from product.clients.trusted_git import git_subprocess_env


def _init_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "-C", str(path), "init"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "test@example.test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(path), "config", "user.name", "Test"], check=True
    )
    (path / "file.txt").write_text("ok\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "file.txt"], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-m", "init"], check=True, capture_output=True)
    return path


def _run(repo: Path) -> subprocess.CompletedProcess[str]:
    return lgp._run_git(repo, "rev-parse", "--show-toplevel")


@pytest.mark.parametrize(
    "metadata", ["config", "HEAD", "packed-refs", "info/exclude", "objects"]
)
def test_git_metadata_symlink_fails_closed(tmp_path: Path, metadata: str) -> None:
    repo = _init_repo(tmp_path / "repo")
    git_dir = repo / ".git"
    target = tmp_path / f"outside-{metadata.replace('/', '-') }"
    source = git_dir / metadata
    source.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        target.mkdir()
        source.rename(tmp_path / "original-metadata")
    else:
        target.write_bytes(
            source.read_bytes() if source.exists() else b"ref: refs/heads/master\n"
        )
        source.unlink(missing_ok=True)
    source.symlink_to(target)

    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


def test_git_config_hardlink_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    config = repo / ".git" / "config"
    outside = tmp_path / "config-copy"
    os.link(config, outside)

    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


@pytest.mark.parametrize(
    "key,value",
    [
        ("filter.hostile.process", "/bin/true"),
        ("filter.hostile.clean", "/bin/true"),
        ("filter.hostile.smudge", "/bin/true"),
        ("diff.hostile.textconv", "/bin/true"),
        ("diff.hostile.command", "/bin/true"),
        ("core.fsmonitor", "/bin/true"),
        ("core.hooksPath", "/tmp/hooks"),
        ("include.path", "/tmp/injected.gitconfig"),
        ("includeIf.onbranch:main.path", "/tmp/conditional.gitconfig"),
    ],
)
def test_execution_capable_repo_config_fails_closed(
    tmp_path: Path, key: str, value: str
) -> None:
    repo = _init_repo(tmp_path / "repo")
    subprocess.run(["git", "-C", str(repo), "config", key, value], check=True)

    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


def test_worktree_config_extension_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    subprocess.run(
        ["git", "-C", str(repo), "config", "extensions.worktreeConfig", "true"],
        check=True,
    )

    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


def test_execution_config_from_worktree_scope_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    subprocess.run(
        ["git", "-C", str(repo), "config", "extensions.worktreeConfig", "true"],
        check=True,
    )
    worktree = tmp_path / "linked"
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "add", "-b", "linked", str(worktree)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(worktree), "config", "--worktree", "core.hooksPath", "/tmp/hooks"],
        check=True,
    )

    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(worktree)


def test_external_common_git_directory_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    external_git = tmp_path / "external.git"
    subprocess.run(
        ["git", "init", "--separate-git-dir", str(external_git), str(repo)],
        check=True,
        capture_output=True,
    )

    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


@pytest.mark.parametrize("metadata", ["objects/info/alternates", "refs/replace", "info/grafts"])
def test_forbidden_git_metadata_fails_closed(tmp_path: Path, metadata: str) -> None:
    repo = _init_repo(tmp_path / "repo")
    target = repo / ".git" / metadata
    if metadata == "refs/replace":
        target.mkdir(parents=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("forbidden\n", encoding="utf-8")

    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


def test_git_config_environment_is_explicitly_neutralized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "repo")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/bin/true")
    env = git_subprocess_env()

    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_CONFIG_COUNT"] >= "10"
    indexed = {
        env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
        for i in range(int(env["GIT_CONFIG_COUNT"]))
    }
    assert indexed["core.fsmonitor"] == "false"
    assert indexed["core.hooksPath"] == os.devnull
    assert indexed["core.sshCommand"] == ""
    assert indexed["core.pager"] == "cat"
    assert indexed["core.editor"] == ""
    assert indexed["core.askPass"] == ""
    assert indexed["diff.external"] == ""
    assert indexed["include.path"] == os.devnull
    assert indexed["includeIf.gitdir:**.path"] == os.devnull
    assert indexed["protocol.ext.allow"] == "never"
    assert indexed["credential.helper"] == ""
    assert repo.exists()


def test_python_interpreter_never_uses_path_or_env_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from product.clients.local_golden_path import LocalCheckError, _resolve_executable

    shim = tmp_path / "python"
    shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    resolved = _resolve_executable("python", os.environ.get("PATH"))
    assert Path(resolved).is_absolute()
    assert Path(resolved) != shim
    with pytest.raises(LocalCheckError, match="absolute Python interpreter"):
        _resolve_executable("/usr/bin/env", os.environ.get("PATH"))
