from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from product.clients import local_golden_path as lgp
from product.clients.trusted_git import git_subprocess_env
from product.protocol._trusted_git import validate_git_repository, verify_git_repository_snapshot


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
    versioned_shim = tmp_path / "python3.14"
    versioned_shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    versioned_shim.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    resolved = _resolve_executable("python", os.environ.get("PATH"))
    assert Path(resolved).is_absolute()
    assert Path(resolved) != shim
    assert _resolve_executable("python3.14", os.environ.get("PATH")) != str(versioned_shim)
    with pytest.raises(LocalCheckError, match="absolute Python interpreter"):
        _resolve_executable("/usr/bin/env", os.environ.get("PATH"))
    with pytest.raises(LocalCheckError, match="absolute Python interpreter"):
        _resolve_executable("/missing/python3.14", os.environ.get("PATH"))


@pytest.mark.parametrize("command", ["diff", "status", "diff-files"])
@pytest.mark.parametrize("nested_form", ["gitlink", "standalone"])
@pytest.mark.parametrize("driver", ["filter", "include", "textconv"])
def test_nested_repository_config_cannot_run_programs(
    tmp_path: Path, command: str, nested_form: str, driver: str
) -> None:
    repo = _init_repo(tmp_path / "repo")
    nested = repo / "sub"
    nested.mkdir()
    subprocess.run(["git", "-C", str(nested), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(nested), "config", "user.name", "Test"], check=True)
    subprocess.run(
        ["git", "-C", str(nested), "config", "user.email", "test@example.test"], check=True
    )
    (nested / ".gitattributes").write_text("f.txt filter=hostile\n", encoding="utf-8")
    (nested / "f.txt").write_text("nested\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(nested), "add", "."], check=True)
    subprocess.run(["git", "-C", str(nested), "commit", "-qm", "nested"], check=True)
    marker = tmp_path / "nested-program-ran"
    if driver == "filter":
        config_key, config_value = "filter.hostile.clean", f"sh -c 'touch {marker}; cat'"
    elif driver == "include":
        included = tmp_path / "included.gitconfig"
        included.write_text(
            f'[filter "hostile"]\nclean = sh -c \'touch {marker}; cat\'\n',
            encoding="utf-8",
        )
        config_key, config_value = "include.path", str(included)
    else:
        config_key, config_value = "diff.hostile.textconv", f"sh -c 'touch {marker}; cat'"
        (nested / ".gitattributes").write_text("f.txt diff=hostile\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(nested), "config", config_key, config_value], check=True
    )
    if nested_form == "gitlink":
        nested_commit = subprocess.run(
            ["git", "-C", str(nested), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(repo), "update-index", "--add", "--cacheinfo",
             f"160000,{nested_commit},sub"],
            check=True,
        )

    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        lgp._run_git(repo, command, "--quiet", "--")
    assert not marker.exists()


@pytest.mark.parametrize(
    "key,value",
    [
        ("gpg.program", "/bin/true"),
        ("gpg.ssh.program", "/bin/true"),
        ("gpg.x509.program", "/bin/true"),
        ("gpg.openpgp.program", "/bin/true"),
        ("log.showSignature", "true"),
        ("core.gitProxy", "/bin/true"),
        ("core.alternateRefsCommand", "/bin/true"),
        ("merge.hostile.driver", "/bin/true"),
        ("remote.origin.uploadpack", "/bin/true"),
        ("remote.origin.receivepack", "/bin/true"),
        ("remote.origin.vcs", "hostile"),
        ("submodule.hostile.update", "!not-a-command"),
        ("sequence.editor", "/bin/true"),
        ("pager.log", "/bin/true"),
        ("core.worktree", "/tmp"),
        ("GPG.Program", "/bin/true"),
        ("Core.Worktree", "/tmp"),
    ],
)
def test_unapproved_repo_config_key_fails_closed(tmp_path: Path, key: str, value: str) -> None:
    repo = _init_repo(tmp_path / "repo")
    subprocess.run(["git", "-C", str(repo), "config", key, value], check=True)
    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


@pytest.mark.parametrize(
    "key,value",
    [
        ("user.name", "Test"),
        ("user.email", "test@example.test"),
        ("remote.origin.url", "https://example.invalid/repo.git"),
        ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
        ("branch.main.remote", "origin"),
        ("branch.main.merge", "refs/heads/main"),
        ("core.filemode", "true"),
        ("core.bare", "false"),
        ("core.logallrefupdates", "true"),
        ("extensions.objectFormat", "sha256"),
    ],
)
def test_approved_repo_config_keys_remain_allowed(tmp_path: Path, key: str, value: str) -> None:
    repo_path = tmp_path / "repo"
    if key == "extensions.objectFormat":
        repo_path.mkdir()
        subprocess.run(
            ["git", "-C", str(repo_path), "init", "--object-format=sha256"],
            check=True,
            capture_output=True,
        )
        repo = repo_path
    else:
        repo = _init_repo(repo_path)
    subprocess.run(["git", "-C", str(repo), "config", key, value], check=True)
    assert _run(repo).returncode == 0


@pytest.mark.parametrize(
    "variable",
    [
        "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_PARAMETERS", "GIT_GRAFT_FILE",
        "GIT_NAMESPACE", "GIT_EXEC_PATH", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS",
        "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_EDITOR", "OTHER_VALUE",
    ],
)
def test_git_extra_environment_drops_everything_except_index_file(
    variable: str, tmp_path: Path
) -> None:
    env = git_subprocess_env({variable: str(tmp_path / "value")})
    assert variable not in env


def test_git_index_file_extra_environment_is_allowed(tmp_path: Path) -> None:
    index_file = tmp_path / "alternate-index"
    assert git_subprocess_env({"GIT_INDEX_FILE": str(index_file)})["GIT_INDEX_FILE"] == str(index_file)


def test_git_index_file_is_the_only_extra_git_value_used(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    index_file = tmp_path / "temporary-index"
    result = lgp._run_git(repo, "rev-parse", "--show-toplevel", env={"GIT_INDEX_FILE": str(index_file)})
    assert result.returncode == 0
    assert result.stdout.strip() == str(repo)
    assert not index_file.exists()


def test_worktree_internal_separate_git_directory_and_shallow_clone_are_allowed(
    tmp_path: Path,
) -> None:
    source = _init_repo(tmp_path / "source")
    linked = tmp_path / "linked"
    subprocess.run(
        ["git", "-C", str(source), "worktree", "add", "-b", "linked", str(linked)],
        check=True,
        capture_output=True,
    )
    assert _run(linked).returncode == 0

    separate = tmp_path / "separate"
    separate.mkdir()
    subprocess.run(
        ["git", "init", "--separate-git-dir", str(separate / ".metadata"), str(separate)],
        check=True,
        capture_output=True,
    )
    assert _run(separate).returncode == 0

    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--depth=1", f"file://{source}", str(shallow)],
        check=True,
        capture_output=True,
    )
    assert _run(shallow).returncode == 0


def test_empty_submodule_directory_with_gitlink_is_allowed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    nested_commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(repo), "update-index", "--add", "--cacheinfo",
         f"160000,{nested_commit},sub"],
        check=True,
    )
    (repo / "sub").mkdir()
    assert _run(repo).returncode == 0


def test_nested_gitfile_is_rejected(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    nested = repo / "vendor" / "checkout"
    nested.mkdir(parents=True)
    (nested / ".git").write_text("gitdir: ../../.git/worktrees/vendor\n", encoding="utf-8")
    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


@pytest.mark.parametrize("name", ["/bin/env", "/usr/local/bin/env"])
def test_python_rule_rejects_env_paths(
    name: str,
) -> None:
    from product.clients.local_golden_path import LocalCheckError, _resolve_executable

    with pytest.raises(LocalCheckError, match="absolute Python interpreter"):
        _resolve_executable(name, "/usr/bin:/bin")


def test_versioned_python_never_resolves_from_path(tmp_path: Path) -> None:
    from product.clients.local_golden_path import _resolve_executable

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake = fake_bin / "python3.12"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    assert _resolve_executable("python3.12", str(fake_bin)) != str(fake)


def test_supported_python_interpreter_forms_remain_allowed() -> None:
    from product.clients.local_golden_path import _resolve_executable

    assert _resolve_executable("python", "") == str(Path(sys.executable).absolute())
    python3 = Path("/usr/bin/python3")
    if python3.is_file() and os.access(python3, os.X_OK):
        assert _resolve_executable(str(python3), "") == str(python3)


def test_loose_ref_symlink_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    refs = repo / ".git" / "refs" / "heads"
    target = tmp_path / "outside-ref"
    target.write_text("0" * 40 + "\n", encoding="utf-8")
    (refs / "evil").symlink_to(target)
    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


def test_git_pointer_symlink_to_internal_directory_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    git_dir = repo / ".git"
    internal = repo / ".metadata"
    git_dir.rename(internal)
    git_dir.symlink_to(internal, target_is_directory=True)
    with pytest.raises(lgp.LocalCheckError, match="GIT_REPOSITORY_UNTRUSTED"):
        _run(repo)


def test_packed_replace_ref_is_rejected_by_repository_check(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    oid = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (repo / ".git" / "packed-refs").write_text(
        f"# pack-refs with: peeled\n{oid} refs/replace/{oid}\n", encoding="utf-8"
    )
    with pytest.raises(lgp.LocalCheckError, match="GIT_REPLACE_REFS_PRESENT"):
        lgp.check_repository(repo)


def test_snapshot_rejects_replaced_stable_metadata_inode(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    snapshot = validate_git_repository(str(lgp.trusted_git()["path"]), repo)
    stable = repo / ".git" / "info" / "exclude"
    replacement = stable.with_name("exclude.new")
    replacement.write_text(stable.read_text(encoding="utf-8") + "# replaced\n", encoding="utf-8")
    replacement.replace(stable)
    with pytest.raises(ValueError, match="Git metadata changed during command"):
        verify_git_repository_snapshot(snapshot, snapshot)


@pytest.mark.parametrize("setting", ["true", "yes", "1"])
def test_commit_graph_setting_cannot_change_ancestry(tmp_path: Path, setting: str) -> None:
    repo = _init_repo(tmp_path / "repo")
    parent = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (repo / "child.txt").write_text("child\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "child.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "child"], check=True, capture_output=True)
    child = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "-C", str(repo), "commit-graph", "write", "--reachable"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "core.commitGraph", setting], check=True)
    assert lgp._run_git(repo, "merge-base", "--is-ancestor", parent, child).returncode == 0


def test_forged_commit_graph_cannot_change_ancestry(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    main = subprocess.run(
        ["git", "-C", str(repo), "branch", "--show-current"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    parent = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (repo / "child.txt").write_text("child\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "child.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "child"], check=True, capture_output=True)
    child = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "-C", str(repo), "checkout", "--orphan", "unrelated"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "rm", "-q", "-rf", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "--allow-empty", "-m", "orphan"], check=True, capture_output=True)
    unrelated = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "-C", str(repo), "checkout", main], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit-graph", "write", "--reachable"], check=True)
    graph = repo / ".git" / "objects" / "info" / "commit-graph"
    data = bytearray(graph.read_bytes())
    chunk_count = data[6]
    chunks: dict[bytes, int] = {}
    for index in range(chunk_count + 1):
        start = 8 + index * 12
        name = bytes(data[start : start + 4])
        offset = struct.unpack(">Q", data[start + 4 : start + 12])[0]
        if name != b"\0\0\0\0":
            chunks[name] = offset
    cdat = chunks[b"CDAT"]
    oidl = chunks[b"OIDL"]
    commit_count = (chunks[b"CDAT"] - oidl) // 20
    oids = [bytes(data[oidl + index * 20 : oidl + (index + 1) * 20]).hex() for index in range(commit_count)]
    positions = {oid: index for index, oid in enumerate(oids)}
    row_size = 20 + 4 + 4 + 8
    row = cdat + positions[child] * row_size
    struct.pack_into(">I", data, row + 20, positions[unrelated] + 1)
    data[-20:] = hashlib.sha1(data[:-20]).digest()
    graph.chmod(0o644)
    graph.write_bytes(data)
    subprocess.run(["git", "-C", str(repo), "config", "core.commitGraph", "true"], check=True)

    result = lgp._run_git(repo, "merge-base", "--is-ancestor", unrelated, child)
    assert result.returncode != 0
    assert lgp._run_git(repo, "merge-base", "--is-ancestor", parent, child).returncode == 0


@pytest.mark.parametrize(
    "override",
    [
        ("-c", "core.commitGraph=true"),
        ("-cCORE.COMMITGRAPH=yes",),
    ],
)
def test_caller_config_cannot_reenable_commit_graph(
    tmp_path: Path, override: tuple[str, ...]
) -> None:
    repo = _init_repo(tmp_path / "repo")
    parent = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (repo / "child.txt").write_text("child\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "child.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "child"], check=True, capture_output=True)
    child = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "-C", str(repo), "commit-graph", "write", "--reachable"], check=True)
    assert lgp._run_git(repo, *override, "merge-base", "--is-ancestor", parent, child).returncode == 0
