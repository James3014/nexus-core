# pyright: strict
"""Resolve and identify a trusted system Git executable."""

from __future__ import annotations

import hashlib
import os
import platform
import stat
import subprocess
import tomllib
from pathlib import Path
from typing import Any, Mapping

SETTING = "TRUSTED_GIT_EXECUTABLE"
ADMIN_CONFIG = Path("/etc/nexus-core/trusted-executables.toml")
_VERSION_CACHE: dict[tuple[str, int, int, int, int], str] = {}


_ENV_ALLOWLIST = ("LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SYSTEMROOT", "TZ")

_GIT_CONFIG_OVERRIDES = (
    ("core.commitGraph", "false"),
    ("core.fsmonitor", "false"),
    ("core.hooksPath", os.devnull),
    ("core.sshCommand", ""),
    ("core.pager", "cat"),
    ("core.askPass", ""),
    ("core.editor", ""),
    ("credential.helper", ""),
    ("diff.external", ""),
    ("diff.*.textconv", ""),
    ("protocol.ext.allow", "never"),
    ("include.path", os.devnull),
    ("includeIf.gitdir:**.path", os.devnull),
)

_CONFIG_COUNT_OVERRIDES = (
    ("core.commitGraph", "false"),
    ("core.fsmonitor", "false"),
    ("core.hooksPath", os.devnull),
    ("core.sshCommand", ""),
    ("core.pager", "cat"),
    ("core.editor", ""),
    ("core.askPass", ""),
    ("diff.external", ""),
    ("include.path", os.devnull),
    ("includeIf.gitdir:**.path", os.devnull),
    ("protocol.ext.allow", "never"),
    ("credential.helper", ""),
)

_METADATA_FILES = (
    "HEAD", "packed-refs", "config", "config.worktree", "info/attributes",
    "info/exclude", "shallow", "grafts", "commondir", "gitdir",
)


def _config_env(env: Mapping[str, str]) -> dict[str, str]:
    result = dict(env)
    for key in tuple(result):
        if key == "GIT_CONFIG_COUNT" or key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            result.pop(key, None)
    result["GIT_CONFIG_COUNT"] = str(len(_CONFIG_COUNT_OVERRIDES))
    for index, (key, value) in enumerate(_CONFIG_COUNT_OVERRIDES):
        result[f"GIT_CONFIG_KEY_{index}"] = key
        result[f"GIT_CONFIG_VALUE_{index}"] = value
    result["GIT_CONFIG_NOSYSTEM"] = "1"
    result["GIT_CONFIG_GLOBAL"] = os.devnull
    result["GIT_NO_REPLACE_OBJECTS"] = "1"
    return result


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _walk_no_symlinks(root: Path) -> None:
    if not root.exists():
        return
    for current, dirs, files in os.walk(root, followlinks=False):
        directory = Path(current)
        for name in [*dirs, *files]:
            item = directory / name
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f"symlink in Git metadata: {item}")


def _reject_nested_git_metadata(worktree: Path) -> None:
    """Reject nested repositories before any Git command can inspect their files."""
    def fail_scan(error: OSError) -> None:
        raise ValueError(f"cannot scan worktree for nested Git metadata: {error}") from error

    for current, dirs, files in os.walk(worktree, followlinks=False, onerror=fail_scan):
        directory = Path(current)
        for name in (*dirs, *files):
            item = directory / name
            if name.casefold() == ".git" and item.parent != worktree:
                raise ValueError(f"nested Git metadata is not permitted: {item}")
        # The top-level .git directory is administrative data, not worktree content.
        if directory == worktree and ".git" in dirs:
            dirs.remove(".git")


def _repo_config_key_allowed(key: str) -> bool:
    key = key.lower()
    if key.startswith("user.") or key.startswith("branch."):
        return True
    return key in {
        "core.bare",
        "core.commitgraph",
        "core.filemode",
        "core.ignorecase",
        "core.logallrefupdates",
        "core.precomposeunicode",
        "core.repositoryformatversion",
        "extensions.objectformat",
        "remote.origin.fetch",
        "remote.origin.url",
    }


def validate_git_repository(executable: str, cwd: Path) -> dict[str, tuple[int, int]]:
    """Validate Git metadata and execution config around one trusted command."""
    _reject_nested_git_metadata(Path(cwd).resolve(strict=True))
    env = _config_env(git_subprocess_env())

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [executable, *args], cwd=cwd, env=env, capture_output=True, text=True,
            check=False, timeout=30,
        )

    resolved = run("rev-parse", "--git-dir", "--git-common-dir", "--absolute-git-dir")
    if resolved.returncode:
        raise ValueError("not a Git repository: " + resolved.stderr.strip())
    values = resolved.stdout.splitlines()
    if len(values) != 3:
        raise ValueError("Git did not resolve git-dir, common-dir, and absolute-git-dir")
    git_dir = Path(values[0])
    common_dir = Path(values[1])
    absolute_git_dir = Path(values[2])
    if not git_dir.is_absolute():
        git_dir = cwd / git_dir
    if not common_dir.is_absolute():
        common_dir = cwd / common_dir
    git_dir = git_dir.resolve(strict=True)
    common_dir = common_dir.resolve(strict=True)
    absolute_git_dir = absolute_git_dir.resolve(strict=True)
    repo = Path(cwd).resolve(strict=True)
    dot_git = repo / ".git"
    if dot_git.exists() and stat.S_ISLNK(dot_git.lstat().st_mode):
        raise ValueError("symlink Git metadata pointer: .git")
    if not (_inside(git_dir, repo) or _inside(git_dir, common_dir)):
        raise ValueError("Git directory escapes repository and its worktree admin directory")
    worktree_admin = _inside(git_dir, common_dir / "worktrees") and dot_git.is_file()
    if not (_inside(common_dir, repo) or worktree_admin):
        raise ValueError("Git common directory escapes repository")
    if absolute_git_dir != git_dir:
        raise ValueError("absolute Git directory disagrees with resolved Git directory")
    for root in {git_dir, common_dir}:
        _walk_no_symlinks(root)
    paths = [git_dir / name for name in _METADATA_FILES]
    paths.extend((common_dir / name for name in ("objects", "refs")))
    for item in paths:
        if not item.exists():
            continue
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"symlink in Git metadata: {item}")
        if not (_inside(item.resolve(strict=True), repo) or _inside(item.resolve(strict=True), common_dir)):
            raise ValueError(f"Git metadata escapes repository: {item}")
    for config in (git_dir / "config", git_dir / "config.worktree", common_dir / "config"):
        if config.exists() and config.lstat().st_nlink > 1:
            raise ValueError(f"Git config is hardlinked: {config}")
    for forbidden in (
        git_dir / "objects/info/alternates",
        common_dir / "objects/info/alternates",
        common_dir / "refs/replace",
        git_dir / "refs/replace",
        git_dir / "info/grafts",
        common_dir / "info/grafts",
    ):
        if forbidden.exists():
            raise ValueError(f"forbidden Git metadata exists: {forbidden}")
    listing = run("config", "--show-origin", "--list", "--includes")
    if listing.returncode:
        raise ValueError("cannot inspect Git config: " + listing.stderr.strip())
    for line in listing.stdout.splitlines():
        origin, _, entry = line.partition("\t")
        if origin.startswith("command line:"):
            continue
        key = entry.split("=", 1)[0].lower()
        if not _repo_config_key_allowed(key):
            raise ValueError(f"execution-capable or unsupported Git config: {key}")
    before: dict[str, tuple[int, int]] = {}
    for label, root in (("@gitdir", git_dir), ("@common", common_dir)):
        info = root.lstat()
        before[label] = (info.st_dev, info.st_ino)
    for root in {git_dir, common_dir}:
        for current, dirs, files in os.walk(root, followlinks=False):
            for name in [".", *dirs, *files]:
                item = Path(current) if name == "." else Path(current) / name
                info = item.lstat()
                before[str(item)] = (info.st_dev, info.st_ino)
    return before


def verify_git_repository_snapshot(
    snapshot: Mapping[str, tuple[int, int]],
    current: Mapping[str, tuple[int, int]],
) -> None:
    for marker in ("@gitdir", "@common"):
        if current.get(marker) != snapshot.get(marker):
            raise ValueError(f"Git repository directory changed during command: {marker}")
    for raw_path, identity in snapshot.items():
        if raw_path.startswith("@"):
            continue
        path = Path(raw_path)
        try:
            info = path.lstat()
        except FileNotFoundError:
            # Git legitimately removes worktree, ref, and reflog entries.
            if any(part in {"refs", "logs", "worktrees", "objects"} for part in path.parts):
                continue
            raise
        # Git legitimately atomically replaces refs/config and creates or
        # removes worktree admin files. The post-run scan validates those paths;
        # stable metadata must retain its inode.
        mutable = "worktrees" in path.parts
        mutable = mutable or ("objects" in path.parts and path.name != "objects")
        mutable = mutable or (
            not stat.S_ISDIR(info.st_mode)
            and any(part in {"refs", "logs"} for part in path.parts)
        )
        mutable = mutable or path.name in {
            "config", "config.worktree", "HEAD", "packed-refs", "index"
        }
        if stat.S_ISLNK(info.st_mode) or (not mutable and (info.st_dev, info.st_ino) != identity):
            raise ValueError(f"Git metadata changed during command: {path}")


def trusted_git_argv(
    executable: str, *args: str, cwd: Path | None = None
) -> list[str]:
    """Build Git argv with repo-local command execution settings disabled."""
    overrides = list(_GIT_CONFIG_OVERRIDES)
    if cwd is not None:
        # Driver names are arbitrary, so discover only the config key names;
        # `git config` reads values as data and does not invoke configured tools.
        discovery = subprocess.Popen(
            trusted_git_argv(
                executable,
                "--no-pager", "config", "--local", "--name-only", "--get-regexp",
                r"^(filter\..*\.(process|clean|smudge)|diff\..*\.textconv)$",
            ),
            cwd=cwd,
            env=git_subprocess_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        discovered, _ = discovery.communicate()
        for key in discovered.splitlines():
            if key not in {configured for configured, _ in overrides}:
                overrides.append((key, ""))
    command = [executable]
    for key, value in overrides:
        command.extend(("-c", f"{key}={value}"))
    pinned_args = _history_pinned_args(args)
    subcommand_index = _git_subcommand_index(pinned_args)
    if (
        subcommand_index < len(pinned_args)
        and pinned_args[subcommand_index] in {"diff", "show", "log", "whatchanged"}
    ):
        command.extend(
            (
                *pinned_args[:subcommand_index],
                pinned_args[subcommand_index],
                "--no-ext-diff",
                "--no-textconv",
                *pinned_args[subcommand_index + 1 :],
            )
        )
    else:
        command.extend(pinned_args)
    return command


def _git_subcommand_index(args: list[str]) -> int:
    """Find the command after Git's leading global options."""
    takes_value = {
        "-c", "-C", "--config-env", "--git-dir", "--work-tree", "--namespace",
        "--exec-path",
    }
    standalone = {
        "--no-pager", "--paginate", "--no-replace-objects", "--bare", "--version",
        "--help",
    }
    index = 0
    while index < len(args):
        option = args[index]
        if option in takes_value:
            index += 2
        elif option in standalone:
            index += 1
        elif (
            option.startswith("--config-env=")
            or option.startswith("--git-dir=")
            or option.startswith("--work-tree=")
            or option.startswith("--namespace=")
            or option.startswith("--exec-path=")
            or (option.startswith("-c") and len(option) > 2)
        ):
            index += 1
        else:
            return index
    return index


def _history_pinned_args(args: tuple[str, ...]) -> list[str]:
    """Remove caller history/config-include overrides and pin them after Git options."""
    values = [str(arg) for arg in args]
    protected = {"core.commitgraph", "core.usereplacerefs", "core.graftfile"}

    def is_protected(setting: str) -> bool:
        key = setting.split("=", 1)[0].lower()
        return (
            key in protected
            or key.startswith(("include.", "includeif."))
        )

    result: list[str] = []
    index = 0
    while index < len(values):
        arg = values[index]
        if arg == "-c" and index + 1 < len(values):
            setting = values[index + 1]
            if is_protected(setting):
                index += 2
                continue
            result.extend((arg, setting))
            index += 2
            continue
        if arg.startswith("--config-env="):
            if is_protected(arg[len("--config-env=") :]):
                index += 1
                continue
        elif arg == "--config-env" and index + 1 < len(values):
            if is_protected(values[index + 1]):
                index += 2
                continue
            result.extend((arg, values[index + 1]))
            index += 2
            continue
        elif arg.startswith("-c") and len(arg) > 2:
            if is_protected(arg[2:]):
                index += 1
                continue
        result.append(arg)
        index += 1

    at = 0
    takes_value = {"-c", "-C", "--config-env", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
    standalone = {"--no-pager", "--paginate", "--no-replace-objects", "--bare", "--version", "--help"}
    while at < len(result):
        option = result[at]
        if option in takes_value and at + 1 < len(result):
            at += 2
        elif option in standalone:
            # --version/--help are commands from Git's global option parser, so put
            # our -c pins before them, not after them.
            if option in {"--version", "--help"}:
                break
            at += 1
        elif option.startswith("--git-dir=") or option.startswith("--work-tree=") or option.startswith("--namespace=") or option.startswith("--exec-path="):
            at += 1
        elif option.startswith("-c") and len(option) > 2:
            at += 1
        else:
            break
    result[at:at] = [
        "-c", "core.commitGraph=false",
        "-c", "core.useReplaceRefs=false",
        "-c", f"core.graftFile={os.devnull}",
    ]
    return result


def git_subprocess_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build a Git environment from an allowlist; never copy ``os.environ``."""
    env = {k: os.environ[k] for k in _ENV_ALLOWLIST if k in os.environ}
    env["PATH"] = os.defpath if os.name == "nt" else "/usr/bin:/bin"
    if SETTING in os.environ:
        env[SETTING] = os.environ[SETTING]
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    if extra and "GIT_INDEX_FILE" in extra:
        env["GIT_INDEX_FILE"] = extra["GIT_INDEX_FILE"]
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return _config_env(env)


def trusted_git(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Select Git by env, root-owned admin config, then trusted absolute defaults."""
    values = os.environ if env is None else env
    uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    groups = set(os.getgroups()) if hasattr(os, "getgroups") else set()
    groups.add(os.getegid() if hasattr(os, "getegid") else os.getgid())

    def caller_writable(info: os.stat_result) -> bool:
        if info.st_uid == uid:
            return bool(info.st_mode & stat.S_IWUSR)
        if info.st_gid in groups:
            return bool(info.st_mode & stat.S_IWGRP)
        return bool(info.st_mode & stat.S_IWOTH)

    selected = values.get(SETTING)
    source = "environment"
    approved_uids = {0}
    if not selected:
        try:
            info = ADMIN_CONFIG.stat()
            if info.st_uid != 0 or caller_writable(info):
                raise ValueError("admin config is not root-owned and protected")
            parent = ADMIN_CONFIG.parent
            while True:
                directory = parent.stat()
                if directory.st_uid != 0 or directory.st_mode & 0o022:
                    raise ValueError(f"admin config directory is not root-owned and protected: {parent}")
                if parent == parent.parent:
                    break
                parent = parent.parent
            data = tomllib.loads(ADMIN_CONFIG.read_text(encoding="utf-8"))
            selected = data.get("git", {}).get("path")
            approved_uids.update(data.get("git", {}).get("approved_installer_uids", []))
            if selected:
                source = "config"
        except FileNotFoundError:
            pass
        except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
            raise RuntimeError(
                f"Trusted Git executable unavailable; configure {SETTING}. "
                f"Administrator executable config is invalid: {exc}"
            ) from exc
    if selected:
        candidates = [Path(selected)]
    elif os.name == "nt":
        candidates = [
            Path(r"C:\Program Files\Git\cmd\git.exe"),
            Path(r"C:\Program Files\Git\bin\git.exe"),
        ]
    elif platform.system() == "Darwin":
        candidates = [
            Path("/usr/bin/git"), Path("/opt/homebrew/bin/git"),
            Path("/usr/local/bin/git"), Path("/opt/local/bin/git"),
        ]
    else:
        candidates = [Path("/usr/bin/git"), Path("/usr/local/bin/git")]
    if not selected:
        source = "default"
    errors: list[str] = []
    for candidate in candidates:
        try:
            path = candidate.resolve(strict=True)
            st = path.stat()
            if not stat.S_ISREG(st.st_mode) or not os.access(path, os.X_OK):
                raise ValueError("not a regular executable")
            if st.st_uid not in approved_uids:
                raise ValueError("owner is not root or an approved installer")
            if caller_writable(st):
                raise ValueError("executable is writable by the caller")
            parent = path.parent
            while True:
                pst = parent.stat()
                if caller_writable(pst):
                    raise ValueError(f"caller-writable directory: {parent}")
                if parent == parent.parent:
                    break
                parent = parent.parent
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            cache_key = (str(path), st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
            reported_version = _VERSION_CACHE.get(cache_key)
            if reported_version is None:
                version = subprocess.Popen(
                    trusted_git_argv(str(path), "--version"),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env=git_subprocess_env(),
                )
                version_stdout, _ = version.communicate()
                if version.returncode != 0:
                    raise ValueError("--version failed")
                reported_version = version_stdout.strip().splitlines()[0]
                _VERSION_CACHE[cache_key] = reported_version
            after = path.stat()
            if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise ValueError("executable changed during validation")
            return {
                "path": str(path), "source": source, "owner_uid": st.st_uid,
                "mode": oct(stat.S_IMODE(st.st_mode)), "sha256": digest,
                "version": reported_version,
            }
        except (OSError, ValueError, IndexError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"{candidate}: {exc}")
            if selected:
                break
    detail = "; ".join(errors) or "no supported system location exists"
    raise RuntimeError(
        f"Trusted Git executable unavailable; configure {SETTING} or install Git in a supported system location. PATH lookup is disabled. {detail}"
    )
