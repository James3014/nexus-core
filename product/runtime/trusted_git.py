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


def git_subprocess_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build a Git environment from an allowlist; never copy ``os.environ``."""
    env = {k: os.environ[k] for k in _ENV_ALLOWLIST if k in os.environ}
    env["PATH"] = os.defpath if os.name == "nt" else "/usr/bin:/bin"
    if SETTING in os.environ:
        env[SETTING] = os.environ[SETTING]
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    if extra:
        env.update(extra)
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return env


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
                version = subprocess.run(
                    [str(path), "--version"], capture_output=True, text=True, check=False,
                    env={**values, "GIT_NO_REPLACE_OBJECTS": "1"},
                )
                if version.returncode != 0:
                    raise ValueError("--version failed")
                reported_version = version.stdout.strip().splitlines()[0]
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
