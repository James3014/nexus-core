"""Build hook: embed the Core build identity (#267).

All project metadata lives in pyproject.toml. This file only adds a step that
writes ``product/_build_identity.json`` into every sdist and wheel:

- From a git checkout: the HEAD commit and tree, whether the shipped sources
  (``product/`` minus ``product/benchmark``) have uncommitted changes, and the
  source digest of exactly the files being packaged.
- From an sdist (no ``.git``): the stamp the sdist already carries is kept as is,
  so a wheel built from the sdist reports the commit the sdist was cut from.
- With no git metadata and no stamp: a stamp with null git fields is written,
  so ``core_identity()`` still reports the version and build source digest.

Editable installs are never stamped: their sources change in place, so
``core_identity()`` reports ``UNSTAMPED`` and only the live ``source_digest``.
Runtime code never calls git.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist

ROOT = Path(__file__).resolve().parent
STAMP_NAME = "_build_identity.json"
GIT_TIMEOUT_SECONDS = 10


def _identity_module():
    path = ROOT / "product" / "protocol" / "build_identity.py"
    spec = importlib.util.spec_from_file_location("_nexus_core_build_identity", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(*args: str) -> str | None:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_") or key in {"GIT_CONFIG_NOSYSTEM"}
    }
    try:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def _git_metadata() -> tuple[str | None, str | None, bool | None]:
    """(commit, tree, dirty) when ROOT is the top of a git work tree."""
    toplevel = _git("rev-parse", "--show-toplevel")
    if toplevel is None or Path(toplevel.strip()).resolve() != ROOT:
        return (None, None, None)
    commit = _git("rev-parse", "--verify", "HEAD^{commit}")
    tree = _git("rev-parse", "--verify", "HEAD^{tree}")
    status = _git(
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        "product",
        ":(exclude)product/benchmark",
    )
    if commit is None or tree is None or status is None:
        return (None, None, None)
    return (commit.strip(), tree.strip(), bool(status.strip()))


def _write_stamp(package_dir: Path, version: str) -> None:
    identity = _identity_module()
    commit, tree, dirty = _git_metadata()
    stamp_path = package_dir / STAMP_NAME
    if commit is None and stamp_path.is_file():
        # Wheel built from an sdist (no .git): keep the stamp the sdist was cut
        # with, unchanged. If the sources were edited since, the runtime
        # core_identity() reports source_matches_build == False.
        existing = json.loads(stamp_path.read_text(encoding="utf-8"))
        if not identity.validate_build_identity(existing) or existing["version"] != version:
            raise RuntimeError(f"refusing to package an invalid build stamp: {stamp_path}")
        return
    stamp = identity.make_build_identity(
        version=version,
        git_commit=commit,
        git_tree=tree,
        git_dirty=dirty,
        source_digest_value=identity.source_digest(package_dir),
    )
    stamp_path.write_text(json.dumps(stamp, sort_keys=True, indent=2) + "\n", encoding="utf-8")


class build_py(_build_py):
    def run(self) -> None:
        super().run()
        if getattr(self, "editable_mode", False):
            return
        package_dir = Path(self.build_lib) / "product"
        if package_dir.is_dir():
            _write_stamp(package_dir, self.distribution.get_version())


class sdist(_sdist):
    def make_release_tree(self, base_dir: str, files: list[str]) -> None:
        super().make_release_tree(base_dir, files)
        package_dir = Path(base_dir) / "product"
        stamp_path = package_dir / STAMP_NAME
        # make_release_tree may hard-link files; never write through a link
        # into the source checkout.
        if stamp_path.exists():
            stamp_path.unlink()
        _write_stamp(package_dir, self.distribution.get_version())


setup(cmdclass={"build_py": build_py, "sdist": sdist})
