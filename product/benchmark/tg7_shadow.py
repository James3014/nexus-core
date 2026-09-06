"""Physical-worktree binding adapter for the extracted TG7 shadow verifier.

The extracted TG7 kernel keeps its historical evidence semantics unchanged.
This adapter adds one missing physical invariant: when a repository path is
supplied, the checked-out worktree bytes/index/untracked state must still match
the selected immutable commit. Expected read-only chmod transformations are
ignored via ``core.fileMode=false``; content drift is not.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Mapping

from product.benchmark import tg7_shadow_kernel as _kernel
from product.benchmark.tg7_shadow_kernel import *  # noqa: F403

_ORIGINAL_VALIDATE_SELECTION = _kernel.validate_selection


def validate_selection(
    selection: Mapping[str, Any], repo_path: Path | str | None = None
) -> list[str]:
    """Validate selection identity plus the physical worktree materialization."""

    errors = list(_ORIGINAL_VALIDATE_SELECTION(selection, repo_path=repo_path))
    if repo_path is None:
        return errors

    path = Path(repo_path)
    if not path.is_dir():
        return errors

    try:
        status = subprocess.check_output(
            [
                "git",
                "--no-optional-locks",
                "-c",
                "core.fileMode=false",
                "-C",
                str(path),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        errors.append(f"failed to verify repository worktree materialization: {exc}")
    else:
        if status:
            errors.append(
                "repository worktree content/index/untracked state does not match selected commit"
            )
    return list(dict.fromkeys(errors))


_kernel.validate_selection = validate_selection
main = _kernel.main


def __getattr__(name: str) -> Any:
    return getattr(_kernel, name)


if __name__ == "__main__":
    main()
