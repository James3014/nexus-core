"""Runtime-facing aliases for the shared trusted Git implementation."""

from product.protocol._trusted_git import (
    git_subprocess_env,
    trusted_git,
    trusted_git_argv,
    validate_git_repository,
    verify_git_repository_snapshot,
)

__all__ = [
    "git_subprocess_env",
    "trusted_git",
    "trusted_git_argv",
    "validate_git_repository",
    "verify_git_repository_snapshot",
]
