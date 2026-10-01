"""Read-only GitHub subject acquisition for Nexus Verify carrying surfaces.

This runtime helper composes the existing acquisition seam into a normalized
result for clients. It owns no authentication, verification, completion, merge,
release, or deployment authority.
"""

from __future__ import annotations

from typing import Any

from product.acquisition.github import (
    AcquisitionDriftError,
    AcquisitionError,
    GitHubPullRequestLocator,
    GitHubReadPort,
    PermissionDenied,
    acquire_github_pull_request,
)

_STATUS_OK = "OK"
_STATUS_UNVERIFIABLE = "UNVERIFIABLE"


def validate_github_locator(
    repository_owner: object,
    repository_name: object,
    pr_number: object,
) -> tuple[str, str, int]:
    """Validate and normalize the existing GitHub locator contract."""

    try:
        locator = GitHubPullRequestLocator(
            repository_owner,  # type: ignore[arg-type]
            repository_name,  # type: ignore[arg-type]
            pr_number,  # type: ignore[arg-type]
        )
    except (AcquisitionError, TypeError, ValueError) as exc:
        raise ValueError("invalid GitHub pull-request locator") from exc
    return locator.repository_owner, locator.repository_name, locator.pr_number


def read_current_pull_request_subject(
    repository_owner: str,
    repository_name: str,
    pr_number: int,
    *,
    github_port: GitHubReadPort,
) -> dict[str, Any]:
    """Acquire the current exact PR subject through the canonical read seam."""

    locator = GitHubPullRequestLocator(repository_owner, repository_name, pr_number)
    try:
        snapshot = acquire_github_pull_request(github_port, locator)
    except PermissionDenied:
        return {
            "status": _STATUS_UNVERIFIABLE,
            "reason_code": "GITHUB_READ_PERMISSION_DENIED",
            "subject": None,
        }
    except AcquisitionDriftError:
        return {
            "status": _STATUS_UNVERIFIABLE,
            "reason_code": "GITHUB_ACQUISITION_DRIFT",
            "subject": None,
        }
    except AcquisitionError:
        return {
            "status": _STATUS_UNVERIFIABLE,
            "reason_code": "GITHUB_ACQUISITION_INVALID",
            "subject": None,
        }

    return {
        "status": _STATUS_OK,
        "reason_code": None,
        "subject": {
            "repository_owner": snapshot.repository_owner,
            "repository_name": snapshot.repository_name,
            "pr_number": snapshot.pr_number,
            "current_base_sha": snapshot.base_sha,
            "current_head_sha": snapshot.head_sha,
            "current_base_tree": snapshot.base_tree_sha,
            "current_head_tree": snapshot.head_tree_sha,
            "freshness_cas": snapshot.freshness_cas,
            "changed_paths": list(snapshot.changed_paths),
            "deleted_paths": list(snapshot.deleted_paths),
        },
    }


__all__ = [
    "read_current_pull_request_subject",
    "validate_github_locator",
]
