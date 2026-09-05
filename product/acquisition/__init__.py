"""Credential-free acquisition ports for externally owned source systems.

Acquisition is deliberately separate from :mod:`product.adapters`: ports are
injected by the controller and return already-authorized, read-only data.
"""

from .github import (
    AcquisitionError,
    GitHubAcquisitionSnapshot,
    GitHubPullRequestAcquisition,
    GitHubPullRequestLocator,
    GitHubReadPort,
    acquire_github_pull_request,
    acquire_pull_request,
    load_github_acquisition_snapshot,
    serialize_github_acquisition_snapshot,
)

__all__ = [
    "AcquisitionError",
    "GitHubAcquisitionSnapshot",
    "GitHubPullRequestAcquisition",
    "GitHubPullRequestLocator",
    "GitHubReadPort",
    "acquire_github_pull_request",
    "acquire_pull_request",
    "load_github_acquisition_snapshot",
    "serialize_github_acquisition_snapshot",
]
