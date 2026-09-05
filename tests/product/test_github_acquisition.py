import ast
import hashlib
from pathlib import Path

import pytest

from product.acquisition.github import (
    AcquisitionDriftError,
    AcquisitionError,
    GitHubPullRequestLocator,
    PermissionDenied,
    _freshness_cas_for,
    acquire_github_pull_request,
    load_github_acquisition_snapshot,
    serialize_github_acquisition_snapshot,
)


def _response(locator=None):
    locator = locator or GitHubPullRequestLocator("James3014", "Nexus-new", 635)
    diff = b"diff --git a/src/a.py b/src/a.py\n"
    return {
        "repository_owner": locator.repository_owner,
        "repository_name": locator.repository_name,
        "pr_number": locator.pr_number,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "base_tree_sha": "c" * 40,
        "head_tree_sha": "d" * 40,
        "merge_base_policy": "base_sha_exact",
        "diff_bytes": diff,
        "diff_hash": "sha256:" + hashlib.sha256(diff).hexdigest(),
        "changed_paths": ["deleted.py", "src/a.py"],
        "deleted_paths": ["deleted.py"],
        "checks": [["ci/test", "sha256:" + "e" * 64]],
        "pagination_complete": True,
        "observed_at": "2026-09-04T00:00:00Z",
        "freshness_cas": "sha256:" + "f" * 64,
    }


def _with_cas(response):
    response["freshness_cas"] = _freshness_cas_for(
        response["repository_owner"],
        response["repository_name"],
        response["pr_number"],
        response["base_sha"],
        response["head_sha"],
        response["base_tree_sha"],
        response["head_tree_sha"],
        response["merge_base_policy"],
        response["diff_hash"],
        tuple(sorted(response["changed_paths"])),
        tuple(sorted(response["deleted_paths"])),
        tuple(sorted(tuple(x) for x in response["checks"])),
    )
    return response


class Port:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def read_pull_request(self, locator):
        self.calls.append(locator)
        value = self.responses.pop(0) if self.responses else _response(locator)
        if isinstance(value, BaseException):
            raise value
        return value


def test_two_reads_produce_immutable_credential_free_snapshot_and_replay():
    locator = GitHubPullRequestLocator("James3014", "Nexus-new", 635)
    port = Port(_with_cas(_response(locator)), _with_cas(_response(locator)))
    snapshot = acquire_github_pull_request(port, locator)
    assert len(port.calls) == 2
    assert snapshot.diff_hash == "sha256:" + hashlib.sha256(snapshot.diff_bytes).hexdigest()
    assert snapshot.locator_hash == locator.locator_hash
    assert (
        load_github_acquisition_snapshot(serialize_github_acquisition_snapshot(snapshot))
        == snapshot
    )


@pytest.mark.parametrize(
    "change, error",
    [
        (lambda x: x.update(head_sha="e" * 40), AcquisitionDriftError),
        (lambda x: x.update(pagination_complete=False), AcquisitionError),
        (lambda x: x.update(repository_name="substituted"), AcquisitionDriftError),
        (lambda x: x.update(diff_hash="sha256:" + "0" * 64), AcquisitionError),
        (lambda x: x.update(changed_paths=["../escape"]), AcquisitionError),
    ],
)
def test_hostile_second_read_fails_closed(change, error):
    locator = GitHubPullRequestLocator("James3014", "Nexus-new", 635)
    second = _with_cas(_response(locator))
    change(second)
    _with_cas(second)
    with pytest.raises(error):
        acquire_github_pull_request(Port(_with_cas(_response(locator)), second), locator)


def test_permission_denial_is_not_a_snapshot():
    locator = GitHubPullRequestLocator("James3014", "Nexus-new", 635)
    with pytest.raises(PermissionDenied):
        acquire_github_pull_request(Port(PermissionError()), locator)


def test_caller_only_or_forged_envelope_is_rejected():
    locator = GitHubPullRequestLocator("James3014", "Nexus-new", 635)
    response = _with_cas(_response(locator))
    response.pop("head_tree_sha")
    with pytest.raises(AcquisitionError):
        acquire_github_pull_request(Port(response, response), locator)


def test_forged_freshness_cas_is_rejected():
    locator = GitHubPullRequestLocator("James3014", "Nexus-new", 635)
    first = _with_cas(_response(locator))
    second = dict(first)
    second["freshness_cas"] = "sha256:" + "0" * 64
    with pytest.raises(AcquisitionError, match="freshness_cas"):
        acquire_github_pull_request(Port(first, second), locator)


@pytest.mark.parametrize(
    "field, value",
    [
        ("merge_base_policy", "merge_base_sha"),
        ("merge_base_policy", " base_sha_exact"),
        ("observed_at", "2026-09-04T00:00:00+00:00"),
        ("observed_at", "2026-09-04T00:00:00"),
        ("observed_at", " 2026-09-04T00:00:00Z"),
        ("observed_at", "2026-13-04T00:00:00Z"),
    ],
)
def test_frozen_policy_and_utc_timestamp_are_canonical(field, value):
    locator = GitHubPullRequestLocator("James3014", "Nexus-new", 635)
    first = _with_cas(_response(locator))
    second = dict(first)
    second[field] = value
    if field == "merge_base_policy":
        _with_cas(second)
    with pytest.raises(AcquisitionError):
        acquire_github_pull_request(Port(first, second), locator)


@pytest.mark.parametrize("field", ["checks", "changed_paths"])
def test_unsorted_or_duplicate_identity_is_rejected(field):
    locator = GitHubPullRequestLocator("James3014", "Nexus-new", 635)
    first = _with_cas(_response(locator))
    second = dict(first)
    second[field] = list(reversed(second[field]))
    if field == "checks":
        second[field] = second[field] + [second[field][0]]
    with pytest.raises(AcquisitionError):
        acquire_github_pull_request(Port(first, second), locator)


def test_locator_rejects_unsafe_identity():
    with pytest.raises(AcquisitionError):
        GitHubPullRequestLocator("owner/replaced", "repo", 1)


def test_acquisition_module_has_no_credential_or_mutation_surface():
    module_path = Path(__import__("product.acquisition.github", fromlist=["__file__"]).__file__)
    tree = ast.parse(module_path.read_text())
    source = module_path.read_text().lower()
    forbidden = {
        "requests",
        "urllib",
        "socket",
        "token",
        "password",
        "secret",
        "merge",
        "mutation",
        "write",
    }
    imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert not any(any(word in item.lower() for word in forbidden) for item in imports)
    assert not any(
        word in source for word in ("requests", "urllib", "socket", "password", "secret")
    )
