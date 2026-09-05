"""Injected, read-only GitHub pull-request acquisition.

The port intentionally has no credential parameter and this module has no
network client.  A controller-owned implementation performs authentication
outside the product package and supplies one complete response per read.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Protocol, runtime_checkable

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})?\Z")
_UTC_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")
_REQUIRED = frozenset({
    "repository_owner",
    "repository_name",
    "pr_number",
    "base_sha",
    "head_sha",
    "base_tree_sha",
    "head_tree_sha",
    "merge_base_policy",
    "diff_bytes",
    "diff_hash",
    "changed_paths",
    "deleted_paths",
    "checks",
    "pagination_complete",
    "observed_at",
    "freshness_cas",
})


class AcquisitionError(ValueError):
    """A response cannot be admitted as an immutable acquisition snapshot."""


class PermissionDenied(AcquisitionError):
    """The injected port could not read the requested PR."""


class AcquisitionDriftError(AcquisitionError):
    """The two independent reads do not describe the same PR identity."""


@dataclass(frozen=True)
class GitHubPullRequestLocator:
    repository_owner: str
    repository_name: str
    pr_number: int

    def __post_init__(self) -> None:
        for field in ("repository_owner", "repository_name"):
            value = getattr(self, field)
            if (
                type(value) is not str
                or not value
                or value != value.strip()
                or _NAME.fullmatch(value) is None
            ):
                raise AcquisitionError(f"{field} is not a normalized GitHub name")
        if type(self.pr_number) is not int or self.pr_number <= 0:
            raise AcquisitionError("pr_number must be a positive exact int")

    @property
    def locator_hash(self) -> str:
        value = [self.repository_owner.lower(), self.repository_name.lower(), self.pr_number]
        return (
            "sha256:"
            + hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()
        )


@runtime_checkable
class GitHubReadPort(Protocol):
    """Controller-provided authenticated read seam; credentials never cross it."""

    def read_pull_request(self, locator: GitHubPullRequestLocator) -> Mapping[str, object]: ...


def _sha(value: object, field: str) -> str:
    if type(value) is not str or _SHA40.fullmatch(value) is None:
        raise AcquisitionError(f"{field} must be lowercase 40-hex SHA")
    return value


def _hash(value: object, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AcquisitionError(f"{field} must be sha256:<64 lowercase hex>")
    return value


def _paths(value: object, field: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) not in (list, tuple):
        raise AcquisitionError(f"{field} must be a path list")
    result = tuple(value)
    if not allow_empty and not result:
        raise AcquisitionError(f"{field} must be non-empty")
    if len(result) != len(set(result)):
        raise AcquisitionError(f"{field} contains duplicate paths")
    for path in result:
        if (
            type(path) is not str
            or not path
            or path != path.strip()
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise AcquisitionError(f"{field} contains an invalid relative path")
    return tuple(sorted(result))


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _freshness_cas_for(
    owner: str,
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    base_tree_sha: str,
    head_tree_sha: str,
    merge_base_policy: str,
    diff_hash: str,
    changed_paths: tuple[str, ...],
    deleted_paths: tuple[str, ...],
    checks: tuple[tuple[str, str], ...],
) -> str:
    subject = {
        "repository_owner": owner.lower(),
        "repository_name": repository.lower(),
        "pr_number": pr_number,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "base_tree_sha": base_tree_sha,
        "head_tree_sha": head_tree_sha,
        "merge_base_policy": merge_base_policy,
        "diff_hash": diff_hash,
        "changed_paths": list(changed_paths),
        "deleted_paths": list(deleted_paths),
        "checks": [list(item) for item in checks],
    }
    return "sha256:" + hashlib.sha256(_canonical(subject).encode()).hexdigest()


@dataclass(frozen=True)
class GitHubAcquisitionSnapshot:
    repository_owner: str
    repository_name: str
    pr_number: int
    base_sha: str
    head_sha: str
    base_tree_sha: str
    head_tree_sha: str
    merge_base_policy: str
    diff_bytes: bytes
    diff_hash: str
    changed_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]
    checks: tuple[tuple[str, str], ...]
    pagination_complete: bool
    observed_at: str
    freshness_cas: str
    locator_hash: str

    def __post_init__(self) -> None:
        locator = GitHubPullRequestLocator(
            self.repository_owner, self.repository_name, self.pr_number
        )
        for field in ("base_sha", "head_sha", "base_tree_sha", "head_tree_sha"):
            _sha(getattr(self, field), field)
        if self.base_sha == self.head_sha:
            raise AcquisitionError("base_sha and head_sha must differ")
        if self.merge_base_policy != "base_sha_exact":
            raise AcquisitionError("merge_base_policy must be base_sha_exact")
        if type(self.diff_bytes) is not bytes:
            raise AcquisitionError("diff_bytes must be immutable bytes")
        expected = "sha256:" + hashlib.sha256(self.diff_bytes).hexdigest()
        if self.diff_hash != expected:
            raise AcquisitionError("diff_hash does not match diff_bytes")
        _hash(self.diff_hash, "diff_hash")
        if self.changed_paths != tuple(sorted(self.changed_paths)):
            raise AcquisitionError("changed_paths must be sorted")
        if self.deleted_paths != tuple(sorted(self.deleted_paths)):
            raise AcquisitionError("deleted_paths must be sorted")
        _paths(self.changed_paths, "changed_paths", allow_empty=False)
        _paths(self.deleted_paths, "deleted_paths")
        if not set(self.deleted_paths).issubset(set(self.changed_paths)):
            raise AcquisitionError("deleted_paths must be a subset of changed_paths")
        if type(self.checks) is not tuple or any(
            type(x) is not tuple or len(x) != 2 for x in self.checks
        ):
            raise AcquisitionError("checks must be (identity, digest) pairs")
        if self.checks != tuple(sorted(self.checks)) or len({x[0] for x in self.checks}) != len(
            self.checks
        ):
            raise AcquisitionError("checks must be sorted and have unique identities")
        for identity, digest in self.checks:
            if (
                type(identity) is not str
                or not identity
                or identity != identity.strip()
                or "\x00" in identity
            ):
                raise AcquisitionError("check identities must be normalized")
            _hash(digest, "check digest")
        if type(self.pagination_complete) is not bool or not self.pagination_complete:
            raise AcquisitionError("pagination_complete must be true")
        if type(self.observed_at) is not str or _UTC_RFC3339.fullmatch(self.observed_at) is None:
            raise AcquisitionError("observed_at must be canonical UTC RFC3339 ending in Z")
        try:
            parsed = datetime.fromisoformat(self.observed_at[:-1])
        except ValueError as exc:
            raise AcquisitionError("observed_at must be a valid UTC RFC3339 timestamp") from exc
        if parsed.tzinfo is not None:
            raise AcquisitionError("observed_at must use canonical Z timezone")
        expected_cas = _freshness_cas_for(
            self.repository_owner,
            self.repository_name,
            self.pr_number,
            self.base_sha,
            self.head_sha,
            self.base_tree_sha,
            self.head_tree_sha,
            self.merge_base_policy,
            self.diff_hash,
            self.changed_paths,
            self.deleted_paths,
            self.checks,
        )
        if self.freshness_cas != expected_cas:
            raise AcquisitionError("freshness_cas does not match snapshot subject")
        if self.locator_hash != locator.locator_hash:
            raise AcquisitionError("locator_hash does not match locator")

    def to_dict(self) -> dict[str, object]:
        return {
            "repository_owner": self.repository_owner,
            "repository_name": self.repository_name,
            "pr_number": self.pr_number,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "base_tree_sha": self.base_tree_sha,
            "head_tree_sha": self.head_tree_sha,
            "merge_base_policy": self.merge_base_policy,
            "diff_bytes": self.diff_bytes.hex(),
            "diff_hash": self.diff_hash,
            "changed_paths": list(self.changed_paths),
            "deleted_paths": list(self.deleted_paths),
            "checks": [list(x) for x in self.checks],
            "pagination_complete": self.pagination_complete,
            "observed_at": self.observed_at,
            "freshness_cas": self.freshness_cas,
            "locator_hash": self.locator_hash,
        }


def _parse(
    raw: Mapping[str, object], locator: GitHubPullRequestLocator
) -> GitHubAcquisitionSnapshot:
    if not isinstance(raw, Mapping) or set(raw) != _REQUIRED:
        raise AcquisitionError("response has an incomplete or substituted schema")
    values = dict(raw)
    if (
        values["repository_owner"] != locator.repository_owner
        or values["repository_name"] != locator.repository_name
        or values["pr_number"] != locator.pr_number
    ):
        raise AcquisitionDriftError("response locator differs from requested locator")
    if type(values["diff_bytes"]) is not bytes:
        raise AcquisitionError("diff_bytes must be bytes from the read port")
    checks = values["checks"]
    if type(checks) not in (list, tuple):
        raise AcquisitionError("checks must be a list")
    values["checks"] = tuple(tuple(x) for x in checks)
    values["changed_paths"] = (
        tuple(values["changed_paths"])
        if type(values["changed_paths"]) in (list, tuple)
        else values["changed_paths"]
    )
    values["deleted_paths"] = (
        tuple(values["deleted_paths"])
        if type(values["deleted_paths"]) in (list, tuple)
        else values["deleted_paths"]
    )
    values["locator_hash"] = locator.locator_hash
    return GitHubAcquisitionSnapshot(**values)


def acquire_github_pull_request(
    port: GitHubReadPort, locator: GitHubPullRequestLocator
) -> GitHubAcquisitionSnapshot:
    """Read twice and admit only convergent, complete, immutable identity."""
    if not isinstance(locator, GitHubPullRequestLocator):
        raise TypeError("locator must be GitHubPullRequestLocator")
    try:
        first = port.read_pull_request(locator)
        second = port.read_pull_request(locator)
    except PermissionError as exc:
        raise PermissionDenied("GitHub read permission denied") from exc
    left = _parse(first, locator)
    right = _parse(second, locator)
    if left != right:
        raise AcquisitionDriftError("independent GitHub reads disagree")
    return left


def serialize_github_acquisition_snapshot(snapshot: GitHubAcquisitionSnapshot) -> dict[str, object]:
    if type(snapshot) is not GitHubAcquisitionSnapshot:
        raise TypeError("snapshot must be GitHubAcquisitionSnapshot")
    return snapshot.to_dict()


def load_github_acquisition_snapshot(payload: Mapping[str, object]) -> GitHubAcquisitionSnapshot:
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")
    values = dict(payload)
    try:
        values["diff_bytes"] = bytes.fromhex(values["diff_bytes"])
        values["checks"] = tuple(tuple(x) for x in values["checks"])
        values["changed_paths"] = tuple(values["changed_paths"])
        values["deleted_paths"] = tuple(values["deleted_paths"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AcquisitionError("malformed serialized acquisition snapshot") from exc
    return GitHubAcquisitionSnapshot(**values)


GitHubPullRequestAcquisition = GitHubAcquisitionSnapshot
acquire_pull_request = acquire_github_pull_request


__all__ = [
    "AcquisitionError",
    "AcquisitionDriftError",
    "GitHubAcquisitionSnapshot",
    "GitHubPullRequestAcquisition",
    "GitHubPullRequestLocator",
    "GitHubReadPort",
    "PermissionDenied",
    "acquire_github_pull_request",
    "acquire_pull_request",
    "load_github_acquisition_snapshot",
    "serialize_github_acquisition_snapshot",
]
