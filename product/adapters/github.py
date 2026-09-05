"""Pure, pre-materialized GitHub pull-request compatibility adapter."""

import re
from dataclasses import dataclass

from product.evidence import ChangeSet
from product.kernel import CertificationInput, certify

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GITHUB_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_GITHUB_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})?\Z")
_FIELDS = frozenset(
    {
        "repository_owner",
        "repository_name",
        "pr_number",
        "base_sha",
        "head_sha",
        "diff_hash",
        "changed_paths",
    }
)


def _text(value, field):
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{field} must be a normalized nonblank string")


@dataclass(frozen=True)
class GitHubPullRequestSnapshot:
    repository_owner: str
    repository_name: str
    pr_number: int
    base_sha: str
    head_sha: str
    diff_hash: str
    changed_paths: tuple[str, ...]

    def __post_init__(self):
        _text(self.repository_owner, "repository_owner")
        _text(self.repository_name, "repository_name")
        for field in ("repository_owner", "repository_name"):
            pattern = _GITHUB_OWNER if field == "repository_owner" else _GITHUB_REPOSITORY
            if pattern.fullmatch(getattr(self, field)) is None:
                raise ValueError(f"{field} must be a GitHub-compatible name")
        if type(self.pr_number) is not int or self.pr_number <= 0:
            raise ValueError("pr_number must be a positive exact int")
        for field in ("base_sha", "head_sha"):
            value = getattr(self, field)
            if type(value) is not str or _SHA40.fullmatch(value) is None:
                raise ValueError(f"{field} must be lowercase 40-hex SHA")
        if self.base_sha == self.head_sha:
            raise ValueError("base_sha and head_sha must differ")
        if type(self.diff_hash) is not str or _SHA256.fullmatch(self.diff_hash) is None:
            raise ValueError("diff_hash must be sha256:<64 lowercase hex>")
        if type(self.changed_paths) is not tuple or not self.changed_paths:
            raise ValueError("changed_paths must be a non-empty tuple")
        if len(self.changed_paths) != len(set(self.changed_paths)):
            raise ValueError("changed_paths must be unique")
        for path in self.changed_paths:
            _text(path, "changed_paths")
            if (
                path.startswith("/")
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
            ):
                raise ValueError("changed_paths must contain normalized relative paths")

    def to_dict(self):
        return {
            "repository_owner": self.repository_owner,
            "repository_name": self.repository_name,
            "pr_number": self.pr_number,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "diff_hash": self.diff_hash,
            "changed_paths": list(self.changed_paths),
        }


def snapshot_to_dict(snapshot):
    if type(snapshot) is not GitHubPullRequestSnapshot:
        raise TypeError("snapshot must be GitHubPullRequestSnapshot")
    return snapshot.to_dict()


def load_snapshot(payload):
    if type(payload) is not dict or set(payload) != _FIELDS:
        raise ValueError("malformed GitHub pull-request snapshot keys")
    values = dict(payload)
    if type(values["changed_paths"]) is not list:
        raise TypeError("changed_paths must be a list in serialized snapshots")
    values["changed_paths"] = tuple(values["changed_paths"])
    return GitHubPullRequestSnapshot(**values)


load_github_pull_request_snapshot = load_snapshot
serialize_github_pull_request_snapshot = snapshot_to_dict


def to_changeset(snapshot):
    if type(snapshot) is not GitHubPullRequestSnapshot:
        raise TypeError("snapshot must be GitHubPullRequestSnapshot")
    change_set_id = (
        f"github:{snapshot.repository_owner}/{snapshot.repository_name}"
        f"#pr-{snapshot.pr_number}@{snapshot.head_sha}"
    )
    return ChangeSet(
        change_set_id,
        snapshot.base_sha,
        snapshot.head_sha,
        snapshot.diff_hash,
        snapshot.changed_paths,
    )


github_snapshot_to_changeset = to_changeset


def _make_trust_sealed_api(snapshot_type, change_set_type, input_type, kernel_certify):
    owner_pattern = _GITHUB_OWNER.fullmatch
    repository_pattern = _GITHUB_REPOSITORY.fullmatch
    sha40 = _SHA40.fullmatch
    sha256 = _SHA256.fullmatch
    fields = frozenset(_FIELDS)
    ordered_fields = (
        "repository_owner",
        "repository_name",
        "pr_number",
        "base_sha",
        "head_sha",
        "diff_hash",
        "changed_paths",
    )

    def validate(value):
        if type(value) is not snapshot_type:
            raise TypeError("snapshot must be GitHubPullRequestSnapshot")
        data = vars(value)
        if set(data) != fields:
            raise ValueError("malformed GitHub pull-request snapshot fields")
        for field, pattern in (
            ("repository_owner", owner_pattern),
            ("repository_name", repository_pattern),
        ):
            item = data[field]
            if type(item) is not str or pattern(item) is None:
                raise ValueError(f"{field} must be a GitHub-compatible name")
        if type(data["pr_number"]) is not int or data["pr_number"] <= 0:
            raise ValueError("pr_number must be a positive exact int")
        if type(data["base_sha"]) is not str or sha40(data["base_sha"]) is None:
            raise ValueError("base_sha must be lowercase 40-hex SHA")
        if type(data["head_sha"]) is not str or sha40(data["head_sha"]) is None:
            raise ValueError("head_sha must be lowercase 40-hex SHA")
        if data["base_sha"] == data["head_sha"]:
            raise ValueError("base_sha and head_sha must differ")
        if type(data["diff_hash"]) is not str or sha256(data["diff_hash"]) is None:
            raise ValueError("diff_hash must be sha256:<64 lowercase hex>")
        paths = data["changed_paths"]
        if type(paths) is not tuple or not paths or len(paths) != len(set(paths)):
            raise ValueError("changed_paths must be a non-empty unique tuple")
        for path in paths:
            if (
                type(path) is not str
                or not path
                or path != path.strip()
                or path.startswith("/")
                or "\\" in path
            ):
                raise ValueError("changed_paths must contain normalized relative paths")
            if any(part in {"", ".", ".."} for part in path.split("/")):
                raise ValueError("changed_paths must contain normalized relative paths")
        return data

    def sealed_to_changeset(value):
        data = validate(value)
        owner = data["repository_owner"].lower()
        repository = data["repository_name"].lower()
        change_set_id = f"github:{owner}/{repository}#pr-{data['pr_number']}@{data['head_sha']}"
        result = change_set_type(
            change_set_id,
            data["base_sha"],
            data["head_sha"],
            data["diff_hash"],
            tuple(sorted(data["changed_paths"])),
        )
        expected = {
            "change_set_id": change_set_id,
            "source_revision": data["base_sha"],
            "target_revision": data["head_sha"],
            "diff_hash": data["diff_hash"],
            "paths": tuple(sorted(data["changed_paths"])),
        }
        if type(result) is not change_set_type or vars(result) != expected:
            raise ValueError("malformed mapped ChangeSet")
        return result

    def sealed_snapshot_to_dict(value):
        data = validate(value)
        return {
            key: (
                sorted(data[key])
                if key == "changed_paths"
                else data[key].lower()
                if key in {"repository_owner", "repository_name"}
                else data[key]
            )
            for key in ordered_fields
        }

    def sealed_load(payload):
        if type(payload) is not dict or set(payload) != fields:
            raise ValueError("malformed GitHub pull-request snapshot keys")
        values = dict(payload)
        if type(values["changed_paths"]) is not list:
            raise TypeError("changed_paths must be a list in serialized snapshots")
        values["repository_owner"] = values["repository_owner"].lower()
        values["repository_name"] = values["repository_name"].lower()
        values["changed_paths"] = tuple(sorted(values["changed_paths"]))
        loaded = snapshot_type(**values)
        validate(loaded)
        if vars(loaded) != values:
            raise ValueError("loaded snapshot differs from payload")
        return loaded

    def sealed_certify(
        value,
        contract,
        plan,
        evidence,
        *,
        policy_accepted=None,
        authority_present=None,
        approval_present=None,
        signing_present=None,
    ):
        change_set = sealed_to_changeset(value)
        return kernel_certify(
            input_type(
                contract,
                change_set,
                plan,
                evidence,
                policy_accepted,
                authority_present,
                approval_present,
                signing_present,
            )
        )

    return sealed_to_changeset, sealed_snapshot_to_dict, sealed_load, sealed_certify


to_changeset, snapshot_to_dict, load_snapshot, certify_pull_request = _make_trust_sealed_api(  # type: ignore[reportAssignmentType]
    GitHubPullRequestSnapshot, ChangeSet, CertificationInput, certify
)
github_snapshot_to_changeset = to_changeset
load_github_pull_request_snapshot = load_snapshot
serialize_github_pull_request_snapshot = snapshot_to_dict
GitHubPullRequestSnapshot.to_dict = snapshot_to_dict  # type: ignore[reportAttributeAccessIssue]


__all__ = [
    "GitHubPullRequestSnapshot",
    "certify_pull_request",
    "github_snapshot_to_changeset",
    "load_github_pull_request_snapshot",
    "serialize_github_pull_request_snapshot",
    "snapshot_to_dict",
    "to_changeset",
]
