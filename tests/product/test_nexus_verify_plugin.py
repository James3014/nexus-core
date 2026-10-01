from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from product.acquisition.github import GitHubPullRequestLocator, _freshness_cas_for
from product.clients.local_golden_path import check_repository, init_repository
from product.clients.nexus_verify import (
    CLAIM_CEILING,
    TOOL_DEFINITION,
    verify_code_change_evidence,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def verified_repo_and_receipt(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    repo = tmp_path / "external"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "external@example.test")
    _git(repo, "config", "user.name", "External User")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "base")
    _git(repo, "checkout", "-b", "feature")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "feature")
    init_repository(
        repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        verifier_command=(sys.executable, "-c", "print('verified')"),
    )
    result = check_repository(repo)
    receipt = json.loads(result["receipt_path"].read_text(encoding="utf-8"))
    return repo, receipt


class FakeGitHubPort:
    def __init__(
        self,
        repo: Path,
        receipt: dict[str, Any],
        *,
        source_sha: str | None = None,
        source_tree: str | None = None,
        target_tree: str | None = None,
        changed_paths: tuple[str, ...] | None = None,
        deleted_paths: tuple[str, ...] | None = None,
        drift: bool = False,
        permission_denied: bool = False,
    ) -> None:
        request = receipt["inputs"]["request"]
        change_set = request["change_set"]
        self.owner = "example"
        self.repository = "demo"
        self.pr_number = 7
        self.base_sha = source_sha or receipt["source_revision"].removeprefix("git-commit:")
        self.head_sha = _git(repo, "rev-parse", "HEAD")
        self.base_tree_sha = source_tree or receipt["source_tree"].removeprefix("git-tree:")
        self.head_tree_sha = target_tree or receipt["target_tree"].removeprefix("git-tree:")
        self.changed_paths = tuple(changed_paths or change_set["paths"])
        self.deleted_paths = tuple(deleted_paths or change_set["deleted_paths"])
        self.drift = drift
        self.permission_denied = permission_denied
        self.calls = 0

    def read_pull_request(self, locator: GitHubPullRequestLocator) -> dict[str, Any]:
        self.calls += 1
        if self.permission_denied:
            raise PermissionError("denied")
        head_sha = self.head_sha
        if self.drift and self.calls == 2:
            head_sha = "f" * 40
        diff_bytes = b"synthetic read-only diff"
        diff_hash = "sha256:" + hashlib.sha256(diff_bytes).hexdigest()
        checks: tuple[tuple[str, str], ...] = ()
        freshness_cas = _freshness_cas_for(
            locator.repository_owner,
            locator.repository_name,
            locator.pr_number,
            self.base_sha,
            head_sha,
            self.base_tree_sha,
            self.head_tree_sha,
            "base_sha_exact",
            diff_hash,
            tuple(sorted(self.changed_paths)),
            tuple(sorted(self.deleted_paths)),
            checks,
        )
        return {
            "repository_owner": locator.repository_owner,
            "repository_name": locator.repository_name,
            "pr_number": locator.pr_number,
            "base_sha": self.base_sha,
            "head_sha": head_sha,
            "base_tree_sha": self.base_tree_sha,
            "head_tree_sha": self.head_tree_sha,
            "merge_base_policy": "base_sha_exact",
            "diff_bytes": diff_bytes,
            "diff_hash": diff_hash,
            "changed_paths": list(sorted(self.changed_paths)),
            "deleted_paths": list(sorted(self.deleted_paths)),
            "checks": [],
            "pagination_complete": True,
            "observed_at": "2026-10-01T00:00:00Z",
            "freshness_cas": freshness_cas,
        }


def _args(receipt: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "repository_owner": "example",
        "repository_name": "demo",
        "pr_number": 7,
        "receipt": receipt,
    }


def test_tool_contract_is_single_read_only_user_outcome():
    assert TOOL_DEFINITION["name"] == "verify_code_change_evidence"
    assert TOOL_DEFINITION["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
    schema = TOOL_DEFINITION["inputSchema"]
    assert schema["required"] == ["repository_owner", "repository_name", "pr_number"]
    assert set(schema["properties"]) == {
        "repository_owner",
        "repository_name",
        "pr_number",
        "receipt",
    }


def test_fresh_valid_receipt_applies_to_current_pr(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt)

    result = verify_code_change_evidence(_args(receipt), github_port=port)

    assert result["receipt_integrity"] == "VALID"
    assert result["evidence_applicability"] == "APPLIES"
    assert result["core_verification"] == "VERIFIED"
    assert result["reason_codes"] == []
    assert result["claim_ceiling"] == list(CLAIM_CEILING)
    assert result["subject"]["current_head_tree"] == receipt["target_tree"].removeprefix(
        "git-tree:"
    )
    assert port.calls == 2


def test_missing_receipt_never_upgrades_github_state_to_verified(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt)

    result = verify_code_change_evidence(_args(None), github_port=port)

    assert result["receipt_integrity"] == "ABSENT"
    assert result["evidence_applicability"] == "EVIDENCE_NOT_SUPPLIED"
    assert result["core_verification"] == "NOT_AVAILABLE"
    assert result["reason_codes"] == ["NEXUS_RECEIPT_NOT_SUPPLIED"]


def test_receipt_target_tree_staleness_is_explicit(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt, target_tree="f" * 40)

    result = verify_code_change_evidence(_args(receipt), github_port=port)

    assert result["receipt_integrity"] == "VALID"
    assert result["evidence_applicability"] == "STALE_TARGET"
    assert result["core_verification"] == "VERIFIED"
    assert result["reason_codes"] == ["RECEIPT_TARGET_DOES_NOT_MATCH_CURRENT_PR"]


def test_receipt_source_staleness_is_explicit(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(
        repo,
        receipt,
        source_sha="e" * 40,
        source_tree="d" * 40,
    )

    result = verify_code_change_evidence(_args(receipt), github_port=port)

    assert result["receipt_integrity"] == "VALID"
    assert result["evidence_applicability"] == "STALE_SOURCE"
    assert result["reason_codes"] == ["RECEIPT_SOURCE_DOES_NOT_MATCH_CURRENT_PR"]


def test_tampered_receipt_fails_closed(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    receipt["outcome"]["status"] = "FAILED_VERIFICATION"
    port = FakeGitHubPort(repo, receipt)

    result = verify_code_change_evidence(_args(receipt), github_port=port)

    assert result["receipt_integrity"] == "INVALID"
    assert result["evidence_applicability"] == "TAMPERED"
    assert result["core_verification"] == "NOT_AVAILABLE"
    assert "RECEIPT_HASH_MISMATCH" in result["reason_codes"]
    assert "OUTCOME_MISMATCH" in result["reason_codes"]


def test_changed_path_mismatch_is_not_treated_as_applicable(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt, changed_paths=("different.py",))

    result = verify_code_change_evidence(_args(receipt), github_port=port)

    assert result["receipt_integrity"] == "VALID"
    assert result["evidence_applicability"] == "SUBJECT_MISMATCH"
    assert result["reason_codes"] == ["RECEIPT_PATH_SCOPE_DOES_NOT_MATCH_CURRENT_PR"]


def test_acquisition_drift_fails_closed_without_retry(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt, drift=True)

    result = verify_code_change_evidence(_args(receipt), github_port=port)

    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["reason_codes"] == ["GITHUB_ACQUISITION_DRIFT"]
    assert port.calls == 2


def test_permission_denied_is_unverifiable_not_absence(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt, permission_denied=True)

    result = verify_code_change_evidence(_args(receipt), github_port=port)

    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["reason_codes"] == ["GITHUB_READ_PERMISSION_DENIED"]
    assert port.calls == 1


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"repository_owner": "example", "repository_name": "demo", "pr_number": True},
        {
            "repository_owner": "example",
            "repository_name": "demo",
            "pr_number": 7,
            "receipt": [],
        },
        {
            "repository_owner": "example",
            "repository_name": "demo",
            "pr_number": 7,
            "extra": True,
        },
    ],
)
def test_invalid_tool_arguments_are_rejected(verified_repo_and_receipt, arguments):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt)
    with pytest.raises((TypeError, ValueError)):
        verify_code_change_evidence(arguments, github_port=port)


def test_adapter_has_no_execution_or_github_mutation_surface():
    path = Path("product/clients/nexus_verify.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = [
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    ]
    imports += [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    forbidden_imports = {
        "subprocess",
        "requests",
        "urllib",
        "aiohttp",
        "github",
        "pygithub",
    }
    assert not any(
        imported.split(".")[0].lower() in forbidden_imports for imported in imports
    )
    source = path.read_text(encoding="utf-8").lower()
    for forbidden in (
        "merge_pull_request",
        "create_comment",
        "rerun",
        "workflow_dispatch",
        "subprocess.run",
        "os.system",
    ):
        assert forbidden not in source
