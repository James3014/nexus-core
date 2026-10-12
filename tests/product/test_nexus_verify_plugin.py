from __future__ import annotations

import ast
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from product.acquisition.github import GitHubPullRequestLocator, _freshness_cas_for
from product.clients.cli import main as cli_main
from product.clients.local_golden_path import check_repository, init_repository
from product.clients.nexus_verify import (
    CLAIM_CEILING,
    RECEIPT_AUTHENTICATION_UNAVAILABLE,
    RECEIPT_NOT_AUTHENTICATED,
    TOOL_DEFINITION,
    authenticate_receipt,
    evaluate_code_change_evidence_subject,
    verify_code_change_evidence,
)
from product.clients.receipt_authentication import (
    AUTHENTICATED,
    NOT_AUTHENTICATED,
    UNAVAILABLE,
    ReceiptAuthentication,
    ReceiptSignerPolicy,
    SigstoreReceiptAuthenticator,
    github_workflow_signer_policy,
)

# Shape-valid Sigstore message-signature bundle; the fake authenticator below
# stands in for the cryptography (real signatures: test_nexus_verify_sigstore_real.py).
_BUNDLE_SHAPE: dict[str, Any] = {
    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
    "verificationMaterial": {"certificate": {"rawBytes": "AA=="}},
    "messageSignature": {"signature": "AA=="},
}
_DEMO_POLICY = github_workflow_signer_policy("example", "demo")


def _receipt_bytes(receipt: dict[str, Any]) -> bytes:
    return (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _signature(receipt_bytes: bytes, bundle: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "receipt_base64": base64.b64encode(receipt_bytes).decode("ascii"),
        "sigstore_bundle": dict(_BUNDLE_SHAPE if bundle is None else bundle),
    }


class FakeAuthenticator:
    """Models a Sigstore signature: valid only for the exact signed bytes and signer."""

    def __init__(
        self,
        signed: dict[bytes, ReceiptSignerPolicy] | None = None,
        *,
        status: str | None = None,
    ) -> None:
        self.signed = dict(signed or {})
        self.status = status
        self.calls: list[tuple[bytes, ReceiptSignerPolicy]] = []

    def sign(self, receipt: dict[str, Any], policy: ReceiptSignerPolicy = _DEMO_POLICY) -> dict[str, Any]:
        data = _receipt_bytes(receipt)
        self.signed[data] = policy
        return _signature(data)

    def authenticate(
        self, *, receipt_bytes: bytes, bundle_json: bytes, policy: ReceiptSignerPolicy
    ) -> ReceiptAuthentication:
        self.calls.append((receipt_bytes, policy))
        if self.status is not None:
            return ReceiptAuthentication(self.status, "forced")
        json.loads(bundle_json)
        if self.signed.get(receipt_bytes) == policy:
            return ReceiptAuthentication(AUTHENTICATED, policy.identity)
        return ReceiptAuthentication(NOT_AUTHENTICATED, "signature does not match")


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
    init_repository(
        repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        verifier_command=(sys.executable, "-c", "print('verified')"),
    )
    _git(repo, "add", ".nexus-core/config.toml")
    _git(repo, "commit", "-m", "trusted config")
    _git(repo, "checkout", "-b", "feature")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "feature")
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


def _args(
    receipt: dict[str, Any] | None,
    receipt_signature: dict[str, Any] | None = None,
) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "repository_owner": "example",
        "repository_name": "demo",
        "pr_number": 7,
        "receipt": receipt,
    }
    if receipt_signature is not None:
        arguments["receipt_signature"] = receipt_signature
    return arguments


def _signed_args(receipt: dict[str, Any]) -> tuple[dict[str, Any], FakeAuthenticator]:
    authenticator = FakeAuthenticator()
    return _args(receipt, authenticator.sign(receipt)), authenticator


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
        "receipt_signature",
    }
    assert schema["$id"] == "nexus.verify-code-change-evidence.input.v2"
    assert TOOL_DEFINITION["outputSchema"]["$id"] == "nexus.verify-code-change-evidence.output.v2"
    signature_schema = schema["properties"]["receipt_signature"]["anyOf"][0]
    assert signature_schema["required"] == ["receipt_base64", "sigstore_bundle"]
    assert signature_schema["additionalProperties"] is False


def test_fresh_valid_receipt_applies_to_current_pr(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt)
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

    assert result["receipt_integrity"] == "VALID"
    assert result["evidence_applicability"] == "APPLIES"
    assert result["core_verification"] == "VERIFIED"
    assert result["reason_codes"] == []
    # The signer is host policy: the subject repository's gate workflow on main.
    assert authenticator.calls == [(_receipt_bytes(receipt), _DEMO_POLICY)]
    assert _DEMO_POLICY.identity == (
        "https://github.com/example/demo/.github/workflows/"
        "nexus-core-issue-completion.yml@refs/heads/main"
    )
    assert result["claim_ceiling"] == list(CLAIM_CEILING)
    assert result["subject"]["current_head_tree"] == receipt["target_tree"].removeprefix(
        "git-tree:"
    )
    assert port.calls == 2


def test_supplied_subject_reducer_matches_mcp_applicability(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt)
    subject = {
        "repository_owner": port.owner,
        "repository_name": port.repository,
        "pr_number": port.pr_number,
        "current_base_sha": port.base_sha,
        "current_head_sha": port.head_sha,
        "current_base_tree": port.base_tree_sha,
        "current_head_tree": port.head_tree_sha,
        "changed_paths": list(port.changed_paths),
        "deleted_paths": list(port.deleted_paths),
    }

    arguments, authenticator = _signed_args(receipt)
    supplied = evaluate_code_change_evidence_subject(
        subject,
        receipt,
        receipt_signature=arguments["receipt_signature"],
        authenticator=authenticator,
    )
    acquired = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

    assert supplied["subject"] is None
    assert supplied["receipt_integrity"] == acquired["receipt_integrity"] == "VALID"
    assert supplied["evidence_applicability"] == acquired["evidence_applicability"] == "APPLIES"
    assert supplied["core_verification"] == acquired["core_verification"] == "VERIFIED"
    assert supplied["reason_codes"] == acquired["reason_codes"] == []
    assert supplied["claim_ceiling"] == acquired["claim_ceiling"] == list(CLAIM_CEILING)


def test_evidence_check_cli_uses_shared_reducer(
    verified_repo_and_receipt,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    import product.clients.receipt_authentication as receipt_authentication

    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt)
    authenticator = FakeAuthenticator()
    signature = authenticator.sign(receipt)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(_receipt_bytes(receipt))
    monkeypatch.setattr(
        receipt_authentication,
        "SigstoreReceiptAuthenticator",
        lambda **_: authenticator,
    )
    args = [
        "evidence-check",
        "--receipt", str(receipt_path),
        "--repository-owner", port.owner,
        "--repository-name", port.repository,
        "--pr-number", str(port.pr_number),
        "--base-sha", port.base_sha,
        "--head-sha", port.head_sha,
        "--base-tree", port.base_tree_sha,
        "--head-tree", port.head_tree_sha,
    ]
    for path in port.changed_paths:
        args += ["--changed-path", path]
    for path in port.deleted_paths:
        args += ["--deleted-path", path]

    # No bundle next to the receipt: the forgery-safe default.
    assert cli_main(args) == 0
    unsigned = json.loads(capsys.readouterr().out)
    assert unsigned["evidence_applicability"] == "UNVERIFIABLE"
    assert unsigned["core_verification"] == "NOT_AVAILABLE"
    assert unsigned["reason_codes"] == [RECEIPT_NOT_AUTHENTICATED]

    # <receipt>.sigstore.json is picked up by default, as CI uploads it.
    Path(f"{receipt_path}.sigstore.json").write_text(
        json.dumps(signature["sigstore_bundle"]), encoding="utf-8"
    )
    assert cli_main(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["subject"] is None
    assert payload["receipt_integrity"] == "VALID"
    assert payload["evidence_applicability"] == "APPLIES"
    assert payload["core_verification"] == "VERIFIED"
    assert payload["claim_ceiling"] == list(CLAIM_CEILING)

    stale_args = list(args)
    stale_args[stale_args.index("--head-tree") + 1] = "f" * 40
    assert cli_main(stale_args) == 0
    stale = json.loads(capsys.readouterr().out)
    assert stale["evidence_applicability"] == "STALE_TARGET"
    assert stale["reason_codes"] == ["RECEIPT_TARGET_DOES_NOT_MATCH_CURRENT_PR"]

    other_signer = [
        *args,
        "--signer-identity",
        "https://github.com/example/demo/.github/workflows/other.yml@refs/heads/main",
    ]
    assert cli_main(other_signer) == 0
    wrong = json.loads(capsys.readouterr().out)
    assert wrong["evidence_applicability"] == "UNVERIFIABLE"
    assert wrong["reason_codes"] == [RECEIPT_NOT_AUTHENTICATED]

    foreign_signer = [
        *args,
        "--signer-identity",
        "https://github.com/attacker/demo/.github/workflows/gate.yml@refs/heads/main",
    ]
    assert cli_main(foreign_signer) == 2


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
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

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
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

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
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

    assert result["receipt_integrity"] == "VALID"
    assert result["evidence_applicability"] == "SUBJECT_MISMATCH"
    assert result["reason_codes"] == ["RECEIPT_PATH_SCOPE_DOES_NOT_MATCH_CURRENT_PR"]


def test_acquisition_drift_fails_closed_without_retry(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt, drift=True)
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["core_verification"] == "VERIFIED"
    assert result["reason_codes"] == ["GITHUB_ACQUISITION_DRIFT"]
    assert port.calls == 2


def test_acquisition_failure_never_reports_verified_for_unsigned_receipt(
    verified_repo_and_receipt,
):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt, drift=True)

    result = verify_code_change_evidence(_args(receipt), github_port=port)

    assert result["receipt_integrity"] == "VALID"
    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["core_verification"] == "NOT_AVAILABLE"
    assert result["reason_codes"] == ["GITHUB_ACQUISITION_DRIFT", RECEIPT_NOT_AUTHENTICATED]


def test_permission_denied_is_unverifiable_not_absence(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    port = FakeGitHubPort(repo, receipt, permission_denied=True)
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

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


def test_untrusted_worktree_config_receipt_is_unverifiable(tmp_path: Path):
    repo = tmp_path / "untrusted"
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
    # Never-committed, caller-chosen config with a no-op verifier.
    init_repository(
        repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        verifier_command=(sys.executable, "-c", "pass"),
    )
    receipt = json.loads(check_repository(repo)["receipt_path"].read_text(encoding="utf-8"))
    assert receipt["config_source"]["kind"] == "worktree"
    # Even a correctly signed receipt is untrusted when its config was not base-ref.
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(
        arguments, github_port=FakeGitHubPort(repo, receipt), authenticator=authenticator
    )

    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["core_verification"] != "VERIFIED"
    assert result["reason_codes"] == ["RECEIPT_CONFIG_SOURCE_UNTRUSTED"]


def test_forged_base_ref_config_source_with_wrong_commit_is_unverifiable(
    verified_repo_and_receipt,
):
    from product.clients.local_golden_path import _receipt_hash

    repo, receipt = verified_repo_and_receipt
    receipt["config_source"] = {**receipt["config_source"], "commit": "0" * 40}
    receipt["receipt_hash"] = _receipt_hash(receipt)
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(
        arguments, github_port=FakeGitHubPort(repo, receipt), authenticator=authenticator
    )

    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["core_verification"] == "NOT_AVAILABLE"
    assert result["reason_codes"] == ["RECEIPT_CONFIG_SOURCE_UNTRUSTED"]


def _forged_receipt(tmp_path: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Issue #231 forgery: relabel a worktree-config receipt as base-ref and re-hash.

    Returns the repository, the genuine (worktree-config) receipt and the forgery
    whose ``config_source`` names the current base commit.
    """
    from product.clients.local_golden_path import _receipt_hash

    repo = tmp_path / "forged"
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
    # Never-committed, caller-chosen config with a no-op verifier.
    init_repository(
        repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        verifier_command=(sys.executable, "-c", "pass"),
    )
    genuine = json.loads(check_repository(repo)["receipt_path"].read_text(encoding="utf-8"))
    assert genuine["config_source"]["kind"] == "worktree"
    forged = json.loads(json.dumps(genuine))
    forged["config_source"] = {
        "kind": "base-ref",
        "ref": "main",
        "commit": genuine["source_revision"].removeprefix("git-commit:"),
        "blob": "0" * 40,
        "worktree_config_hash": genuine["config_hash"],
        "config_drift": False,
    }
    forged["receipt_hash"] = _receipt_hash(forged)
    return repo, genuine, forged


def _assert_not_authenticated(result: dict[str, Any], reason: str = RECEIPT_NOT_AUTHENTICATED):
    assert result["receipt_integrity"] == "VALID"
    assert result["evidence_applicability"] == "UNVERIFIABLE"
    assert result["core_verification"] == "NOT_AVAILABLE"
    assert result["reason_codes"] == [reason]


def test_rehashed_receipt_claiming_current_base_is_not_authenticated(tmp_path: Path):
    """#231 acceptance (1): a re-hashed forged receipt naming the real base is UNVERIFIABLE.

    The receipt hash is an unkeyed SHA-256 and ``config_source`` is self-asserted,
    so the forgery is self-consistent (``receipt_integrity`` VALID). Before #231 it
    returned APPLIES / VERIFIED; without an authenticated Sigstore bundle it must not.
    """
    repo, genuine, forged = _forged_receipt(tmp_path)
    port = FakeGitHubPort(repo, forged)
    assert forged["config_source"]["commit"] == port.base_sha

    # Exactly the Issue's steps, default authenticator, no bundle.
    _assert_not_authenticated(verify_code_change_evidence(_args(forged), github_port=port))

    # A genuine signature over the original bytes does not transfer to the forgery.
    authenticator = FakeAuthenticator()
    genuine_signature = authenticator.sign(genuine)
    _assert_not_authenticated(
        verify_code_change_evidence(
            _args(forged, genuine_signature), github_port=port, authenticator=authenticator
        )
    )
    assert authenticator.calls == []  # rejected before any signature check

    # The forger's own bytes with a (shape-valid) bundle do not verify either.
    _assert_not_authenticated(
        verify_code_change_evidence(
            _args(forged, _signature(_receipt_bytes(forged))),
            github_port=port,
            authenticator=authenticator,
        )
    )
    assert authenticator.calls == [(_receipt_bytes(forged), _DEMO_POLICY)]


def test_missing_bundle_is_not_authenticated(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    authenticator = FakeAuthenticator()
    authenticator.sign(receipt)

    result = verify_code_change_evidence(
        _args(receipt), github_port=FakeGitHubPort(repo, receipt), authenticator=authenticator
    )

    _assert_not_authenticated(result)
    assert authenticator.calls == []


def test_bundle_for_different_bytes_is_not_authenticated(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    authenticator = FakeAuthenticator()
    other = json.loads(json.dumps(receipt))
    other["timestamp"] = "2000-01-01T00:00:00+00:00"
    signed_other = authenticator.sign(other)

    # Supplying the other receipt's signed bytes: they do not encode this receipt.
    result = verify_code_change_evidence(
        _args(receipt, signed_other),
        github_port=FakeGitHubPort(repo, receipt),
        authenticator=authenticator,
    )
    _assert_not_authenticated(result)

    # Same JSON value, different bytes: the bundle signs exact bytes, not the value.
    reformatted = json.dumps(receipt).encode("utf-8")
    result = verify_code_change_evidence(
        _args(receipt, _signature(reformatted)),
        github_port=FakeGitHubPort(repo, receipt),
        authenticator=authenticator,
    )
    _assert_not_authenticated(result)
    assert authenticator.calls[-1][0] == reformatted


@pytest.mark.parametrize(
    ("signed", "supplied"),
    [
        (b'{"a": true}', {"a": 1}),
        (b'{"a": 1}', {"a": 1.0}),
        (b'{"a": 1, "a": 2}', {"a": 1}),
    ],
)
def test_signed_bytes_must_encode_the_exact_receipt_value(signed, supplied):
    authenticator = FakeAuthenticator()
    authenticator.signed[signed] = _DEMO_POLICY

    outcome = authenticate_receipt(
        supplied, _signature(signed), policy=_DEMO_POLICY, authenticator=authenticator
    )

    assert outcome.status == NOT_AUTHENTICATED
    assert authenticator.calls == []
    assert authenticate_receipt(
        json.loads(signed), _signature(signed), policy=_DEMO_POLICY, authenticator=authenticator
    ).authenticated


def test_wrong_signer_identity_is_not_authenticated(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    authenticator = FakeAuthenticator()
    other_workflow = github_workflow_signer_policy("example", "demo", workflow_file="other.yml")
    signature = authenticator.sign(receipt, other_workflow)
    port = FakeGitHubPort(repo, receipt)

    # Signed by another workflow of the same repository: default policy rejects it.
    _assert_not_authenticated(
        verify_code_change_evidence(
            _args(receipt, signature), github_port=port, authenticator=authenticator
        )
    )
    # The host (never the tool caller) may name that workflow as the signer.
    accepted = verify_code_change_evidence(
        _args(receipt, signature),
        github_port=port,
        authenticator=authenticator,
        signer_policy=other_workflow,
    )
    assert accepted["evidence_applicability"] == "APPLIES"
    assert accepted["core_verification"] == "VERIFIED"

    # Signed by the same workflow file in another repository: rejected.
    foreign = github_workflow_signer_policy("attacker", "demo")
    _assert_not_authenticated(
        verify_code_change_evidence(
            _args(receipt, authenticator.sign(receipt, foreign)),
            github_port=port,
            authenticator=authenticator,
        )
    )
    with pytest.raises(ValueError, match="subject repository"):
        verify_code_change_evidence(
            _args(receipt, signature), github_port=port, signer_policy=foreign
        )


def test_signer_policy_rejects_identity_outside_its_repository():
    with pytest.raises(ValueError):
        ReceiptSignerPolicy(
            identity="https://github.com/attacker/demo/.github/workflows/x.yml@refs/heads/main",
            issuer="https://token.actions.githubusercontent.com",
            repository="example/demo",
        )
    with pytest.raises(ValueError):
        ReceiptSignerPolicy(
            identity="https://github.com/example/demo/.github/workflows/x.yml@refs/heads/main",
            issuer="https://accounts.google.com",
            repository="example/demo",
        )
    with pytest.raises(ValueError):
        github_workflow_signer_policy("example", "demo", workflow_file="../x.yml")


@pytest.mark.parametrize("status", [UNAVAILABLE, "SOMETHING_ELSE"])
def test_authenticator_unavailable_or_unknown_is_never_verified(verified_repo_and_receipt, status):
    repo, receipt = verified_repo_and_receipt
    authenticator = FakeAuthenticator(status=status)
    signature = FakeAuthenticator().sign(receipt)

    result = verify_code_change_evidence(
        _args(receipt, signature), github_port=FakeGitHubPort(repo, receipt), authenticator=authenticator
    )

    _assert_not_authenticated(
        result,
        RECEIPT_AUTHENTICATION_UNAVAILABLE if status == UNAVAILABLE else RECEIPT_NOT_AUTHENTICATED,
    )


def test_authenticator_crash_is_unavailable_not_verified(verified_repo_and_receipt):
    class Exploding:
        def authenticate(self, **_: object) -> ReceiptAuthentication:
            raise RuntimeError("boom")

    repo, receipt = verified_repo_and_receipt
    result = verify_code_change_evidence(
        _args(receipt, FakeAuthenticator().sign(receipt)),
        github_port=FakeGitHubPort(repo, receipt),
        authenticator=Exploding(),
    )

    _assert_not_authenticated(result, RECEIPT_AUTHENTICATION_UNAVAILABLE)


def test_default_authenticator_without_sigstore_is_unavailable(
    verified_repo_and_receipt, monkeypatch: pytest.MonkeyPatch
):
    import importlib

    import product.clients.receipt_authentication as receipt_authentication

    real_import = importlib.import_module

    def no_sigstore(name: str, *args: Any, **kwargs: Any):
        if name.split(".")[0] == "sigstore":
            raise ModuleNotFoundError(name=name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(receipt_authentication.importlib, "import_module", no_sigstore)
    outcome = SigstoreReceiptAuthenticator().authenticate(
        receipt_bytes=b"{}", bundle_json=b"{}", policy=_DEMO_POLICY
    )
    assert outcome.status == UNAVAILABLE

    repo, receipt = verified_repo_and_receipt
    result = verify_code_change_evidence(
        _args(receipt, FakeAuthenticator().sign(receipt)),
        github_port=FakeGitHubPort(repo, receipt),
    )
    _assert_not_authenticated(result, RECEIPT_AUTHENTICATION_UNAVAILABLE)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda sig: {**sig, "sigstore_bundle": {}}, id="empty-bundle"),
        pytest.param(
            lambda sig: {**sig, "sigstore_bundle": {**sig["sigstore_bundle"], "mediaType": "x"}},
            id="wrong-media-type",
        ),
        pytest.param(
            lambda sig: {
                **sig,
                "sigstore_bundle": {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "verificationMaterial": {},
                    "dsseEnvelope": {"payload": "e30="},
                },
            },
            id="dsse-envelope",
        ),
        pytest.param(lambda sig: {**sig, "receipt_base64": "not base64!"}, id="bad-base64"),
        pytest.param(
            lambda sig: {**sig, "receipt_base64": base64.b64encode(b"\xff\xfe").decode()},
            id="non-json-bytes",
        ),
    ],
)
def test_malformed_signature_material_is_not_authenticated(verified_repo_and_receipt, mutate):
    repo, receipt = verified_repo_and_receipt
    authenticator = FakeAuthenticator()
    signature = mutate(authenticator.sign(receipt))

    result = verify_code_change_evidence(
        _args(receipt, signature), github_port=FakeGitHubPort(repo, receipt), authenticator=authenticator
    )

    _assert_not_authenticated(result)
    assert authenticator.calls == []


@pytest.mark.parametrize(
    "receipt_signature",
    [
        "bundle",
        {"receipt_base64": "e30="},
        {"receipt_base64": "e30=", "sigstore_bundle": {}, "identity": "x"},
        {"receipt_base64": "", "sigstore_bundle": {}},
        {"receipt_base64": "e30=", "sigstore_bundle": []},
    ],
)
def test_receipt_signature_schema_violations_are_rejected(
    verified_repo_and_receipt, receipt_signature
):
    repo, receipt = verified_repo_and_receipt
    with pytest.raises(ValueError):
        verify_code_change_evidence(
            _args(receipt, receipt_signature), github_port=FakeGitHubPort(repo, receipt)
        )


def test_receipt_signature_without_receipt_is_rejected(verified_repo_and_receipt):
    repo, receipt = verified_repo_and_receipt
    with pytest.raises(ValueError, match="requires receipt"):
        verify_code_change_evidence(
            _args(None, FakeAuthenticator().sign(receipt)),
            github_port=FakeGitHubPort(repo, receipt),
        )
