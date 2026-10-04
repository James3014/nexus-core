from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from product.clients.issue_golden_path import check_issue, init_issue_binding
from product.clients.local_golden_path import LocalCheckError, init_repository
from product.protocol.generic_verification import canonical_hash


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.fixture
def issue_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.test")
    _git(repo, "config", "user.name", "Test User")
    _git(repo, "remote", "add", "origin", "https://github.com/example/project.git")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "base")
    init_repository(
        repo,
        base_ref="main",
        allowed_patterns=("app.py",),
        verifier_command=(sys.executable, "-c", "raise SystemExit(0)"),
    )
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    return repo


def _issue(*, body: str = "Change VALUE", state: str = "open") -> dict[str, object]:
    return {
        "number": 85,
        "title": "Bound change",
        "body": body,
        "state": state,
        "updated_at": "2026-10-05T00:00:00Z",
    }


def test_issue_init_and_check_bind_requirements_to_issue(issue_repo: Path) -> None:
    def reader(repo: str, number: int) -> dict[str, object]:
        return _issue()

    binding_path = init_issue_binding(issue_repo, issue_number=85, issue_reader=reader)
    binding = json.loads(binding_path.read_text(encoding="utf-8"))

    result = check_issue(issue_repo, issue_number=85, issue_reader=reader)

    assert result["status"] == "VERIFIED"
    assert result["github_repository"] == "example/project"
    assert result["issue_number"] == 85
    assert result["claim_ceiling"] == "ISSUE_VERIFIED_NOT_RELEASED"

    receipt = json.loads(result["receipt_path"].read_text(encoding="utf-8"))
    context = receipt["inputs"]["requirements_context"]
    assert context["binding_hash"] == binding["binding_hash"]
    expected = canonical_hash(
        {"config_hash": receipt["config_hash"], "context": context}
    )
    assert (
        receipt["inputs"]["request"]["acceptance_contract"]["requirements_hash"]
        == expected
    )


def test_issue_check_requires_rebind_after_contract_drift(issue_repo: Path) -> None:
    init_issue_binding(issue_repo, issue_number=85, issue_reader=lambda repo, number: _issue())

    with pytest.raises(LocalCheckError) as raised:
        check_issue(
            issue_repo,
            issue_number=85,
            issue_reader=lambda repo, number: _issue(body="Changed contract"),
        )

    assert raised.value.reason_code == "ISSUE_REBIND_REQUIRED"


def test_issue_check_rejects_closed_issue(issue_repo: Path) -> None:
    init_issue_binding(issue_repo, issue_number=85, issue_reader=lambda repo, number: _issue())

    with pytest.raises(LocalCheckError) as raised:
        check_issue(
            issue_repo,
            issue_number=85,
            issue_reader=lambda repo, number: _issue(state="closed"),
        )

    assert raised.value.reason_code == "ISSUE_NOT_OPEN"


def test_issue_binding_tamper_fails_closed(issue_repo: Path) -> None:
    path = init_issue_binding(issue_repo, issue_number=85, issue_reader=lambda repo, number: _issue())
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["issue_contract"]["title"] = "tampered"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(LocalCheckError) as raised:
        check_issue(issue_repo, issue_number=85, issue_reader=lambda repo, number: _issue())

    assert raised.value.reason_code == "ISSUE_BINDING_TAMPERED"


def test_issue_init_rejects_repository_mismatch(issue_repo: Path) -> None:
    with pytest.raises(LocalCheckError) as raised:
        init_issue_binding(
            issue_repo,
            issue_number=85,
            github_repo="other/project",
            issue_reader=lambda repo, number: _issue(),
        )

    assert raised.value.reason_code == "GITHUB_REPOSITORY_MISMATCH"
