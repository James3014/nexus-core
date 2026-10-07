from __future__ import annotations

import io
import json
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

from product.clients import issue_golden_path as issue_gp
from product.clients.issue_golden_path import check_issue, init_issue_binding
from product.clients.local_golden_path import (
    LocalCheckError,
    init_repository,
    validate_verification_receipt,
)
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
    identity = issue_gp._verification_contract_identity(issue_repo)["config_file_sha256"]

    def reader(repo: str, number: int) -> dict[str, object]:
        return _issue(
            body=(
                "Change VALUE\n\n"
                f"<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: {identity} -->"
            )
        )

    binding_path = init_issue_binding(issue_repo, issue_number=85, issue_reader=reader)
    binding = json.loads(binding_path.read_text(encoding="utf-8"))

    result = check_issue(issue_repo, issue_number=85, issue_reader=reader)

    assert result["status"] == "VERIFIED"
    assert result["github_repository"] == "example/project"
    assert result["issue_number"] == 85
    assert result["claim_ceiling"] == "ISSUE_VERIFIED_NOT_RELEASED"
    assert result["issue_evidence_sufficiency_status"] == "BOUND"

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


def test_issue_check_downgrades_green_repository_evidence_without_issue_sufficiency(
    issue_repo: Path,
) -> None:
    def reader(repo: str, number: int) -> dict[str, object]:
        return _issue()

    init_issue_binding(issue_repo, issue_number=85, issue_reader=reader)
    result = check_issue(issue_repo, issue_number=85, issue_reader=reader)

    assert result["status"] == "UNVERIFIABLE"
    assert result["repository_evidence_status"] == "VERIFIED"
    assert result["reason_codes"] == [issue_gp.ISSUE_EVIDENCE_UNBOUND_REASON]
    assert result["claim_ceiling"] == "REPOSITORY_EVIDENCE_VERIFIED_ISSUE_REQUIREMENTS_UNBOUND"
    receipt = json.loads(result["receipt_path"].read_text(encoding="utf-8"))
    assert receipt["outcome"]["status"] == "VERIFIED"
    assert receipt["inputs"]["requirements_context"]["evidence_sufficiency"]["status"] == "UNBOUND"
    assert validate_verification_receipt(result["receipt_path"], repo=issue_repo) == {
        "valid": True,
        "reason_codes": [],
    }


@pytest.mark.parametrize(
    ("relative_path", "content"),
    [
        ("docs/dsh-core-negative-control.txt", "unrelated docs-only negative control\n"),
        ("unrelated.py", "UNRELATED = True\n"),
    ],
)
def test_unrelated_change_with_green_generic_verifier_cannot_issue_false_green(
    issue_repo: Path,
    relative_path: str,
    content: str,
) -> None:
    (issue_repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    config = issue_repo / ".nexus-core" / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            'allowed_patterns = ["app.py"]',
            'allowed_patterns = ["**"]',
        ),
        encoding="utf-8",
    )
    target = issue_repo / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    def reader(repo: str, number: int) -> dict[str, object]:
        return _issue(body="Change app.py VALUE to 2")

    init_issue_binding(issue_repo, issue_number=85, issue_reader=reader)
    result = check_issue(issue_repo, issue_number=85, issue_reader=reader)

    assert result["repository_evidence_status"] == "VERIFIED"
    assert result["status"] == "UNVERIFIABLE"
    assert result["reason_codes"] == [issue_gp.ISSUE_EVIDENCE_UNBOUND_REASON]
    assert result["claim_ceiling"] == "REPOSITORY_EVIDENCE_VERIFIED_ISSUE_REQUIREMENTS_UNBOUND"


def test_issue_evidence_universe_binding_goes_stale_when_verification_contract_changes(
    issue_repo: Path,
) -> None:
    identity = issue_gp._verification_contract_identity(issue_repo)["config_file_sha256"]
    def reader(repo: str, number: int) -> dict[str, object]:
        return _issue(
            body=f"Change VALUE\n\n<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: {identity} -->"
        )

    init_issue_binding(issue_repo, issue_number=85, issue_reader=reader)
    config = issue_repo / ".nexus-core" / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "timeout_seconds = 300",
            "timeout_seconds = 301",
        ),
        encoding="utf-8",
    )

    with pytest.raises(LocalCheckError) as raised:
        check_issue(issue_repo, issue_number=85, issue_reader=reader)

    assert raised.value.reason_code == issue_gp.ISSUE_EVIDENCE_STALE_REASON


def test_rehashed_substituted_issue_evidence_binding_fails_closed(issue_repo: Path) -> None:
    identity = issue_gp._verification_contract_identity(issue_repo)["config_file_sha256"]
    def reader(repo: str, number: int) -> dict[str, object]:
        return _issue(
            body=f"Change VALUE\n\n<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: {identity} -->"
        )

    path = init_issue_binding(issue_repo, issue_number=85, issue_reader=reader)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["evidence_sufficiency"]["config_file_sha256"] = "sha256:" + "f" * 64
    payload["binding_hash"] = issue_gp._hash_without_binding(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(LocalCheckError) as raised:
        check_issue(issue_repo, issue_number=85, issue_reader=reader)

    assert raised.value.reason_code == "ISSUE_BINDING_TAMPERED"


def test_legacy_issue_binding_cannot_retain_strong_issue_claim(issue_repo: Path) -> None:
    path = init_issue_binding(issue_repo, issue_number=85, issue_reader=lambda repo, number: _issue())
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema"] = issue_gp.LEGACY_ISSUE_BINDING_SCHEMA
    payload["version"] = 1
    payload.pop("evidence_sufficiency")
    payload["binding_hash"] = issue_gp._hash_without_binding(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = check_issue(issue_repo, issue_number=85, issue_reader=lambda repo, number: _issue())

    assert result["status"] == "UNVERIFIABLE"
    assert result["repository_evidence_status"] == "VERIFIED"
    assert result["claim_ceiling"] == "REPOSITORY_EVIDENCE_VERIFIED_ISSUE_REQUIREMENTS_UNBOUND"


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

class _FakeHTTPResponse:
    def __init__(self, payload: object) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._raw


def _http_error(
    *,
    body: str,
    headers: dict[str, str] | None = None,
) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/repos/example/project/issues/85",
        403,
        "Forbidden",
        headers or {},
        io.BytesIO(body.encode("utf-8")),
    )


def test_default_issue_reader_retries_rate_limit_and_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    sleeps: list[float] = []

    def fake_urlopen(_request, timeout):
        nonlocal calls
        assert timeout == 15
        calls += 1
        if calls == 1:
            raise _http_error(
                body='{"message":"API rate limit exceeded for installation"}',
                headers={"X-RateLimit-Remaining": "0", "Retry-After": "0"},
            )
        return _FakeHTTPResponse(_issue())

    monkeypatch.setattr(issue_gp.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(issue_gp.time, "sleep", sleeps.append)

    result = issue_gp._default_issue_reader("example/project", 85)

    assert result["number"] == 85
    assert calls == 2
    assert sleeps == [0.0]


def test_default_issue_reader_rate_limit_exhaustion_is_not_access_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    def fake_urlopen(_request, timeout):
        raise _http_error(
            body='{"message":"API rate limit exceeded for installation"}',
            headers={"X-RateLimit-Remaining": "0", "Retry-After": "120"},
        )

    monkeypatch.setattr(issue_gp.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(issue_gp.time, "sleep", sleeps.append)

    with pytest.raises(LocalCheckError) as raised:
        issue_gp._default_issue_reader("example/project", 85)

    assert raised.value.reason_code == "ISSUE_RATE_LIMIT_EXHAUSTED"
    assert "retry_after_seconds=120.000" in raised.value.detail
    assert sleeps == []


def test_default_issue_reader_permission_403_does_not_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    def fake_urlopen(_request, timeout):
        raise _http_error(
            body='{"message":"Resource not accessible by integration"}',
            headers={"X-RateLimit-Remaining": "4999"},
        )

    monkeypatch.setattr(issue_gp.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(issue_gp.time, "sleep", sleeps.append)

    with pytest.raises(LocalCheckError) as raised:
        issue_gp._default_issue_reader("example/project", 85)

    assert raised.value.reason_code == "ISSUE_ACCESS_DENIED"
    assert sleeps == []


def test_issue_check_binds_v2_evidence_universe_and_issue_contract(issue_repo: Path) -> None:
    config = issue_repo / ".nexus-core" / "config.toml"
    config.write_text(
        "\n".join(
            [
                "version = 2",
                'base_ref = "main"',
                'allowed_patterns = ["app.py"]',
                'deletion_policy = "FORBID"',
                "universe_generation = 7",
                "materials = []",
                "",
                "[[verifiers]]",
                'id = "issue-behavior"',
                f"command = [{json.dumps(sys.executable)}, \"-c\", \"import app; assert app.VALUE == 2\"]",
                "timeout_seconds = 30",
                'logical_subject_id = "issue/behavior"',
                'evidence_kind = "test-result"',
                'requirement_mode = "REQUIRED"',
                'applicability = "APPLICABLE"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    identity = issue_gp._verification_contract_identity(issue_repo)["config_file_sha256"]

    def reader(repo: str, number: int) -> dict[str, object]:
        return _issue(
            body=(
                "VALUE must become 2\n\n"
                f"<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: {identity} -->"
            )
        )

    binding_path = init_issue_binding(issue_repo, issue_number=85, issue_reader=reader)
    binding = json.loads(binding_path.read_text(encoding="utf-8"))

    result = check_issue(issue_repo, issue_number=85, issue_reader=reader)

    assert result["status"] == "VERIFIED"
    assert result["issue_evidence_sufficiency_status"] == "BOUND"
    receipt = json.loads(result["receipt_path"].read_text(encoding="utf-8"))
    request = receipt["inputs"]["request"]
    assert receipt["schema_version"] == 2
    assert request["acceptance_contract"]["universe_generation"] == 7
    assert request["acceptance_contract"]["expected_subjects"] == [
        {
            "logical_subject_id": "issue/behavior",
            "evidence_kind": "test-result",
            "requirement_mode": "REQUIRED",
            "applicability": "APPLICABLE",
        }
    ]
    assert receipt["inputs"]["requirements_context"]["binding_hash"] == binding["binding_hash"]
    assert receipt["core_response"]["verification"]["coverage"]["entries"][0]["category"] == "COVERED"
