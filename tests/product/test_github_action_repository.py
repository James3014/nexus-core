from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from product.clients import github_action
from product.clients.github_action import main, run_repository_check
from product.clients.local_golden_path import init_repository


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


@pytest.fixture
def external_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "external"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "external@example.test")
    _git(repo, "config", "user.name", "External User")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_value():\n    assert VALUE > 0\n", encoding="utf-8"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    _git(repo, "checkout", "-b", "feature")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "change")
    init_repository(
        repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        verifier_command=(sys.executable, "-m", "pytest", "-q"),
    )
    return repo


def _write_event(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _set_push_environment(monkeypatch: pytest.MonkeyPatch, event_path: Path) -> None:
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/example")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))


def test_legacy_action_still_rejects_hosted_before_token_read(monkeypatch, tmp_path):
    token_read = False

    def fail_if_token_read(_path: str) -> str:
        nonlocal token_read
        token_read = True
        raise AssertionError("token must not be read")

    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setattr(github_action, "_get_token", fail_if_token_read)

    with pytest.raises(SystemExit) as raised:
        github_action.run_action(tmp_path / "request.json", tmp_path / "token")

    assert raised.value.code == 78
    assert token_read is False


def test_repository_check_rejects_github_hosted_before_verifier(monkeypatch, tmp_path):
    verifier_started = False

    def fail_if_started(_repo: str | Path):
        nonlocal verifier_started
        verifier_started = True
        raise AssertionError("verifier must not start")

    event_path = _write_event(tmp_path, {"repository": {"full_name": "octo/example"}})
    _set_push_environment(monkeypatch, event_path)
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setattr(github_action, "check_repository", fail_if_started)

    with pytest.raises(SystemExit) as raised:
        run_repository_check(tmp_path)

    assert raised.value.code == 78
    assert verifier_started is False


def test_repository_check_rejects_fork_pr_before_verifier(monkeypatch, tmp_path):
    verifier_started = False

    def fail_if_started(_repo: str | Path):
        nonlocal verifier_started
        verifier_started = True
        raise AssertionError("verifier must not start")

    event_path = _write_event(
        tmp_path,
        {
            "repository": {"full_name": "octo/example"},
            "pull_request": {
                "base": {"repo": {"full_name": "octo/example"}},
                "head": {"repo": {"full_name": "attacker/fork", "fork": True}},
            },
        },
    )
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/example")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setattr(github_action, "check_repository", fail_if_started)

    with pytest.raises(SystemExit) as raised:
        run_repository_check(tmp_path)

    assert raised.value.code == 78
    assert verifier_started is False


@pytest.mark.parametrize(
    ("repository", "payload"),
    [
        (None, {"repository": {"full_name": "octo/example"}}),
        ("octo/example/extra", {"repository": {"full_name": "octo/example/extra"}}),
        ("octo/example", {}),
        ("octo/example", {"repository": {"full_name": "other/example"}}),
    ],
)
def test_repository_check_rejects_missing_or_ambiguous_identity_before_verifier(
    monkeypatch, tmp_path, repository, payload
):
    verifier_started = False

    def fail_if_started(_repo: str | Path):
        nonlocal verifier_started
        verifier_started = True
        raise AssertionError("verifier must not start")

    event_path = _write_event(tmp_path, payload)
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    if repository is None:
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    else:
        monkeypatch.setenv("GITHUB_REPOSITORY", repository)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setattr(github_action, "check_repository", fail_if_started)

    with pytest.raises(SystemExit) as raised:
        run_repository_check(tmp_path)

    assert raised.value.code == 78
    assert verifier_started is False


@pytest.mark.parametrize("case", ["missing-event-path", "malformed-event", "unsupported-event"])
def test_repository_check_rejects_bad_event_context_before_verifier(
    monkeypatch, tmp_path, case
):
    verifier_started = False

    def fail_if_started(_repo: str | Path):
        nonlocal verifier_started
        verifier_started = True
        raise AssertionError("verifier must not start")

    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/example")
    monkeypatch.setattr(github_action, "check_repository", fail_if_started)
    if case == "missing-event-path":
        monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    elif case == "malformed-event":
        event_path = tmp_path / "event.json"
        event_path.write_text("{not-json", encoding="utf-8")
        monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    else:
        event_path = _write_event(tmp_path, {"repository": {"full_name": "octo/example"}})
        monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))

    with pytest.raises(SystemExit) as raised:
        run_repository_check(tmp_path)

    assert raised.value.code == 78
    assert verifier_started is False


def test_repository_check_rejects_ambiguous_same_repo_pr_before_verifier(
    monkeypatch, tmp_path
):
    verifier_started = False

    def fail_if_started(_repo: str | Path):
        nonlocal verifier_started
        verifier_started = True
        raise AssertionError("verifier must not start")

    event_path = _write_event(
        tmp_path,
        {
            "repository": {"full_name": "octo/example"},
            "pull_request": {
                "base": {"repo": {"full_name": "octo/example"}},
                "head": {"repo": {"full_name": "octo/example"}},
            },
        },
    )
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/example")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setattr(github_action, "check_repository", fail_if_started)

    with pytest.raises(SystemExit) as raised:
        run_repository_check(tmp_path)

    assert raised.value.code == 78
    assert verifier_started is False


@pytest.mark.parametrize("event_name", ["push", "pull_request"])
def test_trusted_same_repository_event_runs_real_g1_check_to_verified(
    monkeypatch, tmp_path, external_repo, event_name
):
    payload: dict[str, object] = {"repository": {"full_name": "octo/example"}}
    if event_name == "pull_request":
        payload["pull_request"] = {
            "base": {"repo": {"full_name": "octo/example"}},
            "head": {"repo": {"full_name": "octo/example", "fork": False}},
        }
    event_path = _write_event(tmp_path, payload)
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/example")
    monkeypatch.setenv("GITHUB_EVENT_NAME", event_name)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))

    result = run_repository_check(external_repo)

    assert result["result"]["status"] == "VERIFIED"
    assert result["result"]["certification"] is None
    receipt_path = Path(result["outputs"]["receipt-file"])
    assert receipt_path.is_file()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["core_response"]["verification"]["status"] == "VERIFIED"
    assert receipt["core_response"]["certification"] is None
    serialized_config = json.dumps(receipt["inputs"]["config"]).lower()
    assert all(word not in serialized_config for word in ("executor", "model", "agent"))


def test_repository_check_mode_does_not_require_or_read_token(
    monkeypatch, tmp_path, external_repo
):
    event_path = _write_event(tmp_path, {"repository": {"full_name": "octo/example"}})
    _set_push_environment(monkeypatch, event_path)
    monkeypatch.delenv("NEXUS_CORE_TOKEN", raising=False)
    monkeypatch.setattr(
        github_action,
        "_get_token",
        lambda _path: (_ for _ in ()).throw(AssertionError("token must not be read")),
    )

    assert main(["--repository-check", "--repo", str(external_repo)]) == 0


def test_repository_check_failure_verdict_returns_nonzero(monkeypatch, tmp_path, external_repo):
    event_path = _write_event(tmp_path, {"repository": {"full_name": "octo/example"}})
    _set_push_environment(monkeypatch, event_path)
    (external_repo / "app.py").write_text("VALUE = -1\n", encoding="utf-8")

    result = run_repository_check(external_repo)

    assert result["result"]["status"] == "FAILED_VERIFICATION"
    assert result["result"]["transport_error"] is False
    assert main(["--repository-check", "--repo", str(external_repo)]) == 1


def test_action_modes_are_mutually_exclusive_and_legacy_still_requires_token_file(tmp_path):
    with pytest.raises(SystemExit) as raised:
        main(["--request-file", str(tmp_path / "request.json"), "--repository-check"])
    assert raised.value.code == 2

    with pytest.raises(SystemExit) as raised:
        main(["--request-file", str(tmp_path / "request.json")])
    assert raised.value.code == 2
