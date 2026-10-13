"""Live PR state preflight for the issue gate (#250).

Queued or retried gate runs often start after the PR merged and auto-closed its Issue.
The gate then emits a neutral ``PR_ALREADY_CLOSED_SKIPPED`` record instead of a noisy
``ISSUE_NOT_OPEN`` failure. ``receipt-verify`` accepts that record only when the live PR
is merged at exactly the run's head. A closed Issue on an open PR is still a failure,
and a closed Issue alone is never success.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from product.clients import cli, pr_state
from product.clients.issue_golden_path import check_issue, init_issue_binding
from product.clients.local_golden_path import LocalCheckError, init_repository

REPO = "example/project"
HEAD = "a" * 40
OTHER_HEAD = "b" * 40
MERGE = "c" * 40


def _pr(
    *,
    state: str = "open",
    merged: bool = False,
    head: str = HEAD,
    number: int = 7,
) -> dict[str, Any]:
    return {
        "number": number,
        "state": state,
        "merged": merged,
        "merged_at": "2026-10-13T00:00:00Z" if merged else None,
        "merge_commit_sha": MERGE if merged else None,
        "head": {"sha": head},
    }


def _reader(payload: dict[str, Any]) -> pr_state.PullRequestReader:
    def read(repo: str, number: int) -> dict[str, Any]:
        assert (repo, number) == (REPO, 7)
        return payload

    return read


# --------------------------------------------------------------------------- gate mode


def test_gate_open_pr_proceeds_to_issue_binding() -> None:
    record = pr_state.gate_preflight(REPO, 7, HEAD, reader=_reader(_pr()))
    assert record["outcome"] == pr_state.PROCEED
    assert record["observed_state"] == "open"


def test_gate_merged_pr_at_same_head_is_neutral_skip_not_pass() -> None:
    record = pr_state.gate_preflight(
        REPO, 7, HEAD, reader=_reader(_pr(state="closed", merged=True))
    )
    assert record["outcome"] == pr_state.PR_ALREADY_CLOSED_SKIPPED
    assert record["observed_state"] == "merged"
    assert record["head_matches"] is True
    # Never an evidence verdict: no VERIFIED, no receipt claim.
    assert record["evidence_status"] == "NOT_EVALUATED"
    assert "VERIFIED" not in json.dumps(record)
    assert record["schema"] == pr_state.PR_STATE_SCHEMA


def test_gate_closed_unmerged_pr_is_neutral_skip() -> None:
    record = pr_state.gate_preflight(REPO, 7, HEAD, reader=_reader(_pr(state="closed")))
    assert record["outcome"] == pr_state.PR_ALREADY_CLOSED_SKIPPED
    assert record["observed_state"] == "closed_unmerged"
    assert record["evidence_status"] == "NOT_EVALUATED"


def test_gate_merged_pr_at_other_head_records_mismatch() -> None:
    record = pr_state.gate_preflight(
        REPO, 7, HEAD, reader=_reader(_pr(state="closed", merged=True, head=OTHER_HEAD))
    )
    assert record["outcome"] == pr_state.PR_ALREADY_CLOSED_SKIPPED
    assert record["head_matches"] is False
    assert record["observed_head_sha"] == OTHER_HEAD


# --------------------------------------------------------------------------- verify mode


def test_verify_accepts_skip_only_for_merged_pr_at_same_head() -> None:
    record = pr_state.verify_skip(REPO, 7, HEAD, reader=_reader(_pr(state="closed", merged=True)))
    assert record["outcome"] == pr_state.PR_ALREADY_CLOSED_SKIPPED
    assert record["skip_accepted"] is True
    assert record["evidence_status"] == "NOT_EVALUATED"
    assert record["merge_commit_sha"] == MERGE


def test_verify_rejects_merged_pr_at_different_head() -> None:
    with pytest.raises(LocalCheckError) as raised:
        pr_state.verify_skip(
            REPO, 7, HEAD, reader=_reader(_pr(state="closed", merged=True, head=OTHER_HEAD))
        )
    assert raised.value.reason_code == "PR_SKIP_REJECTED_HEAD_MISMATCH"


def test_verify_rejects_closed_unmerged_pr() -> None:
    with pytest.raises(LocalCheckError) as raised:
        pr_state.verify_skip(REPO, 7, HEAD, reader=_reader(_pr(state="closed")))
    assert raised.value.reason_code == "PR_SKIP_REJECTED_NOT_MERGED"


def test_verify_rejects_skip_claim_for_open_pr() -> None:
    with pytest.raises(LocalCheckError) as raised:
        pr_state.verify_skip(REPO, 7, HEAD, reader=_reader(_pr()))
    assert raised.value.reason_code == "PR_SKIP_REJECTED_NOT_MERGED"


@pytest.mark.parametrize(
    "payload",
    [
        {**_pr(state="closed", merged=True), "number": 8},
        {**_pr(state="closed", merged=True), "merged": "true"},
        {**_pr(state="closed", merged=True), "state": "open"},  # merged but open: incoherent
        {**_pr(state="closed", merged=True), "head": {"sha": "short"}},
        {**_pr(state="closed", merged=True), "head": None},
        {**_pr(state="closed", merged=True), "merge_commit_sha": None},
        {**_pr(state="closed", merged=True), "state": "draft"},
        {**_pr(), "state": "draft"},  # unknown state, merged=false: never "closed_unmerged"
        {**_pr(state="closed"), "state": "merged"},
        [],
    ],
)
def test_malformed_pr_payload_fails_closed(payload: Any) -> None:
    for call in (pr_state.gate_preflight, pr_state.verify_skip):
        with pytest.raises(LocalCheckError) as raised:
            call(REPO, 7, HEAD, reader=lambda _r, _n, p=payload: p)
        assert raised.value.reason_code == "PR_STATE_MALFORMED"


def test_invalid_expected_head_or_number_fails_closed() -> None:
    with pytest.raises(LocalCheckError) as raised:
        pr_state.gate_preflight(REPO, 7, "HEAD", reader=_reader(_pr()))
    assert raised.value.reason_code == "PR_STATE_INPUT_INVALID"
    with pytest.raises(LocalCheckError) as raised:
        pr_state.verify_skip(REPO, 0, HEAD, reader=_reader(_pr()))
    assert raised.value.reason_code == "PR_STATE_INPUT_INVALID"


# --------------------------------------------------------------------------- API failure


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _http_error(code: int, body: bytes = b"{}") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/x",
        code,
        "error",
        {},
        io.BytesIO(body),  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (_http_error(404), "PR_STATE_NOT_FOUND"),
        (_http_error(401), "PR_STATE_ACCESS_DENIED"),
        (_http_error(500), "PR_STATE_FETCH_FAILED"),
        (urllib.error.URLError("down"), "PR_STATE_FETCH_FAILED"),
        (TimeoutError("slow"), "PR_STATE_FETCH_FAILED"),
    ],
)
def test_api_failure_fails_closed_in_both_modes(
    monkeypatch: pytest.MonkeyPatch, error: BaseException, reason: str
) -> None:
    def boom(*_args: object, **_kwargs: object) -> Any:
        raise error

    monkeypatch.setattr(pr_state.urllib.request, "urlopen", boom)
    for call in (pr_state.gate_preflight, pr_state.verify_skip):
        with pytest.raises(LocalCheckError) as raised:
            call(REPO, 7, HEAD)
        assert raised.value.reason_code == reason


def test_api_rate_limit_exhaustion_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def limited(*_args: object, **_kwargs: object) -> Any:
        raise urllib.error.HTTPError(
            "https://api.github.com/x",
            429,
            "rate limited",
            {"Retry-After": "3600"},  # type: ignore[arg-type]
            io.BytesIO(b"rate limit exceeded"),
        )

    monkeypatch.setattr(pr_state.urllib.request, "urlopen", limited)
    with pytest.raises(LocalCheckError) as raised:
        pr_state.gate_preflight(REPO, 7, HEAD)
    assert raised.value.reason_code == "PR_STATE_RATE_LIMIT_EXHAUSTED"


def test_default_reader_reads_pulls_endpoint_with_token(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake(request: Any, timeout: float) -> _Response:
        seen["url"] = request.full_url
        seen["auth"] = request.get_header("Authorization")
        return _Response(json.dumps(_pr(state="closed", merged=True)).encode())

    monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    monkeypatch.setattr(pr_state.urllib.request, "urlopen", fake)
    record = pr_state.verify_skip(REPO, 7, HEAD)
    assert record["skip_accepted"] is True
    assert seen["url"] == "https://api.github.com/repos/example/project/pulls/7"
    assert seen["auth"] == "Bearer t0ken"

    # GitHub Enterprise Server: the Actions-provided API base is honoured.
    monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example.test/api/v3/")
    pr_state.gate_preflight(REPO, 7, HEAD)
    assert seen["url"] == "https://ghe.example.test/api/v3/repos/example/project/pulls/7"


@pytest.mark.parametrize(
    "api_url",
    [
        "http://api.github.com",
        "file:///etc/passwd",
        "https://user:pw@api.github.com",
        "https://api.github.com?x=1",
        "https://",
    ],
)
def test_untrusted_api_url_fails_closed(monkeypatch: pytest.MonkeyPatch, api_url: str) -> None:
    def never(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("no request may be sent")

    monkeypatch.setenv("GITHUB_API_URL", api_url)
    monkeypatch.setattr(pr_state.urllib.request, "urlopen", never)
    with pytest.raises(LocalCheckError) as raised:
        pr_state.gate_preflight(REPO, 7, HEAD)
    assert raised.value.reason_code == "PR_STATE_INPUT_INVALID"


# --------------------------------------------------------------------------- CLI


def _cli(monkeypatch: pytest.MonkeyPatch, payload: Any, *argv: str) -> tuple[int, str, str]:
    monkeypatch.setattr(pr_state, "_default_pull_request_reader", lambda _r, _n: payload)
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    code = cli.main(["pr-state", "--github-repo", REPO, "--pr", "7", "--expect-head", HEAD, *argv])
    return code, out.getvalue(), err.getvalue()


def test_cli_gate_mode_prints_json_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    code, out, _err = _cli(monkeypatch, _pr(state="closed", merged=True), "--mode", "gate")
    assert code == 0
    assert json.loads(out)["outcome"] == pr_state.PR_ALREADY_CLOSED_SKIPPED
    code, out, _err = _cli(monkeypatch, _pr(), "--mode", "gate")
    assert code == 0
    assert json.loads(out)["outcome"] == pr_state.PROCEED


def test_cli_verify_mode_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    code, out, _err = _cli(monkeypatch, _pr(state="closed", merged=True), "--mode", "verify-skip")
    assert code == 0 and json.loads(out)["skip_accepted"] is True
    code, out, err = _cli(
        monkeypatch, _pr(state="closed", merged=True, head=OTHER_HEAD), "--mode", "verify-skip"
    )
    assert code != 0 and out == "" and "PR_SKIP_REJECTED_HEAD_MISMATCH" in err
    code, out, err = _cli(monkeypatch, _pr(state="closed"), "--mode", "verify-skip")
    assert code != 0 and out == "" and "PR_SKIP_REJECTED_NOT_MERGED" in err


def test_cli_rejects_non_hex_head(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    with pytest.raises(SystemExit) as raised:
        cli.main(
            ["pr-state", "--github-repo", REPO, "--pr", "7", "--expect-head", "x", "--mode", "gate"]
        )
    assert raised.value.code != 0


# ------------------------------------------------- closed Issue is never success by itself


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)


def test_open_pr_with_closed_issue_still_fails_issue_not_open(tmp_path: Path) -> None:
    """The preflight only short-circuits on a closed *PR*; an open PR keeps the old rule."""
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
    issue = {
        "number": 85,
        "title": "Bound change",
        "body": "Change VALUE",
        "state": "open",
        "author_association": "OWNER",
        "user": {"login": "maintainer"},
    }
    init_issue_binding(repo, issue_number=85, issue_reader=lambda _r, _n: issue)

    record = pr_state.gate_preflight(REPO, 7, HEAD, reader=_reader(_pr()))
    assert record["outcome"] == pr_state.PROCEED

    closed = {**issue, "state": "closed"}
    with pytest.raises(LocalCheckError) as raised:
        check_issue(repo, issue_number=85, issue_reader=lambda _r, _n: closed)
    assert raised.value.reason_code == "ISSUE_NOT_OPEN"
    with pytest.raises(LocalCheckError) as raised:
        init_issue_binding(repo, issue_number=85, issue_reader=lambda _r, _n: closed, force=True)
    assert raised.value.reason_code == "ISSUE_NOT_OPEN"

    # Nor can a verify-side skip be claimed while the PR is still open.
    with pytest.raises(LocalCheckError):
        pr_state.verify_skip(REPO, 7, HEAD, reader=_reader(_pr()))
