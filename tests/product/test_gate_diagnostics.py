"""Copy-paste remediation for Core gate failures (#243, #244).

Diagnostics only: every case below still fails closed with the same reason code
and exit status as before; the tests pin the added remediation text.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from product.clients import cli, gate_diagnostics
from product.clients import issue_golden_path as issue_gp
from product.clients.issue_golden_path import check_issue, init_issue_binding
from product.clients.local_golden_path import (
    LocalCheckError,
    _load_effective_config,
    init_repository,
)
from product.protocol.generic_verification import canonical_hash

ROOT = Path(__file__).resolve().parents[2]
SUMMARY_HEADING = "### Nexus Core gate: how to fix"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@example.test")
    _git(r, "config", "user.name", "T")
    _git(r, "remote", "add", "origin", "https://github.com/example/project.git")
    (r / "app.py").write_text("V = 1\n", encoding="utf-8")
    _git(r, "add", "app.py")
    _git(r, "commit", "-m", "base")
    init_repository(
        r,
        base_ref="main",
        allowed_patterns=("app.py",),
        verifier_command=(sys.executable, "-c", "raise SystemExit(0)"),
    )
    _git(r, "add", ".nexus-core/config.toml")
    _git(r, "commit", "-m", "config")
    (r / "app.py").write_text("V = 2\n", encoding="utf-8")
    return r


@pytest.fixture
def summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(path))
    return path


def _hash(repo: Path) -> str:
    config, _source, _worktree = _load_effective_config(repo)
    return canonical_hash(config)


def _marker(config_hash: str) -> str:
    return f"<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: {config_hash} -->"


def _issue(body: str) -> dict[str, object]:
    return {
        "number": 85,
        "title": "T",
        "body": body,
        "state": "open",
        "author_association": "OWNER",
        "user": {"login": "maintainer"},
        "updated_at": "2026-10-05T00:00:00Z",
    }


def _use_issue_body(monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    monkeypatch.setattr(issue_gp, "_default_issue_reader", lambda repo, number: _issue(body))


def _summary_blocks(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith(SUMMARY_HEADING)
    return re.findall(r"```text\n(.*?)\n```", text)


# --- pure rendering ---------------------------------------------------------------


def test_marker_line_and_remediation_strings_are_exact() -> None:
    h = "sha256:" + "a" * 64
    assert gate_diagnostics.evidence_marker_line(h) == _marker(h)
    assert gate_diagnostics.missing_evidence_universe(85, h) == (
        "ISSUE_MISSING_EVIDENCE_UNIVERSE: add this line to the body of Issue #85, "
        f"then re-run the gate: {_marker(h)}"
    )
    assert gate_diagnostics.stale_evidence_universe(85, h) == (
        "ISSUE_EVIDENCE_UNIVERSE_STALE: replace the NEXUS_CORE_EVIDENCE_UNIVERSE line in "
        f"the body of Issue #85 with this line, then re-run the gate: {_marker(h)}"
    )
    assert gate_diagnostics.malformed_evidence_universe(85, h) == (
        "ISSUE_EVIDENCE_UNIVERSE_BINDING_MALFORMED: keep exactly one "
        f"NEXUS_CORE_EVIDENCE_UNIVERSE line in the body of Issue #85, exactly: {_marker(h)}"
    )


@pytest.mark.parametrize(
    ("base_ref", "command"),
    [
        ("origin/main", "git fetch origin && git rebase origin/main"),
        ("refs/remotes/origin/release/1", "git fetch origin && git rebase origin/release/1"),
        ("main", "git rebase main"),
    ],
)
def test_base_ref_not_ancestor_names_sha_and_rebase_command(base_ref: str, command: str) -> None:
    sha = "b" * 40
    assert gate_diagnostics.base_ref_not_ancestor(base_ref, sha) == (
        f"BASE_REF_NOT_ANCESTOR: HEAD does not descend from {base_ref} at {sha}; "
        f"rebase onto {sha} ({command}) and push again"
    )


def test_emit_without_summary_env_only_prints(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    gate_diagnostics.emit(["X: y"])
    assert capsys.readouterr().out == "X: y\n"


def test_emit_appends_fenced_blocks_so_markers_stay_visible(summary: Path) -> None:
    line = gate_diagnostics.missing_evidence_universe(1, "sha256:" + "c" * 64)
    gate_diagnostics.emit([line])
    assert summary.read_text(encoding="utf-8") == (f"{SUMMARY_HEADING}\n\n```text\n{line}\n```\n\n")


# --- #243: BASE_REF_NOT_ANCESTOR (strict rule unchanged) ---------------------------


def test_check_base_ref_not_ancestor_prints_base_sha_and_remedy(
    repo: Path, summary: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Since the #243 merge-base rule only unrelated history fails ancestry.
    tip = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "--orphan", "feature")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "unrelated root")
    head = _git(repo, "rev-parse", "HEAD")

    assert cli.main(["check", "--repo", str(repo)]) == 2
    out, err = capsys.readouterr()
    remedy = (
        f"BASE_REF_NOT_ANCESTOR: HEAD does not descend from main at {tip}; "
        f"rebase onto {tip} (git rebase main) and push again"
    )
    assert f"BASE_REF_NOT_ANCESTOR: main at {tip} shares no history with HEAD {head}\n" in err
    assert out == remedy + "\n"
    assert _summary_blocks(summary) == [remedy]


# --- #243: ISSUE_EVIDENCE_UNIVERSE_STALE -------------------------------------------


def test_issue_init_stale_marker_prints_expected_line(
    repo: Path, summary: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_issue_body(monkeypatch, "Change V\n\n" + _marker("sha256:" + "0" * 64))
    expected = _marker(_hash(repo))

    assert cli.main(["issue-init", "--repo", str(repo), "--issue", "85"]) == 2
    out, err = capsys.readouterr()
    assert err.startswith(
        "ISSUE_EVIDENCE_UNIVERSE_STALE: Issue evidence-universe marker does not match current "
        f"verification contract; expected Issue body line: {expected}\n"
    )
    remedy = gate_diagnostics.stale_evidence_universe(85, _hash(repo))
    assert out == remedy + "\n"
    assert remedy.endswith(expected)
    assert _summary_blocks(summary) == [remedy]


def test_issue_check_stale_after_config_change_prints_new_expected_line(
    repo: Path, summary: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = "Change V\n\n" + _marker(_hash(repo))
    reader = lambda r, n: _issue(body)  # noqa: E731
    init_issue_binding(repo, issue_number=85, issue_reader=reader)
    config = repo / ".nexus-core" / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "timeout_seconds = 300", "timeout_seconds = 301"
        ),
        encoding="utf-8",
    )
    _git(repo, "add", ".nexus-core/config.toml")
    _git(repo, "commit", "-qm", "config change")
    new_hash = _hash(repo)

    with pytest.raises(LocalCheckError) as raised:
        check_issue(repo, issue_number=85, issue_reader=reader)
    assert raised.value.reason_code == "ISSUE_EVIDENCE_UNIVERSE_STALE"
    assert raised.value.detail == (
        "verification contract changed since Issue evidence sufficiency was bound; "
        f"expected Issue body line: {_marker(new_hash)}"
    )
    assert raised.value.remediation == gate_diagnostics.stale_evidence_universe(85, new_hash)
    assert raised.value.receipt_path is not None


# --- #244: UNVERIFIABLE (missing marker) -------------------------------------------


def test_issue_init_missing_marker_hint_includes_exact_line(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_issue_body(monkeypatch, "Change V")
    assert cli.main(["issue-init", "--repo", str(repo), "--issue", "85"]) == 0
    out = capsys.readouterr().out
    assert gate_diagnostics.missing_evidence_universe(85, _hash(repo)) + "\n" in out


def test_issue_check_unverifiable_prints_reason_code_and_marker(
    repo: Path, summary: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_issue_body(monkeypatch, "Change V")
    assert cli.main(["issue-init", "--repo", str(repo), "--issue", "85"]) == 0
    summary.unlink(missing_ok=True)
    capsys.readouterr()

    assert cli.main(["issue-check", "--repo", str(repo), "--issue", "85"]) == 1
    out = capsys.readouterr().out
    remedy = (
        "ISSUE_MISSING_EVIDENCE_UNIVERSE: add this line to the body of Issue #85, then "
        f"re-run the gate: {_marker(_hash(repo))}"
    )
    assert "issue verification: UNVERIFIABLE (not RELEASED)\n" in out
    assert "reasons: ISSUE_EVIDENCE_UNIVERSE_UNBOUND\n" in out
    assert out.endswith(remedy + "\n")
    assert _summary_blocks(summary) == [remedy]


def test_issue_check_failed_repository_names_receipt(
    tmp_path: Path,
    summary: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    r = tmp_path / "failing"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@example.test")
    _git(r, "config", "user.name", "T")
    _git(r, "remote", "add", "origin", "https://github.com/example/project.git")
    (r / "app.py").write_text("V = 1\n", encoding="utf-8")
    _git(r, "add", "app.py")
    _git(r, "commit", "-m", "base")
    init_repository(
        r,
        base_ref="main",
        allowed_patterns=("app.py",),
        verifier_command=(sys.executable, "-c", "raise SystemExit(1)"),
    )
    _git(r, "add", ".nexus-core/config.toml")
    _git(r, "commit", "-m", "config")
    (r / "app.py").write_text("V = 2\n", encoding="utf-8")
    _use_issue_body(monkeypatch, "Change V\n\n" + _marker(_hash(r)))
    assert cli.main(["issue-init", "--repo", str(r), "--issue", "85"]) == 0
    capsys.readouterr()

    assert cli.main(["issue-check", "--repo", str(r), "--issue", "85"]) == 1
    out = capsys.readouterr().out
    receipt = re.search(r"^receipt: (.+)$", out, re.MULTILINE)
    assert receipt is not None
    reasons = re.search(r"^reasons: (.+)$", out, re.MULTILINE)
    assert reasons is not None
    remedy = (
        "REPOSITORY_VERIFICATION_NOT_VERIFIED: repository verification is FAILED_VERIFICATION "
        f"(reasons: {reasons.group(1)}); fix the cause recorded in receipt {receipt.group(1)}, "
        "then re-run the gate"
    )
    assert out.endswith(remedy + "\n")
    assert _summary_blocks(summary) == [remedy]


def test_issue_check_verified_prints_no_remediation(
    repo: Path, summary: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_issue_body(monkeypatch, "Change V\n\n" + _marker(_hash(repo)))
    assert cli.main(["issue-init", "--repo", str(repo), "--issue", "85"]) == 0
    assert cli.main(["issue-check", "--repo", str(repo), "--issue", "85"]) == 0
    out = capsys.readouterr().out
    assert "ISSUE_MISSING_EVIDENCE_UNIVERSE" not in out
    assert not summary.exists()


# --- #244: receipt-verify ISSUE_VERIFICATION_MISMATCH / STATUS_MISMATCH -------------


def _receipt_check(
    capsys: pytest.CaptureFixture[str], receipt: Path, *flags: str
) -> tuple[int, dict[str, Any], str]:
    code = cli.main(["receipt-check", "--receipt", str(receipt), *flags])
    out, err = capsys.readouterr()
    return code, json.loads(out), err


@pytest.mark.parametrize("flags", [("--expect-issue", "85"), ("--expect-status", "VERIFIED")])
def test_receipt_check_unbound_issue_names_missing_marker(
    repo: Path,
    summary: Path,
    capsys: pytest.CaptureFixture[str],
    flags: tuple[str, ...],
) -> None:
    reader = lambda r, n: _issue("Change V")  # noqa: E731
    init_issue_binding(repo, issue_number=85, issue_reader=reader)
    result = check_issue(repo, issue_number=85, issue_reader=reader)

    code, output, err = _receipt_check(capsys, result["receipt_path"], *flags)
    assert code == 2
    assert output["reason_codes"] == [
        "ISSUE_VERIFICATION_MISMATCH" if flags[0] == "--expect-issue" else "STATUS_MISMATCH"
    ]
    remedy = (
        "ISSUE_MISSING_EVIDENCE_UNIVERSE: Issue #85 has no NEXUS_CORE_EVIDENCE_UNIVERSE line; "
        "copy the line printed in the issue-gate job summary (or by "
        "'nexus-certify markers --issue 85 --check') into the Issue body, "
        "then re-run the gate"
    )
    assert err.endswith(remedy + "\n")
    assert _summary_blocks(summary) == [remedy]


def test_receipt_check_stale_issue_names_stale_marker(
    repo: Path, summary: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = "Change V\n\n" + _marker(_hash(repo))
    reader = lambda r, n: _issue(body)  # noqa: E731
    init_issue_binding(repo, issue_number=85, issue_reader=reader)
    config = repo / ".nexus-core" / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "timeout_seconds = 300", "timeout_seconds = 301"
        ),
        encoding="utf-8",
    )
    _git(repo, "add", ".nexus-core/config.toml")
    _git(repo, "commit", "-qm", "config change")
    with pytest.raises(LocalCheckError) as raised:
        check_issue(repo, issue_number=85, issue_reader=reader)
    receipt = raised.value.receipt_path
    assert receipt is not None

    code, output, err = _receipt_check(capsys, receipt, "--expect-issue", "85")
    assert (code, output["reason_codes"]) == (2, ["ISSUE_VERIFICATION_MISMATCH"])
    stale = (
        "ISSUE_EVIDENCE_UNIVERSE_STALE: the NEXUS_CORE_EVIDENCE_UNIVERSE line in Issue #85 "
        "does not match the current config; replace it with the line printed in the "
        "issue-gate job summary, then re-run the gate"
    )
    assert stale + "\n" in err
    assert stale in _summary_blocks(summary)


def test_receipt_without_issue_binding_names_pr_marker(
    repo: Path, summary: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["check", "--repo", str(repo)]) == 0
    receipt = Path(capsys.readouterr().out.strip().splitlines()[-1].removeprefix("receipt: "))

    code, output, err = _receipt_check(capsys, receipt, "--expect-issue", "85")
    assert code == 2
    assert output["reason_codes"] == ["ISSUE_BINDING_MISMATCH", "ISSUE_VERIFICATION_MISMATCH"]
    remedy = (
        "PR_MISSING_CORE_ISSUE_BINDING: the receipt is not bound to any Issue; add "
        "<!-- NEXUS_CORE_ISSUE: 85 --> to the PR body, then re-run the gate"
    )
    assert err.endswith(remedy + "\n")
    assert _summary_blocks(summary) == [remedy]


def test_receipt_check_remediation_for_other_issue_and_failed_status() -> None:
    payload = {
        "inputs": {"requirements_context": {"issue_number": 7}},
        "issue_verification": {"evidence_universe": "BOUND"},
        "outcome": {"status": "FAILED_VERIFICATION", "reason_codes": ["VERIFIER_FAILED"]},
    }
    assert gate_diagnostics.receipt_remediations(payload, expect_issue=85) == [
        "RECEIPT_ISSUE_BINDING_MISMATCH: the receipt is bound to Issue #7, not #85; make the "
        "PR body name one Issue, then re-run the gate",
        "REPOSITORY_VERIFICATION_NOT_VERIFIED: repository verification is FAILED_VERIFICATION "
        "(reasons: VERIFIER_FAILED); fix the cause shown in the issue-gate 'Diagnose Core "
        "verifier failure' step, then re-run the gate",
    ]
    assert gate_diagnostics.receipt_remediations("not a receipt", expect_issue=85) == []


def test_receipt_check_passing_receipt_emits_no_remediation(
    repo: Path, summary: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = "Change V\n\n" + _marker(_hash(repo))
    reader = lambda r, n: _issue(body)  # noqa: E731
    init_issue_binding(repo, issue_number=85, issue_reader=reader)
    result = check_issue(repo, issue_number=85, issue_reader=reader)
    code, output, err = _receipt_check(
        capsys, result["receipt_path"], "--expect-issue", "85", "--expect-status", "VERIFIED"
    )
    assert (code, output["valid"], err) == (0, True, "")
    assert not summary.exists()


# --- receipt-verify prints the receipt's own verdict first ---------------------------


def _pre_request_failed_receipt(repo: Path) -> Path:
    """A real receipt that failed closed before any Core request (FORBIDDEN_PATH)."""

    body = "Change V\n\n" + _marker(_hash(repo))
    reader = lambda r, n: _issue(body)  # noqa: E731
    init_issue_binding(repo, issue_number=85, issue_reader=reader)
    (repo / "other.py").write_text("X = 1\n", encoding="utf-8")
    with pytest.raises(LocalCheckError) as raised:
        check_issue(repo, issue_number=85, issue_reader=reader)
    assert raised.value.reason_code == "FORBIDDEN_PATH"
    receipt = raised.value.receipt_path
    assert receipt is not None
    payload = json.loads(Path(receipt).read_text(encoding="utf-8"))
    assert payload["inputs"]["request"] is None
    assert payload["outcome"]["status"] == "FAILED_CLOSED"
    return Path(receipt)


def test_receipt_check_prints_receipt_status_before_mismatches(
    repo: Path, summary: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    receipt = _pre_request_failed_receipt(repo)
    capsys.readouterr()

    code, output, err = _receipt_check(
        capsys, receipt, "--expect-status", "VERIFIED", "--expect-issue", "85"
    )
    # Fail-closed behaviour is unchanged: invalid receipt, exit 2.
    assert (code, output["valid"]) == (2, False)
    assert {
        "ISSUE_VERIFICATION_MISMATCH",
        "RECEIPT_FAILED_CLOSED_BEFORE_CORE_REQUEST",
        "STATUS_MISMATCH",
    } <= set(output["reason_codes"])
    lines = err.splitlines()
    assert lines[0] == (
        "RECEIPT_STATUS: FAILED_CLOSED (reasons: FORBIDDEN_PATH); this is the gate's own "
        "verdict, fix its reasons first; the mismatch lines that follow are consequences of it"
    )
    assert lines[1].startswith("reasons: ")
    assert "MALFORMED_RECEIPT" not in err


def test_receipt_status_line_is_silent_for_verified_and_unreadable_receipts() -> None:
    assert gate_diagnostics.receipt_status_line({"outcome": {"status": "VERIFIED"}}) is None
    assert gate_diagnostics.receipt_status_line({"outcome": {}}) is None
    assert gate_diagnostics.receipt_status_line("not a receipt") is None
    assert gate_diagnostics.receipt_status_line(
        {"outcome": {"status": "FAILED_VERIFICATION", "reason_codes": ["A", "B"]}}
    ) == (
        "RECEIPT_STATUS: FAILED_VERIFICATION (reasons: A, B); this is the gate's own "
        "verdict, fix its reasons first; the mismatch lines that follow are consequences of it"
    )


def _rewrite(path: Path, payload: dict[str, Any]) -> Path:
    payload["receipt_hash"] = canonical_hash(
        {key: value for key, value in payload.items() if key != "receipt_hash"}
    )
    out = path.with_name("rewritten.json")
    out.write_text(json.dumps(payload), encoding="utf-8")
    return out


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda p: p["outcome"].update(status="VERIFIED"), id="verified-no-request"),
        pytest.param(lambda p: p["outcome"].update(reason_codes=[]), id="no-reason"),
        pytest.param(lambda p: p["outcome"].update(reason_codes=["A", "B"]), id="two-reasons"),
        pytest.param(lambda p: p.update(core_response={"x": 1}), id="core-response"),
        pytest.param(lambda p: p.update(outcome="FAILED_CLOSED"), id="outcome-not-mapping"),
    ],
)
def test_request_less_receipt_outside_exact_shape_stays_malformed(repo: Path, mutate: Any) -> None:
    from product.clients.local_golden_path import validate_verification_receipt

    receipt = _pre_request_failed_receipt(repo)
    before = validate_verification_receipt(receipt)
    assert before["valid"] is False
    assert "RECEIPT_FAILED_CLOSED_BEFORE_CORE_REQUEST" in before["reason_codes"]
    assert "MALFORMED_RECEIPT" not in before["reason_codes"]
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    mutate(payload)
    result = validate_verification_receipt(_rewrite(receipt, payload))
    assert result["valid"] is False
    assert "MALFORMED_RECEIPT" in result["reason_codes"]
    assert "RECEIPT_FAILED_CLOSED_BEFORE_CORE_REQUEST" not in result["reason_codes"]


# --- #244: markers --issue N --check (read-only creation path) ---------------------


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ("correct", "MATCH", 0),
        ("Change V", "MISSING", 1),
        ("stale", "STALE", 1),
        ("double", "MALFORMED", 1),
    ],
)
def test_markers_check_compares_live_issue_body(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    body: str,
    status: str,
    code: int,
) -> None:
    h = _hash(repo)
    bodies = {
        "correct": "x\n" + _marker(h),
        "stale": "x\n" + _marker("sha256:" + "0" * 64),
        "double": "x\n" + _marker(h) + "\n" + _marker(h),
    }
    _use_issue_body(monkeypatch, bodies.get(body, body))
    tracked = (repo / ".nexus-core" / "config.toml").read_bytes()

    assert cli.main(["markers", "--repo", str(repo), "--issue", "85", "--check"]) == code
    out = capsys.readouterr().out
    assert f"Issue body: {_marker(h)}\n" in out
    expected_last = {
        "MATCH": f"check: Issue #85 evidence-universe marker matches ({h})",
        "MISSING": gate_diagnostics.missing_evidence_universe(85, h),
        "STALE": gate_diagnostics.stale_evidence_universe(85, h),
        "MALFORMED": gate_diagnostics.malformed_evidence_universe(85, h),
    }[status]
    assert out.endswith(expected_last + "\n")
    # Read-only: no binding written, config untouched.
    assert not (repo / ".nexus-core" / "issues").exists()
    assert (repo / ".nexus-core" / "config.toml").read_bytes() == tracked

    assert cli.main(["markers", "--repo", str(repo), "--issue", "85", "--check", "--json"]) == code
    payload = json.loads(capsys.readouterr().out)
    assert payload["issue_check"]["status"] == status


def test_markers_check_requires_issue(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["markers", "--repo", str(repo), "--check"]) == 2
    assert "usage error: markers --check requires --issue N" in capsys.readouterr().err


def test_markers_without_check_never_reads_github(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*_args: object) -> dict[str, object]:
        raise AssertionError("markers without --check must not read the Issue")

    monkeypatch.setattr(issue_gp, "_default_issue_reader", fail)
    assert cli.main(["markers", "--repo", str(repo), "--issue", "85"]) == 0


# --- action scripts ----------------------------------------------------------------


def _step_run(action: str, step_name: str) -> str:
    text = (ROOT / ".github" / "actions" / action / "action.yml").read_text(encoding="utf-8")
    start = text.index(f"- name: {step_name}")
    run_at = text.index("      run: |\n", start)
    lines: list[str] = []
    for line in text[run_at:].splitlines()[1:]:
        if line.strip() and not line.startswith("        "):
            break
        lines.append(line[8:])
    return "\n".join(lines) + "\n"


def _run_bash(script: str, env: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "step.sh"
    path.write_text(script, encoding="utf-8")
    full = {"PATH": os.environ["PATH"], **env}
    return subprocess.run(["bash", str(path)], env=full, capture_output=True, text=True)


ACTION_REMEDY_ISSUE_GATE = (
    "PR_MISSING_CORE_ISSUE_BINDING: add exactly one line <!-- NEXUS_CORE_ISSUE: N --> "
    "(N = the Issue number) to the PR body, then re-run the gate (found 0)"
)
ACTION_REMEDY_RECEIPT_VERIFY = (
    "PR_MISSING_CORE_ISSUE_BINDING: the issue gate resolved no Issue; add exactly one line "
    "<!-- NEXUS_CORE_ISSUE: N --> (N = the Issue number) to the PR body, then re-run the gate"
)


def test_issue_gate_missing_pr_binding_names_fix(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    output = tmp_path / "output"
    result = _run_bash(
        _step_run("issue-gate", "Validate inputs and resolve Issue binding"),
        {
            "IN_ISSUE": "",
            "IN_SOURCE": "ref",
            "IN_REF": "a" * 40,
            "IN_PATH": "",
            "IN_CANDIDATE": "candidate",
            "IN_PYTHON": "3.11",
            "PR_BODY": "no marker here",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
        },
        tmp_path,
    )
    assert result.returncode != 0
    assert "NEXUS_CORE_ISSUE_BINDING_REQUIRED" in result.stderr
    assert ACTION_REMEDY_ISSUE_GATE + "\n" in result.stderr
    assert _summary_blocks(summary) == [ACTION_REMEDY_ISSUE_GATE]


def test_issue_gate_single_pr_binding_still_resolves(tmp_path: Path) -> None:
    output = tmp_path / "output"
    result = _run_bash(
        _step_run("issue-gate", "Validate inputs and resolve Issue binding"),
        {
            "IN_ISSUE": "",
            "IN_SOURCE": "ref",
            "IN_REF": "a" * 40,
            "IN_PATH": "",
            "IN_CANDIDATE": "candidate",
            "IN_PYTHON": "3.11",
            "PR_BODY": "Closes #9\n<!-- NEXUS_CORE_ISSUE: 9 -->",
            "GITHUB_OUTPUT": str(output),
        },
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8") == "issue-number=9\n"


def test_receipt_verify_empty_issue_names_fix_and_still_fails(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    result = _run_bash(
        _step_run("receipt-verify", "Validate inputs"),
        {"IN_ISSUE": "", "IN_ARTIFACT": "", "GITHUB_STEP_SUMMARY": str(summary)},
        tmp_path,
    )
    assert result.returncode == 1
    assert result.stderr == (
        ACTION_REMEDY_RECEIPT_VERIFY + "\nNEXUS_CORE_VERIFY_INPUT_INVALID: issue-number is empty\n"
    )
    assert _summary_blocks(summary) == [ACTION_REMEDY_RECEIPT_VERIFY]


SUGGEST_CASES: list[tuple[str, int | None]] = [
    ("Refs #2230", 2230),
    ("Closes #12\nFixes #12", 12),
    ("Refs #1 and Closes #2", None),
    ("see #5", None),
    ("Closes James3014/other#5", None),
    ("", None),
    ("closes: #7", 7),
    ("<!-- NEXUS_CORE_ISSUE: 0 --> Prefix #3", None),
    ("Resolved #4 <!-- NEXUS_CORE_ISSUE: 0 -->", 4),
    ("<!-- Closes #7 -->", None),
    ("<!-- Closes #7 -->\nRefs #8", 8),
    ("Refs #8 <!-- unterminated Closes #9", 8),
    ("```\nCloses #7\n```", None),
    ("~~~text\nFixes #7\n~~~\nRefs #8", 8),
    ("```\nCloses #7 never closed", None),
    ("see `Closes #7` here", None),
    ("``Closes #7`` then Refs #8", 8),
    ("Closes #" + "1" * 5000, None),
    ("Closes #12345678901", None),
    ("````\nCloses #7\n```\nRefs #8", None),
    ("```\nCloses #7\n~~~\nRefs #8", None),
    ("~~~~\nCloses #7\n~~~~~\nRefs #8", 8),
]


@pytest.mark.parametrize(("body", "expected"), SUGGEST_CASES)
def test_suggest_core_issue_marker_table(body: str, expected: int | None) -> None:
    assert gate_diagnostics.suggest_core_issue_marker(body) == expected


@pytest.mark.parametrize(("body", "expected"), SUGGEST_CASES)
def test_issue_gate_inline_prefill_agrees_with_function(
    tmp_path: Path, body: str, expected: int | None
) -> None:
    summary = tmp_path / "summary.md"
    result = _run_bash(
        _step_run("issue-gate", "Validate inputs and resolve Issue binding"),
        {
            "IN_ISSUE": "",
            "IN_SOURCE": "ref",
            "IN_REF": "a" * 40,
            "IN_PATH": "",
            "IN_CANDIDATE": "candidate",
            "IN_PYTHON": "3.11",
            "PR_BODY": body,
            "GITHUB_OUTPUT": str(tmp_path / "output"),
            "GITHUB_STEP_SUMMARY": str(summary),
        },
        tmp_path,
    )
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    if expected is None:
        assert ACTION_REMEDY_ISSUE_GATE + "\n" in result.stderr
    else:
        line = (
            "PR_MISSING_CORE_ISSUE_BINDING: add this line to the PR body: "
            f"<!-- NEXUS_CORE_ISSUE: {expected} --> then re-run the gate"
        )
        assert line + "\n" in result.stderr
        assert _summary_blocks(summary) == [line]


def test_issue_gate_multiple_markers_not_prefilled(tmp_path: Path) -> None:
    result = _run_bash(
        _step_run("issue-gate", "Validate inputs and resolve Issue binding"),
        {
            "IN_ISSUE": "",
            "IN_SOURCE": "ref",
            "IN_REF": "a" * 40,
            "IN_PATH": "",
            "IN_CANDIDATE": "candidate",
            "IN_PYTHON": "3.11",
            "PR_BODY": "Closes #3\n<!-- NEXUS_CORE_ISSUE: 3 -->\n<!-- NEXUS_CORE_ISSUE: 4 -->",
            "GITHUB_OUTPUT": str(tmp_path / "output"),
        },
        tmp_path,
    )
    assert result.returncode == 1
    assert "add exactly one line" in result.stderr
    assert "add this line" not in result.stderr


def test_issue_gate_inline_regexes_match_function_literals() -> None:
    action = (ROOT / ".github" / "actions" / "issue-gate" / "action.yml").read_text(
        encoding="utf-8"
    )
    keyword = gate_diagnostics._CORE_ISSUE_KEYWORD_REF_RE  # pyright: ignore[reportPrivateUsage]
    hidden = gate_diagnostics._HIDDEN_TEXT_RES  # pyright: ignore[reportPrivateUsage]
    head, tail = keyword.split("[ \\t]*", 1)
    pieces = [*hidden, head, "[ \\t]*" + tail]
    for piece in pieces:
        assert f'r"{piece}"' in action, piece


TIMING_BODIES = [
    "`" * 65536,
    "".join("`" * k + "a" for k in range(1, 360)),
    "`" * 30000 + "a" + "`" * 30001,
]


@pytest.mark.parametrize("body", TIMING_BODIES)
def test_suggest_core_issue_marker_is_fast_on_backtick_floods(body: str) -> None:
    started = time.monotonic()
    assert gate_diagnostics.suggest_core_issue_marker(body) is None
    assert time.monotonic() - started < 2


@pytest.mark.parametrize("body", TIMING_BODIES)
def test_issue_gate_inline_is_fast_on_backtick_floods(tmp_path: Path, body: str) -> None:
    started = time.monotonic()
    result = _run_bash(
        _step_run("issue-gate", "Validate inputs and resolve Issue binding"),
        {
            "IN_ISSUE": "",
            "IN_SOURCE": "ref",
            "IN_REF": "a" * 40,
            "IN_PATH": "",
            "IN_CANDIDATE": "candidate",
            "IN_PYTHON": "3.11",
            "PR_BODY": body,
            "GITHUB_OUTPUT": str(tmp_path / "output"),
        },
        tmp_path,
    )
    assert time.monotonic() - started < 2
    assert result.returncode == 1
    assert ACTION_REMEDY_ISSUE_GATE + "\n" in result.stderr
