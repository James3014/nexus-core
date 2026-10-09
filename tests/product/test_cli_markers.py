from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from product.clients import cli
from product.clients.issue_golden_path import init_issue_binding
from product.clients.local_golden_path import _load_effective_config, init_repository
from product.protocol.generic_verification import canonical_hash


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)


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
    return r


def _commit_config(repo: Path) -> None:
    _git(repo, "add", ".nexus-core/config.toml")
    _git(repo, "commit", "-m", "config")


def test_markers_text_without_issue_untrusted_warns(repo, capsys) -> None:
    assert cli.main(["markers", "--repo", str(repo)]) == 0
    out, err = capsys.readouterr()
    config, _, _ = _load_effective_config(repo)
    assert f"<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: {canonical_hash(config)} -->" in out
    assert "NEXUS_CORE_ISSUE" not in out
    assert "warning: config is not committed on main; the hash will change once it is" in err


def test_markers_text_with_issue_trusted_has_no_warning(repo, capsys) -> None:
    _commit_config(repo)
    assert cli.main(["markers", "--repo", str(repo), "--issue", "42"]) == 0
    out, err = capsys.readouterr()
    assert "<!-- NEXUS_CORE_ISSUE: 42 -->" in out
    assert "NEXUS_CORE_EVIDENCE_UNIVERSE: sha256:" in out
    assert err == ""


def test_markers_json_trusted(repo, capsys) -> None:
    _commit_config(repo)
    assert cli.main(["markers", "--repo", str(repo), "--issue", "7", "--json"]) == 0
    out, err = capsys.readouterr()
    payload = json.loads(out)
    config, _, _ = _load_effective_config(repo)
    assert payload["config_hash"] == canonical_hash(config)
    assert payload["config_source"]["kind"] == "base-ref"
    assert payload["issue_marker"] == (
        f"<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: {payload['config_hash']} -->"
    )
    assert payload["pr_marker"] == "<!-- NEXUS_CORE_ISSUE: 7 -->"
    assert err == ""


def test_markers_json_untrusted_without_issue(repo, capsys) -> None:
    assert cli.main(["markers", "--repo", str(repo), "--json"]) == 0
    out, err = capsys.readouterr()
    payload = json.loads(out)
    assert payload["pr_marker"] is None
    assert payload["config_source"]["kind"] == "worktree"
    assert "warning: config is not committed on main" in err


def test_markers_hash_is_stable_across_committing_config(repo, capsys) -> None:
    cli.main(["markers", "--repo", str(repo), "--json"])
    before = json.loads(capsys.readouterr().out)["config_hash"]
    _commit_config(repo)
    cli.main(["markers", "--repo", str(repo), "--json"])
    after = json.loads(capsys.readouterr().out)["config_hash"]
    assert before == after


def _patch_reader(monkeypatch, body: str) -> None:
    def reader(github_repo: str, number: int) -> dict[str, object]:
        return {
            "number": number,
            "title": "T",
            "body": body,
            "state": "open",
            "updated_at": "2026-10-05T00:00:00Z",
        }

    real = init_issue_binding
    monkeypatch.setattr(
        cli,
        "init_issue_binding",
        lambda *a, **k: real(*a, issue_reader=reader, **k),
    )


def test_issue_init_hints_when_marker_missing(repo, monkeypatch, capsys) -> None:
    _patch_reader(monkeypatch, "Change V")
    assert cli.main(["issue-init", "--repo", str(repo), "--issue", "85"]) == 0
    out = capsys.readouterr().out
    assert "hint: the Issue has no NEXUS_CORE_EVIDENCE_UNIVERSE marker" in out
    assert "nexus-certify markers" in out


def test_issue_init_no_hint_when_marker_present(repo, monkeypatch, capsys) -> None:
    config, _, _ = _load_effective_config(repo)
    marker = f"<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: {canonical_hash(config)} -->"
    _patch_reader(monkeypatch, f"Change V\n\n{marker}\n")
    assert cli.main(["issue-init", "--repo", str(repo), "--issue", "85"]) == 0
    assert "hint:" not in capsys.readouterr().out


_OLD = "git-commit:" + "a" * 40
_NEW = "git-commit:" + "b" * 40


@pytest.fixture
def pin_repo(repo: Path) -> Path:
    (repo / ".nexus-core" / "config.toml").write_text(
        "\n".join(
            [
                "version = 2",
                'base_ref = "main"',
                'allowed_patterns = ["app.py"]',
                'deletion_policy = "FORBID"',
                "universe_generation = 1",
                "verifiers = []",
                "[[materials]]",
                'id = "runtime"',
                f'observe_command = [{json.dumps(sys.executable)}, "-c", "print(1)"]',
                "timeout_seconds = 30",
                'logical_subject_id = "dependency/runtime"',
                'evidence_kind = "resolved-dependency"',
                'requirement_mode = "REQUIRED"',
                'applicability = "APPLICABLE"',
                f'expected_identity = "{_OLD}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    _commit_config(repo)
    return repo


def test_markers_material_transition_prints_exact_line_from_trusted_config(
    pin_repo, capsys
) -> None:
    from product.clients.issue_golden_path import _issue_material_transitions

    argv = ["markers", "--repo", str(pin_repo), "--material-transition", f"runtime={_NEW}"]
    assert cli.main(argv) == 0
    out, err = capsys.readouterr()
    line = f"<!-- NEXUS_CORE_MATERIAL_TRANSITION: runtime {_OLD} -> {_NEW} -->"
    assert "NEXUS_CORE_EVIDENCE_UNIVERSE: sha256:" in out
    assert line in out
    assert err == ""
    assert _issue_material_transitions({"body": line})[0]["to_identity"] == _NEW


def test_markers_material_transition_json_and_unknown_material(pin_repo, capsys) -> None:
    argv = ["markers", "--repo", str(pin_repo), "--json", "--material-transition", f"runtime={_NEW}"]
    assert cli.main(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["material_transition_markers"] == [
        f"<!-- NEXUS_CORE_MATERIAL_TRANSITION: runtime {_OLD} -> {_NEW} -->"
    ]

    argv = ["markers", "--repo", str(pin_repo), "--material-transition", f"nope={_NEW}"]
    assert cli.main(argv) == 2
    assert "MATERIAL_TRANSITION_UNKNOWN_MATERIAL" in capsys.readouterr().err


def test_markers_without_transition_flag_is_unchanged(pin_repo, capsys) -> None:
    assert cli.main(["markers", "--repo", str(pin_repo)]) == 0
    assert "NEXUS_CORE_MATERIAL_TRANSITION" not in capsys.readouterr().out
