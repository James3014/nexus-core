"""#243 Owner decision: ancestry from the merge-base, trusted config from the base tip.

(a) a head branched from main~1 passes ancestry; the subject diff is merge-base..HEAD.
(b) the config applied is the current tip's, including a change landed after the
    branch point.
(c) an orphan head, a head branched off a non-main root, and criss-cross history
    (several merge-bases) still fail BASE_REF_NOT_ANCESTOR.
(d) NCGF-002 / #238: a candidate-created base_ref branch earns no trusted config,
    also when it is a sibling (not an ancestor) of HEAD.
(e) nexus-verify rejects a receipt made before a base-tip config change, and accepts
    a merge-base receipt only while its config tip is the current base tip.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from product.clients.cli import main as cli_main
from product.clients.local_golden_path import (
    LocalCheckError,
    _load_effective_config,
    check_repository,
    init_repository,
)
from product.clients.nexus_verify import verify_code_change_evidence
from product.protocol.generic_verification import canonical_hash
from tests.product.test_nexus_verify_plugin import FakeGitHubPort, _signed_args


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


def _commit_file(repo: Path, name: str, text: str, message: str) -> str:
    (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@example.test")
    _git(r, "config", "user.name", "T")
    (r / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (r / "README.md").write_text("readme\n", encoding="utf-8")
    _git(r, "add", ".")
    _git(r, "commit", "-qm", "base")
    _config(r, "raise SystemExit(0)")
    _git(r, "add", ".nexus-core/config.toml")
    _git(r, "commit", "-qm", "trusted config")
    return r


def _config(
    repo: Path,
    verifier_source: str,
    *,
    base_ref: str = "main",
    patterns: tuple[str, ...] = ("*.py",),
) -> None:
    init_repository(
        repo,
        base_ref=base_ref,
        allowed_patterns=patterns,
        verifier_command=(sys.executable, "-c", verifier_source),
        force=True,
    )


def _branch_behind_main(repo: Path) -> tuple[str, str, str]:
    """feature branches at main~1 after main moves on. Returns (branch_point, tip, head)."""

    branch_point = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "-b", "feature")
    head = _commit_file(repo, "app.py", "VALUE = 2\n", "feature change")
    _git(repo, "checkout", "-q", "main")
    tip = _commit_file(repo, "README.md", "moved\n", "main moves on (non-.py)")
    _git(repo, "checkout", "-q", "feature")
    return branch_point, tip, head


def _receipt(result_path: Path) -> dict[str, Any]:
    return json.loads(result_path.read_text(encoding="utf-8"))


# (a) -------------------------------------------------------------------------------


def test_a_head_branched_from_main_minus_one_passes_with_merge_base_diff(repo: Path) -> None:
    branch_point, tip, head = _branch_behind_main(repo)
    assert _git(repo, "rev-parse", "main~1") == branch_point

    result = check_repository(repo, require_trusted_config=True, expect_config_commit=tip)

    assert result["status"] == "VERIFIED"
    receipt = _receipt(result["receipt_path"])
    assert receipt["source_revision"] == f"git-commit:{branch_point}"
    assert receipt["subject_head"] == f"git-commit:{head}"
    assert receipt["config_source"]["kind"] == "base-ref"
    assert receipt["config_source"]["commit"] == tip
    # merge-base..HEAD: main's later README change is not part of the subject.
    assert receipt["inputs"]["request"]["change_set"]["paths"] == ["app.py"]


def test_a_head_descending_from_tip_keeps_tip_as_source(repo: Path) -> None:
    tip = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "-b", "feature")
    _commit_file(repo, "app.py", "VALUE = 2\n", "feature change")

    result = check_repository(repo, expect_config_commit=tip)

    assert result["status"] == "VERIFIED"
    assert _receipt(result["receipt_path"])["source_revision"] == f"git-commit:{tip}"


# (b) -------------------------------------------------------------------------------


def test_b_config_changed_on_tip_after_branch_point_is_the_one_applied(
    repo: Path, tmp_path: Path
) -> None:
    marker = tmp_path / "tip-verifier-ran"
    branch_point = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "-b", "feature")
    _commit_file(repo, "app.py", "VALUE = 2\n", "feature change")
    _git(repo, "checkout", "-q", "main")
    # The tip's config now requires a verifier that fails (and leaves a marker).
    _config(repo, f"open({str(marker)!r}, 'w').close(); raise SystemExit(1)")
    _git(repo, "commit", "-qam", "tighten config on main")
    tip = _git(repo, "rev-parse", "main")
    tip_config_hash = canonical_hash(_load_effective_config(repo)[0])
    _git(repo, "checkout", "-q", "feature")
    worktree_config = _load_effective_config(repo)[2]
    assert worktree_config is not None
    feature_config_hash = canonical_hash(worktree_config)
    assert tip_config_hash != feature_config_hash

    result = check_repository(repo, require_trusted_config=True, expect_config_commit=tip)

    assert result["status"] == "FAILED_VERIFICATION"
    assert marker.exists()
    receipt = _receipt(result["receipt_path"])
    assert receipt["config_source"]["commit"] == tip
    assert receipt["config_hash"] == tip_config_hash
    assert receipt["source_revision"] == f"git-commit:{branch_point}"


def test_b_pin_on_merge_base_instead_of_tip_is_rejected(repo: Path) -> None:
    branch_point, _tip, _head = _branch_behind_main(repo)
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, expect_config_commit=branch_point)
    assert raised.value.reason_code == "CONFIG_SOURCE_MISMATCH"


# (c) -------------------------------------------------------------------------------


def _assert_not_ancestor(repo: Path, tip: str) -> None:
    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, expect_config_commit=tip)
    assert raised.value.reason_code == "BASE_REF_NOT_ANCESTOR"
    assert raised.value.receipt_path is not None
    assert raised.value.remediation == (
        f"BASE_REF_NOT_ANCESTOR: HEAD does not descend from main at {tip}; "
        f"rebase onto {tip} (git rebase main) and push again"
    )


def test_c_orphan_head_fails(repo: Path) -> None:
    tip = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "--orphan", "orphan")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "unrelated root")
    _commit_file(repo, "app.py", "VALUE = 9\n", "payload")
    _assert_not_ancestor(repo, tip)


def test_c_head_branched_off_non_main_root_fails(repo: Path) -> None:
    tip = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "--orphan", "side")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "side root not on main")
    _git(repo, "checkout", "-q", "-b", "feature")
    _commit_file(repo, "app.py", "VALUE = 9\n", "payload on side branch")
    _assert_not_ancestor(repo, tip)


def test_c_criss_cross_history_with_two_merge_bases_fails(repo: Path) -> None:
    _git(repo, "checkout", "-q", "-b", "y")
    y1 = _commit_file(repo, "y.py", "Y = 1\n", "y1")
    _git(repo, "checkout", "-q", "main")
    x1 = _commit_file(repo, "x.py", "X = 1\n", "x1")
    _git(repo, "merge", "-q", "--no-ff", "-m", "main merges y1", y1)
    tip = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "y")
    _git(repo, "merge", "-q", "--no-ff", "-m", "y merges x1", x1)
    assert len(_git(repo, "merge-base", "--all", tip, "HEAD").split()) == 2

    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, expect_config_commit=tip)
    assert raised.value.reason_code == "BASE_REF_NOT_ANCESTOR"
    assert raised.value.detail.startswith(f"main at {tip} has 2 merge-bases with HEAD ")


# (d) -------------------------------------------------------------------------------


def _sibling_weak_branch(repo: Path, marker: Path) -> tuple[str, str]:
    """A candidate mints branch ``weak`` (weak config) as a sibling of its own HEAD."""

    _config(repo, "raise SystemExit(1)")
    _git(repo, "commit", "-qam", "trusted failing config")
    main_sha = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "-b", "weak")
    _config(repo, f"open({str(marker)!r}, 'w').close()", base_ref="weak", patterns=("**",))
    _git(repo, "commit", "-qam", "weak config")
    weak_sha = _git(repo, "rev-parse", "weak")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "checkout", "-q", "-b", "feature")
    _config(repo, "raise SystemExit(1)", base_ref="weak")
    _git(repo, "commit", "-qam", "point base_ref at weak")
    _commit_file(repo, "app.py", "VALUE = 3\n", "payload")
    assert _git(repo, "merge-base", "weak", "HEAD") == main_sha  # sibling, not ancestor
    return main_sha, weak_sha


def test_d_candidate_created_sibling_base_ref_is_unpinned_not_trusted(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = tmp_path / "weak-verifier-ran"
    _main_sha, weak_sha = _sibling_weak_branch(repo, marker)

    cli_main(["check", "--repo", str(repo), "--require-trusted-config"])

    out = capsys.readouterr().out
    assert f"config: base-ref, unpinned (weak@{weak_sha[:12]})" in out
    assert "config: trusted" not in out


def test_d_pin_rejects_candidate_created_sibling_base_ref_before_verifier(
    repo: Path, tmp_path: Path
) -> None:
    marker = tmp_path / "weak-verifier-ran"
    main_sha, weak_sha = _sibling_weak_branch(repo, marker)

    with pytest.raises(LocalCheckError) as raised:
        check_repository(repo, require_trusted_config=True, expect_config_commit=main_sha)

    assert raised.value.reason_code == "CONFIG_SOURCE_MISMATCH"
    assert not marker.exists()
    assert raised.value.receipt_path is not None
    receipt = _receipt(raised.value.receipt_path)
    assert receipt["outcome"]["reason_codes"] == ["CONFIG_SOURCE_MISMATCH"]
    assert receipt["config_source"]["commit"] == weak_sha


# (e) -------------------------------------------------------------------------------


def _tree(repo: Path, commit: str) -> str:
    return _git(repo, "rev-parse", f"{commit}^{{tree}}")


def test_e_merge_base_receipt_applies_while_its_config_tip_is_current(repo: Path) -> None:
    _branch_point, tip, _head = _branch_behind_main(repo)
    receipt = _receipt(check_repository(repo, expect_config_commit=tip)["receipt_path"])
    port = FakeGitHubPort(repo, receipt, source_sha=tip, source_tree=_tree(repo, tip))
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

    assert result["evidence_applicability"] == "APPLIES"
    assert result["core_verification"] == "VERIFIED"
    assert result["reason_codes"] == []


def test_e_receipt_made_before_base_tip_config_change_is_rejected(repo: Path) -> None:
    old_tip = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "-b", "feature")
    _commit_file(repo, "app.py", "VALUE = 2\n", "feature change")
    receipt = _receipt(check_repository(repo, expect_config_commit=old_tip)["receipt_path"])
    assert receipt["source_revision"] == f"git-commit:{old_tip}"
    assert receipt["config_source"]["commit"] == old_tip

    _git(repo, "checkout", "-q", "main")
    _config(repo, "raise SystemExit(1)")
    _git(repo, "commit", "-qam", "config change on main")
    new_tip = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "feature")
    port = FakeGitHubPort(repo, receipt, source_sha=new_tip, source_tree=_tree(repo, new_tip))
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

    assert result["evidence_applicability"] == "STALE_SOURCE"
    assert result["reason_codes"] == ["RECEIPT_SOURCE_DOES_NOT_MATCH_CURRENT_PR"]


def test_e_merge_base_receipt_is_stale_once_the_base_tip_moves_again(repo: Path) -> None:
    _branch_point, tip, _head = _branch_behind_main(repo)
    receipt = _receipt(check_repository(repo, expect_config_commit=tip)["receipt_path"])
    _git(repo, "checkout", "-q", "main")
    _config(repo, "raise SystemExit(1)")
    _git(repo, "commit", "-qam", "config change after the receipt")
    newer_tip = _git(repo, "rev-parse", "main")
    _git(repo, "checkout", "-q", "feature")
    port = FakeGitHubPort(repo, receipt, source_sha=newer_tip, source_tree=_tree(repo, newer_tip))
    arguments, authenticator = _signed_args(receipt)

    result = verify_code_change_evidence(arguments, github_port=port, authenticator=authenticator)

    assert result["evidence_applicability"] == "STALE_SOURCE"
    assert result["reason_codes"] == ["RECEIPT_SOURCE_DOES_NOT_MATCH_CURRENT_PR"]
