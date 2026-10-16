"""#281: the issue gate signs exactly the receipt Core wrote, never a candidate-planted one.

The candidate tree is attacker-controlled: a PR can commit a future-dated receipt, and
candidate verifier code can write one at runtime. These tests pin the refusal step, the
pointer-based sign step (executed against temp dirs), and the upload path.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.architecture.test_receipt_artifact_lineage import (
    ISSUE_GATE,
    _github,  # pyright: ignore[reportPrivateUsage]
    _load_steps,  # pyright: ignore[reportPrivateUsage]
    _run_step,  # pyright: ignore[reportPrivateUsage]
    _step,  # pyright: ignore[reportPrivateUsage]
)

REFUSE = "Refuse candidate-committed receipts"
GOOD_NAME = "20261016T010203.000004+0000-0123456789ab.json"
FUTURE_NAME = "29991231T235959.999999+0000-ffffffffffff.json"


def _names() -> list[str]:
    return [step.get("name", "") for step in _load_steps(ISSUE_GATE)]


def _refuse_step() -> dict[str, Any]:
    (step,) = [s for s in _load_steps(ISSUE_GATE) if s.get("name") == REFUSE]
    return step


def test_refuse_step_runs_before_issue_init_and_is_gated() -> None:
    names = _names()
    acquire = names.index("Acquire candidate head with plain Git (no submodule handling)")
    refuse = names.index(REFUSE)
    assert acquire < refuse < names.index("Bind exact Issue contract")
    step = _refuse_step()
    assert step["if"] == "steps.prstate.outputs.outcome == 'PROCEED'"
    run = step["run"]
    assert "ls-tree -r --name-only HEAD -- .nexus-core/receipts" in run
    assert "NEXUS_CORE_GATE_CANDIDATE_RECEIPTS_PRESENT" in run
    assert '-L "$CANDIDATE/.nexus-core"' in run
    assert '-e "$CANDIDATE/.nexus-core/receipts"' in run
    assert '-L "$CANDIDATE/.nexus-core/receipts"' in run


def test_no_newest_by_name_selection_remains() -> None:
    text = ISSUE_GATE.read_text(encoding="utf-8")
    assert "max(candidates)" not in text
    assert "candidates.append" not in text
    assert "Sign newest receipt" not in text
    assert "strptime" not in text


def test_check_step_passes_pointer_outside_candidate() -> None:
    step = _step(ISSUE_GATE, "check")
    assert step["name"] == "Verify exact Issue-bound candidate"
    assert step["env"]["RECEIPT_POINTER"] == "${{ runner.temp }}/nexus-core-receipt-pointer"
    assert '--receipt-path-out "$RECEIPT_POINTER"' in step["run"]
    assert 'rm -f "$RECEIPT_POINTER"' in step["run"]


def test_upload_is_the_runner_temp_out_dir_not_the_candidate() -> None:
    (upload,) = [s for s in _load_steps(ISSUE_GATE) if s.get("id") == "upload"]
    assert upload["with"]["path"] == "${{ runner.temp }}/nexus-core-receipt-out/"
    assert "candidate-path" not in upload["with"]["path"]
    sign = _step(ISSUE_GATE, "sign")
    assert sign["name"] == "Sign the receipt issue-check wrote (Sigstore keyless)"
    assert sign["env"]["RECEIPT_OUT"] == "${{ runner.temp }}/nexus-core-receipt-out"


def test_diagnose_step_reads_the_pointer() -> None:
    (diag,) = [
        s for s in _load_steps(ISSUE_GATE) if s.get("name") == "Diagnose Core verifier failure"
    ]
    assert diag["env"]["RECEIPT_POINTER"] == "${{ runner.temp }}/nexus-core-receipt-pointer"
    assert "NEXUS_CORE_DIAGNOSTIC: no receipt available" in diag["run"]
    assert "CANDIDATE" not in diag["env"]


# ------------------------------------------------------------- execute the refuse step


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _candidate(tmp_path: Path) -> Path:
    cand = tmp_path / "candidate"
    cand.mkdir()
    _git(cand, "init", "-q", "-b", "main")
    _git(cand, "config", "user.email", "t@example.test")
    _git(cand, "config", "user.name", "T")
    (cand / "a.txt").write_text("a\n", encoding="utf-8")
    _git(cand, "add", "a.txt")
    _git(cand, "commit", "-qm", "base")
    return cand


def _run_refuse(tmp_path: Path, cand: Path):
    temp = tmp_path / "rtemp"
    temp.mkdir(exist_ok=True)
    context = {"inputs": {"candidate-path": str(cand)}, "runner": {"temp": str(temp)}}
    return _run_step(_refuse_step(), context, tmp_path / "run")


def _fresh(tmp_path: Path) -> None:
    (tmp_path / "run").mkdir(exist_ok=True)


def test_refuse_step_passes_a_clean_candidate(tmp_path: Path) -> None:
    _fresh(tmp_path)
    cand = _candidate(tmp_path)
    (cand / ".nexus-core").mkdir()
    (cand / ".nexus-core" / "config.toml").write_text("x = 1\n", encoding="utf-8")
    assert _run_refuse(tmp_path, cand).returncode == 0


def test_refuse_step_rejects_committed_receipt(tmp_path: Path) -> None:
    _fresh(tmp_path)
    cand = _candidate(tmp_path)
    rdir = cand / ".nexus-core" / "receipts"
    rdir.mkdir(parents=True)
    (rdir / FUTURE_NAME).write_text("{}", encoding="utf-8")
    _git(cand, "add", "-f", ".nexus-core/receipts")
    _git(cand, "commit", "-qm", "planted")
    result = _run_refuse(tmp_path, cand)
    assert result.returncode == 1
    assert "NEXUS_CORE_GATE_CANDIDATE_RECEIPTS_PRESENT" in result.stderr


def test_refuse_step_rejects_untracked_receipts_dir_and_symlinks(tmp_path: Path) -> None:
    _fresh(tmp_path)
    cand = _candidate(tmp_path)
    (cand / ".nexus-core" / "receipts").mkdir(parents=True)
    assert _run_refuse(tmp_path, cand).returncode == 1

    cand2 = tmp_path / "c2"
    cand2.mkdir()
    _git(cand2, "init", "-q", "-b", "main")
    _git(cand2, "config", "user.email", "t@example.test")
    _git(cand2, "config", "user.name", "T")
    (cand2 / "a").write_text("a", encoding="utf-8")
    _git(cand2, "add", "a")
    _git(cand2, "commit", "-qm", "x")
    (cand2 / ".nexus-core").mkdir()
    (cand2 / ".nexus-core" / "receipts").symlink_to(tmp_path / "nowhere")  # dangling
    assert _run_refuse(tmp_path, cand2).returncode == 1

    cand3 = tmp_path / "c3"
    cand3.mkdir()
    _git(cand3, "init", "-q", "-b", "main")
    _git(cand3, "config", "user.email", "t@example.test")
    _git(cand3, "config", "user.name", "T")
    (cand3 / "a").write_text("a", encoding="utf-8")
    _git(cand3, "add", "a")
    _git(cand3, "commit", "-qm", "x")
    (cand3 / ".nexus-core").symlink_to(tmp_path)
    result = _run_refuse(tmp_path, cand3)
    assert result.returncode == 1
    assert "symlink" in result.stderr


# ---------------------------------------------------------- execute the sign step


def _fake_uvx(tmp_path: Path) -> None:
    bindir = tmp_path / "run" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    uvx = bindir / "uvx"
    # uvx --from sigstore==X sigstore sign --bundle B FILE
    uvx.write_text(
        '#!/bin/sh\nprintf "{}" > "$6"\nprintf "%s\\n" "$7" > "$(dirname "$6")/signed.log"\n',
        encoding="utf-8",
    )
    uvx.chmod(0o755)


def _sign(tmp_path: Path, cand: Path, pointer_text: str | None):
    temp = tmp_path / "rtemp"
    temp.mkdir(exist_ok=True)
    if pointer_text is not None:
        (temp / "nexus-core-receipt-pointer").write_text(pointer_text, encoding="utf-8")
    _fake_uvx(tmp_path)
    context = _github("https://api.github.test", run_attempt=1)
    context["runner"] = {"temp": str(temp)}
    context["inputs"] = {"candidate-path": str(cand)}
    return _run_step(_step(ISSUE_GATE, "sign"), context, tmp_path / "run"), temp


def _receipts_dir(cand: Path) -> Path:
    d = cand / ".nexus-core" / "receipts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_sign_step_signs_exactly_the_pointed_receipt_copy(tmp_path: Path) -> None:
    cand = tmp_path / "candidate"
    rdir = _receipts_dir(cand)
    good = rdir / GOOD_NAME
    good.write_text('{"ok": 1}', encoding="utf-8")
    # A newer-looking file in the tree must be ignored.
    (rdir / FUTURE_NAME).write_text('{"forged": 1}', encoding="utf-8")
    result, temp = _sign(tmp_path, cand, f"{good.resolve()}\n")
    assert result.returncode == 0, result.stderr
    out = temp / "nexus-core-receipt-out"
    assert sorted(p.name for p in out.iterdir() if p.name != "signed.log") == [
        GOOD_NAME,
        GOOD_NAME + ".sigstore.json",
    ]
    assert result.outputs["receipt-file"] == str(out / GOOD_NAME)
    assert result.outputs["bundle-file"] == str(out / (GOOD_NAME + ".sigstore.json"))
    assert (out / GOOD_NAME).read_text(encoding="utf-8") == '{"ok": 1}'
    assert not (rdir / (GOOD_NAME + ".sigstore.json")).exists()


@pytest.mark.parametrize("pointer", [None, "", "\n"])
def test_sign_step_without_pointer_signs_nothing(tmp_path: Path, pointer: str | None) -> None:
    cand = tmp_path / "candidate"
    (_receipts_dir(cand) / GOOD_NAME).write_text("{}", encoding="utf-8")
    result, temp = _sign(tmp_path, cand, pointer)
    assert result.returncode == 0
    assert "NEXUS_CORE_SIGN: no receipt" in result.stderr
    assert "receipt-file" not in result.outputs
    assert not (temp / "nexus-core-receipt-out").exists()


def test_sign_step_rejects_invalid_pointers(tmp_path: Path) -> None:
    cand = tmp_path / "candidate"
    rdir = _receipts_dir(cand)
    real = rdir / GOOD_NAME
    real.write_text("{}", encoding="utf-8")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / GOOD_NAME).write_text("{}", encoding="utf-8")
    (rdir / "notes.json").write_text("{}", encoding="utf-8")
    link = rdir / "20261016T010203.000005+0000-0123456789ab.json"
    link.symlink_to(real)
    nested = rdir / "sub"
    nested.mkdir()
    (nested / GOOD_NAME).write_text("{}", encoding="utf-8")
    bad = [
        str(outside / GOOD_NAME),  # outside the receipts dir
        str(rdir / "notes.json"),  # bad name
        str(link),  # symlink
        str(nested / GOOD_NAME),  # not directly inside
        str(rdir / "missing.json"),  # not a file
        GOOD_NAME,  # relative
        str(real) + "\n" + str(real),  # two lines
    ]
    for index, pointer in enumerate(bad):
        sub = tmp_path / f"case{index}"
        sub.mkdir()
        result, temp = _sign(sub, cand, pointer)
        assert result.returncode == 1, (pointer, result.stderr)
        assert "NEXUS_CORE_SIGN_RECEIPT_POINTER_INVALID" in result.stderr
        assert "receipt-file" not in result.outputs
        assert not (temp / "nexus-core-receipt-out").exists()


def test_sign_step_rebuilds_a_stale_out_dir(tmp_path: Path) -> None:
    cand = tmp_path / "candidate"
    good = _receipts_dir(cand) / GOOD_NAME
    good.write_text("{}", encoding="utf-8")
    temp = tmp_path / "rtemp"
    stale = temp / "nexus-core-receipt-out"
    stale.mkdir(parents=True)
    (stale / "old.json").write_text("{}", encoding="utf-8")
    result, _ = _sign(tmp_path, cand, f"{good.resolve()}\n")
    assert result.returncode == 0, result.stderr
    assert not (stale / "old.json").exists()
    assert os.path.exists(stale / GOOD_NAME)


def test_refuse_step_removes_a_stale_pointer_even_when_it_refuses(tmp_path: Path) -> None:
    cand = _candidate(tmp_path)
    temp = tmp_path / "rtemp"
    temp.mkdir()
    (temp / "nexus-core-receipt-pointer").write_text("/stale/receipt.json\n", encoding="utf-8")
    (cand / ".nexus-core" / "receipts").mkdir(parents=True)
    (tmp_path / "run").mkdir()
    result = _run_refuse(tmp_path, cand)
    assert result.returncode != 0
    assert "NEXUS_CORE_GATE_CANDIDATE_RECEIPTS_PRESENT" in result.stderr
    assert not (temp / "nexus-core-receipt-pointer").exists()


def test_sign_step_empties_the_upload_dir_when_there_is_no_receipt(tmp_path: Path) -> None:
    cand = _candidate(tmp_path)
    temp = tmp_path / "rtemp"
    stale = temp / "nexus-core-receipt-out"
    stale.mkdir(parents=True)
    (stale / GOOD_NAME).write_text("{}", encoding="utf-8")
    result, _ = _sign(tmp_path, cand, None)
    assert result.returncode == 0, result.stderr
    assert "receipt-file" not in result.outputs
    assert not stale.exists()


def test_sign_step_runs_only_after_issue_check_ran() -> None:
    sign = _step(ISSUE_GATE, "sign")
    assert sign["if"] == (
        "always() && (steps.check.outcome == 'success' || steps.check.outcome == 'failure')"
    )
    names = _names()
    assert names.index("Verify exact Issue-bound candidate") < names.index(
        "Sign the receipt issue-check wrote (Sigstore keyless)"
    )
