"""Display-only receipt summary (#273)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from product.clients import cli
from product.clients.receipt_summary import (
    escape_workflow_message,
    render_markdown,
    render_notice,
    render_notice_command,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures" / "receipt_summary_verified.json"
ACTIONS = [
    ROOT / ".github" / "actions" / "issue-gate" / "action.yml",
    ROOT / ".github" / "actions" / "receipt-verify" / "action.yml",
]


def _receipt() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_renders_real_shaped_verified_receipt() -> None:
    text = render_markdown(_receipt(), "ab" * 32).replace("\\", "")
    assert text.startswith("### Nexus Core receipt: UNVERIFIED")
    for subject in ("dependency/nexus-learning", "dependency/nexus-runtime", "nexus/fast-l1"):
        assert subject in text
    assert text.count("| PASS |") == 3
    assert "ISSUE_VERIFIED_NOT_RELEASED" in text
    assert "trusted-base-config" in text
    assert ".github/workflows/trusted-deletion-anchor.yml" in text
    assert "Display only" in text
    assert render_notice(_receipt(), "verified") == (
        "GATE VERIFIED · receipt claims VERIFIED · 3/3 subjects covered · universe trusted-base-config g2"
        " · ISSUE_VERIFIED_NOT_RELEASED"
    )


@pytest.mark.parametrize("drop", [["core_response"], ["issue_verification"], ["outcome", "inputs"]])
def test_partial_receipts_render_without_raising(drop: list[str]) -> None:
    receipt = _receipt()
    for key in drop:
        receipt.pop(key)
    assert "###" in render_markdown(receipt)
    assert "::notice" in render_notice_command(receipt)
    for odd in ({}, {"outcome": "x", "core_response": [], "inputs": 3}):
        render_markdown(odd)
        assert "no declared universe" in render_notice(odd)


def test_markdown_injection_is_escaped() -> None:
    receipt = _receipt()
    evil = "a|b`c\nd<script>alert(1)</script>"
    receipt["core_response"]["verification"]["coverage"]["entries"][0]["logical_subject_id"] = evil
    text = render_markdown(receipt)
    assert "<script>" not in text
    assert "a\\|b\\`c d\\<script\\>" in text
    assert "\nd" not in text


def test_notice_cannot_inject_second_command() -> None:
    message = escape_workflow_message("50%\n::warning::boom\r::error::x")
    assert "\n" not in message and "\r" not in message and "::" not in message
    assert "%25" in message and "%0A" in message
    receipt = copy.deepcopy(_receipt())
    receipt["issue_verification"]["claim_ceiling"] = "x\n::error::pwn"
    command = render_notice_command(receipt)
    assert "\n" not in command
    assert command.count("::") == 2


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["receipt-summary", "--receipt", str(FIXTURE)]) == 0
    assert "### Nexus Core receipt: UNVERIFIED" in capsys.readouterr().out
    assert cli.main(["receipt-summary", "--receipt", str(FIXTURE), "--format", "notice"]) == 0
    assert capsys.readouterr().out.startswith("::notice title=Nexus Core receipt::UNVERIFIED")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert cli.main(["receipt-summary", "--receipt", str(bad)]) == 2
    assert "not readable JSON" in capsys.readouterr().err
    assert cli.main(["receipt-summary", "--receipt", str(tmp_path / "missing.json")]) == 2


@pytest.mark.parametrize("path", ACTIONS, ids=lambda p: p.parent.name)
def test_action_publishes_summary_via_env(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    block = text.split("- name: Publish Core receipt summary", 1)[1].split("\n    - name:", 1)[0]
    assert "continue-on-error: true" in block
    assert "if: always()" in block and "PR_ALREADY_CLOSED_SKIPPED" in block
    assert 'receipt-summary --receipt "$RECEIPT"' in block
    run = block.split("run: |", 1)[1]
    assert "${{" not in run


def test_gate_verdict_leads_notice_and_markdown() -> None:
    receipt = _receipt()
    verified = render_notice(receipt, "verified")
    assert verified.startswith("GATE VERIFIED · receipt claims VERIFIED · 3/3")
    rejected = render_notice(receipt, "rejected")
    assert rejected.startswith("GATE REJECTED · receipt claims VERIFIED")
    assert render_notice(receipt).startswith("UNVERIFIED (producer side; receipt-verify decides)")
    assert render_notice_command(receipt, "rejected").startswith("::warning ")
    assert render_notice_command(receipt, "verified").startswith("::notice ")
    assert render_notice_command(receipt).startswith("::notice ")
    assert render_markdown(receipt, None, "rejected").startswith(
        "### Nexus Core receipt: GATE REJECTED"
    )


def test_cli_gate_verdict_option(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["receipt-summary", "--receipt", str(FIXTURE), "--gate-verdict", "rejected"]
    assert cli.main([*args, "--format", "notice"]) == 0
    assert capsys.readouterr().out.startswith("::warning title=Nexus Core receipt::GATE REJECTED")


def test_markdown_links_images_and_code_breakout_neutralised() -> None:
    receipt = _receipt()
    paths = [
        "foo[approve](https://example.invalid/approve)",
        "![x](https://e.invalid/x.png)",
        "a`b` <b>",
        "see https://evil.invalid and www.evil.invalid",
    ]
    receipt["inputs"]["request"]["change_set"]["paths"] = paths
    receipt["core_response"]["verification"]["coverage"]["entries"][0]["logical_subject_id"] = (
        paths[0]
    )
    text = render_markdown(receipt)
    assert "[approve](" not in text and "![x](" not in text
    assert "foo\\[approve\\]\\(https&#58;//example.invalid/approve\\)" in text
    assert "\\!\\[x\\]" in text
    assert "https://" not in text and "www." not in text
    assert "`" not in text.replace("\\`", "")
    assert "<b>" not in text


def test_cli_deeply_nested_json_exits_2(tmp_path: Path) -> None:
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    assert cli.main(["receipt-summary", "--receipt", str(deep)]) == 2
