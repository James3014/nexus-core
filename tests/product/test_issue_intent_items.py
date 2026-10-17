"""KEEP_OPEN intent items/split recorded in the receipt and summary (#276)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from product.clients import issue_golden_path as issue_gp
from product.clients.issue_golden_path import (
    check_issue,
    init_issue_binding,
    parse_issue_items,
)
from product.clients.local_golden_path import (
    LocalCheckError,
    init_repository,
    validate_verification_receipt_payload,
)
from product.clients.receipt_summary import render_markdown, render_notice

ISSUE_BODY = """## Problem
1. first thing
2. second thing
3. third thing
4. fourth thing

## Done when
- [ ] ignored checklist
"""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.email", "test@example.test")
    _git(path, "config", "user.name", "Test User")
    _git(path, "remote", "add", "origin", "https://github.com/example/project.git")
    (path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(path, "add", "app.py")
    _git(path, "commit", "-m", "base")
    init_repository(
        path,
        base_ref="main",
        allowed_patterns=("app.py",),
        verifier_command=(sys.executable, "-c", "raise SystemExit(0)"),
    )
    (path / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    return path


def _reader(repo: Path):  # type: ignore[no-untyped-def]
    identity = issue_gp._verification_contract_identity(repo)["config_hash"]  # pyright: ignore
    body = ISSUE_BODY + f"\n<!-- NEXUS_CORE_EVIDENCE_UNIVERSE: {identity} -->\n"

    def read(github_repo: str, number: int) -> dict[str, object]:
        return {
            "number": 85,
            "title": "Multi item",
            "body": body,
            "state": "open",
            "author_association": "OWNER",
            "user": {"login": "maintainer"},
        }

    return read


def _intent(*entries: dict[str, Any]) -> str:
    return "prose\n<!-- NEXUS_ISSUE_INTENT_V1\n" + json.dumps(list(entries)) + "\nNEXUS_ISSUE_INTENT_V1 -->\n"


def _run(repo: Path, pr_body: str | None) -> dict[str, Any]:
    init_issue_binding(repo, issue_number=85, issue_reader=_reader(repo))
    return check_issue(repo, issue_number=85, issue_reader=_reader(repo), pr_body=pr_body)


def _receipt(result: dict[str, Any]) -> dict[str, Any]:
    return json.loads(result["receipt_path"].read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "body",
    [None, _intent({"issue": 85, "on_merge": "KEEP_OPEN"}), _intent({"issue": 85, "on_merge": "CLOSE"})],
)
def test_absent_items_leaves_receipt_unchanged(repo: Path, body: str | None) -> None:
    result = _run(repo, body)
    verdict = _receipt(result)["issue_verification"]
    assert result["status"] == "VERIFIED"
    assert not {"claimed_items", "remaining_items", "split"} & set(verdict)
    assert "claimed_items" not in result


def test_valid_items_and_split_are_recorded(repo: Path) -> None:
    body = _intent({"issue": 85, "on_merge": "KEEP_OPEN", "items": ["3"], "split": {"4": 2314}})
    result = _run(repo, body)
    receipt = _receipt(result)
    verdict = receipt["issue_verification"]
    assert result["status"] == "VERIFIED"
    assert verdict["claimed_items"] == ["3"]
    assert verdict["remaining_items"] == ["1", "2"]
    assert verdict["split"] == {"4": 2314}
    assert validate_verification_receipt_payload(receipt)["valid"] is True


def test_intent_for_another_issue_is_ignored(repo: Path) -> None:
    body = _intent({"issue": 999, "on_merge": "KEEP_OPEN", "items": ["nope"]})
    assert "claimed_items" not in _receipt(_run(repo, body))["issue_verification"]


@pytest.mark.parametrize("field", [{"items": ["9"]}, {"split": {"9": 5}}])
def test_unknown_item_id_fails_closed_with_receipt(repo: Path, field: dict[str, Any]) -> None:
    init_issue_binding(repo, issue_number=85, issue_reader=_reader(repo))
    body = _intent({"issue": 85, "on_merge": "KEEP_OPEN", **field})
    with pytest.raises(LocalCheckError) as raised:
        check_issue(repo, issue_number=85, issue_reader=_reader(repo), pr_body=body)
    assert raised.value.reason_code == "ISSUE_ITEMS_UNKNOWN"
    assert raised.value.receipt_path is not None


def test_items_with_close_are_rejected(repo: Path) -> None:
    init_issue_binding(repo, issue_number=85, issue_reader=_reader(repo))
    body = _intent({"issue": 85, "on_merge": "CLOSE", "items": ["1"]})
    with pytest.raises(LocalCheckError) as raised:
        check_issue(repo, issue_number=85, issue_reader=_reader(repo), pr_body=body)
    assert raised.value.reason_code == "ISSUE_ITEMS_REQUIRE_KEEP_OPEN"


@pytest.mark.parametrize(
    "field",
    [
        {"items": "3"},
        {"items": []},
        {"items": ["3", "3"]},
        {"items": [3]},
        {"items": ["3"], "split": {"3": 5}},
        {"items": ["3"], "split": {"4": "x"}},
        {"items": ["3"], "split": {"4": 85}},
    ],
)
def test_malformed_items_fail_closed(repo: Path, field: dict[str, Any]) -> None:
    init_issue_binding(repo, issue_number=85, issue_reader=_reader(repo))
    body = _intent({"issue": 85, "on_merge": "KEEP_OPEN", **field})
    with pytest.raises(LocalCheckError) as raised:
        check_issue(repo, issue_number=85, issue_reader=_reader(repo), pr_body=body)
    assert raised.value.reason_code == "ISSUE_ITEMS_MALFORMED"


def test_summary_shows_claimed_and_remaining_items(repo: Path) -> None:
    body = _intent({"issue": 85, "on_merge": "KEEP_OPEN", "items": ["3"], "split": {"4": 2314}})
    receipt = _receipt(_run(repo, body))
    text = render_markdown(receipt).replace("\\", "")
    assert "| claimed items | 3 |" in text
    assert "| remaining items | 1, 2 |" in text
    assert "4 -> #2314" in text
    assert "items claimed 3 remaining 1, 2" in render_notice(receipt)
    plain = json.loads(json.dumps(receipt))
    for key in ("claimed_items", "remaining_items", "split"):
        del plain["issue_verification"][key]
    assert "claimed items" not in render_markdown(plain)
    assert "items claimed" not in render_notice(plain)


def test_legacy_receipt_without_item_fields_stays_valid(repo: Path) -> None:
    receipt = _receipt(_run(repo, None))
    assert validate_verification_receipt_payload(receipt)["valid"] is True


def test_partial_item_fields_in_a_receipt_are_malformed(repo: Path) -> None:
    from product.clients.local_golden_path import _valid_intent_items  # pyright: ignore

    assert _valid_intent_items({"claimed_items": ["1"]}) is False
    assert _valid_intent_items({"claimed_items": ["1"], "remaining_items": [], "split": {"2": "x"}}) is False
    assert _valid_intent_items({}) is True


def test_parse_issue_items_numbered_sections_and_fences() -> None:
    body = "## Problem\n1. a\n2) b\n```\n3. fenced\n```\n## Other\n9. outside\n## Change\n4. c\n"
    assert parse_issue_items(body) == ["1", "2", "4"]


def test_parse_issue_items_checklist_fallback() -> None:
    assert parse_issue_items("intro\n- [ ] one\n- [x] two\n* [ ] three\n") == ["1", "2", "3"]
    assert parse_issue_items("no items here") == []


def test_issue_without_items_rejects_claims() -> None:
    with pytest.raises(LocalCheckError) as raised:
        issue_gp.resolve_intent_items(
            _intent({"issue": 5, "on_merge": "KEEP_OPEN", "items": ["1"]}), 5, "nothing"
        )
    assert raised.value.reason_code == "ISSUE_ITEMS_UNKNOWN"
