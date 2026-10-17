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


def test_null_issue_body_and_proposal_heading() -> None:
    assert parse_issue_items(None) == []  # type: ignore[arg-type]
    assert parse_issue_items("## Proposal\n1. a\n2. b\n") == ["1", "2"]
    with pytest.raises(LocalCheckError) as raised:
        issue_gp.resolve_intent_items(
            _intent({"issue": 5, "on_merge": "KEEP_OPEN", "items": ["1"]}), 5, None  # type: ignore[arg-type]
        )
    assert raised.value.reason_code == "ISSUE_ITEMS_UNKNOWN"


# --- ISSUE_ITEMS_COMPLETE: display-only aggregation across merged PRs (#294) ---


def _merged(number: int, *entries: dict[str, Any]) -> dict[str, Any]:
    return {"number": number, "body": _intent(*entries)}


def _claim(*items: str, issue: int = 85, on_merge: str = "KEEP_OPEN", **extra: Any) -> dict[str, Any]:
    return {"issue": issue, "on_merge": on_merge, "items": list(items), **extra}


def _run_merged(repo: Path, pr_body: str | None, merged: Any) -> dict[str, Any]:
    if not (repo / ".nexus-core" / "issues" / "85.json").exists():
        init_issue_binding(repo, issue_number=85, issue_reader=_reader(repo))
    return check_issue(
        repo,
        issue_number=85,
        issue_reader=_reader(repo),
        pr_body=pr_body,
        merged_claims_reader=lambda _repo, _n: merged,
    )


def _verdict(result: dict[str, Any]) -> dict[str, Any]:
    return _receipt(result)["issue_verification"]


def test_partial_claims_are_incomplete(repo: Path) -> None:
    verdict = _verdict(_run_merged(repo, _intent(_claim("3")), [_merged(10, _claim("1"))]))
    assert verdict["items_status"] == "ISSUE_ITEMS_INCOMPLETE"
    assert verdict["merged_claimed_items"] == ["1"]


def test_all_items_claimed_across_merged_prs_is_complete(repo: Path) -> None:
    merged = [_merged(10, _claim("1", "2")), _merged(11, _claim("3"))]
    result = _run_merged(repo, _intent(_claim("4")), merged)
    receipt = _receipt(result)
    verdict = receipt["issue_verification"]
    assert verdict["items_status"] == "ISSUE_ITEMS_COMPLETE"
    assert verdict["merged_claimed_items"] == ["1", "2", "3"]
    assert result["items_status"] == "ISSUE_ITEMS_COMPLETE"
    assert validate_verification_receipt_payload(receipt)["valid"] is True


def test_complete_is_display_only_and_not_acceptance(repo: Path) -> None:
    result = _run_merged(
        repo, _intent(_claim("4")), [_merged(10, _claim("1", "2", "3"))]
    )
    verdict = _verdict(result)
    assert verdict["items_status"] == "ISSUE_ITEMS_COMPLETE"
    # Verdict, ceiling and reasons are exactly what they are without the aggregation.
    plain = _verdict(
        check_issue(
            repo, issue_number=85, issue_reader=_reader(repo), pr_body=_intent(_claim("4"))
        )
    )
    for key in ("status", "claim_ceiling", "reason_codes"):
        assert verdict[key] == plain[key]
    assert verdict["claim_ceiling"] == "ISSUE_VERIFIED_NOT_RELEASED"
    receipt = _receipt(result)
    text = render_markdown(receipt).replace("\\", "") + render_notice(receipt)
    assert "ISSUE_ITEMS_COMPLETE" in text
    assert "not acceptance" in text
    lowered = text.casefold()
    for forbidden in ("issue is done", "verified behavior", "requirements satisfied", "will close"):
        assert forbidden not in lowered


def test_duplicate_claims_do_not_double_count(repo: Path) -> None:
    merged = [_merged(10, _claim("1", "2")), _merged(11, _claim("2", "3"))]
    verdict = _verdict(_run_merged(repo, _intent(_claim("3")), merged))
    assert verdict["merged_claimed_items"] == ["1", "2", "3"]
    assert verdict["items_status"] == "ISSUE_ITEMS_INCOMPLETE"  # item 4 unclaimed


def test_split_item_is_accounted_for_like_remaining_items(repo: Path) -> None:
    body = _intent(_claim("3", split={"4": 2314}))
    verdict = _verdict(_run_merged(repo, body, [_merged(10, _claim("1"))]))
    assert verdict["items_status"] == "ISSUE_ITEMS_INCOMPLETE"  # item 2 open
    verdict = _verdict(_run_merged(repo, body, [_merged(10, _claim("1", "2"))]))
    assert verdict["items_status"] == "ISSUE_ITEMS_COMPLETE"
    assert verdict["merged_claimed_items"] == ["1", "2"]
    # A split recorded by an earlier merged PR also accounts for its item.
    merged = [_merged(10, _claim("1", "2", split={"4": 2314}))]
    assert _verdict(_run_merged(repo, _intent(_claim("3")), merged))["items_status"] == "ISSUE_ITEMS_COMPLETE"


def test_claims_for_another_issue_or_close_intent_do_not_count(repo: Path) -> None:
    merged = [
        _merged(10, _claim("1", "2", issue=999)),
        _merged(11, _claim("1", "2", on_merge="CLOSE")),
        _merged(12, _claim("7")),  # unknown id is ignored, not a claim
    ]
    verdict = _verdict(_run_merged(repo, _intent(_claim("3")), merged))
    assert verdict["merged_claimed_items"] == []
    assert verdict["items_status"] == "ISSUE_ITEMS_INCOMPLETE"


def test_malformed_merged_bodies_are_ignored(repo: Path) -> None:
    merged = [
        {"number": 10, "body": None},
        {"number": 11, "body": "<!-- NEXUS_ISSUE_INTENT_V1 not json NEXUS_ISSUE_INTENT_V1 -->"},
        {"number": "x", "body": _intent(_claim("1"))},
        _merged(13, _claim("2")),
    ]
    verdict = _verdict(_run_merged(repo, _intent(_claim("3")), merged))
    assert verdict["merged_claimed_items"] == ["2"]


@pytest.mark.parametrize("merged", [None, "garbage"])
def test_unknown_source_never_reports_complete(repo: Path, merged: Any) -> None:
    verdict = _verdict(_run_merged(repo, _intent(_claim("1", "2", "3", "4")), merged))
    assert verdict["items_status"] == "ISSUE_ITEMS_SOURCE_UNAVAILABLE"
    assert "merged_claimed_items" not in verdict


def test_reader_exception_is_source_unavailable(repo: Path) -> None:
    def boom(_repo: str, _n: int) -> Any:
        raise OSError("network down")

    init_issue_binding(repo, issue_number=85, issue_reader=_reader(repo))
    result = check_issue(
        repo,
        issue_number=85,
        issue_reader=_reader(repo),
        pr_body=_intent(_claim("1")),
        merged_claims_reader=boom,
    )
    assert result["status"] == "VERIFIED"
    assert _verdict(result)["items_status"] == "ISSUE_ITEMS_SOURCE_UNAVAILABLE"


def test_no_default_network_when_issue_reader_injected(repo: Path) -> None:
    verdict = _verdict(_run(repo, _intent(_claim("1"))))
    assert verdict["items_status"] == "ISSUE_ITEMS_SOURCE_UNAVAILABLE"


def test_no_items_claim_adds_no_aggregation_fields(repo: Path) -> None:
    verdict = _verdict(_run_merged(repo, None, [_merged(10, _claim("1"))]))
    assert not {"items_status", "merged_claimed_items"} & set(verdict)


def test_status_without_merged_list_or_bad_value_is_malformed(repo: Path) -> None:
    receipt = _receipt(_run_merged(repo, _intent(_claim("1")), [_merged(10, _claim("2"))]))
    assert validate_verification_receipt_payload(receipt)["valid"] is True
    bad = json.loads(json.dumps(receipt))
    bad["issue_verification"]["items_status"] = "ISSUE_DONE"
    assert validate_verification_receipt_payload(bad)["valid"] is False
    lone = json.loads(json.dumps(receipt))
    del lone["issue_verification"]["claimed_items"], lone["issue_verification"]["remaining_items"]
    assert validate_verification_receipt_payload(lone)["valid"] is False


def test_timeline_events_to_merged_prs() -> None:
    def event(number: int, merged: bool, repo: str = "example/project", kind: str = "cross-referenced") -> dict[str, Any]:
        return {
            "event": kind,
            "source": {
                "type": "issue",
                "issue": {
                    "number": number,
                    "body": f"body {number}",
                    "repository": {"full_name": repo},
                    "pull_request": {"merged_at": "2026-10-17T00:00:00Z" if merged else None},
                },
            },
        }

    events = [
        event(1, True),
        event(2, False),  # unmerged PR
        event(3, True, repo="other/fork"),  # other repository
        event(4, True, kind="referenced"),
        {"event": "cross-referenced", "source": {"type": "issue", "issue": {"number": 5, "body": "x"}}},  # plain issue
        event(6, True, repo="Example/Project"),
    ]
    assert issue_gp.merged_prs_from_timeline("example/project", events) == [
        {"number": 1, "body": "body 1"},
        {"number": 6, "body": "body 6"},
    ]
