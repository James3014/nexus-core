#!/usr/bin/env python3
"""G3 controlled conversation-fit scorer for Nexus Verify.

Scores one frozen blind model output against the preregistered G3 corpus/labels.
This is controlled semantic-evaluation evidence only. It does not establish
ChatGPT directory routing, proactive recommendation, or public-user behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from product.protocol.generic_verification import canonical_hash  # noqa: E402

SCHEMA = "nexus.verify.g3.conversation-fit.v1"
SUPPORTED_STATE = "NEXUS_VERIFY_CONVERSATION_FIT_SUPPORTED"
UNSUPPORTED_STATE = "NEXUS_VERIFY_CONVERSATION_FIT_NOT_SUPPORTED"
INVALID_STATE = "INVALID_G3_EVIDENCE"

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
CORPUS_PATH = _FIXTURES / "nexus_verify_g3_corpus.json"
EXPECTED_PATH = _FIXTURES / "nexus_verify_g3_expected.json"
OUTPUT_PATH = _FIXTURES / "nexus_verify_g3_agy_output.json"
RAW_OUTPUT_PATH = _FIXTURES / "nexus_verify_g3_agy_stdout.raw.json"
PROMPT_PATH = _FIXTURES / "nexus_verify_g3_blind_prompt.txt"
OPERATION_PATH = _FIXTURES / "nexus_verify_g3_agy_operation.json"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _by_id(rows: object, *, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        raise ValueError(f"{label} must be a list")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ValueError(f"{label} contains malformed row")
        row_id = row["id"]
        if row_id in result:
            raise ValueError(f"{label} contains duplicate id {row_id}")
        result[row_id] = row
    return result


def _operation_evidence(operation: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    checks = {
        "status": operation.get("status") == "COMPLETED",
        "exit_code": operation.get("exit_code") == 0,
        "requested_model": operation.get("requested_model") == "gemini-3.8-flash-high",
        "observed_model": operation.get("observed_model") == "gemini-3.8-flash-high",
        "rotations": operation.get("rotations") == 0,
        "tool_event_count": operation.get("tool_event_count") == 0,
        "observed_changed_paths": operation.get("observed_changed_paths") == [],
        "prompt_hash": operation.get("blind_prompt_sha256") == _sha256(PROMPT_PATH),
        "stdout_hash": operation.get("stdout_sha256") == _sha256(RAW_OUTPUT_PATH),
    }
    for name, ok in checks.items():
        if not ok:
            failures.append(f"OPERATION_{name.upper()}_MISMATCH")
    return not failures, failures


def score() -> dict[str, Any]:
    corpus = _read_json(CORPUS_PATH)
    expected = _read_json(EXPECTED_PATH)
    output = _read_json(OUTPUT_PATH)
    raw_output = _read_json(RAW_OUTPUT_PATH)
    operation = _read_json(OPERATION_PATH)

    evidence_failures: list[str] = []
    if output != raw_output:
        evidence_failures.append("PARSED_OUTPUT_DIFFERS_FROM_RAW_OUTPUT")
    operation_ok, operation_failures = _operation_evidence(operation)
    evidence_failures.extend(operation_failures)

    corpus_selection = _by_id(corpus.get("selection_prompts"), label="corpus selection")
    corpus_explanations = _by_id(corpus.get("explanation_cases"), label="corpus explanations")
    observed_selection = _by_id(output.get("selection_results"), label="selection results")
    observed_explanations = _by_id(output.get("explanation_results"), label="explanation results")
    expected_selection = expected.get("selections")
    expected_explanations = expected.get("explanations")
    thresholds = expected.get("thresholds")

    if not isinstance(expected_selection, dict) or not isinstance(expected_explanations, dict):
        raise ValueError("expected labels malformed")
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds malformed")

    expected_ids = set(expected_selection)
    if set(corpus_selection) != expected_ids:
        evidence_failures.append("CORPUS_SELECTION_IDS_DO_NOT_MATCH_EXPECTED")
    if set(observed_selection) != expected_ids:
        evidence_failures.append("OUTPUT_SELECTION_IDS_DO_NOT_MATCH_EXPECTED")
    if set(corpus_explanations) != set(expected_explanations):
        evidence_failures.append("CORPUS_EXPLANATION_IDS_DO_NOT_MATCH_EXPECTED")
    if set(observed_explanations) != set(expected_explanations):
        evidence_failures.append("OUTPUT_EXPLANATION_IDS_DO_NOT_MATCH_EXPECTED")

    positive_ids = [f"P{i:02d}" for i in range(1, 29)]
    locator_ids = [f"P{i:02d}" for i in range(1, 25)]
    missing_locator_ids = [f"P{i:02d}" for i in range(25, 29)]
    negative_ids = [f"N{i:02d}" for i in range(1, 19)]
    critical_negative_ids = list(expected.get("critical_negative_ids", []))

    positive_action_failures: list[str] = []
    locator_failures: list[str] = []
    hallucinated_locator_ids: list[str] = []
    negative_false_trigger_ids: list[str] = []
    critical_false_trigger_ids: list[str] = []

    for row_id in positive_ids:
        observed = observed_selection.get(row_id, {})
        wanted = expected_selection.get(row_id, {})
        if observed.get("action") != wanted.get("action"):
            positive_action_failures.append(row_id)

    for row_id in locator_ids:
        observed = observed_selection.get(row_id, {})
        wanted = expected_selection.get(row_id, {})
        if observed.get("action") != "CALL_TOOL" or observed.get("arguments") != wanted.get("arguments"):
            locator_failures.append(row_id)

    for row_id in missing_locator_ids:
        observed = observed_selection.get(row_id, {})
        if observed.get("arguments") is not None:
            hallucinated_locator_ids.append(row_id)

    for row_id in negative_ids:
        observed = observed_selection.get(row_id, {})
        if observed.get("action") != "DO_NOT_CALL" or observed.get("arguments") is not None:
            negative_false_trigger_ids.append(row_id)

    for row_id in critical_negative_ids:
        observed = observed_selection.get(row_id, {})
        if observed.get("action") != "DO_NOT_CALL" or observed.get("arguments") is not None:
            critical_false_trigger_ids.append(row_id)

    explanation_failures: list[str] = []
    claim_ceiling_violations: list[str] = []
    reason_code_mismatches: list[str] = []

    for row_id, wanted in expected_explanations.items():
        observed = observed_explanations.get(row_id, {})
        approvals_ok = (
            observed.get("merge_approved") is wanted.get("merge_approved")
            and observed.get("release_approved") is wanted.get("release_approved")
            and observed.get("deploy_approved") is wanted.get("deploy_approved")
        )
        if any(
            observed.get(field) is True
            for field in ("merge_approved", "release_approved", "deploy_approved")
        ):
            claim_ceiling_violations.append(row_id)

        wanted_reasons = set(wanted.get("reason_codes", []))
        observed_reasons_raw = observed.get("reason_codes_acknowledged")
        observed_reasons = set(observed_reasons_raw) if isinstance(observed_reasons_raw, list) else set()
        reasons_ok = wanted_reasons.issubset(observed_reasons)
        if not reasons_ok:
            reason_code_mismatches.append(row_id)

        text_ok = isinstance(observed.get("user_text"), str) and bool(observed["user_text"].strip())
        status_ok = observed.get("evidence_status") == wanted.get("evidence_status")
        if not (approvals_ok and reasons_ok and text_ok and status_ok):
            explanation_failures.append(row_id)

    positive_exact = len(positive_ids) - len(positive_action_failures)
    locator_exact = len(locator_ids) - len(locator_failures)
    explanation_pass = len(expected_explanations) - len(explanation_failures)

    threshold_results = {
        "positive_exact_action": positive_exact >= thresholds["positive_exact_action_min"],
        "negative_false_trigger": len(negative_false_trigger_ids)
        <= thresholds["negative_false_trigger_max"],
        "critical_false_trigger": len(critical_false_trigger_ids)
        <= thresholds["critical_false_trigger_max"],
        "explicit_locator_exact": locator_exact >= thresholds["explicit_locator_exact_min"],
        "hallucinated_locator": len(hallucinated_locator_ids)
        <= thresholds["hallucinated_locator_max"],
        "explanation_quality": explanation_pass >= thresholds["explanation_pass_min"],
        "claim_ceiling": len(claim_ceiling_violations)
        <= thresholds["claim_ceiling_violation_max"],
        "operation_evidence": operation_ok and not evidence_failures,
    }

    supported = all(threshold_results.values())
    state = SUPPORTED_STATE if supported else UNSUPPORTED_STATE

    summary = {
        "positive_exact_action": positive_exact,
        "positive_total": len(positive_ids),
        "positive_action_failures": positive_action_failures,
        "negative_false_trigger_count": len(negative_false_trigger_ids),
        "negative_total": len(negative_ids),
        "negative_false_trigger_ids": negative_false_trigger_ids,
        "critical_false_trigger_count": len(critical_false_trigger_ids),
        "critical_false_trigger_ids": critical_false_trigger_ids,
        "explicit_locator_exact": locator_exact,
        "explicit_locator_total": len(locator_ids),
        "locator_failures": locator_failures,
        "hallucinated_locator_count": len(hallucinated_locator_ids),
        "hallucinated_locator_ids": hallucinated_locator_ids,
        "explanation_pass": explanation_pass,
        "explanation_total": len(expected_explanations),
        "explanation_failures": explanation_failures,
        "reason_code_mismatches": reason_code_mismatches,
        "claim_ceiling_violation_count": len(claim_ceiling_violations),
        "claim_ceiling_violations": claim_ceiling_violations,
        "evidence_failures": evidence_failures,
    }

    decision_basis = {
        "state": state,
        "threshold_results": threshold_results,
        "summary": summary,
        "evaluator": {
            "provider": operation.get("provider"),
            "requested_model": operation.get("requested_model"),
            "observed_model": operation.get("observed_model"),
            "operation_id": operation.get("operation_id"),
            "rotations": operation.get("rotations"),
            "tool_event_count": operation.get("tool_event_count"),
            "observed_changed_paths": operation.get("observed_changed_paths"),
            "blind_prompt_sha256": operation.get("blind_prompt_sha256"),
            "stdout_sha256": operation.get("stdout_sha256"),
        },
    }

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "controlled_blind_evaluation": True,
        "state": state,
        "claim_ceiling": "CONTROLLED_CONVERSATION_FIT_ONLY",
        "preregistration": expected.get("preregistration"),
        "thresholds": thresholds,
        "threshold_results": threshold_results,
        "summary": summary,
        "evaluator_operation": operation,
        "decision_hash": canonical_hash(decision_basis),
        "limitations": [
            "one blind Agy/Gemini evaluation does not establish ChatGPT platform auto-selection",
            "controlled prompts do not establish real-user usefulness or product-market fit",
            "public plugin discovery, proactive recommendation, and directory ranking are out of scope",
            "G4 public endpoint, OAuth, privacy, retention, and review readiness are out of scope",
        ],
    }
    report["report_hash"] = canonical_hash(report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    report = score()
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.report:
        Path(args.report).write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0 if report["state"] == SUPPORTED_STATE else 2


if __name__ == "__main__":
    raise SystemExit(main())
