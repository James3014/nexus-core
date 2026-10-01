from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest

SCRIPT=Path("scripts/bench/nexus_verify_g3.py")

@pytest.fixture(scope="module")
def gate():
    return runpy.run_path(str(SCRIPT), run_name="nexus_verify_g3_test")

@pytest.fixture(scope="module")
def report(gate):
    return gate["score"]()

def test_g3_supported(report, gate):
    assert report["state"]==gate["SUPPORTED_STATE"]
    assert report["controlled_blind_evaluation"] is True

def test_selection_thresholds(report):
    s=report["summary"]
    assert s["positive_exact_action"]==28
    assert s["negative_false_trigger_count"]==0
    assert s["critical_false_trigger_count"]==0
    assert s["explicit_locator_exact"]==24
    assert s["hallucinated_locator_count"]==0

def test_explanations_and_claim_ceiling(report):
    s=report["summary"]
    assert s["explanation_pass"]==8
    assert s["claim_ceiling_violation_count"]==0
    assert s["reason_code_mismatches"]==[]

def test_evaluator_operation_is_clean(report):
    op=report["evaluator_operation"]
    assert op["status"]=="COMPLETED"
    assert op["exit_code"]==0
    assert op["requested_model"]=="gemini-3.8-flash-high"
    assert op["observed_model"]=="gemini-3.8-flash-high"
    assert op["rotations"]==0
    assert op["tool_event_count"]==0
    assert op["observed_changed_paths"]==[]
    assert report["summary"]["evidence_failures"]==[]

def test_all_thresholds_pass(report):
    assert all(report["threshold_results"].values())

def test_report_hash_recomputes(report, gate):
    body={k:v for k,v in report.items() if k!="report_hash"}
    assert report["report_hash"]==gate["canonical_hash"](body)

def test_cli_writes_report(tmp_path:Path, gate, capsys:pytest.CaptureFixture[str]):
    out=tmp_path/"g3.json"
    rc=gate["main"](["--report",str(out)])
    assert rc==0
    assert json.loads(capsys.readouterr().out)==json.loads(out.read_text())

def test_claim_ceiling_text_is_bounded(report):
    assert report["claim_ceiling"]=="CONTROLLED_CONVERSATION_FIT_ONLY"
    assert any("does not establish ChatGPT platform auto-selection" in x for x in report["limitations"])
