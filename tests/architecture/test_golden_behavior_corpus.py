"""Structural checks for the Golden Behavior Corpus.

These tests never execute the witness tests; run
``scripts/golden_behavior_eval.py`` for that.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path

from tests.golden_behavior.corpus import CASES, FINDINGS

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "golden_behavior" / "corpus.py"

CLASSIFICATIONS = {"invariant", "regression", "compatibility", "security"}
SCENARIOS = {
    "normal",
    "boundary",
    "failure",
    "authority_conflict",
    "partial_state",
    "recovery",
    "idempotency",
    "malformed_input",
    "stale_state",
}


def _headings(path: Path) -> set[str]:
    return {
        match.group(1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if (match := re.match(r"^#{1,6}\s+(.*?)\s*$", line))
    }


def test_corpus_size_and_taxonomy() -> None:
    assert 50 <= len(CASES) <= 100
    assert {case.classification for case in CASES} == CLASSIFICATIONS
    assert {case.scenario for case in CASES} == SCENARIOS
    assert {case.status for case in CASES} <= {"covered", "finding"}


def test_case_ids_are_unique_and_well_formed() -> None:
    ids = [case.case_id for case in CASES]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"NCG-\d{3}", cid) for cid in ids)


def test_every_case_has_expected_behavior_and_authority() -> None:
    for case in CASES:
        assert case.title.strip(), case.case_id
        assert case.expected_behavior.strip(), case.case_id
        assert case.authority_sources, case.case_id


def test_local_authority_paths_and_headings_exist() -> None:
    for case in CASES:
        for source in case.authority_sources:
            if source.startswith("https://"):
                assert source.startswith("https://github.com/James3014/"), source
                continue
            path_part, _, anchor = source.partition("#")
            path = ROOT / path_part
            assert path.is_file(), f"{case.case_id}: {source}"
            if anchor and path.suffix == ".md":
                assert anchor in _headings(path), f"{case.case_id}: {source}"


def test_covered_cases_have_witnesses_and_findings_have_none() -> None:
    for case in CASES:
        if case.status == "covered":
            assert case.automated_tests, case.case_id
            assert case.finding_id is None, case.case_id
        else:
            assert case.automated_tests == (), case.case_id
            assert case.finding_id is not None, case.case_id


def test_finding_ids_match_findings() -> None:
    finding_ids = [case.finding_id for case in CASES if case.status == "finding"]
    assert len(finding_ids) == len(set(finding_ids))
    assert set(finding_ids) == set(FINDINGS)
    assert all(re.fullmatch(r"NCGF-\d{3}", str(fid)) for fid in finding_ids)
    assert all(text.strip() for text in FINDINGS.values())


def test_witness_node_ids_are_well_formed_and_point_at_files() -> None:
    for case in CASES:
        assert len(set(case.automated_tests)) == len(case.automated_tests), case.case_id
        for nodeid in case.automated_tests:
            path, sep, name = nodeid.partition("::")
            assert sep and name, nodeid
            assert path.startswith("tests/") and path.endswith(".py"), nodeid
            assert (ROOT / path).is_file(), nodeid


def test_witnesses_name_defined_test_functions() -> None:
    defined: dict[str, set[str]] = {}
    for case in CASES:
        for nodeid in case.automated_tests:
            path, _, name = nodeid.partition("::")
            if path not in defined:
                tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
                defined[path] = {
                    node.name
                    for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
            function = name.split("::")[-1].split("[", 1)[0]
            assert function in defined[path], nodeid


def test_corpus_is_a_pure_literal() -> None:
    tree = ast.parse(CORPUS.read_text(encoding="utf-8"))
    cases_node = next(
        node.value
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "CASES"
    )
    assert isinstance(cases_node, ast.Tuple)
    assert len(cases_node.elts) == len(CASES)
    for call in cases_node.elts:
        assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        assert call.func.id == "_c"
        for value in [*call.args, *(keyword.value for keyword in call.keywords)]:
            ast.literal_eval(value)
    findings_node = next(
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "FINDINGS" for t in node.targets)
    )
    assert ast.literal_eval(findings_node) == FINDINGS


def test_distribution_is_reported_consistently() -> None:
    counts = Counter(case.status for case in CASES)
    assert counts["covered"] + counts["finding"] == len(CASES)
    assert counts["covered"] > counts["finding"]
