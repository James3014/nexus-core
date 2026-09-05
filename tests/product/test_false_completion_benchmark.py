import ast
import math
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import pytest

import product.benchmark as bm
from product.benchmark import (
    BENCHMARK_ID,
    BENCHMARK_SCHEMA,
    CASE_SPEC,
    CASES,
    EXPECTED_CASE_IDS,
    TASK_SET_HASH,
    CaseDefinition,
    CaseOutcome,
    _build,
    _digest,
    _make_specs,
    _run,
    run_benchmark,
    verify_report,
)


def _rehash(payload):
    body = {k: v for k, v in payload.items() if k != "report_hash"}
    return {**body, "report_hash": _digest(body)}


def test_normal_suite_descriptor_hash_repeatability_and_gate():
    first, second = run_benchmark(), run_benchmark()
    assert len(CASES) == len(CASE_SPEC) == len(EXPECTED_CASE_IDS) == 25
    assert first.canonical_json() == second.canonical_json()
    assert first.report_hash == second.report_hash
    assert (first.schema, first.benchmark_id, first.task_set_hash) == (
        BENCHMARK_SCHEMA,
        BENCHMARK_ID,
        TASK_SET_HASH,
    )
    assert first.case_ids == EXPECTED_CASE_IDS
    assert (
        tuple((c.case_id, c.hostile, c.expected, c.operation, c.params) for c in CASES) == CASE_SPEC
    )
    assert (
        first.eligible_count,
        first.hostile_case_count,
        first.detected_count,
        first.false_completion_count,
    ) == (25, 24, 24, 0)
    assert (
        first.infra_invalid_count,
        first.false_completion_rate,
        first.detection_rate,
        first.trust_mismatch_rate,
    ) == (0, 0.0, 1.0, 0.0)
    assert verify_report(first) == ()


def test_exported_globals_cannot_rebind_run_or_verifier(monkeypatch):
    genuine = run_benchmark()
    fake = CaseDefinition(
        "fake", False, CaseOutcome("INPUT_REJECTED"), "reject", {"kind": "status"}
    )
    for name, value in {
        "CASES": (fake,),
        "CASE_SPEC": (("fake", False, "CERTIFICATION", "reject", ()),),
        "EXPECTED_CASE_IDS": ("fake",),
        "TASK_SET_HASH": "sha256:" + "f" * 64,
    }.items():
        monkeypatch.setattr(bm, name, value)
        assert run_benchmark().canonical_json() == genuine.canonical_json()
        assert run_benchmark().report_hash == genuine.report_hash
    assert verify_report(genuine) == ()
    forged = _rehash({**genuine.payload(), "task_set_hash": bm.TASK_SET_HASH})
    assert verify_report(forged)


def test_public_api_is_sealed_against_transitive_module_rebinding(monkeypatch):
    genuine = run_benchmark()
    forged_cases = [
        {**case, "actual": case["expected"], "detected": False, "infra_invalid": False}
        for case in genuine.payload()["cases"]
    ]
    forged_body = {**genuine.payload(), "cases": forged_cases}
    forged = _rehash(forged_body)
    assert verify_report(forged)

    names = (
        "_direct",
        "_legacy",
        "_reject",
        "_receipt",
        "_special",
        "_input",
        "_hash",
        "certify",
        "certify_changeset",
        "validate_receipt",
        "reduce_verification",
        "replace",
        "cast",
        "AcceptanceContract",
        "ChangeSet",
        "EvidenceBundle",
        "VerificationPlan",
        "Observation",
        "ObservationStatus",
        "IntegrityStatus",
        "CertificationInput",
        "CertificationDisposition",
        "CertificationPolicy",
        "CaseOutcome",
        "BenchmarkCaseResult",
        "FalseCompletionReport",
        "BENCHMARK_SCHEMA",
        "BENCHMARK_ID",
        "TASK_SET_HASH",
        "PUBLIC_PROTOCOL_VERSION",
        "IMPLEMENTATION_SCHEMA",
        "PUBLIC_CLAIM_GATE",
        "CLAIM_CEILING",
        "_canonical",
        "_digest",
        "_rate",
        "_shape",
        "_false",
        "_run",
        "_build",
        "_make_dispatch",
    )

    class Poison:
        def __call__(self, *_args, **_kwargs):
            raise AssertionError("rebound benchmark dependency used")

        def __getattr__(self, _name):
            raise AssertionError("rebound benchmark dependency used")

    for name in names:
        monkeypatch.setattr(bm, name, Poison())
        assert run_benchmark().canonical_json() == genuine.canonical_json(), name
        assert verify_report(genuine) == (), name
        monkeypatch.undo()


def test_report_verifier_rejects_full_mutation_matrix_with_rehashed_attacks():
    base = run_benchmark().payload()
    top_values = {
        "schema": "wrong",
        "benchmark_id": "wrong",
        "task_set_hash": "sha256:" + "0" * 64,
        "protocol_version": "wrong",
        "implementation_schema": "wrong",
        "case_ids": list(reversed(base["case_ids"])),
        "eligible_count": -1,
        "infra_invalid_count": -1,
        "hostile_case_count": -1,
        "detected_count": -1,
        "false_completion_count": -1,
        "false_completion_rate": 0.5,
        "detection_rate": 0.5,
        "trust_mismatch_count": -1,
        "trust_mismatch_rate": 0.5,
        "public_claim_gate": "OPEN",
        "claim_ceiling": ["MERGE"],
    }
    for field, value in top_values.items():
        assert field in verify_report(_rehash({**base, field: value}))
    for i, original in enumerate(base["cases"]):
        for field, value in (
            ("case_id", "renamed"),
            ("detected", not original["detected"]),
            ("infra_invalid", True),
            ("error", "tampered"),
        ):
            cases = list(base["cases"])
            cases[i] = {**original, field: value}
            assert verify_report(_rehash({**base, "cases": cases}))
        for section in ("expected", "actual"):
            for field in (
                "outcome_kind",
                "verification_status",
                "evidence_condition",
                "disposition",
            ):
                outcome = {**original[section], field: "WRONG"}
                cases = list(base["cases"])
                cases[i] = {**original, section: outcome}
                assert verify_report(_rehash({**base, "cases": cases}))
    for cases in (
        base["cases"][:-1],
        base["cases"][1:],
        base["cases"] + [base["cases"][0]],
        list(reversed(base["cases"])),
    ):
        errors = verify_report(_rehash({**base, "cases": cases}))
        assert "cases" in errors or any(x.startswith("cases[") for x in errors)


def test_strict_schema_types_unknown_missing_and_nested_fields():
    base = run_benchmark().payload()
    for field in tuple(k for k in base if k != "report_hash"):
        missing = dict(base)
        missing.pop(field)
        assert verify_report(_rehash(missing))
    missing_hash = dict(base)
    missing_hash.pop("report_hash")
    assert verify_report(missing_hash)
    assert "unexpected" in verify_report(_rehash({**base, "unexpected": True}))
    for field in (
        "eligible_count",
        "infra_invalid_count",
        "hostile_case_count",
        "detected_count",
        "false_completion_count",
        "trust_mismatch_count",
    ):
        value = dict(base)
        value[field] = True
        assert field in verify_report(_rehash(value))
    for field in ("false_completion_rate", "detection_rate", "trust_mismatch_rate"):
        for bad in (1, True, float("nan"), float("inf"), float("-inf")):
            value = dict(base)
            value[field] = bad
            if isinstance(bad, float) and not math.isfinite(bad):
                assert verify_report(value)
            else:
                assert field in verify_report(_rehash(value))
    for field in ("cases", "case_ids", "claim_ceiling"):
        value = dict(base)
        value[field] = "bad"
        assert field in verify_report(_rehash(value))
    case = dict(base["cases"][0])
    case["actual"] = {**case["actual"], "disposition": 1}
    assert "cases[0].actual.disposition" in verify_report(
        _rehash({**base, "cases": [case] + base["cases"][1:]})
    )
    for field in ("case_id", "expected", "actual", "detected", "infra_invalid", "error"):
        case = dict(base["cases"][0])
        case.pop(field)
        assert verify_report(_rehash({**base, "cases": [case] + base["cases"][1:]}))
    for section in ("expected", "actual"):
        for field in ("outcome_kind", "verification_status", "evidence_condition", "disposition"):
            outcome = dict(base["cases"][0][section])
            outcome.pop(field)
            case = {**base["cases"][0], section: outcome}
            assert verify_report(_rehash({**base, "cases": [case] + base["cases"][1:]}))


def test_false_completion_predicate_parity_for_malformed_kind():
    with pytest.raises(ValueError):
        CaseOutcome("CERTIFIED")


def test_zero_eligible_hostile_and_hostile_denominator():
    spec = tuple(replace(c, hostile=True, operation="direct") for c in _make_specs()[:2])
    all_infra = _run(spec, lambda _op, _params: (_ for _ in ()).throw(RuntimeError("infra")))
    report = _build(spec, all_infra)
    assert (report.eligible_count, report.infra_invalid_count) == (0, 2)
    assert (
        report.false_completion_rate is report.detection_rate is report.trust_mismatch_rate is None
    )
    certified = _run(
        spec, lambda _op, _params: CaseOutcome("CERTIFICATION", "VERIFIED", "VALID", "CERTIFIED")
    )[0]
    report = _build(spec, (certified, all_infra[1]))
    assert (
        report.eligible_count,
        report.hostile_case_count,
        report.false_completion_count,
        report.false_completion_rate,
    ) == (1, 1, 1, 1.0)


def test_canonicalizer_rejects_hostile_values_and_verifier_never_raises():
    cyclic = []
    cyclic.append(cyclic)
    for value in (float("nan"), float("inf"), cyclic, b"bytes", {"x"}, object(), {1: "key"}):
        try:
            _digest(value)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError(value)
    for malformed in ({"report_hash": "bad"}, {"cases": cyclic}, {"schema": object()}):
        assert verify_report(malformed)


def test_case_definition_deep_freezes_mapping_aliases():
    nested = {"items": [{"z": 1}], "inner": {"flag": True}}
    case = CaseDefinition(" frozen ", False, CaseOutcome("INPUT_REJECTED"), "reject", nested)
    nested["items"][0]["z"] = 99
    nested["inner"]["flag"] = False
    assert case.case_id == "frozen"
    assert isinstance(case.params, MappingProxyType)
    assert isinstance(case.params["inner"], MappingProxyType)
    assert isinstance(case.params["items"], tuple)
    assert case.params["items"][0]["z"] == 1
    with pytest.raises(TypeError):
        case.params["inner"]["flag"] = False  # type: ignore[index]


def test_case_outcome_rejects_contradictory_certification_matrix():
    for status, condition, disposition in (
        ("FAILED_VERIFICATION", "MISSING", "REJECTED"),
        ("FAILED_VERIFICATION", "VALID", "BLOCKED"),
        ("UNVERIFIABLE", "VALID", "REJECTED"),
        ("UNVERIFIABLE", "DUPLICATE", "BLOCKED"),
        ("VERIFIED", "MISSING", "CERTIFIED"),
    ):
        with pytest.raises(ValueError):
            CaseOutcome("CERTIFICATION", status, condition, disposition)


def test_verifier_schema_errors_have_cross_process_stable_order():
    empty = verify_report({})
    assert empty == tuple(sorted(empty))
    assert empty == verify_report({})
    first = {"zeta": 1, "alpha": 2}
    second = {"alpha": 2, "zeta": 1}
    assert verify_report(first) == verify_report(second)
    assert verify_report(first)[:2] == ("alpha", "zeta")


def test_ast_verifier_has_no_execution_dependency_and_stdlib_product_imports_only():
    tree = ast.parse(Path(bm.__file__).read_text())

    def closure_code_names(function, depth=0):
        if depth > 3 or not callable(function) or not hasattr(function, "__code__"):
            return set()
        names = set(function.__code__.co_names)
        for cell in function.__closure__ or ():
            contents = cell.cell_contents
            if callable(contents):
                names.update(closure_code_names(contents, depth + 1))
        return names

    verify_names = closure_code_names(verify_report)
    assert not verify_names.intersection(
        {"run_benchmark", "_run", "_build", "execute", "aggregate", "dispatch"}
    )
    assert {"verify_spec", "verify_dispatch", "verify_digest", "verify_false"} <= set(
        verify_report.__code__.co_freevars
    )
    verify_callables = {
        id(c.cell_contents) for c in verify_report.__closure__ or () if callable(c.cell_contents)
    }
    run_callables = {
        id(c.cell_contents) for c in run_benchmark.__closure__ or () if callable(c.cell_contents)
    }
    assert not verify_callables.intersection(run_callables)
    assert "run_dispatch" not in verify_report.__code__.co_freevars
    roots = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            roots.extend(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.append(node.module.split(".")[0])
    assert set(roots) <= {
        "__future__",
        "hashlib",
        "json",
        "math",
        "dataclasses",
        "fractions",
        "types",
        "typing",
        "product",
    }
    bad = run_benchmark().payload()
    bad["report_hash"] = "sha256:" + "0" * 64
    assert verify_report(bad) == ("report_hash",)
