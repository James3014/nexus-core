import hashlib
from collections.abc import Iterator, Mapping

import pytest

from product.evidence import ChangeSet, canonical_json
from product.evidence.code_integrity import (
    CI001,
    CI002,
    CI003,
    PROFILE_HASH,
    CodeIntegrityRequirementV1,
    CodeIntegrityStatus,
    CoverageState,
    ImplementationTargetV1,
    JUnitCaseV1,
    ProducerExecutionState,
    analyze_code_integrity,
    observation_from_code_integrity,
)
from product.evidence.code_integrity import (
    TestTargetV1 as IntegrityTestTargetV1,
)

SOURCE_TREE = "1" * 40
TARGET_TREE = "2" * 40


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _required_paths(requirement: CodeIntegrityRequirementV1) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                *(item.path for item in requirement.implementation_targets),
                *(item.path for item in requirement.test_targets),
            }
        )
    )


def _change_set(
    requirement: CodeIntegrityRequirementV1,
    *,
    salt: str = "default",
) -> ChangeSet:
    return ChangeSet(
        change_set_id=f"changeset-{salt}",
        source_revision="git-commit:" + "a" * 40,
        target_revision="git-commit:" + "b" * 40,
        diff_hash=_digest(f"diff:{salt}".encode()),
        paths=_required_paths(requirement),
    )


def _analyze(
    requirement: CodeIntegrityRequirementV1,
    source_files: Mapping[str, bytes],
    *,
    junit: bytes | None = None,
    change_set: ChangeSet | None = None,
    source_tree: str = SOURCE_TREE,
    target_tree: str = TARGET_TREE,
):
    return analyze_code_integrity(
        requirement,
        repository_id="James3014/nexus-core",
        change_set=change_set or _change_set(requirement),
        source_tree=source_tree,
        target_tree=target_tree,
        source_files=source_files,
        junit=junit,
    )


def _report(result):
    assert result.execution_state is ProducerExecutionState.COMPLETED
    assert result.report is not None
    return result.report


def _impl(source: bytes, *, qualname: str = "work"):
    requirement = CodeIntegrityRequirementV1(
        implementation_targets=(ImplementationTargetV1("src/example.py", qualname),)
    )
    return _analyze(requirement, {"src/example.py": source})


def _test_requirement(
    *,
    qualname: str = "test_behavior",
    cases: tuple[JUnitCaseV1, ...] | None = None,
) -> CodeIntegrityRequirementV1:
    return CodeIntegrityRequirementV1(
        test_targets=(
            IntegrityTestTargetV1(
                "tests/test_example.py",
                qualname,
                cases or (JUnitCaseV1("tests.test_example", qualname),),
            ),
        )
    )


def _junit(*rows: tuple[str, str, bool]) -> bytes:
    body = []
    for classname, name, skipped in rows:
        child = '<skipped type="pytest.xfail"/>' if skipped else ""
        body.append(f'<testcase classname="{classname}" name="{name}">{child}</testcase>')
    return (
        f'<testsuite tests="{len(rows)}" failures="0" errors="0">' + "".join(body) + "</testsuite>"
    ).encode()


def test_requirement_is_canonical_and_content_addressed():
    requirement = CodeIntegrityRequirementV1(
        implementation_targets=(
            ImplementationTargetV1("src/z.py", "z"),
            ImplementationTargetV1("src/a.py", "a"),
        ),
        test_targets=(
            IntegrityTestTargetV1(
                "tests/test_x.py",
                "test_x",
                (
                    JUnitCaseV1("suite", "b"),
                    JUnitCaseV1("suite", "a"),
                ),
            ),
        ),
    )
    assert [item.path for item in requirement.implementation_targets] == [
        "src/a.py",
        "src/z.py",
    ]
    assert [case.name for case in requirement.test_targets[0].junit_cases] == ["a", "b"]
    assert requirement.hash.startswith("sha256:")
    assert len(requirement.hash) == 71


def test_requirement_rejects_empty_non_python_and_duplicate_junit_subjects():
    with pytest.raises(ValueError):
        CodeIntegrityRequirementV1()
    with pytest.raises(ValueError):
        ImplementationTargetV1("src/example.pyi", "work")
    with pytest.raises(ValueError):
        ImplementationTargetV1("../example.py", "work")
    case = JUnitCaseV1("suite", "case")
    with pytest.raises(ValueError):
        IntegrityTestTargetV1("tests/test_x.py", "test_x", (case, case))
    with pytest.raises(ValueError):
        CodeIntegrityRequirementV1(
            test_targets=(
                IntegrityTestTargetV1("tests/test_a.py", "test_a", (case,)),
                IntegrityTestTargetV1("tests/test_b.py", "test_b", (case,)),
            )
        )


@pytest.mark.parametrize(
    "body",
    (
        b"def work():\n    pass\n",
        b"def work():\n    ...\n",
        b"def work():\n    raise NotImplementedError\n",
        b"def work():\n    raise NotImplementedError('later')\n",
        b'async def work():\n    """doc"""\n    pass\n',
    ),
)
def test_ci001_blocks_exact_concrete_placeholder_shapes(body):
    report = _report(_impl(body))
    assert report.integrity_status is CodeIntegrityStatus.FAIL
    assert [item.rule_id for item in report.findings] == [CI001]
    assert report.findings[0].reason_code == "CI001_CONCRETE_PLACEHOLDER_IMPLEMENTATION"


@pytest.mark.parametrize(
    "body",
    (
        b"def work():\n    return None\n",
        b"def work():\n    # TODO later\n    return 7\n",
        b"def work():\n    return 'constant'\n",
        b"def work():\n    if True:\n        raise NotImplementedError\n",
    ),
)
def test_ci001_does_not_block_non_frozen_heuristics(body):
    report = _report(_impl(body))
    assert report.integrity_status is CodeIntegrityStatus.PASS
    assert report.findings == ()


def test_ci001_blocks_concrete_method_placeholder():
    source = b"class Service:\n    def work(self):\n        pass\n"
    report = _report(_impl(source, qualname="Service.work"))
    assert report.integrity_status is CodeIntegrityStatus.FAIL
    assert report.findings[0].rule_id == CI001


@pytest.mark.parametrize(
    ("source", "qualname"),
    (
        (
            b"from abc import abstractmethod\n"
            b"class Port:\n"
            b"    @abstractmethod\n"
            b"    def work(self):\n"
            b"        pass\n",
            "Port.work",
        ),
        (
            b"from typing import overload\n@overload\ndef work(x: int) -> int:\n    ...\n",
            "work",
        ),
        (
            b"import typing\n@typing.overload\ndef work(x: int) -> int:\n    ...\n",
            "work",
        ),
        (
            b"import abc\n"
            b"class Port:\n"
            b"    @abc.abstractmethod\n"
            b"    def work(self):\n"
            b"        pass\n",
            "Port.work",
        ),
        (
            b"from typing import Protocol\n"
            b"class Port(Protocol):\n"
            b"    def work(self):\n"
            b"        pass\n",
            "Port.work",
        ),
        (
            b"import typing\nclass Port(typing.Protocol):\n    def work(self):\n        pass\n",
            "Port.work",
        ),
    ),
)
def test_ci001_preserves_legitimate_declaration_exclusions(source, qualname):
    report = _report(_impl(source, qualname=qualname))
    assert report.integrity_status is CodeIntegrityStatus.PASS
    assert report.coverage[0].state is CoverageState.EXCLUDED_VALID_DECLARATION


def test_ci001_multiple_overload_declarations_are_excluded_not_ambiguous():
    source = (
        b"from typing import overload\n"
        b"@overload\ndef work(x: int) -> int:\n    ...\n"
        b"@overload\ndef work(x: str) -> str:\n    ...\n"
    )
    report = _report(_impl(source))
    assert report.integrity_status is CodeIntegrityStatus.PASS
    assert report.coverage[0].state is CoverageState.EXCLUDED_VALID_DECLARATION


@pytest.mark.parametrize(
    "source",
    (
        b"def test_behavior():\n    assert True\n",
        b"def test_behavior():\n    assert True, 'message'\n",
        b'async def test_behavior():\n    """doc"""\n    assert True\n',
    ),
)
def test_ci002_blocks_literal_assert_true_only(source):
    requirement = _test_requirement()
    result = _analyze(
        requirement,
        {"tests/test_example.py": source},
        junit=_junit(("tests.test_example", "test_behavior", False)),
    )
    report = _report(result)
    assert report.integrity_status is CodeIntegrityStatus.FAIL
    assert any(item.rule_id == CI002 for item in report.findings)


@pytest.mark.parametrize(
    "source",
    (
        b"def test_behavior():\n    value = 2 + 2\n    assert value == 4\n",
        b"def test_behavior():\n    assert bool(True)\n",
        b"def test_behavior():\n    assert 1 == 1\n",
        b"def test_behavior():\n    from unittest.mock import MagicMock\n"
        b"    fn = MagicMock(return_value=3)\n    assert fn() == 3\n",
    ),
)
def test_ci002_does_not_expand_beyond_literal_contract(source):
    requirement = _test_requirement()
    result = _analyze(
        requirement,
        {"tests/test_example.py": source},
        junit=_junit(("tests.test_example", "test_behavior", False)),
    )
    report = _report(result)
    assert report.integrity_status is CodeIntegrityStatus.PASS


def test_ci002_blocks_literal_assert_true_in_test_method():
    requirement = _test_requirement(qualname="Tests.test_behavior")
    source = b"class Tests:\n    def test_behavior(self):\n        assert True\n"
    report = _report(
        _analyze(
            requirement,
            {"tests/test_example.py": source},
            junit=_junit(("tests.test_example", "test_behavior", False)),
        )
    )
    assert report.integrity_status is CodeIntegrityStatus.FAIL
    assert any(item.rule_id == CI002 for item in report.findings)


def test_unclaimed_trivial_test_does_not_poison_claimed_real_test():
    requirement = _test_requirement(qualname="test_real")
    source = (
        b"def test_trivial():\n    assert True\n\n"
        b"def test_real():\n    value = 1\n    assert value == 1\n"
    )
    report = _report(
        _analyze(
            requirement,
            {"tests/test_example.py": source},
            junit=_junit(("tests.test_example", "test_real", False)),
        )
    )
    assert report.integrity_status is CodeIntegrityStatus.PASS


def test_ci003_all_exact_claimed_tests_skipped_fails():
    requirement = _test_requirement(
        cases=(
            JUnitCaseV1("tests.test_example", "case_a"),
            JUnitCaseV1("tests.test_example", "case_b"),
        )
    )
    source = b"def test_behavior():\n    value = 1\n    assert value == 1\n"
    report = _report(
        _analyze(
            requirement,
            {"tests/test_example.py": source},
            junit=_junit(
                ("tests.test_example", "case_a", True),
                ("tests.test_example", "case_b", True),
            ),
        )
    )
    assert report.integrity_status is CodeIntegrityStatus.FAIL
    assert any(item.rule_id == CI003 for item in report.findings)


def test_ci003_one_exact_claimed_test_executed_is_not_a_finding():
    requirement = _test_requirement(
        cases=(
            JUnitCaseV1("tests.test_example", "case_a"),
            JUnitCaseV1("tests.test_example", "case_b"),
        )
    )
    source = b"def test_behavior():\n    value = 1\n    assert value == 1\n"
    report = _report(
        _analyze(
            requirement,
            {"tests/test_example.py": source},
            junit=_junit(
                ("tests.test_example", "case_a", True),
                ("tests.test_example", "case_b", False),
            ),
        )
    )
    assert report.integrity_status is CodeIntegrityStatus.PASS
    assert not any(item.rule_id == CI003 for item in report.findings)


@pytest.mark.parametrize(
    ("junit", "reason"),
    (
        (None, "JUNIT_MISSING"),
        (b"<testsuite>", "JUNIT_MALFORMED"),
        (b"<!DOCTYPE testsuite><testsuite></testsuite>", "JUNIT_MALFORMED"),
        (
            _junit(("tests.test_example", "other_test", False)),
            "CLAIMED_TESTCASE_MISSING",
        ),
    ),
)
def test_ci003_missing_or_malformed_claimed_evidence_is_unverifiable(junit, reason):
    requirement = _test_requirement()
    source = b"def test_behavior():\n    value = 1\n    assert value == 1\n"
    report = _report(_analyze(requirement, {"tests/test_example.py": source}, junit=junit))
    assert report.integrity_status is CodeIntegrityStatus.UNVERIFIABLE
    assert reason in report.reason_codes


def test_ci003_duplicate_exact_case_is_unverifiable():
    requirement = _test_requirement()
    source = b"def test_behavior():\n    value = 1\n    assert value == 1\n"
    junit = _junit(
        ("tests.test_example", "test_behavior", False),
        ("tests.test_example", "test_behavior", False),
    )
    report = _report(_analyze(requirement, {"tests/test_example.py": source}, junit=junit))
    assert report.integrity_status is CodeIntegrityStatus.UNVERIFIABLE
    assert "CLAIMED_TESTCASE_DUPLICATE" in report.reason_codes


def test_unrelated_passing_junit_case_cannot_rescue_missing_claimed_case():
    requirement = _test_requirement()
    source = b"def test_behavior():\n    value = 1\n    assert value == 1\n"
    report = _report(
        _analyze(
            requirement,
            {"tests/test_example.py": source},
            junit=_junit(("other.suite", "passes", False)),
        )
    )
    assert report.integrity_status is CodeIntegrityStatus.UNVERIFIABLE
    assert "CLAIMED_TESTCASE_MISSING" in report.reason_codes


@pytest.mark.parametrize(
    ("sources", "reason"),
    (
        ({}, "SOURCE_MISSING"),
        ({"src/example.py": b"def work(:\n"}, "AST_PARSE_ERROR"),
        ({"src/example.py": b"\xff\xfe"}, "SOURCE_DECODE_ERROR"),
    ),
)
def test_missing_or_malformed_source_never_passes(sources, reason):
    requirement = CodeIntegrityRequirementV1(
        implementation_targets=(ImplementationTargetV1("src/example.py", "work"),)
    )
    report = _report(_analyze(requirement, sources))
    assert report.integrity_status is CodeIntegrityStatus.UNVERIFIABLE
    assert reason in report.reason_codes


def test_missing_target_is_unverifiable():
    report = _report(_impl(b"def other():\n    return 1\n"))
    assert report.integrity_status is CodeIntegrityStatus.UNVERIFIABLE
    assert "TARGET_NOT_FOUND" in report.reason_codes


def test_duplicate_target_qualname_is_unverifiable():
    source = b"def work():\n    return 1\n\ndef work():\n    return 2\n"
    report = _report(_impl(source))
    assert report.integrity_status is CodeIntegrityStatus.UNVERIFIABLE
    assert "TARGET_AMBIGUOUS" in report.reason_codes


def test_fail_precedence_preserves_independent_coverage_gap():
    requirement = CodeIntegrityRequirementV1(
        implementation_targets=(ImplementationTargetV1("src/example.py", "work"),),
        test_targets=(
            IntegrityTestTargetV1(
                "tests/test_example.py",
                "test_behavior",
                (JUnitCaseV1("tests.test_example", "test_behavior"),),
            ),
        ),
    )
    sources = {
        "src/example.py": b"def work():\n    pass\n",
        "tests/test_example.py": b"def test_behavior():\n    value = 1\n    assert value == 1\n",
    }
    report = _report(_analyze(requirement, sources, junit=None))
    assert report.integrity_status is CodeIntegrityStatus.FAIL
    assert "CI001_CONCRETE_PLACEHOLDER_IMPLEMENTATION" in report.reason_codes
    assert "JUNIT_MISSING" in report.reason_codes


def test_identical_physical_input_produces_byte_identical_report_and_hash():
    requirement = CodeIntegrityRequirementV1(
        implementation_targets=(
            ImplementationTargetV1("src/a.py", "a"),
            ImplementationTargetV1("src/b.py", "b"),
        )
    )
    left = _report(
        _analyze(
            requirement,
            {
                "src/a.py": b"def a():\n    return 1\n",
                "src/b.py": b"def b():\n    return 2\n",
            },
        )
    )
    right = _report(
        _analyze(
            requirement,
            {
                "src/b.py": b"def b():\n    return 2\n",
                "src/a.py": b"def a():\n    return 1\n",
            },
        )
    )
    assert left.canonical_bytes == right.canonical_bytes
    assert left.artifact_hash == right.artifact_hash
    assert left.canonical_bytes == canonical_json(left.to_dict()).encode()


def test_source_change_changes_input_and_artifact_identity():
    requirement = CodeIntegrityRequirementV1(
        implementation_targets=(ImplementationTargetV1("src/example.py", "work"),)
    )
    left = _report(_analyze(requirement, {"src/example.py": b"def work():\n    return 1\n"}))
    right = _report(_analyze(requirement, {"src/example.py": b"def work():\n    return 2\n"}))
    assert left.input_hash != right.input_hash
    assert left.artifact_hash != right.artifact_hash


def test_requirement_target_identity_changes_input_identity():
    source = {"src/example.py": (b"def work():\n    return 1\n\ndef work_two():\n    return 2\n")}
    first = CodeIntegrityRequirementV1(
        implementation_targets=(ImplementationTargetV1("src/example.py", "work"),)
    )
    second = CodeIntegrityRequirementV1(
        implementation_targets=(ImplementationTargetV1("src/example.py", "work_two"),)
    )
    first_report = _report(_analyze(first, source))
    second_report = _report(_analyze(second, source))
    assert first.hash != second.hash
    assert first_report.input_hash != second_report.input_hash
    assert first_report.artifact_hash != second_report.artifact_hash


def test_changeset_tree_and_junit_changes_bind_report_identity():
    requirement = _test_requirement()
    source = {"tests/test_example.py": b"def test_behavior():\n    assert 2 == 2\n"}
    junit = _junit(("tests.test_example", "test_behavior", False))
    base = _report(_analyze(requirement, source, junit=junit))
    changed_set = _report(
        _analyze(
            requirement,
            source,
            junit=junit,
            change_set=_change_set(requirement, salt="changed"),
        )
    )
    changed_tree = _report(_analyze(requirement, source, junit=junit, target_tree="3" * 40))
    changed_junit = _report(
        _analyze(
            requirement,
            source,
            junit=_junit(("tests.test_example", "test_behavior", True)),
        )
    )
    assert len({base.input_hash, changed_set.input_hash, changed_tree.input_hash}) == 3
    assert base.input_hash != changed_junit.input_hash


def test_invalid_tree_binding_is_unverifiable_not_pass():
    requirement = CodeIntegrityRequirementV1(
        implementation_targets=(ImplementationTargetV1("src/example.py", "work"),)
    )
    report = _report(
        _analyze(
            requirement,
            {"src/example.py": b"def work():\n    return 1\n"},
            target_tree="not-a-tree",
        )
    )
    assert report.integrity_status is CodeIntegrityStatus.UNVERIFIABLE
    assert "INPUT_BINDING_INVALID" in report.reason_codes


class _ExplodingMapping(Mapping[str, bytes]):
    def __getitem__(self, key: str) -> bytes:
        raise RuntimeError("boom")

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("boom")

    def __len__(self) -> int:
        return 1


def test_internal_analyzer_failure_is_unavailable_without_report():
    requirement = CodeIntegrityRequirementV1(
        implementation_targets=(ImplementationTargetV1("src/example.py", "work"),)
    )
    result = _analyze(requirement, _ExplodingMapping())
    assert result.execution_state is ProducerExecutionState.UNAVAILABLE
    assert result.integrity_status is None
    assert result.report is None
    assert result.reason_codes == ("INTERNAL_ANALYZER_ERROR",)
    assert observation_from_code_integrity(result) is None


def test_profile_hash_is_content_addressed_and_stable_shape():
    assert PROFILE_HASH.startswith("sha256:")
    assert len(PROFILE_HASH) == 71
