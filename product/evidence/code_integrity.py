"""Deterministic Python code-integrity evidence producer for Anti-Stub checks."""

from __future__ import annotations

import ast
import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from product.evidence import ChangeSet, Observation, ObservationStatus, _hash, canonical_json

VERIFIER_ID = "code_integrity_v1"
PROFILE_ID = "python-code-integrity-v1"
REQUIREMENT_SCHEMA = "product.evidence.code-integrity-requirement.v1"
REPORT_SCHEMA = "product.evidence.code-integrity-report.v1"
PARSER_ID = "python-ast-v1"
PARSER_RUNTIME = "stdlib-ast"
CI001 = "CI001"
CI002 = "CI002"
CI003 = "CI003"
RULE_IDS = (CI001, CI002, CI003)

_FAIL_REASONS = {
    CI001: "CI001_CONCRETE_PLACEHOLDER_IMPLEMENTATION",
    CI002: "CI002_LITERAL_TRIVIAL_ONLY_TEST",
    CI003: "CI003_CLAIMED_TESTS_SKIP_ONLY",
}

_PROFILE_SPEC = {
    "profile_id": PROFILE_ID,
    "verifier_id": VERIFIER_ID,
    "rules": [
        [CI001, "CONCRETE_PLACEHOLDER_IMPLEMENTATION"],
        [CI002, "LITERAL_TRIVIAL_ONLY_TEST"],
        [CI003, "CLAIMED_TESTS_SKIP_ONLY"],
    ],
    "ci001_exclusions": [
        "abstractmethod",
        "overload",
        "protocol_method",
        "pyi_declaration",
    ],
    "blocking_non_goals": [
        "todo_fixme",
        "mocking",
        "short_code",
        "constant_return",
        "style",
        "generic_static_reachability",
    ],
    "status_precedence": ["FAIL", "UNVERIFIABLE", "PASS"],
}
PROFILE_HASH = _hash(_PROFILE_SPEC)


class ProducerExecutionState(str, Enum):
    COMPLETED = "COMPLETED"
    UNAVAILABLE = "UNAVAILABLE"


class CodeIntegrityStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNVERIFIABLE = "UNVERIFIABLE"


class CoverageState(str, Enum):
    OBSERVED = "OBSERVED"
    EXCLUDED_VALID_DECLARATION = "EXCLUDED_VALID_DECLARATION"
    UNSUPPORTED = "UNSUPPORTED"
    MISSING = "MISSING"
    AMBIGUOUS = "AMBIGUOUS"


def _require_text(value: object, field: str) -> str:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{field} must be normalized non-empty text")
    return value


def _require_qualname(value: object, field: str) -> str:
    text = _require_text(value, field)
    if text.startswith(".") or text.endswith(".") or ".." in text:
        raise ValueError(f"{field} must be a normalized Python qualname")
    return text


def _require_python_path(value: object, field: str) -> str:
    path = _require_text(value, field)
    if (
        path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or not path.endswith(".py")
        or path.endswith(".pyi")
    ):
        raise ValueError(f"{field} must be a repository-relative Python .py path")
    return path


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class ImplementationTargetV1:
    path: str
    qualname: str

    def __post_init__(self) -> None:
        _require_python_path(self.path, "implementation_target.path")
        _require_qualname(self.qualname, "implementation_target.qualname")

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "qualname": self.qualname}


@dataclass(frozen=True)
class JUnitCaseV1:
    classname: str
    name: str

    def __post_init__(self) -> None:
        _require_text(self.classname, "junit_case.classname")
        _require_text(self.name, "junit_case.name")

    def to_dict(self) -> dict[str, str]:
        return {"classname": self.classname, "name": self.name}


@dataclass(frozen=True)
class TestTargetV1:
    path: str
    qualname: str
    junit_cases: tuple[JUnitCaseV1, ...]

    def __post_init__(self) -> None:
        _require_python_path(self.path, "test_target.path")
        _require_qualname(self.qualname, "test_target.qualname")
        if type(self.junit_cases) is not tuple or not self.junit_cases:
            raise ValueError("test_target.junit_cases must be a non-empty tuple")
        if any(type(case) is not JUnitCaseV1 for case in self.junit_cases):
            raise TypeError("test_target.junit_cases must contain JUnitCaseV1")
        ordered = tuple(sorted(self.junit_cases, key=lambda case: (case.classname, case.name)))
        if len({(case.classname, case.name) for case in ordered}) != len(ordered):
            raise ValueError("test_target.junit_cases must be unique")
        object.__setattr__(self, "junit_cases", ordered)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "qualname": self.qualname,
            "junit_cases": [case.to_dict() for case in self.junit_cases],
        }


@dataclass(frozen=True)
class CodeIntegrityRequirementV1:
    implementation_targets: tuple[ImplementationTargetV1, ...] = ()
    test_targets: tuple[TestTargetV1, ...] = ()
    schema: str = REQUIREMENT_SCHEMA
    verifier_id: str = VERIFIER_ID
    profile_id: str = PROFILE_ID

    def __post_init__(self) -> None:
        if self.schema != REQUIREMENT_SCHEMA:
            raise ValueError("unsupported code-integrity requirement schema")
        if self.verifier_id != VERIFIER_ID or self.profile_id != PROFILE_ID:
            raise ValueError("unexpected verifier/profile identity")
        if type(self.implementation_targets) is not tuple or type(self.test_targets) is not tuple:
            raise TypeError("targets must be tuples")
        if any(type(item) is not ImplementationTargetV1 for item in self.implementation_targets):
            raise TypeError("implementation_targets must contain ImplementationTargetV1")
        if any(type(item) is not TestTargetV1 for item in self.test_targets):
            raise TypeError("test_targets must contain TestTargetV1")
        if not self.implementation_targets and not self.test_targets:
            raise ValueError("at least one code-integrity target is required")
        implementations = tuple(
            sorted(self.implementation_targets, key=lambda item: (item.path, item.qualname))
        )
        tests = tuple(sorted(self.test_targets, key=lambda item: (item.path, item.qualname)))
        if len({(item.path, item.qualname) for item in implementations}) != len(implementations):
            raise ValueError("implementation targets must be unique")
        if len({(item.path, item.qualname) for item in tests}) != len(tests):
            raise ValueError("test targets must be unique")
        junit_identities = [
            (case.classname, case.name) for target in tests for case in target.junit_cases
        ]
        if len(set(junit_identities)) != len(junit_identities):
            raise ValueError("JUnit case identities must be globally unique")
        object.__setattr__(self, "implementation_targets", implementations)
        object.__setattr__(self, "test_targets", tests)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "verifier_id": self.verifier_id,
            "profile_id": self.profile_id,
            "implementation_targets": [item.to_dict() for item in self.implementation_targets],
            "test_targets": [item.to_dict() for item in self.test_targets],
        }

    @property
    def hash(self) -> str:
        return _hash(self.to_dict())


@dataclass(frozen=True)
class CoverageRecordV1:
    rule_id: str
    path: str
    selector: str
    state: CoverageState

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "selector": self.selector,
            "state": self.state.value,
        }


@dataclass(frozen=True)
class FindingV1:
    rule_id: str
    path: str
    selector: str
    reason_code: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "selector": self.selector,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class CodeIntegrityReportV1:
    repository_id: str
    change_set_hash: str
    source_revision: str
    target_revision: str
    source_tree: str
    target_tree: str
    input_hash: str
    inspected_paths: tuple[str, ...]
    coverage: tuple[CoverageRecordV1, ...]
    findings: tuple[FindingV1, ...]
    integrity_status: CodeIntegrityStatus
    reason_codes: tuple[str, ...]
    schema: str = REPORT_SCHEMA
    verifier_id: str = VERIFIER_ID
    profile_id: str = PROFILE_ID
    profile_hash: str = PROFILE_HASH
    parser_id: str = PARSER_ID
    parser_runtime: str = PARSER_RUNTIME
    rule_ids: tuple[str, ...] = RULE_IDS

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "verifier_id": self.verifier_id,
            "profile_id": self.profile_id,
            "profile_hash": self.profile_hash,
            "repository_id": self.repository_id,
            "change_set_hash": self.change_set_hash,
            "source_revision": self.source_revision,
            "target_revision": self.target_revision,
            "source_tree": self.source_tree,
            "target_tree": self.target_tree,
            "input_hash": self.input_hash,
            "parser_id": self.parser_id,
            "parser_runtime": self.parser_runtime,
            "inspected_paths": list(self.inspected_paths),
            "rule_ids": list(self.rule_ids),
            "coverage": [item.to_dict() for item in self.coverage],
            "findings": [item.to_dict() for item in self.findings],
            "integrity_status": self.integrity_status.value,
            "reason_codes": list(self.reason_codes),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict()).encode("utf-8")

    @property
    def artifact_hash(self) -> str:
        return _sha256_bytes(self.canonical_bytes)

    @property
    def artifact_id(self) -> str:
        return "code-integrity-report:" + self.artifact_hash.removeprefix("sha256:")


@dataclass(frozen=True)
class CodeIntegrityAnalysisResult:
    execution_state: ProducerExecutionState
    integrity_status: CodeIntegrityStatus | None
    report: CodeIntegrityReportV1 | None
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class _FunctionSubject:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    owner_class: ast.ClassDef | None


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return None


def _function_index(tree: ast.AST) -> dict[str, list[_FunctionSubject]]:
    index: dict[str, list[_FunctionSubject]] = {}

    def visit_body(
        body: list[ast.stmt],
        scope: tuple[str, ...],
        owner_class: ast.ClassDef | None = None,
        inside_function: bool = False,
    ) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit_body(node.body, scope + (node.name,), owner_class=node)
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = ".".join(scope + (node.name,))
                subject = _FunctionSubject(
                    node=node,
                    owner_class=owner_class if not inside_function else None,
                )
                index.setdefault(qualname, []).append(subject)
                visit_body(
                    node.body,
                    scope + (node.name,),
                    owner_class=None,
                    inside_function=True,
                )

    if isinstance(tree, ast.Module):
        visit_body(tree.body, ())
    return index


def _effective_body(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr):
        value = body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            body = body[1:]
    return body


def _valid_declaration(subject: _FunctionSubject) -> bool:
    decorators = {_dotted_name(item) for item in subject.node.decorator_list}
    if decorators & {"abstractmethod", "abc.abstractmethod", "overload", "typing.overload"}:
        return True
    owner = subject.owner_class
    if owner is not None:
        bases = {_dotted_name(base) for base in owner.bases}
        if bases & {"Protocol", "typing.Protocol"}:
            return True
    return False


def _ci001_placeholder(subject: _FunctionSubject) -> bool:
    body = _effective_body(subject.node)
    if len(body) != 1:
        return False
    statement = body[0]
    if isinstance(statement, ast.Pass):
        return True
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
        return statement.value.value is Ellipsis
    if not isinstance(statement, ast.Raise) or statement.cause is not None:
        return False
    exc = statement.exc
    if isinstance(exc, ast.Name):
        return exc.id == "NotImplementedError"
    if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
        return exc.func.id == "NotImplementedError"
    return False


def _ci002_trivial_test(subject: _FunctionSubject) -> bool:
    body = _effective_body(subject.node)
    if len(body) != 1 or not isinstance(body[0], ast.Assert):
        return False
    test = body[0].test
    return isinstance(test, ast.Constant) and type(test.value) is bool and test.value is True


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _junit_cases(data: bytes) -> list[tuple[str, str, bool]]:
    if not data or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ValueError("unsafe or missing JUnit")
    root = ET.fromstring(data)
    cases: list[tuple[str, str, bool]] = []
    for node in root.iter():
        if _local_name(node.tag) != "testcase":
            continue
        classname = node.attrib.get("classname", "")
        name = node.attrib.get("name", "")
        skipped = any(_local_name(child.tag) == "skipped" for child in list(node))
        cases.append((classname, name, skipped))
    if not cases:
        raise ValueError("JUnit contains no testcase elements")
    return cases


def _input_hash(
    requirement: CodeIntegrityRequirementV1,
    repository_id: str,
    change_set: ChangeSet,
    source_tree: str,
    target_tree: str,
    source_files: Mapping[str, bytes],
    junit: bytes | None,
) -> str:
    physical_sources: list[list[str]] = []
    for path in sorted(source_files):
        value = source_files[path]
        if type(value) is bytes:
            digest = _sha256_bytes(value)
        else:
            digest = _hash(["INVALID_SOURCE_TYPE", type(value).__name__])
        physical_sources.append([path, digest])
    return _hash(
        {
            "requirement_hash": requirement.hash,
            "repository_id": repository_id,
            "change_set_hash": change_set.hash,
            "source_tree": source_tree,
            "target_tree": target_tree,
            "sources": physical_sources,
            "junit_sha256_or_null": _sha256_bytes(junit) if type(junit) is bytes else None,
        }
    )


def _tree_id_valid(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(char in "0123456789abcdef" for char in value)
    )


def _coverage_key(item: CoverageRecordV1) -> tuple[str, str, str]:
    return (item.rule_id, item.path, item.selector)


def _finding_key(item: FindingV1) -> tuple[str, str, str, str]:
    return (item.rule_id, item.path, item.selector, item.reason_code)


def _build_report(
    *,
    repository_id: str,
    change_set: ChangeSet,
    source_tree: str,
    target_tree: str,
    input_hash: str,
    inspected_paths: set[str],
    coverage: list[CoverageRecordV1],
    findings: list[FindingV1],
    reasons: set[str],
) -> CodeIntegrityReportV1:
    ordered_coverage = tuple(sorted(coverage, key=_coverage_key))
    ordered_findings = tuple(sorted(findings, key=_finding_key))
    if ordered_findings:
        status = CodeIntegrityStatus.FAIL
        reasons.update(item.reason_code for item in ordered_findings)
    elif (
        any(
            item.state
            in {CoverageState.UNSUPPORTED, CoverageState.MISSING, CoverageState.AMBIGUOUS}
            for item in ordered_coverage
        )
        or reasons
    ):
        status = CodeIntegrityStatus.UNVERIFIABLE
    else:
        status = CodeIntegrityStatus.PASS
        reasons.clear()
    return CodeIntegrityReportV1(
        repository_id=repository_id,
        change_set_hash=change_set.hash,
        source_revision=change_set.source_revision,
        target_revision=change_set.target_revision,
        source_tree=source_tree,
        target_tree=target_tree,
        input_hash=input_hash,
        inspected_paths=tuple(sorted(inspected_paths)),
        coverage=ordered_coverage,
        findings=ordered_findings,
        integrity_status=status,
        reason_codes=tuple(sorted(reasons)),
    )


def _analyze(
    requirement: CodeIntegrityRequirementV1,
    *,
    repository_id: str,
    change_set: ChangeSet,
    source_tree: str,
    target_tree: str,
    source_files: Mapping[str, bytes],
    junit: bytes | None,
) -> CodeIntegrityReportV1:
    _require_text(repository_id, "repository_id")
    if type(change_set) is not ChangeSet:
        raise TypeError("change_set must be ChangeSet")
    if not isinstance(source_files, Mapping):
        raise TypeError("source_files must be a mapping")

    input_hash = _input_hash(
        requirement,
        repository_id,
        change_set,
        source_tree,
        target_tree,
        source_files,
        junit,
    )
    reasons: set[str] = set()
    coverage: list[CoverageRecordV1] = []
    findings: list[FindingV1] = []
    inspected_paths: set[str] = set()

    if not _tree_id_valid(source_tree) or not _tree_id_valid(target_tree):
        reasons.add("INPUT_BINDING_INVALID")

    targets_by_path: dict[str, list[tuple[str, str]]] = {}
    for target in requirement.implementation_targets:
        targets_by_path.setdefault(target.path, []).append((CI001, target.qualname))
    for target in requirement.test_targets:
        targets_by_path.setdefault(target.path, []).append((CI002, target.qualname))

    indexes: dict[str, dict[str, list[_FunctionSubject]]] = {}
    path_states: dict[str, tuple[CoverageState, str] | None] = {}

    for path in sorted(targets_by_path):
        raw = source_files.get(path)
        if raw is None:
            path_states[path] = (CoverageState.MISSING, "SOURCE_MISSING")
            continue
        if type(raw) is not bytes:
            path_states[path] = (CoverageState.UNSUPPORTED, "INPUT_BINDING_INVALID")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            path_states[path] = (CoverageState.UNSUPPORTED, "SOURCE_DECODE_ERROR")
            continue
        try:
            tree = ast.parse(text, filename=path)
        except SyntaxError:
            path_states[path] = (CoverageState.UNSUPPORTED, "AST_PARSE_ERROR")
            continue
        indexes[path] = _function_index(tree)
        inspected_paths.add(path)
        path_states[path] = None

    for target in requirement.implementation_targets:
        failed_path = path_states[target.path]
        if failed_path is not None:
            state, reason = failed_path
            coverage.append(CoverageRecordV1(CI001, target.path, target.qualname, state))
            reasons.add(reason)
            continue
        matches = indexes[target.path].get(target.qualname, [])
        if not matches:
            coverage.append(
                CoverageRecordV1(CI001, target.path, target.qualname, CoverageState.MISSING)
            )
            reasons.add("TARGET_NOT_FOUND")
            continue
        if len(matches) != 1:
            if all(_valid_declaration(subject) for subject in matches):
                coverage.append(
                    CoverageRecordV1(
                        CI001,
                        target.path,
                        target.qualname,
                        CoverageState.EXCLUDED_VALID_DECLARATION,
                    )
                )
                continue
            coverage.append(
                CoverageRecordV1(CI001, target.path, target.qualname, CoverageState.AMBIGUOUS)
            )
            reasons.add("TARGET_AMBIGUOUS")
            continue
        subject = matches[0]
        if _valid_declaration(subject):
            coverage.append(
                CoverageRecordV1(
                    CI001,
                    target.path,
                    target.qualname,
                    CoverageState.EXCLUDED_VALID_DECLARATION,
                )
            )
            continue
        coverage.append(
            CoverageRecordV1(CI001, target.path, target.qualname, CoverageState.OBSERVED)
        )
        if _ci001_placeholder(subject):
            findings.append(
                FindingV1(
                    CI001,
                    target.path,
                    target.qualname,
                    _FAIL_REASONS[CI001],
                )
            )

    for target in requirement.test_targets:
        failed_path = path_states[target.path]
        if failed_path is not None:
            state, reason = failed_path
            coverage.append(CoverageRecordV1(CI002, target.path, target.qualname, state))
            reasons.add(reason)
            continue
        matches = indexes[target.path].get(target.qualname, [])
        if not matches:
            coverage.append(
                CoverageRecordV1(CI002, target.path, target.qualname, CoverageState.MISSING)
            )
            reasons.add("TARGET_NOT_FOUND")
            continue
        if len(matches) != 1:
            coverage.append(
                CoverageRecordV1(CI002, target.path, target.qualname, CoverageState.AMBIGUOUS)
            )
            reasons.add("TARGET_AMBIGUOUS")
            continue
        coverage.append(
            CoverageRecordV1(CI002, target.path, target.qualname, CoverageState.OBSERVED)
        )
        if _ci002_trivial_test(matches[0]):
            findings.append(
                FindingV1(
                    CI002,
                    target.path,
                    target.qualname,
                    _FAIL_REASONS[CI002],
                )
            )

    matched_junit: list[bool] = []
    if requirement.test_targets:
        junit_rows: list[tuple[str, str, bool]] | None = None
        junit_reason: str | None = None
        if junit is None:
            junit_reason = "JUNIT_MISSING"
        elif type(junit) is not bytes:
            junit_reason = "JUNIT_MALFORMED"
        else:
            try:
                junit_rows = _junit_cases(junit)
            except (ET.ParseError, ValueError):
                junit_reason = "JUNIT_MALFORMED"

        for target in requirement.test_targets:
            if junit_reason is not None:
                state = (
                    CoverageState.MISSING
                    if junit_reason == "JUNIT_MISSING"
                    else CoverageState.UNSUPPORTED
                )
                coverage.append(CoverageRecordV1(CI003, target.path, target.qualname, state))
                reasons.add(junit_reason)
                continue
            target_state = CoverageState.OBSERVED
            assert junit_rows is not None
            for expected in target.junit_cases:
                matches = [
                    skipped
                    for classname, name, skipped in junit_rows
                    if classname == expected.classname and name == expected.name
                ]
                if not matches:
                    target_state = CoverageState.MISSING
                    reasons.add("CLAIMED_TESTCASE_MISSING")
                    continue
                if len(matches) > 1:
                    target_state = CoverageState.AMBIGUOUS
                    reasons.add("CLAIMED_TESTCASE_DUPLICATE")
                    continue
                matched_junit.append(matches[0])
            coverage.append(CoverageRecordV1(CI003, target.path, target.qualname, target_state))

        ci003_records = [item for item in coverage if item.rule_id == CI003]
        if (
            ci003_records
            and all(item.state is CoverageState.OBSERVED for item in ci003_records)
            and matched_junit
            and all(matched_junit)
        ):
            first = requirement.test_targets[0]
            findings.append(
                FindingV1(
                    CI003,
                    first.path,
                    "claimed_test_set",
                    _FAIL_REASONS[CI003],
                )
            )

    return _build_report(
        repository_id=repository_id,
        change_set=change_set,
        source_tree=source_tree,
        target_tree=target_tree,
        input_hash=input_hash,
        inspected_paths=inspected_paths,
        coverage=coverage,
        findings=findings,
        reasons=reasons,
    )


def analyze_code_integrity(
    requirement: CodeIntegrityRequirementV1,
    *,
    repository_id: str,
    change_set: ChangeSet,
    source_tree: str,
    target_tree: str,
    source_files: Mapping[str, bytes],
    junit: bytes | None = None,
) -> CodeIntegrityAnalysisResult:
    if type(requirement) is not CodeIntegrityRequirementV1:
        raise TypeError("requirement must be CodeIntegrityRequirementV1")
    try:
        report = _analyze(
            requirement,
            repository_id=repository_id,
            change_set=change_set,
            source_tree=source_tree,
            target_tree=target_tree,
            source_files=source_files,
            junit=junit,
        )
    except Exception:
        return CodeIntegrityAnalysisResult(
            execution_state=ProducerExecutionState.UNAVAILABLE,
            integrity_status=None,
            report=None,
            reason_codes=("INTERNAL_ANALYZER_ERROR",),
        )
    return CodeIntegrityAnalysisResult(
        execution_state=ProducerExecutionState.COMPLETED,
        integrity_status=report.integrity_status,
        report=report,
        reason_codes=report.reason_codes,
    )


def observation_from_code_integrity(
    result: CodeIntegrityAnalysisResult,
) -> Observation | None:
    """Project a completed PASS/FAIL report into the existing Core Observation type."""
    if (
        result.execution_state is not ProducerExecutionState.COMPLETED
        or result.report is None
        or result.integrity_status not in {CodeIntegrityStatus.PASS, CodeIntegrityStatus.FAIL}
    ):
        return None
    status = (
        ObservationStatus.PASS
        if result.integrity_status is CodeIntegrityStatus.PASS
        else ObservationStatus.FAIL
    )
    return Observation(
        verifier_id=VERIFIER_ID,
        artifact_id=result.report.artifact_id,
        artifact_hash=result.report.artifact_hash,
        status=status,
    )


__all__ = [
    "CI001",
    "CI002",
    "CI003",
    "PROFILE_HASH",
    "PROFILE_ID",
    "REPORT_SCHEMA",
    "REQUIREMENT_SCHEMA",
    "RULE_IDS",
    "VERIFIER_ID",
    "CodeIntegrityAnalysisResult",
    "CodeIntegrityReportV1",
    "CodeIntegrityRequirementV1",
    "CodeIntegrityStatus",
    "CoverageRecordV1",
    "CoverageState",
    "FindingV1",
    "ImplementationTargetV1",
    "JUnitCaseV1",
    "ProducerExecutionState",
    "TestTargetV1",
    "analyze_code_integrity",
    "observation_from_code_integrity",
]
