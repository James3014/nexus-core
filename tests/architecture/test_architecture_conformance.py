from __future__ import annotations

from pathlib import Path

import pytest

from tests.architecture.conformance import (
    ALLOWED_DEPENDENCIES,
    FORBIDDEN_ROOTS,
    PACKAGE_LAYER_MAP,
    DependencyGraph,
    build_dependency_graph,
    extract_imports_from_source,
    generate_mermaid_graph,
    verify_conformance,
)


@pytest.fixture(scope="module")
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def current_graph(repo_root: Path) -> DependencyGraph:
    product_dir = repo_root / "product"
    assert product_dir.is_dir(), f"product dir not found at {product_dir}"
    return build_dependency_graph(product_dir, repo_root)


def test_production_product_conforms_to_architecture_boundaries(
    current_graph: DependencyGraph,
):
    violations = verify_conformance(current_graph)
    assert not violations, (
        "Architecture conformance violations detected in product/:\n"
        + "\n".join(f"  - {v.format()}" for v in violations)
    )


def test_all_production_packages_are_explicitly_classified():
    expected_packages = {
        "product.protocol",
        "product.evidence",
        "product.verification",
        "product.completion",
        "product.certification",
        "product.kernel",
        "product.ledger",
        "product.acquisition",
        "product.execution",
        "product.adapters",
        "product.runtime",
        "product.clients",
        "product.benchmark",
    }
    assert set(PACKAGE_LAYER_MAP.keys()) == expected_packages
    assert set(ALLOWED_DEPENDENCIES.keys()) == expected_packages | {"product"}


def test_negative_control_evidence_authority_importing_client_surface(
    repo_root: Path,
):
    source = (
        "from __future__ import annotations\n"
        "from product.clients.cli import main\n"
    )
    fake_file = repo_root / "product" / "evidence" / "_synthetic_violation.py"
    edges = extract_imports_from_source(source, fake_file, repo_root)
    graph = DependencyGraph(
        edges=edges,
        component_graph={"product.evidence": {"product.clients"}},
        file_graph={
            "product/evidence/_synthetic_violation.py": {"product.clients.cli"}
        },
    )
    violations = verify_conformance(graph)
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_name == "AUTHORITY_INVERSION_VIOLATION"
    assert v.source_component == "product.evidence"
    assert v.target_component == "product.clients"
    assert v.lineno == 2
    assert "Forbidden dependency edge: 'product.evidence' -> 'product.clients'" in v.message


def test_negative_control_completion_authority_importing_benchmark(
    repo_root: Path,
):
    source = (
        "import os\n"
        "import product.benchmark.tg7_shadow\n"
    )
    fake_file = repo_root / "product" / "completion" / "_synthetic_bench.py"
    edges = extract_imports_from_source(source, fake_file, repo_root)
    graph = DependencyGraph(
        edges=edges,
        component_graph={"product.completion": {"product.benchmark"}},
        file_graph={
            "product/completion/_synthetic_bench.py": {
                "product.benchmark.tg7_shadow"
            }
        },
    )
    violations = verify_conformance(graph)
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_name == "BENCHMARK_ISOLATION_INVERSION"
    assert v.source_component == "product.completion"
    assert v.target_name == "product.benchmark.tg7_shadow"
    assert v.lineno == 2


def test_negative_control_kernel_depending_on_acquisition(
    repo_root: Path,
):
    source = "from product.acquisition.github import fetch_issue\n"
    fake_file = repo_root / "product" / "kernel" / "_synthetic_acq.py"
    edges = extract_imports_from_source(source, fake_file, repo_root)
    graph = DependencyGraph(
        edges=edges,
        component_graph={"product.kernel": {"product.acquisition"}},
        file_graph={
            "product/kernel/_synthetic_acq.py": {"product.acquisition.github"}
        },
    )
    violations = verify_conformance(graph)
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_name == "AUTHORITY_INVERSION_VIOLATION"
    assert v.source_component == "product.kernel"
    assert v.target_component == "product.acquisition"
    assert v.lineno == 1


def test_negative_control_protocol_depending_on_runtime(
    repo_root: Path,
):
    source = "import product.runtime.service\n"
    fake_file = repo_root / "product" / "protocol" / "_synthetic_runtime.py"
    edges = extract_imports_from_source(source, fake_file, repo_root)
    graph = DependencyGraph(
        edges=edges,
        component_graph={"product.protocol": {"product.runtime"}},
        file_graph={
            "product/protocol/_synthetic_runtime.py": {"product.runtime.service"}
        },
    )
    violations = verify_conformance(graph)
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_name == "PROTOCOL_PURITY_VIOLATION"
    assert v.source_component == "product.protocol"
    assert v.target_component == "product.runtime"
    assert v.lineno == 1


@pytest.mark.parametrize("forbidden_root", FORBIDDEN_ROOTS)
def test_negative_control_legacy_dependency_reintroduction(
    forbidden_root: str, repo_root: Path
):
    source = f"import {forbidden_root}.legacy_module\n"
    fake_file = repo_root / "product" / "adapters" / "_synthetic_legacy.py"
    edges = extract_imports_from_source(source, fake_file, repo_root)
    graph = DependencyGraph(
        edges=edges,
        component_graph={},
        file_graph={},
    )
    violations = verify_conformance(graph)
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_name == "FORBIDDEN_LEGACY_ROOT"
    assert forbidden_root in v.message
    assert v.lineno == 1


def test_generated_mermaid_graph_is_deterministic(
    current_graph: DependencyGraph,
):
    mermaid1 = generate_mermaid_graph(current_graph)
    mermaid2 = generate_mermaid_graph(current_graph)
    assert mermaid1 == mermaid2
    assert "flowchart TD" in mermaid1
    assert "product.evidence" in mermaid1
    assert "product.clients --> product.runtime" in mermaid1


def test_architecture_boundary_doc_is_in_sync(
    repo_root: Path, current_graph: DependencyGraph
):
    boundary_file = repo_root / "docs" / "architecture" / "BOUNDARY.md"
    assert boundary_file.is_file(), f"BOUNDARY.md not found at {boundary_file}"
    content = boundary_file.read_text(encoding="utf-8")
    expected_mermaid = generate_mermaid_graph(current_graph)
    assert expected_mermaid in content, (
        "docs/architecture/BOUNDARY.md architecture diagram is out of sync with current source graph."
    )


def test_source_discovered_components_match_architecture_policy(repo_root: Path):
    product_dir = repo_root / "product"
    discovered = {"product"}

    for py_file in sorted(product_dir.rglob("*.py")):
        rel = py_file.relative_to(repo_root)
        parts = rel.parts
        if len(parts) == 2 and parts[1] == "__init__.py":
            discovered.add("product")
            continue
        if len(parts) >= 2:
            component = parts[1].removesuffix(".py")
            discovered.add(f"product.{component}")

    policy_components = set(PACKAGE_LAYER_MAP) | {"product"}
    assert discovered == policy_components, (
        "Every source-derived top-level product component must be explicitly "
        "classified in PACKAGE_LAYER_MAP. "
        f"discovered={sorted(discovered)} policy={sorted(policy_components)}"
    )
