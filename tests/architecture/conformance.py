from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Sequence


class ModuleLayer(str, Enum):
    PROTOCOL = "PROTOCOL"
    EVIDENCE_TRUST_CORE = "EVIDENCE_TRUST_CORE"
    COMPLETION_CORE = "COMPLETION_CORE"
    CARRYING_STORAGE = "CARRYING_STORAGE"
    CARRYING_ACQUISITION = "CARRYING_ACQUISITION"
    CARRYING_EXECUTION = "CARRYING_EXECUTION"
    CARRYING_ADAPTERS = "CARRYING_ADAPTERS"
    CARRYING_RUNTIME = "CARRYING_RUNTIME"
    CLIENT_SHELL = "CLIENT_SHELL"
    INSTRUMENTATION_BENCHMARK = "INSTRUMENTATION_BENCHMARK"


PACKAGE_LAYER_MAP: dict[str, ModuleLayer] = {
    "product.protocol": ModuleLayer.PROTOCOL,
    "product.evidence": ModuleLayer.EVIDENCE_TRUST_CORE,
    "product.verification": ModuleLayer.EVIDENCE_TRUST_CORE,
    "product.completion": ModuleLayer.COMPLETION_CORE,
    "product.certification": ModuleLayer.COMPLETION_CORE,
    "product.kernel": ModuleLayer.COMPLETION_CORE,
    "product.ledger": ModuleLayer.CARRYING_STORAGE,
    "product.acquisition": ModuleLayer.CARRYING_ACQUISITION,
    "product.execution": ModuleLayer.CARRYING_EXECUTION,
    "product.adapters": ModuleLayer.CARRYING_ADAPTERS,
    "product.runtime": ModuleLayer.CARRYING_RUNTIME,
    "product.clients": ModuleLayer.CLIENT_SHELL,
    "product.benchmark": ModuleLayer.INSTRUMENTATION_BENCHMARK,
}

# Allowed package-level dependency directions.
# Any dependency from a source component to a target component not in this set is a violation.
ALLOWED_DEPENDENCIES: dict[str, set[str]] = {
    "product": set(),
    "product.protocol": {
        "product.protocol",
    },
    "product.evidence": {
        "product.evidence",
        "product.protocol",
    },
    "product.verification": {
        "product.verification",
        "product.evidence",
        "product.protocol",
    },
    "product.completion": {
        "product.completion",
        "product.evidence",
        "product.verification",
        "product.protocol",
    },
    "product.certification": {
        "product.certification",
        "product.evidence",
        "product.verification",
        "product.protocol",
    },
    "product.kernel": {
        "product.kernel",
        "product.certification",
        "product.evidence",
        "product.verification",
        "product.protocol",
    },
    "product.ledger": {
        "product.ledger",
        "product.evidence",
        "product.protocol",
    },
    "product.acquisition": {
        "product.acquisition",
        "product.protocol",
    },
    "product.execution": {
        "product.execution",
        "product.protocol",
    },
    "product.adapters": {
        "product.adapters",
        "product.protocol",
        "product.evidence",
        "product.verification",
        "product.certification",
        "product.kernel",
    },
    "product.runtime": {
        "product.runtime",
        "product.protocol",
        "product.evidence",
        "product.verification",
        "product.certification",
        "product.kernel",
        "product.ledger",
        "product.acquisition",
        "product.execution",
        "product.adapters",
    },
    "product.clients": {
        "product.clients",
        "product.runtime",
        "product.adapters",
        "product.protocol",
    },
    "product.benchmark": {
        "product.benchmark",
        "product.protocol",
        "product.evidence",
        "product.verification",
        "product.certification",
        "product.kernel",
        "product.adapters",
    },
}

FORBIDDEN_ROOTS: tuple[str, ...] = ("nexus", "scripts", "runtimes")


@dataclass(frozen=True)
class ImportEdge:
    source_file: str
    lineno: int
    source_component: str
    target_name: str
    target_component: str | None


@dataclass(frozen=True)
class Violation:
    source_file: str
    lineno: int
    source_component: str
    target_name: str
    target_component: str | None
    rule_name: str
    message: str

    def format(self) -> str:
        return f"{self.source_file}:{self.lineno}: [{self.rule_name}] {self.message}"


@dataclass(frozen=True)
class DependencyGraph:
    edges: list[ImportEdge]
    component_graph: dict[str, set[str]]
    file_graph: dict[str, set[str]]


def get_component_and_pkg_parts(
    file_path: Path, repo_root: Path
) -> tuple[str, list[str]]:
    rel = file_path.resolve().relative_to(repo_root.resolve())
    parts = list(rel.parts)
    is_init = parts[-1] == "__init__.py"
    parts[-1] = parts[-1].removesuffix(".py")
    if is_init:
        parts.pop()
        pkg_parts = parts
    else:
        pkg_parts = parts[:-1]

    if len(parts) >= 2:
        component_name = f"{parts[0]}.{parts[1]}"
    else:
        component_name = ".".join(parts)
    return component_name, pkg_parts


def resolve_import_target(
    node: ast.Import | ast.ImportFrom,
    pkg_parts: Sequence[str],
) -> list[str]:
    targets: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            targets.append(alias.name)
    elif isinstance(node, ast.ImportFrom):
        if node.level > 0:
            if node.level > len(pkg_parts):
                base = []
            else:
                base = list(pkg_parts[: len(pkg_parts) - (node.level - 1)])
            if node.module:
                target_base = ".".join(base) + "." + node.module if base else node.module
                targets.append(target_base)
            else:
                for alias in node.names:
                    target_base = ".".join(base) + "." + alias.name if base else alias.name
                    targets.append(target_base)
        else:
            if node.module:
                if node.module == "product":
                    for alias in node.names:
                        targets.append(f"product.{alias.name}")
                else:
                    targets.append(node.module)
    return targets


def target_to_component(target_name: str) -> str | None:
    parts = target_name.split(".")
    if parts[0] == "product":
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return "product"
    return None


def extract_imports_from_source(
    source_code: str,
    file_path: Path,
    repo_root: Path,
) -> list[ImportEdge]:
    component_name, pkg_parts = get_component_and_pkg_parts(file_path, repo_root)
    rel_path = str(file_path.resolve().relative_to(repo_root.resolve()))
    tree = ast.parse(source_code, filename=rel_path)

    edges: list[ImportEdge] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            targets = resolve_import_target(node, pkg_parts)
            for target in targets:
                edges.append(
                    ImportEdge(
                        source_file=rel_path,
                        lineno=node.lineno,
                        source_component=component_name,
                        target_name=target,
                        target_component=target_to_component(target),
                    )
                )
    return edges


def build_dependency_graph(
    product_dir: Path,
    repo_root: Path,
) -> DependencyGraph:
    edges: list[ImportEdge] = []
    component_graph: dict[str, set[str]] = {k: set() for k in PACKAGE_LAYER_MAP}
    component_graph["product"] = set()
    file_graph: dict[str, set[str]] = {}

    for py_file in sorted(product_dir.rglob("*.py")):
        source_code = py_file.read_text(encoding="utf-8")
        file_edges = extract_imports_from_source(source_code, py_file, repo_root)
        edges.extend(file_edges)

        rel_path = str(py_file.resolve().relative_to(repo_root.resolve()))
        file_graph[rel_path] = set()

        for edge in file_edges:
            file_graph[rel_path].add(edge.target_name)
            if edge.target_component:
                component_graph.setdefault(edge.source_component, set()).add(
                    edge.target_component
                )

    return DependencyGraph(
        edges=edges,
        component_graph=component_graph,
        file_graph=file_graph,
    )


def verify_conformance(
    graph: DependencyGraph,
    allowed_dependencies: Mapping[str, set[str]] | None = None,
    forbidden_roots: Sequence[str] = FORBIDDEN_ROOTS,
) -> list[Violation]:
    allowed_map = allowed_dependencies if allowed_dependencies is not None else ALLOWED_DEPENDENCIES
    violations: list[Violation] = []

    for edge in graph.edges:
        root_pkg = edge.target_name.split(".")[0]

        # 1. Check legacy roots prohibition
        if root_pkg in forbidden_roots:
            violations.append(
                Violation(
                    source_file=edge.source_file,
                    lineno=edge.lineno,
                    source_component=edge.source_component,
                    target_name=edge.target_name,
                    target_component=edge.target_component,
                    rule_name="FORBIDDEN_LEGACY_ROOT",
                    message=(
                        f"Forbidden legacy import root '{root_pkg}' in '{edge.target_name}'"
                    ),
                )
            )
            continue

        # 2. Check benchmark isolation invariant: non-benchmark must not import benchmark
        if (
            edge.target_component == "product.benchmark"
            and edge.source_component != "product.benchmark"
        ):
            violations.append(
                Violation(
                    source_file=edge.source_file,
                    lineno=edge.lineno,
                    source_component=edge.source_component,
                    target_name=edge.target_name,
                    target_component=edge.target_component,
                    rule_name="BENCHMARK_ISOLATION_INVERSION",
                    message=(
                        f"Non-benchmark component '{edge.source_component}' must not import "
                        f"benchmark layer '{edge.target_name}'"
                    ),
                )
            )
            continue

        # 3. Check internal product dependencies
        if edge.target_component is not None:
            allowed = allowed_map.get(edge.source_component)
            if allowed is None:
                violations.append(
                    Violation(
                        source_file=edge.source_file,
                        lineno=edge.lineno,
                        source_component=edge.source_component,
                        target_name=edge.target_name,
                        target_component=edge.target_component,
                        rule_name="UNCLASSIFIED_SOURCE_COMPONENT",
                        message=f"Source component '{edge.source_component}' is not mapped in policy",
                    )
                )
            elif edge.target_component not in allowed:
                # Classify authority inversion vs layer inversion
                source_layer = PACKAGE_LAYER_MAP.get(edge.source_component)
                target_layer = PACKAGE_LAYER_MAP.get(edge.target_component)
                rule_name = "FORBIDDEN_DEPENDENCY_EDGE"
                if source_layer in (
                    ModuleLayer.EVIDENCE_TRUST_CORE,
                    ModuleLayer.COMPLETION_CORE,
                ) and target_layer not in (
                    ModuleLayer.EVIDENCE_TRUST_CORE,
                    ModuleLayer.COMPLETION_CORE,
                    ModuleLayer.PROTOCOL,
                ):
                    rule_name = "AUTHORITY_INVERSION_VIOLATION"
                elif edge.source_component == "product.protocol":
                    rule_name = "PROTOCOL_PURITY_VIOLATION"

                violations.append(
                    Violation(
                        source_file=edge.source_file,
                        lineno=edge.lineno,
                        source_component=edge.source_component,
                        target_name=edge.target_name,
                        target_component=edge.target_component,
                        rule_name=rule_name,
                        message=(
                            f"Forbidden dependency edge: '{edge.source_component}' -> "
                            f"'{edge.target_component}' (via import '{edge.target_name}')"
                        ),
                    )
                )

    return violations


def generate_mermaid_graph(graph: DependencyGraph) -> str:
    lines: list[str] = [
        "```mermaid",
        "flowchart TD",
        '    subgraph Clients["Client Shell"]',
        '        product.clients["product.clients"]',
        "    end",
        '    subgraph Runtime["Carrying Layers & Runtime"]',
        '        product.runtime["product.runtime"]',
        '        product.acquisition["product.acquisition"]',
        '        product.execution["product.execution"]',
        '        product.ledger["product.ledger"]',
        '        product.adapters["product.adapters"]',
        "    end",
        '    subgraph CompletionCore["Completion Core (Truth Authority)"]',
        '        product.kernel["product.kernel"]',
        '        product.certification["product.certification"]',
        '        product.completion["product.completion"]',
        "    end",
        '    subgraph EvidenceTrustCore["Evidence Trust Core (Truth Authority)"]',
        '        product.verification["product.verification"]',
        '        product.evidence["product.evidence"]',
        "    end",
        '    subgraph ProtocolFoundation["Protocol Foundation"]',
        '        product.protocol["product.protocol"]',
        "    end",
        '    subgraph Benchmark["Benchmark & Instrumentation"]',
        '        product.benchmark["product.benchmark"]',
        "    end",
        "",
    ]

    for src in sorted(graph.component_graph):
        if src == "product":
            continue
        for dst in sorted(graph.component_graph[src]):
            if src != dst and dst != "product":
                lines.append(f"    {src} --> {dst}")

    lines.append("```")
    return "\n".join(lines)


def format_report(violations: list[Violation]) -> str:
    if not violations:
        return "PASS: All source dependencies conform to architecture boundaries."
    lines = [f"FAIL: {len(violations)} architecture violation(s) found:"]
    for v in violations:
        lines.append(f"  - {v.format()}")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    repo_root = Path(__file__).resolve().parent.parent.parent
    product_dir = repo_root / "product"
    graph = build_dependency_graph(product_dir, repo_root)

    if "--mermaid" in sys.argv:
        print(generate_mermaid_graph(graph))
        sys.exit(0)

    violations = verify_conformance(graph)
    print(format_report(violations))
    if violations:
        sys.exit(1)
    sys.exit(0)
