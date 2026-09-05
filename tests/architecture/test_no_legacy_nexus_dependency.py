from __future__ import annotations

import ast
from pathlib import Path

FORBIDDEN_ROOTS = ("nexus", "scripts", "runtimes")


def test_production_product_has_no_legacy_nexus_dependency():
    repo_root = Path(__file__).resolve().parent.parent.parent
    product_dir = repo_root / "product"
    assert product_dir.is_dir(), f"Product directory not found at {product_dir}"

    violations: list[str] = []
    for py_file in product_dir.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except Exception as exc:
            violations.append(f"{py_file}: failed to parse AST: {exc}")
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    if root_pkg in FORBIDDEN_ROOTS:
                        violations.append(f"{py_file}:{node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_pkg = node.module.split(".")[0]
                    if root_pkg in FORBIDDEN_ROOTS:
                        violations.append(f"{py_file}:{node.lineno}: from {node.module} import ...")

    assert not violations, "Found forbidden legacy imports in product/:\n" + "\n".join(violations)
