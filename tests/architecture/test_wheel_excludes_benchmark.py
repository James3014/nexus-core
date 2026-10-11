"""The wheel must not ship benchmark-only code (#148)."""

from __future__ import annotations

import tomllib
from fnmatch import fnmatchcase
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _wheel_packages() -> list[str]:
    """Mirror setuptools.packages.find (regular packages) without needing setuptools."""

    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    find = config["tool"]["setuptools"]["packages"]["find"]
    root = REPO_ROOT / find["where"][0]
    include, exclude = find["include"], find.get("exclude", [])
    packages = []
    for init in sorted(root.rglob("__init__.py")):
        parts = init.parent.relative_to(root).parts
        if not parts or any(not part.isidentifier() for part in parts):
            continue
        if any(not root.joinpath(*parts[:i], "__init__.py").exists() for i in range(1, len(parts))):
            continue
        name = ".".join(parts)
        if any(fnmatchcase(name, pat) for pat in include) and not any(
            fnmatchcase(name, pat) for pat in exclude
        ):
            packages.append(name)
    return packages


def test_benchmark_package_is_excluded_from_wheel() -> None:
    packages = _wheel_packages()
    assert "product" in packages
    assert not [p for p in packages if p.split(".")[:2] == ["product", "benchmark"]]


def test_compatibility_gate_is_not_in_any_wheel_package() -> None:
    leaked = []
    for package in _wheel_packages():
        package_dir = REPO_ROOT.joinpath(*package.split("."))
        leaked.extend(
            str(path.relative_to(REPO_ROOT)) for path in package_dir.glob("*compatibility_gate*.py")
        )
    assert leaked == []
