"""#304: the pyright verifier must not install Node.js from the live release index.

The Core gate runs ``uv run pyright product`` inside the verifier container, whose
image has no Node.js. pyright-python then falls back to nodeenv, which picks the
newest entry of https://nodejs.org/dist/index.json; when that became
``27.0.0-alpha.0.0.0`` nodeenv 1.10.0 crashed and every receipt was
FAILED_VERIFICATION (EVIDENCE_CLAIM_FAILED, pyright). The dev group therefore
installs ``pyright[nodejs]``: Node.js comes from the hash-locked
``nodejs-wheel-binaries`` wheel and nodeenv is never reached.
"""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _lock_packages() -> list[dict[str, Any]]:
    return tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]


def test_dev_group_locks_pyright_with_nodejs_wheel() -> None:
    packages = _lock_packages()
    project = next(p for p in packages if p["name"] == "nexus-certify")
    dev = project["dev-dependencies"]["dev"]
    pyright = [d for d in dev if d["name"] == "pyright"]
    assert len(pyright) == 1
    assert "nodejs" in pyright[0].get("extra", []), (
        "dev group must install pyright[nodejs] so the verifier never runs nodeenv"
    )

    wheel = [p for p in packages if p["name"] == "nodejs-wheel-binaries"]
    assert len(wheel) == 1, "uv.lock must pin exactly one nodejs-wheel-binaries"
    version = wheel[0]["version"]
    assert all(part.isdigit() for part in version.split(".")), (
        f"nodejs-wheel-binaries must be a final release, not {version}"
    )
    linux = [w for w in wheel[0]["wheels"] if "manylinux" in w["url"] and "x86_64" in w["url"]]
    assert linux and all(w["hash"].startswith("sha256:") for w in linux)


def test_locked_environment_resolves_node_from_wheel_not_nodeenv() -> None:
    assert importlib.util.find_spec("nodejs_wheel") is not None, (
        "nodejs-wheel-binaries is not installed; pyright would fall back to nodeenv"
    )
    from pyright import node

    strategy = node._resolve_strategy("node")  # pyright: ignore[reportPrivateUsage]
    assert strategy.type == "nodejs_wheel"
