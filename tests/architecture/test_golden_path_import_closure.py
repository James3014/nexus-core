"""Golden Path import closure: no aiohttp, runtime or benchmark in a fresh interpreter."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parents[2].resolve()

PROBE = (
    "import sys, product.clients.cli, product.clients.local_golden_path, "
    "product.clients.issue_golden_path; "
    "mods=sorted(m for m in sys.modules if m.startswith('product.')); "
    "print(len(mods)); "
    "print('aiohttp' in sys.modules); "
    "print(any(m.startswith('product.runtime') for m in sys.modules)); "
    "print(any(m.startswith('product.benchmark') for m in sys.modules)); "
    "print(chr(10).join(mods))"
)


def test_golden_path_import_closure_is_stdlib_only_and_small():
    res = subprocess.run(
        [sys.executable, "-I", "-c", PROBE],
        cwd=str(REPO_ROOT),
        env={"PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stderr
    lines = res.stdout.splitlines()
    count, has_aiohttp, has_runtime, has_benchmark = lines[:4]
    listing = "\n".join(lines[4:])
    assert has_aiohttp == "False", listing
    assert has_runtime == "False", listing
    assert has_benchmark == "False", listing
    assert int(count) < 25, f"{count} product.* modules loaded:\n{listing}"
