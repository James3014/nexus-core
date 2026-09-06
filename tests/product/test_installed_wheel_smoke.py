"""Test that the built standalone nexus-core wheel installs and executes cleanly."""

import subprocess
import sys
from pathlib import Path

import pytest


def test_installed_wheel_smoke_in_isolated_venv(tmp_path: Path):
    repo_root = Path(__file__).parents[2].resolve()
    dist_dir = repo_root / "dist"
    wheels = sorted(dist_dir.glob("nexus_core-*.whl"))
    if not wheels:
        try:
            subprocess.run(["uv", "build"], cwd=str(repo_root), check=True)
            wheels = sorted(dist_dir.glob("nexus_core-*.whl"))
        except Exception:
            pass
    if not wheels:
        pytest.skip("No nexus-core wheel found in dist/ and uv build not available.")

    target_wheel = wheels[-1]

    # Create isolated venv
    venv_dir = tmp_path / "smoke_venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    venv_pip = venv_dir / "bin" / "pip"
    venv_python = venv_dir / "bin" / "python"
    venv_certify = venv_dir / "bin" / "nexus-certify"

    # Install the wheel
    subprocess.run([str(venv_pip), "install", str(target_wheel)], check=True)

    # 1. Verify CLI executable works
    assert venv_certify.is_file()
    res_cli = subprocess.run([str(venv_certify), "--help"], capture_output=True, text=True, check=True)
    assert "nexus-certify" in res_cli.stdout

    # 2. Run runner verification script outside the repo checkout
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    probe_script = outside_dir / "probe.py"
    probe_script.write_text(
        """\
import sys
from pathlib import Path
import product
from product.execution.python_runner import PythonOCIRunner

product_path = Path(product.__file__).resolve()
print("PRODUCT_FILE:", product_path)
assert "site-packages" in str(product_path), f"Not in site-packages: {product_path}"

runner = PythonOCIRunner()
assert runner.profile is not None
assert runner.profile.profile_id == "python-oci-pytest-v1"
assert runner.profile.command == ("python", "-m", "pytest", "--junitxml=/evidence/junit.xml")
print("PROBE_OK")
"""
    )

    res_probe = subprocess.run(
        [str(venv_python), str(probe_script)],
        cwd=str(outside_dir),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "PROBE_OK" in res_probe.stdout
    assert str(repo_root) not in res_probe.stdout
