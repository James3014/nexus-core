"""Test that the built standalone nexus-certify wheel installs and executes cleanly."""

import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


def test_installed_wheel_smoke_in_isolated_venv(tmp_path: Path):
    repo_root = Path(__file__).parents[2].resolve()
    dist_dir = tmp_path / "dist"
    res_build = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    if res_build.returncode != 0:
        pytest.fail(f"Failed to build nexus-certify wheel: {res_build.stderr}")
    wheels = sorted(dist_dir.glob("nexus_certify-*.whl"))

    if not wheels:
        pytest.fail("No nexus-certify wheel found in dist/ after build attempt.")

    target_wheel = wheels[-1]

    # Create isolated venv
    venv_dir = tmp_path / "smoke_venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    venv_pip = venv_dir / "bin" / "pip"
    venv_python = venv_dir / "bin" / "python"
    venv_certify = venv_dir / "bin" / "nexus-certify"

    # Benchmark harness is source-only and must not ship in the wheel.
    with zipfile.ZipFile(target_wheel) as zf:
        assert not [n for n in zf.namelist() if n.startswith("product/benchmark/")]

    # Install the wheel without dependencies: Golden Path must need nothing else.
    subprocess.run([str(venv_pip), "install", "--no-deps", str(target_wheel)], check=True)

    # 1. Verify exact distribution identity and CLI surface.
    assert venv_certify.is_file()
    res_version = subprocess.run(
        [
            str(venv_python),
            "-c",
            "import importlib.metadata as m; print(m.version('nexus-certify'))",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res_version.stdout.strip() == "0.2.0"

    res_cli = subprocess.run(
        [str(venv_certify), "--help"], capture_output=True, text=True, check=True
    )
    assert "nexus-certify" in res_cli.stdout
    assert "issue-init" in res_cli.stdout
    assert "issue-check" in res_cli.stdout

    for command in ("issue-init", "issue-check"):
        res_subcommand = subprocess.run(
            [str(venv_certify), command, "--help"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert command in res_subcommand.stdout

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

    # 3. Golden Path end-to-end on a tiny temp repository, no third-party packages.
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
            cwd=str(repo),
            check=True,
            capture_output=True,
        )

    git("init", "-q", "-b", "main")
    (repo / "a.txt").write_text("base\n")
    git("add", ".")
    git("commit", "-qm", "base")
    res_init = subprocess.run(
        [
            str(venv_certify),
            "init",
            "--base-ref",
            "main",
            "--allow",
            "**",
            "--verifier",
            "python",
            "-c",
            "import sys; sys.exit(0)",
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert res_init.returncode == 0, res_init.stderr
    git("add", ".nexus-core/config.toml")
    git("commit", "-qm", "config")
    git("checkout", "-q", "-b", "feature")
    (repo / "a.txt").write_text("changed\n")
    git("add", ".")
    git("commit", "-qm", "change")
    # The verifier is invoked as "python": make the venv python resolvable.
    env = {**os.environ, "PATH": f"{venv_dir / 'bin'}{os.pathsep}{os.environ['PATH']}"}
    for command in ("doctor", "check"):
        res = subprocess.run(
            [str(venv_certify), command],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=env,
        )
        assert res.returncode == 0, (command, res.stdout, res.stderr)
        if command == "check":
            assert "VERIFIED" in res.stdout, (command, res.stdout)
        else:
            assert "doctor: OK" in res.stdout, res.stdout

    # 4. Runtime commands: help works, execution without aiohttp prints the hint.
    res_help = subprocess.run([str(venv_certify), "submit", "--help"], capture_output=True, text=True)
    assert res_help.returncode == 0
    res_submit = subprocess.run(
        [str(venv_certify), "submit", "--request", "x.json"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert res_submit.returncode == 2
    assert "pip install 'nexus-certify[runtime]'" in res_submit.stderr

    # 5. The [runtime] extra provides aiohttp (needs network).
    res_extra = subprocess.run(
        [str(venv_pip), "install", f"{target_wheel}[runtime]"], capture_output=True, text=True
    )
    if res_extra.returncode != 0:
        pytest.skip(f"offline: cannot install [runtime] extra: {res_extra.stderr[-200:]}")
    subprocess.run([str(venv_python), "-c", "import aiohttp"], check=True)
