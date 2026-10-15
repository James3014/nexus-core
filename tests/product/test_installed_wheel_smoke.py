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
    assert res_version.stdout.strip() == "0.3.0"

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


def _git_head(repo_root: Path) -> tuple[str, str] | None:
    try:
        top = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if Path(top).resolve() != repo_root:
            return None
        commit = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD^{tree}"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return (commit, tree)


def test_release_build_embeds_commit_and_core_identity_runs_without_git(tmp_path: Path):
    """#267: `uv build` (sdist, then wheel from the sdist) embeds the commit."""
    import json
    import tarfile

    from product.protocol.build_identity import shipped_source_paths, source_digest

    repo_root = Path(__file__).parents[2].resolve()
    head = _git_head(repo_root)
    if head is None:
        pytest.skip("not a git checkout: nothing to embed")
    dist_dir = tmp_path / "dist"
    res_build = subprocess.run(
        ["uv", "build", "--out-dir", str(dist_dir)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    assert res_build.returncode == 0, res_build.stderr
    wheel = next(dist_dir.glob("nexus_certify-*.whl"))
    sdist = next(dist_dir.glob("nexus_certify-*.tar.gz"))

    with zipfile.ZipFile(wheel) as zf:
        wheel_stamp = json.loads(zf.read("product/_build_identity.json"))
        wheel_files = {
            name for name in zf.namelist()
            if name.startswith("product/") and not name.endswith("/")
        }
    with tarfile.open(sdist, "r:gz") as tf:
        member = next(m for m in tf.getmembers() if m.name.endswith("/product/_build_identity.json"))
        extracted = tf.extractfile(member)
        assert extracted is not None
        sdist_stamp = json.loads(extracted.read())

    commit, tree = head
    assert wheel_stamp == sdist_stamp
    assert (wheel_stamp["git_commit"], wheel_stamp["git_tree"]) == (commit, tree)
    assert wheel_stamp["version"] == "0.3.0"
    checkout_digest = source_digest(repo_root / "product")
    assert wheel_stamp["source_digest"] == checkout_digest
    # The digest covers exactly what the wheel ships, minus the stamp.
    assert wheel_files - {"product/_build_identity.json"} == set(shipped_source_paths(repo_root / "product"))

    venv_dir = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    subprocess.run(
        [str(venv_dir / "bin" / "pip"), "install", "-q", "--no-deps", str(wheel)], check=True
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["PATH"] = str(tmp_path / "no-git-bin")
    outside = tmp_path / "outside"
    outside.mkdir()
    probe = (
        "import json, shutil, product.protocol as p; "
        "assert shutil.which('git') is None; "
        "assert 'site-packages' in p.__file__, p.__file__; "
        "print(json.dumps(p.core_identity()))"
    )
    runs = []
    for _ in range(2):  # the first import writes __pycache__ into site-packages
        res = subprocess.run(
            [str(venv_dir / "bin" / "python"), "-c", probe],
            cwd=str(outside), env=env, capture_output=True, text=True,
        )
        assert res.returncode == 0, res.stderr
        runs.append(json.loads(res.stdout))
    assert runs[0] == runs[1]
    identity = runs[0]
    assert identity["build_identity"] == "EMBEDDED"
    assert (identity["git_commit"], identity["git_tree"]) == (commit, tree)
    assert identity["source_digest"] == checkout_digest
    assert identity["source_matches_build"] is True


def test_git_dirty_counts_ignored_packaged_files_but_not_bytecode(tmp_path: Path):
    """#270 review: an ignored .py inside a package ships, so it is dirty."""
    import json

    repo_root = Path(__file__).parents[2].resolve()
    if _git_head(repo_root) is None:
        pytest.skip("not a git checkout")
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", "--no-hardlinks", str(repo_root), str(clone)],
        check=True, capture_output=True,
    )
    # Bytecode only: still clean.
    subprocess.run([sys.executable, "-m", "compileall", "-q", str(clone / "product")], check=True)

    from product.protocol.build_identity import shipped_source_paths, source_digest

    def build_stamp(name: str) -> dict:
        out = tmp_path / name
        res = subprocess.run(
            ["uv", "build", "--wheel", "--out-dir", str(out)],
            cwd=str(clone), capture_output=True, text=True,
        )
        assert res.returncode == 0, res.stderr
        with zipfile.ZipFile(next(out.glob("*.whl"))) as zf:
            stamp = json.loads(zf.read("product/_build_identity.json"))
            shipped = {
                n for n in zf.namelist()
                if n.startswith("product/") and not n.endswith("/")
            } - {"product/_build_identity.json"}
        # The digest covers exactly what the wheel ships.
        assert shipped == set(shipped_source_paths(clone / "product"))
        assert stamp["source_digest"] == source_digest(clone / "product")
        return stamp

    clean = build_stamp("clean")
    assert clean["git_dirty"] is False
    # ".gitignore" ignores "build/": product/build/ is still a shipped package.
    (clone / "product" / "build").mkdir()
    (clone / "product" / "build" / "__init__.py").write_text("x = 1\n")
    # Namespace directory (no __init__.py) ships too; dotted names do not.
    (clone / "product" / "nsdir").mkdir()
    (clone / "product" / "nsdir" / "mod.py").write_text("x = 1\n")
    (clone / "product" / "x.y").mkdir()
    (clone / "product" / "x.y" / "m.py").write_text("x = 1\n")
    subprocess.run(["rm", "-rf", str(clone / "build")], check=True)
    dirty = build_stamp("dirty")
    assert dirty["git_dirty"] is True
    assert dirty["git_commit"] == clean["git_commit"]
    assert dirty["source_digest"] != clean["source_digest"]
    assert "product/nsdir/mod.py" in shipped_source_paths(clone / "product")
