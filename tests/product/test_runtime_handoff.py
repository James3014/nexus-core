"""Tests for runtime and manual handoff readiness (issue #83).

Covers all 10 Negative Controls and the Positive Golden Path for
MANUAL_TEST_HANDOFF_READY_NOT_RELEASED.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Generator

import pytest

import product.clients.runtime_handoff as runtime_handoff_module
from product.clients.cli import main
from product.clients.local_golden_path import (
    LocalCheckError,
    check_repository,
    init_repository,
    validate_verification_receipt,
)
from product.clients.runtime_handoff import (
    HANDOFF_CLAIM_CEILING,
    check_handoff,
    handoff_status,
    init_handoff,
    validate_handoff_receipt,
)
from product.protocol.runtime_handoff import HANDOFF_NON_CLAIMS


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def test_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "owner@example.test")
    _git(repo, "config", "user.name", "Owner")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "test_app.py").write_text(
        "from app import VALUE\ndef test_val():\n    assert VALUE > 0\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial commit")

    # Create feature branch with a change from main
    _git(repo, "checkout", "-b", "feature")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "feature change")

    # Initialize and check repository to obtain prerequisite VERIFIED receipt
    init_repository(
        repo,
        base_ref="main",
        allowed_patterns=("**",),
        verifier_command=(sys.executable, "-m", "pytest", "-q"),
    )
    res = check_repository(repo)
    assert res["status"] == "VERIFIED"
    return repo


@pytest.fixture
def dummy_server(tmp_path: Path) -> Generator[dict[str, Any], None, None]:
    port = _get_free_port()
    pid_file = tmp_path / "server.pid"
    cmd = [
        sys.executable,
        "-u",
        "-c",
        f"""
import http.server, os, sys, time
port = {port}
with open('{pid_file}', 'w') as f:
    f.write(str(os.getpid()))
server = http.server.HTTPServer(('127.0.0.1', port), http.server.SimpleHTTPRequestHandler)
server.serve_forever()
""",
    ]
    proc = subprocess.Popen(cmd)

    # Wait until reachable
    deadline = time.time() + 5.0
    ready = False
    while time.time() < deadline:
        if pid_file.is_file():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    ready = True
                    break
            except OSError:
                pass
        time.sleep(0.05)

    assert ready, "dummy server failed to start"
    yield {
        "port": port,
        "endpoint": f"http://127.0.0.1:{port}",
        "pid_file": str(pid_file),
        "proc": proc,
    }
    proc.terminate()
    proc.wait()


# --- Positive Control: Happy Path ---

def test_handoff_happy_path(test_repo: Path, dummy_server: dict[str, Any]):
    """Verify that a live service + passing handoff verifier produces HANDOFF_READY."""
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )

    result = check_handoff(test_repo)
    assert result["status"] == "HANDOFF_READY"
    assert result["claim_ceiling"] == HANDOFF_CLAIM_CEILING

    status = handoff_status(test_repo)
    assert status["status"] == "HANDOFF_READY"
    assert status["fresh"] is True
    assert status["reason_codes"] == []

    # Validate receipt payload
    validation = validate_handoff_receipt(result["receipt_path"], repo=test_repo)
    assert validation["valid"] is True
    assert validation["reason_codes"] == []


# --- NC-01: Repository VERIFIED alone must not imply handoff-ready ---

def test_nc01_repo_verified_alone_does_not_imply_handoff_ready(test_repo: Path):
    """NC-01: repository check is VERIFIED, but handoff status is MISSING, not HANDOFF_READY."""
    status = handoff_status(test_repo)
    assert status["status"] == "MISSING"
    assert status["fresh"] is False
    assert "HANDOFF_RECEIPT_MISSING" in status["reason_codes"]


def test_prerequisite_tampered_repository_receipt_blocks_handoff(
    test_repo: Path, dummy_server: dict[str, Any]
):
    """A forged/stale VERIFIED string is not enough; the prerequisite receipt must validate."""
    repo_receipt = sorted((test_repo / ".nexus-core" / "receipts").glob("*.json"))[-1]
    payload = json.loads(repo_receipt.read_text(encoding="utf-8"))
    assert payload["outcome"]["status"] == "VERIFIED"
    payload["receipt_hash"] = "sha256:" + "0" * 64
    repo_receipt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )

    with pytest.raises(LocalCheckError) as raised:
        check_handoff(test_repo)

    assert raised.value.reason_code == "PREREQUISITE_REPOSITORY_NOT_VERIFIED"
    assert "RECEIPT_HASH_MISMATCH" in raised.value.detail


def test_prerequisite_repository_receipt_must_match_current_product_tree(
    test_repo: Path, dummy_server: dict[str, Any]
):
    """A valid receipt for an older product tree cannot authorize a newer handoff."""
    (test_repo / "new.py").write_text("VALUE = 3\n", encoding="utf-8")
    _git(test_repo, "add", "new.py")
    _git(test_repo, "commit", "-m", "advance source after repo verification")

    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )

    with pytest.raises(LocalCheckError) as raised:
        check_handoff(test_repo)

    assert raised.value.reason_code == "PREREQUISITE_REPOSITORY_NOT_VERIFIED"
    assert "REPOSITORY_RECEIPT_STALE" in raised.value.detail


# --- NC-02: Handoff verification against old HEAD does not apply to new HEAD ---

def test_nc02_head_drift_invalidates_handoff_receipt(test_repo: Path, dummy_server: dict[str, Any]):
    """NC-02: Moving HEAD to a new commit stales previous handoff receipt."""
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )
    check_handoff(test_repo)
    assert handoff_status(test_repo)["fresh"] is True

    # Advance HEAD
    (test_repo / "docs.txt").write_text("New doc\n", encoding="utf-8")
    _git(test_repo, "add", "docs.txt")
    _git(test_repo, "commit", "-m", "advance HEAD")

    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"
    assert status["fresh"] is False
    assert "SOURCE_HEAD_CHANGED" in status["reason_codes"]


# --- NC-03: Dirty source after handoff verification must stale handoff claim ---

def test_nc03_dirty_source_stales_handoff_claim(test_repo: Path, dummy_server: dict[str, Any]):
    """NC-03: Uncommitted changes after verification cause handoff status to become stale/blocked."""
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )
    check_handoff(test_repo)
    assert handoff_status(test_repo)["fresh"] is True

    # Dirty the working tree
    (test_repo / "app.py").write_text("VALUE = 999\n", encoding="utf-8")

    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"
    assert status["fresh"] is False
    assert "WORKTREE_DIRTY" in status["reason_codes"]


# --- NC-04: Required service unavailable -> no handoff-ready claim ---

def test_nc04_required_service_unavailable_blocks_handoff(test_repo: Path):
    """NC-04: Service is down or connection refused -> check_handoff fails with RUNTIME_SERVICE_UNREACHABLE."""
    dead_port = _get_free_port()
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": f"http://127.0.0.1:{dead_port}",
                "port": dead_port,
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )

    with pytest.raises(LocalCheckError) as exc_info:
        check_handoff(test_repo)

    assert exc_info.value.reason_code == "RUNTIME_SERVICE_UNREACHABLE"
    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"
    assert status["fresh"] is False


# --- NC-05: Service process identity changed -> fail or stale according to contract ---

def test_nc05_service_process_identity_changed(test_repo: Path, dummy_server: dict[str, Any], tmp_path: Path):
    """NC-05: When process PID / start time changes, handoff receipt becomes stale."""
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )
    check_handoff(test_repo)
    assert handoff_status(test_repo)["fresh"] is True

    # Mutate the PID in pid_file to simulate process restart / PID change
    Path(dummy_server["pid_file"]).write_text("99999\n", encoding="utf-8")

    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"
    assert status["fresh"] is False
    assert "RUNTIME_PROCESS_IDENTITY_CHANGED" in status["reason_codes"]


def test_configured_pid_file_requires_process_identity(
    test_repo: Path, dummy_server: dict[str, Any]
):
    """An explicit pid_file requirement cannot silently degrade to endpoint-only readiness."""
    missing_pid = test_repo / "missing.pid"
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": str(missing_pid),
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )

    with pytest.raises(LocalCheckError) as raised:
        check_handoff(test_repo)

    assert raised.value.reason_code == "RUNTIME_PROCESS_IDENTITY_UNAVAILABLE"
    assert handoff_status(test_repo)["status"] == "BLOCKED"


# --- NC-06: Product-specific verifier assertion fails -> no handoff-ready claim ---

def test_nc06_handoff_verifier_failure_blocks_claim(test_repo: Path, dummy_server: dict[str, Any]):
    """NC-06: Verifier command exiting with non-zero exit code produces HANDOFF_BLOCKED."""
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(1)"],
    )

    with pytest.raises(LocalCheckError) as exc_info:
        check_handoff(test_repo)

    assert exc_info.value.reason_code == "HANDOFF_VERIFIER_FAILED"
    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"
    assert status["fresh"] is False


# --- NC-07: Stale earlier PASS cannot survive later failed attempt ---

def test_nc07_earlier_pass_cannot_survive_later_failure(test_repo: Path, dummy_server: dict[str, Any]):
    """NC-07: Fail-closed rule: An earlier PASS receipt is invalidated by a subsequent failed run."""
    # 1. Successful first run
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )
    first_res = check_handoff(test_repo)
    assert first_res["status"] == "HANDOFF_READY"
    assert handoff_status(test_repo)["fresh"] is True

    # A later failure must supersede the earlier PASS even within the same wall-clock second.
    # 2. Re-initialize with a failing verifier command to simulate later regression
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(1)"],
        force=True,
    )

    with pytest.raises(LocalCheckError):
        check_handoff(test_repo)

    # 3. Read-back: handoff_status MUST report BLOCKED, not the earlier PASS
    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"
    assert status["fresh"] is False
    assert status["receipt_path"] != first_res["receipt_path"]


def test_handoff_config_change_stales_previous_ready_receipt(
    test_repo: Path, dummy_server: dict[str, Any]
):
    """Management config drift cannot reuse an earlier HANDOFF_READY receipt."""
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )
    check_handoff(test_repo)
    assert handoff_status(test_repo)["fresh"] is True

    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "print('different verifier')"],
        force=True,
    )

    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"
    assert "HANDOFF_CONFIG_CHANGED" in status["reason_codes"]


def test_handoff_config_validation_is_strict(test_repo: Path, dummy_server: dict[str, Any]):
    with pytest.raises(LocalCheckError, match="timeout_seconds"):
        init_handoff(
            test_repo,
            handoff_id="web-app",
            services=[
                {
                    "service_id": "web",
                    "endpoint": dummy_server["endpoint"],
                    "port": dummy_server["port"],
                }
            ],
            verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
            timeout_seconds=0,
        )


# --- NC-08: Handoff-ready must not imply merge/release/deploy/production-ready ---

def test_nc08_claim_ceiling_enforces_no_merge_no_deploy(test_repo: Path, dummy_server: dict[str, Any]):
    """NC-08: Receipt claim ceiling explicitly denies merge, deployment, and production claims."""
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[
            {
                "service_id": "web",
                "endpoint": dummy_server["endpoint"],
                "port": dummy_server["port"],
                "pid_file": dummy_server["pid_file"],
            }
        ],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )
    result = check_handoff(test_repo)
    receipt_data = json.loads(result["receipt_path"].read_text(encoding="utf-8"))

    assert receipt_data["claim_ceiling"] == HANDOFF_CLAIM_CEILING
    assert receipt_data["claim_ceiling"] == "MANUAL_TEST_HANDOFF_READY_NOT_RELEASED"
    for non_claim in HANDOFF_NON_CLAIMS:
        assert non_claim in receipt_data["non_claims"]


# --- NC-09: Consumer prose cannot mint handoff readiness ---

def test_nc09_consumer_prose_cannot_mint_readiness(test_repo: Path, tmp_path: Path):
    """NC-09: Unstructured text or fabricated file is rejected by validate_handoff_receipt."""
    fake_receipt = tmp_path / "fake_receipt.json"
    fake_receipt.write_text("I opened localhost:5200 and it looks good!\n", encoding="utf-8")

    validation = validate_handoff_receipt(fake_receipt, repo=test_repo)
    assert validation["valid"] is False
    assert "MALFORMED_RECEIPT" in validation["reason_codes"]


# --- NC-10: Repository verification remains valid even if handoff check is absent/failed ---

def test_nc10_repository_verification_narrow_claim_remains_valid(test_repo: Path):
    """NC-10: Even if handoff readiness fails or is absent, repository receipt remains VERIFIED."""
    repo_receipts_dir = test_repo / ".nexus-core" / "receipts"
    receipts = sorted(repo_receipts_dir.glob("*.json"))
    assert len(receipts) >= 1
    repo_receipt = receipts[-1]

    # Repository receipt validation
    val = validate_verification_receipt(repo_receipt, repo=test_repo)
    assert val["valid"] is True

    # Handoff status is still MISSING, showing independent claim boundaries
    status = handoff_status(test_repo)
    assert status["status"] == "MISSING"


# --- Independent-review regression controls ---

def test_level2_cannot_disable_repository_prerequisite(
    test_repo: Path, dummy_server: dict[str, Any]
):
    """The public CLI must not expose a bypass around Level 1 verification."""
    with pytest.raises(SystemExit):
        main([
            "handoff-init",
            "--repo", str(test_repo),
            "--handoff-id", "web-app",
            "--service", f"web={dummy_server['endpoint']}",
            "--no-prereq",
            "--verifier", sys.executable, "-c", "import sys; sys.exit(0)",
        ])


def test_status_revalidates_current_repository_receipt(
    test_repo: Path, dummy_server: dict[str, Any]
):
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[{
            "service_id": "web",
            "endpoint": dummy_server["endpoint"],
            "port": dummy_server["port"],
            "pid_file": dummy_server["pid_file"],
        }],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )
    ready = check_handoff(test_repo)
    ready_receipt = ready["receipt_path"]

    repo_receipt = sorted((test_repo / ".nexus-core" / "receipts").glob("*.json"))[-1]
    payload = json.loads(repo_receipt.read_text(encoding="utf-8"))
    payload["receipt_hash"] = "sha256:" + "0" * 64
    repo_receipt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"
    assert "PREREQUISITE_REPOSITORY_NOT_VERIFIED" in status["reason_codes"]

    validation = validate_handoff_receipt(ready_receipt, repo=test_repo)
    assert validation["valid"] is False
    assert "PREREQUISITE_REPOSITORY_NOT_VERIFIED" in validation["reason_codes"]


def test_endpoint_without_process_identity_blocks(
    test_repo: Path,
    dummy_server: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(runtime_handoff_module, "_find_pid_for_port", lambda _port: None)
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[{
            "service_id": "web",
            "endpoint": dummy_server["endpoint"],
            "port": dummy_server["port"],
        }],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )

    with pytest.raises(LocalCheckError) as raised:
        check_handoff(test_repo)

    assert raised.value.reason_code == "RUNTIME_PROCESS_IDENTITY_UNAVAILABLE"


def test_pid_file_must_identify_endpoint_owner(
    test_repo: Path, dummy_server: dict[str, Any], tmp_path: Path
):
    wrong_pid_file = tmp_path / "wrong.pid"
    wrong_pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[{
            "service_id": "web",
            "endpoint": dummy_server["endpoint"],
            "port": dummy_server["port"],
            "pid_file": str(wrong_pid_file),
        }],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )

    with pytest.raises(LocalCheckError) as raised:
        check_handoff(test_repo)

    assert raised.value.reason_code == "RUNTIME_PROCESS_ENDPOINT_MISMATCH"


def test_interrupted_attempt_cannot_leave_old_ready_current(
    test_repo: Path,
    dummy_server: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
):
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[{
            "service_id": "web",
            "endpoint": dummy_server["endpoint"],
            "port": dummy_server["port"],
            "pid_file": dummy_server["pid_file"],
        }],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )
    check_handoff(test_repo)
    assert handoff_status(test_repo)["status"] == "HANDOFF_READY"

    def interrupted(_repo: Path) -> dict[str, Any]:
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime_handoff_module, "_load_handoff_config", interrupted)
    with pytest.raises(KeyboardInterrupt):
        check_handoff(test_repo)

    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"
    assert "HANDOFF_CHECK_IN_PROGRESS" in status["reason_codes"]


def test_invalid_config_attempt_supersedes_old_ready_even_after_restore(
    test_repo: Path, dummy_server: dict[str, Any]
):
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[{
            "service_id": "web",
            "endpoint": dummy_server["endpoint"],
            "port": dummy_server["port"],
            "pid_file": dummy_server["pid_file"],
        }],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )
    ready = check_handoff(test_repo)
    config_path = test_repo / ".nexus-core" / "handoff.toml"
    original = config_path.read_text(encoding="utf-8")

    config_path.write_text("not = [valid\n", encoding="utf-8")
    with pytest.raises(LocalCheckError) as raised:
        check_handoff(test_repo)
    assert raised.value.reason_code == "INVALID_HANDOFF_CONFIG"

    config_path.write_text(original, encoding="utf-8")
    status = handoff_status(test_repo)
    assert status["status"] == "BLOCKED"

    validation = validate_handoff_receipt(ready["receipt_path"], repo=test_repo)
    assert validation["valid"] is False
    assert "SUPERSEDED_HANDOFF_RECEIPT" in validation["reason_codes"]


def test_ignored_physical_residue_blocks_handoff(
    test_repo: Path, dummy_server: dict[str, Any]
):
    git_exclude = test_repo / ".git" / "info" / "exclude"
    with git_exclude.open("a", encoding="utf-8") as handle:
        handle.write("\nruntime.cache\n")
    (test_repo / "runtime.cache").write_text("ignored runtime residue\n", encoding="utf-8")

    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[{
            "service_id": "web",
            "endpoint": dummy_server["endpoint"],
            "port": dummy_server["port"],
            "pid_file": dummy_server["pid_file"],
        }],
        verifier_command=[sys.executable, "-c", "import sys; sys.exit(0)"],
    )

    with pytest.raises(LocalCheckError) as raised:
        check_handoff(test_repo)

    assert raised.value.reason_code == "IGNORED_RESIDUE"


def test_verifier_created_ignored_residue_blocks_handoff(
    test_repo: Path, dummy_server: dict[str, Any]
):
    git_exclude = test_repo / ".git" / "info" / "exclude"
    with git_exclude.open("a", encoding="utf-8") as handle:
        handle.write("\nruntime.cache\n")

    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[{
            "service_id": "web",
            "endpoint": dummy_server["endpoint"],
            "port": dummy_server["port"],
            "pid_file": dummy_server["pid_file"],
        }],
        verifier_command=[
            sys.executable,
            "-c",
            "from pathlib import Path; Path('runtime.cache').write_text('created by verifier')",
        ],
    )

    with pytest.raises(LocalCheckError) as raised:
        check_handoff(test_repo)

    assert raised.value.reason_code == "IGNORED_RESIDUE"


def test_verifier_config_mutation_blocks_handoff(
    test_repo: Path, dummy_server: dict[str, Any]
):
    init_handoff(
        test_repo,
        handoff_id="web-app",
        services=[{
            "service_id": "web",
            "endpoint": dummy_server["endpoint"],
            "port": dummy_server["port"],
            "pid_file": dummy_server["pid_file"],
        }],
        verifier_command=[
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "p=Path('.nexus-core/handoff.toml'); "
                "p.write_text(p.read_text().replace('timeout_seconds = 300', "
                "'timeout_seconds = 301'))"
            ),
        ],
    )

    with pytest.raises(LocalCheckError) as raised:
        check_handoff(test_repo)

    assert raised.value.reason_code == "HANDOFF_CONFIG_CHANGED"


# --- CLI Coverage ---

def test_cli_handoff_lifecycle(test_repo: Path, dummy_server: dict[str, Any]):
    """Test CLI commands: handoff-init, handoff-check, handoff-status."""
    repo_str = str(test_repo)

    # 1. handoff-init
    ret = main([
        "handoff-init",
        "--repo", repo_str,
        "--handoff-id", "test-web",
        "--service", f"web={dummy_server['endpoint']}",
        "--verifier", sys.executable, "-c", "import sys; sys.exit(0)",
    ])
    assert ret == 0

    # 2. handoff-check
    ret = main(["handoff-check", "--repo", repo_str])
    assert ret == 0

    # 3. handoff-status
    ret = main(["handoff-status", "--repo", repo_str])
    assert ret == 0
