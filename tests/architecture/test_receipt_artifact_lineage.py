"""Issue #142: the receipt verifier must consume the exact producing attempt's artifact.

A rerun of the same workflow run (new ``github.run_attempt``) keeps the artifacts of
earlier attempts. When the artifact name was bound only to the PR head sha, attempt 1's
(bad) and attempt 2's (good) receipt artifacts shared one name and the verifier
downloaded the old one (live: Nexus-new run 37999579750, artifacts 11648224599 and
11647544876).

These tests execute the real ``run:`` scripts of the composite actions with the step
``env:`` expressions evaluated against a simulated GitHub context, and resolve the
artifact against a fake GitHub REST API that retains every attempt's artifacts.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ISSUE_GATE = REPO_ROOT / ".github" / "actions" / "issue-gate" / "action.yml"
RECEIPT_VERIFY = REPO_ROOT / ".github" / "actions" / "receipt-verify" / "action.yml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "nexus-core-issue-completion.yml"

REPOSITORY = "James3014/Nexus-new"
RUN_ID = 37999579750
HEAD = "1" * 40
BASE = "2" * 40
OTHER_HEAD = "3" * 40
# Live ids from the incident. The stale attempt-1 artifact has the HIGHER id and is
# given the NEWER timestamp, so any "newest wins" heuristic selects the wrong one.
BAD_ATTEMPT1_ID = 11648224599
GOOD_ATTEMPT2_ID = 11647544876


# --------------------------------------------------------------------------- YAML steps


def _load_steps(path: Path) -> list[dict[str, Any]]:
    """Parse the ``runs.steps`` list of a composite action (fixed indentation layout)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    start = lines.index("  steps:") + 1
    steps: list[dict[str, Any]] = []
    step: dict[str, Any] | None = None
    block: str | None = None
    run_lines: list[str] = []

    def close_run() -> None:
        nonlocal run_lines
        if step is not None and block == "run":
            while run_lines and not run_lines[-1].strip():
                run_lines.pop()
            step["run"] = "\n".join(run_lines) + "\n"
        run_lines = []

    for line in lines[start:]:
        if line.startswith("    - "):
            close_run()
            step = {"env": {}, "with": {}}
            steps.append(step)
            block = None
            line = "      " + line[6:]
        assert step is not None
        if block == "run" and (not line.strip() or line.startswith("        ")):
            run_lines.append(line[8:])
            continue
        if line.strip().startswith("#"):
            continue
        if line.startswith("      ") and not line.startswith("       "):
            close_run()
            key, _, value = line.strip().partition(":")
            value = value.strip()
            if key in ("env", "with"):
                block = key
            elif key == "run":
                assert value == "|", f"unsupported run style in {path}"
                block = "run"
            else:
                block = None
                step[key] = value
        elif block in ("env", "with") and line.startswith("        "):
            key, _, value = line.strip().partition(":")
            step[block][key] = value.strip().strip('"')
        elif line.strip():
            raise AssertionError(f"unparsed line in {path}: {line!r}")
    close_run()
    return steps


def _step(path: Path, step_id: str) -> dict[str, Any]:
    matches = [step for step in _load_steps(path) if step.get("id") == step_id]
    assert len(matches) == 1, f"{path.name}: expected exactly one step with id {step_id!r}"
    return matches[0]


_EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


def _evaluate(value: str, context: dict[str, Any]) -> str:
    def lookup(match: re.Match[str]) -> str:
        expression = match.group(1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*", expression):
            raise AssertionError(f"unsupported expression in test harness: {expression!r}")
        node: Any = context
        for part in expression.split("."):
            node = node[part]
        return str(node)

    return _EXPRESSION.sub(lookup, value)


@dataclass
class StepResult:
    returncode: int
    outputs: dict[str, str]
    stderr: str


def _run_step(step: dict[str, Any], context: dict[str, Any], tmp_path: Path) -> StepResult:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    python3 = bindir / "python3"
    if not python3.exists():
        python3.symlink_to(sys.executable)
    output_file = tmp_path / "github_output"
    output_file.write_text("", encoding="utf-8")
    env = {
        "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
        "GITHUB_OUTPUT": str(output_file),
    }
    env.update({key: _evaluate(value, context) for key, value in step["env"].items()})
    result = subprocess.run(
        ["bash", "-c", step["run"]], env=env, capture_output=True, text=True, timeout=60
    )
    outputs: dict[str, str] = {}
    for line in output_file.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        outputs[key] = value
    return StepResult(result.returncode, outputs, result.stderr + result.stdout)


# ------------------------------------------------------------------- fake artifact store


@dataclass
class Artifact:
    id: int
    name: str
    run_id: int
    created_at: str
    expired: bool = False


@dataclass
class ArtifactStore:
    """Every attempt's artifacts of one repository, as GitHub retains them across reruns."""

    artifacts: list[Artifact] = field(default_factory=list)
    override: dict[str, Any] | None = None
    requests: list[dict[str, str]] = field(default_factory=list)

    def upload(self, artifact: Artifact) -> None:
        self.artifacts.append(artifact)

    def by_name(self, name: str) -> list[Artifact]:
        return [artifact for artifact in self.artifacts if artifact.name == name]


@pytest.fixture
def store() -> Iterator[tuple[ArtifactStore, str]]:
    state = ArtifactStore()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # pragma: no cover - silence
            return

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            url = urlsplit(self.path)
            query = {key: values[0] for key, values in parse_qs(url.query).items()}
            state.requests.append(
                {"path": url.path, "auth": self.headers.get("Authorization", ""), **query}
            )
            match = re.fullmatch(r"/repos/([^/]+/[^/]+)/actions/runs/(\d+)/artifacts", url.path)
            if not match or match.group(1) != REPOSITORY:
                self.send_response(404)
                self.end_headers()
                return
            run_id = int(match.group(2))
            selected = [
                artifact
                for artifact in state.artifacts
                if artifact.run_id == run_id
                and ("name" not in query or artifact.name == query["name"])
            ]
            payload = state.override or {
                "total_count": len(selected),
                "artifacts": [
                    {
                        "id": artifact.id,
                        "name": artifact.name,
                        "expired": artifact.expired,
                        "created_at": artifact.created_at,
                        "workflow_run": {"id": artifact.run_id},
                    }
                    for artifact in selected
                ],
            }
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


# ------------------------------------------------------------------------ GitHub model


def _github(api_url: str, *, run_attempt: int, head: str = HEAD) -> dict[str, Any]:
    return {
        "github": {
            "run_id": str(RUN_ID),
            "run_attempt": str(run_attempt),
            "repository": REPOSITORY,
            "api_url": api_url,
            "server_url": "https://github.com",
            "token": "ghs_test_token",
            "event": {"pull_request": {"head": {"sha": head}, "base": {"sha": BASE}}},
        },
        "runner": {"temp": "/tmp/runner"},
    }


def _produce(
    tmp_path: Path, api_url: str, state: ArtifactStore, *, attempt: int, artifact_id: int,
    created_at: str,
) -> dict[str, str]:
    """Run issue-gate's naming step for one attempt and 'upload' under the produced name."""
    naming = _step(ISSUE_GATE, "names")
    result = _run_step(naming, _github(api_url, run_attempt=attempt), tmp_path)
    assert result.returncode == 0, result.stderr
    name = result.outputs["artifact-name"]
    state.upload(Artifact(artifact_id, name, RUN_ID, created_at))
    return {"artifact-name": name, "artifact-id": str(artifact_id)}


def _consume(
    tmp_path: Path, api_url: str, *, run_attempt: int, producer: dict[str, str],
    head: str = HEAD,
) -> tuple[StepResult, StepResult | None]:
    """Run receipt-verify's validation + artifact resolution with the producer's outputs."""
    context = _github(api_url, run_attempt=run_attempt, head=head)
    context["inputs"] = {
        "artifact-name": producer.get("artifact-name", ""),
        "artifact-id": producer.get("artifact-id", ""),
        "expected-identity": (
            "https://github.com/James3014/Nexus-new/.github/workflows/"
            "nexus-core-issue-completion.yml@refs/heads/main"
        ),
        "github-repository": REPOSITORY,
        "head-sha": head,
        "base-sha": BASE,
        "issue-number": "7",
        "nexus-certify-source": "ref",
        "nexus-certify-ref": "4" * 40,
        "nexus-certify-path": "",
        "python-version": "3.11",
        "sigstore-version": "4.5.0",
    }
    validated = _run_step(_step(RECEIPT_VERIFY, "validate"), context, tmp_path)
    if validated.returncode != 0:
        return validated, None
    return validated, _run_step(_step(RECEIPT_VERIFY, "artifact"), context, tmp_path)


def _retained_attempts(tmp_path: Path, api_url: str, state: ArtifactStore):
    attempt1 = _produce(
        tmp_path, api_url, state, attempt=1, artifact_id=BAD_ATTEMPT1_ID,
        created_at="2026-10-09T10:05:00Z",
    )
    attempt2 = _produce(
        tmp_path, api_url, state, attempt=2, artifact_id=GOOD_ATTEMPT2_ID,
        created_at="2026-10-09T10:00:00Z",
    )
    return attempt1, attempt2


def _downloaded(state: ArtifactStore, resolved: StepResult) -> Artifact:
    """What the download step fetches: it downloads by the resolved, unique name."""
    candidates = state.by_name(resolved.outputs["artifact-name"])
    assert len(candidates) == 1, "download-by-name would be ambiguous"
    assert str(candidates[0].id) == resolved.outputs["artifact-id"]
    return candidates[0]


# ------------------------------------------------------------------------------- tests


def test_rerun_attempts_produce_distinct_artifact_identities(tmp_path, store):
    state, api_url = store
    attempt1, attempt2 = _retained_attempts(tmp_path, api_url, state)

    assert attempt1["artifact-name"] != attempt2["artifact-name"]
    assert len(state.by_name(attempt1["artifact-name"])) == 1
    assert len(state.by_name(attempt2["artifact-name"])) == 1


def test_consumer_selects_attempt2_when_attempt1_and_attempt2_are_retained(tmp_path, store):
    state, api_url = store
    _, attempt2 = _retained_attempts(tmp_path, api_url, state)

    validated, resolved = _consume(tmp_path, api_url, run_attempt=2, producer=attempt2)

    assert validated.returncode == 0, validated.stderr
    assert resolved is not None and resolved.returncode == 0, resolved and resolved.stderr
    assert _downloaded(state, resolved).id == GOOD_ATTEMPT2_ID
    assert state.requests[-1]["auth"] == "Bearer ghs_test_token"
    assert state.requests[-1]["path"] == f"/repos/{REPOSITORY}/actions/runs/{RUN_ID}/artifacts"


def test_consumer_selects_by_name_without_optional_artifact_id(tmp_path, store):
    state, api_url = store
    _, attempt2 = _retained_attempts(tmp_path, api_url, state)

    producer = {"artifact-name": attempt2["artifact-name"]}
    validated, resolved = _consume(tmp_path, api_url, run_attempt=2, producer=producer)

    assert validated.returncode == 0, validated.stderr
    assert resolved is not None and resolved.returncode == 0, resolved and resolved.stderr
    assert _downloaded(state, resolved).id == GOOD_ATTEMPT2_ID


@pytest.mark.parametrize(
    ("producer_attempt", "expected_id"),
    [(2, GOOD_ATTEMPT2_ID), (1, BAD_ATTEMPT1_ID)],
)
def test_verifier_only_rerun_reads_the_producer_attempt(
    tmp_path, store, producer_attempt, expected_id
):
    # "Re-run failed jobs" re-runs only 'verify' as attempt 3; 'needs.run.outputs' are
    # the producing attempt's outputs. The verifier must read exactly that producer's
    # artifact and never guess from the current attempt or the newest artifact.
    state, api_url = store
    attempt1, attempt2 = _retained_attempts(tmp_path, api_url, state)
    producer = attempt2 if producer_attempt == 2 else attempt1

    validated, resolved = _consume(tmp_path, api_url, run_attempt=3, producer=producer)

    assert validated.returncode == 0, validated.stderr
    assert resolved is not None and resolved.returncode == 0, resolved and resolved.stderr
    assert _downloaded(state, resolved).id == expected_id


def _legacy_name(head: str = HEAD) -> str:
    return f"nexus-core-receipts-{head}"


@pytest.mark.parametrize(
    "artifact_name",
    [
        "",
        _legacy_name(),  # head-only: ambiguous across attempts
        f"{_legacy_name()}-run{RUN_ID}",
        f"{_legacy_name()}-run{RUN_ID}-attempt",
        f"{_legacy_name()}-run{RUN_ID}-attempt0",
        f"{_legacy_name()}-run{RUN_ID}-attempt01",
        f"{_legacy_name()}-run{RUN_ID}-attempt3",  # attempt after the current one
        f"{_legacy_name()}-run{RUN_ID + 1}-attempt1",  # another workflow run
        f"{_legacy_name(OTHER_HEAD)}-run{RUN_ID}-attempt1",  # another head
        f"{_legacy_name()}-run{RUN_ID}-attempt1-x",
    ],
)
def test_invalid_artifact_identity_fails_closed_before_any_lookup(
    tmp_path, store, artifact_name
):
    state, api_url = store
    _retained_attempts(tmp_path, api_url, state)

    validated, resolved = _consume(
        tmp_path, api_url, run_attempt=2, producer={"artifact-name": artifact_name}
    )

    assert validated.returncode != 0
    assert resolved is None
    assert "NEXUS_CORE_VERIFY" in validated.stderr
    assert state.requests == []


@pytest.mark.parametrize("artifact_id", ["0", "-1", "abc", "1e3", " 11647544876"])
def test_malformed_artifact_id_fails_closed(tmp_path, store, artifact_id):
    state, api_url = store
    _, attempt2 = _retained_attempts(tmp_path, api_url, state)

    producer = {"artifact-name": attempt2["artifact-name"], "artifact-id": artifact_id}
    validated, resolved = _consume(tmp_path, api_url, run_attempt=2, producer=producer)

    assert validated.returncode != 0
    assert resolved is None


def test_artifact_id_from_another_attempt_fails_closed(tmp_path, store):
    state, api_url = store
    _, attempt2 = _retained_attempts(tmp_path, api_url, state)

    producer = {"artifact-name": attempt2["artifact-name"], "artifact-id": str(BAD_ATTEMPT1_ID)}
    validated, resolved = _consume(tmp_path, api_url, run_attempt=2, producer=producer)

    assert validated.returncode == 0, validated.stderr
    assert resolved is not None and resolved.returncode != 0
    assert "NEXUS_CORE_VERIFY_ARTIFACT_ID_MISMATCH" in resolved.stderr
    assert "artifact-id" not in resolved.outputs


def test_ambiguous_artifact_identity_fails_closed(tmp_path, store):
    state, api_url = store
    _, attempt2 = _retained_attempts(tmp_path, api_url, state)
    state.upload(Artifact(99, attempt2["artifact-name"], RUN_ID, "2026-10-09T11:00:00Z"))

    validated, resolved = _consume(tmp_path, api_url, run_attempt=2, producer=attempt2)

    assert validated.returncode == 0, validated.stderr
    assert resolved is not None and resolved.returncode != 0
    assert "NEXUS_CORE_VERIFY_ARTIFACT_AMBIGUOUS" in resolved.stderr
    assert "artifact-id" not in resolved.outputs


def test_missing_producer_artifact_fails_closed(tmp_path, store):
    state, api_url = store
    _produce(
        tmp_path, api_url, state, attempt=1, artifact_id=BAD_ATTEMPT1_ID,
        created_at="2026-10-09T10:05:00Z",
    )
    # Attempt 2's name is well-formed but nothing was uploaded under it: never fall
    # back to attempt 1.
    name = state.artifacts[0].name.replace("-attempt1", "-attempt2")

    validated, resolved = _consume(
        tmp_path, api_url, run_attempt=2, producer={"artifact-name": name}
    )

    assert validated.returncode == 0, validated.stderr
    assert resolved is not None and resolved.returncode != 0
    assert "NEXUS_CORE_VERIFY_ARTIFACT_MISSING" in resolved.stderr


def test_expired_producer_artifact_fails_closed(tmp_path, store):
    state, api_url = store
    _, attempt2 = _retained_attempts(tmp_path, api_url, state)
    state.artifacts[1].expired = True

    validated, resolved = _consume(tmp_path, api_url, run_attempt=2, producer=attempt2)

    assert resolved is not None and resolved.returncode != 0
    assert "NEXUS_CORE_VERIFY_ARTIFACT_EXPIRED" in resolved.stderr


@pytest.mark.parametrize(
    "override",
    [
        {"total_count": 2, "artifacts": []},  # truncated page
        {"artifacts": []},  # no total_count
        {"total_count": "1", "artifacts": [{}]},
        {
            "total_count": 1,
            "artifacts": [
                {"id": True, "name": "x", "expired": False, "workflow_run": {"id": RUN_ID}}
            ],
        },
        "not-an-object",
    ],
)
def test_malformed_api_response_fails_closed(tmp_path, store, override):
    state, api_url = store
    _, attempt2 = _retained_attempts(tmp_path, api_url, state)
    state.override = override  # type: ignore[assignment]

    validated, resolved = _consume(tmp_path, api_url, run_attempt=2, producer=attempt2)

    assert resolved is not None and resolved.returncode != 0
    assert "artifact-id" not in resolved.outputs


def test_api_response_for_another_run_or_name_fails_closed(tmp_path, store):
    state, api_url = store
    _, attempt2 = _retained_attempts(tmp_path, api_url, state)
    for wrong in (
        {"id": GOOD_ATTEMPT2_ID, "name": attempt2["artifact-name"], "expired": False,
         "workflow_run": {"id": RUN_ID + 1}},
        {"id": GOOD_ATTEMPT2_ID, "name": "other", "expired": False,
         "workflow_run": {"id": RUN_ID}},
    ):
        state.override = {"total_count": 1, "artifacts": [wrong]}
        validated, resolved = _consume(tmp_path, api_url, run_attempt=2, producer=attempt2)
        assert resolved is not None and resolved.returncode != 0, wrong


@pytest.mark.parametrize("bad", [("run_id", "0"), ("run_id", ""), ("run_attempt", "x")])
def test_producer_naming_fails_closed_on_invalid_run_identity(tmp_path, store, bad):
    _, api_url = store
    context = _github(api_url, run_attempt=1)
    context["github"][bad[0]] = bad[1]

    result = _run_step(_step(ISSUE_GATE, "names"), context, tmp_path)

    assert result.returncode != 0
    assert "artifact-name" not in result.outputs


def test_download_uses_only_the_resolved_identity_after_resolution():
    steps = _load_steps(RECEIPT_VERIFY)
    ids = [step.get("id") for step in steps]
    downloads = [step for step in steps if step.get("uses", "").startswith("actions/download-artifact@")]
    assert len(downloads) == 1
    download = downloads[0]
    assert ids.index("validate") < ids.index("artifact") < steps.index(download)
    assert download["with"] == {
        "name": "${{ steps.artifact.outputs.artifact-name }}",
        "path": "${{ runner.temp }}/nexus-core-receipt-artifact",
    }


def test_upload_is_skipped_without_a_valid_attempt_bound_name():
    steps = _load_steps(ISSUE_GATE)
    uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
    assert len(uploads) == 1
    assert uploads[0]["with"]["name"] == "${{ steps.names.outputs.artifact-name }}"
    assert uploads[0]["if"] == "always() && steps.names.outcome == 'success'"


def test_core_workflow_passes_producer_artifact_identity_to_verifier():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "artifact-id: ${{ steps.gate.outputs.artifact-id }}" in text
    assert "artifact-id: ${{ needs.run.outputs.artifact-id }}" in text
    assert "artifact-name: ${{ needs.run.outputs.artifact-name }}" in text
