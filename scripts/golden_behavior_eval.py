"""Run the Nexus Core Golden Behavior Corpus as a repeatable eval suite.

The corpus lives in ``tests/golden_behavior/corpus.py``.  Each covered case binds
an expected behavior to its authority sources (contract docs, product source,
GitHub Issues) and to existing pytest node ids that witness it.  Findings
(``status="finding"``) document known gaps and carry no witnesses.

Usage (from the repository root)::

    uv run python scripts/golden_behavior_eval.py
    uv run python scripts/golden_behavior_eval.py --json-report /tmp/golden.json
    uv run python scripts/golden_behavior_eval.py --validate-only --include-findings
    uv run python scripts/golden_behavior_eval.py --scenario stale_state
    uv run python scripts/golden_behavior_eval.py --classification security
    uv run python scripts/golden_behavior_eval.py --case NCG-014 --case NCG-020

Steps:

1. Structural validation of the whole corpus (ids, taxonomy, statuses, finding
   ids, witness shape, local authority paths and ``#heading`` anchors).
2. Collect-only check: every selected witness node id must collect.  A node id
   without a ``[param]`` suffix covers all of its parametrizations.
3. Execution of the selected witnesses in one pytest run with ``--junitxml``;
   each node passes only if every collected item for it passed (skips fail).

Exit code is 0 only when validation, collection and execution all succeed; any
error, uncollectable node, failure or skip exits 1.  ``--json-report`` writes a
machine-readable report with source revision, tree, workspace dirtiness and the
corpus SHA-256.  Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CORPUS_PATH = ROOT / "tests" / "golden_behavior" / "corpus.py"

CLASSIFICATIONS = {"invariant", "regression", "compatibility", "security"}
SCENARIOS = {
    "normal",
    "boundary",
    "failure",
    "authority_conflict",
    "partial_state",
    "recovery",
    "idempotency",
    "malformed_input",
    "stale_state",
}
STATUSES = {"covered", "finding"}
CASE_ID = re.compile(r"^NCG-\d{3}$")
FINDING_ID = re.compile(r"^NCGF-\d{3}$")
NODE_ID = re.compile(r"^tests/[\w/]+\.py(::[A-Za-z_]\w*)+(\[.+\])?$")


def load_corpus() -> tuple[tuple[Any, ...], dict[str, str]]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    module = importlib.import_module("tests.golden_behavior.corpus")
    return module.CASES, module.FINDINGS


def _headings(path: Path) -> set[str]:
    found = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#{1,6}\s+(.*?)\s*$", line)
        if match:
            found.add(match.group(1))
    return found


def _authority_errors(case_id: str, source: str) -> list[str]:
    if source.startswith("https://"):
        return []
    path_part, _, anchor = source.partition("#")
    path = ROOT / path_part
    if not path_part or not path.is_file():
        return [f"{case_id}: authority path does not exist: {source}"]
    if anchor and path.suffix == ".md" and anchor not in _headings(path):
        return [f"{case_id}: authority heading not found: {source}"]
    return []


def validate_corpus(cases: tuple[Any, ...], findings: dict[str, str]) -> list[str]:
    """Return structural errors in the corpus (empty list means valid)."""
    errors: list[str] = []
    seen: set[str] = set()
    used_findings: list[str] = []
    for case in cases:
        cid = case.case_id
        if not CASE_ID.match(cid):
            errors.append(f"{cid}: malformed case id")
        if cid in seen:
            errors.append(f"{cid}: duplicate case id")
        seen.add(cid)
        if case.classification not in CLASSIFICATIONS:
            errors.append(f"{cid}: unknown classification {case.classification!r}")
        if case.scenario not in SCENARIOS:
            errors.append(f"{cid}: unknown scenario {case.scenario!r}")
        if case.status not in STATUSES:
            errors.append(f"{cid}: unknown status {case.status!r}")
        if not case.title.strip() or not case.expected_behavior.strip():
            errors.append(f"{cid}: missing title or expected behavior")
        if not case.authority_sources:
            errors.append(f"{cid}: missing authority sources")
        for source in case.authority_sources:
            errors.extend(_authority_errors(cid, source))
        if len(set(case.automated_tests)) != len(case.automated_tests):
            errors.append(f"{cid}: duplicate witness node id")
        for nodeid in case.automated_tests:
            if not NODE_ID.match(nodeid):
                errors.append(f"{cid}: malformed node id {nodeid!r}")
            elif not (ROOT / nodeid.split("::", 1)[0]).is_file():
                errors.append(f"{cid}: witness file does not exist: {nodeid}")
        if case.status == "covered":
            if not case.automated_tests:
                errors.append(f"{cid}: covered case has no witness node ids")
            if case.finding_id is not None:
                errors.append(f"{cid}: covered case carries a finding id")
        elif case.status == "finding":
            if case.automated_tests:
                errors.append(f"{cid}: finding must not claim witness node ids")
            if case.finding_id is None or not FINDING_ID.match(case.finding_id):
                errors.append(f"{cid}: finding has malformed finding id {case.finding_id!r}")
            else:
                used_findings.append(case.finding_id)
    if len(set(used_findings)) != len(used_findings):
        errors.append("duplicate finding id across cases")
    if set(used_findings) != set(findings):
        errors.append(
            f"finding ids {sorted(set(used_findings))} do not match FINDINGS {sorted(findings)}"
        )
    return errors


def _git(*args: str) -> str | None:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def _provenance() -> dict[str, Any]:
    status = _git("status", "--porcelain")
    return {
        "source_revision": _git("rev-parse", "HEAD"),
        "source_tree": _git("rev-parse", "HEAD^{tree}"),
        "workspace_dirty": None if status is None else bool(status),
        "corpus_path": str(CORPUS_PATH.relative_to(ROOT)),
        "corpus_sha256": hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest(),
    }


def _pytest(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _matches(nodeid: str, item: str) -> bool:
    return item == nodeid or (item.startswith(nodeid + "[") and "[" not in nodeid)


def collect(nodeids: list[str]) -> tuple[dict[str, list[str]], str]:
    """Map each node id to its collected items (empty list = uncollectable)."""
    files = sorted({nodeid.split("::", 1)[0] for nodeid in nodeids})
    completed = _pytest(["--collect-only", *files])
    items = [line.strip() for line in completed.stdout.splitlines() if "::" in line]
    result = {nodeid: [item for item in items if _matches(nodeid, item)] for nodeid in nodeids}
    return result, completed.stdout[-1500:] + completed.stderr[-1500:]


def _junit_nodeid(row: ET.Element) -> str:
    classname = row.attrib.get("classname", "")
    parts = classname.split(".")
    # Module path parts end at the first component whose .py file exists.
    for index in range(len(parts), 0, -1):
        candidate = "/".join(parts[:index]) + ".py"
        if (ROOT / candidate).is_file():
            return "::".join([candidate, *parts[index:], row.attrib.get("name", "")])
    return f"{classname}::{row.attrib.get('name', '')}"


def execute(nodeids: list[str]) -> tuple[dict[str, str], int, str]:
    """Run node ids once; return item id -> passed/failed/error/skipped."""
    with tempfile.TemporaryDirectory(prefix="nexus-core-golden-") as tmp:
        junit = Path(tmp) / "junit.xml"
        completed = _pytest([f"--junitxml={junit}", *nodeids])
        outcomes: dict[str, str] = {}
        if junit.exists():
            for row in ET.parse(junit).getroot().iter("testcase"):
                if row.find("failure") is not None:
                    status = "failed"
                elif row.find("error") is not None:
                    status = "error"
                elif row.find("skipped") is not None:
                    status = "skipped"
                else:
                    status = "passed"
                outcomes[_junit_nodeid(row)] = status
    return outcomes, completed.returncode, completed.stdout[-3000:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Nexus Core Golden Behavior Corpus.")
    parser.add_argument("--classification", choices=sorted(CLASSIFICATIONS))
    parser.add_argument("--scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--case", action="append", default=[], help="case id (repeatable)")
    parser.add_argument("--include-findings", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--json-report", type=Path)
    args = parser.parse_args(argv)

    cases, findings = load_corpus()
    errors = validate_corpus(cases, findings)
    known = {case.case_id for case in cases}
    errors.extend(f"unknown --case {cid}" for cid in args.case if cid not in known)

    selected = [
        case
        for case in cases
        if (args.classification is None or case.classification == args.classification)
        and (args.scenario is None or case.scenario == args.scenario)
        and (not args.case or case.case_id in args.case)
        and (args.include_findings or case.status == "covered")
    ]
    nodeids = sorted({n for case in selected for n in case.automated_tests})

    collected: dict[str, list[str]] = {}
    outcomes: dict[str, str] = {}
    pytest_exit: int | None = None
    detail = ""
    if not args.validate_only and not errors and nodeids:
        collected, detail = collect(nodeids)
        uncollectable = [n for n, items in collected.items() if not items]
        errors.extend(f"uncollectable node id: {n}" for n in uncollectable)
        if not uncollectable:
            outcomes, pytest_exit, detail = execute(nodeids)

    node_rows: dict[str, dict[str, Any]] = {}
    for nodeid in nodeids:
        items = collected.get(nodeid, [])
        item_status = {item: outcomes.get(item, "not_run") for item in items}
        if args.validate_only:
            status = "not_run"
        elif not items:
            status = "uncollectable" if collected else "not_run"
        elif all(s == "passed" for s in item_status.values()):
            status = "passed"
        else:
            status = "failed"
        node_rows[nodeid] = {"status": status, "items": item_status}

    case_rows = []
    for case in selected:
        if case.status == "finding":
            result = "finding"
        elif args.validate_only:
            result = "not_run"
        else:
            states = {node_rows[n]["status"] for n in case.automated_tests}
            result = "passed" if states == {"passed"} else "failed"
        case_rows.append(
            {
                "case_id": case.case_id,
                "title": case.title,
                "classification": case.classification,
                "scenario": case.scenario,
                "status": case.status,
                "finding_id": case.finding_id,
                "result": result,
                "authority_sources": list(case.authority_sources),
                "witnesses": {n: node_rows[n]["status"] for n in case.automated_tests},
            }
        )

    failed_nodes = [n for n, row in node_rows.items() if row["status"] not in {"passed", "not_run"}]
    if not args.validate_only and not errors and pytest_exit not in (None, 0) and not failed_nodes:
        errors.append(f"pytest exited {pytest_exit} without an attributable failure")
    ok = not errors and not failed_nodes
    items_total = sum(len(row["items"]) for row in node_rows.values())
    items_passed = sum(
        1 for row in node_rows.values() for s in row["items"].values() if s == "passed"
    )
    summary = {
        "cases_total": len(cases),
        "cases_selected": len(selected),
        "cases_passed": sum(1 for row in case_rows if row["result"] == "passed"),
        "cases_failed": sum(1 for row in case_rows if row["result"] == "failed"),
        "findings_selected": sum(1 for row in case_rows if row["result"] == "finding"),
        "nodes_selected": len(nodeids),
        "nodes_passed": sum(1 for row in node_rows.values() if row["status"] == "passed"),
        "items_executed": items_total,
        "items_passed": items_passed,
    }
    report = {
        "schema": "nexus-core.golden-behavior-eval.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **_provenance(),
        "filters": {
            "classification": args.classification,
            "scenario": args.scenario,
            "case": args.case,
            "include_findings": args.include_findings,
            "validate_only": args.validate_only,
        },
        "summary": summary,
        "errors": errors,
        "pytest_exit_code": pytest_exit,
        "cases": case_rows,
        "findings": {fid: text for fid, text in findings.items() if args.include_findings},
        "nodes": node_rows,
        "exit_code": 0 if ok else 1,
    }
    if not ok and detail:
        report["pytest_output_tail"] = detail
    if args.json_report:
        args.json_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    for error in errors:
        print(f"ERROR: {error}")
    for nodeid in failed_nodes:
        print(f"FAILED: {nodeid} ({node_rows[nodeid]['status']})")
    print(
        "golden-behavior: {verdict} cases={cases_selected}/{cases_total} "
        "passed={cases_passed} failed={cases_failed} findings={findings_selected} "
        "nodes={nodes_passed}/{nodes_selected} items={items_passed}/{items_executed}".format(
            verdict="OK" if ok else "FAIL", **summary
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
