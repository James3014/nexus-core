#!/usr/bin/env python3
"""G2 controlled comparative evidence-value experiment for Nexus Verify.

This harness compares:
A. facts available from ordinary GitHub state alone; and
B. the existing Nexus Verify read-only tool with an optional Nexus receipt.

It is synthetic/controlled benchmark instrumentation. It does not claim
real-user value, public distribution value, or production readiness.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from product.acquisition.github import (  # noqa: E402
    GitHubPullRequestLocator,
    _freshness_cas_for,
)
from product.adapters.generic_verification import verify_generic_changeset  # noqa: E402
from product.clients.local_golden_path import (  # noqa: E402
    check_repository,
    init_repository,
)
from product.clients.nexus_verify import (  # noqa: E402
    CLAIM_CEILING,
    verify_code_change_evidence,
)
from product.protocol.generic_verification import (  # noqa: E402
    acceptance_contract_hash,
    canonical_hash,
    evidence_bundle_hash,
    verification_plan_hash,
)

SCHEMA = "nexus.verify.g2.comparative-evidence.v1"
SUPPORTED_STATE = "NEXUS_VERIFY_INCREMENTAL_EVIDENCE_VALUE_SUPPORTED"
DUPLICATE_STATE = "PLUGIN_VALUE_DUPLICATES_COMMODITY_BASELINE"
INVALID_STATE = "INVALID_G2_EVIDENCE"
MIN_UNIQUE_CASES = 5
DEFAULT_REPETITIONS = 21


@dataclass(frozen=True)
class Scenario:
    case_id: str
    description: str
    receipt: dict[str, Any] | None
    base_sha: str
    head_sha: str
    base_tree: str
    head_tree: str
    changed_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...] = ()
    native_checks_green: bool = True
    pagination_complete: bool = True
    drift_second_read: bool = False
    checks: tuple[tuple[str, str], ...] = (("required/test", "sha256:" + "1" * 64),)
    expected_receipt_integrity: str = "VALID"
    expected_applicability: str = "APPLIES"
    expected_core_verification: str = "VERIFIED"
    expected_accept: bool = True
    expected_unique_value: bool = True
    commodity_overlap: bool = False


class ScenarioPort:
    """Deterministic read-only GitHub port with explicit call accounting."""

    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.read_calls = 0

    def read_pull_request(self, locator: GitHubPullRequestLocator) -> Mapping[str, object]:
        self.read_calls += 1
        head_sha = self.scenario.head_sha
        head_tree = self.scenario.head_tree
        if self.scenario.drift_second_read and self.read_calls % 2 == 0:
            head_sha = "f" * 40
            head_tree = "e" * 40
        diff_bytes = (
            f"synthetic-diff:{self.scenario.case_id}:"
            f"{self.scenario.base_tree}:{head_tree}:"
            f"{','.join(self.scenario.changed_paths)}"
        ).encode("utf-8")
        import hashlib

        diff_hash = "sha256:" + hashlib.sha256(diff_bytes).hexdigest()
        freshness_cas = _freshness_cas_for(
            locator.repository_owner,
            locator.repository_name,
            locator.pr_number,
            self.scenario.base_sha,
            head_sha,
            self.scenario.base_tree,
            head_tree,
            "base_sha_exact",
            diff_hash,
            tuple(sorted(self.scenario.changed_paths)),
            tuple(sorted(self.scenario.deleted_paths)),
            tuple(sorted(self.scenario.checks)),
        )
        return {
            "repository_owner": locator.repository_owner,
            "repository_name": locator.repository_name,
            "pr_number": locator.pr_number,
            "base_sha": self.scenario.base_sha,
            "head_sha": head_sha,
            "base_tree_sha": self.scenario.base_tree,
            "head_tree_sha": head_tree,
            "merge_base_policy": "base_sha_exact",
            "diff_bytes": diff_bytes,
            "diff_hash": diff_hash,
            "changed_paths": list(sorted(self.scenario.changed_paths)),
            "deleted_paths": list(sorted(self.scenario.deleted_paths)),
            "checks": [list(item) for item in sorted(self.scenario.checks)],
            "pagination_complete": self.scenario.pagination_complete,
            "observed_at": "2026-10-01T00:00:00Z",
            "freshness_cas": freshness_cas,
        }


def _git(repo: Path, *args: str) -> str:
    env = os.environ.copy()
    env["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:00Z"
    env["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:00Z"
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _receipt_hash(receipt: Mapping[str, Any]) -> str:
    return canonical_hash({key: value for key, value in receipt.items() if key != "receipt_hash"})


def _read_receipt(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("receipt must be an object")
    return value


def _make_receipts(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Produce an older valid receipt and a current valid receipt from a real temp Git repo."""

    repo = root / "controlled-repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "g2@example.invalid")
    _git(repo, "config", "user.name", "G2 Fixture")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "base")
    _git(repo, "checkout", "-b", "feature")

    init_repository(
        repo,
        base_ref="main",
        allowed_patterns=("*.py",),
        verifier_command=(sys.executable, "-c", "print('verified')"),
    )

    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "feature-one")
    older = _read_receipt(check_repository(repo)["receipt_path"])

    (repo / "app.py").write_text("VALUE = 3\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "feature-two")
    current = _read_receipt(check_repository(repo)["receipt_path"])
    return older, current


def _with_missing_required_verifier(receipt: dict[str, Any]) -> dict[str, Any]:
    """Create an internally valid receipt whose canonical Core result lacks a required verifier."""

    value = copy.deepcopy(receipt)
    request = value["inputs"]["request"]
    contract = request["acceptance_contract"]
    required = sorted(set(contract["required_verifier_ids"]) | {"missing-verifier"})
    contract["required_verifier_ids"] = required

    plan = request["verification_plan"]
    plan["acceptance_contract_hash"] = acceptance_contract_hash(contract)
    plan["required_verifier_ids"] = required

    evidence = request["evidence_bundle"]
    evidence["acceptance_contract_hash"] = plan["acceptance_contract_hash"]
    evidence["verification_plan_hash"] = verification_plan_hash(plan)
    evidence["claimed_bundle_hash"] = None
    evidence["claimed_bundle_hash"] = evidence_bundle_hash(evidence)

    status, response = verify_generic_changeset(request)
    if status != 200:
        raise RuntimeError("controlled missing-verifier request was rejected")
    value["core_response"] = response
    value["outcome"]["status"] = response["verification"]["status"]
    value["outcome"]["reason_codes"] = response["verification"]["reason_codes"]
    value["receipt_hash"] = _receipt_hash(value)
    return value


def _tampered_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(receipt)
    value["outcome"]["status"] = "FAILED_VERIFICATION"
    return value


def _receipt_identity(receipt: Mapping[str, Any]) -> tuple[str, str, str, str, tuple[str, ...]]:
    request = receipt["inputs"]["request"]
    change_set = request["change_set"]
    manifest = request["change_manifest"]
    base_sha = str(receipt["source_revision"]).removeprefix("git-commit:")
    base_tree = str(receipt["source_tree"]).removeprefix("git-tree:")
    head_tree = str(receipt["target_tree"]).removeprefix("git-tree:")
    paths = tuple(sorted(str(path) for path in change_set["paths"]))
    # GitHub head commit SHA is not stored in the local receipt; use a stable synthetic
    # commit identity while binding applicability to the exact target tree.
    head_sha = "b" * 40
    if manifest["target_tree"] != receipt["target_tree"]:
        raise RuntimeError("receipt target-tree binding drift")
    return base_sha, head_sha, base_tree, head_tree, paths


def build_scenarios(older: dict[str, Any], current: dict[str, Any]) -> list[Scenario]:
    base_sha, head_sha, base_tree, head_tree, paths = _receipt_identity(current)
    missing = _with_missing_required_verifier(current)
    tampered = _tampered_receipt(current)

    return [
        Scenario(
            case_id="G2-01-FRESH-EXACT",
            description="exact matching fresh Nexus evidence",
            receipt=current,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=paths,
        ),
        Scenario(
            case_id="G2-02-OLDER-TARGET",
            description="receipt evidence bound to an older target revision",
            receipt=older,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=paths,
            expected_applicability="STALE_TARGET",
            expected_core_verification="VERIFIED",
            expected_accept=False,
        ),
        Scenario(
            case_id="G2-03-HEAD-MOVES-DURING-READ",
            description="PR head moves between independent reads after evidence existed",
            receipt=current,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=paths,
            drift_second_read=True,
            expected_applicability="UNVERIFIABLE",
            expected_core_verification="VERIFIED",
            expected_accept=False,
            expected_unique_value=False,
            commodity_overlap=True,
        ),
        Scenario(
            case_id="G2-04-TAMPERED-RECEIPT",
            description="receipt/evidence was tampered after creation",
            receipt=tampered,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=paths,
            expected_receipt_integrity="INVALID",
            expected_applicability="TAMPERED",
            expected_core_verification="NOT_AVAILABLE",
            expected_accept=False,
        ),
        Scenario(
            case_id="G2-05-REQUIRED-VERIFIER-MISSING",
            description="canonical Core result is missing a required verifier",
            receipt=missing,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=paths,
            expected_applicability="APPLIES",
            expected_core_verification="UNVERIFIABLE",
            expected_accept=False,
        ),
        Scenario(
            case_id="G2-06-SCOPE-MISMATCH",
            description="evidence exists but does not apply to the acquired changed-path scope",
            receipt=current,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=("other.py",),
            expected_applicability="SUBJECT_MISMATCH",
            expected_core_verification="VERIFIED",
            expected_accept=False,
        ),
        Scenario(
            case_id="G2-07-GREEN-CHECKS-NO-RECEIPT",
            description="ordinary GitHub checks are green but no Nexus evidence was supplied",
            receipt=None,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=paths,
            expected_receipt_integrity="ABSENT",
            expected_applicability="EVIDENCE_NOT_SUPPLIED",
            expected_core_verification="NOT_AVAILABLE",
            expected_accept=False,
            expected_unique_value=False,
        ),
        Scenario(
            case_id="G2-08-INCOMPLETE-ACQUISITION",
            description="GitHub acquisition/pagination is incomplete",
            receipt=current,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=paths,
            pagination_complete=False,
            expected_applicability="UNVERIFIABLE",
            expected_core_verification="VERIFIED",
            expected_accept=False,
            expected_unique_value=False,
            commodity_overlap=True,
        ),
        Scenario(
            case_id="G2-09-VALID-EVIDENCE-CHECK-CHURN",
            description="valid exact receipt remains accepted despite unrelated current check churn",
            receipt=current,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=paths,
            checks=(
                ("required/test", "sha256:" + "2" * 64),
                ("advisory/new-check", "sha256:" + "3" * 64),
            ),
        ),
        Scenario(
            case_id="G2-10-GITHUB-NATIVE-SUFFICIENT",
            description="latest-SHA required-check question is already handled by GitHub-native state",
            receipt=None,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree=base_tree,
            head_tree=head_tree,
            changed_paths=paths,
            expected_receipt_integrity="ABSENT",
            expected_applicability="EVIDENCE_NOT_SUPPLIED",
            expected_core_verification="NOT_AVAILABLE",
            expected_accept=False,
            expected_unique_value=False,
            commodity_overlap=True,
        ),
    ]


def _baseline_once(scenario: Scenario) -> tuple[dict[str, Any], int]:
    """Strong commodity baseline: two GitHub reads, but no Nexus receipt semantics."""

    port = ScenarioPort(scenario)
    locator = GitHubPullRequestLocator("example", "demo", 7)
    first = dict(port.read_pull_request(locator))
    second = dict(port.read_pull_request(locator))

    if not first.get("pagination_complete") or not second.get("pagination_complete"):
        return (
            {
                "state": "UNVERIFIABLE_INCOMPLETE_GITHUB_EVIDENCE",
                "can_assess_nexus_receipt": False,
                "current_head_sha": second["head_sha"],
                "current_head_tree": second["head_tree_sha"],
                "required_checks_green": scenario.native_checks_green,
            },
            port.read_calls,
        )

    identity_fields = (
        "base_sha",
        "head_sha",
        "base_tree_sha",
        "head_tree_sha",
        "diff_hash",
        "changed_paths",
        "deleted_paths",
        "checks",
        "freshness_cas",
    )
    if any(first[field] != second[field] for field in identity_fields):
        return (
            {
                "state": "UNVERIFIABLE_GITHUB_SUBJECT_DRIFT",
                "can_assess_nexus_receipt": False,
                "current_head_sha": second["head_sha"],
                "current_head_tree": second["head_tree_sha"],
                "required_checks_green": scenario.native_checks_green,
            },
            port.read_calls,
        )

    return (
        {
            "state": (
                "GITHUB_REQUIRED_CHECKS_GREEN"
                if scenario.native_checks_green
                else "GITHUB_REQUIRED_CHECKS_NOT_GREEN"
            ),
            "can_assess_nexus_receipt": False,
            "current_head_sha": second["head_sha"],
            "current_head_tree": second["head_tree_sha"],
            "required_checks_green": scenario.native_checks_green,
        },
        port.read_calls,
    )


def _assisted_once(scenario: Scenario) -> tuple[dict[str, Any], int]:
    port = ScenarioPort(scenario)
    result = verify_code_change_evidence(
        {
            "repository_owner": "example",
            "repository_name": "demo",
            "pr_number": 7,
            "receipt": scenario.receipt,
        },
        github_port=port,
    )
    return result, port.read_calls


def _timed_median_ns(fn, repetitions: int) -> int:
    values: list[int] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        fn()
        values.append(time.perf_counter_ns() - started)
    return int(statistics.median(values))


def evaluate_case(scenario: Scenario, repetitions: int) -> dict[str, Any]:
    baseline, baseline_calls = _baseline_once(scenario)
    assisted, assisted_calls = _assisted_once(scenario)

    accepted = (
        assisted["receipt_integrity"] == "VALID"
        and assisted["evidence_applicability"] == "APPLIES"
        and assisted["core_verification"] == "VERIFIED"
    )
    false_green = bool(accepted and not scenario.expected_accept)
    false_block = bool(scenario.expected_accept and not accepted)

    expected_match = (
        assisted["receipt_integrity"] == scenario.expected_receipt_integrity
        and assisted["evidence_applicability"] == scenario.expected_applicability
        and assisted["core_verification"] == scenario.expected_core_verification
        and accepted == scenario.expected_accept
    )

    claim_ceiling_ok = assisted["claim_ceiling"] == list(CLAIM_CEILING)
    unique_value = bool(scenario.expected_unique_value and expected_match)
    overlap = bool(scenario.commodity_overlap and not scenario.expected_unique_value)

    return {
        "case_id": scenario.case_id,
        "description": scenario.description,
        "baseline": baseline,
        "assisted": assisted,
        "expected": {
            "receipt_integrity": scenario.expected_receipt_integrity,
            "evidence_applicability": scenario.expected_applicability,
            "core_verification": scenario.expected_core_verification,
            "accept": scenario.expected_accept,
            "unique_value": scenario.expected_unique_value,
            "commodity_overlap": scenario.commodity_overlap,
        },
        "observed": {
            "accept": accepted,
            "unique_value": unique_value,
            "commodity_overlap": overlap,
            "false_green": false_green,
            "false_block": false_block,
            "expected_match": expected_match,
            "claim_ceiling_ok": claim_ceiling_ok,
        },
        "cost": {
            "baseline_logical_github_reads": baseline_calls,
            "assisted_logical_github_reads": assisted_calls,
            "baseline_median_ns": _timed_median_ns(
                lambda: _baseline_once(scenario), repetitions
            ),
            "assisted_median_ns": _timed_median_ns(
                lambda: _assisted_once(scenario), repetitions
            ),
        },
    }


def run_experiment(*, repetitions: int = DEFAULT_REPETITIONS) -> dict[str, Any]:
    if type(repetitions) is not int or repetitions < 3 or repetitions > 1000:
        raise ValueError("repetitions must be an int from 3 through 1000")

    with tempfile.TemporaryDirectory(prefix="nexus-verify-g2-") as tmp:
        older, current = _make_receipts(Path(tmp))
        cases = [evaluate_case(case, repetitions) for case in build_scenarios(older, current)]

    false_green = sum(row["observed"]["false_green"] for row in cases)
    false_block = sum(row["observed"]["false_block"] for row in cases)
    mismatches = [row["case_id"] for row in cases if not row["observed"]["expected_match"]]
    claim_ceiling_violations = [
        row["case_id"] for row in cases if not row["observed"]["claim_ceiling_ok"]
    ]
    unique_cases = [row["case_id"] for row in cases if row["observed"]["unique_value"]]
    overlap_cases = [row["case_id"] for row in cases if row["observed"]["commodity_overlap"]]
    positive_controls = [
        row["case_id"]
        for row in cases
        if row["expected"]["accept"] and row["observed"]["accept"]
    ]

    supported = (
        not mismatches
        and false_green == 0
        and false_block == 0
        and not claim_ceiling_violations
        and len(unique_cases) >= MIN_UNIQUE_CASES
        and len(positive_controls) >= 2
    )
    state = SUPPORTED_STATE if supported else DUPLICATE_STATE
    decision_basis = {
        "state": SUPPORTED_STATE if supported else DUPLICATE_STATE,
        "summary": {
            "unique_value_cases": unique_cases,
            "commodity_overlap_cases": overlap_cases,
            "false_green_count": false_green,
            "false_block_count": false_block,
            "expected_mismatch_cases": mismatches,
            "claim_ceiling_violations": claim_ceiling_violations,
            "positive_controls_accepted": positive_controls,
        },
        "cases": [
            {
                "case_id": row["case_id"],
                "baseline_state": row["baseline"]["state"],
                "assisted_receipt_integrity": row["assisted"]["receipt_integrity"],
                "assisted_applicability": row["assisted"]["evidence_applicability"],
                "assisted_core_verification": row["assisted"]["core_verification"],
                "expected": row["expected"],
                "observed": row["observed"],
            }
            for row in cases
        ],
    }
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "synthetic_controlled": True,
        "state": state,
        "claim_ceiling": "CONTROLLED_COMPARATIVE_EVIDENCE_ONLY",
        "repetitions_per_arm": repetitions,
        "thresholds": {
            "min_unique_cases": MIN_UNIQUE_CASES,
            "max_false_green": 0,
            "max_false_block": 0,
            "min_positive_controls": 2,
        },
        "summary": {
            "case_count": len(cases),
            "unique_value_case_count": len(unique_cases),
            "unique_value_cases": unique_cases,
            "commodity_overlap_case_count": len(overlap_cases),
            "commodity_overlap_cases": overlap_cases,
            "false_green_count": false_green,
            "false_block_count": false_block,
            "expected_mismatch_cases": mismatches,
            "claim_ceiling_violations": claim_ceiling_violations,
            "positive_controls_accepted": positive_controls,
            "baseline_subject_reads_per_case": 2,
            "assisted_subject_reads_per_case": 2,
            "baseline_case_median_ns": int(
                statistics.median(row["cost"]["baseline_median_ns"] for row in cases)
            ),
            "assisted_case_median_ns": int(
                statistics.median(row["cost"]["assisted_median_ns"] for row in cases)
            ),
            "manual_interpretation_required": False,
        },
        "cases": cases,
        "decision_hash": canonical_hash(decision_basis),
        "limitations": [
            "controlled synthetic fixtures do not establish real-user value",
            "nanosecond timings are local harness timings, not public-network latency",
            "logical GitHub read counts are adapter reads, not raw REST-request counts",
            "G3 conversation/tool-selection behavior is intentionally out of scope",
            "G4 public endpoint/OAuth/review readiness is intentionally out of scope",
        ],
    }
    report["report_hash"] = canonical_hash(report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    report = run_experiment(repetitions=args.repetitions)
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.report:
        Path(args.report).write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0 if report["state"] == SUPPORTED_STATE else 2


if __name__ == "__main__":
    raise SystemExit(main())
