"""Repository-aware adapter for the extracted TG8 protocol maturity kernel.

The TG8 adjudication logic was extracted byte-for-byte from Nexus-new.  This
module keeps that kernel intact while making repository identity explicit after
the standalone nexus-core cutover:

* current TG8 envelopes and reports bind James3014/nexus-core;
* pre-cutover envelopes remain replayable as historical Nexus-new evidence;
* TG4/TG5/TG6 accepted dependency receipts remain immutable Nexus-new
  provenance and are still validated by the extracted kernel.

No protocol promotion, release, or acceptance authority is added here.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import compatibility_gate_kernel as _kernel
from .compatibility_gate_kernel import *  # noqa: F403

CANONICAL_REPOSITORY = "James3014/nexus-core"
LEGACY_ACCEPTANCE_REPOSITORY = "James3014/Nexus-new"
REPOSITORY_CUTOVER_AT = datetime.fromisoformat("2026-09-05T23:38:18+00:00")

_ORIGINAL_VALIDATE_THRESHOLDS = _kernel._validate_thresholds
_ORIGINAL_ISSUES = _kernel._issues
_ORIGINAL_REPORT = _kernel._report


def _repository_for_observed_at(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if observed.tzinfo is None:
        return None
    return (
        LEGACY_ACCEPTANCE_REPOSITORY
        if observed < REPOSITORY_CUTOVER_AT
        else CANONICAL_REPOSITORY
    )


def _validate_thresholds(value: Mapping[str, Any], sha_file: Path) -> list[str]:
    """Validate TG8 thresholds without rewriting pre-cutover provenance."""

    errors: list[str] = []
    expected_repository = _repository_for_observed_at(value.get("observed_at"))
    if expected_repository is not None and value.get("repository") != expected_repository:
        errors.append("THRESHOLDS:REPOSITORY")

    if not _kernel._hashok(value, "threshold_hash"):
        errors.append("THRESHOLDS:HASH")

    try:
        expected_hash_text = sha_file.read_text(encoding="utf-8")
    except OSError:
        errors.append("THRESHOLDS:EXPECTED_HASH_FILE")
    else:
        claimed = value.get("threshold_hash")
        expected = claimed[7:] + "\n" if isinstance(claimed, str) and claimed.startswith("sha256:") else ""
        if expected_hash_text != expected:
            errors.append("THRESHOLDS:EXPECTED_HASH")

    # The extracted kernel still expects the historical donor repository.  Feed
    # it a normalized view for every non-repository invariant while separately
    # validating the original envelope/hash above.
    normalized = dict(value)
    normalized["repository"] = LEGACY_ACCEPTANCE_REPOSITORY
    normalized.pop("threshold_hash", None)
    normalized["threshold_hash"] = _kernel._digest(normalized)
    kernel_errors = _ORIGINAL_VALIDATE_THRESHOLDS(normalized, sha_file)
    filtered = {
        "THRESHOLDS:REPOSITORY",
        "THRESHOLDS:HASH",
        "THRESHOLDS:EXPECTED_HASH_FILE",
        "THRESHOLDS:EXPECTED_HASH",
    }
    errors.extend(error for error in kernel_errors if error not in filtered)
    return list(dict.fromkeys(errors))


def _issues(value: Mapping[str, Any]) -> list[str]:
    """Require the repository appropriate to the observation timestamp."""

    errors: list[str] = []
    expected_repository = _repository_for_observed_at(value.get("observed_at"))
    if expected_repository is not None and value.get("repository") != expected_repository:
        errors.append("OPEN_ISSUES:SCHEMA")
    if not _kernel._hashok(value, "snapshot_hash"):
        errors.append("OPEN_ISSUES:HASH")

    normalized = dict(value)
    normalized["repository"] = LEGACY_ACCEPTANCE_REPOSITORY
    normalized.pop("snapshot_hash", None)
    normalized["snapshot_hash"] = _kernel._digest(normalized)
    kernel_errors = _ORIGINAL_ISSUES(normalized)
    filtered = {"OPEN_ISSUES:SCHEMA", "OPEN_ISSUES:HASH"}
    errors.extend(error for error in kernel_errors if error not in filtered)
    return list(dict.fromkeys(errors))


def _report(
    path: Path,
    t: Mapping[str, Any] | None,
    hashes: Mapping[str, str],
    state: str,
    reasons: Sequence[str],
    compat: Mapping[str, int],
    conf: Mapping[str, Any],
    up: Mapping[str, Any],
    runs: Sequence[Mapping[str, Any]],
    denominator: int,
    false_count: int,
) -> dict[str, Any]:
    """Emit a canonical nexus-core report while preserving kernel semantics."""

    report = _ORIGINAL_REPORT(
        path,
        t,
        hashes,
        state,
        reasons,
        compat,
        conf,
        up,
        runs,
        denominator,
        false_count,
    )
    report = dict(report)
    report.pop("report_hash", None)
    report["repository"] = CANONICAL_REPOSITORY
    report["report_hash"] = _kernel._digest(report)
    path.write_text(
        _kernel.json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return report


# Patch only the repository-aware seams used by the extracted adjudicator.  All
# substantive compatibility/conformance/upgrade/TG7/stable logic remains in the
# byte-identical kernel blob.
_kernel._validate_thresholds = _validate_thresholds
_kernel._issues = _issues
_kernel._report = _report

adjudicate = _kernel.adjudicate
main = _kernel.main


def __getattr__(name: str) -> Any:
    return getattr(_kernel, name)


if __name__ == "__main__":
    raise SystemExit(main())
