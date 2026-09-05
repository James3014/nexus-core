"""TG-9 paired usability/value evidence verifier.

This module is measurement and adjudication tooling only. It does not contact
design partners, present consent, authenticate commercial signals, promote a
protocol, or create public/commercial truth. Real evidence remains
controller-owned; worker-safe execution is limited to synthetic fixtures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

STUDY_SCHEMA = "nexus.core-v1.tg9-study.v1"
ELIGIBILITY_SCHEMA = "nexus.core-v1.tg9-eligibility.v1"
CONSENT_SCHEMA = "nexus.core-v1.tg9-consent.v1"
OBSERVATION_SCHEMA = "nexus.core-v1.tg9-observation.v1"
TRUST_SCHEMA = "nexus.core-v1.tg9-trust.v1"
SIGNAL_SCHEMA = "nexus.core-v1.tg9-signal.v1"
PRIVACY_SCAN_SCHEMA = "nexus.core-v1.tg9-privacy-scan.v1"
REPORT_SCHEMA = "nexus.core-v1.tg9-report.v1"

SYNTHETIC_STATE = "SYNTHETIC_ONLY"
VALUE_READY_STATE = "PAIRED_USABILITY_VALUE_EVIDENCE_READY"
ALLOWED_STATES = frozenset({
    VALUE_READY_STATE,
    SYNTHETIC_STATE,
    "MISSING_EVIDENCE",
    "INVALID_EVIDENCE",
    "UNVERIFIABLE",
})
CLAIM_CEILING = "BOUNDED_PAIRED_USABILITY_VALUE_EVIDENCE"
ASSIGNMENT_SEED = "20260904"
BOOTSTRAP_SEED = 20260904
BOOTSTRAP_REPLICATES = 10_000
MIN_PARTNERS = 3
MAX_PARTNERS = 5
MIN_PAIRS_PER_PARTNER = 8
MIN_TOTAL_PAIRS = 24
MIN_WEEKS = 4
MAX_WEEKS = 8
MIN_IMPROVEMENT = 0.30
MIN_POSITIVE_FRACTION = 0.70
MIN_WASHOUT_MS = 24 * 60 * 60 * 1000

TRUST_OUTCOMES = ("CORRECT", "FALSE_ACCEPT", "FALSE_REJECT", "UNRESOLVED")
SIGNAL_TYPES = frozenset({
    "SIGNED_PILOT_CONTINUATION",
    "SIGNED_LOI_ORDER",
    "PAID_INVOICE_PROCESSOR_RECEIPT",
    "RENEWAL",
})
CLOSED_EXCLUSIONS = frozenset({
    "CONSENT_WITHDRAWAL",
    "CORRUPTED_TIMING_BEFORE_OUTCOME",
    "PROTOCOL_RUNTIME_DRIFT_BEFORE_PAIR",
    "MISSING_BLINDED_ORACLE",
    "PRIVACY_INVALIDATION",
})
FORBIDDEN_KEY_FRAGMENTS = (
    "real_name",
    "full_name",
    "email",
    "organization_name",
    "company_name",
    "account_id",
    "account_number",
    "private_url",
    "repository_url",
    "raw_code",
    "raw_repository",
    "ip_address",
    "device_id",
    "free_text",
    "notes",
    "pepper",
    "lookup",
)
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
URL_RE = re.compile(r"(?i)\bhttps?://")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PSEUDONYM_RE = re.compile(r"^p_[0-9a-f]{16,64}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _canonical(value: Any) -> str:
    """Return deterministic JSON for the bounded evidence vocabulary."""

    def encode(item: Any) -> Any:
        if item is None or type(item) in (bool, int, str):
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError("non-finite float")
            return item
        if isinstance(item, Mapping):
            if any(type(key) is not str for key in item):
                raise TypeError("mapping keys must be strings")
            return {key: encode(item[key]) for key in sorted(item)}
        if isinstance(item, (list, tuple)):
            return [encode(entry) for entry in item]
        raise TypeError(type(item).__name__)

    return json.dumps(
        encode(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _hash_valid(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _git_sha(value: Any) -> bool:
    return isinstance(value, str) and GIT_SHA_RE.fullmatch(value) is not None


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        return None
    return result


def _strict_hash(
    value: Mapping[str, Any],
    hash_key: str,
    required: frozenset[str],
    *,
    schema_key: str = "schema",
    schema_value: str | None = None,
) -> list[str]:
    errors: list[str] = []
    keys = set(value)
    if keys != required:
        missing = sorted(required - keys)
        extra = sorted(keys - required)
        if missing:
            errors.append(f"MISSING_KEYS:{','.join(missing)}")
        if extra:
            errors.append(f"UNKNOWN_KEYS:{','.join(extra)}")
        return errors
    if schema_value is not None and value.get(schema_key) != schema_value:
        errors.append(f"BAD_SCHEMA:{schema_value}")
    body = {key: value[key] for key in value if key != hash_key}
    if value.get(hash_key) != _digest(body):
        errors.append(f"BAD_HASH:{hash_key}")
    return errors


def assignment_for(study_id: str, partner_id: str, pair_id: str) -> str:
    payload = f"{study_id}|{partner_id}|{pair_id}|{ASSIGNMENT_SEED}".encode()
    low_bit = hashlib.sha256(payload).digest()[-1] & 1
    return "AB" if low_bit == 0 else "BA"


STUDY_KEYS = frozenset({
    "schema",
    "study_id",
    "synthetic",
    "tg8_receipt_hash",
    "source_commit",
    "source_tree",
    "protocol_version",
    "runtime_hash",
    "package_hash",
    "package_version",
    "study_start_at",
    "study_end_at",
    "analysis_at",
    "narrow_icp_code",
    "assignment_seed",
    "bootstrap_seed",
    "bootstrap_replicates",
    "min_partners",
    "max_partners",
    "min_pairs_per_partner",
    "min_total_pairs",
    "min_weeks",
    "max_weeks",
    "min_improvement",
    "min_positive_fraction",
    "oracle_rubric_hash",
    "consent_version",
    "retention_policy_code",
    "withdrawal_channel_code",
    "manifest_hash",
})
ELIGIBILITY_KEYS = frozenset({
    "schema",
    "study_id",
    "partners",
    "reserve_order",
    "selected_at",
    "eligibility_hash",
})
PARTNER_KEYS = frozenset({
    "partner_id",
    "eligibility_state",
    "role_class",
    "organization_size_bucket",
    "workflow_class",
    "inclusion_reason_code",
    "exclusion_reason_code",
    "slot_number",
    "reserve_rank",
    "eligibility_receipt_hash",
})
CONSENT_KEYS = frozenset({"schema", "study_id", "receipts", "consent_hash"})
CONSENT_RECEIPT_KEYS = frozenset({
    "partner_id",
    "consent_version",
    "status",
    "scope_code",
    "consented_at",
    "data_classes",
    "retention_policy_code",
    "withdrawal_channel_code",
    "issuer_authority_hash",
    "external_verification_receipt_hash",
    "receipt_hash",
})
OBSERVATION_KEYS = frozenset({
    "schema",
    "study_id",
    "partner_id",
    "pair_id",
    "assignment",
    "baseline_task_id",
    "assisted_task_id",
    "difficulty_hash",
    "source_commit",
    "protocol_version",
    "runtime_hash",
    "package_hash",
    "baseline_human_ms",
    "nexus_human_ms",
    "nexus_read_followup_ms",
    "washout_ms",
    "baseline_outcome",
    "assisted_outcome",
    "high_risk_error",
    "oracle_receipt_hash",
    "attempt_ids",
    "excluded",
    "exclusion_reason",
    "observed_at",
    "observation_hash",
})
TRUST_KEYS = frozenset({
    "schema",
    "study_id",
    "oracle_rubric_hash",
    "all_assigned_pairs",
    "baseline_counts",
    "assisted_counts",
    "partner_high_risk_errors",
    "trust_hash",
})
SIGNAL_KEYS = frozenset({
    "schema",
    "study_id",
    "partner_id",
    "type",
    "issuer_authority_hash",
    "observed_at",
    "issued_at",
    "expires_at",
    "revoked",
    "algorithm",
    "signature_hash",
    "signed_payload_hash",
    "external_verification_receipt_schema",
    "external_verification_receipt_hash",
    "verified",
    "signal_hash",
})


def validate_manifest(manifest: Mapping[str, Any]) -> list[str]:
    errors = _strict_hash(manifest, "manifest_hash", STUDY_KEYS, schema_value=STUDY_SCHEMA)
    if errors:
        return errors
    if not isinstance(manifest["study_id"], str) or not manifest["study_id"]:
        errors.append("INVALID_STUDY_ID")
    if type(manifest["synthetic"]) is not bool:
        errors.append("INVALID_SYNTHETIC_FLAG")
    if not _hash_valid(manifest["tg8_receipt_hash"]):
        errors.append("INVALID_TG8_RECEIPT_HASH")
    if not _git_sha(manifest["source_commit"]) or not _git_sha(manifest["source_tree"]):
        errors.append("INVALID_SOURCE_IDENTITY")
    for key in ("runtime_hash", "package_hash", "oracle_rubric_hash"):
        if not _hash_valid(manifest[key]):
            errors.append(f"INVALID_HASH:{key}")
    if manifest["assignment_seed"] != ASSIGNMENT_SEED:
        errors.append("ASSIGNMENT_SEED_DRIFT")
    if manifest["bootstrap_seed"] != BOOTSTRAP_SEED:
        errors.append("BOOTSTRAP_SEED_DRIFT")
    if manifest["bootstrap_replicates"] != BOOTSTRAP_REPLICATES:
        errors.append("BOOTSTRAP_REPLICATES_DRIFT")
    expected_thresholds = {
        "min_partners": MIN_PARTNERS,
        "max_partners": MAX_PARTNERS,
        "min_pairs_per_partner": MIN_PAIRS_PER_PARTNER,
        "min_total_pairs": MIN_TOTAL_PAIRS,
        "min_weeks": MIN_WEEKS,
        "max_weeks": MAX_WEEKS,
        "min_improvement": MIN_IMPROVEMENT,
        "min_positive_fraction": MIN_POSITIVE_FRACTION,
    }
    for key, expected in expected_thresholds.items():
        if manifest[key] != expected:
            errors.append(f"THRESHOLD_DRIFT:{key}")
    start = _timestamp(manifest["study_start_at"])
    end = _timestamp(manifest["study_end_at"])
    analysis = _timestamp(manifest["analysis_at"])
    if start is None or end is None or analysis is None:
        errors.append("INVALID_STUDY_TIMESTAMP")
    elif not start < end <= analysis:
        errors.append("INVALID_STUDY_WINDOW")
    return errors


def validate_eligibility(eligibility: Mapping[str, Any], manifest: Mapping[str, Any]) -> list[str]:
    errors = _strict_hash(
        eligibility, "eligibility_hash", ELIGIBILITY_KEYS, schema_value=ELIGIBILITY_SCHEMA
    )
    if errors:
        return errors
    if eligibility["study_id"] != manifest["study_id"]:
        errors.append("ELIGIBILITY_STUDY_MISMATCH")
    if _timestamp(eligibility["selected_at"]) is None:
        errors.append("INVALID_SELECTION_TIMESTAMP")
    partners = eligibility["partners"]
    if not isinstance(partners, list):
        return errors + ["PARTNERS_NOT_LIST"]
    ids: set[str] = set()
    enrolled = 0
    for row in partners:
        if not isinstance(row, Mapping) or set(row) != PARTNER_KEYS:
            errors.append("INVALID_PARTNER_ROW")
            continue
        partner_id = row["partner_id"]
        if not isinstance(partner_id, str) or PSEUDONYM_RE.fullmatch(partner_id) is None:
            errors.append("INVALID_PARTNER_PSEUDONYM")
        elif partner_id in ids:
            errors.append("DUPLICATE_PARTNER")
        else:
            ids.add(partner_id)
        if row["eligibility_state"] not in {"ENROLLED", "RESERVE", "EXCLUDED"}:
            errors.append("INVALID_ELIGIBILITY_STATE")
        if row["eligibility_state"] == "ENROLLED":
            enrolled += 1
            if row["slot_number"] is None:
                errors.append("ENROLLED_SLOT_REQUIRED")
        if not _hash_valid(row["eligibility_receipt_hash"]):
            errors.append("INVALID_ELIGIBILITY_RECEIPT")
        if row["exclusion_reason_code"] is not None and not isinstance(
            row["exclusion_reason_code"], str
        ):
            errors.append("INVALID_EXCLUSION_REASON")
    if not MIN_PARTNERS <= enrolled <= MAX_PARTNERS:
        errors.append("COHORT_SIZE_OUT_OF_RANGE")
    reserve = eligibility["reserve_order"]
    if not isinstance(reserve, list) or any(item not in ids for item in reserve):
        errors.append("INVALID_RESERVE_ORDER")
    return errors


def validate_consent(
    consent: Mapping[str, Any], manifest: Mapping[str, Any], eligibility: Mapping[str, Any]
) -> list[str]:
    errors = _strict_hash(consent, "consent_hash", CONSENT_KEYS, schema_value=CONSENT_SCHEMA)
    if errors:
        return errors
    if consent["study_id"] != manifest["study_id"]:
        errors.append("CONSENT_STUDY_MISMATCH")
    partner_rows = {
        row["partner_id"]: row
        for row in eligibility["partners"]
        if isinstance(row, Mapping) and row.get("eligibility_state") == "ENROLLED"
    }
    receipts = consent["receipts"]
    if not isinstance(receipts, list):
        return errors + ["CONSENT_RECEIPTS_NOT_LIST"]
    seen: set[str] = set()
    for row in receipts:
        if not isinstance(row, Mapping) or set(row) != CONSENT_RECEIPT_KEYS:
            errors.append("INVALID_CONSENT_ROW")
            continue
        partner_id = row["partner_id"]
        if partner_id not in partner_rows:
            errors.append("CONSENT_FOR_NON_ENROLLED_PARTNER")
        if partner_id in seen:
            errors.append("DUPLICATE_CONSENT")
        seen.add(partner_id)
        body = {key: row[key] for key in row if key != "receipt_hash"}
        if row["receipt_hash"] != _digest(body):
            errors.append("BAD_CONSENT_RECEIPT_HASH")
        if row["consent_version"] != manifest["consent_version"]:
            errors.append("CONSENT_VERSION_DRIFT")
        if row["status"] not in {"CONSENTED", "WITHDRAWN"}:
            errors.append("INVALID_CONSENT_STATUS")
        if row["status"] != "CONSENTED":
            errors.append("WITHDRAWN_PARTNER")
        if row["retention_policy_code"] != manifest["retention_policy_code"]:
            errors.append("RETENTION_POLICY_DRIFT")
        if row["withdrawal_channel_code"] != manifest["withdrawal_channel_code"]:
            errors.append("WITHDRAWAL_CHANNEL_DRIFT")
        if _timestamp(row["consented_at"]) is None:
            errors.append("INVALID_CONSENT_TIMESTAMP")
        if not isinstance(row["data_classes"], list) or not row["data_classes"]:
            errors.append("INVALID_CONSENT_DATA_CLASSES")
        if not _hash_valid(row["issuer_authority_hash"]) or not _hash_valid(
            row["external_verification_receipt_hash"]
        ):
            errors.append("UNVERIFIED_CONSENT_AUTHORITY")
    if set(partner_rows) - seen:
        errors.append("MISSING_CONSENT")
    return errors


def validate_observation(row: Mapping[str, Any], manifest: Mapping[str, Any]) -> list[str]:
    errors = _strict_hash(
        row, "observation_hash", OBSERVATION_KEYS, schema_value=OBSERVATION_SCHEMA
    )
    if errors:
        return errors
    if row["study_id"] != manifest["study_id"]:
        errors.append("OBSERVATION_STUDY_MISMATCH")
    if PSEUDONYM_RE.fullmatch(str(row["partner_id"])) is None:
        errors.append("INVALID_PARTNER_PSEUDONYM")
    expected_assignment = assignment_for(manifest["study_id"], row["partner_id"], row["pair_id"])
    if row["assignment"] != expected_assignment:
        errors.append("ASSIGNMENT_MISMATCH")
    if row["baseline_task_id"] == row["assisted_task_id"]:
        errors.append("TASKS_NOT_DISTINCT")
    if not _hash_valid(row["difficulty_hash"]):
        errors.append("INVALID_DIFFICULTY_HASH")
    for key in ("source_commit", "protocol_version", "runtime_hash", "package_hash"):
        if row[key] != manifest[key]:
            errors.append(f"REVISION_DRIFT:{key}")
    for key in ("baseline_human_ms", "nexus_human_ms", "nexus_read_followup_ms"):
        value = row[key]
        if type(value) is not int or value < 0:
            errors.append(f"INVALID_TIMING:{key}")
    if row["baseline_human_ms"] <= 0:
        errors.append("BASELINE_TIME_MUST_BE_POSITIVE")
    if type(row["washout_ms"]) is not int or row["washout_ms"] < MIN_WASHOUT_MS:
        errors.append("WASHOUT_TOO_SHORT")
    if row["baseline_outcome"] not in TRUST_OUTCOMES:
        errors.append("INVALID_BASELINE_OUTCOME")
    if row["assisted_outcome"] not in TRUST_OUTCOMES:
        errors.append("INVALID_ASSISTED_OUTCOME")
    if type(row["high_risk_error"]) is not bool:
        errors.append("INVALID_HIGH_RISK_FLAG")
    if not _hash_valid(row["oracle_receipt_hash"]):
        errors.append("INVALID_ORACLE_RECEIPT")
    if (
        not isinstance(row["attempt_ids"], list)
        or len(row["attempt_ids"]) != 2
        or len(set(row["attempt_ids"])) != 2
        or any(not isinstance(item, str) or not item for item in row["attempt_ids"])
    ):
        errors.append("INVALID_ATTEMPT_IDENTITIES")
    if type(row["excluded"]) is not bool:
        errors.append("INVALID_EXCLUDED_FLAG")
    if row["excluded"]:
        if row["exclusion_reason"] not in CLOSED_EXCLUSIONS:
            errors.append("OPEN_ENDED_EXCLUSION")
    elif row["exclusion_reason"] is not None:
        errors.append("UNEXPECTED_EXCLUSION_REASON")
    if _timestamp(row["observed_at"]) is None:
        errors.append("INVALID_OBSERVATION_TIMESTAMP")
    return errors


def _counts(rows: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    result = {outcome: 0 for outcome in TRUST_OUTCOMES}
    for row in rows:
        result[row[key]] += 1
    return result


def validate_trust(
    trust: Mapping[str, Any], manifest: Mapping[str, Any], observations: Sequence[Mapping[str, Any]]
) -> tuple[list[str], dict[str, int], dict[str, int]]:
    errors = _strict_hash(trust, "trust_hash", TRUST_KEYS, schema_value=TRUST_SCHEMA)
    if errors:
        return errors, {}, {}
    if trust["study_id"] != manifest["study_id"]:
        errors.append("TRUST_STUDY_MISMATCH")
    if trust["oracle_rubric_hash"] != manifest["oracle_rubric_hash"]:
        errors.append("ORACLE_RUBRIC_DRIFT")
    assigned = [row for row in observations if not row["excluded"]]
    baseline = _counts(assigned, "baseline_outcome")
    assisted = _counts(assigned, "assisted_outcome")
    if trust["all_assigned_pairs"] != len(assigned):
        errors.append("TRUST_DENOMINATOR_MISMATCH")
    if trust["baseline_counts"] != baseline:
        errors.append("BASELINE_TRUST_COUNTS_MISMATCH")
    if trust["assisted_counts"] != assisted:
        errors.append("ASSISTED_TRUST_COUNTS_MISMATCH")
    high_risk = sorted({row["partner_id"] for row in assigned if row["high_risk_error"]})
    if trust["partner_high_risk_errors"] != high_risk:
        errors.append("HIGH_RISK_PARTNER_MISMATCH")
    return errors, baseline, assisted


def validate_signal(
    signal: Mapping[str, Any], manifest: Mapping[str, Any], eligible_partner_ids: set[str]
) -> list[str]:
    errors = _strict_hash(signal, "signal_hash", SIGNAL_KEYS, schema_value=SIGNAL_SCHEMA)
    if errors:
        return errors
    if signal["study_id"] != manifest["study_id"]:
        errors.append("SIGNAL_STUDY_MISMATCH")
    if signal["partner_id"] not in eligible_partner_ids:
        errors.append("SIGNAL_PARTNER_NOT_ELIGIBLE")
    if signal["type"] not in SIGNAL_TYPES:
        errors.append("INVALID_SIGNAL_TYPE")
    if signal["algorithm"] != "Ed25519":
        errors.append("INVALID_SIGNAL_ALGORITHM")
    if signal["revoked"] is not False:
        errors.append("SIGNAL_REVOKED")
    if signal["verified"] is not True:
        errors.append("SIGNAL_NOT_EXTERNALLY_VERIFIED")
    for key in (
        "issuer_authority_hash",
        "signature_hash",
        "signed_payload_hash",
        "external_verification_receipt_hash",
    ):
        if not _hash_valid(signal[key]):
            errors.append(f"INVALID_SIGNAL_HASH:{key}")
    observed = _timestamp(signal["observed_at"])
    issued = _timestamp(signal["issued_at"])
    expires = _timestamp(signal["expires_at"])
    start = _timestamp(manifest["study_start_at"])
    end = _timestamp(manifest["study_end_at"])
    if None in (observed, issued, expires, start, end):
        errors.append("INVALID_SIGNAL_TIMESTAMP")
    else:
        assert observed is not None and issued is not None and expires is not None
        assert start is not None and end is not None
        if not start <= issued <= observed <= end:
            errors.append("SIGNAL_OUTSIDE_STUDY_WINDOW")
        if observed >= expires:
            errors.append("SIGNAL_EXPIRED")
    return errors


def _privacy_walk(value: Any, path: str, findings: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = key.lower()
            if any(fragment in lowered for fragment in FORBIDDEN_KEY_FRAGMENTS):
                findings.append(f"FORBIDDEN_KEY:{path}/{key}")
            _privacy_walk(item, f"{path}/{key}", findings)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _privacy_walk(item, f"{path}/{index}", findings)
    elif isinstance(value, str):
        if EMAIL_RE.search(value):
            findings.append(f"EMAIL_VALUE:{path}")
        if URL_RE.search(value):
            findings.append(f"URL_VALUE:{path}")
        if IPV4_RE.search(value):
            findings.append(f"IP_VALUE:{path}")


def privacy_findings(values: Iterable[Any]) -> list[str]:
    findings: list[str] = []
    for index, value in enumerate(values):
        _privacy_walk(value, f"${index}", findings)
    return sorted(set(findings))


def scan_privacy_root(root: Path) -> dict[str, Any]:
    root = root.resolve()
    findings: list[str] = []
    scanned: list[dict[str, str]] = []
    if not root.is_dir():
        findings.append("ROOT_MISSING")
    else:
        mode = root.stat().st_mode & 0o777
        if mode & 0o077:
            findings.append("ROOT_PERMISSIONS_TOO_BROAD")
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            file_mode = path.stat().st_mode & 0o777
            if file_mode & 0o077:
                findings.append(f"FILE_PERMISSIONS_TOO_BROAD:{path.name}")
            if path.suffix not in {".json", ".jsonl"}:
                findings.append(f"UNEXPECTED_FILE_TYPE:{path.name}")
                continue
            scanned.append({
                "path": path.relative_to(root).as_posix(),
                "sha256": _file_digest(path),
            })
            try:
                if path.suffix == ".json":
                    values = [json.loads(path.read_text(encoding="utf-8"))]
                else:
                    values = [
                        json.loads(line)
                        for line in path.read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    ]
            except (OSError, json.JSONDecodeError):
                findings.append(f"UNREADABLE_JSON:{path.name}")
                continue
            findings.extend(privacy_findings(values))
    body = {
        "schema": PRIVACY_SCAN_SCHEMA,
        "root_class": "CONTROLLER_OWNED_STUDY_ROOT",
        "scanned_files": scanned,
        "finding_count": len(set(findings)),
        "findings": sorted(set(findings)),
        "status": "PASS" if not findings else "FAIL",
    }
    return {**body, "scan_hash": _digest(body)}


def _percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise ValueError("empty percentile")
    ordered = sorted(values)
    index = probability * (len(ordered) - 1)
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def bootstrap_interval(partner_medians: Sequence[float]) -> tuple[float, float]:
    if not partner_medians:
        raise ValueError("no partner medians")
    rng = random.Random(BOOTSTRAP_SEED)
    draws: list[float] = []
    count = len(partner_medians)
    for _ in range(BOOTSTRAP_REPLICATES):
        sample = [partner_medians[rng.randrange(count)] for _ in range(count)]
        draws.append(float(statistics.median(sample)))
    return _percentile(draws, 0.025), _percentile(draws, 0.975)


def _error_state(errors: Sequence[str]) -> str:
    missing_markers = ("MISSING_", "COHORT_", "DURATION_", "PAIR_DENOMINATOR_", "SIGNAL_")
    if errors and all(error.startswith(missing_markers) for error in errors):
        return "MISSING_EVIDENCE"
    return "INVALID_EVIDENCE"


def _minimal_report(
    manifest: Mapping[str, Any], state: str, reasons: Sequence[str]
) -> dict[str, Any]:
    if state not in ALLOWED_STATES:
        raise ValueError(state)
    body = {
        "schema": REPORT_SCHEMA,
        "study_id": str(manifest.get("study_id", "unknown")),
        "synthetic": bool(manifest.get("synthetic", False)),
        "state": state,
        "reasons": sorted(set(reasons)),
        "claim_ceiling": CLAIM_CEILING,
        "generated_at": str(manifest.get("analysis_at", "unknown")),
    }
    return {**body, "report_hash": _digest(body)}


def adjudicate(
    manifest: Mapping[str, Any],
    eligibility: Mapping[str, Any],
    consent: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
    trust: Mapping[str, Any],
    signal: Mapping[str, Any],
) -> dict[str, Any]:
    errors = validate_manifest(manifest)
    if errors:
        return _minimal_report(manifest, "INVALID_EVIDENCE", errors)
    errors = validate_eligibility(eligibility, manifest)
    if errors:
        return _minimal_report(manifest, "INVALID_EVIDENCE", errors)
    errors = validate_consent(consent, manifest, eligibility)
    if errors:
        return _minimal_report(manifest, "INVALID_EVIDENCE", errors)

    if not isinstance(observations, Sequence) or isinstance(observations, (str, bytes)):
        return _minimal_report(manifest, "INVALID_EVIDENCE", ["OBSERVATIONS_NOT_SEQUENCE"])
    observation_errors: list[str] = []
    seen_pairs: set[tuple[str, str]] = set()
    seen_attempts: set[str] = set()
    enrolled = {
        row["partner_id"]
        for row in eligibility["partners"]
        if row["eligibility_state"] == "ENROLLED"
    }
    for index, row in enumerate(observations):
        if not isinstance(row, Mapping):
            observation_errors.append(f"OBSERVATION_{index}:NOT_OBJECT")
            continue
        observation_errors.extend(
            f"OBSERVATION_{index}:{error}" for error in validate_observation(row, manifest)
        )
        identity = (str(row.get("partner_id")), str(row.get("pair_id")))
        if identity in seen_pairs:
            observation_errors.append(f"OBSERVATION_{index}:DUPLICATE_PAIR")
        seen_pairs.add(identity)
        if row.get("partner_id") not in enrolled:
            observation_errors.append(f"OBSERVATION_{index}:NON_ENROLLED_PARTNER")
        attempts = row.get("attempt_ids", [])
        if isinstance(attempts, list):
            for attempt in attempts:
                if attempt in seen_attempts:
                    observation_errors.append(f"OBSERVATION_{index}:DUPLICATE_ATTEMPT")
                if isinstance(attempt, str):
                    seen_attempts.add(attempt)
    if observation_errors:
        return _minimal_report(manifest, "INVALID_EVIDENCE", observation_errors)

    privacy = privacy_findings([manifest, eligibility, consent, observations, trust, signal])
    if privacy:
        return _minimal_report(
            manifest, "INVALID_EVIDENCE", [f"PRIVACY:{finding}" for finding in privacy]
        )

    trust_errors, baseline_counts, assisted_counts = validate_trust(trust, manifest, observations)
    if trust_errors:
        return _minimal_report(manifest, "INVALID_EVIDENCE", trust_errors)
    signal_errors = validate_signal(signal, manifest, enrolled)
    if signal_errors:
        return _minimal_report(manifest, _error_state(signal_errors), signal_errors)

    valid_rows = [row for row in observations if not row["excluded"]]
    partner_values: dict[str, list[float]] = {partner_id: [] for partner_id in enrolled}
    assignment_counts: dict[str, dict[str, int]] = {
        partner_id: {"AB": 0, "BA": 0} for partner_id in enrolled
    }
    for row in valid_rows:
        baseline_ms = row["baseline_human_ms"]
        assisted_ms = row["nexus_human_ms"] + row["nexus_read_followup_ms"]
        partner_values[row["partner_id"]].append((baseline_ms - assisted_ms) / baseline_ms)
        assignment_counts[row["partner_id"]][row["assignment"]] += 1

    reasons: list[str] = []
    complete_partner_values = {
        partner_id: values
        for partner_id, values in partner_values.items()
        if len(values) >= MIN_PAIRS_PER_PARTNER
    }
    if len(complete_partner_values) < MIN_PARTNERS:
        reasons.append("COHORT_VALID_PARTNERS_BELOW_MINIMUM")
    if len(valid_rows) < MIN_TOTAL_PAIRS:
        reasons.append("PAIR_DENOMINATOR_BELOW_MINIMUM")
    for partner_id in complete_partner_values:
        counts = assignment_counts[partner_id]
        if abs(counts["AB"] - counts["BA"]) > 1:
            reasons.append(f"ASSIGNMENT_IMBALANCE:{partner_id}")

    start = _timestamp(manifest["study_start_at"])
    end = _timestamp(manifest["study_end_at"])
    assert start is not None and end is not None
    duration_weeks = (end - start).total_seconds() / (86400.0 * 7)
    if duration_weeks < MIN_WEEKS:
        reasons.append("DURATION_BELOW_MINIMUM")
    if duration_weeks > MAX_WEEKS:
        reasons.append("DURATION_ABOVE_MAXIMUM")

    partner_medians = {
        partner_id: float(statistics.median(values))
        for partner_id, values in complete_partner_values.items()
    }
    if partner_medians:
        cohort_median = float(statistics.median(partner_medians.values()))
        interval_low, interval_high = bootstrap_interval(list(partner_medians.values()))
    else:
        cohort_median = interval_low = interval_high = 0.0
    positive_pairs = sum(
        value > 0 for values in complete_partner_values.values() for value in values
    )
    denominator = sum(len(values) for values in complete_partner_values.values())
    positive_fraction = positive_pairs / denominator if denominator else 0.0
    if cohort_median < MIN_IMPROVEMENT:
        reasons.append("COHORT_IMPROVEMENT_BELOW_THRESHOLD")
    if positive_fraction < MIN_POSITIVE_FRACTION:
        reasons.append("POSITIVE_PAIR_FRACTION_BELOW_THRESHOLD")
    if any(value < 0 for value in partner_medians.values()):
        reasons.append("NEGATIVE_PARTNER_MEDIAN")

    trust_denominator = trust["all_assigned_pairs"]
    baseline_bad = (
        baseline_counts["FALSE_ACCEPT"]
        + baseline_counts["FALSE_REJECT"]
        + baseline_counts["UNRESOLVED"]
    )
    assisted_bad = (
        assisted_counts["FALSE_ACCEPT"]
        + assisted_counts["FALSE_REJECT"]
        + assisted_counts["UNRESOLVED"]
    )
    baseline_error_rate = baseline_bad / trust_denominator if trust_denominator else 1.0
    assisted_error_rate = assisted_bad / trust_denominator if trust_denominator else 1.0
    if assisted_counts["FALSE_ACCEPT"] != 0:
        reasons.append("ASSISTED_FALSE_ACCEPT")
    if assisted_error_rate > baseline_error_rate:
        reasons.append("TRUST_REGRESSION")
    if trust["partner_high_risk_errors"]:
        reasons.append("HIGH_RISK_PARTNER_ERROR")

    if manifest["synthetic"]:
        state = SYNTHETIC_STATE
    elif reasons:
        state = "MISSING_EVIDENCE"
    else:
        state = VALUE_READY_STATE
    input_hashes = {
        "manifest": manifest["manifest_hash"],
        "eligibility": eligibility["eligibility_hash"],
        "consent": consent["consent_hash"],
        "observations": _digest([row["observation_hash"] for row in observations]),
        "trust": trust["trust_hash"],
        "signal": signal["signal_hash"],
    }
    body = {
        "schema": REPORT_SCHEMA,
        "study_id": manifest["study_id"],
        "tg8_receipt_hash": manifest["tg8_receipt_hash"],
        "source_commit": manifest["source_commit"],
        "source_tree": manifest["source_tree"],
        "protocol_version": manifest["protocol_version"],
        "runtime_hash": manifest["runtime_hash"],
        "package_hash": manifest["package_hash"],
        "package_version": manifest["package_version"],
        "input_hashes": input_hashes,
        "synthetic": manifest["synthetic"],
        "partner_count_enrolled": len(enrolled),
        "partner_count_valid": len(complete_partner_values),
        "valid_pair_count": len(valid_rows),
        "excluded_pair_count": len(observations) - len(valid_rows),
        "duration_weeks": duration_weeks,
        "partner_medians": dict(sorted(partner_medians.items())),
        "cohort_median_improvement": cohort_median,
        "bootstrap_95_interval": [interval_low, interval_high],
        "positive_pair_fraction": positive_fraction,
        "trust": {
            "denominator": trust_denominator,
            "baseline_counts": baseline_counts,
            "assisted_counts": assisted_counts,
            "baseline_error_rate": baseline_error_rate,
            "assisted_error_rate": assisted_error_rate,
            "high_risk_partners": trust["partner_high_risk_errors"],
        },
        "signal_type": signal["type"],
        "signal_hash": signal["signal_hash"],
        "state": state,
        "reasons": sorted(set(reasons)),
        "claim_ceiling": CLAIM_CEILING,
        "generated_at": manifest["analysis_at"],
    }
    return {**body, "report_hash": _digest(body)}


def _hashed(body: dict[str, Any], hash_key: str) -> dict[str, Any]:
    return {**body, hash_key: _digest(body)}


def _synthetic_fixture() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    study_id = "tg9-synthetic-study-v1"
    source_commit = "a" * 40
    source_tree = "b" * 40
    runtime_hash = "sha256:" + "1" * 64
    package_hash = "sha256:" + "2" * 64
    oracle_hash = "sha256:" + "3" * 64
    manifest = _hashed(
        {
            "schema": STUDY_SCHEMA,
            "study_id": study_id,
            "synthetic": True,
            "tg8_receipt_hash": "sha256:" + "4" * 64,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "protocol_version": "0.1.0-experimental",
            "runtime_hash": runtime_hash,
            "package_hash": package_hash,
            "package_version": "28.3.0",
            "study_start_at": "2026-01-01T00:00:00+00:00",
            "study_end_at": "2026-01-29T00:00:00+00:00",
            "analysis_at": "2026-01-29T12:00:00+00:00",
            "narrow_icp_code": "SYNTHETIC_NARROW_ICP",
            "assignment_seed": ASSIGNMENT_SEED,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "bootstrap_replicates": BOOTSTRAP_REPLICATES,
            "min_partners": MIN_PARTNERS,
            "max_partners": MAX_PARTNERS,
            "min_pairs_per_partner": MIN_PAIRS_PER_PARTNER,
            "min_total_pairs": MIN_TOTAL_PAIRS,
            "min_weeks": MIN_WEEKS,
            "max_weeks": MAX_WEEKS,
            "min_improvement": MIN_IMPROVEMENT,
            "min_positive_fraction": MIN_POSITIVE_FRACTION,
            "oracle_rubric_hash": oracle_hash,
            "consent_version": "synthetic-consent-v1",
            "retention_policy_code": "SYNTHETIC_DELETE_AFTER_TEST",
            "withdrawal_channel_code": "SYNTHETIC_NONE",
        },
        "manifest_hash",
    )
    partner_ids = [f"p_{index:016x}" for index in range(1, 4)]
    partners = [
        {
            "partner_id": partner_id,
            "eligibility_state": "ENROLLED",
            "role_class": "SYNTHETIC_REVIEWER",
            "organization_size_bucket": "SYNTHETIC_SMALL",
            "workflow_class": "SYNTHETIC_CHANGE_REVIEW",
            "inclusion_reason_code": "SYNTHETIC_MATCH",
            "exclusion_reason_code": None,
            "slot_number": slot,
            "reserve_rank": None,
            "eligibility_receipt_hash": "sha256:" + f"{slot + 4:x}" * 64,
        }
        for slot, partner_id in enumerate(partner_ids, start=1)
    ]
    eligibility = _hashed(
        {
            "schema": ELIGIBILITY_SCHEMA,
            "study_id": study_id,
            "partners": partners,
            "reserve_order": [],
            "selected_at": "2025-12-31T12:00:00+00:00",
        },
        "eligibility_hash",
    )
    receipts = [
        _hashed(
            {
                "partner_id": partner_id,
                "consent_version": "synthetic-consent-v1",
                "status": "CONSENTED",
                "scope_code": "SYNTHETIC_TOOLING_ONLY",
                "consented_at": "2025-12-31T13:00:00+00:00",
                "data_classes": ["SYNTHETIC_TIMING", "SYNTHETIC_TRUST"],
                "retention_policy_code": "SYNTHETIC_DELETE_AFTER_TEST",
                "withdrawal_channel_code": "SYNTHETIC_NONE",
                "issuer_authority_hash": "sha256:" + f"{index + 7:x}" * 64,
                "external_verification_receipt_hash": "sha256:" + f"{index + 10:x}" * 64,
            },
            "receipt_hash",
        )
        for index, partner_id in enumerate(partner_ids, start=1)
    ]
    consent = _hashed(
        {"schema": CONSENT_SCHEMA, "study_id": study_id, "receipts": receipts},
        "consent_hash",
    )
    observations: list[dict[str, Any]] = []
    sequence = 0
    for partner_id in partner_ids:
        chosen: list[str] = []
        assignment_counts = {"AB": 0, "BA": 0}
        candidate_index = 1
        while len(chosen) < 8:
            pair_id = f"pair-{candidate_index:02d}"
            candidate_index += 1
            assignment = assignment_for(study_id, partner_id, pair_id)
            if assignment_counts[assignment] >= 4:
                continue
            assignment_counts[assignment] += 1
            chosen.append(pair_id)
        for pair_index, pair_id in enumerate(chosen, start=1):
            sequence += 1
            observations.append(
                _hashed(
                    {
                        "schema": OBSERVATION_SCHEMA,
                        "study_id": study_id,
                        "partner_id": partner_id,
                        "pair_id": pair_id,
                        "assignment": assignment_for(study_id, partner_id, pair_id),
                        "baseline_task_id": f"base-{partner_id[-4:]}-{pair_index:02d}",
                        "assisted_task_id": f"assist-{partner_id[-4:]}-{pair_index:02d}",
                        "difficulty_hash": "sha256:" + "d" * 64,
                        "source_commit": source_commit,
                        "protocol_version": "0.1.0-experimental",
                        "runtime_hash": runtime_hash,
                        "package_hash": package_hash,
                        "baseline_human_ms": 100_000,
                        "nexus_human_ms": 45_000,
                        "nexus_read_followup_ms": 10_000,
                        "washout_ms": MIN_WASHOUT_MS,
                        "baseline_outcome": "CORRECT",
                        "assisted_outcome": "CORRECT",
                        "high_risk_error": False,
                        "oracle_receipt_hash": "sha256:" + "e" * 64,
                        "attempt_ids": [
                            f"attempt-{sequence:03d}-baseline",
                            f"attempt-{sequence:03d}-assisted",
                        ],
                        "excluded": False,
                        "exclusion_reason": None,
                        "observed_at": "2026-01-15T12:00:00+00:00",
                    },
                    "observation_hash",
                )
            )
    trust = _hashed(
        {
            "schema": TRUST_SCHEMA,
            "study_id": study_id,
            "oracle_rubric_hash": oracle_hash,
            "all_assigned_pairs": len(observations),
            "baseline_counts": _counts(observations, "baseline_outcome"),
            "assisted_counts": _counts(observations, "assisted_outcome"),
            "partner_high_risk_errors": [],
        },
        "trust_hash",
    )
    signal = _hashed(
        {
            "schema": SIGNAL_SCHEMA,
            "study_id": study_id,
            "partner_id": partner_ids[0],
            "type": "SIGNED_PILOT_CONTINUATION",
            "issuer_authority_hash": "sha256:" + "5" * 64,
            "observed_at": "2026-01-20T12:00:00+00:00",
            "issued_at": "2026-01-20T11:00:00+00:00",
            "expires_at": "2026-02-20T00:00:00+00:00",
            "revoked": False,
            "algorithm": "Ed25519",
            "signature_hash": "sha256:" + "6" * 64,
            "signed_payload_hash": "sha256:" + "7" * 64,
            "external_verification_receipt_schema": "synthetic.external-verification.v1",
            "external_verification_receipt_hash": "sha256:" + "8" * 64,
            "verified": True,
        },
        "signal_hash",
    )
    return manifest, eligibility, consent, observations, trust, signal


def synthetic_self_test() -> dict[str, Any]:
    fixture = _synthetic_fixture()
    report = adjudicate(*fixture)
    if report["state"] != SYNTHETIC_STATE or report["synthetic"] is not True:
        raise RuntimeError("synthetic fixture escaped claim ceiling")
    manifest, eligibility, consent, observations, trust, signal = fixture
    bad = dict(observations[0])
    bad["nexus_read_followup_ms"] = -1
    bad["observation_hash"] = _digest({
        key: value for key, value in bad.items() if key != "observation_hash"
    })
    negative = adjudicate(manifest, eligibility, consent, [bad, *observations[1:]], trust, signal)
    if negative["state"] == VALUE_READY_STATE:
        raise RuntimeError("invalid synthetic evidence produced value-ready")
    return {
        "schema": "nexus.core-v1.tg9-synthetic-self-test.v1",
        "state": SYNTHETIC_STATE,
        "synthetic": True,
        "positive_report_hash": report["report_hash"],
        "negative_state": negative["state"],
        "negative_checks_passed": True,
        "claim_ceiling": CLAIM_CEILING,
    }


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number} must contain one JSON object")
        rows.append(value)
    return rows


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical(value) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TG9 paired usability/value evidence verifier")
    parser.add_argument("--synthetic-self-test", action="store_true")
    parser.add_argument("--privacy-scan", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--eligibility", type=Path)
    parser.add_argument("--consent", type=Path)
    parser.add_argument("--observations", type=Path)
    parser.add_argument("--trust", type=Path)
    parser.add_argument("--signal", type=Path)
    parser.add_argument("--report", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.synthetic_self_test:
        if any(
            value is not None
            for value in (
                args.privacy_scan,
                args.manifest,
                args.eligibility,
                args.consent,
                args.observations,
                args.trust,
                args.signal,
                args.report,
            )
        ):
            raise SystemExit("--synthetic-self-test cannot be combined with evidence paths")
        print(_canonical(synthetic_self_test()))
        return 0
    if args.privacy_scan is not None:
        if args.report is None:
            raise SystemExit("--privacy-scan requires --report")
        if any(
            value is not None
            for value in (
                args.manifest,
                args.eligibility,
                args.consent,
                args.observations,
                args.trust,
                args.signal,
            )
        ):
            raise SystemExit("--privacy-scan cannot be combined with adjudication inputs")
        scan = scan_privacy_root(args.privacy_scan)
        _write_json(args.report, scan)
        print(_canonical(scan))
        return 0 if scan["status"] == "PASS" else 2
    required = {
        "--manifest": args.manifest,
        "--eligibility": args.eligibility,
        "--consent": args.consent,
        "--observations": args.observations,
        "--trust": args.trust,
        "--signal": args.signal,
        "--report": args.report,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise SystemExit("missing required arguments: " + ", ".join(missing))
    assert args.manifest is not None
    assert args.eligibility is not None
    assert args.consent is not None
    assert args.observations is not None
    assert args.trust is not None
    assert args.signal is not None
    assert args.report is not None
    report = adjudicate(
        _load_json(args.manifest),
        _load_json(args.eligibility),
        _load_json(args.consent),
        _load_jsonl(args.observations),
        _load_json(args.trust),
        _load_json(args.signal),
    )
    _write_json(args.report, report)
    print(_canonical(report))
    return 0 if report["state"] in {VALUE_READY_STATE, SYNTHETIC_STATE, "MISSING_EVIDENCE"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
