"""TG8 protocol RC/Stable evidence gate; never a promotion authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from product.protocol import (
    CERTIFICATION_RECEIPT_SCHEMA,
    EVIDENCE_BUNDLE_SCHEMA,
    IMPLEMENTATION_SCHEMA,
    PROVENANCE_ENVELOPE_SCHEMA,
    PUBLIC_PROTOCOL_VERSION,
)

THRESHOLDS_SCHEMA = "nexus.core-v1.tg8-thresholds.v1"
TG4_ACCEPTANCE_SCHEMA = "nexus.core-v1.tg4-acceptance.v1"
TG5_ACCEPTANCE_SCHEMA = "nexus.core-v1.tg5-acceptance.v1"
TG6_ACCEPTANCE_SCHEMA = "nexus.core-v1.tg6-acceptance.v1"
COMPATIBILITY_SCHEMA = "nexus.core-v1.protocol-compatibility.v1"
CONFORMANCE_SCHEMA = "nexus.core-v1.client-conformance.v1"
UPGRADE_ROLLBACK_SCHEMA = "nexus.core-v1.upgrade-rollback.v1"
OPEN_ISSUES_SCHEMA = "nexus.core-v1.tg8-open-issues.v1"
STABLE_RUN_SCHEMA = "nexus.core-v1.tg8-stable-run.v1"
GATE_REPORT_SCHEMA = "nexus.core-v1.tg8-gate-report.v1"

RC_READY = "PROTOCOL_RC_EVIDENCE_READY"
STABLE_READY = "PROTOCOL_STABLE_EVIDENCE_READY"
LOWER_MATURITY = "LOWER_MATURITY"
UNVERIFIABLE = "UNVERIFIABLE"
ALLOWED_STATES = frozenset({RC_READY, STABLE_READY, LOWER_MATURITY, UNVERIFIABLE})
RC_CANDIDATE = "1.0.0-rc.1"
STABLE_CANDIDATE = "1.0.0"
PROFILE_ID = "python-oci-pytest-v1"
LEDGER_SCHEMA = "nexus.ledger-entry.v1"
HTTP_SCHEMA = "nexus.core.http-response.v1"
REQUIRED_CLIENTS = ("CLI", "MCP", "ACTION")
HOSTILE_FAMILIES = (
    "AUTH_ISSUER_TAMPER",
    "CRASH_UNKNOWN_EFFECT",
    "DUPLICATE_REPLAY_CONFLICT",
    "MALFORMED_PROTOCOL_SCHEMA",
    "MISSING_INADEQUATE_ORACLE",
    "PATH_SCOPE_ESCAPE",
    "PROVENANCE_HASH_TAMPER",
    "STALE_REVISION_GENERATION",
)
REQUIRED_AXES = frozenset({
    "public_protocol",
    "implementation_schema",
    "evidence_bundle_schema",
    "provenance_envelope_schema",
    "certification_receipt_schema",
    "ledger_schema",
    "ledger_generation",
    "http_schema",
    "cli_client",
    "mcp_client",
    "action_client",
    "reader_version",
})
EXPECTED_AXIS_SOURCES = {
    "public_protocol": PUBLIC_PROTOCOL_VERSION,
    "implementation_schema": IMPLEMENTATION_SCHEMA,
    "evidence_bundle_schema": EVIDENCE_BUNDLE_SCHEMA,
    "provenance_envelope_schema": PROVENANCE_ENVELOPE_SCHEMA,
    "certification_receipt_schema": CERTIFICATION_RECEIPT_SCHEMA,
    "ledger_schema": LEDGER_SCHEMA,
    "http_schema": HTTP_SCHEMA,
}

REQUIRED_UPGRADE_KINDS = frozenset({
    "CURRENT_TO_RC",
    "RC_PATCH",
    "RC_TO_STABLE",
    "INCOMPATIBLE_PROTOCOL",
    "INCOMPATIBLE_SCHEMA",
    "INCOMPATIBLE_LEDGER",
    "FAILED_UPGRADE_ROLLBACK",
})
REQUIRED_INPUTS = frozenset({
    "tg4_receipt",
    "tg5_receipt",
    "tg6_receipt",
    "compatibility",
    "conformance",
    "upgrade_rollback",
    "open_issues",
    "tg7_selection",
    "tg7_corpus",
    "tg7_shadow",
    "tg7_report",
})
STABLE_INPUTS = ("stable_run_1", "stable_run_2", "stable_run_3")
FORBIDDEN_OUTPUT_STATES = frozenset({
    "PROTOCOL_RC_OR_STABLE_EVIDENCE_READY",
    "PROMOTED",
    "RELEASED",
    "PRODUCTION_READY",
    "VALUE_READY",
})
CLAIM_CEILING = (
    "EVIDENCE_READINESS_ONLY",
    "NO_PROTOCOL_PROMOTION",
    "NO_RELEASE_AUTHORIZATION",
    "NO_DEPLOYMENT_TRUTH",
    "NO_PRODUCTION_READINESS",
    "NO_VALUE_CLAIM",
)


def _canonical(value: Any, *, _isfinite=math.isfinite, _dumps=json.dumps) -> str:
    active: set[int] = set()

    def enc(v: Any) -> Any:
        if v is None or type(v) in (bool, int, str):
            return v
        if type(v) is float:
            if not _isfinite(v):
                raise ValueError("non-finite")
            return v
        if isinstance(v, Mapping):
            if any(type(k) is not str for k in v):
                raise TypeError("mapping key")
            if id(v) in active:
                raise ValueError("cycle")
            active.add(id(v))
            try:
                return {k: enc(v[k]) for k in sorted(v)}
            finally:
                active.remove(id(v))
        if isinstance(v, (list, tuple)):
            if id(v) in active:
                raise ValueError("cycle")
            active.add(id(v))
            try:
                return [enc(x) for x in v]
            finally:
                active.remove(id(v))
        raise TypeError(type(v).__name__)

    return _dumps(
        enc(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _digest(value: Any, *, _canonical_fn=_canonical, _sha256=hashlib.sha256) -> str:
    return "sha256:" + _sha256(_canonical_fn(value).encode()).hexdigest()


def _file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(c in "0123456789abcdef" for c in value[7:])
    )


def _git(value: Any) -> bool:
    return (
        isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value)
    )


def _time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _keys(value: Any, expected: set[str] | frozenset[str], label: str) -> list[str]:
    if not isinstance(value, Mapping):
        return [f"{label}:NOT_OBJECT"]
    if set(value) == expected:
        return []
    return [f"{label}:KEYS"]


def _hashok(value: Mapping[str, Any], key: str) -> bool:
    claimed = value.get(key)
    return _sha(claimed) and claimed == _digest({k: v for k, v in value.items() if k != key})


def _load(
    path: Path, label: str, optional: bool = False
) -> tuple[dict[str, Any] | None, list[str]]:
    if not path.is_file():
        return (None, []) if optional else (None, [f"{label}:MISSING"])
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, [f"{label}:MALFORMED"]
    return (value, []) if isinstance(value, dict) else (None, [f"{label}:NOT_OBJECT"])


def _forbidden(value: Any, path: str = "") -> list[str]:
    bad_keys = {
        "promoted",
        "released",
        "production_ready",
        "value_ready",
        "revenue",
        "market_fit",
    }
    out: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            at = f"{path}.{key}" if path else str(key)
            if str(key).lower() in bad_keys:
                out.append(f"FORBIDDEN_CLAIM_FIELD:{at}")
            out.extend(_forbidden(child, at))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            out.extend(_forbidden(child, f"{path}[{i}]"))
    elif isinstance(value, str) and value in FORBIDDEN_OUTPUT_STATES:
        out.append(f"FORBIDDEN_CLAIM_VALUE:{path}:{value}")
    return out


def _validate_thresholds(value: Mapping[str, Any], sha_file: Path) -> list[str]:
    keys = frozenset({
        "schema",
        "repository",
        "rc_candidate",
        "stable_candidate",
        "subject_commit",
        "subject_tree",
        "dependency_subjects",
        "input_hashes",
        "compatibility_manifest",
        "upgrade_manifest",
        "required_clients",
        "forbidden_output_states",
        "observed_at",
        "threshold_hash",
    })
    e = _keys(value, keys, "THRESHOLDS")
    if e:
        return e
    checks = [
        (value["schema"] == THRESHOLDS_SCHEMA, "SCHEMA"),
        (value["repository"] == "James3014/Nexus-new", "REPOSITORY"),
        (
            value["rc_candidate"] == RC_CANDIDATE and value["stable_candidate"] == STABLE_CANDIDATE,
            "CANDIDATES",
        ),
        (_git(value["subject_commit"]) and _git(value["subject_tree"]), "SUBJECT"),
        (_time(value["observed_at"]), "OBSERVED_AT"),
        (
            isinstance(value["required_clients"], list)
            and tuple(value["required_clients"]) == REQUIRED_CLIENTS,
            "CLIENTS",
        ),
        (
            isinstance(value["forbidden_output_states"], list)
            and set(value["forbidden_output_states"]) == FORBIDDEN_OUTPUT_STATES,
            "FORBIDDEN",
        ),
        (_hashok(value, "threshold_hash"), "HASH"),
    ]
    e.extend(f"THRESHOLDS:{name}" for ok, name in checks if not ok)
    deps = value["dependency_subjects"]
    if not isinstance(deps, Mapping) or set(deps) != {"tg4", "tg5", "tg6", "tg7"}:
        e.append("THRESHOLDS:DEPENDENCIES")
    else:
        for name, dep in deps.items():
            if (
                not isinstance(dep, Mapping)
                or set(dep) != {"commit", "tree", "receipt_hash"}
                or not _git(dep.get("commit"))
                or not _git(dep.get("tree"))
                or not _sha(dep.get("receipt_hash"))
            ):
                e.append(f"THRESHOLDS:DEPENDENCY:{name}")
    hashes = value["input_hashes"]
    if (
        not isinstance(hashes, Mapping)
        or not REQUIRED_INPUTS.issubset(hashes)
        or set(hashes) - (REQUIRED_INPUTS | set(STABLE_INPUTS))
        or any(not _sha(v) for v in hashes.values())
    ):
        e.append("THRESHOLDS:INPUT_HASHES")
    cm = value["compatibility_manifest"]
    if not isinstance(cm, list) or not cm:
        e.append("THRESHOLDS:COMPATIBILITY_MANIFEST")
    else:
        axes, ids = set(), set()
        for row in cm:
            if not isinstance(row, Mapping) or set(row) != {
                "row_id",
                "axis",
                "source",
                "target",
                "expected",
            }:
                e.append("THRESHOLDS:COMPATIBILITY_ROW")
                continue
            if not all(isinstance(row[key], str) for key in row):
                e.append("THRESHOLDS:COMPATIBILITY_ROW_TYPES")
                continue
            if row["row_id"] in ids or row["expected"] not in {"SUPPORTED", "REFUSED"}:
                e.append("THRESHOLDS:COMPATIBILITY_ROW_ID")
            expected_source = EXPECTED_AXIS_SOURCES.get(row["axis"])
            if expected_source is not None and row["source"] != expected_source:
                e.append(f"THRESHOLDS:COMPATIBILITY_SOURCE:{row['axis']}")
            ids.add(row["row_id"])
            axes.add(row["axis"])
        if axes != REQUIRED_AXES:
            e.append("THRESHOLDS:COMPATIBILITY_AXES")
    um = value["upgrade_manifest"]
    if not isinstance(um, list) or not um:
        e.append("THRESHOLDS:UPGRADE_MANIFEST")
    else:
        kinds, ids = set(), set()
        for row in um:
            if not isinstance(row, Mapping) or set(row) != {
                "row_id",
                "kind",
                "source",
                "target",
                "expected",
            }:
                e.append("THRESHOLDS:UPGRADE_ROW")
                continue
            if not all(isinstance(row[key], str) for key in row):
                e.append("THRESHOLDS:UPGRADE_ROW_TYPES")
                continue
            if row["row_id"] in ids or row["expected"] not in {"SUPPORTED", "REFUSED"}:
                e.append("THRESHOLDS:UPGRADE_ROW_ID")
            ids.add(row["row_id"])
            kinds.add(row["kind"])
        if kinds != REQUIRED_UPGRADE_KINDS:
            e.append("THRESHOLDS:UPGRADE_KINDS")
    try:
        text = sha_file.read_text(encoding="utf-8")
    except OSError:
        e.append("THRESHOLDS:EXPECTED_HASH_FILE")
    else:
        if text != str(value["threshold_hash"])[7:] + "\n":
            e.append("THRESHOLDS:EXPECTED_HASH")
    return e


def _binding(
    value: Mapping[str, Any], schema: str, dep: Mapping[str, Any], claim: str
) -> list[str]:
    keys = frozenset({
        "schema",
        "repository",
        "subject_commit",
        "subject_tree",
        "status",
        "claim",
        "authority_source",
        "evidence_hashes",
        "observed_at",
        "receipt_hash",
    })
    e = _keys(value, keys, schema)
    if e:
        return e
    hashes = value["evidence_hashes"]
    checks = [
        (value["schema"] == schema, "SCHEMA"),
        (value["repository"] == "James3014/Nexus-new", "REPOSITORY"),
        (
            value["subject_commit"] == dep["commit"] and value["subject_tree"] == dep["tree"],
            "SUBJECT",
        ),
        (value["receipt_hash"] == dep["receipt_hash"], "BOUND_HASH"),
        (value["status"] == "ACCEPTED" and value["claim"] == claim, "STATUS"),
        (
            isinstance(value["authority_source"], str) and bool(value["authority_source"]),
            "AUTHORITY",
        ),
        (
            isinstance(hashes, Mapping) and bool(hashes) and all(_sha(x) for x in hashes.values()),
            "EVIDENCE",
        ),
        (_time(value["observed_at"]), "OBSERVED_AT"),
        (_hashok(value, "receipt_hash"), "HASH"),
    ]
    return [f"{schema}:{name}" for ok, name in checks if not ok]


def _cert(value: Mapping[str, Any]) -> list[str]:
    keys = frozenset({
        "acceptance_contract_hash",
        "certification",
        "change_set_hash",
        "claim_ceiling",
        "evidence_hash",
        "implementation_schema",
        "protocol_version",
        "receipt_hash",
        "receipt_schema",
        "verification",
        "verification_plan_hash",
    })
    e = _keys(value, keys, "TG5_CERT")
    if e:
        return e
    cert, ver = value["certification"], value["verification"]
    checks = [
        (value["receipt_schema"] == CERTIFICATION_RECEIPT_SCHEMA, "SCHEMA"),
        (value["protocol_version"] == PUBLIC_PROTOCOL_VERSION, "PROTOCOL"),
        (value["implementation_schema"] == IMPLEMENTATION_SCHEMA, "IMPLEMENTATION"),
        (
            isinstance(cert, Mapping) and cert.get("disposition") == "CERTIFIED",
            "DISPOSITION",
        ),
        (
            isinstance(ver, Mapping)
            and ver.get("status") == "VERIFIED"
            and ver.get("condition") == "VALID",
            "VERIFY",
        ),
        (_hashok(value, "receipt_hash"), "HASH"),
    ]
    return [f"TG5_CERT:{name}" for ok, name in checks if not ok]


def _tg5(value: Mapping[str, Any], dep: Mapping[str, Any]) -> list[str]:
    keys = frozenset({
        "schema",
        "repository",
        "subject_commit",
        "subject_tree",
        "status",
        "controlled_pr",
        "controlled_pr_base",
        "controlled_pr_head",
        "live_run_id",
        "mandatory_commands",
        "certification_receipt",
        "certification_receipt_hash",
        "observed_at",
        "receipt_hash",
    })
    e = _keys(value, keys, "TG5")
    if e:
        return e
    receipt = value["certification_receipt"]
    checks = [
        (
            value["schema"] == TG5_ACCEPTANCE_SCHEMA
            and value["repository"] == "James3014/Nexus-new",
            "SCHEMA",
        ),
        (
            value["subject_commit"] == dep["commit"] and value["subject_tree"] == dep["tree"],
            "SUBJECT",
        ),
        (
            value["receipt_hash"] == dep["receipt_hash"] and _hashok(value, "receipt_hash"),
            "HASH",
        ),
        (value["status"] == "ACCEPTED", "STATUS"),
        (
            value["controlled_pr"] == 635
            and _git(value["controlled_pr_base"])
            and _git(value["controlled_pr_head"]),
            "PR",
        ),
        (isinstance(value["live_run_id"], str) and bool(value["live_run_id"]), "LIVE"),
        (
            isinstance(value["mandatory_commands"], list) and len(value["mandatory_commands"]) >= 2,
            "COMMANDS",
        ),
        (isinstance(receipt, Mapping), "CERT"),
        (_sha(value["certification_receipt_hash"]), "CERT_HASH"),
        (_time(value["observed_at"]), "OBSERVED_AT"),
    ]
    e.extend(f"TG5:{name}" for ok, name in checks if not ok)
    if isinstance(receipt, Mapping):
        e.extend(_cert(receipt))
        if receipt.get("receipt_hash") != value["certification_receipt_hash"]:
            e.append("TG5:CERT_BINDING")
    return e


def _index(rows: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    return {
        row["row_id"]: row
        for row in rows
        if isinstance(row, Mapping) and isinstance(row.get("row_id"), str)
    }


def _compat(value: Mapping[str, Any], t: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    e = _keys(
        value,
        frozenset({"schema", "subject_commit", "subject_tree", "rows", "matrix_hash"}),
        "COMPAT",
    )
    f: list[str] = []
    if e:
        return e, f
    if (
        value["schema"] != COMPATIBILITY_SCHEMA
        or (value["subject_commit"], value["subject_tree"])
        != (t["subject_commit"], t["subject_tree"])
        or not _hashok(value, "matrix_hash")
    ):
        e.append("COMPAT:ENVELOPE")
    manifest = _index(t["compatibility_manifest"])
    rows = value["rows"]
    if not isinstance(rows, list):
        return e + ["COMPAT:ROWS"], f
    actual = _index([r for r in rows if isinstance(r, Mapping) and "row_id" in r])
    if len(actual) != len(rows) or set(actual) != set(manifest):
        e.append("COMPAT:ROW_SET")
    for rid, spec in manifest.items():
        row = actual.get(rid)
        if row is None:
            continue
        keys = {
            "row_id",
            "axis",
            "source",
            "target",
            "expected",
            "observed",
            "reason_code",
            "receipt_preservation_hash",
            "row_hash",
        }
        if (
            set(row) != keys
            or not _hashok(row, "row_hash")
            or not _sha(row.get("receipt_preservation_hash"))
        ):
            e.append(f"COMPAT:ROW:{rid}")
            continue
        if any(row[k] != spec[k] for k in ("axis", "source", "target", "expected")):
            e.append(f"COMPAT:BIND:{rid}")
        if row["observed"] not in {"SUPPORTED", "REFUSED"}:
            e.append(f"COMPAT:OBSERVED:{rid}")
        elif row["observed"] != spec["expected"]:
            f.append(f"COMPAT:OUTCOME:{rid}")
    return e, f


def _conformance(value: Mapping[str, Any], t: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    keys = frozenset({
        "schema",
        "subject_commit",
        "subject_tree",
        "canonical_request_hash",
        "canonical_response_hash",
        "endpoint_sequence",
        "redaction_set",
        "clients",
        "parity",
        "report_hash",
    })
    e, f = _keys(value, keys, "CONFORMANCE"), []
    if e:
        return e, f
    if (
        value["schema"] != CONFORMANCE_SCHEMA
        or (value["subject_commit"], value["subject_tree"])
        != (t["subject_commit"], t["subject_tree"])
        or not _hashok(value, "report_hash")
    ):
        e.append("CONFORMANCE:ENVELOPE")
    if not _sha(value["canonical_request_hash"]) or not _sha(value["canonical_response_hash"]):
        e.append("CONFORMANCE:CANONICAL")
    rows = value["clients"]
    if not isinstance(rows, list):
        return e + ["CONFORMANCE:CLIENTS"], f
    actual = {
        r["name"]: r for r in rows if isinstance(r, Mapping) and isinstance(r.get("name"), str)
    }
    if set(actual) != set(REQUIRED_CLIENTS) or len(actual) != len(rows):
        e.append("CONFORMANCE:CLIENT_SET")
    for name, row in actual.items():
        if set(row) != {
            "name",
            "artifact_hash",
            "output_hash",
            "parity",
            "row_hash",
        } or not _hashok(row, "row_hash"):
            e.append(f"CONFORMANCE:ROW:{name}")
            continue
        if not _sha(row["artifact_hash"]) or not _sha(row["output_hash"]):
            e.append(f"CONFORMANCE:HASH:{name}")
        if row["parity"] is not True:
            f.append(f"CONFORMANCE:PARITY:{name}")
    if value["parity"] is not True:
        f.append("CONFORMANCE:PARITY")
    return e, f


def _upgrade(value: Mapping[str, Any], t: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    e = _keys(
        value,
        frozenset({"schema", "subject_commit", "subject_tree", "rows", "report_hash"}),
        "UPGRADE",
    )
    f: list[str] = []
    if e:
        return e, f
    if (
        value["schema"] != UPGRADE_ROLLBACK_SCHEMA
        or (value["subject_commit"], value["subject_tree"])
        != (t["subject_commit"], t["subject_tree"])
        or not _hashok(value, "report_hash")
    ):
        e.append("UPGRADE:ENVELOPE")
    manifest = _index(t["upgrade_manifest"])
    rows = value["rows"]
    if not isinstance(rows, list):
        return e + ["UPGRADE:ROWS"], f
    actual = _index([r for r in rows if isinstance(r, Mapping) and "row_id" in r])
    if len(actual) != len(rows) or set(actual) != set(manifest):
        e.append("UPGRADE:ROW_SET")
    hash_fields = (
        "old_wheel_hash",
        "new_wheel_hash",
        "old_runtime_hash",
        "new_runtime_hash",
        "old_ledger_hash",
        "new_ledger_hash",
        "old_receipt_hash",
        "new_receipt_hash",
    )
    expected_keys = {
        "row_id",
        "kind",
        "source",
        "target",
        "expected",
        "observed",
        *hash_fields,
        "old_receipt_byte_equal",
        "rollback_state",
        "reason_code",
        "row_hash",
    }
    for rid, spec in manifest.items():
        row = actual.get(rid)
        if row is None:
            continue
        if (
            set(row) != expected_keys
            or not _hashok(row, "row_hash")
            or any(not _sha(row.get(k)) for k in hash_fields)
        ):
            e.append(f"UPGRADE:ROW:{rid}")
            continue
        if any(row[k] != spec[k] for k in ("kind", "source", "target", "expected")):
            e.append(f"UPGRADE:BIND:{rid}")
        if row["observed"] not in {"SUPPORTED", "REFUSED"}:
            e.append(f"UPGRADE:OBSERVED:{rid}")
        elif row["observed"] != spec["expected"]:
            f.append(f"UPGRADE:OUTCOME:{rid}")
        if row["old_receipt_byte_equal"] is not True:
            f.append(f"UPGRADE:RECEIPT_REWRITE:{rid}")
        if spec["kind"] == "FAILED_UPGRADE_ROLLBACK" and row["rollback_state"] != "RESTORED_EXACT":
            f.append(f"UPGRADE:ROLLBACK:{rid}")
    return e, f


def _issues(value: Mapping[str, Any]) -> list[str]:
    keys = frozenset({
        "schema",
        "repository",
        "observed_at",
        "query_manifest_hash",
        "raw_issue_ids",
        "severity_high_issue_ids",
        "classifications",
        "severity_high_count",
        "snapshot_hash",
    })
    e = _keys(value, keys, "OPEN_ISSUES")
    if e:
        return e
    raw, high, classes = (
        value["raw_issue_ids"],
        value["severity_high_issue_ids"],
        value["classifications"],
    )
    checks = [
        (
            value["schema"] == OPEN_ISSUES_SCHEMA and value["repository"] == "James3014/Nexus-new",
            "SCHEMA",
        ),
        (
            _time(value["observed_at"]) and _sha(value["query_manifest_hash"]),
            "IDENTITY",
        ),
        (
            isinstance(raw, list)
            and all(type(x) is int and x > 0 for x in raw)
            and raw == sorted(set(raw)),
            "RAW",
        ),
        (
            isinstance(high, list)
            and all(type(x) is int and x > 0 for x in high)
            and high == sorted(set(high)),
            "HIGH",
        ),
        (
            isinstance(classes, Mapping) and set(classes) == {str(x) for x in raw},
            "CLASSIFICATIONS",
        ),
        (
            type(value["severity_high_count"]) is int and value["severity_high_count"] == len(high),
            "COUNT",
        ),
        (_hashok(value, "snapshot_hash"), "HASH"),
    ]
    e.extend(f"OPEN_ISSUES:{name}" for ok, name in checks if not ok)
    if isinstance(raw, list) and isinstance(high, list) and not set(high).issubset(raw):
        e.append("OPEN_ISSUES:SUBSET")
    return e


def _tg7(
    s: Mapping[str, Any],
    c: Mapping[str, Any],
    sh: Mapping[str, Any],
    r: Mapping[str, Any],
    dep: Mapping[str, Any],
    tg5_hash: str,
) -> tuple[list[str], list[str]]:
    e, f = [], []
    if s.get("schema") != "nexus.core-v1.tg7-selection.v1" or not _hashok(s, "selection_hash"):
        e.append("TG7:SELECTION")
    if c.get("schema") != "nexus.core-v1.tg7-corpus.v1" or not _hashok(c, "corpus_hash"):
        e.append("TG7:CORPUS")
    if sh.get("schema") != "nexus.core-v1.tg7-shadow-receipt.v1" or not _hashok(sh, "receipt_hash"):
        e.append("TG7:SHADOW")
    if r.get("schema") != "nexus.core-v1.tg7-report.v1" or not _hashok(r, "report_hash"):
        e.append("TG7:REPORT")
    if r.get("report_hash") != dep["receipt_hash"]:
        e.append("TG7:BOUND_REPORT")
    if r.get("selection_hash") != s.get("selection_hash") or sh.get("selection_hash") != s.get(
        "selection_hash"
    ):
        e.append("TG7:SELECTION_BIND")
    if r.get("shadow_receipt_hash") != sh.get("receipt_hash") or sh.get("corpus_hash") != c.get(
        "corpus_hash"
    ):
        e.append("TG7:SHADOW_BIND")
    if r.get("tg5_receipt_hash") != tg5_hash or sh.get("tg5_receipt_hash") != tg5_hash:
        e.append("TG7:TG5_BIND")
    repo = {
        "owner": s.get("owner"),
        "name": s.get("name"),
        "commit": s.get("commit"),
        "tree": s.get("tree"),
    }
    shadow_repo = sh.get("repository")
    if c.get("repository") != repo:
        e.append("TG7:REPOSITORY")
    elif not isinstance(shadow_repo, Mapping):
        e.append("TG7:REPOSITORY")
    else:
        shadow_identity = {key: shadow_repo.get(key) for key in ("owner", "name", "commit", "tree")}
        expected_shadow_keys = {"owner", "name", "commit", "tree", "bottle_py_hash"}
        if (
            shadow_identity != repo
            or set(shadow_repo) != expected_shadow_keys
            or not _sha(shadow_repo.get("bottle_py_hash"))
        ):
            e.append("TG7:REPOSITORY")
    cases = c.get("cases")
    if not isinstance(cases, list) or c.get("case_count") != len(cases) or len(cases) < 50:
        f.append("TG7:CORPUS_DENOMINATOR")
    elif any(
        not isinstance(x, Mapping) or x.get("hostile_family") not in HOSTILE_FAMILIES for x in cases
    ):
        e.append("TG7:CORPUS_CASES")
    if (
        r.get("denominator") != r.get("eligible_count")
        or not isinstance(r.get("denominator"), int)
        or r["denominator"] < 50
    ):
        f.append("TG7:DENOMINATOR")
    if r.get("false_certification_count") != 0 or r.get("false_certification_case_ids") != []:
        f.append("TG7:FALSE_CERTIFICATION")
    if r.get("infra_invalid_count") != 0 or r.get("trust_mismatches") != 0:
        f.append("TG7:TRUST_OR_INFRA")
    counts = r.get("family_counts")
    if not isinstance(counts, Mapping) or set(counts) != set(HOSTILE_FAMILIES):
        e.append("TG7:FAMILIES")
    elif any(type(counts[x]) is not int or counts[x] < 5 for x in HOSTILE_FAMILIES):
        f.append("TG7:FAMILY_DENOMINATOR")
    if r.get("maximum_claim") != "CROSS_REPO_TRUST_SHADOW_VERIFIED":
        f.append("TG7:CLAIM")
    return e, f


def _stable(
    value: Mapping[str, Any], t: Mapping[str, Any], bindings: Mapping[str, str]
) -> tuple[list[str], list[str]]:
    keys = frozenset({
        "schema",
        "run_id",
        "candidate_commit",
        "candidate_tree",
        "observed_at",
        "complete",
        "tg5_run_id",
        "tg7_run_id",
        "eligible_attempts",
        "required_skips",
        "false_certification_count",
        "client_parity",
        "factual_outcome_hash",
        "compatibility_hash",
        "conformance_hash",
        "upgrade_rollback_hash",
        "tg5_receipt_hash",
        "tg7_report_hash",
        "run_hash",
    })
    e, f = _keys(value, keys, "STABLE_RUN"), []
    if e:
        return e, f
    checks = [
        (value["schema"] == STABLE_RUN_SCHEMA, "SCHEMA"),
        (
            (value["candidate_commit"], value["candidate_tree"])
            == (t["subject_commit"], t["subject_tree"]),
            "SUBJECT",
        ),
        (
            isinstance(value["run_id"], str)
            and bool(value["run_id"])
            and _time(value["observed_at"]),
            "RUN",
        ),
        (
            type(value["complete"]) is bool
            and type(value["eligible_attempts"]) is int
            and value["eligible_attempts"] >= 0,
            "COUNTS",
        ),
        (_sha(value["factual_outcome_hash"]) and _hashok(value, "run_hash"), "HASH"),
    ]
    e.extend(f"STABLE_RUN:{name}" for ok, name in checks if not ok)
    for key, expected in bindings.items():
        if value.get(key) != expected:
            e.append(f"STABLE_RUN:BIND:{key}")
    if (
        value["required_skips"] != 0
        or value["false_certification_count"] != 0
        or value["client_parity"] is not True
    ):
        f.append("STABLE_RUN:FACTUAL_FAILURE")
    return e, f


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
    payload = {
        "schema": GATE_REPORT_SCHEMA,
        "repository": "James3014/Nexus-new",
        "subject_commit": t.get("subject_commit") if t else None,
        "subject_tree": t.get("subject_tree") if t else None,
        "threshold_hash": t.get("threshold_hash") if t else None,
        "input_hashes": dict(sorted(hashes.items())),
        "compatibility_counts": dict(compat),
        "conformance_summary": dict(conf),
        "upgrade_summary": dict(up),
        "stable_run_ids": [str(x.get("run_id")) for x in runs],
        "stable_run_count": len(runs),
        "eligible_denominator": denominator,
        "false_certification_count": false_count,
        "classification": state,
        "reasons": sorted(set(reasons)),
        "claim_ceiling": list(CLAIM_CEILING),
        "generated_at": (
            t.get("observed_at")
            if t and _time(t.get("observed_at"))
            else "1970-01-01T00:00:00+00:00"
        ),
    }
    payload["report_hash"] = _digest(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return payload


def adjudicate(
    *,
    thresholds_path: Path,
    expected_thresholds_sha256_file: Path,
    compatibility_path: Path,
    conformance_path: Path,
    upgrade_rollback_path: Path,
    open_issues_path: Path,
    tg4_receipt_path: Path,
    tg5_receipt_path: Path,
    tg6_receipt_path: Path,
    tg7_selection_path: Path,
    tg7_corpus_path: Path,
    tg7_shadow_path: Path,
    tg7_report_path: Path,
    stable_run_paths: Sequence[Path],
    report_path: Path,
) -> dict[str, Any]:
    structural: list[str] = []
    failures: list[str] = []
    hashes: dict[str, str] = {}
    t, e = _load(thresholds_path, "THRESHOLDS")
    structural += e
    if t is None:
        return _report(report_path, None, {}, UNVERIFIABLE, structural, {}, {}, {}, [], 0, 0)
    threshold_errors = _validate_thresholds(t, expected_thresholds_sha256_file)
    structural += threshold_errors
    thresholds_valid = not threshold_errors

    paths = {
        "compatibility": compatibility_path,
        "conformance": conformance_path,
        "upgrade_rollback": upgrade_rollback_path,
        "open_issues": open_issues_path,
        "tg4_receipt": tg4_receipt_path,
        "tg5_receipt": tg5_receipt_path,
        "tg6_receipt": tg6_receipt_path,
        "tg7_selection": tg7_selection_path,
        "tg7_corpus": tg7_corpus_path,
        "tg7_shadow": tg7_shadow_path,
        "tg7_report": tg7_report_path,
    }
    docs: dict[str, dict[str, Any] | None] = {}
    for key, path in paths.items():
        if path.is_file():
            hashes[key] = _file_hash(path)
        doc, errs = _load(path, key.upper())
        docs[key] = doc
        structural += errs
        if doc is not None:
            structural += _forbidden(doc, key)
    for i, path in enumerate(stable_run_paths, 1):
        if path.is_file():
            hashes[f"stable_run_{i}"] = _file_hash(path)

    expected = t.get("input_hashes", {})
    if isinstance(expected, Mapping):
        for key in REQUIRED_INPUTS:
            if hashes.get(key) != expected.get(key):
                structural.append(f"INPUT_HASH:{key}")
        for key in STABLE_INPUTS:
            if key in expected and hashes.get(key) != expected[key]:
                structural.append(f"INPUT_HASH:{key}")
            if key not in expected and key in hashes:
                structural.append(f"UNBOUND_INPUT:{key}")

    deps = t.get("dependency_subjects", {})
    if thresholds_valid and isinstance(deps, Mapping):
        if docs["tg4_receipt"] is not None:
            structural += _binding(
                docs["tg4_receipt"],
                TG4_ACCEPTANCE_SCHEMA,
                deps["tg4"],
                "LOCAL_LEDGER_RECONCILIATION_VERIFIED",
            )
        if docs["tg5_receipt"] is not None:
            structural += _tg5(docs["tg5_receipt"], deps["tg5"])
        if docs["tg6_receipt"] is not None:
            structural += _binding(
                docs["tg6_receipt"],
                TG6_ACCEPTANCE_SCHEMA,
                deps["tg6"],
                "OPERATOR_JOURNEY_VERIFIED",
            )

    cf: list[str] = []
    conf_f: list[str] = []
    up_f: list[str] = []
    if thresholds_valid and docs["compatibility"] is not None:
        se, sf = _compat(docs["compatibility"], t)
        structural += se
        failures += sf
        cf = sf
    if thresholds_valid and docs["conformance"] is not None:
        se, sf = _conformance(docs["conformance"], t)
        structural += se
        failures += sf
        conf_f = sf
    if thresholds_valid and docs["upgrade_rollback"] is not None:
        se, sf = _upgrade(docs["upgrade_rollback"], t)
        structural += se
        failures += sf
        up_f = sf
    if docs["open_issues"] is not None:
        structural += _issues(docs["open_issues"])

    denominator = false_count = 0
    tg5 = docs["tg5_receipt"]
    tg7r = docs["tg7_report"]
    if (
        all(
            docs[k] is not None for k in ("tg7_selection", "tg7_corpus", "tg7_shadow", "tg7_report")
        )
        and isinstance(tg5, Mapping)
        and thresholds_valid
        and isinstance(deps, Mapping)
    ):
        se, sf = _tg7(
            docs["tg7_selection"],
            docs["tg7_corpus"],
            docs["tg7_shadow"],
            docs["tg7_report"],
            deps["tg7"],
            str(tg5.get("certification_receipt_hash")),
        )
        structural += se
        failures += sf
        denominator_value = tg7r.get("denominator", 0)
        false_count_value = tg7r.get("false_certification_count", 0)
        denominator = denominator_value if type(denominator_value) is int else 0
        false_count = false_count_value if type(false_count_value) is int else 0

    runs: list[dict[str, Any]] = []
    stable_failures: list[str] = []
    if (
        thresholds_valid
        and all(
            isinstance(docs[k], Mapping)
            for k in ("compatibility", "conformance", "upgrade_rollback", "tg7_report")
        )
        and isinstance(tg5, Mapping)
    ):
        bindings = {
            "compatibility_hash": str(docs["compatibility"]["matrix_hash"]),
            "conformance_hash": str(docs["conformance"]["report_hash"]),
            "upgrade_rollback_hash": str(docs["upgrade_rollback"]["report_hash"]),
            "tg5_receipt_hash": str(tg5.get("certification_receipt_hash")),
            "tg7_report_hash": str(tg7r.get("report_hash")),
        }
        for i, path in enumerate(stable_run_paths, 1):
            run, errs = _load(path, f"STABLE_RUN_{i}", optional=True)
            structural += errs
            if run is None:
                continue
            runs.append(run)
            structural += _forbidden(run, f"stable_run_{i}")
            se, sf = _stable(run, t, bindings)
            structural += se
            stable_failures += sf

    comp = docs["compatibility"]
    rows = comp.get("rows", []) if isinstance(comp, Mapping) else []
    if not isinstance(rows, list):
        rows = []
    compat_summary = {
        "total": len(rows),
        "supported": sum(r.get("observed") == "SUPPORTED" for r in rows if isinstance(r, Mapping)),
        "refused": sum(r.get("observed") == "REFUSED" for r in rows if isinstance(r, Mapping)),
        "failed": len(cf),
    }
    conf_summary = {
        "required_clients": 3,
        "parity": (
            bool(docs["conformance"].get("parity"))
            if isinstance(docs["conformance"], Mapping)
            else False
        ),
        "failed": len(conf_f),
    }
    upgrade_rows = (
        docs["upgrade_rollback"].get("rows", [])
        if isinstance(docs["upgrade_rollback"], Mapping)
        else []
    )
    if not isinstance(upgrade_rows, list):
        upgrade_rows = []
    upgrade_summary = {
        "total": len(upgrade_rows),
        "failed": len(up_f),
    }

    if structural:
        state, reasons = UNVERIFIABLE, structural
    elif failures:
        state, reasons = LOWER_MATURITY, failures
    else:
        state, reasons = RC_READY, ["RC_CONDITIONS_SATISFIED"]
        if len(runs) == 3:
            stable_ok = (
                all(x.get("complete") is True for x in runs)
                and len({x.get("run_id") for x in runs}) == 3
                and len({x.get("observed_at") for x in runs}) == 3
                and len({x.get("factual_outcome_hash") for x in runs}) == 1
                and sum(int(x.get("eligible_attempts", 0)) for x in runs) >= 150
                and not stable_failures
                and isinstance(docs["open_issues"], Mapping)
                and docs["open_issues"].get("severity_high_count") == 0
            )
            if stable_ok:
                state, reasons = STABLE_READY, ["STABLE_CONDITIONS_SATISFIED"]
            else:
                reasons.append("STABLE_EVIDENCE_INCOMPLETE_OR_NOT_REPRODUCIBLE")
    return _report(
        report_path,
        t,
        hashes,
        state,
        reasons,
        compat_summary,
        conf_summary,
        upgrade_summary,
        runs,
        denominator,
        false_count,
    )


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    for name in (
        "thresholds",
        "expected-thresholds-sha256-file",
        "compatibility",
        "conformance",
        "upgrade-rollback",
        "open-issues",
        "tg4-receipt",
        "tg5-receipt",
        "tg6-receipt",
        "tg7-selection",
        "tg7-corpus",
        "tg7-shadow",
        "tg7-report",
        "stable-run-1",
        "stable-run-2",
        "stable-run-3",
        "report",
    ):
        p.add_argument(f"--{name}", required=True, type=Path)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    r = adjudicate(
        thresholds_path=a.thresholds,
        expected_thresholds_sha256_file=a.expected_thresholds_sha256_file,
        compatibility_path=a.compatibility,
        conformance_path=a.conformance,
        upgrade_rollback_path=a.upgrade_rollback,
        open_issues_path=a.open_issues,
        tg4_receipt_path=a.tg4_receipt,
        tg5_receipt_path=a.tg5_receipt,
        tg6_receipt_path=a.tg6_receipt,
        tg7_selection_path=a.tg7_selection,
        tg7_corpus_path=a.tg7_corpus,
        tg7_shadow_path=a.tg7_shadow,
        tg7_report_path=a.tg7_report,
        stable_run_paths=(a.stable_run_1, a.stable_run_2, a.stable_run_3),
        report_path=a.report,
    )
    print(json.dumps(r, sort_keys=True, separators=(",", ":")))
    return 0 if r["classification"] in {RC_READY, STABLE_READY} else 2


if __name__ == "__main__":
    raise SystemExit(main())
