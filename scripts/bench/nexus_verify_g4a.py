#!/usr/bin/env python3
"""G4A internal public-review readiness gate for Nexus Verify.

This gate validates source and review-package readiness only. It deliberately
fails to claim public deployment, publisher verification, domain verification,
OpenAI tool scan, review, or publication.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from product.clients.nexus_verify import TOOL_DEFINITION  # noqa: E402
from product.protocol.generic_verification import canonical_hash  # noqa: E402

SCHEMA = "nexus.verify.g4a.internal-public-review-readiness.v1"
READY_STATE = "NEXUS_VERIFY_INTERNAL_PUBLIC_REVIEW_PACKAGE_READY"
NOT_READY_STATE = "NEXUS_VERIFY_INTERNAL_PUBLIC_REVIEW_PACKAGE_NOT_READY"
CLAIM_CEILING = "INTERNAL_PUBLIC_REVIEW_READINESS_ONLY"

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
PACKAGE_PATH = _FIXTURES / "nexus_verify_g4a_review_package.json"
SERVER_PATH = _REPO_ROOT / "scripts" / "nexus_verify_mcp_server.py"

_REQUIRED_DOC_MARKERS: dict[str, tuple[str, ...]] = {
    "docs/nexus_verify/PRIVACY_POLICY_DRAFT.md": (
        "Data we process",
        "Why we process data",
        "Recipients and subprocessors",
        "Retention",
        "User controls",
    ),
    "docs/nexus_verify/TERMS_OF_SERVICE_DRAFT.md": (
        "Service",
        "Verification claim boundary",
        "Acceptable use",
        "Privacy",
        "Contact",
    ),
    "docs/nexus_verify/SUPPORT.md": (
        "Product support",
        "Security reports",
    ),
    "docs/nexus_verify/OPERATIONS.md": (
        "Abuse and rate limiting",
        "Logging",
        "Retention",
        "Monitoring",
        "Rollback and removal",
    ),
    "docs/nexus_verify/WEBSITE_COPY.md": (
        "Nexus Verify",
        "Public v0",
        "Result boundary",
    ),
    "docs/nexus_verify/PUBLIC_REVIEW_READINESS.md": (
        "Product boundary",
        "Authentication model",
        "External activation gates",
    ),
}

_EXTERNAL_NOT_READY = {
    "publisher_identity_verification": {"NOT_RUN"},
    "apps_write_permission": {"NOT_OBSERVED"},
    "apps_read_permission": {"NOT_OBSERVED"},
    "stable_https_mcp_endpoint": {"UNBOUND_EXTERNAL"},
    "website_https_url": {"UNBOUND_EXTERNAL"},
    "support_https_url": {"UNBOUND_EXTERNAL"},
    "privacy_https_url": {"UNBOUND_EXTERNAL"},
    "terms_https_url": {"UNBOUND_EXTERNAL"},
    "domain_verification": {"NOT_RUN"},
    "production_tool_scan": {"NOT_RUN"},
    "demo_recording_url": {"UNBOUND_EXTERNAL"},
    "portal_submission": {"NOT_RUN"},
    "public_review": {"NOT_RUN"},
    "publication": {"NOT_RUN"},
}


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_server_module():
    spec = importlib.util.spec_from_file_location("nexus_verify_g4a_server", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Nexus Verify MCP server")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _check_docs(package: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    artifacts = package.get("policy_artifacts")
    if not isinstance(artifacts, Mapping):
        return False, ["POLICY_ARTIFACTS_MALFORMED"]

    required_paths = set(_REQUIRED_DOC_MARKERS)
    declared_paths = {value for value in artifacts.values() if isinstance(value, str)}
    if required_paths != declared_paths:
        failures.append("POLICY_ARTIFACT_SET_MISMATCH")

    for relative, markers in _REQUIRED_DOC_MARKERS.items():
        path = _REPO_ROOT / relative
        if not path.is_file():
            failures.append(f"MISSING_DOC:{relative}")
            continue
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                failures.append(f"MISSING_DOC_MARKER:{relative}:{marker}")
    return not failures, failures


def _check_review_cases(package: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    review_cases = package.get("review_cases")
    if not isinstance(review_cases, Mapping):
        return False, ["REVIEW_CASES_MALFORMED"]
    positive = review_cases.get("positive")
    negative = review_cases.get("negative")
    if not isinstance(positive, list) or len(positive) != 5:
        failures.append("POSITIVE_REVIEW_CASE_COUNT_MUST_BE_5")
    if not isinstance(negative, list) or len(negative) != 3:
        failures.append("NEGATIVE_REVIEW_CASE_COUNT_MUST_BE_3")
    rows = [*(positive if isinstance(positive, list) else []), *(negative if isinstance(negative, list) else [])]
    ids = [row.get("id") for row in rows if isinstance(row, Mapping)]
    if len(ids) != len(set(ids)):
        failures.append("REVIEW_CASE_IDS_NOT_UNIQUE")
    for row in positive if isinstance(positive, list) else []:
        if not isinstance(row, Mapping) or row.get("expected_action") != "CALL_TOOL":
            failures.append("POSITIVE_REVIEW_CASE_ACTION_INVALID")
    for row in negative if isinstance(negative, list) else []:
        if not isinstance(row, Mapping) or row.get("expected_action") != "DO_NOT_CALL":
            failures.append("NEGATIVE_REVIEW_CASE_ACTION_INVALID")
    return not failures, failures


def _check_tool_contract(package: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    mcp = package.get("mcp")
    if not isinstance(mcp, Mapping):
        return False, ["MCP_PACKAGE_MALFORMED"]

    if TOOL_DEFINITION.get("name") != "verify_code_change_evidence":
        failures.append("TOOL_NAME_DRIFT")
    input_schema = TOOL_DEFINITION.get("inputSchema")
    output_schema = TOOL_DEFINITION.get("outputSchema")
    if not isinstance(input_schema, Mapping) or input_schema.get("$id") != "nexus.verify-code-change-evidence.input.v1":
        failures.append("INPUT_SCHEMA_DRIFT")
    if not isinstance(output_schema, Mapping) or output_schema.get("$id") != "nexus.verify-code-change-evidence.output.v1":
        failures.append("OUTPUT_SCHEMA_DRIFT")
    expected_annotations = {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
    if TOOL_DEFINITION.get("annotations") != expected_annotations:
        failures.append("TOOL_ANNOTATION_DRIFT")
    if mcp.get("annotations") != expected_annotations:
        failures.append("REVIEW_PACKAGE_ANNOTATION_DRIFT")
    if mcp.get("auth_mode") != "noauth":
        failures.append("PUBLIC_AUTH_MODE_NOT_NOAUTH")
    if mcp.get("repository_scope") != "PUBLIC_GITHUB_ONLY":
        failures.append("PUBLIC_REPOSITORY_SCOPE_DRIFT")
    if mcp.get("user_oauth") is not False:
        failures.append("UNEXPECTED_USER_OAUTH")
    return not failures, failures


def _check_server_source(package: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    module = _load_server_module()
    source = SERVER_PATH.read_text(encoding="utf-8")

    expected_meta = {
        "securitySchemes": [{"type": "noauth"}],
        "openai/toolInvocation/invoking": "Checking verification evidence...",
        "openai/toolInvocation/invoked": "Verification evidence checked",
    }
    if module.PUBLIC_TOOL_META != expected_meta:
        failures.append("PUBLIC_TOOL_META_DRIFT")
    if module.PUBLIC_REVIEW_GITHUB_TOKEN_ENV != "NEXUS_VERIFY_PUBLIC_GITHUB_TOKEN":
        failures.append("PUBLIC_TOKEN_ENV_DRIFT")
    if "from_public_review_environment" not in source or "public_only=True" not in source:
        failures.append("PUBLIC_ONLY_FACTORY_MISSING")
    if "_require_public_repository" not in source:
        failures.append("PUBLIC_REPOSITORY_VISIBILITY_GUARD_MISSING")
    if "_require_loopback(host)" not in source:
        failures.append("LOCAL_PREDEPLOYMENT_BIND_GUARD_MISSING")
    for forbidden in ('method="POST"', 'method="PUT"', 'method="PATCH"', 'method="DELETE"'):
        if forbidden in source:
            failures.append(f"GITHUB_WRITE_METHOD_PRESENT:{forbidden}")
    if package.get("mcp", {}).get("meta") != expected_meta:
        failures.append("REVIEW_PACKAGE_META_DRIFT")
    return not failures, failures


def _check_listing(package: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    listing = package.get("listing")
    if not isinstance(listing, Mapping):
        return False, ["LISTING_MALFORMED"]
    for key in ("website", "support", "privacy", "terms"):
        value = listing.get(key)
        if not isinstance(value, Mapping):
            failures.append(f"LISTING_{key.upper()}_MALFORMED")
            continue
        if value.get("status") != "UNBOUND_EXTERNAL" or value.get("https_url") is not None:
            failures.append(f"LISTING_{key.upper()}_MUST_REMAIN_EXTERNAL")
    prompts = listing.get("default_prompts")
    if not isinstance(prompts, list) or not 1 <= len(prompts) <= 3:
        failures.append("DEFAULT_PROMPT_COUNT_INVALID")
    if listing.get("screenshots", []) not in ([], None) and package.get("product", {}).get("no_ui") is True:
        failures.append("NO_UI_MUST_NOT_CLAIM_SCREENSHOTS")
    if not isinstance(listing.get("release_notes"), str) or not listing["release_notes"].strip():
        failures.append("RELEASE_NOTES_MISSING")
    if listing.get("demo_recording_status") != "UNBOUND_EXTERNAL":
        failures.append("DEMO_RECORDING_STATUS_MUST_REMAIN_EXTERNAL")
    return not failures, failures


def _check_external_boundary(package: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    external = package.get("external_activation")
    if not isinstance(external, Mapping):
        return False, ["EXTERNAL_ACTIVATION_MALFORMED"]
    for key, allowed in _EXTERNAL_NOT_READY.items():
        if external.get(key) not in allowed:
            failures.append(f"EXTERNAL_GATE_OVERCLAIM:{key}")
    return not failures, failures


def score() -> dict[str, Any]:
    package = _read_json(PACKAGE_PATH)
    checks: dict[str, dict[str, Any]] = {}

    for name, fn in (
        ("docs", _check_docs),
        ("review_cases", _check_review_cases),
        ("tool_contract", _check_tool_contract),
        ("server_source", _check_server_source),
        ("listing", _check_listing),
        ("external_boundary", _check_external_boundary),
    ):
        ok, failures = fn(package)
        checks[name] = {"ok": ok, "failures": failures}

    package_identity_ok = (
        package.get("schema") == "nexus.verify.g4a.public-review-package.v1"
        and package.get("status") == "INTERNAL_REVIEW_PACKAGE"
        and package.get("claim_ceiling") == CLAIM_CEILING
    )
    checks["package_identity"] = {
        "ok": package_identity_ok,
        "failures": [] if package_identity_ok else ["PACKAGE_IDENTITY_MISMATCH"],
    }

    ready = all(row["ok"] for row in checks.values())
    state = READY_STATE if ready else NOT_READY_STATE
    failures = [
        failure
        for row in checks.values()
        for failure in row["failures"]
    ]

    summary = {
        "internal_check_count": len(checks),
        "internal_checks_passed": sum(bool(row["ok"]) for row in checks.values()),
        "failure_count": len(failures),
        "failures": failures,
        "positive_review_cases": len(package.get("review_cases", {}).get("positive", [])),
        "negative_review_cases": len(package.get("review_cases", {}).get("negative", [])),
        "external_activation_ready": False,
        "external_activation_status": dict(package.get("external_activation", {})),
    }

    decision_basis = {
        "state": state,
        "checks": checks,
        "summary": summary,
    }
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "state": state,
        "claim_ceiling": CLAIM_CEILING,
        "checks": checks,
        "summary": summary,
        "decision_hash": canonical_hash(decision_basis),
        "limitations": [
            "internal readiness does not prove a public HTTPS endpoint exists",
            "publisher identity and Apps Management permissions are not observed here",
            "domain verification and production tool scan are not run",
            "OpenAI review and publication are not authorized or claimed",
            "G4B must rebind current external requirements before activation",
        ],
    }
    report["report_hash"] = canonical_hash(report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    report = score()
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.report:
        Path(args.report).write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0 if report["state"] == READY_STATE else 2


if __name__ == "__main__":
    raise SystemExit(main())
