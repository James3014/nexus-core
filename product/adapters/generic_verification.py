"""Transport-neutral adapter for deterministic Core ChangeSet verification.

The adapter validates the public wire contract, projects it into the existing
Evidence/Verification/Certification domain objects, and returns only Core-owned
truth. It does not acquire source, run verifiers, or make execution/merge
choices.
"""

from __future__ import annotations

from typing import Any, Mapping

from product.evidence import (
    AcceptanceContract,
    Applicability,
    ChangeSet,
    EvidenceBundle,
    ExpectedEvidenceSubject,
    Observation,
    ObservationStatus,
    RequirementMode,
    VerificationPlan,
)
from product.kernel import CertificationInput, certify
from product.protocol import PUBLIC_PROTOCOL_VERSION
from product.protocol.generic_verification import (
    GENERIC_VERIFICATION_ERROR_SCHEMA_ID,
    GENERIC_VERIFICATION_REQUEST_SCHEMA_ID,
    GENERIC_VERIFICATION_RESPONSE_SCHEMA_ID,
    acceptance_contract_hash,
    change_manifest_hash,
    change_set_hash,
    evidence_bundle_hash,
    is_git_tree_ref,
    is_hash,
    is_revision_ref,
    verification_plan_hash,
)
from product.verification import verify

_MAX_TEXT = 512


def _error(code: str, field: str) -> dict[str, Any]:
    return {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "schema": GENERIC_VERIFICATION_ERROR_SCHEMA_ID,
        "error": {"code": code, "field": field},
    }


def _text(value: Any) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and "\x00" not in value
        and len(value.encode("utf-8")) <= _MAX_TEXT
    )


def _paths(value: Any, *, allow_empty: bool = False) -> bool:
    if type(value) is not list or (not value and not allow_empty):
        return False
    if any(
        not _text(path)
        or path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        for path in value
    ):
        return False
    return len(value) == len(set(value))


def _ids(value: Any) -> bool:
    return type(value) is list and bool(value) and all(_text(item) for item in value) and len(value) == len(set(value))


def _exact(value: Any, keys: set[str]) -> bool:
    return type(value) is dict and set(value) == keys


def _subset_exact(value: Any, required: set[str], optional: set[str]) -> bool:
    return type(value) is dict and required.issubset(value) and set(value).issubset(
        required | optional
    )


def _git_oid_or_none(value: Any) -> bool:
    return value is None or (
        type(value) is str
        and len(value) == 40
        and all(char in "0123456789abcdef" for char in value)
    )


def _git_mode_or_none(value: Any) -> bool:
    return value is None or (
        type(value) is str and len(value) == 6 and all(char in "01234567" for char in value)
    )


def _validate_subject(value: Any) -> str | None:
    if not _exact(
        value,
        {"logical_subject_id", "evidence_kind", "requirement_mode", "applicability"},
    ):
        return None
    if not _text(value["logical_subject_id"]):
        return None
    if not _text(value["evidence_kind"]):
        return None
    if value["requirement_mode"] not in {"REQUIRED", "CONDITIONALLY_REQUIRED", "NOT_APPLICABLE"}:
        return None
    if value["applicability"] not in {"APPLICABLE", "NOT_APPLICABLE", "UNRESOLVED"}:
        return None
    return value


def _validate_contract(value: Any) -> str | None:
    required = {
        "contract_id",
        "requirements_hash",
        "required_verifier_ids",
        "allowed_paths",
        "deletion_policy",
    }
    if not _subset_exact(value, required, {"expected_subjects", "universe_generation"}):
        return "acceptance_contract"
    if not _text(value["contract_id"]):
        return "acceptance_contract.contract_id"
    if not is_hash(value["requirements_hash"]):
        return "acceptance_contract.requirements_hash"
    if not _ids(value["required_verifier_ids"]):
        return "acceptance_contract.required_verifier_ids"
    if not _paths(value["allowed_paths"]):
        return "acceptance_contract.allowed_paths"
    if value["deletion_policy"] not in {"FORBID", "ALLOW"}:
        return "acceptance_contract.deletion_policy"
    expected = value.get("expected_subjects")
    generation = value.get("universe_generation")
    if expected is None and generation is None:
        return None
    if expected is None or generation is None:
        return "acceptance_contract.expected_subjects"
    if type(expected) is not list or not expected:
        return "acceptance_contract.expected_subjects"
    if type(generation) is not int or isinstance(generation, bool) or generation < 0:
        return "acceptance_contract.universe_generation"
    logical_ids: list[str] = []
    for index, subject in enumerate(expected):
        prefix = f"acceptance_contract.expected_subjects[{index}]"
        if _validate_subject(subject) is None:
            return prefix
        if subject["requirement_mode"] == "REQUIRED" and subject["applicability"] != "APPLICABLE":
            return prefix + ".applicability"
        if (
            subject["requirement_mode"] == "NOT_APPLICABLE"
            and subject["applicability"] != "NOT_APPLICABLE"
        ):
            return prefix + ".applicability"
        logical_ids.append(subject["logical_subject_id"])
    if len(logical_ids) != len(set(logical_ids)):
        return "acceptance_contract.expected_subjects"
    return None


def _validate_change_set(value: Any) -> str | None:
    keys = {
        "change_set_id",
        "source_revision",
        "target_revision",
        "diff_hash",
        "paths",
        "deleted_paths",
    }
    if not _exact(value, keys):
        return "change_set"
    if not _text(value["change_set_id"]):
        return "change_set.change_set_id"
    if not is_revision_ref(value["source_revision"]):
        return "change_set.source_revision"
    if not is_revision_ref(value["target_revision"]):
        return "change_set.target_revision"
    if value["source_revision"] == value["target_revision"]:
        return "change_set.target_revision"
    if not is_hash(value["diff_hash"]):
        return "change_set.diff_hash"
    if not _paths(value["paths"]):
        return "change_set.paths"
    if not _paths(value["deleted_paths"], allow_empty=True):
        return "change_set.deleted_paths"
    if not set(value["deleted_paths"]).issubset(value["paths"]):
        return "change_set.deleted_paths"
    return None


def _validate_manifest(value: Any) -> str | None:
    if not _exact(value, {"source_tree", "target_tree", "entries"}):
        return "change_manifest"
    if not is_git_tree_ref(value["source_tree"]):
        return "change_manifest.source_tree"
    if not is_git_tree_ref(value["target_tree"]):
        return "change_manifest.target_tree"
    entries = value["entries"]
    if type(entries) is not list or not entries:
        return "change_manifest.entries"
    seen: set[str] = set()
    for index, row in enumerate(entries):
        prefix = f"change_manifest.entries[{index}]"
        if not _exact(
            row,
            {
                "path",
                "change_type",
                "before_oid",
                "after_oid",
                "before_mode",
                "after_mode",
            },
        ):
            return prefix
        if not _paths([row["path"]]) or row["path"] in seen:
            return prefix + ".path"
        seen.add(row["path"])
        if row["change_type"] not in {"ADD", "MODIFY", "DELETE"}:
            return prefix + ".change_type"
        before_oid, after_oid = row["before_oid"], row["after_oid"]
        before_mode, after_mode = row["before_mode"], row["after_mode"]
        if not _git_oid_or_none(before_oid) or not _git_oid_or_none(after_oid):
            return prefix + ".oid"
        if not _git_mode_or_none(before_mode) or not _git_mode_or_none(after_mode):
            return prefix + ".mode"
        if row["change_type"] == "ADD" and not (
            before_oid is None and before_mode is None and after_oid is not None and after_mode is not None
        ):
            return prefix + ".ADD"
        if row["change_type"] == "DELETE" and not (
            before_oid is not None and before_mode is not None and after_oid is None and after_mode is None
        ):
            return prefix + ".DELETE"
        if row["change_type"] == "MODIFY" and not (
            before_oid is not None
            and before_mode is not None
            and after_oid is not None
            and after_mode is not None
            and (before_oid != after_oid or before_mode != after_mode)
        ):
            return prefix + ".MODIFY"
    return None


def _validate_plan(value: Any) -> str | None:
    keys = {"plan_id", "acceptance_contract_hash", "change_set_hash", "required_verifier_ids"}
    if not _exact(value, keys):
        return "verification_plan"
    if not _text(value["plan_id"]):
        return "verification_plan.plan_id"
    if not is_hash(value["acceptance_contract_hash"]):
        return "verification_plan.acceptance_contract_hash"
    if not is_hash(value["change_set_hash"]):
        return "verification_plan.change_set_hash"
    if not _ids(value["required_verifier_ids"]):
        return "verification_plan.required_verifier_ids"
    return None


def _validate_evidence(value: Any) -> str | None:
    keys = {
        "bundle_id",
        "acceptance_contract_hash",
        "change_set_hash",
        "verification_plan_hash",
        "observations",
        "claimed_bundle_hash",
    }
    if not _exact(value, keys):
        return "evidence_bundle"
    if not _text(value["bundle_id"]):
        return "evidence_bundle.bundle_id"
    for key in ("acceptance_contract_hash", "change_set_hash", "verification_plan_hash"):
        if not is_hash(value[key]):
            return f"evidence_bundle.{key}"
    if value["claimed_bundle_hash"] is not None and not is_hash(value["claimed_bundle_hash"]):
        return "evidence_bundle.claimed_bundle_hash"
    observations = value["observations"]
    if type(observations) is not list or not observations:
        return "evidence_bundle.observations"
    verifier_ids: set[str] = set()
    artifact_ids: set[str] = set()
    logical_ids: set[str] = set()
    for index, row in enumerate(observations):
        prefix = f"evidence_bundle.observations[{index}]"
        if not _subset_exact(
            row,
            {"verifier_id", "artifact_id", "artifact_hash", "status"},
            {"logical_subject_id", "evidence_kind"},
        ):
            return prefix
        if (row.get("logical_subject_id") is None) != (row.get("evidence_kind") is None):
            return prefix + ".logical_subject_id"
        if not _text(row["verifier_id"]) or row["verifier_id"] in verifier_ids:
            return prefix + ".verifier_id"
        if not _text(row["artifact_id"]) or row["artifact_id"] in artifact_ids:
            return prefix + ".artifact_id"
        verifier_ids.add(row["verifier_id"])
        artifact_ids.add(row["artifact_id"])
        logical_subject_id = row.get("logical_subject_id")
        if logical_subject_id is not None:
            if not _text(logical_subject_id) or logical_subject_id in logical_ids:
                return prefix + ".logical_subject_id"
            if not _text(row["evidence_kind"]):
                return prefix + ".evidence_kind"
            logical_ids.add(logical_subject_id)
        if not is_hash(row["artifact_hash"]):
            return prefix + ".artifact_hash"
        if row["status"] not in {"PASS", "FAIL"}:
            return prefix + ".status"
    return None


def _validate_policy(value: Any) -> str | None:
    if value is None:
        return None
    keys = {"accepted", "authority_present", "approval_present", "signing_present"}
    if not _exact(value, keys):
        return "certification_policy"
    if any(value[key] is not None and type(value[key]) is not bool for key in keys):
        return "certification_policy"
    return None


def validate_generic_verification_request(payload: Any) -> tuple[str, str] | None:
    top = {
        "protocol_version",
        "schema",
        "acceptance_contract",
        "change_set",
        "change_manifest",
        "verification_plan",
        "evidence_bundle",
        "certification_policy",
    }
    if not _exact(payload, top):
        return ("MALFORMED_REQUEST", "request")
    if payload["protocol_version"] != PUBLIC_PROTOCOL_VERSION:
        return ("UNSUPPORTED_PROTOCOL", "protocol_version")
    if payload["schema"] != GENERIC_VERIFICATION_REQUEST_SCHEMA_ID:
        return ("UNSUPPORTED_SCHEMA", "schema")
    for validator, key in (
        (_validate_contract, "acceptance_contract"),
        (_validate_change_set, "change_set"),
        (_validate_manifest, "change_manifest"),
        (_validate_plan, "verification_plan"),
        (_validate_evidence, "evidence_bundle"),
        (_validate_policy, "certification_policy"),
    ):
        field = validator(payload[key])
        if field is not None:
            return ("MALFORMED_REQUEST", field)

    contract = payload["acceptance_contract"]
    change = payload["change_set"]
    manifest = payload["change_manifest"]
    plan = payload["verification_plan"]
    evidence = payload["evidence_bundle"]

    manifest_paths = {row["path"] for row in manifest["entries"]}
    manifest_deleted = {row["path"] for row in manifest["entries"] if row["change_type"] == "DELETE"}
    if set(change["paths"]) != manifest_paths:
        return ("CROSS_BINDING_INVALID", "change_set.paths")
    if set(change["deleted_paths"]) != manifest_deleted:
        return ("CROSS_BINDING_INVALID", "change_set.deleted_paths")
    if change["diff_hash"] != change_manifest_hash(manifest):
        return ("CROSS_BINDING_INVALID", "change_set.diff_hash")
    if is_git_tree_ref(change["source_revision"]) and change["source_revision"] != manifest["source_tree"]:
        return ("CROSS_BINDING_INVALID", "change_manifest.source_tree")
    if is_git_tree_ref(change["target_revision"]) and change["target_revision"] != manifest["target_tree"]:
        return ("CROSS_BINDING_INVALID", "change_manifest.target_tree")

    contract_hash = acceptance_contract_hash(contract)
    cs_hash = change_set_hash(change)
    plan_hash = verification_plan_hash(plan)
    evidence_hash = evidence_bundle_hash(evidence)
    if plan["acceptance_contract_hash"] != contract_hash:
        return ("CROSS_BINDING_INVALID", "verification_plan.acceptance_contract_hash")
    if plan["change_set_hash"] != cs_hash:
        return ("CROSS_BINDING_INVALID", "verification_plan.change_set_hash")
    if evidence["acceptance_contract_hash"] != contract_hash:
        return ("CROSS_BINDING_INVALID", "evidence_bundle.acceptance_contract_hash")
    if evidence["change_set_hash"] != cs_hash:
        return ("CROSS_BINDING_INVALID", "evidence_bundle.change_set_hash")
    if evidence["verification_plan_hash"] != plan_hash:
        return ("CROSS_BINDING_INVALID", "evidence_bundle.verification_plan_hash")
    if evidence["claimed_bundle_hash"] is not None and evidence["claimed_bundle_hash"] != evidence_hash:
        return ("TAMPERED", "evidence_bundle.claimed_bundle_hash")
    return None


def _domain_objects(payload: Mapping[str, Any]) -> tuple[AcceptanceContract, ChangeSet, VerificationPlan, EvidenceBundle]:
    contract_value = payload["acceptance_contract"]
    change_value = payload["change_set"]
    plan_value = payload["verification_plan"]
    evidence_value = payload["evidence_bundle"]

    expected = contract_value.get("expected_subjects")
    contract = AcceptanceContract(
        contract_value["contract_id"],
        contract_value["requirements_hash"],
        tuple(contract_value["required_verifier_ids"]),
        tuple(contract_value["allowed_paths"]),
        contract_value["deletion_policy"],
        tuple(
            ExpectedEvidenceSubject(
                subject["logical_subject_id"],
                subject["evidence_kind"],
                RequirementMode(subject["requirement_mode"]),
                Applicability(subject["applicability"]),
            )
            for subject in expected
        )
        if expected
        else (),
        contract_value.get("universe_generation", 0),
    )
    change_set = ChangeSet(
        change_value["change_set_id"],
        change_value["source_revision"],
        change_value["target_revision"],
        change_value["diff_hash"],
        tuple(change_value["paths"]),
        tuple(change_value["deleted_paths"]),
    )
    plan = VerificationPlan(
        plan_value["plan_id"],
        plan_value["acceptance_contract_hash"],
        plan_value["change_set_hash"],
        tuple(plan_value["required_verifier_ids"]),
    )
    evidence = EvidenceBundle(
        evidence_value["bundle_id"],
        evidence_value["acceptance_contract_hash"],
        evidence_value["change_set_hash"],
        evidence_value["verification_plan_hash"],
        tuple(
            Observation(
                row["verifier_id"],
                row["artifact_id"],
                row["artifact_hash"],
                ObservationStatus(row["status"]),
                row.get("logical_subject_id"),
                row.get("evidence_kind"),
            )
            for row in evidence_value["observations"]
        ),
        evidence_value["claimed_bundle_hash"],
    )
    return contract, change_set, plan, evidence


def verify_generic_changeset(payload: Any) -> tuple[int, dict[str, Any]]:
    problem = validate_generic_verification_request(payload)
    if problem is not None:
        code, field = problem
        return (422, _error(code, field))

    contract, change_set, plan, evidence = _domain_objects(payload)
    result = verify(contract, change_set, plan, evidence)
    verification_value: dict[str, Any] = {
        "status": result.status.value,
        "reason_codes": list(result.reason_codes),
        "integrity": result.integrity.value,
    }
    if result.coverage is not None:
        verification_value["coverage"] = result.coverage.to_dict()
    response: dict[str, Any] = {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "schema": GENERIC_VERIFICATION_RESPONSE_SCHEMA_ID,
        "verification": verification_value,
        "hashes": {
            "acceptance_contract_hash": contract.hash,
            "change_set_hash": change_set.hash,
            "verification_plan_hash": plan.hash,
            "evidence_bundle_hash": evidence.hash,
            "change_manifest_hash": change_manifest_hash(payload["change_manifest"]),
        },
        "certification": None,
    }

    policy = payload["certification_policy"]
    if policy is not None:
        certified = certify(
            CertificationInput(
                contract,
                change_set,
                plan,
                evidence,
                policy["accepted"],
                policy["authority_present"],
                policy["approval_present"],
                policy["signing_present"],
            )
        )
        # Defensive equality: public verification is factual truth; certification
        # must not obtain a different factual result through the same Core input.
        if certified.verification.status != result.status or certified.verification.reason_codes != result.reason_codes:
            return (500, _error("CORE_VERIFICATION_DIVERGENCE", "verification"))
        response["certification"] = {
            "disposition": certified.disposition.value,
            "receipt": certified.receipt.to_dict(),
        }

    return (200, response)


__all__ = ["validate_generic_verification_request", "verify_generic_changeset"]
