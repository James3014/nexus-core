"""Transport-neutral public protocol for deterministic Core ChangeSet verification.

This module is deliberately dependency-free with respect to other product layers.
It defines wire schemas, canonical hashing rules, and conformance metadata only.
It does not perform verification or certification.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from product.protocol import PUBLIC_PROTOCOL_VERSION

GENERIC_VERIFICATION_REQUEST_SCHEMA_ID = "nexus.core.generic-verification-request.v1-experimental"
GENERIC_VERIFICATION_RESPONSE_SCHEMA_ID = "nexus.core.generic-verification-response.v1-experimental"
GENERIC_VERIFICATION_ERROR_SCHEMA_ID = "nexus.core.generic-verification-error.v1-experimental"
ACCEPTANCE_CONTRACT_SCHEMA_ID = "nexus.core.acceptance-contract.v1-experimental"
CHANGE_SET_SCHEMA_ID = "nexus.core.change-set.v1-experimental"
VERIFICATION_PLAN_SCHEMA_ID = "nexus.core.verification-plan.v1-experimental"
OBSERVATION_SCHEMA_ID = "nexus.core.observation.v1-experimental"
EVIDENCE_BUNDLE_INPUT_SCHEMA_ID = "nexus.core.evidence-bundle-input.v1-experimental"
CHANGE_MANIFEST_SCHEMA_ID = "nexus.core.git-change-manifest.v1-experimental"
GENERIC_PROTOCOL_DESCRIPTOR_SCHEMA_ID = "nexus.core.generic-verification-protocol.v1-experimental"

_HASH_PATTERN = r"^sha256:[0-9a-f]{64}$"
_GIT_REVISION_PATTERN = r"^git-(?:commit|tree):[0-9a-f]{40}$"
_GIT_TREE_PATTERN = r"^git-tree:[0-9a-f]{40}$"
_GIT_OBJECT_PATTERN = r"^[0-9a-f]{40}$"
_PATH_PATTERN = r"^(?!/)(?!.*\\)(?!.*//)(?!.*(?:^|/)\.\.?/)(?!.*(?:^|/)\.\.?$).+$"
_REVISION_RE = re.compile(_GIT_REVISION_PATTERN)
_GIT_TREE_RE = re.compile(_GIT_TREE_PATTERN)
_HASH_RE = re.compile(_HASH_PATTERN)


def canonical_json(value: Any) -> str:
    """Return the protocol canonical JSON representation.

    The wire rule intentionally matches the Core's existing canonical hashing:
    recursively JSON-compatible values, lexicographically sorted object keys,
    no insignificant whitespace, UTF-8, and no NaN/Infinity.
    """

    def normalize(item: Any) -> Any:
        if item is None or type(item) in (str, int, bool):
            return item
        if type(item) in (list, tuple):
            return [normalize(child) for child in item]
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise TypeError("canonical object keys must be strings")
            return {key: normalize(item[key]) for key in sorted(item)}
        raise TypeError(f"unsupported canonical value: {type(item).__name__}")

    return json.dumps(
        normalize(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def acceptance_contract_canonical_value(value: Mapping[str, Any]) -> list[Any]:
    return [
        value["contract_id"],
        value["requirements_hash"],
        sorted(value["required_verifier_ids"]),
        sorted(value["allowed_paths"]),
        value["deletion_policy"],
    ]


def acceptance_contract_hash(value: Mapping[str, Any]) -> str:
    return canonical_hash(acceptance_contract_canonical_value(value))


def change_set_canonical_value(value: Mapping[str, Any]) -> list[Any]:
    result: list[Any] = [
        value["change_set_id"],
        value["source_revision"],
        value["target_revision"],
        value["diff_hash"],
        sorted(value["paths"]),
    ]
    # Compatibility rule: legacy/no-deletion ChangeSets retain the pre-v1 hash.
    # Deletion-bearing generic ChangeSets bind the deletion set as the sixth item.
    if value["deleted_paths"]:
        result.append(sorted(value["deleted_paths"]))
    return result


def change_set_hash(value: Mapping[str, Any]) -> str:
    return canonical_hash(change_set_canonical_value(value))


def verification_plan_canonical_value(value: Mapping[str, Any]) -> list[Any]:
    return [
        value["plan_id"],
        value["acceptance_contract_hash"],
        value["change_set_hash"],
        sorted(value["required_verifier_ids"]),
    ]


def verification_plan_hash(value: Mapping[str, Any]) -> str:
    return canonical_hash(verification_plan_canonical_value(value))


def evidence_bundle_canonical_value(value: Mapping[str, Any]) -> list[Any]:
    observations = sorted(
        value["observations"], key=lambda row: (row["verifier_id"], row["artifact_id"])
    )
    return [
        value["bundle_id"],
        value["acceptance_contract_hash"],
        value["change_set_hash"],
        value["verification_plan_hash"],
        [
            [row["verifier_id"], row["artifact_id"], row["artifact_hash"], row["status"]]
            for row in observations
        ],
    ]


def evidence_bundle_hash(value: Mapping[str, Any]) -> str:
    return canonical_hash(evidence_bundle_canonical_value(value))


def change_manifest_canonical_value(value: Mapping[str, Any]) -> list[Any]:
    entries = sorted(value["entries"], key=lambda row: row["path"])
    return [
        CHANGE_MANIFEST_SCHEMA_ID,
        value["source_tree"],
        value["target_tree"],
        [
            [
                row["path"],
                row["change_type"],
                row["before_oid"],
                row["after_oid"],
                row["before_mode"],
                row["after_mode"],
            ]
            for row in entries
        ],
    ]


def change_manifest_hash(value: Mapping[str, Any]) -> str:
    return canonical_hash(change_manifest_canonical_value(value))


def is_revision_ref(value: Any) -> bool:
    return type(value) is str and _REVISION_RE.fullmatch(value) is not None


def is_git_tree_ref(value: Any) -> bool:
    return type(value) is str and _GIT_TREE_RE.fullmatch(value) is not None


def is_hash(value: Any) -> bool:
    return type(value) is str and _HASH_RE.fullmatch(value) is not None


_NORMALIZED_TEXT_SCHEMA: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "x-nexus-normalized-text": True,
    "x-nexus-max-utf8-bytes": 512,
}
_PATH_SCHEMA: dict[str, Any] = {
    **_NORMALIZED_TEXT_SCHEMA,
    "pattern": _PATH_PATTERN,
    "x-nexus-repository-relative-path": True,
}
_HASH_SCHEMA: dict[str, Any] = {"type": "string", "pattern": _HASH_PATTERN}
_REVISION_SCHEMA: dict[str, Any] = {"type": "string", "pattern": _GIT_REVISION_PATTERN}
_TREE_SCHEMA: dict[str, Any] = {"type": "string", "pattern": _GIT_TREE_PATTERN}
_OBJECT_SCHEMA: dict[str, Any] = {"type": ["string", "null"], "pattern": _GIT_OBJECT_PATTERN}
_MODE_SCHEMA: dict[str, Any] = {"type": ["string", "null"], "pattern": r"^[0-7]{6}$"}

ACCEPTANCE_CONTRACT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": ACCEPTANCE_CONTRACT_SCHEMA_ID,
    "type": "object",
    "required": [
        "contract_id",
        "requirements_hash",
        "required_verifier_ids",
        "allowed_paths",
        "deletion_policy",
    ],
    "properties": {
        "contract_id": _NORMALIZED_TEXT_SCHEMA,
        "requirements_hash": _HASH_SCHEMA,
        "required_verifier_ids": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": True,
            "items": _NORMALIZED_TEXT_SCHEMA,
        },
        "allowed_paths": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": True,
            "items": _PATH_SCHEMA,
        },
        "deletion_policy": {"type": "string", "enum": ["FORBID", "ALLOW"]},
    },
    "additionalProperties": False,
}

CHANGE_SET_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": CHANGE_SET_SCHEMA_ID,
    "type": "object",
    "required": [
        "change_set_id",
        "source_revision",
        "target_revision",
        "diff_hash",
        "paths",
        "deleted_paths",
    ],
    "properties": {
        "change_set_id": _NORMALIZED_TEXT_SCHEMA,
        "source_revision": _REVISION_SCHEMA,
        "target_revision": _REVISION_SCHEMA,
        "diff_hash": _HASH_SCHEMA,
        "paths": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": True,
            "items": _PATH_SCHEMA,
        },
        "deleted_paths": {
            "type": "array",
            "uniqueItems": True,
            "items": _PATH_SCHEMA,
        },
    },
    "additionalProperties": False,
}

VERIFICATION_PLAN_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": VERIFICATION_PLAN_SCHEMA_ID,
    "type": "object",
    "required": [
        "plan_id",
        "acceptance_contract_hash",
        "change_set_hash",
        "required_verifier_ids",
    ],
    "properties": {
        "plan_id": _NORMALIZED_TEXT_SCHEMA,
        "acceptance_contract_hash": _HASH_SCHEMA,
        "change_set_hash": _HASH_SCHEMA,
        "required_verifier_ids": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": True,
            "items": _NORMALIZED_TEXT_SCHEMA,
        },
    },
    "additionalProperties": False,
}

OBSERVATION_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": OBSERVATION_SCHEMA_ID,
    "type": "object",
    "required": ["verifier_id", "artifact_id", "artifact_hash", "status"],
    "properties": {
        "verifier_id": _NORMALIZED_TEXT_SCHEMA,
        "artifact_id": _NORMALIZED_TEXT_SCHEMA,
        "artifact_hash": _HASH_SCHEMA,
        "status": {"type": "string", "enum": ["PASS", "FAIL"]},
    },
    "additionalProperties": False,
}

EVIDENCE_BUNDLE_INPUT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": EVIDENCE_BUNDLE_INPUT_SCHEMA_ID,
    "type": "object",
    "required": [
        "bundle_id",
        "acceptance_contract_hash",
        "change_set_hash",
        "verification_plan_hash",
        "observations",
        "claimed_bundle_hash",
    ],
    "properties": {
        "bundle_id": _NORMALIZED_TEXT_SCHEMA,
        "acceptance_contract_hash": _HASH_SCHEMA,
        "change_set_hash": _HASH_SCHEMA,
        "verification_plan_hash": _HASH_SCHEMA,
        "observations": {
            "type": "array",
            "minItems": 1,
            "items": OBSERVATION_SCHEMA,
        },
        "claimed_bundle_hash": {"anyOf": [_HASH_SCHEMA, {"type": "null"}]},
    },
    "additionalProperties": False,
}

CHANGE_MANIFEST_ENTRY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "path",
        "change_type",
        "before_oid",
        "after_oid",
        "before_mode",
        "after_mode",
    ],
    "properties": {
        "path": _PATH_SCHEMA,
        "change_type": {"type": "string", "enum": ["ADD", "MODIFY", "DELETE"]},
        "before_oid": _OBJECT_SCHEMA,
        "after_oid": _OBJECT_SCHEMA,
        "before_mode": _MODE_SCHEMA,
        "after_mode": _MODE_SCHEMA,
    },
    "additionalProperties": False,
}

CHANGE_MANIFEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": CHANGE_MANIFEST_SCHEMA_ID,
    "type": "object",
    "required": ["source_tree", "target_tree", "entries"],
    "properties": {
        "source_tree": _TREE_SCHEMA,
        "target_tree": _TREE_SCHEMA,
        "entries": {
            "type": "array",
            "minItems": 1,
            "items": CHANGE_MANIFEST_ENTRY_SCHEMA,
        },
    },
    "additionalProperties": False,
}

_CERTIFICATION_POLICY_SCHEMA: dict[str, Any] = {
    "anyOf": [
        {"type": "null"},
        {
            "type": "object",
            "required": ["accepted", "authority_present", "approval_present", "signing_present"],
            "properties": {
                "accepted": {"type": ["boolean", "null"]},
                "authority_present": {"type": ["boolean", "null"]},
                "approval_present": {"type": ["boolean", "null"]},
                "signing_present": {"type": ["boolean", "null"]},
            },
            "additionalProperties": False,
        },
    ]
}

GENERIC_VERIFICATION_REQUEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": GENERIC_VERIFICATION_REQUEST_SCHEMA_ID,
    "type": "object",
    "required": [
        "protocol_version",
        "schema",
        "acceptance_contract",
        "change_set",
        "change_manifest",
        "verification_plan",
        "evidence_bundle",
        "certification_policy",
    ],
    "properties": {
        "protocol_version": {"type": "string", "const": PUBLIC_PROTOCOL_VERSION},
        "schema": {"type": "string", "const": GENERIC_VERIFICATION_REQUEST_SCHEMA_ID},
        "acceptance_contract": ACCEPTANCE_CONTRACT_SCHEMA,
        "change_set": CHANGE_SET_SCHEMA,
        "change_manifest": CHANGE_MANIFEST_SCHEMA,
        "verification_plan": VERIFICATION_PLAN_SCHEMA,
        "evidence_bundle": EVIDENCE_BUNDLE_INPUT_SCHEMA,
        "certification_policy": _CERTIFICATION_POLICY_SCHEMA,
    },
    "additionalProperties": False,
}

GENERIC_VERIFICATION_ERROR_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": GENERIC_VERIFICATION_ERROR_SCHEMA_ID,
    "type": "object",
    "required": ["protocol_version", "schema", "error"],
    "properties": {
        "protocol_version": {"type": "string", "const": PUBLIC_PROTOCOL_VERSION},
        "schema": {"type": "string", "const": GENERIC_VERIFICATION_ERROR_SCHEMA_ID},
        "error": {
            "type": "object",
            "required": ["code", "field"],
            "properties": {
                "code": {"type": "string", "minLength": 1},
                "field": {"type": "string", "minLength": 1},
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}

GENERIC_VERIFICATION_RESPONSE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": GENERIC_VERIFICATION_RESPONSE_SCHEMA_ID,
    "type": "object",
    "required": [
        "protocol_version",
        "schema",
        "verification",
        "hashes",
        "certification",
    ],
    "properties": {
        "protocol_version": {"type": "string", "const": PUBLIC_PROTOCOL_VERSION},
        "schema": {"type": "string", "const": GENERIC_VERIFICATION_RESPONSE_SCHEMA_ID},
        "verification": {
            "type": "object",
            "required": ["status", "reason_codes", "integrity"],
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["VERIFIED", "FAILED_VERIFICATION", "UNVERIFIABLE"],
                },
                "reason_codes": {"type": "array", "items": {"type": "string"}},
                "integrity": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "hashes": {
            "type": "object",
            "required": [
                "acceptance_contract_hash",
                "change_set_hash",
                "verification_plan_hash",
                "evidence_bundle_hash",
                "change_manifest_hash",
            ],
            "properties": {
                "acceptance_contract_hash": _HASH_SCHEMA,
                "change_set_hash": _HASH_SCHEMA,
                "verification_plan_hash": _HASH_SCHEMA,
                "evidence_bundle_hash": _HASH_SCHEMA,
                "change_manifest_hash": _HASH_SCHEMA,
            },
            "additionalProperties": False,
        },
        "certification": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "required": ["disposition", "receipt"],
                    "properties": {
                        "disposition": {
                            "type": "string",
                            "enum": ["CERTIFIED", "REJECTED", "BLOCKED"],
                        },
                        "receipt": {"type": "object"},
                    },
                    "additionalProperties": False,
                },
            ]
        },
    },
    "additionalProperties": False,
}

GENERIC_PROTOCOL_SCHEMA_BUNDLE: dict[str, dict[str, Any]] = {
    "acceptance_contract": ACCEPTANCE_CONTRACT_SCHEMA,
    "change_set": CHANGE_SET_SCHEMA,
    "change_manifest": CHANGE_MANIFEST_SCHEMA,
    "verification_plan": VERIFICATION_PLAN_SCHEMA,
    "observation": OBSERVATION_SCHEMA,
    "evidence_bundle_input": EVIDENCE_BUNDLE_INPUT_SCHEMA,
    "request": GENERIC_VERIFICATION_REQUEST_SCHEMA,
    "response": GENERIC_VERIFICATION_RESPONSE_SCHEMA,
    "error": GENERIC_VERIFICATION_ERROR_SCHEMA,
}

GENERIC_PROTOCOL_SCHEMA_BUNDLE_HASH = canonical_hash(GENERIC_PROTOCOL_SCHEMA_BUNDLE)

# Hard-coded vectors are filled with stable values and expected hashes. They are
# intentionally data, not executable tests, so non-Python consumers can compare
# their implementation against the same bytes/hashes exposed by the descriptor.
GENERIC_PROTOCOL_CONFORMANCE_VECTORS: dict[str, Any] = {
    "acceptance_contract": {
        "value": {
            "contract_id": "ac-conformance-1",
            "requirements_hash": "sha256:" + "1" * 64,
            "required_verifier_ids": ["lint", "unit"],
            "allowed_paths": ["src/a.py", "tests/test_a.py"],
            "deletion_policy": "FORBID",
        },
        "expected_hash": "sha256:5a97aa6989c3ddf00e08c57327436f626bb0be918844eef0225e276121e21eff",
    },
    "acceptance_contract_unicode": {
        "value": {
            "contract_id": "ac-雪-1",
            "requirements_hash": "sha256:" + "c" * 64,
            "required_verifier_ids": ["lint", "測試"],
            "allowed_paths": ["src/雪.py"],
            "deletion_policy": "ALLOW",
        },
        "expected_hash": "sha256:21face1a76514a320f54660053e4c1e9e51f54ab31f346a599db88a2107174d4",
    },
    "change_set_no_deletion": {
        "value": {
            "change_set_id": "cs-conformance-1",
            "source_revision": "git-commit:" + "2" * 40,
            "target_revision": "git-tree:" + "3" * 40,
            "diff_hash": "sha256:" + "4" * 64,
            "paths": ["src/a.py"],
            "deleted_paths": [],
        },
        "expected_hash": "sha256:6a5d849712b409d4a30a30b50138ddd840847ae4aaf4c1916108e6711fae594c",
    },
    "change_set_with_deletion": {
        "value": {
            "change_set_id": "cs-conformance-2",
            "source_revision": "git-commit:" + "2" * 40,
            "target_revision": "git-tree:" + "5" * 40,
            "diff_hash": "sha256:" + "6" * 64,
            "paths": ["src/a.py", "src/old.py"],
            "deleted_paths": ["src/old.py"],
        },
        "expected_hash": "sha256:ffa70fd13cb1651d951437c0fc8006e5e3888f81115d2c40d96a56b0d4cde39f",
    },
    "verification_plan": {
        "value": {
            "plan_id": "vp-conformance-1",
            "acceptance_contract_hash": "sha256:5a97aa6989c3ddf00e08c57327436f626bb0be918844eef0225e276121e21eff",
            "change_set_hash": "sha256:6a5d849712b409d4a30a30b50138ddd840847ae4aaf4c1916108e6711fae594c",
            "required_verifier_ids": ["lint", "unit"],
        },
        "expected_hash": "sha256:3e1e5d25ac55d605cf52620f658cb8bd399f501e85caac9cc2e6a7814c4a73c9",
    },
    "evidence_bundle": {
        "value": {
            "bundle_id": "eb-conformance-1",
            "acceptance_contract_hash": "sha256:5a97aa6989c3ddf00e08c57327436f626bb0be918844eef0225e276121e21eff",
            "change_set_hash": "sha256:6a5d849712b409d4a30a30b50138ddd840847ae4aaf4c1916108e6711fae594c",
            "verification_plan_hash": "sha256:3e1e5d25ac55d605cf52620f658cb8bd399f501e85caac9cc2e6a7814c4a73c9",
            "observations": [
                {
                    "verifier_id": "unit",
                    "artifact_id": "art-unit",
                    "artifact_hash": "sha256:" + "d" * 64,
                    "status": "PASS",
                },
                {
                    "verifier_id": "lint",
                    "artifact_id": "art-lint",
                    "artifact_hash": "sha256:" + "e" * 64,
                    "status": "PASS",
                },
            ],
            "claimed_bundle_hash": None,
        },
        "expected_hash": "sha256:f245f85800e26e13af723108c56c1eeb0d4b6e801e1cef5b1c35d694a1e93113",
    },
    "change_manifest": {
        "value": {
            "source_tree": "git-tree:" + "7" * 40,
            "target_tree": "git-tree:" + "8" * 40,
            "entries": [
                {
                    "path": "src/a.py",
                    "change_type": "MODIFY",
                    "before_oid": "9" * 40,
                    "after_oid": "a" * 40,
                    "before_mode": "100644",
                    "after_mode": "100644",
                },
                {
                    "path": "src/old.py",
                    "change_type": "DELETE",
                    "before_oid": "b" * 40,
                    "after_oid": None,
                    "before_mode": "100644",
                    "after_mode": None,
                },
            ],
        },
        "expected_hash": "sha256:74fe182f5f886cbe1f2df82f0fe7efaaeac868cb8e27353380ff1e0023711fcf",
    },
}


def _request_conformance_vector() -> dict[str, Any]:
    manifest = {
        "source_tree": "git-tree:" + "a" * 40,
        "target_tree": "git-tree:" + "b" * 40,
        "entries": [
            {
                "path": "src/a.py",
                "change_type": "MODIFY",
                "before_oid": "1" * 40,
                "after_oid": "2" * 40,
                "before_mode": "100644",
                "after_mode": "100644",
            }
        ],
    }
    contract = {
        "contract_id": "ac-request-vector-1",
        "requirements_hash": "sha256:" + "c" * 64,
        "required_verifier_ids": ["unit"],
        "allowed_paths": ["src/a.py"],
        "deletion_policy": "FORBID",
    }
    change_set = {
        "change_set_id": "cs-request-vector-1",
        "source_revision": "git-commit:" + "d" * 40,
        "target_revision": manifest["target_tree"],
        "diff_hash": change_manifest_hash(manifest),
        "paths": ["src/a.py"],
        "deleted_paths": [],
    }
    plan = {
        "plan_id": "vp-request-vector-1",
        "acceptance_contract_hash": acceptance_contract_hash(contract),
        "change_set_hash": change_set_hash(change_set),
        "required_verifier_ids": ["unit"],
    }
    evidence = {
        "bundle_id": "eb-request-vector-1",
        "acceptance_contract_hash": plan["acceptance_contract_hash"],
        "change_set_hash": plan["change_set_hash"],
        "verification_plan_hash": verification_plan_hash(plan),
        "observations": [
            {
                "verifier_id": "unit",
                "artifact_id": "artifact-request-vector-1",
                "artifact_hash": "sha256:" + "e" * 64,
                "status": "PASS",
            }
        ],
        "claimed_bundle_hash": None,
    }
    return {
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "schema": GENERIC_VERIFICATION_REQUEST_SCHEMA_ID,
        "acceptance_contract": contract,
        "change_set": change_set,
        "change_manifest": manifest,
        "verification_plan": plan,
        "evidence_bundle": evidence,
        "certification_policy": None,
    }


GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR = _request_conformance_vector()

GENERIC_PROTOCOL_ORDERING_CONFORMANCE_VECTORS: dict[str, Any] = {
    "json_object_field_order": {
        "left": {"b": 2, "a": 1},
        "right": {"a": 1, "b": 2},
        "expected_canonical_json": '{"a":1,"b":2}',
        "expected_hash": "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
    },
    "acceptance_path_and_verifier_order": {
        "left": {
            "contract_id": "ac-order-vector-1",
            "requirements_hash": "sha256:" + "f" * 64,
            "required_verifier_ids": ["lint", "unit"],
            "allowed_paths": ["src/a.py", "tests/test_a.py"],
            "deletion_policy": "FORBID",
        },
        "right": {
            "deletion_policy": "FORBID",
            "allowed_paths": ["tests/test_a.py", "src/a.py"],
            "required_verifier_ids": ["unit", "lint"],
            "requirements_hash": "sha256:" + "f" * 64,
            "contract_id": "ac-order-vector-1",
        },
    },
    "evidence_observation_order": {
        "left": {
            "bundle_id": "eb-order-vector-1",
            "acceptance_contract_hash": "sha256:" + "1" * 64,
            "change_set_hash": "sha256:" + "2" * 64,
            "verification_plan_hash": "sha256:" + "3" * 64,
            "observations": [
                {
                    "verifier_id": "unit",
                    "artifact_id": "artifact-unit",
                    "artifact_hash": "sha256:" + "4" * 64,
                    "status": "PASS",
                },
                {
                    "verifier_id": "lint",
                    "artifact_id": "artifact-lint",
                    "artifact_hash": "sha256:" + "5" * 64,
                    "status": "PASS",
                },
            ],
            "claimed_bundle_hash": None,
        },
        "right": {
            "claimed_bundle_hash": None,
            "observations": [
                {
                    "status": "PASS",
                    "artifact_hash": "sha256:" + "5" * 64,
                    "artifact_id": "artifact-lint",
                    "verifier_id": "lint",
                },
                {
                    "status": "PASS",
                    "artifact_hash": "sha256:" + "4" * 64,
                    "artifact_id": "artifact-unit",
                    "verifier_id": "unit",
                },
            ],
            "verification_plan_hash": "sha256:" + "3" * 64,
            "change_set_hash": "sha256:" + "2" * 64,
            "acceptance_contract_hash": "sha256:" + "1" * 64,
            "bundle_id": "eb-order-vector-1",
        },
    },
}

GENERIC_PROTOCOL_NEGATIVE_CONFORMANCE_VECTORS: dict[str, Any] = {
    "invalid_path": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/allowed_paths",
        "value": ["../escape.py"],
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.allowed_paths"},
    },
    "invalid_deletion_policy": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/deletion_policy",
        "value": "MAYBE",
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.deletion_policy"},
    },
    "malformed_hash": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/requirements_hash",
        "value": "sha256:not-a-hash",
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.requirements_hash"},
    },
    "duplicate_verifier_ids": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/required_verifier_ids",
        "value": ["unit", "unit"],
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.required_verifier_ids"},
    },
    "padded_identifier": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/contract_id",
        "value": " ac-request-vector-1 ",
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.contract_id"},
    },
    "overlong_utf8_identifier": {
        "base": "generic_request",
        "replace_pointer": "/acceptance_contract/contract_id",
        "value": "雪" * 171,
        "expected_http_status": 422,
        "expected_error": {"code": "MALFORMED_REQUEST", "field": "acceptance_contract.contract_id"},
    },
}

GENERIC_PROTOCOL_VALIDATION_CONSTRAINTS: dict[str, Any] = {
    "normalized_text": {
        "nonblank": True,
        "leading_or_trailing_strip_characters_forbidden": True,
        "nul_forbidden": True,
        "max_utf8_bytes": 512,
        "normative_rule": "type(value) is str and bool(value) and value == value.strip() and NUL not in value and len(value.encode('utf-8')) <= 512",
    },
    "repository_relative_path": {
        "inherits": "normalized_text",
        "absolute_forbidden": True,
        "backslash_forbidden": True,
        "empty_segment_forbidden": True,
        "dot_segment_forbidden": True,
        "dotdot_segment_forbidden": True,
    },
}



def protocol_descriptor() -> dict[str, Any]:
    return {
        "schema": GENERIC_PROTOCOL_DESCRIPTOR_SCHEMA_ID,
        "protocol_version": PUBLIC_PROTOCOL_VERSION,
        "schema_bundle_hash": GENERIC_PROTOCOL_SCHEMA_BUNDLE_HASH,
        "schemas": GENERIC_PROTOCOL_SCHEMA_BUNDLE,
        "canonicalization": {
            "encoding": "utf-8",
            "ensure_ascii": True,
            "json_object_keys": "lexicographic",
            "json_separators": [",", ":"],
            "allow_nan": False,
            "revision_refs": ["git-commit:<40-lowercase-hex>", "git-tree:<40-lowercase-hex>"],
            "change_set_hash_compatibility": (
                "deleted_paths omitted from the canonical hash only when the deletion set is empty; "
                "non-empty deleted_paths is the sixth canonical tuple/list item"
            ),
            "diff_hash": "sha256 of canonical nexus.core.git-change-manifest.v1-experimental value",
        },
        "conformance_vectors": GENERIC_PROTOCOL_CONFORMANCE_VECTORS,
        "request_conformance_vector": GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR,
        "ordering_conformance_vectors": GENERIC_PROTOCOL_ORDERING_CONFORMANCE_VECTORS,
        "negative_conformance_vectors": GENERIC_PROTOCOL_NEGATIVE_CONFORMANCE_VECTORS,
        "validation_constraints": GENERIC_PROTOCOL_VALIDATION_CONSTRAINTS,
    }


__all__ = [
    "ACCEPTANCE_CONTRACT_SCHEMA",
    "CHANGE_MANIFEST_SCHEMA",
    "CHANGE_MANIFEST_SCHEMA_ID",
    "CHANGE_SET_SCHEMA",
    "EVIDENCE_BUNDLE_INPUT_SCHEMA",
    "GENERIC_PROTOCOL_CONFORMANCE_VECTORS",
    "GENERIC_PROTOCOL_NEGATIVE_CONFORMANCE_VECTORS",
    "GENERIC_PROTOCOL_ORDERING_CONFORMANCE_VECTORS",
    "GENERIC_PROTOCOL_REQUEST_CONFORMANCE_VECTOR",
    "GENERIC_PROTOCOL_VALIDATION_CONSTRAINTS",
    "GENERIC_PROTOCOL_DESCRIPTOR_SCHEMA_ID",
    "GENERIC_PROTOCOL_SCHEMA_BUNDLE",
    "GENERIC_PROTOCOL_SCHEMA_BUNDLE_HASH",
    "GENERIC_VERIFICATION_ERROR_SCHEMA",
    "GENERIC_VERIFICATION_ERROR_SCHEMA_ID",
    "GENERIC_VERIFICATION_REQUEST_SCHEMA",
    "GENERIC_VERIFICATION_REQUEST_SCHEMA_ID",
    "GENERIC_VERIFICATION_RESPONSE_SCHEMA",
    "GENERIC_VERIFICATION_RESPONSE_SCHEMA_ID",
    "OBSERVATION_SCHEMA",
    "VERIFICATION_PLAN_SCHEMA",
    "acceptance_contract_hash",
    "canonical_hash",
    "canonical_json",
    "change_manifest_hash",
    "change_set_hash",
    "evidence_bundle_hash",
    "is_git_tree_ref",
    "is_hash",
    "is_revision_ref",
    "protocol_descriptor",
    "verification_plan_hash",
]
