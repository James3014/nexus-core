"""Transport-neutral public protocol for runtime and manual handoff readiness.

This module defines wire schemas, canonical hashing rules, and claim ceilings
for handoff readiness evidence. It does not perform verification or certification.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from product.protocol import PUBLIC_PROTOCOL_VERSION
from product.protocol.generic_verification import canonical_hash, canonical_json

RUNTIME_HANDOFF_SCHEMA_ID = "nexus.core.runtime-handoff.v1"
RUNTIME_HANDOFF_RECEIPT_KIND = "NEXUS_CORE_RUNTIME_HANDOFF_RECEIPT"
HANDOFF_CLAIM_CEILING = "MANUAL_TEST_HANDOFF_READY_NOT_RELEASED"

HANDOFF_NON_CLAIMS = (
    "NO_CANDIDATE_ACCEPTANCE",
    "NO_MERGE_AUTHORIZATION",
    "NO_DEPLOYMENT_TRUTH",
    "NO_OUTCOME_TRUTH",
    "NO_PRODUCTION_READINESS",
    "NO_SEMANTIC_BUG_FREEDOM",
)

_HASH_PATTERN = r"^sha256:[0-9a-f]{64}$"
_GIT_COMMIT_PATTERN = r"^git-commit:[0-9a-f]{40}$"
_GIT_TREE_PATTERN = r"^git-tree:[0-9a-f]{40}$"
_HASH_RE = re.compile(_HASH_PATTERN)
_COMMIT_RE = re.compile(_GIT_COMMIT_PATTERN)
_TREE_RE = re.compile(_GIT_TREE_PATTERN)


def is_sha256_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_HASH_RE.match(value))


def is_git_commit_ref(value: Any) -> bool:
    return isinstance(value, str) and bool(_COMMIT_RE.match(value))


def is_git_tree_ref(value: Any) -> bool:
    return isinstance(value, str) and bool(_TREE_RE.match(value))


def runtime_handoff_receipt_hash(receipt_payload: Mapping[str, Any]) -> str:
    """Return canonical sha256 hash of receipt contents excluding receipt_hash itself."""
    filtered = {k: v for k, v in receipt_payload.items() if k != "receipt_hash"}
    return canonical_hash(filtered)


__all__ = [
    "HANDOFF_CLAIM_CEILING",
    "HANDOFF_NON_CLAIMS",
    "PUBLIC_PROTOCOL_VERSION",
    "RUNTIME_HANDOFF_RECEIPT_KIND",
    "RUNTIME_HANDOFF_SCHEMA_ID",
    "canonical_hash",
    "canonical_json",
    "is_git_commit_ref",
    "is_git_tree_ref",
    "is_sha256_hash",
    "runtime_handoff_receipt_hash",
]
