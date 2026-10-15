# pyright: strict, reportUnnecessaryIsInstance=false, reportUnnecessaryComparison=false
PUBLIC_PROTOCOL_VERSION = "0.1.0-experimental"
IMPLEMENTATION_SCHEMA = "nexus.changeset_certification.v2"
EVIDENCE_BUNDLE_SCHEMA = "nexus.evidence_bundle.v1-experimental"
CERTIFICATION_RECEIPT_SCHEMA = "nexus.certification_receipt.v1-experimental"
PROVENANCE_ENVELOPE_SCHEMA = "product.evidence.provenance.v1"
INGESTION_RECEIPT_SCHEMA = "nexus.ingestion_receipt.v1-experimental"
EVIDENCE_REQUIREMENT_SCHEMA = "nexus.evidence_requirement.v2-experimental"
RUNTIME_HANDOFF_SCHEMA = "nexus.core.runtime-handoff.v1"

# Git-free Core build identity (#267). build_identity is a leaf module.
from product.protocol.build_identity import (  # noqa: E402
    CORE_IDENTITY_SCHEMA_ID,
    core_identity,
    source_digest,
)

__all__ = [
    "PUBLIC_PROTOCOL_VERSION",
    "IMPLEMENTATION_SCHEMA",
    "EVIDENCE_BUNDLE_SCHEMA",
    "CERTIFICATION_RECEIPT_SCHEMA",
    "PROVENANCE_ENVELOPE_SCHEMA",
    "INGESTION_RECEIPT_SCHEMA",
    "EVIDENCE_REQUIREMENT_SCHEMA",
    "RUNTIME_HANDOFF_SCHEMA",
    "CORE_IDENTITY_SCHEMA_ID",
    "core_identity",
    "source_digest",
]
