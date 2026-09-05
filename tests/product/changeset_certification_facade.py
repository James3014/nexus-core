"""Compatibility facade for the v2 ChangeSet certification adapter."""

from product.adapters.changeset_certification_v2 import (
    CHANGESET_CERTIFICATION_SCHEMA as CHANGESET_CERTIFICATION_SCHEMA,
)
from product.adapters.changeset_certification_v2 import (
    CHANGESET_CERTIFICATION_VERSION as CHANGESET_CERTIFICATION_VERSION,
)
from product.adapters.changeset_certification_v2 import (
    CLAIM_CEILING as CLAIM_CEILING,
)
from product.adapters.changeset_certification_v2 import (
    LEGACY_CHANGESET_CERTIFICATION_SCHEMA as LEGACY_CHANGESET_CERTIFICATION_SCHEMA,
)
from product.adapters.changeset_certification_v2 import (
    LEGACY_CHANGESET_CERTIFICATION_VERSION as LEGACY_CHANGESET_CERTIFICATION_VERSION,
)
from product.adapters.changeset_certification_v2 import (
    CertificationStatus as CertificationStatus,
)
from product.adapters.changeset_certification_v2 import (
    ChangeSetCertification as ChangeSetCertification,
)
from product.adapters.changeset_certification_v2 import (
    ChangeSetIdentity as ChangeSetIdentity,
)
from product.adapters.changeset_certification_v2 import (
    EvidenceRef as EvidenceRef,
)
from product.adapters.changeset_certification_v2 import (
    VerificationResult as VerificationResult,
)
from product.adapters.changeset_certification_v2 import (
    VerificationStatus as VerificationStatus,
)
from product.adapters.changeset_certification_v2 import (
    build_changeset_certification as build_changeset_certification,
)
from product.adapters.changeset_certification_v2 import (
    canonical_hash as canonical_hash,
)
from product.adapters.changeset_certification_v2 import (
    canonical_json as canonical_json,
)
from product.adapters.changeset_certification_v2 import (
    certify_changeset as certify_changeset,
)
from product.adapters.changeset_certification_v2 import (
    derive_verification_result as derive_verification_result,
)
from product.adapters.changeset_certification_v2 import (
    validate_changeset_certification as validate_changeset_certification,
)

__all__ = [
    "CLAIM_CEILING",
    "CHANGESET_CERTIFICATION_SCHEMA",
    "CHANGESET_CERTIFICATION_VERSION",
    "LEGACY_CHANGESET_CERTIFICATION_SCHEMA",
    "LEGACY_CHANGESET_CERTIFICATION_VERSION",
    "CertificationStatus",
    "ChangeSetCertification",
    "ChangeSetIdentity",
    "EvidenceRef",
    "VerificationResult",
    "VerificationStatus",
    "build_changeset_certification",
    "canonical_hash",
    "canonical_json",
    "certify_changeset",
    "derive_verification_result",
    "validate_changeset_certification",
]
