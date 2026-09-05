"""Bounded compatibility adapter for legacy evidence values."""

from dataclasses import dataclass

from product.evidence.ingestion import (
    EvidenceSubmission,  # noqa: F401
    IngestionResult,  # noqa: F401
    IntegrityStatus,  # noqa: F401
    TrustedIngestionContext,  # noqa: F401
    _parse_time,  # noqa: F401
    classify_ingestion_result,  # noqa: F401
    ingest_evidence,  # noqa: F401
    is_trusted_ingestion_result,  # noqa: F401
)


@dataclass(frozen=True)
class LegacyAdapterResult:
    ingestion: IngestionResult | None
    fallback_integrity: IntegrityStatus | None
    reasons: tuple[str, ...]


def adapt_legacy_evidence(context: TrustedIngestionContext, value: object) -> LegacyAdapterResult:
    if type(value) is EvidenceSubmission:
        return LegacyAdapterResult(ingest_evidence(context, (value,)), None, ())
    if type(value) is str:
        return LegacyAdapterResult(
            None, IntegrityStatus.LEGACY_NON_CERTIFIABLE, ("LEGACY_NARRATIVE_NON_CERTIFIABLE",)
        )
    return LegacyAdapterResult(None, IntegrityStatus.MALFORMED, ("LEGACY_STRUCTURED_MALFORMED",))


__all__ = ["LegacyAdapterResult", "adapt_legacy_evidence"]
