"""Runtime facade for handoff evidence validation.

This module exposes handoff evidence validation to carrying layers and client shells
without violating the Architecture Boundary.
"""

from __future__ import annotations

from typing import Any, Mapping

from product.evidence.runtime_handoff import validate_handoff_evidence_envelope


def validate_runtime_handoff_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate handoff payload against Core Evidence Trust authority."""
    return validate_handoff_evidence_envelope(payload)


__all__ = ["validate_runtime_handoff_payload"]
