"""Execution request/response ports and the deterministic Python profile."""

from dataclasses import dataclass

from product.protocol import IMPLEMENTATION_SCHEMA, PUBLIC_PROTOCOL_VERSION


@dataclass(frozen=True)
class ExecutionRequest:
    operation: str
    protocol_version: str = PUBLIC_PROTOCOL_VERSION
    implementation_schema: str = IMPLEMENTATION_SCHEMA


@dataclass(frozen=True)
class ExecutionResponse:
    observations: tuple[object, ...]


# Keep the small port types available from the package root while the concrete
# profile remains in its own module.  The import is deliberately last: the
# runner only depends on stdlib and these two immutable port types.
from product.execution.python_runner import (  # noqa: E402
    ExecutionAttempt,
    PythonOCIProfile,
    PythonOCIRunner,
    RunnerResult,
    RunnerStatus,
)

__all__ = [
    "ExecutionRequest",
    "ExecutionResponse",
    "ExecutionAttempt",
    "PythonOCIProfile",
    "PythonOCIRunner",
    "RunnerResult",
    "RunnerStatus",
]
