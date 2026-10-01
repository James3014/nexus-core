"""Nexus Core V1 Thin Clients package.

Provides lightweight transport-only client entry points:
- CLI: nexus-certify (product.clients.cli)
- MCP: library adapter (product.clients.mcp)
- GitHub Action: self-hosted runner wrapper (product.clients.github_action)

Candidate provenance is bound to the exact PR head; this module does not mint acceptance truth.
"""

from product.clients.cli import main as cli_main
from product.clients.github_action import run_action
from product.clients.mcp import nexus_certify
from product.clients.nexus_verify import (
    TOOL_DEFINITION as NEXUS_VERIFY_TOOL_DEFINITION,
)
from product.clients.nexus_verify import (
    verify_code_change_evidence,
)

__all__ = [
    "NEXUS_VERIFY_TOOL_DEFINITION",
    "cli_main",
    "nexus_certify",
    "run_action",
    "verify_code_change_evidence",
]
