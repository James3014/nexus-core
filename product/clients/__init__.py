"""Nexus Core V1 Thin Clients package.

Intentionally exports nothing eagerly: the Golden Path commands must import with
only the standard library. Import submodules explicitly:
- product.clients.cli (nexus-certify)
- product.clients.mcp, product.clients.github_action, product.clients.nexus_verify
"""
