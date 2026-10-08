"""Canonical Core V1 loopback HTTP runtime and certification service (TG-5).

Names are resolved lazily (PEP 562) so importing a submodule that does not need
aiohttp (for example ``product.runtime.schemas``) does not load the HTTP stack.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from product.runtime.auth import (
        AuthSecurityError as AuthSecurityError,
    )
    from product.runtime.auth import (
        generate_bearer_token as generate_bearer_token,
    )
    from product.runtime.auth import (
        read_bearer_token as read_bearer_token,
    )
    from product.runtime.auth import (
        resolve_token_path as resolve_token_path,
    )
    from product.runtime.auth import (
        validate_auth_header as validate_auth_header,
    )
    from product.runtime.auth import (
        write_secure_token as write_secure_token,
    )
    from product.runtime.http import (
        LoopbackBindError as LoopbackBindError,
    )
    from product.runtime.http import (
        RuntimeHandle as RuntimeHandle,
    )
    from product.runtime.http import (
        create_app as create_app,
    )
    from product.runtime.http import (
        start_runtime as start_runtime,
    )
    from product.runtime.http import (
        stop_runtime as stop_runtime,
    )
    from product.runtime.schemas import (
        CERTIFICATION_REQUEST_SCHEMA as CERTIFICATION_REQUEST_SCHEMA,
    )
    from product.runtime.schemas import (
        HTTP_ERROR_SCHEMA as HTTP_ERROR_SCHEMA,
    )
    from product.runtime.schemas import (
        HTTP_RESPONSE_SCHEMA as HTTP_RESPONSE_SCHEMA,
    )
    from product.runtime.schemas import (
        RECEIPT_VERIFY_REQUEST_SCHEMA as RECEIPT_VERIFY_REQUEST_SCHEMA,
    )
    from product.runtime.schemas import (
        RECEIPT_VERIFY_RESPONSE_SCHEMA as RECEIPT_VERIFY_RESPONSE_SCHEMA,
    )
    from product.runtime.schemas import (
        SCHEMA_BUNDLE as SCHEMA_BUNDLE,
    )
    from product.runtime.schemas import (
        SCHEMA_BUNDLE_HASH as SCHEMA_BUNDLE_HASH,
    )
    from product.runtime.schemas import (
        make_http_error as make_http_error,
    )
    from product.runtime.schemas import (
        make_http_response as make_http_response,
    )
    from product.runtime.schemas import (
        validate_certification_request as validate_certification_request,
    )
    from product.runtime.schemas import (
        validate_receipt_verify_request as validate_receipt_verify_request,
    )
    from product.runtime.service import (
        InFlightJob as InFlightJob,
    )
    from product.runtime.service import (
        RuntimeCertificationService as RuntimeCertificationService,
    )

_EXPORTS = {
    "AuthSecurityError": "product.runtime.auth",
    "generate_bearer_token": "product.runtime.auth",
    "read_bearer_token": "product.runtime.auth",
    "resolve_token_path": "product.runtime.auth",
    "validate_auth_header": "product.runtime.auth",
    "write_secure_token": "product.runtime.auth",
    "LoopbackBindError": "product.runtime.http",
    "RuntimeHandle": "product.runtime.http",
    "create_app": "product.runtime.http",
    "start_runtime": "product.runtime.http",
    "stop_runtime": "product.runtime.http",
    "CERTIFICATION_REQUEST_SCHEMA": "product.runtime.schemas",
    "HTTP_ERROR_SCHEMA": "product.runtime.schemas",
    "HTTP_RESPONSE_SCHEMA": "product.runtime.schemas",
    "RECEIPT_VERIFY_REQUEST_SCHEMA": "product.runtime.schemas",
    "RECEIPT_VERIFY_RESPONSE_SCHEMA": "product.runtime.schemas",
    "SCHEMA_BUNDLE": "product.runtime.schemas",
    "SCHEMA_BUNDLE_HASH": "product.runtime.schemas",
    "make_http_error": "product.runtime.schemas",
    "make_http_response": "product.runtime.schemas",
    "validate_certification_request": "product.runtime.schemas",
    "validate_receipt_verify_request": "product.runtime.schemas",
    "InFlightJob": "product.runtime.service",
    "RuntimeCertificationService": "product.runtime.service",
}

__all__ = [
    "AuthSecurityError",
    "LoopbackBindError",
    "RuntimeHandle",
    "create_app",
    "start_runtime",
    "stop_runtime",
    "generate_bearer_token",
    "read_bearer_token",
    "resolve_token_path",
    "validate_auth_header",
    "write_secure_token",
    "CERTIFICATION_REQUEST_SCHEMA",
    "HTTP_ERROR_SCHEMA",
    "HTTP_RESPONSE_SCHEMA",
    "RECEIPT_VERIFY_REQUEST_SCHEMA",
    "RECEIPT_VERIFY_RESPONSE_SCHEMA",
    "SCHEMA_BUNDLE",
    "SCHEMA_BUNDLE_HASH",
    "make_http_error",
    "make_http_response",
    "validate_certification_request",
    "validate_receipt_verify_request",
    "InFlightJob",
    "RuntimeCertificationService",
]


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value
