"""Canonical aiohttp loopback server implementation for Nexus Core HTTP runtime (TG-5)."""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from aiohttp import web

from product.ledger import resolve_ledger_path, verify_chain
from product.runtime.auth import (
    create_auth_middleware,
    read_bearer_token,
)
from product.runtime.schemas import (
    make_http_error,
)
from product.runtime.service import RuntimeCertificationService

MAX_REQUEST_BODY_BYTES = 1_048_576  # 1 MB
MAX_PATH_BYTES = 512
MAX_ID_BYTES = 128
HEADER_READ_TIMEOUT_SECONDS = 10.0
DEFAULT_DRAIN_TIMEOUT_SECONDS = 30.0

logger = logging.getLogger(__name__)


class LoopbackBindError(ValueError):
    """Raised when bind address is not strictly a loopback interface."""


def _is_loopback(host: str) -> bool:
    """Verify that host string is strictly loopback (reject 0.0.0.0, ::, public IPs)."""
    if host.lower() in {"localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False


def _limits_middleware() -> Callable[[web.Request, Callable[[web.Request], Any]], Any]:
    """Enforce path length, body size limits, and canonical error envelope."""

    @web.middleware
    async def limits_middleware(
        request: web.Request,
        handler: Callable[[web.Request], Any],
    ) -> web.Response:
        # Check path length
        path_bytes = len(request.path.encode("utf-8"))
        if path_bytes > MAX_PATH_BYTES:
            return web.json_response(
                make_http_error(
                    code="MALFORMED_REQUEST",
                    request_id=None,
                    message="request path exceeds maximum length of 512 bytes",
                ),
                status=400,
            )

        # Check content length before reading body
        if request.content_length is not None and request.content_length > MAX_REQUEST_BODY_BYTES:
            return web.json_response(
                make_http_error(
                    code="REQUEST_TOO_LARGE",
                    request_id=None,
                    message=f"request payload exceeds maximum limit of {MAX_REQUEST_BODY_BYTES} bytes",
                ),
                status=413,
            )

        try:
            return await handler(request)
        except web.HTTPMethodNotAllowed:
            return web.json_response(
                make_http_error(
                    code="METHOD_NOT_ALLOWED",
                    request_id=None,
                    message=f"HTTP method {request.method} is not supported for this path",
                ),
                status=405,
            )
        except web.HTTPNotFound:
            return web.json_response(
                make_http_error(
                    code="ROUTE_NOT_FOUND",
                    request_id=None,
                    message=f"path {request.path} not found",
                ),
                status=404,
            )

    return limits_middleware


SERVICE_APP_KEY: web.AppKey[RuntimeCertificationService] = web.AppKey("service")


def create_app(
    service: RuntimeCertificationService,
    bearer_token: str,
) -> web.Application:
    """Create canonical aiohttp application with route handlers and middleware without listening."""
    app = web.Application(
        client_max_size=MAX_REQUEST_BODY_BYTES,
        middlewares=[
            create_auth_middleware(bearer_token),
            _limits_middleware(),
        ],
    )
    app[SERVICE_APP_KEY] = service

    async def handle_post_certifications(request: web.Request) -> web.Response:
        if not request.content_type or "application/json" not in request.content_type:
            return web.json_response(
                make_http_error(
                    code="UNSUPPORTED_MEDIA_TYPE",
                    request_id=None,
                    message="Content-Type must be application/json",
                ),
                status=415,
            )
        try:
            body = await request.read()
            if len(body) > MAX_REQUEST_BODY_BYTES:
                return web.json_response(
                    make_http_error(
                        code="REQUEST_TOO_LARGE",
                        request_id=None,
                        message="request body exceeds 1 MB",
                    ),
                    status=413,
                )
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return web.json_response(
                make_http_error(
                    code="MALFORMED_REQUEST",
                    request_id=None,
                    message="malformed JSON body",
                ),
                status=400,
            )

        status_code, resp = await service.submit_certification(payload)
        return web.json_response(resp, status=status_code)

    async def handle_get_status(request: web.Request) -> web.Response:
        req_id = request.match_info["request_id"]
        if len(req_id.encode("utf-8")) > MAX_ID_BYTES:
            return web.json_response(
                make_http_error(
                    code="MALFORMED_REQUEST",
                    request_id=None,
                    message="request ID exceeds maximum allowed length",
                ),
                status=400,
            )
        status_code, resp = await service.get_status(req_id)
        return web.json_response(resp, status=status_code)

    async def handle_get_receipt(request: web.Request) -> web.Response:
        req_id = request.match_info["request_id"]
        if len(req_id.encode("utf-8")) > MAX_ID_BYTES:
            return web.json_response(
                make_http_error(
                    code="MALFORMED_REQUEST",
                    request_id=None,
                    message="request ID exceeds maximum allowed length",
                ),
                status=400,
            )
        status_code, resp = await service.get_receipt(req_id)
        return web.json_response(resp, status=status_code)

    async def handle_verify_receipt(request: web.Request) -> web.Response:
        if not request.content_type or "application/json" not in request.content_type:
            return web.json_response(
                make_http_error(
                    code="UNSUPPORTED_MEDIA_TYPE",
                    request_id=None,
                    message="Content-Type must be application/json",
                ),
                status=415,
            )
        try:
            body = await request.read()
            if len(body) > MAX_REQUEST_BODY_BYTES:
                return web.json_response(
                    make_http_error(
                        code="REQUEST_TOO_LARGE",
                        request_id=None,
                        message="request body exceeds 1 MB",
                    ),
                    status=413,
                )
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return web.json_response(
                make_http_error(
                    code="MALFORMED_REQUEST",
                    request_id=None,
                    message="malformed JSON body",
                ),
                status=400,
            )

        status_code, resp = await service.verify_receipt(payload)
        return web.json_response(resp, status=status_code)

    # Register canonical four routes
    app.router.add_post("/v1/certifications", handle_post_certifications)
    app.router.add_get("/v1/certifications/{request_id}", handle_get_status)
    app.router.add_get("/v1/certifications/{request_id}/receipt", handle_get_receipt)
    app.router.add_post("/v1/receipts/verify", handle_verify_receipt)

    return app


@dataclass
class RuntimeHandle:
    host: str
    port: int
    app: web.Application
    runner: web.AppRunner
    site: web.TCPSite
    service: RuntimeCertificationService
    token: str

    async def stop(self, timeout: float = DEFAULT_DRAIN_TIMEOUT_SECONDS) -> None:
        """Stop runtime safely."""
        await stop_runtime(self, timeout=timeout)


async def start_runtime(
    host: str = "127.0.0.1",
    port: int = 8767,
    *,
    token_path: Path | str | None = None,
    db_path: Path | str | None = None,
    service: Optional[RuntimeCertificationService] = None,
    github_port: Any = None,
    runner_executor: Any = None,
) -> RuntimeHandle:
    """Start the Core V1 canonical HTTP runtime.

    Preflights:
    - Verifies bind address is strictly loopback (rejects 0.0.0.0, non-loopback).
    - Preflights bearer token source (mode 0600 file, mode 0700 dir, UID ownership, 43 chars).
    - Preflights SQLite ledger storage (creates table/triggers, tests connection).
    - Binds only after all preflights succeed.
    """
    if not _is_loopback(host):
        raise LoopbackBindError(
            f"host {host} is not a valid loopback address; only 127.0.0.1/localhost is allowed"
        )

    # Preflight token
    token = read_bearer_token(token_path)

    # Preflight ledger
    ledger_resolved = resolve_ledger_path(db_path)
    # verify_chain creates tables and verifies existing ledger state
    chain_res = verify_chain(db_path=ledger_resolved)
    if not chain_res.valid:
        raise ValueError(f"ledger preflight failed: {chain_res.status} - {chain_res.error_reason}")

    # Create service if not supplied
    if service is None:
        service = RuntimeCertificationService(
            db_path=ledger_resolved,
            github_port=github_port,
            runner_executor=runner_executor,
        )

    app = create_app(service, token)
    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, host=host, port=port)
    await site.start()

    # If port=0 was passed, query the assigned port from server socket
    assigned_port = port
    if port == 0:
        server = site._server
        if server and server.sockets:
            assigned_port = server.sockets[0].getsockname()[1]

    return RuntimeHandle(
        host=host,
        port=assigned_port,
        app=app,
        runner=runner,
        site=site,
        service=service,
        token=token,
    )


async def stop_runtime(
    handle: RuntimeHandle,
    timeout: float = DEFAULT_DRAIN_TIMEOUT_SECONDS,
) -> None:
    """Stop runtime gracefully: drain in-flight, close site and runner without leaked processes/ports."""
    # 1. Drain service requests
    await handle.service.drain(timeout=timeout)

    # 2. Stop site and cleanup runner
    try:
        await handle.site.stop()
    except Exception:
        pass
    try:
        await handle.runner.cleanup()
    except Exception:
        pass


__all__ = [
    "LoopbackBindError",
    "RuntimeHandle",
    "create_app",
    "start_runtime",
    "stop_runtime",
]
