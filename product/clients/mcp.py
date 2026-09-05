"""Nexus Core V1 MCP Library Adapter.

Host-projected library adapter exposing nexus_certify tool contract (TG-6).
Pure HTTP transport adapter; adds no MCP daemon dependency and owns no trust/completion logic.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from product.runtime.auth import read_bearer_token
from product.runtime.schemas import (
    CERTIFICATION_REQUEST_SCHEMA,
    HTTP_RESPONSE_SCHEMA,
    SCHEMA_BUNDLE_HASH,
    validate_certification_request,
)

TOOL_NAME: str = "nexus_certify"
TOOL_DESCRIPTION: str = "Certify a pull request changeset via canonical Nexus Core HTTP runtime"
INPUT_SCHEMA: dict[str, Any] = CERTIFICATION_REQUEST_SCHEMA
OUTPUT_SCHEMA: dict[str, Any] = HTTP_RESPONSE_SCHEMA

TOOL_DEFINITION: dict[str, Any] = {
    "name": TOOL_NAME,
    "description": TOOL_DESCRIPTION,
    "inputSchema": INPUT_SCHEMA,
    "outputSchema": OUTPUT_SCHEMA,
    "schema_bundle_hash": SCHEMA_BUNDLE_HASH,
}

DEFAULT_SERVICE_URL = "http://127.0.0.1:8767"
HEADER_READ_TIMEOUT_SECONDS = 10.0
CERTIFICATION_WAIT_TIMEOUT_SECONDS = 330.0
POLL_INTERVAL_SECONDS = 0.5


def _send_http(
    http_transport: Any,
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Execute HTTP call via custom transport or standard urllib."""
    if http_transport is not None:
        if callable(http_transport):
            try:
                res = http_transport(method=method, url=url, headers=headers, json=payload)
            except TypeError:
                res = http_transport(method, url, headers, payload)
        elif hasattr(http_transport, "request"):
            res = http_transport.request(method, url, headers=headers, json=payload)
        elif method.upper() == "POST" and hasattr(http_transport, "post"):
            res = http_transport.post(url, headers=headers, json=payload)
        elif method.upper() == "GET" and hasattr(http_transport, "get"):
            res = http_transport.get(url, headers=headers)
        else:
            raise ValueError(f"unsupported http_transport object: {type(http_transport)}")

        # Extract status and payload
        if isinstance(res, tuple) and len(res) == 2:
            return res[0], res[1]
        if isinstance(res, dict):
            status = res.get("status_code", 200)
            return status, res
        if hasattr(res, "status_code"):
            status = getattr(res, "status_code")
            data = res.json() if callable(getattr(res, "json", None)) else getattr(res, "json")
            return status, data
        raise ValueError(f"unexpected response format from http_transport: {res}")

    # Standard urllib default
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=HEADER_READ_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            raw = response.read().decode("utf-8")
            data = json.loads(raw) if raw else {}
            return status, data
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read().decode("utf-8", errors="ignore")
        data = json.loads(raw) if raw else {}
        return status, data
    except Exception as exc:
        raise ConnectionError(f"HTTP transport failed: {exc}") from exc


def nexus_certify(
    arguments: dict[str, Any],
    http_transport: Any = None,
    service_url: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Callable MCP tool contract for Nexus Core certification.

    Only effect is canonical HTTP transport; cannot construct trust or disposition locally.
    """
    errs = validate_certification_request(arguments)
    if errs:
        raise ValueError(f"invalid certification request arguments: {'; '.join(errs)}")

    url = (service_url or os.environ.get("NEXUS_SERVICE_URL") or DEFAULT_SERVICE_URL).rstrip("/")
    if token is None:
        token_file = os.environ.get("NEXUS_TOKEN_FILE")
        try:
            token = read_bearer_token(token_file)
        except Exception:
            token = ""

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    status, resp = _send_http(
        http_transport=http_transport,
        method="POST",
        url=f"{url}/v1/certifications",
        headers=headers,
        payload=arguments,
    )

    if status not in (200, 202):
        return resp

    state = resp.get("state")
    if status == 200 or state in ("COMPLETED", "FAILED", "UNVERIFIABLE"):
        return resp

    req_id = resp.get("request_id")
    if not req_id:
        return resp

    deadline = time.time() + CERTIFICATION_WAIT_TIMEOUT_SECONDS
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_SECONDS)
        st_code, st_resp = _send_http(
            http_transport=http_transport,
            method="GET",
            url=f"{url}/v1/certifications/{req_id}",
            headers=headers,
            payload=None,
        )
        if st_code != 200:
            return st_resp
        cur_state = st_resp.get("state")
        if cur_state in ("COMPLETED", "FAILED", "UNVERIFIABLE"):
            return st_resp

    return resp
