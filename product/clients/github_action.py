"""Nexus Core V1 GitHub Action Wrapper.

Encapsulates GitHub Action execution on self-hosted runners (TG-6).
Requires RUNNER_ENVIRONMENT=self-hosted and loopback URL.
Exits HOSTED_RUNNER_FORBIDDEN / 78 before reading token on any violation.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

from product.clients.cli import _get_token, _make_http_request, _map_http_status_to_exit_code
from product.runtime.schemas import (
    validate_certification_request,
)

DEFAULT_URL = "http://127.0.0.1:8767"
HEADER_READ_TIMEOUT_SECONDS = 10.0
CERTIFICATION_WAIT_TIMEOUT_SECONDS = 330.0
POLL_INTERVAL_SECONDS = 0.5


def _is_loopback(host: str) -> bool:
    """Verify that host string is strictly loopback interface."""
    if host.lower() in {"localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False


def validate_action_environment(service_url: str) -> None:
    """Validate runner environment and service URL before accessing credentials."""
    runner_env = os.environ.get("RUNNER_ENVIRONMENT", "")
    if runner_env != "self-hosted":
        sys.stderr.write("HOSTED_RUNNER_FORBIDDEN: self-hosted runner required\n")
        sys.exit(78)

    parsed = urllib.parse.urlparse(service_url)
    host = parsed.hostname or ""
    if not _is_loopback(host):
        sys.stderr.write(f"HOSTED_RUNNER_FORBIDDEN: service URL {service_url} is not loopback\n")
        sys.exit(78)


def write_github_output(outputs: Mapping[str, str]) -> None:
    """Append outputs to $GITHUB_OUTPUT if running inside GitHub Actions."""
    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    try:
        with open(out_path, "a", encoding="utf-8") as f:
            for k, v in outputs.items():
                f.write(f"{k}={v}\n")
    except OSError as exc:
        sys.stderr.write(f"failed to write GITHUB_OUTPUT: {exc}\n")


def run_action(
    request_file: str | Path,
    token_file: str | Path,
    service_url: str = DEFAULT_URL,
    receipt_out_path: str | Path | None = None,
) -> dict[str, Any]:
    """Execute certification action wrapper logic.

    Enforces self-hosted runner and loopback service URL before reading token.
    """
    validate_action_environment(service_url)

    req_path = Path(request_file)
    if not req_path.is_file():
        sys.stderr.write(f"request file not found: {request_file}\n")
        sys.exit(2)

    try:
        with open(req_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as exc:
        sys.stderr.write(f"malformed request file: {exc}\n")
        sys.exit(2)

    errs = validate_certification_request(payload)
    if errs:
        sys.stderr.write(f"invalid certification request: {'; '.join(errs)}\n")
        sys.exit(2)

    token = _get_token(str(token_file))
    base_url = service_url.rstrip("/")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    body_bytes = json.dumps(payload).encode("utf-8")

    status_code, resp = _make_http_request(
        method="POST",
        url=f"{base_url}/v1/certifications",
        headers=headers,
        body=body_bytes,
        timeout=HEADER_READ_TIMEOUT_SECONDS,
    )

    if status_code not in (200, 202):
        err_code = _map_http_status_to_exit_code(status_code, resp)
        sys.stderr.write(f"action submission failed with HTTP {status_code}: {resp}\n")
        sys.exit(err_code)

    req_id = resp.get("request_id", "")
    state = resp.get("state", "PENDING")

    # If pending, poll until complete
    if status_code == 202 and state in ("PENDING", "RUNNING") and req_id:
        import time

        deadline = time.time() + CERTIFICATION_WAIT_TIMEOUT_SECONDS
        while time.time() < deadline:
            time.sleep(POLL_INTERVAL_SECONDS)
            st_code, st_resp = _make_http_request(
                method="GET",
                url=f"{base_url}/v1/certifications/{req_id}",
                headers=headers,
                timeout=HEADER_READ_TIMEOUT_SECONDS,
            )
            if st_code != 200:
                err_code = _map_http_status_to_exit_code(st_code, st_resp)
                sys.stderr.write(f"action polling failed with HTTP {st_code}: {st_resp}\n")
                sys.exit(err_code)

            resp = st_resp
            state = resp.get("state", state)
            if state in ("COMPLETED", "FAILED", "UNVERIFIABLE"):
                break

    claim_ceiling = resp.get("claim_ceiling", [])
    receipt_data = resp.get("receipt")

    if receipt_out_path is None:
        receipt_file = Path(tempfile.gettempdir()) / f"nexus-receipt-{req_id}.json"
    else:
        receipt_file = Path(receipt_out_path)

    if receipt_data:
        receipt_file.parent.mkdir(parents=True, exist_ok=True)
        with open(receipt_file, "w", encoding="utf-8") as f:
            json.dump(receipt_data, f, indent=2)
        receipt_file_str = str(receipt_file.resolve())
    else:
        receipt_file_str = ""

    action_outputs = {
        "request-id": req_id,
        "state": state,
        "receipt-file": receipt_file_str,
        "claim-ceiling": json.dumps(claim_ceiling),
    }

    write_github_output(action_outputs)
    return {
        "outputs": action_outputs,
        "response": resp,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Nexus Core V1 GitHub Action runner")
    parser.add_argument("--request-file", required=True, help="Path to request JSON file")
    parser.add_argument("--token-file", required=True, help="Path to token file")
    parser.add_argument(
        "--service-url", default=DEFAULT_URL, help=f"Service URL (default: {DEFAULT_URL})"
    )
    parser.add_argument("--receipt-output-file", default=None, help="Path to write receipt file")
    args = parser.parse_args(argv)

    run_action(
        request_file=args.request_file,
        token_file=args.token_file,
        service_url=args.service_url,
        receipt_out_path=args.receipt_output_file,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
