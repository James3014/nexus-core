"""Nexus Core V1 nexus-certify thin CLI.

Canonical CLI transport for Core V1 certification runtime (TG-6).
Does not construct trust decisions, dispositions, or receipts locally.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from product.runtime.auth import AuthSecurityError, read_bearer_token
from product.runtime.schemas import (
    validate_certification_request,
    validate_receipt_verify_request,
)

DEFAULT_URL = "http://127.0.0.1:8767"
HEADER_READ_TIMEOUT_SECONDS = 10.0
CERTIFICATION_WAIT_TIMEOUT_SECONDS = 330.0
POLL_INTERVAL_SECONDS = 0.5


class CertifyCLIError(Exception):
    def __init__(self, message: str, exit_code: int):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


class CertifyArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        sys.stderr.write(f"usage error: {message}\n")
        sys.exit(2)


def _make_http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    timeout: float = HEADER_READ_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any]]:
    """Perform HTTP request returning (status_code, response_dict)."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.getcode()
            data = resp.read().decode("utf-8")
            try:
                parsed = json.loads(data) if data else {}
            except json.JSONDecodeError:
                parsed = {"raw": data}
            return status_code, parsed
    except urllib.error.HTTPError as e:
        status_code = e.code
        err_body = e.read().decode("utf-8", errors="ignore")
        try:
            parsed = json.loads(err_body) if err_body else {}
        except json.JSONDecodeError:
            parsed = {"error": err_body}
        return status_code, parsed
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise CertifyCLIError(f"transport error: {e}", exit_code=7) from e


def _map_http_status_to_exit_code(status_code: int, payload: dict[str, Any]) -> int:
    if status_code in (401, 403):
        return 3
    if status_code == 404:
        return 4
    if status_code == 409:
        return 5
    if status_code in (400, 413, 415):
        return 2
    if status_code >= 500:
        return 7
    return 0


def _get_token(token_file: str | None) -> str:
    try:
        return read_bearer_token(token_file)
    except (AuthSecurityError, ValueError, OSError) as exc:
        raise CertifyCLIError(f"authentication error: {exc}", exit_code=3) from exc


def cmd_submit(args: argparse.Namespace) -> int:
    req_path = Path(args.request)
    if not req_path.is_file():
        raise CertifyCLIError(f"request file not found: {args.request}", exit_code=2)
    try:
        with open(req_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise CertifyCLIError(f"malformed request file: {e}", exit_code=2) from e

    errs = validate_certification_request(payload)
    if errs:
        raise CertifyCLIError(f"invalid certification request: {'; '.join(errs)}", exit_code=2)

    token = _get_token(args.token_file)
    service_url = args.url.rstrip("/")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    body_bytes = json.dumps(payload).encode("utf-8")

    status_code, resp = _make_http_request(
        method="POST",
        url=f"{service_url}/v1/certifications",
        headers=headers,
        body=body_bytes,
        timeout=HEADER_READ_TIMEOUT_SECONDS,
    )

    if status_code not in (200, 202):
        err_code = _map_http_status_to_exit_code(status_code, resp)
        sys.stderr.write(f"submit failed with HTTP {status_code}: {resp.get('message', resp)}\n")
        return err_code

    req_id = resp.get("request_id")
    state = resp.get("state")

    # If already terminal (e.g. 200 replayed or terminal)
    if status_code == 200 or state in ("COMPLETED", "FAILED", "UNVERIFIABLE"):
        print(json.dumps(resp, indent=2))
        if state == "UNVERIFIABLE":
            return 6
        return 0

    if not req_id:
        raise CertifyCLIError("missing request_id in submit response", exit_code=7)

    deadline = time.time() + CERTIFICATION_WAIT_TIMEOUT_SECONDS
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_SECONDS)
        st_code, st_resp = _make_http_request(
            method="GET",
            url=f"{service_url}/v1/certifications/{req_id}",
            headers=headers,
            timeout=HEADER_READ_TIMEOUT_SECONDS,
        )
        if st_code != 200:
            err_code = _map_http_status_to_exit_code(st_code, st_resp)
            sys.stderr.write(
                f"polling status failed with HTTP {st_code}: {st_resp.get('message', st_resp)}\n"
            )
            return err_code

        cur_state = st_resp.get("state")
        if cur_state in ("COMPLETED", "FAILED", "UNVERIFIABLE"):
            print(json.dumps(st_resp, indent=2))
            if cur_state == "UNVERIFIABLE":
                return 6
            return 0

    sys.stderr.write(f"certification timed out after {CERTIFICATION_WAIT_TIMEOUT_SECONDS}s\n")
    return 7


def cmd_status(args: argparse.Namespace) -> int:
    token = _get_token(args.token_file)
    service_url = args.url.rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
    }
    status_code, resp = _make_http_request(
        method="GET",
        url=f"{service_url}/v1/certifications/{args.request_id}",
        headers=headers,
        timeout=HEADER_READ_TIMEOUT_SECONDS,
    )
    if status_code != 200:
        err_code = _map_http_status_to_exit_code(status_code, resp)
        sys.stderr.write(
            f"status query failed with HTTP {status_code}: {resp.get('message', resp)}\n"
        )
        return err_code

    print(json.dumps(resp, indent=2))
    if resp.get("state") == "UNVERIFIABLE":
        return 6
    return 0


def cmd_receipt(args: argparse.Namespace) -> int:
    token = _get_token(args.token_file)
    service_url = args.url.rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
    }
    status_code, resp = _make_http_request(
        method="GET",
        url=f"{service_url}/v1/certifications/{args.request_id}/receipt",
        headers=headers,
        timeout=HEADER_READ_TIMEOUT_SECONDS,
    )
    if status_code != 200:
        err_code = _map_http_status_to_exit_code(status_code, resp)
        sys.stderr.write(
            f"receipt query failed with HTTP {status_code}: {resp.get('message', resp)}\n"
        )
        return err_code

    print(json.dumps(resp, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    receipt_path = Path(args.receipt)
    if not receipt_path.is_file():
        raise CertifyCLIError(f"receipt file not found: {args.receipt}", exit_code=2)
    try:
        with open(receipt_path, "r", encoding="utf-8") as f:
            receipt_payload = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise CertifyCLIError(f"malformed receipt file: {e}", exit_code=2) from e

    verify_payload = {
        "receipt": receipt_payload,
        "requested_scope": getattr(args, "scope", "AUTO") or "AUTO",
        "original_inputs": None,
    }
    errs = validate_receipt_verify_request(verify_payload)
    if errs:
        raise CertifyCLIError(f"invalid verify request: {'; '.join(errs)}", exit_code=2)

    token = _get_token(args.token_file)
    service_url = args.url.rstrip("/")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    body_bytes = json.dumps(verify_payload).encode("utf-8")

    status_code, resp = _make_http_request(
        method="POST",
        url=f"{service_url}/v1/receipts/verify",
        headers=headers,
        body=body_bytes,
        timeout=HEADER_READ_TIMEOUT_SECONDS,
    )

    if status_code != 200:
        err_code = _map_http_status_to_exit_code(status_code, resp)
        sys.stderr.write(
            f"receipt verify failed with HTTP {status_code}: {resp.get('message', resp)}\n"
        )
        return err_code

    print(json.dumps(resp, indent=2))
    if resp.get("status") == "UNVERIFIABLE":
        return 6
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = CertifyArgumentParser(
        prog="nexus-certify",
        description="Nexus Core V1 canonical certification CLI (transport-only)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # submit
    p_submit = subparsers.add_parser("submit", help="Submit certification request")
    p_submit.add_argument("--request", required=True, help="Path to request JSON file")
    p_submit.add_argument(
        "--url", default=DEFAULT_URL, help=f"Service URL (default: {DEFAULT_URL})"
    )
    p_submit.add_argument("--token-file", default=None, help="Path to protected token file")

    # status
    p_status = subparsers.add_parser("status", help="Get certification status")
    p_status.add_argument("request_id", help="Request ID")
    p_status.add_argument(
        "--url", default=DEFAULT_URL, help=f"Service URL (default: {DEFAULT_URL})"
    )
    p_status.add_argument("--token-file", default=None, help="Path to protected token file")

    # receipt
    p_receipt = subparsers.add_parser("receipt", help="Get certification receipt")
    p_receipt.add_argument("request_id", help="Request ID")
    p_receipt.add_argument(
        "--url", default=DEFAULT_URL, help=f"Service URL (default: {DEFAULT_URL})"
    )
    p_receipt.add_argument("--token-file", default=None, help="Path to protected token file")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify receipt")
    p_verify.add_argument("--receipt", required=True, help="Path to receipt JSON file")
    p_verify.add_argument(
        "--url", default=DEFAULT_URL, help=f"Service URL (default: {DEFAULT_URL})"
    )
    p_verify.add_argument("--token-file", default=None, help="Path to protected token file")
    p_verify.add_argument(
        "--scope",
        choices=["AUTO", "ENVELOPE_ONLY", "FULL"],
        default="AUTO",
        help="Requested verification scope (default: AUTO)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "submit":
            return cmd_submit(args)
        elif args.command == "status":
            return cmd_status(args)
        elif args.command == "receipt":
            return cmd_receipt(args)
        elif args.command == "verify":
            return cmd_verify(args)
        else:
            sys.stderr.write(f"unknown command: {args.command}\n")
            return 2
    except CertifyCLIError as exc:
        sys.stderr.write(f"{exc.message}\n")
        return exc.exit_code
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return 7


if __name__ == "__main__":
    sys.exit(main())
