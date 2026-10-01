# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==2.2.0", "aiohttp==3.14.3", "PyGithub==2.10.0"]
# ///

"""Loopback Streamable HTTP MCP host for Nexus Verify.

This host supports the G1 developer profile and a G4A public-review profile for
local pre-deployment validation. Both profiles remain loopback-only here. Nexus
Core remains the sole evidence/verification authority. Public deployment,
publisher identity, domain verification, and plugin submission are external
effects and remain out of scope for this script.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from product.acquisition.github import (  # noqa: E402
    AcquisitionError,
    GitHubPullRequestLocator,
    _freshness_cas_for,
)
from product.clients.nexus_verify import (  # noqa: E402
    INPUT_SCHEMA,
    OUTPUT_SCHEMA,
    TOOL_DESCRIPTION,
    TOOL_NAME,
    verify_code_change_evidence,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8768
DEFAULT_GITHUB_API_URL = "https://api.github.com"
_GITHUB_API_VERSION = "2022-11-28"
_GITHUB_JSON_ACCEPT = "application/vnd.github+json"
_GITHUB_DIFF_ACCEPT = "application/vnd.github.v3.diff"
_MAX_PAGES = 100
PUBLIC_REVIEW_GITHUB_TOKEN_ENV = "NEXUS_VERIFY_PUBLIC_GITHUB_TOKEN"
PUBLIC_HOST_ENV = "NEXUS_VERIFY_PUBLIC_HOST"
MAX_PUBLIC_RECEIPT_BYTES = 512 * 1024
PUBLIC_TOOL_META: dict[str, Any] = {
    "securitySchemes": [{"type": "noauth"}],
    "openai/toolInvocation/invoking": "Checking verification evidence...",
    "openai/toolInvocation/invoked": "Verification evidence checked",
}

RawRequester = Callable[[str, Mapping[str, str]], tuple[int, Mapping[str, str], bytes]]


def _validate_public_tool_arguments(
    arguments: Mapping[str, Any],
    *,
    public_review: bool,
) -> None:
    if not isinstance(arguments, Mapping):
        raise ValueError("tool arguments must be an object")
    values = dict(arguments)
    required = {"repository_owner", "repository_name", "pr_number"}
    allowed = {*required, "receipt"}
    if not required.issubset(values):
        raise ValueError("repository_owner, repository_name and pr_number are required")
    if set(values) - allowed:
        raise ValueError("unexpected tool arguments")
    try:
        GitHubPullRequestLocator(
            values["repository_owner"],
            values["repository_name"],
            values["pr_number"],
        )
    except (AcquisitionError, TypeError, ValueError) as exc:
        raise ValueError("invalid GitHub pull-request locator") from exc

    receipt = values.get("receipt")
    if receipt is not None and not isinstance(receipt, dict):
        raise ValueError("receipt must be an object or null")
    if public_review and receipt is not None:
        encoded_receipt = json.dumps(
            receipt,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded_receipt) > MAX_PUBLIC_RECEIPT_BYTES:
            raise ValueError("receipt exceeds public-review size limit")


def _normalize_public_host(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("public host must be a non-empty hostname")
    if any(token in value for token in ("://", "/", "?", "#", "*", "@")):
        raise ValueError("public host must be a hostname without scheme, path, port, or wildcard")
    parsed = urllib.parse.urlsplit(f"//{value}")
    if parsed.hostname != value.lower() or parsed.port is not None:
        raise ValueError("public host must be a hostname without scheme, path, port, or wildcard")
    return value.lower()


def _transport_security_settings(public_host: str | None):
    from mcp.server.transport_security import TransportSecuritySettings

    allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    allowed_origins = [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]
    normalized = _normalize_public_host(public_host)
    if normalized is not None:
        allowed_hosts.extend([normalized, f"{normalized}:*"])
        allowed_origins.extend([f"https://{normalized}", f"https://{normalized}:*"])
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _default_requester(
    url: str, headers: Mapping[str, str]
) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=20.0) as response:
            return response.getcode(), dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()
    except (OSError, urllib.error.URLError) as exc:
        raise AcquisitionError("GitHub read transport failed") from exc


class PublicGitHubReadPort:
    """Read-only GitHub REST adapter owned by the developer-mode MCP host."""

    def __init__(
        self,
        *,
        token: str | None = None,
        api_url: str = DEFAULT_GITHUB_API_URL,
        requester: RawRequester | None = None,
        public_only: bool = False,
    ) -> None:
        self._token = token
        self._api_url = api_url.rstrip("/")
        self._requester = requester or _default_requester
        self._public_only = public_only

    @classmethod
    def from_environment(cls) -> "PublicGitHubReadPort":
        token = os.environ.get("NEXUS_VERIFY_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        return cls(token=token)

    @classmethod
    def from_public_review_environment(cls) -> "PublicGitHubReadPort":
        """Build the review profile without accepting generic host/user GitHub tokens."""

        token = os.environ.get(PUBLIC_REVIEW_GITHUB_TOKEN_ENV)
        return cls(token=token, public_only=True)

    def _headers(self, accept: str) -> dict[str, str]:
        headers = {
            "Accept": accept,
            "User-Agent": "nexus-verify-g1-developer-mode",
            "X-GitHub-Api-Version": _GITHUB_API_VERSION,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _request(
        self,
        path: str,
        *,
        accept: str = _GITHUB_JSON_ACCEPT,
        params: Mapping[str, object] | None = None,
    ) -> bytes:
        query = ""
        if params:
            query = "?" + urllib.parse.urlencode({key: str(value) for key, value in params.items()})
        status, _headers, body = self._requester(
            f"{self._api_url}{path}{query}",
            self._headers(accept),
        )
        if status in {401, 403}:
            raise PermissionError("GitHub read permission denied")
        if status != 200:
            raise AcquisitionError(f"GitHub read failed with HTTP {status}")
        return body

    def _json(
        self,
        path: str,
        *,
        params: Mapping[str, object] | None = None,
    ) -> Any:
        try:
            return json.loads(self._request(path, params=params).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcquisitionError("GitHub returned malformed JSON") from exc

    @staticmethod
    def _repo_path(locator: GitHubPullRequestLocator) -> str:
        owner = urllib.parse.quote(locator.repository_owner, safe="")
        repository = urllib.parse.quote(locator.repository_name, safe="")
        return f"/repos/{owner}/{repository}"

    def _require_public_repository(self, repository_path: str) -> None:
        payload = self._json(repository_path)
        if not isinstance(payload, dict) or not isinstance(payload.get("private"), bool):
            raise AcquisitionError("GitHub repository visibility is malformed")
        if payload["private"]:
            raise PermissionError("public-review profile supports public GitHub repositories only")

    def _git_tree(self, repository_path: str, commit_sha: str) -> str:
        commit = self._json(f"{repository_path}/git/commits/{commit_sha}")
        try:
            tree_sha = commit["tree"]["sha"]
        except (KeyError, TypeError) as exc:
            raise AcquisitionError("GitHub commit response missing tree identity") from exc
        if not isinstance(tree_sha, str):
            raise AcquisitionError("GitHub commit tree identity is malformed")
        return tree_sha

    def _pull_files(
        self, repository_path: str, pr_number: int
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        paths: list[str] = []
        deleted: list[str] = []
        for page in range(1, _MAX_PAGES + 1):
            payload = self._json(
                f"{repository_path}/pulls/{pr_number}/files",
                params={"per_page": 100, "page": page},
            )
            if not isinstance(payload, list):
                raise AcquisitionError("GitHub pull files response is malformed")
            for row in payload:
                if not isinstance(row, dict) or not isinstance(row.get("filename"), str):
                    raise AcquisitionError("GitHub pull files entry is malformed")
                paths.append(row["filename"])
                if row.get("status") == "removed":
                    deleted.append(row["filename"])
            if len(payload) < 100:
                return tuple(sorted(paths)), tuple(sorted(deleted))
        raise AcquisitionError("GitHub pull files pagination exceeded safety bound")

    def _check_runs(
        self, repository_path: str, head_sha: str
    ) -> tuple[tuple[str, str], ...]:
        rows: list[tuple[str, str]] = []
        seen = 0
        total_count: int | None = None
        for page in range(1, _MAX_PAGES + 1):
            payload = self._json(
                f"{repository_path}/commits/{head_sha}/check-runs",
                params={"per_page": 100, "page": page},
            )
            if not isinstance(payload, dict) or not isinstance(payload.get("check_runs"), list):
                raise AcquisitionError("GitHub check-runs response is malformed")
            if total_count is None:
                raw_total = payload.get("total_count")
                if (
                    not isinstance(raw_total, int)
                    or isinstance(raw_total, bool)
                    or raw_total < 0
                ):
                    raise AcquisitionError("GitHub check-runs total_count is malformed")
                total_count = raw_total
            page_rows = payload["check_runs"]
            for run in page_rows:
                if not isinstance(run, dict):
                    raise AcquisitionError("GitHub check-run entry is malformed")
                app = run.get("app")
                app_slug = app.get("slug") if isinstance(app, dict) else None
                identity = (
                    f"check-run:{app_slug or 'unknown'}:"
                    f"{run.get('name', 'unknown')}:{run.get('id', 'unknown')}"
                )
                digest = _canonical_hash(
                    {
                        "id": run.get("id"),
                        "name": run.get("name"),
                        "status": run.get("status"),
                        "conclusion": run.get("conclusion"),
                        "head_sha": run.get("head_sha"),
                        "details_url": run.get("details_url"),
                        "app_slug": app_slug,
                    }
                )
                rows.append((identity, digest))
            seen += len(page_rows)
            if total_count == 0 or seen >= total_count:
                return tuple(sorted(rows))
            if not page_rows:
                raise AcquisitionError("GitHub check-runs pagination ended early")
        raise AcquisitionError("GitHub check-runs pagination exceeded safety bound")

    def read_pull_request(self, locator: GitHubPullRequestLocator) -> Mapping[str, object]:
        repository_path = self._repo_path(locator)
        if self._public_only:
            self._require_public_repository(repository_path)
        pull = self._json(f"{repository_path}/pulls/{locator.pr_number}")
        if not isinstance(pull, dict):
            raise AcquisitionError("GitHub pull response is malformed")
        try:
            base_sha = pull["base"]["sha"]
            head_sha = pull["head"]["sha"]
            observed_at = pull["updated_at"]
        except (KeyError, TypeError) as exc:
            raise AcquisitionError("GitHub pull response missing exact identity") from exc
        if not all(isinstance(item, str) for item in (base_sha, head_sha, observed_at)):
            raise AcquisitionError("GitHub pull identity is malformed")

        base_tree_sha = self._git_tree(repository_path, base_sha)
        head_tree_sha = self._git_tree(repository_path, head_sha)
        diff_bytes = self._request(
            f"{repository_path}/pulls/{locator.pr_number}",
            accept=_GITHUB_DIFF_ACCEPT,
        )
        diff_hash = "sha256:" + hashlib.sha256(diff_bytes).hexdigest()
        changed_paths, deleted_paths = self._pull_files(repository_path, locator.pr_number)
        checks = self._check_runs(repository_path, head_sha)
        freshness_cas = _freshness_cas_for(
            locator.repository_owner,
            locator.repository_name,
            locator.pr_number,
            base_sha,
            head_sha,
            base_tree_sha,
            head_tree_sha,
            "base_sha_exact",
            diff_hash,
            changed_paths,
            deleted_paths,
            checks,
        )
        return {
            "repository_owner": locator.repository_owner,
            "repository_name": locator.repository_name,
            "pr_number": locator.pr_number,
            "base_sha": base_sha,
            "head_sha": head_sha,
            "base_tree_sha": base_tree_sha,
            "head_tree_sha": head_tree_sha,
            "merge_base_policy": "base_sha_exact",
            "diff_bytes": diff_bytes,
            "diff_hash": diff_hash,
            "changed_paths": list(changed_paths),
            "deleted_paths": list(deleted_paths),
            "checks": [list(item) for item in checks],
            "pagination_complete": True,
            "observed_at": observed_at,
            "freshness_cas": freshness_cas,
        }


def create_mcp_server(
    github_port_factory: Callable[[], object] | None = None,
    *,
    public_review: bool = False,
):
    """Create the one-tool Nexus Verify MCP server without starting a listener."""

    from mcp.server import MCPServer
    from mcp.types import ToolAnnotations

    class ContractBoundMCPServer(MCPServer):
        async def list_tools(self):
            tools = await super().list_tools()
            return [
                tool.model_copy(
                    update={
                        "input_schema": dict(INPUT_SCHEMA),
                        "output_schema": dict(OUTPUT_SCHEMA),
                    }
                )
                if tool.name == TOOL_NAME
                else tool
                for tool in tools
            ]

        async def call_tool(self, name, arguments, context=None):
            if name == TOOL_NAME:
                _validate_public_tool_arguments(
                    arguments,
                    public_review=public_review,
                )
            return await super().call_tool(name, arguments, context)

    port_factory = github_port_factory or PublicGitHubReadPort.from_environment
    server = ContractBoundMCPServer(
        "Nexus Verify",
        instructions=(
            "Use Nexus Verify only to evaluate whether supplied Nexus verification "
            "evidence still applies to the exact current GitHub pull-request state. "
            "VERIFIED never means merge approval, release approval, or deployment readiness."
        ),
    )

    @server.tool(
        name=TOOL_NAME,
        title="Verify code-change evidence",
        description=TOOL_DESCRIPTION,
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=True,
        ),
        meta=dict(PUBLIC_TOOL_META),
        structured_output=True,
    )
    def verify_tool(
        repository_owner: str,
        repository_name: str,
        pr_number: int,
        receipt: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return verify_code_change_evidence(
            {
                "repository_owner": repository_owner,
                "repository_name": repository_name,
                "pr_number": pr_number,
                "receipt": receipt,
            },
            github_port=port_factory(),
        )

    return server


def create_public_review_mcp_server():
    """Create the G4A public-review profile without enabling public networking."""

    return create_mcp_server(
        github_port_factory=PublicGitHubReadPort.from_public_review_environment,
        public_review=True,
    )


def _require_loopback(host: str) -> str:
    if host.lower() == "localhost":
        return host
    try:
        if ipaddress.ip_address(host).is_loopback:
            return host
    except ValueError:
        pass
    raise ValueError("G1 developer-mode MCP host must bind loopback only")


def run_server(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    profile: str = "developer",
    public_host: str | None = None,
) -> None:
    """Run a loopback Streamable HTTP server at /mcp for local validation."""

    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 through 65535")
    if profile not in {"developer", "public-review"}:
        raise ValueError("profile must be developer or public-review")
    server = (
        create_public_review_mcp_server()
        if profile == "public-review"
        else create_mcp_server()
    )
    server.run(
        transport="streamable-http",
        host=_require_loopback(host),
        port=port,
        stateless_http=True,
        json_response=True,
        transport_security=_transport_security_settings(
            public_host if profile == "public-review" else None
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Nexus Verify loopback MCP host")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--profile",
        choices=("developer", "public-review"),
        default="developer",
    )
    parser.add_argument(
        "--public-host",
        default=os.environ.get(PUBLIC_HOST_ENV),
        help="Exact external hostname admitted by the public-review DNS-rebinding guard.",
    )
    args = parser.parse_args()
    run_server(
        host=args.host,
        port=args.port,
        profile=args.profile,
        public_host=args.public_host,
    )


if __name__ == "__main__":
    main()
