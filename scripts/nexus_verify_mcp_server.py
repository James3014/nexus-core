# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==2.2.0", "aiohttp==3.14.3", "PyGithub==2.10.0"]
# ///

"""Developer-mode Streamable HTTP MCP host for Nexus Verify.

This G1 host is intentionally loopback-only. It owns MCP transport and GitHub
read transport only. Nexus Core remains the sole evidence/verification
authority. Public deployment, OAuth, persistence, and plugin submission are out
of scope.
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

RawRequester = Callable[[str, Mapping[str, str]], tuple[int, Mapping[str, str], bytes]]


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
    ) -> None:
        self._token = token
        self._api_url = api_url.rstrip("/")
        self._requester = requester or _default_requester

    @classmethod
    def from_environment(cls) -> "PublicGitHubReadPort":
        token = os.environ.get("NEXUS_VERIFY_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        return cls(token=token)

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
):
    """Create the one-tool Nexus Verify MCP server without starting a listener."""

    from mcp.server import MCPServer
    from mcp.types import ToolAnnotations

    port_factory = github_port_factory or PublicGitHubReadPort.from_environment
    server = MCPServer(
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
            open_world_hint=True,
        ),
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


def _require_loopback(host: str) -> str:
    if host.lower() == "localhost":
        return host
    try:
        if ipaddress.ip_address(host).is_loopback:
            return host
    except ValueError:
        pass
    raise ValueError("G1 developer-mode MCP host must bind loopback only")


def run_server(*, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Run the developer-mode Streamable HTTP server at /mcp."""

    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 through 65535")
    server = create_mcp_server()
    server.run(
        transport="streamable-http",
        host=_require_loopback(host),
        port=port,
        stateless_http=True,
        json_response=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Nexus Verify G1 MCP developer host")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
