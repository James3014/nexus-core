"""Secure loopback bearer token authentication for Nexus Core HTTP runtime (TG-5)."""

from __future__ import annotations

import base64
import hmac
import os
import re
import stat
from pathlib import Path
from typing import Any, Callable, Optional

from aiohttp import web

from product.runtime.schemas import make_http_error

TOKEN_LENGTH = 43
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}")


class AuthSecurityError(ValueError):
    """Raised when token storage or token file permissions fail security checks."""


def resolve_token_path(override_path: Path | str | None = None) -> Path:
    """Resolve token file path from override or XDG configuration.

    Resolution:
    - override_path if given
    - /nexus-core/token
    - ~/.config/nexus-core/token
    """
    if override_path is not None:
        p = Path(override_path)
        if p.is_symlink():
            raise AuthSecurityError("token path cannot be a symlink")
        return p.resolve()

    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config and xdg_config.strip():
        base = Path(xdg_config).resolve()
    else:
        base = (Path.home() / ".config").resolve()
    return (base / "nexus-core" / "token").resolve()


def generate_bearer_token() -> str:
    """Generate a 43-character ASCII base64url-encoded random token without padding."""
    raw = os.urandom(32)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def write_secure_token(
    token: str,
    token_path: Path | str | None = None,
) -> Path:
    """Write bearer token enforcing mode 0700 dir and mode 0600 file owned by current UID."""
    if len(token) != TOKEN_LENGTH or not _TOKEN_PATTERN.fullmatch(token):
        raise ValueError("token must be exactly 43 base64url characters without padding")

    target = resolve_token_path(token_path)
    parent = target.parent
    if not parent.exists():
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        parent.chmod(0o700)
    except OSError:
        pass

    parent_st = parent.stat()
    if parent_st.st_uid != os.getuid():
        raise AuthSecurityError("config directory not owned by current UID")

    # Write securely
    fd = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(fd, token.encode("ascii"))
    finally:
        os.close(fd)

    os.chmod(target, 0o600)
    return target


def read_bearer_token(token_path: Path | str | None = None) -> str:
    """Read and validate per-install bearer token with strict filesystem checks.

    Security checks:
    - O_NOFOLLOW open
    - regular file (not dir or special device)
    - link count == 1 (no hardlinks)
    - exact file mode 0600
    - parent directory mode 0700
    - current UID ownership
    - exactly 43 ASCII base64url characters without whitespace/padding
    """
    target = resolve_token_path(token_path)
    if not target.exists():
        raise AuthSecurityError("token file does not exist")

    # Parent directory check
    parent = target.parent
    if not parent.exists():
        raise AuthSecurityError("token parent directory does not exist")
    if parent.is_symlink():
        raise AuthSecurityError("token directory cannot be a symlink")
    parent_st = parent.stat()
    if parent_st.st_uid != os.getuid():
        raise AuthSecurityError("token parent directory not owned by current UID")
    if (parent_st.st_mode & 0o777) != 0o700:
        raise AuthSecurityError(
            f"token parent directory mode must be 0700, got {oct(parent_st.st_mode & 0o777)}"
        )

    # Secure open with O_NOFOLLOW
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        raise AuthSecurityError("failed to open token file securely") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AuthSecurityError("token path is not a regular file")
        if st.st_nlink != 1:
            raise AuthSecurityError(f"token file has invalid link count: {st.st_nlink}")
        if st.st_uid != os.getuid():
            raise AuthSecurityError("token file not owned by current UID")
        if (st.st_mode & 0o777) != 0o600:
            raise AuthSecurityError(f"token file mode must be 0600, got {oct(st.st_mode & 0o777)}")

        data = os.read(fd, 256)
    finally:
        os.close(fd)

    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AuthSecurityError("token contains non-ASCII bytes") from exc

    if len(text) != TOKEN_LENGTH or not _TOKEN_PATTERN.fullmatch(text):
        raise AuthSecurityError(
            "token format invalid: must be exactly 43 unpadded base64url characters"
        )

    return text


def validate_auth_header(
    header_value: Optional[str],
    expected_token: str,
) -> bool:
    """Validate Authorization header in constant time."""
    if not header_value or not isinstance(header_value, str):
        return False
    parts = header_value.split(" ", 1)
    if len(parts) != 2 or parts[0] != "Bearer":
        return False
    token = parts[1]
    if len(token) != TOKEN_LENGTH:
        return False
    return hmac.compare_digest(token, expected_token)


def create_auth_middleware(
    expected_token: str,
) -> Callable[[web.Request, Callable[[web.Request], Any]], Any]:
    """Create aiohttp middleware enforcing constant-time Bearer authentication.

    Runs before route disclosure so unauthenticated requests to unknown paths receive 401.
    """

    @web.middleware
    async def auth_middleware(
        request: web.Request,
        handler: Callable[[web.Request], Any],
    ) -> web.Response:
        auth_header = request.headers.get("Authorization")
        if not validate_auth_header(auth_header, expected_token):
            error_body = make_http_error(
                code="UNAUTHORIZED",
                request_id=None,
                message="unauthorized",
            )
            return web.json_response(error_body, status=401)
        return await handler(request)

    return auth_middleware


__all__ = [
    "TOKEN_LENGTH",
    "AuthSecurityError",
    "resolve_token_path",
    "generate_bearer_token",
    "write_secure_token",
    "read_bearer_token",
    "validate_auth_header",
    "create_auth_middleware",
]
