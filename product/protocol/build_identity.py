# pyright: strict, reportUnnecessaryIsInstance=false, reportUnnecessaryComparison=false
"""Git-free Core build identity (#267).

``core_identity()`` reports which Core is running without calling git:

- the build identity embedded at wheel/sdist build time by ``setup.py``
  (``product/_build_identity.json``: distribution, version, git commit/tree,
  dirty flag and the source digest of what was built), and
- a runtime ``source_digest`` over the shipped source files on disk.

The source digest covers the files a wheel ships: every ``*.py`` file under the
``product`` package plus the declared package data
(``product/execution/profiles/*.json`` and ``*.lock``). It skips
``__pycache__`` directories, bytecode, the source-only ``product/benchmark``
harness and the build stamp itself, so importing Core (which writes
``__pycache__``) never changes it, while changing any shipped source byte does.

Digest rule (also published in ``protocol_descriptor()``):
``"sha256:" + sha256(manifest)`` where ``manifest`` is the concatenation, in
ascending order of the UTF-8 relative path, of one line per file:
``<sha256-hex of file bytes> + "  " + <relative path, "/" separated, starting
with "product/"> + "\\n"`` (the ``sha256sum`` line format).

Leaf module: imports nothing from ``product`` so that ``setup.py`` can load it
by file path at build time, before the package is importable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, cast

CORE_IDENTITY_SCHEMA_ID = "nexus.core.core-identity.v1-experimental"
BUILD_IDENTITY_SCHEMA_ID = "nexus.core.build-identity.v1-experimental"
BUILD_IDENTITY_FILENAME = "_build_identity.json"
DISTRIBUTION_NAME = "nexus-certify"
PACKAGE_NAME = "product"

# build_identity values in core_identity():
# - EMBEDDED: a well-formed build stamp is present (installed wheel, or a wheel
#   built from the sdist).
# - UNSTAMPED: no stamp (plain source checkout or editable install). The git
#   fields are null; source_digest is always present and is the identity to pin.
# - INVALID_STAMP: a stamp file exists but is unreadable or malformed. The git
#   fields are null so a host never binds to a stamp Core could not validate.
BUILD_IDENTITY_EMBEDDED = "EMBEDDED"
BUILD_IDENTITY_UNSTAMPED = "UNSTAMPED"
BUILD_IDENTITY_INVALID = "INVALID_STAMP"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# SHA-1 (40 hex) or SHA-256 (64 hex) git object names.
_GIT_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_PACKAGE_DATA_DIR = ("execution", "profiles")
_PACKAGE_DATA_SUFFIXES = (".json", ".lock")
_EXCLUDED_TOP_LEVEL_DIRS = frozenset({"benchmark"})
_STAMP_KEYS = frozenset(
    {
        "schema",
        "distribution",
        "version",
        "git_commit",
        "git_tree",
        "git_dirty",
        "source_digest",
    }
)


def _is_shipped(parts: tuple[str, ...]) -> bool:
    """``parts`` is the path relative to the package root, split on "/"."""
    if len(parts) == 0 or "__pycache__" in parts:
        return False
    if len(parts) > 1 and parts[0] in _EXCLUDED_TOP_LEVEL_DIRS:
        return False
    name = parts[-1]
    if name == BUILD_IDENTITY_FILENAME and len(parts) == 1:
        return False
    if name.endswith(".py"):
        return True
    return parts[:-1] == _PACKAGE_DATA_DIR and name.endswith(_PACKAGE_DATA_SUFFIXES)


def source_digest_of_files(files: Mapping[str, bytes] | Iterable[tuple[str, bytes]]) -> str:
    """Digest of ``(relative path, bytes)`` pairs under the published rule.

    Paths are "/" separated and include the ``product/`` prefix. This is the
    pure form of :func:`source_digest`; non-Python hosts can reproduce it with
    ``sha256sum`` (see the conformance vector in ``protocol_descriptor()``).
    """
    items: list[tuple[str, bytes]] = (
        list(cast("Mapping[str, bytes]", files).items())
        if isinstance(files, Mapping)
        else list(files)
    )
    for path, data in items:
        if type(path) is not str or not path or "\n" in path or "\\" in path:
            raise ValueError(f"invalid source digest path: {path!r}")
        if type(data) is not bytes:
            raise TypeError(f"source digest content must be bytes: {path!r}")
    paths = [path for path, _ in items]
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate path in source digest input")
    manifest = hashlib.sha256()
    for path, data in sorted(items, key=lambda item: item[0].encode("utf-8")):
        manifest.update(hashlib.sha256(data).hexdigest().encode("ascii"))
        manifest.update(b"  ")
        manifest.update(path.encode("utf-8"))
        manifest.update(b"\n")
    return "sha256:" + manifest.hexdigest()


def _iter_shipped_files(package_root: Path) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(package_root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name != "__pycache__"]
        rel_dir = Path(dirpath).relative_to(package_root).parts
        for filename in filenames:
            parts = (*rel_dir, filename)
            path = Path(dirpath, filename)
            if _is_shipped(parts) and path.is_file():
                found.append(("/".join((PACKAGE_NAME, *parts)), path))
    return found


def shipped_source_paths(package_root: str | os.PathLike[str] | None = None) -> list[str]:
    """Relative paths (``product/...``) that :func:`source_digest` covers."""
    root = Path(package_root) if package_root is not None else _package_root()
    return sorted((rel for rel, _ in _iter_shipped_files(root)), key=lambda p: p.encode("utf-8"))


def source_digest(package_root: str | os.PathLike[str] | None = None) -> str:
    """Digest of the shipped Core sources under ``package_root``.

    ``package_root`` is the ``product`` package directory; it defaults to the
    directory of the running Core. No git, no bytecode.
    """
    root = Path(package_root) if package_root is not None else _package_root()
    if not (root / "__init__.py").is_file():
        raise FileNotFoundError(f"not a Core package directory: {root}")
    return source_digest_of_files((rel, path.read_bytes()) for rel, path in _iter_shipped_files(root))


def _package_root() -> Path:
    # product/protocol/core_identity.py -> product/
    return Path(__file__).resolve().parent.parent


def validate_build_identity(value: Any) -> bool:
    """True when ``value`` is a well-formed embedded build stamp."""
    if type(value) is not dict:
        return False
    stamp = cast("dict[str, Any]", value)
    if set(stamp) != _STAMP_KEYS:
        return False
    if stamp["schema"] != BUILD_IDENTITY_SCHEMA_ID or stamp["distribution"] != DISTRIBUTION_NAME:
        return False
    if type(stamp["version"]) is not str or not stamp["version"]:
        return False
    if type(stamp["source_digest"]) is not str or not _DIGEST_RE.fullmatch(stamp["source_digest"]):
        return False
    commit, tree, dirty = stamp["git_commit"], stamp["git_tree"], stamp["git_dirty"]
    if commit is None:
        return tree is None and dirty is None
    return (
        type(commit) is str
        and _GIT_OBJECT_RE.fullmatch(commit) is not None
        and type(tree) is str
        and _GIT_OBJECT_RE.fullmatch(tree) is not None
        and type(dirty) is bool
    )


def read_build_identity(package_root: str | os.PathLike[str] | None = None) -> tuple[str, dict[str, Any] | None]:
    """Return ``(build_identity_state, stamp_or_None)``."""
    root = Path(package_root) if package_root is not None else _package_root()
    stamp_path = root / BUILD_IDENTITY_FILENAME
    try:
        raw = stamp_path.read_bytes()
    except FileNotFoundError:
        return (BUILD_IDENTITY_UNSTAMPED, None)
    except OSError:
        return (BUILD_IDENTITY_INVALID, None)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return (BUILD_IDENTITY_INVALID, None)
    if not validate_build_identity(value):
        return (BUILD_IDENTITY_INVALID, None)
    return (BUILD_IDENTITY_EMBEDDED, value)


def core_identity(package_root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Identity of the running Core, computed without git.

    Fields:
    - ``schema``: ``nexus.core.core-identity.v1-experimental``.
    - ``distribution``: ``"nexus-certify"``.
    - ``build_identity``: ``EMBEDDED`` / ``UNSTAMPED`` / ``INVALID_STAMP``.
    - ``version``, ``git_commit``, ``git_tree`` (40 or 64 hex, no prefix),
      ``git_dirty``, ``build_source_digest``: from the embedded stamp; all
      null unless ``build_identity == "EMBEDDED"``. ``git_*`` are also null
      for a stamped build made without git metadata.
    - ``source_digest``: always present; digest of the shipped sources on disk
      now. This is the identity to pin for a source checkout or editable
      install.
    - Trust: this is self-reported provenance, not authentication. Whoever can
      write the installed package can rewrite the stamp (or this function).
      Bind to a signed artifact digest when authenticity is required.
    - ``source_matches_build``: ``source_digest == build_source_digest`` when
      stamped, else null. ``False`` means the installed files differ from what
      was built (or the build was made from a dirty tree that changed later).
    """
    root = Path(package_root) if package_root is not None else _package_root()
    state, stamp = read_build_identity(root)
    digest = source_digest(root)
    result: dict[str, Any] = {
        "schema": CORE_IDENTITY_SCHEMA_ID,
        "distribution": DISTRIBUTION_NAME,
        "build_identity": state,
        "version": None,
        "git_commit": None,
        "git_tree": None,
        "git_dirty": None,
        "build_source_digest": None,
        "source_digest": digest,
        "source_matches_build": None,
    }
    if stamp is not None:
        result.update(
            {
                "version": stamp["version"],
                "git_commit": stamp["git_commit"],
                "git_tree": stamp["git_tree"],
                "git_dirty": stamp["git_dirty"],
                "build_source_digest": stamp["source_digest"],
                "source_matches_build": stamp["source_digest"] == digest,
            }
        )
    return result


def make_build_identity(
    *,
    version: str,
    git_commit: str | None,
    git_tree: str | None,
    git_dirty: bool | None,
    source_digest_value: str,
) -> dict[str, Any]:
    """Build-time helper used by ``setup.py``; validates before returning."""
    stamp: dict[str, Any] = {
        "schema": BUILD_IDENTITY_SCHEMA_ID,
        "distribution": DISTRIBUTION_NAME,
        "version": version,
        "git_commit": git_commit,
        "git_tree": git_tree,
        "git_dirty": git_dirty,
        "source_digest": source_digest_value,
    }
    if not validate_build_identity(stamp):
        raise ValueError(f"malformed build identity: {stamp!r}")
    return stamp


CORE_IDENTITY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": CORE_IDENTITY_SCHEMA_ID,
    "type": "object",
    "required": [
        "schema",
        "distribution",
        "build_identity",
        "version",
        "git_commit",
        "git_tree",
        "git_dirty",
        "build_source_digest",
        "source_digest",
        "source_matches_build",
    ],
    "properties": {
        "schema": {"type": "string", "const": CORE_IDENTITY_SCHEMA_ID},
        "distribution": {"type": "string", "const": DISTRIBUTION_NAME},
        "build_identity": {
            "type": "string",
            "enum": [BUILD_IDENTITY_EMBEDDED, BUILD_IDENTITY_UNSTAMPED, BUILD_IDENTITY_INVALID],
        },
        "version": {"type": ["string", "null"], "minLength": 1},
        "git_commit": {"type": ["string", "null"], "pattern": _GIT_OBJECT_RE.pattern},
        "git_tree": {"type": ["string", "null"], "pattern": _GIT_OBJECT_RE.pattern},
        "git_dirty": {"type": ["boolean", "null"]},
        "build_source_digest": {"type": ["string", "null"], "pattern": _DIGEST_RE.pattern},
        "source_digest": {"type": "string", "pattern": _DIGEST_RE.pattern},
        "source_matches_build": {"type": ["boolean", "null"]},
    },
    "additionalProperties": False,
}

SOURCE_DIGEST_RULE = (
    "sha256 over the concatenation, sorted by UTF-8 relative path, of "
    "'<sha256-hex(file bytes)>  <path>\\n' for every shipped file: product/**/*.py "
    "and product/execution/profiles/*.json|*.lock, excluding __pycache__, bytecode, "
    "product/benchmark/** and product/_build_identity.json; result prefixed 'sha256:'"
)

SOURCE_DIGEST_CONFORMANCE_VECTOR: dict[str, Any] = {
    "files": [
        {"path": "product/__init__.py", "content_utf8": '"""Core."""\n'},
        {"path": "product/protocol/__init__.py", "content_utf8": ""},
        {"path": "product/execution/profiles/p.json", "content_utf8": "{}\n"},
    ],
    "expected_digest": "sha256:5fa2250aff6962d6c5c5007b8fb8fb1fd5faa8ed279d3dad3f5f091c09f751b7",
}


__all__ = [
    "BUILD_IDENTITY_EMBEDDED",
    "BUILD_IDENTITY_FILENAME",
    "BUILD_IDENTITY_INVALID",
    "BUILD_IDENTITY_SCHEMA_ID",
    "BUILD_IDENTITY_UNSTAMPED",
    "CORE_IDENTITY_SCHEMA",
    "CORE_IDENTITY_SCHEMA_ID",
    "DISTRIBUTION_NAME",
    "SOURCE_DIGEST_CONFORMANCE_VECTOR",
    "SOURCE_DIGEST_RULE",
    "core_identity",
    "make_build_identity",
    "read_build_identity",
    "shipped_source_paths",
    "source_digest",
    "source_digest_of_files",
    "validate_build_identity",
]
