#!/usr/bin/env python3
"""Build the Nexus Verify OpenAI plugin ZIP reproducibly from repository source."""

from __future__ import annotations

import argparse
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "distribution" / "nexus-verify-plugin"
DEFAULT_OUTPUT = ROOT / "dist" / "nexus-verify-plugin.zip"
FIXED_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def build(output: Path) -> Path:
    files = sorted(path for path in PACKAGE_ROOT.rglob("*") if path.is_file())
    if not files:
        raise RuntimeError("Nexus Verify plugin package is empty")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(PACKAGE_ROOT).as_posix()
            info = zipfile.ZipInfo(relative, FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, path.read_bytes())
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(build(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
