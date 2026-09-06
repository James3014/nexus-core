"""Clean environment installed-wheel smoke test.

Verifies:
1. Imports product from site-packages outside checkout directory.
2. Asserts product.__file__ is from site-packages, not checkout.
3. Constructs PythonOCIRunner() and loads packaged profile resources.
"""

import os
import sys
import tempfile
from pathlib import Path


def main() -> int:
    outside = Path(tempfile.gettempdir()).resolve()
    os.chdir(outside)

    import product
    from product.execution.python_runner import PythonOCIRunner

    product_file = Path(product.__file__).resolve()
    print(f"[smoke] Loaded product from: {product_file}")

    if "site-packages" not in str(product_file):
        print(f"[smoke] ERROR: product was not imported from site-packages: {product_file}", file=sys.stderr)
        return 1

    runner = PythonOCIRunner()
    if runner.profile is None:
        print("[smoke] ERROR: PythonOCIRunner profile is None", file=sys.stderr)
        return 1

    if runner.profile.profile_id != "python-oci-pytest-v1":
        print(f"[smoke] ERROR: Unexpected profile_id: {runner.profile.profile_id}", file=sys.stderr)
        return 1

    print(f"[smoke] SUCCESS: PythonOCIRunner profile loaded: {runner.profile.profile_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
