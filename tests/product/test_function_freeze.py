from __future__ import annotations

from types import FunctionType

import product.certification.receipt as receipt_module
import product.evidence as evidence_module
from product.protocol._function_freeze import _freeze_function_globals


def test_freeze_helper_is_a_single_shared_definition():
    assert evidence_module._freeze_function_globals is _freeze_function_globals
    assert receipt_module._freeze_function_globals is _freeze_function_globals


def test_frozen_function_keeps_original_global_after_rebinding():
    namespace: dict[str, object] = {"VALUE": "original"}
    exec("def read_value():\n    return VALUE\n", namespace)
    original = namespace["read_value"]
    assert isinstance(original, FunctionType)

    frozen = _freeze_function_globals(original)
    namespace["VALUE"] = "rebound"

    assert original() == "rebound"
    assert frozen() == "original"
    assert frozen is not original
