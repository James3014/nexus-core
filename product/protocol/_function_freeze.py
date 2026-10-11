"""Shared helper that snapshots a function's module globals.

Leaf module: imports nothing from ``product``.
"""

from types import FunctionType


def _freeze_function_globals(function):
    frozen = FunctionType(
        function.__code__,
        dict(function.__globals__),
        function.__name__,
        function.__defaults__,
        function.__closure__,
    )
    frozen.__kwdefaults__ = (
        dict(function.__kwdefaults__) if function.__kwdefaults__ is not None else None
    )
    frozen.__annotations__ = dict(function.__annotations__)
    return frozen
