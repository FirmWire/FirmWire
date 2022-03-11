## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import types


def copy_function(function, module=None, name=None):
    """
    Copy a function and optionally change its name and module definition
    """
    name = name if name else function.__name__
    module = module if module else function.__module__

    new_function = types.FunctionType(
        function.__code__,
        function.__globals__,
        name,
        function.__defaults__,
        function.__closure__,
    )

    new_function.__dict__.update(function.__dict__)

    new_function.__qualname__ = name
    new_function.__module__ = module

    return new_function
