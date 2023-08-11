## Copyright (c) 2023, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from argparse import ArgumentParser
from firmwire.util.param import ParamValidator
from pathlib import Path


class MachineInitParams:
    ARGS = {
        "injected-task": {"type": str},
        "consecutive-ports": {"type": int},
        "fuzz": {"type": str},
        "fuzz-triage": {"type": str},
        "fuzz-input": {"type": str, "default": None},
        "fuzz-persistent": {"type": int},
        "fuzz-crashlog-dir": {"type": str, "default": None},
        "fuzz-crashlog-replay": {"type": str, "default": None},
        "raw-asm-logging": {"type": bool},
    }

    @staticmethod
    def param_arg_spec(name):
        name = name.replace("--", "")
        spec = dict(MachineInitParams.ARGS[name])

        if "type" in spec and spec["type"] == bool:
            del spec["type"]

        return spec

    def __init__(self):
        self._param_remap = {k.replace("-", "_"): k for k in self.ARGS}
        self._params = {k: None for k in self._param_remap}

    def __getitem__(self, name):
        return self.get(name)

    def __setitem__(self, name, value):
        return self.set(name, value)

    def __getattr__(self, name):
        if self._params and name in self._params:
            return self._params[name]

        return self.__getattribute__(name)

    def validate(self, arg_parser=None):
        def error(msg):
            raise ValueError(msg)

        if arg_parser:
            assert isinstance(arg_parser, ArgumentParser)
            error = lambda x: arg_parser.error(x)

        if (
            sum([bool(a) for a in [self.fuzz, self.fuzz_triage, self.injected_task]])
            > 1
        ):
            error("--fuzz, --fuzz-triage, and --module are mutually exclusive")

        if (self.fuzz or self.fuzz_triage) and not (
            self.fuzz_input or self.fuzz_crashlog_replay
        ):
            error(
                "--fuzz and --fuzz-triage flags need --fuzz-input or --fuzz-crashlog-replay as well"
            )
        if self.fuzz_persistent and not (self.fuzz or self.fuzz_triage):
            error("--fuzz-persistent requires --fuzz")
        if self.fuzz_persistent and self.fuzz_persistent < 1:
            error("--fuzz-persistent loops count must be one or greater")
        if self.fuzz_crashlog_dir and self.fuzz_crashlog_replay:
            error(
                "--fuzz-crashlog-dir and --fuzz-crashlog-replay are mutually exclusive"
            )
        if self.fuzz_crashlog_replay and self.fuzz_input:
            error("Cannot replay a crash log and a single file at the same time.")

        return True

    def set(self, param_name, value):
        if value is None:
            raise ValueError("Parameters must have a value")

        if param_name not in self._params:
            raise KeyError("Parameter %s does not exist" % (param_name))

        ty = self.ARGS[self._param_remap[param_name]]["type"]

        if type(value) != ty:
            raise TypeError("Parameter %s must have type %s" % (param_name, ty))

        self._params[param_name] = value
        return self

    def has(self, param_name):
        return param_name in self._params

    def get(self, param_name):
        if param_name not in self._params:
            raise KeyError("Parameter %s does not exist" % (param_name))
        return self._params[param_name]

    def unset(self, param_name):
        if param_name not in self._params:
            raise KeyError("Parameter %s does not exist" % (param_name))
        self._params[param_name] = None
        return self

    def set_fuzz(self, fuzzing_module, inp):
        return self.unset("fuzz_triage").set("fuzz", fuzzing_module).set_fuzz_input(inp)

    def set_fuzz_input(self, inp):
        return self.set("fuzz_input", inp)

    def set_fuzz_persistent(self, times):
        return self.set("fuzz_persistent", times)

    def set_fuzz_triage(self, fuzzing_module, inp):
        return self.unset("fuzz").set("fuzz_triage", fuzzing_module).set_fuzz_input(inp)
