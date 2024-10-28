## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import argparse
import shlex
from collections.abc import Mapping


class ParamValidationError(Exception):
    pass


class ArgumentParserNoExit(argparse.ArgumentParser):
    # Convert argparse's error exit to an exception
    def error(self, message):
        raise ParamValidationError(message)


class ParamValidator:
    def __init__(self, arg_name_prefix=""):
        self._arg_name_prefix = arg_name_prefix
        self.reset()

    def reset(self):
        """Clear the parsed parameters"""
        self._parser = ArgumentParserNoExit()
        self._actions = {}
        self._known_keys = set()
        self._built_params = {}

    def build_params(self, params):
        """Build a set of parameters from a specification"""
        assert isinstance(params, Mapping)

        for param, props in sorted(params.items(), key=lambda x: x[0]):
            self.create_param(param, **props)

        return self

    def iterparams(self):
        for k, v in self._built_params.items():
            yield (k, v)

    def copy_params_to_parser(self, parser, param_hook=None, arg_name_prefix=""):
        actions = {}

        """Copy the created parameters to another parser"""
        for name, params in sorted(self._built_params.items(), key=lambda x: x[0]):
            if param_hook:
                # make a shallow copy to allow the hook to make changes to keys
                params = dict(params)
                param_hook(name, params)

            action = self._create_argparse_param(
                parser, name, params, arg_name_prefix=arg_name_prefix
            )
            actions[name] = action

        return actions

    def create_param(self, name, **kwargs):
        assert name not in self._known_keys, "Duplicate parameter %s" % (name)

        # set some fields if missing
        for k, v in [
            ("required", False),
            ("help", None),
            ("default", None),
            ("type", None),
            ("choices", None),
        ]:
            if k not in kwargs:
                kwargs[k] = v

        action = self._create_argparse_param(self._parser, name, kwargs)

        self._known_keys.add(name)
        self._built_params[name] = kwargs
        self._actions[name] = action

        return self

    def extract_relevant_params(self, params, arg_name_prefix=""):
        if hasattr(params, "__dict__"):
            params = vars(params)

        if not arg_name_prefix:
            arg_name_prefix = self._arg_name_prefix

        ext_params = {
            k: params[k]
            for k in filter(
                lambda x: x in map(lambda x: arg_name_prefix + x, self._known_keys),
                params.keys(),
            )
        }
        replaced_params = dict(
            map(lambda x: (x[0].replace(arg_name_prefix, ""), x[1]), ext_params.items())
        )
        non_none_params = dict(
            filter(lambda x: x[1] is not None, replaced_params.items())
        )

        return non_none_params

    def parse_from_dict(self, params):
        flat_params = []
        [
            flat_params.extend(["--" + self._arg_name_prefix + str(k), str(v)])
            for k, v in params.items()
        ]

        return self.parse_from_args(flat_params)

    def parse_from_args(self, args):
        return vars(self._parser.parse_args(args))

    def parse_from_cmdline(self, cmdline):
        return self.parse_from_args(shlex.split(cmdline))

    def _create_argparse_param(self, parser, name, kwargs, arg_name_prefix=""):
        disallowed_keys = kwargs.keys() - set(
            ["type", "choices", "default", "required", "help"]
        )

        if len(disallowed_keys):
            raise ParamValidationError(
                "Unable to create parameter %s: illegal key %s"
                % (name, list(disallowed_keys))
            )

        if name.startswith("-"):
            raise ParamValidationError("Parameter %s starts with a '-'" % name)

        if not arg_name_prefix:
            arg_name_prefix = self._arg_name_prefix

        try:
            # no short arguments are allowed
            action = parser.add_argument(
                "--" + arg_name_prefix + name, dest=arg_name_prefix + name, **kwargs
            )
        except TypeError as e:
            raise ParamValidationError(
                "Unable to create parameter %s: ArgumentParser.add_argument unexpected keyword"
                % (name)
            )

        return action
