## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import os
import logging

from abc import ABC, abstractmethod
from collections import OrderedDict
from firmwire.util.symbol import SymbolTable
from firmwire.memory_map import MemoryMap
from firmwire.util.param import ParamValidator, ParamValidationError
from firmwire.emulator.firmwire import FirmWireEmu

log = logging.getLogger(__name__)


class Loader(ABC, MemoryMap):
    def __init__(self, path, workspace, **kwargs):
        # ABC validation case
        if path is None:
            return

        MemoryMap.__init__(self)

        self.path = path
        self.workspace = workspace
        self.symbol_table = SymbolTable()
        self._machine_class = None

        # Convert the loader args specification
        self.loader_args = (
            ParamValidator().build_params(self.LOADER_ARGS).parse_from_dict(kwargs)
        )

        ########################
        # this line vvvv must be last in __init__. Subloaders should not override __init__
        self._base_props = set(list(self.__dict__.keys()) + ["_base_props"])
        ########################

    @property
    @abstractmethod
    def NAME():
        """Class attribute: the name of the loader. Must be unique across the codebase"""
        pass

    @property
    @abstractmethod
    def ARCH(self):
        """Property: the CPU architecture of the firmware. CPU may not be known until after loading"""
        pass

    @property
    @classmethod
    @abstractmethod
    def LOADER_ARGS(cls):
        """
        Class attribute: specify the parameters that can be passed to the loader

        Format is a dictionary with the key as the parameter name. The value is another
        dictionary who's keys are directly passed to argparse.ArgumentParser.add_argument for validation.

        Args are parsed on loader creation and their values saved as the loader_args variable
        """
        pass

    @staticmethod
    @abstractmethod
    def is_relevant(path):
        """
        Check the path to see if it is relevant to this loader. This should
        be very fast and just try to eliminate obviously irrelevant files.

        This should not use the built in Workspace. If any files needs to be created
        to check if its appropriate to load, create a new ScratchWorkspace
        """
        pass

    @abstractmethod
    def try_load(self):
        """
        Try to load the target path. Return a boolean of the result.

        If the loader returns True, the loading was successful and this is able
        to be used by the vendor specific emulation controller.

        If this function returns False, the loader is in an undefined state.

        This function should only be called once for the lifetime of a loader
        object.
        """
        pass

    def get_loader_keys(self):
        """Get the new attribute names created during the loading process"""
        new_keys = list(set(list(self.__dict__.keys())) - self._base_props)
        return new_keys

    def get_machine(self):
        """Get an instance of the loader specified machine after try_load succeeds"""
        assert self._machine_class is not None, "Loader failed to define a machine"
        assert issubclass(
            self._machine_class, FirmWireEmu
        ), "Loader machine class not the right type"
        return self._machine_class()


################################

LOADER_BY_NAME = OrderedDict()


def load_any(
    path,
    workspace,
    keep_trying=True,
    loader_specific_args=None,
    loader_filter=None,
    **any_loader_args
):
    """Try loading firmware using all registered loaders"""

    if not os.path.exists(path):
        raise FileNotFoundError("Path does not exist")

    loaders = find_relevant_loaders(path)

    if len(loaders) == 0:
        log.error("No loaders signal support for %s", path)
        return None

    # use the first one that succeeded
    for loader_cls in find_relevant_loaders(path):
        if loader_filter and not loader_filter(loader_cls):
            continue

        loader_args = {}
        loader_args.update(any_loader_args)

        if loader_specific_args is not None:
            if loader_cls.NAME in loader_specific_args:
                loader_args.update(loader_specific_args[loader_cls.NAME])

        obj = _do_load(loader_cls, path, workspace, **loader_args)

        if obj is not None:
            return obj
        elif not keep_trying:
            break

    log.error("No more loaders to try")

    return None


def load(path, workspace, loader_name, **loader_args):
    """Try loading firmware using a specific loader by name"""

    if not os.path.exists(path):
        raise FileNotFoundError("Path does not exist")

    if loader_name not in LOADER_BY_NAME:
        raise ValueError("Requested loader '%s' does not exist" % (loader_name))

    loader_cls = LOADER_BY_NAME[loader_name]
    return _do_load(loader_cls, path, workspace, **loader_args)


def _do_load(loader_cls, path, workspace, **loader_args):
    if len(loader_args):
        log.info(
            "Reading firmware using %s (%s) and args %s",
            loader_cls.__name__,
            loader_cls.NAME,
            loader_args,
        )
    else:
        log.info("Reading firmware using %s (%s)", loader_cls.__name__, loader_cls.NAME)

    try:
        obj = loader_cls(path, workspace, **loader_args)
    except ParamValidationError as e:
        log.error("Invalid params passed to loader: %s", e)
        return None

    if obj.try_load():
        log.info("Loading complete")
        return obj
    else:
        log.error("Loading failed!")
        return None


def find_relevant_loaders(path):
    if not os.path.exists(path):
        raise FileNotFoundError("Path does not exist")

    loaders = []

    for name, loader in LOADER_BY_NAME.items():
        if loader.is_relevant(path):
            loaders += [loader]

    return loaders


def get_loaders():
    return list(LOADER_BY_NAME.values())


def get_loader(name):
    return LOADER_BY_NAME[name]


def register_loader(loader):
    Loader.register(loader)
    # Try instantiating it to check for abstract methods
    loader(None, None)

    global LOADER_BY_NAME
    LOADER_BY_NAME[loader.NAME] = loader
