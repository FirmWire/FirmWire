## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from collections import OrderedDict
from abc import ABC, abstractmethod


class FirmWireSOC(ABC):
    @property
    @abstractmethod
    def peripherals():
        pass

    @property
    @abstractmethod
    def name():
        pass


class SOCPeripheral(object):
    def __init__(self, cls, address, size, **kwargs):
        self._cls = cls
        self._address = address
        self._size = size
        self._attr = kwargs
        self._created_peripheral = None

    def __call__(self, name, address, size, **kwargs):
        # XXX: peripherals which are class properties are single instance, breaking this as only a single instance can exist
        assert (
            self._created_peripheral is None
        ), "SOCPeripheral can only be realized once"
        self._created_peripheral = self._cls(name, address, size, **kwargs)
        return self._created_peripheral

    def resolve(self):
        """Return a reference to the created peripheral object"""
        assert self._created_peripheral is not None, "SOCPeripheral was never created"
        return self._created_peripheral


################################

SOC_BY_NAME = OrderedDict()


def get_soc(vendor, name):
    vendor_socs = SOC_BY_NAME.get(vendor)

    if vendor_socs is None:
        return None

    return vendor_socs.get(name)


def get_socs(vendor=None):
    if vendor:
        return OrderedDict(SOC_BY_NAME.get(vendor))
    else:
        return OrderedDict(SOC_BY_NAME)


def register_soc(vendor, cls):
    global SOC_BY_NAME

    assert issubclass(cls, FirmWireSOC), "SOC must be derived from FirmWireSOC"

    if vendor not in SOC_BY_NAME:
        SOC_BY_NAME[vendor] = OrderedDict()

    assert cls.name not in SOC_BY_NAME[vendor], (
        "SOC registered twice or with duplicate name %s" % cls.name
    )

    SOC_BY_NAME[vendor][cls.name] = cls
