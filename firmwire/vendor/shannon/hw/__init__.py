## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from firmwire.hw.peripheral import *

from .uart import UARTPeripheral, MotoUARTPeripheral
from .shannoncp import SHMPeripheral
from .shannonsoc import ShannonSOCPeripheral
from .Unknown2Peripheral import Unknown2Peripheral
from .sipc import SIPCPeripheral
from .ClkPeripheral import *
from .PMICPeripheral import PMICPeripheral
from .DSPPeripheral import DSPPeripheral, S355DSPBufferPeripheral, MarconiPeripheral
from .shannon_timer import ShannonTimer, ShannonTCU, ShannonUptimer
from .abox import ShannonAbox
from .s3xxap import S3xxAPBoot
