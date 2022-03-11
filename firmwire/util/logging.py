## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import sys
import logging

COLOR_RED_INTENSE = "\033[1;31m"
COLOR_RED = "\033[31m"
COLOR_WHITE_INTENSE = "\033[1;37m"
COLOR_WHITE = "\033[37m"
COLOR_YELLOW_INTENSE = "\033[1;33m"
COLOR_YELLOW = "\033[33m"
COLOR_DEFAULT = "\033[0m"

COLOR_MAP = {
    logging.INFO: COLOR_WHITE_INTENSE,
    logging.ERROR: COLOR_RED_INTENSE,
    logging.WARNING: COLOR_YELLOW_INTENSE,
    logging.CRITICAL: COLOR_RED_INTENSE,
}

LEVEL_NAME = {
    logging.INFO: "INFO",
    logging.ERROR: "ERROR",
    logging.WARNING: "WARN",
    logging.CRITICAL: "CRIT",
}


def setup_logging(
    debug=False, enable_colors=False, avatar_debug=False, show_package=False
):
    if debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    if not avatar_debug:
        logger = logging.getLogger("avatar")
        logger.propagate = False

    if show_package:
        fmt = "[%(levelname)s] %(name)s: %(message)s"
    else:
        fmt = "[%(levelname)s] %(message)s"

    root = logging.getLogger()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)

    root.addHandler(handler)

    for k, v in LEVEL_NAME.items():
        if enable_colors:
            logging.addLevelName(k, COLOR_MAP[k] + v + COLOR_DEFAULT)
        else:
            logging.addLevelName(k, v)
