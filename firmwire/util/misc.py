## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import types
import sys
import os
import re
import argparse
import logging

log = logging.getLogger(__name__)


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


def arg_tuple(s, lhs=None, rhs=None):
    match = re.match(r"^([^\s,]+),([^\s,]+)$", s)

    if not match:
        raise argparse.ArgumentTypeError('must be a tuple (ex: "lhs,rhs")')

    return [lhs(match.group(1)), rhs(match.group(2))]


def arg_snapshot(s):
    return arg_tuple(s, lhs=number_parse, rhs=str)


def number_parse(s):
    match = re.match(r"^(0x[a-fA-f0-9]+)|([0-9]+)$", s)

    if not match:
        raise argparse.ArgumentTypeError('expected number, got "{}"'.format(s))

    if match.group(1):
        return int(match.group(1), 16)
    elif match.group(2):
        return int(match.group(2), 10)
    else:
        assert 0


def download_url(url):
    """Download a URL to a file. Return's the filename"""
    import requests
    from urllib.parse import urlparse

    log.info("Downloading %s...", url)

    with requests.get(url, stream=True) as r:
        r.raise_for_status()

        headers = r.headers
        length = int(headers.get("Content-Length", "0"))

        filename = urlparse(url).path
        cd_filename = headers.get("Content-Disposition", "")

        m = re.search(r'filename[^\'"=;\n]*=[\'"]([^\'";\n]+)', cd_filename)
        if m:
            filename = m.group(1)

        filename = os.path.basename(os.path.normpath(filename.strip()))

        if filename == "":
            log.error("Unable to get filename from URL")
            return None

        if os.path.exists(filename) and os.stat(filename).st_size == length:
            log.info("Using cached file %s", filename)
            return filename

        with open(filename, "wb") as fp:
            nprint = 10
            length_downloaded = 0

            for chunk in r.iter_content(chunk_size=1 * 1024):
                length_downloaded += len(chunk)
                fp.write(chunk)

                if length:
                    percentage = int(100.0 * length_downloaded / length)
                    if percentage >= nprint:
                        log.info("Downloaded %d%%...", percentage)
                        nprint = min(percentage + 10, 100)

        log.info("Downloaded %d byte file %s", length_downloaded, filename)
        return filename
