## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import os
import logging
import json
import re
import pickle
import shutil
import shlex

from subprocess import run
from datetime import datetime

log = logging.getLogger(__name__)

SNAPSHOT_RE = re.compile(r"[-a-zA-Z0-9_]+")

SNAPSHOT_VERSION = 2

# if the metadata or fields saved change, bump the version
SNAPSHOT_METADATA = {
    "address": int,  # where the snapshot was taken
    "qemu_arguments": list,  # the arguments to QEMU/Panda/PyPanda
    "firmwire_arguments": list,  # the arguments to firmwire
    "reason": str,  # the purpose of this snapshot
}


class QemuSnapshotManager(object):
    def __init__(self, snapshot_store):
        self.snapshot_store = snapshot_store
        self.snapshot_qcow_path = os.path.join(self.snapshot_store, "snapshots.qcow2")
        self._clear_cache()

    def check(self, create_if_missing=True):
        self._qemu_img = shutil.which("qemu-img")

        if self._qemu_img is None:
            log.error("Unable to find `qemu-img` in PATH. Unable to manage snapshots")
            return False

        if not os.access(self.snapshot_qcow_path, os.R_OK):
            create_args = ["create", "-f", "qcow2", self.snapshot_qcow_path, "128M"]

            if not create_if_missing:
                log.error(
                    "Missing QEMU snapshot image storage: %s", self.snapshot_qcow_path
                )
                log.error(
                    "Please create it by running `%s`",
                    " ".join([shlex.quote(x) for x in [self._qemu_img] + create_args]),
                )
                return False
            else:
                log.info("Snapshot storage misssing. Creating...")
                output = self._exec(create_args)

                if output is None:
                    log.error("Unable to create snapshot storage")
                    return False

                log.info("Created snapshot storage: %s", output.strip())

        try:
            # check the storage to make sure its working and cache the snapshots
            self.list()
        except ValueError as e:
            log.error("Unable to get snapshot list: %s", e)
            return False

        return True

    def _clear_cache(self):
        self._snapshot_list_cache = None
        self._snapshot_aux_cache = {}

    def list(self):
        if self._snapshot_list_cache is not None:
            return self._snapshot_list_cache

        output = self._exec(
            ["info", "-f", "qcow2", "--output=json", self.snapshot_qcow_path]
        )

        if output is None:
            raise ValueError("Failed to get json response")

        try:
            meta = json.loads(output)
        except json.JSONDecodeError as e:
            raise ValueError("Failed to decode json response: %s" % (e))

        if "format" not in meta:
            raise ValueError("Missing required key 'format' from qemu-img response")
        else:
            if meta["format"] != "qcow2":
                raise ValueError(
                    "Snapshot store is not in QCOW2 format: %s" % (meta["format"])
                )

        snapshot_dict = {}

        # qemu-img doesn't have this key if there arent snapshots yet
        if "snapshots" not in meta:
            meta["snapshots"] = []

        for s in meta["snapshots"]:
            name = s["name"]
            del s["name"]
            snapshot_dict[name] = s

        self._snapshot_list_cache = snapshot_dict

        return snapshot_dict

    def take(self, name, monitor, peripherals, machine_state, metadata={}):
        # we assume QEMU is already stopped
        if not SNAPSHOT_RE.match(name):
            raise ValueError("Snapshot name %s illegal" % name)

        self._clear_cache()
        self._validate_metadata(metadata)

        snapshot_info_path = os.path.join(self.snapshot_store, "%s.snapinfo" % name)

        if metadata["reason"]:
            log.info(
                "Taking snapshot %s to %s (reason: %s)",
                name,
                self.snapshot_qcow_path,
                metadata["reason"],
            )
        else:
            log.info("Taking snapshot %s to %s", name, self.snapshot_qcow_path)

        log.info("Saving snapshot auxiliary data to %s", snapshot_info_path)

        snapshot_info = {
            "version": SNAPSHOT_VERSION,
            "metadata": metadata,
            "peripherals": peripherals,
            "machine_state": machine_state,
        }

        try:
            with open(snapshot_info_path, "wb") as fp:
                pickle.dump(snapshot_info, fp)
        except (pickle.PicklingError, IOError, TypeError, AttributeError) as e:
            log.error("Snapshot failed to save snapinfo: %s", e)
            return False

        log.info("Snapshotting QEMU state...")
        result = monitor.execute_command(
            "human-monitor-command", {"command-line": "savevm %s" % name}
        )

        if result != "":
            os.unlink(snapshot_info_path)
            log.error("Snapshot failed: " + result)
            return False
        else:
            log.info("Snapshot completed!")
            return True

    def restore(self, name, monitor):
        # we assume QEMU is already stopped
        if not SNAPSHOT_RE.match(name):
            raise ValueError("Snapshot name %s illegal" % name)

        self._clear_cache()
        snapshots = self.list()

        if name not in snapshots:
            log.error("Snapshot %s does not exist in %s", name, self.snapshot_qcow_path)
            return None

        log.info("Restoring snapshot %s from %s", name, self.snapshot_qcow_path)

        snapshot_info = self._load_auxiliary_file(name)

        if snapshot_info is None:
            return None

        result = monitor.execute_command(
            "human-monitor-command", {"command-line": "loadvm %s" % name}
        )

        if "error" in result:
            log.error("Restoring QEMU snapshot failed:\n%s", result)
            return None

        log.info("Restored QEMU snapshot memory image")

        return snapshot_info

    def _load_auxiliary_file(self, name):
        snapshots = self.list()

        if name in self._snapshot_aux_cache:
            return self._snapshot_aux_cache[name]

        snapshot_info_path = os.path.join(self.snapshot_store, "%s.snapinfo" % name)
        log.info("Loading snapshot auxiliary data from %s", snapshot_info_path)

        try:
            with open(snapshot_info_path, "rb") as fp:
                snapshot_info = pickle.load(fp)
        except IOError:
            # likely pre-versioned snapshot store
            try:
                legacy_name = "avatar-snapshot-%s" % name
                with open(legacy_name, "rb") as fp:
                    peripherals = pickle.load(fp)

                log.warning(
                    "Snapshot %s is using legacy auxiliary file path %s",
                    name,
                    legacy_name,
                )

                snapshot_info = {
                    "version": 0,
                    "metadata": {},
                    "peripherals": peripherals,
                }
            except IOError:
                log.error("Snapshot %s is missing auxiliary file", name)
                return None
        except (pickle.PicklingError, TypeError, AttributeError) as e:
            log.error("Snapshot failed to load snapinfo: %s", e)
            return None

        if snapshot_info["version"] > 0:
            if snapshot_info["version"] != SNAPSHOT_VERSION:
                log.error(
                    "Saved snapshot version mismatch (got v%d, current v%d). Retake snapshot!",
                    snapshot_info["version"],
                    SNAPSHOT_VERSION,
                )
                return None

            if "metadata" not in snapshot_info:
                log.error("Malformed snapshot auxiliary file: missing metadata key")
                return None

            self._validate_metadata(snapshot_info["metadata"])

        # enrich the metadata with qemu snapshot info
        snapshot_info["qemu"] = snapshots[name]

        self._snapshot_aux_cache[name] = snapshot_info

        return snapshot_info

    def print_info(self, name):
        data = self._load_auxiliary_file(name)

        if data is None:
            raise ValueError("Invalid snapshot %s" % name)

        if data["version"] >= 1:
            m = data["metadata"]
            log.info("Snapshot address: 0x%08x", m["address"])
            log.info("Snapshot reason: %s", m["reason"])
            log.info("Snapshot firmwire args: %s", " ".join(m["firmwire_arguments"]))

        log.info("Snapshot time: %s", datetime.fromtimestamp(data["qemu"]["date-sec"]))
        log.info(
            "Snapshot VM stop time: %d.%d",
            data["qemu"]["vm-clock-sec"],
            data["qemu"]["vm-clock-nsec"],
        )

    def _validate_metadata(self, metadata):
        if SNAPSHOT_VERSION in [1, 2]:
            for k, v in metadata.items():
                if k not in SNAPSHOT_METADATA:
                    raise ValueError("Snapshot metadata key %s not supported" % k)

                if type(v) != SNAPSHOT_METADATA[k]:
                    raise ValueError(
                        "Snapshot metadata key %s not type mismatch (%s != %s expected)"
                        % (k, type(v), SNAPSHOT_METADATA[k])
                    )
        else:
            raise NotImplementedError(
                "Snapshot metadata validation not supported for version %d"
                % SNAPSHOT_VERSION
            )

    def _exec(self, args):
        cmdline = [self._qemu_img] + args
        proc = run(cmdline, capture_output=True)

        if proc.returncode != 0:
            log.error("'%s' returned error %d", " ".join(cmdline), proc.returncode)
            stdout = proc.stdout.decode(errors="ignore")
            stderr = proc.stderr.decode(errors="ignore")

            if stdout:
                log.error("--- STDOUT ---\n%s--------------", stdout)

            if stderr:
                log.error("--- STDERR ---\n%s--------------", stderr)

            return None

        return proc.stdout.decode()
