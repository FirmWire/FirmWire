## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import re


class FirmWireGuestLogger:
    def __init__(self, machine):
        self._machine = machine
        self.reset()

    def reset(self):
        # None = all, {} = no logging, "name" in {...} = "name" enabled
        self._tasks_enabled = None

        self._repeat_streak = 0
        self._repeat_streak_step = 2
        self._disabled_streak = 0
        self._skipped_names = {}
        self._last_msg = ""

        self._banned_addresses = set()
        self._banned_log_hashes = set()
        self._banned_log_patterns = []

    def add_ban_pattern(self, pattern):
        pat = re.compile(pattern)
        self._banned_log_patterns.append(pat)

    def add_ban_string(self, string):
        pat = re.compile(re.escape(string))
        self._banned_log_patterns.append(pat)

    def log_emit(self, fmt, *args, **meta):
        task_name = meta.get("task_name", None)
        address = meta.get("address", None)

        if task_name is None:
            task_name = "NO_TASK"

        this_msg = None

        # fallback to the string itself if no address was provided
        # this is more expensive - pass an address
        if address is None:
            this_msg = (fmt) % (args)
            log_hash = hash(this_msg)
        else:
            log_hash = None

        if (
            self.task_log_enabled(task_name)
            and address not in self._banned_addresses
            and log_hash not in self._banned_log_hashes
        ):
            if self._disabled_streak > 0:
                self._write(
                    ("[%.5f] %d total log lines omitted [%s]")
                    % (
                        self._machine.time_running(),
                        self._disabled_streak,
                        self._format_skipped_report(),
                    )
                )
                self._disabled_streak = 0
                self._skipped_names = {}

            if this_msg is None:
                this_msg = (fmt) % (args)

            if this_msg == self._last_msg:
                self._repeat_streak += 1
                if (self._repeat_streak % self._repeat_streak_step) == 0:
                    if self._repeat_streak > 10000:
                        deadlock_warn = " [Deadlock?]"
                    else:
                        deadlock_warn = ""

                    self._write(
                        ("[%.5f] last message repeated %d times%s")
                        % (
                            self._machine.time_running(),
                            self._repeat_streak,
                            deadlock_warn,
                        )
                    )
                    self._repeat_streak_step = min(self._repeat_streak * 2, 10000)
            else:
                self._repeat_streak = 0
                self._repeat_streak_step = 2

                if address is not None:
                    location = "0x%x" % address

                    sym = self._machine.symbol_table.lookup(address)

                    if sym is not None:
                        offset = address - sym.address

                        if abs(offset) < 0x1000:
                            location = sym.format(offset) + " (%s)" % location

                    self._write(
                        ("[%.5f][%s] %s %s")
                        % (self._machine.time_running(), task_name, location, this_msg)
                    )
                else:
                    self._write(
                        ("[%.5f][%s] %s")
                        % (self._machine.time_running(), task_name, this_msg)
                    )

            for vibe_check in self._banned_log_patterns:
                if vibe_check.search(this_msg):
                    if address is not None:
                        self._banned_addresses.add(address)

                    if log_hash is not None:
                        self._banned_log_hashes.add(log_hash)

                    self._write(
                        ("[%.5f] last message matched ban pattern '%s'")
                        % (self._machine.time_running(), vibe_check.pattern)
                    )
                    break

            self._last_msg = this_msg
        else:
            self._disabled_streak += 1
            self._skipped_names[task_name] = self._skipped_names.get(task_name, 0) + 1

            if (self._disabled_streak % 1000) == 0:
                self._write(
                    ("[%.5f] %d log lines omitted [%s]")
                    % (
                        self._machine.time_running(),
                        self._disabled_streak,
                        self._format_skipped_report(),
                    )
                )

    def task_log_enabled(self, task_name):
        if self._tasks_enabled is None:
            return True

        return task_name in self._tasks_enabled

    def task_log_enable_all(self):
        self._tasks_enabled = None

    def task_log_disable_all(self):
        self._tasks_enabled = set()

    def task_log_enable(self, *tasks):
        if self._tasks_enabled is None:
            self._tasks_enabled = set()

        for task_name in tasks:
            self._tasks_enabled.add(task_name)

    def task_log_exclusive(self, *tasks):
        self.task_log_disable_all()

        for task_name in tasks:
            self._tasks_enabled.add(task_name)

    def task_log_disable(self, *tasks):
        if self._tasks_enabled is None:
            return

        for task_name in tasks:
            self._tasks_enabled.discard(task_name)

    def _format_skipped_report(self):
        MAX_NAME = 10
        sorted_skipped = sorted(
            self._skipped_names.items(), reverse=True, key=lambda x: x[1]
        )
        overflow = len(sorted_skipped) > MAX_NAME

        if overflow:
            sorted_skipped = sorted_skipped[:MAX_NAME]

        return " ".join(["%s=%d" % (name, count) for name, count in sorted_skipped]) + (
            " ..." if overflow else ""
        )

    def _write(self, logdata):
        print(logdata)
