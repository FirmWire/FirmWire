#!/usr/bin/env python3
"""Add guarded timer hooks to the existing Cortex-R5 GNU ThreadX example.

Usage: python3 enable_timer.py /path/to/ports/cortex_r5/gnu/example_build
Backups use the suffix .before_shannon_timer. Existing build_threadx_sample.sh
continues to build the baseline because it does not define TX_SHANNON_TIMER.
"""
import argparse
import re
import shutil
from pathlib import Path


INSTALLER_REVISION = "stack-match-v2"


DECLARE = '''/* SHANNON TIMER DEMO: declaration */
#ifdef TX_SHANNON_TIMER
void threadx_board_timer_init(void);
#endif'''

INITIALIZE = '''    /* SHANNON TIMER DEMO: initialize peripherals with IRQs masked. */
#ifdef TX_SHANNON_TIMER
    threadx_board_timer_init();
#endif
'''

DISPATCH = '''/* SHANNON TIMER DEMO: hardware acknowledge and ThreadX tick. */
#ifdef TX_SHANNON_TIMER
    BL     threadx_board_irq_dispatch
#else
    BL     _tx_timer_interrupt
#endif'''


def replace_once(text, pattern, replacement, label):
    result, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"Expected one {label}; found {count}. No sources were changed.")
    return result


def normalize_boot_stack(text):
    """Find the initial SP assignment before startup calls C code.

    Accept a direct LDR into SP, or an LDR into a register immediately followed
    by MOV SP, that-register. Comments, capitalization and spacing can vary.
    Require exactly one initial SP assignment before changing its load.
    """
    lines = text.splitlines(keepends=True)
    clean = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"),
                   text, flags=re.DOTALL).splitlines()
    clean = [line.split("@", 1)[0].strip() for line in clean]

    start = None
    for label in ("_mainCRTStartup", "_start", "start"):
        for index, line in enumerate(clean):
            if line == label + ":":
                start = index + 1
                break
        if start is not None:
            break
    if start is None:
        raise ValueError("Cannot locate the C startup label in crt0.S. No sources were changed.")

    stop = next((i for i in range(start, len(clean))
                 if re.match(r"blx?\b", clean[i], re.I)), min(start + 80, len(clean)))
    instructions = [(i, clean[i]) for i in range(start, stop)
                    if clean[i] and not clean[i].startswith((".", "#"))
                    and not clean[i].endswith(":")]
    candidates = []
    assignments = []
    for position, (index, instruction) in enumerate(instructions):
        if re.match(r"(?:ldr|mov|adr)\s+(?:sp|r13)\s*,", instruction, re.I):
            assignments.append(index)
        load = re.fullmatch(r"ldr\s+(r[0-9]+|ip|sp)\s*,\s*(.+)", instruction, re.I)
        if not load:
            continue
        register, operand = load.groups()
        if register.lower() in ("sp", "r13"):
            candidates.append((index, "sp", operand, index))
        elif position + 1 < len(instructions):
            next_index, next_instruction = instructions[position + 1]
            if re.fullmatch(r"mov\s+(?:sp|r13)\s*,\s*" + re.escape(register),
                            next_instruction, re.I):
                candidates.append((index, register, operand, next_index))

    if len(candidates) != 1 or assignments != [candidates[0][3]]:
        excerpt = "".join(f"{i+1}: {lines[i]}" for i in range(start, min(stop, start + 35)))
        raise ValueError("Cannot safely identify one initial stack assignment in crt0.S. "
                         "No sources were changed. Paste this startup block:\n" + excerpt)

    index, register, operand, unused = candidates[0]
    normalized = re.sub(r"[\s()]", "", operand)
    if normalized == "=_stack_bottom+1024":
        return text

    original = lines[index]
    if not re.match(r"\s*ldr\b", original, re.I):
        raise ValueError("The stack load shares a line with a block comment. "
                         "No sources were changed. Paste the start of crt0.S.")
    indent = re.match(r"[ \t]*", original).group(0)
    comment_positions = [p for p in (original.find("@"), original.find("/*")) if p >= 0]
    if comment_positions:
        before_comment = original[:min(comment_positions)]
        if re.sub(r"\s+", "", before_comment) != re.sub(r"\s+", "", clean[index]):
            raise ValueError("The stack load contains an embedded block comment. "
                             "No sources were changed. Paste the start of crt0.S.")
    comment = " " + original[min(comment_positions):].rstrip("\r\n") if comment_positions else ""
    ending = "\n" if original.endswith("\n") else ""
    lines[index] = indent + f"ldr {register}, =_stack_bottom + 1024" + comment + ending
    return "".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("example_build", type=Path)
    args = parser.parse_args()
    print(f"Timer installer: {INSTALLER_REVISION}")
    example = args.example_build.expanduser().resolve(strict=True)
    bundle = Path(__file__).resolve().parent

    paths = {name: example / name for name in
             ("crt0.S", "sample_threadx.c", "tx_initialize_low_level.S")}
    updated = {name: path.read_text() for name, path in paths.items()}

    updated["crt0.S"] = normalize_boot_stack(updated["crt0.S"])

    app = updated["sample_threadx.c"]
    if "SHANNON TIMER DEMO: declaration" not in app:
        app = replace_once(app, r'^#include "tx_api\.h"[ \t]*$',
                           '#include "tx_api.h"\n\n' + DECLARE, "tx_api.h include")
    if "SHANNON TIMER DEMO: initialize peripherals" not in app:
        app = replace_once(app, r"^[ \t]*tx_kernel_enter\(\);[ \t]*$",
                           INITIALIZE + "    tx_kernel_enter();", "kernel-entry call")
    updated["sample_threadx.c"] = app

    low = updated["tx_initialize_low_level.S"]
    if "SHANNON TIMER DEMO: hardware acknowledge" not in low:
        low = replace_once(low, r"^[ \t]*BL[ \t]+_tx_timer_interrupt[^\n]*$",
                           DISPATCH, "timer interrupt call")
    updated["tx_initialize_low_level.S"] = low

    # Finish all validation before making backups or changing the sources.
    additions = ("threadx_shannon_timer.c", "build_threadx_timer.sh")
    for name in additions:
        if not (bundle / name).is_file():
            raise ValueError(f"Bundle file is missing: {name}")

    for name, path in paths.items():
        backup = path.with_name(path.name + ".before_shannon_timer")
        if not backup.exists():
            shutil.copy2(path, backup)
    for name, path in paths.items():
        if path.read_text() != updated[name]:
            path.write_text(updated[name])
    for name in additions:
        target = example / name
        if target.exists() and target.read_bytes() != (bundle / name).read_bytes():
            backup = target.with_name(target.name + ".before_shannon_timer")
            if not backup.exists():
                shutil.copy2(target, backup)
        shutil.copy2(bundle / name, target)

    print(f"Installed guarded timer hooks in {example}")
    print("Original sources have .before_shannon_timer backups.")
    print(f"Next: bash {example / 'build_threadx_timer.sh'}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error))
