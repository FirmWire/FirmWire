# ThreadX timer test using FirmWire's Shannon backend

The baseline has already reached `main`, started thread 0, incremented its
counter to 1, put it into `TX_SLEEP` (state 4), and switched to thread 1. Its
ThreadX clock remained 0 because no timer peripheral was configured.

This separate build adds periodic timer interrupts so thread 0 can wake after
10 ticks and increment its counter again. Runtime behavior must be verified
in the working FirmWire container. This bundle was checked against the
v6.5.2.202603_rel Cortex-R5 GNU example; it assumes the default non-nested IRQ
configuration used by that example.

## What changes

- `enable_timer.py` saves backups, corrects the startup stack if necessary,
  and adds `TX_SHANNON_TIMER` guards around the board initialization and IRQ
  dispatcher hooks.
- `build_threadx_timer.sh` defines that macro and produces
  `sample_threadx_timer.out` using the existing `tx.a` kernel library.
- `threadx_shannon_timer.c` programs the timer/GIC and dispatches the timer IRQ
  to `_tx_timer_interrupt` after the existing ThreadX assembly context save.
- `run_threadx_timer.py` creates the same RAM/CPU setup as the baseline, plus
  the native Shannon timer and GIC devices. It includes the PANDA signal-method
  compatibility fix and silences the expected empty-Python-queue warning.

The existing `build_threadx_sample.sh` does not define the new macro. Source
backups have the suffix `.before_shannon_timer`; the timer build uses its own
object directory and output ELF.

The installer prints `Timer installer: stack-match-v2`. It recognizes the initial
stack instruction sequence, including different spacing/capitalization, trailing
comments, an existing `_sp` load, or a direct load into `sp`. If it cannot identify
that sequence safely, it prints the relevant startup block before changing files.

| Component | Address / setting | Purpose |
|---|---|---|
| RAM | `0x00000000` to `0x001fffff` | Firmware and application memory |
| GIC CPU interface | `0x80000100` | IRQ acknowledgment and completion |
| GIC distributor | `0x80001000` | Enable/route IRQ 34 to CPU 0 |
| Shannon timer | `0x82008000` | Periodic interrupt source |
| Timer input | 100,000 Hz | The driver's reload is input / ThreadX tick rate |
| Timer IRQ | 34 | The only IRQ handled as a ThreadX tick |

With the default `TX_TIMER_TICKS_PER_SECOND` of 100, the timer reload is 1000
and each tick represents about 10 ms of emulated virtual time. Debugger stops
pause the guest; use tick differences to verify the sleep interval.

## 1. Install and build on the host

Extract this folder into `~/FirmWire/threadx_timer_test`.

```bash
python3 ~/FirmWire/threadx_timer_test/enable_timer.py \
  "$HOME/threadx/threadx-r5/ports/cortex_r5/gnu/example_build"

bash "$HOME/threadx/threadx-r5/ports/cortex_r5/gnu/example_build/build_threadx_timer.sh"
```

If `tx.a` is absent, first run the original `build_threadx.sh` in that example
directory. Existing Newlib file/console syscall warnings can remain for this
debugger-driven test.

## 2. Stop the previous run and copy the new files

In the old GDB session, use `detach`, then `quit`. Stop the old launcher with
Ctrl+C in its container terminal, leaving the container's shell open.

From a host terminal:

```bash
docker cp \
  "$HOME/threadx/threadx-r5/ports/cortex_r5/gnu/example_build/sample_threadx_timer.out" \
  14f44fdaaad8:/firmwire/sample_threadx_timer.out

docker cp "$HOME/FirmWire/threadx_timer_test/run_threadx_timer.py" \
  14f44fdaaad8:/firmwire/run_threadx_timer.py
```

The container ID above is the currently observed one; use the current ID if
you have replaced the container.

## 3. Start the timer demo

In the container's shell:

```bash
python3 /firmwire/run_threadx_timer.py /firmwire/sample_threadx_timer.out
```

From a second host terminal:

```bash
docker exec -it 14f44fdaaad8 \
  gdb-multiarch -q /firmwire/sample_threadx_timer.out
```

In GDB:

```gdb
target remote 127.0.0.1:3333
set $cpsr = 0xd3
tbreak main
continue
watch thread_0_counter
continue
print thread_0_counter
set $start_ticks = _tx_timer_system_clock
continue
print thread_0_counter
print _tx_timer_system_clock - $start_ticks
print board_timer_irq_count
print board_unexpected_irq_count
```

The two watchpoint stops should show the counter changing 0 -> 1 -> 2.
At the second stop, the clock should have advanced by at least 10 ticks,
`board_timer_irq_count` should be positive, and `board_unexpected_irq_count`
should be zero. Record the actual output before calling the timer test passed.

If `continue` does not reach the next watchpoint, interrupt GDB with Ctrl+C and
collect:

```gdb
info registers
x/8i $pc
print board_last_irq
print board_timer_irq_count
print board_unexpected_irq_count
print _tx_timer_system_clock
x/2wx 0x82008000
x/wx 0x82008034
x/wx 0x80000118
```

## Scope and verification

The installer was checked against the upstream example, including backups and
repeat-run behavior. Baseline/timer IRQ preprocessing, the C syntax and warning
checks, Python syntax, Bash syntax, and the shared address/IRQ constants were
checked. The ARM build and actual PANDA interrupt/wake behavior require the
working runtime used for the baseline and have not yet been verified here.

This is a synthetic test board using FirmWire's PANDA fork and Shannon CPU and
peripheral support. A registered FirmWire ThreadX vendor loader and Unisoc
hardware emulation are separate work.

## Primary sources

- [FirmWire Shannon loader](https://github.com/FirmWire/FirmWire/blob/master/firmwire/vendor/shannon/loader.py)
- [Native Shannon timer](https://github.com/FirmWire/panda/blob/main/hw/timer/shannon_timer.c)
- [A9 private peripherals and GIC mapping](https://github.com/FirmWire/panda/blob/main/hw/cpu/a9mpcore.c)
- [Configurable machine IRQ wiring](https://github.com/FirmWire/panda/blob/main/hw/avatar/configurable_machine.c)
- [ThreadX Cortex-R5 example](https://github.com/eclipse-threadx/threadx/tree/v6.5.2.202603_rel/ports/cortex_r5/gnu/example_build)
