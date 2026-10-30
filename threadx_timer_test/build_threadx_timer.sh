#!/usr/bin/env bash
set -euo pipefail

threadx_example_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
threadx_root="$(cd -- "$threadx_example_dir/../../../.." && pwd)"
threadx_port="$(cd -- "$threadx_example_dir/.." && pwd)"
threadx_build_dir="$threadx_example_dir/threadx_timer_build"
threadx_cc="${THREADX_CC:-arm-none-eabi-gcc}"

if [[ ! -f "$threadx_example_dir/tx.a" ]]; then
    echo "Build the ThreadX kernel first: bash build_threadx.sh" >&2
    exit 1
fi

mkdir -p -- "$threadx_build_dir"
cd -- "$threadx_build_dir"
threadx_flags=(
    -g -mcpu=cortex-r5 -DTX_SHANNON_TIMER
    -I"$threadx_root/common/inc" -I"$threadx_port/inc"
)

"$threadx_cc" "${threadx_flags[@]}" -c "$threadx_example_dir/reset.S" -o reset.o
"$threadx_cc" "${threadx_flags[@]}" -c "$threadx_example_dir/crt0.S" -o crt0.o
"$threadx_cc" "${threadx_flags[@]}" -c "$threadx_example_dir/tx_initialize_low_level.S" -o tx_initialize_low_level.o
"$threadx_cc" "${threadx_flags[@]}" -c "$threadx_example_dir/sample_threadx.c" -o sample_threadx.o
"$threadx_cc" "${threadx_flags[@]}" -c "$threadx_example_dir/threadx_shannon_timer.c" -o threadx_shannon_timer.o

# Run the linker from this directory so reset.o in the linker script resolves
# to this build's vector table.
"$threadx_cc" -g -nostartfiles -mcpu=cortex-r5 \
    -T "$threadx_example_dir/sample_threadx.ld" --specs=nosys.specs \
    -o "$threadx_example_dir/sample_threadx_timer.out" \
    -Wl,-Map="$threadx_example_dir/sample_threadx_timer.map" \
    reset.o crt0.o tx_initialize_low_level.o sample_threadx.o \
    threadx_shannon_timer.o "$threadx_example_dir/tx.a"

echo "Built: $threadx_example_dir/sample_threadx_timer.out"
