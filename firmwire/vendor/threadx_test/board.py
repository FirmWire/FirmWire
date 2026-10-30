"""Hardware settings from the verified standalone ThreadX timer test."""

RAM_BASE = 0x00000000
RAM_SIZE = 2 * 1024 * 1024
GIC_BASE = 0x80000000
TIMER_BASE = 0x82008000
TIMER_IRQ = 34
TIMER_CLOCK_HZ = 100000


def add_board_memory(loader, segment_path):
    loader.add_memory_range(
        RAM_BASE, RAM_SIZE, name="threadx_ram", file=segment_path,
        file_offset=0, file_bytes=segment_path.stat().st_size, permissions="rwx"
    )
    loader.add_memory_range(
        GIC_BASE, 0x2000, name="gic", qemu_name="a9mpcore_priv",
        qemu_properties=[
            {"name": "num-cpu", "type": "uint32", "value": 1},
            {"name": "num-irq", "type": "uint32", "value": 64},
        ],
    )
    loader.add_memory_range(
        TIMER_BASE, 0x1000, name="threadx_tick_timer", qemu_name="shannon_timer",
        qemu_properties=[
            {"name": "irq_num", "type": "uint32", "value": TIMER_IRQ},
            {"name": "freq", "type": "uint32", "value": TIMER_CLOCK_HZ},
            {"name": "gic_model", "type": "uint32", "value": 0},
        ],
        permissions="rw-",
    )
