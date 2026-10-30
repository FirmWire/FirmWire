/* Minimal ThreadX tick support for FirmWire's emulated Shannon timer.
 * This is an ordinary C IRQ dispatcher called by ThreadX's assembly wrapper.
 * Keep IRQ nesting disabled for this initial test.
 */
#include <stdint.h>
#include "tx_api.h"

#define GIC_BASE        UINT32_C(0x80000000)
#define GIC_CPU         (GIC_BASE + UINT32_C(0x100))
#define GIC_DIST        (GIC_BASE + UINT32_C(0x1000))
#define TIMER_BASE      UINT32_C(0x82008000)
#define TIMER_IRQ       34U
#define TIMER_CLOCK_HZ  100000U

#if (TX_TIMER_TICKS_PER_SECOND == 0) || (TIMER_CLOCK_HZ % TX_TIMER_TICKS_PER_SECOND != 0)
#error "The selected ThreadX tick rate must divide the 100000 Hz timer clock."
#endif

#define REG32(address) (*(volatile uint32_t *)(uintptr_t)(address))
#define REG8(address)  (*(volatile uint8_t *)(uintptr_t)(address))

volatile ULONG board_timer_irq_count;
volatile ULONG board_unexpected_irq_count;
volatile ULONG board_last_irq;

extern void _tx_timer_interrupt(void);

static inline void io_complete(void)
{
    __asm__ volatile ("dsb sy" ::: "memory");
}

void threadx_board_timer_init(void)
{
    uint32_t control;
    const uint32_t bit = UINT32_C(1) << (TIMER_IRQ % 32U);
    const uint32_t enable_word = 4U * (TIMER_IRQ / 32U);
    const uint32_t config_word = 4U * (TIMER_IRQ / 16U);
    const uint32_t config_shift = 2U * (TIMER_IRQ % 16U);
    const uint32_t vectors = 0U;

    /* ThreadX's scheduler will restore the thread's interrupt-enable state. */
    __asm__ volatile ("cpsid if" ::: "memory");

    /* Use the exception vectors that the ELF loads at address zero. */
    __asm__ volatile ("mrc p15, 0, %0, c1, c0, 0" : "=r" (control));
    control &= ~(UINT32_C(1) << 13); /* SCTLR.V: select low vectors. */
    __asm__ volatile ("mcr p15, 0, %0, c1, c0, 0" :: "r" (control) : "memory");
    __asm__ volatile ("mcr p15, 0, %0, c12, c0, 0" :: "r" (vectors) : "memory");
    __asm__ volatile ("dsb sy\n\tisb sy" ::: "memory");

    REG32(TIMER_BASE + 0x04U) = 0U; /* Stop the timer. */
    REG32(TIMER_BASE + 0x10U) = 1U; /* Deassert its interrupt line. */
    REG32(GIC_DIST + 0x000U) = 0U;
    REG32(GIC_CPU + 0x000U) = 0U;

    REG32(GIC_DIST + 0x180U + enable_word) = bit; /* Disable IRQ 34. */
    REG32(GIC_DIST + 0x280U + enable_word) = bit; /* Clear pending. */
    REG8(GIC_DIST + 0x400U + TIMER_IRQ) = 0x80U; /* Priority. */
    REG8(GIC_DIST + 0x800U + TIMER_IRQ) = 1U;    /* Target CPU 0. */
    REG32(GIC_DIST + 0xc00U + config_word) &=
        ~(UINT32_C(3) << config_shift);          /* Level-triggered. */

    REG32(GIC_CPU + 0x004U) = 0xffU; /* Priority mask permits this IRQ. */
    REG32(GIC_CPU + 0x008U) = 0U;    /* Binary point. */
    REG32(GIC_DIST + 0x100U + enable_word) = bit;
    REG32(GIC_CPU + 0x000U) = 1U;
    REG32(GIC_DIST + 0x000U) = 1U;
    io_complete();

    REG32(TIMER_BASE + 0x00U) = TIMER_CLOCK_HZ / TX_TIMER_TICKS_PER_SECOND;
    REG32(TIMER_BASE + 0x04U) = 3U; /* ENABLE | PERIODIC. */
    io_complete();
}

void threadx_board_irq_dispatch(void)
{
    const uint32_t acknowledge = REG32(GIC_CPU + 0x00cU);
    const uint32_t irq = acknowledge & 0x3ffU;

    board_last_irq = irq;
    if (irq >= 1020U) {
        return; /* Spurious/special GIC IDs must not be completed. */
    }

    if (irq == TIMER_IRQ) {
        REG32(TIMER_BASE + 0x10U) = 1U;
        io_complete();
        ++board_timer_irq_count;
        _tx_timer_interrupt();
    } else {
        ++board_unexpected_irq_count;
    }

    REG32(GIC_CPU + 0x010U) = acknowledge; /* End this interrupt. */
    io_complete();
}

/* The plain-C sample has no shutdown cleanup; an existing strong hook wins. */
__attribute__((weak)) void _fini(void)
{
}
