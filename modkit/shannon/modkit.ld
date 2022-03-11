ENTRY (task_main)

SECTIONS
{
    _STACK_SIZE = 0x1000;
    /* Base address of the task */
    . = 0x0;

    /* Let the source know about the task start */
    _TASK_START = .;

    /* make sure the sections are 16-byte aligned */
    .text ALIGN (0x10) :
    {
      *(.text.task_main)
      *(.text.*)
    }
    .rodata ALIGN (0x10) :
    {
      *(.rodata*)
    }
    .data ALIGN (0x10) : { *(.data*) }
    .bss ALIGN (0x10) :
    {
        _BSS_START = .; /* sbss and ebss allow us to easily zero the bss */
        *(.bss)
        *(COMMON)
        _BSS_END = .;
    }

    .stack ALIGN (0x10) : {
        . += _STACK_SIZE;
    }

    /* Let the source know about the task end */
    _TASK_END = .;
    _BSS_SIZE    = _BSS_END    - _BSS_START;
    _TASK_SIZE = _TASK_END - _TASK_START;
}

