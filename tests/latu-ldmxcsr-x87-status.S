/* SPDX-License-Identifier: MIT
 * Linux x86-64 guest: LDMXCSR must neither set nor clear x87 exceptions.
 * Build with cc -nostdlib -static. A nonzero exit identifies the failed case.
 */
.text
.global _start
_start:
.macro check operand, expected
    inc %edi
    ldmxcsr \operand(%rip)
    fnstsw %ax
    and $0x3f,%eax
    cmp $\expected,%eax
    jne exit
    stmxcsr observed(%rip)
    mov observed(%rip),%eax
    cmp \operand(%rip),%eax
    jne exit
.endm
    xor %edi,%edi
    fninit
    check all_flags, 0
    check clean, 0

    /* Divide by zero; leave the exception pending across the load. */
    fld1
    fldz
    fdivrp
    check precision, 4
    check clean, 4

    /* A masked x87 invalid operation must survive an MXCSR clear as well. */
    fninit
    fldz
    fldz
    fdivp
    check clean, 1
    check all_flags, 1

    xor %edi,%edi
exit:
    mov $60,%eax
    syscall
.section .rodata
.p2align 2
clean: .long 0x1f80
precision: .long 0x5fa0
all_flags: .long 0x1fbf
.bss
.p2align 2
observed: .skip 4
.section .note.GNU-stack,"",@progbits
