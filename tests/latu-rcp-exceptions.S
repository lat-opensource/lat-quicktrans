/* SPDX-License-Identifier: MIT
 * Linux x86-64 guest, native or LATU with LATX_SOFTFPU=1.
 * Exit zero if reciprocal estimates preserve pending SSE exceptions and
 * never raise one, including when all exceptions are unmasked.
 */
.text
.globl _start
_start:
    xor %edi,%edi
.macro check op
    inc %edi
    ldmxcsr preset(%rip)
    /* Real divide-by-zero has set a sticky bit which STMXCSR has not read. */
    movss one(%rip),%xmm0
    divss zero(%rip),%xmm0
    movaps inputs(%rip),%xmm1
    \op %xmm1,%xmm2
    stmxcsr observed(%rip)
    cmpl $0x5fa4,observed(%rip)
    jne exit

    inc %edi
    ldmxcsr unmasked(%rip)
    \op inputs(%rip),%xmm2
    stmxcsr observed(%rip)
    cmpl $0,observed(%rip)
    jne exit
.endm
    check rcpss
    check rcpps
    check rsqrtss
    check rsqrtps
    xor %edi,%edi
exit:
    mov $60,%eax
    syscall
.section .rodata
.balign 16
inputs: .long 0,0x40400000,0xbf800000,0x7f800001
one: .float 1
zero: .float 0
preset: .long 0x5fa0
unmasked: .long 0
.bss
.balign 4
observed: .skip 4
.section .note.GNU-stack,"",@progbits
