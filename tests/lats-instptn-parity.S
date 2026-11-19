/* SPDX-License-Identifier: MIT */

/* LATS system-mode instruction patterns. Build as a static x86-64 ELF.
 * Each failing group returns its number. Run with and without instptn. */
.global _start
.text
_start:
    mov $8, %edi
    mov $-21, %rax
    mov $4, %ecx
    cqto
    idiv %rcx
    cmp $-5, %rax
    jne fail
    cmp $-1, %rdx
    jne fail
    mov $-7, %rax
    cqto
    idiv %rax                 /* divisor aliases the quotient destination */
    cmp $1, %rax
    jne fail
    test %rdx, %rdx
    jne fail
    xor %edi, %edi
fail:
    mov $60, %eax
    syscall
.data
value: .long 3
.balign 4096
output: .byte 0
.section .note.GNU-stack,"",@progbits
