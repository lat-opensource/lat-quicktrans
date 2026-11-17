/* SPDX-License-Identifier: MIT
 * Linux x86-64 guest regression: keep comparison flags across a page fault.
 * Build four binaries with -DCASE=1..4; exit 0 means correct guest semantics.
 */
#ifndef CASE
#define CASE 1
#endif
.global _start
.text
_start:
    lea arena(%rip), %rbx
    mov %rbx, %rdx
    lea arena+96(%rip), %rcx
    mov $4096, %rax
    mov $4096, %r13
    lea arena+256(%rip), %r8
    mov $85, %edi
    or $1, %rax                 /* Known stale ZF=0 if CMP is omitted. */
    cmp %rdx, %rbx              /* Equal: ZF must become 1. */
#if CASE == 1
    mov %rcx, 96(%rbx)          /* First write faults in this data page. */
    setne %dl
#elif CASE == 2
    mov 96(%rbx), %rcx          /* First read faults in this data page. */
    setne %dl
#elif CASE == 3
    setne 96(%rbx)              /* The consumer itself may fault. */
#elif CASE == 4
    cmovne 96(%rbx), %rdi       /* Reads memory even for a false condition. */
#else
#error CASE must be 1, 2, 3 or 4
#endif
    or $1, %rax                 /* Make the old comparison flags dead. */
#if CASE == 1 || CASE == 2
    movzbl %dl, %edi
#elif CASE == 3
    movzbl 96(%rbx), %edi
#else
    xor $85, %edi
#endif
    mov $60, %eax
    syscall
.data
.balign 4096
arena:
    .skip 4096
.section .note.GNU-stack,"",@progbits
