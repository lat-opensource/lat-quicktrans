/* SPDX-License-Identifier: MIT */
/* Static x86-64 guest. Run with a timeout longer than the one-second alarm.
 * A signal must reach its handler while the conditional self-loop is live. */
.section .rodata
.balign 8
action:
    .quad handler, 0x04000000, restorer, 0  /* SA_RESTORER */
.text
.global _start
_start:
    mov $13, %eax                  /* rt_sigaction(SIGALRM, ...) */
    mov $14, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jnz fail
    mov $37, %eax                  /* alarm(1) */
    mov $1, %edi
    syscall
    xor %ecx, %ecx
    jmp loop_head
.p2align 4
loop_head:
    inc %rcx
    jne loop_head
fail:
    mov $1, %edi
    jmp quit
handler:
    xor %edi, %edi
quit:
    mov $60, %eax
    syscall
restorer:
    mov $15, %eax
    syscall
.section .note.GNU-stack,"",@progbits
