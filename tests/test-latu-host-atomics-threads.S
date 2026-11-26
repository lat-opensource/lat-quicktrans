/*
 * SPDX-License-Identifier: MIT
 *
 * Build with cc -nostdlib -static on x86-64. Run with Quicktrans enabled.
 * Both threads update an aligned byte, a halfword straddling an 8-byte
 * boundary and an aligned 128-bit pair. Exit zero only if all counts match.
 */
.text
.globl _start
_start:
    mov $56, %eax                   /* clone */
    mov $0x50f00, %edi              /* VM, FS, FILES, SIGHAND, THREAD, SYSVSEM */
    lea stack_end(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    js fail
    mov %eax, %r9d
    lock incl ready(%rip)
wait_ready:
    cmpl $2, ready(%rip)
    jne wait_ready
    mov $64, %r8d
again:
    mov $1, %eax
    lock xaddb %al, aligned_byte(%rip)
    mov $1, %eax
    lock xaddw %ax, split_word(%rip)
    xor %edx, %edx
    xor %eax, %eax
retry:
    lea 1(%rax), %rbx
    lea 1(%rdx), %rcx
    lock cmpxchg16b pair(%rip)
    jne retry
    dec %r8d
    jne again
    test %r9d, %r9d
    jne wait_child
    movl $1, finished(%rip)
    xor %edi, %edi
    mov $60, %eax                  /* exit this thread */
    syscall
wait_child:
    cmpl $0, finished(%rip)
    je wait_child
    cmpb $128, aligned_byte(%rip)
    jne fail
    cmpw $128, split_word(%rip)
    jne fail
    cmpb $0, split_word-1(%rip)
    jne fail
    cmpb $0, split_word+2(%rip)
    jne fail
    cmpq $128, pair(%rip)
    jne fail
    cmpq $128, pair+8(%rip)
    jne fail
    xor %edi, %edi
    jmp done
fail:
    mov $1, %edi
done:
    mov $231, %eax                 /* exit_group */
    syscall

.bss
.balign 16
pair: .space 16
aligned_byte: .byte 0
.space 6
split_word: .word 0
.byte 0
.balign 4
ready: .long 0
finished: .long 0
.balign 16
.space 65536
stack_end:
.section .note.GNU-stack,"",@progbits
