/* Build on x86-64 with cc -nostdlib -static and run under latx-x86_64.
 * Exit zero when compare/exchange and narrow updates preserve guest state. */
.text
.globl _start
_start:
    lea slot(%rip), %rsi
    mov $7, %eax
    mov $9, %ecx
    lock cmpxchgl %ecx, (%rsi)
    jne fail
    lock cmpxchgl %ecx, (%rsi)
    je fail
    cmp $9, %eax
    jne fail

    mov $2, %ecx
    lock xaddb %cl, (%rsi)
    cmp $9, %ecx
    jne fail
    cmpw $11, (%rsi)
    jne fail

    mov $11, %eax
    xor %edx, %edx
    mov $13, %ebx
    mov $17, %ecx
    lock cmpxchg16b (%rsi)
    jne fail
    cmpq $13, (%rsi)
    jne fail
    cmpq $17, 8(%rsi)
    jne fail

    xor %edi, %edi
    jmp done
fail:
    mov $1, %edi
done:
    mov $60, %eax
    syscall

.data
.balign 16
slot: .quad 7, 0
.section .note.GNU-stack,"",@progbits
