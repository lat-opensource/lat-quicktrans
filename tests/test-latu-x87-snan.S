/* x86-64 guest. Build with cc -nostdlib -static.
 * A ten-byte x87 load/store transports a signaling NaN. Only the
 * arithmetic operation should quiet it and raise invalid. */
.section .rodata
.balign 8
values:
    .quad 0xa123456789abc800
    .short 0x7fff
    .quad 0xa123456789abc800
    .short 0xffff
    .quad 0xe123456789abc800
    .short 0x7fff
.section .bss
copy: .skip 10
.text
.global _start
_start:
    lea values(%rip), %rsi
    mov $3, %ecx
.Lnext:
    mov $1, %edi                    /* Round-trip payload or sign. */
    fninit
    fldt (%rsi)
    fstpt copy(%rip)
    mov (%rsi), %rax
    cmp copy(%rip), %rax
    jne .Lfail
    mov 8(%rsi), %ax
    cmp copy+8(%rip), %ax
    jne .Lfail
    mov $2, %edi                    /* Unexpected invalid during transfer. */
    fnstsw %ax
    test $1, %eax
    jnz .Lfail

    fldt (%rsi)
    mov $3, %edi                    /* FRNDINT exception or quiet result. */
    frndint
    fnstsw %ax
    and $1, %eax
    cmp $1, %ecx                    /* Last operand is a quiet NaN. */
    setne %dl
    cmp %dl, %al
    jne .Lfail
    fstpt copy(%rip)
    btq $62, copy(%rip)
    jnc .Lfail
    add $10, %rsi
    dec %ecx
    jnz .Lnext
    xor %edi, %edi
.Lfail:
    mov $60, %eax
    syscall
.section .note.GNU-stack,"",@progbits
