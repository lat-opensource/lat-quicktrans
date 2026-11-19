/* SPDX-License-Identifier: MIT */

/* LATS system-mode instruction patterns. Build as a static x86-64 ELF.
 * Each failing group returns its number. Run with and without instptn. */
.global _start
.text
_start:
    mov $1, %edi
    mov $1, %eax
    mov $5, %ecx
    .byte 0x3b, 0xc1         /* cmp eax,ecx: same operand order as 39 c8 */
    jae fail
    cmp $7, %eax
    jae fail
    cmp %ecx, %eax
    jns fail

    mov $2, %edi
    mov $0x80, %eax
    test $0x80, %al
    je fail
    test %al, %al
    jns fail
    testb $1, value(%rip)
    je fail

    mov $3, %edi
    cmp $7, %eax
    mov $1, %eax             /* interrupt the live range of the operand */
    nop
    movzbl value(%rip), %ecx
    mov %ecx, %r11d
    nop
    jbe fail

    mov $4, %edi
    mov $-2, %eax
    cmp $-1, %eax
    setb %al                 /* later consumers need the original EAX */
    setl output(%rip)        /* first write to a fresh page */
    cmovl value(%rip), %ecx
    setge %dl
    cmpb $1, output(%rip)
    jne fail
    cmp $3, %ecx
    jne fail
    test %dl, %dl
    jne fail

    mov $5, %edi
    mov $5, %eax
    cmp $7, %eax
    sbb %ah, %ah
    cmp $0xff05, %eax
    jne fail
    mov $9, %r8
    mov $3, %r9
    cmp %r8, %r9
    jae fail
    cmp $9, %r8
    jne fail
    cmp $3, %r9
    jne fail

    mov $6, %edi
    andb $2, value(%rip)
    je fail
    xorb $2, value(%rip)
    jne fail
    subb $1, value(%rip)
    jns fail
    shrb $1, value(%rip)
    je fail

    mov $7, %edi
    xorps %xmm0, %xmm0
    ucomiss %xmm0, %xmm0
    jg fail
    ucomiss %xmm0, %xmm0
    jl fail
    ucomisd %xmm0, %xmm0
    movzbl value(%rip), %edx
    nop
    jge 1f
    jmp fail
1:  comiss %xmm0, %xmm0
    jle 2f
    jmp fail
2:  ucomisd %xmm0, %xmm0
    seta output(%rip)
    cmpb $0, output(%rip)
    jne fail
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
    mov $9, %edi
    movl $2, value(%rip)
    btl $0, value(%rip)
    jb fail
    btl $1, value(%rip)
    mov %eax, %r11d
    jae fail
    mov $255, %eax
    rol $8, %eax
    dec %ah
    je fail
    sarb $1, value(%rip)
    js fail
    movb $0x80, value(%rip)
    sarb $1, value(%rip)
    jns fail
    xor %edi, %edi
fail:
    mov $60, %eax
    syscall
.data
value: .long 3
.balign 4096
output: .byte 0
.section .note.GNU-stack,"",@progbits
