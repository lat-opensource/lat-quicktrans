/* SPDX-License-Identifier: MIT
 * Build with as --32 and ld -m elf_i386. Exit 0 means both checks passed.
 */
.text
.globl _start
_start:
    movl %esp, %esi
    leal -4(%esi), %edi
    call check_entry
after_call:
    cmpl %esi, %esp
    jne fail

    /* Test RET independently: padding makes an erroneous eight-byte
     * load land at the same PC, so only the stack-pointer check decides. */
    pushl $0
    pushl $after_ret
    ret $4
after_ret:
    cmpl %esi, %esp
    jne fail
    xorl %ebx, %ebx
    jmp exit
check_entry:
    cmpl %edi, %esp
    jne fail
    cmpl $after_call, (%esp)
    jne fail
    ret
fail:
    movl $1, %ebx
exit:
    movl $1, %eax
    int $0x80
.section .note.GNU-stack,"",@progbits
