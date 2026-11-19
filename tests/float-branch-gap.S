/* SPDX-License-Identifier: MIT
 * Linux x86-64 guest. Build with cc -nostdlib -static. Exit 0 passes.
 */
.text
.globl _start
_start:
    xorps %xmm0, %xmm0
    mov $42, %eax
    /* Fault in the page before the compare so the gap executes in one block. */
    mov %rax, value(%rip)
    jmp compare
compare:
    ucomiss %xmm0, %xmm0
    mov value(%rip), %r10
    jne fail
    cmp $42, %r10
    jne fail
    /* Unordered sets CF and ZF. Check both the direct branch and the
     * guest flags used after the branch target is reached. */
    movss nan_value(%rip), %xmm1
    jmp unordered
unordered:
    ucomiss %xmm1, %xmm0
    mov %r10, value(%rip)
    jb check_zf
    jmp fail
check_zf:
    jne fail
    ucomiss %xmm1, %xmm0
    lea value(%rip), %r10
    ja fail

    /* A first read on a different page can restart the MOV in a new
     * translation block, where JNE reads the architectural flags. */
    ucomiss %xmm0, %xmm0
    mov cold_value(%rip), %r10
    jne fail
    xor %edi, %edi
    jmp done
fail:
    mov $1, %edi
done:
    mov $60, %eax
    syscall
.data
.p2align 3
value: .quad 0
nan_value: .long 0x7fc00001
.bss
.balign 65536
cold_value: .skip 8
