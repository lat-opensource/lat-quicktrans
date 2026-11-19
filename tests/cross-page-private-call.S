/* SPDX-License-Identifier: MIT
 * Linux x86-64 guest test. Build with cc -nostdlib -static; exit 0 passes.
 * Both processes execute the same caller. A write in the child gives only
 * its target page a private physical copy. The parent must still return 1.
 */
.text
.global _start
_start:
    call caller
    cmp $1, %eax
    jne fail
    mov $57, %eax
    syscall
    test %eax, %eax
    js fail
    jz child
    mov %eax, %edi
    sub $8, %rsp
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js fail
    cmpl $0, (%rsp)
    jne fail
    call caller
    cmp $1, %eax
    jne fail
    jmp pass
child:
    lea target(%rip), %rdi
    mov $4096, %esi
    mov $7, %edx
    mov $10, %eax
    syscall
    test %eax, %eax
    jne fail
    movb $2,target+1(%rip)
    call caller
    cmp $2, %eax
    jne fail
pass:
    xor %edi, %edi
    jmp done
fail:
    mov $1, %edi
done:
    mov $60,%eax
    syscall
.p2align 4
caller:
    call target
    ret
.balign 4096
target:
    mov $1, %eax
    ret
