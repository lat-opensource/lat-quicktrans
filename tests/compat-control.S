/* SPDX-License-Identifier: MIT
 * Linux guest regressions. Build once with -m64 and once with -m32:
 * gcc -m64 -nostdlib -static -no-pie compat-control.S -o far32-offset
 * gcc -m32 -nostdlib -static -no-pie compat-control.S -o inc-dec-int80
 * Both executables must return zero under strict LATS Quicktrans.
 */
#ifdef __x86_64__
.global _start
.text
_start:
    mov %cs,%ax
    mov %ax,ptr+4(%rip)
    lea ptr(%rip),%rbx
    mov $71,%edi
    /* JMP far [rbx+0], m16:32. Only the target may return success. */
    .byte 0xff,0x6b,0x00
    jmp finish
target:
    xor %edi,%edi
finish:
    mov $60,%eax
    syscall
.data
ptr: .long target
     .word 0
#else
.global _start
.text
_start:
 mov $0x7fffffff,%ecx
 stc
 .byte 0x41
 jnc bad
 jno bad
 cmp $0x80000000,%ecx
 jne bad
 mov $0x12340000,%edx
 stc
 .byte 0x66,0x4a
 jnc bad
 cmp $0x1234ffff,%edx
 jne bad
 xor %ebx,%ebx
 jmp done
bad: mov $83,%ebx
done: mov $1,%eax
 int $0x80
#endif
