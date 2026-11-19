/* SPDX-License-Identifier: MIT
 * Build as a static x86-64 Linux executable with -nostdlib -no-pie.
 * A guest SIGILL handler must receive UD2 and exit successfully.
 */
.global _start
.text
_start:
    mov $13,%eax
    mov $4,%edi
    lea action(%rip),%rsi
    xor %edx,%edx
    mov $8,%r10d
    syscall
    test %rax,%rax
    jne bad
    ud2
bad:
    mov $93,%edi
    jmp finish
handler:
    xor %edi,%edi
finish:
    mov $60,%eax
    syscall
restore:
    mov $15,%eax
    syscall
.data
action: .quad handler,0x4000000,restore,0
