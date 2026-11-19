/* SPDX-License-Identifier: MIT
 * Build with gcc -nostdlib -static -no-pie and expect exit 0.
 * Also suitable as a PE32 entry point when assembled with _WIN32.
 */
.text
.globl _start
_start:
#ifdef __x86_64__
    push %rbx
#else
    push %ebx
#endif
    mov $0x12345678,%eax
    mov %eax,%ebx
    mov %eax,%ecx
    mov %eax,%edx
    stc
    .byte 0xc6,0xc4,0x58       /* mov ah,0x58 */
    .byte 0xc6,0xc5,0x59
    .byte 0xc6,0xc6,0x5a
    .byte 0xc6,0xc7,0x5b
    jnc .Lbyte
    cmp $0x12345878,%eax
    jne .Lbyte
    cmp $0x12345978,%ecx
    jne .Lbyte
    cmp $0x12345a78,%edx
    jne .Lbyte
    cmp $0x12345b78,%ebx
    jne .Lbyte
#ifdef __x86_64__
    /* With REX the same r/m byte selects SPL instead of AH. */
    mov %rsp,%r10
    .byte 0x40,0xc6,0xc4,0x5c
    mov %rsp,%r11
    mov %r10,%rsp
    movzbl %r11b,%ecx
    cmp $0x5c,%ecx
    jne .Lbyte
    cmp $0x12345878,%eax
    jne .Lbyte
#endif
    xor %eax,%eax
    jmp .Lexit
.Lbyte:
    mov $11,%eax
    jmp .Lexit
.Lexit:
#ifdef __x86_64__
    pop %rbx
#else
    pop %ebx
#endif
#ifdef _WIN32
    ret
#elif defined(__x86_64__)
    mov %eax,%edi
    mov $60,%eax
    syscall
#else
    mov %eax,%ebx
    mov $1,%eax
    int $0x80
#endif
