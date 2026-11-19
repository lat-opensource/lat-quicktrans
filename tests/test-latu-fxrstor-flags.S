/* x86-64 guest regression. Build with cc -nostdlib -static and run under LATU.
 * glibc's lazy resolver uses FXSAVE/FXRSTOR between raising and testing
 * floating-point exceptions. Read both status words just as fetestexcept does. */
.section .bss
.balign 16
fx_state: .skip 512
mxcsr:    .skip 4

.text
.global _start
_start:
    pxor %xmm0, %xmm0
    divss %xmm0, %xmm0              /* invalid: 0 / 0 */
    mov $0x3f800000, %eax
    movd %eax, %xmm0
    pxor %xmm1, %xmm1
    divss %xmm1, %xmm0              /* divide by zero: 1 / 0 */

    fxsave fx_state(%rip)
    fxrstor fx_state(%rip)
    fnstsw %ax
    stmxcsr mxcsr(%rip)
    or mxcsr(%rip), %eax
    and $0x3d, %eax                  /* FE_ALL_EXCEPT on x86 */
    cmp $5, %eax                    /* FE_INVALID | FE_DIVBYZERO */
    setne %dil
    movzbl %dil, %edi
    mov $60, %eax
    syscall
.section .note.GNU-stack,"",@progbits
