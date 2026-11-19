/* SPDX-License-Identifier: MIT
 * Linux x86-64 guest. Build with cc -nostdlib -static. Run on either
 * LATU path with LATX_SOFTFPU=1; expectations include legacy DE/DAZ behavior.
 */
.text
.global _start
_start:
    /* x87 exceptions stay in the status word, even across SSE work. */
    fninit
    ldmxcsr clean(%rip)
    fld1
    fldz
    fdivrp
    fnstsw %ax
    movzwl %ax,%eax
    and $63,%eax
    mov %eax,res(%rip)
    stmxcsr res+4(%rip)
    movss half(%rip),%xmm0
    cvtss2si %xmm0,%eax
    fldz
    fldz
    fdivp
    fnstsw %ax
    movzwl %ax,%eax
    and $63,%eax
    mov %eax,res+8(%rip)
    stmxcsr res+12(%rip)
    stmxcsr res+16(%rip)
    movss one(%rip),%xmm0
    divss zero(%rip),%xmm0
    stmxcsr res+20(%rip)
    ldmxcsr preset(%rip)
    stmxcsr res+24(%rip)
    ldmxcsr clean(%rip)
    stmxcsr res+28(%rip)
    movss half(%rip),%xmm0
    cvtss2si %xmm0,%eax
    /* Saving observes pending SSE flags. Restoring replaces them. */
    fxsave image(%rip)
    mov image+24(%rip),%eax
    mov %eax,res+32(%rip)
    movl $0x3f82,image+24(%rip)
    fxrstor image(%rip)
    stmxcsr res+36(%rip)
    /* LATU converts subnormal inputs directly even when MXCSR.DAZ is set. */
    ldmxcsr daz(%rip)
    cvtps2pd subs(%rip),%xmm0
    movups %xmm0,res+40(%rip)
    stmxcsr res+56(%rip)
    cvtpd2ps subd(%rip),%xmm1
    movups %xmm1,res+60(%rip)
    stmxcsr res+76(%rip)
    ldmxcsr clean(%rip)
    movups unused(%rip),%xmm1
    cvtss2sd %xmm1,%xmm0
    stmxcsr res+80(%rip)
    cvtps2pd %xmm1,%xmm1
    stmxcsr res+84(%rip)
    /* With DAZ clear, widening a subnormal does not add DE on LATU. */
    cvtps2pd subs(%rip),%xmm1
    stmxcsr res+88(%rip)
    /* An explicitly loaded DE still survives an exact conversion. */
    ldmxcsr preset(%rip)
    cvtss2sd one(%rip),%xmm0
    stmxcsr res+92(%rip)
    /* A nonzero exit code identifies the first differing 32-bit word. */
    lea expected(%rip),%rsi
    lea res(%rip),%rdx
    xor %edi,%edi
check:
    mov (%rsi,%rdi,4),%eax
    cmp (%rdx,%rdi,4),%eax
    jne failed
    inc %edi
    cmp $(end_expected-expected)/4,%edi
    jne check
    xor %edi,%edi
    jmp exit
failed:
    inc %edi
exit:
    mov $60,%eax
    syscall
.section .rodata
.p2align 2
expected:
    .long 4,0x1f80,5,0x1fa0,0x1fa0,0x1fa4,0x1f92,0x1f80
    .long 0x1fa0,0x3f82
    .quad 0xb6a0000000000000,0x36a0000000000000
    .long 0x1fc0,0x80000000,0x3f800000,0,0,0x1ff0,0x1f80,0x1f80
    .long 0x1f80,0x1f92
end_expected:
.data
.p2align 4
subs: .long 0x80000001,1
.p2align 4
subd: .quad 0x8000000000000001,0x3ff0000000000000
unused: .long 0x3f800000,0,1,1
clean: .long 0x1f80
daz: .long 0x1fc0
preset: .long 0x1f92
one: .float 1
half: .float 0.5
zero: .float 0
.bss
.p2align 4
image: .skip 512
res: .skip end_expected-expected
.section .note.GNU-stack,"",@progbits
