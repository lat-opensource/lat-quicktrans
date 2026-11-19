/* SPDX-License-Identifier: MIT
 * Build this relocation-free PE32 probe with GNU binutils:
 * as --32 latu-wow64-near.S -o probe.o
 * objcopy -O pe-i386 probe.o probe.obj
 * ld -mi386pe --subsystem console --entry _start probe.obj -o probe.exe
 * Wine WoW64 should return 73. Failure codes 11-14 identify the transfer.
 */
.text
.globl _start
_start:
    push %esi
    push %ebx
    mov %esp,%ebx
    push $41
    call add_one
    cmp $42,%eax
    jne bad_direct
    cmp %ebx,%esp
    jne bad_direct
    call here
here:
    pop %esi
    lea add_one-here(%esi), %ecx
    push $52
    call *%ecx
    cmp $53,%eax
    jne bad_register
    cmp %ebx,%esp
    jne bad_register
    push $0xfeedface
    push %ecx
    push $63
    call *4(%esp)
    add $8,%esp
    cmp $64,%eax
    jne bad_memory
    cmp %ebx,%esp
    jne bad_memory
    sub $4096,%esp
    movl $77,(%esp)
    call large_pop
    cmp $78,%eax
    jne bad_cleanup
    cmp %ebx,%esp
    jne bad_cleanup
    lea success-here(%esi),%edx
    push $0xfeedface
    push %edx
    jmp *(%esp)
success:
    mov $73,%eax
    jmp done
bad_direct:
    mov $11,%eax
    jmp done
bad_register:
    mov $12,%eax
    jmp done
bad_memory:
    mov $13,%eax
    jmp done
bad_cleanup:
    mov $14,%eax
done:
    mov %ebx,%esp
    pop %ebx
    pop %esi
    ret
add_one:
    mov 4(%esp),%eax
    inc %eax
    ret $4
large_pop:
    mov 4(%esp),%eax
    inc %eax
    ret $4096
