/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

static void ft_emit_cpuid_helper_epilogue(uint32_t **out);

#ifdef QUICKTRANS_LATU
/* Same segment cache and CS mode policy as legacy store_ireg_to_ir1_seg.
 * t2 holds the zero-extended selector; preserve r21 (return target).
 */
static void ft_emit_latu_store_seg(uint32_t **out, int seg)
{
    FastBranchLabel mode64 = { 0 }, mode_done = { 0 };
    FastBranchLabel ldt = { 0 }, table_done = { 0 };
    FastBranchFixup mode64_fix, mode_done_fix, ldt_fix, table_done_fix;

    ft_emit_store_env(out, la_t2,
                      offsetof(CPUX86State, segs[0].selector) +
                      seg * sizeof(SegmentCache),
                      FT_LA_OPCODE_ST_W);
    if (seg == R_CS) {
        FT_LA_ORI_EMIT(out, la_t1, la_zero, 0x23);
        ft_emit_branch_placeholder(out, &mode64_fix, FT_BRANCH_BNE,
                                   la_t2, la_t1, &mode64);
        ft_emit_store_env(out, la_zero, offsetof(CPUX86State, sys.codemode),
                          FT_LA_OPCODE_ST_W);
        ft_emit_load_env(out, la_t0, offsetof(CPUX86State, hflags), FT_LA_OPCODE_LD_W);
        ft_emit_li32(out, la_t1, ~HF_CS64_MASK);
        FT_LA_AND_EMIT(out, la_t0, la_t0, la_t1);
        ft_emit_li32(out, la_t1, HF_CS32_MASK);
        FT_LA_OR_EMIT(out, la_t0, la_t0, la_t1);
        ft_emit_branch_placeholder(out, &mode_done_fix, FT_BRANCH_BEQ,
                                   la_zero, la_zero, &mode_done);
        ft_bind_branch_label(&mode64, *out);
        FT_LA_ORI_EMIT(out, la_t1, la_zero, 1);
        ft_emit_store_env(out, la_t1, offsetof(CPUX86State, sys.codemode),
                          FT_LA_OPCODE_ST_W);
        ft_emit_load_env(out, la_t0, offsetof(CPUX86State, hflags), FT_LA_OPCODE_LD_W);
        ft_emit_li32(out, la_t1, HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK);
        FT_LA_OR_EMIT(out, la_t0, la_t0, la_t1);
        ft_emit_li32(out, la_t1, ~HF_ADDSEG_MASK);
        FT_LA_AND_EMIT(out, la_t0, la_t0, la_t1);
        ft_bind_branch_label(&mode_done, *out);
        ft_resolve_branch_fixup(&mode64_fix);
        ft_resolve_branch_fixup(&mode_done_fix);
        ft_emit_store_env(out, la_t0, offsetof(CPUX86State, hflags), FT_LA_OPCODE_ST_W);
    }

    FT_LA_ANDI_EMIT(out, la_t1, la_t2, 4);
    ft_emit_branch_placeholder(out, &ldt_fix, FT_BRANCH_BNE, la_t1, la_zero, &ldt);
    ft_emit_load_env(out, la_t0, offsetof(CPUX86State, gdt.base), FT_LA_OPCODE_LD_D);
    ft_emit_branch_placeholder(out, &table_done_fix, FT_BRANCH_BEQ,
                               la_zero, la_zero, &table_done);
    ft_bind_branch_label(&ldt, *out);
    ft_emit_load_env(out, la_t0, offsetof(CPUX86State, ldt.base), FT_LA_OPCODE_LD_D);
    ft_bind_branch_label(&table_done, *out);
    ft_resolve_branch_fixup(&ldt_fix);
    ft_resolve_branch_fixup(&table_done_fix);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t2, 15, 3);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 3);
    FT_LA_ADD_D_EMIT(out, la_t0, la_t0, la_t1);
    FT_LA_LD_D_EMIT(out, la_t0, la_t0, 0);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t0, 39, 16);
    FT_LA_BSTRPICK_D_EMIT(out, la_t3, la_t0, 63, 56);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_t3, 31, 24);
    ft_emit_store_env(out, la_t1,
                      offsetof(CPUX86State, segs[0].base) +
                      seg * sizeof(SegmentCache),
                      FT_LA_OPCODE_ST_D);
    ft_emit_li32(out, la_t1, 0xffffffffu);
    ft_emit_store_env(out, la_t1,
                      offsetof(CPUX86State, segs[0].limit) +
                      seg * sizeof(SegmentCache),
                      FT_LA_OPCODE_ST_W);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t0, 55, 40);
    FT_LA_ORI_EMIT(out, la_t1, la_t1, 1);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 8);
    ft_emit_store_env(out, la_t1,
                      offsetof(CPUX86State, segs[0].flags) +
                      seg * sizeof(SegmentCache),
                      FT_LA_OPCODE_ST_W);
}
#endif

static int ft_emit_call_pcmpistri_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc);
static int ft_emit_call_pcmpistrm_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc);
static int ft_emit_call_pcmpestri_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc);
static int ft_emit_call_pcmpestrm_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc);
static int ft_emit_fxsave_restore_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc, bool restore);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static int ft_emit_xsave_restore_helper(uint32_t **out,
                                        const FastTemplateFields *fields,
                                        target_ulong pc);
#endif
static int ft_emit_fsave_restore_helper(uint32_t **out,
                                        const FastTemplateFields *fields,
                                        target_ulong pc, bool restore);
static int ft_emit_fenv_helper(uint32_t **out,
                               const FastTemplateFields *fields,
                               target_ulong pc, bool restore);
#ifdef QUICKTRANS_LATU
static void ft_emit_default_helper_call(uint32_t **out, void *func,
                                        unsigned pointer_args,
                                        bool static_context);
#endif
static void ft_emit_default_helper_epilogue(uint32_t **out,
                                            bool static_context,
                                            bool helper_uses_fprs);

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static int ft_io_width_bytes(const FastTemplateFields *fields)
{
    if ((fields->opcode0 & 1) == 0) {
        return 1;
    }
    return fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 2 : 4;
}

static bool ft_io_needs_permission_check(const TranslationBlock *tb)
{
    int cpl = tb->flags & HF_CPL_MASK;
    int iopl = (tb->flags & HF_IOPL_MASK) >> HF_IOPL_SHIFT;

    return (tb->flags & HF_PE_MASK) &&
           (cpl > iopl || (tb->flags & HF_VM_MASK));
}

static void ft_emit_io_port_arg(uint32_t **out,
                                const FastTemplateFields *fields)
{
    if (fields->opcode0 >= 0xe4 && fields->opcode0 <= 0xe7) {
        FT_LA_ORI_EMIT(out, la_a1, la_zero, fields->imm & 0xff);
        return;
    }

    ft_emit_load_env(out, la_a1, lsenv_offset_of_gpr(lsenv, rdx_index),
                     FT_LA_OPCODE_LD_D);
    FT_LA_BSTRPICK_D_EMIT(out, la_a1, la_a1, 15, 0);
}

static void ft_emit_io_can_do(uint32_t **out, TranslationBlock *tb,
                              bool enabled)
{
    int offset;

    if (!(tb->cflags & CF_USE_ICOUNT)) {
        return;
    }
    offset = (int)offsetof(X86CPU, parent_obj.can_do_io) -
             (int)offsetof(X86CPU, env);
    FT_LA_ADDI_D_EMIT(out, la_a3, la_zero, enabled ? 1 : 0);
    ft_emit_store_env(out, la_a3, offset, FT_LA_OPCODE_ST_W);
}

static void ft_emit_io_check(uint32_t **out,
                             const FastTemplateFields *fields,
                             TranslationBlock *tb, int bytes,
                             bool static_context)
{
    if (!ft_io_needs_permission_check(tb)) {
        return;
    }
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_io_port_arg(out, fields);
    FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, bytes);
    ft_emit_default_helper_call(out, (void *)helper_check_io,
                                1u << 0, static_context);
}

static void ft_emit_io_breakpoint(uint32_t **out,
                                  const FastTemplateFields *fields,
                                  TranslationBlock *tb, target_ulong pc,
                                  int bytes, bool static_context)
{
    if (!(tb->flags & HF_IOBPT_MASK)) {
        return;
    }
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_io_port_arg(out, fields);
    FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, bytes);
    ft_emit_li64(out, la_a3, pc + fields->size);
    ft_emit_default_helper_call(out, (void *)helper_bpt_io,
                                1u << 0, static_context);
}

static void *ft_io_in_helper(int bytes)
{
    return bytes == 1 ? (void *)helper_inb :
           bytes == 2 ? (void *)helper_inw : (void *)helper_inl;
}

static void *ft_io_out_helper(int bytes)
{
    return bytes == 1 ? (void *)helper_outb :
           bytes == 2 ? (void *)helper_outw : (void *)helper_outl;
}
#endif

static int ft_emit_helper_indirect_exit(uint32_t **out, TranslationBlock *tb,
                                        uint32_t *code, int target,
                                        bool is_ret)
{
    ft_prepare_ret_indirect_goto(tb, code);
#if defined(QUICKTRANS_LATU) && !defined(QUICKTRANS_LATU_MINIMAL_HOST)
    FT_LA_OR_EMIT(out, la_r21, target, la_zero);
    return (*out - code) + latx_indirect_goto_macro_emit_for_fast(*out);
#elif defined(QUICKTRANS_LATU)
    return 0;
#else
    return (*out - code) +
           ft_emit_lats_indirect_lookup_exit(tb, out, target, la_t1, is_ret);
#endif
}

static void ft_emit_interrupt_helper(uint32_t **out, target_ulong pc,
                                     int intno, int next_eip_addend)
{
#ifdef CONFIG_SOFTMMU
    bool static_context = ft_emit_default_helper_prologue(out, false);
#else
    ft_emit_helper_prologue(out);
#endif
    ft_emit_li64(out, la_t0, pc);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_eip(lsenv),
                      FT_LA_OPCODE_ST_D);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, intno);
    FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, next_eip_addend);
#ifdef CONFIG_SOFTMMU
    ft_emit_default_helper_call(out, (void *)helper_raise_interrupt, 1u << 0,
                                static_context);
#else
    ft_emit_host_call(out, (void *)helper_raise_interrupt, 1u << 0);
#endif
    FT_LA_BREAK_EMIT(out, 0);
}

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static void ft_emit_system_dmw_ptr(uint32_t **out, int reg)
{
    if (hamt_enabled() && hamt_mode_dmw()) {
        FT_LA_LU52I_D_EMIT(out, reg, reg, -0x700);
    }
}

static void ft_emit_system_seg_cache(uint32_t **out, int seg, int selector,
                                     uint32_t flags)
{
    ft_emit_store_env(out, selector,
                      offsetof(CPUX86State, segs[seg].selector),
                      FT_LA_OPCODE_ST_W);
    ft_emit_store_env(out, la_zero,
                      offsetof(CPUX86State, segs[seg].base),
                      FT_LA_OPCODE_ST_D);
    ft_emit_li32(out, la_t2, UINT32_MAX);
    ft_emit_store_env(out, la_t2,
                      offsetof(CPUX86State, segs[seg].limit),
                      FT_LA_OPCODE_ST_W);
    ft_emit_li32(out, la_t2, flags);
    ft_emit_store_env(out, la_t2,
                      offsetof(CPUX86State, segs[seg].flags),
                      FT_LA_OPCODE_ST_W);
}

static bool ft_emit_fast_system_syscall(uint32_t **out, TranslationBlock *tb,
                                        target_ulong pc, int size)
{
    const uint32_t cs_flags = DESC_G_MASK | DESC_P_MASK | DESC_S_MASK |
                              DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK |
                              DESC_L_MASK;
    const uint32_t ss_flags = DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                              DESC_S_MASK | DESC_W_MASK | DESC_A_MASK;
    FastBranchLabel helper = { 0 };
    FastBranchLabel lookup = { 0 };
    FastBranchFixup sce_miss;
    FastBranchFixup mode_miss;
    FastBranchFixup cache_miss;
    FastBranchFixup pc_miss;

    if (!option_opt_syscall || !tb) {
        return false;
    }

    ft_emit_load_env(out, la_t0, lsenv_offset_of_efer(lsenv),
                     FT_LA_OPCODE_LD_D);
    FT_LA_ANDI_EMIT(out, la_t0, la_t0, MSR_EFER_SCE);
    ft_emit_branch_placeholder(out, &sce_miss, FT_BRANCH_BEQ, la_t0,
                               la_zero, &helper);

    ft_emit_load_env(out, la_t0, lsenv_offset_of_hflags(lsenv),
                     FT_LA_OPCODE_LD_WU);
    ft_emit_li32(out, la_t1, HF_LMA_MASK | HF_CS64_MASK);
    FT_LA_AND_EMIT(out, la_t2, la_t0, la_t1);
    ft_emit_branch_placeholder(out, &mode_miss, FT_BRANCH_BNE, la_t2,
                               la_t1, &helper);

    ft_emit_li64(out, ft_gpr(rcx_index), pc + size);
    if (!ft_emit_collect_rflags(out)) {
        return false;
    }
    FT_LA_OR_EMIT(out, ft_gpr(r11_index), la_t0, la_zero);

    ft_emit_load_env(out, la_t0, lsenv_offset_of_eflags(lsenv),
                     FT_LA_OPCODE_LD_WU);
    ft_emit_load_env(out, la_t1, lsenv_offset_of_fmask(lsenv),
                     FT_LA_OPCODE_LD_D);
    ft_emit_li32(out, la_t2, RF_MASK);
    FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);
    FT_LA_ANDN_EMIT(out, la_t0, la_t0, la_t1);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_eflags(lsenv),
                      FT_LA_OPCODE_ST_W);

    FT_LA_ANDI_EMIT(out, la_t1, la_t0,
                    CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    ft_emit_store_env(out, la_t1, lsenv_offset_of_cc_src(lsenv),
                      FT_LA_OPCODE_ST_D);
    ft_emit_li32(out, la_t2, CC_OP_EFLAGS);
    ft_emit_store_env(out, la_t2, lsenv_offset_of_cc_op(lsenv),
                      FT_LA_OPCODE_ST_D);
    FT_LA_X86MTFLAG_EMIT(out, la_t1, 0x3f);
    FT_LA_SRLI_D_EMIT(out, la_t1, la_t0, 10);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 1);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 1);
    FT_LA_ADDI_D_EMIT(out, la_t2, la_zero, 1);
    FT_LA_SUB_D_EMIT(out, la_t1, la_t2, la_t1);
    ft_emit_store_env(out, la_t1, lsenv_offset_of_df(lsenv),
                      FT_LA_OPCODE_ST_W);

    ft_emit_load_env(out, la_t0, lsenv_offset_of_star(lsenv),
                     FT_LA_OPCODE_LD_D);
    FT_LA_SRLI_D_EMIT(out, la_t1, la_t0, 32);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t1, 15, 0);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_zero, 1, 0);
    ft_emit_system_seg_cache(out, R_CS, la_t1, cs_flags);
    FT_LA_ADDI_D_EMIT(out, la_t1, la_t1, 8);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_zero, 1, 0);
    ft_emit_system_seg_cache(out, R_SS, la_t1, ss_flags);

    ft_emit_load_env(out, la_t0, lsenv_offset_of_hflags(lsenv),
                     FT_LA_OPCODE_LD_WU);
    ft_emit_li32(out, la_t1,
                 HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK);
    FT_LA_OR_EMIT(out, la_t0, la_t0, la_t1);
    ft_emit_li32(out, la_t1,
                 HF_ADDSEG_MASK | HF_CPL_MASK | HF_MPX_EN_MASK);
    FT_LA_ANDN_EMIT(out, la_t0, la_t0, la_t1);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_hflags(lsenv),
                      FT_LA_OPCODE_ST_W);
    ft_emit_load_env(out, la_t0, lsenv_offset_of_hflags2(lsenv),
                     FT_LA_OPCODE_LD_WU);
    ft_emit_li32(out, la_t1, HF2_MPX_PR_MASK);
    FT_LA_ANDN_EMIT(out, la_t0, la_t0, la_t1);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_hflags2(lsenv),
                      FT_LA_OPCODE_ST_W);

    ft_emit_load_env(out, la_t1, lsenv_offset_of_lstar(lsenv),
                     FT_LA_OPCODE_LD_D);
    ft_emit_store_env(out, la_t1, lsenv_offset_of_eip(lsenv),
                      FT_LA_OPCODE_ST_D);

    /* The kernel TB may use f0-f7, so preserve live MMX state first. */
    ft_emit_save_fprs_for_exception(out);

    add_misc_flags(tb, MF_END_SYSCALL);
    ft_emit_load_env(out, la_t0, lsenv_offset_of_syscall_tb(lsenv),
                     FT_LA_OPCODE_LD_D);
    ft_emit_branch_placeholder(out, &cache_miss, FT_BRANCH_BEQ, la_t0,
                               la_zero, &lookup);
    ft_emit_system_dmw_ptr(out, la_t0);
    if (option_opt_syscall == 2) {
        FT_LA_LD_D_EMIT(out, la_t2, la_t0,
                        offsetof(TranslationBlock, pc));
        ft_emit_branch_placeholder(out, &pc_miss, FT_BRANCH_BNE, la_t1,
                                   la_t2, &lookup);
        FT_LA_LD_D_EMIT(out, la_t0, la_t0,
                        offsetof(TranslationBlock, tc.ptr));
        ft_emit_system_dmw_ptr(out, la_t0);
    }
    FT_LA_JIRL_EMIT(out, la_zero, la_t0, 0);

    ft_bind_branch_label(&lookup, *out);
    ft_resolve_branch_fixup(&cache_miss);
    if (option_opt_syscall == 2) {
        ft_resolve_branch_fixup(&pc_miss);
    }
    ft_emit_direct_link_exit(tb, out, 0,
                             ((CPUX86State *)lsenv->cpu_state)->lstar,
                             la_t0);

    ft_bind_branch_label(&helper, *out);
    ft_resolve_branch_fixup(&sce_miss);
    ft_resolve_branch_fixup(&mode_miss);
    ft_emit_raise_syscall(out, tb, pc, size);
    return true;
}
#endif

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
/* LATS soft-FPU keeps guest masks in hflags. Hardware enables are zero,
 * except V when its masked-invalid recovery option is enabled.
 * Clobbers t0/t2/t3, preserving the environment memory address in t4. */
static void ft_emit_lats_soft_fcsr_from_mxcsr(uint32_t **out, int mxcsr)
{
    FT_LA_BSTRPICK_W_EMIT(out, la_t0, mxcsr, 14, 13);
    FT_LA_ANDI_EMIT(out, la_t2, la_t0, 1);
    FT_LA_SLLI_W_EMIT(out, la_t2, la_t2, 1);
    FT_LA_XOR_EMIT(out, la_t0, la_t0, la_t2);
    FT_LA_SLLI_W_EMIT(out, la_t2, la_t0, FCSR_OFF_RM);
    FT_LA_SLLI_W_EMIT(out, la_t3, mxcsr, 2);
    FT_LA_BITREV_4B_EMIT(out, la_t3, la_t3);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, 27, 24);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, 19, 16);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 0, 0);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, 28, 28);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, 20, 20);
    if (ft_fast_masked_v_enabled()) {
        FT_LA_ORI_EMIT(out, la_t2, la_t2, 1u << FCSR_OFF_EN_V);
    }
    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t2);
}
#endif

static void ft_emit_fcsr_from_mxcsr(uint32_t **out, int mxcsr)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (option_soft_fpu) {
        ft_emit_lats_soft_fcsr_from_mxcsr(out, mxcsr);
        return;
    }
#endif

    FT_LA_MOVFCSR2GR_EMIT(out, la_t2, 0);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_zero, FCSR_OFF_EN_V,
                         FCSR_OFF_EN_I);

    /* MXCSR mask bits are inverted relative to FCSR enable bits. */
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 7, 7);
    FT_LA_XORI_EMIT(out, la_t3, la_t3, 1);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_EN_V,
                         FCSR_OFF_EN_V);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 9, 9);
    FT_LA_XORI_EMIT(out, la_t3, la_t3, 1);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_EN_Z,
                         FCSR_OFF_EN_Z);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 10, 10);
    FT_LA_XORI_EMIT(out, la_t3, la_t3, 1);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_EN_O,
                         FCSR_OFF_EN_O);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 11, 11);
    FT_LA_XORI_EMIT(out, la_t3, la_t3, 1);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_EN_U,
                         FCSR_OFF_EN_U);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 12, 12);
    FT_LA_XORI_EMIT(out, la_t3, la_t3, 1);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_EN_I,
                         FCSR_OFF_EN_I);

    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_zero, FCSR_OFF_FLAGS_V,
                         FCSR_OFF_FLAGS_I);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 0, 0);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_FLAGS_V,
                         FCSR_OFF_FLAGS_V);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 2, 2);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_FLAGS_Z,
                         FCSR_OFF_FLAGS_Z);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 3, 3);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_FLAGS_O,
                         FCSR_OFF_FLAGS_O);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 4, 4);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_FLAGS_U,
                         FCSR_OFF_FLAGS_U);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 5, 5);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_FLAGS_I,
                         FCSR_OFF_FLAGS_I);

    FT_LA_BSTRPICK_W_EMIT(out, la_t3, mxcsr, 14, 13);
    FT_LA_ANDI_EMIT(out, la_t4, la_t3, 1);
    FT_LA_BEQ_EMIT(out, la_t4, la_zero, 2);
    FT_LA_XORI_EMIT(out, la_t3, la_t3, 2);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_RM + 1,
                         FCSR_OFF_RM);
    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t2);
}

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
/* LATS keeps CPUX86State in s0; short MXCSR field accesses need no copy. */
static void ft_emit_lats_mxcsr_load(uint32_t **out, int dst, int offset)
{
    if (ft_offset_fits_imm12(offset)) {
        FT_LA_LD_WU_EMIT(out, dst, la_s0, offset);
    } else {
        ft_emit_load_env(out, dst, offset, FT_LA_OPCODE_LD_WU);
    }
}

static void ft_emit_lats_mxcsr_store(uint32_t **out, int src, int offset)
{
    if (ft_offset_fits_imm12(offset)) {
        FT_LA_ST_W_EMIT(out, src, la_s0, offset);
    } else {
        ft_emit_store_env(out, src, offset, FT_LA_OPCODE_ST_W);
    }
}

/* Legacy soft-FPU LDMXCSR only maintains the exception-enable summary. */
static void ft_emit_lats_mxcsr_hflags(uint32_t **out, int mxcsr)
{
    FT_LA_BSTRPICK_W_EMIT(out, la_t0, mxcsr, 12, 7);
    FT_LA_XORI_EMIT(out, la_t0, la_t0, 0x3f);
    FT_LA_ANDI_EMIT(out, la_t0, la_t0, 0x3d);
    FT_LA_SLTU_EMIT(out, la_t0, la_zero, la_t0);
    ft_emit_lats_mxcsr_load(out, la_t2, offsetof(CPUX86State, hflags));
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t0, HF_SIGFPE_ON, HF_SIGFPE_ON);
    ft_emit_lats_mxcsr_store(out, la_t2, offsetof(CPUX86State, hflags));
}

/* Match update_mxcsr_status without a host call. Always rewrite the exception
 * flags: identical MXCSR loads may follow an SSE helper that raised flags. */
static void ft_emit_lats_mxcsr_status(uint32_t **out, int mxcsr)
{
    const int status = offsetof(CPUX86State, sse_status);
    const uint64_t rounding = (uint64_t)float_round_nearest_even |
        ((uint64_t)float_round_down << 8) |
        ((uint64_t)float_round_up << 16) |
        ((uint64_t)float_round_to_zero << 24);

    QEMU_BUILD_BUG_ON(sizeof(((float_status *)0)->float_rounding_mode) != 1);
    QEMU_BUILD_BUG_ON(sizeof(((float_status *)0)->float_exception_flags) != 2);
    QEMU_BUILD_BUG_ON(float_flag_invalid != 1 || float_flag_divbyzero != 2 ||
                      float_flag_overflow != 4 || float_flag_underflow != 8 ||
                      float_flag_inexact != 16);
    FT_LA_BSTRPICK_W_EMIT(out, la_t0, mxcsr, 14, 13);
    FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 3);
    ft_emit_li64(out, la_t2, rounding);
    FT_LA_SRL_D_EMIT(out, la_t0, la_t2, la_t0);
    ft_emit_store_env(out, la_t0,
                     status + offsetof(float_status, float_rounding_mode),
                     FT_LA_OPCODE_ST_B);

    FT_LA_SRLI_D_EMIT(out, la_t0, mxcsr, 1);
    FT_LA_ANDI_EMIT(out, la_t0, la_t0, 0x1e);
    FT_LA_ANDI_EMIT(out, la_t2, mxcsr, 1);
    FT_LA_OR_EMIT(out, la_t0, la_t0, la_t2);
    ft_emit_store_env(out, la_t0,
                     status + offsetof(float_status, float_exception_flags),
                     FT_LA_OPCODE_ST_H);

    FT_LA_BSTRPICK_W_EMIT(out, la_t0, mxcsr, 6, 6);
    ft_emit_store_env(out, la_t0,
                     status + offsetof(float_status, flush_inputs_to_zero),
                     FT_LA_OPCODE_ST_B);
    FT_LA_BSTRPICK_W_EMIT(out, la_t0, mxcsr, 15, 15);
    ft_emit_store_env(out, la_t0,
                     status + offsetof(float_status, flush_to_zero),
                     FT_LA_OPCODE_ST_B);

    ft_emit_lats_mxcsr_hflags(out, mxcsr);
}
#endif

static void ft_emit_mxcsr_flags_from_fcsr(uint32_t **out, int mxcsr)
{
    FT_LA_MOVFCSR2GR_EMIT(out, la_t2, 0);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, la_t2, FCSR_OFF_FLAGS_V,
                          FCSR_OFF_FLAGS_V);
    FT_LA_BSTRPICK_W_EMIT(out, la_t4, la_t2, FCSR_OFF_FLAGS_Z,
                          FCSR_OFF_FLAGS_Z);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t4, 2);
    FT_LA_OR_EMIT(out, la_t3, la_t3, la_t4);
    FT_LA_BSTRPICK_W_EMIT(out, la_t4, la_t2, FCSR_OFF_FLAGS_O,
                          FCSR_OFF_FLAGS_O);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t4, 3);
    FT_LA_OR_EMIT(out, la_t3, la_t3, la_t4);
    FT_LA_BSTRPICK_W_EMIT(out, la_t4, la_t2, FCSR_OFF_FLAGS_U,
                          FCSR_OFF_FLAGS_U);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t4, 4);
    FT_LA_OR_EMIT(out, la_t3, la_t3, la_t4);
    FT_LA_BSTRPICK_W_EMIT(out, la_t4, la_t2, FCSR_OFF_FLAGS_I,
                          FCSR_OFF_FLAGS_I);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t4, 5);
    FT_LA_OR_EMIT(out, la_t3, la_t3, la_t4);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (option_soft_fpu) {
        /* Legacy FXSAVE/STMXCSR replace the hardware-backed flag bits.
         * OR would retain a software IE set by masked-invalid recovery
         * after the handler has cleared the hardware flag. Preserve DE. */
        FT_LA_BSTRINS_W_EMIT(out, mxcsr, la_t3, 0, 0);
        FT_LA_SRLI_W_EMIT(out, la_t3, la_t3, 2);
        FT_LA_BSTRINS_W_EMIT(out, mxcsr, la_t3, 5, 2);
        return;
    }
#endif
    FT_LA_OR_EMIT(out, mxcsr, mxcsr, la_t3);
}

#ifndef QUICKTRANS_LATU
static bool ft_emit_lats_static_helper_context(uint32_t **out,
                                                bool prologue,
                                                bool nofp)
{
    CPUState *cpu;
    CPUArchState *env;
    int mtcc_id;
    ADDR target;

    if (!scs_enabled()) {
        return false;
    }
    cpu = current_cpu;
    env = cpu ? cpu->env_ptr : NULL;
    mtcc_id = env ? curr_mtcc(env) : 0;
    if (prologue) {
        if (nofp) {
            target = GET_SC_TABLE_OFFSET(
                mtcc_id, scs_prologue_nofp,
                lsenv->tr_data->tcg_region_offset);
        } else {
            target = GET_SC_TABLE_OFFSET(
                mtcc_id, scs_prologue,
                lsenv->tr_data->tcg_region_offset);
        }
    } else {
        if (nofp) {
            target = GET_SC_TABLE_OFFSET(
                mtcc_id, scs_epilogue_nofp,
                lsenv->tr_data->tcg_region_offset);
        } else {
            target = GET_SC_TABLE_OFFSET(
                mtcc_id, scs_epilogue,
                lsenv->tr_data->tcg_region_offset);
        }
    }

    ft_emit_lats_static_call(out, target, la_t0, false);
    return true;
}

static bool ft_emit_lats_nofp_helper(uint32_t **out, void *func)
{
    bool static_context = ft_emit_nofp_helper_prologue(out);

    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_default_helper_call(out, func, 1u << 0, static_context);
    ft_emit_nofp_helper_epilogue(out, static_context);
    return true;
}

static bool ft_emit_lats_selector_helper_prologue(
    uint32_t **out, const FastTemplateFields *fields, target_ulong pc,
    bool *static_context)
{
    bool use_static_context = scs_enabled();
    int selector = use_static_context ? la_a2 : la_a3;
    int src;

    /* Read guest memory before the static prologue leaves the guest ASID. */
    if (!ft_emit_load_rm16(out, fields, pc, &src)) {
        return false;
    }
    FT_LA_BSTRPICK_D_EMIT(out, selector, src, 15, 0);
    *static_context = ft_emit_nofp_helper_prologue(out);
    lsassert(*static_context == use_static_context);
    FT_LA_OR_EMIT(out, la_a1, selector, la_zero);
    return true;
}

static bool ft_emit_lats_selector_default_helper_prologue(
    uint32_t **out, const FastTemplateFields *fields, target_ulong pc,
    bool *static_context)
{
    bool use_static_context = scs_enabled();
    int selector = use_static_context ? la_a2 : la_a3;
    int src;

    /* Read guest memory before the static prologue leaves the guest ASID. */
    if (!ft_emit_load_rm16(out, fields, pc, &src)) {
        return false;
    }
    FT_LA_BSTRPICK_D_EMIT(out, selector, src, 15, 0);
    *static_context = ft_emit_default_helper_prologue(out, false);
    lsassert(*static_context == use_static_context);
    FT_LA_OR_EMIT(out, la_a1, selector, la_zero);
    return true;
}
#endif

static int ft_emit_helper_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;

    switch (fields->kind) {
    case FT_IO:
    {
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        bool is_in = fields->id == dt_X86_INS_IN;
        bool static_context;
        int bytes;

        if (!tb) {
            return 0;
        }
        bytes = ft_io_width_bytes(fields);
        static_context = ft_emit_nofp_helper_prologue(&out);
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_io_check(&out, fields, tb, bytes, static_context);
        ft_emit_io_can_do(&out, tb, true);

        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_io_port_arg(&out, fields);
        if (!is_in) {
            ft_emit_load_env(&out, la_a2,
                             lsenv_offset_of_gpr(lsenv, rax_index),
                             FT_LA_OPCODE_LD_D);
        }
        ft_emit_default_helper_call(&out,
                                    is_in ? ft_io_in_helper(bytes) :
                                            ft_io_out_helper(bytes),
                                    1u << 0, static_context);
        ft_emit_io_can_do(&out, tb, false);

        if (is_in) {
            ft_emit_load_env(&out, la_a1,
                             lsenv_offset_of_gpr(lsenv, rax_index),
                             FT_LA_OPCODE_LD_D);
            if (bytes == 1) {
                FT_LA_BSTRINS_D_EMIT(&out, la_a1, la_a0, 7, 0);
            } else if (bytes == 2) {
                FT_LA_BSTRINS_D_EMIT(&out, la_a1, la_a0, 15, 0);
            } else {
                FT_LA_BSTRPICK_D_EMIT(&out, la_a1, la_a0, 31, 0);
            }
            ft_emit_store_env(&out, la_a1,
                              lsenv_offset_of_gpr(lsenv, rax_index),
                              FT_LA_OPCODE_ST_D);
        }
        ft_emit_io_breakpoint(&out, fields, tb, pc, bytes,
                              static_context);
        ft_emit_nofp_helper_epilogue(&out, static_context);
#else
        ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
#endif
        break;
    }
    case FT_LGDT:
    case FT_LIDT:
    {
        int addr;
        int offset;
        bool code64;
        int base_bytes;

        if (!tb) {
            return 0;
        }
        if (tb->flags & HF_CPL_MASK) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }
        if (fields->modrm_mod == 3 ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        offset = ft_mem_access_offset(fields, addr);
        code64 = (tb->flags & HF_CS64_MASK) != 0;
        base_bytes = code64 ? 8 : 4;
        if (!ft_emit_load_addr_bytes(&out, addr, offset, la_t2, 2) ||
            !ft_emit_load_addr_bytes(&out, addr, offset + 2, la_t3,
                                     base_bytes)) {
            return 0;
        }
        if (!code64 && fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
            FT_LA_BSTRPICK_D_EMIT(&out, la_t3, la_t3, 23, 0);
        }
        ft_emit_store_env(&out, la_t3,
                          fields->kind == FT_LGDT ?
                          ft_lsenv_offset_of_gdtr_base(lsenv) :
                          ft_lsenv_offset_of_idtr_base(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_store_env(&out, la_t2,
                          fields->kind == FT_LGDT ?
                          ft_lsenv_offset_of_gdtr_limit(lsenv) :
                          ft_lsenv_offset_of_idtr_limit(lsenv),
                          FT_LA_OPCODE_ST_W);
        break;
    }
    case FT_SGDT:
    case FT_SIDT:
    {
        int addr;
        int offset;

        if (fields->modrm_mod == 3 ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        offset = ft_mem_access_offset(fields, addr);
        ft_emit_load_env(&out, la_t2,
                         fields->kind == FT_SGDT ?
                         ft_lsenv_offset_of_gdtr_limit(lsenv) :
                         ft_lsenv_offset_of_idtr_limit(lsenv),
                         FT_LA_OPCODE_LD_WU);
        ft_emit_load_env(&out, la_t3,
                         fields->kind == FT_SGDT ?
                         ft_lsenv_offset_of_gdtr_base(lsenv) :
                         ft_lsenv_offset_of_idtr_base(lsenv),
                         FT_LA_OPCODE_LD_D);
        if (!ft_emit_store_addr_bytes(&out, pc, addr, offset, la_t2, 2) ||
            !ft_emit_store_addr_bytes(&out, pc, addr, offset + 2, la_t3, 8)) {
            return 0;
        }
        break;
    }
    case FT_LLDT:
    case FT_LTR:
    {
#ifndef QUICKTRANS_LATU
        bool static_context;
#else
        int src;
#endif

        if (!tb || !(tb->flags & HF_PE_MASK) || (tb->flags & HF_VM_MASK)) {
            ft_emit_raise_illop(&out, pc);
            break;
        }
        if (tb->flags & HF_CPL_MASK) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }

#ifndef QUICKTRANS_LATU
        if (!ft_emit_lats_selector_default_helper_prologue(
                &out, fields, pc, &static_context)) {
            return 0;
        }
#else
        ft_emit_helper_prologue(&out);
        if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_BSTRPICK_D_EMIT(&out, la_a1, src, 15, 0);
#endif
        ft_emit_cpu_env_ptr(&out, la_a0);
#ifndef QUICKTRANS_LATU
        ft_emit_default_helper_call(&out,
                                    fields->kind == FT_LLDT ?
                                    (void *)helper_lldt : (void *)helper_ltr,
                                    1u << 0,
                                    static_context);
        ft_emit_default_helper_epilogue(&out, static_context, false);
#else
        ft_emit_host_call(&out,
                          fields->kind == FT_LLDT ?
                          (void *)helper_lldt : (void *)helper_ltr,
                          1u << 0);
        ft_emit_helper_epilogue(&out);
#endif
        break;
    }
    case FT_SLDT:
    case FT_STR:
        if (!tb || !(tb->flags & HF_PE_MASK) || (tb->flags & HF_VM_MASK)) {
            ft_emit_raise_illop(&out, pc);
            break;
        }
        ft_emit_load_env(&out, la_t0,
                         fields->kind == FT_SLDT ?
                         ft_lsenv_offset_of_ldtr_selector(lsenv) :
                         ft_lsenv_offset_of_tr_selector(lsenv),
                         FT_LA_OPCODE_LD_HU);
        if (fields->modrm_mod != 3) {
            if (!ft_emit_store_rm16(&out, fields, pc, la_t0)) {
                return 0;
            }
        } else if (ft_rex_w(fields)) {
            if (!ft_emit_store_rm64(&out, fields, pc, la_t0)) {
                return 0;
            }
        } else if (fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
            if (!ft_emit_store_rm16(&out, fields, pc, la_t0)) {
                return 0;
            }
        } else if (!ft_emit_store_rm32(&out, fields, pc, la_t0, true)) {
            return 0;
        }
        break;
    case FT_SMSW:
        ft_emit_load_env(&out, la_t0, ft_lsenv_offset_of_cr0(lsenv),
                         FT_LA_OPCODE_LD_D);
        if (fields->modrm_mod != 3) {
            if (!ft_emit_store_rm16(&out, fields, pc, la_t0)) {
                return 0;
            }
        } else if (ft_rex_w(fields)) {
            if (!ft_emit_store_rm64(&out, fields, pc, la_t0)) {
                return 0;
            }
        } else if (fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
            if (!ft_emit_store_rm16(&out, fields, pc, la_t0)) {
                return 0;
            }
        } else if (!ft_emit_store_rm32(&out, fields, pc, la_t0, true)) {
            return 0;
        }
        break;
    case FT_CLTS:
        if (!tb) {
            return 0;
        }
        if (tb->flags & HF_CPL_MASK) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }
        ft_emit_load_env(&out, la_t0, ft_lsenv_offset_of_cr0(lsenv),
                         FT_LA_OPCODE_LD_WU);
        ft_emit_li32(&out, la_t1, CR0_TS_MASK);
        FT_LA_ANDN_EMIT(&out, la_t0, la_t0, la_t1);
        ft_emit_store_env(&out, la_t0, ft_lsenv_offset_of_cr0(lsenv),
                          FT_LA_OPCODE_ST_W);
        ft_emit_load_env(&out, la_t0, ft_lsenv_offset_of_hflags(lsenv),
                         FT_LA_OPCODE_LD_WU);
        ft_emit_li32(&out, la_t1, HF_TS_MASK);
        FT_LA_ANDN_EMIT(&out, la_t0, la_t0, la_t1);
        ft_emit_store_env(&out, la_t0, ft_lsenv_offset_of_hflags(lsenv),
                          FT_LA_OPCODE_ST_W);
        ft_emit_li64(&out, la_t0, pc + fields->size);
        ft_emit_tu_indirect_dispatch_exit(tb, &out, la_t0, la_t1);
        return out - code;
    case FT_CLAC:
        if (!tb) {
            return 0;
        }
        if (!(((CPUX86State *)lsenv->cpu_state)->features[FEAT_7_0_EBX] &
              CPUID_7_0_EBX_SMAP) || (tb->flags & HF_CPL_MASK)) {
            ft_emit_raise_illop(&out, pc);
            break;
        }
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eflags(lsenv),
                         FT_LA_OPCODE_LD_WU);
        ft_emit_li32(&out, la_t1, AC_MASK);
        FT_LA_ANDN_EMIT(&out, la_t0, la_t0, la_t1);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eflags(lsenv),
                          FT_LA_OPCODE_ST_W);
        break;
    case FT_STAC:
        if (!tb) {
            return 0;
        }
        if (!(((CPUX86State *)lsenv->cpu_state)->features[FEAT_7_0_EBX] &
              CPUID_7_0_EBX_SMAP) || (tb->flags & HF_CPL_MASK)) {
            ft_emit_raise_illop(&out, pc);
            break;
        }
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eflags(lsenv),
                         FT_LA_OPCODE_LD_WU);
        ft_emit_li32(&out, la_t1, AC_MASK);
        FT_LA_OR_EMIT(&out, la_t0, la_t0, la_t1);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eflags(lsenv),
                          FT_LA_OPCODE_ST_W);
        break;
    case FT_INVD:
    case FT_WBINVD:
        if (!tb) {
            return 0;
        }
        if (tb->flags & HF_CPL_MASK) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
        } else {
            FT_LA_NOP_EMIT(&out);
        }
        break;
    case FT_INVLPG:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    {
        bool static_context;
        bool code64;
        int addr;
        int offset;
        int saved_addr;

        if (!tb || fields->modrm_mod == 3) {
            return 0;
        }
        if (tb->flags & HF_CPL_MASK) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        offset = ft_mem_access_offset(fields, addr);
        saved_addr = scs_enabled() ? la_a2 : la_a3;
        if (offset) {
            if (ft_fits_simm12(offset)) {
                FT_LA_ADDI_D_EMIT(&out, saved_addr, addr, offset);
            } else {
                if (!ft_emit_li32(&out, la_t2, (uint32_t)offset)) {
                    return 0;
                }
                FT_LA_ADD_D_EMIT(&out, saved_addr, addr, la_t2);
            }
        } else {
            FT_LA_OR_EMIT(&out, saved_addr, addr, la_zero);
        }
        code64 = (tb->flags & HF_CS64_MASK) != 0;
        if (!code64) {
            FT_LA_BSTRPICK_D_EMIT(&out, saved_addr, saved_addr, 31, 0);
        }

        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        static_context = ft_emit_default_helper_prologue(&out, false);
        FT_LA_OR_EMIT(&out, la_a1, saved_addr, la_zero);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_default_helper_call(&out, (void *)helper_flush_page,
                                    1u << 0, static_context);
        ft_emit_default_helper_epilogue(&out, static_context, false);

        ft_emit_li64(&out, la_t0, pc + fields->size);
        ft_emit_tu_indirect_dispatch_exit(tb, &out, la_t0, la_t1);
        return out - code;
    }
#else
        return 0;
#endif
    case FT_RDPMC:
    {
        bool static_context;

        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        static_context = ft_emit_default_helper_prologue(&out, false);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_default_helper_call(&out, (void *)helper_rdpmc,
                                    1u << 0, static_context);
        ft_emit_default_helper_epilogue(&out, static_context, false);
        break;
    }
    case FT_RDMSR:
    {
#ifndef QUICKTRANS_LATU
        bool static_context;
#endif

        if (!tb) {
            return 0;
        }
        if (tb->flags & HF_CPL_MASK) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
#ifndef QUICKTRANS_LATU
        static_context = ft_emit_nofp_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_default_helper_call(&out, (void *)helper_rdmsr,
                                    1u << 0, static_context);
        ft_emit_nofp_helper_epilogue(&out, static_context);
#else
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)helper_rdmsr, 1u << 0);
        ft_emit_helper_epilogue(&out);
#endif
        break;
    }
    case FT_WRMSR:
    {
        bool static_context;

        if (!tb) {
            return 0;
        }
        if (tb->flags & HF_CPL_MASK) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        static_context = ft_emit_default_helper_prologue(&out, false);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_default_helper_call(&out, (void *)helper_wrmsr,
                                    1u << 0, static_context);
        ft_emit_default_helper_epilogue(&out, static_context, false);
        ft_emit_li64(&out, la_t0, pc + fields->size);
        ft_emit_tu_indirect_dispatch_exit(tb, &out, la_t0, la_t1);
        return out - code;
    }
    case FT_RSM:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    {
        bool static_context;

        if (!tb) {
            return 0;
        }
        if (!(tb->flags & HF_SMM_MASK)) {
            ft_emit_raise_illop(&out, pc);
            break;
        }

        ft_emit_li64(&out, la_t0, pc + fields->size);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        static_context = ft_emit_nofp_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_default_helper_call(&out, (void *)helper_rsm,
                                    1u << 0, static_context);
        ft_emit_nofp_helper_epilogue(&out, static_context);
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                         FT_LA_OPCODE_LD_D);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
    }
#else
        return 0;
#endif
    case FT_SWAPGS:
        if (!tb || !(tb->flags & HF_CS64_MASK)) {
            ft_emit_raise_illop(&out, pc);
            break;
        }
        if (tb->flags & HF_CPL_MASK) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }
        ft_emit_load_env(&out, la_t0,
                         offsetof(CPUX86State, segs[gs_index].base),
                         FT_LA_OPCODE_LD_D);
        ft_emit_load_env(&out, la_t1,
                         offsetof(CPUX86State, kernelgsbase),
                         FT_LA_OPCODE_LD_D);
        ft_emit_store_env(&out, la_t1,
                          offsetof(CPUX86State, segs[gs_index].base),
                          FT_LA_OPCODE_ST_D);
        ft_emit_store_env(&out, la_t0,
                          offsetof(CPUX86State, kernelgsbase),
                          FT_LA_OPCODE_ST_D);
        break;
    case FT_LFS:
    case FT_LGS:
    case FT_LSS:
    {
        int addr;
        int offset;
        int dst = ft_modrm_reg_index(fields);
        int data_bytes = fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 2 : 4;
#ifndef QUICKTRANS_LATU
        bool static_context;
        bool use_static_context;
        int selector;
#endif

        if (!tb || dst < 0 || dst >= GPR_NUM ||
            fields->modrm_mod == 3 || ft_rex_w(fields) ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        offset = ft_mem_access_offset(fields, addr);
#ifndef QUICKTRANS_LATU
        use_static_context = scs_enabled();
        selector = use_static_context ? la_a2 : la_a3;
#else
        const int selector = la_t3;
#endif
        if (!ft_emit_load_addr_bytes(&out, addr, offset, la_t2,
                                     data_bytes) ||
            !ft_emit_load_addr_bytes(&out, addr, offset + data_bytes,
                                     selector, 2)) {
            return 0;
        }
#ifndef QUICKTRANS_LATU
        ft_emit_store_env(&out, la_t2,
                          offsetof(CPUX86State, tmparea[0]),
                          FT_LA_OPCODE_ST_D);
        static_context = ft_emit_nofp_helper_prologue(&out);
        lsassert(static_context == use_static_context);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero,
                          fields->kind == FT_LFS ? fs_index :
                          fields->kind == FT_LGS ? gs_index : ss_index);
        if (!static_context) {
            FT_LA_OR_EMIT(&out, la_a2, selector, la_zero);
        }
        ft_emit_default_helper_call(&out, (void *)helper_load_seg,
                                    1u << 0, static_context);
        ft_emit_nofp_helper_epilogue(&out, static_context);
#else
        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
        FT_LA_ST_D_EMIT(&out, la_t2, la_sp, 0);
        ft_emit_host_stack_end(&out);
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero,
                          fields->kind == FT_LFS ? fs_index :
                          fields->kind == FT_LGS ? gs_index : ss_index);
        FT_LA_OR_EMIT(&out, la_a2, selector, la_zero);
        ft_emit_host_call(&out, (void *)helper_load_seg, 1u << 0);
        ft_emit_helper_epilogue(&out);
#endif
#ifndef QUICKTRANS_LATU
        ft_emit_load_env(&out, la_t0,
                         offsetof(CPUX86State, tmparea[0]),
                         FT_LA_OPCODE_LD_D);
#else
        ft_emit_host_stack_begin(&out);
        FT_LA_LD_D_EMIT(&out, la_t0, la_sp, 0);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
        ft_emit_host_stack_end(&out);
#endif
        if (data_bytes == 2) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
        } else {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), la_t0, 31, 0);
        }
        if (fields->kind == FT_LSS) {
            ft_emit_load_env(&out, la_t0, ft_lsenv_offset_of_hflags(lsenv),
                             FT_LA_OPCODE_LD_WU);
            FT_LA_ORI_EMIT(&out, la_t0, la_t0, HF_INHIBIT_IRQ_MASK);
            ft_emit_store_env(&out, la_t0, ft_lsenv_offset_of_hflags(lsenv),
                              FT_LA_OPCODE_ST_W);
            ft_emit_li64(&out, la_t0, pc + fields->size);
            ft_emit_tu_indirect_dispatch_exit(tb, &out, la_t0, la_t1);
            return out - code;
        }
        break;
    }
    case FT_HELPER_BCD:
    {
        void *func;

        switch (fields->id) {
        case dt_X86_INS_AAA: func = (void *)helper_aaa; break;
        case dt_X86_INS_AAS: func = (void *)helper_aas; break;
        case dt_X86_INS_DAA: func = (void *)helper_daa; break;
        case dt_X86_INS_DAS: func = (void *)helper_das; break;
        case dt_X86_INS_AAM: func = (void *)helper_aam; break;
        case dt_X86_INS_AAD: func = (void *)helper_aad; break;
        default: return 0;
        }
        if (fields->id == dt_X86_INS_AAM && fields->imm == 0) {
            ft_emit_raise_exception(&out, pc, EXCP00_DIVZ);
            break;
        }
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        if (fields->id == dt_X86_INS_AAM || fields->id == dt_X86_INS_AAD) {
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->imm);
        }
        ft_emit_host_call(&out, func, 1u << 0);
        ft_emit_helper_epilogue(&out);
        break;
    }
    case FT_HELPER_INTO:
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->size);
        ft_emit_host_call(&out, (void *)helper_into, 1u << 0);
        ft_emit_helper_epilogue(&out);
        break;
    case FT_LAR:
    case FT_LSL:
    {
#ifndef QUICKTRANS_LATU
        bool static_context;
#endif
        void *helper = fields->kind == FT_LAR ?
            (void *)ft_helper_lar : (void *)ft_helper_lsl;
        int dst = ft_modrm_reg_index(fields);
#ifdef QUICKTRANS_LATU
        int src;
#endif
        int width = ft_rex_w(fields) ? 64 :
                    fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;

        if (!tb || !(tb->flags & HF_PE_MASK) || (tb->flags & HF_VM_MASK) ||
            dst < 0 || dst >= GPR_NUM) {
            ft_emit_raise_illop(&out, pc);
            break;
        }

#ifndef QUICKTRANS_LATU
        if (!ft_emit_lats_selector_helper_prologue(
                &out, fields, pc, &static_context)) {
            return 0;
        }
#else
        ft_emit_helper_prologue(&out);
        if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_BSTRPICK_D_EMIT(&out, la_a1, src, 15, 0);
#endif
        ft_emit_cpu_env_ptr(&out, la_a0);
#ifndef QUICKTRANS_LATU
        ft_emit_default_helper_call(&out, helper, 1u << 0,
                                    static_context);
        ft_emit_nofp_helper_epilogue(&out, static_context);
#else
        ft_emit_host_call(&out, helper, 1u << 0);
        ft_emit_helper_epilogue(&out);
#endif

        FT_LA_X86MFFLAG_EMIT(&out, la_t0, ZF_USEDEF_BIT);
        FT_LA_BEQ_EMIT(&out, la_t0, la_zero, 2);
        if (width == 64) {
            FT_LA_OR_EMIT(&out, ft_gpr(dst), la_a0, la_zero);
        } else if (width == 32) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), la_a0, 31, 0);
        } else {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_a0, 15, 0);
        }
        break;
    }
    case FT_VERR:
    {
#ifndef QUICKTRANS_LATU
        bool static_context;
#endif
#ifdef QUICKTRANS_LATU
        int src;
#endif

        if (!tb || !(tb->flags & HF_PE_MASK) || (tb->flags & HF_VM_MASK)) {
            ft_emit_raise_illop(&out, pc);
            break;
        }

#ifndef QUICKTRANS_LATU
        if (!ft_emit_lats_selector_helper_prologue(
                &out, fields, pc, &static_context)) {
            return 0;
        }
#else
        ft_emit_helper_prologue(&out);
        if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_BSTRPICK_D_EMIT(&out, la_a1, src, 15, 0);
#endif
        ft_emit_cpu_env_ptr(&out, la_a0);
#ifndef QUICKTRANS_LATU
        ft_emit_default_helper_call(&out, (void *)ft_helper_verr, 1u << 0,
                                    static_context);
        ft_emit_nofp_helper_epilogue(&out, static_context);
#else
        ft_emit_host_call(&out, (void *)ft_helper_verr, 1u << 0);
        ft_emit_helper_epilogue(&out);
#endif
        break;
    }
    case FT_VERW:
    {
#ifndef QUICKTRANS_LATU
        bool static_context;
#else
        int src;
#endif

        if (!tb || !(tb->flags & HF_PE_MASK) || (tb->flags & HF_VM_MASK)) {
            ft_emit_raise_illop(&out, pc);
            break;
        }

#ifndef QUICKTRANS_LATU
        if (!ft_emit_lats_selector_helper_prologue(
                &out, fields, pc, &static_context)) {
            return 0;
        }
#else
        ft_emit_helper_prologue(&out);
        if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_BSTRPICK_D_EMIT(&out, la_a1, src, 15, 0);
#endif
        ft_emit_cpu_env_ptr(&out, la_a0);
#ifndef QUICKTRANS_LATU
        ft_emit_default_helper_call(&out, (void *)ft_helper_verw, 1u << 0,
                                    static_context);
        ft_emit_nofp_helper_epilogue(&out, static_context);
#else
        ft_emit_host_call(&out, (void *)ft_helper_verw, 1u << 0);
        ft_emit_helper_epilogue(&out);
#endif
        break;
    }
    case FT_HELPER_CPUID:
#ifndef QUICKTRANS_LATU
        if (ft_emit_lats_nofp_helper(&out, (void *)helper_cpuid)) {
            break;
        }
#endif
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)helper_cpuid, 1u << 0);
        ft_emit_cpuid_helper_epilogue(&out);
        break;
    case FT_HELPER_PCMPISTRI:
        if (!ft_emit_call_pcmpistri_helper(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_HELPER_PCMPISTRM:
        if (!ft_emit_call_pcmpistrm_helper(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_HELPER_PCMPESTRI:
        if (!ft_emit_call_pcmpestri_helper(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_HELPER_PCMPESTRM:
        if (!ft_emit_call_pcmpestrm_helper(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_HELPER_LDMXCSR:
    {
        int addr;
        int mxcsr_offset = lsenv_offset_of_mxcsr(lsenv);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        FastBranchLabel updated = { 0 };
        FastBranchFixup updated_fixup;
        FastBranchLabel update = { 0 };
        FastBranchFixup update_fixup;
#endif

        if (fields->modrm_mod == 3 ||
            fields->modrm_reg != 2) {
            return 0;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_LD_WU_EMIT(&out, la_t1, addr, ft_mem_access_offset(fields, addr));
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_lazy_mxcsr) {
            ft_emit_lats_mxcsr_load(&out, la_t2, mxcsr_offset);
        }
        if (option_lazy_mxcsr) {
            /* Match the host's opt-in lazy policy, including retained flags
             * when an identical load follows a floating-point operation. */
            ft_emit_lats_mxcsr_load(&out, la_t0,
                                   offsetof(CPUX86State, old_mxcsr));
            /* Restore helpers can change MXCSR without updating old_mxcsr. */
            ft_emit_branch_placeholder(&out, &update_fixup, FT_BRANCH_BNE,
                                       la_t2, la_t1, &update);
            ft_emit_branch_placeholder(&out, &updated_fixup, FT_BRANCH_BEQ,
                                       la_t0, la_t1, &updated);
            ft_bind_branch_label(&update, out);
            ft_resolve_branch_fixup(&update_fixup);
            /* Both fields already equal the input on a lazy hit.  Keep
             * the stale-cache guard, but write only on the update path. */
            ft_emit_lats_mxcsr_store(&out, la_t1,
                                    offsetof(CPUX86State, old_mxcsr));
        }
        ft_emit_lats_mxcsr_store(&out, la_t1, mxcsr_offset);
#else
        ft_emit_store_env(&out, la_t1, mxcsr_offset, FT_LA_OPCODE_ST_W);
#endif
        ft_emit_fcsr_from_mxcsr(&out, la_t1);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_soft_fpu) {
            ft_emit_lats_mxcsr_hflags(&out, la_t1);
        }
        if (option_lazy_mxcsr) {
            ft_bind_branch_label(&updated, out);
            ft_resolve_branch_fixup(&updated_fixup);
        }
#endif

#ifndef QUICKTRANS_LATU
#ifdef CONFIG_SOFTMMU
        /* Match legacy soft-FPU policy: lazy hits skip hflags too, and
         * LDMXCSR does not maintain the software SSE status fields. */
        if (!option_soft_fpu) {
            ft_emit_lats_mxcsr_status(&out, la_t1);
        }
#else
        ft_emit_lats_nofp_helper(&out, (void *)update_mxcsr_status);
#endif
#else
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)update_mxcsr_status, 1u << 0);
        ft_emit_helper_epilogue(&out);
#endif
        break;
    }
    case FT_HELPER_FXSAVE:
    case FT_HELPER_FXRSTOR:
        if (!ft_emit_fxsave_restore_helper(
                &out, fields, pc, fields->kind == FT_HELPER_FXRSTOR)) {
            return 0;
        }
        break;
    case FT_HELPER_XSAVE:
    case FT_HELPER_XRSTOR:
    case FT_HELPER_XSAVEOPT:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (!tb) {
            return 0;
        }
        if (!(((CPUX86State *)lsenv->cpu_state)->features[FEAT_1_ECX] &
              CPUID_EXT_XSAVE) ||
            (fields->kind == FT_HELPER_XSAVEOPT &&
             !(((CPUX86State *)lsenv->cpu_state)->features[FEAT_XSAVE] &
               CPUID_XSAVE_XSAVEOPT))) {
            ft_emit_raise_illop(&out, pc);
            break;
        }
        if (!ft_emit_xsave_restore_helper(&out, fields, pc)) {
            return 0;
        }
        if (fields->kind == FT_HELPER_XRSTOR) {
            /* The helper restored guest r8/r9 in t0/t1 already. */
            ft_emit_li64(&out, la_a4, pc + fields->size);
            ft_emit_tu_indirect_dispatch_exit(tb, &out, la_a4, la_a5);
            return out - code;
        }
        break;
#else
        return 0;
#endif
    case FT_HELPER_FNSAVE:
    case FT_HELPER_FRSTOR:
        if (!ft_emit_fsave_restore_helper(
                &out, fields, pc, fields->kind == FT_HELPER_FRSTOR)) {
            return 0;
        }
        break;
    case FT_HELPER_FLDENV:
    case FT_HELPER_FNSTENV:
        if (!ft_emit_fenv_helper(
                &out, fields, pc, fields->kind == FT_HELPER_FLDENV)) {
            return 0;
        }
        break;
    case FT_HELPER_SYSCALL:
    {
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (ft_emit_fast_system_syscall(&out, tb, pc, fields->size)) {
            break;
        }
#endif
#ifndef CONFIG_SOFTMMU
        /* These reports are flushed by the linux-user exit cleanup path. */
        bool exit_cleanup_requested =
            (ft_startup_flags() & FT_STARTUP_EXIT_CLEANUP) != 0;

        if (!exit_cleanup_requested) {
            /* Guest exit still needs linux-user's per-thread cleanup. */
            FT_LA_ADDI_D_EMIT(&out, la_t0, la_zero, 231);
            FT_LA_BNE_EMIT(&out, ft_gpr(rax_index), la_t0, 5);
            FT_LA_OR_EMIT(&out, la_a0, ft_gpr(rdi_index), la_zero);
            FT_LA_ADDI_D_EMIT(&out, la_a7, la_zero, 94);
            FT_LA_SYSCALL_EMIT(&out, 0);
            FT_LA_BREAK_EMIT(&out, 0);
        }
#endif

        ft_emit_raise_syscall(&out, tb, pc, fields->size);
        break;
    }
    case FT_HELPER_SYSENTER:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (!tb) {
            return 0;
        }
        if (!(tb->flags & HF_PE_MASK)) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }
        ft_emit_helper_prologue(&out);
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)helper_sysenter, 1u << 0);
        ft_emit_helper_epilogue(&out);
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                         FT_LA_OPCODE_LD_D);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
#else
        return 0;
#endif
    case FT_HELPER_SYSEXIT:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (!tb) {
            return 0;
        }
        if (!(tb->flags & HF_PE_MASK)) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }
        ft_emit_helper_prologue(&out);
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero,
                          fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 0 : 1);
        ft_emit_host_call(&out, (void *)helper_sysexit, 1u << 0);
        ft_emit_helper_epilogue(&out);
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                         FT_LA_OPCODE_LD_D);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
#else
        return 0;
#endif
    case FT_HELPER_SYSRET:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (!tb) {
            return 0;
        }
        if (!(tb->flags & HF_PE_MASK)) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }
        ft_emit_helper_prologue(&out);
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero,
                          (fields->rex_bits & 8) ? 2 :
                          (fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 0 : 1));
        ft_emit_host_call(&out, (void *)helper_sysret, 1u << 0);
        ft_emit_helper_epilogue(&out);
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                         FT_LA_OPCODE_LD_D);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
#else
        return 0;
#endif
    case FT_HELPER_GPF:
        ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
        break;
    case FT_HELPER_INT:
        ft_emit_interrupt_helper(&out, pc, fields->imm, fields->size);
        break;
    case FT_HELPER_INT3:
        ft_emit_interrupt_helper(&out, pc, EXCP03_INT3, fields->size);
        break;
    case FT_HELPER_IRET:
    case FT_HELPER_IRETD:
    {
        int shift = fields->kind == FT_HELPER_IRET ? 0 :
                    1;

        ft_emit_helper_prologue(&out);
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, shift);
        ft_emit_li64(&out, la_a2, pc + fields->size);
        ft_emit_host_call(&out, (void *)helper_iret_protected, 1u << 0);
        ft_emit_helper_epilogue(&out);
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                         FT_LA_OPCODE_LD_D);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
    }
    case FT_HELPER_IRETQ:
#ifdef CONFIG_SOFTMMU
        ft_emit_helper_prologue(&out);
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, 2);
        ft_emit_li64(&out, la_a2, pc + fields->size);
        ft_emit_host_call(&out, (void *)helper_iret_protected, 1u << 0);
        ft_emit_helper_epilogue(&out);
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                         FT_LA_OPCODE_LD_D);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
#else
        FT_LA_LD_D_EMIT(&out, la_t4, ft_gpr(rsp_index), 0);
        FT_LA_OR_EMIT(&out, la_r21, la_t4, la_zero);
        FT_LA_LD_HU_EMIT(&out, la_t2, ft_gpr(rsp_index), 8);
#ifdef QUICKTRANS_LATU
        ft_emit_latu_store_seg(&out, R_CS);
#else
        ft_emit_store_env(&out, la_t2,
                          offsetof(CPUX86State, segs[cs_index].selector),
                          FT_LA_OPCODE_ST_W);
#endif
        FT_LA_LD_D_EMIT(&out, la_t0, ft_gpr(rsp_index), 16);
        if (!ft_emit_apply_popfq(&out, tb)) {
            return 0;
        }
        FT_LA_LD_HU_EMIT(&out, la_t2, ft_gpr(rsp_index), 32);
#ifdef QUICKTRANS_LATU
        ft_emit_latu_store_seg(&out, R_SS);
#else
        ft_emit_store_env(&out, la_t2,
                          offsetof(CPUX86State, segs[ss_index].selector),
                          FT_LA_OPCODE_ST_W);
#endif
        FT_LA_LD_D_EMIT(&out, la_t3, ft_gpr(rsp_index), 24);
        FT_LA_OR_EMIT(&out, ft_gpr(rsp_index), la_t3, la_zero);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_r21, false);
#endif
    case FT_HELPER_LCALL:
    {
#ifdef CONFIG_SOFTMMU
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_li32(&out, la_a1, fields->imm & 0xffff);
        ft_emit_li64(&out, la_a2, fields->imm64);
        FT_LA_ADDI_D_EMIT(&out, la_a3, la_zero,
                          fields->alu_width == 32 ? 1 : 0);
        ft_emit_li64(&out, la_a4, pc + fields->size);
        /* la_t0 aliases the fifth ABI argument in LATS system mode. */
        ft_emit_host_call_via(&out, (void *)helper_lcall_protected,
                              1u << 0, la_t4);
        ft_emit_helper_epilogue(&out);
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                         FT_LA_OPCODE_LD_D);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
#else
        return 0;
#endif
    }
    case FT_HELPER_LJMP:
    {
        if (fields->modrm < 0) {
#ifdef CONFIG_SOFTMMU
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_li32(&out, la_a1, fields->imm & 0xffff);
            ft_emit_li64(&out, la_a2, fields->imm64);
            ft_emit_li64(&out, la_a3, pc + fields->size);
            ft_emit_host_call(&out, (void *)helper_ljmp_protected, 1u << 0);
            ft_emit_helper_epilogue(&out);
            ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                             FT_LA_OPCODE_LD_D);
            return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
#else
            return 0;
#endif
        }
        int addr;
        int offset;

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (fields->alu_width == 16 || fields->alu_width == 32) {
            int bytes = fields->alu_width / 8;
            bool static_context;

            if (!tb || !(tb->flags & HF_PE_MASK) || (tb->flags & HF_VM_MASK) ||
                !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            offset = ft_mem_access_offset(fields, addr);
            if (!ft_fits_simm12(offset)) {
                return 0;
            }
            /* Read the guest pointer before switching to the helper ASID. */
            FT_LA_ADDI_D_EMIT(&out, la_a4, addr, offset);
            if (bytes == 2) {
                FT_LA_LD_HU_EMIT(&out, la_a2, la_a4, 0);
            } else {
                FT_LA_LD_WU_EMIT(&out, la_a2, la_a4, 0);
            }
            FT_LA_LD_HU_EMIT(&out, la_a3, la_a4, bytes);
            FT_LA_BSTRINS_D_EMIT(&out, la_a2, la_a3, 47, 32);
            ft_emit_store_env(&out, la_a2, offsetof(CPUX86State, tmparea[0]),
                              FT_LA_OPCODE_ST_D);
            static_context = ft_emit_default_helper_prologue(&out, false);
            ft_emit_load_env(&out, la_a2, offsetof(CPUX86State, tmparea[0]),
                             FT_LA_OPCODE_LD_D);
            FT_LA_SRLI_D_EMIT(&out, la_a1, la_a2, 32);
            FT_LA_BSTRPICK_D_EMIT(&out, la_a2, la_a2, 31, 0);
            ft_emit_li64(&out, la_a3, pc + fields->size);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_default_helper_call(&out, (void *)helper_ljmp_protected,
                                        1u << 0, static_context);
            ft_emit_default_helper_epilogue(&out, static_context, false);
            /* A far jump can change CS and the target's decode mode. */
            ft_emit_load_env(&out, la_a4, lsenv_offset_of_eip(lsenv),
                             FT_LA_OPCODE_LD_D);
            ft_emit_tu_indirect_dispatch_exit(tb, &out, la_a4, la_a5);
            return out - code;
        }
#endif
#ifndef QUICKTRANS_LATU
        if (fields->alu_width != 64) {
            return 0;
        }
#endif
#ifdef CONFIG_SOFTMMU
        ft_emit_helper_prologue(&out);
#endif
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        offset = ft_mem_access_offset(fields, addr);
#ifdef CONFIG_SOFTMMU
        FT_LA_LD_D_EMIT(&out, la_a2, addr, offset);
        FT_LA_LD_HU_EMIT(&out, la_a1, addr, offset + 8);
        ft_emit_li64(&out, la_a3, pc + fields->size);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)helper_ljmp_protected, 1u << 0);
        ft_emit_helper_epilogue(&out);
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                         FT_LA_OPCODE_LD_D);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
#else
#ifdef QUICKTRANS_LATU
        int bytes = fields->alu_width / 8;
        /* Keep the address out of selector/scratch registers and make the
         * complete far pointer fit the byte-load immediate range. */
        if (!ft_fits_simm12(offset)) {
            return 0;
        }
        FT_LA_ADDI_D_EMIT(&out, la_t4, addr, offset);
        addr = la_t4;
        offset = 0;
        if ((bytes != 2 && bytes != 4 && bytes != 8) ||
            !ft_emit_load_addr_bytes(&out, addr, offset, la_r21, bytes) ||
            !ft_emit_load_addr_bytes(&out, addr, offset + bytes, la_t2, 2)) {
            return 0;
        }
        ft_emit_latu_store_seg(&out, R_CS);
#else
        FT_LA_LD_D_EMIT(&out, la_t4, addr, offset);
        FT_LA_OR_EMIT(&out, la_r21, la_t4, la_zero);
        FT_LA_LD_HU_EMIT(&out, la_t2, addr, offset + 8);
        ft_emit_store_env(&out, la_t2,
                          offsetof(CPUX86State, segs[cs_index].selector),
                          FT_LA_OPCODE_ST_W);
#endif
        return ft_emit_helper_indirect_exit(&out, tb, code, la_r21, false);
#endif
    }
    case FT_HELPER_RETFQ:
#ifdef CONFIG_SOFTMMU
        ft_emit_helper_prologue(&out);
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero,
                          fields->alu_width == 16 ? 0 :
                          fields->alu_width == 32 ? 1 : 2);
        ft_emit_li32(&out, la_a2, fields->imm & 0xffff);
        ft_emit_host_call(&out, (void *)helper_lret_protected, 1u << 0);
        ft_emit_helper_epilogue(&out);
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                         FT_LA_OPCODE_LD_D);
        return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
#else
        {
#ifdef QUICKTRANS_LATU
        int slot = fields->alu_width / 8;
        if (slot != 2 && slot != 4 && slot != 8) {
            return 0;
        }
        if (slot == 2) {
            FT_LA_LD_HU_EMIT(&out, la_t4, ft_gpr(rsp_index), 0);
        } else if (slot == 4) {
            FT_LA_LD_WU_EMIT(&out, la_t4, ft_gpr(rsp_index), 0);
        } else {
            FT_LA_LD_D_EMIT(&out, la_t4, ft_gpr(rsp_index), 0);
        }
#else
        int slot = 8;
        FT_LA_LD_D_EMIT(&out, la_t4, ft_gpr(rsp_index), 0);
#endif
        FT_LA_OR_EMIT(&out, la_r21, la_t4, la_zero);
        FT_LA_LD_HU_EMIT(&out, la_t2, ft_gpr(rsp_index), slot);
#ifdef QUICKTRANS_LATU
        ft_emit_latu_store_seg(&out, R_CS);
#else
        ft_emit_store_env(&out, la_t2,
                          offsetof(CPUX86State, segs[cs_index].selector),
                          FT_LA_OPCODE_ST_W);
#endif
#ifdef QUICKTRANS_LATU
        if (!ft_fits_simm12(2 * slot + fields->imm)) {
            if (!ft_emit_li32(&out, la_t2, 2 * slot + fields->imm)) {
                return 0;
            }
            FT_LA_ADD_D_EMIT(&out, ft_gpr(rsp_index),
                            ft_gpr(rsp_index), la_t2);
        } else
#endif
        {
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index),
                              2 * slot + fields->imm);
        }
        return ft_emit_helper_indirect_exit(&out, tb, code, la_r21, false);
        }
#endif
    case FT_HELPER_UD0:
    case FT_HELPER_UD1:
    case FT_HELPER_UD2:
        ft_emit_raise_illop(&out, pc);
        break;
    case FT_XGETBV:
    {
        bool static_context = ft_emit_default_helper_prologue(&out, false);

        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_BSTRPICK_D_EMIT(&out, la_a1, ft_gpr(rcx_index), 31, 0);
        ft_emit_default_helper_call(&out, (void *)helper_xgetbv, 1u << 0,
                                    static_context);
        ft_emit_default_helper_epilogue(&out, static_context, false);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), la_a0, 31, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rdx_index), la_a0, 63, 32);
        break;
    }
    case FT_XSETBV:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    {
        bool static_context;

        if (!tb) {
            return 0;
        }
        if (!(((CPUX86State *)lsenv->cpu_state)->features[FEAT_1_ECX] &
              CPUID_EXT_XSAVE)) {
            ft_emit_raise_illop(&out, pc);
            break;
        }
        if (tb->flags & HF_CPL_MASK) {
            ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
            break;
        }

        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        static_context = ft_emit_default_helper_prologue(&out, false);
        FT_LA_BSTRPICK_D_EMIT(&out, la_a1, ft_gpr(rcx_index), 31, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, la_a2, ft_gpr(rdx_index), 31, 0);
        FT_LA_SLLI_D_EMIT(&out, la_a2, la_a2, 32);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(rax_index), 31, 0);
        FT_LA_OR_EMIT(&out, la_a2, la_a2, la_t0);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_default_helper_call(&out, (void *)helper_xsetbv,
                                    1u << 0, static_context);
        ft_emit_default_helper_epilogue(&out, static_context, false);
        ft_emit_li64(&out, la_t0, pc + fields->size);
        ft_emit_tu_indirect_dispatch_exit(tb, &out, la_t0, la_t1);
        return out - code;
    }
#else
        return 0;
#endif
    default:
        return 0;
    }

    return (out - code);
}

static void ft_emit_save_fprs_to_env(uint32_t **out)
{
#ifdef QUICKTRANS_LATU
    /* Mode 1 still has host MMX aliases: legacy TB exits save them to env. */
    if (option_soft_fpu == 2) {
#else
    if (option_soft_fpu) {
#endif
        return;
    }

    if (!option_soft_fpu) {
        FT_LA_X86MFTOP_EMIT(out, la_t0);
        ft_emit_store_env(out, la_t0, lsenv_offset_of_top(lsenv),
                          FT_LA_OPCODE_ST_W);
        FT_LA_X86CLRTM_EMIT(out);
    }
    for (int i = 0; i < 8; i++) {
        ft_emit_store_env(out, ft_mmx(i), lsenv_offset_of_mmx(lsenv, i),
                          FT_LA_OPCODE_FST_D);
    }
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_X87_SIGNAL_ABI)
    if (!option_soft_fpu) {
        FT_LA_ORI_EMIT(out, la_t0, la_zero, 1);
        ft_emit_store_env(out, la_t0,
                          offsetof(CPUX86State, qt_hard_signal_protocol_enabled),
                          FT_LA_OPCODE_ST_B);
        ft_emit_load_env(out, la_t0, offsetof(CPUX86State, mode_fpu),
                         FT_LA_OPCODE_LD_BU);
        FT_LA_XORI_EMIT(out, la_t0, la_t0, 1);
        FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 1);
        ft_emit_store_env(out, la_t0,
                          offsetof(CPUX86State, qt_x87_env_format),
                          FT_LA_OPCODE_ST_B);
    }
#endif
}

static void ft_emit_load_fprs_from_env(uint32_t **out)
{
#ifdef QUICKTRANS_LATU
    if (option_soft_fpu != 2) {
#else
    if (!option_soft_fpu) {
#endif
        for (int i = 0; i < 8; i++) {
            ft_emit_load_env(out, ft_mmx(i), lsenv_offset_of_mmx(lsenv, i),
                             FT_LA_OPCODE_FLD_D);
        }
        if (!option_soft_fpu) {
            ft_emit_x87_top_load(out);
        }
    }
}

static void ft_emit_enter_mmx(uint32_t **out)
{
#if defined(CONFIG_LATX_OPT_NOFP) && !defined(QUICKTRANS_LATU)
    FastBranchLabel ready = { 0 };
    FastBranchFixup ready_fixup;
    int nofp;

    if (!option_soft_fpu) {
        return;
    }

    ft_emit_store_env(out, la_zero, lsenv_offset_of_top(lsenv),
                      FT_LA_OPCODE_ST_W);
    ft_emit_store_env(out, la_zero, lsenv_offset_of_tag_word(lsenv),
                      FT_LA_OPCODE_ST_D);

    nofp = ft_scratch_avoid3(-1, -1, -1);
    ft_emit_load_env(out, nofp, lsenv_offset_of_nofp(lsenv),
                     FT_LA_OPCODE_LD_W);
    ft_emit_branch_placeholder(out, &ready_fixup, FT_BRANCH_BNE, nofp,
                               la_zero, &ready);

    ft_emit_cpu_env_ptr(out, nofp);
    ft_emit_store_env(out, nofp, lsenv_offset_of_nofp(lsenv),
                      FT_LA_OPCODE_ST_W);
    for (int i = 0; i < 8; i++) {
        ft_emit_load_env(out, ft_mmx(i), lsenv_offset_of_mmx(lsenv, i),
                         FT_LA_OPCODE_FLD_D);
    }

    ft_bind_branch_label(&ready, *out);
    ft_resolve_branch_fixup(&ready_fixup);
#else
    ft_emit_store_env(out, la_zero, ft_lsenv_offset_of_mode_fpu(lsenv),
                      FT_LA_OPCODE_ST_D);
#endif
}

static void ft_emit_leave_mmx(uint32_t **out)
{
#if defined(CONFIG_LATX_OPT_NOFP) && !defined(QUICKTRANS_LATU)
    FastBranchLabel ready = { 0 };
    FastBranchFixup ready_fixup;
    int nofp = ft_scratch_avoid3(-1, -1, -1);

    ft_emit_load_env(out, nofp, lsenv_offset_of_nofp(lsenv),
                     FT_LA_OPCODE_LD_W);
    ft_emit_branch_placeholder(out, &ready_fixup, FT_BRANCH_BEQ, nofp,
                               la_zero, &ready);
    for (int i = 0; i < 8; i++) {
        ft_emit_store_env(out, ft_mmx(i), lsenv_offset_of_mmx(lsenv, i),
                          FT_LA_OPCODE_FST_D);
    }
    ft_emit_store_env(out, la_zero, lsenv_offset_of_nofp(lsenv),
                      FT_LA_OPCODE_ST_W);

    ft_bind_branch_label(&ready, *out);
    ft_resolve_branch_fixup(&ready_fixup);
#else
    int mode = ft_scratch_avoid3(-1, -1, -1);

    FT_LA_ORI_EMIT(out, mode, la_zero, 1);
    ft_emit_store_env(out, mode, ft_lsenv_offset_of_mode_fpu(lsenv),
                      FT_LA_OPCODE_ST_D);
#endif
}

static void ft_emit_store_xmm_env(uint32_t **out, int xmm)
{
    int offset = lsenv_offset_of_xmm(lsenv, xmm);
    int env_reg = ft_scratch_avoid3(-1, -1, -1);
    int offset_reg = ft_scratch_avoid3(env_reg, -1, -1);

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    env_reg = la_s8;
#else
    ft_emit_cpu_env_ptr(out, env_reg);
#endif
    if (ft_offset_fits_imm12(offset)) {
        FT_LA_VST_EMIT(out, ft_xmm(xmm), env_reg, offset);
        return;
    }
    ft_emit_li64(out, offset_reg, (uint64_t)(int64_t)offset);
    FT_LA_ADD_D_EMIT(out, offset_reg, env_reg, offset_reg);
    FT_LA_VST_EMIT(out, ft_xmm(xmm), offset_reg, 0);
}

static void ft_emit_load_xmm_env(uint32_t **out, int xmm)
{
    int offset = lsenv_offset_of_xmm(lsenv, xmm);
    int env_reg = ft_scratch_avoid3(-1, -1, -1);
    int offset_reg = ft_scratch_avoid3(env_reg, -1, -1);

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    env_reg = la_s8;
#else
    ft_emit_cpu_env_ptr(out, env_reg);
#endif
    if (ft_offset_fits_imm12(offset)) {
        FT_LA_VLD_EMIT(out, ft_xmm(xmm), env_reg, offset);
        return;
    }
    ft_emit_li64(out, offset_reg, (uint64_t)(int64_t)offset);
    FT_LA_ADD_D_EMIT(out, offset_reg, env_reg, offset_reg);
    FT_LA_VLD_EMIT(out, ft_xmm(xmm), offset_reg, 0);
}

/* Consecutive env slots share one address when their offsets exceed imm12.
 * Keep every vector access and its order; only address construction is shared.
 * Use the same scratch as the single-slot fallback, preserving helper results.
 */
static void ft_emit_xmms_env(uint32_t **out, bool restore)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    int base_offset = 0;
    int base_reg = la_s8;
    int scratch = ft_scratch_avoid3(ft_scratch_avoid3(-1, -1, -1), -1, -1);

    for (int i = 0; i < XMM_NUM; i++) {
        int offset = lsenv_offset_of_xmm(lsenv, i);
        if (!ft_offset_fits_imm12(offset - base_offset)) {
            ft_emit_li64(out, scratch, (uint64_t)(int64_t)offset);
            FT_LA_ADD_D_EMIT(out, scratch, la_s8, scratch);
            base_reg = scratch;
            base_offset = offset;
        }
        if (restore) {
            FT_LA_VLD_EMIT(out, ft_xmm(i), base_reg, offset - base_offset);
        } else {
            FT_LA_VST_EMIT(out, ft_xmm(i), base_reg, offset - base_offset);
        }
    }
#else
    for (int i = 0; i < XMM_NUM; i++) {
        if (restore) {
            ft_emit_load_xmm_env(out, i);
        } else {
            ft_emit_store_xmm_env(out, i);
        }
    }
#endif
}

static void ft_emit_save_xmms_to_env(uint32_t **out)
{
    ft_emit_xmms_env(out, false);
}

static void ft_emit_load_xmms_from_env(uint32_t **out)
{
    ft_emit_xmms_env(out, true);
}

static void ft_emit_helper_prologue(uint32_t **out)
{
    ft_emit_save_gprs_to_env(out);
    ft_emit_save_fprs_to_env(out);
    ft_emit_save_xmms_to_env(out);
    ft_emit_save_condition_flags(out);
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_X87_SIGNAL_ABI)
    if (!option_soft_fpu) {
        /* Save FCSR after physical-slot save has cleared TOP mode. */
        FT_LA_MOVFCSR2GR_EMIT(out, la_t0, 0);
        ft_emit_store_env(out, la_t0, lsenv_offset_of_fcsr(lsenv),
                          FT_LA_OPCODE_ST_W);
        FT_LA_ORI_EMIT(out, la_t0, la_zero, 1);
        ft_emit_store_env(out, la_t0, offsetof(CPUX86State, qt_helper_env_saved),
                          FT_LA_OPCODE_ST_B);
    }
#endif
}

static void ft_emit_helper_epilogue_gprs(uint32_t **out, int first_gpr)
{
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_X87_SIGNAL_ABI)
    if (!option_soft_fpu) {
        ft_emit_store_env(out, la_zero,
                          offsetof(CPUX86State, qt_helper_env_saved),
                          FT_LA_OPCODE_ST_B);
    }
#endif
    ft_emit_restore_condition_flags(out);
    ft_emit_load_xmms_from_env(out);
    ft_emit_load_fprs_from_env(out);
    for (int i = first_gpr; i < GPR_NUM; i++) {
        ft_emit_load_env(out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i),
                         FT_LA_OPCODE_LD_D);
    }
}

static void ft_emit_helper_epilogue(uint32_t **out)
{
    ft_emit_helper_epilogue_gprs(out, 0);
}

/* CPUID changes only its four architectural result registers. Keep every
 * pre-call env snapshot, and retain the other ABI-preserved GPR mappings. */
static void ft_emit_cpuid_helper_epilogue(uint32_t **out)
{
    int first_gpr = 0;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    while (first_gpr < 8 && ft_gpr(first_gpr) == la_s0 + first_gpr) {
        ++first_gpr;
    }
#endif
    ft_emit_helper_epilogue_gprs(out, first_gpr);
    for (int i = 0; i < first_gpr; ++i) {
        if (i == rax_index || i == rbx_index ||
            i == rcx_index || i == rdx_index) {
            ft_emit_load_env(out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i),
                             FT_LA_OPCODE_LD_D);
        }
    }
}

/* x87 helpers do not change guest GPRs. Keep the pre-call fault snapshot,
 * but retain ABI-preserved mappings on a normal mode-2 LATU return. */
static void ft_emit_x87_helper_epilogue(uint32_t **out)
{
    int first_gpr = 0;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (option_soft_fpu == 2) {
        while (first_gpr < 8 && ft_gpr(first_gpr) == la_s0 + first_gpr) {
            ++first_gpr;
        }
    }
#endif
    ft_emit_helper_epilogue_gprs(out, first_gpr);
}

#ifndef QUICKTRANS_LATU
static bool ft_emit_nofp_helper_prologue(uint32_t **out)
{
    if (ft_emit_lats_static_helper_context(out, true, true)) {
        return true;
    }

    ft_emit_save_gprs_to_env(out);
    ft_emit_save_xmms_to_env(out);
    ft_emit_save_condition_flags(out);
    return false;
}

static void ft_emit_nofp_helper_epilogue(uint32_t **out,
                                         bool static_context)
{
    if (static_context) {
        ft_emit_lats_static_helper_context(out, false, true);
        return;
    }

    ft_emit_restore_condition_flags(out);
    ft_emit_load_xmms_from_env(out);
    for (int i = 0; i < GPR_NUM; i++) {
        ft_emit_load_env(out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i),
                         FT_LA_OPCODE_LD_D);
    }
}
#endif

static void ft_emit_lats_helper_mmx_save(uint32_t **out,
                                          bool static_context)
{
#if defined(CONFIG_LATX_OPT_NOFP) && !defined(QUICKTRANS_LATU)
    FastBranchLabel done = { 0 };
    FastBranchFixup done_fixup;
    int mmx_active = ft_gpr(rax_index);

    ft_emit_load_env(out, mmx_active, lsenv_offset_of_nofp(lsenv),
                     FT_LA_OPCODE_LD_W);
    ft_emit_branch_placeholder(out, &done_fixup, FT_BRANCH_BEQ,
                               mmx_active, la_zero, &done);
    if (!static_context) {
        ft_emit_host_stack_begin(out);
    }
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -64);
    for (int i = 0; i < 8; i++) {
        FT_LA_FST_D_EMIT(out, ft_mmx(i), la_sp, i * 8);
    }
    if (!static_context) {
        ft_emit_host_stack_end(out);
    }
    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&done_fixup);
#else
    (void)out;
    (void)static_context;
#endif
}

static void ft_emit_lats_helper_mmx_restore(uint32_t **out,
                                             bool static_context)
{
#if defined(CONFIG_LATX_OPT_NOFP) && !defined(QUICKTRANS_LATU)
    FastBranchLabel done = { 0 };
    FastBranchFixup done_fixup;
    int mmx_active = ft_gpr(rax_index);

    ft_emit_branch_placeholder(out, &done_fixup, FT_BRANCH_BEQ,
                               mmx_active, la_zero, &done);
    if (!static_context) {
        ft_emit_host_stack_begin(out);
    }
    for (int i = 0; i < 8; i++) {
        FT_LA_FLD_D_EMIT(out, ft_mmx(i), la_sp, i * 8);
    }
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 64);
    if (!static_context) {
        ft_emit_host_stack_end(out);
    }
    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&done_fixup);
#else
    (void)out;
    (void)static_context;
#endif
}

static bool ft_emit_default_helper_prologue(uint32_t **out,
                                            bool helper_uses_fprs)
{
#ifndef QUICKTRANS_LATU
    if (ft_emit_lats_static_helper_context(out, true, false)) {
        if (helper_uses_fprs) {
            ft_emit_lats_helper_mmx_save(out, true);
        }
        return true;
    }
#else
    (void)helper_uses_fprs;
#endif
    ft_emit_helper_prologue(out);
#if defined(CONFIG_LATX_OPT_NOFP) && !defined(QUICKTRANS_LATU)
    if (helper_uses_fprs && option_soft_fpu == 2) {
        ft_emit_lats_helper_mmx_save(out, false);
    }
#endif
    return false;
}

static void ft_emit_default_helper_call_via(uint32_t **out, void *func,
                                            unsigned pointer_args,
                                            int target_reg,
                                            bool static_context)
{
#ifndef QUICKTRANS_LATU
    if (static_context) {
        ft_emit_host_call_in_host_as_via(out, func, pointer_args, target_reg);
        return;
    }
#else
    (void)static_context;
#endif
    ft_emit_host_call_via(out, func, pointer_args, target_reg);
}

static void ft_emit_default_helper_call(uint32_t **out, void *func,
                                       unsigned pointer_args,
                                       bool static_context)
{
    ft_emit_default_helper_call_via(out, func, pointer_args, la_t0,
                                    static_context);
}

static void ft_emit_default_helper_epilogue(uint32_t **out,
                                            bool static_context,
                                            bool helper_uses_fprs)
{
#ifndef QUICKTRANS_LATU
    if (static_context) {
        if (helper_uses_fprs) {
            ft_emit_lats_helper_mmx_restore(out, true);
        }
        ft_emit_lats_static_helper_context(out, false, false);
        return;
    }
#else
    (void)static_context;
    (void)helper_uses_fprs;
#endif
#if defined(CONFIG_LATX_OPT_NOFP) && !defined(QUICKTRANS_LATU)
    if (helper_uses_fprs && option_soft_fpu == 2) {
        ft_emit_lats_helper_mmx_restore(out, false);
    }
#endif
    ft_emit_helper_epilogue(out);
}

/* AES/SHA helpers only update the destination vector.  Guest GPRs in
 * ABI-preserved host registers need no normal-return reload.  Keep the
 * complete pre-call snapshot for faults and all vector/FPR/flags handling. */
static void ft_emit_crypto_helper_epilogue(uint32_t **out, bool static_context)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    int first_gpr = 0;

    (void)static_context;
    while (first_gpr < 8 && ft_gpr(first_gpr) == la_s0 + first_gpr) {
        ++first_gpr;
    }
    ft_emit_helper_epilogue_gprs(out, first_gpr);
#else
    ft_emit_default_helper_epilogue(out, static_context, true);
#endif
}

static void ft_emit_xmm_env_addr(uint32_t **out, int dst, int xmm)
{
    int offset = lsenv_offset_of_xmm(lsenv, xmm);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (ft_offset_fits_imm12(offset)) {
        FT_LA_ADDI_D_EMIT(out, dst, la_s8, offset);
    } else {
        ft_emit_li64(out, dst, (uint64_t)(int64_t)offset);
        FT_LA_ADD_D_EMIT(out, dst, la_s8, dst);
    }
#else
#ifdef CONFIG_SOFTMMU
    /*
     * System-mode helper arguments occupy a0-a4.  Keep their already-built
     * addresses intact while preparing the remaining arguments.
     */
    int env_reg = la_a5;
#else
    int env_reg = ft_scratch_avoid3(dst, -1, -1);
#endif

    ft_emit_cpu_env_ptr(out, env_reg);
    ft_emit_li64(out, dst, (uint64_t)(int64_t)offset);
    FT_LA_ADD_D_EMIT(out, dst, env_reg, dst);
#endif
}

static int ft_emit_call_xmm_helper3(uint32_t **out, void *func,
                                    int dst_xmm, int src1_xmm, int src2_xmm)
{
    uint32_t *start = *out;
    bool static_context = ft_emit_default_helper_prologue(out, true);

    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_xmm_env_addr(out, la_a1, dst_xmm);
    ft_emit_xmm_env_addr(out, la_a2, src1_xmm);
    ft_emit_xmm_env_addr(out, la_a3, src2_xmm);
    ft_emit_default_helper_call(out, func, 0xf, static_context);
    ft_emit_crypto_helper_epilogue(out, static_context);
    return *out - start;
}

static int ft_emit_call_sha_reg_helper(uint32_t **out, void *func,
                                       int dst_xmm, int src_xmm,
                                       bool sha256rnds2)
{
    uint32_t *start = *out;
    unsigned pointer_args;
    bool static_context = ft_emit_default_helper_prologue(out, true);

    pointer_args = ft_emit_host_sha_reg_args(out, dst_xmm, src_xmm,
                                             sha256rnds2);
    ft_emit_default_helper_call_via(out, func, pointer_args,
                                    sha256rnds2 ? la_t4 : la_t0,
                                    static_context);
    ft_emit_crypto_helper_epilogue(out, static_context);
    return *out - start;
}

static int ft_emit_call_xmm_helper_imm(uint32_t **out, void *func,
                                       int dst_xmm, int src_xmm, int imm)
{
    uint32_t *start = *out;
    bool static_context = ft_emit_default_helper_prologue(out, true);

    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_xmm_env_addr(out, la_a1, dst_xmm);
    ft_emit_xmm_env_addr(out, la_a2, src_xmm);
    ft_emit_li64(out, la_a3, (uint64_t)(uint32_t)imm);
    ft_emit_default_helper_call(out, func, 0x7, static_context);
    ft_emit_crypto_helper_epilogue(out, static_context);
    return *out - start;
}

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
static int ft_emit_latu_pcmp_helper(uint32_t **out,
                                    const FastTemplateFields *fields,
                                    target_ulong pc, void *func,
                                    bool explicit_length, bool index_result)
{
    uint32_t *start = *out;
    int dst = ft_modrm_reg_index(fields);
    int src = ft_modrm_rm_index(fields);
    bool memory = fields->modrm_mod != 3;
    uint32_t ctrl = (uint32_t)fields->imm;
    int first_gpr = 0;

    if (dst >= XMM_NUM || fields->imm < 0 || fields->imm > 0xff ||
        (!memory && src >= XMM_NUM)) {
        return 0;
    }
    if (memory) {
        int addr;
        if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
            return 0;
        }
        /* Complete the guest read before changing the host stack. */
        FT_LA_VLD_EMIT(out, ft_vscratch, addr,
                       ft_mem_access_offset(fields, addr));
        FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -16);
        FT_LA_VST_EMIT(out, ft_vscratch, la_sp, 0);
    }
    if (explicit_length && fields->rex >= 0 && (fields->rex & 8)) {
        ctrl |= 1u << 8;
    }
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_xmm_env_addr(out, la_a1, dst);
    if (memory) {
        FT_LA_OR_EMIT(out, la_a2, la_sp, la_zero);
    } else {
        ft_emit_xmm_env_addr(out, la_a2, src);
    }
    ft_emit_li64(out, la_a3, ctrl);
    ft_emit_host_call(out, func, 0x7);

    /* Only the index variants write a GPR (ECX).  All other preserved
     * mappings retain their input values across the C helper call. */
    while (first_gpr < 8 && ft_gpr(first_gpr) == la_s0 + first_gpr) {
        ++first_gpr;
    }
    ft_emit_helper_epilogue_gprs(out, first_gpr);
    if (index_result && rcx_index < first_gpr) {
        ft_emit_load_env(out, ft_gpr(rcx_index),
                         lsenv_offset_of_gpr(lsenv, rcx_index),
                         FT_LA_OPCODE_LD_D);
    }
    if (memory) {
        FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    }
    return *out - start;
}
#endif

static int ft_emit_call_pcmpistri_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    return ft_emit_latu_pcmp_helper(out, fields, pc,
                                    (void *)helper_pcmpistri_xmm,
                                    false, true);
#else
    uint32_t *start = *out;
    bool static_context;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int temp_xmm;

    if (dst >= XMM_NUM || fields->imm < 0 || fields->imm > 0xff) {
        return 0;
    }

    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= XMM_NUM) {
            return 0;
        }
        temp_xmm = -1;
    } else {
        int addr;

        temp_xmm = (dst + 1) & 7;
        if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_VOR_V_EMIT(out, ft_vscratch, ft_xmm(temp_xmm),
                         ft_xmm(temp_xmm));
        FT_LA_VLD_EMIT(out, ft_xmm(temp_xmm), addr,
                       ft_mem_access_offset(fields, addr));
        src = temp_xmm;
    }

    static_context = ft_emit_default_helper_prologue(out, true);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_xmm_env_addr(out, la_a1, dst);
    ft_emit_xmm_env_addr(out, la_a2, src);
    ft_emit_li64(out, la_a3, (uint64_t)(uint32_t)fields->imm);
    ft_emit_default_helper_call(out, (void *)helper_pcmpistri_xmm, 0x7,
                                static_context);
    ft_emit_default_helper_epilogue(out, static_context, true);

    if (temp_xmm >= 0) {
        FT_LA_VOR_V_EMIT(out, ft_xmm(temp_xmm), ft_vscratch, ft_vscratch);
    }
    return *out - start;
#endif
}

static int ft_emit_call_pcmpistrm_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    return ft_emit_latu_pcmp_helper(out, fields, pc,
                                    (void *)helper_pcmpistrm_xmm,
                                    false, false);
#else
    uint32_t *start = *out;
    bool static_context;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int temp_xmm;

    if (dst >= XMM_NUM || fields->imm < 0 || fields->imm > 0xff) {
        return 0;
    }

    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= XMM_NUM) {
            return 0;
        }
        temp_xmm = -1;
    } else {
        int addr;

        temp_xmm = (dst + 1) & 7;
        if (temp_xmm == 0) {
            temp_xmm = 1;
        }
        if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_VOR_V_EMIT(out, ft_vscratch, ft_xmm(temp_xmm),
                         ft_xmm(temp_xmm));
        FT_LA_VLD_EMIT(out, ft_xmm(temp_xmm), addr,
                       ft_mem_access_offset(fields, addr));
        src = temp_xmm;
    }

    static_context = ft_emit_default_helper_prologue(out, true);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_xmm_env_addr(out, la_a1, dst);
    ft_emit_xmm_env_addr(out, la_a2, src);
    ft_emit_li64(out, la_a3, (uint64_t)(uint32_t)fields->imm);
    ft_emit_default_helper_call(out, (void *)helper_pcmpistrm_xmm, 0x7,
                                static_context);
    ft_emit_default_helper_epilogue(out, static_context, true);

    if (temp_xmm >= 0) {
        FT_LA_VOR_V_EMIT(out, ft_xmm(temp_xmm), ft_vscratch, ft_vscratch);
    }
    return *out - start;
#endif
}

static int ft_emit_call_pcmpestrm_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    return ft_emit_latu_pcmp_helper(out, fields, pc,
                                    (void *)helper_pcmpestrm_xmm,
                                    true, false);
#else
    uint32_t *start = *out;
    bool static_context;
    uint32_t ctrl = (uint32_t)fields->imm;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int temp_xmm;

    if (dst >= XMM_NUM || fields->imm < 0 || fields->imm > 0xff) {
        return 0;
    }

    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= XMM_NUM) {
            return 0;
        }
        temp_xmm = -1;
    } else {
        int addr;

        temp_xmm = (dst + 1) & 7;
        if (temp_xmm == 0) {
            temp_xmm = 1;
        }
        if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_VOR_V_EMIT(out, ft_vscratch, ft_xmm(temp_xmm),
                         ft_xmm(temp_xmm));
        FT_LA_VLD_EMIT(out, ft_xmm(temp_xmm), addr,
                       ft_mem_access_offset(fields, addr));
        src = temp_xmm;
    }

    if (fields->rex >= 0 && (fields->rex & 8)) {
        ctrl |= 1u << 8;
    }
    static_context = ft_emit_default_helper_prologue(out, true);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_xmm_env_addr(out, la_a1, dst);
    ft_emit_xmm_env_addr(out, la_a2, src);
    ft_emit_li64(out, la_a3, ctrl);
    ft_emit_default_helper_call(out, (void *)helper_pcmpestrm_xmm, 0x7,
                                static_context);
    ft_emit_default_helper_epilogue(out, static_context, true);

    if (temp_xmm >= 0) {
        FT_LA_VOR_V_EMIT(out, ft_xmm(temp_xmm), ft_vscratch, ft_vscratch);
    }
    return *out - start;
#endif
}

static int ft_emit_call_pcmpestri_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    return ft_emit_latu_pcmp_helper(out, fields, pc,
                                    (void *)helper_pcmpestri_xmm,
                                    true, true);
#else
    uint32_t *start = *out;
    bool static_context;
    uint32_t ctrl = (uint32_t)fields->imm;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int temp_xmm;

    if (dst >= XMM_NUM || fields->imm < 0 || fields->imm > 0xff) {
        return 0;
    }

    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= XMM_NUM) {
            return 0;
        }
        temp_xmm = -1;
    } else {
        int addr;

        temp_xmm = (dst + 1) & 7;
        if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_VOR_V_EMIT(out, ft_vscratch, ft_xmm(temp_xmm),
                         ft_xmm(temp_xmm));
        FT_LA_VLD_EMIT(out, ft_xmm(temp_xmm), addr,
                       ft_mem_access_offset(fields, addr));
        src = temp_xmm;
    }

    if (fields->rex >= 0 && (fields->rex & 8)) {
        ctrl |= 1u << 8;
    }
    static_context = ft_emit_default_helper_prologue(out, true);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_xmm_env_addr(out, la_a1, dst);
    ft_emit_xmm_env_addr(out, la_a2, src);
    ft_emit_li64(out, la_a3, ctrl);
    ft_emit_default_helper_call(out, (void *)helper_pcmpestri_xmm, 0x7,
                                static_context);
    ft_emit_default_helper_epilogue(out, static_context, true);

    if (temp_xmm >= 0) {
        FT_LA_VOR_V_EMIT(out, ft_xmm(temp_xmm), ft_vscratch, ft_vscratch);
    }
    return *out - start;
#endif
}
