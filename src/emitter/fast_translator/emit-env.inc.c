/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* CPU env, exception, and x87 TOP emit helpers. */

static bool ft_offset_fits_imm12(int offset)
{
    return offset >= -2048 && offset <= 2047;
}

static int ft_scratch_avoid3(int avoid0, int avoid1, int avoid2)
{
#ifdef CONFIG_SOFTMMU
    /*
     * t0-t7 and s1-s8 carry guest GPRs in the system static-code ABI.
     * Environment accesses must use call-clobbered argument registers so a
     * following native-to-BT epilogue saves the original guest register set.
     */
    static const int candidates[] = { la_a0, la_a1, la_a2, la_a3 };
#else
    static const int candidates[] = { la_t4, la_t3, la_t2, la_t1, la_t0 };
#endif

    for (int i = 0; i < ARRAY_SIZE(candidates); ++i) {
        int reg = candidates[i];

        if (reg != avoid0 && reg != avoid1 && reg != avoid2) {
            return reg;
        }
    }

    return la_t0;
}

static void ft_emit_cpu_env_ptr(uint32_t **out, int dst)
{
#ifdef CONFIG_SOFTMMU
    /* System static code keeps CPUX86State in the callee-saved $s0. */
    FT_LA_OR_EMIT(out, dst, la_s0, la_zero);
#else
    /* User static code keeps the current CPUX86State in $s8. */
    FT_LA_OR_EMIT(out, dst, la_s8, la_zero);
#endif
}

/*
 * System-mode translated code runs with DMW-tagged host pointers and ASID 0xf.
 * Host C helpers instead run in the normal host address space, so make the ABI
 * transition explicit at every direct helper call.
 */
static void ft_emit_host_pointer_args(uint32_t **out, unsigned pointer_args)
{
#ifdef CONFIG_SOFTMMU
    static const int arg_regs[] = {
        la_a0, la_a1, la_a2, la_a3, la_a4, la_a5, la_a6, la_a7,
    };

    if (hamt_enabled() && hamt_mode_dmw()) {
        for (int i = 0; i < ARRAY_SIZE(arg_regs); ++i) {
            if (pointer_args & (1u << i)) {
                FT_LA_LU52I_D_EMIT(out, arg_regs[i], arg_regs[i], 0);
            }
        }
    }
#else
    (void)out;
    (void)pointer_args;
#endif
}

static void ft_emit_host_call_begin(uint32_t **out, unsigned pointer_args)
{
    ft_emit_host_pointer_args(out, pointer_args);
#ifdef CONFIG_SOFTMMU
    if (hamt_enabled() && hamt_mode_dmw() && !hamt_disable_asid()) {
        ft_emit_raw(out, 0x04000020u | (0x18u << 10));
    }
#endif
}

static void ft_emit_host_call_end(uint32_t **out)
{
#ifdef CONFIG_SOFTMMU
    if (hamt_enabled() && hamt_mode_dmw() && !hamt_disable_asid()) {
        FT_LA_ORI_EMIT(out, la_t0, la_zero, 0xf);
        ft_emit_raw(out, 0x04000020u | (0x18u << 10) | la_t0);
    }
#else
    (void)out;
#endif
}

static void ft_emit_host_stack_begin(uint32_t **out)
{
    ft_emit_host_call_begin(out, 0);
}

static void ft_emit_host_stack_end(uint32_t **out)
{
    ft_emit_host_call_end(out);
}

static void ft_emit_host_call_via(uint32_t **out, void *func,
                                  unsigned pointer_args, int target_reg)
{
    ft_emit_li64(out, target_reg, (uint64_t)(uintptr_t)func);
    ft_emit_host_call_begin(out, pointer_args);
    FT_LA_JIRL_EMIT(out, la_ra, target_reg, 0);
    ft_emit_host_call_end(out);
}

/* The caller's static prologue and epilogue already switch the ASID. */
static void ft_emit_host_call_in_host_as_via(uint32_t **out, void *func,
                                             unsigned pointer_args,
                                             int target_reg)
{
    ft_emit_li64(out, target_reg, (uint64_t)(uintptr_t)func);
    ft_emit_host_pointer_args(out, pointer_args);
    FT_LA_JIRL_EMIT(out, la_ra, target_reg, 0);
}

static void ft_emit_host_call(uint32_t **out, void *func,
                              unsigned pointer_args)
{
    ft_emit_host_call_via(out, func, pointer_args, la_t0);
}

static void ft_emit_store_env(uint32_t **out, int src, int offset,
                              uint32_t store_op);

static int ft_emit_x87_top_load(uint32_t **out)
{
    uint32_t *start = *out;
    FastBranchLabel top_match[8] = { 0 };
    FastBranchFixup top_match_fixup[8];
    int top_offset = lsenv_offset_of_top(lsenv);

    if (!ft_offset_fits_imm12(top_offset)) {
        return 0;
    }

    int env_reg = ft_scratch_avoid3(la_t0, -1, -1);

    FT_LA_X86SETTM_EMIT(out);
    ft_emit_cpu_env_ptr(out, env_reg);
    FT_LA_LD_HU_EMIT(out, la_t0, env_reg, top_offset);
    FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);

    /*
     * LBT has immediate mttop, not GPR->TOP. Match tr_load_top_from_env()
     * by trying each immediate TOP value until the loaded counter reaches 0.
     */
    for (int i = 0; i < 8; ++i) {
        FT_LA_X86MTTOP_EMIT(out, i);
        ft_emit_branch_placeholder(out, &top_match_fixup[i], FT_BRANCH_BEQ,
                                   la_t0, la_zero, &top_match[i]);
        if (i != 7) {
            FT_LA_ADDI_W_EMIT(out, la_t0, la_t0, -1);
        }
    }

    for (int i = 0; i < 8; ++i) {
        ft_bind_branch_label(&top_match[i], *out);
        ft_resolve_branch_fixup(&top_match_fixup[i]);
    }
    return *out - start;
}

static int ft_emit_x87_top_store(uint32_t **out)
{
    uint32_t *start = *out;
    int top_offset = lsenv_offset_of_top(lsenv);

    if (!ft_offset_fits_imm12(top_offset)) {
        return 0;
    }

    FT_LA_X86MFTOP_EMIT(out, la_t0);
    ft_emit_store_env(out, la_t0, top_offset, FT_LA_OPCODE_ST_W);
    return *out - start;
}

static int ft_emit_x87_top_save(uint32_t **out)
{
    uint32_t *start = *out;
    int top_offset = lsenv_offset_of_top(lsenv);

    if (!ft_offset_fits_imm12(top_offset)) {
        return 0;
    }

    if (!ft_emit_x87_top_store(out)) {
        return 0;
    }
    FT_LA_X86CLRTM_EMIT(out);
    return *out - start;
}

static void ft_emit_store_env(uint32_t **out, int src, int offset,
                              uint32_t store_op)
{
    int env_reg = ft_scratch_avoid3(src, -1, -1);
    int offset_reg = ft_scratch_avoid3(src, env_reg, -1);

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    /* The LATU ABI keeps CPUX86State in s8 throughout translated code. */
    env_reg = la_s8;
#else
    ft_emit_cpu_env_ptr(out, env_reg);
#endif
    if (ft_offset_fits_imm12(offset)) {
        ft_emit_raw(out, ft_gpr3_imm12(store_op, src, env_reg, offset));
        return;
    }

    ft_emit_li64(out, offset_reg, (uint64_t)(int64_t)offset);
    FT_LA_ADD_D_EMIT(out, offset_reg, env_reg, offset_reg);
    ft_emit_raw(out, ft_gpr3_imm12(store_op, src, offset_reg, 0));
}

static void ft_emit_load_env(uint32_t **out, int dst, int offset,
                             uint32_t load_op)
{
    int env_reg = ft_scratch_avoid3(dst, -1, -1);
    int offset_reg = ft_scratch_avoid3(dst, env_reg, -1);

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    /* The LATU ABI keeps CPUX86State in s8 throughout translated code. */
    env_reg = la_s8;
#else
    ft_emit_cpu_env_ptr(out, env_reg);
#endif
    if (ft_offset_fits_imm12(offset)) {
        ft_emit_raw(out, ft_gpr3_imm12(load_op, dst, env_reg, offset));
        return;
    }

    ft_emit_li64(out, offset_reg, (uint64_t)(int64_t)offset);
    FT_LA_ADD_D_EMIT(out, offset_reg, env_reg, offset_reg);
    ft_emit_raw(out, ft_gpr3_imm12(load_op, dst, offset_reg, 0));
}

static void ft_emit_save_gprs_to_env(uint32_t **out)
{
    for (int i = 0; i < GPR_NUM; i++) {
        ft_emit_store_env(out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i),
                          FT_LA_OPCODE_ST_D);
    }
}

static int ft_emit_raise_syscall(uint32_t **out, TranslationBlock *tb,
                                 target_ulong pc,
                                 int next_eip_addend)
{
    uint32_t *start = *out;

#ifdef CONFIG_SOFTMMU
    /*
     * Match latxs_translate_syscall(): helper_syscall mutates architectural
     * state, then execution must return through the system context switch.
     */
    ft_emit_helper_prologue(out);
    ft_emit_li64(out, la_t0, pc);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_eip(lsenv),
                      FT_LA_OPCODE_ST_D);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, next_eip_addend);
    ft_emit_host_call(out, (void *)helper_syscall, 1u << 0);
    ft_emit_helper_epilogue(out);
    ft_prepare_tu_env_dispatch_exit(tb, 0);
    ft_emit_jump_epilogue(out, ft_context_switch_ret0_target(), la_t0);
#else
    ft_emit_save_gprs_to_env(out);
#ifdef QUICKTRANS_LATU
    /* The linux-user loop restores these from env after the syscall. */
    FT_LA_MOVFCSR2GR_EMIT(out, la_t0, 0);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_fcsr(lsenv),
                      FT_LA_OPCODE_ST_W);
    ft_emit_save_fprs_to_env(out);
    ft_emit_save_xmms_to_env(out);
#endif
    ft_emit_save_condition_flags(out);

    ft_emit_li64(out, la_t0, pc);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_eip(lsenv),
                      FT_LA_OPCODE_ST_D);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, next_eip_addend);
    ft_emit_host_call(out, (void *)helper_syscall, 1u << 0);
    FT_LA_BREAK_EMIT(out, 0);
#endif
    return *out - start;
}

static void ft_emit_save_fprs_for_exception(uint32_t **out)
{
#if defined(CONFIG_LATX_OPT_NOFP) && !defined(QUICKTRANS_LATU)
    FastBranchLabel inactive = { 0 };
    FastBranchFixup inactive_fixup;
    int nofp = ft_scratch_avoid3(-1, -1, -1);

    ft_emit_load_env(out, nofp, lsenv_offset_of_nofp(lsenv),
                     FT_LA_OPCODE_LD_W);
    ft_emit_branch_placeholder(out, &inactive_fixup, FT_BRANCH_BEQ, nofp,
                               la_zero, &inactive);
    ft_emit_save_fprs_to_env(out);
    FT_LA_ADDI_D_EMIT(out, nofp, la_zero, -1);
    for (int i = 0; i < 8; i++) {
        /* FXSAVE represents an active MMX register with exponent 0xffff. */
        ft_emit_store_env(out, nofp, lsenv_offset_of_mmx(lsenv, i) + 8,
                          FT_LA_OPCODE_ST_H);
    }
    ft_emit_store_env(out, la_zero, lsenv_offset_of_nofp(lsenv),
                      FT_LA_OPCODE_ST_W);

    ft_bind_branch_label(&inactive, *out);
    ft_resolve_branch_fixup(&inactive_fixup);
#else
    ft_emit_save_fprs_to_env(out);
#endif
}

static int ft_emit_raise_exception(uint32_t **out, target_ulong pc,
                                   int exception)
{
    uint32_t *start = *out;

    ft_emit_save_gprs_to_env(out);
    ft_emit_save_fprs_for_exception(out);
    ft_emit_save_xmms_to_env(out);
    ft_emit_save_condition_flags(out);

    ft_emit_li64(out, la_t0, pc);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_eip(lsenv), FT_LA_OPCODE_ST_D);

    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, exception);
    ft_emit_host_call(out, (void *)helper_raise_exception, 1u << 0);
    FT_LA_BREAK_EMIT(out, 0);
    return *out - start;
}

static int ft_emit_raise_illop(uint32_t **out, target_ulong pc)
{
    return ft_emit_raise_exception(out, pc, EXCP06_ILLOP);
}
