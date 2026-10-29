/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Host-translator ABI adapters used by otherwise shared emitters. */

static target_ulong ft_helper_lar(CPUX86State *env, target_ulong selector)
{
#ifdef QUICKTRANS_LATU
    const target_ulong cc_mask =
        CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C;
    target_ulong result;

    env->cc_src = env->eflags & cc_mask;
    env->cc_op = CC_OP_EFLAGS;
    result = helper_lar(env, selector);
    env->eflags = (env->eflags & ~cc_mask) | (env->cc_src & cc_mask);
    return result;
#else
    return helper_lar(env, selector);
#endif
}

static target_ulong ft_helper_lsl(CPUX86State *env, target_ulong selector)
{
#ifdef QUICKTRANS_LATU
    const target_ulong cc_mask =
        CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C;
    target_ulong result;

    /* LATU keeps live flags in LBT and saves them in eflags at helpers. */
    env->cc_src = env->eflags & cc_mask;
    env->cc_op = CC_OP_EFLAGS;
    result = helper_lsl(env, selector);
    env->eflags = (env->eflags & ~cc_mask) | (env->cc_src & cc_mask);
    return result;
#else
    return helper_lsl(env, selector);
#endif
}

static void ft_helper_verr(CPUX86State *env, target_ulong selector)
{
#ifdef QUICKTRANS_LATU
    const target_ulong cc_mask =
        CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C;

    env->cc_src = env->eflags & cc_mask;
    env->cc_op = CC_OP_EFLAGS;
    helper_verr(env, selector);
    env->eflags = (env->eflags & ~cc_mask) | (env->cc_src & cc_mask);
#else
    helper_verr(env, selector);
#endif
}

static void ft_helper_verw(CPUX86State *env, target_ulong selector)
{
#ifdef QUICKTRANS_LATU
    const target_ulong cc_mask =
        CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C;

    env->cc_src = env->eflags & cc_mask;
    env->cc_op = CC_OP_EFLAGS;
    helper_verw(env, selector);
    env->eflags = (env->eflags & ~cc_mask) | (env->cc_src & cc_mask);
#else
    helper_verw(env, selector);
#endif
}

static void ft_emit_save_condition_flags(uint32_t **out)
{
    FT_LA_X86MFFLAG_EMIT(out, la_t0, 0x3f);
#ifdef QUICKTRANS_LATU
    FT_LA_OR_EMIT(out, la_a6, la_a6, la_t0);
    ft_emit_store_env(out, la_a6, lsenv_offset_of_eflags(lsenv),
                      FT_LA_OPCODE_ST_W);
#else
    ft_emit_store_env(out, la_t0, lsenv_offset_of_cc_src(lsenv),
                      FT_LA_OPCODE_ST_W);
    FT_LA_ADDI_D_EMIT(out, la_t0, la_zero, 1);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_cc_op(lsenv),
                      FT_LA_OPCODE_ST_W);
#endif
}

static void ft_emit_restore_condition_flags(uint32_t **out)
{
#ifdef QUICKTRANS_LATU
    ft_emit_load_env(out, la_a6, lsenv_offset_of_eflags(lsenv),
                     FT_LA_OPCODE_LD_W);
    FT_LA_X86MTFLAG_EMIT(out, la_a6, 0x3f);
    FT_LA_ANDI_EMIT(out, la_a6, la_a6, 0x702);
#else
    ft_emit_load_env(out, la_t0, lsenv_offset_of_cc_src(lsenv),
                     FT_LA_OPCODE_LD_W);
    FT_LA_X86MTFLAG_EMIT(out, la_t0, 0x3f);
#endif
}

static void ft_emit_set_direction_flag(uint32_t **out, bool reverse)
{
#ifdef QUICKTRANS_LATU
    if (reverse) {
        FT_LA_ORI_EMIT(out, la_a6, la_a6, 0x400);
    } else {
        FT_LA_BSTRINS_D_EMIT(out, la_a6, la_zero, 10, 10);
    }
#else
    FT_LA_ADDI_D_EMIT(out, la_t0, la_zero, reverse ? -1 : 1);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_df(lsenv),
                      FT_LA_OPCODE_ST_W);
#endif
}

static bool ft_emit_direction_step(uint32_t **out, int dst, int bytes)
{
    int shift;

    switch (bytes) {
    case 1:
        shift = 0;
        break;
    case 2:
        shift = 1;
        break;
    case 4:
        shift = 2;
        break;
    case 8:
        shift = 3;
        break;
    default:
        return false;
    }

#ifdef QUICKTRANS_LATU
    FT_LA_ANDI_EMIT(out, dst, la_a6, 0x400);
    FT_LA_SRAI_W_EMIT(out, dst, dst, 9 - shift);
    FT_LA_ADDI_W_EMIT(out, dst, dst, -bytes);
#else
    ft_emit_load_env(out, dst, lsenv_offset_of_df(lsenv),
                     FT_LA_OPCODE_LD_W);
    if (shift) {
        FT_LA_SLLI_D_EMIT(out, dst, dst, shift);
    }
    FT_LA_SUB_D_EMIT(out, dst, la_zero, dst);
#endif
    return true;
}

static bool ft_emit_collect_rflags(uint32_t **out)
{
    FT_LA_X86MFFLAG_EMIT(out, la_t0, 0x3f);
#ifdef QUICKTRANS_LATU
    /* Legacy LATU keeps non-arithmetic flags (including ID) in a6. */
    FT_LA_OR_EMIT(out, la_t0, la_t0, la_a6);
#else
    ft_emit_load_env(out, la_t1, lsenv_offset_of_eflags(lsenv),
                     FT_LA_OPCODE_LD_WU);
    if (!ft_emit_li32(out, la_t2, ~0xcd5u)) {
        return false;
    }
    FT_LA_AND_EMIT(out, la_t1, la_t1, la_t2);
    FT_LA_OR_EMIT(out, la_t0, la_t0, la_t1);
    ft_emit_load_env(out, la_t1, lsenv_offset_of_df(lsenv),
                     FT_LA_OPCODE_LD_W);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 0x400);
    FT_LA_OR_EMIT(out, la_t0, la_t0, la_t1);
    if (!ft_emit_li32(out, la_t1, ~(VM_MASK | RF_MASK))) {
        return false;
    }
    FT_LA_AND_EMIT(out, la_t0, la_t0, la_t1);
#endif
    return true;
}

static bool ft_emit_apply_popfq(uint32_t **out, TranslationBlock *tb)
{
    FT_LA_X86MTFLAG_EMIT(out, la_t0, 0x3f);
#ifdef QUICKTRANS_LATU
    (void)tb;
    if (!ft_emit_li32(out, la_t1, 0xfffff500u)) {
        return false;
    }
    FT_LA_AND_EMIT(out, la_a6, la_t0, la_t1);
    FT_LA_ORI_EMIT(out, la_a6, la_a6, 0x202);
#else
    uint32_t update_mask = TF_MASK | AC_MASK | ID_MASK | NT_MASK;
    int cpl = tb->flags & HF_CPL_MASK;
    int iopl = (tb->flags & HF_IOPL_MASK) >> HF_IOPL_SHIFT;

    if (cpl == 0) {
        update_mask |= IF_MASK | IOPL_MASK;
    } else if (cpl <= iopl) {
        update_mask |= IF_MASK;
    }

    FT_LA_SRLI_D_EMIT(out, la_t1, la_t0, 9);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 2);
    FT_LA_SUB_D_EMIT(out, la_t1, la_zero, la_t1);
    FT_LA_ADDI_D_EMIT(out, la_t1, la_t1, 1);
    ft_emit_store_env(out, la_t1, lsenv_offset_of_df(lsenv),
                      FT_LA_OPCODE_ST_W);

    if (!ft_emit_li32(out, la_t1, update_mask)) {
        return false;
    }
    FT_LA_AND_EMIT(out, la_t2, la_t0, la_t1);
    ft_emit_load_env(out, la_t3, lsenv_offset_of_eflags(lsenv),
                     FT_LA_OPCODE_LD_WU);
    FT_LA_NOR_EMIT(out, la_t1, la_t1, la_zero);
    FT_LA_AND_EMIT(out, la_t3, la_t3, la_t1);
    FT_LA_OR_EMIT(out, la_t2, la_t2, la_t3);
    FT_LA_ORI_EMIT(out, la_t2, la_t2, 2);
    ft_emit_store_env(out, la_t2, lsenv_offset_of_eflags(lsenv),
                      FT_LA_OPCODE_ST_W);
#endif
    return true;
}

static bool ft_emit_data_store(uint32_t **out, target_ulong guest_pc,
                               int addr, int offset, int value, int bytes)
{
#if !defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (!ft_fits_simm12(offset) || bytes <= 0 || bytes > 8) {
        return false;
    }
    if (!page_store_data_mixed_promoted(guest_pc)) {
        return false;
    }

    if (offset) {
        FT_LA_ADDI_D_EMIT(out, la_a0, addr, offset);
    } else {
        FT_LA_OR_EMIT(out, la_a0, addr, la_zero);
    }
    FT_LA_OR_EMIT(out, la_a1, value, la_zero);
    FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, bytes);
    for (int i = r8_index; i <= r15_index; i++) {
        ft_emit_store_env(out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i),
                          FT_LA_OPCODE_ST_D);
    }
    ft_emit_host_call(out, (void *)page_store_data_mixed, 1u << 0);
    for (int i = r8_index; i <= r15_index; i++) {
        ft_emit_load_env(out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i),
                         FT_LA_OPCODE_LD_D);
    }
    return true;
#else
    (void)out;
    (void)guest_pc;
    (void)addr;
    (void)offset;
    (void)value;
    (void)bytes;
    return false;
#endif
}

static void *ft_host_sha256rnds2_helper(void)
{
#ifdef QUICKTRANS_LATU
    return (void *)helper_sha256rnds2_xmm0;
#else
    return (void *)helper_sha256rnds2;
#endif
}

static unsigned ft_emit_host_sha_reg_args(uint32_t **out, int dst_xmm,
                                          int src_xmm, bool sha256rnds2)
{
#ifdef QUICKTRANS_LATU
    (void)sha256rnds2;
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_xmm_env_addr(out, la_a1, dst_xmm);
    ft_emit_xmm_env_addr(out, la_a2, dst_xmm);
    ft_emit_xmm_env_addr(out, la_a3, src_xmm);
    return 0xf;
#else
    ft_emit_xmm_env_addr(out, la_a0, dst_xmm);
    ft_emit_xmm_env_addr(out, la_a1, dst_xmm);
    ft_emit_xmm_env_addr(out, la_a2, src_xmm);
    if (sha256rnds2) {
        FT_LA_VPICKVE2GR_WU_EMIT(out, la_a3, ft_xmm(0), 0);
        FT_LA_VPICKVE2GR_WU_EMIT(out, la_a4, ft_xmm(0), 1);
    }
    return 0x7;
#endif
}
