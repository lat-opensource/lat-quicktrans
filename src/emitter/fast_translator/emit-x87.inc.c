/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

static int ft_emit_emms_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)fields;
    (void)tb;
    (void)pc;

    ft_emit_li64(&out, la_t0, 0x0101010101010101ULL);
    ft_emit_store_env(&out, la_t0, lsenv_offset_of_tag_word(lsenv),
                      FT_LA_OPCODE_ST_D);
    ft_emit_leave_mmx(&out);
    return (out - code);
}

#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
/* Mirror update_fp_status without a host call. cw must be la_t0.
 * Direct stores are retained for FRSTOR only: deleting these pointer moves
 * regressed measured FLDCW/FLDENV execution, despite reducing code size. */
static void ft_emit_x87_soft_control(uint32_t **out, bool direct_env)
{
#ifdef QUICKTRANS_LATU
    const int env_reg = la_s8;
#else
    const int env_reg = la_s0;
#endif
    int status = lsenv_offset_of_fp_status(lsenv);
    int rounding = status + offsetof(float_status, float_rounding_mode);
    int precision = status + offsetof(float_status, floatx80_rounding_precision);
    FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t0, 11, 10);
    if (direct_env && ft_offset_fits_imm12(rounding)) {
        FT_LA_ST_B_EMIT(out, la_t2, env_reg,
                       rounding);
    } else {
        ft_emit_store_env(out, la_t2, rounding, FT_LA_OPCODE_ST_B);
    }
#ifdef QUICKTRANS_LATU
    /* Legacy mode-2 fast arithmetic uses host rounding even though
     * LATX_SOFTFPU normally disables the helper's fesetround option. */
    if (option_set_rounding_opt ||
        (option_soft_fpu == 2 && option_softfpu_fast)) {
#endif
    FT_LA_MOVFCSR2GR_EMIT(out, la_t1, 0);
    FT_LA_ANDI_EMIT(out, la_t3, la_t2, 1);
    FT_LA_BEQ_EMIT(out, la_t3, la_zero, 2);
    FT_LA_XORI_EMIT(out, la_t2, la_t2, 2);
    FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t2, FCSR_OFF_RM + 1, FCSR_OFF_RM);
    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t1);
#ifdef QUICKTRANS_LATU
    }
#endif
    /* PC=01 is reserved; use the helper's extended-precision default. */
    FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t0, 9, 8);
    ft_emit_li64(out, la_t3, floatx80_precision_s |
                   (floatx80_precision_x << 8) |
                   (floatx80_precision_d << 16) |
                   (floatx80_precision_x << 24));
    FT_LA_SLLI_W_EMIT(out, la_t2, la_t2, 3);
    FT_LA_SRL_D_EMIT(out, la_t3, la_t3, la_t2);
    if (direct_env && ft_offset_fits_imm12(precision)) {
        FT_LA_ST_B_EMIT(out, la_t3, env_reg,
                       precision);
    } else {
        ft_emit_store_env(out, la_t3, precision, FT_LA_OPCODE_ST_B);
    }
}
#endif

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
/* FNINIT has a fixed control word: do not emit variable-CW decoding. */
static void ft_emit_x87_fast_init(uint32_t **out)
{
    FT_LA_X86MTTOP_EMIT(out, 0);
    FT_LA_ORI_EMIT(out, la_t0, la_zero, 0x37f);
    FT_LA_ST_H_EMIT(out, la_t0, la_s0, lsenv_offset_of_control_word(lsenv));
    FT_LA_ST_H_EMIT(out, la_zero, la_s0, lsenv_offset_of_status_word(lsenv));
    FT_LA_ST_W_EMIT(out, la_zero, la_s0, lsenv_offset_of_top(lsenv));
    ft_emit_li64(out, la_t0, 0x0101010101010101ULL);
    FT_LA_ST_D_EMIT(out, la_t0, la_s0, lsenv_offset_of_tag_word(lsenv));
    int status = lsenv_offset_of_fp_status(lsenv);
    FT_LA_ST_B_EMIT(out, la_zero, la_s0,
                   status + offsetof(float_status, float_rounding_mode));
    ft_emit_li64(out, la_t0, floatx80_precision_x);
    FT_LA_ST_B_EMIT(out, la_t0, la_s0,
                   status + offsetof(float_status, floatx80_rounding_precision));
    FT_LA_MOVFCSR2GR_EMIT(out, la_t0, 0);
    FT_LA_BSTRINS_W_EMIT(out, la_t0, la_zero, FCSR_OFF_RM + 1, FCSR_OFF_RM);
    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t0);
    FT_LA_ST_H_EMIT(out, la_zero, la_s0, offsetof(CPUX86State, fpcs));
    FT_LA_ST_H_EMIT(out, la_zero, la_s0, offsetof(CPUX86State, fpds));
    FT_LA_ST_D_EMIT(out, la_zero, la_s0, offsetof(CPUX86State, fpip));
    FT_LA_ST_D_EMIT(out, la_zero, la_s0, offsetof(CPUX86State, fpdp));
}
#endif

static int ft_emit_x87_state_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    (void)pc;

    switch (fields->kind) {
    case FT_FNINIT:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_soft_fpu && option_soft_fpu_fast) {
            ft_emit_x87_fast_init(&out);
            break;
        }
#endif
        FT_LA_X86MTTOP_EMIT(&out, 0);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        /* Little-endian adjacent SW/CW, as in legacy translate_fninit. */
        QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->fpus) != 2);
        QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->fpuc) != 2);
        QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpuc) !=
                          offsetof(CPUX86State, fpus) + 2);
        QEMU_BUILD_BUG_ON(offsetof(CPUX86State, fpus) % 4 != 0);
        ft_emit_li32(&out, la_t0, 0x037f0000);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_status_word(lsenv),
                          FT_LA_OPCODE_ST_W);
#else
        FT_LA_ORI_EMIT(&out, la_t0, la_zero, 0x37f);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_control_word(lsenv),
                          FT_LA_OPCODE_ST_H);
        ft_emit_store_env(&out, la_zero, lsenv_offset_of_status_word(lsenv),
                          FT_LA_OPCODE_ST_H);
#endif
        ft_emit_store_env(&out, la_zero, lsenv_offset_of_top(lsenv),
                          FT_LA_OPCODE_ST_W);
        ft_emit_li64(&out, la_t0, 0x0101010101010101ULL);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_tag_word(lsenv),
                          FT_LA_OPCODE_ST_D);
        if (option_soft_fpu) {
#ifdef QUICKTRANS_LATU
            if (option_soft_fpu == 2) {
                int status = lsenv_offset_of_fp_status(lsenv);
                ft_emit_store_env(&out, la_zero,
                    status + offsetof(float_status, float_rounding_mode),
                    FT_LA_OPCODE_ST_B);
                ft_emit_li64(&out, la_t0, floatx80_precision_x);
                ft_emit_store_env(&out, la_t0,
                    status + offsetof(float_status, floatx80_rounding_precision),
                    FT_LA_OPCODE_ST_B);
                if (option_set_rounding_opt || option_softfpu_fast) {
                    FT_LA_MOVFCSR2GR_EMIT(&out, la_t0, 0);
                    FT_LA_BSTRINS_W_EMIT(&out, la_t0, la_zero,
                                         FCSR_OFF_RM + 1, FCSR_OFF_RM);
                    FT_LA_MOVGR2FCSR_EMIT(&out, 0, la_t0);
                }
            } else
#endif
            {
                ft_emit_helper_prologue(&out);
                ft_emit_cpu_env_ptr(&out, la_a0);
                ft_emit_host_call(&out, (void *)update_fp_status, 1u << 0);
                ft_emit_x87_helper_epilogue(&out);
            }
        } else {
            FT_LA_MOVFCSR2GR_EMIT(&out, la_t0, 0);
            FT_LA_BSTRINS_W_EMIT(&out, la_t0, la_zero, FCSR_OFF_EN_V,
                                 FCSR_OFF_EN_I);
            FT_LA_BSTRINS_W_EMIT(&out, la_t0, la_zero, FCSR_OFF_RM + 1,
                                 FCSR_OFF_RM);
            FT_LA_BSTRINS_W_EMIT(&out, la_t0, la_zero, FCSR_OFF_FLAGS_V,
                                 FCSR_OFF_FLAGS_I);
            FT_LA_MOVGR2FCSR_EMIT(&out, 0, la_t0);
        }
        break;
    case FT_FNCLEX:
    {
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

        if (!ft_fits_simm12(fpus_offset)) {
            return 0;
        }
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_soft_fpu && option_soft_fpu_fast) {
            FT_LA_LD_HU_EMIT(&out, la_t0, la_s0, fpus_offset);
            FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_zero, 7, 0);
            FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_zero, 15, 15);
            FT_LA_ST_H_EMIT(&out, la_t0, la_s0, fpus_offset);
            break;
        }
#endif
        ft_emit_load_env(&out, la_t0, fpus_offset, FT_LA_OPCODE_LD_HU);
        FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_zero, 7, 0);
        FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_zero, 15, 15);
#ifdef QUICKTRANS_LATU
        /* Soft x87 exceptions live in env; FCSR flags belong to SIMD here. */
        if (!option_soft_fpu)
#elif defined(CONFIG_SOFTMMU)
        if (!(option_soft_fpu && option_soft_fpu_fast))
#endif
        {
            ft_emit_raw(&out, FT_LA_OPCODE_MOVFCSR2GR | la_t1);
            FT_LA_BSTRINS_D_EMIT(&out, la_t1, la_zero, 20, 16);
            ft_emit_raw(&out, FT_LA_OPCODE_MOVGR2FCSR | (la_t1 << 5));
        }
        ft_emit_store_env(&out, la_t0, fpus_offset, FT_LA_OPCODE_ST_H);
        break;
    }
    default:
        return 0;
    }

    return (out - code);
}

static void ft_emit_x87_update_fcsr_by_cw(uint32_t **out, int cw)
{
    FT_LA_MOVFCSR2GR_EMIT(out, la_t1, 0);

    if (0) {
        FT_LA_BSTRINS_W_EMIT(out, la_t1, la_zero, FCSR_OFF_EN_V,
                             FCSR_OFF_EN_I);

        FT_LA_BSTRPICK_W_EMIT(out, la_t2, cw, X87_CR_OFF_IM,
                              X87_CR_OFF_IM);
        FT_LA_XORI_EMIT(out, la_t2, la_t2, 1);
        FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t2, FCSR_OFF_EN_V,
                             FCSR_OFF_EN_V);

        FT_LA_BSTRPICK_W_EMIT(out, la_t2, cw, X87_CR_OFF_ZM,
                              X87_CR_OFF_ZM);
        FT_LA_XORI_EMIT(out, la_t2, la_t2, 1);
        FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t2, FCSR_OFF_EN_Z,
                             FCSR_OFF_EN_Z);

        FT_LA_BSTRPICK_W_EMIT(out, la_t2, cw, X87_CR_OFF_OM,
                              X87_CR_OFF_OM);
        FT_LA_XORI_EMIT(out, la_t2, la_t2, 1);
        FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t2, FCSR_OFF_EN_O,
                             FCSR_OFF_EN_O);

        FT_LA_BSTRPICK_W_EMIT(out, la_t2, cw, X87_CR_OFF_UM,
                              X87_CR_OFF_UM);
        FT_LA_XORI_EMIT(out, la_t2, la_t2, 1);
        FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t2, FCSR_OFF_EN_U,
                             FCSR_OFF_EN_U);
        FT_LA_BSTRINS_W_EMIT(out, la_t1, la_zero, FCSR_OFF_EN_I,
                             FCSR_OFF_EN_I);
    } else {
        FT_LA_BITREV_W_EMIT(out, la_t2, cw);
        FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t2, 30, 26);
        FT_LA_BSTRINS_W_EMIT(out, la_t2, cw, FCSR_OFF_EN_V,
                             FCSR_OFF_EN_V);
        FT_LA_XORI_EMIT(out, la_t2, la_t2, 0x1f);
        FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t2, FCSR_OFF_EN_V,
                             FCSR_OFF_EN_I);
    }

    /* The final BSTRINS replaces both RM bits on either branch. */
    FT_LA_BSTRPICK_W_EMIT(out, la_t2, cw, X87_CR_OFF_RC + 1,
                          X87_CR_OFF_RC);
    FT_LA_ANDI_EMIT(out, la_t3, la_t2, 1);
    FT_LA_BEQ_EMIT(out, la_t3, la_zero, 2);
    FT_LA_XORI_EMIT(out, la_t2, la_t2, 2);
    FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t2, FCSR_OFF_RM + 1,
                         FCSR_OFF_RM);

    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t1);
}

static void ft_emit_x87_update_sw_by_fcsr(uint32_t **out, int sw, int fcsr,
                                          int tmp);
static bool ft_emit_x87_sync_status_from_fcsr(uint32_t **out);

static bool ft_emit_x87_mark_denormal_operand(uint32_t **out, int bits,
                                              bool is_double)
{
    int fpus_offset = lsenv_offset_of_status_word(lsenv);
    FastBranchLabel done = { 0 };
    FastBranchFixup exponent_fixup;
    FastBranchFixup zero_fixup;

    if (!ft_offset_fits_imm12(fpus_offset)) {
        return false;
    }

    FT_LA_BSTRPICK_D_EMIT(out, la_t0, bits,
                          is_double ? 62 : 30,
                          is_double ? 52 : 23);
    ft_emit_branch_placeholder(out, &exponent_fixup, FT_BRANCH_BNE,
                               la_t0, la_zero, &done);
    FT_LA_BSTRPICK_D_EMIT(out, la_t0, bits,
                          is_double ? 51 : 22, 0);
    ft_emit_branch_placeholder(out, &zero_fixup, FT_BRANCH_BEQ,
                               la_t0, la_zero, &done);
    ft_emit_load_env(out, la_t0, fpus_offset, FT_LA_OPCODE_LD_HU);
    FT_LA_ORI_EMIT(out, la_t0, la_t0, 1u << X87_SR_OFF_DE);
    ft_emit_store_env(out, la_t0, fpus_offset, FT_LA_OPCODE_ST_H);

    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&exponent_fixup);
    ft_resolve_branch_fixup(&zero_fixup);
    return true;
}

static void ft_emit_x87_fcom_status(uint32_t **out, int lhs, int rhs,
                                    bool signal_all_nans)
{
    int fpus_offset = lsenv_offset_of_status_word(lsenv);
    FastBranchLabel ordered = { 0 };
    FastBranchLabel done = { 0 };
    FastBranchFixup ordered_fixup;
    FastBranchFixup done_fixup;

    ft_emit_load_env(out, la_t0, fpus_offset, FT_LA_OPCODE_LD_HU);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 14, 14);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 10, 8);
    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, lhs, rhs,
                                  signal_all_nans ? 0x09 : 0x08));
    FT_LA_MOVCF2GR_EMIT(out, la_t1, 0);
    ft_emit_branch_placeholder(out, &ordered_fixup, FT_BRANCH_BEQ,
                               la_t1, la_zero, &ordered);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 14, 14);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 10, 10);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 8, 8);
    ft_emit_branch_placeholder(out, &done_fixup, FT_BRANCH_B, 0, 0, &done);

    ft_bind_branch_label(&ordered, *out);
    ft_resolve_branch_fixup(&ordered_fixup);
    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, rhs, lhs,
                                  0x02));
    FT_LA_MOVCF2GR_EMIT(out, la_t1, 0);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 8, 8);
    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, lhs, rhs,
                                  0x04));
    FT_LA_MOVCF2GR_EMIT(out, la_t1, 0);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 14, 14);

    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&done_fixup);
    ft_emit_x87_update_sw_by_fcsr(out, la_t0, la_t2, la_t3);
    ft_emit_store_env(out, la_t0, fpus_offset, FT_LA_OPCODE_ST_H);
}

static bool ft_emit_x87_fcomi_flags(uint32_t **out, int src, int st0,
                                    bool signal_all_nans, bool skip_flags)
{
#ifdef QUICKTRANS_LATU
    if (skip_flags) {
        /* Dead integer flags do not make x87 exceptions or status dead. */
        ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, src, st0,
                                     signal_all_nans ? 0x09 : 0x08));
        ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, st0, src,
                                     0x02));
        ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, st0, src,
                                     0x04));
        return ft_emit_x87_sync_status_from_fcsr(out);
    }
#else
    (void)skip_flags;
#endif
    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, src, st0,
                                  signal_all_nans ? 0x09 : 0x08));
    FT_LA_MOVCF2GR_EMIT(out, la_t0, 0);
    FT_LA_OR_EMIT(out, la_t2, la_zero, la_t0);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t0, 2);
    FT_LA_OR_EMIT(out, la_t2, la_t2, la_t1);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t0, 6);
    FT_LA_OR_EMIT(out, la_t2, la_t2, la_t1);

    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, st0, src,
                                  0x02));
    FT_LA_MOVCF2GR_EMIT(out, la_t0, 0);
    FT_LA_OR_EMIT(out, la_t2, la_t2, la_t0);

    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, st0, src,
                                  0x04));
    FT_LA_MOVCF2GR_EMIT(out, la_t0, 0);
    FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 6);
    FT_LA_OR_EMIT(out, la_t2, la_t2, la_t0);

    FT_LA_X86MTFLAG_EMIT(out, la_t2, 0x3f);
    return ft_emit_x87_sync_status_from_fcsr(out);
}

static void ft_emit_x87_update_sw_by_fcsr(uint32_t **out, int sw, int fcsr,
                                          int tmp)
{
    FT_LA_MOVFCSR2GR_EMIT(out, fcsr, 0);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    /* Reverse V/Z/O/U/I once, then leave the x87 denormal bit (bit 1)
     * untouched while ORing the other five sticky exception flags. */
    FT_LA_BITREV_W_EMIT(out, tmp, fcsr);
    FT_LA_BSTRPICK_D_EMIT(out, tmp, tmp, 15, 11);
    FT_LA_BSTRINS_D_EMIT(out, tmp, tmp, 5, 1);
    FT_LA_ANDI_EMIT(out, tmp, tmp, 0x3d);
    FT_LA_OR_EMIT(out, sw, sw, tmp);
#else
    FT_LA_BITREV_W_EMIT(out, tmp, fcsr);
    FT_LA_SRLI_D_EMIT(out, tmp, tmp, 11);
    FT_LA_BSTRPICK_D_EMIT(out, tmp, tmp, 0, 0);
    FT_LA_OR_EMIT(out, sw, sw, tmp);

    FT_LA_BITREV_W_EMIT(out, tmp, fcsr);
    FT_LA_SRLI_D_EMIT(out, tmp, tmp, 11);
    FT_LA_BSTRPICK_D_EMIT(out, tmp, tmp, 4, 1);
    FT_LA_SLLI_D_EMIT(out, tmp, tmp, 2);
    FT_LA_OR_EMIT(out, sw, sw, tmp);

#endif

    FT_LA_BSTRINS_W_EMIT(out, fcsr, la_zero, FCSR_OFF_FLAGS_V,
                         FCSR_OFF_FLAGS_I);
    FT_LA_MOVGR2FCSR_EMIT(out, 0, fcsr);
}

static bool ft_emit_x87_sync_status_from_fcsr(uint32_t **out)
{
    int fpus_offset = lsenv_offset_of_status_word(lsenv);

    if (!ft_offset_fits_imm12(fpus_offset)) {
        return false;
    }
    ft_emit_load_env(out, la_t0, fpus_offset, FT_LA_OPCODE_LD_HU);
    ft_emit_x87_update_sw_by_fcsr(out, la_t0, la_t1, la_t2);
    ft_emit_store_env(out, la_t0, fpus_offset, FT_LA_OPCODE_ST_H);
    return true;
}

static bool ft_emit_x87_reload_control_clear_fcsr(uint32_t **out)
{
    int fpuc_offset = lsenv_offset_of_control_word(lsenv);

    if (!ft_offset_fits_imm12(fpuc_offset)) {
        return false;
    }
    ft_emit_load_env(out, la_t0, fpuc_offset, FT_LA_OPCODE_LD_HU);
    ft_emit_x87_update_fcsr_by_cw(out, la_t0);
    FT_LA_MOVFCSR2GR_EMIT(out, la_t0, 0);
    FT_LA_BSTRINS_W_EMIT(out, la_t0, la_zero, FCSR_OFF_FLAGS_V,
                         FCSR_OFF_FLAGS_I);
    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t0);
    return true;
}

static bool ft_emit_x87_reload_control_status_fcsr(uint32_t **out)
{
    int fpuc_offset = lsenv_offset_of_control_word(lsenv);
    int fpus_offset = lsenv_offset_of_status_word(lsenv);

    if (!ft_offset_fits_imm12(fpuc_offset) ||
        !ft_offset_fits_imm12(fpus_offset)) {
        return false;
    }
    ft_emit_load_env(out, la_t0, fpuc_offset, FT_LA_OPCODE_LD_HU);
    ft_emit_x87_update_fcsr_by_cw(out, la_t0);

    ft_emit_load_env(out, la_t0, fpus_offset, FT_LA_OPCODE_LD_HU);
    FT_LA_MOVFCSR2GR_EMIT(out, la_t1, 0);
    FT_LA_BITREV_W_EMIT(out, la_t2, la_t0);
    FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t2, 30, 26);
    FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t2, FCSR_OFF_FLAGS_Z,
                         FCSR_OFF_FLAGS_I);
    FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t0, FCSR_OFF_FLAGS_V,
                         FCSR_OFF_FLAGS_V);
    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t1);
    return true;
}

#ifdef QUICKTRANS_LATU
/* Legacy FDIV variants make IE/ZE sticky in the x87 state immediately.
 * A later LDMXCSR may clear the shared host FCSR before FNSTSW reads it. */
static void ft_emit_latu_x87_div_status(uint32_t **out)
{
    FastBranchLabel done = { 0 };
    FastBranchFixup done_fixup;

    FT_LA_MOVFCSR2GR_EMIT(out, la_t1, 0);
    FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t1, FCSR_OFF_CAUSE_V,
                         FCSR_OFF_CAUSE_Z);
    /* Leave sticky guest status untouched when neither cause is present. */
    ft_emit_branch_placeholder(out, &done_fixup, FT_BRANCH_BEQ,
                               la_t2, la_zero, &done);
    ft_emit_load_env(out, la_t0, lsenv_offset_of_status_word(lsenv),
                     FT_LA_OPCODE_LD_HU);
    FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t1, FCSR_OFF_CAUSE_Z,
                         FCSR_OFF_CAUSE_Z);
    FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, X87_SR_OFF_ZE);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t1, FCSR_OFF_CAUSE_V,
                         FCSR_OFF_CAUSE_V);
    FT_LA_OR_EMIT(out, la_t0, la_t0, la_t2);
    FT_LA_OR_EMIT(out, la_t0, la_t0, la_t1);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_status_word(lsenv),
                      FT_LA_OPCODE_ST_H);
    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&done_fixup);
}
#endif

static void ft_emit_x87_status_top(uint32_t **out)
{
    int fpus_offset = lsenv_offset_of_status_word(lsenv);

    ft_emit_load_env(out, la_t0, fpus_offset, FT_LA_OPCODE_LD_HU);
    FT_LA_X86MFTOP_EMIT(out, la_t1);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 13, 11);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 11);
    FT_LA_OR_EMIT(out, la_t0, la_t0, la_t1);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 9, 9);
    ft_emit_store_env(out, la_t0, fpus_offset, FT_LA_OPCODE_ST_H);
}

static void ft_emit_x87_empty_qnan(uint32_t **out, int freg)
{
    ft_emit_li64(out, la_t0, 0xfff8000000000000ULL);
    FT_LA_MOVGR2FR_D_EMIT(out, freg, la_t0);
}

static void ft_emit_x87_st_tag_addr(uint32_t **out, int addr, int top,
                                    unsigned int st_index)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    int offset = lsenv_offset_of_tag_word(lsenv);

    /* As in load/store_env, the LATU ABI already keeps CPU state in s8. */
    if (ft_offset_fits_imm12(offset)) {
        FT_LA_ADDI_D_EMIT(out, addr, la_s8, offset);
    } else {
        ft_emit_li64(out, top, (uint64_t)(int64_t)offset);
        FT_LA_ADD_D_EMIT(out, addr, la_s8, top);
    }
#else
    ft_emit_cpu_env_ptr(out, addr);
    ft_emit_li64(out, top, (uint64_t)(int64_t)lsenv_offset_of_tag_word(lsenv));
    FT_LA_ADD_D_EMIT(out, addr, addr, top);
#endif
    FT_LA_X86MFTOP_EMIT(out, top);
    if (st_index) {
        FT_LA_ADDI_D_EMIT(out, top, top, st_index);
        FT_LA_ANDI_EMIT(out, top, top, 7);
    }
    FT_LA_ADD_D_EMIT(out, addr, addr, top);
}

static void ft_emit_x87_current_tag_addr(uint32_t **out, int addr, int top)
{
    ft_emit_x87_st_tag_addr(out, addr, top, 0);
}

static void ft_emit_x87_mark_st_tag(uint32_t **out, unsigned int st_index,
                                    int tag)
{
    ft_emit_x87_st_tag_addr(out, la_t3, la_t2, st_index);
    if (tag == 0) {
        FT_LA_ST_B_EMIT(out, la_zero, la_t3, 0);
    } else {
        FT_LA_ORI_EMIT(out, la_t0, la_zero, tag);
        FT_LA_ST_B_EMIT(out, la_t0, la_t3, 0);
    }
}

static void ft_emit_x87_mark_current_tag(uint32_t **out, int tag)
{
    /* Ordinary hard-FPU pushes/pops follow LATX_FPUTAG. Explicit FFREE
     * uses mark_st_tag directly and must still invalidate its slot.
     */
    if (ft_x87_latu_legacy_no_tag()) {
        return;
    }
    ft_emit_x87_mark_st_tag(out, 0, tag);
}

static void ft_emit_x87_pop(uint32_t **out)
{
    ft_emit_x87_mark_current_tag(out, 1);
    FT_LA_X86INCTOP_EMIT(out);
}

static void ft_emit_x87_load_current_tag(uint32_t **out, int dst)
{
    ft_emit_x87_current_tag_addr(out, la_t3, la_t2);
    FT_LA_LD_BU_EMIT(out, dst, la_t3, 0);
}

static void ft_emit_x87_load_st_tag(uint32_t **out, int dst,
                                    unsigned int st_index)
{
    ft_emit_x87_st_tag_addr(out, la_t3, la_t2, st_index);
    FT_LA_LD_BU_EMIT(out, dst, la_t3, 0);
}

static void ft_emit_x87_load_int_to_freg(uint32_t **out, int addr, int offset,
                                         int width, int freg)
{
    switch (width) {
    case 16:
        FT_LA_LD_H_EMIT(out, la_t0, addr, offset);
        FT_LA_MOVGR2FR_D_EMIT(out, freg, la_t0);
        FT_LA_FFINT_D_W_EMIT(out, freg, freg);
        break;
    case 32:
        FT_LA_FLD_S_EMIT(out, freg, addr, offset);
        FT_LA_FFINT_D_W_EMIT(out, freg, freg);
        break;
    case 64:
        FT_LA_FLD_D_EMIT(out, freg, addr, offset);
        FT_LA_FFINT_D_L_EMIT(out, freg, freg);
        break;
    default:
        break;
    }
}

static bool ft_x87_fild_width(FastTemplateKind kind, int *width)
{
    switch (kind) {
    case FT_X87_FILD_M16:
        *width = 16;
        return true;
    case FT_X87_FILD_M32:
        *width = 32;
        return true;
    case FT_X87_FILD_M64:
        *width = 64;
        return true;
    default:
        return false;
    }
}

static bool ft_x87_fist_width(FastTemplateKind kind, int *width, bool *trunc)
{
    switch (kind) {
    case FT_X87_FISTP_M16:
        *width = 16;
        *trunc = false;
        return true;
    case FT_X87_FISTP_M32:
        *width = 32;
        *trunc = false;
        return true;
    case FT_X87_FISTP_M64:
        *width = 64;
        *trunc = false;
        return true;
    case FT_X87_FISTTP_M16:
        *width = 16;
        *trunc = true;
        return true;
    case FT_X87_FISTTP_M32:
        *width = 32;
        *trunc = true;
        return true;
    case FT_X87_FISTTP_M64:
        *width = 64;
        *trunc = true;
        return true;
    default:
        return false;
    }
}

static void ft_emit_x87_store_int(uint32_t **out, int addr, int offset,
                                  int width, bool trunc, int value_reg)
{
    switch (width) {
    case 16:
    {
        FastBranchLabel invalid = { 0 };
        FastBranchLabel store = { 0 };
        FastBranchFixup invalid_fixup;
        FastBranchFixup store_fixup;

        if (trunc) {
            FT_LA_FTINTRZ_W_D_EMIT(out, ft_vscratch + 1, ft_mmx(0));
        } else {
            FT_LA_FTINT_W_D_EMIT(out, ft_vscratch + 1, ft_mmx(0));
        }
        FT_LA_MOVFR2GR_S_EMIT(out, value_reg, ft_vscratch + 1);
        FT_LA_EXT_W_H_EMIT(out, la_t2, value_reg);
        ft_emit_branch_placeholder(out, &invalid_fixup, FT_BRANCH_BNE,
                                   la_t2, value_reg, &invalid);
        ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0,
                                      ft_mmx(0), ft_mmx(0), 0x08));
        FT_LA_MOVCF2GR_EMIT(out, la_t2, 0);
        ft_emit_branch_placeholder(out, &store_fixup, FT_BRANCH_BEQ,
                                   la_t2, la_zero, &store);
        ft_bind_branch_label(&invalid, *out);
        ft_resolve_branch_fixup(&invalid_fixup);
        ft_emit_li64(out, value_reg, 0x8000);
        FT_LA_MOVFCSR2GR_EMIT(out, la_t2, 0);
        FT_LA_ADDI_D_EMIT(out, la_t3, la_zero, 1);
        FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t3, FCSR_OFF_FLAGS_V,
                             FCSR_OFF_FLAGS_V);
        FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t2);
        ft_bind_branch_label(&store, *out);
        ft_resolve_branch_fixup(&store_fixup);
        FT_LA_ST_H_EMIT(out, value_reg, addr, offset);
        break;
    }
    case 32:
    {
        FastBranchLabel store = { 0 };
        FastBranchFixup store_fixup;

        if (trunc) {
            FT_LA_FTINTRZ_W_D_EMIT(out, ft_vscratch + 1, ft_mmx(0));
        } else {
            FT_LA_FTINT_W_D_EMIT(out, ft_vscratch + 1, ft_mmx(0));
        }
        FT_LA_MOVFR2GR_S_EMIT(out, value_reg, ft_vscratch + 1);
        FT_LA_MOVFCSR2GR_EMIT(out, la_t2, 0);
        FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t2, FCSR_OFF_CAUSE_V,
                              FCSR_OFF_CAUSE_V);
        ft_emit_branch_placeholder(out, &store_fixup, FT_BRANCH_BEQ,
                                   la_t2, la_zero, &store);
        ft_emit_li64(out, value_reg, 0x80000000);
        ft_bind_branch_label(&store, *out);
        ft_resolve_branch_fixup(&store_fixup);
        FT_LA_ST_W_EMIT(out, value_reg, addr, offset);
        break;
    }
    case 64:
    {
        FastBranchLabel store = { 0 };
        FastBranchFixup store_fixup;

        if (trunc) {
            FT_LA_FTINTRZ_L_D_EMIT(out, ft_vscratch + 1, ft_mmx(0));
        } else {
            FT_LA_FTINT_L_D_EMIT(out, ft_vscratch + 1, ft_mmx(0));
        }
        FT_LA_MOVFR2GR_D_EMIT(out, value_reg, ft_vscratch + 1);
        FT_LA_MOVFCSR2GR_EMIT(out, la_t2, 0);
        FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t2, FCSR_OFF_CAUSE_V,
                              FCSR_OFF_CAUSE_V);
        ft_emit_branch_placeholder(out, &store_fixup, FT_BRANCH_BEQ,
                                   la_t2, la_zero, &store);
        ft_emit_li64(out, value_reg, 0x8000000000000000ULL);
        ft_bind_branch_label(&store, *out);
        ft_resolve_branch_fixup(&store_fixup);
        FT_LA_ST_D_EMIT(out, value_reg, addr, offset);
        break;
    }
    default:
        break;
    }
}

static void ft_emit_x87_call_unary_double(uint32_t **out, void *func)
{
    FT_LA_FMOV_D_EMIT(out, ft_vscratch, ft_mmx(0));
    ft_emit_save_gprs_to_env(out);
    ft_emit_save_fprs_to_env(out);
    ft_emit_save_xmms_to_env(out);
    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -16);
    FT_LA_FST_D_EMIT(out, ft_vscratch + 1, la_sp, 0);
    ft_emit_host_stack_end(out);
    FT_LA_FMOV_D_EMIT(out, 0, ft_vscratch);
    ft_emit_host_call(out, func, 0);
    FT_LA_FMOV_D_EMIT(out, ft_vscratch, 0);
    ft_emit_host_stack_begin(out);
    FT_LA_FLD_D_EMIT(out, ft_vscratch + 1, la_sp, 0);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    ft_emit_host_stack_end(out);
    ft_emit_load_xmms_from_env(out);
    ft_emit_load_fprs_from_env(out);
    FT_LA_FMOV_D_EMIT(out, ft_mmx(0), ft_vscratch);
    for (int i = 0; i < GPR_NUM; i++) {
        ft_emit_load_env(out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i),
                         FT_LA_OPCODE_LD_D);
    }
}

static void ft_emit_x87_soft_store(uint32_t **out, int addr_reg,
                                   int value_reg, int width)
{
#ifdef CONFIG_SOFTMMU
    void *helper = width == 16 ? (void *)ft_x87_helper_store16 :
                   width == 32 ? (void *)ft_x87_helper_store32 :
                                 (void *)ft_x87_helper_store64;

    FT_LA_OR_EMIT(out, la_a2, value_reg, la_zero);
    if (addr_reg != la_a1) {
        FT_LA_OR_EMIT(out, la_a1, addr_reg, la_zero);
    }
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_host_call(out, helper, 1u << 0);
#else
    if (width == 16) {
        FT_LA_ST_H_EMIT(out, value_reg, addr_reg, 0);
    } else if (width == 32) {
        FT_LA_ST_W_EMIT(out, value_reg, addr_reg, 0);
    } else {
        FT_LA_ST_D_EMIT(out, value_reg, addr_reg, 0);
    }
#endif
}

static void ft_emit_x87_call_fsincos(uint32_t **out)
{
#ifdef QUICKTRANS_LATU
    /* Keep both results on the host stack until guest FPRs are restored.
     * The caller then pushes: old ST0 becomes ST1 (sin), old ST7 becomes
     * the new ST0 (cos). Match legacy LATU's unconditional C2 clearing. */
    ft_emit_load_env(out, la_t0, lsenv_offset_of_status_word(lsenv),
                     FT_LA_OPCODE_LD_HU);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 10, 10);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_status_word(lsenv),
                      FT_LA_OPCODE_ST_H);
    FT_LA_FMOV_D_EMIT(out, ft_vscratch, ft_mmx(0));
    ft_emit_save_gprs_to_env(out);
    ft_emit_save_fprs_to_env(out);
    ft_emit_save_xmms_to_env(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -16);
    FT_LA_FMOV_D_EMIT(out, 0, ft_vscratch);
    FT_LA_OR_EMIT(out, la_a0, la_sp, la_zero);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_sp, 8);
    ft_emit_host_call(out, (void *)sincos, 0x3);
    ft_emit_load_xmms_from_env(out);
    ft_emit_load_fprs_from_env(out);
    FT_LA_FLD_D_EMIT(out, ft_mmx(0), la_sp, 0);
    FT_LA_FLD_D_EMIT(out, ft_mmx(7), la_sp, 8);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    for (int i = 0; i < GPR_NUM; i++) {
        ft_emit_load_env(out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i),
                         FT_LA_OPCODE_LD_D);
    }
#else
    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -16);
    FT_LA_FST_D_EMIT(out, ft_mmx(0), la_sp, 0);
    ft_emit_host_stack_end(out);
    ft_emit_x87_call_unary_double(out, (void *)sin);
    FT_LA_FMOV_D_EMIT(out, ft_vscratch + 1, ft_mmx(0));
    ft_emit_host_stack_begin(out);
    FT_LA_FLD_D_EMIT(out, ft_mmx(0), la_sp, 0);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    ft_emit_host_stack_end(out);
    ft_emit_x87_call_unary_double(out, (void *)cos);
    FT_LA_FMOV_D_EMIT(out, ft_mmx(7), ft_mmx(0));
    FT_LA_FMOV_D_EMIT(out, ft_mmx(0), ft_vscratch + 1);
#endif
}

static void ft_emit_x87_helper(uint32_t **out, void *func)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (option_soft_fpu && option_soft_fpu_fast) {
        ft_emit_lats_nofp_helper(out, func);
        return;
    }
#endif
    ft_emit_helper_prologue(out);
    if (!option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_64_to_x80, 1u << 0);
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)update_fp_status, 1u << 0);
    }
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_host_call(out, func, 1u << 0);
    if (!option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_x80_to_64, 1u << 0);
    }
    ft_emit_x87_helper_epilogue(out);
}

/* LATS fast mode intentionally follows legacy stack/special-value policy. */
static void ft_emit_x87_complex_helper(uint32_t **out, void *checked, void *legacy)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (option_soft_fpu && option_soft_fpu_fast) {
        if (legacy == (void *)helper_fsincos) {
            /* libm sin/cos can clobber vector lanes. Unlike the legacy nofp
             * call, preserve the complete guest XMM register contents. */
            bool context = ft_emit_default_helper_prologue(out, false);
            ft_emit_cpu_env_ptr(out, la_a0);
            ft_emit_default_helper_call(out, legacy, 1u << 0, context);
            ft_emit_default_helper_epilogue(out, context, false);
            return;
        }
        ft_emit_lats_nofp_helper(out, legacy);
        return;
    }
#else
    (void)legacy;
#endif
    ft_emit_x87_helper(out, checked);
}

#include "emit-x87-soft-env.inc.c"

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
/* The static context preserves a2 and the guest FCSR. Keep MXCSR handling
 * around the helper just as in the expanded soft-FPU fallback below. */
static bool ft_emit_x87_fx_fallback(uint32_t **out,
                                   const FastTemplateFields *fields,
                                   target_ulong pc, bool restore)
{
    if (!scs_enabled()) return false;
    int mxcsr_offset = lsenv_offset_of_mxcsr(lsenv);
    if (!ft_fits_simm12(mxcsr_offset)) return false;
    uint32_t *start = *out;
    int addr;
    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        *out = start;
        return false;
    }
    int offset = ft_mem_access_offset(fields, addr);
    if (!ft_fits_simm12(offset)) { *out = start; return false; }
    FT_LA_ADDI_D_EMIT(out, la_a2, addr, offset);
    bool context = ft_emit_default_helper_prologue(out, false);
    FT_LA_OR_EMIT(out, la_a1, la_a2, la_zero);
    if (!restore) {
        ft_emit_load_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_LD_WU);
        ft_emit_mxcsr_flags_from_fcsr(out, la_t1);
        ft_emit_store_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_ST_W);
    }
    ft_emit_cpu_env_ptr(out, la_a0);
    /* a1 is a guest virtual address, not a host pointer. */
    ft_emit_default_helper_call(out, restore ? (void *)helper_fxrstor
                                            : (void *)helper_fxsave,
                                1u << 0, context);
    if (restore) {
        ft_emit_load_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_LD_WU);
        ft_emit_lats_softfpu_mxcsr(out, la_t1);
    }
    ft_emit_default_helper_epilogue(out, context, false);
    return true;
}
#endif

static int ft_emit_fxsave_restore_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc, bool restore)
{
    uint32_t *start = *out;
    int addr;
    int offset;
    int stack_bytes = 16;
    bool preserve_hard_fxsave = false;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    preserve_hard_fxsave = !restore && !option_soft_fpu;
    QEMU_BUILD_BUG_ON(sizeof(((CPUX86State *)0)->fpregs) != 128);
    if (preserve_hard_fxsave) {
        stack_bytes += 128;
    }
#endif

    if (fields->modrm_mod == 3 ||
        fields->modrm_reg != (restore ? 1 : 0)) {
        return 0;
    }

    /* Save the guest GPRs before address formation uses ABI scratch regs. */
    FtSoftEnv fast = {0};
    ft_emit_soft_environment(out, fields, pc, restore, 2, &fast);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (fast.active && ft_emit_x87_fx_fallback(out, fields, pc, restore)) {
        ft_soft_environment_end(out, &fast);
        return *out - start;
    }
#endif

    ft_emit_save_gprs_to_env(out);
    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        return 0;
    }
    offset = ft_mem_access_offset(fields, addr);
    if (!ft_fits_simm12(offset)) {
        return 0;
    }
    if (offset) {
        FT_LA_ADDI_D_EMIT(out, la_a1, addr, offset);
    } else {
        FT_LA_OR_EMIT(out, la_a1, addr, la_zero);
    }

    /* Host calls may clobber every call-clobbered guest mapping. */
    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -stack_bytes);
    FT_LA_ST_D_EMIT(out, la_a1, la_sp, 0);
    if (preserve_hard_fxsave) {
        FT_LA_MOVFCSR2GR_EMIT(out, la_t0, 0);
        FT_LA_ST_W_EMIT(out, la_t0, la_sp, 8);
    }
    ft_emit_host_stack_end(out);

    ft_emit_save_fprs_to_env(out);
    ft_emit_save_xmms_to_env(out);
    ft_emit_save_condition_flags(out);

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (preserve_hard_fxsave) {
        ft_emit_host_stack_begin(out);
        FT_LA_ADDI_D_EMIT(out, la_a1, la_sp, 16);
        ft_emit_host_stack_end(out);
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_latu_fxsave_prepare, 1u << 0);
    } else
#endif
    if (!option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_64_to_x80,
                          1u << 0);
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)update_fp_status, 1u << 0);
    }

    ft_emit_host_stack_begin(out);
    FT_LA_LD_D_EMIT(out, la_a1, la_sp, 0);
    ft_emit_host_stack_end(out);
    if (!restore) {
        int mxcsr_offset = lsenv_offset_of_mxcsr(lsenv);

        if (!ft_fits_simm12(mxcsr_offset)) {
            return 0;
        }
        ft_emit_load_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_LD_WU);
        /* LATU hard mode exports the saved MXCSR, as the old path does. */
        if (!preserve_hard_fxsave) {
            ft_emit_mxcsr_flags_from_fcsr(out, la_t1);
        }
#ifdef CONFIG_SOFTMMU
        /* helper_fxsave performs the guest-memory write through softmmu. */
        ft_emit_store_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_ST_W);
#else
        FT_LA_ST_W_EMIT(out, la_t1, la_a1, 24);
#endif
        if (!preserve_hard_fxsave && !option_soft_fpu &&
            !ft_emit_x87_sync_status_from_fcsr(out)) {
            return 0;
        }
    }
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_host_call(out, restore ? (void *)helper_fxrstor
                                   : (void *)helper_fxsave,
                      1u << 0);

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (restore && option_soft_fpu) {
        ft_emit_load_env(out, la_t1, lsenv_offset_of_mxcsr(lsenv),
                         FT_LA_OPCODE_LD_WU);
        ft_emit_lats_softfpu_mxcsr(out, la_t1);
    }
#endif

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (preserve_hard_fxsave) {
        ft_emit_host_stack_begin(out);
        FT_LA_ADDI_D_EMIT(out, la_a1, la_sp, 16);
        ft_emit_host_stack_end(out);
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_latu_fxsave_finish, 1u << 0);
        ft_emit_host_stack_begin(out);
        FT_LA_LD_WU_EMIT(out, la_t0, la_sp, 8);
        ft_emit_host_stack_end(out);
        FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t0);
        /* The saved FCSR can re-enable LBT TOP mapping. The epilogue must
         * load physical FPR slots first, then restore TOP mapping itself. */
        FT_LA_X86CLRTM_EMIT(out);
    } else
#endif
    if (!option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_x80_to_64,
                          1u << 0);
        if (!ft_emit_x87_reload_control_clear_fcsr(out)) {
            return 0;
        }
    }

    /* Drop the host-stack slot before restoring t0-t7 guest mappings. */
    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, stack_bytes);
    ft_emit_host_stack_end(out);
    ft_emit_x87_helper_epilogue(out);
    ft_soft_environment_end(out, &fast);
    return *out - start;
}

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static int ft_emit_xsave_restore_helper(uint32_t **out,
                                        const FastTemplateFields *fields,
                                        target_ulong pc)
{
    uint32_t *start = *out;
    void *helper;
    int expected_ext;
    int addr;
    int offset;
    int mxcsr_offset;

    switch (fields->kind) {
    case FT_HELPER_XSAVE:
        expected_ext = 4;
        helper = (void *)helper_xsave;
        break;
    case FT_HELPER_XRSTOR:
        expected_ext = 5;
        helper = (void *)helper_xrstor;
        break;
    case FT_HELPER_XSAVEOPT:
        expected_ext = 6;
        helper = (void *)helper_xsaveopt;
        break;
    default:
        return 0;
    }

    if (fields->modrm_mod == 3 || fields->modrm_reg != expected_ext) {
        return 0;
    }

    /* Address formation may use registers that the helper call clobbers. */
    ft_emit_save_gprs_to_env(out);
    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        return 0;
    }
    offset = ft_mem_access_offset(fields, addr);
    if (!ft_fits_simm12(offset)) {
        return 0;
    }
    if (offset) {
        FT_LA_ADDI_D_EMIT(out, la_a1, addr, offset);
    } else {
        FT_LA_OR_EMIT(out, la_a1, addr, la_zero);
    }
    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -16);
    FT_LA_ST_D_EMIT(out, la_a1, la_sp, 0);
    ft_emit_host_stack_end(out);

    ft_emit_save_fprs_to_env(out);
    ft_emit_save_xmms_to_env(out);
    ft_emit_save_condition_flags(out);

    if (!option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_64_to_x80,
                          1u << 0);
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)update_fp_status, 1u << 0);
    }

    mxcsr_offset = lsenv_offset_of_mxcsr(lsenv);
    if (!ft_fits_simm12(mxcsr_offset)) {
        return 0;
    }
    ft_emit_load_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_LD_WU);
    ft_emit_mxcsr_flags_from_fcsr(out, la_t1);
    ft_emit_store_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_ST_W);
    if (!option_soft_fpu && !ft_emit_x87_sync_status_from_fcsr(out)) {
        return 0;
    }

    ft_emit_host_stack_begin(out);
    FT_LA_LD_D_EMIT(out, la_a1, la_sp, 0);
    ft_emit_host_stack_end(out);
    ft_emit_load_env(out, la_a2, lsenv_offset_of_gpr(lsenv, rdx_index),
                     FT_LA_OPCODE_LD_D);
    FT_LA_BSTRPICK_D_EMIT(out, la_a2, la_a2, 31, 0);
    FT_LA_SLLI_D_EMIT(out, la_a2, la_a2, 32);
    ft_emit_load_env(out, la_t0, lsenv_offset_of_gpr(lsenv, rax_index),
                     FT_LA_OPCODE_LD_D);
    FT_LA_BSTRPICK_D_EMIT(out, la_t0, la_t0, 31, 0);
    FT_LA_OR_EMIT(out, la_a2, la_a2, la_t0);

    ft_emit_li64(out, la_t0, pc);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_eip(lsenv),
                      FT_LA_OPCODE_ST_D);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_host_call(out, helper, 1u << 0);

    if (!option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_x80_to_64,
                          1u << 0);
        if (!ft_emit_x87_reload_control_clear_fcsr(out)) {
            return 0;
        }
    }
    ft_emit_load_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_LD_WU);
    ft_emit_fcsr_from_mxcsr(out, la_t1);

    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    ft_emit_host_stack_end(out);
    ft_emit_x87_helper_epilogue(out);
    /* Pure soft-FPU mode keeps x87 state in env. Enabling LBT register
     * mapping here would also remap registers used by native C code. */
    if (fields->kind == FT_HELPER_XRSTOR && option_soft_fpu == 2) {
        if (option_soft_fpu == 2) {
            for (int i = 0; i < 8; i++) {
                ft_emit_load_env(out, ft_mmx(i),
                                 lsenv_offset_of_mmx(lsenv, i),
                                 FT_LA_OPCODE_FLD_D);
            }
        }
        if (!ft_emit_x87_top_load(out)) {
            return 0;
        }
    }
    return *out - start;
}
#endif

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
/* The shared default context saves the same guest registers as the expanded
 * fallback. a2 survives its prologue; consume the address before data32. */
static bool ft_emit_x87_environment_fallback(uint32_t **out,
                                      const FastTemplateFields *fields,
                                      target_ulong pc, bool data32, void *helper)
{
    if (!scs_enabled()) return false;
    uint32_t *start = *out;
    int addr;
    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        *out = start;
        return false;
    }
    int offset = ft_mem_access_offset(fields, addr);
    if (!ft_fits_simm12(offset)) { *out = start; return false; }
    FT_LA_ADDI_D_EMIT(out, la_a2, addr, offset);
    bool context = ft_emit_default_helper_prologue(out, false);
    FT_LA_OR_EMIT(out, la_a1, la_a2, la_zero);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, data32);
    ft_emit_default_helper_call(out, helper,
                                (1u << 0) | (1u << 1), context);
    ft_emit_default_helper_epilogue(out, context, false);
    return true;
}
#endif

static bool ft_emit_x87_latu_fldenv(uint32_t **out,
                                   const FastTemplateFields *f,
                                   target_ulong pc, FtSoftEnv *s, bool regs);

static bool ft_emit_x87_latu_fstenv(uint32_t **out,
                                   const FastTemplateFields *f,
                                   target_ulong pc, FtSoftEnv *s, bool regs);

static int ft_emit_fsave_restore_helper(uint32_t **out,
                                        const FastTemplateFields *fields,
                                        target_ulong pc, bool restore)
{
    uint32_t *start = *out;
    int addr;
    int offset;
    int data32 = fields->prefix2 != dt_X86_PREFIX_OPSIZE;

    if (fields->modrm_mod == 3 ||
        fields->modrm_reg != (restore ? 4 : 6)) {
        return 0;
    }

    FtSoftEnv fast = {0};
    bool latu_direct = restore ? ft_emit_x87_latu_fldenv(out, fields, pc, &fast, true) :
                                 ft_emit_x87_latu_fstenv(out, fields, pc, &fast, true);
    if (!latu_direct) {
        ft_emit_soft_environment(out, fields, pc, restore, 1, &fast);
    }
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (fast.active &&
        ft_emit_x87_environment_fallback(out, fields, pc, data32,
            restore ? (void *)helper_frstor : (void *)helper_fsave)) {
        ft_soft_environment_end(out, &fast);
        return *out - start;
    }
#endif

    ft_emit_save_gprs_to_env(out);
    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        return 0;
    }
    offset = ft_mem_access_offset(fields, addr);
    if (!ft_fits_simm12(offset)) {
        return 0;
    }
    if (offset) {
        FT_LA_ADDI_D_EMIT(out, la_a1, addr, offset);
    } else {
        FT_LA_OR_EMIT(out, la_a1, addr, la_zero);
    }

    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -16);
    FT_LA_ST_D_EMIT(out, la_a1, la_sp, 0);
    ft_emit_host_stack_end(out);

    ft_emit_save_fprs_to_env(out);
    ft_emit_save_xmms_to_env(out);
    ft_emit_save_condition_flags(out);

    if (!option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_64_to_x80,
                          1u << 0);
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)update_fp_status, 1u << 0);
    }

    ft_emit_host_stack_begin(out);
    FT_LA_LD_D_EMIT(out, la_a1, la_sp, 0);
    ft_emit_host_stack_end(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, data32);
    void *save_helper = (void *)helper_fsave;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    /* The old translator has no explicit 14-byte no-tag policy. Keep that
     * format on its existing helper rather than guessing a new tag value.
     */
    if (!restore && data32 && ft_x87_latu_legacy_no_tag()) {
        save_helper = (void *)ft_x87_latu_fsave32_no_tag;
    }
#endif
    ft_emit_host_call(out, restore ? (void *)helper_frstor : save_helper,
                      (1u << 0) | (1u << 1));

#ifdef QUICKTRANS_LATU
    if (option_soft_fpu == 2) {
        ft_emit_load_env(out, la_t0, lsenv_offset_of_control_word(lsenv),
                         FT_LA_OPCODE_LD_HU);
        ft_emit_x87_soft_control(out, true);
    }
#endif

    if (!option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_x80_to_64,
                          1u << 0);
    }

    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    ft_emit_host_stack_end(out);
    ft_emit_x87_helper_epilogue(out);
    ft_soft_environment_end(out, &fast);
    return *out - start;
}

/* Export the same fields and zero pointer slots as the LATU soft helper. */
static bool ft_emit_x87_latu_fstenv(uint32_t **out,
                                   const FastTemplateFields *f,
                                   target_ulong pc, FtSoftEnv *s, bool regs)
{
#ifdef QUICKTRANS_LATU
    int addr;
    bool data32 = f->prefix2 != dt_X86_PREFIX_OPSIZE;
    uint32_t *start = *out;
    if (option_soft_fpu != 2) return false;
    if (regs && lsenv_offset_of_fpr(lsenv, 1) -
                lsenv_offset_of_fpr(lsenv, 0) != 16) return false;
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) {
        *out = start;
        return false;
    }
    FT_LA_ADDI_D_EMIT(out, la_t4, addr, ft_mem_access_offset(f, addr));
    FT_LA_ANDI_EMIT(out, la_t0, la_t4, 4095);
    ft_emit_li32(out, la_t1, 4096 - (data32 ? 28 : 14) - (regs ? 80 : 0));
    ft_emit_branch_placeholder(out, &s->guard[s->count++], FT_BRANCH_BLTU,
                               la_t1, la_t0, &s->slow);
    FT_LA_LD_HU_EMIT(out, la_a0, la_s8, lsenv_offset_of_control_word(lsenv));
    FT_LA_LD_HU_EMIT(out, la_a1, la_s8, lsenv_offset_of_status_word(lsenv));
    FT_LA_LD_WU_EMIT(out, la_t0, la_s8, lsenv_offset_of_top(lsenv));
    FT_LA_BSTRINS_W_EMIT(out, la_a1, la_t0, 13, 11);
    ft_soft_env_tags(out, false);
    if (data32) {
        FT_LA_ST_W_EMIT(out, la_a0, la_t4, 0);
        FT_LA_ST_W_EMIT(out, la_a1, la_t4, 4);
        FT_LA_ST_W_EMIT(out, la_t0, la_t4, 8);
        for (int i = 12; i < 28; i += 4) FT_LA_ST_W_EMIT(out, la_zero, la_t4, i);
    } else {
        FT_LA_ST_H_EMIT(out, la_a0, la_t4, 0);
        FT_LA_ST_H_EMIT(out, la_a1, la_t4, 2);
        FT_LA_ST_H_EMIT(out, la_t0, la_t4, 4);
        for (int i = 6; i < 14; i += 2) FT_LA_ST_H_EMIT(out, la_zero, la_t4, i);
    }
    if (regs) {
        /* The image contains logical ST0..ST7, not physical slot order. */
        FT_LA_LD_WU_EMIT(out, la_t2, la_s8, lsenv_offset_of_top(lsenv));
        for (int i = 0; i < 8; ++i) {
            FT_LA_ANDI_EMIT(out, la_t2, la_t2, 7);
            FT_LA_SLLI_D_EMIT(out, la_t3, la_t2, 4);
            FT_LA_ADD_D_EMIT(out, la_t3, la_s8, la_t3);
            FT_LA_LD_D_EMIT(out, la_t0, la_t3, lsenv_offset_of_fpr(lsenv, 0));
            FT_LA_LD_HU_EMIT(out, la_t1, la_t3, lsenv_offset_of_fpr(lsenv, 0) + 8);
            FT_LA_ST_D_EMIT(out, la_t0, la_t4, (data32 ? 28 : 14) + i * 10);
            FT_LA_ST_H_EMIT(out, la_t1, la_t4, (data32 ? 28 : 14) + i * 10 + 8);
            FT_LA_ADDI_W_EMIT(out, la_t2, la_t2, 1);
        }
        /* Reset only after the complete image has been written. */
        FT_LA_ORI_EMIT(out, la_t0, la_zero, 0x37f);
        ft_emit_store_env(out, la_t0, lsenv_offset_of_control_word(lsenv), FT_LA_OPCODE_ST_H);
        ft_emit_x87_soft_control(out, true);
        ft_emit_store_env(out, la_zero, lsenv_offset_of_status_word(lsenv), FT_LA_OPCODE_ST_H);
        ft_emit_store_env(out, la_zero, lsenv_offset_of_top(lsenv), FT_LA_OPCODE_ST_W);
        ft_emit_li64(out, la_t0, 0x0101010101010101ULL);
        ft_emit_store_env(out, la_t0, lsenv_offset_of_tag_word(lsenv), FT_LA_OPCODE_ST_D);
    }
    ft_emit_branch_placeholder(out, &s->finish, FT_BRANCH_B, 0, 0, &s->done);
    ft_bind_branch_label(&s->slow, *out);
    ft_resolve_branch_fixup(&s->guard[0]);
    s->active = true;
    return true;
#else
    (void)out; (void)f; (void)pc; (void)s; (void)regs;
    return false;
#endif
}

/* Same-page mode-2 FLDENV: preserve the helper for partial-access faults. */
static bool ft_emit_x87_latu_fldenv(uint32_t **out,
                                   const FastTemplateFields *f,
                                   target_ulong pc, FtSoftEnv *s, bool regs)
{
#ifdef QUICKTRANS_LATU
    int addr;
    bool data32 = f->prefix2 != dt_X86_PREFIX_OPSIZE;
    uint32_t *start = *out;
    if (option_soft_fpu != 2) return false;
    if (regs && lsenv_offset_of_fpr(lsenv, 1) -
                lsenv_offset_of_fpr(lsenv, 0) != 16) return false;
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) {
        *out = start;
        return false;
    }
    FT_LA_ADDI_D_EMIT(out, la_t4, addr, ft_mem_access_offset(f, addr));
    FT_LA_ANDI_EMIT(out, la_t0, la_t4, 4095);
    int bytes = regs ? (data32 ? 108 : 94) : (data32 ? 10 : 6);
    ft_emit_li32(out, la_t1, 4096 - bytes);
    ft_emit_branch_placeholder(out, &s->guard[s->count++], FT_BRANCH_BLTU,
                               la_t1, la_t0, &s->slow);
    /* These three reads cover exactly the fields consumed by do_fldenv. */
    FT_LA_LD_HU_EMIT(out, la_t0, la_t4, 0);
    FT_LA_LD_HU_EMIT(out, la_a1, la_t4, data32 ? 4 : 2);
    FT_LA_LD_HU_EMIT(out, la_a0, la_t4, data32 ? 8 : 4);
    ft_emit_store_env(out, la_t0, lsenv_offset_of_control_word(lsenv),
                      FT_LA_OPCODE_ST_H);
    ft_emit_x87_soft_control(out, true);
    FT_LA_BSTRPICK_W_EMIT(out, la_t1, la_a1, 13, 11);
    ft_emit_store_env(out, la_t1, lsenv_offset_of_top(lsenv), FT_LA_OPCODE_ST_W);
    ft_emit_li32(out, la_t1, 0x47ff);
    FT_LA_AND_EMIT(out, la_a1, la_a1, la_t1);
    FT_LA_BSTRPICK_W_EMIT(out, la_t1, la_a1, 7, 7);
    FT_LA_BSTRINS_W_EMIT(out, la_a1, la_t1, 15, 15);
    FT_LA_ANDN_EMIT(out, la_t1, la_a1, la_t0);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 0x3f);
    FT_LA_SLTU_EMIT(out, la_t1, la_zero, la_t1);
    FT_LA_SLLI_W_EMIT(out, la_t2, la_t1, 8);
    FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);
    FT_LA_SLLI_W_EMIT(out, la_t1, la_t1, 7);
    FT_LA_OR_EMIT(out, la_a1, la_a1, la_t1);
    ft_emit_store_env(out, la_a1, lsenv_offset_of_status_word(lsenv),
                      FT_LA_OPCODE_ST_H);
    FT_LA_OR_EMIT(out, la_t3, la_zero, la_zero);
    for (int i = 0; i < 8; ++i) {
        FT_LA_BSTRPICK_W_EMIT(out, la_t1, la_a0, i * 2 + 1, i * 2);
        FT_LA_XORI_EMIT(out, la_t1, la_t1, 3);
        FT_LA_SLTUI_EMIT(out, la_t1, la_t1, 1);
        if (i) FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, i * 8);
        FT_LA_OR_EMIT(out, la_t3, la_t3, la_t1);
    }
    ft_emit_store_env(out, la_t3, lsenv_offset_of_tag_word(lsenv),
                      FT_LA_OPCODE_ST_D);
    if (regs) {
        /* FRSTOR stores logical ST(i) in (TOP + i) & 7, like its helper. */
        FT_LA_LD_WU_EMIT(out, la_t2, la_s8, lsenv_offset_of_top(lsenv));
        for (int i = 0; i < 8; ++i) {
            FT_LA_ANDI_EMIT(out, la_t2, la_t2, 7);
            FT_LA_SLLI_D_EMIT(out, la_t3, la_t2, 4);
            FT_LA_ADD_D_EMIT(out, la_t3, la_s8, la_t3);
            FT_LA_LD_D_EMIT(out, la_t0, la_t4, (data32 ? 28 : 14) + i * 10);
            FT_LA_LD_HU_EMIT(out, la_t1, la_t4, (data32 ? 28 : 14) + i * 10 + 8);
            FT_LA_ST_D_EMIT(out, la_t0, la_t3, lsenv_offset_of_fpr(lsenv, 0));
            FT_LA_ST_H_EMIT(out, la_t1, la_t3, lsenv_offset_of_fpr(lsenv, 0) + 8);
            FT_LA_ADDI_W_EMIT(out, la_t2, la_t2, 1);
        }
    }
    ft_emit_branch_placeholder(out, &s->finish, FT_BRANCH_B, 0, 0, &s->done);
    ft_bind_branch_label(&s->slow, *out);
    ft_resolve_branch_fixup(&s->guard[0]);
    s->active = true;
    return true;
#else
    (void)out; (void)f; (void)pc; (void)s; (void)regs;
    return false;
#endif
}

static int ft_emit_fenv_helper(uint32_t **out,
                               const FastTemplateFields *fields,
                               target_ulong pc, bool restore)
{
    uint32_t *start = *out;
    int addr;
    int offset;
    int data32 = fields->prefix2 != dt_X86_PREFIX_OPSIZE;
    bool preserve_hard_regs = false;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    preserve_hard_regs = !restore && !option_soft_fpu;
#endif

    if (fields->modrm_mod == 3 ||
        fields->modrm_reg != (restore ? 4 : 6)) {
        return 0;
    }

    FtSoftEnv fast = {0};
    bool latu_direct = restore ? ft_emit_x87_latu_fldenv(out, fields, pc, &fast, false) :
                                 ft_emit_x87_latu_fstenv(out, fields, pc, &fast, false);
    if (!latu_direct) {
        ft_emit_soft_environment(out, fields, pc, restore, 0, &fast);
    }
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (fast.active &&
        ft_emit_x87_environment_fallback(out, fields, pc, data32,
            restore ? (void *)helper_fldenv : (void *)helper_fstenv)) {
        ft_soft_environment_end(out, &fast);
        return *out - start;
    }
#endif

    ft_emit_save_gprs_to_env(out);
    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        return 0;
    }
    offset = ft_mem_access_offset(fields, addr);
    if (!ft_fits_simm12(offset)) {
        return 0;
    }
    if (offset) {
        FT_LA_ADDI_D_EMIT(out, la_a1, addr, offset);
    } else {
        FT_LA_OR_EMIT(out, la_a1, addr, la_zero);
    }

    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -16);
    FT_LA_ST_D_EMIT(out, la_a1, la_sp, 0);
    ft_emit_host_stack_end(out);

    ft_emit_save_fprs_to_env(out);
    ft_emit_save_xmms_to_env(out);
    ft_emit_save_condition_flags(out);
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_X87_SIGNAL_ABI)
    /* This custom prologue has the same complete guest snapshot as the
     * generic helper prologue. A fault inside C must not restore its scratch
     * registers as guest GPRs (in particular RSP). */
    if (!option_soft_fpu) {
        FT_LA_MOVFCSR2GR_EMIT(out, la_t0, 0);
        ft_emit_store_env(out, la_t0, lsenv_offset_of_fcsr(lsenv),
                          FT_LA_OPCODE_ST_W);
    }
    FT_LA_ORI_EMIT(out, la_t0, la_zero, 1);
    ft_emit_store_env(out, la_t0, offsetof(CPUX86State, qt_helper_env_saved),
                      FT_LA_OPCODE_ST_B);
#endif

    if (!restore && !option_soft_fpu) {
        if (!preserve_hard_regs) {
            ft_emit_cpu_env_ptr(out, la_a0);
            ft_emit_host_call(out, (void *)ft_convert_fpregs_64_to_x80,
                              1u << 0);
        }
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)update_fp_status, 1u << 0);
        if (!ft_emit_x87_sync_status_from_fcsr(out)) {
            return 0;
        }
    }

    ft_emit_host_stack_begin(out);
    FT_LA_LD_D_EMIT(out, la_a1, la_sp, 0);
    ft_emit_host_stack_end(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, data32);
    void *save_helper = (void *)helper_fstenv;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (preserve_hard_regs) {
        save_helper = (void *)ft_x87_latu_fstenv_hard;
    } else if (!restore && data32 && ft_x87_latu_legacy_no_tag()) {
        save_helper = (void *)ft_x87_latu_fstenv32_no_tag;
    }
#endif
    ft_emit_host_call(out, restore ? (void *)helper_fldenv : save_helper,
                      (1u << 0) | (1u << 1));

#ifdef QUICKTRANS_LATU
    if (restore && option_soft_fpu == 2) {
        /* A successful cross-page helper must establish the same fast
         * arithmetic rounding state as the direct same-page path. */
        ft_emit_load_env(out, la_t0, lsenv_offset_of_control_word(lsenv),
                         FT_LA_OPCODE_LD_HU);
        ft_emit_x87_soft_control(out, true);
    }
#endif
    if (!option_soft_fpu) {
        if (restore) {
            if (!ft_emit_x87_reload_control_status_fcsr(out)) {
                return 0;
            }
        } else {
            int fpuc_offset = lsenv_offset_of_control_word(lsenv);

            if (!ft_offset_fits_imm12(fpuc_offset)) {
                return 0;
            }
            ft_emit_load_env(out, la_t0, fpuc_offset, FT_LA_OPCODE_LD_HU);
            FT_LA_ORI_EMIT(out, la_t0, la_t0, X87_CR_EXCP_MASK);
            ft_emit_store_env(out, la_t0, fpuc_offset, FT_LA_OPCODE_ST_H);
            ft_emit_x87_update_fcsr_by_cw(out, la_t0);

            if (!preserve_hard_regs) {
                ft_emit_cpu_env_ptr(out, la_a0);
                ft_emit_host_call(out, (void *)ft_convert_fpregs_x80_to_64,
                                  1u << 0);
            }
        }
    }

    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    ft_emit_host_stack_end(out);
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_X87_SIGNAL_ABI)
    if (option_soft_fpu) {
        ft_emit_store_env(out, la_zero,
                          offsetof(CPUX86State, qt_helper_env_saved),
                          FT_LA_OPCODE_ST_B);
    }
#endif
    ft_emit_x87_helper_epilogue(out);
    ft_soft_environment_end(out, &fast);
    return *out - start;
}

static void ft_emit_x87_hard_helper(uint32_t **out, void *func)
{
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_host_call(out, func, 1u << 0);
    ft_emit_x87_helper_epilogue(out);
}

static bool ft_x87_const_bits(unsigned int id, uint64_t *bits)
{
    switch (id) {
    case dt_X86_INS_FLDL2T:
        *bits = 0x400a934f0979a371ULL;
        return true;
    case dt_X86_INS_FLDL2E:
        *bits = 0x3ff71547652b82feULL;
        return true;
    case dt_X86_INS_FLDPI:
        *bits = 0x400921fb54442d18ULL;
        return true;
    case dt_X86_INS_FLDLG2:
        *bits = 0x3fd34413509f79ffULL;
        return true;
    case dt_X86_INS_FLDLN2:
        *bits = 0x3fe62e42fefa39efULL;
        return true;
    case dt_X86_INS_FLDZ:
        *bits = 0;
        return true;
    default:
        return false;
    }
}

static void ft_emit_x87_soft_sign(uint32_t **out, bool negate)
{
#ifdef QUICKTRANS_LATU
    FastBranchLabel slow = {0}, done = {0};
    FastBranchFixup empty_fix, done_fix;
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    int tag = lsenv_offset_of_tag_word(lsenv);
    bool direct_sign = option_soft_fpu == 2 &&
                       ft_offset_fits_imm12(fp + 8) &&
                       ft_offset_fits_imm12(tag);
    if (direct_sign) {
        ft_emit_load_env(out, la_t0, lsenv_offset_of_top(lsenv),
                         FT_LA_OPCODE_LD_WU);
        ft_emit_cpu_env_ptr(out, la_t3);
        FT_LA_ADD_D_EMIT(out, la_t1, la_t3, la_t0);
        FT_LA_LD_BU_EMIT(out, la_t2, la_t1, tag);
        /* Keep Quicktrans's empty-stack handling instead of copying the
         * legacy unchecked sign update for an empty slot. */
        ft_emit_branch_placeholder(out, &empty_fix, FT_BRANCH_BNE,
                                   la_t2, la_zero, &slow);
        FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t1, la_t3, la_t0);
        FT_LA_LD_HU_EMIT(out, la_t2, la_t1, fp + 8);
        if (negate) {
            FT_LA_LU12I_W_EMIT(out, la_t0, 8);
            FT_LA_XOR_EMIT(out, la_t2, la_t2, la_t0);
        } else {
            FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t2, 14, 0);
        }
        FT_LA_ST_H_EMIT(out, la_t2, la_t1, fp + 8);
        ft_emit_branch_placeholder(out, &done_fix, FT_BRANCH_B, 0, 0, &done);
        ft_bind_branch_label(&slow, *out);
        ft_resolve_branch_fixup(&empty_fix);
    }
#elif defined(CONFIG_SOFTMMU)
    bool inline_sign = option_soft_fpu_fast &&
        ft_offset_fits_imm12(lsenv_offset_of_top(lsenv)) &&
        ft_offset_fits_imm12(lsenv_offset_of_fpr(lsenv, 0) + 8);

    if (inline_sign) {
        /* Match the legacy fast path: change only the floatx80 sign bit. */
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_top(lsenv));
        FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t1, la_s0, la_t0);
        FT_LA_LD_HU_EMIT(out, la_t2, la_t1,
                         lsenv_offset_of_fpr(lsenv, 0) + 8);
        if (negate) {
            FT_LA_LU12I_W_EMIT(out, la_t0, 8);
            FT_LA_XOR_EMIT(out, la_t2, la_t2, la_t0);
        } else {
            FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t2, 14, 0);
        }
        FT_LA_ST_H_EMIT(out, la_t2, la_t1,
                        lsenv_offset_of_fpr(lsenv, 0) + 8);
        return;
    }
#endif
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, negate);
    ft_emit_host_call(out, (void *)ft_x87_helper_unary, 1u << 0);
    ft_emit_x87_helper_epilogue(out);
#ifdef QUICKTRANS_LATU
    if (direct_sign) {
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&done_fix);
    }
#endif
}

/* LATS fast mode deliberately follows the legacy translator's unchecked
 * float64 arithmetic. Empty-stack/special-value status handling belongs to
 * the software helpers selected when the corresponding fast bit is off.
 * LATU keeps its existing empty-stack helper check when fast bits are on. */
static void ft_emit_x87_soft_unary(uint32_t **out, bool square_root)
{
#ifdef QUICKTRANS_LATU
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    const int top = lsenv_offset_of_top(lsenv);
    const int tag = lsenv_offset_of_tag_word(lsenv);
    if (option_soft_fpu == 2 &&
        (option_softfpu_fast & (square_root ? 0x10000 : 0x4000)) &&
        ft_offset_fits_imm12(fp + 8) && ft_offset_fits_imm12(tag)) {
        FastBranchLabel slow = {0}, done = {0};
        FastBranchFixup empty, finish;
        const int x = ft_vscratch, tmp = ft_vscratch + 1;
        ft_emit_load_env(out, la_t0, top, FT_LA_OPCODE_LD_WU);
        ft_emit_cpu_env_ptr(out, la_t4);
        FT_LA_ADD_D_EMIT(out, la_t1, la_t4, la_t0);
        FT_LA_LD_BU_EMIT(out, la_t1, la_t1, tag);
        ft_emit_branch_placeholder(out, &empty, FT_BRANCH_BNE,
                                   la_t1, la_zero, &slow);
        FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t0, la_t4, la_t0);
        /* Explicit fast bits select the legacy float64 approximation.
         * Do not discard the existing empty-stack helper semantics. */
        FT_LA_VLD_EMIT(out, x, la_t0, fp);
        FT_LA_VEXTRINS_H_EMIT(out, tmp, x, 0x4);
        FT_LA_FCVT_D_LD_EMIT(out, x, x, tmp);
        if (square_root) {
            FT_LA_FSQRT_D_EMIT(out, x, x);
        } else {
            FT_LA_FRINT_D_EMIT(out, x, x);
        }
        FT_LA_FCVT_UD_D_EMIT(out, tmp, x);
        FT_LA_FCVT_LD_D_EMIT(out, x, x);
        FT_LA_VEXTRINS_H_EMIT(out, x, tmp, 0x40);
        FT_LA_VST_EMIT(out, x, la_t0, fp);
        ft_emit_branch_placeholder(out, &finish, FT_BRANCH_B, 0, 0, &done);
        ft_bind_branch_label(&slow, *out);
        ft_resolve_branch_fixup(&empty);
        ft_emit_x87_helper(out, square_root ? (void *)ft_x87_helper_fsqrt :
                                              (void *)ft_x87_helper_frndint);
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&finish);
        return;
    }
#endif
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    const int top = lsenv_offset_of_top(lsenv);
    bool fast = (option_soft_fpu_fast & (square_root ? 0x10000 : 0x4000)) &&
        ft_offset_fits_imm12(fp + 8) && ft_offset_fits_imm12(top);
    if (fast) {
        const int x = ft_vscratch, tmp = ft_vscratch + 1;
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, top);
        FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t0, la_s0, la_t0);
        /* Same floatx80 -> double -> floatx80 tradeoff as la_calcute_float64.
         * The fast option deliberately does not check rounding per operation. */
        FT_LA_VLD_EMIT(out, x, la_t0, fp);
        FT_LA_VEXTRINS_H_EMIT(out, tmp, x, 0x4);
        FT_LA_FCVT_D_LD_EMIT(out, x, x, tmp);
        if (square_root) {
            FT_LA_FSQRT_D_EMIT(out, x, x);
        } else {
            FT_LA_FRINT_D_EMIT(out, x, x);
        }
        FT_LA_FCVT_UD_D_EMIT(out, tmp, x);
        FT_LA_FCVT_LD_D_EMIT(out, x, x);
        FT_LA_VEXTRINS_H_EMIT(out, x, tmp, 0x40);
        FT_LA_VST_EMIT(out, x, la_t0, fp);
        return;
    }
#endif
    ft_emit_x87_helper(out, square_root ? (void *)ft_x87_helper_fsqrt :
                                          (void *)ft_x87_helper_frndint);
}

/* Like the legacy softfpu_fast option, direct arithmetic assumes host
 * rounding is suitable. Independent x87/SSE rounding after restore is a
 * known limitation when enabled; disabled mode retains software helpers. */
static void ft_emit_x87_soft_binary_reg(uint32_t **out, int index,
                                       int op, int mode)
{
    void *helper = op == FT_X87_REG_SCALE ? (void *)ft_x87_helper_fscale :
                                           (void *)ft_x87_binary_helpers[mode][op];
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    static const unsigned masks[2][6] = {
        { 0x2, 0x1000, 0x20000, 0x80000, 0x4, 0x10 },
        { 0x1, 0x2000, 0x40000, 0x100000, 0x8, 0x20 },
    };
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    const int top = lsenv_offset_of_top(lsenv);
#ifdef QUICKTRANS_LATU
    const int env_reg = la_s8;
    const unsigned fast_options = option_soft_fpu == 2 ? option_softfpu_fast : 0;
#else
    const int env_reg = la_s0;
    const unsigned fast_options = option_soft_fpu_fast;
#endif
    bool fast = (fast_options & (op == FT_X87_REG_SCALE ? 0x8000 :
                                masks[mode == 2][op])) &&
        ft_offset_fits_imm12(fp + 8) && ft_offset_fits_imm12(top) &&
        (mode != 2 || ft_offset_fits_imm12(lsenv_offset_of_tag_word(lsenv)));
#ifdef QUICKTRANS_LATU
    fast = fast && ft_offset_fits_imm12(lsenv_offset_of_tag_word(lsenv));
#endif
    if (fast) {
        const int x = ft_vscratch, y = ft_vscratch + 1;
        const int tmp = ft_vscratch + 2;
        FT_LA_LD_W_EMIT(out, la_t0, env_reg, top);
        FT_LA_ADDI_D_EMIT(out, la_t1, la_t0, index);
        FT_LA_ANDI_EMIT(out, la_t1, la_t1, 7);
#ifdef QUICKTRANS_LATU
        FastBranchLabel slow = {0}, done = {0};
        FastBranchFixup guards[2], finish;
        const int tag = lsenv_offset_of_tag_word(lsenv);
        FT_LA_ADD_D_EMIT(out, la_t2, env_reg, la_t0);
        FT_LA_LD_BU_EMIT(out, la_t2, la_t2, tag);
        ft_emit_branch_placeholder(out, &guards[0], FT_BRANCH_BNE,
                                   la_t2, la_zero, &slow);
        FT_LA_ADD_D_EMIT(out, la_t2, env_reg, la_t1);
        FT_LA_LD_BU_EMIT(out, la_t2, la_t2, tag);
        ft_emit_branch_placeholder(out, &guards[1], FT_BRANCH_BNE,
                                   la_t2, la_zero, &slow);
#endif
        FT_LA_SLLI_D_EMIT(out, la_t4, la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t4, env_reg, la_t4);
        FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 4);
        FT_LA_ADD_D_EMIT(out, la_t1, env_reg, la_t1);
        int dst = mode ? la_t1 : la_t4;
        int src = mode ? la_t4 : la_t1;
        FT_LA_VLD_EMIT(out, x, dst, fp);
        FT_LA_VLD_EMIT(out, y, src, fp);
        FT_LA_VEXTRINS_H_EMIT(out, tmp, x, 0x4);
        FT_LA_FCVT_D_LD_EMIT(out, x, x, tmp);
        FT_LA_VEXTRINS_H_EMIT(out, tmp, y, 0x4);
        FT_LA_FCVT_D_LD_EMIT(out, y, y, tmp);
        switch (op) {
        case FT_X87_REG_ADD: FT_LA_FADD_D_EMIT(out, x, x, y); break;
        case FT_X87_REG_MUL: FT_LA_FMUL_D_EMIT(out, x, x, y); break;
        case FT_X87_REG_SUB: FT_LA_FSUB_D_EMIT(out, x, x, y); break;
        case FT_X87_REG_SUBR: FT_LA_FSUB_D_EMIT(out, x, y, x); break;
        case FT_X87_REG_DIV: FT_LA_FDIV_D_EMIT(out, x, x, y); break;
        case FT_X87_REG_DIVR: FT_LA_FDIV_D_EMIT(out, x, y, x); break;
        case FT_X87_REG_SCALE:
            FT_LA_FTINTRZ_L_D_EMIT(out, tmp, y);
            FT_LA_FSCALEB_D_EMIT(out, x, x, tmp);
            break;
        }
        FT_LA_FCVT_UD_D_EMIT(out, tmp, x);
        FT_LA_FCVT_LD_D_EMIT(out, x, x);
        FT_LA_VEXTRINS_H_EMIT(out, x, tmp, 0x40);
        FT_LA_VST_EMIT(out, x, dst, fp);
        if (mode == 2) {
            FT_LA_ADD_D_EMIT(out, la_t2, env_reg, la_t0);
            FT_LA_ORI_EMIT(out, la_t1, la_zero, 1);
            FT_LA_ST_B_EMIT(out, la_t1, la_t2, lsenv_offset_of_tag_word(lsenv));
            FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, 1);
            FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
            FT_LA_ST_W_EMIT(out, la_t0, env_reg, top);
        }
#ifdef QUICKTRANS_LATU
        ft_emit_branch_placeholder(out, &finish, FT_BRANCH_B, 0, 0, &done);
        ft_bind_branch_label(&slow, *out);
        ft_resolve_branch_fixup(&guards[0]);
        ft_resolve_branch_fixup(&guards[1]);
        ft_emit_helper_prologue(out);
        ft_emit_cpu_env_ptr(out, la_a0);
        if (op != FT_X87_REG_SCALE) FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, index);
        ft_emit_host_call(out, helper, 1u << 0);
        ft_emit_x87_helper_epilogue(out);
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&finish);
#endif
        return;
    }
#endif
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    if (op != FT_X87_REG_SCALE) FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, index);
    ft_emit_host_call(out, helper, 1u << 0);
    ft_emit_x87_helper_epilogue(out);
}

/* Match gen_float64_ST0_MEM in the LATS soft-fpu translator. */
static bool ft_emit_x87_soft_binary_mem(uint32_t **out,
                                      const FastTemplateFields *fields,
                                      target_ulong pc, int width,
                                      bool integer, int op)
{
    static void *const helpers[8] = {
        (void *)ft_x87_memory_fadd, (void *)ft_x87_memory_fmul,
        NULL, NULL, (void *)ft_x87_memory_fsub,
        (void *)ft_x87_memory_fsubr, (void *)ft_x87_memory_fdiv,
        (void *)ft_x87_memory_fdivr,
    };
    int addr;
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    static const unsigned masks[2][8] = {
        { 0x2, 0x1000, 0, 0, 0x20000, 0x80000, 0x4, 0x10 },
        { 0x40, 0x200, 0, 0, 0x400, 0x800, 0x80, 0x100 },
    };
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    const int top = lsenv_offset_of_top(lsenv);
#ifdef QUICKTRANS_LATU
    const int env_reg = la_s8;
    const unsigned fast_options = option_soft_fpu == 2 ? option_softfpu_fast : 0;
    FastBranchLabel slow = {0}, done = {0};
    FastBranchFixup empty, finish;
#else
    const int env_reg = la_s0;
    const unsigned fast_options = option_soft_fpu_fast;
#endif
    bool fast = (fast_options & masks[integer][op]) &&
        ft_offset_fits_imm12(fp + 8) && ft_offset_fits_imm12(top);
#ifdef QUICKTRANS_LATU
    fast = fast && ft_offset_fits_imm12(lsenv_offset_of_tag_word(lsenv));
#endif
    if (fast) {
        const int x = ft_vscratch, y = ft_vscratch + 1;
        const int tmp = ft_vscratch + 2;
#ifdef QUICKTRANS_LATU
        /* Checking a tag has no architectural effect. The helper fallback
         * still performs its guest read before its stack-fault handling. */
        FT_LA_LD_WU_EMIT(out, la_t0, env_reg, top);
        FT_LA_ADD_D_EMIT(out, la_t4, env_reg, la_t0);
        FT_LA_LD_BU_EMIT(out, la_t4, la_t4, lsenv_offset_of_tag_word(lsenv));
        ft_emit_branch_placeholder(out, &empty, FT_BRANCH_BNE,
                                   la_t4, la_zero, &slow);
#endif
        /* Match the legacy fast mode: load once and calculate directly. */
        if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
            return false;
        }
        int offset = ft_mem_access_offset(fields, addr);
        if (width == 16) {
            FT_LA_LD_H_EMIT(out, la_t4, addr, offset);
        } else if (width == 32) {
            FT_LA_LD_W_EMIT(out, la_t4, addr, offset);
        } else {
            FT_LA_LD_D_EMIT(out, la_t4, addr, offset);
        }
        FT_LA_MOVGR2FR_D_EMIT(out, y, la_t4);
        FT_LA_LD_W_EMIT(out, la_t0, env_reg, top);
        FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t0, env_reg, la_t0);
        if (integer) {
            FT_LA_FFINT_D_W_EMIT(out, y, y);
        } else if (width == 32) {
            FT_LA_FCVT_D_S_EMIT(out, y, y);
        }
        FT_LA_VLD_EMIT(out, x, la_t0, fp);
        FT_LA_VEXTRINS_H_EMIT(out, tmp, x, 0x4);
        FT_LA_FCVT_D_LD_EMIT(out, x, x, tmp);
        switch (op) {
        case 0: FT_LA_FADD_D_EMIT(out, x, x, y); break;
        case 1: FT_LA_FMUL_D_EMIT(out, x, x, y); break;
        case 4: FT_LA_FSUB_D_EMIT(out, x, x, y); break;
        case 5: FT_LA_FSUB_D_EMIT(out, x, y, x); break;
        case 6: FT_LA_FDIV_D_EMIT(out, x, x, y); break;
        case 7: FT_LA_FDIV_D_EMIT(out, x, y, x); break;
        }
        FT_LA_FCVT_UD_D_EMIT(out, tmp, x);
        FT_LA_FCVT_LD_D_EMIT(out, x, x);
        FT_LA_VEXTRINS_H_EMIT(out, x, tmp, 0x40);
        FT_LA_VST_EMIT(out, x, la_t0, fp);
#ifdef QUICKTRANS_LATU
        ft_emit_branch_placeholder(out, &finish, FT_BRANCH_B, 0, 0, &done);
        ft_bind_branch_label(&slow, *out);
        ft_resolve_branch_fixup(&empty);
#else
        return true;
#endif
    }
#endif
    ft_emit_helper_prologue(out);
    {
        if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
            return false;
        }
        int offset = ft_mem_access_offset(fields, addr);
        if (width == 16) {
            FT_LA_LD_H_EMIT(out, la_a1, addr, offset);
        } else if (integer) {
            FT_LA_LD_W_EMIT(out, la_a1, addr, offset);
        } else if (width == 32) {
            FT_LA_LD_WU_EMIT(out, la_a1, addr, offset);
        } else {
            FT_LA_LD_D_EMIT(out, la_a1, addr, offset);
        }
    }
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_host_call(out, integer ? (void *)helper_fildl_FT0 :
                      width == 32 ? (void *)ft_x87_memory_flds :
                      (void *)ft_x87_memory_fldl, 1u << 0);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_host_call(out, helpers[op], 1u << 0);
    ft_emit_x87_helper_epilogue(out);
#ifdef QUICKTRANS_LATU
    if (fast) {
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&finish);
    }
#endif
    return true;
}

/* Inline mode-2 constants, retaining checked overflow handling. */
/* Exact mode-2 loads; exceptional floats and large int64 use helpers. */
static bool ft_emit_x87_latu_soft_load(uint32_t **out,
                                     const FastTemplateFields *f,
                                     target_ulong pc)
{
#ifdef QUICKTRANS_LATU
    int width = 0, addr;
    bool integer = f->kind != FT_X87_FLD_M32 && f->kind != FT_X87_FLD_M64;
    int top = lsenv_offset_of_top(lsenv);
    int tag = lsenv_offset_of_tag_word(lsenv);
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    FastBranchLabel slow = {0}, done = {0};
    FastBranchFixup guards[2], finish;
    unsigned count = 0;

    if (option_soft_fpu != 2 || f->modrm_mod == 3 ||
        (integer && !ft_x87_fild_width(f->kind, &width)) ||
        !ft_offset_fits_imm12(tag) || !ft_offset_fits_imm12(fp) ||
        !ft_emit_rip_or_mem_addr(out, f, pc, &addr)) {
        return false;
    }
    if (!integer) width = f->kind == FT_X87_FLD_M32 ? 32 : 64;
    /* a1 is not a LATU guest GPR and survives the inline helper prologue. */
    int offset = ft_mem_access_offset(f, addr);
    if (width == 16) FT_LA_LD_H_EMIT(out, la_a1, addr, offset);
    else if (width == 32) FT_LA_LD_W_EMIT(out, la_a1, addr, offset);
    else FT_LA_LD_D_EMIT(out, la_a1, addr, offset);
    if (!integer) {
        FT_LA_BSTRPICK_D_EMIT(out, la_t0, la_a1, width == 32 ? 30 : 62,
                             width == 32 ? 23 : 52);
        ft_emit_branch_placeholder(out, &guards[count++], FT_BRANCH_BEQ,
                                   la_t0, la_zero, &slow);
        FT_LA_XORI_EMIT(out, la_t0, la_t0, width == 32 ? 0xff : 0x7ff);
        ft_emit_branch_placeholder(out, &guards[count++], FT_BRANCH_BEQ,
                                   la_t0, la_zero, &slow);
    } else if (width == 64) {
        FT_LA_SRAI_D_EMIT(out, la_t0, la_a1, 63);
        FT_LA_XOR_EMIT(out, la_t1, la_a1, la_t0);
        FT_LA_SUB_D_EMIT(out, la_t1, la_t1, la_t0);
        FT_LA_SRLI_D_EMIT(out, la_t1, la_t1, 52);
        ft_emit_branch_placeholder(out, &guards[count++], FT_BRANCH_BNE,
                                   la_t1, la_zero, &slow);
    }
    FT_LA_MOVGR2FR_D_EMIT(out, ft_vscratch, la_a1);
    if (integer) {
        if (width == 64) FT_LA_FFINT_D_L_EMIT(out, ft_vscratch, ft_vscratch);
        else FT_LA_FFINT_D_W_EMIT(out, ft_vscratch, ft_vscratch);
    } else if (width == 32) {
        FT_LA_FCVT_D_S_EMIT(out, ft_vscratch, ft_vscratch);
    }
    FT_LA_FCVT_UD_D_EMIT(out, ft_vscratch + 1, ft_vscratch);
    FT_LA_FCVT_LD_D_EMIT(out, ft_vscratch, ft_vscratch);
    FT_LA_VEXTRINS_H_EMIT(out, ft_vscratch, ft_vscratch + 1, 0x40);
    ft_emit_load_env(out, la_t0, top, FT_LA_OPCODE_LD_WU);
    FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, -1);
    FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
    ft_emit_cpu_env_ptr(out, la_t4);
    FT_LA_ADD_D_EMIT(out, la_t1, la_t4, la_t0);
    FT_LA_ST_B_EMIT(out, la_zero, la_t1, tag);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t0, 4);
    FT_LA_ADD_D_EMIT(out, la_t1, la_t4, la_t1);
    FT_LA_VST_EMIT(out, ft_vscratch, la_t1, fp);
    ft_emit_store_env(out, la_t0, top, FT_LA_OPCODE_ST_W);
    if (count) {
        ft_emit_branch_placeholder(out, &finish, FT_BRANCH_B, 0, 0, &done);
        ft_bind_branch_label(&slow, *out);
        for (unsigned i = 0; i < count; ++i) ft_resolve_branch_fixup(&guards[i]);
        ft_emit_helper_prologue(out);
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, integer ? (void *)helper_fildll_ST0 :
                          width == 32 ? (void *)helper_flds_ST0 :
                                        (void *)helper_fldl_ST0, 1u << 0);
        ft_emit_x87_helper_epilogue(out);
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&finish);
    }
    return true;
#else
    (void)out; (void)f; (void)pc;
    return false;
#endif
}

static bool ft_emit_x87_latu_soft_constant(uint32_t **out,
                                          const FastTemplateFields *f)
{
#ifdef QUICKTRANS_LATU
    uint64_t low;
    unsigned high;
    int rounding = 0;
    void *helper;
    FastBranchLabel slow = {0}, done = {0};
    FastBranchFixup full, finish;
    int top = lsenv_offset_of_top(lsenv);
    int tag = lsenv_offset_of_tag_word(lsenv);
    int fp = lsenv_offset_of_fpr(lsenv, 0);

    if (option_soft_fpu != 2 ||
        !(f->kind == FT_X87_FLD1 || f->kind == FT_X87_FLD_CONST) ||
        !ft_offset_fits_imm12(tag) || !ft_offset_fits_imm12(fp + 8)) {
        return false;
    }
    if (f->kind == FT_X87_FLD1) {
        low = UINT64_C(0x8000000000000000); high = 0x3fff;
        helper = (void *)ft_x87_helper_fld1;
    } else {
        switch (f->id) {
        case dt_X86_INS_FLDZ:
            low = 0; high = 0; helper = (void *)ft_x87_helper_fldz; break;
        case dt_X86_INS_FLDL2T:
            low = UINT64_C(0xd49a784bcd1b8afe); high = 0x4000;
            rounding = 1; helper = (void *)ft_x87_helper_fldl2t; break;
        case dt_X86_INS_FLDL2E:
            low = UINT64_C(0xb8aa3b295c17f0bc); high = 0x3fff;
            rounding = -1; helper = (void *)ft_x87_helper_fldl2e; break;
        case dt_X86_INS_FLDPI:
            low = UINT64_C(0xc90fdaa22168c235); high = 0x4000;
            rounding = -1; helper = (void *)ft_x87_helper_fldpi; break;
        case dt_X86_INS_FLDLG2:
            low = UINT64_C(0x9a209a84fbcff799); high = 0x3ffd;
            rounding = -1; helper = (void *)ft_x87_helper_fldlg2; break;
        case dt_X86_INS_FLDLN2:
            low = UINT64_C(0xb17217f7d1cf79ac); high = 0x3ffe;
            rounding = -1; helper = (void *)ft_x87_helper_fldln2; break;
        default: return false;
        }
    }
    ft_emit_load_env(out, la_t0, top, FT_LA_OPCODE_LD_WU);
    FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, -1);
    FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
    ft_emit_cpu_env_ptr(out, la_t4);
    FT_LA_ADD_D_EMIT(out, la_t1, la_t4, la_t0);
    FT_LA_LD_BU_EMIT(out, la_t2, la_t1, tag);
    ft_emit_branch_placeholder(out, &full, FT_BRANCH_BEQ,
                               la_t2, la_zero, &slow);
    ft_emit_li64(out, la_t2, low);
    if (rounding) {
        ft_emit_load_env(out, la_t3, lsenv_offset_of_control_word(lsenv),
                         FT_LA_OPCODE_LD_HU);
        if (rounding > 0) {
            /* L2T rounds up only for RC=2, never for truncation (RC=3). */
            FT_LA_BSTRPICK_D_EMIT(out, la_t3, la_t3, 11, 10);
            FT_LA_XORI_EMIT(out, la_t3, la_t3, 2);
            FT_LA_SLTUI_EMIT(out, la_t3, la_t3, 1);
            FT_LA_ADD_D_EMIT(out, la_t2, la_t2, la_t3);
        } else {
            FT_LA_BSTRPICK_D_EMIT(out, la_t3, la_t3, 10, 10);
            FT_LA_SUB_D_EMIT(out, la_t2, la_t2, la_t3);
        }
    }
    FT_LA_ST_B_EMIT(out, la_zero, la_t1, tag);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t0, 4);
    FT_LA_ADD_D_EMIT(out, la_t1, la_t4, la_t1);
    FT_LA_ST_D_EMIT(out, la_t2, la_t1, fp);
    ft_emit_li64(out, la_t2, high);
    FT_LA_ST_H_EMIT(out, la_t2, la_t1, fp + 8);
    ft_emit_store_env(out, la_t0, top, FT_LA_OPCODE_ST_W);
    ft_emit_branch_placeholder(out, &finish, FT_BRANCH_B, 0, 0, &done);
    ft_bind_branch_label(&slow, *out);
    ft_resolve_branch_fixup(&full);
    ft_emit_x87_helper(out, helper);
    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&finish);
    return true;
#else
    (void)out;
    (void)f;
    return false;
#endif
}

/* Mode-2 register moves retain checked helper behavior on empty/full stacks. */
static bool ft_emit_x87_latu_soft_move(uint32_t **out,
                                      const FastTemplateFields *f)
{
#ifdef QUICKTRANS_LATU
    bool load = f->kind == FT_X87_FLD_REG;
    bool store = f->kind == FT_X87_FST_REG || f->kind == FT_X87_FSTP_REG;
    bool exchange = f->kind == FT_X87_FXCH;
    bool pop = f->kind == FT_X87_FSTP_REG;
    int index = f->modrm & 7;
    int top = lsenv_offset_of_top(lsenv);
    int tag = lsenv_offset_of_tag_word(lsenv);
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    int status = lsenv_offset_of_status_word(lsenv);
    FastBranchLabel slow = {0}, done = {0};
    FastBranchFixup guards[2], done_fix;
    int n = 0;

    if (option_soft_fpu != 2 || !(load || store || exchange) ||
        !ft_offset_fits_imm12(tag) || !ft_offset_fits_imm12(fp) ||
        (load && (f->modrm < 0xc0 || f->modrm > 0xc7)) ||
        (exchange && (f->modrm < 0xc8 || f->modrm > 0xcf)) ||
        (f->kind == FT_X87_FST_REG &&
         (f->modrm < 0xd0 || f->modrm > 0xd7)) ||
        (pop && (f->modrm < 0xd8 || f->modrm > 0xdf))) {
        return false;
    }
    ft_emit_load_env(out, la_t0, top, FT_LA_OPCODE_LD_WU);
    FT_LA_ADDI_D_EMIT(out, la_t1, la_t0, index);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 7);
    ft_emit_cpu_env_ptr(out, la_t4);
    FT_LA_ADD_D_EMIT(out, la_t3, la_t4, load ? la_t1 : la_t0);
    FT_LA_LD_BU_EMIT(out, la_t3, la_t3, tag);
    ft_emit_branch_placeholder(out, &guards[n++], FT_BRANCH_BNE,
                               la_t3, la_zero, &slow);
    if (load) {
        FT_LA_ADDI_D_EMIT(out, la_t2, la_t0, -1);
        FT_LA_ANDI_EMIT(out, la_t2, la_t2, 7);
        FT_LA_ADD_D_EMIT(out, la_t3, la_t4, la_t2);
        FT_LA_LD_BU_EMIT(out, la_t3, la_t3, tag);
        ft_emit_branch_placeholder(out, &guards[n++], FT_BRANCH_BEQ,
                                   la_t3, la_zero, &slow);
    } else if (exchange) {
        FT_LA_ADD_D_EMIT(out, la_t3, la_t4, la_t1);
        FT_LA_LD_BU_EMIT(out, la_t3, la_t3, tag);
        ft_emit_branch_placeholder(out, &guards[n++], FT_BRANCH_BNE,
                                   la_t3, la_zero, &slow);
    }
    /* No architectural writes before all stack guards have passed. */
    FT_LA_ADD_D_EMIT(out, la_t3, la_t4, load ? la_t2 : la_t1);
    FT_LA_ST_B_EMIT(out, la_zero, la_t3, tag);
    FT_LA_SLLI_D_EMIT(out, la_t3, load ? la_t1 : la_t0, 4);
    FT_LA_ADD_D_EMIT(out, la_t3, la_t4, la_t3);
    FT_LA_SLLI_D_EMIT(out, la_t1, load ? la_t2 : la_t1, 4);
    FT_LA_ADD_D_EMIT(out, la_t1, la_t4, la_t1);
    FT_LA_VLD_EMIT(out, ft_vscratch, la_t3, fp);
    if (exchange) {
        FT_LA_VLD_EMIT(out, ft_vscratch + 1, la_t1, fp);
        FT_LA_VST_EMIT(out, ft_vscratch + 1, la_t3, fp);
    }
    FT_LA_VST_EMIT(out, ft_vscratch, la_t1, fp);
    if (load) {
        ft_emit_store_env(out, la_t2, top, FT_LA_OPCODE_ST_W);
    } else {
        if (pop) {
            FT_LA_ADD_D_EMIT(out, la_t3, la_t4, la_t0);
            FT_LA_ORI_EMIT(out, la_t1, la_zero, 1);
            FT_LA_ST_B_EMIT(out, la_t1, la_t3, tag);
            FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, 1);
            FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
            ft_emit_store_env(out, la_t0, top, FT_LA_OPCODE_ST_W);
        }
        ft_emit_load_env(out, la_t1, status, FT_LA_OPCODE_LD_HU);
        FT_LA_BSTRINS_D_EMIT(out, la_t1, la_zero, 9, 9);
        ft_emit_store_env(out, la_t1, status, FT_LA_OPCODE_ST_H);
    }
    ft_emit_branch_placeholder(out, &done_fix, FT_BRANCH_B, 0, 0, &done);
    ft_bind_branch_label(&slow, *out);
    for (int i = 0; i < n; ++i) ft_resolve_branch_fixup(&guards[i]);
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, index);
    if (store) FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, pop);
    ft_emit_host_call(out, load ? (void *)ft_x87_helper_fld_reg :
                      exchange ? (void *)ft_x87_helper_fxch :
                      (void *)ft_x87_helper_fst_reg, 1u << 0);
    ft_emit_x87_helper_epilogue(out);
    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&done_fix);
    return true;
#else
    (void)out;
    (void)f;
    return false;
#endif
}

/* Integer addressing and vector copies only: no float64 precision conversion. */
static bool ft_emit_x87_soft_stack(uint32_t **out,
                                    const FastTemplateFields *fields)
{
#ifdef QUICKTRANS_LATU
    bool release = fields->kind == FT_X87_FFREE;
    bool adjust = fields->kind == FT_X87_TOP_ADJ;
    int top = lsenv_offset_of_top(lsenv);
    int tag = lsenv_offset_of_tag_word(lsenv);
    int status = lsenv_offset_of_status_word(lsenv);

    /* Legacy LATU mode 2 stores TOP/tags in env, with no fast-option bit
     * needed for these operations. Mode 1 retains its MMX synchronization. */
    if (option_soft_fpu != 2 || !(release || adjust) ||
        !ft_offset_fits_imm12(tag) ||
        (adjust && fields->id != dt_X86_INS_FINCSTP &&
         fields->id != dt_X86_INS_FDECSTP)) {
        return false;
    }
    ft_emit_load_env(out, la_t0, top, FT_LA_OPCODE_LD_WU);
    if (adjust) {
        FT_LA_ADDI_D_EMIT(out, la_t0, la_t0,
                          fields->id == dt_X86_INS_FDECSTP ? -1 : 1);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
        ft_emit_store_env(out, la_t0, top, FT_LA_OPCODE_ST_W);
        ft_emit_load_env(out, la_t1, status, FT_LA_OPCODE_LD_HU);
        FT_LA_BSTRINS_D_EMIT(out, la_t1, la_zero, 10, 8);
        FT_LA_BSTRINS_D_EMIT(out, la_t1, la_zero, 14, 14);
        ft_emit_store_env(out, la_t1, status, FT_LA_OPCODE_ST_H);
        return true;
    }
    FT_LA_ADDI_D_EMIT(out, la_t1, la_t0, fields->modrm & 7);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 7);
    ft_emit_cpu_env_ptr(out, la_t3);
    FT_LA_ADD_D_EMIT(out, la_t1, la_t3, la_t1);
    FT_LA_ORI_EMIT(out, la_t2, la_zero, 1);
    FT_LA_ST_B_EMIT(out, la_t2, la_t1, tag);
    if (fields->id == dt_X86_INS_FFREEP) {
        FT_LA_ADD_D_EMIT(out, la_t1, la_t3, la_t0);
        FT_LA_ST_B_EMIT(out, la_t2, la_t1, tag);
        FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, 1);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
        ft_emit_store_env(out, la_t0, top, FT_LA_OPCODE_ST_W);
    }
    return true;
#elif defined(CONFIG_SOFTMMU)
    int kind = fields->kind, index = fields->modrm & 7;
    bool load = kind == FT_X87_FLD_REG;
    bool store = kind == FT_X87_FST_REG || kind == FT_X87_FSTP_REG;
    bool exchange = kind == FT_X87_FXCH;
    bool release = kind == FT_X87_FFREE;
    bool adjust = kind == FT_X87_TOP_ADJ;
    bool pop = kind == FT_X87_FSTP_REG ||
               (release && fields->id == dt_X86_INS_FFREEP);
    int top = lsenv_offset_of_top(lsenv);
    int tag = lsenv_offset_of_tag_word(lsenv);
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    int status = lsenv_offset_of_status_word(lsenv);
    /* Validate before emitting. FST/FSTP share the legacy store option bit. */
    if ((load && (fields->modrm < 0xc0 || fields->modrm > 0xc7)) ||
        (kind == FT_X87_FST_REG &&
         (fields->modrm < 0xd0 || fields->modrm > 0xd7)) ||
        (kind == FT_X87_FSTP_REG &&
         (fields->modrm < 0xd8 || fields->modrm > 0xdf)) ||
        (exchange && (fields->modrm < 0xc8 || fields->modrm > 0xcf)) ||
        (adjust && fields->id != dt_X86_INS_FINCSTP &&
         fields->id != dt_X86_INS_FDECSTP)) return false;
    if (!option_soft_fpu || !option_soft_fpu_fast ||
        (store && !(option_soft_fpu_fast & 0x800000)) ||
        !(load || store || exchange || release || adjust) ||
        !ft_offset_fits_imm12(top) || !ft_offset_fits_imm12(tag) ||
        !ft_offset_fits_imm12(fp) || !ft_offset_fits_imm12(status)) return false;

    FT_LA_LD_W_EMIT(out, la_t0, la_s0, top);
    if (adjust) {
        FT_LA_ADDI_D_EMIT(out, la_t0, la_t0,
                          fields->id == dt_X86_INS_FDECSTP ? -1 : 1);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
        FT_LA_ST_W_EMIT(out, la_t0, la_s0, top);
        /* Legacy FINCSTP/FDECSTP explicitly clear C0/C1/C2/C3. */
        FT_LA_LD_HU_EMIT(out, la_t1, la_s0, status);
        FT_LA_BSTRINS_D_EMIT(out, la_t1, la_zero, 10, 8);
        FT_LA_BSTRINS_D_EMIT(out, la_t1, la_zero, 14, 14);
        FT_LA_ST_H_EMIT(out, la_t1, la_s0, status);
        return true;
    }
    FT_LA_ADDI_D_EMIT(out, la_t1, la_t0, index);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 7);
    if (release) {
        FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t1);
        FT_LA_ORI_EMIT(out, la_t4, la_zero, 1);
        FT_LA_ST_B_EMIT(out, la_t4, la_t3, tag);
    } else {
        if (load) {
            FT_LA_ADDI_D_EMIT(out, la_t2, la_t0, -1);
            FT_LA_ANDI_EMIT(out, la_t2, la_t2, 7);
        }
        /* Source and destination addresses before any stack state changes. */
        FT_LA_SLLI_D_EMIT(out, la_t3, store ? la_t0 : la_t1, 4);
        FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t3);
        FT_LA_SLLI_D_EMIT(out, la_t4, store ? la_t1 : load ? la_t2 : la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t4, la_s0, la_t4);
        FT_LA_VLD_EMIT(out, ft_vscratch, la_t3, fp);
        if (exchange) {
            FT_LA_VLD_EMIT(out, ft_vscratch + 1, la_t4, fp);
            FT_LA_VST_EMIT(out, ft_vscratch + 1, la_t3, fp);
        }
        FT_LA_VST_EMIT(out, ft_vscratch, la_t4, fp);
        if (load) {
            FT_LA_ST_W_EMIT(out, la_t2, la_s0, top);
            FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t2);
            FT_LA_ST_B_EMIT(out, la_zero, la_t3, tag);
        }
        /* Like fmov_STN_STM, FST/FXCH do not rewrite destination tags. */
    }
    if (pop) {
        FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t0);
        FT_LA_ORI_EMIT(out, la_t4, la_zero, 1);
        FT_LA_ST_B_EMIT(out, la_t4, la_t3, tag);
        FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, 1);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
        FT_LA_ST_W_EMIT(out, la_t0, la_s0, top);
    }
    return true;
#else
    (void)out;
    (void)fields;
    return false;
#endif
}

#include "emit-x87-soft-fast.inc.c"

/* The explicit store-fast bit selects the legacy double conversion policy. */
static bool ft_emit_x87_latu_soft_fst(uint32_t **out,
                                    const FastTemplateFields *f,
                                    target_ulong pc, FtSoftX87 *s)
{
#ifdef QUICKTRANS_LATU
    int width, addr;
    bool pop;
    switch (f->kind) {
    case FT_X87_FST_M32: width = 32; pop = false; break;
    case FT_X87_FST_M64: width = 64; pop = false; break;
    case FT_X87_FSTP_M32: width = 32; pop = true; break;
    case FT_X87_FSTP_M64: width = 64; pop = true; break;
    default: return false;
    }
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    int top = lsenv_offset_of_top(lsenv);
    int tag = lsenv_offset_of_tag_word(lsenv);
    if (option_soft_fpu != 2 || !(option_softfpu_fast & 0x800000) ||
        f->modrm_mod == 3 || !ft_offset_fits_imm12(fp + 8) ||
        !ft_offset_fits_imm12(tag)) return false;
    uint32_t *start = *out;
    memset(s, 0, sizeof(*s));
    ft_emit_load_env(out, la_t0, top, FT_LA_OPCODE_LD_WU);
    FT_LA_ADD_D_EMIT(out, la_t1, la_s8, la_t0);
    FT_LA_LD_BU_EMIT(out, la_t1, la_t1, tag);
    ft_emit_branch_placeholder(out, &s->guards[s->count++], FT_BRANCH_BNE,
                               la_t1, la_zero, &s->slow);
    FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
    FT_LA_ADD_D_EMIT(out, la_t0, la_s8, la_t0);
    FT_LA_VLD_EMIT(out, ft_vscratch, la_t0, fp);
    FT_LA_VEXTRINS_H_EMIT(out, ft_vscratch + 1, ft_vscratch, 0x4);
    FT_LA_FCVT_D_LD_EMIT(out, ft_vscratch, ft_vscratch, ft_vscratch + 1);
    if (width == 32) FT_LA_FCVT_S_D_EMIT(out, ft_vscratch, ft_vscratch);
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) {
        *out = start;
        return false;
    }
    int value = ft_scratch_avoid3(addr, -1, -1);
    FT_LA_MOVFR2GR_D_EMIT(out, value, ft_vscratch);
    int offset = ft_mem_access_offset(f, addr);
    if (width == 32) FT_LA_ST_W_EMIT(out, value, addr, offset);
    else FT_LA_ST_D_EMIT(out, value, addr, offset);
    if (pop) {
        ft_emit_load_env(out, la_t0, top, FT_LA_OPCODE_LD_WU);
        FT_LA_ADD_D_EMIT(out, la_t1, la_s8, la_t0);
        FT_LA_ORI_EMIT(out, la_t2, la_zero, 1);
        FT_LA_ST_B_EMIT(out, la_t2, la_t1, tag);
        FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, 1);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
        ft_emit_store_env(out, la_t0, top, FT_LA_OPCODE_ST_W);
    }
    ft_emit_branch_placeholder(out, &s->done_fix, FT_BRANCH_B, 0, 0, &s->done);
    ft_bind_branch_label(&s->slow, *out);
    ft_resolve_branch_fixup(&s->guards[0]);
    return true;
#else
    (void)out; (void)f; (void)pc; (void)s;
    return false;
#endif
}

/* Keep the checked helper for empty stacks and values outside legacy gates. */
static bool ft_emit_x87_latu_soft_fist(uint32_t **out,
                                     const FastTemplateFields *f,
                                     target_ulong pc, FtSoftX87 *s)
{
#ifdef QUICKTRANS_LATU
    int width, addr;
    bool pop = false;
    switch (f->kind) {
    case FT_X87_FIST_M16: width = 16; break;
    case FT_X87_FIST_M32: width = 32; break;
    case FT_X87_FISTP_M16: width = 16; pop = true; break;
    case FT_X87_FISTP_M32: width = 32; pop = true; break;
    case FT_X87_FISTP_M64: width = 64; pop = true; break;
    default: return false;
    }
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    int top = lsenv_offset_of_top(lsenv);
    int tag = lsenv_offset_of_tag_word(lsenv);
    int round = lsenv_offset_of_fp_status(lsenv) +
                offsetof(float_status, float_rounding_mode);
    if (option_soft_fpu != 2 || f->modrm_mod == 3 ||
        !(option_softfpu_fast & (pop ? 0x400000 : 0x200000)) ||
        !ft_offset_fits_imm12(fp + 8) || !ft_offset_fits_imm12(tag) ||
        !ft_offset_fits_imm12(round)) return false;
    uint32_t *start = *out;
    memset(s, 0, sizeof(*s));
    ft_emit_load_env(out, la_t0, top, FT_LA_OPCODE_LD_WU);
    FT_LA_ADD_D_EMIT(out, la_t1, la_s8, la_t0);
    FT_LA_LD_BU_EMIT(out, la_t1, la_t1, tag);
    ft_emit_branch_placeholder(out, &s->guards[s->count++], FT_BRANCH_BNE,
                               la_t1, la_zero, &s->slow);
    ft_emit_load_env(out, la_t1, round, FT_LA_OPCODE_LD_BU);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t1, 2, 2);
    ft_emit_branch_placeholder(out, &s->guards[s->count++], FT_BRANCH_BNE,
                               la_t1, la_zero, &s->slow);
    FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
    FT_LA_ADD_D_EMIT(out, la_t0, la_s8, la_t0);
    FT_LA_LD_HU_EMIT(out, la_t1, la_t0, fp + 8);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t1, 14, 0);
    /* The legacy m16 fast path can truncate overflowed results. Keep those
     * values on the checked helper instead of introducing that difference. */
    ft_emit_li64(out, la_t2, 0x3fff + (width == 64 ? 52 : width == 16 ? 15 : 24));
    ft_emit_branch_placeholder(out, &s->guards[s->count++], FT_BRANCH_BGE,
                               la_t1, la_t2, &s->slow);
    FT_LA_VLD_EMIT(out, ft_vscratch, la_t0, fp);
    FT_LA_VEXTRINS_H_EMIT(out, ft_vscratch + 1, ft_vscratch, 0x4);
    FT_LA_FCVT_D_LD_EMIT(out, ft_vscratch, ft_vscratch, ft_vscratch + 1);
    if (width == 64) FT_LA_FTINT_L_D_EMIT(out, ft_vscratch, ft_vscratch);
    else FT_LA_FTINT_W_D_EMIT(out, ft_vscratch, ft_vscratch);
    if (width == 16) {
        FT_LA_MOVFR2GR_S_EMIT(out, la_t1, ft_vscratch);
        FT_LA_EXT_W_H_EMIT(out, la_t2, la_t1);
        ft_emit_branch_placeholder(out, &s->guards[s->count++], FT_BRANCH_BNE,
                                   la_t1, la_t2, &s->slow);
    }
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) {
        *out = start;
        return false;
    }
    int value = ft_scratch_avoid3(addr, -1, -1);
    FT_LA_MOVFR2GR_D_EMIT(out, value, ft_vscratch);
    int offset = ft_mem_access_offset(f, addr);
    if (width == 16) FT_LA_ST_H_EMIT(out, value, addr, offset);
    else if (width == 32) FT_LA_ST_W_EMIT(out, value, addr, offset);
    else FT_LA_ST_D_EMIT(out, value, addr, offset);
    if (pop) {
        ft_emit_load_env(out, la_t0, top, FT_LA_OPCODE_LD_WU);
        FT_LA_ADD_D_EMIT(out, la_t1, la_s8, la_t0);
        FT_LA_ORI_EMIT(out, la_t2, la_zero, 1);
        FT_LA_ST_B_EMIT(out, la_t2, la_t1, tag);
        FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, 1);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
        ft_emit_store_env(out, la_t0, top, FT_LA_OPCODE_ST_W);
    }
    ft_emit_branch_placeholder(out, &s->done_fix, FT_BRANCH_B, 0, 0, &s->done);
    ft_bind_branch_label(&s->slow, *out);
    for (unsigned i = 0; i < s->count; ++i) ft_resolve_branch_fixup(&s->guards[i]);
    return true;
#else
    (void)out; (void)f; (void)pc; (void)s;
    return false;
#endif
}


/* Compact exceptional comparison path. The fast emitter has already read
 * the memory operand; do not read guest memory again in host context. */
static bool ft_emit_x87_compare_fallback(uint32_t **out,
                                         const FastTemplateFields *f)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (!scs_enabled()) return false;
    bool memory = false, integer = false;
    bool quiet = f->id == dt_X86_INS_FUCOM || f->id == dt_X86_INS_FUCOMP ||
                 f->id == dt_X86_INS_FUCOMPP || f->id == dt_X86_INS_FUCOMI ||
                 f->id == dt_X86_INS_FUCOMIP;
    int pop = 0, index = f->modrm_rm;
    void *helper = (void *)ft_x87_helper_compare_reg_fast;
    switch (f->kind) {
    case FT_X87_FTST: helper = (void *)ft_x87_helper_ftst_fast; break;
    case FT_X87_FCOMP_REG: pop = 1; break;
    case FT_X87_FCOM_REG: break;
    case FT_X87_FCOMPP: case FT_X87_FUCOMPP: pop = 2; index = 1; break;
    case FT_X87_FCOMIP_REG: pop = 1; /* fall through */
    case FT_X87_FCOMI_REG: helper = (void *)ft_x87_helper_fcomi_fast; break;
    case FT_X87_FI_BIN_M16: case FT_X87_FI_BIN_M32: integer = true; /* fall through */
    case FT_X87_FCOM_M32: case FT_X87_FCOM_M64:
        memory = true; pop = f->modrm_reg == 3; break;
    default: return false;
    }
    if (memory) {
        FT_LA_MOVFR2GR_D_EMIT(out, la_t4, ft_vscratch + 1);
        if (!integer && !ft_emit_x87_mark_denormal_operand(out, la_t4,
                                                    f->kind == FT_X87_FCOM_M64)) {
            return false;
        }
        FT_LA_MOVFR2GR_D_EMIT(out, la_a2, ft_vscratch + 1);
    }
    bool context = ft_emit_nofp_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    if (memory) {
        FT_LA_OR_EMIT(out, la_a1, la_a2, la_zero);
        helper = integer ? (void *)ft_x87_helper_compare_int_fast :
                 f->kind == FT_X87_FCOM_M64 ? (void *)ft_x87_helper_compare_m64_fast :
                                             (void *)ft_x87_helper_compare_m32_fast;
        ft_emit_default_helper_call(out, helper, 1u << 0, context);
    } else {
        if (f->kind != FT_X87_FTST) {
            FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, index);
            FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, quiet | (pop << 1));
        }
        ft_emit_default_helper_call(out, helper, 1u << 0, context);
    }
    ft_emit_nofp_helper_epilogue(out, context);
    if (memory && pop) ft_soft_x87_pop(out, pop);
    return true;
#else
    (void)out; (void)f;
    return false;
#endif
}

/* Preserve the full inline helper context for guarded integer fallbacks,
 * but avoid copying the system env pointer for each register access. */
static bool ft_emit_x87_integer_inline_context(uint32_t **out, bool restore)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (!option_soft_fpu || !option_soft_fpu_fast) return false;
    for (int i = 0; i < GPR_NUM; ++i) {
        if (!ft_offset_fits_imm12(lsenv_offset_of_gpr(lsenv, i))) return false;
    }
    for (int i = 0; i < XMM_NUM; ++i) {
        if (!ft_offset_fits_imm12(lsenv_offset_of_xmm(lsenv, i))) return false;
    }
    if (restore) {
        ft_emit_restore_condition_flags(out);
        for (int i = 0; i < XMM_NUM; ++i)
            FT_LA_VLD_EMIT(out, ft_xmm(i), la_s0, lsenv_offset_of_xmm(lsenv, i));
        for (int i = 0; i < GPR_NUM; ++i)
            FT_LA_LD_D_EMIT(out, ft_gpr(i), la_s0, lsenv_offset_of_gpr(lsenv, i));
    } else {
        for (int i = 0; i < GPR_NUM; ++i)
            FT_LA_ST_D_EMIT(out, ft_gpr(i), la_s0, lsenv_offset_of_gpr(lsenv, i));
        for (int i = 0; i < XMM_NUM; ++i)
            FT_LA_VST_EMIT(out, ft_xmm(i), la_s0, lsenv_offset_of_xmm(lsenv, i));
        ft_emit_save_condition_flags(out);
    }
    return true;
#else
    (void)out;
    (void)restore;
    return false;
#endif
}

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
/* Share the legacy no-FP context for guarded integer-conversion fallbacks.
 * Like FISTTP, the static epilogue preserves a0 until the guest store. */
static bool ft_emit_x87_integer_fallback(uint32_t **out,
                                        const FastTemplateFields *f,
                                        target_ulong pc)
{
    if (!scs_enabled()) return false;
    void *helper;
    int width = 0;
    bool pop = false;
    /* Preserve the already loaded FILD64 integer across the no-FP prologue. */
    switch (f->kind) {
    case FT_X87_FILD_M64: helper = (void *)helper_fildll_ST0; break;
    case FT_X87_FIST_M16: width = 16; helper = (void *)ft_x87_helper_fist; break;
    case FT_X87_FIST_M32: width = 32; helper = (void *)ft_x87_helper_fistl; break;
    case FT_X87_FISTP_M16: width = 16; pop = true; helper = (void *)ft_x87_helper_fist; break;
    case FT_X87_FISTP_M32: width = 32; pop = true; helper = (void *)ft_x87_helper_fistl; break;
    case FT_X87_FISTP_M64: width = 64; pop = true; helper = (void *)ft_x87_helper_fistll; break;
    default: return false;
    }
    uint32_t *start = *out;
    if (!width) FT_LA_MOVFR2GR_D_EMIT(out, la_a2, ft_vscratch + 1);
    bool context = ft_emit_nofp_helper_prologue(out);
    if (!width) FT_LA_OR_EMIT(out, la_a1, la_a2, la_zero);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_default_helper_call(out, helper, 1u << 0, context);
    ft_emit_nofp_helper_epilogue(out, context);
    if (width) {
        int addr;
        if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) { *out = start; return false; }
        int offset = ft_mem_access_offset(f, addr);
        if (width == 16) FT_LA_ST_H_EMIT(out, la_a0, addr, offset);
        else if (width == 32) FT_LA_ST_W_EMIT(out, la_a0, addr, offset);
        else FT_LA_ST_D_EMIT(out, la_a0, addr, offset);
        if (pop) ft_soft_x87_pop(out, 1);
    }
    return true;
}
#endif

static int ft_emit_x87_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (option_soft_fpu && option_soft_fpu_fast &&
        fields->kind == FT_X87_FCMOVCC && ft_soft_x87_cmov(&out, fields)) {
        return out - code;
    }
#endif
    if (ft_emit_x87_latu_soft_load(&out, fields, pc) ||
        ft_emit_x87_latu_soft_constant(&out, fields) ||
        ft_emit_x87_latu_soft_move(&out, fields) ||
        ft_emit_x87_soft_stack(&out, fields)) {
        return out - code;
    }
    FtSoftX87 extra;
    bool direct_extra = ft_emit_x87_latu_soft_fst(&out, fields, pc, &extra) ||
                        ft_emit_x87_latu_soft_fist(&out, fields, pc, &extra) ||
                        ft_emit_x87_soft_extra(&out, fields, pc, &extra);
    if (direct_extra && extra.count == 0) {
        /* Complete direct path: no template helper copy is needed. */
        return out - code;
    }
    if (direct_extra && ft_emit_x87_compare_fallback(&out, fields)) {
        ft_bind_branch_label(&extra.done, out);
        ft_resolve_branch_fixup(&extra.done_fix);
        return out - code;
    }
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (direct_extra && ft_emit_x87_integer_fallback(&out, fields, pc)) {
        ft_bind_branch_label(&extra.done, out);
        ft_resolve_branch_fixup(&extra.done_fix);
        return out - code;
    }
#endif
    FtSoftEnv memory_call;
    memory_call.active = false;
    ft_emit_soft_memory_call(&out, fields, pc, &memory_call);
    if (memory_call.active &&
        (fields->kind == FT_X87_FBLD || fields->kind == FT_X87_FBSTP)) {
        return out - code;
    }
    switch (fields->kind) {
    case FT_X87_FLD1:
        if (option_soft_fpu) {
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_fld1);
            break;
        }
        FT_LA_ORI_EMIT(&out, la_t0, la_zero, 1);
        FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(7), la_t0);
        FT_LA_FFINT_D_W_EMIT(&out, ft_mmx(7), ft_mmx(7));
        FT_LA_X86DECTOP_EMIT(&out);
        ft_emit_x87_mark_current_tag(&out, 0);
        break;
    case FT_X87_FLD_CONST:
    {
        uint64_t bits;

        if (option_soft_fpu) {
            void *helper;

            switch (fields->id) {
            case dt_X86_INS_FLDZ:   helper = (void *)ft_x87_helper_fldz; break;
            case dt_X86_INS_FLDL2T: helper = (void *)ft_x87_helper_fldl2t; break;
            case dt_X86_INS_FLDL2E: helper = (void *)ft_x87_helper_fldl2e; break;
            case dt_X86_INS_FLDPI:  helper = (void *)ft_x87_helper_fldpi; break;
            case dt_X86_INS_FLDLG2: helper = (void *)ft_x87_helper_fldlg2; break;
            case dt_X86_INS_FLDLN2: helper = (void *)ft_x87_helper_fldln2; break;
            default: return 0;
            }
            ft_emit_x87_helper(&out, helper);
            break;
        }
        if (!ft_x87_const_bits(fields->id, &bits)) {
            return 0;
        }
        ft_emit_li64(&out, la_t0, bits);
        FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(7), la_t0);
        FT_LA_X86DECTOP_EMIT(&out);
        ft_emit_x87_mark_current_tag(&out, 0);
        break;
    }
    case FT_X87_FLD_M32:
    case FT_X87_FLD_M64:
    {
        int addr;

        if (fields->modrm_mod == 3) {
            return 0;
        }
        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            if (direct_extra && extra.loaded) {
                FT_LA_MOVFR2GR_D_EMIT(&out, la_a1, ft_vscratch + 1);
            } else {
                if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                    return 0;
                }
                if (fields->kind == FT_X87_FLD_M32) {
                    FT_LA_LD_WU_EMIT(&out, la_a1, addr,
                                     ft_mem_access_offset(fields, addr));
                } else {
                    FT_LA_LD_D_EMIT(&out, la_a1, addr,
                                    ft_mem_access_offset(fields, addr));
                }
            }
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, fields->kind == FT_X87_FLD_M32 ?
                              (void *)helper_flds_ST0 :
                              (void *)helper_fldl_ST0, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        if (fields->kind == FT_X87_FLD_M32) {
            FT_LA_FLD_S_EMIT(&out, ft_mmx(7), addr,
                             ft_mem_access_offset(fields, addr));
            FT_LA_FCVT_D_S_EMIT(&out, ft_mmx(7), ft_mmx(7));
        } else {
            FT_LA_FLD_D_EMIT(&out, ft_mmx(7), addr,
                             ft_mem_access_offset(fields, addr));
        }
        FT_LA_X86DECTOP_EMIT(&out);
        ft_emit_x87_mark_current_tag(&out, 0);
        break;
    }
    case FT_X87_FLD_M80:
    {
        int addr;
        int offset;

        if (fields->modrm_mod == 3 ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }

        offset = ft_mem_access_offset(fields, addr);
        FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);

#ifdef QUICKTRANS_LATU
        if (option_soft_fpu == 2 &&
            ft_offset_fits_imm12(lsenv_offset_of_fpr(lsenv, 0) + 8) &&
            ft_offset_fits_imm12(lsenv_offset_of_tag_word(lsenv))) {
            int fp = lsenv_offset_of_fpr(lsenv, 0);
            int tag = lsenv_offset_of_tag_word(lsenv);
            /* Match helper_fldt_ST0: read all ten bytes before any state
             * update. In particular a fault at ptr+8 must not push TOP. */
            FT_LA_LD_D_EMIT(&out, la_t0, la_a1, 0);
            FT_LA_LD_HU_EMIT(&out, la_t1, la_a1, 8);
            ft_emit_load_env(&out, la_t2, lsenv_offset_of_top(lsenv),
                             FT_LA_OPCODE_LD_WU);
            FT_LA_ADDI_D_EMIT(&out, la_t2, la_t2, -1);
            FT_LA_ANDI_EMIT(&out, la_t2, la_t2, 7);
            ft_emit_cpu_env_ptr(&out, la_t4);
            FT_LA_SLLI_D_EMIT(&out, la_t3, la_t2, 4);
            FT_LA_ADD_D_EMIT(&out, la_t3, la_t4, la_t3);
            FT_LA_ST_D_EMIT(&out, la_t0, la_t3, fp);
            FT_LA_ST_H_EMIT(&out, la_t1, la_t3, fp + 8);
            ft_emit_store_env(&out, la_t2, lsenv_offset_of_top(lsenv),
                              FT_LA_OPCODE_ST_W);
            FT_LA_ADD_D_EMIT(&out, la_t3, la_t4, la_t2);
            FT_LA_ST_B_EMIT(&out, la_zero, la_t3, tag);
            break;
        }
#endif

        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
        FT_LA_ST_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);

        ft_emit_helper_prologue(&out);
        if (!option_soft_fpu) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_64_to_x80,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)helper_fldt_ST0, 1u << 0);
        if (!option_soft_fpu) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_x80_to_64,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
        ft_emit_host_stack_end(&out);
        ft_emit_x87_helper_epilogue(&out);
        break;
    }
    case FT_X87_FLD_REG:
    {
        int st_index = fields->modrm & 7;

        if (fields->modrm < 0xc0 || fields->modrm > 0xc7) {
            return 0;
        }
        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, st_index);
            ft_emit_host_call(&out, (void *)ft_x87_helper_fld_reg, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        FT_LA_FMOV_D_EMIT(&out, ft_mmx(7), ft_mmx(st_index));
        FT_LA_X86DECTOP_EMIT(&out);
        ft_emit_x87_mark_current_tag(&out, 0);
        break;
    }
    case FT_X87_FST_REG:
    case FT_X87_FSTP_REG:
    {
        int st_index = fields->modrm & 7;

        if ((fields->kind == FT_X87_FST_REG &&
             (fields->modrm < 0xd0 || fields->modrm > 0xd7)) ||
            (fields->kind == FT_X87_FSTP_REG &&
             (fields->modrm < 0xd8 || fields->modrm > 0xdf))) {
            return 0;
        }
        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, st_index);
            FT_LA_ADDI_D_EMIT(&out, la_a2, la_zero,
                              fields->kind == FT_X87_FSTP_REG);
            ft_emit_host_call(&out, (void *)ft_x87_helper_fst_reg, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (st_index != 0) {
            FT_LA_FMOV_D_EMIT(&out, ft_mmx(st_index), ft_mmx(0));
        }
        /* The register destination becomes occupied before a possible pop.
         * Otherwise a later helper/state save treats the copied value as empty.
         * Keep the legacy tag-off policy, and let FSTP ST(0) invalidate the
         * slot again when it pops below.
         */
        if (!ft_x87_latu_legacy_no_tag()) {
            ft_emit_x87_mark_st_tag(&out, st_index, 0);
        }
        if (fields->kind == FT_X87_FSTP_REG) {
            ft_emit_x87_pop(&out);
        }
        break;
    }
    case FT_X87_UNARY:
        if (option_soft_fpu &&
            (fields->id == dt_X86_INS_FABS ||
             fields->id == dt_X86_INS_FCHS)) {
            ft_emit_x87_soft_sign(&out, fields->id == dt_X86_INS_FCHS);
        } else if (fields->id == dt_X86_INS_FABS) {
            FT_LA_FABS_D_EMIT(&out, ft_mmx(0), ft_mmx(0));
        } else if (fields->id == dt_X86_INS_FCHS) {
            FT_LA_FNEG_D_EMIT(&out, ft_mmx(0), ft_mmx(0));
        } else {
            return 0;
        }
        break;
    case FT_X87_TOP_ADJ:
        if (option_soft_fpu && fields->id == dt_X86_INS_FDECSTP) {
            ft_emit_x87_helper(&out, (void *)helper_fdecstp);
        } else if (option_soft_fpu && fields->id == dt_X86_INS_FINCSTP) {
            ft_emit_x87_helper(&out, (void *)helper_fincstp);
        } else if (fields->id == dt_X86_INS_FDECSTP) {
            FT_LA_X86DECTOP_EMIT(&out);
        } else if (fields->id == dt_X86_INS_FINCSTP) {
            FT_LA_X86INCTOP_EMIT(&out);
        } else {
            return 0;
        }
#ifdef QUICKTRANS_LATU
        /* Soft helpers own fpstt/fpus; the hardware TOP is unrelated. */
        if (!option_soft_fpu)
#endif
        {
            ft_emit_x87_status_top(&out);
        }
        break;
    case FT_X87_FTST:
    {
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_x87_helper_ftst, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_offset_fits_imm12(fpus_offset)) {
            return 0;
        }
        FT_LA_MOVGR2FR_W_EMIT(&out, ft_vscratch + 1, la_zero);
        FT_LA_FFINT_D_W_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1);
        ft_emit_x87_fcom_status(&out, ft_vscratch + 1, ft_mmx(0), true);
        break;
    }
    case FT_X87_FXCH:
    {
        int st_index = fields->modrm & 7;

        if (fields->modrm < 0xc8 || fields->modrm > 0xcf) {
            return 0;
        }
        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, st_index);
            ft_emit_host_call(&out, (void *)ft_x87_helper_fxch, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (st_index == 0) {
            FT_LA_ORI_EMIT(&out, la_zero, la_zero, 0);
        } else {
            FT_LA_FMOV_D_EMIT(&out, ft_vscratch + 2, ft_mmx(0));
            FT_LA_FMOV_D_EMIT(&out, ft_mmx(0), ft_mmx(st_index));
            FT_LA_FMOV_D_EMIT(&out, ft_mmx(st_index), ft_vscratch + 2);
        }
        break;
    }
    case FT_X87_FCOM_REG:
    case FT_X87_FCOMP_REG:
    {
        int st_index = fields->modrm & 7;
        int src = ft_mmx(st_index);
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

        if (option_soft_fpu) {
            int mode = (fields->id == dt_X86_INS_FUCOM ||
                        fields->id == dt_X86_INS_FUCOMP) |
                       ((fields->kind == FT_X87_FCOMP_REG) << 1);

            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, st_index);
            FT_LA_ADDI_D_EMIT(&out, la_a2, la_zero, mode);
            ft_emit_host_call(&out, (void *)ft_x87_helper_compare_reg, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_offset_fits_imm12(fpus_offset)) {
            return 0;
        }
        ft_emit_x87_fcom_status(&out, src, ft_mmx(0),
                                fields->id == dt_X86_INS_FCOM ||
                                fields->id == dt_X86_INS_FCOMP);
        if (fields->kind == FT_X87_FCOMP_REG) {
            ft_emit_x87_pop(&out);
        }
        break;
    }
    case FT_X87_FUCOMPP:
    {
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, 1);
            FT_LA_ADDI_D_EMIT(&out, la_a2, la_zero, 5);
            ft_emit_host_call(&out, (void *)ft_x87_helper_compare_reg, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_offset_fits_imm12(fpus_offset)) {
            return 0;
        }
        ft_emit_x87_fcom_status(&out, ft_mmx(1), ft_mmx(0), false);
        ft_emit_x87_pop(&out);
        ft_emit_x87_pop(&out);
        break;
    }
    case FT_X87_FCOMI_REG:
    case FT_X87_FCOMIP_REG:
    {
        int st_index = fields->modrm & 7;
        int src = ft_mmx(st_index);

        if (option_soft_fpu) {
            bool quiet = fields->id == dt_X86_INS_FUCOMI ||
                         fields->id == dt_X86_INS_FUCOMIP;

            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, st_index);
            FT_LA_ADDI_D_EMIT(&out, la_a2, la_zero,
                              quiet | ((fields->kind == FT_X87_FCOMIP_REG) << 1));
            ft_emit_host_call(&out, (void *)ft_x87_helper_fcomi, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_x87_fcomi_flags(&out, src, ft_mmx(0),
                                     fields->id == dt_X86_INS_FCOMI ||
                                     fields->id == dt_X86_INS_FCOMIP,
                                     fields->skip_flags)) {
            return 0;
        }
        if (fields->kind == FT_X87_FCOMIP_REG) {
            ft_emit_x87_pop(&out);
        }
        break;
    }
    case FT_X87_FCMOVCC:
    {
        int cond;
        int flag_mask;
        bool skip_when_set;

        if (fields->modrm_rm > 7) {
            return 0;
        }
        switch (fields->id) {
        case dt_X86_INS_FCMOVB:
            cond = COND_B;
            flag_mask = CF_USEDEF_BIT;
            skip_when_set = false;
            break;
        case dt_X86_INS_FCMOVE:
            cond = COND_E;
            flag_mask = ZF_USEDEF_BIT;
            skip_when_set = false;
            break;
        case dt_X86_INS_FCMOVBE:
            cond = COND_BE;
            flag_mask = CF_USEDEF_BIT | ZF_USEDEF_BIT;
            skip_when_set = false;
            break;
        case dt_X86_INS_FCMOVU:
            cond = COND_PE;
            flag_mask = PF_USEDEF_BIT;
            skip_when_set = false;
            break;
        case dt_X86_INS_FCMOVNB:
            cond = COND_AE;
            flag_mask = CF_USEDEF_BIT;
            skip_when_set = true;
            break;
        case dt_X86_INS_FCMOVNE:
            cond = COND_NE;
            flag_mask = ZF_USEDEF_BIT;
            skip_when_set = true;
            break;
        case dt_X86_INS_FCMOVNBE:
            cond = COND_A;
            flag_mask = CF_USEDEF_BIT | ZF_USEDEF_BIT;
            skip_when_set = true;
            break;
        case dt_X86_INS_FCMOVNU:
            cond = COND_PO;
            flag_mask = PF_USEDEF_BIT;
            skip_when_set = true;
            break;
        default:
            return 0;
        }
        if (option_soft_fpu) {
            int mode = ((flag_mask & CF_USEDEF_BIT) ? CC_C : 0) |
                       ((flag_mask & PF_USEDEF_BIT) ? CC_P : 0) |
                       ((flag_mask & ZF_USEDEF_BIT) ? CC_Z : 0) |
                       (skip_when_set ? 0x100 : 0);
#ifdef QUICKTRANS_LATU
            FastBranchLabel slow = {0}, done = {0};
            FastBranchFixup guards[2], skip, finish;
            bool direct = option_soft_fpu == 2;
            if (direct) {
                int fp = lsenv_offset_of_fpr(lsenv, 0);
                int tag = lsenv_offset_of_tag_word(lsenv);
                direct = ft_offset_fits_imm12(fp) &&
                         ft_offset_fits_imm12(tag);
                if (direct) {
                    ft_emit_load_env(&out, la_t0,
                                     lsenv_offset_of_top(lsenv),
                                     FT_LA_OPCODE_LD_WU);
                    FT_LA_ADDI_D_EMIT(&out, la_t1, la_t0, fields->modrm_rm);
                    FT_LA_ANDI_EMIT(&out, la_t1, la_t1, 7);
                    ft_emit_cpu_env_ptr(&out, la_t4);
                    FT_LA_ADD_D_EMIT(&out, la_t2, la_t4, la_t0);
                    FT_LA_LD_BU_EMIT(&out, la_t2, la_t2, tag);
                    ft_emit_branch_placeholder(&out, &guards[0],
                                               FT_BRANCH_BNE, la_t2,
                                               la_zero, &slow);
                    FT_LA_ADD_D_EMIT(&out, la_t2, la_t4, la_t1);
                    FT_LA_LD_BU_EMIT(&out, la_t2, la_t2, tag);
                    ft_emit_branch_placeholder(&out, &guards[1],
                                               FT_BRANCH_BNE, la_t2,
                                               la_zero, &slow);
                    /* Stack faults must be checked even for false conditions.
                     * Valid operands retain C1, as in the existing helper. */
                    FT_LA_SETX86J_EMIT(&out, la_t2, cond);
                    ft_emit_branch_placeholder(&out, &skip, FT_BRANCH_BEQ,
                                               la_t2, la_zero, &done);
                    FT_LA_SLLI_D_EMIT(&out, la_t0, la_t0, 4);
                    FT_LA_ADD_D_EMIT(&out, la_t0, la_t4, la_t0);
                    FT_LA_SLLI_D_EMIT(&out, la_t1, la_t1, 4);
                    FT_LA_ADD_D_EMIT(&out, la_t1, la_t4, la_t1);
                    FT_LA_VLD_EMIT(&out, ft_vscratch, la_t1, fp);
                    FT_LA_VST_EMIT(&out, ft_vscratch, la_t0, fp);
                    ft_emit_branch_placeholder(&out, &finish,
                                               FT_BRANCH_B, 0, 0, &done);
                    ft_bind_branch_label(&slow, out);
                    ft_resolve_branch_fixup(&guards[0]);
                    ft_resolve_branch_fixup(&guards[1]);
                }
            }
#endif
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->modrm_rm);
            FT_LA_ADDI_D_EMIT(&out, la_a2, la_zero, mode);
            ft_emit_host_call(&out, (void *)ft_x87_helper_fcmov, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
#ifdef QUICKTRANS_LATU
            if (direct) {
                ft_bind_branch_label(&done, out);
                ft_resolve_branch_fixup(&skip);
                ft_resolve_branch_fixup(&finish);
            }
#endif
            break;
        }
        FT_LA_SETX86J_EMIT(&out, la_t0, cond);
        FT_LA_BEQ_EMIT(&out, la_t0, la_zero, 2);
        FT_LA_FMOV_D_EMIT(&out, ft_mmx(0), ft_mmx(fields->modrm_rm));
        break;
    }
    case FT_X87_F2XM1:
    {
        if (option_soft_fpu) {
            ft_emit_x87_complex_helper(&out, (void *)ft_x87_helper_f2xm1,
                                        (void *)helper_f2xm1);
            break;
        }
        FastBranchLabel skip = { 0 };
        FastBranchLabel neg_half = { 0 };
        FastBranchLabel pos_half = { 0 };
        FastBranchLabel generic_done = { 0 };
        FastBranchLabel neg_done = { 0 };
        FastBranchFixup skip_fixup;
        FastBranchFixup neg_half_fixup;
        FastBranchFixup pos_half_fixup;
        FastBranchFixup generic_done_fixup;
        FastBranchFixup neg_done_fixup;

        FT_LA_MOVFR2GR_D_EMIT(&out, la_t0, ft_mmx(0));
        ft_emit_li64(&out, la_t1, 0xc004000000000000ULL);
        ft_emit_branch_placeholder(&out, &skip_fixup, FT_BRANCH_BEQ, la_t0,
                                   la_t1, &skip);
        ft_emit_li64(&out, la_t1, 0xbfe0000000000000ULL);
        ft_emit_branch_placeholder(&out, &neg_half_fixup, FT_BRANCH_BEQ,
                                   la_t0, la_t1, &neg_half);
        ft_emit_li64(&out, la_t1, 0x3fe0000000000000ULL);
        ft_emit_branch_placeholder(&out, &pos_half_fixup, FT_BRANCH_BEQ,
                                   la_t0, la_t1, &pos_half);
        ft_emit_x87_call_unary_double(&out, (void *)exp2);
        FT_LA_ORI_EMIT(&out, la_t0, la_zero, 1);
        FT_LA_MOVGR2FR_D_EMIT(&out, ft_vscratch + 2, la_t0);
        FT_LA_FFINT_D_W_EMIT(&out, ft_vscratch + 2, ft_vscratch + 2);
        FT_LA_FSUB_D_EMIT(&out, ft_mmx(0), ft_mmx(0), ft_vscratch + 2);
        ft_emit_branch_placeholder(&out, &generic_done_fixup, FT_BRANCH_B,
                                   0, 0, &generic_done);
        ft_bind_branch_label(&neg_half, out);
        ft_resolve_branch_fixup(&neg_half_fixup);
        ft_emit_li64(&out, la_t1, 0xbfd2bec333018867ULL);
        FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(0), la_t1);
        ft_emit_branch_placeholder(&out, &neg_done_fixup, FT_BRANCH_B, 0, 0,
                                   &neg_done);
        ft_bind_branch_label(&pos_half, out);
        ft_resolve_branch_fixup(&pos_half_fixup);
        ft_emit_li64(&out, la_t1, 0x3fda827999fcef32ULL);
        FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(0), la_t1);
        ft_bind_branch_label(&skip, out);
        ft_resolve_branch_fixup(&skip_fixup);
        ft_bind_branch_label(&generic_done, out);
        ft_resolve_branch_fixup(&generic_done_fixup);
        ft_bind_branch_label(&neg_done, out);
        ft_resolve_branch_fixup(&neg_done_fixup);
        break;
    }
    case FT_X87_FRNDINT:
        if (option_soft_fpu) {
            ft_emit_x87_soft_unary(&out, false);
            break;
        }
        FT_LA_FRINT_D_EMIT(&out, ft_mmx(0), ft_mmx(0));
        break;
    case FT_X87_FSCALE:
        if (option_soft_fpu) {
#ifdef QUICKTRANS_LATU
            ft_emit_x87_soft_binary_reg(&out, 1, FT_X87_REG_SCALE, 0);
#else
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_fscale);
#endif
            break;
        }
        if (ft_x87_latu_legacy_no_tag()) {
            FT_LA_FTINTRZ_L_D_EMIT(&out, ft_vscratch + 2, ft_mmx(1));
            FT_LA_FSCALEB_D_EMIT(&out, ft_mmx(0), ft_mmx(0),
                                 ft_vscratch + 2);
            break;
        }
    {
        FastBranchLabel normal = { 0 };
        FastBranchLabel done = { 0 };
        FastBranchFixup normal_fixup;
        FastBranchFixup done_fixup;

        ft_emit_x87_load_st_tag(&out, la_t0, 1);
        ft_emit_branch_placeholder(&out, &normal_fixup, FT_BRANCH_BEQ,
                                   la_t0, la_zero, &normal);
        ft_emit_x87_empty_qnan(&out, ft_mmx(0));
        ft_emit_branch_placeholder(&out, &done_fixup, FT_BRANCH_B, 0, 0,
                                   &done);
        ft_bind_branch_label(&normal, out);
        ft_resolve_branch_fixup(&normal_fixup);
        FT_LA_FTINTRZ_L_D_EMIT(&out, ft_vscratch + 2, ft_mmx(1));
        FT_LA_FSCALEB_D_EMIT(&out, ft_mmx(0), ft_mmx(0),
                             ft_vscratch + 2);
        ft_bind_branch_label(&done, out);
        ft_resolve_branch_fixup(&done_fixup);
        break;
    }
    case FT_X87_FSIN:
    case FT_X87_FCOS:
        if (option_soft_fpu) {
            ft_emit_x87_complex_helper(&out, fields->kind == FT_X87_FSIN ?
                               (void *)ft_x87_helper_fsin : (void *)ft_x87_helper_fcos,
                               fields->kind == FT_X87_FSIN ?
                               (void *)helper_fsin : (void *)helper_fcos);
        } else {
            ft_emit_x87_call_unary_double(&out,
                                          fields->kind == FT_X87_FSIN ?
                                          (void *)sin : (void *)cos);
#ifdef QUICKTRANS_LATU
            /* Legacy hard-FPU FSIN/FCOS clear C2 after the math call. */
            ft_emit_load_env(&out, la_t0, lsenv_offset_of_status_word(lsenv),
                             FT_LA_OPCODE_LD_HU);
            FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_zero, 10, 10);
            ft_emit_store_env(&out, la_t0, lsenv_offset_of_status_word(lsenv),
                              FT_LA_OPCODE_ST_H);
#endif
        }
        break;
    case FT_X87_FSINCOS:
        if (option_soft_fpu) {
            ft_emit_x87_complex_helper(&out, (void *)ft_x87_helper_fsincos,
                                        (void *)helper_fsincos);
        } else {
            ft_emit_x87_call_fsincos(&out);
            FT_LA_X86DECTOP_EMIT(&out);
            ft_emit_x87_mark_current_tag(&out, 0);
        }
        break;
    case FT_X87_FPTAN:
        if (option_soft_fpu) {
            ft_emit_x87_complex_helper(&out, (void *)ft_x87_helper_fptan,
                                        (void *)helper_fptan);
        } else {
            ft_emit_x87_call_unary_double(&out, (void *)tan);
            FT_LA_ORI_EMIT(&out, la_t0, la_zero, 1);
            FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(7), la_t0);
            FT_LA_FFINT_D_W_EMIT(&out, ft_mmx(7), ft_mmx(7));
            FT_LA_X86DECTOP_EMIT(&out);
            ft_emit_x87_mark_current_tag(&out, 0);
        }
        break;
    case FT_X87_FPATAN:
        if (option_soft_fpu) {
            ft_emit_x87_complex_helper(&out, (void *)ft_x87_helper_fpatan,
                                        (void *)helper_fpatan);
        } else {
            ft_emit_x87_hard_helper(&out, (void *)ft_x87_hard_fpatan);
        }
        break;
    case FT_X87_FPREM:
        if (option_soft_fpu) {
            ft_emit_x87_complex_helper(&out, (void *)ft_x87_helper_fprem,
                                        (void *)helper_fprem);
        } else {
            ft_emit_x87_hard_helper(&out, (void *)ft_x87_hard_fprem);
        }
        break;
    case FT_X87_FPREM1:
        if (option_soft_fpu) {
            ft_emit_x87_complex_helper(&out, (void *)ft_x87_helper_fprem1,
                                        (void *)helper_fprem1);
        } else {
            ft_emit_x87_hard_helper(&out, (void *)ft_x87_hard_fprem1);
        }
        break;
    case FT_X87_FYL2X:
        if (option_soft_fpu) {
            ft_emit_x87_complex_helper(&out, (void *)ft_x87_helper_fyl2x,
                                        (void *)helper_fyl2x);
        } else {
            ft_emit_x87_hard_helper(&out, (void *)ft_x87_hard_fyl2x);
        }
        break;
    case FT_X87_FYL2XP1:
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (!option_soft_fpu) {
            ft_emit_x87_hard_helper(&out,
                                     (void *)ft_x87_hard_fyl2xp1_checked);
            break;
        }
#endif
        ft_emit_x87_complex_helper(&out, (void *)ft_x87_helper_fyl2xp1,
                                        (void *)helper_fyl2xp1);
        break;
    case FT_X87_FBLD:
    {
        int addr;
        int offset;
        void *helper = (void *)helper_fbld_ST0;
        bool convert_hard_regs = !option_soft_fpu;

#if defined(QUICKTRANS_LATU) && defined(CONFIG_LATX_FAST_TRANSLATOR) && \
    defined(TARGET_X86_64) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_BCD_HARD64_ABI)
        if (!option_soft_fpu) {
            helper = (void *)ft_x87_hard_fbld;
            convert_hard_regs = false;
        }
#endif

        if (fields->modrm_mod == 3 ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        offset = ft_mem_access_offset(fields, addr);
        if (!ft_fits_simm12(offset)) {
            return 0;
        }
        FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);
        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
        FT_LA_ST_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);

        ft_emit_helper_prologue(&out);
        if (convert_hard_regs) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_64_to_x80,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, helper, 1u << 0);
        if (convert_hard_regs) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_x80_to_64,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
        ft_emit_host_stack_end(&out);
        ft_emit_x87_helper_epilogue(&out);
        break;
    }
    case FT_X87_FBSTP:
    {
        int addr;
        int offset;
        void *helper = (void *)helper_fbst_ST0;
        bool convert_hard_regs = !option_soft_fpu;
        bool pop_after_helper = true;

#if defined(QUICKTRANS_LATU) && defined(CONFIG_LATX_FAST_TRANSLATOR) && \
    defined(TARGET_X86_64) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_BCD_HARD64_ABI)
        if (!option_soft_fpu) {
            helper = (void *)ft_x87_hard_fbstp;
            convert_hard_regs = false;
            pop_after_helper = false;
        }
#endif

        if (fields->modrm_mod == 3 ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        offset = ft_mem_access_offset(fields, addr);
        if (!ft_fits_simm12(offset)) {
            return 0;
        }
        FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);
        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
        FT_LA_ST_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);

        ft_emit_helper_prologue(&out);
        if (convert_hard_regs) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_64_to_x80,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, helper, 1u << 0);
        if (pop_after_helper) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fpop, 1u << 0);
        }
        if (convert_hard_regs) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_x80_to_64,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
        ft_emit_host_stack_end(&out);
        ft_emit_x87_helper_epilogue(&out);
        break;
    }
    case FT_X87_FXAM:
    {
        if (option_soft_fpu) {
            ft_emit_x87_helper(&out, (void *)helper_fxam_ST0);
            break;
        }

        int status_offset = lsenv_offset_of_status_word(lsenv);
        FastBranchLabel not_empty = { 0 };
        FastBranchLabel empty_done = { 0 };
        FastBranchLabel inf_nan = { 0 };
        FastBranchLabel zero_denorm = { 0 };
        FastBranchLabel normal_done = { 0 };
        FastBranchLabel infinity = { 0 };
        FastBranchLabel nan_done = { 0 };
        FastBranchLabel infinity_done = { 0 };
        FastBranchLabel zero = { 0 };
        FastBranchLabel denorm_done = { 0 };
        FastBranchFixup not_empty_fixup;
        FastBranchFixup empty_done_fixup;
        FastBranchFixup inf_nan_fixup;
        FastBranchFixup zero_denorm_fixup;
        FastBranchFixup normal_done_fixup;
        FastBranchFixup infinity_fixup;
        FastBranchFixup nan_done_fixup;
        FastBranchFixup infinity_done_fixup;
        FastBranchFixup zero_fixup;
        FastBranchFixup denorm_done_fixup;

        if (!ft_offset_fits_imm12(status_offset)) {
            return 0;
        }

        FT_LA_MOVFR2GR_D_EMIT(&out, la_t0, ft_mmx(0));

        ft_emit_load_env(&out, la_t1, status_offset, FT_LA_OPCODE_LD_HU);
        ft_emit_li64(&out, la_t2, 0xb8ff);
        FT_LA_AND_EMIT(&out, la_t1, la_t1, la_t2);

        /* C1 is exactly the sign bit, including empty and NaN inputs. */
        FT_LA_BSTRPICK_D_EMIT(&out, la_t3, la_t0, 63, 63);
        FT_LA_BSTRINS_D_EMIT(&out, la_t1, la_t3, 9, 9);

        if (ft_x87_latu_legacy_no_tag()) {
            /* Legacy tag-off FXAM approximates empty by TOP == 0. */
            FT_LA_X86MFTOP_EMIT(&out, la_t4);
            ft_emit_branch_placeholder(&out, &not_empty_fixup, FT_BRANCH_BNE,
                                       la_t4, la_zero, &not_empty);
        } else {
            ft_emit_x87_load_current_tag(&out, la_t4);
            ft_emit_branch_placeholder(&out, &not_empty_fixup, FT_BRANCH_BEQ,
                                       la_t4, la_zero, &not_empty);
        }
        ft_emit_li64(&out, la_t2, 0x4100);
        FT_LA_OR_EMIT(&out, la_t1, la_t1, la_t2);
        ft_emit_branch_placeholder(&out, &empty_done_fixup, FT_BRANCH_B, 0,
                                   0, &empty_done);
        ft_bind_branch_label(&not_empty, out);
        ft_resolve_branch_fixup(&not_empty_fixup);

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        FT_LA_BSTRPICK_D_EMIT(&out, la_t3, la_t0, 62, 52);
        FT_LA_ORI_EMIT(&out, la_t2, la_zero, 0x7ff);
#else
        ft_emit_li64(&out, la_t2, 0x7ff0000000000000ULL);
        FT_LA_AND_EMIT(&out, la_t3, la_t0, la_t2);
#endif
        ft_emit_branch_placeholder(&out, &inf_nan_fixup, FT_BRANCH_BEQ,
                                   la_t3, la_t2, &inf_nan);
        ft_emit_branch_placeholder(&out, &zero_denorm_fixup, FT_BRANCH_BEQ,
                                   la_t3, la_zero, &zero_denorm);
        FT_LA_ORI_EMIT(&out, la_t1, la_t1, 0x400);
        ft_emit_branch_placeholder(&out, &normal_done_fixup, FT_BRANCH_B, 0,
                                   0, &normal_done);

        ft_bind_branch_label(&inf_nan, out);
        ft_resolve_branch_fixup(&inf_nan_fixup);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        FT_LA_BSTRPICK_D_EMIT(&out, la_t3, la_t0, 51, 0);
#else
        ft_emit_li64(&out, la_t2, 0x000fffffffffffffULL);
        FT_LA_AND_EMIT(&out, la_t3, la_t0, la_t2);
#endif
        ft_emit_branch_placeholder(&out, &infinity_fixup, FT_BRANCH_BEQ,
                                   la_t3, la_zero, &infinity);
        FT_LA_ORI_EMIT(&out, la_t1, la_t1, 0x100);
        ft_emit_branch_placeholder(&out, &nan_done_fixup, FT_BRANCH_B, 0, 0,
                                   &nan_done);
        ft_bind_branch_label(&infinity, out);
        ft_resolve_branch_fixup(&infinity_fixup);
        FT_LA_ORI_EMIT(&out, la_t1, la_t1, 0x500);
        ft_emit_branch_placeholder(&out, &infinity_done_fixup, FT_BRANCH_B,
                                   0, 0, &infinity_done);

        ft_bind_branch_label(&zero_denorm, out);
        ft_resolve_branch_fixup(&zero_denorm_fixup);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        FT_LA_BSTRPICK_D_EMIT(&out, la_t3, la_t0, 51, 0);
#else
        ft_emit_li64(&out, la_t2, 0x000fffffffffffffULL);
        FT_LA_AND_EMIT(&out, la_t3, la_t0, la_t2);
#endif
        ft_emit_branch_placeholder(&out, &zero_fixup, FT_BRANCH_BEQ, la_t3,
                                   la_zero, &zero);
        ft_emit_li64(&out, la_t2, 0x4400);
        FT_LA_OR_EMIT(&out, la_t1, la_t1, la_t2);
        ft_emit_branch_placeholder(&out, &denorm_done_fixup, FT_BRANCH_B, 0,
                                   0, &denorm_done);
        ft_bind_branch_label(&zero, out);
        ft_resolve_branch_fixup(&zero_fixup);
        ft_emit_li64(&out, la_t2, 0x4000);
        FT_LA_OR_EMIT(&out, la_t1, la_t1, la_t2);

        ft_bind_branch_label(&empty_done, out);
        ft_resolve_branch_fixup(&empty_done_fixup);
        ft_bind_branch_label(&normal_done, out);
        ft_resolve_branch_fixup(&normal_done_fixup);
        ft_bind_branch_label(&nan_done, out);
        ft_resolve_branch_fixup(&nan_done_fixup);
        ft_bind_branch_label(&infinity_done, out);
        ft_resolve_branch_fixup(&infinity_done_fixup);
        ft_bind_branch_label(&denorm_done, out);
        ft_resolve_branch_fixup(&denorm_done_fixup);
        ft_emit_store_env(&out, la_t1, status_offset, FT_LA_OPCODE_ST_H);
        break;
    }
    case FT_X87_FXTRACT:
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (!option_soft_fpu) {
            ft_emit_x87_hard_helper(&out,
                                     (void *)ft_x87_hard_fxtract_checked);
            break;
        }
#endif
        ft_emit_x87_complex_helper(&out, (void *)ft_x87_helper_fxtract,
                                        (void *)helper_fxtract);
        break;
    case FT_X87_FSQRT:
        if (option_soft_fpu) {
            ft_emit_x87_soft_unary(&out, true);
            break;
        }
#ifdef QUICKTRANS_LATU
        /* Match the legacy LATU sequence, including negative zero and NaNs. */
        FT_LA_FSQRT_D_EMIT(&out, ft_mmx(0), ft_mmx(0));
#else
        FT_LA_MOVFR2GR_D_EMIT(&out, la_t0, ft_mmx(0));
        FT_LA_SRAI_D_EMIT(&out, la_t1, la_t0, 63);
        FT_LA_FSQRT_D_EMIT(&out, ft_mmx(0), ft_mmx(0));
        FT_LA_MOVFR2GR_D_EMIT(&out, la_t2, ft_mmx(0));
        ft_emit_li64(&out, la_t3, 0xfff8000000000000ULL);
        FT_LA_AND_EMIT(&out, la_t3, la_t3, la_t1);
        FT_LA_ANDN_EMIT(&out, la_t2, la_t2, la_t1);
        FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t3);
        FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(0), la_t2);
#endif
        break;
    case FT_X87_FIST_M16:
    {
        int addr;
        int offset;
        int value_reg;

        if (fields->modrm_mod == 3 || fields->modrm_reg != 2) {
            return 0;
        }
        if (option_soft_fpu) {
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            offset = ft_mem_access_offset(fields, addr);
            FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);
            ft_emit_host_stack_begin(&out);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
            FT_LA_ST_D_EMIT(&out, la_a1, la_sp, 0);
            ft_emit_host_stack_end(&out);
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_x87_helper_fist, 1u << 0);
            ft_emit_host_stack_begin(&out);
            FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
            ft_emit_host_stack_end(&out);
            FT_LA_ST_H_EMIT(&out, la_a0, la_a1, 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        value_reg = addr == la_t0 ? la_t1 : la_t0;
        ft_emit_x87_store_int(&out, addr, ft_mem_access_offset(fields, addr),
                              16, false, value_reg);
        break;
    }
    case FT_X87_FIST_M32:
    {
        int addr;
        int offset;
        int value_reg;

        if (fields->modrm_mod == 3 ||
            fields->modrm_reg != 2) {
            return 0;
        }
        if (option_soft_fpu) {
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            offset = ft_mem_access_offset(fields, addr);
            FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);
            ft_emit_host_stack_begin(&out);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
            FT_LA_ST_D_EMIT(&out, la_a1, la_sp, 0);
            ft_emit_host_stack_end(&out);
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_x87_helper_fistl, 1u << 0);
            ft_emit_host_stack_begin(&out);
            FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
            ft_emit_host_stack_end(&out);
            FT_LA_ST_W_EMIT(&out, la_a0, la_a1, 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        value_reg = addr == la_t0 ? la_t1 : la_t0;
        ft_emit_x87_store_int(&out, addr, ft_mem_access_offset(fields, addr),
                              32, false, value_reg);
        break;
    }
    case FT_X87_FI_BIN_M16:
    case FT_X87_FI_BIN_M32:
    {
        int addr;
        int op_ext = (fields->modrm >> 3) & 7;
        int width = fields->kind == FT_X87_FI_BIN_M16 ? 16 : 32;

        if (fields->modrm_mod == 3) {
            return 0;
        }
        if (option_soft_fpu) {
            if (op_ext != 2 && op_ext != 3) {
                if (!ft_emit_x87_soft_binary_mem(&out, fields, pc, width,
                                                true, op_ext)) {
                    return 0;
                }
                break;
            }
            ft_emit_helper_prologue(&out);
            if (direct_extra && extra.loaded) {
                FT_LA_MOVFR2GR_D_EMIT(&out, la_a1, ft_vscratch + 1);
            } else {
                if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                    return 0;
                }
                if (width == 16) {
                    FT_LA_LD_H_EMIT(&out, la_a1, addr,
                                     ft_mem_access_offset(fields, addr));
                } else {
                    FT_LA_LD_W_EMIT(&out, la_a1, addr,
                                     ft_mem_access_offset(fields, addr));
                }
            }
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fildl_FT0, 1u << 0);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fcom_ST0_FT0, 1u << 0);
            if (op_ext == 3) {
                ft_emit_cpu_env_ptr(&out, la_a0);
                ft_emit_host_call(&out, (void *)helper_fpop, 1u << 0);
            }
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        ft_emit_x87_load_int_to_freg(&out, addr,
                                     ft_mem_access_offset(fields, addr),
                                     width, ft_vscratch + 1);
        switch (op_ext) {
        case 0:
            FT_LA_FADD_D_EMIT(&out, ft_mmx(0), ft_mmx(0),
                              ft_vscratch + 1);
            break;
        case 1:
            FT_LA_FMUL_D_EMIT(&out, ft_mmx(0), ft_mmx(0),
                              ft_vscratch + 1);
            break;
        case 2:
        case 3:
            ft_emit_x87_fcom_status(&out, ft_vscratch + 1, ft_mmx(0), true);
            if (op_ext == 3) {
                ft_emit_x87_pop(&out);
                ft_emit_x87_empty_qnan(&out, ft_vscratch);
            }
            break;
        case 4:
            FT_LA_FSUB_D_EMIT(&out, ft_mmx(0), ft_mmx(0),
                              ft_vscratch + 1);
            break;
        case 5:
            FT_LA_FSUB_D_EMIT(&out, ft_mmx(0), ft_vscratch + 1,
                              ft_mmx(0));
            break;
        case 6:
            FT_LA_FDIV_D_EMIT(&out, ft_mmx(0), ft_mmx(0),
                              ft_vscratch + 1);
            break;
        case 7:
            FT_LA_FDIV_D_EMIT(&out, ft_mmx(0), ft_vscratch + 1,
                              ft_mmx(0));
            break;
        default:
            return 0;
        }
        break;
    }
    case FT_X87_FILD_M16:
    case FT_X87_FILD_M32:
    case FT_X87_FILD_M64:
    {
        int addr;
        int width;

        if (fields->modrm_mod == 3 ||
            !ft_x87_fild_width(fields->kind, &width)) {
            return 0;
        }
        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            if (direct_extra && extra.loaded) {
                FT_LA_MOVFR2GR_D_EMIT(&out, la_a1, ft_vscratch + 1);
            } else {
                if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                    return 0;
                }
                if (width == 16) {
                    FT_LA_LD_H_EMIT(&out, la_a1, addr,
                                    ft_mem_access_offset(fields, addr));
                } else if (width == 32) {
                    FT_LA_LD_W_EMIT(&out, la_a1, addr,
                                    ft_mem_access_offset(fields, addr));
                } else {
                    FT_LA_LD_D_EMIT(&out, la_a1, addr,
                                    ft_mem_access_offset(fields, addr));
                }
            }
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, width == 64 ?
                              (void *)helper_fildll_ST0 :
                              (void *)helper_fildl_ST0, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        ft_emit_x87_load_int_to_freg(&out, addr,
                                     ft_mem_access_offset(fields, addr),
                                     width, ft_mmx(7));
        FT_LA_X86DECTOP_EMIT(&out);
        ft_emit_x87_mark_current_tag(&out, 0);
        break;
    }
    case FT_X87_FISTP_M16:
    case FT_X87_FISTP_M32:
    case FT_X87_FISTP_M64:
    case FT_X87_FISTTP_M16:
    case FT_X87_FISTTP_M32:
    case FT_X87_FISTTP_M64:
    {
        int addr;
        int offset;
        int width;
        int value_reg;
        bool trunc;

        if (fields->modrm_mod == 3 ||
            !ft_x87_fist_width(fields->kind, &width, &trunc)) {
            return 0;
        }
        if (option_soft_fpu) {
            void *helper = width == 16 ?
                (trunc ? (void *)ft_x87_helper_fistt :
                         (void *)ft_x87_helper_fist) :
                width == 32 ?
                (trunc ? (void *)ft_x87_helper_fisttl :
                         (void *)ft_x87_helper_fistl) :
                (trunc ? (void *)ft_x87_helper_fisttll :
                         (void *)ft_x87_helper_fistll);

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            offset = ft_mem_access_offset(fields, addr);
            FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);
            ft_emit_host_stack_begin(&out);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
            FT_LA_ST_D_EMIT(&out, la_a1, la_sp, 0);
            ft_emit_host_stack_end(&out);
            bool compact_context = direct_extra &&
                fields->kind == FT_X87_FISTP_M32;
            if (!(compact_context && ft_emit_x87_integer_inline_context(&out, false)))
                ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, helper, 1u << 0);
            ft_emit_host_stack_begin(&out);
            FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
            ft_emit_host_stack_end(&out);
            ft_emit_x87_soft_store(&out, la_a1, la_a0, width);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fpop, 1u << 0);
            if (!(compact_context && ft_emit_x87_integer_inline_context(&out, true)))
                ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        value_reg = addr == la_t0 ? la_t1 : la_t0;
        ft_emit_x87_store_int(&out, addr, ft_mem_access_offset(fields, addr),
                              width, trunc, value_reg);
        ft_emit_x87_pop(&out);
        break;
    }
    case FT_X87_FST_M32:
    case FT_X87_FST_M64:
    case FT_X87_FSTP_M32:
    case FT_X87_FSTP_M64:
    {
        int addr;
        int offset;
        bool is_m32 = fields->kind == FT_X87_FSTP_M32 ||
                      fields->kind == FT_X87_FST_M32;
        bool is_pop = fields->kind == FT_X87_FSTP_M64 ||
                      fields->kind == FT_X87_FSTP_M32;
        FastBranchLabel normal = { 0 };
        FastBranchLabel done = { 0 };
        FastBranchFixup normal_fixup;
        FastBranchFixup done_fixup;
        bool have_normal = false;
        bool have_done = false;

        if (fields->modrm_mod == 3) {
            return 0;
        }

        if (option_soft_fpu) {
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            offset = ft_mem_access_offset(fields, addr);
            FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);
            ft_emit_host_stack_begin(&out);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
            FT_LA_ST_D_EMIT(&out, la_a1, la_sp, 0);
            ft_emit_host_stack_end(&out);
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, is_m32 ? (void *)ft_x87_helper_fsts :
                              (void *)ft_x87_helper_fstl, 1u << 0);
            ft_emit_host_stack_begin(&out);
            FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
            ft_emit_host_stack_end(&out);
            ft_emit_x87_soft_store(&out, la_a1, la_a0,
                                   is_m32 ? 32 : 64);
            if (is_pop) {
                ft_emit_cpu_env_ptr(&out, la_a0);
                ft_emit_host_call(&out, (void *)helper_fpop, 1u << 0);
            }
            ft_emit_x87_helper_epilogue(&out);
            break;
        }

        if (!ft_x87_latu_legacy_no_tag()) {
            ft_emit_x87_load_current_tag(&out, la_t0);
            ft_emit_branch_placeholder(&out, &normal_fixup, FT_BRANCH_BEQ,
                                       la_t0, la_zero, &normal);
            have_normal = true;
        }

        if (have_normal) {
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            int value_reg = addr == la_t0 ? la_t1 : la_t0;

            if (is_m32) {
                ft_emit_li64(&out, value_reg, 0xffc00000u);
                FT_LA_ST_W_EMIT(&out, value_reg, addr,
                                ft_mem_access_offset(fields, addr));
            } else {
                ft_emit_li64(&out, value_reg, 0xfff8000000000000ULL);
                FT_LA_ST_D_EMIT(&out, value_reg, addr,
                                ft_mem_access_offset(fields, addr));
            }
            if (is_pop) {
                ft_emit_x87_pop(&out);
            }
            if (!have_normal) {
                break;
            }
            ft_emit_branch_placeholder(&out, &done_fixup, FT_BRANCH_B, 0, 0,
                                       &done);
            have_done = true;
            ft_bind_branch_label(&normal, out);
            ft_resolve_branch_fixup(&normal_fixup);
        }

        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        if (is_m32) {
            int value_reg = addr == la_t0 ? la_t1 : la_t0;

            FT_LA_MOVFR2GR_D_EMIT(&out, value_reg, ft_mmx(0));
            FT_LA_MOVGR2FR_D_EMIT(&out, ft_vscratch, value_reg);
            FT_LA_FCVT_S_D_EMIT(&out, ft_vscratch + 1, ft_vscratch);
            FT_LA_FST_S_EMIT(&out, ft_vscratch + 1, addr,
                             ft_mem_access_offset(fields, addr));
        } else {
            FT_LA_FST_D_EMIT(&out, ft_mmx(0), addr,
                             ft_mem_access_offset(fields, addr));
        }
        if (is_pop) {
            ft_emit_x87_pop(&out);
        }
        if (have_done) {
            ft_bind_branch_label(&done, out);
            ft_resolve_branch_fixup(&done_fixup);
        }
        break;
    }
    case FT_X87_FSTP_M80:
    {
        int addr;
        int offset;

        if (fields->modrm_mod == 3 ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }

        offset = ft_mem_access_offset(fields, addr);
        FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);

#ifdef QUICKTRANS_LATU
        FastBranchLabel slow = {0}, done = {0};
        FastBranchFixup empty, finish;
        int fp = lsenv_offset_of_fpr(lsenv, 0);
        int tag = lsenv_offset_of_tag_word(lsenv);
        bool direct = option_soft_fpu == 2 &&
                      (option_softfpu_fast & 0x800000) &&
                      ft_offset_fits_imm12(fp + 8) &&
                      ft_offset_fits_imm12(tag);
        if (direct) {
            ft_emit_load_env(&out, la_t0, lsenv_offset_of_top(lsenv),
                             FT_LA_OPCODE_LD_WU);
            ft_emit_cpu_env_ptr(&out, la_t4);
            FT_LA_ADD_D_EMIT(&out, la_t3, la_t4, la_t0);
            FT_LA_LD_BU_EMIT(&out, la_t1, la_t3, tag);
            ft_emit_branch_placeholder(&out, &empty, FT_BRANCH_BNE,
                                       la_t1, la_zero, &slow);
            /* Preserve helper ordering: clear C1 before the stores, but
             * pop only after both guest writes have succeeded. */
            ft_emit_load_env(&out, la_t1, lsenv_offset_of_status_word(lsenv),
                             FT_LA_OPCODE_LD_HU);
            FT_LA_BSTRINS_D_EMIT(&out, la_t1, la_zero, 9, 9);
            ft_emit_store_env(&out, la_t1, lsenv_offset_of_status_word(lsenv),
                              FT_LA_OPCODE_ST_H);
            FT_LA_SLLI_D_EMIT(&out, la_t3, la_t0, 4);
            FT_LA_ADD_D_EMIT(&out, la_t3, la_t4, la_t3);
            FT_LA_LD_D_EMIT(&out, la_t1, la_t3, fp);
            FT_LA_LD_HU_EMIT(&out, la_t2, la_t3, fp + 8);
            FT_LA_ST_D_EMIT(&out, la_t1, la_a1, 0);
            FT_LA_ST_H_EMIT(&out, la_t2, la_a1, 8);
            FT_LA_ADD_D_EMIT(&out, la_t3, la_t4, la_t0);
            FT_LA_ORI_EMIT(&out, la_t1, la_zero, 1);
            FT_LA_ST_B_EMIT(&out, la_t1, la_t3, tag);
            FT_LA_ADDI_D_EMIT(&out, la_t0, la_t0, 1);
            FT_LA_ANDI_EMIT(&out, la_t0, la_t0, 7);
            ft_emit_store_env(&out, la_t0, lsenv_offset_of_top(lsenv),
                              FT_LA_OPCODE_ST_W);
            ft_emit_branch_placeholder(&out, &finish,
                                       FT_BRANCH_B, 0, 0, &done);
            ft_bind_branch_label(&slow, out);
            ft_resolve_branch_fixup(&empty);
        }
#endif

        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
        FT_LA_ST_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);

        ft_emit_helper_prologue(&out);
        if (!option_soft_fpu) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_64_to_x80,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        if (option_soft_fpu) {
            ft_emit_host_call(&out, (void *)ft_x87_helper_fstp80, 1u << 0);
        } else {
            ft_emit_host_call(&out, (void *)helper_fstt_ST0, 1u << 0);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fpop, 1u << 0);
        }
        if (!option_soft_fpu) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_x80_to_64,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
        ft_emit_host_stack_end(&out);
        ft_emit_x87_helper_epilogue(&out);
#ifdef QUICKTRANS_LATU
        if (direct) {
            ft_bind_branch_label(&done, out);
            ft_resolve_branch_fixup(&finish);
        }
#endif
        break;
    }
    case FT_X87_BIN_REG:
    {
        int st_index = fields->modrm & 7;

        if (fields->modrm_mod != 3) {
            return 0;
        }
        if (option_soft_fpu) {
            int op;
            switch (fields->id) {
            case dt_X86_INS_FADD: op = FT_X87_REG_ADD; break;
            case dt_X86_INS_FMUL: op = FT_X87_REG_MUL; break;
            case dt_X86_INS_FSUB: op = FT_X87_REG_SUB; break;
            case dt_X86_INS_FSUBR: op = FT_X87_REG_SUBR; break;
            case dt_X86_INS_FDIV: op = FT_X87_REG_DIV; break;
            case dt_X86_INS_FDIVR: op = FT_X87_REG_DIVR; break;
            default: return 0;
            }
            ft_emit_x87_soft_binary_reg(&out, st_index, op,
                                        fields->opcode0 != 0xd8);
            break;
        }
        if (fields->opcode0 == 0xd8) {
            switch (fields->id) {
            case dt_X86_INS_FADD:
                FT_LA_FADD_D_EMIT(&out, ft_mmx(0), ft_mmx(0), ft_mmx(st_index));
                break;
            case dt_X86_INS_FMUL:
                FT_LA_FMUL_D_EMIT(&out, ft_mmx(0), ft_mmx(0), ft_mmx(st_index));
                break;
            case dt_X86_INS_FSUB:
                FT_LA_FSUB_D_EMIT(&out, ft_mmx(0), ft_mmx(0), ft_mmx(st_index));
                break;
            case dt_X86_INS_FSUBR:
                FT_LA_FSUB_D_EMIT(&out, ft_mmx(0), ft_mmx(st_index), ft_mmx(0));
                break;
            case dt_X86_INS_FDIV:
                FT_LA_FDIV_D_EMIT(&out, ft_mmx(0), ft_mmx(0), ft_mmx(st_index));
                break;
            case dt_X86_INS_FDIVR:
                FT_LA_FDIV_D_EMIT(&out, ft_mmx(0), ft_mmx(st_index), ft_mmx(0));
                break;
            default:
                return 0;
            }
        } else {
            switch (fields->id) {
            case dt_X86_INS_FADD:
                FT_LA_FADD_D_EMIT(&out, ft_mmx(st_index), ft_mmx(st_index), ft_mmx(0));
                break;
            case dt_X86_INS_FMUL:
                FT_LA_FMUL_D_EMIT(&out, ft_mmx(st_index), ft_mmx(st_index), ft_mmx(0));
                break;
            case dt_X86_INS_FSUB:
                FT_LA_FSUB_D_EMIT(&out, ft_mmx(st_index), ft_mmx(st_index), ft_mmx(0));
                break;
            case dt_X86_INS_FSUBR:
                FT_LA_FSUB_D_EMIT(&out, ft_mmx(st_index), ft_mmx(0), ft_mmx(st_index));
                break;
            case dt_X86_INS_FDIV:
                FT_LA_FDIV_D_EMIT(&out, ft_mmx(st_index), ft_mmx(st_index), ft_mmx(0));
                break;
            case dt_X86_INS_FDIVR:
                FT_LA_FDIV_D_EMIT(&out, ft_mmx(st_index), ft_mmx(0), ft_mmx(st_index));
                break;
            default:
                return 0;
            }
        }
#ifdef QUICKTRANS_LATU
        if (fields->id == dt_X86_INS_FDIV || fields->id == dt_X86_INS_FDIVR) {
            ft_emit_latu_x87_div_status(&out);
        }
#endif
        break;
    }
    case FT_X87_BIN_M32:
    case FT_X87_BIN_M64:
    {
        int addr;
        int op_ext = (fields->modrm >> 3) & 7;
        bool is_m32 = fields->kind == FT_X87_BIN_M32;

        if (fields->modrm_mod == 3) {
            return 0;
        }
        if (option_soft_fpu) {
            if (op_ext == 2 || op_ext == 3 ||
                !ft_emit_x87_soft_binary_mem(&out, fields, pc,
                                            is_m32 ? 32 : 64, false, op_ext)) {
                return 0;
            }
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        if (is_m32) {
            FT_LA_FLD_S_EMIT(&out, ft_vscratch, addr,
                             ft_mem_access_offset(fields, addr));
            FT_LA_FCVT_D_S_EMIT(&out, ft_vscratch, ft_vscratch);
        } else {
            FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                             ft_mem_access_offset(fields, addr));
        }
        switch (op_ext) {
        case 0:
            FT_LA_FADD_D_EMIT(&out, ft_mmx(0), ft_mmx(0), ft_vscratch);
            break;
        case 1:
            FT_LA_FMUL_D_EMIT(&out, ft_mmx(0), ft_mmx(0), ft_vscratch);
            break;
        case 4:
            FT_LA_FSUB_D_EMIT(&out, ft_mmx(0), ft_mmx(0), ft_vscratch);
            break;
        case 5:
            FT_LA_FSUB_D_EMIT(&out, ft_mmx(0), ft_vscratch, ft_mmx(0));
            break;
        case 6:
            FT_LA_FDIV_D_EMIT(&out, ft_mmx(0), ft_mmx(0), ft_vscratch);
            break;
        case 7:
            FT_LA_FDIV_D_EMIT(&out, ft_mmx(0), ft_vscratch, ft_mmx(0));
            break;
        default:
            return 0;
        }
#ifdef QUICKTRANS_LATU
        if (op_ext == 6 || op_ext == 7) {
            ft_emit_latu_x87_div_status(&out);
        }
#endif
        break;
    }
    case FT_X87_FCOM_M64:
    {
        int addr;
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

        if (fields->modrm_mod == 3 ||
            (fields->modrm_reg != 2 && fields->modrm_reg != 3)) {
            return 0;
        }
        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            if (direct_extra && extra.loaded) {
                FT_LA_MOVFR2GR_D_EMIT(&out, la_a1, ft_vscratch + 1);
            } else {
                if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                    return 0;
                }
                FT_LA_LD_D_EMIT(&out, la_a1, addr,
                                ft_mem_access_offset(fields, addr));
            }
            if (!ft_emit_x87_mark_denormal_operand(&out, la_a1, true)) {
                return 0;
            }
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fldl_FT0, 1u << 0);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fcom_ST0_FT0, 1u << 0);
            if (fields->modrm_reg == 3) {
                ft_emit_cpu_env_ptr(&out, la_a0);
                ft_emit_host_call(&out, (void *)helper_fpop, 1u << 0);
            }
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr) ||
            !ft_offset_fits_imm12(fpus_offset)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        FT_LA_MOVFR2GR_D_EMIT(&out, la_t4, ft_vscratch);
        if (!ft_emit_x87_mark_denormal_operand(&out, la_t4, true)) {
            return 0;
        }
        ft_emit_x87_fcom_status(&out, ft_vscratch, ft_mmx(0), true);
        if (fields->modrm_reg == 3) {
            ft_emit_x87_pop(&out);
        }
        break;
    }
    case FT_X87_FCOM_M32:
    {
        int addr;
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

        if (fields->modrm_mod == 3 ||
            (fields->modrm_reg != 2 && fields->modrm_reg != 3)) {
            return 0;
        }
        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            if (direct_extra && extra.loaded) {
                FT_LA_MOVFR2GR_D_EMIT(&out, la_a1, ft_vscratch + 1);
            } else {
                if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                    return 0;
                }
                FT_LA_LD_WU_EMIT(&out, la_a1, addr,
                                 ft_mem_access_offset(fields, addr));
            }
            if (!ft_emit_x87_mark_denormal_operand(&out, la_a1, false)) {
                return 0;
            }
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_flds_FT0, 1u << 0);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fcom_ST0_FT0, 1u << 0);
            if (fields->modrm_reg == 3) {
                ft_emit_cpu_env_ptr(&out, la_a0);
                ft_emit_host_call(&out, (void *)helper_fpop, 1u << 0);
            }
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr) ||
            !ft_offset_fits_imm12(fpus_offset)) {
            return 0;
        }
        FT_LA_FLD_S_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        FT_LA_MOVFR2GR_S_EMIT(&out, la_t4, ft_vscratch);
        if (!ft_emit_x87_mark_denormal_operand(&out, la_t4, false)) {
            return 0;
        }
        FT_LA_FCVT_D_S_EMIT(&out, ft_vscratch, ft_vscratch);
        ft_emit_x87_fcom_status(&out, ft_vscratch, ft_mmx(0), true);
        if (fields->modrm_reg == 3) {
            ft_emit_x87_pop(&out);
        }
        break;
    }
    case FT_X87_FADDP:
    case FT_X87_FSUBP:
    case FT_X87_FSUBRP:
    case FT_X87_FMULP:
    case FT_X87_FDIVP:
    case FT_X87_FDIVRP:
    {
        int st_index = fields->modrm & 7;

        if (option_soft_fpu) {
            int op;
            switch (fields->kind) {
            case FT_X87_FADDP: op = FT_X87_REG_ADD; break;
            case FT_X87_FMULP: op = FT_X87_REG_MUL; break;
            case FT_X87_FSUBP: op = FT_X87_REG_SUB; break;
            case FT_X87_FSUBRP: op = FT_X87_REG_SUBR; break;
            case FT_X87_FDIVP: op = FT_X87_REG_DIV; break;
            case FT_X87_FDIVRP: op = FT_X87_REG_DIVR; break;
            default: return 0;
            }
            ft_emit_x87_soft_binary_reg(&out, st_index, op, 2);
            break;
        }
        switch (fields->kind) {
        case FT_X87_FADDP:
            FT_LA_FADD_D_EMIT(&out, ft_mmx(st_index), ft_mmx(st_index),
                              ft_mmx(0));
            break;
        case FT_X87_FSUBP:
            FT_LA_FSUB_D_EMIT(&out, ft_mmx(st_index), ft_mmx(st_index),
                              ft_mmx(0));
            break;
        case FT_X87_FSUBRP:
            FT_LA_FSUB_D_EMIT(&out, ft_mmx(st_index), ft_mmx(0),
                              ft_mmx(st_index));
            break;
        case FT_X87_FMULP:
            FT_LA_FMUL_D_EMIT(&out, ft_mmx(st_index), ft_mmx(st_index),
                              ft_mmx(0));
            break;
        case FT_X87_FDIVP:
            FT_LA_FDIV_D_EMIT(&out, ft_mmx(st_index), ft_mmx(st_index),
                              ft_mmx(0));
            break;
        case FT_X87_FDIVRP:
            FT_LA_FDIV_D_EMIT(&out, ft_mmx(st_index), ft_mmx(0),
                              ft_mmx(st_index));
            break;
        default:
            return 0;
        }
#ifdef QUICKTRANS_LATU
        if (fields->kind == FT_X87_FDIVP || fields->kind == FT_X87_FDIVRP) {
            ft_emit_latu_x87_div_status(&out);
        }
#endif
        ft_emit_x87_pop(&out);
        break;
    }
    case FT_X87_FFREE:
        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->modrm & 7);
            ft_emit_host_call(&out, (void *)helper_ffree_STN, 1u << 0);
            if (fields->id == dt_X86_INS_FFREEP) {
                ft_emit_cpu_env_ptr(&out, la_a0);
                ft_emit_host_call(&out, (void *)helper_fpop, 1u << 0);
            }
            ft_emit_x87_helper_epilogue(&out);
        } else {
            ft_emit_x87_mark_st_tag(&out, fields->modrm & 7, 1);
            if (fields->id == dt_X86_INS_FFREEP) {
                ft_emit_x87_pop(&out);
            }
        }
        break;
    case FT_X87_FCOMPP:
    {
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, 1);
            FT_LA_ADDI_D_EMIT(&out, la_a2, la_zero, 4);
            ft_emit_host_call(&out, (void *)ft_x87_helper_compare_reg, 1u << 0);
            ft_emit_x87_helper_epilogue(&out);
            break;
        }
        if (!ft_offset_fits_imm12(fpus_offset)) {
            return 0;
        }
        ft_emit_x87_fcom_status(&out, ft_mmx(1), ft_mmx(0), true);
        ft_emit_x87_pop(&out);
        ft_emit_x87_pop(&out);
        break;
    }
    case FT_X87_FSTSW_AX:
    {
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

#ifdef QUICKTRANS_LATU
        if (option_soft_fpu == 2) {
            ft_emit_load_env(&out, la_t0, fpus_offset, FT_LA_OPCODE_LD_HU);
            ft_emit_load_env(&out, la_t1, lsenv_offset_of_top(lsenv),
                             FT_LA_OPCODE_LD_WU);
            FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_t1, 13, 11);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t0, 15, 0);
            break;
        }
#endif
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_soft_fpu && option_soft_fpu_fast &&
            ft_offset_fits_imm12(fpus_offset) &&
            ft_offset_fits_imm12(lsenv_offset_of_top(lsenv))) {
            /* Same status composition as the old soft-fpu translator. */
            FT_LA_LD_HU_EMIT(&out, la_t0, la_s0, fpus_offset);
            FT_LA_LD_WU_EMIT(&out, la_t1, la_s0,
                             lsenv_offset_of_top(lsenv));
            FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_t1, 13, 11);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t0, 15, 0);
            break;
        }
#endif
        if (option_soft_fpu) {
            ft_emit_host_stack_begin(&out);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
            ft_emit_host_stack_end(&out);
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fnstsw, 1u << 0);
            ft_emit_host_stack_begin(&out);
            FT_LA_ST_D_EMIT(&out, la_a0, la_sp, 0);
            ft_emit_host_stack_end(&out);
            ft_emit_x87_helper_epilogue(&out);
            ft_emit_host_stack_begin(&out);
            FT_LA_LD_D_EMIT(&out, la_a0, la_sp, 0);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
            ft_emit_host_stack_end(&out);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_a0, 15, 0);
            break;
        }
        if (!ft_offset_fits_imm12(fpus_offset)) {
            return 0;
        }
        ft_emit_load_env(&out, la_t0, fpus_offset, FT_LA_OPCODE_LD_HU);
        ft_emit_x87_update_sw_by_fcsr(&out, la_t0, la_t1, la_t2);
        FT_LA_X86MFTOP_EMIT(&out, la_t1);
        FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_t1, 13, 11);
        ft_emit_store_env(&out, la_t0, fpus_offset, FT_LA_OPCODE_ST_H);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t0, 15, 0);
        break;
    }
    case FT_X87_FNSTSW_M16:
    {
        int addr;
        int value;
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

        if (fields->modrm_mod == 3) {
            return 0;
        }
#ifdef QUICKTRANS_LATU
        if (option_soft_fpu == 2) {
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            value = addr == la_t0 ? la_t1 : la_t0;
            int top = ft_scratch_avoid3(addr, value, -1);
            ft_emit_load_env(&out, value, fpus_offset, FT_LA_OPCODE_LD_HU);
            ft_emit_load_env(&out, top, lsenv_offset_of_top(lsenv),
                             FT_LA_OPCODE_LD_WU);
            FT_LA_BSTRINS_D_EMIT(&out, value, top, 13, 11);
            FT_LA_ST_H_EMIT(&out, value, addr,
                            ft_mem_access_offset(fields, addr));
            break;
        }
#endif
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_soft_fpu && option_soft_fpu_fast &&
            ft_offset_fits_imm12(fpus_offset) &&
            ft_offset_fits_imm12(lsenv_offset_of_top(lsenv))) {
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            value = addr == la_t0 ? la_t1 : la_t0;
            int top = ft_scratch_avoid3(addr, value, -1);

            FT_LA_LD_HU_EMIT(&out, value, la_s0, fpus_offset);
            FT_LA_LD_WU_EMIT(&out, top, la_s0,
                             lsenv_offset_of_top(lsenv));
            FT_LA_BSTRINS_D_EMIT(&out, value, top, 13, 11);
            FT_LA_ST_H_EMIT(&out, value, addr,
                            ft_mem_access_offset(fields, addr));
            break;
        }
#endif
        if (option_soft_fpu) {
            int offset;

            ft_emit_host_stack_begin(&out);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
            ft_emit_host_stack_end(&out);
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_fnstsw, 1u << 0);
            ft_emit_host_stack_begin(&out);
            FT_LA_ST_D_EMIT(&out, la_a0, la_sp, 0);
            ft_emit_host_stack_end(&out);
            ft_emit_x87_helper_epilogue(&out);
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            offset = ft_mem_access_offset(fields, addr);
            if (!ft_fits_simm12(offset)) {
                return 0;
            }
            if (offset) {
                FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);
            } else {
                FT_LA_OR_EMIT(&out, la_a1, addr, la_zero);
            }
            ft_emit_host_stack_begin(&out);
            FT_LA_LD_D_EMIT(&out, la_a0, la_sp, 0);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
            ft_emit_host_stack_end(&out);
            FT_LA_ST_H_EMIT(&out, la_a0, la_a1, 0);
            break;
        }
        if (!ft_offset_fits_imm12(fpus_offset) ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        value = addr == la_t0 ? la_t1 : la_t0;
        ft_emit_load_env(&out, value, fpus_offset, FT_LA_OPCODE_LD_HU);
        ft_emit_x87_update_sw_by_fcsr(&out, value, la_t2, la_t3);
        FT_LA_X86MFTOP_EMIT(&out, la_t2);
        FT_LA_BSTRINS_D_EMIT(&out, value, la_t2, 13, 11);
        ft_emit_store_env(&out, value, fpus_offset, FT_LA_OPCODE_ST_H);
        FT_LA_ST_H_EMIT(&out, value, addr,
                        ft_mem_access_offset(fields, addr));
        break;
    }
    case FT_X87_FLDCW_M16:
    {
        int addr;
        int fpuc_offset = lsenv_offset_of_control_word(lsenv);

        if (fields->modrm_mod == 3 ||
            !ft_offset_fits_imm12(fpuc_offset) ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_LD_HU_EMIT(&out, la_t0, addr,
                         ft_mem_access_offset(fields, addr));
        ft_emit_store_env(&out, la_t0, fpuc_offset, FT_LA_OPCODE_ST_H);
#ifdef QUICKTRANS_LATU
        if (option_soft_fpu) {
            ft_emit_x87_soft_control(&out, false);
            break;
        }
#endif
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_soft_fpu && option_soft_fpu_fast) {
            ft_emit_x87_soft_control(&out, false);
        } else
#endif
        ft_emit_x87_update_fcsr_by_cw(&out, la_t0);
        break;
    }
    case FT_X87_FNSTCW_M16:
    {
        int addr;
        int value;
        int fpuc_offset = lsenv_offset_of_control_word(lsenv);

        if (fields->modrm_mod == 3 ||
            !ft_offset_fits_imm12(fpuc_offset) ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        value = addr == la_t0 ? la_t1 : la_t0;
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_soft_fpu && option_soft_fpu_fast) {
            FT_LA_LD_H_EMIT(&out, value, la_s0, fpuc_offset);
        } else
#endif
        ft_emit_load_env(&out, value, fpuc_offset, FT_LA_OPCODE_LD_H);
        FT_LA_ST_H_EMIT(&out, value, addr,
                        ft_mem_access_offset(fields, addr));
        break;
    }
    default:
        return 0;
    }

    ft_soft_environment_end(&out, &memory_call);
    if (direct_extra) {
        ft_bind_branch_label(&extra.done, out);
        ft_resolve_branch_fixup(&extra.done_fix);
    }

    if (!option_soft_fpu && !ft_emit_x87_top_store(&out)) {
        return 0;
    }

    return (out - code);
}
