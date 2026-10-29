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

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
/* Mirror update_fp_status without a host call. cw must be la_t0. */
static void ft_emit_x87_soft_control(uint32_t **out)
{
    int status = lsenv_offset_of_fp_status(lsenv);
    FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t0, 11, 10);
    ft_emit_store_env(out, la_t2,
        status + offsetof(float_status, float_rounding_mode), FT_LA_OPCODE_ST_B);
    FT_LA_MOVFCSR2GR_EMIT(out, la_t1, 0);
    FT_LA_ANDI_EMIT(out, la_t3, la_t2, 1);
    FT_LA_BEQ_EMIT(out, la_t3, la_zero, 2);
    FT_LA_XORI_EMIT(out, la_t2, la_t2, 2);
    FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t2, FCSR_OFF_RM + 1, FCSR_OFF_RM);
    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t1);
    /* PC=01 is reserved; use the helper's extended-precision default. */
    FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t0, 9, 8);
    ft_emit_li64(out, la_t3, floatx80_precision_s |
                   (floatx80_precision_x << 8) |
                   (floatx80_precision_d << 16) |
                   (floatx80_precision_x << 24));
    FT_LA_SLLI_W_EMIT(out, la_t2, la_t2, 3);
    FT_LA_SRL_D_EMIT(out, la_t3, la_t3, la_t2);
    ft_emit_store_env(out, la_t3,
        status + offsetof(float_status, floatx80_rounding_precision), FT_LA_OPCODE_ST_B);
}
#endif

static int ft_emit_x87_state_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    (void)pc;

    switch (fields->kind) {
    case FT_FNINIT:
        FT_LA_X86MTTOP_EMIT(&out, 0);
        FT_LA_ORI_EMIT(&out, la_t0, la_zero, 0x37f);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_control_word(lsenv),
                          FT_LA_OPCODE_ST_H);
        ft_emit_store_env(&out, la_zero, lsenv_offset_of_status_word(lsenv),
                          FT_LA_OPCODE_ST_H);
        ft_emit_store_env(&out, la_zero, lsenv_offset_of_top(lsenv),
                          FT_LA_OPCODE_ST_W);
        ft_emit_li64(&out, la_t0, 0x0101010101010101ULL);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_tag_word(lsenv),
                          FT_LA_OPCODE_ST_D);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_soft_fpu && option_soft_fpu_fast) {
            FT_LA_ORI_EMIT(&out, la_t0, la_zero, 0x37f);
            ft_emit_x87_soft_control(&out);
            ft_emit_store_env(&out, la_zero, offsetof(CPUX86State, fpcs), FT_LA_OPCODE_ST_H);
            ft_emit_store_env(&out, la_zero, offsetof(CPUX86State, fpds), FT_LA_OPCODE_ST_H);
            ft_emit_store_env(&out, la_zero, offsetof(CPUX86State, fpip), FT_LA_OPCODE_ST_D);
            ft_emit_store_env(&out, la_zero, offsetof(CPUX86State, fpdp), FT_LA_OPCODE_ST_D);
        } else
#endif
        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)update_fp_status, 1u << 0);
            ft_emit_helper_epilogue(&out);
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
        ft_emit_load_env(&out, la_t0, fpus_offset, FT_LA_OPCODE_LD_HU);
        FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_zero, 7, 0);
        FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_zero, 15, 15);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
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

    FT_LA_BSTRINS_W_EMIT(out, la_t1, la_zero, FCSR_OFF_RM + 1,
                         FCSR_OFF_RM);
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
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 10, 10);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 9, 9);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 8, 8);
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
                                    bool signal_all_nans)
{
    FT_LA_OR_EMIT(out, la_t2, la_zero, la_zero);

    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0, src, st0,
                                  signal_all_nans ? 0x09 : 0x08));
    FT_LA_MOVCF2GR_EMIT(out, la_t0, 0);
    FT_LA_OR_EMIT(out, la_t2, la_t2, la_t0);
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
    FT_LA_BITREV_W_EMIT(out, tmp, fcsr);
    FT_LA_SRLI_D_EMIT(out, tmp, tmp, 11);
    FT_LA_BSTRPICK_D_EMIT(out, tmp, tmp, 0, 0);
    FT_LA_OR_EMIT(out, sw, sw, tmp);

    FT_LA_BITREV_W_EMIT(out, tmp, fcsr);
    FT_LA_SRLI_D_EMIT(out, tmp, tmp, 11);
    FT_LA_BSTRPICK_D_EMIT(out, tmp, tmp, 4, 1);
    FT_LA_SLLI_D_EMIT(out, tmp, tmp, 2);
    FT_LA_OR_EMIT(out, sw, sw, tmp);

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
    ft_emit_cpu_env_ptr(out, addr);
    ft_emit_li64(out, top, (uint64_t)(int64_t)lsenv_offset_of_tag_word(lsenv));
    FT_LA_ADD_D_EMIT(out, addr, addr, top);
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
    FT_LA_ORI_EMIT(out, la_t0, la_zero, tag);
    FT_LA_ST_B_EMIT(out, la_t0, la_t3, 0);
}

static void ft_emit_x87_mark_current_tag(uint32_t **out, int tag)
{
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
        FT_LA_LD_W_EMIT(out, la_t0, addr, offset);
        FT_LA_MOVGR2FR_D_EMIT(out, freg, la_t0);
        FT_LA_FFINT_D_W_EMIT(out, freg, freg);
        break;
    case 64:
        FT_LA_LD_D_EMIT(out, la_t0, addr, offset);
        FT_LA_MOVGR2FR_D_EMIT(out, freg, la_t0);
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
    ft_emit_helper_epilogue(out);
}

#include "emit-x87-soft-env.inc.c"

static int ft_emit_fxsave_restore_helper(uint32_t **out,
                                         const FastTemplateFields *fields,
                                         target_ulong pc, bool restore)
{
    uint32_t *start = *out;
    int addr;
    int offset;

    if (fields->modrm_mod == 3 ||
        fields->modrm_reg != (restore ? 1 : 0)) {
        return 0;
    }

    /* Save the guest GPRs before address formation uses ABI scratch regs. */
    FtSoftEnv fast = {0};
    ft_emit_soft_environment(out, fields, pc, restore, 2, &fast);

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
    if (!restore) {
        int mxcsr_offset = lsenv_offset_of_mxcsr(lsenv);

        if (!ft_fits_simm12(mxcsr_offset)) {
            return 0;
        }
        ft_emit_load_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_LD_WU);
        ft_emit_mxcsr_flags_from_fcsr(out, la_t1);
#ifdef CONFIG_SOFTMMU
        /* helper_fxsave performs the guest-memory write through softmmu. */
        ft_emit_store_env(out, la_t1, mxcsr_offset, FT_LA_OPCODE_ST_W);
#else
        FT_LA_ST_W_EMIT(out, la_t1, la_a1, 24);
#endif
        if (!option_soft_fpu && !ft_emit_x87_sync_status_from_fcsr(out)) {
            return 0;
        }
    }
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_host_call(out, restore ? (void *)helper_fxrstor
                                   : (void *)helper_fxsave,
                      1u << 0);

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (restore && option_soft_fpu) {
        /* The system-mode restore helper writes env->mxcsr but does not
         * synchronize hardware rounding. Restore SSE rounding without
         * changing exception enables/flags. x87 checks its own mode. */
        ft_emit_load_env(out, la_t0, lsenv_offset_of_mxcsr(lsenv),
                         FT_LA_OPCODE_LD_WU);
        FT_LA_BSTRPICK_W_EMIT(out, la_t0, la_t0, 14, 13);
        FT_LA_ANDI_EMIT(out, la_t2, la_t0, 1);
        FT_LA_SLLI_W_EMIT(out, la_t2, la_t2, 1);
        FT_LA_XOR_EMIT(out, la_t0, la_t0, la_t2);
        FT_LA_MOVFCSR2GR_EMIT(out, la_t1, 0);
        FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t0, FCSR_OFF_RM + 1,
                             FCSR_OFF_RM);
        FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t1);
    }
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
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    ft_emit_host_stack_end(out);
    ft_emit_helper_epilogue(out);
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
    ft_emit_helper_epilogue(out);
    if (fields->kind == FT_HELPER_XRSTOR && option_soft_fpu) {
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
    ft_emit_soft_environment(out, fields, pc, restore, 1, &fast);

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
    ft_emit_host_call(out, restore ? (void *)helper_frstor
                                   : (void *)helper_fsave,
                      (1u << 0) | (1u << 1));

    if (!option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_x80_to_64,
                          1u << 0);
    }

    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    ft_emit_host_stack_end(out);
    ft_emit_helper_epilogue(out);
    ft_soft_environment_end(out, &fast);
    return *out - start;
}

static int ft_emit_fenv_helper(uint32_t **out,
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
    ft_emit_soft_environment(out, fields, pc, restore, 0, &fast);

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

    if (!restore && !option_soft_fpu) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)ft_convert_fpregs_64_to_x80,
                          1u << 0);
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
    ft_emit_host_call(out, restore ? (void *)helper_fldenv
                                   : (void *)helper_fstenv,
                      (1u << 0) | (1u << 1));

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

            ft_emit_cpu_env_ptr(out, la_a0);
            ft_emit_host_call(out, (void *)ft_convert_fpregs_x80_to_64,
                              1u << 0);
        }
    }

    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    ft_emit_host_stack_end(out);
    ft_emit_helper_epilogue(out);
    ft_soft_environment_end(out, &fast);
    return *out - start;
}

static void ft_emit_x87_hard_helper(uint32_t **out, void *func)
{
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_host_call(out, func, 1u << 0);
    ft_emit_helper_epilogue(out);
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
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    FastBranchLabel slow = { 0 }, done = { 0 };
    FastBranchFixup nofp_fixup, empty_fixup, done_fixup;
    bool inline_sign = option_soft_fpu_fast &&
        ft_offset_fits_imm12(lsenv_offset_of_top(lsenv)) &&
        ft_offset_fits_imm12(lsenv_offset_of_tag_word(lsenv)) &&
        ft_offset_fits_imm12(lsenv_offset_of_fpr(lsenv, 0) + 8);
#ifdef CONFIG_LATX_OPT_NOFP
    inline_sign = inline_sign &&
        ft_offset_fits_imm12(lsenv_offset_of_nofp(lsenv));
#endif

    if (inline_sign) {
        /* Like the old soft-fpu path, change only the floatx80 sign bit.
         * Keep the checked helper for empty slots or live MMX state. */
#ifdef CONFIG_LATX_OPT_NOFP
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_nofp(lsenv));
        ft_emit_branch_placeholder(out, &nofp_fixup, FT_BRANCH_BNE,
                                   la_t0, la_zero, &slow);
#endif
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_top(lsenv));
        FT_LA_ADD_D_EMIT(out, la_t1, la_s0, la_t0);
        FT_LA_LD_BU_EMIT(out, la_t2, la_t1,
                         lsenv_offset_of_tag_word(lsenv));
        ft_emit_branch_placeholder(out, &empty_fixup, FT_BRANCH_BNE,
                                   la_t2, la_zero, &slow);
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
        ft_emit_branch_placeholder(out, &done_fixup, FT_BRANCH_BEQ,
                                   la_zero, la_zero, &done);
        ft_bind_branch_label(&slow, *out);
#ifdef CONFIG_LATX_OPT_NOFP
        ft_resolve_branch_fixup(&nofp_fixup);
#endif
        ft_resolve_branch_fixup(&empty_fixup);
    }
#endif
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, negate);
    ft_emit_host_call(out, (void *)ft_x87_helper_unary, 1u << 0);
    ft_emit_helper_epilogue(out);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (inline_sign) {
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&done_fixup);
    }
#endif
}

static void ft_emit_x87_soft_unary(uint32_t **out, bool square_root)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    const int top = lsenv_offset_of_top(lsenv);
    const int tag = lsenv_offset_of_tag_word(lsenv);
    FastBranchLabel slow = { 0 }, done = { 0 };
    FastBranchFixup nofp_fix, empty_fix, zero_fix, special_fix, sign_fix;
    FastBranchFixup done_fix;
    bool fast = (option_soft_fpu_fast & (square_root ? 0x10000 : 0x4000)) &&
        ft_offset_fits_imm12(fp + 8) && ft_offset_fits_imm12(top) &&
        ft_offset_fits_imm12(tag);
#ifdef CONFIG_LATX_OPT_NOFP
    fast = fast && ft_offset_fits_imm12(lsenv_offset_of_nofp(lsenv));
#endif
    if (fast) {
        const int x = ft_vscratch, tmp = ft_vscratch + 1;
#ifdef CONFIG_LATX_OPT_NOFP
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_nofp(lsenv));
        ft_emit_branch_placeholder(out, &nofp_fix, FT_BRANCH_BNE,
                                   la_t0, la_zero, &slow);
#endif
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, top);
        FT_LA_ADD_D_EMIT(out, la_t1, la_s0, la_t0);
        FT_LA_LD_BU_EMIT(out, la_t1, la_t1, tag);
        ft_emit_branch_placeholder(out, &empty_fix, FT_BRANCH_BNE,
                                   la_t1, la_zero, &slow);
        FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t0, la_s0, la_t0);
        FT_LA_LD_HU_EMIT(out, la_t1, la_t0, fp + 8);
        if (square_root) {
            FT_LA_SRLI_W_EMIT(out, la_t2, la_t1, 15);
            ft_emit_branch_placeholder(out, &sign_fix, FT_BRANCH_BNE,
                                       la_t2, la_zero, &slow);
        }
        FT_LA_BSTRPICK_W_EMIT(out, la_t1, la_t1, 14, 0);
        ft_emit_branch_placeholder(out, &zero_fix, FT_BRANCH_BEQ,
                                   la_t1, la_zero, &slow);
        ft_emit_li64(out, la_t2, 0x7fff);
        ft_emit_branch_placeholder(out, &special_fix, FT_BRANCH_BEQ,
                                   la_t1, la_t2, &slow);
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
        ft_emit_branch_placeholder(out, &done_fix, FT_BRANCH_BEQ,
                                   la_zero, la_zero, &done);
        ft_bind_branch_label(&slow, *out);
#ifdef CONFIG_LATX_OPT_NOFP
        ft_resolve_branch_fixup(&nofp_fix);
#endif
        ft_resolve_branch_fixup(&empty_fix);
        ft_resolve_branch_fixup(&zero_fix);
        ft_resolve_branch_fixup(&special_fix);
        if (square_root) {
            ft_resolve_branch_fixup(&sign_fix);
        }
    }
#endif
    ft_emit_x87_helper(out, square_root ? (void *)ft_x87_helper_fsqrt :
                                          (void *)ft_x87_helper_frndint);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (fast) {
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&done_fix);
    }
#endif
}

/* Like the legacy softfpu_fast option, direct arithmetic assumes host
 * rounding is suitable. Independent x87/SSE rounding after restore is a
 * known limitation when enabled; disabled mode retains software helpers. */
static void ft_emit_x87_soft_binary_reg(uint32_t **out, int index,
                                       int op, int mode)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    static const unsigned masks[2][6] = {
        { 0x2, 0x1000, 0x20000, 0x80000, 0x4, 0x10 },
        { 0x1, 0x2000, 0x40000, 0x100000, 0x8, 0x20 },
    };
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    const int top = lsenv_offset_of_top(lsenv);
    const int tag = lsenv_offset_of_tag_word(lsenv);
    FastBranchLabel slow = { 0 }, done = { 0 };
    FastBranchFixup nofp_fix, empty0_fix, emptyn_fix, done_fix;
    bool fast = (option_soft_fpu_fast & masks[mode == 2][op]) &&
        ft_offset_fits_imm12(fp + 8) && ft_offset_fits_imm12(top) &&
        ft_offset_fits_imm12(tag);
#ifdef CONFIG_LATX_OPT_NOFP
    fast = fast && ft_offset_fits_imm12(lsenv_offset_of_nofp(lsenv));
#endif
    if (fast) {
        const int x = ft_vscratch, y = ft_vscratch + 1;
        const int tmp = ft_vscratch + 2;
#ifdef CONFIG_LATX_OPT_NOFP
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_nofp(lsenv));
        ft_emit_branch_placeholder(out, &nofp_fix, FT_BRANCH_BNE,
                                   la_t0, la_zero, &slow);
#endif
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, top);
        FT_LA_ADDI_D_EMIT(out, la_t1, la_t0, index);
        FT_LA_ANDI_EMIT(out, la_t1, la_t1, 7);
        FT_LA_ADD_D_EMIT(out, la_t2, la_s0, la_t0);
        FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t1);
        FT_LA_LD_BU_EMIT(out, la_t4, la_t2, tag);
        ft_emit_branch_placeholder(out, &empty0_fix, FT_BRANCH_BNE,
                                   la_t4, la_zero, &slow);
        FT_LA_LD_BU_EMIT(out, la_t4, la_t3, tag);
        ft_emit_branch_placeholder(out, &emptyn_fix, FT_BRANCH_BNE,
                                   la_t4, la_zero, &slow);
        FT_LA_SLLI_D_EMIT(out, la_t4, la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t4, la_s0, la_t4);
        FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 4);
        FT_LA_ADD_D_EMIT(out, la_t1, la_s0, la_t1);
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
        }
        FT_LA_FCVT_UD_D_EMIT(out, tmp, x);
        FT_LA_FCVT_LD_D_EMIT(out, x, x);
        FT_LA_VEXTRINS_H_EMIT(out, x, tmp, 0x40);
        FT_LA_VST_EMIT(out, x, dst, fp);
        if (mode == 2) {
            FT_LA_ORI_EMIT(out, la_t1, la_zero, 1);
            FT_LA_ST_B_EMIT(out, la_t1, la_t2, tag);
            FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, 1);
            FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
            FT_LA_ST_W_EMIT(out, la_t0, la_s0, top);
        }
        ft_emit_branch_placeholder(out, &done_fix, FT_BRANCH_BEQ,
                                   la_zero, la_zero, &done);
        ft_bind_branch_label(&slow, *out);
#ifdef CONFIG_LATX_OPT_NOFP
        ft_resolve_branch_fixup(&nofp_fix);
#endif
        ft_resolve_branch_fixup(&empty0_fix);
        ft_resolve_branch_fixup(&emptyn_fix);
    }
#endif
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, index);
    ft_emit_host_call(out, (void *)ft_x87_binary_helpers[mode][op], 1u << 0);
    ft_emit_helper_epilogue(out);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (fast) {
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&done_fix);
    }
#endif
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
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    static const unsigned masks[2][8] = {
        { 0x2, 0x1000, 0, 0, 0x20000, 0x80000, 0x4, 0x10 },
        { 0x40, 0x200, 0, 0, 0x400, 0x800, 0x80, 0x100 },
    };
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    const int top = lsenv_offset_of_top(lsenv);
    const int tag = lsenv_offset_of_tag_word(lsenv);
    FastBranchLabel slow = { 0 }, done = { 0 };
    FastBranchFixup nofp_fix, empty_fix, special_st_fix, special_mem_fix;
    FastBranchFixup zero_st_fix, zero_mem_fix, done_fix;
    bool fast = (option_soft_fpu_fast & masks[integer][op]) &&
        ft_offset_fits_imm12(fp + 8) && ft_offset_fits_imm12(top) &&
        ft_offset_fits_imm12(tag);
#ifdef CONFIG_LATX_OPT_NOFP
    fast = fast && ft_offset_fits_imm12(lsenv_offset_of_nofp(lsenv));
#endif
    if (fast) {
        const int x = ft_vscratch, y = ft_vscratch + 1;
        const int tmp = ft_vscratch + 2;
        /* Read once, including the special-value path. The helper prologue
         * only saves guest registers and does not overwrite scratch FPR y. */
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
#ifdef CONFIG_LATX_OPT_NOFP
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_nofp(lsenv));
        ft_emit_branch_placeholder(out, &nofp_fix, FT_BRANCH_BNE,
                                   la_t0, la_zero, &slow);
#endif
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, top);
        FT_LA_ADD_D_EMIT(out, la_t1, la_s0, la_t0);
        FT_LA_LD_BU_EMIT(out, la_t1, la_t1, tag);
        ft_emit_branch_placeholder(out, &empty_fix, FT_BRANCH_BNE,
                                   la_t1, la_zero, &slow);
        if (!integer) {
            FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t4,
                                 width == 32 ? 30 : 62,
                                 width == 32 ? 23 : 52);
            ft_emit_branch_placeholder(out, &zero_mem_fix, FT_BRANCH_BEQ,
                                       la_t1, la_zero, &slow);
            FT_LA_ADDI_D_EMIT(out, la_t1, la_t1,
                              width == 32 ? -255 : -2047);
            ft_emit_branch_placeholder(out, &special_mem_fix, FT_BRANCH_BEQ,
                                       la_t1, la_zero, &slow);
        } else if (op == 6) {
            ft_emit_branch_placeholder(out, &zero_mem_fix, FT_BRANCH_BEQ,
                                       la_t4, la_zero, &slow);
        }
        FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
        FT_LA_ADD_D_EMIT(out, la_t0, la_s0, la_t0);
        FT_LA_LD_HU_EMIT(out, la_t1, la_t0, fp + 8);
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t1, 14, 0);
        ft_emit_branch_placeholder(out, &zero_st_fix, FT_BRANCH_BEQ,
                                   la_t1, la_zero, &slow);
        ft_emit_li64(out, la_t2, 0x7fff);
        ft_emit_branch_placeholder(out, &special_st_fix, FT_BRANCH_BEQ,
                                   la_t1, la_t2, &slow);
        /* Keep software exception flags for zero, denormal and NaN operands.
         * In particular, converting a signaling NaN first loses its identity. */
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
        ft_emit_branch_placeholder(out, &done_fix, FT_BRANCH_BEQ,
                                   la_zero, la_zero, &done);
        ft_bind_branch_label(&slow, *out);
#ifdef CONFIG_LATX_OPT_NOFP
        ft_resolve_branch_fixup(&nofp_fix);
#endif
        ft_resolve_branch_fixup(&empty_fix);
        ft_resolve_branch_fixup(&special_st_fix);
        ft_resolve_branch_fixup(&zero_st_fix);
        if (!integer) {
            ft_resolve_branch_fixup(&special_mem_fix);
        }
        if (!integer || op == 6) {
            ft_resolve_branch_fixup(&zero_mem_fix);
        }
    }
#endif
    ft_emit_helper_prologue(out);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (fast) {
        FT_LA_MOVFR2GR_D_EMIT(out, la_a1, ft_vscratch + 1);
    } else
#endif
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
    ft_emit_helper_epilogue(out);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (fast) {
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&done_fix);
    }
#endif
    return true;
}

/* Integer addressing and vector copies only: no float64 precision conversion. */
static bool ft_emit_x87_soft_stack(uint32_t **out,
                                    const FastTemplateFields *fields)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    int kind = fields->kind, index = fields->modrm & 7;
    bool load = kind == FT_X87_FLD_REG;
    bool store = kind == FT_X87_FST_REG || kind == FT_X87_FSTP_REG;
    bool exchange = kind == FT_X87_FXCH;
    bool release = kind == FT_X87_FFREE;
    bool adjust = kind == FT_X87_TOP_ADJ;
    int top = lsenv_offset_of_top(lsenv);
    int tag = lsenv_offset_of_tag_word(lsenv);
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    int status = lsenv_offset_of_status_word(lsenv);
    /* This path precedes the template switch; keep its operand validation. */
    if ((load && (fields->modrm < 0xc0 || fields->modrm > 0xc7)) ||
        (kind == FT_X87_FST_REG &&
         (fields->modrm < 0xd0 || fields->modrm > 0xd7)) ||
        (kind == FT_X87_FSTP_REG &&
         (fields->modrm < 0xd8 || fields->modrm > 0xdf)) ||
        (exchange && (fields->modrm < 0xc8 || fields->modrm > 0xcf)) ||
        (adjust && fields->id != dt_X86_INS_FINCSTP &&
         fields->id != dt_X86_INS_FDECSTP)) {
        return false;
    }
    if (!option_soft_fpu || !option_soft_fpu_fast ||
        !(load || store || exchange || release || adjust) ||
        !ft_offset_fits_imm12(top) || !ft_offset_fits_imm12(tag) ||
        !ft_offset_fits_imm12(fp) || !ft_offset_fits_imm12(status)) {
        return false;
    }
    FastBranchLabel slow = { 0 }, done = { 0 };
    FastBranchFixup nofp_fix, src_fix, dst_fix, done_fix;
#ifdef CONFIG_LATX_OPT_NOFP
    if (!ft_offset_fits_imm12(lsenv_offset_of_nofp(lsenv))) {
        return false;
    }
    FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_nofp(lsenv));
    ft_emit_branch_placeholder(out, &nofp_fix, FT_BRANCH_BNE,
                               la_t0, la_zero, &slow);
#endif
    FT_LA_LD_W_EMIT(out, la_t0, la_s0, top);
    FT_LA_ADDI_D_EMIT(out, la_t1, la_t0, index);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 7);
    if (load) {
        FT_LA_ADDI_D_EMIT(out, la_t2, la_t0, -1);
        FT_LA_ANDI_EMIT(out, la_t2, la_t2, 7);
    } else {
        FT_LA_OR_EMIT(out, la_t2, la_t0, la_zero);
    }
    if (load || exchange || store) {
        FT_LA_ADD_D_EMIT(out, la_t3, la_s0, store ? la_t0 : la_t1);
        FT_LA_LD_BU_EMIT(out, la_t3, la_t3, tag);
        ft_emit_branch_placeholder(out, &src_fix, FT_BRANCH_BNE,
                                   la_t3, la_zero, &slow);
        if (load || exchange) {
            FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t2);
            FT_LA_LD_BU_EMIT(out, la_t3, la_t3, tag);
            ft_emit_branch_placeholder(out, &dst_fix,
                                       load ? FT_BRANCH_BEQ : FT_BRANCH_BNE,
                                       la_t3, la_zero, &slow);
        }
        FT_LA_SLLI_D_EMIT(out, la_t3, store ? la_t0 : la_t1, 4);
        FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t3);
        FT_LA_SLLI_D_EMIT(out, la_t4, store ? la_t1 : la_t2, 4);
        FT_LA_ADD_D_EMIT(out, la_t4, la_s0, la_t4);
        FT_LA_VLD_EMIT(out, ft_vscratch, la_t3, fp);
        if (exchange) {
            FT_LA_VLD_EMIT(out, ft_vscratch + 1, la_t4, fp);
            FT_LA_VST_EMIT(out, ft_vscratch + 1, la_t3, fp);
        }
        FT_LA_VST_EMIT(out, ft_vscratch, la_t4, fp);
        if (load || store) {
            FT_LA_ADD_D_EMIT(out, la_t3, la_s0, load ? la_t2 : la_t1);
            FT_LA_ST_B_EMIT(out, la_zero, la_t3, tag);
        }
        if (load) {
            FT_LA_ST_W_EMIT(out, la_t2, la_s0, top);
        }
    }
    if (release) {
        FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t1);
        FT_LA_ORI_EMIT(out, la_t4, la_zero, 1);
        FT_LA_ST_B_EMIT(out, la_t4, la_t3, tag);
    }
    bool pop = kind == FT_X87_FSTP_REG ||
               (release && fields->id == dt_X86_INS_FFREEP);
    if (pop || adjust) {
        if (pop) {
            FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t0);
            FT_LA_ORI_EMIT(out, la_t4, la_zero, 1);
            FT_LA_ST_B_EMIT(out, la_t4, la_t3, tag);
        }
        FT_LA_ADDI_D_EMIT(out, la_t0, la_t0,
                          adjust && fields->id == dt_X86_INS_FDECSTP ? -1 : 1);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
        FT_LA_ST_W_EMIT(out, la_t0, la_s0, top);
    }
    if (!release && !exchange) {
        FT_LA_LD_HU_EMIT(out, la_t0, la_s0, status);
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 9, 9);
        FT_LA_ST_H_EMIT(out, la_t0, la_s0, status);
    }
    ft_emit_branch_placeholder(out, &done_fix, FT_BRANCH_BEQ,
                               la_zero, la_zero, &done);
    ft_bind_branch_label(&slow, *out);
#ifdef CONFIG_LATX_OPT_NOFP
    ft_resolve_branch_fixup(&nofp_fix);
#endif
    if (load || store || exchange) {
        ft_resolve_branch_fixup(&src_fix);
        if (load || exchange) ft_resolve_branch_fixup(&dst_fix);
    }
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    FT_LA_ADDI_D_EMIT(out, la_a1, la_zero, index);
    void *helper = load ? (void *)ft_x87_helper_fld_reg :
                   store ? (void *)ft_x87_helper_fst_reg :
                   exchange ? (void *)ft_x87_helper_fxch :
                   release ? (void *)helper_ffree_STN :
                   fields->id == dt_X86_INS_FDECSTP ?
                       (void *)helper_fdecstp : (void *)helper_fincstp;
    if (store) FT_LA_ADDI_D_EMIT(out, la_a2, la_zero, pop);
    ft_emit_host_call(out, helper, 1u << 0);
    if (release && pop) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_host_call(out, (void *)helper_fpop, 1u << 0);
    }
    ft_emit_helper_epilogue(out);
    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&done_fix);
    return true;
#else
    (void)out;
    (void)fields;
    return false;
#endif
}

#include "emit-x87-soft-fast.inc.c"

static int ft_emit_x87_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;

    if (ft_emit_x87_soft_stack(&out, fields)) {
        return out - code;
    }
    FtSoftX87 extra;
    bool direct_extra = ft_emit_x87_soft_extra(&out, fields, pc, &extra);
    FtSoftEnv memory_call;
    memory_call.active = false;
    ft_emit_soft_memory_call(&out, fields, pc, &memory_call);
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
            ft_emit_helper_epilogue(&out);
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
        ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
            break;
        }
        if (st_index != 0) {
            FT_LA_FMOV_D_EMIT(&out, ft_mmx(st_index), ft_mmx(0));
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
        ft_emit_x87_status_top(&out);
        break;
    case FT_X87_FTST:
    {
        int fpus_offset = lsenv_offset_of_status_word(lsenv);

        if (option_soft_fpu) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_x87_helper_ftst, 1u << 0);
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
            break;
        }
        if (!ft_emit_x87_fcomi_flags(&out, src, ft_mmx(0),
                                     fields->id == dt_X86_INS_FCOMI ||
                                     fields->id == dt_X86_INS_FCOMIP)) {
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

            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->modrm_rm);
            FT_LA_ADDI_D_EMIT(&out, la_a2, la_zero, mode);
            ft_emit_host_call(&out, (void *)ft_x87_helper_fcmov, 1u << 0);
            ft_emit_helper_epilogue(&out);
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
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_f2xm1);
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
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_fscale);
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
            ft_emit_x87_helper(&out, fields->kind == FT_X87_FSIN ?
                               (void *)ft_x87_helper_fsin : (void *)ft_x87_helper_fcos);
        } else {
            ft_emit_x87_call_unary_double(&out,
                                          fields->kind == FT_X87_FSIN ?
                                          (void *)sin : (void *)cos);
        }
        break;
    case FT_X87_FSINCOS:
        if (option_soft_fpu) {
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_fsincos);
        } else {
            ft_emit_x87_call_fsincos(&out);
            FT_LA_X86DECTOP_EMIT(&out);
            ft_emit_x87_mark_current_tag(&out, 0);
        }
        break;
    case FT_X87_FPTAN:
        if (option_soft_fpu) {
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_fptan);
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
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_fpatan);
        } else {
            ft_emit_x87_hard_helper(&out, (void *)ft_x87_hard_fpatan);
        }
        break;
    case FT_X87_FPREM:
        if (option_soft_fpu) {
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_fprem);
        } else {
            ft_emit_x87_hard_helper(&out, (void *)ft_x87_hard_fprem);
        }
        break;
    case FT_X87_FPREM1:
        if (option_soft_fpu) {
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_fprem1);
        } else {
            ft_emit_x87_hard_helper(&out, (void *)ft_x87_hard_fprem1);
        }
        break;
    case FT_X87_FYL2X:
        if (option_soft_fpu) {
            ft_emit_x87_helper(&out, (void *)ft_x87_helper_fyl2x);
        } else {
            ft_emit_x87_hard_helper(&out, (void *)ft_x87_hard_fyl2x);
        }
        break;
    case FT_X87_FYL2XP1:
        ft_emit_x87_helper(&out, (void *)ft_x87_helper_fyl2xp1);
        break;
    case FT_X87_FBLD:
    {
        int addr;
        int offset;

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
        if (!option_soft_fpu) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_64_to_x80,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)helper_fbld_ST0, 1u << 0);
        if (!option_soft_fpu) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_x80_to_64,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
        ft_emit_host_stack_end(&out);
        ft_emit_helper_epilogue(&out);
        break;
    }
    case FT_X87_FBSTP:
    {
        int addr;
        int offset;

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
        if (!option_soft_fpu) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_64_to_x80,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
        ft_emit_host_stack_end(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)helper_fbst_ST0, 1u << 0);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)helper_fpop, 1u << 0);
        if (!option_soft_fpu) {
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)ft_convert_fpregs_x80_to_64,
                              1u << 0);
        }
        ft_emit_host_stack_begin(&out);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
        ft_emit_host_stack_end(&out);
        ft_emit_helper_epilogue(&out);
        break;
    }
    case FT_X87_FXAM:
    {
        if (option_soft_fpu) {
            ft_emit_x87_helper(&out, (void *)helper_fxam_ST0);
            break;
        }

        int status_offset = lsenv_offset_of_status_word(lsenv);
        FastBranchLabel not_sign = { 0 };
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
        FastBranchFixup not_sign_fixup;
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

        ft_emit_li64(&out, la_t2, 0x8000000000000000ULL);
        FT_LA_AND_EMIT(&out, la_t3, la_t0, la_t2);
        ft_emit_branch_placeholder(&out, &not_sign_fixup, FT_BRANCH_BNE,
                                   la_t3, la_t2, &not_sign);
        FT_LA_ORI_EMIT(&out, la_t1, la_t1, 0x200);
        ft_bind_branch_label(&not_sign, out);
        ft_resolve_branch_fixup(&not_sign_fixup);

        ft_emit_x87_load_current_tag(&out, la_t4);
        ft_emit_branch_placeholder(&out, &not_empty_fixup, FT_BRANCH_BEQ,
                                   la_t4, la_zero, &not_empty);
        ft_emit_li64(&out, la_t2, 0x4100);
        FT_LA_OR_EMIT(&out, la_t1, la_t1, la_t2);
        ft_emit_branch_placeholder(&out, &empty_done_fixup, FT_BRANCH_B, 0,
                                   0, &empty_done);
        ft_bind_branch_label(&not_empty, out);
        ft_resolve_branch_fixup(&not_empty_fixup);

        ft_emit_li64(&out, la_t2, 0x7ff0000000000000ULL);
        FT_LA_AND_EMIT(&out, la_t3, la_t0, la_t2);
        ft_emit_branch_placeholder(&out, &inf_nan_fixup, FT_BRANCH_BEQ,
                                   la_t3, la_t2, &inf_nan);
        ft_emit_branch_placeholder(&out, &zero_denorm_fixup, FT_BRANCH_BEQ,
                                   la_t3, la_zero, &zero_denorm);
        FT_LA_ORI_EMIT(&out, la_t1, la_t1, 0x400);
        ft_emit_branch_placeholder(&out, &normal_done_fixup, FT_BRANCH_B, 0,
                                   0, &normal_done);

        ft_bind_branch_label(&inf_nan, out);
        ft_resolve_branch_fixup(&inf_nan_fixup);
        ft_emit_li64(&out, la_t2, 0x000fffffffffffffULL);
        FT_LA_AND_EMIT(&out, la_t3, la_t0, la_t2);
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
        ft_emit_li64(&out, la_t2, 0x000fffffffffffffULL);
        FT_LA_AND_EMIT(&out, la_t3, la_t0, la_t2);
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
        ft_emit_x87_helper(&out, (void *)ft_x87_helper_fxtract);
        break;
    case FT_X87_FSQRT:
        if (option_soft_fpu) {
            ft_emit_x87_soft_unary(&out, true);
            break;
        }
        FT_LA_MOVFR2GR_D_EMIT(&out, la_t0, ft_mmx(0));
        FT_LA_SRAI_D_EMIT(&out, la_t1, la_t0, 63);
        FT_LA_FSQRT_D_EMIT(&out, ft_mmx(0), ft_mmx(0));
        FT_LA_MOVFR2GR_D_EMIT(&out, la_t2, ft_mmx(0));
        ft_emit_li64(&out, la_t3, 0xfff8000000000000ULL);
        FT_LA_AND_EMIT(&out, la_t3, la_t3, la_t1);
        FT_LA_ANDN_EMIT(&out, la_t2, la_t2, la_t1);
        FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t3);
        FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(0), la_t2);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
            break;
        }

        ft_emit_x87_load_current_tag(&out, la_t0);
        ft_emit_branch_placeholder(&out, &normal_fixup, FT_BRANCH_BEQ,
                                   la_t0, la_zero, &normal);
        have_normal = true;

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
        ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
            ft_emit_helper_epilogue(&out);
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
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        if (option_soft_fpu && option_soft_fpu_fast) {
            ft_emit_x87_soft_control(&out);
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
