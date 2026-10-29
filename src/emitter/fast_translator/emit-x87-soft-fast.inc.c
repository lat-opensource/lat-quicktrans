/* SPDX-License-Identifier: MIT */

/* Guards use a direct cold block or the existing template's helper path.
 * Keep architectural writes after guards and faulting memory accesses. */
typedef struct FtSoftX87 {
    FastBranchLabel slow, done;
    FastBranchFixup guards[16], done_fix;
    unsigned count;
    bool loaded;
    bool integer_infinity;
    bool compare_inline;
    unsigned compare_exponent_mask;
    FastBranchLabel compare_exponent[2], compare_resume[2], compare_invalid;
    FastBranchLabel infinity, infinity_resume;
    FastBranchFixup infinity_fix;
} FtSoftX87;

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static void ft_soft_x87_guard(uint32_t **out, FtSoftX87 *s,
                              int branch, int lhs, int rhs)
{
    assert(s->count < 16);
    ft_emit_branch_placeholder(out, &s->guards[s->count++], branch,
                               lhs, rhs, &s->slow);
}

static void ft_soft_x87_base(uint32_t **out, FtSoftX87 *s)
{
#ifdef CONFIG_LATX_OPT_NOFP
    FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_nofp(lsenv));
    ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t0, la_zero);
#endif
}

/* Result is an env-relative address with the slot's 80-bit value at fp. */
static void ft_soft_x87_slot(uint32_t **out, FtSoftX87 *s, int index,
                             int address, bool empty)
{
    FT_LA_LD_W_EMIT(out, address, la_s0, lsenv_offset_of_top(lsenv));
    if (index) FT_LA_ADDI_D_EMIT(out, address, address, index);
    FT_LA_ANDI_EMIT(out, address, address, 7);
    FT_LA_ADD_D_EMIT(out, la_t4, la_s0, address);
    FT_LA_LD_BU_EMIT(out, la_t4, la_t4, lsenv_offset_of_tag_word(lsenv));
    ft_soft_x87_guard(out, s, empty ? FT_BRANCH_BEQ : FT_BRANCH_BNE,
                      la_t4, la_zero);
    FT_LA_SLLI_D_EMIT(out, address, address, 4);
    FT_LA_ADD_D_EMIT(out, address, la_s0, address);
}

/* Legacy fast-mode slot address, with no tag or nofp checks. */
static void ft_soft_x87_slot_direct(uint32_t **out, int index, int address)
{
    FT_LA_LD_W_EMIT(out, address, la_s0, lsenv_offset_of_top(lsenv));
    if (index) {
        FT_LA_ADDI_D_EMIT(out, address, address, index);
        FT_LA_ANDI_EMIT(out, address, address, 7);
    }
    FT_LA_SLLI_D_EMIT(out, address, address, 4);
    FT_LA_ADD_D_EMIT(out, address, la_s0, address);
}

static void ft_soft_x87_clear_c1(uint32_t **out)
{
    int sw = lsenv_offset_of_status_word(lsenv);
    FT_LA_LD_HU_EMIT(out, la_t4, la_s0, sw);
    FT_LA_BSTRINS_D_EMIT(out, la_t4, la_zero, 9, 9);
    FT_LA_ST_H_EMIT(out, la_t4, la_s0, sw);
}

static void ft_soft_x87_push(uint32_t **out)
{
    FT_LA_LD_W_EMIT(out, la_t3, la_s0, lsenv_offset_of_top(lsenv));
    FT_LA_ADDI_D_EMIT(out, la_t3, la_t3, -1);
    FT_LA_ANDI_EMIT(out, la_t3, la_t3, 7);
    FT_LA_ST_W_EMIT(out, la_t3, la_s0, lsenv_offset_of_top(lsenv));
    FT_LA_ADD_D_EMIT(out, la_t3, la_s0, la_t3);
    FT_LA_ST_B_EMIT(out, la_zero, la_t3, lsenv_offset_of_tag_word(lsenv));
}

static void ft_soft_x87_pop(uint32_t **out, int count)
{
    FT_LA_LD_W_EMIT(out, la_t3, la_s0, lsenv_offset_of_top(lsenv));
    FT_LA_ORI_EMIT(out, la_t4, la_zero, 1);
    for (int i = 0; i < count; ++i) {
        FT_LA_ADD_D_EMIT(out, la_t2, la_s0, la_t3);
        FT_LA_ST_B_EMIT(out, la_t4, la_t2, lsenv_offset_of_tag_word(lsenv));
        FT_LA_ADDI_D_EMIT(out, la_t3, la_t3, 1);
        FT_LA_ANDI_EMIT(out, la_t3, la_t3, 7);
    }
    FT_LA_ST_W_EMIT(out, la_t3, la_s0, lsenv_offset_of_top(lsenv));
}

static void ft_soft_x87_to_double(uint32_t **out, int address, int freg)
{
    FT_LA_VLD_EMIT(out, freg, address, lsenv_offset_of_fpr(lsenv, 0));
    FT_LA_VEXTRINS_H_EMIT(out, ft_vscratch + 2, freg, 0x4);
    FT_LA_FCVT_D_LD_EMIT(out, freg, freg, ft_vscratch + 2);
}

static void ft_soft_x87_from_double(uint32_t **out, int freg)
{
    FT_LA_FCVT_UD_D_EMIT(out, ft_vscratch + 2, freg);
    FT_LA_FCVT_LD_D_EMIT(out, freg, freg);
    FT_LA_VEXTRINS_H_EMIT(out, freg, ft_vscratch + 2, 0x40);
}

/* FLDZ needs no materialized constant or second TOP calculation. */
static void ft_soft_x87_zero(uint32_t **out)
{
    FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_top(lsenv));
    FT_LA_ADDI_D_EMIT(out, la_t0, la_t0, -1);
    FT_LA_ANDI_EMIT(out, la_t0, la_t0, 7);
    FT_LA_ST_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_top(lsenv));
    FT_LA_ADD_D_EMIT(out, la_t1, la_s0, la_t0);
    FT_LA_ST_B_EMIT(out, la_zero, la_t1, lsenv_offset_of_tag_word(lsenv));
    FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 4);
    FT_LA_ADD_D_EMIT(out, la_t0, la_s0, la_t0);
    FT_LA_ST_D_EMIT(out, la_zero, la_t0, lsenv_offset_of_fpr(lsenv, 0));
    FT_LA_ST_H_EMIT(out, la_zero, la_t0, lsenv_offset_of_fpr(lsenv, 0) + 8);
}

static bool ft_soft_x87_constant(uint32_t **out, FtSoftX87 *s, int id)
{
    uint64_t low;
    int high, rounding = 0;
    switch (id) {
    case dt_X86_INS_FLDZ: ft_soft_x87_zero(out); return true;
    case dt_X86_INS_FLD1: low = UINT64_C(0x8000000000000000); high = 0x3fff; break;
    case dt_X86_INS_FLDL2E: low = UINT64_C(0xb8aa3b295c17f0bc); high = 0x3fff; rounding = -1; break;
    case dt_X86_INS_FLDL2T: low = UINT64_C(0xd49a784bcd1b8afe); high = 0x4000; rounding = 1; break;
    case dt_X86_INS_FLDLG2: low = UINT64_C(0x9a209a84fbcff799); high = 0x3ffd; rounding = -1; break;
    case dt_X86_INS_FLDLN2: low = UINT64_C(0xb17217f7d1cf79ac); high = 0x3ffe; rounding = -1; break;
    case dt_X86_INS_FLDPI: low = UINT64_C(0xc90fdaa22168c235); high = 0x4000; rounding = -1; break;
    default: return false;
    }
    ft_soft_x87_slot_direct(out, -1, la_t0);
    ft_emit_li64(out, la_t1, low);
    if (rounding) {
        FT_LA_LD_HU_EMIT(out, la_t2, la_s0, lsenv_offset_of_control_word(lsenv));
        if (rounding < 0) {
            FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t2, 10, 10);
            FT_LA_SUB_D_EMIT(out, la_t1, la_t1, la_t2);
        } else {
            /* Match legacy fast FLDL2T: both RC=up and RC=truncate
             * select the incremented constant (control-word bit 11). */
            FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t2, 11, 11);
            FT_LA_ADD_D_EMIT(out, la_t1, la_t1, la_t2);
        }
    }
    FT_LA_ST_D_EMIT(out, la_t1, la_t0, lsenv_offset_of_fpr(lsenv, 0));
    ft_emit_li64(out, la_t1, high);
    FT_LA_ST_H_EMIT(out, la_t1, la_t0, lsenv_offset_of_fpr(lsenv, 0) + 8);
    ft_soft_x87_push(out);
    return true;
}

static bool ft_soft_x87_cmov(uint32_t **out, const FastTemplateFields *f)
{
    int cond;
    switch (f->id) {
    case dt_X86_INS_FCMOVB: cond = COND_B; break;
    case dt_X86_INS_FCMOVE: cond = COND_E; break;
    case dt_X86_INS_FCMOVBE: cond = COND_BE; break;
    case dt_X86_INS_FCMOVU: cond = COND_PE; break;
    case dt_X86_INS_FCMOVNB: cond = COND_AE; break;
    case dt_X86_INS_FCMOVNE: cond = COND_NE; break;
    case dt_X86_INS_FCMOVNBE: cond = COND_A; break;
    case dt_X86_INS_FCMOVNU: cond = COND_PO; break;
    default: return false;
    }
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    const int top = lsenv_offset_of_top(lsenv);
    if (f->modrm_rm > 7 || !ft_offset_fits_imm12(fp) ||
        !ft_offset_fits_imm12(top)) return false;
    /* Match legacy FCMOV: test first, do not update C1 or inspect tags. */
    FastBranchLabel done = { 0 };
    FastBranchFixup skip;
    FT_LA_SETX86J_EMIT(out, la_t2, cond);
    ft_emit_branch_placeholder(out, &skip, FT_BRANCH_BEQ,
                               la_t2, la_zero, &done);
    FT_LA_LD_W_EMIT(out, la_t0, la_s0, top);
    FT_LA_ADDI_D_EMIT(out, la_t1, la_t0, f->modrm_rm);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 7);
    /* ALSL.D encodes shift - 1: each x87 slot occupies 16 bytes. */
    FT_LA_ALSL_D_EMIT(out, la_t0, la_t0, la_s0, 3);
    FT_LA_ALSL_D_EMIT(out, la_t1, la_t1, la_s0, 3);
    FT_LA_VLD_EMIT(out, ft_vscratch, la_t1, fp);
    FT_LA_VST_EMIT(out, ft_vscratch, la_t0, fp);
    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&skip);
    return true;
}
/* Only ordinary finite operands enter float64 arithmetic. */
static void ft_soft_x87_normal(uint32_t **out, FtSoftX87 *s, int address)
{
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    FT_LA_LD_HU_EMIT(out, la_t3, address, fp + 8);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, la_t3, 14, 0);
    ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t3, la_zero);
    ft_emit_li64(out, la_t4, 0x7fff);
    ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t3, la_t4);
    FT_LA_LD_D_EMIT(out, la_t4, address, fp);
    FT_LA_SRLI_D_EMIT(out, la_t4, la_t4, 63);
    ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t4, la_zero);
}

static bool ft_soft_x87_scale(uint32_t **out, FtSoftX87 *s)
{
    if (!(option_soft_fpu_fast & 0x8000)) return false;
    /* Match legacy la_calcute_float64: truncate ST1, then scale ST0. */
    ft_soft_x87_slot_direct(out, 0, la_t0);
    ft_soft_x87_slot_direct(out, 1, la_t1);
    ft_soft_x87_to_double(out, la_t0, ft_vscratch);
    ft_soft_x87_to_double(out, la_t1, ft_vscratch + 1);
    FT_LA_FTINTRZ_L_D_EMIT(out, ft_vscratch + 1, ft_vscratch + 1);
    FT_LA_FSCALEB_D_EMIT(out, ft_vscratch, ft_vscratch, ft_vscratch + 1);
    ft_soft_x87_from_double(out, ft_vscratch);
    FT_LA_VST_EMIT(out, ft_vscratch, la_t0, lsenv_offset_of_fpr(lsenv, 0));
    return true;
}

static bool ft_soft_x87_examine(uint32_t **out, FtSoftX87 *s)
{
    /* Classify the original float80 bits exactly like legacy FXAM. No
     * float64 conversion or helper fallback (including zero and empty). */
    FastBranchLabel empty = {0}, special = {0}, zero = {0};
    FastBranchLabel infinity = {0}, done = {0};
    FastBranchFixup jumps[12];
    unsigned n = 0;
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    const int sw = lsenv_offset_of_status_word(lsenv);
    (void)s;
    ft_soft_x87_slot_direct(out, 0, la_t0);
    FT_LA_LD_HU_EMIT(out, la_t2, la_t0, fp + 8);
    FT_LA_LD_D_EMIT(out, la_t3, la_t0, fp);
    FT_LA_LD_HU_EMIT(out, la_t1, la_s0, sw);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_zero, 10, 8);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_zero, 14, 14);
    FT_LA_SRLI_D_EMIT(out, la_t4, la_t2, 15);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_t4, 9, 9);
    FT_LA_LD_W_EMIT(out, la_t4, la_s0, lsenv_offset_of_top(lsenv));
    FT_LA_ADD_D_EMIT(out, la_t4, la_s0, la_t4);
    FT_LA_LD_BU_EMIT(out, la_t4, la_t4, lsenv_offset_of_tag_word(lsenv));
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_BNE, la_t4, la_zero, &empty);
    FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t2, 14, 0);
    ft_emit_li64(out, la_t4, 0x7fff);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_BEQ, la_t2, la_t4, &special);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_BEQ, la_t2, la_zero, &zero);
    FT_LA_SRLI_D_EMIT(out, la_t4, la_t3, 63);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_BEQ, la_t4, la_zero, &done);
    FT_LA_ORI_EMIT(out, la_t1, la_t1, 0x400);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_B, 0, 0, &done);
    ft_bind_branch_label(&special, *out);
    FT_LA_SRLI_D_EMIT(out, la_t4, la_t3, 63);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_BEQ, la_t4, la_zero, &done);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t3, 1);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_BEQ, la_t4, la_zero, &infinity);
    FT_LA_ORI_EMIT(out, la_t1, la_t1, 0x100);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_B, 0, 0, &done);
    ft_bind_branch_label(&infinity, *out);
    FT_LA_ORI_EMIT(out, la_t1, la_t1, 0x500);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_B, 0, 0, &done);
    ft_bind_branch_label(&zero, *out);
    ft_emit_li64(out, la_t4, 0x4000);
    FT_LA_OR_EMIT(out, la_t1, la_t1, la_t4);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_BEQ, la_t3, la_zero, &done);
    FT_LA_ORI_EMIT(out, la_t1, la_t1, 0x400);
    ft_emit_branch_placeholder(out, &jumps[n++], FT_BRANCH_B, 0, 0, &done);
    ft_bind_branch_label(&empty, *out);
    ft_emit_li64(out, la_t4, 0x4100);
    FT_LA_OR_EMIT(out, la_t1, la_t1, la_t4);
    ft_bind_branch_label(&done, *out);
    FT_LA_ST_H_EMIT(out, la_t1, la_s0, sw);
    for (unsigned i = 0; i < n; ++i) ft_resolve_branch_fixup(&jumps[i]);
    return true;
}

static bool ft_soft_x87_load(uint32_t **out, FtSoftX87 *s,
                             const FastTemplateFields *f, target_ulong pc)
{
    int addr, width = 0;
    bool integer = ft_x87_fild_width(f->kind, &width);
    if (!integer) width = f->kind == FT_X87_FLD_M32 ? 32 : 64;
    if (f->modrm_mod == 3 || !ft_emit_rip_or_mem_addr(out, f, pc, &addr)) return false;
    int offset = ft_mem_access_offset(f, addr);
    if (width == 16) FT_LA_LD_H_EMIT(out, la_t4, addr, offset);
    else if (width == 32) FT_LA_LD_W_EMIT(out, la_t4, addr, offset);
    else FT_LA_LD_D_EMIT(out, la_t4, addr, offset);
    /* Both paths consume this one read, including volatile memory operands. */
    int loaded_reg = integer && width != 64 ? ft_vscratch : ft_vscratch + 1;
    FT_LA_MOVGR2FR_D_EMIT(out, loaded_reg, la_t4);
    s->loaded = true;
    if (integer && width == 64) {
        ft_soft_x87_base(out, s);
        ft_soft_x87_slot(out, s, -1, la_t0, true);
        FT_LA_MOVFR2GR_D_EMIT(out, la_t1, ft_vscratch + 1);
    } else {
        ft_soft_x87_slot_direct(out, -1, la_t0);
    }
    if (integer && width == 64) {
        /* Like the old path, leave large integers to the exact helper. */
        FT_LA_SRAI_D_EMIT(out, la_t2, la_t1, 63);
        FT_LA_XOR_EMIT(out, la_t3, la_t1, la_t2);
        FT_LA_SUB_D_EMIT(out, la_t3, la_t3, la_t2);
        FT_LA_SRLI_D_EMIT(out, la_t3, la_t3, 52);
        ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t3, la_zero);
    }
    if (loaded_reg != ft_vscratch) FT_LA_FMOV_D_EMIT(out, ft_vscratch, loaded_reg);
    if (integer) {
        if (width == 64) FT_LA_FFINT_D_L_EMIT(out, ft_vscratch, ft_vscratch);
        else FT_LA_FFINT_D_W_EMIT(out, ft_vscratch, ft_vscratch);
    } else if (width == 32) FT_LA_FCVT_D_S_EMIT(out, ft_vscratch, ft_vscratch);
    ft_soft_x87_from_double(out, ft_vscratch);
    FT_LA_VST_EMIT(out, ft_vscratch, la_t0, lsenv_offset_of_fpr(lsenv, 0));
    ft_soft_x87_push(out);
    /* Legacy inline FILD preserves C1; its large-value helper owns C1. */
    return true;
}

static bool ft_soft_x87_store(uint32_t **out, FtSoftX87 *s,
                              const FastTemplateFields *f, target_ulong pc)
{
    int width, addr;
    bool integer = false, pop = false;
    unsigned mask;
    switch (f->kind) {
    case FT_X87_FST_M32: width = 32; break;
    case FT_X87_FST_M64: width = 64; break;
    case FT_X87_FSTP_M32: width = 32; pop = true; break;
    case FT_X87_FSTP_M64: width = 64; pop = true; break;
    case FT_X87_FIST_M16: width = 16; integer = true; break;
    case FT_X87_FIST_M32: width = 32; integer = true; break;
    case FT_X87_FISTP_M16: width = 16; integer = pop = true; break;
    case FT_X87_FISTP_M32: width = 32; integer = pop = true; break;
    case FT_X87_FISTP_M64: width = 64; integer = pop = true; break;
    default: return false;
    }
    mask = integer ? (pop ? 0x400000 : 0x200000) : 0x800000;
    if (!(option_soft_fpu_fast & mask) || f->modrm_mod == 3) return false;
    if (integer) {
        /* Keep the legacy rounding-mode and exponent gates. Fractional
         * inputs are allowed; the host conversion applies the rounding. */
        int round = lsenv_offset_of_fp_status(lsenv) +
                    offsetof(float_status, float_rounding_mode);
        if (!ft_offset_fits_imm12(round)) return false;
        FT_LA_LD_BU_EMIT(out, la_t3, la_s0, round);
        FT_LA_BSTRPICK_D_EMIT(out, la_t3, la_t3, 2, 2);
        ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t3, la_zero);
    }
    if (f->kind == FT_X87_FST_M64) {
        FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_top(lsenv));
        FT_LA_ALSL_D_EMIT(out, la_t0, la_t0, la_s0, 3);
    } else {
        ft_soft_x87_slot_direct(out, 0, la_t0);
    }
    if (integer) {
        FT_LA_LD_HU_EMIT(out, la_t3, la_t0, lsenv_offset_of_fpr(lsenv, 0) + 8);
        FT_LA_BSTRPICK_D_EMIT(out, la_t3, la_t3, 14, 0);
        ft_emit_li64(out, la_t4, 0x3fff + (width == 64 ? 52 : 24));
        ft_soft_x87_guard(out, s, FT_BRANCH_BGE, la_t3, la_t4);
    }
    ft_soft_x87_to_double(out, la_t0, ft_vscratch);
    if (integer) {
        if (width == 64) FT_LA_FTINT_L_D_EMIT(out, ft_vscratch, ft_vscratch);
        else FT_LA_FTINT_W_D_EMIT(out, ft_vscratch, ft_vscratch);
    } else if (width == 32) FT_LA_FCVT_S_D_EMIT(out, ft_vscratch, ft_vscratch);
    /* The address calculation may use all integer scratch registers. */
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) return false;
    int value = ft_scratch_avoid3(addr, -1, -1);
    FT_LA_MOVFR2GR_D_EMIT(out, value, ft_vscratch);
    int offset = ft_mem_access_offset(f, addr);
    if (width == 16) FT_LA_ST_H_EMIT(out, value, addr, offset);
    else if (width == 32) FT_LA_ST_W_EMIT(out, value, addr, offset);
    else FT_LA_ST_D_EMIT(out, value, addr, offset);
    if (pop) ft_soft_x87_pop(out, 1);
    return true;
}

static bool ft_soft_x87_memory80(uint32_t **out, FtSoftX87 *s,
                                 const FastTemplateFields *f, target_ulong pc)
{
    bool load = f->kind == FT_X87_FLD_M80;
    if (f->modrm_mod == 3 || (!load && !(option_soft_fpu_fast & 0x800000))) return false;
    (void)s;
    int addr;
    const int fp = lsenv_offset_of_fpr(lsenv, 0);
    if (!load) {
        ft_soft_x87_slot_direct(out, 0, la_t0);
        FT_LA_VLD_EMIT(out, ft_vscratch, la_t0, fp);
        FT_LA_VEXTRINS_H_EMIT(out, ft_vscratch + 1, ft_vscratch, 0x4);
    }
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) return false;
    /* Materialize the effective address before using integer scratch regs.
     * Access only ten guest bytes, in the same order as the legacy path. */
    FT_LA_ADDI_D_EMIT(out, la_t1, addr, ft_mem_access_offset(f, addr));
    if (load) {
        FT_LA_LD_D_EMIT(out, la_t2, la_t1, 0);
        FT_LA_MOVGR2FR_D_EMIT(out, ft_vscratch, la_t2);
        FT_LA_LD_HU_EMIT(out, la_t2, la_t1, 8);
        FT_LA_MOVGR2FR_D_EMIT(out, ft_vscratch + 1, la_t2);
        FT_LA_VEXTRINS_H_EMIT(out, ft_vscratch, ft_vscratch + 1, 0x40);
        ft_soft_x87_slot_direct(out, -1, la_t0);
        FT_LA_VST_EMIT(out, ft_vscratch, la_t0, fp);
        ft_soft_x87_push(out);
    } else {
        FT_LA_MOVFR2GR_D_EMIT(out, la_t2, ft_vscratch + 1);
        FT_LA_ST_H_EMIT(out, la_t2, la_t1, 8);
        FT_LA_MOVFR2GR_D_EMIT(out, la_t2, ft_vscratch);
        FT_LA_ST_D_EMIT(out, la_t2, la_t1, 0);
        ft_soft_x87_pop(out, 1);
    }
    /* Legacy fast FLD/FSTP preserve C1, and update TOP only after accesses. */
    return true;
}

/* The legacy float64 comparison option accepts precision/range loss.
 * Send invalid encodings and NaNs to their cold state-update exits, but
 * do not reject zero, denormals or non-double-exact finite operands. */
static void ft_soft_x87_compare_operand(uint32_t **out, FtSoftX87 *s, int address, bool allow_infinity)
{
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    FT_LA_LD_HU_EMIT(out, la_t3, address, fp + 8);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, la_t3, 14, 0);
    if (!allow_infinity) {
        ft_emit_li64(out, la_t2, 0x7fff);
        if (s->integer_infinity) {
            ft_emit_branch_placeholder(out, &s->infinity_fix, FT_BRANCH_BEQ,
                                       la_t3, la_t2, &s->infinity);
        } else if (s->compare_inline) {
            unsigned slot = address == la_t0 ? 0 : 1;
            s->compare_exponent_mask |= 1u << slot;
            ft_emit_branch_placeholder(out, &s->guards[s->count++], FT_BRANCH_BEQ,
                                       la_t3, la_t2, &s->compare_exponent[slot]);
            ft_bind_branch_label(&s->compare_resume[slot], *out);
        } else {
            ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t3, la_t2);
        }
        FT_LA_SLTU_EMIT(out, la_t3, la_zero, la_t3);
        FT_LA_LD_D_EMIT(out, la_t4, address, fp);
        FT_LA_SRLI_D_EMIT(out, la_t2, la_t4, 63);
        FT_LA_XORI_EMIT(out, la_t2, la_t2, 1);
        FT_LA_AND_EMIT(out, la_t3, la_t3, la_t2);
        if (s->compare_inline) {
            ft_emit_branch_placeholder(out, &s->guards[s->count++], FT_BRANCH_BNE,
                                       la_t3, la_zero, &s->compare_invalid);
        } else {
            ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t3, la_zero);
        }
        if (s->integer_infinity) ft_bind_branch_label(&s->infinity_resume, *out);
        return;
    }
    FT_LA_LD_D_EMIT(out, la_t4, address, fp);
    ft_emit_li64(out, la_t2, 0x7fff);
    FastBranchLabel finite = {0};
    FastBranchFixup skip;
    ft_emit_branch_placeholder(out, &skip, FT_BRANCH_BNE, la_t3, la_t2, &finite);
    /* Infinity is valid and converts exactly to float64. Keep NaNs slow. */
    FT_LA_SLLI_D_EMIT(out, la_t2, la_t4, 1);
    ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t2, la_zero);
    ft_bind_branch_label(&finite, *out);
    ft_resolve_branch_fixup(&skip);
    /* A nonzero exponent without the explicit integer bit is invalid. */
    FT_LA_SLTU_EMIT(out, la_t3, la_zero, la_t3);
    FT_LA_SRLI_D_EMIT(out, la_t2, la_t4, 63);
    FT_LA_XORI_EMIT(out, la_t2, la_t2, 1);
    FT_LA_AND_EMIT(out, la_t3, la_t3, la_t2);
    if (s->compare_inline) {
        ft_emit_branch_placeholder(out, &s->guards[s->count++], FT_BRANCH_BNE,
                                   la_t3, la_zero, &s->compare_invalid);
    } else {
        ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t3, la_zero);
    }
}

static bool ft_soft_x87_compare(uint32_t **out, FtSoftX87 *s,
                                 const FastTemplateFields *f, target_ulong pc)
{
    bool flags = f->kind == FT_X87_FCOMI_REG || f->kind == FT_X87_FCOMIP_REG;
    bool zero = f->kind == FT_X87_FTST;
    bool integer = f->kind == FT_X87_FI_BIN_M16 || f->kind == FT_X87_FI_BIN_M32;
    bool memory = integer || f->kind == FT_X87_FCOM_M32 || f->kind == FT_X87_FCOM_M64;
    bool quiet = f->id == dt_X86_INS_FUCOM || f->id == dt_X86_INS_FUCOMP ||
                 f->id == dt_X86_INS_FUCOMPP || f->id == dt_X86_INS_FUCOMI ||
                 f->id == dt_X86_INS_FUCOMIP;
    unsigned mask = flags ? (quiet ? 0x8000000 : 0x4000000) :
                            (quiet ? 0x2000000 : 0x1000000);
    if (!(option_soft_fpu_fast & mask)) return false;
    int pop = f->kind == FT_X87_FCOMPP || f->kind == FT_X87_FUCOMPP ? 2 :
              f->kind == FT_X87_FCOMP_REG || f->kind == FT_X87_FCOMIP_REG ||
              (memory && f->modrm_reg == 3);
    int index = pop == 2 ? 1 : f->modrm_rm;
    int width = f->kind == FT_X87_FI_BIN_M16 ? 16 :
                f->kind == FT_X87_FCOM_M64 ? 64 : 32;
    if (memory) {
        int addr;
        if (f->modrm_mod == 3 || !ft_emit_rip_or_mem_addr(out, f, pc, &addr)) return false;
        int offset = ft_mem_access_offset(f, addr);
        if (width == 16) FT_LA_LD_H_EMIT(out, la_t4, addr, offset);
        else if (width == 32) FT_LA_LD_W_EMIT(out, la_t4, addr, offset);
        else FT_LA_LD_D_EMIT(out, la_t4, addr, offset);
        FT_LA_MOVGR2FR_D_EMIT(out, ft_vscratch + 1, la_t4);
        s->loaded = true;
    }
    s->integer_infinity = integer;
    s->compare_inline = true;
    ft_soft_x87_slot_direct(out, 0, la_t0);
    ft_soft_x87_compare_operand(out, s, la_t0, memory && !integer);
    if (!memory && !zero) {
        ft_soft_x87_slot_direct(out, index, la_t1);
        ft_soft_x87_compare_operand(out, s, la_t1, false);
    } else if (memory && !integer) {
        FT_LA_MOVFR2GR_D_EMIT(out, la_t2, ft_vscratch + 1);
        FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t2, width == 32 ? 30 : 62,
                              width == 32 ? 23 : 52);
        FT_LA_ADDI_D_EMIT(out, la_t2, la_t2, width == 32 ? -255 : -2047);
        FastBranchLabel finite_memory = {0};
        FastBranchFixup skip;
        ft_emit_branch_placeholder(out, &skip, FT_BRANCH_BNE, la_t2, la_zero,
                                   &finite_memory);
        FT_LA_MOVFR2GR_D_EMIT(out, la_t2, ft_vscratch + 1);
        FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, width == 32 ? 41 : 12);
        ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t2, la_zero);
        ft_bind_branch_label(&finite_memory, *out);
        ft_resolve_branch_fixup(&skip);
    }
    ft_soft_x87_to_double(out, la_t0, ft_vscratch);
    if (zero) FT_LA_MOVGR2FR_D_EMIT(out, ft_vscratch + 1, la_zero);
    else if (!memory) ft_soft_x87_to_double(out, la_t1, ft_vscratch + 1);
    else if (integer) FT_LA_FFINT_D_W_EMIT(out, ft_vscratch + 1, ft_vscratch + 1);
    else if (width == 32) FT_LA_FCVT_D_S_EMIT(out, ft_vscratch + 1, ft_vscratch + 1);
    if (!flags && !pop && !zero && !memory && !quiet) {
        int sw = lsenv_offset_of_status_word(lsenv);
        /* Interleave independent status work with the two comparisons. */
        FT_LA_LD_HU_EMIT(out, la_t0, la_s0, sw);
        ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0,
                                     ft_vscratch, ft_vscratch + 1, 0x02));
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 10, 10);
        FT_LA_MOVCF2GR_EMIT(out, la_t1, 0);
        ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0,
                                     ft_vscratch, ft_vscratch + 1, 0x04));
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 8, 8);
        FT_LA_MOVCF2GR_EMIT(out, la_t2, 0);
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t2, 14, 14);
        FT_LA_ST_H_EMIT(out, la_t0, la_s0, sw);
        return true;
    }
    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0,
                                 ft_vscratch, ft_vscratch + 1, 0x02));
    FT_LA_MOVCF2GR_EMIT(out, la_t1, 0);
    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0,
                                 ft_vscratch, ft_vscratch + 1, 0x04));
    FT_LA_MOVCF2GR_EMIT(out, la_t2, 0);
    int sw = lsenv_offset_of_status_word(lsenv);
    if (flags) {
        FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, 6);
        FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);
        FT_LA_X86MTFLAG_EMIT(out, la_t1, 0x3f);
    } else {
        FT_LA_LD_HU_EMIT(out, la_t0, la_s0, sw);
        /* Legacy fast comparison updates C0/C2/C3 and preserves C1. */
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 8, 8);
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 10, 10);
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t2, 14, 14);
        FT_LA_ST_H_EMIT(out, la_t0, la_s0, sw);
    }
    if (pop) ft_soft_x87_pop(out, pop);
    return true;
}


/* Called only after a NaN/invalid guard. Test sNaN directly in the stored
 * float80 value; do not convert it or reread a guest memory operand. */
static void ft_soft_x87_snan(uint32_t **out, int index,
                              FastBranchLabel *raise,
                              FastBranchFixup *fix)
{
    FastBranchLabel next = {0};
    FastBranchFixup finite, quiet;
    ft_soft_x87_slot_direct(out, index, la_t0);
    FT_LA_LD_HU_EMIT(out, la_t2, la_t0, lsenv_offset_of_fpr(lsenv, 0) + 8);
    FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t2, 14, 0);
    ft_emit_li64(out, la_t4, 0x7fff);
    ft_emit_branch_placeholder(out, &finite, FT_BRANCH_BNE, la_t2, la_t4, &next);
    FT_LA_LD_D_EMIT(out, la_t3, la_t0, lsenv_offset_of_fpr(lsenv, 0));
    FT_LA_BSTRPICK_D_EMIT(out, la_t4, la_t3, 62, 62);
    ft_emit_branch_placeholder(out, &quiet, FT_BRANCH_BNE, la_t4, la_zero, &next);
    FT_LA_SLLI_D_EMIT(out, la_t3, la_t3, 2);
    ft_emit_branch_placeholder(out, fix, FT_BRANCH_BNE, la_t3, la_zero, raise);
    ft_bind_branch_label(&next, *out);
    ft_resolve_branch_fixup(&finite);
    ft_resolve_branch_fixup(&quiet);
}

/* Preserve the finite path and use each guard's known failure reason.
 * Infinity rejoins the original operand checks. NaN/invalid values write
 * unordered state directly; no duplicate numeric comparison or helper. */
static void ft_soft_x87_compare_cold(uint32_t **out, FtSoftX87 *s,
                                      const FastTemplateFields *f)
{
    bool flags = f->kind == FT_X87_FCOMI_REG || f->kind == FT_X87_FCOMIP_REG;
    bool quiet = f->id == dt_X86_INS_FUCOM || f->id == dt_X86_INS_FUCOMP ||
                 f->id == dt_X86_INS_FUCOMPP || f->id == dt_X86_INS_FUCOMI ||
                 f->id == dt_X86_INS_FUCOMIP;
    bool memory = f->kind == FT_X87_FI_BIN_M16 || f->kind == FT_X87_FI_BIN_M32 ||
                  f->kind == FT_X87_FCOM_M32 || f->kind == FT_X87_FCOM_M64;
    int pop = f->kind == FT_X87_FCOMPP || f->kind == FT_X87_FUCOMPP ? 2 :
              f->kind == FT_X87_FCOMP_REG || f->kind == FT_X87_FCOMIP_REG ||
              (memory && f->modrm_reg == 3);
    FastBranchLabel first_nan = {0};
    for (unsigned i = 0; i < 2; ++i) {
        if (!(s->compare_exponent_mask & (1u << i))) continue;
        ft_bind_branch_label(&s->compare_exponent[i], *out);
        FT_LA_LD_D_EMIT(out, la_t4, i == 0 ? la_t0 : la_t1,
                        lsenv_offset_of_fpr(lsenv, 0));
        ft_emit_li64(out, la_t2, UINT64_C(0x8000000000000000));
        FastBranchFixup infinity, invalid, signaling, nan;
        ft_emit_branch_placeholder(out, &infinity, FT_BRANCH_BEQ, la_t4, la_t2,
                                   &s->compare_resume[i]);
        ft_resolve_branch_fixup(&infinity);
        if (quiet) {
            FT_LA_SRLI_D_EMIT(out, la_t2, la_t4, 63);
            ft_emit_branch_placeholder(out, &invalid, FT_BRANCH_BEQ,
                                       la_t2, la_zero, &s->compare_invalid);
            /* Exact infinity was already excluded. With the integer bit set,
             * a clear quiet bit identifies sNaN without reloading the slot. */
            FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t4, 62, 62);
            ft_emit_branch_placeholder(out, &signaling, FT_BRANCH_BEQ,
                                       la_t2, la_zero, &s->compare_invalid);
        }
        ft_emit_branch_placeholder(out, &nan, FT_BRANCH_B, 0, 0,
                                   quiet && i == 0 ? &first_nan : &s->slow);
        /* Targets are forward; keep the fixups in the existing bounded list. */
        if (quiet) {
            s->guards[s->count++] = invalid;
            s->guards[s->count++] = signaling;
        }
        s->guards[s->count++] = nan;
    }
    FastBranchLabel result = {0}, store = {0};
    FastBranchFixup other_signaling, result_fix, store_fix;
    if (quiet) {
        ft_bind_branch_label(&first_nan, *out);
        /* ST0 qNaN skips the ordinary ST(i) check, so still test that slot
         * for sNaN. A ST(i) qNaN means ST0 already passed all its checks. */
        ft_soft_x87_snan(out, pop == 2 ? 1 : f->modrm_rm,
                         &s->compare_invalid, &other_signaling);
    }
    ft_bind_branch_label(&s->slow, *out);
    if (quiet) {
        FT_LA_OR_EMIT(out, la_t1, la_zero, la_zero);
        ft_emit_branch_placeholder(out, &result_fix, FT_BRANCH_B, 0, 0, &result);
    }
    ft_bind_branch_label(&s->compare_invalid, *out);
    if (quiet) {
        ft_resolve_branch_fixup(&other_signaling);
        FT_LA_ADDI_D_EMIT(out, la_t1, la_zero, 1);
        ft_bind_branch_label(&result, *out);
        ft_resolve_branch_fixup(&result_fix);
    }
    int sw = lsenv_offset_of_status_word(lsenv);
    int exc = lsenv_offset_of_fp_status(lsenv) +
              offsetof(float_status, float_exception_flags);
    FT_LA_LD_HU_EMIT(out, la_t0, la_s0, sw);
    if (flags) {
        FT_LA_X86MFFLAG_EMIT(out, la_t4, 0x3f);
        FT_LA_ORI_EMIT(out, la_t4, la_t4, 0x45);
        FT_LA_X86MTFLAG_EMIT(out, la_t4, 0x3f);
    } else {
        ft_emit_li64(out, la_t4, 0x4500);
        FT_LA_OR_EMIT(out, la_t0, la_t0, la_t4);
    }
    if (quiet) ft_emit_branch_placeholder(out, &store_fix, FT_BRANCH_BEQ,
                                          la_t1, la_zero, &store);
    FT_LA_LD_HU_EMIT(out, la_t2, la_s0, exc);
    FT_LA_ORI_EMIT(out, la_t2, la_t2, 1);
    FT_LA_ST_H_EMIT(out, la_t2, la_s0, exc);
    FT_LA_ORI_EMIT(out, la_t0, la_t0, 1);
    FT_LA_LD_HU_EMIT(out, la_t2, la_s0, lsenv_offset_of_control_word(lsenv));
    FT_LA_ANDI_EMIT(out, la_t2, la_t2, 1);
    FT_LA_XORI_EMIT(out, la_t2, la_t2, 1);
    FT_LA_BSTRINS_D_EMIT(out, la_t2, la_t2, 8, 8);
    FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, 7);
    FT_LA_OR_EMIT(out, la_t0, la_t0, la_t2);
    ft_bind_branch_label(&store, *out);
    if (quiet) ft_resolve_branch_fixup(&store_fix);
    FT_LA_ST_H_EMIT(out, la_t0, la_s0, sw);
    if (pop) ft_soft_x87_pop(out, pop);
    ft_bind_branch_label(&s->done, *out);
    ft_resolve_branch_fixup(&s->done_fix);
    assert(s->count <= 16);
    for (unsigned i = 0; i < s->count; ++i) ft_resolve_branch_fixup(&s->guards[i]);
    s->count = 0;
}

#endif

/* Match legacy fast FISTTP: only conversion runs in host context.  The
 * static no-FP epilogue preserves a0, the helper return register.  Recompute
 * the address after restoring guest registers and store before popping. */
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static bool ft_soft_x87_fisttp(uint32_t **out, const FastTemplateFields *f,
                              target_ulong pc)
{
    if (f->modrm_mod == 3 || !scs_enabled()) return false;
    void *helper;
    int width;
    switch (f->kind) {
    case FT_X87_FISTTP_M16: width = 16; helper = (void *)helper_fistt_ST0; break;
    case FT_X87_FISTTP_M32: width = 32; helper = (void *)helper_fisttl_ST0; break;
    case FT_X87_FISTTP_M64: width = 64; helper = (void *)helper_fisttll_ST0; break;
    default: return false;
    }
    uint32_t *start = *out;
    bool static_context = ft_emit_nofp_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_default_helper_call(out, helper, 1u << 0, static_context);
    ft_emit_nofp_helper_epilogue(out, static_context);
    int addr;
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) {
        *out = start;
        return false;
    }
    int offset = ft_mem_access_offset(f, addr);
    if (width == 16) FT_LA_ST_H_EMIT(out, la_a0, addr, offset);
    else if (width == 32) FT_LA_ST_W_EMIT(out, la_a0, addr, offset);
    else FT_LA_ST_D_EMIT(out, la_a0, addr, offset);
    ft_soft_x87_pop(out, 1);
    return true;
}
#endif

static bool ft_emit_x87_soft_extra(uint32_t **out,
                                   const FastTemplateFields *f,
                                   target_ulong pc, FtSoftX87 *s)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (!option_soft_fpu || !option_soft_fpu_fast) return false;
    enum { LOAD, STORE, MEMORY80, COMPARE, SCALE, CONSTANT, EXAMINE, FISTTP } group;
    switch (f->kind) {
    case FT_X87_FLD_M32: case FT_X87_FLD_M64:
    case FT_X87_FILD_M16: case FT_X87_FILD_M32: case FT_X87_FILD_M64:
        group = LOAD; break;
    case FT_X87_FST_M32: case FT_X87_FST_M64:
    case FT_X87_FSTP_M32: case FT_X87_FSTP_M64:
    case FT_X87_FIST_M16: case FT_X87_FIST_M32:
    case FT_X87_FISTP_M16: case FT_X87_FISTP_M32: case FT_X87_FISTP_M64:
        group = STORE; break;
    case FT_X87_FLD_M80: case FT_X87_FSTP_M80:
        group = MEMORY80; break;
    case FT_X87_FI_BIN_M16: case FT_X87_FI_BIN_M32:
        if (f->modrm_reg != 2 && f->modrm_reg != 3) return false;
        /* fall through */
    case FT_X87_FTST: case FT_X87_FCOM_REG: case FT_X87_FCOMP_REG:
    case FT_X87_FCOMI_REG: case FT_X87_FCOMIP_REG:
    case FT_X87_FCOMPP: case FT_X87_FUCOMPP:
    case FT_X87_FCOM_M32: case FT_X87_FCOM_M64:
        group = COMPARE; break;
    case FT_X87_FISTTP_M16: case FT_X87_FISTTP_M32: case FT_X87_FISTTP_M64:
        group = FISTTP; break;
    case FT_X87_FSCALE: group = SCALE; break;
    case FT_X87_FXAM: group = EXAMINE; break;
    case FT_X87_FLD1: case FT_X87_FLD_CONST: group = CONSTANT; break;
    default: return false;
    }
    if (!ft_offset_fits_imm12(lsenv_offset_of_fpr(lsenv, 7) + 8) ||
        !ft_offset_fits_imm12(lsenv_offset_of_top(lsenv)) ||
        !ft_offset_fits_imm12(lsenv_offset_of_tag_word(lsenv) + 7) ||
        !ft_offset_fits_imm12(lsenv_offset_of_status_word(lsenv)) ||
        !ft_offset_fits_imm12(lsenv_offset_of_control_word(lsenv))) return false;
#ifdef CONFIG_LATX_OPT_NOFP
    if (!ft_offset_fits_imm12(lsenv_offset_of_nofp(lsenv))) return false;
#endif
    memset(s, 0, sizeof(*s));
    bool ok;
    switch (group) {
    case FISTTP: ok = ft_soft_x87_fisttp(out, f, pc); break;
    case LOAD: ok = ft_soft_x87_load(out, s, f, pc); break;
    case STORE: ok = ft_soft_x87_store(out, s, f, pc); break;
    case MEMORY80: ok = ft_soft_x87_memory80(out, s, f, pc); break;
    case COMPARE: ok = ft_soft_x87_compare(out, s, f, pc); break;
    case SCALE: ok = ft_soft_x87_scale(out, s); break;
    case EXAMINE: ok = ft_soft_x87_examine(out, s); break;
    case CONSTANT: ok = ft_soft_x87_constant(out, s, f->id); break;
    default: return false;
    }
    if (!ok) return false;
    if (s->count == 0) return true;
    ft_emit_branch_placeholder(out, &s->done_fix, FT_BRANCH_B, 0, 0, &s->done);
    if (s->integer_infinity) {
        /* Keep the finite FICOM/P path unchanged. Only valid +/-infinity
         * bypasses the existing checked helper through this cold block. */
        ft_bind_branch_label(&s->infinity, *out);
        ft_resolve_branch_fixup(&s->infinity_fix);
        FT_LA_LD_D_EMIT(out, la_t4, la_t0, lsenv_offset_of_fpr(lsenv, 0));
        ft_emit_li64(out, la_t2, UINT64_C(0x8000000000000000));
        ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t4, la_t2);
        FastBranchFixup resume;
        ft_emit_branch_placeholder(out, &resume, FT_BRANCH_B, 0, 0,
                                   &s->infinity_resume);
        ft_resolve_branch_fixup(&resume);
    }
    if (group == COMPARE) {
        ft_soft_x87_compare_cold(out, s, f);
        return true;
    }
    ft_bind_branch_label(&s->slow, *out);
    for (unsigned i = 0; i < s->count; ++i) ft_resolve_branch_fixup(&s->guards[i]);
    return true;
#else
    (void)out; (void)f; (void)s; (void)pc;
    return false;
#endif
}
