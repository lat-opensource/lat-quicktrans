/* SPDX-License-Identifier: MIT */

/* A direct path rejoins the existing template's helper path on any guard.
 * Keep all architectural writes after guards and faulting memory accesses. */
typedef struct FtSoftX87 {
    FastBranchLabel slow, done;
    FastBranchFixup guards[16], done_fix;
    unsigned count;
    bool loaded;
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

static bool ft_soft_x87_constant(uint32_t **out, FtSoftX87 *s, int id)
{
    uint64_t low;
    int high, rounding = 0;
    switch (id) {
    case dt_X86_INS_FLDZ: low = 0; high = 0; break;
    case dt_X86_INS_FLD1: low = UINT64_C(0x8000000000000000); high = 0x3fff; break;
    case dt_X86_INS_FLDL2E: low = UINT64_C(0xb8aa3b295c17f0bc); high = 0x3fff; rounding = -1; break;
    case dt_X86_INS_FLDL2T: low = UINT64_C(0xd49a784bcd1b8afe); high = 0x4000; rounding = 1; break;
    case dt_X86_INS_FLDLG2: low = UINT64_C(0x9a209a84fbcff799); high = 0x3ffd; rounding = -1; break;
    case dt_X86_INS_FLDLN2: low = UINT64_C(0xb17217f7d1cf79ac); high = 0x3ffe; rounding = -1; break;
    case dt_X86_INS_FLDPI: low = UINT64_C(0xc90fdaa22168c235); high = 0x4000; rounding = -1; break;
    default: return false;
    }
    ft_soft_x87_base(out, s);
    ft_soft_x87_slot(out, s, -1, la_t0, true);
    ft_emit_li64(out, la_t1, low);
    if (rounding) {
        FT_LA_LD_HU_EMIT(out, la_t2, la_s0, lsenv_offset_of_control_word(lsenv));
        if (rounding < 0) {
            FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t2, 10, 10);
            FT_LA_SUB_D_EMIT(out, la_t1, la_t1, la_t2);
        } else {
            /* log2(10) rounds up only for RC=up, not RC=truncate. */
            FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t2, 11, 10);
            FT_LA_XORI_EMIT(out, la_t2, la_t2, 2);
            FT_LA_SLTUI_EMIT(out, la_t2, la_t2, 1);
            FT_LA_ADD_D_EMIT(out, la_t1, la_t1, la_t2);
        }
    }
    FT_LA_ST_D_EMIT(out, la_t1, la_t0, lsenv_offset_of_fpr(lsenv, 0));
    ft_emit_li64(out, la_t1, high);
    FT_LA_ST_H_EMIT(out, la_t1, la_t0, lsenv_offset_of_fpr(lsenv, 0) + 8);
    ft_soft_x87_push(out);
    ft_soft_x87_clear_c1(out);
    return true;
}

static bool ft_soft_x87_cmov(uint32_t **out, FtSoftX87 *s,
                             const FastTemplateFields *f)
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
    if (f->modrm_rm > 7) return false;
    ft_soft_x87_base(out, s);
    ft_soft_x87_slot(out, s, 0, la_t0, false);
    ft_soft_x87_slot(out, s, f->modrm_rm, la_t1, false);
    ft_soft_x87_clear_c1(out);
    FT_LA_SETX86J_EMIT(out, la_t2, cond);
    FT_LA_BEQ_EMIT(out, la_t2, la_zero, 3);
    FT_LA_VLD_EMIT(out, ft_vscratch, la_t1, lsenv_offset_of_fpr(lsenv, 0));
    FT_LA_VST_EMIT(out, ft_vscratch, la_t0, lsenv_offset_of_fpr(lsenv, 0));
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
    ft_soft_x87_base(out, s);
    ft_soft_x87_slot(out, s, 0, la_t0, false);
    ft_soft_x87_slot(out, s, 1, la_t1, false);
    ft_soft_x87_normal(out, s, la_t0);
    ft_emit_li64(out, la_t4, 0x3c01);
    ft_soft_x87_guard(out, s, FT_BRANCH_BLTU, la_t3, la_t4);
    ft_emit_li64(out, la_t4, 0x43fe);
    ft_soft_x87_guard(out, s, FT_BRANCH_BGEU, la_t3, la_t4);
    ft_soft_x87_normal(out, s, la_t1);
    /* Keep exceptional scales and double-range overflow in the checked helper. */
    ft_emit_li64(out, la_t4, 0x4008);
    ft_soft_x87_guard(out, s, FT_BRANCH_BGEU, la_t3, la_t4);
    ft_soft_x87_to_double(out, la_t0, ft_vscratch);
    ft_soft_x87_to_double(out, la_t1, ft_vscratch + 1);
    FT_LA_FTINTRZ_L_D_EMIT(out, ft_vscratch + 1, ft_vscratch + 1);
    FT_LA_MOVFR2GR_D_EMIT(out, la_t2, ft_vscratch + 1);
    FT_LA_LD_HU_EMIT(out, la_t3, la_t0, lsenv_offset_of_fpr(lsenv, 0) + 8);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, la_t3, 14, 0);
    FT_LA_ADD_D_EMIT(out, la_t3, la_t3, la_t2);
    ft_emit_li64(out, la_t4, 0x3c01);
    ft_soft_x87_guard(out, s, FT_BRANCH_BLT, la_t3, la_t4);
    ft_emit_li64(out, la_t4, 0x43fe);
    ft_soft_x87_guard(out, s, FT_BRANCH_BGE, la_t3, la_t4);
    FT_LA_FSCALEB_D_EMIT(out, ft_vscratch, ft_vscratch, ft_vscratch + 1);
    ft_soft_x87_from_double(out, ft_vscratch);
    FT_LA_VST_EMIT(out, ft_vscratch, la_t0, lsenv_offset_of_fpr(lsenv, 0));
    return true;
}
static bool ft_soft_x87_examine(uint32_t **out, FtSoftX87 *s)
{
    ft_soft_x87_base(out, s);
    ft_soft_x87_slot(out, s, 0, la_t0, false);
    ft_soft_x87_normal(out, s, la_t0);
    /* Normal finite: C3/C2/C0 = 010; C1 is the operand's sign. */
    FT_LA_LD_HU_EMIT(out, la_t1, la_t0, lsenv_offset_of_fpr(lsenv, 0) + 8);
    FT_LA_SRLI_W_EMIT(out, la_t1, la_t1, 15);
    FT_LA_LD_HU_EMIT(out, la_t0, la_s0, lsenv_offset_of_status_word(lsenv));
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 14, 14);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 8, 8);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 9, 9);
    FT_LA_ORI_EMIT(out, la_t0, la_t0, 0x400);
    FT_LA_ST_H_EMIT(out, la_t0, la_s0, lsenv_offset_of_status_word(lsenv));
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
    FT_LA_MOVGR2FR_D_EMIT(out, ft_vscratch + 1, la_t4);
    s->loaded = true;
    ft_soft_x87_base(out, s);
    ft_soft_x87_slot(out, s, -1, la_t0, true);
    FT_LA_MOVFR2GR_D_EMIT(out, la_t1, ft_vscratch + 1);
    if (!integer) {
        FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t1, width == 32 ? 30 : 62,
                              width == 32 ? 23 : 52);
        ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t2, la_zero);
        FT_LA_ADDI_D_EMIT(out, la_t2, la_t2, width == 32 ? -255 : -2047);
        ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t2, la_zero);
    } else if (width == 64) {
        /* Like the old path, leave large integers to the exact helper. */
        FT_LA_SRAI_D_EMIT(out, la_t2, la_t1, 63);
        FT_LA_XOR_EMIT(out, la_t3, la_t1, la_t2);
        FT_LA_SUB_D_EMIT(out, la_t3, la_t3, la_t2);
        FT_LA_SRLI_D_EMIT(out, la_t3, la_t3, 52);
        ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t3, la_zero);
    }
    FT_LA_FMOV_D_EMIT(out, ft_vscratch, ft_vscratch + 1);
    if (integer) {
        if (width == 64) FT_LA_FFINT_D_L_EMIT(out, ft_vscratch, ft_vscratch);
        else FT_LA_FFINT_D_W_EMIT(out, ft_vscratch, ft_vscratch);
    } else if (width == 32) FT_LA_FCVT_D_S_EMIT(out, ft_vscratch, ft_vscratch);
    ft_soft_x87_from_double(out, ft_vscratch);
    FT_LA_VST_EMIT(out, ft_vscratch, la_t0, lsenv_offset_of_fpr(lsenv, 0));
    ft_soft_x87_push(out);
    ft_soft_x87_clear_c1(out);
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
    ft_soft_x87_base(out, s);
    ft_soft_x87_slot(out, s, 0, la_t0, false);
    ft_soft_x87_normal(out, s, la_t0);
    int fp = lsenv_offset_of_fpr(lsenv, 0);
    if (integer) {
        /* Exact, in-range integers need neither rounding nor exception repair.
         * Fractional/out-of-range values retain the checked conversion helper. */
        ft_emit_li64(out, la_t4, 0x3fff);
        ft_soft_x87_guard(out, s, FT_BRANCH_BLTU, la_t3, la_t4);
        ft_emit_li64(out, la_t4, 0x3fff + (width == 64 ? 52 : width - 1));
        ft_soft_x87_guard(out, s, FT_BRANCH_BGEU, la_t3, la_t4);
        ft_emit_li64(out, la_t4, 0x3ffe);
        FT_LA_SUB_D_EMIT(out, la_t3, la_t3, la_t4);
        FT_LA_LD_D_EMIT(out, la_t1, la_t0, fp);
        FT_LA_SLL_D_EMIT(out, la_t1, la_t1, la_t3);
        ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t1, la_zero);
    } else {
        ft_emit_li64(out, la_t4, width == 32 ? 0x3f81 : 0x3c01);
        ft_soft_x87_guard(out, s, FT_BRANCH_BLTU, la_t3, la_t4);
        ft_emit_li64(out, la_t4, width == 32 ? 0x407f : 0x43ff);
        ft_soft_x87_guard(out, s, FT_BRANCH_BGEU, la_t3, la_t4);
        FT_LA_LD_D_EMIT(out, la_t1, la_t0, fp);
        FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, width == 32 ? 24 : 53);
        ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t1, la_zero);
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
    ft_soft_x87_clear_c1(out);
    return true;
}

static bool ft_soft_x87_memory80(uint32_t **out, FtSoftX87 *s,
                                 const FastTemplateFields *f, target_ulong pc)
{
    bool load = f->kind == FT_X87_FLD_M80;
    if (f->modrm_mod == 3 || (!load && !(option_soft_fpu_fast & 0x800000))) return false;
    ft_soft_x87_base(out, s);
    ft_soft_x87_slot(out, s, load ? -1 : 0, la_t0, load);
    int addr;
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) return false;
    FT_LA_ADDI_D_EMIT(out, la_t1, addr, ft_mem_access_offset(f, addr));
    /* Use the original helper for a two-page access. No partial fast store. */
    FT_LA_ANDI_EMIT(out, la_t2, la_t1, 0xfff);
    ft_emit_li64(out, la_t3, 4096 - 9);
    ft_soft_x87_guard(out, s, FT_BRANCH_BGEU, la_t2, la_t3);
    if (load) {
        FT_LA_LD_D_EMIT(out, la_t2, la_t1, 0);
        FT_LA_LD_HU_EMIT(out, la_t3, la_t1, 8);
        FT_LA_MOVGR2FR_D_EMIT(out, ft_vscratch, la_t2);
        FT_LA_MOVGR2FR_D_EMIT(out, ft_vscratch + 1, la_t3);
        ft_soft_x87_slot(out, s, -1, la_t0, true);
        FT_LA_MOVFR2GR_D_EMIT(out, la_t2, ft_vscratch);
        FT_LA_MOVFR2GR_D_EMIT(out, la_t3, ft_vscratch + 1);
        FT_LA_ST_D_EMIT(out, la_t2, la_t0, lsenv_offset_of_fpr(lsenv, 0));
        FT_LA_ST_H_EMIT(out, la_t3, la_t0, lsenv_offset_of_fpr(lsenv, 0) + 8);
        ft_soft_x87_push(out);
    } else {
        /* Keep the destination address while recovering the source slot. */
        ft_soft_x87_slot(out, s, 0, la_t0, false);
        FT_LA_LD_D_EMIT(out, la_t2, la_t0, lsenv_offset_of_fpr(lsenv, 0));
        FT_LA_LD_HU_EMIT(out, la_t3, la_t0, lsenv_offset_of_fpr(lsenv, 0) + 8);
        FT_LA_ST_D_EMIT(out, la_t2, la_t1, 0);
        FT_LA_ST_H_EMIT(out, la_t3, la_t1, 8);
        ft_soft_x87_pop(out, 1);
    }
    ft_soft_x87_clear_c1(out);
    return true;
}
/* Conversion is exact here: unlike arithmetic, comparison must not collapse
 * distinct 80-bit values into the same double. */
static void ft_soft_x87_exact_double(uint32_t **out, FtSoftX87 *s, int address)
{
    int fp = lsenv_offset_of_fpr(lsenv, 0);

    FT_LA_LD_HU_EMIT(out, la_t3, address, fp + 8);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, la_t3, 14, 0);
    ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t3, la_zero);
    ft_emit_li64(out, la_t2, 0x7fff);
    ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t3, la_t2);
    FT_LA_LD_D_EMIT(out, la_t4, address, fp);
    FT_LA_SRLI_D_EMIT(out, la_t2, la_t4, 63);
    ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t2, la_zero);
    ft_emit_li64(out, la_t2, 0x3c01);
    ft_soft_x87_guard(out, s, FT_BRANCH_BLTU, la_t3, la_t2);
    ft_emit_li64(out, la_t2, 0x43ff);
    ft_soft_x87_guard(out, s, FT_BRANCH_BGEU, la_t3, la_t2);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t4, 53);
    ft_soft_x87_guard(out, s, FT_BRANCH_BNE, la_t4, la_zero);
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
    ft_soft_x87_base(out, s);
    ft_soft_x87_slot(out, s, 0, la_t0, false);
    ft_soft_x87_exact_double(out, s, la_t0);
    if (!memory && !zero) {
        ft_soft_x87_slot(out, s, index, la_t1, false);
        ft_soft_x87_exact_double(out, s, la_t1);
    } else if (memory && !integer) {
        FT_LA_MOVFR2GR_D_EMIT(out, la_t2, ft_vscratch + 1);
        FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t2, width == 32 ? 30 : 62,
                              width == 32 ? 23 : 52);
        ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t2, la_zero);
        FT_LA_ADDI_D_EMIT(out, la_t2, la_t2, width == 32 ? -255 : -2047);
        ft_soft_x87_guard(out, s, FT_BRANCH_BEQ, la_t2, la_zero);
    }
    ft_soft_x87_to_double(out, la_t0, ft_vscratch);
    if (zero) FT_LA_MOVGR2FR_D_EMIT(out, ft_vscratch + 1, la_zero);
    else if (!memory) ft_soft_x87_to_double(out, la_t1, ft_vscratch + 1);
    else if (integer) FT_LA_FFINT_D_W_EMIT(out, ft_vscratch + 1, ft_vscratch + 1);
    else if (width == 32) FT_LA_FCVT_D_S_EMIT(out, ft_vscratch + 1, ft_vscratch + 1);
    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0,
                                 ft_vscratch, ft_vscratch + 1, 0x02));
    FT_LA_MOVCF2GR_EMIT(out, la_t1, 0);
    ft_emit_raw(out, ft_fcmp_cond(FT_LA_OPCODE_FCMP_COND_D, 0,
                                 ft_vscratch, ft_vscratch + 1, 0x04));
    FT_LA_MOVCF2GR_EMIT(out, la_t2, 0);
    int sw = lsenv_offset_of_status_word(lsenv);
    FT_LA_LD_HU_EMIT(out, la_t0, la_s0, sw);
    if (flags) {
        FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, 6);
        FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);
        FT_LA_X86MTFLAG_EMIT(out, la_t1, 0x3f);
    } else {
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 9, 9);
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 8, 8);
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_zero, 10, 10);
        FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t2, 14, 14);
    }
    FT_LA_ST_H_EMIT(out, la_t0, la_s0, sw);
    if (pop) ft_soft_x87_pop(out, pop);
    return true;
}

#endif

static bool ft_emit_x87_soft_extra(uint32_t **out,
                                   const FastTemplateFields *f,
                                   target_ulong pc, FtSoftX87 *s)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (!option_soft_fpu || !option_soft_fpu_fast) return false;
    enum { LOAD, STORE, MEMORY80, COMPARE, SCALE, CMOV, CONSTANT, EXAMINE } group;
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
    case FT_X87_FSCALE: group = SCALE; break;
    case FT_X87_FXAM: group = EXAMINE; break;
    case FT_X87_FCMOVCC: group = CMOV; break;
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
    case LOAD: ok = ft_soft_x87_load(out, s, f, pc); break;
    case STORE: ok = ft_soft_x87_store(out, s, f, pc); break;
    case MEMORY80: ok = ft_soft_x87_memory80(out, s, f, pc); break;
    case COMPARE: ok = ft_soft_x87_compare(out, s, f, pc); break;
    case SCALE: ok = ft_soft_x87_scale(out, s); break;
    case EXAMINE: ok = ft_soft_x87_examine(out, s); break;
    case CMOV: ok = ft_soft_x87_cmov(out, s, f); break;
    case CONSTANT: ok = ft_soft_x87_constant(out, s, f->id); break;
    default: return false;
    }
    if (!ok) return false;
    ft_emit_branch_placeholder(out, &s->done_fix, FT_BRANCH_B, 0, 0, &s->done);
    ft_bind_branch_label(&s->slow, *out);
    for (unsigned i = 0; i < s->count; ++i) ft_resolve_branch_fixup(&s->guards[i]);
    return true;
#else
    (void)out; (void)f; (void)s; (void)pc;
    return false;
#endif
}
