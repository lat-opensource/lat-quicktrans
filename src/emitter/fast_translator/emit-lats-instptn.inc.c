/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 * SPDX-License-Identifier: MIT
 */

/* temp128 is LATS' per-vCPU translator scratch. Quicktrans never calls the
 * legacy split-load/store emitter inside a block. A restarted block reads
 * guest flags; it never inherits a pattern from its predecessor. */
static void ft_emit_pattern_addr(uint32_t **out)
{
    int offset = offsetof(CPUX86State, temp128);
    if (ft_offset_fits_imm12(offset)) {
        FT_LA_ADDI_D_EMIT(out, la_a0, la_s0, offset);
    } else {
        ft_emit_li64(out, la_a0, offset);
        FT_LA_ADD_D_EMIT(out, la_a0, la_s0, la_a0);
    }
}

/* Result/BT patterns may have written memory or a high byte. Read the
 * live zero/sign/carry condition without issuing a second guest load. */
static bool ft_emit_lats_pattern_condition(uint32_t **out,
                                          const FastTemplateFields *f, int dst)
{
    bool cmp = f->pattern_inputs == FT_PATTERN_CMP || f->pattern_inputs == FT_PATTERN_CMP_REGS;
    int cc = f->alu_op == FT_ALU_SBB ? FT_CC_B : ft_pattern_cc(f);
    int positive = cc & ~1;
    bool invert = cc & 1;
    int lhs = la_a1, rhs = la_a2;
    int width = f->direct_cmp_width;

    if (f->pattern_inputs == FT_PATTERN_FLAGS) {
        int mask;
        switch (positive) {
        case FT_CC_O: mask = OF_USEDEF_BIT; break;
        case FT_CC_B: mask = CF_USEDEF_BIT; break;
        case FT_CC_E: mask = ZF_USEDEF_BIT; break;
        case FT_CC_BE: mask = CF_USEDEF_BIT | ZF_USEDEF_BIT; break;
        case FT_CC_S: mask = SF_USEDEF_BIT; break;
        /* Logical producers clear OF, so signed LE tests SF or ZF. */
        case FT_CC_L: mask = SF_USEDEF_BIT; break;
        case FT_CC_LE: mask = SF_USEDEF_BIT | ZF_USEDEF_BIT; break;
        default: return false;
        }
        FT_LA_X86MFFLAG_EMIT(out, dst, mask);
        FT_LA_SLTU_EMIT(out, dst, la_zero, dst);
    } else {
        if (f->pattern_inputs == FT_PATTERN_RESULT) {
            ft_emit_pattern_addr(out);
            FT_LA_LD_D_EMIT(out, lhs, la_a0, 0);
            rhs = la_zero;
        } else if (f->pattern_inputs != FT_PATTERN_CMP_REGS &&
                   f->pattern_inputs != FT_PATTERN_TEST_REGS) {
            ft_emit_pattern_addr(out);
            FT_LA_LD_D_EMIT(out, lhs, la_a0, 0);
            FT_LA_LD_D_EMIT(out, rhs, la_a0, 8);
        }
        if (!cmp && rhs != la_zero) {
            FT_LA_AND_EMIT(out, lhs, lhs, rhs);
            rhs = la_zero;
        }
        if (positive == FT_CC_S && cmp) {
            FT_LA_SUB_D_EMIT(out, lhs, lhs, rhs);
            rhs = la_zero;
        }
        bool sign = positive == FT_CC_S || positive == FT_CC_L || positive == FT_CC_LE;
        if (width < 64) {
            if (sign) {
                FT_LA_SLLI_D_EMIT(out, lhs, lhs, 64 - width);
                FT_LA_SRAI_D_EMIT(out, lhs, lhs, 64 - width);
                if (rhs != la_zero) {
                    FT_LA_SLLI_D_EMIT(out, rhs, rhs, 64 - width);
                    FT_LA_SRAI_D_EMIT(out, rhs, rhs, 64 - width);
                }
            } else {
                FT_LA_BSTRPICK_D_EMIT(out, lhs, lhs, width - 1, 0);
                if (rhs != la_zero)
                    FT_LA_BSTRPICK_D_EMIT(out, rhs, rhs, width - 1, 0);
            }
        }
        switch (positive) {
        case FT_CC_O: FT_LA_OR_EMIT(out, dst, la_zero, la_zero); break;
        case FT_CC_B: FT_LA_SLTU_EMIT(out, dst, lhs, rhs); break;
        case FT_CC_E:
            FT_LA_XOR_EMIT(out, dst, lhs, rhs);
            FT_LA_SLTUI_EMIT(out, dst, dst, 1);
            break;
        case FT_CC_BE: FT_LA_SLTU_EMIT(out, dst, rhs, lhs); invert = !invert; break;
        case FT_CC_S: case FT_CC_L: FT_LA_SLT_EMIT(out, dst, lhs, rhs); break;
        case FT_CC_LE: FT_LA_SLT_EMIT(out, dst, rhs, lhs); invert = !invert; break;
        default: return false;
        }
    }
    if (invert) FT_LA_XORI_EMIT(out, dst, dst, 1);
    return true;
}
