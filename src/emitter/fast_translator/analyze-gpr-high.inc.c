/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Bounded ordinary-TB high-half demand, folded into the existing flags walk.
 * No old GHBR result, machine-code scan or cross-TB state is consumed.
 * Translation overhead has not been measured.
 */
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
_Static_assert(GPR_NUM > 0 && GPR_NUM < 32, "GPR demand mask width");
#define FT_GPR_HIGH_ALL ((UINT32_C(1) << GPR_NUM) - 1)

/* A recognized instruction reads only low 32-bit GPR operands and cannot
 * fault, call a helper or exit. Its architectural destination is a complete
 * 32-bit write (including an aliased source/destination). Return false for
 * every other instruction so fault/helper/exit observers require all highs.
 * MOV reg,reg kills destination demand but is not an omission candidate:
 * its BSTRPICK also copies the source and must remain.
 */
static bool ft_gpr_high_32_info(const FastTemplateFields *f,
                               const FastTemplateRuntimeInfo *meta,
                               uint32_t *write32, bool *can_omit)
{
    int dst = -1;

    *write32 = 0;
    *can_omit = false;


    if (f->alu_op != FT_ALU_NONE) {
        if (f->alu_width != 32) {
            return false;
        }
        switch (f->alu_op) {
        case FT_ALU_ADD: case FT_ALU_SUB:
        case FT_ALU_ADC: case FT_ALU_SBB:
        case FT_ALU_AND: case FT_ALU_OR: case FT_ALU_XOR:
        case FT_ALU_CMP: case FT_ALU_TEST:
            break;
        default:
            return false;
        }
        switch (f->alu_form) {
        case FT_ALU_FORM_RM_R:
        case FT_ALU_FORM_R_RM:
            if (f->modrm_mod != 3 ||
                ft_modrm_reg_index(f) >= GPR_NUM ||
                ft_modrm_rm_index(f) >= GPR_NUM) {
                return false;
            }
            dst = f->alu_form == FT_ALU_FORM_RM_R ?
                  ft_modrm_rm_index(f) : ft_modrm_reg_index(f);
            break;
        case FT_ALU_FORM_RM_IMM:
            if (f->modrm_mod != 3) {
                return false;
            }
            dst = ft_modrm_rm_index(f);
            break;
        case FT_ALU_FORM_ACC_IMM:
            dst = rax_index;
            break;
        default:
            return false;
        }
        if (dst < 0 || dst >= GPR_NUM) {
            return false;
        }
        if (f->alu_op == FT_ALU_CMP || f->alu_op == FT_ALU_TEST) {
            goto validate; /* Pure low-half read, no destination kill. */
        }
        *can_omit = true;
    } else {
        switch (f->kind) {
        case FT_INC_RM32:
        case FT_DEC_RM32:
        case FT_NEG_RM32:
        case FT_NOT_RM32:
            if (f->modrm_mod != 3 ||
                f->modrm_reg != (f->kind == FT_INC_RM32 ? 0 :
                                 f->kind == FT_DEC_RM32 ? 1 :
                                 f->kind == FT_NOT_RM32 ? 2 : 3)) {
                return false;
            }
            dst = ft_modrm_rm_index(f);
            *can_omit = true;
            break;
        case FT_SHIFT_RM_IMM8:
        case FT_SHIFT_RM_ONE:
        case FT_SHIFT_RM_CL:
            /* Only r32 rotates. Every count, including zero, writes r32;
             * read CL before a possibly aliased ECX destination is updated.
             * RCL/RCR's nonzero result store also copies its temporary and
             * cannot be deleted. Its CL pre-clear is independent instead. */
            if (f->modrm_mod != 3 || f->modrm_reg > 3 ||
                f->opcode0 != (f->kind == FT_SHIFT_RM_IMM8 ? 0xc1 :
                               f->kind == FT_SHIFT_RM_ONE ? 0xd1 : 0xd3)) {
                return false;
            }
            dst = ft_modrm_rm_index(f);
            if (f->kind == FT_SHIFT_RM_CL) {
                *can_omit = true;
            } else if (f->modrm_reg < 2) {
                /* Immediate-zero ROL/ROR can omit their sole high clear
                 * only through the matching ordinary-TB zero-code policy.
                 */
                *can_omit = true;
            } else {
                *can_omit = f->kind == FT_SHIFT_RM_IMM8 &&
                            (f->imm & 31) == 0;
            }
            break;
        case FT_SHLD_RM_R_IMM8:
        case FT_SHRD_RM_R_IMM8:
            /* CL can skip its entire store on count zero. Do not infer an
             * unconditional destination kill from that separate template. */
            if (f->modrm_mod != 3 || (f->imm & 31) == 0 ||
                ft_modrm_reg_index(f) >= GPR_NUM) {
                return false;
            }
            dst = ft_modrm_rm_index(f);
            *can_omit = true;
            break;
        case FT_MOVD_RM32_MMX:
            /* LATU's separate MMX entry only updates env.mode_fpu; it does
             * not observe GPR highs, call a helper or change guest flags. */
            if (f->modrm_mod != 3 || f->prefix0 != 0 ||
                f->id != dt_X86_INS_MOVD || ft_modrm_reg_index(f) >= 8) {
                return false;
            }
            dst = ft_modrm_rm_index(f);
            *can_omit = true;
            break;
        case FT_CWDE:
            dst = rax_index;
            *can_omit = true;
            break;
        case FT_MOV_R32_IMM32:
            dst = f->reg;
            *can_omit = true;
            break;
        case FT_MOV_RM32_IMM32:
            if (f->modrm_mod != 3 || f->modrm_reg != 0) {
                return false;
            }
            dst = ft_modrm_rm_index(f);
            *can_omit = true;
            break;
        case FT_MOV_R32_RM32:
        case FT_MOV_RM32_R32:
            if (f->modrm_mod != 3 ||
                ft_modrm_reg_index(f) >= GPR_NUM ||
                ft_modrm_rm_index(f) >= GPR_NUM) {
                return false;
            }
            dst = f->kind == FT_MOV_R32_RM32 ?
                  ft_modrm_reg_index(f) : ft_modrm_rm_index(f);
            break;
        default:
            return false;
        }
    }
validate:
    /* Reject unrecognized kinds/forms before checking combination metadata.
     * Every successful path still passes the original safety checks. */
    if (!meta || meta->terminal_exit || f->segment >= 0 || ft_rex_w(f) ||
        f->prefix0 == dt_X86_PREFIX_LOCK ||
        f->prefix2 == dt_X86_PREFIX_OPSIZE || f->instptn_skip ||
        f->instptn_div_kind || f->direct_cmp_width ||
        f->direct_cmp_lhs_gpr >= 0 || f->direct_cmp_rhs_gpr >= 0 ||
        f->direct_bit_index_gpr >= 0 || f->direct_bit_index_imm >= 0 ||
        f->direct_branch_kind != FT_DIRECT_BRANCH_NONE ||
        f->direct_float_result || f->direct_float_xx) {
        return false;
    }
    if (f->alu_op == FT_ALU_CMP || f->alu_op == FT_ALU_TEST) {
        return true;
    }
    if (dst < 0 || dst >= GPR_NUM) {
        return false;
    }
    *write32 = UINT32_C(1) << dst;
    return true;
}

static void ft_analyze_gpr_high_step(FastTemplateFields *f,
                                    const FastTemplateRuntimeInfo *meta,
                                    uint32_t *need_hi, bool enabled)
{
    uint32_t write32;
    bool can_omit;

    f->omit_zext32 = false;
    if (!enabled || !ft_gpr_high_32_info(f, meta, &write32, &can_omit)) {
        *need_hi = FT_GPR_HIGH_ALL;
        return;
    }
    f->omit_zext32 = can_omit && !(*need_hi & write32);
    *need_hi &= ~write32;
}
#endif /* QUICKTRANS_LATU && !CONFIG_SOFTMMU */
