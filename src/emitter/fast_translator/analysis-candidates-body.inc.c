/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 * SPDX-License-Identifier: MIT
 */

/* Included twice for LATU: compile out RSP merge work when disabled. */
static unsigned int FT_SPECIALIZED_NAME(const FastTemplateFields *fields)
{
#ifdef QUICKTRANS_LATU
    unsigned int mask = fields->alu_op == FT_ALU_SBB ? FT_ANALYZE_SBB : 0;

    switch (fields->kind) {
    case FT_SETCC_RM8:
    case FT_CMOV_R64_RM64:
    case FT_CMOV_R32_RM32:
    case FT_CMOV_R16_RM16:
        mask |= FT_ANALYZE_XXCC;
        break;
    case FT_DIV_RM32:
    case FT_DIV_RM64:
    case FT_IDIV_RM32:
    case FT_IDIV_RM64:
        mask |= FT_ANALYZE_DIV;
        break;
    case FT_SIMD_SCALAR_CMP_XMM_XMMM:
        mask |= FT_ANALYZE_FLOAT;
        break;
#if !defined(CONFIG_SOFTMMU) && defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
    case FT_LEAVE: case FT_ENTER: case FT_ENTER16: case FT_ENTER_ZERO_LEVEL1:
    case FT_PUSH_R64: case FT_POP_R64: case FT_PUSH_R16: case FT_POP_R16:
    case FT_PUSH_RM64: case FT_POP_RM64: case FT_PUSH_RM16: case FT_POP_RM16:
    case FT_PUSHFQ: case FT_PUSH_SEG64: case FT_PUSH_SEG16:
    case FT_PUSH_IMM32: case FT_PUSH_IMM8: case FT_PUSH_IMM16:
        mask |= FT_ANALYZE_RSP;
        break;
    case FT_LEA_R64_M:
        if (ft_modrm_reg_index(fields) == rsp_index) {
            mask |= FT_ANALYZE_RSP;
        }
        break;
    case FT_INC_RM64: case FT_DEC_RM64:
        if (fields->modrm_mod == 3 &&
            ft_modrm_rm_index(fields) == rsp_index) {
            mask |= FT_ANALYZE_RSP;
        }
        break;
#endif
    default:
#if !defined(CONFIG_SOFTMMU) && defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
    /* Flags have not been analyzed yet: conservatively retain every ADD/SUB
     * immediate that can later become an RSP adjustment with dead flags. */
    if ((fields->alu_op == FT_ALU_ADD || fields->alu_op == FT_ALU_SUB) &&
        fields->alu_form == FT_ALU_FORM_RM_IMM && fields->alu_width == 64 &&
        fields->modrm_mod == 3 && ft_modrm_rm_index(fields) == rsp_index) {
        mask |= FT_ANALYZE_RSP;
    }
#endif
        break;
    }
    return mask;
#else
    (void)fields;
    return FT_ANALYZE_ALL;
#endif
}

