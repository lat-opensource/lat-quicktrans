/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Fast translator template constraint checks. */

static bool fast_template_addr_mode_ok(const FastTemplateFields *fields,
                                       uint8_t allowed)
{
    int mod = fields->modrm_mod;

    if (!allowed) {
        return true;
    }
    if (mod == 3) {
        return allowed & FT_TM_ADDR_REG;
    }
    if (fields->segment >= 0) {
        return allowed & FT_TM_ADDR_SEGMENT;
    }
    if (mod == 0 && fields->modrm_rm == 5) {
        return allowed & FT_TM_ADDR_RIP;
    }
    if ((allowed & FT_TM_ADDR_BASE) &&
        ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                           fields->sib)) {
        return true;
    }
    return (allowed & FT_TM_ADDR_LEA) &&
           ft_supported_lea_addr(fields->rex, fields->modrm, fields->sib);
}

static bool fast_template_meta_constraints_ok(const FastTemplateFields *fields)
{
    const FastTemplateDesc *desc = &fast_templates[fields->kind];
    uint32_t flags = desc->meta_flags;

    if (!(flags & FT_TM_CONSTRAINTS_DECLARED)) {
        return false;
    }
    if ((flags & FT_TM_REQUIRES_REX_W) && !ft_rex_w(fields)) {
        return false;
    }
    if ((flags & FT_TM_FORBIDS_REX_W) && ft_rex_w(fields)) {
        return false;
    }
    if ((flags & FT_TM_MODRM_REG_ONLY) &&
        fields->modrm_mod != 3) {
        return false;
    }
    if ((flags & FT_TM_MODRM_MEM_ONLY) &&
        fields->modrm_mod == 3) {
        return false;
    }
    if ((flags & FT_TM_NO_HIGH8_RM) && ft_modrm_rm_is_high8(fields)) {
        return false;
    }
    if ((flags & FT_TM_NO_HIGH8_REG) && ft_modrm_reg_is_high8(fields)) {
        return false;
    }
    if ((flags & FT_TM_OPCODE_REG_VALID) &&
        (fields->reg < 0 || fields->reg >= GPR_NUM)) {
        return false;
    }
    if ((flags & FT_TM_OPCODE_REG_NONZERO) &&
        ft_rex_base_from_opcode(fields->rex, fields->opcode0) == 0) {
        return false;
    }
    if ((flags & FT_TM_IMM_U8) &&
        (fields->imm < 0 || fields->imm > 0xff)) {
        return false;
    }
    if ((flags & FT_TM_IMM_NONNEG) && fields->imm < 0) {
        return false;
    }
    if ((flags & FT_TM_IMM_SIMM12) && !ft_fits_simm12(fields->imm)) {
        return false;
    }
    if ((flags & FT_TM_DISP_SIMM12) && !ft_fits_simm12(fields->disp)) {
        return false;
    }
    if ((flags & FT_TM_RIP_ALIGNED) &&
        !ft_rip_mem_aligned(fields, desc->rip_align)) {
        return false;
    }
    if ((flags & FT_TM_PREFIX0_REP) &&
        fields->prefix0 != dt_X86_PREFIX_REP) {
        return false;
    }
    if ((flags & FT_TM_MODRM_REG_EXT_VALID) &&
        fields->modrm_reg != desc->modrm_reg_ext) {
        return false;
    }
    if ((flags & FT_TM_MODRM_REG_EXT_MASK) &&
        !(desc->modrm_reg_ext_mask & (1u << fields->modrm_reg))) {
        return false;
    }
    return fast_template_addr_mode_ok(fields, desc->addr_modes);
}

static bool fast_template_emit_constraints_ok(const FastTemplateFields *fields)
{
    if (fast_templates[fields->kind].meta_flags & FT_TM_CONSTRAINTS_DECLARED) {
        return fast_template_meta_constraints_ok(fields);
    }

    switch (fields->kind) {
    case FT_HELPER_CPUID:
        return true;
    case FT_HELPER_PCMPISTRI:
    case FT_HELPER_PCMPISTRM:
    case FT_HELPER_PCMPESTRI:
    case FT_HELPER_PCMPESTRM:
        return fields->imm >= 0 && fields->imm <= 0xff &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_MOV_RM64_IMM32:
        if (fields->modrm_reg != 0) {
            return false;
        }
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_CALL_RM64:
    case FT_JMP_RM64:
        if (fields->modrm_reg !=
            (fields->kind == FT_CALL_RM64 ? 2 : 4)) {
            return false;
        }
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return true;
    case FT_TEST_AL_IMM8:
        return fields->imm >= 0 && fields->imm <= 0xff;
    case FT_AND_AL_IMM8:
    case FT_OR_AL_IMM8:
    case FT_XOR_AL_IMM8:
        return fields->imm >= 0 && fields->imm <= 0xff;
    case FT_TEST_EAX_IMM32:
    case FT_TEST_RAX_IMM32:
        return true;
    case FT_ADD_R64_IMM8:
        return fields->imm >= 0;
    case FT_ADD_AL_IMM8:
    case FT_ADC_AL_IMM8:
    case FT_SUB_AL_IMM8:
        return fields->imm >= 0 && fields->imm <= 0xff;
    case FT_ADD_AX_IMM16:
    case FT_SUB_AX_IMM16:
    case FT_ADD_EAX_IMM32:
    case FT_ADD_RAX_IMM32:
        return true;
    case FT_SUB_EAX_IMM32:
        return true;
    case FT_SUB_R64_IMM32:
        return fields->imm >= 0;
    case FT_SUB_R64_IMM8:
        return ft_fits_simm12(-(int64_t)fields->imm);
    case FT_ADD_R64_IMM32:
        return fields->imm >= 0;
    case FT_ALU_ACC_IMM:
        return fields->alu_form == FT_ALU_FORM_ACC_IMM &&
               fields->alu_op != FT_ALU_NONE;
    case FT_ALU_RM_R:
    case FT_ALU_R_RM:
        if ((fields->alu_form != FT_ALU_FORM_RM_R &&
             fields->alu_form != FT_ALU_FORM_R_RM) ||
            fields->alu_op == FT_ALU_NONE) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_TEST_RM16_IMM16:
        if (fields->modrm_reg != 0) {
            return false;
        }
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_CMP_RM64_IMM8:
    case FT_CMP_RM16_IMM8:
    case FT_CMP_RM32_IMM8:
        if (!ft_fits_simm12(fields->imm)) {
            return false;
        }
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_CMP_RM64_IMM32:
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_CMP_RM16_IMM16:
        return fields->modrm_reg == 7;
    case FT_TEST_RM64_R64:
    case FT_TEST_RM64_IMM32:
    case FT_ADD_R64_RM64:
    case FT_ADD_R32_RM32:
    case FT_ADD_R16_RM16:
    case FT_ADC_R64_RM64:
    case FT_ADC_R32_RM32:
    case FT_ADC_R16_RM16:
    case FT_ADD_RM16_R16:
    case FT_ADC_RM64_R64:
    case FT_ADC_RM32_R32:
    case FT_ADC_RM16_R16:
    case FT_CMP_RM16_R16:
    case FT_CMP_R16_RM16:
    case FT_ADD_RM64_R64:
    case FT_SUB_R64_RM64:
    case FT_SUB_R32_RM32:
    case FT_SUB_R16_RM16:
    case FT_SUB_R8_RM8:
    case FT_SUB_RM16_R16:
    case FT_SUB_RM8_R8:
    case FT_AND_RM64_R64:
    case FT_AND_RM32_R32:
    case FT_AND_R64_RM64:
    case FT_AND_R32_RM32:
    case FT_OR_R64_RM64:
    case FT_OR_R32_RM32:
    case FT_OR_R16_RM16:
    case FT_OR_R8_RM8:
    case FT_XOR_RM64_R64:
    case FT_XOR_RM32_R32:
    case FT_XOR_R64_RM64:
    case FT_XOR_R32_RM32:
    case FT_XOR_R16_RM16:
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return true;
    case FT_SUB_RM64_R64:
        return true;
    case FT_OR_RM64_R64:
    case FT_OR_RM32_R32:
    case FT_SUB_RM32_R32:
        return true;
    case FT_SHIFT_RM_IMM8:
        if ((fields->modrm_reg != 0 &&
             fields->modrm_reg != 1 &&
             fields->modrm_reg != 2 &&
             fields->modrm_reg != 3 &&
             fields->modrm_reg != 4 &&
             fields->modrm_reg != 5 &&
             fields->modrm_reg != 7)) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_ROL_RM64_IMM8:
        return ft_rex_w(fields) && fields->modrm_mod == 3 &&
               fields->modrm_reg == 0;
    case FT_ROR_RM64_IMM8:
        return ft_rex_w(fields) && fields->modrm_mod == 3 &&
               fields->modrm_reg == 1;
    case FT_SHIFT_RM_CL:
    case FT_SHIFT_RM_ONE:
        if (fields->modrm_reg != 0 &&
            fields->modrm_reg != 1 &&
            fields->modrm_reg != 2 &&
            fields->modrm_reg != 3 &&
            fields->modrm_reg != 4 &&
            fields->modrm_reg != 5 &&
            fields->modrm_reg != 7) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_SHR_RM8_IMM8:
        return fields->modrm_reg == 5 &&
               (fields->imm & 31) > 0 && (fields->imm & 31) < 8;
    case FT_SHR_RM8_ONE:
        return fields->modrm_reg == 5;
    case FT_SHR_RM16_IMM8:
        return !ft_rex_w(fields) && fields->modrm_reg == 5 &&
               (fields->imm & 31) > 0 && (fields->imm & 31) < 16;
    case FT_PREFETCH:
    case FT_PREFETCHW:
    case FT_PREFETCHT0:
    case FT_PREFETCHNTA:
    case FT_PREFETCHT1:
    case FT_PREFETCHT2:
        if (fields->modrm_mod == 3 ||
            fields->modrm_reg != (fields->kind == FT_PREFETCH ? 0 :
                                  fields->kind == FT_PREFETCHNTA ? 0 :
                                  fields->kind == FT_PREFETCHT1 ? 2 :
                                  fields->kind == FT_PREFETCHT2 ? 3 : 1) ||
            fields->prefix0 != 0 || fields->prefix2 != 0) {
            return false;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_BNDMOV:
        return fields->id == dt_X86_INS_BNDMOV &&
               fields->prefix0 == 0 &&
               fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
               (fields->opcode1 == 0x1a || fields->opcode1 == 0x1b) &&
               !ft_rex_r(fields) && fields->modrm_reg <= 3 &&
               (fields->modrm_mod != 3 ||
                (!ft_rex_b(fields) && fields->modrm_rm <= 3));
    case FT_PHADD_SUB_MMX_MMXM64:
        if (fields->prefix0 != 0 || fields->prefix2 != 0 ||
            fields->modrm_reg >= 8 ||
            !((fields->opcode1 == 0x01 &&
               fields->id == dt_X86_INS_PHADDW) ||
              (fields->opcode1 == 0x02 &&
               fields->id == dt_X86_INS_PHADDD) ||
              (fields->opcode1 == 0x03 &&
               fields->id == dt_X86_INS_PHADDSW) ||
              (fields->opcode1 == 0x05 &&
               fields->id == dt_X86_INS_PHSUBW) ||
              (fields->opcode1 == 0x06 &&
               fields->id == dt_X86_INS_PHSUBD) ||
              (fields->opcode1 == 0x07 &&
               fields->id == dt_X86_INS_PHSUBSW))) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PSHUFB_MMX_MMXM64:
    case FT_SIMD_MADD_MMX_MMXM64:
    case FT_SIMD_BIN_MMX_MMXM64:
        if (fields->prefix0 != 0 || fields->prefix2 != 0 ||
            fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PMAXSW_MMX_MMXM64:
        if (fields->id != dt_X86_INS_PMAXSW || fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PMINSW_MMX_MMXM64:
        if (fields->id != dt_X86_INS_PMINSW || fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PADDB_MMX_MMXM64:
    case FT_PADDD_MMX_MMXM64:
    case FT_PADDQ_MMX_MMXM64:
        if (fields->id != (fields->kind == FT_PADDB_MMX_MMXM64 ?
                           dt_X86_INS_PADDB :
                           fields->kind == FT_PADDD_MMX_MMXM64 ?
                           dt_X86_INS_PADDD : dt_X86_INS_PADDQ) ||
            fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PADDW_MMX_MMXM64:
        if (fields->id != dt_X86_INS_PADDW || fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PADDSB_MMX_MMXM64:
    case FT_PADDSW_MMX_MMXM64:
        if ((fields->kind == FT_PADDSB_MMX_MMXM64 &&
             fields->id != dt_X86_INS_PADDSB) ||
            (fields->kind == FT_PADDSW_MMX_MMXM64 &&
             fields->id != dt_X86_INS_PADDSW) ||
            fields->prefix0 != 0 || fields->prefix2 != 0 ||
            fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PCMPGTB_MMX_MMXM64:
    case FT_PCMPGTW_MMX_MMXM64:
    case FT_PCMPGTD_MMX_MMXM64:
    case FT_PCMPEQB_MMX_MMXM64:
    case FT_PCMPEQW_MMX_MMXM64:
    case FT_PCMPEQD_MMX_MMXM64:
        if (!((fields->kind == FT_PCMPGTB_MMX_MMXM64 &&
               fields->id == dt_X86_INS_PCMPGTB) ||
              (fields->kind == FT_PCMPGTW_MMX_MMXM64 &&
               fields->id == dt_X86_INS_PCMPGTW) ||
              (fields->kind == FT_PCMPGTD_MMX_MMXM64 &&
               fields->id == dt_X86_INS_PCMPGTD) ||
              (fields->kind == FT_PCMPEQB_MMX_MMXM64 &&
               fields->id == dt_X86_INS_PCMPEQB) ||
              (fields->kind == FT_PCMPEQW_MMX_MMXM64 &&
               fields->id == dt_X86_INS_PCMPEQW) ||
              (fields->kind == FT_PCMPEQD_MMX_MMXM64 &&
               fields->id == dt_X86_INS_PCMPEQD)) || fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PMULLW_MMX_MMXM64:
        if (fields->id != dt_X86_INS_PMULLW || fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PMULUDQ_MMX_MMXM64:
        if (fields->id != dt_X86_INS_PMULUDQ || fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PMULHW_MMX_MMXM64:
    case FT_PMULHUW_MMX_MMXM64:
        if (fields->id != (fields->kind == FT_PMULHUW_MMX_MMXM64 ?
                           dt_X86_INS_PMULHUW : dt_X86_INS_PMULHW) ||
            fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PSRAW_MMX_MMXM64:
    case FT_PSRAD_MMX_MMXM64:
        if (fields->id != (fields->kind == FT_PSRAW_MMX_MMXM64 ?
                           dt_X86_INS_PSRAW : dt_X86_INS_PSRAD) ||
            fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PXOR_MMX_MMXM64:
        if (fields->id != dt_X86_INS_PXOR || fields->prefix0 != 0 ||
            fields->prefix2 != 0 || fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PXOR_XMM_XMMM:
    case FT_PADD_XMM_XMMM:
    case FT_PADDQ_XMM_XMMM:
    case FT_PMULUDQ_XMM_XMMM:
    case FT_PCMPEQB_XMM_XMMM:
    case FT_SIMD_BIN_XMM_XMMM:
    case FT_PUNPCK_XMM_XMMM:
    case FT_UNPCKPD_XMM_XMMM:
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_MASKMOVQ_MMX_MMX:
        return fields->id == dt_X86_INS_MASKMOVQ &&
               fields->prefix0 == 0 && fields->prefix2 == 0 &&
               fields->opcode1 == 0xf7 && fields->modrm_mod == 3 &&
               fields->modrm_reg < 8 && fields->modrm_rm < 8;
    case FT_PACK_XMM_XMM:
        return !ft_rex_w(fields) &&
               fields->prefix0 == 0 &&
               fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib)) &&
               (fields->id == dt_X86_INS_PACKSSWB ||
                fields->id == dt_X86_INS_PACKSSDW ||
                fields->id == dt_X86_INS_PACKUSWB ||
                fields->id == dt_X86_INS_PACKUSDW);
    case FT_SIMD_MADD_XMM_XMM:
        return !ft_rex_w(fields) &&
               fields->prefix0 == 0 &&
               fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib)) &&
               (fields->id == dt_X86_INS_PMADDWD ||
                fields->id == dt_X86_INS_PMULHRSW ||
                fields->id == dt_X86_INS_PMADDUBSW);
    case FT_SIMD_SCALAR_BIN_XMM_XMMM:
        return (fields->prefix0 == dt_X86_PREFIX_REPNE ||
                fields->prefix0 == dt_X86_PREFIX_REP) &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_SIMD_SCALAR_CMP_XMM_XMMM:
        return ((fields->prefix0 == 0 && fields->prefix2 == 0) ||
                fields->prefix2 == 0x66) &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_PSRLQ_XMM_IMM8:
    case FT_PSLLQ_XMM_IMM8:
        return fields->modrm_mod == 3 &&
               (fields->modrm_reg == 2 ||
                fields->modrm_reg == 6) &&
               fields->imm >= 0 && fields->imm <= 255;
    case FT_PSHIFT_XMM_IMM8:
        return fields->modrm_mod == 3 &&
               fields->imm >= 0 && fields->imm <= 255 &&
               (fields->opcode1 == 0x71 || fields->opcode1 == 0x72 ||
                fields->opcode1 == 0x73) &&
               (fields->modrm_reg == 2 ||
                fields->modrm_reg == 4 ||
                fields->modrm_reg == 6);
    case FT_PSHIFT_MMX_IMM8:
        return fields->prefix0 == 0 && fields->prefix2 == 0 &&
               fields->modrm_mod == 3 && fields->modrm_rm_index < 8 &&
               fields->imm >= 0 && fields->imm <= 255 &&
               (fields->opcode1 == 0x71 || fields->opcode1 == 0x72 ||
                fields->opcode1 == 0x73) &&
               (fields->modrm_reg == 2 || fields->modrm_reg == 4 ||
                fields->modrm_reg == 6) &&
               (fields->opcode1 != 0x73 ||
                (fields->modrm_reg == 2 || fields->modrm_reg == 6));
    case FT_SHUF_XMM_XMMM_IMM8:
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PSRLDQ_XMM_IMM8:
    case FT_PSLLDQ_XMM_IMM8:
        return fields->modrm_mod == 3 &&
               fields->modrm_reg ==
               (fields->kind == FT_PSRLDQ_XMM_IMM8 ? 3 : 7);
    case FT_MOVLPS_XMM_M64:
    case FT_MOVLPD_XMM_M64:
        return fields->modrm_mod != 3 &&
               (ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_MOVHPS_XMM_M64:
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_MOVSD_XMM_M64:
        return (fields->prefix0 == dt_X86_PREFIX_REPNE ||
                fields->prefix0 == dt_X86_PREFIX_REP) &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_MOVSD_M64_XMM:
        if (fields->prefix0 != dt_X86_PREFIX_REPNE &&
            fields->prefix0 != dt_X86_PREFIX_REP) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        if (!ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                fields->sib) &&
            !ft_supported_lea_addr(fields->rex, fields->modrm, fields->sib)) {
            return false;
        }
        return true;
    case FT_STMXCSR_M32:
        return fields->modrm_mod != 3 &&
               fields->modrm_reg == 3 &&
               (ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_PALIGNR_XMM_XMMM_IMM8:
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PALIGNR_MMX_MMXM64_IMM8:
        if (fields->prefix0 != 0 || fields->prefix2 != 0 ||
            fields->modrm_reg >= 8) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return fields->modrm_rm < 8;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_SETCC_RM8:
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_BSF_R64_RM64:
    case FT_BSR_R64_RM64:
        return ft_rex_w(fields);
    case FT_MUL_RM64:
        return ft_rex_w(fields) && fields->modrm_reg == 4;
    case FT_MUL_RM8:
        if (ft_rex_w(fields) || fields->modrm_reg != 4) {
            return false;
        }
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_DIV_RM8:
        if (ft_rex_w(fields) || fields->modrm_reg != 6) {
            return false;
        }
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_DIV_RM16:
        return !ft_rex_w(fields) && fields->modrm_reg == 6 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_DIV_RM32:
        return !ft_rex_w(fields) && fields->modrm_reg == 6 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_DIV_RM64:
        return ft_rex_w(fields) && fields->modrm_reg == 6 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_IDIV_RM8:
        if (ft_rex_w(fields) || fields->modrm_reg != 7) {
            return false;
        }
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_IDIV_RM16:
        return !ft_rex_w(fields) && fields->modrm_reg == 7 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_IDIV_RM32:
        return !ft_rex_w(fields) && fields->modrm_reg == 7 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_IDIV_RM64:
        return ft_rex_w(fields) && fields->modrm_reg == 7 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_MOVSX_R64_RM8:
    case FT_MOVSX_R32_RM8:
    case FT_MOVSX_R16_RM8:
    case FT_MOVSX_R64_RM16:
    case FT_MOVSX_R32_RM16:
    case FT_MOVSX_R16_RM16:
        if ((fields->kind == FT_MOVSX_R64_RM8 ||
             fields->kind == FT_MOVSX_R64_RM16) != ft_rex_w(fields)) {
            return false;
        }
        if (((fields->kind == FT_MOVSX_R16_RM8 ||
              fields->kind == FT_MOVSX_R16_RM16) &&
             fields->prefix2 != dt_X86_PREFIX_OPSIZE) ||
            (fields->kind != FT_MOVSX_R16_RM8 &&
             fields->kind != FT_MOVSX_R16_RM16 &&
             !ft_rex_w(fields) &&
             fields->prefix2 == dt_X86_PREFIX_OPSIZE)) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PUSH_RM64:
        return fields->modrm_reg == 6 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_POP_RM64:
        return fields->modrm_reg == 0 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_PUSH_RM16:
        return !ft_rex_w(fields) && fields->modrm_reg == 6 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_POP_RM16:
        return !ft_rex_w(fields) && fields->modrm_reg == 0 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_BSF_R32_RM32:
    case FT_BSR_R32_RM32:
        return !ft_rex_w(fields);
    case FT_BSF_R16_RM16:
    case FT_BSR_R16_RM16:
        return !ft_rex_w(fields) &&
               fields->prefix2 == dt_X86_PREFIX_OPSIZE;
    case FT_MUL_RM32:
        return !ft_rex_w(fields) && fields->reg >= 0 &&
               fields->reg < GPR_NUM;
    case FT_MOVQ_XMM_R64:
    case FT_MOVQ_R64_XMM:
        return ft_rex_w(fields) && fields->modrm_mod == 3;
    case FT_PINSR_XMM_GPR_IMM8:
        return fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib)) &&
               (fields->id == dt_X86_INS_PINSRB ||
                fields->id == dt_X86_INS_PINSRW ||
                (fields->id == dt_X86_INS_PINSRD && !ft_rex_w(fields)) ||
                (fields->id == dt_X86_INS_PINSRQ && ft_rex_w(fields)));
    case FT_PINSRW_MMX_RM16_IMM8:
        return fields->prefix0 == 0 && fields->prefix2 == 0 &&
               fields->id == dt_X86_INS_PINSRW &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_PEXTR_GPR_XMM_IMM8:
        return fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib)) &&
               (fields->id == dt_X86_INS_PEXTRB ||
                (fields->id == dt_X86_INS_PEXTRD && !ft_rex_w(fields)) ||
                (fields->id == dt_X86_INS_PEXTRQ && ft_rex_w(fields)));
    case FT_MOVQ_MMX_RM64:
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_MOVD_MMX_RM32:
    case FT_MOVD_RM32_MMX:
        return !ft_rex_w(fields) && fields->prefix0 == 0 &&
               fields->prefix2 == 0 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib));
    case FT_MOVQ_MMX_RM64_GPR:
        return ft_rex_w(fields) && fields->prefix0 == 0 &&
               fields->prefix2 == 0 &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_MOVQ_MMXM64_MMX:
        return (fields->id == dt_X86_INS_MOVQ ||
                (fields->id == dt_X86_INS_MOVNTQ &&
                 fields->modrm_mod != 3)) &&
               (ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_CVTPI2PD_XMM_MMX:
        return !ft_rex_w(fields) &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_CVTSI2SS_XMM_RM:
    case FT_CVTSI2SD_XMM_RM:
    case FT_CVTTSS2SI_GPR_XMMM:
    case FT_CVTSS2SI_GPR_XMMM:
    case FT_CVTTSD2SI_GPR_XMMM:
    case FT_CVTSD2SI_GPR_XMMM:
    case FT_CVT_FP_XMM_XMMM:
    case FT_CVT_FP2I_XMM_XMMM:
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_CVTPI2PS_XMM_MMX:
    case FT_CVT_FP2I_MMX_XMMM:
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PEXTRQ_R64_XMM_IMM8:
        return ft_rex_w(fields) &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_PEXTRW_SSE41_RM16_XMM_IMM8:
        return fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
               fields->id == dt_X86_INS_PEXTRW &&
               (fields->modrm_mod == 3 ||
                ft_supported_base_disp_or_rip_addr(fields->rex,
                                                   fields->modrm,
                                                   fields->sib) ||
                ft_supported_lea_addr(fields->rex, fields->modrm,
                                      fields->sib));
    case FT_AND_R64_IMM8:
        return fields->modrm_mod == 3;
    case FT_CMP_RM64_R64:
    case FT_CMP_RM32_R32:
    case FT_CMP_R64_RM64:
    case FT_CMP_R32_RM32:
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return true;
    case FT_TEST_RM32_R32:
    case FT_TEST_RM32_IMM32:
    case FT_TEST_RM16_R16:
        return true;
    case FT_NEG_RM16:
    case FT_NEG_RM8:
    case FT_NEG_RM32:
    case FT_NEG_RM64:
        if (((fields->kind == FT_NEG_RM64) != ft_rex_w(fields)) ||
            fields->modrm_reg != 3) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_MOVSXD_R64_RM32:
    case FT_MOVSXD_R32_RM32:
    case FT_MOVSXD_R16_RM16:
        return true;
    case FT_MOVZX_R32_RM16:
    case FT_MOVZX_R16_RM8:
    case FT_MOVZX_R32_RM8:
        if (fields->kind == FT_MOVZX_R16_RM8 &&
            fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
            return false;
        }
        if (fields->kind != FT_MOVZX_R16_RM8 &&
            fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_PUSH_R16:
        return !ft_rex_w(fields) && fields->reg >= 0 && fields->reg < GPR_NUM;
    case FT_POP_R16:
        return !ft_rex_w(fields) && fields->reg >= 0 &&
               fields->reg < GPR_NUM
#ifndef QUICKTRANS_LATU
               && fields->reg != rsp_index
#endif
               ;
    case FT_INC_RM32:
    case FT_INC_RM16:
        return !ft_rex_w(fields) && fields->modrm_reg == 0;
    case FT_INC_RM64:
        return ft_rex_w(fields) && fields->modrm_reg == 0;
    case FT_DEC_RM32:
    case FT_DEC_RM16:
        return !ft_rex_w(fields) && fields->modrm_reg == 1;
    case FT_DEC_RM64:
        return ft_rex_w(fields) && fields->modrm_reg == 1;
    case FT_NOT_RM64:
    case FT_NOT_RM32:
    case FT_NOT_RM16:
    case FT_NOT_RM8:
        if (((fields->kind == FT_NOT_RM64) != ft_rex_w(fields)) ||
            ((fields->kind != FT_NOT_RM64) && ft_rex_w(fields)) ||
            fields->modrm_reg != 2) {
            return false;
        }
        if (fields->segment >= 0) {
            return true;
        }
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm, fields->sib);
    case FT_XCHG_RM64_R64:
        if (!ft_rex_w(fields)) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_XCHG_RM32_R32:
        if (ft_rex_w(fields)) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_XCHG_RM8_R8:
        if (ft_rex_w(fields)) {
            return false;
        }
        if (fields->modrm_mod == 3) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_XCHG_R64_RAX:
        return ft_rex_w(fields) &&
               ft_rex_base_from_opcode(fields->rex, fields->opcode0) > 0;
    case FT_XCHG_R32_EAX:
        return !ft_rex_w(fields) &&
               ft_rex_base_from_opcode(fields->rex, fields->opcode0) > 0;
    case FT_XCHG_R16_AX:
        return !ft_rex_w(fields) &&
               ft_rex_base_from_opcode(fields->rex, fields->opcode0) > 0;
    case FT_SBB_RM32_R32:
        return !ft_rex_w(fields) && fields->modrm_mod == 3;
    case FT_ADD_R32_IMM8:
        return fields->modrm_mod == 3 && fields->imm >= 0;
    case FT_AND_R32_IMM8:
        return fields->modrm_mod == 3;
    case FT_SUB_R32_IMM8:
        return fields->modrm_mod == 3;
    case FT_CMP_AL_IMM8:
        return ft_fits_simm12(fields->imm);
    case FT_AND_AX_IMM16:
    case FT_AND_EAX_IMM32:
        return true;
    case FT_AND_RAX_IMM32:
        return ft_rex_w(fields);
    case FT_OR_AX_IMM16:
    case FT_OR_EAX_IMM32:
    case FT_XOR_AX_IMM16:
    case FT_XOR_EAX_IMM32:
        return true;
    case FT_OR_RAX_IMM32:
        return ft_rex_w(fields);
    case FT_XOR_RAX_IMM32:
        return true;
    case FT_CMP_AX_IMM16:
    case FT_CMP_EAX_IMM32:
    case FT_CMP_RAX_IMM32:
        return true;
    case FT_CMP_RM8_IMM8:
        if (fields->rex < 0 && fields->modrm_mod == 3 &&
            fields->modrm_rm >= 4) {
            return false;
        }
        if (!ft_fits_simm12(fields->imm)) {
            return false;
        }
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm, fields->sib);
    case FT_MOV_RM8_R8:
    case FT_INC_RM8:
    case FT_DEC_RM8:
    case FT_ADD_RM8_R8:
    case FT_ADC_RM8_R8:
    case FT_CMP_RM8_R8:
    case FT_CMP_R8_RM8:
        if (fields->rex < 0 && fields->modrm_reg >= 4 &&
            fields->kind != FT_MOV_RM8_R8 &&
            fields->kind != FT_CMP_R8_RM8) {
            return false;
        }
        if (fields->kind != FT_MOV_RM8_R8 &&
            fields->kind != FT_INC_RM8 &&
            fields->kind != FT_DEC_RM8 &&
            fields->kind != FT_CMP_R8_RM8 &&
            fields->rex < 0 && fields->modrm_mod == 3 &&
            fields->modrm_rm >= 4) {
            return false;
        }
        if (fields->segment >= 0) {
            return true;
        }
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm, fields->sib);
    case FT_TEST_RM8_R8:
    case FT_OR_RM8_R8:
    case FT_AND_RM8_R8:
    case FT_XOR_RM8_R8:
    case FT_XOR_R8_RM8:
    case FT_ADD_R8_RM8:
    case FT_ADC_R8_RM8:
    case FT_AND_R8_RM8:
    case FT_MOV_R8_RM8:
        if (fields->segment >= 0) {
            return true;
        }
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm, fields->sib);
    case FT_OR_RM8_IMM8:
    case FT_AND_RM8_IMM8:
        if (fields->imm < 0 || fields->imm > 0xff ||
            fields->modrm_reg !=
                (fields->kind == FT_OR_RM8_IMM8 ? 1 : 4)) {
            return false;
        }
        if (fields->segment >= 0) {
            return true;
        }
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_supported_lea_addr(fields->rex, fields->modrm, fields->sib);
    case FT_MOV_RM8_IMM8:
        if (fields->imm < 0 || fields->imm > 0xff) {
            return false;
        }
        if (fields->rex < 0 && fields->modrm_mod == 3 &&
            fields->modrm_rm >= 4) {
            return false;
        }
        if (fields->segment >= 0) {
            return true;
        }
        return fields->modrm_mod == 3 ||
               ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    case FT_TEST_RM8_IMM8:
        if (fields->imm < 0 || fields->imm > 0xff) {
            return false;
        }
        if (fields->segment >= 0) {
            return true;
        }
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_supported_lea_addr(fields->rex, fields->modrm, fields->sib);
    case FT_ADD_RM32_R32:
    case FT_MOV_RM32_R32:
    case FT_MOV_RM32_IMM32:
    case FT_GRP1_RM32_IMM32:
    case FT_GRP1_RM64_IMM32:
    case FT_GRP1_RM64_IMM8:
    case FT_GRP1_RM32_IMM8:
    case FT_GRP1_RM16_IMM8:
    case FT_GRP1_RM8_IMM8:
        if ((fields->kind == FT_GRP1_RM64_IMM8 ||
             fields->kind == FT_GRP1_RM64_IMM32) && !ft_rex_w(fields)) {
            return false;
        }
        if ((fields->kind == FT_GRP1_RM32_IMM8 ||
             fields->kind == FT_GRP1_RM16_IMM8) && ft_rex_w(fields)) {
            return false;
        }
        if ((fields->kind == FT_GRP1_RM64_IMM8 ||
             fields->kind == FT_GRP1_RM32_IMM8 ||
             fields->kind == FT_GRP1_RM16_IMM8 ||
             fields->kind == FT_GRP1_RM8_IMM8) &&
            !ft_grp1_ext_supported(fields->modrm_reg)) {
            return false;
        }
        if ((fields->kind == FT_GRP1_RM64_IMM8 ||
             fields->kind == FT_GRP1_RM32_IMM8 ||
             fields->kind == FT_GRP1_RM16_IMM8 ||
             fields->kind == FT_GRP1_RM8_IMM8) &&
            fields->segment >= 0) {
            return true;
        }
        if (fields->kind == FT_MOV_RM32_IMM32 && fields->segment >= 0) {
            return true;
        }
        if (fields->kind == FT_MOV_RM32_R32) {
            return true;
        }
        if (fields->kind == FT_GRP1_RM32_IMM32 ||
            fields->kind == FT_GRP1_RM64_IMM32) {
            return true;
        }
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex, fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm, fields->sib);
    case FT_PUSH_IMM32:
        return fields->imm >= INT32_MIN && fields->imm <= UINT32_MAX;
    case FT_PUSH_IMM16:
        return fields->imm >= INT16_MIN && fields->imm <= UINT16_MAX;
    case FT_MOV_R64_RM64:
        return true;
    case FT_MOV_RM64_R64:
        return true;
    case FT_MOV_ACC_MOFFS:
        return fields->id == dt_X86_INS_MOV &&
               (fields->opcode0 == 0xa0 || fields->opcode0 == 0xa1) &&
               (fields->alu_width == 8 || fields->alu_width == 16 ||
                fields->alu_width == 32 || fields->alu_width == 64);
    case FT_MOV_MOFFS_ACC:
        return fields->id == dt_X86_INS_MOV &&
               (fields->opcode0 == 0xa2 || fields->opcode0 == 0xa3) &&
               (fields->alu_width == 8 || fields->alu_width == 16 ||
                fields->alu_width == 32 || fields->alu_width == 64);
    case FT_LEA_R64_M:
    case FT_LEA_R32_M:
    case FT_LEA_R16_M:
        return fields->modrm_mod != 3;
    case FT_X87_FXCH:
        return fields->id == dt_X86_INS_FXCH &&
               fields->modrm >= 0xc8 && fields->modrm <= 0xcf;
    case FT_X87_BIN_REG:
        return (fields->opcode0 == 0xd8 || fields->opcode0 == 0xdc) &&
               fields->modrm >= 0xc0 &&
               (fields->id == dt_X86_INS_FADD ||
                fields->id == dt_X86_INS_FMUL ||
                fields->id == dt_X86_INS_FSUB ||
                fields->id == dt_X86_INS_FSUBR ||
                fields->id == dt_X86_INS_FDIV ||
                fields->id == dt_X86_INS_FDIVR);
    case FT_X87_FCOM_REG:
    case FT_X87_FCOMP_REG:
    case FT_X87_FCOMI_REG:
    case FT_X87_FCOMIP_REG:
        return fields->modrm_rm <= 7;
    case FT_X87_FCMOVCC:
        return fields->modrm_rm <= 7;
    case FT_X87_FADDP:
        return fields->id == dt_X86_INS_FADDP &&
               fields->modrm >= 0xc0 && fields->modrm <= 0xc7;
    case FT_X87_FMULP:
        return fields->id == dt_X86_INS_FMULP &&
               fields->modrm >= 0xc8 && fields->modrm <= 0xcf;
    case FT_X87_FSUBRP:
        return fields->id == dt_X86_INS_FSUBR &&
               fields->modrm >= 0xe0 && fields->modrm <= 0xe7;
    case FT_X87_FSUBP:
        return fields->id == dt_X86_INS_FSUBP &&
               fields->modrm >= 0xe8 && fields->modrm <= 0xef;
    case FT_X87_FDIVRP:
        return fields->id == dt_X86_INS_FDIVR &&
               fields->modrm >= 0xf0 && fields->modrm <= 0xf7;
    case FT_X87_FDIVP:
        return fields->id == dt_X86_INS_FDIVP &&
               fields->modrm >= 0xf8 && fields->modrm <= 0xff;
    case FT_X87_F2XM1:
    case FT_X87_FRNDINT:
    case FT_X87_FSCALE:
    case FT_X87_FSIN:
    case FT_X87_FCOS:
    case FT_X87_FSINCOS:
    case FT_X87_FPTAN:
    case FT_X87_FPATAN:
    case FT_X87_FPREM:
    case FT_X87_FPREM1:
    case FT_X87_FYL2X:
    case FT_X87_FYL2XP1:
    case FT_X87_FXAM:
    case FT_X87_FXTRACT:
        return true;
    case FT_X87_FUCOMPP:
        return fields->id == dt_X86_INS_FUCOMPP &&
               fields->modrm == 0xe9;
    case FT_X87_FLD_REG:
        return fields->id == dt_X86_INS_FLD &&
               fields->modrm >= 0xc0 && fields->modrm <= 0xc7;
    case FT_X87_FSTP_REG:
        return (fields->id == dt_X86_INS_FSTP ||
                fields->id == dt_X86_INS_FSTPNCE) &&
               fields->modrm >= 0xd8 && fields->modrm <= 0xdf;
    case FT_X87_FST_REG:
        return fields->id == dt_X86_INS_FST &&
               fields->modrm >= 0xd0 && fields->modrm <= 0xd7;
    case FT_X87_FI_BIN_M16:
    case FT_X87_FI_BIN_M32:
    case FT_X87_FILD_M16:
    case FT_X87_FILD_M32:
    case FT_X87_FILD_M64:
    case FT_X87_FLD_M80:
    case FT_X87_FIST_M16:
    case FT_X87_FISTP_M16:
    case FT_X87_FISTP_M32:
    case FT_X87_FISTP_M64:
    case FT_X87_FISTTP_M16:
    case FT_X87_FISTTP_M32:
    case FT_X87_FISTTP_M64:
    case FT_X87_FSTP_M80:
    case FT_X87_FBLD:
    case FT_X87_FBSTP:
        return fields->modrm_mod != 3;
    case FT_MOV_R32_RM32:
        return true;
    case FT_MOV_R16_RM16:
        if (ft_rex_w(fields)) {
            return false;
        }
        if (fields->segment >= 0) {
            return true;
        }
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_fits_simm12(fields->disp);
    case FT_MOV_RM16_R16:
        if (fields->modrm_mod == 3 ||
            (fields->modrm_mod == 0 && fields->modrm_rm == 5)) {
            return true;
        }
        return ft_supported_base_disp_or_rip_addr(fields->rex,
                                                  fields->modrm,
                                                  fields->sib) ||
               ft_supported_lea_addr(fields->rex, fields->modrm,
                                     fields->sib);
    default:
        return false;
    }
}
