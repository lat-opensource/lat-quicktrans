/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Fast decoder info to FastTemplateFields conversion. */

#ifndef FAST_TEMPLATE_SKIP_FIELD_FILL
static int ft_ir1_modrm_offset(const struct la_dt_insn *info)
{
    int offset = 0;

    while (offset < info->size) {
        switch (info->bytes[offset]) {
        case 0xf0:
        case 0xf2:
        case 0xf3:
        case 0x2e:
        case 0x3e:
        case 0x26:
        case 0x36:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x67:
            offset++;
            continue;
        default:
            break;
        }
        break;
    }
    if (offset < info->size && info->bytes[offset] >= 0x40 &&
        info->bytes[offset] <= 0x4f) {
        offset++;
    }
    if (offset >= info->size) {
        return -1;
    }
    if (info->bytes[offset] == 0x0f) {
        offset++;
        if (offset < info->size &&
            (info->bytes[offset] == 0x38 || info->bytes[offset] == 0x3a)) {
            offset++;
        }
    }
    offset++;
    return offset < info->size ? offset : -1;
}

static int ft_ir1_sib_byte(const struct la_dt_insn *info)
{
    const dt_x86_op_mem *mem = NULL;
    int i;

    if ((info->x86.modrm & 7) != 4 || ft_modrm_mod(info->x86.modrm) == 3) {
        return 0;
    }
    for (i = 0; i < info->x86.op_count; i++) {
        if (info->x86.operands[i].type == dt_X86_OP_MEM) {
            mem = &info->x86.operands[i].mem;
            break;
        }
    }
    if (mem) {
        int base = ft_x86_gpr_index(mem->base);
        int index = ft_x86_gpr_index(mem->index);
        int scale = ft_sib_scale_bits(mem->scale ? mem->scale : 1);
        int sib_base;
        int sib_index;

        if (scale < 0) {
            return 0;
        }
        sib_base = base >= 0 ? (base & 7) : 5;
        sib_index = index >= 0 ? (index & 7) : 4;
        return (scale << 6) | (sib_index << 3) | sib_base;
    }
    {
        int modrm_offset = ft_ir1_modrm_offset(info);

        if (modrm_offset < 0 || info->size <= modrm_offset + 1) {
            return 0;
        }
        return info->bytes[modrm_offset + 1];
    }
}

static int ft_sib_scale_bits(int scale)
{
    switch (scale) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
        return 2;
    case 8:
        return 3;
    default:
        return -1;
    }
}

static bool ft_fill_mem_fields_from_ir1(FastTemplateFields *fields,
                                        const struct la_dt_insn *info)
{
    const dt_x86_op_mem *mem = NULL;
    int i;

    if (fields->modrm_mod == 3) {
        return true;
    }
    for (i = 0; i < info->x86.op_count; i++) {
        if (info->x86.operands[i].type == dt_X86_OP_MEM) {
            mem = &info->x86.operands[i].mem;
            break;
        }
    }
    if (!mem) {
        return true;
    }

    fields->disp = mem->disp;
    if (fields->modrm_rm == 4) {
        int base = ft_x86_gpr_index(mem->base);
        int index = ft_x86_gpr_index(mem->index);
        int scale = ft_sib_scale_bits(mem->scale ? mem->scale : 1);
        int sib_base;
        int sib_index;

        if (scale < 0) {
            return false;
        }
        sib_base = base >= 0 ? (base & 7) : 5;
        sib_index = index >= 0 ? (index & 7) : 4;
        fields->sib = (scale << 6) | (sib_index << 3) | sib_base;
    }
    return true;
}
#endif

static bool ft_jcc_opcode_info(uint8_t cc, int *cond, int *id)
{
    static const int cond_by_cc[16] = {
        COND_O, COND_NO, COND_B, COND_AE,
        COND_E, COND_NE, COND_BE, COND_A,
        COND_S, COND_NS, COND_PE, COND_PO,
        COND_L, COND_GE, COND_LE, COND_G,
    };
    static const int id_by_cc[16] = {
        dt_X86_INS_JO, dt_X86_INS_JNO, dt_X86_INS_JB, dt_X86_INS_JAE,
        dt_X86_INS_JE, dt_X86_INS_JNE, dt_X86_INS_JBE, dt_X86_INS_JA,
        dt_X86_INS_JS, dt_X86_INS_JNS, dt_X86_INS_JP, dt_X86_INS_JNP,
        dt_X86_INS_JL, dt_X86_INS_JGE, dt_X86_INS_JLE, dt_X86_INS_JG,
    };

    if (cc >= 16) {
        return false;
    }
    *cond = cond_by_cc[cc];
    *id = id_by_cc[cc];
    return true;
}

static bool ft_cmov_opcode_info(uint8_t opcode, int *cond, int *id)
{
    static const int id_by_cc[16] = {
        dt_X86_INS_CMOVO, dt_X86_INS_CMOVNO,
        dt_X86_INS_CMOVB, dt_X86_INS_CMOVAE,
        dt_X86_INS_CMOVE, dt_X86_INS_CMOVNE,
        dt_X86_INS_CMOVBE, dt_X86_INS_CMOVA,
        dt_X86_INS_CMOVS, dt_X86_INS_CMOVNS,
        dt_X86_INS_CMOVP, dt_X86_INS_CMOVNP,
        dt_X86_INS_CMOVL, dt_X86_INS_CMOVGE,
        dt_X86_INS_CMOVLE, dt_X86_INS_CMOVG,
    };

    if (opcode < 0x40 || opcode > 0x4f) {
        return false;
    }
    return ft_jcc_opcode_info(opcode & 0xf, cond, id) &&
           (*id = id_by_cc[opcode & 0xf], true);
}

static bool ft_setcc_opcode_info(uint8_t opcode, int *cond, int *id)
{
    static const int id_by_cc[16] = {
        dt_X86_INS_SETO, dt_X86_INS_SETNO,
        dt_X86_INS_SETB, dt_X86_INS_SETAE,
        dt_X86_INS_SETE, dt_X86_INS_SETNE,
        dt_X86_INS_SETBE, dt_X86_INS_SETA,
        dt_X86_INS_SETS, dt_X86_INS_SETNS,
        dt_X86_INS_SETP, dt_X86_INS_SETNP,
        dt_X86_INS_SETL, dt_X86_INS_SETGE,
        dt_X86_INS_SETLE, dt_X86_INS_SETG,
    };

    if (opcode < 0x90 || opcode > 0x9f) {
        return false;
    }
    return ft_jcc_opcode_info(opcode & 0xf, cond, id) &&
           (*id = id_by_cc[opcode & 0xf], true);
}

static inline int ft_rex_base_from_opcode(int rex, int opcode)
{
    return (opcode & 7) | (rex >= 0 ? (rex & 1) << 3 : 0);
}

static inline bool ft_fits_simm12(int64_t value)
{
    return value >= -2048 && value <= 2047;
}

static inline bool ft_grp1_ext_supported(int ext)
{
    return ext >= 0 && ext <= 7;
}

static bool ft_punpck_opcode_info(uint8_t prefix2, uint8_t opcode,
                                  uint32_t *la_opcode, int *id)
{
    switch (opcode) {
    case 0x14:
        if (prefix2 != 0) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VILVL_W;
        *id = dt_X86_INS_UNPCKLPS;
        return true;
    case 0x15:
        if (prefix2 != 0) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VILVH_W;
        *id = dt_X86_INS_UNPCKHPS;
        return true;
    case 0x60:
        *la_opcode = FT_LA_OPCODE_VILVL_B;
        *id = dt_X86_INS_PUNPCKLBW;
        return true;
    case 0x61:
        *la_opcode = FT_LA_OPCODE_VILVL_H;
        *id = dt_X86_INS_PUNPCKLWD;
        return true;
    case 0x62:
        *la_opcode = FT_LA_OPCODE_VILVL_W;
        *id = dt_X86_INS_PUNPCKLDQ;
        return true;
    case 0x6c:
        *la_opcode = FT_LA_OPCODE_VILVL_D;
        *id = dt_X86_INS_PUNPCKLQDQ;
        return true;
    case 0x68:
        *la_opcode = FT_LA_OPCODE_VILVH_B;
        *id = dt_X86_INS_PUNPCKHBW;
        return true;
    case 0x69:
        *la_opcode = FT_LA_OPCODE_VILVH_H;
        *id = dt_X86_INS_PUNPCKHWD;
        return true;
    case 0x6a:
        *la_opcode = FT_LA_OPCODE_VILVH_W;
        *id = dt_X86_INS_PUNPCKHDQ;
        return true;
    case 0x6d:
        *la_opcode = FT_LA_OPCODE_VILVH_D;
        *id = dt_X86_INS_PUNPCKHQDQ;
        return true;
    default:
        return false;
    }
}

static bool ft_padd_opcode_info(uint8_t opcode, uint32_t *la_opcode, int *id)
{
    switch (opcode) {
    case 0xfc:
        *la_opcode = FT_LA_OPCODE_VADD_B;
        *id = dt_X86_INS_PADDB;
        return true;
    case 0xfd:
        *la_opcode = FT_LA_OPCODE_VADD_H;
        *id = dt_X86_INS_PADDW;
        return true;
    case 0xfe:
        *la_opcode = FT_LA_OPCODE_VADD_W;
        *id = dt_X86_INS_PADDD;
        return true;
    case 0xd4:
        *la_opcode = FT_LA_OPCODE_VADD_D;
        *id = dt_X86_INS_PADDQ;
        return true;
    default:
        return false;
    }
}

static bool ft_pcmpeq_opcode_info(uint8_t opcode, uint32_t *la_opcode, int *id)
{
    switch (opcode) {
    case 0x74:
        *la_opcode = FT_LA_OPCODE_VSEQ_B;
        *id = dt_X86_INS_PCMPEQB;
        return true;
    case 0x75:
        *la_opcode = FT_LA_OPCODE_VSEQ_H;
        *id = dt_X86_INS_PCMPEQW;
        return true;
    case 0x76:
        *la_opcode = FT_LA_OPCODE_VSEQ_W;
        *id = dt_X86_INS_PCMPEQD;
        return true;
    case 0x29:
        *la_opcode = FT_LA_OPCODE_VSEQ_D;
        *id = dt_X86_INS_PCMPEQQ;
        return true;
    default:
        return false;
    }
}

static bool ft_simd_bin_opcode_info(uint8_t prefix0, uint8_t prefix2,
                                    uint8_t opcode,
                                    uint32_t *la_opcode, int *id,
                                    bool *reverse_operands)
{
    bool is_double = prefix2 == 0x66;

    *reverse_operands = false;
    switch (opcode) {
    case 0x51:
        if (prefix0 != 0) {
            return false;
        }
        *la_opcode = is_double ? FT_LA_OPCODE_VFSQRT_D :
                                 FT_LA_OPCODE_VFSQRT_S;
        *id = is_double ? dt_X86_INS_SQRTPD : dt_X86_INS_SQRTPS;
        return true;
    case 0x52:
        if (prefix0 != 0 || is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VFRSQRT_S;
        *id = dt_X86_INS_RSQRTPS;
        return true;
    case 0x53:
        if (prefix0 != 0 || is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VFRECIP_S;
        *id = dt_X86_INS_RCPPS;
        return true;
    case 0x58:
        *la_opcode = is_double ? FT_LA_OPCODE_VFADD_D :
                                 FT_LA_OPCODE_VFADD_S;
        *id = is_double ? dt_X86_INS_ADDPD : dt_X86_INS_ADDPS;
        return true;
    case 0x59:
        *la_opcode = is_double ? FT_LA_OPCODE_VFMUL_D :
                                 FT_LA_OPCODE_VFMUL_S;
        *id = is_double ? dt_X86_INS_MULPD : dt_X86_INS_MULPS;
        return true;
    case 0x5c:
        *la_opcode = is_double ? FT_LA_OPCODE_VFSUB_D :
                                 FT_LA_OPCODE_VFSUB_S;
        *id = is_double ? dt_X86_INS_SUBPD : dt_X86_INS_SUBPS;
        return true;
    case 0x5d:
        *la_opcode = is_double ? FT_LA_OPCODE_VFMIN_D :
                                 FT_LA_OPCODE_VFMIN_S;
        *id = is_double ? dt_X86_INS_MINPD : dt_X86_INS_MINPS;
        return true;
    case 0x5e:
        *la_opcode = is_double ? FT_LA_OPCODE_VFDIV_D :
                                 FT_LA_OPCODE_VFDIV_S;
        *id = is_double ? dt_X86_INS_DIVPD : dt_X86_INS_DIVPS;
        return true;
    case 0x5f:
        *la_opcode = is_double ? FT_LA_OPCODE_VFMAX_D :
                                 FT_LA_OPCODE_VFMAX_S;
        *id = is_double ? dt_X86_INS_MAXPD : dt_X86_INS_MAXPS;
        return true;
    case 0x54:
        *la_opcode = FT_LA_OPCODE_VAND_V;
        *id = is_double ? dt_X86_INS_ANDPD : dt_X86_INS_ANDPS;
        return true;
    case 0x55:
        *la_opcode = FT_LA_OPCODE_VANDN_V;
        *id = is_double ? dt_X86_INS_ANDNPD : dt_X86_INS_ANDNPS;
        return true;
    case 0x56:
        *la_opcode = FT_LA_OPCODE_VOR_V;
        *id = is_double ? dt_X86_INS_ORPD : dt_X86_INS_ORPS;
        return true;
    case 0x57:
        *la_opcode = FT_LA_OPCODE_VXOR_V;
        *id = is_double ? dt_X86_INS_XORPD : dt_X86_INS_XORPS;
        return true;
    case 0x66:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSLT_W;
        *id = dt_X86_INS_PCMPGTD;
        *reverse_operands = true;
        return true;
    case 0x64:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSLT_B;
        *id = dt_X86_INS_PCMPGTB;
        *reverse_operands = true;
        return true;
    case 0x65:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSLT_H;
        *id = dt_X86_INS_PCMPGTW;
        *reverse_operands = true;
        return true;
    case 0x37:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSLT_D;
        *id = dt_X86_INS_PCMPGTQ;
        *reverse_operands = true;
        return true;
    case 0xd0:
        if (prefix2 == 0x66) {
            *la_opcode = FT_LA_OPCODE_VFADDSUB_D;
            *id = dt_X86_INS_ADDSUBPD;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REPNE) {
            *la_opcode = FT_LA_OPCODE_VFADDSUB_S;
            *id = dt_X86_INS_ADDSUBPS;
            return true;
        }
        return false;
    case 0x1c:
        if (!is_double) {
            return false;
        }
#ifdef QUICKTRANS_LATU
        *la_opcode = FT_LA_OPCODE_VSIGNCOV_B;
#else
        *la_opcode = FT_LA_OPCODE_VABSD_B;
#endif
        *id = dt_X86_INS_PABSB;
        return true;
    case 0x1d:
        if (!is_double) {
            return false;
        }
#ifdef QUICKTRANS_LATU
        *la_opcode = FT_LA_OPCODE_VSIGNCOV_H;
#else
        *la_opcode = FT_LA_OPCODE_VABSD_H;
#endif
        *id = dt_X86_INS_PABSW;
        return true;
    case 0x1e:
        if (!is_double) {
            return false;
        }
#ifdef QUICKTRANS_LATU
        *la_opcode = FT_LA_OPCODE_VSIGNCOV_W;
#else
        *la_opcode = FT_LA_OPCODE_VABSD_W;
#endif
        *id = dt_X86_INS_PABSD;
        return true;
    case 0x08:
        if (prefix0 != 0 || !is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSIGNCOV_B;
        *id = dt_X86_INS_PSIGNB;
        *reverse_operands = true;
        return true;
    case 0x09:
        if (prefix0 != 0 || !is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSIGNCOV_H;
        *id = dt_X86_INS_PSIGNW;
        *reverse_operands = true;
        return true;
    case 0x0a:
        if (prefix0 != 0 || !is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSIGNCOV_W;
        *id = dt_X86_INS_PSIGND;
        *reverse_operands = true;
        return true;
    case 0xd1:
        if (prefix0 == 0 && prefix2 == 0) {
            *la_opcode = FT_LA_OPCODE_VSRL_H;
            *id = dt_X86_INS_PSRLW;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSRL_H;
        *id = dt_X86_INS_PSRLW;
        return true;
    case 0xd2:
        if (prefix0 == 0 && prefix2 == 0) {
            *la_opcode = FT_LA_OPCODE_VSRL_W;
            *id = dt_X86_INS_PSRLD;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSRL_W;
        *id = dt_X86_INS_PSRLD;
        return true;
    case 0xd3:
        if (prefix0 == 0 && prefix2 == 0) {
            *la_opcode = FT_LA_OPCODE_VSRL_D;
            *id = dt_X86_INS_PSRLQ;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSRL_D;
        *id = dt_X86_INS_PSRLQ;
        return true;
    case 0xe1:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSRA_H;
        *id = dt_X86_INS_PSRAW;
        return true;
    case 0xe2:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSRA_W;
        *id = dt_X86_INS_PSRAD;
        return true;
    case 0xf1:
        if (prefix0 == 0 && prefix2 == 0) {
            *la_opcode = FT_LA_OPCODE_VSLL_H;
            *id = dt_X86_INS_PSLLW;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSLL_H;
        *id = dt_X86_INS_PSLLW;
        return true;
    case 0xf2:
        if (prefix0 == 0 && prefix2 == 0) {
            *la_opcode = FT_LA_OPCODE_VSLL_W;
            *id = dt_X86_INS_PSLLD;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSLL_W;
        *id = dt_X86_INS_PSLLD;
        return true;
    case 0xf3:
        if (prefix0 == 0 && prefix2 == 0) {
            *la_opcode = FT_LA_OPCODE_VSLL_D;
            *id = dt_X86_INS_PSLLQ;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSLL_D;
        *id = dt_X86_INS_PSLLQ;
        return true;
    case 0xda:
        if (prefix0 == 0 && prefix2 == 0) {
            *la_opcode = FT_LA_OPCODE_VMIN_BU;
            *id = dt_X86_INS_PMINUB;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMIN_BU;
        *id = dt_X86_INS_PMINUB;
        return true;
    case 0xd9:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSSUB_HU;
        *id = dt_X86_INS_PSUBUSW;
        return true;
    case 0xd8:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSSUB_BU;
        *id = dt_X86_INS_PSUBUSB;
        return true;
    case 0xf8:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSUB_B;
        *id = dt_X86_INS_PSUBB;
        return true;
    case 0xf9:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSUB_H;
        *id = dt_X86_INS_PSUBW;
        return true;
    case 0xfa:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSUB_W;
        *id = dt_X86_INS_PSUBD;
        return true;
    case 0xfb:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSUB_D;
        *id = dt_X86_INS_PSUBQ;
        return true;
    case 0xe8:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSSUB_B;
        *id = dt_X86_INS_PSUBSB;
        return true;
    case 0xe9:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSSUB_H;
        *id = dt_X86_INS_PSUBSW;
        return true;
    case 0xec:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSADD_B;
        *id = dt_X86_INS_PADDSB;
        return true;
    case 0xed:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSADD_H;
        *id = dt_X86_INS_PADDSW;
        return true;
    case 0xdc:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSADD_BU;
        *id = dt_X86_INS_PADDUSB;
        return true;
    case 0xdd:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VSADD_HU;
        *id = dt_X86_INS_PADDUSW;
        return true;
    case 0xdb:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VAND_V;
        *id = dt_X86_INS_PAND;
        return true;
    case 0xdf:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VANDN_V;
        *id = dt_X86_INS_PANDN;
        return true;
    case 0xeb:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VOR_V;
        *id = dt_X86_INS_POR;
        return true;
    case 0xe0:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VAVGR_BU;
        *id = dt_X86_INS_PAVGB;
        return true;
    case 0xe3:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VAVGR_HU;
        *id = dt_X86_INS_PAVGW;
        return true;
    case 0xd5:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMUL_H;
        *id = dt_X86_INS_PMULLW;
        return true;
    case 0xe5:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMUH_H;
        *id = dt_X86_INS_PMULHW;
        return true;
    case 0xe4:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMUH_HU;
        *id = dt_X86_INS_PMULHUW;
        return true;
    case 0x40:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMUL_W;
        *id = dt_X86_INS_PMULLD;
        return true;
    case 0x28:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMULWEV_D_W;
        *id = dt_X86_INS_PMULDQ;
        return true;
    case 0xde:
        if (prefix0 == 0 && prefix2 == 0) {
            *la_opcode = FT_LA_OPCODE_VMAX_BU;
            *id = dt_X86_INS_PMAXUB;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMAX_BU;
        *id = dt_X86_INS_PMAXUB;
        return true;
    case 0xee:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMAX_H;
        *id = dt_X86_INS_PMAXSW;
        return true;
    case 0xea:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMIN_H;
        *id = dt_X86_INS_PMINSW;
        return true;
    case 0x38:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMIN_B;
        *id = dt_X86_INS_PMINSB;
        return true;
    case 0x39:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMIN_W;
        *id = dt_X86_INS_PMINSD;
        return true;
    case 0x3a:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMIN_HU;
        *id = dt_X86_INS_PMINUW;
        return true;
    case 0x3b:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMIN_WU;
        *id = dt_X86_INS_PMINUD;
        return true;
    case 0x3c:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMAX_B;
        *id = dt_X86_INS_PMAXSB;
        return true;
    case 0x3d:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMAX_W;
        *id = dt_X86_INS_PMAXSD;
        return true;
    case 0x3e:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMAX_HU;
        *id = dt_X86_INS_PMAXUW;
        return true;
    case 0x3f:
        if (!is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_VMAX_WU;
        *id = dt_X86_INS_PMAXUD;
        return true;
    default:
        return false;
    }
}

static bool ft_simd_scalar_bin_opcode_info(uint8_t prefix, uint8_t opcode,
                                           uint32_t *la_opcode, int *id)
{
    bool is_double = prefix == dt_X86_PREFIX_REPNE;

    if (prefix != dt_X86_PREFIX_REPNE && prefix != dt_X86_PREFIX_REP) {
        return false;
    }
    switch (opcode) {
    case 0x51:
        *la_opcode = is_double ? FT_LA_OPCODE_FSQRT_D : FT_LA_OPCODE_FSQRT_S;
        *id = is_double ? dt_X86_INS_SQRTSD : dt_X86_INS_SQRTSS;
        return true;
    case 0x52:
        if (is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_FRSQRT_S;
        *id = dt_X86_INS_RSQRTSS;
        return true;
    case 0x53:
        if (is_double) {
            return false;
        }
        *la_opcode = FT_LA_OPCODE_FRECIP_S;
        *id = dt_X86_INS_RCPSS;
        return true;
    case 0x58:
        *la_opcode = is_double ? FT_LA_OPCODE_FADD_D : FT_LA_OPCODE_FADD_S;
        *id = is_double ? dt_X86_INS_ADDSD : dt_X86_INS_ADDSS;
        return true;
    case 0x5c:
        *la_opcode = is_double ? FT_LA_OPCODE_FSUB_D : FT_LA_OPCODE_FSUB_S;
        *id = is_double ? dt_X86_INS_SUBSD : dt_X86_INS_SUBSS;
        return true;
    case 0x59:
        *la_opcode = is_double ? FT_LA_OPCODE_FMUL_D : FT_LA_OPCODE_FMUL_S;
        *id = is_double ? dt_X86_INS_MULSD : dt_X86_INS_MULSS;
        return true;
    case 0x5e:
        *la_opcode = is_double ? FT_LA_OPCODE_FDIV_D : FT_LA_OPCODE_FDIV_S;
        *id = is_double ? dt_X86_INS_DIVSD : dt_X86_INS_DIVSS;
        return true;
    case 0x5d:
        *la_opcode = is_double ? FT_LA_OPCODE_FMIN_D : FT_LA_OPCODE_FMIN_S;
        *id = is_double ? dt_X86_INS_MINSD : dt_X86_INS_MINSS;
        return true;
    case 0x5f:
        *la_opcode = is_double ? FT_LA_OPCODE_FMAX_D : FT_LA_OPCODE_FMAX_S;
        *id = is_double ? dt_X86_INS_MAXSD : dt_X86_INS_MAXSS;
        return true;
    default:
        return false;
    }
}

static bool ft_simd_scalar_cmp_opcode_info(uint8_t prefix0, uint8_t prefix2,
                                           uint8_t opcode, bool *is_double,
                                           bool *qnan, int *id)
{
    if (opcode != 0x2f && opcode != 0x2e) {
        return false;
    }
    *qnan = opcode == 0x2f;
    if (prefix2 == 0x66) {
        *is_double = true;
        *id = *qnan ? dt_X86_INS_COMISD : dt_X86_INS_UCOMISD;
        return true;
    }
    if (prefix0 == 0 && prefix2 == 0) {
        *is_double = false;
        *id = *qnan ? dt_X86_INS_COMISS : dt_X86_INS_UCOMISS;
        return true;
    }
    return false;
}

static int ft_simm20_field(uint32_t value)
{
    value &= 0xfffffu;
    return (int32_t)(value << 12) >> 12;
}

static int ft_simm12_field(uint32_t value)
{
    value &= 0xfffu;
    return (int32_t)(value << 20) >> 20;
}

static bool ft_emit_li32(uint32_t **code, int rd, uint32_t value)
{
    if (value <= 0xfff) {
        FT_LA_ORI_EMIT(code, rd, la_zero, value);
        return true;
    }

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if ((int32_t)value >= -2048 && (int32_t)value < 0) {
        FT_LA_ADDI_D_EMIT(code, rd, la_zero, (int32_t)value);
        return true;
    }
#endif
    FT_LA_LU12I_W_EMIT(code, rd, ft_simm20_field(value >> 12));
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (value & 0xfff)
#endif
    FT_LA_ORI_EMIT(code, rd, rd, value & 0xfff);
    return true;
}

static void ft_emit_li32_two(uint32_t **code, int rd, uint32_t value)
{
    FT_LA_LU12I_W_EMIT(code, rd, ft_simm20_field(value >> 12));
    FT_LA_ORI_EMIT(code, rd, rd, value & 0xfff);
}

static void ft_emit_li64(uint32_t **code, int rd, uint64_t value)
{
    uint32_t hi32 = value >> 32;
    uint32_t lo32 = value & 0xffffffffu;
    char sign_bitmap;
    char all0_bitmap;
    char allf_bitmap;
    char sign_extension_by_previous;
    char extension_by_previous_hi;
    char extension_by_previous_lo;

    sign_bitmap = (((hi32 & 0x80000000u) != 0) << 3) |
                  (((hi32 & 0x00080000u) != 0) << 2) |
                  (((lo32 & 0x80000000u) != 0) << 1) |
                  ((lo32 & 0x00000800u) != 0);
    all0_bitmap = (((hi32 & 0xfff00000u) == 0) << 3) |
                  (((hi32 & 0x000fffffu) == 0) << 2) |
                  (((lo32 & 0xfffff000u) == 0) << 1) |
                  ((lo32 & 0x00000fffu) == 0);
    allf_bitmap = (((hi32 & 0xfff00000u) == 0xfff00000u) << 3) |
                  (((hi32 & 0x000fffffu) == 0x000fffffu) << 2) |
                  (((lo32 & 0xfffff000u) == 0xfffff000u) << 1) |
                  ((lo32 & 0x00000fffu) == 0x00000fffu);
    sign_extension_by_previous = (all0_bitmap ^ allf_bitmap) &
                                 (all0_bitmap ^ (sign_bitmap << 1));
    extension_by_previous_lo = sign_extension_by_previous & 0x3;
    extension_by_previous_hi = sign_extension_by_previous >> 2;

    if (sign_extension_by_previous == 0x7) {
        FT_LA_LU52I_D_EMIT(code, rd, la_zero, ft_simm12_field(hi32 >> 20));
        return;
    }

    switch (extension_by_previous_lo) {
    case 0x0:
        if ((all0_bitmap & 0x3) == 0x2) {
            FT_LA_ORI_EMIT(code, rd, la_zero, lo32 & 0xfff);
        } else {
            FT_LA_LU12I_W_EMIT(code, rd, ft_simm20_field(lo32 >> 12));
            FT_LA_ORI_EMIT(code, rd, rd, lo32 & 0xfff);
        }
        break;
    case 0x1:
        FT_LA_LU12I_W_EMIT(code, rd, ft_simm20_field(lo32 >> 12));
        break;
    case 0x2:
        FT_LA_ADDI_W_EMIT(code, rd, la_zero, lo32);
        break;
    case 0x3:
        FT_LA_OR_EMIT(code, rd, la_zero, la_zero);
        break;
    }

    switch (extension_by_previous_hi) {
    case 0x0:
        FT_LA_LU32I_D_EMIT(code, rd, ft_simm20_field(hi32));
        FT_LA_LU52I_D_EMIT(code, rd, rd, ft_simm12_field(hi32 >> 20));
        break;
    case 0x1:
        FT_LA_LU52I_D_EMIT(code, rd, rd, ft_simm12_field(hi32 >> 20));
        break;
    case 0x2:
        FT_LA_LU32I_D_EMIT(code, rd, ft_simm20_field(hi32));
        break;
    case 0x3:
        break;
    }
}

static bool ft_emit_guest_addr(uint32_t **code, int rd, uint64_t value)
{
    if (value <= INT32_MAX) {
        return ft_emit_li32(code, rd, (uint32_t)value);
    }
    ft_emit_li64(code, rd, value);
    return true;
}

#ifndef FAST_TEMPLATE_SKIP_FIELD_FILL
static int16_t ft_read_i16(const uint8_t *code)
{
    return (int16_t)((uint16_t)code[0] | ((uint16_t)code[1] << 8));
}

static int32_t ft_read_i32(const uint8_t *code)
{
    return (int32_t)((uint32_t)code[0] |
                     ((uint32_t)code[1] << 8) |
                     ((uint32_t)code[2] << 16) |
                     ((uint32_t)code[3] << 24));
}

static int ft_read_simm(const uint8_t *code, int size)
{
    switch (size) {
    case 1:
        return (int8_t)code[0];
    case 2:
        return ft_read_i16(code);
    case 4:
        return ft_read_i32(code);
    default:
        return 0;
    }
}

bool fast_template_fill_fields_from_info(const FastTemplateDesc *tmpl,
                                         const struct la_dt_insn *info,
                                         bool flags_live,
                                         FastTemplateFields *fields)
{
    fields->kind = tmpl->kind;
    fields->modrm = info->x86.modrm;
    ft_fields_set_rex(fields, info->x86.rex ? info->x86.rex : -1);
    fields->sib = 0;
    fields->segment = ft_prefix_seg_index(info->x86.prefix[1]);
    fields->disp = 0;
    fields->imm = 0;
    fields->imm64 = 0;
    fields->reg = 0;
    fields->size = info->size;
    fields->address = info->address;
    fields->id = info->id;
    fields->vex_v = info->x86.op_count > 1 &&
                    info->x86.operands[1].type == dt_X86_OP_REG ?
                    ft_x86_xmm_index(info->x86.operands[1].reg) : -1;
    fields->opcode0 = info->x86.opcode[0];
    fields->prefix0 = info->x86.prefix[0];
    fields->prefix2 = info->x86.prefix[2];
    fields->opcode1 = info->x86.opcode[1];
    fields->alu_op = FT_ALU_NONE;
    fields->alu_form = FT_ALU_FORM_NONE;
    fields->alu_width = 0;
    fields->direct_cmp_lhs_gpr = -1;
    fields->direct_cmp_rhs_gpr = -1;
    fields->direct_bit_index_gpr = -1;
    fields->direct_bit_index_imm = -1;
    fields->instptn_div_kind = 0;
    fields->pattern_inputs = 0;
    fields->instptn_skip = false;
    fields->atomic_no_barrier = false;
    fields->direct_float_result = false;
    fields->direct_float_xx = false;
    fields->direct_cmp_width = 0;
    fields->addr32 = info->x86.prefix[3] == 0x67;
    fields->skip_flags = !flags_live;
    fields->omit_zext32 = false;
    fields->scalar_direct_dst = false;
    fields->direct_branch_kind = FT_DIRECT_BRANCH_NONE;

    {
        FastAluOp alu_op;
        FastAluForm alu_form;

        if (ft_template_alu_info(tmpl->kind, &alu_op, &alu_form,
                                 &fields->alu_width)) {
            fields->alu_op = alu_op;
            fields->alu_form = alu_form;
        }
    }
    if (fields->alu_op != FT_ALU_NONE ||
        tmpl->kind == FT_ALU_RM_R ||
        tmpl->kind == FT_ALU_R_RM ||
        tmpl->kind == FT_ALU_ACC_IMM) {
        ft_fill_generic_alu_info(fields);
    }
    if (fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
        (tmpl->kind == FT_AND_RM32_R32 ||
         tmpl->kind == FT_OR_RM32_R32 ||
         tmpl->kind == FT_XOR_RM32_R32)) {
        fields->alu_width = 16;
    }

    if (tmpl->meta_flags & FT_TM_READS_RAW_MODRM) {
        int modrm_offset = ft_ir1_modrm_offset(info);

        if (modrm_offset < 1 || modrm_offset >= info->size) {
            return false;
        }
        fields->opcode0 = info->bytes[modrm_offset - 1];
        ft_fields_set_modrm(fields, info->bytes[modrm_offset]);
        if (tmpl->meta_flags & FT_TM_READS_RAW_IMM8) {
            if (modrm_offset + 1 >= info->size) {
                return false;
            }
            fields->imm = info->bytes[info->size - 1];
        }
    }

    if (tmpl->kind == FT_GRP1_RM64_IMM8 ||
        tmpl->kind == FT_GRP1_RM32_IMM8 ||
        tmpl->kind == FT_GRP1_RM16_IMM8 ||
        tmpl->kind == FT_GRP1_RM8_IMM8 ||
        tmpl->kind == FT_GRP1_RM32_IMM32 ||
        tmpl->kind == FT_GRP1_RM64_IMM32) {
        if (!ft_fill_group1_alu_info(fields)) {
            return false;
        }
    }

    if (fields->modrm_mod != 3 && fields->modrm_rm == 4) {
        fields->sib = ft_ir1_sib_byte(info);
    }

    switch (tmpl->kind) {
    case FT_XLATB:
        fields->addr32 = info->x86.addr_size == 4;
        break;
    case FT_MOV_R64_RM64:
    case FT_LEA_R64_M:
    case FT_LEA_R32_M:
    case FT_LEA_R16_M:
    case FT_CMP_R64_RM64:
    case FT_CMP_R32_RM32:
    case FT_CMP_R16_RM16:
    case FT_OR_R16_RM16:
    case FT_MOV_R8_RM8:
    case FT_MOV_R16_RM16:
    case FT_MOV_R32_RM32:
    case FT_IMUL_R64_RM64:
    case FT_IMUL_R64_RM64_IMM32:
    case FT_IMUL_R64_RM64_IMM8:
    case FT_IMUL_R16_RM16:
    case FT_IMUL_R16_RM16_IMM16:
    case FT_IMUL_R16_RM16_IMM8:
    case FT_IMUL_R32_RM32:
    case FT_IMUL_R32_RM32_IMM32:
    case FT_IMUL_R32_RM32_IMM8:
    case FT_BSF_R64_RM64:
    case FT_BSF_R32_RM32:
    case FT_BSR_R64_RM64:
    case FT_BSR_R32_RM32:
    case FT_LZCNT_R64_RM64:
    case FT_LZCNT_R32_RM32:
    case FT_LZCNT_R16_RM16:
    case FT_TZCNT_R64_RM64:
    case FT_TZCNT_R32_RM32:
    case FT_TZCNT_R16_RM16:
    case FT_POPCNT_R64_RM64:
    case FT_POPCNT_R32_RM32:
    case FT_POPCNT_R16_RM16:
    case FT_ANDN_R64_R_RM:
    case FT_ANDN_R32_R_RM:
    case FT_BLS_R64_RM:
    case FT_BLS_R32_RM:
    case FT_BEXTR_R64_RM_R:
    case FT_BEXTR_R32_RM_R:
    case FT_SARX_R64_RM_R:
    case FT_SARX_R32_RM_R:
    case FT_SHRX_R64_RM_R:
    case FT_SHRX_R32_RM_R:
    case FT_BZHI_R64_RM_R:
    case FT_BZHI_R32_RM_R:
    case FT_MOVBE_R64_M64:
    case FT_MOVBE_R32_M32:
    case FT_MOVBE_R16_M16:
    case FT_CRC32_R_RM8:
    case FT_CRC32_R_RM16:
    case FT_CRC32_R_RM32:
    case FT_CRC32_R_RM64:
    case FT_IMUL_RM8:
    case FT_IMUL_RM16:
    case FT_IMUL_RM32:
    case FT_IMUL_RM64:
    case FT_MUL_RM8:
    case FT_MUL_RM64:
    case FT_DIV_RM8:
    case FT_DIV_RM16:
    case FT_DIV_RM32:
    case FT_DIV_RM64:
    case FT_IDIV_RM8:
    case FT_IDIV_RM16:
    case FT_IDIV_RM32:
    case FT_IDIV_RM64:
    case FT_MOVSX_R64_RM8:
    case FT_MOVSX_R32_RM8:
    case FT_MOVSX_R16_RM8:
    case FT_MOVSX_R64_RM16:
    case FT_MOVSX_R32_RM16:
    case FT_MOVSX_R16_RM16:
    case FT_MOVZX_R32_RM16:
    case FT_MOVZX_R16_RM8:
    case FT_MOVZX_R32_RM8:
    case FT_TEST_RM16_IMM16:
    case FT_ADD_R8_RM8:
    case FT_ADC_R8_RM8:
    case FT_SUB_R8_RM8:
    case FT_AND_R8_RM8:
    case FT_ALU_R_RM:
    case FT_MOVQ_MMX_RM64_GPR:
    case FT_MOVQ_XMM_RM64:
    case FT_MOV128_XMM_XMMM:
    case FT_PALIGNR_XMM_XMMM_IMM8:
    case FT_PALIGNR_MMX_MMXM64_IMM8:
    case FT_SHUF_XMM_XMMM_IMM8:
    case FT_BLEND_XMM_XMMM_IMM8:
    case FT_BLENDV_XMM_XMMM:
    case FT_PSHUFB_XMM_XMMM:
    case FT_PSHUFB_MMX_MMXM64:
    case FT_PHADD_SUB_XMM_XMMM:
    case FT_PHADD_SUB_MMX_MMXM64:
    case FT_SIMD_MADD_MMX_MMXM64:
    case FT_SIMD_BIN_MMX_MMXM64:
    case FT_HADD_SUB_XMM_XMMM:
    case FT_MOVDUP_XMM_XMMM:
    case FT_PSADBW_XMM_XMMM:
    case FT_MPSADBW_XMM_XMMM_IMM8:
    case FT_PMOVX_XMM_XMMM:
    case FT_PTEST_XMM_XMMM:
    case FT_INSERTPS_XMM_XMMM_IMM8:
    case FT_PSHUFW_MMX_MMXM_IMM8:
    case FT_PHMINPOSUW_XMM_XMMM:
    case FT_CVT_FP_XMM_XMMM:
    case FT_CVTPI2PS_XMM_MMX:
    case FT_CVT_FP2I_XMM_XMMM:
    case FT_CVT_FP2I_MMX_XMMM:
    case FT_CMP_XMM_XMMM_IMM8:
    case FT_ROUND_XMM_XMMM_IMM8:
    case FT_DP_XMM_XMMM_IMM8:
    case FT_PCLMULQDQ_XMM_XMMM_IMM8:
    case FT_AES_ROUND_XMM_XMMM:
    case FT_AESIMC_XMM_XMMM:
    case FT_AESKEYGEN_XMM_XMMM_IMM8:
    case FT_HELPER_PCMPISTRI:
    case FT_HELPER_PCMPISTRM:
    case FT_HELPER_PCMPESTRI:
    case FT_HELPER_PCMPESTRM:
    case FT_MOVLPS_XMM_M64:
    case FT_MOVLPD_XMM_M64:
    case FT_MOVHPS_XMM_M64:
    case FT_MOVSD_XMM_M64:
        fields->disp = info->x86.operands[1].mem.disp;
        break;
    case FT_FMA132_XMM_XMMM:
        fields->disp = info->x86.operands[2].mem.disp;
        break;
    case FT_EXTRACTPS_RM32_XMM_IMM8:
        fields->disp = info->x86.operands[0].mem.disp;
        break;
    case FT_MOV_RM64_R64:
    case FT_PUSH_RM64:
    case FT_POP_RM64:
    case FT_PUSH_RM16:
    case FT_POP_RM16:
    case FT_CALL_RM64:
    case FT_JMP_RM64:
    case FT_MOV_RM32_R32:
    case FT_MOV_RM16_R16:
    case FT_MOV_RM_SEG:
    case FT_OR_RM64_R64:
    case FT_OR_RM32_R32:
    case FT_OR_RM8_R8:
    case FT_OR_RM8_IMM8:
    case FT_ADD_RM8_R8:
    case FT_ADC_RM8_R8:
    case FT_ADC_RM64_R64:
    case FT_ADC_RM32_R32:
    case FT_ADC_RM16_R16:
    case FT_AND_RM8_R8:
    case FT_AND_RM8_IMM8:
    case FT_XOR_RM8_R8:
    case FT_SHR_RM8_IMM8:
    case FT_SHR_RM8_ONE:
    case FT_SHR_RM16_IMM8:
    case FT_XCHG_RM32_R32:
    case FT_XCHG_RM8_R8:
    case FT_SUB_RM32_R32:
    case FT_SUB_RM16_R16:
    case FT_SUB_RM8_R8:
    case FT_INC_RM16:
    case FT_DEC_RM16:
    case FT_INC_RM8:
    case FT_DEC_RM8:
    case FT_MOV_RM8_R8:
    case FT_MOV_RM8_IMM8:
    case FT_TEST_RM8_IMM8:
    case FT_CMP_RM64_IMM8:
    case FT_CMP_RM32_IMM8:
    case FT_CMP_RM16_IMM8:
    case FT_CMP_RM16_IMM16:
    case FT_CMP_RM16_R16:
    case FT_CMP_RM8_IMM8:
    case FT_GRP1_RM64_IMM8:
    case FT_GRP1_RM32_IMM8:
    case FT_GRP1_RM16_IMM8:
    case FT_GRP1_RM8_IMM8:
    case FT_MOVQ_RM64_XMM:
    case FT_MOVQ_RM64_MMX:
    case FT_MOV128_XMMM_XMM:
    case FT_STMXCSR_M32:
    case FT_MOVSD_M64_XMM:
    case FT_MOVBE_M64_R64:
    case FT_MOVBE_M32_R32:
    case FT_MOVBE_M16_R16:
    case FT_CMPXCHG_RM8_R8:
    case FT_CMPXCHG_RM16_R16:
    case FT_CMPXCHG_RM32_R32:
    case FT_CMPXCHG_RM64_R64:
    case FT_CMPXCHG8B:
    case FT_CMPXCHG16B:
    case FT_SHLD_RM_R_IMM8:
    case FT_SHLD_RM_R_CL:
    case FT_SHRD_RM_R_IMM8:
    case FT_SHRD_RM_R_CL:
    case FT_XADD_RM32_R32:
    case FT_XADD_RM64_R64:
    case FT_XADD_RM8_R8:
    case FT_XADD_RM16_R16:
    case FT_ALU_RM_R:
    case FT_BTX_RM_R:
    case FT_X87_FLDCW_M16:
    case FT_X87_FNSTCW_M16:
    case FT_X87_FNSTSW_M16:
    case FT_HELPER_LDMXCSR:
    case FT_HELPER_FXSAVE:
    case FT_HELPER_FXRSTOR:
    case FT_HELPER_FNSAVE:
    case FT_HELPER_FRSTOR:
    case FT_HELPER_FLDENV:
    case FT_HELPER_FNSTENV:
        fields->disp = info->x86.operands[0].mem.disp;
        break;
    case FT_MOV_SEG_RM:
    case FT_PINSR_XMM_GPR_IMM8:
    case FT_PINSRW_MMX_RM16_IMM8:
        fields->disp = info->x86.operands[1].mem.disp;
        break;
    default:
        break;
    }

    if (!ft_fill_mem_fields_from_ir1(fields, info)) {
        return false;
    }

    switch (tmpl->kind) {
    case FT_PUSH_R64:
    case FT_POP_R64:
    case FT_PUSH_R16:
    case FT_POP_R16:
        fields->reg = ft_rex_base_from_opcode(fields->rex,
                                              info->x86.opcode[0]);
        break;
    case FT_MOV_RM64_IMM32:
        fields->imm = info->x86.operands[1].imm;
        break;
    case FT_MOV_RM32_IMM32:
        fields->imm = info->x86.operands[1].imm;
        if (fields->rex >= 0) {
            int rex = fields->rex & ~8;

            ft_fields_set_rex(fields, rex ? rex : -1);
        }
        break;
    case FT_MOV_R64_IMM64:
        fields->imm64 = info->x86.operands[1].imm;
        fields->reg = ft_rex_base_from_opcode(fields->rex,
                                              info->x86.opcode[0]);
        break;
    case FT_MOV_R32_IMM32:
    case FT_MOV_R8_IMM8:
    case FT_MOV_R16_IMM16:
        fields->imm = info->x86.operands[1].imm;
        fields->reg = ft_rex_base_from_opcode(fields->rex,
                                              info->x86.opcode[0]);
        if (tmpl->kind == FT_MOV_R8_IMM8) {
            fields->imm &= 0xff;
        } else if (tmpl->kind == FT_MOV_R16_IMM16) {
            fields->imm &= 0xffff;
        }
        break;
    case FT_BSWAP_R32:
    case FT_BSWAP_R64:
        fields->reg = ft_x86_gpr_index(info->x86.operands[0].reg);
        break;
    case FT_RDRAND_R64:
    case FT_RDRAND_R32:
    case FT_RDRAND_R16:
        fields->reg = ft_modrm_rm_index(fields);
        break;
    case FT_MOV_RM_SEG:
        fields->reg = ft_x86_seg_index(info->x86.operands[1].reg);
        break;
    case FT_MOV_SEG_RM:
        fields->reg = ft_x86_seg_index(info->x86.operands[0].reg);
        break;
    case FT_ANDN_R64_R_RM:
    case FT_ANDN_R32_R_RM:
        fields->reg = ft_modrm_reg_index(fields);
        fields->imm = info->size >= 3 ? ((~info->bytes[2] >> 3) & 0xf) : -1;
        break;
    case FT_BLS_R64_RM:
    case FT_BLS_R32_RM:
        fields->reg = info->size >= 3 ? ((~info->bytes[2] >> 3) & 0xf) : -1;
        break;
    case FT_BEXTR_R64_RM_R:
    case FT_BEXTR_R32_RM_R:
    case FT_SARX_R64_RM_R:
    case FT_SARX_R32_RM_R:
    case FT_BZHI_R64_RM_R:
    case FT_BZHI_R32_RM_R:
    case FT_PEXT_R64_R_RM:
    case FT_PEXT_R32_R_RM:
    case FT_PDEP_R64_R_RM:
    case FT_PDEP_R32_R_RM:
        fields->reg = ft_modrm_reg_index(fields);
        fields->imm = info->size >= 3 ? ((~info->bytes[2] >> 3) & 0xf) : -1;
        break;
    case FT_RORX_R64_RM64_IMM8:
    case FT_RORX_R32_RM32_IMM8:
        fields->reg = ft_modrm_reg_index(fields);
        fields->imm = info->x86.operands[2].imm;
        break;
    case FT_ADD_R64_IMM8:
    case FT_ADD_R64_IMM32:
    case FT_ALU_ACC_IMM:
    case FT_ADD_AL_IMM8:
    case FT_ADC_AL_IMM8:
    case FT_ADD_AX_IMM16:
    case FT_ADD_EAX_IMM32:
    case FT_ADD_RAX_IMM32:
    case FT_AND_AL_IMM8:
    case FT_OR_AL_IMM8:
    case FT_OR_AX_IMM16:
    case FT_OR_EAX_IMM32:
    case FT_OR_RAX_IMM32:
    case FT_XOR_AL_IMM8:
    case FT_XOR_AX_IMM16:
    case FT_XOR_EAX_IMM32:
    case FT_XOR_RAX_IMM32:
    case FT_CMP_AL_IMM8:
    case FT_SUB_EAX_IMM32:
    case FT_SUB_AL_IMM8:
    case FT_SUB_AX_IMM16:
    case FT_SUB_R64_IMM32:
    case FT_SUB_R64_IMM8:
    case FT_CMP_RM64_IMM32:
    case FT_CMP_AX_IMM16:
    case FT_CMP_EAX_IMM32:
    case FT_CMP_RAX_IMM32:
    case FT_TEST_RM16_IMM16:
    case FT_CMP_RM16_IMM16:
    case FT_TEST_AL_IMM8:
    case FT_TEST_EAX_IMM32:
    case FT_TEST_RAX_IMM32:
    case FT_TEST_RM64_IMM32:
    case FT_TEST_RM32_IMM32:
    case FT_TEST_RM8_IMM8:
    case FT_AND_RM8_IMM8:
    case FT_OR_RM8_IMM8:
    case FT_MOV_RM8_IMM8:
    case FT_SHIFT_RM_IMM8:
    case FT_ROL_RM64_IMM8:
    case FT_ROR_RM64_IMM8:
    case FT_SHR_RM8_IMM8:
    case FT_SHR_RM16_IMM8:
    case FT_SUB_R32_IMM8:
    case FT_GRP1_RM64_IMM8:
    case FT_GRP1_RM32_IMM8:
    case FT_GRP1_RM16_IMM8:
    case FT_GRP1_RM8_IMM8:
    case FT_GRP1_RM32_IMM32:
    case FT_GRP1_RM64_IMM32:
    case FT_PSHIFT_XMM_IMM8:
    case FT_PSHIFT_MMX_IMM8:
    case FT_PSRLDQ_XMM_IMM8:
    case FT_PSLLDQ_XMM_IMM8:
        fields->imm = info->x86.operands[1].imm;
        break;
    case FT_IMUL_R32_RM32_IMM32:
    case FT_IMUL_R32_RM32_IMM8:
    case FT_IMUL_R64_RM64_IMM32:
    case FT_IMUL_R64_RM64_IMM8:
    case FT_IMUL_R16_RM16_IMM16:
    case FT_IMUL_R16_RM16_IMM8:
    case FT_PALIGNR_XMM_XMMM_IMM8:
    case FT_PALIGNR_MMX_MMXM64_IMM8:
    case FT_SHUF_XMM_XMMM_IMM8:
    case FT_BLEND_XMM_XMMM_IMM8:
    case FT_MPSADBW_XMM_XMMM_IMM8:
    case FT_INSERTPS_XMM_XMMM_IMM8:
    case FT_EXTRACTPS_RM32_XMM_IMM8:
    case FT_PSHUFW_MMX_MMXM_IMM8:
    case FT_CMP_XMM_XMMM_IMM8:
    case FT_ROUND_XMM_XMMM_IMM8:
    case FT_DP_XMM_XMMM_IMM8:
    case FT_PCLMULQDQ_XMM_XMMM_IMM8:
    case FT_AESKEYGEN_XMM_XMMM_IMM8:
    case FT_HELPER_PCMPISTRI:
    case FT_HELPER_PCMPISTRM:
    case FT_HELPER_PCMPESTRI:
    case FT_HELPER_PCMPESTRM:
    case FT_PINSR_XMM_GPR_IMM8:
    case FT_PINSRW_MMX_RM16_IMM8:
    case FT_PEXTR_GPR_XMM_IMM8:
    case FT_PEXTRQ_R64_XMM_IMM8:
    case FT_PEXTRW_R32_XMM_IMM8:
    case FT_PEXTRW_SSE41_RM16_XMM_IMM8:
    case FT_PEXTRW_R32_MMX_IMM8:
    case FT_SHLD_RM_R_IMM8:
    case FT_SHRD_RM_R_IMM8:
        fields->imm = info->x86.operands[2].imm;
        break;
    case FT_AND_AX_IMM16:
    case FT_AND_EAX_IMM32:
    case FT_AND_RAX_IMM32:
        fields->imm = info->x86.operands[1].imm;
        break;
    case FT_PUSH_IMM32:
    case FT_PUSH_IMM16:
    case FT_PUSH_IMM8:
    case FT_RET_IMM16:
        fields->imm = info->x86.operands[0].imm;
        break;
    case FT_BTX_RM32_IMM8:
        fields->imm = info->x86.operands[1].imm;
        break;
    case FT_JCC_REL:
        if (info->x86.opcode[0] == 0x0f) {
            int cond;
            int id;

            if (info->size < 6 ||
                !ft_jcc_opcode_info(info->x86.opcode[1] & 0xf,
                                    &cond, &id)) {
                return false;
            }
            fields->reg = cond;
            fields->id = id;
            fields->imm64 = info->address + info->size +
                            ft_read_simm(&info->bytes[info->size - 4], 4);
        } else {
            int cond;
            int id;

            if (info->size < 2 ||
                !ft_jcc_opcode_info(info->x86.opcode[0] & 0xf,
                                    &cond, &id)) {
                return false;
            }
            fields->reg = cond;
            fields->id = id;
            fields->imm64 = info->address + info->size +
                            ft_read_simm(&info->bytes[info->size - 1], 1);
        }
        break;
    case FT_JRCXZ_REL8:
    case FT_LOOP_REL8:
    case FT_LOOPE_REL8:
    case FT_LOOPNE_REL8:
        if (info->size < 2) {
            return false;
        }
        fields->imm64 = info->address + info->size +
                        ft_read_simm(&info->bytes[info->size - 1], 1);
        break;
    case FT_CALL_REL32:
    case FT_JMP_REL32:
        fields->imm = info->x86.operands[0].imm -
                      (info->address + info->size);
        break;
    default:
        break;
    }

    return true;
}
#endif
