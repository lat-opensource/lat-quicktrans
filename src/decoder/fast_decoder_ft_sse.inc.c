/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

static bool fd_ft_mov128_opcode_supported(uint8_t prefix0, uint8_t prefix2,
                                          uint8_t opcode, bool *store)
{
    if (prefix0 == 0 && (prefix2 == 0 || prefix2 == 0x66) &&
        (opcode == 0x10 || opcode == 0x11 ||
         opcode == 0x28 || opcode == 0x29)) {
        *store = opcode == 0x11 || opcode == 0x29;
        return true;
    }
    if (prefix0 == 0 && prefix2 == 0x66 &&
        (opcode == 0x6f || opcode == 0x7f)) {
        *store = opcode == 0x7f;
        return true;
    }
    if (prefix0 == dt_X86_PREFIX_REP && prefix2 == 0 &&
        (opcode == 0x6f || opcode == 0x7f)) {
        *store = opcode == 0x7f;
        return true;
    }
    return false;
}

static bool fd_ft_simd_bin_opcode_info(uint8_t prefix0, uint8_t prefix2,
                                       uint8_t opcode, int *id)
{
    bool is_double = prefix2 == dt_X86_PREFIX_OPSIZE;

    if (prefix0 != 0 &&
        !(opcode == 0xd0 && prefix0 == dt_X86_PREFIX_REPNE && prefix2 == 0)) {
        return false;
    }

    switch (opcode) {
    case 0x51:
        *id = is_double ? dt_X86_INS_SQRTPD : dt_X86_INS_SQRTPS;
        return true;
    case 0x52:
        if (is_double) {
            return false;
        }
        *id = dt_X86_INS_RSQRTPS;
        return true;
    case 0x53:
        if (is_double) {
            return false;
        }
        *id = dt_X86_INS_RCPPS;
        return true;
    case 0x54:
        *id = is_double ? dt_X86_INS_ANDPD : dt_X86_INS_ANDPS;
        return true;
    case 0x55:
        *id = is_double ? dt_X86_INS_ANDNPD : dt_X86_INS_ANDNPS;
        return true;
    case 0x56:
        *id = is_double ? dt_X86_INS_ORPD : dt_X86_INS_ORPS;
        return true;
    case 0x57:
        *id = is_double ? dt_X86_INS_XORPD : dt_X86_INS_XORPS;
        return true;
    case 0x58:
        *id = is_double ? dt_X86_INS_ADDPD : dt_X86_INS_ADDPS;
        return true;
    case 0x59:
        *id = is_double ? dt_X86_INS_MULPD : dt_X86_INS_MULPS;
        return true;
    case 0x5c:
        *id = is_double ? dt_X86_INS_SUBPD : dt_X86_INS_SUBPS;
        return true;
    case 0x5d:
        *id = is_double ? dt_X86_INS_MINPD : dt_X86_INS_MINPS;
        return true;
    case 0x5e:
        *id = is_double ? dt_X86_INS_DIVPD : dt_X86_INS_DIVPS;
        return true;
    case 0x5f:
        *id = is_double ? dt_X86_INS_MAXPD : dt_X86_INS_MAXPS;
        return true;
    case 0x08:
        if (prefix0 != 0 || !is_double) {
            return false;
        }
        *id = dt_X86_INS_PSIGNB;
        return true;
    case 0x09:
        if (prefix0 != 0 || !is_double) {
            return false;
        }
        *id = dt_X86_INS_PSIGNW;
        return true;
    case 0x0a:
        if (prefix0 != 0 || !is_double) {
            return false;
        }
        *id = dt_X86_INS_PSIGND;
        return true;
    case 0x1c:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PABSB;
        return true;
    case 0x1d:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PABSW;
        return true;
    case 0x1e:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PABSD;
        return true;
    case 0x28:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULDQ;
        return true;
    case 0x37:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PCMPGTQ;
        return true;
    case 0x38:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINSB;
        return true;
    case 0x39:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINSD;
        return true;
    case 0x3a:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINUW;
        return true;
    case 0x3b:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINUD;
        return true;
    case 0x3c:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXSB;
        return true;
    case 0x3d:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXSD;
        return true;
    case 0x3e:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXUW;
        return true;
    case 0x3f:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXUD;
        return true;
    case 0x40:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULLD;
        return true;
    case 0x64:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PCMPGTB;
        return true;
    case 0x65:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PCMPGTW;
        return true;
    case 0x66:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PCMPGTD;
        return true;
    case 0xd0:
        if (prefix2 == dt_X86_PREFIX_OPSIZE) {
            *id = dt_X86_INS_ADDSUBPD;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REPNE) {
            *id = dt_X86_INS_ADDSUBPS;
            return true;
        }
        return false;
    case 0xd1:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PSRLW;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRLW;
        return true;
    case 0xd2:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PSRLD;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRLD;
        return true;
    case 0xd3:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PSRLQ;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRLQ;
        return true;
    case 0xd5:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULLW;
        return true;
    case 0xd8:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBUSB;
        return true;
    case 0xd9:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBUSW;
        return true;
    case 0xda:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PMINUB;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINUB;
        return true;
    case 0xdb:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PAND;
        return true;
    case 0xdc:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PADDUSB;
        return true;
    case 0xdd:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PADDUSW;
        return true;
    case 0xde:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PMAXUB;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXUB;
        return true;
    case 0xdf:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PANDN;
        return true;
    case 0xe0:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PAVGB;
        return true;
    case 0xe1:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRAW;
        return true;
    case 0xe2:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRAD;
        return true;
    case 0xe3:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PAVGW;
        return true;
    case 0xe4:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULHUW;
        return true;
    case 0xe5:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULHW;
        return true;
    case 0xe8:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBSB;
        return true;
    case 0xe9:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBSW;
        return true;
    case 0xea:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINSW;
        return true;
    case 0xeb:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_POR;
        return true;
    case 0xec:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PADDSB;
        return true;
    case 0xed:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PADDSW;
        return true;
    case 0xee:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXSW;
        return true;
    case 0xf1:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PSLLW;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSLLW;
        return true;
    case 0xf2:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PSLLD;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSLLD;
        return true;
    case 0xf3:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PSLLQ;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSLLQ;
        return true;
    case 0xf8:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBB;
        return true;
    case 0xf9:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBW;
        return true;
    case 0xfa:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBD;
        return true;
    case 0xfb:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBQ;
        return true;
    default:
        return false;
    }
}

static bool fd_ft_sse_read_modrm_imm8(FDState *s, FastTemplateFields *fields)
{
    int imm;

    if (!fd_ft_read_modrm(s, fields)) {
        return false;
    }
    imm = fd_read_byte(s);
    if (imm < 0) {
        return false;
    }
    fields->imm = imm & 0xff;
    return true;
}

static bool fd_ft_simd_cmp_imm8_info(uint8_t prefix0, uint8_t prefix2,
                                     int *id)
{
    if (prefix0 == 0 && prefix2 == 0) {
        *id = dt_X86_INS_CMPPS;
        return true;
    }
    if (prefix0 == 0 && prefix2 == dt_X86_PREFIX_OPSIZE) {
        *id = dt_X86_INS_CMPPD;
        return true;
    }
    if (prefix0 == dt_X86_PREFIX_REP && prefix2 == 0) {
        *id = dt_X86_INS_CMPSS;
        return true;
    }
    if (prefix0 == dt_X86_PREFIX_REPNE && prefix2 == 0) {
        *id = dt_X86_INS_CMPSD;
        return true;
    }
    return false;
}

static bool fd_ft_simd_scalar_bin_opcode_info(uint8_t prefix0,
                                              uint8_t opcode, int *id)
{
    bool is_double = prefix0 == dt_X86_PREFIX_REPNE;

    if (prefix0 != dt_X86_PREFIX_REPNE && prefix0 != dt_X86_PREFIX_REP) {
        return false;
    }

    switch (opcode) {
    case 0x51:
        *id = is_double ? dt_X86_INS_SQRTSD : dt_X86_INS_SQRTSS;
        return true;
    case 0x52:
        if (is_double) {
            return false;
        }
        *id = dt_X86_INS_RSQRTSS;
        return true;
    case 0x53:
        if (is_double) {
            return false;
        }
        *id = dt_X86_INS_RCPSS;
        return true;
    case 0x58:
        *id = is_double ? dt_X86_INS_ADDSD : dt_X86_INS_ADDSS;
        return true;
    case 0x59:
        *id = is_double ? dt_X86_INS_MULSD : dt_X86_INS_MULSS;
        return true;
    case 0x5c:
        *id = is_double ? dt_X86_INS_SUBSD : dt_X86_INS_SUBSS;
        return true;
    case 0x5d:
        *id = is_double ? dt_X86_INS_MINSD : dt_X86_INS_MINSS;
        return true;
    case 0x5e:
        *id = is_double ? dt_X86_INS_DIVSD : dt_X86_INS_DIVSS;
        return true;
    case 0x5f:
        *id = is_double ? dt_X86_INS_MAXSD : dt_X86_INS_MAXSS;
        return true;
    default:
        return false;
    }
}

static bool fd_ft_simd_scalar_cmp_opcode_info(uint8_t prefix0,
                                              uint8_t prefix2,
                                              uint8_t opcode, int *id)
{
    bool qnan;

    if (opcode != 0x2e && opcode != 0x2f) {
        return false;
    }
    qnan = opcode == 0x2f;
    if (prefix0 == 0 && prefix2 == dt_X86_PREFIX_OPSIZE) {
        *id = qnan ? dt_X86_INS_COMISD : dt_X86_INS_UCOMISD;
        return true;
    }
    if (prefix0 == 0 && prefix2 == 0) {
        *id = qnan ? dt_X86_INS_COMISS : dt_X86_INS_UCOMISS;
        return true;
    }
    return false;
}

static bool fd_ft_sse_cvt_opcode_info(uint8_t prefix0, uint8_t prefix2,
                                      uint8_t opcode, FastTemplateKind *kind,
                                      int *id)
{
    switch (opcode) {
    case 0x2a:
        if (prefix0 == 0 && prefix2 == dt_X86_PREFIX_OPSIZE) {
            *kind = FT_CVTPI2PD_XMM_MMX;
            *id = dt_X86_INS_CVTPI2PD;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REP && prefix2 == 0) {
            *kind = FT_CVTSI2SS_XMM_RM;
            *id = dt_X86_INS_CVTSI2SS;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REPNE && prefix2 == 0) {
            *kind = FT_CVTSI2SD_XMM_RM;
            *id = dt_X86_INS_CVTSI2SD;
            return true;
        }
        if (prefix0 == 0 && prefix2 == 0) {
            *kind = FT_CVTPI2PS_XMM_MMX;
            *id = dt_X86_INS_CVTPI2PS;
            return true;
        }
        return false;
    case 0x2c:
        if (prefix0 == dt_X86_PREFIX_REP && prefix2 == 0) {
            *kind = FT_CVTTSS2SI_GPR_XMMM;
            *id = dt_X86_INS_CVTTSS2SI;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REPNE && prefix2 == 0) {
            *kind = FT_CVTTSD2SI_GPR_XMMM;
            *id = dt_X86_INS_CVTTSD2SI;
            return true;
        }
        if (prefix0 == 0 && prefix2 == dt_X86_PREFIX_OPSIZE) {
            *kind = FT_CVT_FP2I_MMX_XMMM;
            *id = dt_X86_INS_CVTTPD2PI;
            return true;
        }
        if (prefix0 == 0 && prefix2 == 0) {
            *kind = FT_CVT_FP2I_MMX_XMMM;
            *id = dt_X86_INS_CVTTPS2PI;
            return true;
        }
        return false;
    case 0x2d:
        if (prefix0 == dt_X86_PREFIX_REP && prefix2 == 0) {
            *kind = FT_CVTSS2SI_GPR_XMMM;
            *id = dt_X86_INS_CVTSS2SI;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REPNE && prefix2 == 0) {
            *kind = FT_CVTSD2SI_GPR_XMMM;
            *id = dt_X86_INS_CVTSD2SI;
            return true;
        }
        if (prefix0 == 0 && prefix2 == dt_X86_PREFIX_OPSIZE) {
            *kind = FT_CVT_FP2I_MMX_XMMM;
            *id = dt_X86_INS_CVTPD2PI;
            return true;
        }
        if (prefix0 == 0 && prefix2 == 0) {
            *kind = FT_CVT_FP2I_MMX_XMMM;
            *id = dt_X86_INS_CVTPS2PI;
            return true;
        }
        return false;
    case 0x5a:
        *kind = FT_CVT_FP_XMM_XMMM;
        if (prefix0 == 0 && prefix2 == dt_X86_PREFIX_OPSIZE) {
            *id = dt_X86_INS_CVTPD2PS;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REPNE && prefix2 == 0) {
            *id = dt_X86_INS_CVTSD2SS;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REP && prefix2 == 0) {
            *id = dt_X86_INS_CVTSS2SD;
            return true;
        }
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_CVTPS2PD;
            return true;
        }
        return false;
    case 0x5b:
        if (prefix0 == 0 && prefix2 == 0) {
            *kind = FT_CVT_FP_XMM_XMMM;
            *id = dt_X86_INS_CVTDQ2PS;
            return true;
        }
        if (prefix0 == 0 && prefix2 == dt_X86_PREFIX_OPSIZE) {
            *kind = FT_CVT_FP2I_XMM_XMMM;
            *id = dt_X86_INS_CVTPS2DQ;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REP && prefix2 == 0) {
            *kind = FT_CVT_FP2I_XMM_XMMM;
            *id = dt_X86_INS_CVTTPS2DQ;
            return true;
        }
        return false;
    case 0xe6:
        if (prefix0 == dt_X86_PREFIX_REP && prefix2 == 0) {
            return false;
        }
        if (prefix0 == 0 && prefix2 == dt_X86_PREFIX_OPSIZE) {
            *kind = FT_CVT_FP2I_XMM_XMMM;
            *id = dt_X86_INS_CVTTPD2DQ;
            return true;
        }
        if (prefix0 == dt_X86_PREFIX_REPNE && prefix2 == 0) {
            *kind = FT_CVT_FP2I_XMM_XMMM;
            *id = dt_X86_INS_CVTPD2DQ;
            return true;
        }
        return false;
    default:
        return false;
    }
}

static bool fd_ft_padd_opcode_info(uint8_t opcode, int *id)
{
    switch (opcode) {
    case 0xfc:
        *id = dt_X86_INS_PADDB;
        return true;
    case 0xfd:
        *id = dt_X86_INS_PADDW;
        return true;
    case 0xfe:
        *id = dt_X86_INS_PADDD;
        return true;
    case 0xd4:
        *id = dt_X86_INS_PADDQ;
        return true;
    default:
        return false;
    }
}

static bool fd_ft_pcmpeq_opcode_info(uint8_t opcode, int *id)
{
    switch (opcode) {
    case 0x74:
        *id = dt_X86_INS_PCMPEQB;
        return true;
    case 0x75:
        *id = dt_X86_INS_PCMPEQW;
        return true;
    case 0x76:
        *id = dt_X86_INS_PCMPEQD;
        return true;
    case 0x29:
        *id = dt_X86_INS_PCMPEQQ;
        return true;
    default:
        return false;
    }
}

static bool fd_ft_punpck_opcode_info(uint8_t prefix2, uint8_t opcode, int *id)
{
    switch (opcode) {
    case 0x14:
        if (prefix2 != 0) {
            return false;
        }
        *id = dt_X86_INS_UNPCKLPS;
        return true;
    case 0x15:
        if (prefix2 != 0) {
            return false;
        }
        *id = dt_X86_INS_UNPCKHPS;
        return true;
    case 0x60:
        *id = dt_X86_INS_PUNPCKLBW;
        return true;
    case 0x61:
        *id = dt_X86_INS_PUNPCKLWD;
        return true;
    case 0x62:
        *id = dt_X86_INS_PUNPCKLDQ;
        return true;
    case 0x6c:
        *id = dt_X86_INS_PUNPCKLQDQ;
        return true;
    case 0x68:
        *id = dt_X86_INS_PUNPCKHBW;
        return true;
    case 0x69:
        *id = dt_X86_INS_PUNPCKHWD;
        return true;
    case 0x6a:
        *id = dt_X86_INS_PUNPCKHDQ;
        return true;
    case 0x6d:
        *id = dt_X86_INS_PUNPCKHQDQ;
        return true;
    default:
        return false;
    }
}

static bool fd_ft_sse3a_opcode_info(uint8_t opcode, bool rex_w,
                                    FastTemplateKind *kind, int *id,
                                    bool *has_imm8)
{
    *has_imm8 = true;
    switch (opcode) {
    case 0x08:
        *kind = FT_ROUND_XMM_XMMM_IMM8;
        *id = dt_X86_INS_ROUNDPS;
        return true;
    case 0x09:
        *kind = FT_ROUND_XMM_XMMM_IMM8;
        *id = dt_X86_INS_ROUNDPD;
        return true;
    case 0x0a:
        *kind = FT_ROUND_XMM_XMMM_IMM8;
        *id = dt_X86_INS_ROUNDSS;
        return true;
    case 0x0b:
        *kind = FT_ROUND_XMM_XMMM_IMM8;
        *id = dt_X86_INS_ROUNDSD;
        return true;
    case 0x0c:
        *kind = FT_BLEND_XMM_XMMM_IMM8;
        *id = dt_X86_INS_BLENDPS;
        return true;
    case 0x0d:
        *kind = FT_BLEND_XMM_XMMM_IMM8;
        *id = dt_X86_INS_BLENDPD;
        return true;
    case 0x0e:
        *kind = FT_BLEND_XMM_XMMM_IMM8;
        *id = dt_X86_INS_PBLENDW;
        return true;
    case 0x0f:
        *kind = FT_PALIGNR_XMM_XMMM_IMM8;
        *id = dt_X86_INS_PALIGNR;
        return true;
    case 0x14:
        *kind = FT_PEXTR_GPR_XMM_IMM8;
        *id = dt_X86_INS_PEXTRB;
        return true;
    case 0x15:
        *kind = FT_PEXTRW_SSE41_RM16_XMM_IMM8;
        *id = dt_X86_INS_PEXTRW;
        return true;
    case 0x16:
        *kind = rex_w ? FT_PEXTRQ_R64_XMM_IMM8 : FT_PEXTR_GPR_XMM_IMM8;
        *id = rex_w ? dt_X86_INS_PEXTRQ : dt_X86_INS_PEXTRD;
        return true;
    case 0x17:
        *kind = FT_EXTRACTPS_RM32_XMM_IMM8;
        *id = dt_X86_INS_EXTRACTPS;
        return true;
    case 0x20:
        *kind = FT_PINSR_XMM_GPR_IMM8;
        *id = dt_X86_INS_PINSRB;
        return true;
    case 0x21:
        *kind = FT_INSERTPS_XMM_XMMM_IMM8;
        *id = dt_X86_INS_INSERTPS;
        return true;
    case 0x22:
        *kind = FT_PINSR_XMM_GPR_IMM8;
        *id = rex_w ? dt_X86_INS_PINSRQ : dt_X86_INS_PINSRD;
        return true;
    case 0x40:
        *kind = FT_DP_XMM_XMMM_IMM8;
        *id = dt_X86_INS_DPPS;
        return true;
    case 0x41:
        *kind = FT_DP_XMM_XMMM_IMM8;
        *id = dt_X86_INS_DPPD;
        return true;
    case 0x42:
        *kind = FT_MPSADBW_XMM_XMMM_IMM8;
        *id = dt_X86_INS_MPSADBW;
        return true;
    case 0x44:
        *kind = FT_PCLMULQDQ_XMM_XMMM_IMM8;
        *id = dt_X86_INS_PCLMULQDQ;
        return true;
    case 0x60:
        *kind = FT_HELPER_PCMPESTRM;
        *id = dt_X86_INS_PCMPESTRM;
        return true;
    case 0x61:
        *kind = FT_HELPER_PCMPESTRI;
        *id = dt_X86_INS_PCMPESTRI;
        return true;
    case 0x62:
        *kind = FT_HELPER_PCMPISTRM;
        *id = dt_X86_INS_PCMPISTRM;
        return true;
    case 0x63:
        *kind = FT_HELPER_PCMPISTRI;
        *id = dt_X86_INS_PCMPISTRI;
        return true;
    case 0xdf:
        *kind = FT_AESKEYGEN_XMM_XMMM_IMM8;
        *id = dt_X86_INS_AESKEYGENASSIST;
        return true;
    default:
        return false;
    }
}

static bool fd_ft_sse38_opcode_info(uint8_t opcode, FastTemplateKind *kind,
                                    int *id)
{
    switch (opcode) {
    case 0x00:
        *kind = FT_PSHUFB_XMM_XMMM;
        *id = dt_X86_INS_PSHUFB;
        return true;
    case 0x01:
        *kind = FT_PHADD_SUB_XMM_XMMM;
        *id = dt_X86_INS_PHADDW;
        return true;
    case 0x02:
        *kind = FT_PHADD_SUB_XMM_XMMM;
        *id = dt_X86_INS_PHADDD;
        return true;
    case 0x03:
        *kind = FT_PHADD_SUB_XMM_XMMM;
        *id = dt_X86_INS_PHADDSW;
        return true;
    case 0x04:
        *kind = FT_SIMD_MADD_XMM_XMM;
        *id = dt_X86_INS_PMADDUBSW;
        return true;
    case 0x05:
        *kind = FT_PHADD_SUB_XMM_XMMM;
        *id = dt_X86_INS_PHSUBW;
        return true;
    case 0x06:
        *kind = FT_PHADD_SUB_XMM_XMMM;
        *id = dt_X86_INS_PHSUBD;
        return true;
    case 0x07:
        *kind = FT_PHADD_SUB_XMM_XMMM;
        *id = dt_X86_INS_PHSUBSW;
        return true;
    case 0x10:
        *kind = FT_BLENDV_XMM_XMMM;
        *id = dt_X86_INS_PBLENDVB;
        return true;
    case 0x14:
        *kind = FT_BLENDV_XMM_XMMM;
        *id = dt_X86_INS_BLENDVPS;
        return true;
    case 0x15:
        *kind = FT_BLENDV_XMM_XMMM;
        *id = dt_X86_INS_BLENDVPD;
        return true;
    case 0x17:
        *kind = FT_PTEST_XMM_XMMM;
        *id = dt_X86_INS_PTEST;
        return true;
    case 0x0b:
        *kind = FT_SIMD_MADD_XMM_XMM;
        *id = dt_X86_INS_PMULHRSW;
        return true;
    case 0x20:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVSXBW;
        return true;
    case 0x21:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVSXBD;
        return true;
    case 0x22:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVSXBQ;
        return true;
    case 0x23:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVSXWD;
        return true;
    case 0x24:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVSXWQ;
        return true;
    case 0x25:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVSXDQ;
        return true;
    case 0x2b:
        *kind = FT_PACK_XMM_XMM;
        *id = dt_X86_INS_PACKUSDW;
        return true;
    case 0x29:
        *kind = FT_PCMPEQB_XMM_XMMM;
        *id = dt_X86_INS_PCMPEQQ;
        return true;
    case 0x30:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVZXBW;
        return true;
    case 0x31:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVZXBD;
        return true;
    case 0x32:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVZXBQ;
        return true;
    case 0x33:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVZXWD;
        return true;
    case 0x34:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVZXWQ;
        return true;
    case 0x35:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_PMOVZXDQ;
        return true;
    case 0x41:
        *kind = FT_PHMINPOSUW_XMM_XMMM;
        *id = dt_X86_INS_PHMINPOSUW;
        return true;
    case 0x2a:
        *kind = FT_MOV128_XMM_XMMM;
        *id = dt_X86_INS_MOVNTDQA;
        return true;
    case 0xdb:
        *kind = FT_AESIMC_XMM_XMMM;
        *id = dt_X86_INS_AESIMC;
        return true;
    case 0xdc:
        *kind = FT_AES_ROUND_XMM_XMMM;
        *id = dt_X86_INS_AESENC;
        return true;
    case 0xdd:
        *kind = FT_AES_ROUND_XMM_XMMM;
        *id = dt_X86_INS_AESENCLAST;
        return true;
    case 0xde:
        *kind = FT_AES_ROUND_XMM_XMMM;
        *id = dt_X86_INS_AESDEC;
        return true;
    case 0xdf:
        *kind = FT_AES_ROUND_XMM_XMMM;
        *id = dt_X86_INS_AESDECLAST;
        return true;
    default:
        return false;
    }
}

static bool fd_ft_mmx_sse38_opcode_info(uint8_t opcode,
                                        FastTemplateKind *kind, int *id)
{
    switch (opcode) {
    case 0x00:
        *kind = FT_PSHUFB_MMX_MMXM64;
        *id = dt_X86_INS_PSHUFB;
        return true;
    case 0x01:
        *id = dt_X86_INS_PHADDW;
        *kind = FT_PHADD_SUB_MMX_MMXM64;
        return true;
    case 0x02:
        *id = dt_X86_INS_PHADDD;
        *kind = FT_PHADD_SUB_MMX_MMXM64;
        return true;
    case 0x03:
        *id = dt_X86_INS_PHADDSW;
        *kind = FT_PHADD_SUB_MMX_MMXM64;
        return true;
    case 0x05:
        *id = dt_X86_INS_PHSUBW;
        *kind = FT_PHADD_SUB_MMX_MMXM64;
        return true;
    case 0x06:
        *id = dt_X86_INS_PHSUBD;
        *kind = FT_PHADD_SUB_MMX_MMXM64;
        return true;
    case 0x07:
        *id = dt_X86_INS_PHSUBSW;
        *kind = FT_PHADD_SUB_MMX_MMXM64;
        return true;
    case 0x04:
        *id = dt_X86_INS_PMADDUBSW;
        *kind = FT_SIMD_MADD_MMX_MMXM64;
        return true;
    case 0x0b:
        *id = dt_X86_INS_PMULHRSW;
        *kind = FT_SIMD_MADD_MMX_MMXM64;
        return true;
    case 0x08:
        *id = dt_X86_INS_PSIGNB;
        *kind = FT_SIMD_BIN_MMX_MMXM64;
        return true;
    case 0x09:
        *id = dt_X86_INS_PSIGNW;
        *kind = FT_SIMD_BIN_MMX_MMXM64;
        return true;
    case 0x0a:
        *id = dt_X86_INS_PSIGND;
        *kind = FT_SIMD_BIN_MMX_MMXM64;
        return true;
    case 0x1c:
        *id = dt_X86_INS_PABSB;
        *kind = FT_SIMD_BIN_MMX_MMXM64;
        return true;
    case 0x1d:
        *id = dt_X86_INS_PABSW;
        *kind = FT_SIMD_BIN_MMX_MMXM64;
        return true;
    case 0x1e:
        *id = dt_X86_INS_PABSD;
        *kind = FT_SIMD_BIN_MMX_MMXM64;
        return true;
    default:
        return false;
    }
}

static bool fd_ft_sha38_opcode_info(uint8_t opcode, FastTemplateKind *kind,
                                    int *id)
{
    *kind = FT_SHA_XMM_XMMM;
    switch (opcode) {
    case 0xc8:
        *id = dt_X86_INS_SHA1NEXTE;
        return true;
    case 0xc9:
        *id = dt_X86_INS_SHA1MSG1;
        return true;
    case 0xca:
        *id = dt_X86_INS_SHA1MSG2;
        return true;
    case 0xcb:
        *id = dt_X86_INS_SHA256RNDS2;
        return true;
    case 0xcc:
        *id = dt_X86_INS_SHA256MSG1;
        return true;
    case 0xcd:
        *id = dt_X86_INS_SHA256MSG2;
        return true;
    default:
        return false;
    }
}

static FastDecoderFTMatch fd_ft_try_sse_three_byte(FDState *s,
                                                   uint8_t opcode0,
                                                   uint8_t opcode1,
                                                   uint64_t address,
                                                   FastDecodedFT *decoded)
{
    FastTemplateKind kind;
    int id;
    int opcode2;
    bool has_imm8 = false;

    if (opcode0 != 0x0f || (opcode1 != 0x38 && opcode1 != 0x3a)) {
        return FD_FT_NO_MATCH;
    }

    opcode2 = fd_read_byte(s);
    if (opcode2 < 0) {
        return FD_FT_REJECT;
    }

    if (s->prefix[2] == 0 && s->prefix[0] == 0) {
        if (opcode1 == 0x3a && opcode2 == 0x0f) {
            kind = FT_PALIGNR_MMX_MMXM64_IMM8;
            id = dt_X86_INS_PALIGNR;
            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode2, id);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }
        if (opcode1 == 0x38 &&
            fd_ft_mmx_sse38_opcode_info(opcode2, &kind, &id)) {
            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode2, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }
        if (opcode1 == 0x38 &&
            fd_ft_sha38_opcode_info(opcode2, &kind, &id)) {
            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode2, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }
        if (opcode1 == 0x3a && opcode2 == 0xcc) {
            kind = FT_SHA1RNDS4_XMM_XMMM_IMM8;
            id = dt_X86_INS_SHA1RNDS4;
            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode2, id);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }
        return FD_FT_NO_MATCH;
    }

    if (s->prefix[2] != dt_X86_PREFIX_OPSIZE) {
        return FD_FT_NO_MATCH;
    }

    if (opcode1 == 0x3a) {
        if (!fd_ft_sse3a_opcode_info(opcode2, s->rex_w, &kind, &id,
                                     &has_imm8)) {
            return FD_FT_NO_MATCH;
        }
    } else {
        if (!fd_ft_sse38_opcode_info(opcode2, &kind, &id)) {
            if (!fd_ft_simd_bin_opcode_info(s->prefix[0], s->prefix[2],
                                            opcode2, &id)) {
                return FD_FT_NO_MATCH;
            }
            kind = FT_SIMD_BIN_XMM_XMMM;
        }
    }

    fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                      opcode2, id);
    if (has_imm8) {
        if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
    } else if (!fd_ft_read_modrm(s, &decoded->fields)) {
        return FD_FT_REJECT;
    }
    return fd_ft_finish_match(decoded, s, kind, false);
}

static bool fd_ft_vex_opcode_info(uint8_t opcode, FastTemplateKind *kind,
                                  int *id)
{
    switch (opcode) {
    case 0x21:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_VPMOVSXBD;
        return true;
    case 0x22:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_VPMOVSXBQ;
        return true;
    case 0x31:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_VPMOVZXBD;
        return true;
    case 0x32:
        *kind = FT_PMOVX_XMM_XMMM;
        *id = dt_X86_INS_VPMOVZXBQ;
        return true;
    case 0x98:
        *kind = FT_FMA132_XMM_XMMM;
        *id = dt_X86_INS_VFMADD132PS;
        return true;
    case 0x9a:
        *kind = FT_FMA132_XMM_XMMM;
        *id = dt_X86_INS_VFMSUB132PS;
        return true;
    default:
        return false;
    }
}

static FastDecoderFTMatch fd_ft_try_sse_vex3(FDState *s, uint8_t opcode0,
                                             uint64_t address,
                                             FastDecodedFT *decoded)
{
    FastTemplateKind kind;
    int id;
    int vex2;
    int vex3;
    int opcode;

    if (opcode0 != 0xc4) {
        return FD_FT_NO_MATCH;
    }

    vex2 = fd_read_byte(s);
    vex3 = fd_read_byte(s);
    opcode = fd_read_byte(s);
    if (vex2 < 0 || vex3 < 0 || opcode < 0) {
        return FD_FT_REJECT;
    }
    if ((vex2 & 0x1f) != 2) {
        return FD_FT_NO_MATCH;
    }
    if (!fd_ft_vex_opcode_info(opcode, &kind, &id)) {
        return FD_FT_NO_MATCH;
    }

    s->rex_r = ((~vex2 >> 7) & 1) << 3;
    s->rex_x = ((~vex2 >> 6) & 1) << 3;
    s->rex_b = ((~vex2 >> 5) & 1) << 3;
    s->rex_w = (vex3 >> 7) & 1;
    s->rex = 0x40 | (s->rex_w << 3) | (s->rex_r >> 1) |
             (s->rex_x >> 2) | (s->rex_b >> 3);
    s->has_rex = 1;
    s->vex_v = (~vex3 >> 3) & 0xf;

    fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                      opcode, id);
    decoded->fields.vex_v = s->vex_v;
    if (!fd_ft_read_modrm(s, &decoded->fields)) {
        return FD_FT_REJECT;
    }
    return fd_ft_finish_match(decoded, s, kind, false);
}

static inline FastDecoderFTMatch fd_ft_try_sse(FDState *s, uint8_t opcode0,
                                               uint8_t opcode1, bool two_byte,
                                               uint64_t address,
                                               FastDecodedFT *decoded)
{
    if (!two_byte) {
        FastDecoderFTMatch match = fd_ft_try_sse_vex3(s, opcode0, address,
                                                      decoded);
        if (match != FD_FT_NO_MATCH) {
            return match;
        }
    }

    if (two_byte) {
        bool store;
        FastDecoderFTMatch match;

        match = fd_ft_try_sse_three_byte(s, opcode0, opcode1, address,
                                         decoded);
        if (match != FD_FT_NO_MATCH) {
            return match;
        }
        if (opcode1 == 0x38 || opcode1 == 0x3a) {
            return FD_FT_NO_MATCH;
        }

        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            (opcode1 == 0x6e || opcode1 == 0x7e)) {
            FastTemplateKind kind;
            int id;

            if (opcode1 == 0x6e) {
                kind = s->rex_w ? FT_MOVQ_XMM_R64 : FT_MOVD_XMM_R32;
                id = s->rex_w ? dt_X86_INS_MOVQ : dt_X86_INS_MOVD;
            } else {
                kind = s->rex_w ? FT_MOVQ_R64_XMM : FT_MOVD_R32_XMM;
                id = s->rex_w ? dt_X86_INS_MOVQ : dt_X86_INS_MOVD;
            }
            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            if (s->rex_w && decoded->fields.modrm_mod != 3) {
                kind = opcode1 == 0x6e ? FT_MOVQ_XMM_RM64 : FT_MOVQ_RM64_XMM;
                decoded->fields.kind = kind;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && !s->rex_w &&
            (opcode1 == 0x6e || opcode1 == 0x7e)) {
            FastTemplateKind kind = opcode1 == 0x6e ?
                                    FT_MOVD_MMX_RM32 :
                                    FT_MOVD_RM32_MMX;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, dt_X86_INS_MOVD);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && s->rex_w &&
            opcode1 == 0x6e) {
            fd_ft_init_fields(&decoded->fields, FT_MOVQ_MMX_RM64_GPR, s,
                              address, opcode0, opcode1, dt_X86_INS_MOVQ);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_MOVQ_MMX_RM64_GPR,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            (opcode1 == 0x6f || opcode1 == 0x7f ||
             (opcode1 == 0x7e && s->rex_w))) {
            FastTemplateKind kind;

            if (opcode1 == 0x6f) {
                kind = FT_MOVQ_MMX_RM64;
            } else if (opcode1 == 0x7f) {
                kind = FT_MOVQ_MMXM64_MMX;
            } else if (opcode1 == 0x7e && s->rex_w) {
                kind = FT_MOVQ_RM64_MMX;
            } else {
                return FD_FT_NO_MATCH;
            }

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, dt_X86_INS_MOVQ);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0x77) {
            fd_ft_init_fields(&decoded->fields, FT_EMMS, s, address,
                              opcode0, opcode1, dt_X86_INS_EMMS);
            return fd_ft_finish_match(decoded, s, FT_EMMS, false);
        }

        if (fd_ft_mov128_opcode_supported(s->prefix[0], s->prefix[2],
                                          opcode1, &store)) {
            FastTemplateKind kind = store ? FT_MOV128_XMMM_XMM :
                                            FT_MOV128_XMM_XMMM;
            int id = (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ?
                     dt_X86_INS_MOVAPD : dt_X86_INS_MOVAPS;

            if (opcode1 == 0x10 || opcode1 == 0x11) {
                id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                     dt_X86_INS_MOVUPD : dt_X86_INS_MOVUPS;
            } else if (opcode1 == 0x6f || opcode1 == 0x7f) {
                id = s->prefix[0] == dt_X86_PREFIX_REP ?
                     dt_X86_INS_MOVDQU : dt_X86_INS_MOVDQA;
            }
            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xc5) {
            fd_ft_init_fields(&decoded->fields, FT_PEXTRW_R32_MMX_IMM8, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PEXTRW);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            if (decoded->fields.modrm_mod != 3) {
                return FD_FT_NO_MATCH;
            }
            return fd_ft_finish_match(decoded, s, FT_PEXTRW_R32_MMX_IMM8,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xc4) {
            fd_ft_init_fields(&decoded->fields, FT_PINSRW_MMX_RM16_IMM8, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PINSRW);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s,
                                      FT_PINSRW_MMX_RM16_IMM8, false);
        }

        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            (opcode1 == 0xc4 || opcode1 == 0xc5)) {
            FastTemplateKind kind = opcode1 == 0xc5 ?
                                    FT_PEXTRW_R32_XMM_IMM8 :
                                    FT_PINSR_XMM_GPR_IMM8;
            int id = opcode1 == 0xc5 ? dt_X86_INS_PEXTRW :
                                        dt_X86_INS_PINSRW;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 &&
            (s->prefix[2] == dt_X86_PREFIX_OPSIZE || s->prefix[2] == 0) &&
            (opcode1 == 0x71 || opcode1 == 0x72 || opcode1 == 0x73)) {
            static const int pshift_id[3][8] = {
                {
                    dt_X86_INS_INVALID, dt_X86_INS_INVALID,
                    dt_X86_INS_PSRLW, dt_X86_INS_INVALID,
                    dt_X86_INS_PSRAW, dt_X86_INS_INVALID,
                    dt_X86_INS_PSLLW, dt_X86_INS_INVALID,
                },
                {
                    dt_X86_INS_INVALID, dt_X86_INS_INVALID,
                    dt_X86_INS_PSRLD, dt_X86_INS_INVALID,
                    dt_X86_INS_PSRAD, dt_X86_INS_INVALID,
                    dt_X86_INS_PSLLD, dt_X86_INS_INVALID,
                },
                {
                    dt_X86_INS_INVALID, dt_X86_INS_INVALID,
                    dt_X86_INS_PSRLQ, dt_X86_INS_PSRLDQ,
                    dt_X86_INS_INVALID, dt_X86_INS_INVALID,
                    dt_X86_INS_PSLLQ, dt_X86_INS_PSLLDQ,
                },
            };
            FastTemplateKind kind;
            int ext;
            int id;
            bool is_mmx = s->prefix[2] == 0;

            fd_ft_init_fields(&decoded->fields, FT_PSHIFT_XMM_IMM8, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_INVALID);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            if (((decoded->fields.modrm >> 6) & 3) != 3) {
                return FD_FT_NO_MATCH;
            }
            ext = (decoded->fields.modrm >> 3) & 7;
            id = pshift_id[opcode1 - 0x71][ext];
            if (id == dt_X86_INS_INVALID) {
                return FD_FT_NO_MATCH;
            }
            if (is_mmx) {
                if (opcode1 == 0x73 && ext != 2 && ext != 6) {
                    return FD_FT_NO_MATCH;
                }
                kind = FT_PSHIFT_MMX_IMM8;
            } else if (opcode1 == 0x73 && ext == 2) {
                kind = FT_PSRLQ_XMM_IMM8;
            } else if (opcode1 == 0x73 && ext == 6) {
                kind = FT_PSLLQ_XMM_IMM8;
            } else if (opcode1 == 0x73 && ext == 3) {
                kind = FT_PSRLDQ_XMM_IMM8;
            } else if (opcode1 == 0x73 && ext == 7) {
                kind = FT_PSLLDQ_XMM_IMM8;
            } else {
                kind = FT_PSHIFT_XMM_IMM8;
            }
            decoded->fields.kind = kind;
            decoded->fields.id = id;
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE && opcode1 == 0xf6) {
            fd_ft_init_fields(&decoded->fields, FT_PSADBW_XMM_XMMM, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PSADBW);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PSADBW_XMM_XMMM,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xf6) {
            fd_ft_init_fields(&decoded->fields, FT_PSADBW_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PSADBW);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PSADBW_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xd5) {
            fd_ft_init_fields(&decoded->fields, FT_PMULLW_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PMULLW);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PMULLW_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            (opcode1 == 0xe4 || opcode1 == 0xe5)) {
            FastTemplateKind kind = opcode1 == 0xe4 ?
                                    FT_PMULHUW_MMX_MMXM64 :
                                    FT_PMULHW_MMX_MMXM64;
            int id = opcode1 == 0xe4 ? dt_X86_INS_PMULHUW :
                                      dt_X86_INS_PMULHW;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            (opcode1 == 0xe1 || opcode1 == 0xe2)) {
            FastTemplateKind kind = opcode1 == 0xe1 ?
                                    FT_PSRAW_MMX_MMXM64 :
                                    FT_PSRAD_MMX_MMXM64;
            int id = opcode1 == 0xe1 ? dt_X86_INS_PSRAW :
                                      dt_X86_INS_PSRAD;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0x70) {
            fd_ft_init_fields(&decoded->fields, FT_PSHUFW_MMX_MMXM_IMM8,
                              s, address, opcode0, opcode1,
                              dt_X86_INS_PSHUFW);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PSHUFW_MMX_MMXM_IMM8,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            opcode1 >= 0xf8 && opcode1 <= 0xfb) {
            FastTemplateKind kind = opcode1 == 0xf8 ? FT_PSUBB_MMX_MMXM64 :
                                    opcode1 == 0xf9 ? FT_PSUBW_MMX_MMXM64 :
                                    opcode1 == 0xfa ? FT_PSUBD_MMX_MMXM64 :
                                                      FT_PSUBQ_MMX_MMXM64;
            int id = opcode1 == 0xf8 ? dt_X86_INS_PSUBB :
                     opcode1 == 0xf9 ? dt_X86_INS_PSUBW :
                     opcode1 == 0xfa ? dt_X86_INS_PSUBD :
                                       dt_X86_INS_PSUBQ;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xd8) {
            fd_ft_init_fields(&decoded->fields, FT_PSUBUSB_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PSUBUSB);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PSUBUSB_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            (opcode1 == 0xe8 || opcode1 == 0xe9)) {
            FastTemplateKind kind = opcode1 == 0xe8 ?
                                    FT_PSUBSB_MMX_MMXM64 :
                                    FT_PSUBSW_MMX_MMXM64;
            int id = opcode1 == 0xe8 ? dt_X86_INS_PSUBSB :
                                       dt_X86_INS_PSUBSW;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xd9) {
            fd_ft_init_fields(&decoded->fields, FT_PSUBUSW_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PSUBUSW);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PSUBUSW_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xdc) {
            fd_ft_init_fields(&decoded->fields, FT_PADDUSB_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PADDUSB);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PADDUSB_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xdd) {
            fd_ft_init_fields(&decoded->fields, FT_PADDUSW_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PADDUSW);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PADDUSW_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            (opcode1 == 0xec || opcode1 == 0xed)) {
            FastTemplateKind kind = opcode1 == 0xec ?
                                    FT_PADDSB_MMX_MMXM64 :
                                    FT_PADDSW_MMX_MMXM64;
            int id = opcode1 == 0xec ? dt_X86_INS_PADDSB :
                                      dt_X86_INS_PADDSW;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            (opcode1 == 0xe0 || opcode1 == 0xe3)) {
            FastTemplateKind kind = opcode1 == 0xe0 ?
                                    FT_PAVGB_MMX_MMXM64 :
                                    FT_PAVGW_MMX_MMXM64;
            int id = opcode1 == 0xe0 ? dt_X86_INS_PAVGB :
                                      dt_X86_INS_PAVGW;

            fd_ft_init_fields(&decoded->fields, kind, s,
                              address, opcode0, opcode1,
                              id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            (opcode1 == 0xdb || opcode1 == 0xdf)) {
            FastTemplateKind kind = opcode1 == 0xdb ?
                                    FT_PAND_MMX_MMXM64 :
                                    FT_PANDN_MMX_MMXM64;
            int id = opcode1 == 0xdb ? dt_X86_INS_PAND :
                                      dt_X86_INS_PANDN;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xeb) {
            fd_ft_init_fields(&decoded->fields, FT_POR_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_POR);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_POR_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xef) {
            fd_ft_init_fields(&decoded->fields, FT_PXOR_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PXOR);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PXOR_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            (opcode1 == 0x63 || opcode1 == 0x67 || opcode1 == 0x6b)) {
            FastTemplateKind kind = opcode1 == 0x63 ?
                                    FT_PACKSSWB_MMX_MMXM64 :
                                    opcode1 == 0x67 ?
                                    FT_PACKUSWB_MMX_MMXM64 :
                                    FT_PACKSSDW_MMX_MMXM64;
            int id = opcode1 == 0x63 ? dt_X86_INS_PACKSSWB :
                     opcode1 == 0x67 ? dt_X86_INS_PACKUSWB :
                                       dt_X86_INS_PACKSSDW;

            fd_ft_init_fields(&decoded->fields, kind, s, address,
                              opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xf5) {
            fd_ft_init_fields(&decoded->fields, FT_PMADDWD_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PMADDWD);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PMADDWD_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xee) {
            fd_ft_init_fields(&decoded->fields, FT_PMAXSW_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PMAXSW);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PMAXSW_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xea) {
            fd_ft_init_fields(&decoded->fields, FT_PMINSW_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PMINSW);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PMINSW_MMX_MMXM64,
                                      false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
            (opcode1 == 0xd4 || opcode1 == 0xfc || opcode1 == 0xfe)) {
            FastTemplateKind kind = opcode1 == 0xd4 ?
                                    FT_PADDQ_MMX_MMXM64 :
                                    opcode1 == 0xfc ?
                                    FT_PADDB_MMX_MMXM64 :
                                    FT_PADDD_MMX_MMXM64;
            int id = opcode1 == 0xd4 ? dt_X86_INS_PADDQ :
                     opcode1 == 0xfc ? dt_X86_INS_PADDB :
                                      dt_X86_INS_PADDD;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xfd) {
            fd_ft_init_fields(&decoded->fields, FT_PADDW_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PADDW);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PADDW_MMX_MMXM64,
                                      false);
        }

        if (opcode1 == 0xd6 &&
            (s->prefix[0] == dt_X86_PREFIX_REPNE ||
             s->prefix[0] == dt_X86_PREFIX_REP) &&
            s->prefix[2] == 0) {
            FastTemplateKind kind = s->prefix[0] == dt_X86_PREFIX_REPNE ?
                                    FT_MOVDQ2Q_MMX_XMM :
                                    FT_MOVQ2DQ_XMM_MMX;
            int id = s->prefix[0] == dt_X86_PREFIX_REPNE ?
                     dt_X86_INS_MOVDQ2Q : dt_X86_INS_MOVQ2DQ;

            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields) ||
                ((decoded->fields.modrm >> 6) & 3) != 3) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xae) {
            FastTemplateKind kind;
            int id;

            fd_ft_init_fields(&decoded->fields, FT_STMXCSR_M32, s, address,
                              opcode0, opcode1, dt_X86_INS_STMXCSR);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            if (decoded->fields.modrm_mod == 3) {
                return FD_FT_NO_MATCH;
            }
            switch (decoded->fields.modrm_reg) {
            case 0:
                kind = FT_HELPER_FXSAVE;
                id = dt_X86_INS_FXSAVE;
                break;
            case 1:
                kind = FT_HELPER_FXRSTOR;
                id = dt_X86_INS_FXRSTOR;
                break;
            case 2:
                kind = FT_HELPER_LDMXCSR;
                id = dt_X86_INS_LDMXCSR;
                break;
            case 3:
                kind = FT_STMXCSR_M32;
                id = dt_X86_INS_STMXCSR;
                break;
            case 4:
                kind = FT_HELPER_XSAVE;
                id = dt_X86_INS_XSAVE;
                break;
            case 5:
                kind = FT_HELPER_XRSTOR;
                id = dt_X86_INS_XRSTOR;
                break;
            case 6:
                kind = FT_HELPER_XSAVEOPT;
                id = dt_X86_INS_XSAVEOPT;
                break;
            default:
                return FD_FT_NO_MATCH;
            }
            decoded->fields.kind = kind;
            decoded->fields.id = id;
            return fd_ft_finish_match(decoded, s, kind,
                                      kind == FT_HELPER_FXRSTOR ||
                                      kind == FT_HELPER_XRSTOR);
        }
    }

    if (two_byte && (opcode1 == 0x10 || opcode1 == 0x11) &&
        (s->prefix[0] == dt_X86_PREFIX_REPNE ||
         s->prefix[0] == dt_X86_PREFIX_REP)) {
        FastTemplateKind kind = opcode1 == 0x10 ? FT_MOVSD_XMM_M64 :
                                                  FT_MOVSD_M64_XMM;
        int id = s->prefix[0] == dt_X86_PREFIX_REPNE ? dt_X86_INS_MOVSD :
                                                        dt_X86_INS_MOVSS;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, id);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte) {
        int id;

        if (fd_ft_simd_bin_opcode_info(s->prefix[0], s->prefix[2],
                                       opcode1, &id)) {
            fd_ft_init_fields(&decoded->fields, FT_SIMD_BIN_XMM_XMMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_SIMD_BIN_XMM_XMMM,
                                      false);
        }
    }

    if (two_byte) {
        int id;
        FastTemplateKind kind = FT_UNSUPPORTED;

        if (s->prefix[0] == 0 && s->prefix[2] == 0) {
            switch (opcode1) {
            case 0x74:
                kind = FT_PCMPEQB_MMX_MMXM64;
                id = dt_X86_INS_PCMPEQB;
                break;
            case 0x75:
                kind = FT_PCMPEQW_MMX_MMXM64;
                id = dt_X86_INS_PCMPEQW;
                break;
            case 0x76:
                kind = FT_PCMPEQD_MMX_MMXM64;
                id = dt_X86_INS_PCMPEQD;
                break;
            case 0x64:
                kind = FT_PCMPGTB_MMX_MMXM64;
                id = dt_X86_INS_PCMPGTB;
                break;
            case 0x65:
                kind = FT_PCMPGTW_MMX_MMXM64;
                id = dt_X86_INS_PCMPGTW;
                break;
            case 0x66:
                kind = FT_PCMPGTD_MMX_MMXM64;
                id = dt_X86_INS_PCMPGTD;
                break;
            default:
                break;
            }
        }
        if (kind != FT_UNSUPPORTED) {
            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            fd_ft_padd_opcode_info(opcode1, &id)) {
            fd_ft_init_fields(&decoded->fields, FT_PADD_XMM_XMMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PADD_XMM_XMMM, false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            fd_ft_pcmpeq_opcode_info(opcode1, &id)) {
            fd_ft_init_fields(&decoded->fields, FT_PCMPEQB_XMM_XMMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PCMPEQB_XMM_XMMM,
                                      false);
        }
        if (s->prefix[0] == 0 && fd_ft_punpck_opcode_info(s->prefix[2],
                                                           opcode1, &id)) {
            fd_ft_init_fields(&decoded->fields, FT_PUNPCK_XMM_XMMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PUNPCK_XMM_XMMM,
                                      false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            (opcode1 == 0x14 || opcode1 == 0x15)) {
            id = opcode1 == 0x14 ? dt_X86_INS_UNPCKLPD :
                                    dt_X86_INS_UNPCKHPD;
            fd_ft_init_fields(&decoded->fields, FT_UNPCKPD_XMM_XMMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_UNPCKPD_XMM_XMMM,
                                      false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            opcode1 == 0xef) {
            fd_ft_init_fields(&decoded->fields, FT_PXOR_XMM_XMMM, s,
                              address, opcode0, opcode1, dt_X86_INS_PXOR);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PXOR_XMM_XMMM, false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xf4) {
            fd_ft_init_fields(&decoded->fields, FT_PMULUDQ_MMX_MMXM64, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PMULUDQ);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PMULUDQ_MMX_MMXM64,
                                      false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            opcode1 == 0xf4) {
            fd_ft_init_fields(&decoded->fields, FT_PMULUDQ_XMM_XMMM, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PMULUDQ);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PMULUDQ_XMM_XMMM,
                                      false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xd7) {
            fd_ft_init_fields(&decoded->fields, FT_PMOVMSKB_R32_MMX, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PMOVMSKB);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            if (decoded->fields.modrm_mod != 3) {
                return FD_FT_NO_MATCH;
            }
            return fd_ft_finish_match(decoded, s, FT_PMOVMSKB_R32_MMX,
                                      false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            opcode1 == 0xd7) {
            fd_ft_init_fields(&decoded->fields, FT_PMOVMSKB_R32_XMM, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PMOVMSKB);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PMOVMSKB_R32_XMM,
                                      false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == 0 && opcode1 == 0xf7) {
            fd_ft_init_fields(&decoded->fields, FT_MASKMOVQ_MMX_MMX, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_MASKMOVQ);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            if (decoded->fields.modrm_mod != 3) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_MASKMOVQ_MMX_MMX,
                                      false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            opcode1 == 0xf7) {
            fd_ft_init_fields(&decoded->fields, FT_MASKMOVDQU_XMM_XMM, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_MASKMOVDQU);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            if (decoded->fields.modrm_mod != 3) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_MASKMOVDQU_XMM_XMM,
                                      false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            (opcode1 == 0x63 || opcode1 == 0x67 ||
             opcode1 == 0x6b)) {
            id = opcode1 == 0x63 ? dt_X86_INS_PACKSSWB :
                 opcode1 == 0x67 ? dt_X86_INS_PACKUSWB :
                                    dt_X86_INS_PACKSSDW;
            fd_ft_init_fields(&decoded->fields, FT_PACK_XMM_XMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PACK_XMM_XMM, false);
        }
        if (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE &&
            opcode1 == 0xf5) {
            fd_ft_init_fields(&decoded->fields, FT_SIMD_MADD_XMM_XMM, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_PMADDWD);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_SIMD_MADD_XMM_XMM,
                                      false);
        }
        if (opcode1 == 0x50 && s->prefix[0] == 0 &&
            (s->prefix[2] == 0 || s->prefix[2] == dt_X86_PREFIX_OPSIZE)) {
            id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                 dt_X86_INS_MOVMSKPD : dt_X86_INS_MOVMSKPS;
            fd_ft_init_fields(&decoded->fields, FT_PMOVMSKB_R32_XMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_PMOVMSKB_R32_XMM,
                                      false);
        }
        if ((opcode1 == 0xc6) && s->prefix[0] == 0 &&
            (s->prefix[2] == 0 || s->prefix[2] == dt_X86_PREFIX_OPSIZE)) {
            id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                 dt_X86_INS_SHUFPD : dt_X86_INS_SHUFPS;
            fd_ft_init_fields(&decoded->fields, FT_SHUF_XMM_XMMM_IMM8, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_SHUF_XMM_XMMM_IMM8,
                                      false);
        }
        if (opcode1 == 0x70 &&
            ((s->prefix[0] == dt_X86_PREFIX_REPNE && s->prefix[2] == 0) ||
             (s->prefix[0] == dt_X86_PREFIX_REP && s->prefix[2] == 0) ||
             (s->prefix[0] == 0 && s->prefix[2] == dt_X86_PREFIX_OPSIZE))) {
            id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ? dt_X86_INS_PSHUFD :
                 s->prefix[0] == dt_X86_PREFIX_REPNE ? dt_X86_INS_PSHUFLW :
                                                        dt_X86_INS_PSHUFHW;
            fd_ft_init_fields(&decoded->fields, FT_SHUF_XMM_XMMM_IMM8, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_SHUF_XMM_XMMM_IMM8,
                                      false);
        }
        if ((opcode1 == 0x7c || opcode1 == 0x7d) &&
            ((s->prefix[2] == dt_X86_PREFIX_OPSIZE && s->prefix[0] == 0) ||
             (s->prefix[0] == dt_X86_PREFIX_REPNE && s->prefix[2] == 0))) {
            if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
                id = opcode1 == 0x7c ? dt_X86_INS_HADDPD :
                                        dt_X86_INS_HSUBPD;
            } else {
                id = opcode1 == 0x7c ? dt_X86_INS_HADDPS :
                                        dt_X86_INS_HSUBPS;
            }
            fd_ft_init_fields(&decoded->fields, FT_HADD_SUB_XMM_XMMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_HADD_SUB_XMM_XMMM,
                                      false);
        }
        if ((opcode1 == 0x12 || opcode1 == 0x16) &&
            (s->prefix[0] == dt_X86_PREFIX_REPNE ||
             s->prefix[0] == dt_X86_PREFIX_REP)) {
            id = opcode1 == 0x12 ?
                 (s->prefix[0] == dt_X86_PREFIX_REPNE ?
                  dt_X86_INS_MOVDDUP : dt_X86_INS_MOVSLDUP) :
                 dt_X86_INS_MOVSHDUP;
            fd_ft_init_fields(&decoded->fields, FT_MOVDUP_XMM_XMMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_MOVDUP_XMM_XMMM,
                                      false);
        }
        if (opcode1 == 0xe7 && s->prefix[0] == 0 &&
            s->prefix[2] == 0) {
            fd_ft_init_fields(&decoded->fields, FT_MOVQ_MMXM64_MMX, s,
                              address, opcode0, opcode1,
                              dt_X86_INS_MOVNTQ);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_MOVQ_MMXM64_MMX,
                                      false);
        }
        if (((opcode1 == 0x2b &&
             (s->prefix[2] == 0 ||
              s->prefix[2] == dt_X86_PREFIX_OPSIZE)) ||
             (opcode1 == 0xe7 &&
              s->prefix[2] == dt_X86_PREFIX_OPSIZE)) &&
            s->prefix[0] == 0) {
            id = opcode1 == 0xe7 ? dt_X86_INS_MOVNTDQ :
                 s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                 dt_X86_INS_MOVNTPD : dt_X86_INS_MOVNTPS;
            fd_ft_init_fields(&decoded->fields, FT_MOV128_XMMM_XMM, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_MOV128_XMMM_XMM,
                                      false);
        }
        if (opcode1 == 0xf0 && s->prefix[0] == dt_X86_PREFIX_REPNE &&
            s->prefix[2] == 0) {
            fd_ft_init_fields(&decoded->fields, FT_MOV128_XMM_XMMM, s,
                              address, opcode0, opcode1, dt_X86_INS_LDDQU);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_MOV128_XMM_XMMM,
                                      false);
        }
        if ((opcode1 == 0x16 || opcode1 == 0x17) &&
            s->prefix[0] == 0 &&
            (s->prefix[2] == 0 || s->prefix[2] == dt_X86_PREFIX_OPSIZE)) {
            if (opcode1 == 0x17) {
                id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                     dt_X86_INS_MOVHPD : dt_X86_INS_MOVHPS;
            } else {
                id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                     dt_X86_INS_MOVHPD : dt_X86_INS_MOVHPS;
            }
            fd_ft_init_fields(&decoded->fields, FT_MOVHPS_XMM_M64, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_MOVHPS_XMM_M64, false);
        }
        if ((opcode1 == 0x12 || opcode1 == 0x13) &&
            s->prefix[0] == 0 &&
            (s->prefix[2] == 0 || s->prefix[2] == dt_X86_PREFIX_OPSIZE)) {
            bool load = opcode1 == 0x12;
            bool is_reg;

            fd_ft_init_fields(&decoded->fields, FT_MOVQ_XMM_RM64, s,
                              address, opcode0, opcode1, dt_X86_INS_MOVLPS);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            is_reg = ((decoded->fields.modrm >> 6) & 3) == 3;
            if (is_reg) {
                kind = FT_MOVHPS_XMM_M64;
                id = load ? dt_X86_INS_MOVHLPS : dt_X86_INS_MOVLHPS;
            } else if (load) {
                kind = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                       FT_MOVLPD_XMM_M64 : FT_MOVLPS_XMM_M64;
                id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                     dt_X86_INS_MOVLPD : dt_X86_INS_MOVLPS;
            } else {
                kind = load ? FT_MOVQ_XMM_RM64 : FT_MOVQ_RM64_XMM;
                id = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                     dt_X86_INS_MOVLPD : dt_X86_INS_MOVLPS;
            }
            decoded->fields.kind = kind;
            decoded->fields.id = id;
            return fd_ft_finish_match(decoded, s, kind, false);
        }

        if (fd_ft_simd_scalar_bin_opcode_info(s->prefix[0], opcode1, &id)) {
            fd_ft_init_fields(&decoded->fields, FT_SIMD_SCALAR_BIN_XMM_XMMM,
                              s, address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s,
                                      FT_SIMD_SCALAR_BIN_XMM_XMMM, false);
        }
        if (fd_ft_simd_scalar_cmp_opcode_info(s->prefix[0], s->prefix[2],
                                              opcode1, &id)) {
            fd_ft_init_fields(&decoded->fields, FT_SIMD_SCALAR_CMP_XMM_XMMM,
                              s, address, opcode0, opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s,
                                      FT_SIMD_SCALAR_CMP_XMM_XMMM, false);
        }
        if (fd_ft_sse_cvt_opcode_info(s->prefix[0], s->prefix[2], opcode1,
                                      &kind, &id)) {
            fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                              opcode1, id);
            if (!fd_ft_read_modrm(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, kind, false);
        }
    }

    if (two_byte && opcode1 == 0xc2) {
        int id;

        if (fd_ft_simd_cmp_imm8_info(s->prefix[0], s->prefix[2], &id)) {
            fd_ft_init_fields(&decoded->fields, FT_CMP_XMM_XMMM_IMM8, s,
                              address, opcode0, opcode1, id);
            if (!fd_ft_sse_read_modrm_imm8(s, &decoded->fields)) {
                return FD_FT_REJECT;
            }
            return fd_ft_finish_match(decoded, s, FT_CMP_XMM_XMMM_IMM8,
                                      false);
        }
    }

    if (two_byte && opcode1 == 0x7e &&
        s->prefix[0] == dt_X86_PREFIX_REP) {
        fd_ft_init_fields(&decoded->fields, FT_MOVQ_XMM_RM64, s, address,
                          opcode0, opcode1, dt_X86_INS_MOVQ);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_MOVQ_XMM_RM64, false);
    }

    if (two_byte && opcode1 == 0xd6 &&
        s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
        fd_ft_init_fields(&decoded->fields, FT_MOVQ_RM64_XMM, s, address,
                          opcode0, opcode1, dt_X86_INS_MOVQ);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_MOVQ_RM64_XMM, false);
    }

    if (two_byte && opcode1 == 0xe6 &&
        s->prefix[0] == dt_X86_PREFIX_REP) {
        FastTemplateKind kind;

        fd_ft_init_fields(&decoded->fields, FT_CVT_FP_XMM_XMMM, s,
                          address, opcode0, opcode1, dt_X86_INS_CVTDQ2PD);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        kind = decoded->fields.modrm_mod == 3 ? FT_CVTDQ2PD_XMM_XMM :
                                                FT_CVT_FP_XMM_XMMM;
        decoded->fields.kind = kind;
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (two_byte && opcode1 == 0x14 &&
        s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
        fd_ft_init_fields(&decoded->fields, FT_UNPCKPD_XMM_XMMM, s,
                          address, opcode0, opcode1, dt_X86_INS_UNPCKLPD);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_UNPCKPD_XMM_XMMM, false);
    }

    if (two_byte && opcode1 == 0x28 &&
        s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
        fd_ft_init_fields(&decoded->fields, FT_MOVAPD_XMM_M128, s,
                          address, opcode0, opcode1, dt_X86_INS_MOVAPD);
        if (!fd_ft_read_modrm(s, &decoded->fields) ||
            ((decoded->fields.modrm >> 6) & 3) == 3) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_MOVAPD_XMM_M128, false);
    }

    if (two_byte && opcode1 == 0x59 &&
        s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
        fd_ft_init_fields(&decoded->fields, FT_MULPD_XMM_XMM, s,
                          address, opcode0, opcode1, dt_X86_INS_MULPD);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, FT_MULPD_XMM_XMM, false);
    }

    if (two_byte && (opcode1 == 0x10 || opcode1 == 0x11) &&
        s->prefix[0] == dt_X86_PREFIX_REPNE) {
        FastTemplateKind kind = opcode1 == 0x10 ? FT_MOVSD_XMM_M64 :
                                                  FT_MOVSD_M64_XMM;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0,
                          opcode1, dt_X86_INS_MOVSD);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    return FD_FT_NO_MATCH;
}
