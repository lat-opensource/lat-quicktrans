/*
 * SPDX-FileCopyrightText: 2021-2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

#include "quicktrans/detail/fast_decoder.h"
#include "quicktrans/detail/x86.h"

/* Helper: write immediate operand value */
static void opnd_write_imm_val(dt_cs_x86_op *opnd, int size_bits, int64_t val)
{
    opnd->type = dt_X86_OP_IMM;
    opnd->size = size_bits / 8;
    opnd->imm  = val;
    opnd->avx_bcast = dt_X86_AVX_BCAST_INVALID;
    opnd->avx_zero_opmask = 0;
}

static unsigned int fd_sse_prefix_id(FDState *s, int idx, unsigned int ins_id)
{
    switch (idx) {
    case 0x10:
    case 0x11:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_MOVUPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_MOVSD;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_MOVSS;
        return ins_id;
    case 0x12:
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_MOVDDUP;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_MOVSLDUP;
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_MOVLPD;
        if (!s->prefix[0] && !s->prefix[1] && !s->prefix[2] && !s->prefix[3])
            return dt_X86_INS_MOVLPS;
        return 0;
    case 0x14:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_UNPCKLPD;
        if (!s->prefix[0] && !s->prefix[1] && !s->prefix[2] && !s->prefix[3])
            return dt_X86_INS_UNPCKLPS;
        return 0;
    case 0x15:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_UNPCKHPD;
        if (!s->prefix[0] && !s->prefix[1] && !s->prefix[2] && !s->prefix[3])
            return dt_X86_INS_UNPCKHPS;
        return 0;
    case 0x16:
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_MOVSHDUP;
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_MOVHPD;
        if (!s->prefix[0] && !s->prefix[1] && !s->prefix[2] && !s->prefix[3])
            return dt_X86_INS_MOVHPS;
        return 0;
    case 0x28:
    case 0x29:
        return (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_MOVAPD : ins_id;
    case 0x2b:
        return (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_MOVNTPD : ins_id;
    case 0x2e:
        return (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_UCOMISD : ins_id;
    case 0x2f:
        return (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_COMISD : ins_id;
    case 0x51:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_SQRTPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_SQRTSD;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_SQRTSS;
        return ins_id;
    case 0x52:
        return (s->prefix[0] == dt_X86_PREFIX_REP) ? dt_X86_INS_RSQRTSS : ins_id;
    case 0x53:
        return (s->prefix[0] == dt_X86_PREFIX_REP) ? dt_X86_INS_RCPSS : ins_id;
    case 0x58:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_ADDPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_ADDSD;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_ADDSS;
        return ins_id;
    case 0x59:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_MULPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_MULSD;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_MULSS;
        return ins_id;
    case 0x5a:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_CVTPD2PS;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_CVTSD2SS;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_CVTSS2SD;
        return ins_id;
    case 0x5b:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_CVTPS2DQ;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_CVTTPS2DQ;
        return ins_id;
    case 0x54:
        return (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_ANDPD : ins_id;
    case 0x55:
        return (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_ANDNPD : ins_id;
    case 0x56:
        return (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_ORPD : ins_id;
    case 0x57:
        return (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_XORPD : ins_id;
    case 0x5c:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_SUBPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_SUBSD;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_SUBSS;
        return ins_id;
    case 0x5d:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_MINPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_MINSD;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_MINSS;
        return ins_id;
    case 0x5e:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_DIVPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_DIVSD;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_DIVSS;
        return ins_id;
    case 0x5f:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_MAXPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_MAXSD;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_MAXSS;
        return ins_id;
    case 0x7c:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_HADDPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_HADDPS;
        return 0;
    case 0x7d:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_HSUBPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_HSUBPS;
        return 0;
    case 0xd0:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_ADDSUBPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_ADDSUBPS;
        return 0;
    case 0xf0:
        return (s->prefix[0] == dt_X86_PREFIX_REPNE) ? dt_X86_INS_LDDQU : 0;
    case 0xc2:
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
            return dt_X86_INS_CMPPD;
        if (s->prefix[0] == dt_X86_PREFIX_REPNE)
            return dt_X86_INS_CMPSD;
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            return dt_X86_INS_CMPSS;
        return ins_id;
    default:
        return ins_id;
    }
}

static int fd_sse_mem_size(unsigned int ins_id)
{
    switch (ins_id) {
    case dt_X86_INS_MOVSD:
    case dt_X86_INS_ADDSD:
    case dt_X86_INS_SUBSD:
    case dt_X86_INS_MULSD:
    case dt_X86_INS_DIVSD:
    case dt_X86_INS_MINSD:
    case dt_X86_INS_MAXSD:
    case dt_X86_INS_COMISD:
    case dt_X86_INS_UCOMISD:
    case dt_X86_INS_CVTSD2SS:
    case dt_X86_INS_SQRTSD:
    case dt_X86_INS_ROUNDSD:
    case dt_X86_INS_MOVDDUP:
        return 8;
    case dt_X86_INS_MOVSS:
    case dt_X86_INS_ADDSS:
    case dt_X86_INS_SUBSS:
    case dt_X86_INS_MULSS:
    case dt_X86_INS_DIVSS:
    case dt_X86_INS_MINSS:
    case dt_X86_INS_MAXSS:
    case dt_X86_INS_COMISS:
    case dt_X86_INS_UCOMISS:
    case dt_X86_INS_CVTSS2SD:
    case dt_X86_INS_SQRTSS:
    case dt_X86_INS_RSQRTSS:
    case dt_X86_INS_RCPSS:
    case dt_X86_INS_ROUNDSS:
    case dt_X86_INS_INSERTPS:
    case dt_X86_INS_EXTRACTPS:
        return 4;
    case dt_X86_INS_CVTPS2PD:
        return 8;
    default:
        return 16;
    }
}

static int fd_sse_extract_like(FDState *s, struct la_dt_insn *info,
                               unsigned int ins_id, int dst_size,
                               int dst_reg_size)
{
    int m = fd_read_byte_s(s);
    if (m < 0) return 0;
    int mod_val = (m >> 6) & 3;
    int reg = ((m >> 3) & 7) | s->rex_r;
    int rm = (m & 7) | s->rex_b;

    info->x86.modrm = m;
    info->id = ins_id;
    info->x86.op_count = 3;
    if (mod_val == 3) {
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = dst_reg_size;
        info->x86.operands[0].reg = fd_reg_by_size(rm, dst_reg_size * 8);
    } else {
        info->x86.operands[0].type = dt_X86_OP_MEM;
        info->x86.operands[0].size = dst_size;
        fd_decode_mem_addr_s(s, &info->x86.operands[0], mod_val, m & 7);
    }
    info->x86.operands[1].type = dt_X86_OP_REG;
    info->x86.operands[1].size = 16;
    info->x86.operands[1].reg = fd_reg_xmm_export(reg);
    opnd_write_imm_val(&info->x86.operands[2], 8, (uint8_t)fd_read_byte_s(s));
    info->x86.operands[0].access = 0;
    info->x86.operands[1].access = 0;
    info->x86.operands[2].access = 0;
    return 1;
}

static int fd_sse_pinsr(FDState *s, struct la_dt_insn *info,
                        unsigned int ins_id, int src_size)
{
    int m = fd_read_byte_s(s);
    if (m < 0) return 0;
    int mod_val = (m >> 6) & 3;
    int reg = ((m >> 3) & 7) | s->rex_r;
    int rm = (m & 7) | s->rex_b;

    info->x86.modrm = m;
    info->id = ins_id;
    info->x86.op_count = 3;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = 16;
    info->x86.operands[0].reg = fd_reg_xmm_export(reg);
    if (mod_val == 3) {
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = src_size;
        info->x86.operands[1].reg = fd_reg_by_size(rm, src_size * 8);
    } else {
        info->x86.operands[1].type = dt_X86_OP_MEM;
        info->x86.operands[1].size = src_size;
        fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
    }
    opnd_write_imm_val(&info->x86.operands[2], 8, (uint8_t)fd_read_byte_s(s));
    info->x86.operands[0].access = 0;
    info->x86.operands[1].access = 0;
    info->x86.operands[2].access = 0;
    return 1;
}

static int fd_vex_pmovx(FDState *s, struct la_dt_insn *info,
                        unsigned int ins_id)
{
    int m = fd_read_byte_s(s);
    if (m < 0) return 0;
    int mod_val = (m >> 6) & 3;
    int reg = ((m >> 3) & 7) | s->rex_r;
    int rm = (m & 7) | s->rex_b;

    info->x86.modrm = m;
    info->id = ins_id;
    info->x86.op_count = 2;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = 16;
    info->x86.operands[0].reg = fd_reg_xmm_export(reg);
    if (mod_val == 3) {
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = 16;
        info->x86.operands[1].reg = fd_reg_xmm_export(rm);
    } else {
        info->x86.operands[1].type = dt_X86_OP_MEM;
        info->x86.operands[1].size =
            (ins_id == dt_X86_INS_VPMOVSXBQ ||
             ins_id == dt_X86_INS_VPMOVZXBQ) ? 2 : 4;
        fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
    }
    info->x86.operands[0].access = 0;
    info->x86.operands[1].access = 0;
    return 1;
}

static int fd_sse_movbe(FDState *s, struct la_dt_insn *info, int is_store)
{
    int m = fd_read_byte_s(s);
    if (m < 0) {
        return 0;
    }
    int mod_val = (m >> 6) & 3;
    int reg = ((m >> 3) & 7) | s->rex_r;
    int rm = (m & 7) | s->rex_b;
    int size = s->rex_w ? 8 :
               s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 2 : 4;

    if (mod_val == 3) {
        return 0;
    }

    info->x86.modrm = m;
    info->id = dt_X86_INS_MOVBE;
    info->x86.op_count = 2;
    if (is_store) {
        info->x86.operands[0].type = dt_X86_OP_MEM;
        info->x86.operands[0].size = size;
        info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[0].avx_zero_opmask = 0;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[0],
                                 mod_val, m & 7) < 0) {
            return 0;
        }
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = size;
        info->x86.operands[1].reg = fd_reg_by_size(reg, size * 8);
    } else {
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = size;
        info->x86.operands[0].reg = fd_reg_by_size(reg, size * 8);
        info->x86.operands[1].type = dt_X86_OP_MEM;
        info->x86.operands[1].size = size;
        info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[1].avx_zero_opmask = 0;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[1],
                                 mod_val, m & 7) < 0) {
            return 0;
        }
    }
    info->x86.operands[0].access = 0;
    info->x86.operands[1].access = 0;
    (void)rm;
    return 1;
}

static int fd_sse_adx(FDState *s, struct la_dt_insn *info)
{
    int m = fd_read_byte_s(s);
    int mod_val;
    int reg;
    int rm;
    int width;
    unsigned int id;

    if (m < 0) {
        return 0;
    }
    if (s->prefix[0] == dt_X86_PREFIX_REP && s->prefix[2] == 0) {
        id = dt_X86_INS_ADOX;
    } else if (s->prefix[0] == 0 &&
               s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
        id = dt_X86_INS_ADCX;
    } else {
        return 0;
    }

    mod_val = (m >> 6) & 3;
    reg = ((m >> 3) & 7) | s->rex_r;
    rm = (m & 7) | s->rex_b;
    width = s->rex_w ? 64 : 32;

    info->x86.modrm = m;
    info->id = id;
    info->x86.op_count = 2;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = width / 8;
    info->x86.operands[0].reg = fd_reg_by_size(reg, width);
    info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
    info->x86.operands[0].avx_zero_opmask = 0;
    info->x86.operands[0].access = 0;
    if (mod_val == 3) {
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = width / 8;
        info->x86.operands[1].reg = fd_reg_by_size(rm, width);
        info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[1].avx_zero_opmask = 0;
    } else {
        info->x86.operands[1].type = dt_X86_OP_MEM;
        info->x86.operands[1].size = width / 8;
        info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[1].avx_zero_opmask = 0;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val,
                                 m & 7) < 0) {
            return 0;
        }
    }
    info->x86.operands[1].access = dt_CS_AC_READ;
    return 1;
}

static int fd_vex_bmi_andn(FDState *s, struct la_dt_insn *info)
{
    int m = fd_read_byte_s(s);
    if (m < 0) {
        return 0;
    }
    int mod_val = (m >> 6) & 3;
    int reg = ((m >> 3) & 7) | s->rex_r;
    int rm = (m & 7) | s->rex_b;
    int size = s->rex_w ? 64 : 32;

    info->x86.modrm = m;
    info->id = dt_X86_INS_ANDN;
    info->x86.op_count = 3;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = size / 8;
    info->x86.operands[0].reg = fd_reg_by_size(reg, size);
    info->x86.operands[0].access = dt_CS_AC_WRITE;
    info->x86.operands[1].type = dt_X86_OP_REG;
    info->x86.operands[1].size = size / 8;
    info->x86.operands[1].reg = fd_reg_by_size(s->vex_v, size);
    info->x86.operands[1].access = dt_CS_AC_READ;
    if (mod_val == 3) {
        info->x86.operands[2].type = dt_X86_OP_REG;
        info->x86.operands[2].size = size / 8;
        info->x86.operands[2].reg = fd_reg_by_size(rm, size);
    } else {
        info->x86.operands[2].type = dt_X86_OP_MEM;
        info->x86.operands[2].size = size / 8;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[2],
                                 mod_val, m & 7) < 0) {
            return 0;
        }
    }
    info->x86.operands[2].access = dt_CS_AC_READ;
    return 1;
}

static int fd_vex_bmi_pext_pdep(FDState *s, struct la_dt_insn *info,
                                unsigned int id)
{
    int m = fd_read_byte_s(s);
    int mod_val;
    int reg;
    int rm;
    int size;

    if (m < 0) {
        return 0;
    }
    mod_val = (m >> 6) & 3;
    reg = ((m >> 3) & 7) | s->rex_r;
    rm = (m & 7) | s->rex_b;
    size = s->rex_w ? 64 : 32;

    info->x86.modrm = m;
    info->id = id;
    info->x86.op_count = 3;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = size / 8;
    info->x86.operands[0].reg = fd_reg_by_size(reg, size);
    info->x86.operands[0].access = dt_CS_AC_WRITE;
    info->x86.operands[1].type = dt_X86_OP_REG;
    info->x86.operands[1].size = size / 8;
    info->x86.operands[1].reg = fd_reg_by_size(s->vex_v, size);
    info->x86.operands[1].access = dt_CS_AC_READ;
    if (mod_val == 3) {
        info->x86.operands[2].type = dt_X86_OP_REG;
        info->x86.operands[2].size = size / 8;
        info->x86.operands[2].reg = fd_reg_by_size(rm, size);
    } else {
        info->x86.operands[2].type = dt_X86_OP_MEM;
        info->x86.operands[2].size = size / 8;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[2],
                                 mod_val, m & 7) < 0) {
            return 0;
        }
    }
    info->x86.operands[2].access = dt_CS_AC_READ;
    return 1;
}

static int fd_vex_bmi_bzhi(FDState *s, struct la_dt_insn *info)
{
    int m = fd_read_byte_s(s);
    int mod_val;
    int reg;
    int rm;
    int size;

    if (m < 0) {
        return 0;
    }
    mod_val = (m >> 6) & 3;
    reg = ((m >> 3) & 7) | s->rex_r;
    rm = (m & 7) | s->rex_b;
    size = s->rex_w ? 64 : 32;

    info->x86.modrm = m;
    info->id = dt_X86_INS_BZHI;
    info->x86.op_count = 3;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = size / 8;
    info->x86.operands[0].reg = fd_reg_by_size(reg, size);
    info->x86.operands[0].access = dt_CS_AC_WRITE;
    if (mod_val == 3) {
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = size / 8;
        info->x86.operands[1].reg = fd_reg_by_size(rm, size);
    } else {
        info->x86.operands[1].type = dt_X86_OP_MEM;
        info->x86.operands[1].size = size / 8;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[1],
                                 mod_val, m & 7) < 0) {
            return 0;
        }
    }
    info->x86.operands[1].access = dt_CS_AC_READ;
    info->x86.operands[2].type = dt_X86_OP_REG;
    info->x86.operands[2].size = size / 8;
    info->x86.operands[2].reg = fd_reg_by_size(s->vex_v, size);
    info->x86.operands[2].access = dt_CS_AC_READ;
    return 1;
}

static int fd_vex_bmi_bls(FDState *s, struct la_dt_insn *info)
{
    static const unsigned int bls_id[8] = {
        [1] = dt_X86_INS_BLSR,
        [2] = dt_X86_INS_BLSMSK,
        [3] = dt_X86_INS_BLSI,
    };
    int m = fd_read_byte_s(s);
    if (m < 0) {
        return 0;
    }
    int ext = (m >> 3) & 7;
    int mod_val = (m >> 6) & 3;
    int rm = (m & 7) | s->rex_b;
    int size = s->rex_w ? 64 : 32;

    if (!bls_id[ext]) {
        return 0;
    }

    info->x86.modrm = m;
    info->id = bls_id[ext];
    info->x86.op_count = 2;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = size / 8;
    info->x86.operands[0].reg = fd_reg_by_size(s->vex_v, size);
    info->x86.operands[0].access = dt_CS_AC_WRITE;
    if (mod_val == 3) {
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = size / 8;
        info->x86.operands[1].reg = fd_reg_by_size(rm, size);
    } else {
        info->x86.operands[1].type = dt_X86_OP_MEM;
        info->x86.operands[1].size = size / 8;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[1],
                                 mod_val, m & 7) < 0) {
            return 0;
        }
    }
    info->x86.operands[1].access = dt_CS_AC_READ;
    return 1;
}

static int fd_vex_bmi_bextr(FDState *s, struct la_dt_insn *info)
{
    int m = fd_read_byte_s(s);
    if (m < 0) {
        return 0;
    }
    int mod_val = (m >> 6) & 3;
    int reg = ((m >> 3) & 7) | s->rex_r;
    int rm = (m & 7) | s->rex_b;
    int size = s->rex_w ? 64 : 32;

    info->x86.modrm = m;
    info->id = dt_X86_INS_BEXTR;
    info->x86.op_count = 3;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = size / 8;
    info->x86.operands[0].reg = fd_reg_by_size(reg, size);
    info->x86.operands[0].access = dt_CS_AC_WRITE;
    if (mod_val == 3) {
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = size / 8;
        info->x86.operands[1].reg = fd_reg_by_size(rm, size);
    } else {
        info->x86.operands[1].type = dt_X86_OP_MEM;
        info->x86.operands[1].size = size / 8;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[1],
                                 mod_val, m & 7) < 0) {
            return 0;
        }
    }
    info->x86.operands[1].access = dt_CS_AC_READ;
    info->x86.operands[2].type = dt_X86_OP_REG;
    info->x86.operands[2].size = size / 8;
    info->x86.operands[2].reg = fd_reg_by_size(s->vex_v, size);
    info->x86.operands[2].access = dt_CS_AC_READ;
    return 1;
}

static int fd_vex_fma132(FDState *s, struct la_dt_insn *info,
                         unsigned int ins_id)
{
    int m = fd_read_byte_s(s);
    int mod_val;
    int reg;
    int rm;

    if (m < 0) {
        return 0;
    }

    mod_val = (m >> 6) & 3;
    reg = ((m >> 3) & 7) | s->rex_r;
    rm = (m & 7) | s->rex_b;

    info->x86.modrm = m;
    info->id = ins_id;
    info->x86.op_count = 3;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = 16;
    info->x86.operands[0].reg = fd_reg_xmm_export(reg);
    info->x86.operands[0].access = dt_CS_AC_READ | dt_CS_AC_WRITE;
    info->x86.operands[1].type = dt_X86_OP_REG;
    info->x86.operands[1].size = 16;
    info->x86.operands[1].reg = fd_reg_xmm_export(s->vex_v);
    info->x86.operands[1].access = dt_CS_AC_READ;
    if (mod_val == 3) {
        info->x86.operands[2].type = dt_X86_OP_REG;
        info->x86.operands[2].size = 16;
        info->x86.operands[2].reg = fd_reg_xmm_export(rm);
    } else {
        info->x86.operands[2].type = dt_X86_OP_MEM;
        info->x86.operands[2].size = 16;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[2],
                                 mod_val, m & 7) < 0) {
            return 0;
        }
    }
    info->x86.operands[2].access = dt_CS_AC_READ;
    return 1;
}

/* SSE helper: decode ModR/M with optional memory, fill two XMM operands.
 * Called for reg-reg and reg-mem SSE instructions.
 * Returns 1 on success, 0 on failure.
 */
static int fd_sse_modrm(FDState *s, struct la_dt_insn *info,
                         unsigned int ins_id, int has_imm8)
{
    int modrm = fd_read_byte_s(s);
    if (modrm < 0) return 0;
    int mod_val = (modrm >> 6) & 3;
    int reg = ((modrm >> 3) & 7) | s->rex_r;
    int rm  = (modrm & 7) | s->rex_b;
    int rm_raw = modrm & 7;

    info->x86.modrm = modrm;
    info->id = ins_id;
    info->x86.op_count = has_imm8 ? 3 : 2;

    /* Store form (odd opcodes: 0x11, 0x29, 0x2B, 0x7F, 0xD6):
     *   opnd[0]=mem(dest), opnd[1]=xmm(src) */
    int opcode = s->code[s->pos - 2];
    int is_3byte = s->pos >= 3 &&
                   (s->code[s->pos - 3] == 0x38 ||
                    s->code[s->pos - 3] == 0x3a);
    int is_store = !is_3byte &&
                   (opcode == 0x11 || opcode == 0x29 || opcode == 0x2b ||
                    opcode == 0x7f);
    if (is_store) {
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = 16;
        info->x86.operands[1].reg = fd_reg_xmm_export(reg);
        info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[1].avx_zero_opmask = 0;
        info->x86.operands[1].access = 0;
        if (mod_val == 3) return 0;
        /* opnd[0] = mem dest */
        info->x86.operands[0].type = dt_X86_OP_MEM;
        info->x86.operands[0].size = fd_sse_mem_size(ins_id);
        info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[0].avx_zero_opmask = 0;
        info->x86.operands[0].access = 0;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[0], mod_val, rm_raw) < 0)
            return 0;
        return 1;
    }

    /* opnd[0] = XMM dest (reg field) */
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = 16; /* 128-bit XMM */
    info->x86.operands[0].reg = fd_reg_xmm_export(reg);
    info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
    info->x86.operands[0].avx_zero_opmask = 0;
    info->x86.operands[0].access = 0;

    /* opnd[1] = XMM/mem source */
    if (mod_val == 3) {
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = 16;
        info->x86.operands[1].reg = fd_reg_xmm_export(rm);
        info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[1].avx_zero_opmask = 0;
    } else {
        info->x86.operands[1].type = dt_X86_OP_MEM;
        info->x86.operands[1].size = fd_sse_mem_size(ins_id);
        info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[1].avx_zero_opmask = 0;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, rm_raw) < 0)
            return 0;
    }
    info->x86.operands[1].access = dt_CS_AC_READ;

    /* opnd[2] = imm8 (if applicable) */
    if (has_imm8) {
        opnd_write_imm_val(&info->x86.operands[2], 8, (uint8_t)fd_read_byte_s(s));
        info->x86.operands[2].access = dt_CS_AC_READ;
    }

    return 1;
}

/* Decode legacy MMX binary instructions.  REX extends addressing here, but
 * never the MMX register fields or their fixed 64-bit data width. */
static int fd_sse_mmx_bin(FDState *s, struct la_dt_insn *info,
                          unsigned int ins_id)
{
    int modrm = fd_read_byte_s(s);
    int mod_val;
    int reg;
    int rm_raw;

    if (modrm < 0) {
        return 0;
    }
    mod_val = (modrm >> 6) & 3;
    reg = (modrm >> 3) & 7;
    rm_raw = modrm & 7;

    info->x86.modrm = modrm;
    info->id = ins_id;
    info->x86.op_count = 2;
    info->x86.operands[0].type = dt_X86_OP_REG;
    info->x86.operands[0].size = 8;
    info->x86.operands[0].reg = fd_reg_mmx_export(reg);
    if (mod_val == 3) {
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = 8;
        info->x86.operands[1].reg = fd_reg_mmx_export(rm_raw);
    } else {
        info->x86.operands[1].type = dt_X86_OP_MEM;
        info->x86.operands[1].size = 8;
        if (fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val,
                                 rm_raw) < 0) {
            return 0;
        }
    }
    info->x86.operands[0].access = 0;
    info->x86.operands[1].access = 0;
    return 1;
}

static int fd_sse_mmx_bin_imm8(FDState *s, struct la_dt_insn *info,
                               unsigned int ins_id)
{
    int imm;

    if (!fd_sse_mmx_bin(s, info, ins_id)) {
        return 0;
    }
    imm = fd_read_byte_s(s);
    if (imm < 0) {
        return 0;
    }
    info->x86.op_count = 3;
    opnd_write_imm_val(&info->x86.operands[2], 8, (uint8_t)imm);
    info->x86.operands[2].access = dt_CS_AC_READ;
    return 1;
}

/* SSE instruction opcode lookup table.
 * Maps (op & 0x7f) → dt_X86_INS_* for common SSE instructions.
 * Unmapped entries = 0 (unsupported).
 */
static const unsigned int sse_insn_map[256] = {
    [0x10] = dt_X86_INS_MOVUPS,
    [0x11] = dt_X86_INS_MOVUPS,
    [0x12] = dt_X86_INS_MOVLPS,
    [0x13] = dt_X86_INS_MOVLPS,
    [0x14] = dt_X86_INS_UNPCKLPS,
    [0x15] = dt_X86_INS_UNPCKHPS,
    [0x16] = dt_X86_INS_MOVHPS,
    [0x17] = dt_X86_INS_MOVHPS,
    [0x28] = dt_X86_INS_MOVAPS,
    [0x29] = dt_X86_INS_MOVAPS,
    [0x2B] = dt_X86_INS_MOVNTPS,
    [0x2A] = dt_X86_INS_CVTSI2SD,   /* CVTSI2SD (F2) */
    [0x2C] = dt_X86_INS_CVTTSD2SI,  /* CVTTSD2SI (F2) */
    [0x2D] = dt_X86_INS_CVTSD2SI,   /* CVTSD2SI (F2) */
    [0x2E] = dt_X86_INS_UCOMISS,    /* UCOMISS (66) */
    [0x2F] = dt_X86_INS_COMISS,     /* COMISS (66) */
    [0x50] = dt_X86_INS_MOVMSKPS,   /* MOVMSKPS/MOVMSKPD */
    [0x51] = dt_X86_INS_SQRTPS,     /* SQRTPS/SQRTPD/SQRTSS/SQRTSD */
    [0x52] = dt_X86_INS_RSQRTPS,    /* RSQRTPS/RSQRTSS */
    [0x53] = dt_X86_INS_RCPPS,      /* RCPPS/RCPSS */
    [0x54] = dt_X86_INS_ANDPS,
    [0x55] = dt_X86_INS_ANDNPS,     /* ANDNPS */
    [0x56] = dt_X86_INS_ORPS,       /* ORPS */
    [0x57] = dt_X86_INS_XORPS,      /* XORPS */
    [0x58] = dt_X86_INS_ADDPS,      /* ADDPS */
    [0x59] = dt_X86_INS_MULPS,      /* MULPS */
    [0x5A] = dt_X86_INS_CVTPS2PD,   /* CVTPS2PD */
    [0x5B] = dt_X86_INS_CVTDQ2PS,   /* CVTDQ2PS */
    [0x5C] = dt_X86_INS_SUBPS,      /* SUBPS */
    [0x5D] = dt_X86_INS_MINPS,      /* MINPS */
    [0x5E] = dt_X86_INS_DIVPS,      /* DIVPS */
    [0x5F] = dt_X86_INS_MAXPS,      /* MAXPS */
    [0x60] = dt_X86_INS_PUNPCKLBW,  /* PUNPCKLBW */
    [0x61] = dt_X86_INS_PUNPCKLWD,  /* PUNPCKLWD */
    [0x62] = dt_X86_INS_PUNPCKLDQ,  /* PUNPCKLDQ */
    [0x63] = dt_X86_INS_PACKSSWB,   /* PACKSSWB */
    [0x64] = dt_X86_INS_PCMPGTB,    /* PCMPGTB */
    [0x65] = dt_X86_INS_PCMPGTW,    /* PCMPGTW */
    [0x66] = dt_X86_INS_PCMPGTD,    /* PCMPGTD */
    [0x67] = dt_X86_INS_PACKUSWB,   /* PACKUSWB */
    [0x68] = dt_X86_INS_PUNPCKHBW,  /* PUNPCKHBW */
    [0x69] = dt_X86_INS_PUNPCKHWD,  /* PUNPCKHWD */
    [0x6A] = dt_X86_INS_PUNPCKHDQ,  /* PUNPCKHDQ */
    [0x6B] = dt_X86_INS_PACKSSDW,   /* PACKSSDW */
    [0x6C] = dt_X86_INS_PUNPCKLQDQ, /* PUNPCKLQDQ */
    [0x6D] = dt_X86_INS_PUNPCKHQDQ, /* PUNPCKHQDQ */
    [0x6E] = dt_X86_INS_MOVD,       /* MOVD xmm, r/m32 */
    [0x6F] = dt_X86_INS_MOVDQA,     /* MOVDQA xmm, xmm/m128 */
    [0x70] = dt_X86_INS_PSHUFD,     /* PSHUFD (has imm8) */
    [0x71] = dt_X86_INS_PSLLW,      /* PSLLW with Grp */
    [0x72] = dt_X86_INS_PSLLD,      /* PSLLD with Grp */
    [0x73] = dt_X86_INS_PSLLQ,      /* PSLLQ/PSRLQ with Grp */
    [0x74] = dt_X86_INS_PCMPEQB,    /* PCMPEQB */
    [0x75] = dt_X86_INS_PCMPEQW,    /* PCMPEQW */
    [0x76] = dt_X86_INS_PCMPEQD,    /* PCMPEQD */
    [0x7E] = dt_X86_INS_MOVD,       /* MOVD r/m32, xmm */
    [0x7F] = dt_X86_INS_MOVDQA,     /* MOVDQA xmm/m128, xmm */
    [0x7C] = dt_X86_INS_HADDPD,     /* HADDPD/HADDPS */
    [0x7D] = dt_X86_INS_HSUBPD,     /* HSUBPD/HSUBPS */
    /* 0xBC-0xBD: BSF/BSR -- handled elsewhere */
    /* 0xBE-0xBF: MOVSX -- handled elsewhere */
    /* 0xC0-0xC1: XADD -- skip */
    [0xC2] = dt_X86_INS_CMPPS,      /* CMPPS (has imm8) */
    [0xC4] = dt_X86_INS_PINSRW,     /* PINSRW (has imm8) */
    [0xC5] = dt_X86_INS_PEXTRW,     /* PEXTRW (has imm8) */
    [0xC6] = dt_X86_INS_SHUFPS,     /* SHUFPS (has imm8) */
    [0xD4] = dt_X86_INS_PADDQ,      /* PADDQ */
    [0xD5] = dt_X86_INS_PMULLW,     /* PMULLW */
    [0xD6] = dt_X86_INS_MOVQ,       /* MOVQ */
    [0xD7] = dt_X86_INS_PMOVMSKB,   /* PMOVMSKB */
    [0xD8] = dt_X86_INS_PSUBUSB,    /* PSUBUSB */
    [0xD9] = dt_X86_INS_PSUBUSW,    /* PSUBUSW */
    [0xDA] = dt_X86_INS_PMINUB,     /* PMINUB */
    [0xDB] = dt_X86_INS_PAND,       /* PAND */
    [0xDC] = dt_X86_INS_PADDUSB,    /* PADDUSB */
    [0xDD] = dt_X86_INS_PADDUSW,    /* PADDUSW */
    [0xDE] = dt_X86_INS_PMAXUB,     /* PMAXUB */
    [0xDF] = dt_X86_INS_PANDN,      /* PANDN */
    [0xE0] = dt_X86_INS_PAVGB,      /* PAVGB */
    [0xE1] = dt_X86_INS_PSRAW,      /* PSRAW */
    [0xE2] = dt_X86_INS_PSRAD,      /* PSRAD */
    [0xE3] = dt_X86_INS_PAVGW,      /* PAVGW */
    [0xE4] = dt_X86_INS_PMULHUW,    /* PMULHUW */
    [0xE5] = dt_X86_INS_PMULHW,     /* PMULHW */
    [0xE6] = dt_X86_INS_CVTDQ2PD,   /* CVTDQ2PD (F3) */
    [0xE7] = dt_X86_INS_MOVNTQ,     /* MOVNTQ/MOVNTDQ */
    [0xE8] = dt_X86_INS_PSUBSB,     /* PSUBSB */
    [0xE9] = dt_X86_INS_PSUBSW,     /* PSUBSW */
    [0xEA] = dt_X86_INS_PMINSW,     /* PMINSW */
    [0xEB] = dt_X86_INS_POR,        /* POR */
    [0xEC] = dt_X86_INS_PADDSB,     /* PADDSB */
    [0xED] = dt_X86_INS_PADDSW,     /* PADDSW */
    [0xEE] = dt_X86_INS_PMAXSW,     /* PMAXSW */
    [0xEF] = dt_X86_INS_PXOR,       /* PXOR */
    [0xF0] = dt_X86_INS_LDDQU,      /* LDDQU */
    [0xF1] = dt_X86_INS_PSLLW,      /* PSLLW */
    [0xF2] = dt_X86_INS_PSLLD,      /* PSLLD */
    [0xF3] = dt_X86_INS_PSLLQ,      /* PSLLQ */
    [0xF4] = dt_X86_INS_PMULUDQ,    /* PMULUDQ */
    [0xF5] = dt_X86_INS_PMADDWD,    /* PMADDWD */
    [0xF6] = dt_X86_INS_PSADBW,     /* PSADBW */
    [0xF7] = dt_X86_INS_MASKMOVDQU, /* MASKMOVDQU */
    [0xF8] = dt_X86_INS_PSUBB,      /* PSUBB */
    [0xF9] = dt_X86_INS_PSUBW,      /* PSUBW */
    [0xFA] = dt_X86_INS_PSUBD,      /* PSUBD */
    [0xFB] = dt_X86_INS_PSUBQ,      /* PSUBQ */
    [0xFC] = dt_X86_INS_PADDB,      /* PADDB */
    [0xFD] = dt_X86_INS_PADDW,      /* PADDW */
    [0xFE] = dt_X86_INS_PADDD,      /* PADDD */
    [0xD0] = dt_X86_INS_ADDSUBPD,   /* ADDSUBPD/ADDSUBPS */
    [0xD1] = dt_X86_INS_PSRLW,
    [0xD2] = dt_X86_INS_PSRLD,
    [0xD3] = dt_X86_INS_PSRLQ,
};

int fd_dispatch_sse(FDState *s, int op, struct la_dt_insn *info)
{
    if ((op & 0xff0000) == 0xc40000) {
        int pp = (op >> 8) & 3;
        int opcode = op & 0xff;
        if (pp == 0 && opcode == 0xf2) {
            return fd_vex_bmi_andn(s, info);
        }
        if (pp == 0 && opcode == 0xf3) {
            return fd_vex_bmi_bls(s, info);
        }
        if (pp == 0 && opcode == 0xf7) {
            return fd_vex_bmi_bextr(s, info);
        }
        if (pp == 2 && opcode == 0xf5) {
            return fd_vex_bmi_pext_pdep(s, info, dt_X86_INS_PEXT);
        }
        if (pp == 3 && opcode == 0xf5) {
            return fd_vex_bmi_pext_pdep(s, info, dt_X86_INS_PDEP);
        }
        if (pp == 0 && opcode == 0xf5) {
            return fd_vex_bmi_bzhi(s, info);
        }
        if (pp != 1)
            return 0;
        switch (opcode) {
        case 0x98:
            return fd_vex_fma132(s, info,
                s->rex_w ? dt_X86_INS_VFMADD132PD :
                           dt_X86_INS_VFMADD132PS);
        case 0x9a:
            return fd_vex_fma132(s, info,
                s->rex_w ? dt_X86_INS_VFMSUB132PD :
                           dt_X86_INS_VFMSUB132PS);
        case 0x21:
            return fd_vex_pmovx(s, info, dt_X86_INS_VPMOVSXBD);
        case 0x22:
            return fd_vex_pmovx(s, info, dt_X86_INS_VPMOVSXBQ);
        case 0x31:
            return fd_vex_pmovx(s, info, dt_X86_INS_VPMOVZXBD);
        case 0x32:
            return fd_vex_pmovx(s, info, dt_X86_INS_VPMOVZXBQ);
        default:
            return 0;
        }
    }

    if (op >= 0x10000) {
        /* Three-byte SSE: 0F 38 XX or 0F 3A XX */
        int pref = (op >> 8) & 0xff;
        int xx = op & 0xff;
        if (pref == 0x3a) {
            static const unsigned int sse3a_map[] = {
                [0x08] = dt_X86_INS_ROUNDPS,
                [0x09] = dt_X86_INS_ROUNDPD,
                [0x0A] = dt_X86_INS_ROUNDSS,
                [0x0B] = dt_X86_INS_ROUNDSD,
                [0x0C] = dt_X86_INS_BLENDPS,
                [0x0D] = dt_X86_INS_BLENDPD,
                [0x0E] = dt_X86_INS_PBLENDW,
                [0x0F] = dt_X86_INS_PALIGNR,
                [0x14] = dt_X86_INS_PEXTRB,
                [0x15] = dt_X86_INS_PEXTRW,
                [0x17] = dt_X86_INS_EXTRACTPS,
                [0x20] = dt_X86_INS_PINSRB,
                [0x21] = dt_X86_INS_INSERTPS,
                [0x22] = dt_X86_INS_PINSRD,
                [0x40] = dt_X86_INS_DPPS,
                [0x41] = dt_X86_INS_DPPD,
                [0x42] = dt_X86_INS_MPSADBW,
                [0x44] = dt_X86_INS_PCLMULQDQ,
                [0x60] = dt_X86_INS_PCMPESTRM,
                [0x63] = dt_X86_INS_PCMPISTRI,
                [0xCC] = dt_X86_INS_SHA1RNDS4,
                [0xDF] = dt_X86_INS_AESKEYGENASSIST,
            };
            if (xx < 256) {
                unsigned int ins_id = sse3a_map[xx];
                if (xx == 0x0f && s->prefix[0] == 0 &&
                    s->prefix[2] == 0) {
                    return fd_sse_mmx_bin_imm8(s, info,
                                               dt_X86_INS_PALIGNR);
                }
                if (xx == 0x22 && s->rex_w)
                    ins_id = dt_X86_INS_PINSRQ;
                if (xx == 0x14)
                    return fd_sse_extract_like(s, info, dt_X86_INS_PEXTRB, 1, 4);
                if (xx == 0x15 && !s->rex_w)
                    return fd_sse_extract_like(s, info, dt_X86_INS_PEXTRW, 2, 4);
                if (xx == 0x16)
                    return fd_sse_extract_like(s, info,
                        s->rex_w ? dt_X86_INS_PEXTRQ : dt_X86_INS_PEXTRD,
                        s->rex_w ? 8 : 4, s->rex_w ? 8 : 4);
                if (xx == 0x17)
                    return fd_sse_extract_like(s, info, dt_X86_INS_EXTRACTPS,
                                               4, 4);
                if (xx == 0x20)
                    return fd_sse_pinsr(s, info, dt_X86_INS_PINSRB, 4);
                if (xx == 0x22)
                    return fd_sse_pinsr(s, info, ins_id, s->rex_w ? 8 : 4);
                if (ins_id) {
                    int has_imm8 = (xx == 0x08 || xx == 0x09 ||
                                    xx == 0x0A || xx == 0x0B ||
                                    xx == 0x0C || xx == 0x0D ||
                                    xx == 0x0E || xx == 0x0F ||
                                    xx == 0x20 || xx == 0x21 ||
                                    xx == 0x22 || xx == 0x40 ||
                                    xx == 0x41 || xx == 0x42 ||
                                    xx == 0x44 || xx == 0x60 ||
                                    xx == 0x63 ||
                                    xx == 0xCC ||
                                    xx == 0xDF);
                    return fd_sse_modrm(s, info, ins_id, has_imm8);
                }
            }
        }
        if (pref == 0x38) {
            if (xx == 0xf6 &&
                ((s->prefix[0] == dt_X86_PREFIX_REP &&
                  s->prefix[2] == 0) ||
                 (s->prefix[0] == 0 &&
                  s->prefix[2] == dt_X86_PREFIX_OPSIZE))) {
                return fd_sse_adx(s, info);
            }
            if (xx == 0xf0 || xx == 0xf1) {
                return fd_sse_movbe(s, info, xx == 0xf1);
            }
            static const unsigned int sse38_map[] = {
                [0x00] = dt_X86_INS_PSHUFB,
                [0x01] = dt_X86_INS_PHADDW,
                [0x02] = dt_X86_INS_PHADDD,
                [0x03] = dt_X86_INS_PHADDSW,
                [0x04] = dt_X86_INS_PMADDUBSW,
                [0x05] = dt_X86_INS_PHSUBW,
                [0x06] = dt_X86_INS_PHSUBD,
                [0x07] = dt_X86_INS_PHSUBSW,
                [0x08] = dt_X86_INS_PSIGNB,
                [0x09] = dt_X86_INS_PSIGNW,
                [0x0A] = dt_X86_INS_PSIGND,
                [0x0B] = dt_X86_INS_PMULHRSW,
                [0x14] = dt_X86_INS_BLENDVPS,
                [0x15] = dt_X86_INS_BLENDVPD,
                [0x10] = dt_X86_INS_PBLENDVB,
                [0x17] = dt_X86_INS_PTEST,
                [0x1C] = dt_X86_INS_PABSB,
                [0x1D] = dt_X86_INS_PABSW,
                [0x1E] = dt_X86_INS_PABSD,
                [0x20] = dt_X86_INS_PMOVSXBW,
                [0x21] = dt_X86_INS_PMOVSXBD,
                [0x22] = dt_X86_INS_PMOVSXBQ,
                [0x23] = dt_X86_INS_PMOVSXWD,
                [0x24] = dt_X86_INS_PMOVSXWQ,
                [0x25] = dt_X86_INS_PMOVSXDQ,
                [0x28] = dt_X86_INS_PMULDQ,
                [0x29] = dt_X86_INS_PCMPEQQ,
                [0x2A] = dt_X86_INS_MOVNTDQA,
                [0x2B] = dt_X86_INS_PACKUSDW,
                [0x30] = dt_X86_INS_PMOVZXBW,
                [0x31] = dt_X86_INS_PMOVZXBD,
                [0x32] = dt_X86_INS_PMOVZXBQ,
                [0x33] = dt_X86_INS_PMOVZXWD,
                [0x34] = dt_X86_INS_PMOVZXWQ,
                [0x35] = dt_X86_INS_PMOVZXDQ,
                [0x37] = dt_X86_INS_PCMPGTQ,
                [0x38] = dt_X86_INS_PMINSB,
                [0x39] = dt_X86_INS_PMINSD,
                [0x3A] = dt_X86_INS_PMINUW,
                [0x3B] = dt_X86_INS_PMINUD,
                [0x3C] = dt_X86_INS_PMAXSB,
                [0x3D] = dt_X86_INS_PMAXSD,
                [0x3E] = dt_X86_INS_PMAXUW,
                [0x3F] = dt_X86_INS_PMAXUD,
                [0x40] = dt_X86_INS_PMULLD,
                [0x41] = dt_X86_INS_PHMINPOSUW,
                [0xC8] = dt_X86_INS_SHA1NEXTE,
                [0xC9] = dt_X86_INS_SHA1MSG1,
                [0xCA] = dt_X86_INS_SHA1MSG2,
                [0xCB] = dt_X86_INS_SHA256RNDS2,
                [0xCC] = dt_X86_INS_SHA256MSG1,
                [0xCD] = dt_X86_INS_SHA256MSG2,
                [0xDB] = dt_X86_INS_AESIMC,
                [0xDC] = dt_X86_INS_AESENC,
                [0xDD] = dt_X86_INS_AESENCLAST,
                [0xDE] = dt_X86_INS_AESDEC,
                [0xDF] = dt_X86_INS_AESDECLAST,
            };
            if (xx < 256) {
                unsigned int ins_id = sse38_map[xx];
                if (ins_id && s->prefix[0] == 0 && s->prefix[2] == 0 &&
                    (xx <= 0x0b ||
                     (xx >= 0x1c && xx <= 0x1e))) {
                    return fd_sse_mmx_bin(s, info, ins_id);
                }
                if (ins_id)
                    return fd_sse_modrm(s, info, ins_id, 0);
            }
        }
        return 0;
    }

    int idx = op & 0xff;
    unsigned int ins_id = sse_insn_map[idx];
    if (!ins_id)
        return 0;
    ins_id = fd_sse_prefix_id(s, idx, ins_id);
    if (!ins_id)
        return 0;

    if (s->prefix[0] == 0 && s->prefix[2] == 0 && idx == 0xf7) {
        return fd_sse_mmx_bin(s, info, dt_X86_INS_MASKMOVQ);
    }

    if (s->prefix[0] == 0 && s->prefix[2] == 0 &&
        ((idx >= 0x60 && idx <= 0x62) || idx == 0x63 ||
         (idx >= 0x64 && idx <= 0x66) || (idx >= 0x68 && idx <= 0x6a) ||
         idx == 0x67 || idx == 0x6b ||
         (idx >= 0x74 && idx <= 0x76) ||
         (idx >= 0xd8 && idx <= 0xd9) || (idx >= 0xdc && idx <= 0xdd) ||
         idx == 0xe0 || idx == 0xe3 ||
         (idx >= 0xe8 && idx <= 0xe9) ||
         idx == 0xea ||
         (idx >= 0xf8 && idx <= 0xfb) ||
         idx == 0xdf || idx == 0xf4)) {
        return fd_sse_mmx_bin(s, info, ins_id);
    }

    if (idx == 0x6f && s->prefix[0] != dt_X86_PREFIX_REP &&
        s->prefix[2] != dt_X86_PREFIX_OPSIZE) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm = (m & 7) | s->rex_b;
        info->x86.modrm = m;
        info->id = dt_X86_INS_MOVQ;
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 8;
        info->x86.operands[0].reg = fd_reg_mmx_export(reg);
        if (mod_val == 3) {
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 8;
            info->x86.operands[1].reg = fd_reg_mmx_export(rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = 8;
            fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
        }
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    if (idx == 0x7f && s->prefix[0] == 0 && s->prefix[2] == 0 &&
        !s->rex_w) {
        int m = fd_read_byte_s(s);
        int mod_val;
        int reg;
        int rm;

        if (m < 0) {
            return 0;
        }
        mod_val = (m >> 6) & 3;
        reg = ((m >> 3) & 7) | s->rex_r;
        rm = (m & 7) | s->rex_b;
        info->x86.modrm = m;
        info->id = dt_X86_INS_MOVQ;
        info->x86.op_count = 2;
        if (mod_val == 3) {
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = 8;
            info->x86.operands[0].reg = fd_reg_mmx_export(rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = 8;
            fd_decode_mem_addr_s(s, &info->x86.operands[0], mod_val, m & 7);
        }
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = 8;
        info->x86.operands[1].reg = fd_reg_mmx_export(reg);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* MOVD (0x6E/0x7E) and MOVQ (0xD6) — mixed XMM/r/m32(r/m64) sizes */
    if (idx == 0x6e || idx == 0x7e || idx == 0xd6) {
        if (s->prefix[0] != dt_X86_PREFIX_REP &&
            s->prefix[2] != dt_X86_PREFIX_OPSIZE &&
            idx == 0x7e) {
            int m = fd_read_byte_s(s);
            if (m < 0) return 0;
            int mod_val = (m >> 6) & 3;
            int reg = ((m >> 3) & 7) | s->rex_r;
            int rm = (m & 7) | s->rex_b;
            info->x86.modrm = m;
            info->id = dt_X86_INS_MOVQ;
            info->x86.op_count = 2;
            if (mod_val == 3) {
                info->x86.operands[0].type = dt_X86_OP_REG;
                info->x86.operands[0].size = 8;
                info->x86.operands[0].reg = fd_reg_by_size(rm,
                                                           s->rex_w ? 64 : 32);
            } else {
                info->x86.operands[0].type = dt_X86_OP_MEM;
                info->x86.operands[0].size = s->rex_w ? 8 : 4;
                fd_decode_mem_addr_s(s, &info->x86.operands[0], mod_val, m & 7);
            }
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 8;
            info->x86.operands[1].reg = fd_reg_mmx_export(reg);
            info->x86.operands[0].access = 0;
            info->x86.operands[1].access = 0;
            return 1;
        }
        if (idx == 0xd6 && (s->prefix[0] == dt_X86_PREFIX_REPNE ||
                             s->prefix[0] == dt_X86_PREFIX_REP)) {
            int m = fd_read_byte_s(s);
            if (m < 0) return 0;
            int mod_val = (m >> 6) & 3;
            if (mod_val != 3) return 0;
            int reg = ((m >> 3) & 7) | s->rex_r;
            int rm = (m & 7) | s->rex_b;
            int modrm_reg = (m >> 3) & 7;
            int modrm_rm = m & 7;
            info->x86.modrm = m;
            info->id = (s->prefix[0] == dt_X86_PREFIX_REPNE)
                     ? dt_X86_INS_MOVDQ2Q : dt_X86_INS_MOVQ2DQ;
            info->x86.op_count = 2;
            if (info->id == dt_X86_INS_MOVDQ2Q) {
                info->x86.operands[0].type = dt_X86_OP_REG;
                info->x86.operands[0].size = 8;
                info->x86.operands[0].reg = fd_reg_mmx_export(modrm_reg);
                info->x86.operands[1].type = dt_X86_OP_REG;
                info->x86.operands[1].size = 16;
                info->x86.operands[1].reg = fd_reg_xmm_export(rm);
            } else {
                info->x86.operands[0].type = dt_X86_OP_REG;
                info->x86.operands[0].size = 16;
                info->x86.operands[0].reg = fd_reg_xmm_export(reg);
                info->x86.operands[1].type = dt_X86_OP_REG;
                info->x86.operands[1].size = 8;
                info->x86.operands[1].reg = fd_reg_mmx_export(modrm_rm);
            }
            info->x86.operands[0].access = 0;
            info->x86.operands[1].access = 0;
            return 1;
        }
        if (idx == 0xd6)
            ins_id = dt_X86_INS_MOVQ;
        else if (s->rex_w)
            ins_id = dt_X86_INS_MOVQ;
        else if (idx == 0x7e && s->prefix[0] == dt_X86_PREFIX_REP)
            ins_id = dt_X86_INS_MOVQ;
        else
            ins_id = dt_X86_INS_MOVD;
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm = (m & 7) | s->rex_b;
        int rw = m & 7;
        bool mmx_movd = s->prefix[0] == 0 && s->prefix[2] == 0 &&
                         (idx == 0x6e || idx == 0x7e);
        info->x86.modrm = m;
        info->id = ins_id;
        info->x86.op_count = 2;
        int gpr_sz = mmx_movd ? (s->rex_w ? 8 : 4) :
                     (idx == 0xd6 || (idx == 0x7e && s->prefix[0] == dt_X86_PREFIX_REP)) ? 8 :
                     (s->rex_w ? 8 : 4);
        int simd_reg = mmx_movd ? fd_reg_mmx_export(reg) :
                       fd_reg_xmm_export(reg);
        info->x86.operands[1].access = 0;
        info->x86.operands[0].access = 0;
        if ((op & 0xff) == 0x6e) {
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = mmx_movd ? 8 : 16;
            info->x86.operands[0].reg = simd_reg;
            if (mod_val == 3) {
                info->x86.operands[1].type = dt_X86_OP_REG;
                info->x86.operands[1].size = gpr_sz;
                info->x86.operands[1].reg = fd_reg_by_size(rm, gpr_sz * 8);
            } else {
                info->x86.operands[1].type = dt_X86_OP_MEM;
                info->x86.operands[1].size = gpr_sz;
                fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, rw);
            }
        } else if ((op & 0xff) == 0xd6) {
            /* MOVQ m64/xmm, xmm */
            int mem_sz = (mod_val == 3) ? 16 : 8;
            if (mod_val == 3) {
                info->x86.operands[0].type = dt_X86_OP_REG;
                info->x86.operands[0].size = 16;
                info->x86.operands[0].reg = fd_reg_xmm_export(rm);
            } else {
                info->x86.operands[0].type = dt_X86_OP_MEM;
                info->x86.operands[0].size = mem_sz;
                fd_decode_mem_addr_s(s, &info->x86.operands[0], mod_val, rw);
            }
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 16;
            info->x86.operands[1].reg = fd_reg_xmm_export(reg);
        } else {
            /* 0x7E: MOVD r/m32, xmm — or MOVQ xmm, r/m64 with F3 prefix */
            int is_load = ((op & 0xff) == 0x7e && s->prefix[0] == dt_X86_PREFIX_REP);
            if (is_load) {
                /* F3 0F 7E: MOVQ xmm, r/m64 (LOAD) */
                info->x86.operands[0].type = dt_X86_OP_REG;
                info->x86.operands[0].size = 16;
                info->x86.operands[0].reg = simd_reg;
                if (mod_val == 3) {
                    info->x86.operands[1].type = dt_X86_OP_REG;
                    info->x86.operands[1].size = 16;
                    info->x86.operands[1].reg = fd_reg_xmm_export(rm);
                } else {
                    info->x86.operands[1].type = dt_X86_OP_MEM;
                    info->x86.operands[1].size = gpr_sz;
                    fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, rw);
                }
            } else {
                /* 0x7E: MOVD r/m32, xmm (STORE) */
                if (mod_val == 3) {
                    info->x86.operands[0].type = dt_X86_OP_REG;
                    info->x86.operands[0].size = gpr_sz;
                    info->x86.operands[0].reg = fd_reg_by_size(rm, gpr_sz * 8);
                } else {
                    info->x86.operands[0].type = dt_X86_OP_MEM;
                    info->x86.operands[0].size = gpr_sz;
                    fd_decode_mem_addr_s(s, &info->x86.operands[0], mod_val, rw);
                }
                info->x86.operands[1].type = dt_X86_OP_REG;
                info->x86.operands[1].size = mmx_movd ? 8 : 16;
                info->x86.operands[1].reg = simd_reg;
            }
        }
        return 1;
    }

    /* PMOVMSKB (0xD7): opnd[1] is MMX without 0x66, XMM with it. */
    if (idx == 0xd7) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        bool is_mmx = s->prefix[0] == 0 && s->prefix[2] == 0;

        if (!is_mmx &&
            !(s->prefix[0] == 0 &&
              s->prefix[2] == dt_X86_PREFIX_OPSIZE)) {
            return 0;
        }
        if (mod_val != 3) return 0;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm = is_mmx ? (m & 7) : ((m & 7) | s->rex_b);
        info->x86.modrm = m;
        info->id = dt_X86_INS_PMOVMSKB;
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 4;
        info->x86.operands[0].reg = fd_reg_by_size(reg, 32);
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = is_mmx ? 8 : 16;
        info->x86.operands[1].reg = is_mmx ? fd_reg_mmx_export(rm) :
                                             fd_reg_xmm_export(rm);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* MOVDQA vs MOVDQU (0x6F/0x7F with F3 prefix) */
    if (idx == 0x6f || idx == 0x7f) {
        if (s->prefix[0] == dt_X86_PREFIX_REP)
            ins_id = dt_X86_INS_MOVDQU;
        else
            ins_id = dt_X86_INS_MOVDQA;
    }

    /* PSHUFW/PSHUFD/PSHUFHW/PSHUFLW (0x70 with none/66/F3/F2 prefix) */
    if (idx == 0x70 && s->prefix[0] != dt_X86_PREFIX_REP &&
        s->prefix[0] != dt_X86_PREFIX_REPNE &&
        s->prefix[2] != dt_X86_PREFIX_OPSIZE) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm = (m & 7) | s->rex_b;

        info->x86.modrm = m;
        info->id = dt_X86_INS_PSHUFW;
        info->x86.op_count = 3;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 8;
        info->x86.operands[0].reg = fd_reg_mmx_export(reg);
        if (mod_val == 3) {
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 8;
            info->x86.operands[1].reg = fd_reg_mmx_export(rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = 8;
            fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
        }
        opnd_write_imm_val(&info->x86.operands[2], 8,
                           (uint8_t)fd_read_byte_s(s));
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        info->x86.operands[2].access = 0;
        return 1;
    }
    if (idx == 0x70 && s->prefix[0] == dt_X86_PREFIX_REP)
        ins_id = dt_X86_INS_PSHUFHW;
    if (idx == 0x70 && s->prefix[0] == dt_X86_PREFIX_REPNE)
        ins_id = dt_X86_INS_PSHUFLW;
    if (idx == 0xc6 && s->prefix[2] == dt_X86_PREFIX_OPSIZE)
        ins_id = dt_X86_INS_SHUFPD;

    /* MOVMSKPS/MOVMSKPD (0x50): opnd[0]=GPR32, opnd[1]=XMM */
    if (idx == 0x50) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        if (mod_val != 3) return 0;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm = (m & 7) | s->rex_b;
        info->x86.modrm = m;
        info->id = (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_MOVMSKPD
                                                           : dt_X86_INS_MOVMSKPS;
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 4;
        info->x86.operands[0].reg = fd_reg_by_size(reg, 32);
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = 16;
        info->x86.operands[1].reg = fd_reg_xmm_export(rm);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* PINSRW (0xC4): opnd[0]=xmm, opnd[1]=r/m16, opnd[2]=imm8 */
    if (idx == 0xc4) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        bool is_mmx = s->prefix[0] == 0 && s->prefix[2] == 0;
        int reg = ((m >> 3) & 7) | (is_mmx ? 0 : s->rex_r);
        int rm = (m & 7) | s->rex_b;

        if (!is_mmx && s->prefix[2] != dt_X86_PREFIX_OPSIZE) {
            return 0;
        }
        info->x86.modrm = m;
        info->id = dt_X86_INS_PINSRW;
        info->x86.op_count = 3;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = is_mmx ? 8 : 16;
        info->x86.operands[0].reg = is_mmx ? fd_reg_mmx_export(reg) :
                                             fd_reg_xmm_export(reg);
        if (mod_val == 3) {
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 4;
            info->x86.operands[1].reg = fd_reg_by_size(rm, 32);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = 2;
            fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
        }
        opnd_write_imm_val(&info->x86.operands[2], 8, (uint8_t)fd_read_byte_s(s));
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        info->x86.operands[2].access = 0;
        return 1;
    }

    /* PEXTRW (0xC5): legacy MMX or 66-prefixed XMM source. */
    if (idx == 0xc5) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        if (mod_val != 3) return 0;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm_raw = m & 7;
        info->x86.modrm = m;
        info->id = dt_X86_INS_PEXTRW;
        info->x86.op_count = 3;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 4;
        info->x86.operands[0].reg = fd_reg_by_size(reg, 32);
        info->x86.operands[1].type = dt_X86_OP_REG;
        if (s->prefix[0] == 0 && s->prefix[2] == 0) {
            /* REX.W and REX.B do not extend legacy MMX register operands. */
            info->x86.operands[1].size = 8;
            info->x86.operands[1].reg = fd_reg_mmx_export(rm_raw);
        } else if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
            info->x86.operands[1].size = 16;
            info->x86.operands[1].reg = fd_reg_xmm_export(rm_raw | s->rex_b);
        } else {
            return 0;
        }
        opnd_write_imm_val(&info->x86.operands[2], 8, (uint8_t)fd_read_byte_s(s));
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        info->x86.operands[2].access = 0;
        return 1;
    }

    /* CMPPS/CMPPD/CMPSS/CMPSD: op0=xmm, op1=xmm/mem, op2=imm8. */
    if (idx == 0xc2) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm = (m & 7) | s->rex_b;
        int mem_sz = 16;
        if (s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
        } else if (s->prefix[0] == dt_X86_PREFIX_REP) {
            mem_sz = 4;
        } else if (s->prefix[0] == dt_X86_PREFIX_REPNE) {
            mem_sz = 8;
        }
        info->x86.modrm = m;
        info->id = ins_id;
        info->x86.op_count = 3;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 16;
        info->x86.operands[0].reg = fd_reg_xmm_export(reg);
        if (mod_val == 3) {
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 16;
            info->x86.operands[1].reg = fd_reg_xmm_export(rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = mem_sz;
            fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
        }
        opnd_write_imm_val(&info->x86.operands[2], 8,
                           (uint8_t)fd_read_byte_s(s));
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        info->x86.operands[2].access = 0;
        return 1;
    }

    /* MOVLPS/MOVLPD (0x12/0x13) and MOVHPS/MOVHPD (0x16/0x17).
     * Memory source is m64; register forms are MOVHLPS/MOVLHPS. */
    if (idx == 0x12 || idx == 0x13 || idx == 0x16 || idx == 0x17) {
        if ((idx == 0x12 || idx == 0x16) &&
            (s->prefix[0] == dt_X86_PREFIX_REP ||
             s->prefix[0] == dt_X86_PREFIX_REPNE))
            return fd_sse_modrm(s, info, ins_id, 0);
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        if ((idx == 0x13 || idx == 0x17) && mod_val == 3)
            return 0;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm = (m & 7) | s->rex_b;
        int rw = m & 7;
        info->x86.modrm = m;
        info->x86.op_count = 2;
        int is_store = (idx == 0x13 || idx == 0x17);
        if (!is_store) {
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = 16;
            info->x86.operands[0].reg = fd_reg_xmm_export(reg);
        }
        if (mod_val == 3) {
            info->id = (idx == 0x12) ? dt_X86_INS_MOVHLPS : dt_X86_INS_MOVLHPS;
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 16;
            info->x86.operands[1].reg = fd_reg_xmm_export(rm);
            info->x86.operands[0].access = 0;
            info->x86.operands[1].access = 0;
            return 1;
        }
        info->id = ins_id;
        if (idx == 0x13)
            info->id = (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_MOVLPD
                                                              : dt_X86_INS_MOVLPS;
        else if (idx == 0x17)
            info->id = (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_MOVHPD
                                                              : dt_X86_INS_MOVHPS;
        int mem_idx = is_store ? 0 : 1;
        int reg_idx = is_store ? 1 : 0;
        info->x86.operands[mem_idx].type = dt_X86_OP_MEM;
        info->x86.operands[mem_idx].size = 8;
        info->x86.operands[mem_idx].mem.segment = dt_X86_REG_INVALID;
        info->x86.operands[mem_idx].mem.index = dt_X86_REG_INVALID;
        info->x86.operands[mem_idx].mem.scale = 0;
        info->x86.operands[mem_idx].mem.disp = 0;
        info->x86.operands[mem_idx].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[mem_idx].avx_zero_opmask = 0;
        if (is_store) {
            info->x86.operands[reg_idx].type = dt_X86_OP_REG;
            info->x86.operands[reg_idx].size = 16;
            info->x86.operands[reg_idx].reg = fd_reg_xmm_export(reg);
        }
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        int base = rw | s->rex_b;
        int index = -1, scale = 0, havesib = 0;
        if (s->aflag == 64 || s->aflag == 32) {
            if (rw == 4) {
                int sib = fd_read_byte_s(s);
                if (sib < 0) return 0;
                scale = (sib >> 6) & 3;
                index = ((sib >> 3) & 7) | s->rex_x;
                if (index == 4) index = -1;
                base = (sib & 7) | s->rex_b; havesib = 1;
            }
            switch (mod_val) {
            case 0:
                if ((base & 7) == 5) {
                    if (s->aflag == 64 && !havesib)
                        info->x86.operands[mem_idx].mem.base = dt_X86_REG_RIP;
                    info->x86.operands[mem_idx].mem.disp = (int32_t)fd_read_imm32_s(s);
                    base = -1;
                }
                break;
            case 1: info->x86.operands[mem_idx].mem.disp = (int8_t)fd_read_byte_s(s); break;
            case 2: info->x86.operands[mem_idx].mem.disp = (int32_t)fd_read_imm32_s(s); break;
            }
        }
        if (base >= 0) info->x86.operands[mem_idx].mem.base = fd_reg_gpr(base, s);
        if (index >= 0) info->x86.operands[mem_idx].mem.index = fd_reg_gpr(index, s);
        info->x86.operands[mem_idx].mem.scale = 1 << scale;
        return 1;
    }

    /* Grp shift (0x71/0x72/0x73): instruction depends on ModRM reg field */
    if (idx == 0x71 || idx == 0x72 || idx == 0x73) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        int op_ext = (m >> 3) & 7;
        int rm = (m & 7) | s->rex_b;
        bool is_mmx = s->prefix[0] == 0 && s->prefix[2] == 0;
        static const unsigned int g71[] = {0,0,dt_X86_INS_PSRLW,0,dt_X86_INS_PSRAW,0,dt_X86_INS_PSLLW,0};
        static const unsigned int g72[] = {0,0,dt_X86_INS_PSRLD,0,dt_X86_INS_PSRAD,0,dt_X86_INS_PSLLD,0};
        static const unsigned int g73[] = {0,0,dt_X86_INS_PSRLQ,dt_X86_INS_PSRLDQ,0,0,dt_X86_INS_PSLLQ,dt_X86_INS_PSLLDQ};
        const unsigned int *tbl = (idx == 0x71)?g71:(idx == 0x72)?g72:g73;
        if ((!is_mmx && s->prefix[2] != dt_X86_PREFIX_OPSIZE) ||
            mod_val != 3 || op_ext > 7 || !tbl[op_ext] ||
            (is_mmx && idx == 0x73 && op_ext != 2 && op_ext != 6)) {
            return 0;
        }
        info->x86.modrm = m;
        info->id = tbl[op_ext];
        info->x86.op_count = 2;
        if (is_mmx) {
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = 8;
            info->x86.operands[0].reg = fd_reg_mmx_export(m & 7);
        } else {
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = 16;
            info->x86.operands[0].reg = fd_reg_xmm_export(rm);
        }
        info->x86.operands[0].access = 0;
        info->x86.operands[1].type = dt_X86_OP_IMM;
        info->x86.operands[1].size = 1;
        info->x86.operands[1].imm = (int8_t)fd_read_byte_s(s);
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* CVTSI2SD/CVTSI2SS (0x2A, F2/F3): dest=XMM, src=GP r/m32/r/m64 */
    if (idx == 0x2a) {
        if (s->prefix[0] != dt_X86_PREFIX_REPNE && s->prefix[0] != dt_X86_PREFIX_REP)
            return 0;
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm  = (m & 7) | s->rex_b;
        info->x86.modrm = m;
        info->id = (s->prefix[0] == dt_X86_PREFIX_REPNE) ? dt_X86_INS_CVTSI2SD
                                                          : dt_X86_INS_CVTSI2SS;
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 16;
        info->x86.operands[0].reg = fd_reg_xmm_export(reg);
        info->x86.operands[0].access = dt_CS_AC_WRITE;
        int gpr_sz = s->rex_w ? 8 : 4;
        if (mod_val == 3) {
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = gpr_sz;
            info->x86.operands[1].reg = fd_reg_by_size(rm, gpr_sz * 8);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = gpr_sz;
            fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
        }
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* CVTTSD2SI/CVTTSS2SI (0x2C, F2/F3): dest=GPR, src=XMM/m64|m32 */
    if (idx == 0x2c || idx == 0x2d) {
        if (s->prefix[0] != dt_X86_PREFIX_REPNE && s->prefix[0] != dt_X86_PREFIX_REP)
            return 0;
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm  = (m & 7) | s->rex_b;
        int gpr_sz = s->rex_w ? 8 : 4;
        int mem_sz = (s->prefix[0] == dt_X86_PREFIX_REPNE) ? 8 : 4;
        info->x86.modrm = m;
        info->id = (idx == 0x2c)
                 ? ((s->prefix[0] == dt_X86_PREFIX_REPNE) ? dt_X86_INS_CVTTSD2SI
                                                           : dt_X86_INS_CVTTSS2SI)
                 : ((s->prefix[0] == dt_X86_PREFIX_REPNE) ? dt_X86_INS_CVTSD2SI
                                                           : dt_X86_INS_CVTSS2SI);
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = gpr_sz;
        info->x86.operands[0].reg = fd_reg_by_size(reg, gpr_sz * 8);
        info->x86.operands[0].access = dt_CS_AC_WRITE;
        if (mod_val == 3) {
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 16;
            info->x86.operands[1].reg = fd_reg_xmm_export(rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = mem_sz;
            fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
        }
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    if (idx == 0xe7 && s->prefix[2] == dt_X86_PREFIX_OPSIZE) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        if (mod_val == 3) return 0;
        int reg = ((m >> 3) & 7) | s->rex_r;

        info->x86.modrm = m;
        info->id = dt_X86_INS_MOVNTDQ;
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_MEM;
        info->x86.operands[0].size = 16;
        fd_decode_mem_addr_s(s, &info->x86.operands[0], mod_val, m & 7);
        info->x86.operands[1].type = dt_X86_OP_REG;
        info->x86.operands[1].size = 16;
        info->x86.operands[1].reg = fd_reg_xmm_export(reg);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* COMISS/UCOMISS or COMISD/UCOMISD: op0=XMM, op1=XMM/m32/m64 */
    if (idx == 0x2f || idx == 0x2e) {
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm  = (m & 7) | s->rex_b;
        info->x86.modrm = m;
        info->id = ins_id;
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 16;
        info->x86.operands[0].reg = fd_reg_xmm_export(reg);
        info->x86.operands[0].access = dt_CS_AC_READ;
        if (mod_val == 3) {
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 16;
            info->x86.operands[1].reg = fd_reg_xmm_export(rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = (ins_id == dt_X86_INS_COMISD) ? 16 :
                                          fd_sse_mem_size(ins_id);
            fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
        }
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* CVTDQ2PD/CVT(T)PD2DQ (0xE6, F3/66/F2): dest=XMM, src=XMM/m64|m128 */
    if (idx == 0xe6) {
        if (s->prefix[0] != dt_X86_PREFIX_REP &&
            s->prefix[0] != dt_X86_PREFIX_REPNE &&
            s->prefix[2] != dt_X86_PREFIX_OPSIZE)
            return 0;
        int m = fd_read_byte_s(s);
        if (m < 0) return 0;
        int mod_val = (m >> 6) & 3;
        int reg = ((m >> 3) & 7) | s->rex_r;
        int rm  = (m & 7) | s->rex_b;
        info->x86.modrm = m;
        info->id = (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? dt_X86_INS_CVTTPD2DQ
                 : (s->prefix[0] == dt_X86_PREFIX_REPNE) ? dt_X86_INS_CVTPD2DQ
                                                          : dt_X86_INS_CVTDQ2PD;
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 16;
        info->x86.operands[0].reg = fd_reg_xmm_export(reg);
        info->x86.operands[0].access = dt_CS_AC_WRITE;
        if (mod_val == 3) {
            info->x86.operands[1].type = dt_X86_OP_REG;
            info->x86.operands[1].size = 16;
            info->x86.operands[1].reg = fd_reg_xmm_export(rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size =
                (info->id == dt_X86_INS_CVTTPD2DQ ||
                 info->id == dt_X86_INS_CVTPD2DQ) ? 16 : 8;
            fd_decode_mem_addr_s(s, &info->x86.operands[1], mod_val, m & 7);
        }
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    int has_imm8 = (idx == 0x70 || idx == 0xC2 || idx == 0xC4
                 || idx == 0xC5 || idx == 0xC6);
    return fd_sse_modrm(s, info, ins_id, has_imm8);
}
