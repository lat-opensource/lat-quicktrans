/*
 * SPDX-FileCopyrightText: 2021-2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/*
 * fast_decoder.c — TCG-inspired x86 instruction decoder for LATX.
 *
 * Designed to replace Capstone in the decode path.
 * Generates la_dt_insn (IR1) directly from raw x86 bytes.
 *
 * Reference architecture: target/i386/tcg/translate.c prefix loop + opcode switch.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "quicktrans/detail/fast_decoder.h"
#include "quicktrans/detail/x86.h"
#include "quicktrans/detail/latx-disassemble-trace.h"


/* ------------------------------------------------------------------ */
/*  Register mapping tables                                           */
/* ------------------------------------------------------------------ */

static const dt_x86_reg fd_reg8[] = {
    dt_X86_REG_AL, dt_X86_REG_CL, dt_X86_REG_DL, dt_X86_REG_BL,
    dt_X86_REG_AH, dt_X86_REG_CH, dt_X86_REG_DH, dt_X86_REG_BH,
    dt_X86_REG_R8B, dt_X86_REG_R9B, dt_X86_REG_R10B, dt_X86_REG_R11B,
    dt_X86_REG_R12B, dt_X86_REG_R13B, dt_X86_REG_R14B, dt_X86_REG_R15B,
};

static const dt_x86_reg fd_reg16[] = {
    dt_X86_REG_AX, dt_X86_REG_CX, dt_X86_REG_DX, dt_X86_REG_BX,
    dt_X86_REG_SP, dt_X86_REG_BP, dt_X86_REG_SI, dt_X86_REG_DI,
    dt_X86_REG_R8W, dt_X86_REG_R9W, dt_X86_REG_R10W, dt_X86_REG_R11W,
    dt_X86_REG_R12W, dt_X86_REG_R13W, dt_X86_REG_R14W, dt_X86_REG_R15W,
};

static const dt_x86_reg fd_reg32[] = {
    dt_X86_REG_EAX, dt_X86_REG_ECX, dt_X86_REG_EDX, dt_X86_REG_EBX,
    dt_X86_REG_ESP, dt_X86_REG_EBP, dt_X86_REG_ESI, dt_X86_REG_EDI,
    dt_X86_REG_R8D, dt_X86_REG_R9D, dt_X86_REG_R10D, dt_X86_REG_R11D,
    dt_X86_REG_R12D, dt_X86_REG_R13D, dt_X86_REG_R14D, dt_X86_REG_R15D,
};

static const dt_x86_reg fd_reg64[] = {
    dt_X86_REG_RAX, dt_X86_REG_RCX, dt_X86_REG_RDX, dt_X86_REG_RBX,
    dt_X86_REG_RSP, dt_X86_REG_RBP, dt_X86_REG_RSI, dt_X86_REG_RDI,
    dt_X86_REG_R8,  dt_X86_REG_R9,  dt_X86_REG_R10, dt_X86_REG_R11,
    dt_X86_REG_R12, dt_X86_REG_R13, dt_X86_REG_R14, dt_X86_REG_R15,
};

static const dt_x86_reg fd_reg_xmm[] = {
    dt_X86_REG_XMM0,  dt_X86_REG_XMM1,  dt_X86_REG_XMM2,  dt_X86_REG_XMM3,
    dt_X86_REG_XMM4,  dt_X86_REG_XMM5,  dt_X86_REG_XMM6,  dt_X86_REG_XMM7,
    dt_X86_REG_XMM8,  dt_X86_REG_XMM9,  dt_X86_REG_XMM10, dt_X86_REG_XMM11,
    dt_X86_REG_XMM12, dt_X86_REG_XMM13, dt_X86_REG_XMM14, dt_X86_REG_XMM15,
};

static const dt_x86_reg fd_reg_st[] = {
    dt_X86_REG_ST0, dt_X86_REG_ST1, dt_X86_REG_ST2, dt_X86_REG_ST3,
    dt_X86_REG_ST4, dt_X86_REG_ST5, dt_X86_REG_ST6, dt_X86_REG_ST7,
};

static const dt_x86_reg fd_reg_mmx[] = {
    dt_X86_REG_MM0, dt_X86_REG_MM1, dt_X86_REG_MM2, dt_X86_REG_MM3,
    dt_X86_REG_MM4, dt_X86_REG_MM5, dt_X86_REG_MM6, dt_X86_REG_MM7,
};

static const dt_x86_reg fd_reg_seg[] = {
    dt_X86_REG_ES, dt_X86_REG_CS, dt_X86_REG_SS,
    dt_X86_REG_DS, dt_X86_REG_FS, dt_X86_REG_GS,
};

static const dt_x86_reg fd_reg8_rex[] = {
    dt_X86_REG_AL, dt_X86_REG_CL, dt_X86_REG_DL, dt_X86_REG_BL,
    dt_X86_REG_SPL, dt_X86_REG_BPL, dt_X86_REG_SIL, dt_X86_REG_DIL,
    dt_X86_REG_R8B, dt_X86_REG_R9B, dt_X86_REG_R10B, dt_X86_REG_R11B,
    dt_X86_REG_R12B, dt_X86_REG_R13B, dt_X86_REG_R14B, dt_X86_REG_R15B,
};

static inline dt_x86_reg fd_reg(int num, int size_bits)
{
    int idx = num & 0xf;
    switch (size_bits) {
    case 8:  return fd_reg8[idx];
    case 16: return fd_reg16[idx];
    case 32: return fd_reg32[idx];
    case 64: return fd_reg64[idx];
    case 128: return fd_reg_xmm[idx];
    default: return dt_X86_REG_INVALID;
    }
}

/* Reserved for future use (FPU instructions)
static dt_x86_reg fd_reg8_aware(FDState *s, int num)
{
    if (s->has_rex)
        return fd_reg8_rex[num & 0xf];
    return fd_reg8[num & 0xf];
}
*/

/* ------------------------------------------------------------------ */
/*  Decode context (defined in fast_decoder.h)                          */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  Byte reader                                                        */
/* ------------------------------------------------------------------ */

static inline int fd_read_byte(FDState *s)
{
    if (s->pos >= s->code_size)
        return -1;
    return s->code[s->pos++];
}

static inline int fd_read_imm8(FDState *s)
{
    int v = fd_read_byte(s);
    return v < 0 ? 0 : (int8_t)v;
}

static inline uint32_t fd_read_imm32(FDState *s)
{
    if (s->pos + 4 > s->code_size)
        return 0;
    uint32_t v = *(const uint32_t *)(s->code + s->pos);
    s->pos += 4;
    return v;
}

static inline uint16_t fd_read_imm16(FDState *s)
{
    if (s->pos + 2 > s->code_size)
        return 0;
    uint16_t v = *(const uint16_t *)(s->code + s->pos);
    s->pos += 2;
    return v;
}

/* Exported wrappers for SSE/FPU decoders */
int fd_read_byte_s(FDState *s) { return fd_read_byte(s); }
uint32_t fd_read_imm32_s(FDState *s) { return fd_read_imm32(s); }
dt_x86_reg fd_reg_gpr(int num, FDState *s) {
    int sz = (s->aflag == 64) ? 64 : s->aflag;
    return fd_reg(num, sz);
}
dt_x86_reg fd_reg_xmm_export(int num) {
    num &= 0xf;
    return (num < 16) ? fd_reg_xmm[num] : dt_X86_REG_INVALID;
}
dt_x86_reg fd_reg_mmx_export(int num) {
    return fd_reg_mmx[num & 7];
}
dt_x86_reg fd_reg_by_size(int num, int size_bits) {
    return fd_reg(num, size_bits);
}
int fd_decode_mem_addr_s(FDState *s, void *opnd, int mod_val, int rm_raw) {
    return fd_decode_mem_addr(s, (dt_cs_x86_op*)opnd, mod_val, rm_raw, NULL, NULL);
}

/* ------------------------------------------------------------------ */
/*  Prefix scanner — modeled after TCG translate.c:4514-4623          */
/* ------------------------------------------------------------------ */

static int parse_prefixes(FDState *s)
{
    int b;
    while (s->pos < s->code_size) {
        b = s->code[s->pos];
        switch (b) {
        case 0xf0: s->prefix[0] = dt_X86_PREFIX_LOCK;  s->pos++; break;
        case 0xf3: s->prefix[0] = dt_X86_PREFIX_REP;   s->pos++; break;
        case 0xf2: s->prefix[0] = dt_X86_PREFIX_REPNE; s->pos++; break;
        case 0x2e: s->prefix[1] = dt_X86_PREFIX_CS;    s->pos++; break;
        case 0x36: s->prefix[1] = dt_X86_PREFIX_SS;    s->pos++; break;
        case 0x3e: s->prefix[1] = dt_X86_PREFIX_DS;    s->pos++; break;
        case 0x26: s->prefix[1] = dt_X86_PREFIX_ES;    s->pos++; break;
        case 0x64: s->prefix[1] = dt_X86_PREFIX_FS;    s->pos++; break;
        case 0x65: s->prefix[1] = dt_X86_PREFIX_GS;    s->pos++; break;
        case 0x66: s->prefix[2] = dt_X86_PREFIX_OPSIZE;   s->pos++; break;
        case 0x67: s->prefix[3] = dt_X86_PREFIX_ADDRSIZE; s->pos++; break;
        default:
            if (s->mode && b >= 0x40 && b <= 0x4f) {
                s->rex = b;
                s->has_rex = 1;
                s->rex_w = (b >> 3) & 1;
                s->rex_r = (b & 0x4) << 1;
                s->rex_x = (b & 0x2) << 2;
                s->rex_b = (b & 0x1) << 3;
                s->pos++;
                continue;
            }
            s->pos++;
            return b;
        }
        /* A legacy prefix after REX makes that REX ineffective.  A later
         * REX can still replace it on the next iteration. */
        if (s->has_rex) {
            s->rex = 0;
            s->has_rex = 0;
            s->rex_w = s->rex_r = s->rex_x = s->rex_b = 0;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Size determination — modeled after TCG translate.c:4627-4647      */
/* ------------------------------------------------------------------ */

static void determine_sizes(FDState *s)
{
    if (s->mode) {
        /* 64-bit mode */
        s->dflag = s->rex_w ? 64
                  : (s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 : 32);
        s->aflag = (s->prefix[3] == dt_X86_PREFIX_ADDRSIZE) ? 32 : 64;
    } else {
        /* 32-bit mode */
        s->dflag = (s->prefix[2] == dt_X86_PREFIX_OPSIZE) ? 16 : 32;
        s->aflag = (s->prefix[3] == dt_X86_PREFIX_ADDRSIZE) ? 16 : 32;
    }
}

/* Generic memory address decoder (for Grp1/2/3/C7 etc.), exported for SSE */
static void fd_set_segment(FDState *s, dt_cs_x86_op *opnd)
{
    /* Match Capstone convention: segment=INVALID unless overridden by prefix.
     * The translator determines the effective segment from the base register. */
    if (s->prefix[1] == dt_X86_PREFIX_CS)
        opnd->mem.segment = dt_X86_REG_CS;
    else if (s->prefix[1] == dt_X86_PREFIX_SS)
        opnd->mem.segment = dt_X86_REG_SS;
    else if (s->prefix[1] == dt_X86_PREFIX_DS)
        opnd->mem.segment = dt_X86_REG_DS;
    else if (s->prefix[1] == dt_X86_PREFIX_ES)
        opnd->mem.segment = dt_X86_REG_ES;
    else if (s->prefix[1] == dt_X86_PREFIX_FS)
        opnd->mem.segment = dt_X86_REG_FS;
    else if (s->prefix[1] == dt_X86_PREFIX_GS)
        opnd->mem.segment = dt_X86_REG_GS;
    /* else: leave as INVALID (default) */
}

int fd_decode_mem_addr(FDState *s, dt_cs_x86_op *opnd,
                               int mod, int rm_raw, int *out_base, int *out_index)
{
    int base = (rm_raw | s->rex_b);
    int index = -1, scale = 0, havesib = 0;
    opnd->mem.segment = dt_X86_REG_INVALID;
    opnd->mem.index = dt_X86_REG_INVALID;
    opnd->mem.disp = 0;

    if (s->aflag == 64 || s->aflag == 32) {
        if (rm_raw == 4) {
            int sib = fd_read_byte(s);
            if (sib < 0) return -1;
            scale = (sib >> 6) & 3;
            index = ((sib >> 3) & 7) | s->rex_x;
            if (index == 4) index = -1;
            base = (sib & 7) | s->rex_b;
            havesib = 1;
        }
        switch (mod) {
        case 0:
            if ((base & 7) == 5) {
                if (s->aflag == 64 && !havesib)
                    opnd->mem.base = dt_X86_REG_RIP;
                opnd->mem.disp = (int32_t)fd_read_imm32(s);
                base = -1;
            }
            break;
        case 1: opnd->mem.disp = (int8_t)fd_read_imm8(s); break;
        case 2: opnd->mem.disp = (int32_t)fd_read_imm32(s); break;
        }
    }
    if (base >= 0) {
        opnd->mem.base = fd_reg(base, s->aflag == 64 ? 64 : s->aflag);
    }
    if (index >= 0)
        opnd->mem.index = fd_reg(index, s->aflag == 64 ? 64 : s->aflag);
    opnd->mem.scale = 1 << scale;

    /* Set segment based on prefix override (matches Capstone convention) */
    fd_set_segment(s, opnd);

    if (out_base) *out_base = base;
    if (out_index) *out_index = index;
    return mod;
}

/* Reserved for future use (0xFF group instructions)
static int read_reg_reg_modrm(FDState *s, int *out_reg, int *out_rm)
{
    int modrm = fd_read_byte(s);
    if (modrm < 0) return -1;

    int mod = (modrm >> 6) & 3;
    if (mod != 3)
        return -1;

    *out_reg = ((modrm >> 3) & 7) | s->rex_r;
    *out_rm  = (modrm & 7) | s->rex_b;
    return modrm;
}
*/

/* ------------------------------------------------------------------ */
/*  Operand filling helpers                                            */
/* ------------------------------------------------------------------ */

static inline void opnd_write_reg(dt_cs_x86_op *opnd, int size_bits, int reg_num)
{
    opnd->type = dt_X86_OP_REG;
    opnd->size = size_bits / 8;
    opnd->reg  = fd_reg(reg_num, size_bits);
    opnd->avx_bcast = dt_X86_AVX_BCAST_INVALID;
    opnd->avx_zero_opmask = 0;
}

static inline void opnd_write_seg(dt_cs_x86_op *opnd, int seg_num)
{
    opnd->type = dt_X86_OP_REG;
    opnd->size = 2;
    opnd->reg = seg_num >= 0 && seg_num < 6 ? fd_reg_seg[seg_num] :
                                              dt_X86_REG_INVALID;
    opnd->avx_bcast = dt_X86_AVX_BCAST_INVALID;
    opnd->avx_zero_opmask = 0;
}

static inline void opnd_write_imm(dt_cs_x86_op *opnd, int size_bits, int64_t val)
{
    opnd->type = dt_X86_OP_IMM;
    opnd->size = size_bits / 8;
    opnd->imm  = val;
    opnd->avx_bcast = dt_X86_AVX_BCAST_INVALID;
    opnd->avx_zero_opmask = 0;
}

/* Write an 8-bit register operand, with REX-aware register mapping */
static inline void opnd_write_reg8(dt_cs_x86_op *opnd, int reg_num, int has_rex)
{
    opnd->type = dt_X86_OP_REG;
    opnd->size = 1;
    opnd->reg  = has_rex ? fd_reg8_rex[reg_num & 0xf] : fd_reg8[reg_num & 0xf];
    opnd->avx_bcast = dt_X86_AVX_BCAST_INVALID;
    opnd->avx_zero_opmask = 0;
}

static inline void opnd_write_mem_base(dt_cs_x86_op *opnd, int size_bits,
                                       dt_x86_reg base, dt_x86_reg segment)
{
    opnd->type = dt_X86_OP_MEM;
    opnd->size = size_bits / 8;
    opnd->mem.segment = segment;
    opnd->mem.base = base;
    opnd->mem.index = dt_X86_REG_INVALID;
    opnd->mem.scale = 1;
    opnd->mem.disp = 0;
    opnd->avx_bcast = dt_X86_AVX_BCAST_INVALID;
    opnd->avx_zero_opmask = 0;
}

static inline int fd_string_addr_size(FDState *s)
{
    return s->aflag == 64 ? 64 : 32;
}

static inline void opnd_write_fpu_reg(dt_cs_x86_op *opnd, int reg_num)
{
    opnd->type = dt_X86_OP_REG;
    opnd->size = 10;
    opnd->reg = fd_reg_st[reg_num & 7];
    opnd->avx_bcast = dt_X86_AVX_BCAST_INVALID;
    opnd->avx_zero_opmask = 0;
}

static void opnd_write_fpu_mem(FDState *s, dt_cs_x86_op *opnd,
                               int mod_val, int rm_raw, int size,
                               int access)
{
    opnd->type = dt_X86_OP_MEM;
    opnd->size = size;
    opnd->avx_bcast = dt_X86_AVX_BCAST_INVALID;
    opnd->avx_zero_opmask = 0;
    fd_decode_mem_addr(s, opnd, mod_val, rm_raw, NULL, NULL);
    opnd->access = access;
}

static int64_t fd_read_acc_imm(FDState *s, int size_bits)
{
    if (size_bits == 16)
        return fd_read_imm16(s);
    if (size_bits == 64)
        return (int32_t)fd_read_imm32(s);
    return fd_read_imm32(s);
}

static int64_t fd_read_acc_imm_unsigned16(FDState *s, int size_bits)
{
    if (size_bits == 16)
        return fd_read_imm16(s);
    return fd_read_acc_imm(s, size_bits);
}

/* ------------------------------------------------------------------ */
/*  Opcode dispatch helper for ALU reg-reg (01/03/29/2b/31/39/3b/85/89/8b) */
/* ------------------------------------------------------------------ */

static int decode_reg_reg_alu(FDState *s, struct la_dt_insn *info,
                               unsigned int ins_id, int swap_operands)
{
    int reg, rm;
    int modrm = fd_read_byte(s);
    if (modrm < 0) return 0;

    int mod_val = (modrm >> 6) & 3;
    reg = ((modrm >> 3) & 7) | s->rex_r;
    rm  = (modrm & 7) | s->rex_b;
    int rm_raw = modrm & 7;

    info->x86.modrm = modrm;
    info->id = ins_id;
    info->x86.op_count = 2;

    /* swap_operands: 0 for "Ev, Gv" → opnd[0]=rm(Ev), opnd[1]=reg(Gv)
     *                1 for "Gv, Ev" → opnd[0]=reg(Gv), opnd[1]=rm(Ev) */
    dt_cs_x86_op *op0 = &info->x86.operands[0];
    dt_cs_x86_op *op1 = &info->x86.operands[1];

    if (mod_val == 3) {
        opnd_write_reg(op0, s->dflag, swap_operands ? reg : rm);
        opnd_write_reg(op1, s->dflag, swap_operands ? rm  : reg);
    } else {
        /* Memory operand on the rm(Ev) side */
        int mem_opnd_idx = swap_operands ? 1 : 0;
        int reg_opnd_idx = swap_operands ? 0 : 1;
        opnd_write_reg(&info->x86.operands[reg_opnd_idx], s->dflag, reg);
        info->x86.operands[mem_opnd_idx].type = dt_X86_OP_MEM;
        info->x86.operands[mem_opnd_idx].size = s->dflag / 8;
        info->x86.operands[mem_opnd_idx].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[mem_opnd_idx].avx_zero_opmask = 0;
        fd_decode_mem_addr(s, &info->x86.operands[mem_opnd_idx], mod_val, rm_raw, NULL, NULL);
    }
    int writes_dest = (ins_id != dt_X86_INS_CMP && ins_id != dt_X86_INS_TEST);
    info->x86.operands[0].access = writes_dest ? (dt_CS_AC_READ | dt_CS_AC_WRITE) : dt_CS_AC_READ;
    info->x86.operands[1].access = 0;

    return 1;
}

static int decode_reg_reg_alu8(FDState *s, struct la_dt_insn *info,
                               unsigned int ins_id, int swap_operands)
{
    int modrm = fd_read_byte(s);
    if (modrm < 0) return 0;

    int mod_val = (modrm >> 6) & 3;
    int reg = ((modrm >> 3) & 7) | s->rex_r;
    int rm  = (modrm & 7) | s->rex_b;
    int rm_raw = modrm & 7;

    info->x86.modrm = modrm;
    info->id = ins_id;
    info->x86.op_count = 2;

    if (mod_val == 3) {
        opnd_write_reg8(&info->x86.operands[0], swap_operands ? reg : rm, s->has_rex);
        opnd_write_reg8(&info->x86.operands[1], swap_operands ? rm : reg, s->has_rex);
    } else {
        int mem_opnd_idx = swap_operands ? 1 : 0;
        int reg_opnd_idx = swap_operands ? 0 : 1;

        opnd_write_reg8(&info->x86.operands[reg_opnd_idx], reg, s->has_rex);
        info->x86.operands[mem_opnd_idx].type = dt_X86_OP_MEM;
        info->x86.operands[mem_opnd_idx].size = 1;
        info->x86.operands[mem_opnd_idx].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[mem_opnd_idx].avx_zero_opmask = 0;
        fd_decode_mem_addr(s, &info->x86.operands[mem_opnd_idx], mod_val, rm_raw, NULL, NULL);
    }

    int writes_dest = (ins_id != dt_X86_INS_CMP && ins_id != dt_X86_INS_TEST);
    info->x86.operands[0].access = writes_dest ? (dt_CS_AC_READ | dt_CS_AC_WRITE) : dt_CS_AC_READ;
    info->x86.operands[1].access = dt_CS_AC_READ;
    return 1;
}

static int decode_rm_unary8(FDState *s, struct la_dt_insn *info,
                            unsigned int ins_id)
{
    int modrm = fd_read_byte(s);
    if (modrm < 0) return 0;

    int mod_val = (modrm >> 6) & 3;
    int rm = (modrm & 7) | s->rex_b;
    int rm_raw = modrm & 7;

    info->x86.modrm = modrm;
    info->id = ins_id;
    info->x86.op_count = 1;

    if (mod_val == 3) {
        opnd_write_reg8(&info->x86.operands[0], rm, s->has_rex);
    } else {
        info->x86.operands[0].type = dt_X86_OP_MEM;
        info->x86.operands[0].size = 1;
        info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[0].avx_zero_opmask = 0;
        fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
    }
    info->x86.operands[0].access = dt_CS_AC_READ | dt_CS_AC_WRITE;
    return 1;
}

static int decode_modrm_gpr(FDState *s, struct la_dt_insn *info,
                            unsigned int ins_id, int operand_size,
                            int dest_is_rm, int source_is_rm)
{
    int modrm = fd_read_byte(s);
    if (modrm < 0) return 0;

    int mod_val = (modrm >> 6) & 3;
    int reg = ((modrm >> 3) & 7) | s->rex_r;
    int rm = (modrm & 7) | s->rex_b;
    int rm_raw = modrm & 7;
    int rm_idx = dest_is_rm ? 0 : 1;
    int reg_idx = dest_is_rm ? 1 : 0;

    info->x86.modrm = modrm;
    info->id = ins_id;
    info->x86.op_count = 2;

    opnd_write_reg(&info->x86.operands[reg_idx], operand_size, reg);
    info->x86.operands[reg_idx].access = source_is_rm ? dt_CS_AC_WRITE
                                                       : dt_CS_AC_READ;

    if (mod_val == 3) {
        opnd_write_reg(&info->x86.operands[rm_idx], operand_size, rm);
    } else {
        info->x86.operands[rm_idx].type = dt_X86_OP_MEM;
        info->x86.operands[rm_idx].size = operand_size / 8;
        info->x86.operands[rm_idx].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[rm_idx].avx_zero_opmask = 0;
        fd_decode_mem_addr(s, &info->x86.operands[rm_idx], mod_val, rm_raw,
                           NULL, NULL);
    }
    info->x86.operands[rm_idx].access = dest_is_rm
        ? (dt_CS_AC_READ | dt_CS_AC_WRITE)
        : dt_CS_AC_READ;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Opcode dispatch — main switch                                      */
/* ------------------------------------------------------------------ */

static int dispatch_instruction(FDState *s, int op, struct la_dt_insn *info)
{
    int modrm, reg, rm;
    int64_t target;

    switch (op) {

    /* ----- ADD Ev, Gv (0x01) / ADD Gv, Ev (0x03) ----- */
    case 0x00:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_ADD, 0);
    case 0x01:
        return decode_reg_reg_alu(s, info, dt_X86_INS_ADD, 0);
    case 0x02:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_ADD, 1);
    case 0x03:
        return decode_reg_reg_alu(s, info, dt_X86_INS_ADD, 1);

    /* ----- ADD al, imm8 (0x04) / ADD eax, imm (0x05) ----- */
    case 0x04:
    case 0x05: {
        int sz = (op == 0x04) ? 8 : s->dflag;
        info->id = dt_X86_INS_ADD;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], sz, 0);
        info->x86.operands[0].access = 0;
        int64_t imm = (op == 0x04) ? (uint8_t)fd_read_imm8(s) : fd_read_acc_imm(s, sz);
        opnd_write_imm(&info->x86.operands[1], sz, imm);
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- ADC r/m8, r8 (0x10) / ADC r/m, r (0x11) / ADC r8, r/m8 (0x12) / ADC r, r/m (0x13) ----- */
    case 0x10:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_ADC, 0);
    case 0x11:
        return decode_reg_reg_alu(s, info, dt_X86_INS_ADC, 0);
    case 0x12:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_ADC, 1);
    case 0x13:
        return decode_reg_reg_alu(s, info, dt_X86_INS_ADC, 1);

    /* ----- ADC al, imm8 (0x14) / ADC eax, imm (0x15) ----- */
    case 0x14:
    case 0x15: {
        int sz = (op == 0x14) ? 8 : s->dflag;
        info->id = dt_X86_INS_ADC;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], sz, 0);
        int64_t imm = (op == 0x14) ? (uint8_t)fd_read_imm8(s) : fd_read_acc_imm(s, sz);
        opnd_write_imm(&info->x86.operands[1], sz, imm);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- OR r/m8, r8 (0x08) / OR r/m, r (0x09) / OR r8, r/m8 (0x0a) / OR r, r/m (0x0b) ----- */
    case 0x08:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_OR, 0);
    case 0x09:
        return decode_reg_reg_alu(s, info, dt_X86_INS_OR, 0);
    case 0x0a:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_OR, 1);
    case 0x0b:
        return decode_reg_reg_alu(s, info, dt_X86_INS_OR, 1);

    /* ----- OR al, imm8 (0x0c) / OR eax, imm (0x0d) ----- */
    case 0x0c:
    case 0x0d: {
        int sz = (op == 0x0c) ? 8 : s->dflag;
        info->id = dt_X86_INS_OR;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], sz, 0);
        int64_t imm = (op == 0x0c) ? (uint8_t)fd_read_imm8(s) : fd_read_acc_imm(s, sz);
        opnd_write_imm(&info->x86.operands[1], sz, imm);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- SBB r/m8, r8 (0x18) / SBB r/m, r (0x19) / SBB r8, r/m8 (0x1a) / SBB r, r/m (0x1b) ----- */
    case 0x18:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_SBB, 0);
    case 0x19:
        return decode_reg_reg_alu(s, info, dt_X86_INS_SBB, 0);
    case 0x1a:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_SBB, 1);
    case 0x1b:
        return decode_reg_reg_alu(s, info, dt_X86_INS_SBB, 1);

    /* ----- SBB al, imm8 (0x1c) / SBB eax, imm (0x1d) ----- */
    case 0x1c:
    case 0x1d: {
        int sz = (op == 0x1c) ? 8 : s->dflag;
        info->id = dt_X86_INS_SBB;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], sz, 0);
        int64_t imm = (op == 0x1c) ? (uint8_t)fd_read_imm8(s) : fd_read_acc_imm(s, sz);
        opnd_write_imm(&info->x86.operands[1], sz, imm);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- AND r/m8, r8 (0x20) / AND r/m, r (0x21) / AND r8, r/m8 (0x22) / AND r, r/m (0x23) ----- */
    case 0x20:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_AND, 0);
    case 0x21:
        return decode_reg_reg_alu(s, info, dt_X86_INS_AND, 0);
    case 0x22:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_AND, 1);
    case 0x23:
        return decode_reg_reg_alu(s, info, dt_X86_INS_AND, 1);

    /* ----- AND al, imm8 (0x24) ----- */
    case 0x24: {
        info->id = dt_X86_INS_AND;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], 8, 0); /* al */
        opnd_write_imm(&info->x86.operands[1], 8, (uint8_t)fd_read_imm8(s));
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- SUB Ev, Gv (0x29) / SUB Gv, Ev (0x2b) ----- */
    case 0x28:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_SUB, 0);
    case 0x29:
        return decode_reg_reg_alu(s, info, dt_X86_INS_SUB, 0);
    case 0x2a:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_SUB, 1);
    case 0x2b:
        return decode_reg_reg_alu(s, info, dt_X86_INS_SUB, 1);

    /* ----- XOR Ev, Gv (0x31) ----- */
    case 0x31:
        return decode_reg_reg_alu(s, info, dt_X86_INS_XOR, 0);
    case 0x33: /* XOR Gv, Ev */
        return decode_reg_reg_alu(s, info, dt_X86_INS_XOR, 1);

    /* ----- XOR r/m8, r8 (0x30) / XOR r8, r/m8 (0x32) ----- */
    case 0x30:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_XOR, 0);
    case 0x32:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_XOR, 1);

    /* ----- CMP Ev, Gv (0x39) / CMP Gv, Ev (0x3b) ----- */
    case 0x39:
        return decode_reg_reg_alu(s, info, dt_X86_INS_CMP, 0);
    case 0x3b:
        return decode_reg_reg_alu(s, info, dt_X86_INS_CMP, 1);

    /* ----- CMP r/m8, r8 (0x38) / CMP r8, r/m8 (0x3a) ----- */
    case 0x38:
    case 0x3a: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm  = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_CMP;
        info->x86.op_count = 2;
        int swap = (op == 0x3a);
        opnd_write_reg8(&info->x86.operands[swap ? 0 : 1], reg, s->has_rex);
        info->x86.operands[swap ? 0 : 1].access = 0;
        if (mod_val == 3)
            opnd_write_reg8(&info->x86.operands[swap ? 1 : 0], rm, s->has_rex);
        else {
            info->x86.operands[swap ? 1 : 0].type = dt_X86_OP_MEM;
            info->x86.operands[swap ? 1 : 0].size = 1;
            info->x86.operands[swap ? 1 : 0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[swap ? 1 : 0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[swap ? 1 : 0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[swap ? 1 : 0].access = 0;
        return 1;
    }

    /* ----- MOVSXD Gv, Ev (0x63) ----- */
    case 0x63: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm  = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_MOVSXD;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], s->dflag, reg);       /* dest: 64-bit */
        if (mod_val == 3)
            opnd_write_reg(&info->x86.operands[1], 32, rm);          /* src: 32-bit reg */
        else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = 4;
            info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[1].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- MOV r8, r/m8 (0x8a) / MOV r/m8, r8 (0x88) ----- */
    case 0x88:
    case 0x8a: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm  = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_MOV;
        info->x86.op_count = 2;
        int swap = (op == 0x8a); /* 8A: dest=reg, src=rm; 88: dest=rm, src=reg */
        /* Register operand */
        opnd_write_reg8(&info->x86.operands[swap ? 0 : 1], reg, s->has_rex);
        info->x86.operands[swap ? 0 : 1].access = swap ? dt_CS_AC_WRITE : dt_CS_AC_READ;
        /* R/M operand */
        if (mod_val == 3) {
            opnd_write_reg8(&info->x86.operands[swap ? 1 : 0], rm, s->has_rex);
        } else {
            info->x86.operands[swap ? 1 : 0].type = dt_X86_OP_MEM;
            info->x86.operands[swap ? 1 : 0].size = 1;
            info->x86.operands[swap ? 1 : 0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[swap ? 1 : 0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[swap ? 1 : 0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[swap ? 1 : 0].access = swap ? dt_CS_AC_READ : dt_CS_AC_WRITE;
        return 1;
    }

    /* ----- XCHG eax, reg (0x91-0x97) ----- */
    case 0x91 ... 0x97: {
        int reg_num = (op & 7) | s->rex_b;
        info->id = dt_X86_INS_XCHG;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], s->dflag, reg_num);
        opnd_write_reg(&info->x86.operands[1], s->dflag, 0);    /* eax */
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- STOSB/STOSW/STOSD/STOSQ (0xaa / 0xab) ----- */
    case 0xaa:
    case 0xab: {
        int size = (op == 0xaa) ? 8 : s->dflag;
        info->id = (op == 0xaa) ? dt_X86_INS_STOSB
                 : (size == 16) ? dt_X86_INS_STOSW
                 : (size == 64) ? dt_X86_INS_STOSQ
                 : dt_X86_INS_STOSD;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[1], size, 0); /* al/ax/eax/rax */
        info->x86.operands[0].type = dt_X86_OP_MEM;
        info->x86.operands[0].size = size / 8;
        info->x86.operands[0].mem.base = fd_reg(s->mode ? 7 : 7, s->mode ? 64 : s->aflag);
        info->x86.operands[0].mem.scale = 1;
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- MOVSB/MOVSW/MOVSD/MOVSQ (0xa4, 0xa5) ----- */
    case 0xa4:
    case 0xa5: {
        int size = (op == 0xa4) ? 8 : s->dflag;
        info->id = (op == 0xa4) ? dt_X86_INS_MOVSB
                 : (size == 16) ? dt_X86_INS_MOVSW
                 : (size == 64) ? dt_X86_INS_MOVSQ
                 : dt_X86_INS_MOVSD;
        info->x86.op_count = 2;
        int addr_size = fd_string_addr_size(s);
        dt_x86_reg dst_base = fd_reg(7, addr_size);
        dt_x86_reg src_base = fd_reg(6, addr_size);
        opnd_write_mem_base(&info->x86.operands[0], size, dst_base,
                            dt_X86_REG_ES);
        info->x86.operands[0].access = dt_CS_AC_WRITE;
        opnd_write_mem_base(&info->x86.operands[1], size, src_base,
                            dt_X86_REG_INVALID);
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- CMPSB/CMPSW/CMPSD/CMPSQ (0xa6, 0xa7) ----- */
    case 0xa6:
    case 0xa7: {
        int size = (op == 0xa6) ? 8 : s->dflag;
        info->id = (op == 0xa6) ? dt_X86_INS_CMPSB
                 : (size == 16) ? dt_X86_INS_CMPSW
                 : (size == 64) ? dt_X86_INS_CMPSQ
                 : dt_X86_INS_CMPSD;
        info->x86.op_count = 2;
        int addr_size = fd_string_addr_size(s);
        dt_x86_reg src_base = fd_reg(6, addr_size);
        dt_x86_reg dst_base = fd_reg(7, addr_size);
        opnd_write_mem_base(&info->x86.operands[0], size, src_base,
                            dt_X86_REG_INVALID);
        info->x86.operands[0].access = dt_CS_AC_READ;
        opnd_write_mem_base(&info->x86.operands[1], size, dst_base,
                            dt_X86_REG_ES);
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- TEST Ev, Gv (0x85) ----- */
    case 0x85:
        return decode_reg_reg_alu(s, info, dt_X86_INS_TEST, 0);

    /* ----- XCHG Ev, Gv (0x87) ----- */
    case 0x87:
        return decode_reg_reg_alu(s, info, dt_X86_INS_XCHG, 0);

    /* ----- XLATB (0xd7) ----- */
    case 0xd7:
        if (s->aflag == 16 || s->prefix[0] || s->prefix[1] ||
            (s->prefix[2] && s->prefix[2] != dt_X86_PREFIX_OPSIZE)) {
            return 0;
        }
        info->id = dt_X86_INS_XLATB;
        info->x86.op_count = 0;
        return 1;

    /* ----- MOV r/m, imm (0xc7 /0, 0xc6 /0) ----- */
    case 0xc6:
    case 0xc7: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        if (op_ext != 0) return 0;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_MOV;
        int sz = (op == 0xc6) ? 8 : s->dflag;
        info->x86.op_count = 2;
        if (mod_val == 3) {
            if (sz == 8)
                opnd_write_reg8(&info->x86.operands[0], rm, s->has_rex);
            else
                opnd_write_reg(&info->x86.operands[0], sz, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = sz / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = 0;
        int64_t imm = (op == 0xc6) ? (uint8_t)fd_read_byte(s)
                    : (sz == 16) ? fd_read_imm16(s) : fd_read_imm32(s);
        if (sz == 64) imm = (int32_t)imm;
        opnd_write_imm(&info->x86.operands[1], sz, imm);
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- MOV Ev, Gv (0x89) / MOV Gv, Ev (0x8b) ----- */
    case 0x89:
    case 0x8b: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg  = ((modrm >> 3) & 7) | s->rex_r;
        rm   = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_MOV;
        info->x86.op_count = 2;
        int dest_is_reg = (op == 0x8b);

        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[0], s->dflag, dest_is_reg ? reg : rm);
            opnd_write_reg(&info->x86.operands[1], s->dflag, dest_is_reg ? rm  : reg);
            info->x86.operands[0].access = 0;
            info->x86.operands[1].access = 0;
            return 1;
        }

        /* Memory operand */
        dt_cs_x86_op *mem_op = dest_is_reg ? &info->x86.operands[1] : &info->x86.operands[0];
        dt_cs_x86_op *reg_op = dest_is_reg ? &info->x86.operands[0] : &info->x86.operands[1];
        reg_op->access = dest_is_reg ? dt_CS_AC_WRITE : dt_CS_AC_READ;
        mem_op->access = dest_is_reg ? dt_CS_AC_READ  : dt_CS_AC_WRITE;
        opnd_write_reg(reg_op, s->dflag, reg);

        mem_op->type = dt_X86_OP_MEM;
        mem_op->size = s->dflag / 8;
        fd_set_segment(s, mem_op);
        mem_op->mem.index = dt_X86_REG_INVALID;
        mem_op->mem.scale = 0;
        mem_op->mem.disp  = 0;
        mem_op->avx_bcast = dt_X86_AVX_BCAST_INVALID;
        mem_op->avx_zero_opmask = 0;

        int base = rm, index = -1, scale = 0, havesib = 0;
        if (s->aflag == 64 || s->aflag == 32) {
            if (rm_raw == 4) {
                int sib = fd_read_byte(s);
                if (sib < 0) return 0;
                scale = (sib >> 6) & 3;
                index = ((sib >> 3) & 7) | s->rex_x;
                if (index == 4) index = -1;
                base = (sib & 7) | s->rex_b;
                havesib = 1;
            }
            switch (mod_val) {
            case 0:
                if ((base & 7) == 5) {
                    if (s->aflag == 64 && !havesib)
                        mem_op->mem.base = dt_X86_REG_RIP;
                    mem_op->mem.disp = (int32_t)fd_read_imm32(s);
                    base = -1;
                }
                break;
            case 1: mem_op->mem.disp = (int8_t)fd_read_imm8(s); break;
            case 2: mem_op->mem.disp = (int32_t)fd_read_imm32(s); break;
            }
        }
        if (base >= 0)
            mem_op->mem.base = fd_reg(base, s->aflag == 64 ? 64 : s->aflag);
        if (index >= 0)
            mem_op->mem.index = fd_reg(index, s->aflag == 64 ? 64 : s->aflag);
        mem_op->mem.scale = 1 << scale;
        return 1;
    }

    /* ----- MOV r/m, Sreg (0x8c) / MOV Sreg, r/m16 (0x8e) ----- */
    case 0x8c:
    case 0x8e: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int seg = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;

        if (seg >= 6 || (op == 0x8e && seg == 1)) {
            return 0;
        }

        info->x86.modrm = modrm;
        info->id = dt_X86_INS_MOV;
        info->x86.op_count = 2;

        dt_cs_x86_op *rm_op = op == 0x8c ? &info->x86.operands[0] :
                                           &info->x86.operands[1];
        dt_cs_x86_op *seg_op = op == 0x8c ? &info->x86.operands[1] :
                                            &info->x86.operands[0];

        if (mod_val == 3) {
            opnd_write_reg(rm_op, op == 0x8c ? s->dflag : 16, rm);
        } else {
            rm_op->type = dt_X86_OP_MEM;
            rm_op->size = 2;
            rm_op->avx_bcast = dt_X86_AVX_BCAST_INVALID;
            rm_op->avx_zero_opmask = 0;
            fd_decode_mem_addr(s, rm_op, mod_val, rm_raw, NULL, NULL);
        }

        opnd_write_seg(seg_op, seg);
        rm_op->access = op == 0x8c ? dt_CS_AC_WRITE : dt_CS_AC_READ;
        seg_op->access = op == 0x8c ? dt_CS_AC_READ : dt_CS_AC_WRITE;
        return 1;
    }

    /* ----- LEA Gv, M (0x8d) ----- */
    case 0x8d: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;

        int mod_val = (modrm >> 6) & 3;
        reg  = ((modrm >> 3) & 7) | s->rex_r;
        rm   = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;

        info->x86.modrm = modrm;
        info->id = dt_X86_INS_LEA;

        if (mod_val == 3)
            return 0;

        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], s->dflag, reg);
        info->x86.operands[0].access = 0;

        info->x86.operands[1].type    = dt_X86_OP_MEM;
        info->x86.operands[1].size    = s->dflag / 8;
        fd_set_segment(s, &info->x86.operands[1]);
        info->x86.operands[1].mem.index   = dt_X86_REG_INVALID;
        info->x86.operands[1].mem.scale   = 0;
        info->x86.operands[1].mem.disp    = 0;
        info->x86.operands[1].access = 0;
        info->x86.operands[1].avx_bcast   = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[1].avx_zero_opmask = 0;

        int base = rm;
        int index = -1;
        int scale = 0;
        int havesib = 0;

        if (s->aflag == 64 || s->aflag == 32) {
            if (rm_raw == 4) {
                int sib = fd_read_byte(s);
                if (sib < 0) return 0;
                scale = (sib >> 6) & 3;
                index = ((sib >> 3) & 7) | s->rex_x;
                if (index == 4)
                    index = -1;
                base  = (sib & 7) | s->rex_b;
                havesib = 1;
            }

            switch (mod_val) {
            case 0:
                if ((base & 7) == 5) {
                    if (s->aflag == 64 && !havesib) {
                        info->x86.operands[1].mem.base = dt_X86_REG_RIP;
                        info->x86.operands[1].mem.disp = (int32_t)fd_read_imm32(s);
                    } else {
                        info->x86.operands[1].mem.disp = (int32_t)fd_read_imm32(s);
                    }
                    base = -1;
                }
                break;
            case 1:
                info->x86.operands[1].mem.disp = (int8_t)fd_read_imm8(s);
                break;
            case 2:
                    info->x86.operands[1].mem.disp = (int32_t)fd_read_imm32(s);
                break;
            }
        }

        if (base >= 0)
            info->x86.operands[1].mem.base = fd_reg(base, s->aflag == 64 ? 64 : s->aflag);
        if (index >= 0)
            info->x86.operands[1].mem.index = fd_reg(index, s->aflag == 64 ? 64 : s->aflag);
        info->x86.operands[1].mem.scale = 1 << scale;

        return 1;
    }

    /* ----- MOV reg, imm (0xb0-0xbf) ----- */
    case 0xb0 ... 0xbf: {
        int reg_num = (op & 7) | s->rex_b;
        info->id = dt_X86_INS_MOV;
        int size = (op < 0xb8) ? 8 : s->dflag;
        info->x86.op_count = (size == 8 || size == s->dflag) ? 2 : 0;
        if (info->x86.op_count == 0) return 0;

        if (size == 8) {
            opnd_write_reg8(&info->x86.operands[0], reg_num, s->has_rex);
        } else {
            opnd_write_reg(&info->x86.operands[0], size, reg_num);
        }
        info->x86.operands[0].access = 0;

        int64_t imm;
        if (size == 64) {
            uint64_t lo = (uint64_t)(uint32_t)fd_read_imm32(s);
            uint64_t hi = (uint64_t)(uint32_t)fd_read_imm32(s);
            imm = (int64_t)(lo | (hi << 32));
        } else if (size == 32) {
            imm = fd_read_imm32(s);
        } else if (size == 16) {
            int b0 = fd_read_byte(s);
            int b1 = fd_read_byte(s);
            imm = (int16_t)(b0 | (b1 << 8));
        } else {
            imm = (int8_t)fd_read_imm8(s);
        }

        opnd_write_imm(&info->x86.operands[1], size, imm);
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- PUSH reg (0x50-0x57) ----- */
    case 0x50 ... 0x57: {
        int reg_num = (op & 7) | s->rex_b;
        info->id = dt_X86_INS_PUSH;
        info->x86.op_count = 1;
        int push_size = s->mode ? 64 : s->dflag;
        opnd_write_reg(&info->x86.operands[0], push_size, reg_num);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- POP reg (0x58-0x5f) ----- */
    case 0x58 ... 0x5f: {
        int reg_num = (op & 7) | s->rex_b;
        info->id = dt_X86_INS_POP;
        info->x86.op_count = 1;
        int pop_size = (s->mode && s->prefix[2] != dt_X86_PREFIX_OPSIZE) ? 64 : s->dflag;
        opnd_write_reg(&info->x86.operands[0], pop_size, reg_num);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- Jcc rel8 (0x70-0x7f) ----- */
    case 0x70 ... 0x7f: {
        static const unsigned int jcc_tab[] = {
            dt_X86_INS_JO, dt_X86_INS_JNO, dt_X86_INS_JB, dt_X86_INS_JAE,
            dt_X86_INS_JE, dt_X86_INS_JNE, dt_X86_INS_JBE, dt_X86_INS_JA,
            dt_X86_INS_JS, dt_X86_INS_JNS, dt_X86_INS_JP, dt_X86_INS_JNP,
            dt_X86_INS_JL, dt_X86_INS_JGE, dt_X86_INS_JLE, dt_X86_INS_JG,
        };
        info->id = jcc_tab[op & 0xf];
        info->x86.op_count = 1;
        int8_t disp8 = (int8_t)fd_read_imm8(s);
        target = s->address + s->pos + disp8;
        opnd_write_imm(&info->x86.operands[0], s->mode ? 64 : s->dflag, target);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- RET (0xc3) ----- */
    case 0xc3:
        info->id = dt_X86_INS_RET;
        info->x86.op_count = 0;
        return 1;

    /* ----- RET imm16 (0xc2) ----- */
    case 0xc2:
        info->id = dt_X86_INS_RET;
        info->x86.op_count = 1;
        opnd_write_imm(&info->x86.operands[0], s->mode ? 64 : s->dflag,
                       fd_read_imm16(s));
        info->x86.operands[0].access = 0;
        return 1;

    /* ----- AND eax, imm32 (0x25) ----- */
    case 0x25: {
        info->id = dt_X86_INS_AND;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], s->dflag, 0); /* eax */
        int64_t imm = fd_read_acc_imm(s, s->dflag);
        opnd_write_imm(&info->x86.operands[1], s->dflag, imm);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- SUB al, imm8 (0x2c) / SUB eax, imm32 (0x2d) ----- */
    case 0x2c:
    case 0x2d: {
        int sz = (op == 0x2c) ? 8 : s->dflag;
        info->id = dt_X86_INS_SUB;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], sz, 0); /* al/eax/rax */
        info->x86.operands[0].access = 0;
        int64_t imm = (op == 0x2c) ? (uint8_t)fd_read_imm8(s)
                    : fd_read_acc_imm(s, s->dflag);
        opnd_write_imm(&info->x86.operands[1], sz, imm);
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- TEST al, imm8 (0xa8) / TEST eax, imm32 (0xa9) ----- */
    case 0xa8:
    case 0xa9: {
        info->id = dt_X86_INS_TEST;
        info->x86.op_count = 2;
        int size = (op == 0xa8) ? 8 : s->dflag;
        opnd_write_reg(&info->x86.operands[0], size, 0); /* al/eax */
        int64_t imm = (op == 0xa8) ? (int8_t)fd_read_imm8(s)
                     : (size == 16) ? (int64_t)fd_read_imm16(s) : (int64_t)fd_read_imm32(s);
        if (op == 0xa8)
            imm = (uint8_t)imm;
        else if (size == 64)
            imm = (int32_t)imm;
        opnd_write_imm(&info->x86.operands[1], size, imm);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- TEST r/m8, r8 (0x84) ----- */
    case 0x84:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_TEST, 0);

    /* ----- XCHG r/m8, r8 (0x86) ----- */
    case 0x86:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_XCHG, 0);

    /* ----- Grp3: NOT/NEG/MUL/IMUL/DIV/IDIV (0xf7 /0-7, 0xf6 /0-7) ----- */
    case 0xf6:
    case 0xf7: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        if (op_ext > 7) return 0;
        info->x86.modrm = modrm;
        static const unsigned int grp3_insn[] = {
            dt_X86_INS_TEST, 0, dt_X86_INS_NOT, dt_X86_INS_NEG,
            dt_X86_INS_MUL, dt_X86_INS_IMUL, dt_X86_INS_DIV, dt_X86_INS_IDIV,
        };
        info->id = grp3_insn[op_ext];
        int size = (op == 0xf6) ? 8 : s->dflag;

        if (op_ext == 0) {
            /* TEST r/m, imm8/imm32 */
            info->x86.op_count = 2;
            if (mod_val == 3) {
                if (size == 8) {
                    info->x86.operands[0].type = dt_X86_OP_REG;
                    info->x86.operands[0].size = 1;
                    info->x86.operands[0].reg = (s->rex ? fd_reg8_rex : fd_reg8)[rm & 0xf];
                } else {
                    opnd_write_reg(&info->x86.operands[0], size, rm);
                }
            } else {
                info->x86.operands[0].type = dt_X86_OP_MEM;
                info->x86.operands[0].size = size / 8;
                info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
                info->x86.operands[0].avx_zero_opmask = 0;
                fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
            }
            opnd_write_imm(&info->x86.operands[1], size,
                           (op == 0xf6) ? (int64_t)(uint8_t)fd_read_imm8(s)
                                        : (size == 16) ? (int64_t)fd_read_imm16(s)
                                        : (size == 64) ? (int64_t)(int32_t)fd_read_imm32(s)
                                        : (int64_t)fd_read_imm32(s));
            info->x86.operands[0].access = 0;
            info->x86.operands[1].access = 0;
            return 1;
        }
        if (op_ext < 2) return 0; /* unsupported */

        /* NOT/NEG: single operand, MUL/IMUL/DIV/IDIV: implicit reg + explicit */
        info->x86.op_count = 1;
        if (mod_val == 3) {
            if (size == 8) {
                info->x86.operands[0].type = dt_X86_OP_REG;
                info->x86.operands[0].size = 1;
                info->x86.operands[0].reg = (s->rex ? fd_reg8_rex : fd_reg8)[rm & 0xf];
            } else {
                opnd_write_reg(&info->x86.operands[0], size, rm);
            }
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = size / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- JMP/CALL/DEC/PUSH indirect (0xff /2, /4, /1, /6) ----- */
    case 0xff: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        if (op_ext != 0 && op_ext != 1 && op_ext != 2 && op_ext != 4 && op_ext != 6) return 0;
        info->x86.modrm = modrm;
        if (op_ext == 0)      info->id = dt_X86_INS_INC;
        else if (op_ext == 1) info->id = dt_X86_INS_DEC;
        else if (op_ext == 2) info->id = dt_X86_INS_CALL;
        else if (op_ext == 4) info->id = dt_X86_INS_JMP;
        else                  info->id = dt_X86_INS_PUSH;
        info->x86.op_count = 1;
        int push_sz = (s->mode && s->prefix[2] != dt_X86_PREFIX_OPSIZE) ? 64 : s->dflag;
        int reg_sz = (op_ext == 2 || op_ext == 4) ? (s->mode ? 64 : s->dflag)
                   : (op_ext == 6) ? push_sz : s->dflag;
        int mem_sz = (op_ext == 2 || op_ext == 4) ? (s->mode ? 8 : s->dflag / 8)
                   : (op_ext == 6) ? (push_sz / 8) : (s->dflag / 8);
        if (mod_val == 3) {
            if (reg_sz == 8)
                opnd_write_reg8(&info->x86.operands[0], rm, s->has_rex);
            else
                opnd_write_reg(&info->x86.operands[0], reg_sz, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = mem_sz;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- POP r/m (0x8f /0) ----- */
    case 0x8f: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        if (op_ext != 0) return 0;

        info->x86.modrm = modrm;
        info->id = dt_X86_INS_POP;
        info->x86.op_count = 1;
        int pop_size = (s->mode && s->prefix[2] != dt_X86_PREFIX_OPSIZE) ? 64 : s->dflag;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[0], pop_size, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = pop_size / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = dt_CS_AC_WRITE;
        return 1;
    }

    /* ----- Grp2 8-bit shift by 1 (0xd0) ----- */
    case 0xd0: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        if (op_ext > 7) return 0;
        if (mod_val != 3) return 0;
        info->x86.modrm = modrm;
        static const unsigned int shift_insn[] = {
            dt_X86_INS_ROL, dt_X86_INS_ROR, dt_X86_INS_RCL, dt_X86_INS_RCR,
            dt_X86_INS_SHL, dt_X86_INS_SHR, dt_X86_INS_SHL,
            dt_X86_INS_SAR,
        };
        info->id = shift_insn[op_ext];
        info->x86.op_count = 2;
        opnd_write_reg8(&info->x86.operands[0], rm, s->has_rex);
        opnd_write_imm(&info->x86.operands[1], 8, 1);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- Grp4 INC/DEC r/m8 (0xfe /0-/1) ----- */
    case 0xfe: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int op_ext = (modrm >> 3) & 7;
        s->pos--;
        if (op_ext == 0)
            return decode_rm_unary8(s, info, dt_X86_INS_INC);
        if (op_ext == 1)
            return decode_rm_unary8(s, info, dt_X86_INS_DEC);
        return 0;
    }

    /* ----- Grp2 8-bit shift/rotate by CL (0xd2) ----- */
    case 0xd2: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        static const unsigned int shift_insn[] = {
            dt_X86_INS_ROL, dt_X86_INS_ROR, dt_X86_INS_RCL, dt_X86_INS_RCR,
            dt_X86_INS_SHL, dt_X86_INS_SHR, dt_X86_INS_SHL,
            dt_X86_INS_SAR,
        };
        if (op_ext > 7 || !shift_insn[op_ext]) return 0;

        info->x86.modrm = modrm;
        info->id = shift_insn[op_ext];
        info->x86.op_count = 2;
        if (mod_val == 3) {
            opnd_write_reg8(&info->x86.operands[0], rm, s->has_rex);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = 1;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = dt_CS_AC_READ | dt_CS_AC_WRITE;
        opnd_write_reg8(&info->x86.operands[1], 1, 0); /* cl */
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- CQO/CDQE (0x99) ----- */
    case 0x99:
        info->id = (s->dflag == 64) ? dt_X86_INS_CQO :
                   (s->dflag == 32) ? dt_X86_INS_CDQ : dt_X86_INS_CWD;
        info->x86.op_count = 0;
        return 1;

    /* ----- FWAIT/WAIT (0x9b) ----- */
    case 0x9b:
        info->id = dt_X86_INS_WAIT;
        info->x86.op_count = 0;
        return 1;

    /* ----- FPU group (0xd8, 0xd9, 0xda, 0xdb, 0xdd, 0xde, 0xdf) ----- */
    case 0xd8:
    case 0xdc:
    case 0xda:
    case 0xd9:
    case 0xdb:
    case 0xdd:
    case 0xde:
    case 0xdf: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        int fpu_rm  = modrm & 7;
        info->x86.modrm = modrm;

        if (op == 0xd9 && mod_val == 3 && op_ext >= 4) {
            static const unsigned int d9_reg_insn[4][8] = {
                { dt_X86_INS_FCHS,   dt_X86_INS_FABS,    0,                  0,
                  dt_X86_INS_FTST,   dt_X86_INS_FXAM,    0,                  0 },
                { dt_X86_INS_FLD1,   dt_X86_INS_FLDL2T,  dt_X86_INS_FLDL2E,  dt_X86_INS_FLDPI,
                  dt_X86_INS_FLDLG2, dt_X86_INS_FLDLN2,  dt_X86_INS_FLDZ,    0 },
                { dt_X86_INS_F2XM1,  dt_X86_INS_FYL2X,   dt_X86_INS_FPTAN,   dt_X86_INS_FPATAN,
                  dt_X86_INS_FXTRACT, dt_X86_INS_FPREM1, dt_X86_INS_FDECSTP, dt_X86_INS_FINCSTP },
                { dt_X86_INS_FPREM,  dt_X86_INS_FYL2XP1, dt_X86_INS_FSQRT,   dt_X86_INS_FSINCOS,
                  dt_X86_INS_FRNDINT, dt_X86_INS_FSCALE, dt_X86_INS_FSIN,    dt_X86_INS_FCOS },
            };
            info->id = d9_reg_insn[op_ext - 4][fpu_rm];
            if (!info->id)
                return 0;
            info->x86.op_count = 0;
        } else if (op == 0xd9 && mod_val == 3 && op_ext == 0) {
            info->id = dt_X86_INS_FLD;
            info->x86.op_count = 1;
            opnd_write_fpu_reg(&info->x86.operands[0], fpu_rm);
            info->x86.operands[0].access = dt_CS_AC_READ;
        } else if (op == 0xd9 && mod_val == 3 && op_ext == 1) {
            info->id = dt_X86_INS_FXCH;
            info->x86.op_count = 2;
            opnd_write_fpu_reg(&info->x86.operands[0], 0);
            opnd_write_fpu_reg(&info->x86.operands[1], fpu_rm);
            info->x86.operands[0].access = dt_CS_AC_READ | dt_CS_AC_WRITE;
            info->x86.operands[1].access = dt_CS_AC_READ | dt_CS_AC_WRITE;
        } else if (op == 0xd9 && mod_val != 3) {
            static const unsigned int d9_mem_insn[8] = {
                dt_X86_INS_FLD, 0, dt_X86_INS_FST, dt_X86_INS_FSTP,
                dt_X86_INS_FLDENV, dt_X86_INS_FLDCW,
                dt_X86_INS_FNSTENV, dt_X86_INS_FNSTCW,
            };
            static const uint8_t d9_mem_size[8] = { 4, 0, 4, 4, 28, 2, 28, 2 };
            static const uint8_t d9_mem_access[8] = {
                dt_CS_AC_READ, 0, dt_CS_AC_WRITE, dt_CS_AC_WRITE,
                dt_CS_AC_READ, dt_CS_AC_READ, dt_CS_AC_WRITE, dt_CS_AC_WRITE,
            };
            info->id = d9_mem_insn[op_ext];
            if (!info->id)
                return 0;
            info->x86.op_count = 1;
            opnd_write_fpu_mem(s, &info->x86.operands[0], mod_val, fpu_rm,
                               d9_mem_size[op_ext], d9_mem_access[op_ext]);
        } else if (op == 0xdb && mod_val == 3 && op_ext >= 5) {
            info->id = (op_ext == 5) ? dt_X86_INS_FUCOMI :
                       (op_ext == 6) ? dt_X86_INS_FCOMI : dt_X86_INS_FCOMIP;
            info->x86.op_count = 1;
            opnd_write_fpu_reg(&info->x86.operands[0], fpu_rm);
            info->x86.operands[0].access = dt_CS_AC_READ;
        } else if (op == 0xdb && mod_val != 3) {
            static const unsigned int db_mem_insn[8] = {
                dt_X86_INS_FILD, dt_X86_INS_FISTTP, dt_X86_INS_FIST,
                dt_X86_INS_FISTP, 0, dt_X86_INS_FLD, 0, dt_X86_INS_FSTP,
            };
            static const uint8_t db_mem_size[8] = { 4, 4, 4, 4, 0, 10, 0, 10 };
            static const uint8_t db_mem_access[8] = {
                dt_CS_AC_READ, dt_CS_AC_WRITE, dt_CS_AC_WRITE, dt_CS_AC_WRITE,
                0, dt_CS_AC_READ, 0, dt_CS_AC_WRITE,
            };
            info->id = db_mem_insn[op_ext];
            if (!info->id)
                return 0;
            info->x86.op_count = 1;
            opnd_write_fpu_mem(s, &info->x86.operands[0], mod_val, fpu_rm,
                               db_mem_size[op_ext], db_mem_access[op_ext]);
        } else if (op == 0xdd && mod_val != 3) {
            static const unsigned int dd_mem_insn[8] = {
                dt_X86_INS_FLD, 0, dt_X86_INS_FST, dt_X86_INS_FSTP,
                dt_X86_INS_FRSTOR, 0, dt_X86_INS_FNSAVE, dt_X86_INS_FNSTSW,
            };
            static const uint8_t dd_mem_size[8] = { 8, 0, 8, 8, 108, 0, 108, 2 };
            static const uint8_t dd_mem_access[8] = {
                dt_CS_AC_READ, 0, dt_CS_AC_WRITE, dt_CS_AC_WRITE,
                dt_CS_AC_READ, 0, dt_CS_AC_WRITE, dt_CS_AC_WRITE,
            };
            info->id = dd_mem_insn[op_ext];
            if (!info->id)
                return 0;
            info->x86.op_count = 1;
            opnd_write_fpu_mem(s, &info->x86.operands[0], mod_val, fpu_rm,
                               dd_mem_size[op_ext], dd_mem_access[op_ext]);
        } else if (op == 0xdd && mod_val == 3 && (op_ext == 4 || op_ext == 5)) {
            info->id = (op_ext == 4) ? dt_X86_INS_FUCOM : dt_X86_INS_FUCOMP;
            info->x86.op_count = 1;
            opnd_write_fpu_reg(&info->x86.operands[0], fpu_rm);
            info->x86.operands[0].access = dt_CS_AC_READ;
        } else if (op == 0xdf && mod_val != 3) {
            static const unsigned int df_mem_insn[8] = {
                dt_X86_INS_FILD, dt_X86_INS_FISTTP, dt_X86_INS_FIST,
                dt_X86_INS_FISTP, dt_X86_INS_FBLD, dt_X86_INS_FILD,
                dt_X86_INS_FBSTP, dt_X86_INS_FISTP,
            };
            static const uint8_t df_mem_size[8] = { 2, 2, 2, 2, 10, 8, 10, 8 };
            static const uint8_t df_mem_access[8] = {
                dt_CS_AC_READ, dt_CS_AC_WRITE, dt_CS_AC_WRITE, dt_CS_AC_WRITE,
                dt_CS_AC_READ, dt_CS_AC_READ, dt_CS_AC_WRITE, dt_CS_AC_WRITE,
            };
            info->id = df_mem_insn[op_ext];
            info->x86.op_count = 1;
            opnd_write_fpu_mem(s, &info->x86.operands[0], mod_val, fpu_rm,
                               df_mem_size[op_ext], df_mem_access[op_ext]);
        } else if (op == 0xdf && mod_val == 3 && (op_ext == 5 || op_ext == 6 || op_ext == 7)) {
            info->id = (op_ext == 5) ? dt_X86_INS_FUCOMIP :
                       dt_X86_INS_FCOMIP;
            info->x86.op_count = 1;
            opnd_write_fpu_reg(&info->x86.operands[0], fpu_rm);
            info->x86.operands[0].access = dt_CS_AC_READ;
        } else if (op == 0xd8 && mod_val == 3 && (op_ext == 2 || op_ext == 3)) {
            info->id = (op_ext == 2) ? dt_X86_INS_FCOM : dt_X86_INS_FCOMP;
            info->x86.op_count = 1;
            opnd_write_fpu_reg(&info->x86.operands[0], fpu_rm);
            info->x86.operands[0].access = dt_CS_AC_READ;
        } else if (op == 0xda && mod_val == 3) {
            static const unsigned int da_reg_insn[8] = {
                dt_X86_INS_FCMOVB,  dt_X86_INS_FCMOVE,
                dt_X86_INS_FCMOVBE, dt_X86_INS_FCMOVU,
                0,                  dt_X86_INS_FUCOMPP,
                0,                  0,
            };
            if (!da_reg_insn[op_ext])
                return 0;
            info->id = da_reg_insn[op_ext];
            if (info->id == dt_X86_INS_FUCOMPP) {
                info->x86.op_count = 0;
            } else {
                info->x86.op_count = 2;
                opnd_write_fpu_reg(&info->x86.operands[0], 0);
                opnd_write_fpu_reg(&info->x86.operands[1], fpu_rm);
                info->x86.operands[0].access = dt_CS_AC_WRITE;
                info->x86.operands[1].access = dt_CS_AC_READ;
            }
        } else if (op == 0xda && mod_val != 3) {
            static const unsigned int da_mem_insn[8] = {
                dt_X86_INS_FIADD,  dt_X86_INS_FIMUL,
                dt_X86_INS_FICOM,  dt_X86_INS_FICOMP,
                dt_X86_INS_FISUB,  dt_X86_INS_FISUBR,
                dt_X86_INS_FIDIV,  dt_X86_INS_FIDIVR,
            };
            info->id = da_mem_insn[op_ext];
            info->x86.op_count = 1;
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = 4;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, fpu_rm,
                               NULL, NULL);
            info->x86.operands[0].access = dt_CS_AC_READ;
        } else if (op == 0xdc && mod_val != 3) {
            static const unsigned int dc_mem_insn[8] = {
                dt_X86_INS_FADD,  dt_X86_INS_FMUL,
                dt_X86_INS_FCOM,  dt_X86_INS_FCOMP,
                dt_X86_INS_FSUB,  dt_X86_INS_FSUBR,
                dt_X86_INS_FDIV,  dt_X86_INS_FDIVR,
            };
            info->id = dc_mem_insn[op_ext];
            info->x86.op_count = 1;
            opnd_write_fpu_mem(s, &info->x86.operands[0], mod_val, fpu_rm,
                               8, dt_CS_AC_READ);
        } else if (op == 0xd9 && op_ext == 5 && mod_val != 3) {
            /* FLDCW m2byte */
            info->id = dt_X86_INS_FLDCW;
            info->x86.op_count = 1;
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = 2;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, fpu_rm, NULL, NULL);
            info->x86.operands[0].access = dt_CS_AC_READ;
        } else if (op == 0xd9 && op_ext == 7 && mod_val != 3) {
            /* FNSTCW m2byte */
            info->id = dt_X86_INS_FNSTCW;
            info->x86.op_count = 1;
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = 2;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, fpu_rm, NULL, NULL);
            info->x86.operands[0].access = dt_CS_AC_WRITE;
        } else if (op == 0xdb && op_ext == 4 && mod_val == 3 && fpu_rm == 2) {
            info->id = dt_X86_INS_FNCLEX;
            info->x86.op_count = 0;
        } else if (op == 0xdb && op_ext == 4 && mod_val == 3) {
            /* FNINIT: no operands */
            info->id = dt_X86_INS_FNINIT;
            info->x86.op_count = 0;
        } else if (op == 0xdf && op_ext == 4 && mod_val == 3) {
            /* FNSTSW ax (always 16-bit AX) */
            info->id = dt_X86_INS_FNSTSW;
            info->x86.op_count = 1;
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = 2;
            info->x86.operands[0].reg = dt_X86_REG_AX;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            info->x86.operands[0].access = dt_CS_AC_WRITE;
        } else if (op == 0xdd && op_ext == 0 && mod_val == 3) {
            /* FFREE st(i) */
            info->id = dt_X86_INS_FFREE;
            info->x86.op_count = 1;
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = 10;
            info->x86.operands[0].reg = fd_reg_st[fpu_rm];
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            info->x86.operands[0].access = 0;
        } else if (op == 0xdd && op_ext == 2 && mod_val == 3) {
            /* FST st(i) — register destination */
            info->id = dt_X86_INS_FST;
            info->x86.op_count = 1;
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = 10;
            info->x86.operands[0].reg = fd_reg_st[fpu_rm];
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            info->x86.operands[0].access = dt_CS_AC_WRITE;
        } else if (op == 0xde && mod_val == 3) {
            /* DE C0+i: FADDP st(i),st(0)  DE C8+i: FMULP st(i),st(0)
             * DE D9: FCOMPP (no st(i))  DE E0+i: FSUBRP  DE E8+i: FSUBP
             * DE F0+i: FDIVRP  DE F8+i: FDIVP */
            static const unsigned int de_insn[8] = {
                dt_X86_INS_FADD,   dt_X86_INS_FMULP,
                dt_X86_INS_FCOM,   dt_X86_INS_FCOMP,
                dt_X86_INS_FSUBRP, dt_X86_INS_FSUBP,
                dt_X86_INS_FDIVRP, dt_X86_INS_FDIVP,
            };
            if (op_ext == 3 && fpu_rm == 1) {
                /* DE D9: FCOMPP — special case, no st(i) operand */
                info->id = dt_X86_INS_FCOMPP;
                info->x86.op_count = 0;
            } else {
                info->id = de_insn[op_ext];
                info->x86.op_count = 1;
                info->x86.operands[0].type = dt_X86_OP_REG;
                info->x86.operands[0].size = 10;  /* 80-bit */
                info->x86.operands[0].reg = fd_reg_st[fpu_rm];
                info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
                info->x86.operands[0].avx_zero_opmask = 0;
                info->x86.operands[0].access = 0;
            }
        } else if (op == 0xdd && mod_val != 3 && op_ext == 2) {
            /* FST m64 — memory store */
            info->id = dt_X86_INS_FST;
            info->x86.op_count = 1;
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, fpu_rm, NULL, NULL);
            info->x86.operands[0].access = dt_CS_AC_WRITE;
        } else {
            /* FLD m64 or other memory/register FPU */
            if (mod_val == 3) {
                info->id = dt_X86_INS_FLD;
                info->x86.op_count = 1;
                info->x86.operands[0].type = dt_X86_OP_REG;
                info->x86.operands[0].size = 10;
                info->x86.operands[0].reg = fd_reg_st[fpu_rm];
                info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
                info->x86.operands[0].avx_zero_opmask = 0;
                info->x86.operands[0].access = dt_CS_AC_READ;
            } else {
                info->id = dt_X86_INS_FLD;
                info->x86.op_count = 1;
                info->x86.operands[0].type = dt_X86_OP_MEM;
                info->x86.operands[0].size = (op == 0xd9) ? 4 :
                                              (op == 0xdf) ? 2 :
                                              (op == 0xde) ? 2 :
                                              (op == 0xdb) ? 4 : 8;
                info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
                info->x86.operands[0].avx_zero_opmask = 0;
                fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, fpu_rm, NULL, NULL);
                info->x86.operands[0].access = dt_CS_AC_READ;
            }
        }
        return 1;
    }

    /* ----- Grp1 ALU r/m, imm (0x80 /0-7, 0x81 /0-7, 0x83 /0-7) ----- */
    case 0x80:
    case 0x81:
    case 0x83: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;

        int mod_val  = (modrm >> 6) & 3;
        int op_ext   = (modrm >> 3) & 7;
        rm           = (modrm & 7) | s->rex_b;

        info->x86.modrm = modrm;

        static const unsigned int grp1_insn[] = {
            dt_X86_INS_ADD, dt_X86_INS_OR,  dt_X86_INS_ADC, dt_X86_INS_SBB,
            dt_X86_INS_AND, dt_X86_INS_SUB, dt_X86_INS_XOR, dt_X86_INS_CMP,
        };
        info->id = grp1_insn[op_ext];

        int dfl = (op == 0x80) ? 8 : s->dflag;
        info->x86.op_count = 2;
        if (mod_val == 3) {
            if (dfl == 8) {
                info->x86.operands[0].type = dt_X86_OP_REG;
                info->x86.operands[0].size = 1;
                info->x86.operands[0].reg = s->rex ? fd_reg8_rex[rm & 0xf] : fd_reg8[rm & 0xf];
            } else
                opnd_write_reg(&info->x86.operands[0], dfl, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = dfl / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            int rm_r = modrm & 7;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_r, NULL, NULL);
        }
        info->x86.operands[0].access = 0;

        int64_t imm;
        if (op == 0x83 || op == 0x80) {
            int i8 = (int8_t)fd_read_imm8(s);
            if (dfl == 8) {
                imm = (int64_t)(uint8_t)i8;
            } else if (s->dflag == 64) {
                imm = (int64_t)i8;
            } else if (s->dflag == 32) {
                int arith = (op_ext == 0 || op_ext == 2 || op_ext == 3
                          || op_ext == 5 || op_ext == 7);
                imm = arith ? (int64_t)i8 : (uint32_t)(int32_t)i8;
            } else if (s->dflag == 16) {
                imm = (int16_t)i8;
            } else {
                imm = (int64_t)i8;
            }
        } else {
            if (s->dflag == 16) {
                uint16_t raw = fd_read_imm16(s);
                imm = raw;
            } else {
                imm = fd_read_imm32(s);
                if (s->dflag == 64)
                    imm = (int32_t)imm;
                else if (s->dflag == 32)
                    imm = (uint64_t)(uint32_t)imm;
            }
        }
        opnd_write_imm(&info->x86.operands[1], dfl, imm);
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- Grp2 Shift/Rotate (0xc1 /0-7, 0xd1 /0-7, 0xd3 /0-7) ----- */
    case 0xc1:
    case 0xd1:
    case 0xd3: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        if (op_ext > 7) return 0;
        info->x86.modrm = modrm;
        static const unsigned int shift_insn[] = {
            dt_X86_INS_ROL, dt_X86_INS_ROR, dt_X86_INS_RCL, dt_X86_INS_RCR,
            dt_X86_INS_SHL, dt_X86_INS_SHR, dt_X86_INS_SHL,
            dt_X86_INS_SAR,
        };
        info->id = shift_insn[op_ext];
        info->x86.op_count = 2;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[0], s->dflag, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = s->dflag / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = 0;
        if (op == 0xd3)
            opnd_write_reg(&info->x86.operands[1], 8, 1); /* cl */
        else if (op == 0xd1)
            opnd_write_imm(&info->x86.operands[1], s->dflag, 1); /* imm=1 */
        else
            opnd_write_imm(&info->x86.operands[1], 8,
                           (int8_t)fd_read_imm8(s)); /* imm8 */
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- IMUL Gv, Ev, Iz (0x69) ----- */
    case 0x69: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg  = ((modrm >> 3) & 7) | s->rex_r;
        rm   = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_IMUL;
        info->x86.op_count = 3;
        opnd_write_reg(&info->x86.operands[0], s->dflag, reg);
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[1], s->dflag, rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = s->dflag / 8;
            info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[1].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw, NULL, NULL);
        }
        int64_t imul_imm = s->dflag == 16 ? (int64_t)fd_read_imm16(s)
                         : s->dflag == 64 ? (int64_t)(int32_t)fd_read_imm32(s)
                         : (int64_t)fd_read_imm32(s);
        opnd_write_imm(&info->x86.operands[2], s->dflag, imul_imm);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        info->x86.operands[2].access = 0;
        return 1;
    }

    /* ----- NOP (0x90) ----- */
    case 0x90:
        info->id = (s->prefix[0] == dt_X86_PREFIX_REP) ? dt_X86_INS_PAUSE
                                                        : dt_X86_INS_NOP;
        info->x86.op_count = 0;
        return 1;

    /* ----- ENTER (0xc8) / LEAVE (0xc9) ----- */
    case 0xc8:
        info->id = dt_X86_INS_ENTER;
        info->x86.op_count = 2;
        opnd_write_imm(&info->x86.operands[0],
                       s->mode ? 64 : s->dflag, fd_read_imm16(s));
        info->x86.operands[0].access = 0;
        opnd_write_imm(&info->x86.operands[1],
                       s->mode ? 64 : s->dflag, fd_read_byte(s));
        info->x86.operands[1].access = 0;
        return 1;
    case 0xc9:
        info->id = dt_X86_INS_LEAVE;
        info->x86.op_count = 0;
        return 1;

    /* ----- CLC (0xf8) / STC (0xf9) / CMC (0xf5) ----- */
    case 0xf5: case 0xf8: case 0xf9:
        info->id = (op == 0xf8) ? dt_X86_INS_CLC :
                   (op == 0xf9) ? dt_X86_INS_STC : dt_X86_INS_CMC;
        info->x86.op_count = 0;
        return 1;

    /* ----- LAHF (0x9f) / SAHF (0x9e) / PUSHFQ (0x9c) / POPFQ (0x9d) ----- */
    case 0x9c: case 0x9d: case 0x9e: case 0x9f:
        info->id = (op == 0x9f) ? dt_X86_INS_LAHF : (op == 0x9e) ? dt_X86_INS_SAHF :
                   (op == 0x9c) ? dt_X86_INS_PUSHFQ : dt_X86_INS_POPFQ;
        info->x86.op_count = 0;
        return 1;

    /* ----- CLD (0xfc) / STD (0xfd) ----- */
    case 0xfc:
    case 0xfd:
        info->id = (op == 0xfc) ? dt_X86_INS_CLD : dt_X86_INS_STD;
        info->x86.op_count = 0;
        return 1;

    /* ----- LODSB/LODSW/LODSD/LODSQ (0xac / 0xad) ----- */
    case 0xac:
    case 0xad: {
        int size = (op == 0xac) ? 8 : s->dflag;
        info->id = (op == 0xac) ? dt_X86_INS_LODSB
                 : (size == 16) ? dt_X86_INS_LODSW
                 : (size == 64) ? dt_X86_INS_LODSQ
                 : dt_X86_INS_LODSD;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], size, 0);
        dt_x86_reg src_base = fd_reg(6, fd_string_addr_size(s));
        opnd_write_mem_base(&info->x86.operands[1], size, src_base,
                            dt_X86_REG_INVALID);
        info->x86.operands[0].access = dt_CS_AC_WRITE;
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- SCASB/SCASW/SCASD/SCASQ (0xae / 0xaf) ----- */
    case 0xae:
    case 0xaf: {
        int size = (op == 0xae) ? 8 : s->dflag;
        info->id = (op == 0xae) ? dt_X86_INS_SCASB
                 : (size == 16) ? dt_X86_INS_SCASW
                 : (size == 64) ? dt_X86_INS_SCASQ
                 : dt_X86_INS_SCASD;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], size, 0);
        dt_x86_reg dst_base = fd_reg(7, fd_string_addr_size(s));
        opnd_write_mem_base(&info->x86.operands[1], size, dst_base,
                            dt_X86_REG_ES);
        info->x86.operands[0].access = dt_CS_AC_READ;
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- XOR al, imm8 (0x34) / XOR eax, imm32 (0x35) ----- */
    case 0x34:
    case 0x35: {
        int sz = (op == 0x34) ? 8 : s->dflag;
        info->id = dt_X86_INS_XOR;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], sz, 0); /* al/eax/rax */
        info->x86.operands[0].access = 0;
        int64_t imm = (op == 0x34) ? (uint8_t)fd_read_imm8(s)
                    : fd_read_acc_imm(s, s->dflag);
        opnd_write_imm(&info->x86.operands[1], sz, imm);
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- JCXZ/JECXZ/JRCXZ (0xe3) ----- */
    case 0xe3: {
        info->id = (s->aflag == 64) ? dt_X86_INS_JRCXZ :
                   (s->aflag == 32) ? dt_X86_INS_JECXZ : dt_X86_INS_JCXZ;
        info->x86.op_count = 1;
        int8_t disp = (int8_t)fd_read_imm8(s);
        target = s->address + s->pos + disp;
        opnd_write_imm(&info->x86.operands[0], s->mode ? 64 : s->dflag, target);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- LOOPNE/LOOPE/LOOP (0xe0, 0xe1, 0xe2) ----- */
    case 0xe0:
    case 0xe1:
    case 0xe2: {
        info->id = (op == 0xe2) ? dt_X86_INS_LOOP :
                   (op == 0xe1) ? dt_X86_INS_LOOPE : dt_X86_INS_LOOPNE;
        info->x86.op_count = 1;
        int8_t disp = (int8_t)fd_read_imm8(s);
        target = s->address + s->pos + disp;
        opnd_write_imm(&info->x86.operands[0], s->mode ? 64 : s->dflag, target);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- IMUL Gv, Ev (0x0f 0xaf) ----- */
    case 0x1af: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg  = ((modrm >> 3) & 7) | s->rex_r;
        rm   = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_IMUL;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], s->dflag, reg);
        info->x86.operands[0].access = 0;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[1], s->dflag, rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = s->dflag / 8;
            info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[1].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- CMP AL, imm8 (0x3c) / CMP eax, imm32 (0x3d) ----- */
    case 0x3c:
    case 0x3d: {
        int sz = (op == 0x3c) ? 8 : s->dflag;
        info->id = dt_X86_INS_CMP;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], sz, 0); /* al/eax/rax */
        int64_t imm = (op == 0x3c) ? (uint8_t)fd_read_imm8(s)
                     : fd_read_acc_imm_unsigned16(s, s->dflag);
        opnd_write_imm(&info->x86.operands[1], sz, imm);
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- PUSH imm8 (0x6a) ----- */
    case 0x6a: {
        info->id = dt_X86_INS_PUSH;
        info->x86.op_count = 1;
        int64_t imm = (int8_t)fd_read_imm8(s);
        opnd_write_imm(&info->x86.operands[0], s->mode ? 64 : s->dflag, imm);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- PUSH imm16/imm32 (0x68) ----- */
    case 0x68: {
        info->id = dt_X86_INS_PUSH;
        info->x86.op_count = 1;
        bool is_16bit = s->prefix[2] == dt_X86_PREFIX_OPSIZE;
        int64_t imm = is_16bit ? (int16_t)fd_read_imm16(s) :
                                 (int32_t)fd_read_imm32(s);

        opnd_write_imm(&info->x86.operands[0],
                       is_16bit ? 16 : (s->mode ? 64 : s->dflag), imm);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- IMUL Gv, Ev, Ib (0x6b) ----- */
    case 0x6b: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg  = ((modrm >> 3) & 7) | s->rex_r;
        rm   = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_IMUL;
        info->x86.op_count = 3;
        opnd_write_reg(&info->x86.operands[0], s->dflag, reg);
        info->x86.operands[0].access = 0;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[1], s->dflag, rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = s->dflag / 8;
            info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[1].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[1].access = 0;
        opnd_write_imm(&info->x86.operands[2], s->dflag, (int8_t)fd_read_imm8(s));
        info->x86.operands[2].access = 0;
        return 1;
    }

    /* ----- CBW/CWDE/CDQE (0x98) ----- */
    case 0x98:
        info->id = (s->dflag == 64) ? dt_X86_INS_CDQE :
                   (s->dflag == 32) ? dt_X86_INS_CWDE : dt_X86_INS_CBW;
        info->x86.op_count = 0;
        return 1;

    /* ----- SETcc (0x0f 0x90-0x9f) ----- */
    case 0x190 ... 0x19f: {
        static const unsigned int setcc_tab[] = {
            dt_X86_INS_SETO, dt_X86_INS_SETNO, dt_X86_INS_SETB, dt_X86_INS_SETAE,
            dt_X86_INS_SETE, dt_X86_INS_SETNE, dt_X86_INS_SETBE, dt_X86_INS_SETA,
            dt_X86_INS_SETS, dt_X86_INS_SETNS, dt_X86_INS_SETP, dt_X86_INS_SETNP,
            dt_X86_INS_SETL, dt_X86_INS_SETGE, dt_X86_INS_SETLE, dt_X86_INS_SETG,
        };
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = setcc_tab[op & 0xf];
        info->x86.op_count = 1;
        if (mod_val == 3) {
            opnd_write_reg8(&info->x86.operands[0], rm, s->has_rex);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = 1;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- Grp2 Shift/Rotate 8-bit (0xc0) ----- */
    case 0xc0: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        if (op_ext > 7) return 0;
        if (mod_val != 3) return 0;
        info->x86.modrm = modrm;
        static const unsigned int shift_insn[] = {
            dt_X86_INS_ROL, dt_X86_INS_ROR, dt_X86_INS_RCL, dt_X86_INS_RCR,
            dt_X86_INS_SHL, dt_X86_INS_SHR, dt_X86_INS_SHL,
            dt_X86_INS_SAR,
        };
        info->id = shift_insn[op_ext];
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_REG;
        info->x86.operands[0].size = 1;
        info->x86.operands[0].reg = s->rex ? fd_reg8_rex[rm & 0xf] : fd_reg8[rm & 0xf];
        opnd_write_imm(&info->x86.operands[1], 8, (int8_t)fd_read_imm8(s));
        info->x86.operands[0].access = 0;
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- BSWAP (0f c8+rd) ----- */
    case 0x1c8 ... 0x1cf: {
        info->id = dt_X86_INS_BSWAP;
        info->x86.op_count = 1;
        opnd_write_reg(&info->x86.operands[0], s->rex_w ? 64 : 32, (op & 7) | s->rex_b);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- BSF/TZCNT (0f bc) / BSR (0f bd) ----- */
    case 0x1bc: /* BSF/TZCNT */
    case 0x1bd: /* BSR */
        info->id = (op == 0x1bc && s->prefix[0] == dt_X86_PREFIX_REP) ? dt_X86_INS_TZCNT :
                   (op == 0x1bd && s->prefix[0] == dt_X86_PREFIX_REP) ? dt_X86_INS_LZCNT :
                   (op == 0x1bc) ? dt_X86_INS_BSF : dt_X86_INS_BSR;
        return decode_reg_reg_alu(s, info, info->id, 1); /* Gv, Ev */

    /* ----- CMPXCHG (0x0f 0xb0 / 0x0f 0xb1) ----- */
    case 0x1b0:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_CMPXCHG, 0);
    case 0x1b1: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm  = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_CMPXCHG;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[1], s->dflag, reg);
        info->x86.operands[1].access = 0;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[0], s->dflag, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = s->dflag / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- CMPXCHG8B m64 (0x0f 0xc7 /1), RDRAND r16/r32/r64 (/6) ----- */
    case 0x1c7: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        if (mod_val != 3 && op_ext == 1) {
            info->x86.modrm = modrm;
            info->id = dt_X86_INS_CMPXCHG8B;
            info->x86.op_count = 1;
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val,
                               modrm & 7, NULL, NULL);
            info->x86.operands[0].access = 0;
            return 1;
        }
        if (mod_val != 3 || op_ext != 6) {
            return 0;
        }
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_RDRAND;
        info->x86.op_count = 1;
        opnd_write_reg(&info->x86.operands[0], s->dflag, rm);
        info->x86.operands[0].access = dt_CS_AC_WRITE;
        return 1;
    }

    /* ----- BTR/BTC r/m, r (0x0f 0xb3 / 0x0f 0xbb) ----- */
    case 0x1b3:
        return decode_reg_reg_alu(s, info, dt_X86_INS_BTR, 0);
    case 0x1bb:
        return decode_reg_reg_alu(s, info, dt_X86_INS_BTC, 0);

    /* ----- POPCNT Gv, Ev (0xf3 0x0f 0xb8) ----- */
    case 0x1b8:
        if (s->prefix[0] != dt_X86_PREFIX_REP)
            return 0;
        return decode_modrm_gpr(s, info, dt_X86_INS_POPCNT,
                                s->rex_w ? 64 : s->dflag, 0, 1);

    /* ----- CLDEMOTE m8 (0F 1C /0) ----- */
    case 0x11c: {
        int mod_val;

        if (s->prefix[0] != 0 || s->prefix[2] != 0) {
            return 0;
        }
        modrm = fd_read_byte(s);
        if (modrm < 0) {
            return 0;
        }
        mod_val = (modrm >> 6) & 3;
        if (mod_val == 3 || ((modrm >> 3) & 7) != 0) {
            return 0;
        }
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_CLDEMOTE;
        info->x86.op_count = 1;
        info->x86.operands[0].type = dt_X86_OP_MEM;
        info->x86.operands[0].size = 1;
        info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[0].avx_zero_opmask = 0;
        fd_decode_mem_addr(s, &info->x86.operands[0], mod_val,
                           modrm & 7, NULL, NULL);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- MOVNTI m, r (0x0f 0xc3) ----- */
    case 0x1c3: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        if (mod_val == 3) return 0;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        int rm_raw = modrm & 7;
        int size = s->rex_w ? 64 : s->dflag;

        info->x86.modrm = modrm;
        info->id = dt_X86_INS_MOVNTI;
        info->x86.op_count = 2;
        info->x86.operands[0].type = dt_X86_OP_MEM;
        info->x86.operands[0].size = size / 8;
        info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
        info->x86.operands[0].avx_zero_opmask = 0;
        fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw,
                           NULL, NULL);
        info->x86.operands[0].access = dt_CS_AC_WRITE;
        opnd_write_reg(&info->x86.operands[1], size, reg);
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- CALL rel32 (0xe8) ----- */
    case 0xe8: {
        info->id = dt_X86_INS_CALL;
        info->x86.op_count = 1;
        int32_t rel32 = (int32_t)fd_read_imm32(s);
        target = s->address + s->pos + rel32;
        opnd_write_imm(&info->x86.operands[0], s->mode ? 64 : s->dflag, target);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- JMP rel32 (0xe9) ----- */
    case 0xe9: {
        info->id = dt_X86_INS_JMP;
        info->x86.op_count = 1;
        int32_t rel32 = (int32_t)fd_read_imm32(s);
        target = s->address + s->pos + rel32;
        opnd_write_imm(&info->x86.operands[0], s->mode ? 64 : s->dflag, target);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- JMP rel8 (0xeb) ----- */
    case 0xeb: {
        info->id = dt_X86_INS_JMP;
        info->x86.op_count = 1;
        int8_t disp8 = (int8_t)fd_read_imm8(s);
        target = s->address + s->pos + disp8;
        opnd_write_imm(&info->x86.operands[0], s->mode ? 64 : s->dflag, target);
        info->x86.operands[0].access = 0;
        return 1;
    }

    /* ----- 0x0F-prefixed instructions ----- */
    case 0x11e: /* ENDBR32/ENDBR64 */
        info->id = dt_X86_INS_NOP;
        info->x86.op_count = 0;
        modrm = fd_read_byte(s);
        if (modrm >= 0) info->x86.modrm = modrm;
        return 1;

    case 0x11f: /* Multi-byte NOP (0F 1F /r) */
        info->id = dt_X86_INS_NOP;
        info->x86.op_count = 1;
        modrm = fd_read_byte(s);
        if (modrm >= 0) {
            info->x86.modrm = modrm;
            int m = (modrm >> 6) & 3;
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = s->dflag / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            if (m != 3)
                fd_decode_mem_addr(s, &info->x86.operands[0], m, modrm & 7, NULL, NULL);
            else
                info->x86.operands[0].mem.base = fd_reg(modrm & 7, s->dflag);
        }
        return 1;

    case 0x142 ... 0x149: /* CMOVcc (0F 42-49) */
    case 0x14c ... 0x14f: /* CMOVcc (0F 4C-4F) */
    {
        static const unsigned int cmov_tab[] = {
            dt_X86_INS_CMOVB, dt_X86_INS_CMOVAE, /* 42,43 */
            dt_X86_INS_CMOVE, dt_X86_INS_CMOVNE, /* 44,45 */
            dt_X86_INS_CMOVBE, dt_X86_INS_CMOVA,  /* 46,47 */
            dt_X86_INS_CMOVS, dt_X86_INS_CMOVNS,  /* 48,49 */
            0, 0,  /* 4A,4B */
            dt_X86_INS_CMOVL, dt_X86_INS_CMOVGE, /* 4C,4D */
            dt_X86_INS_CMOVLE, dt_X86_INS_CMOVG,  /* 4E,4F */
        };
        info->id = cmov_tab[(op & 0xf) - 2];
        return decode_reg_reg_alu(s, info, info->id, 1);
    }

    /* ----- CVTPI2PD/CVTTPS2PI/CVTPS2PI/CVTTPD2PI/CVTPD2PI ----- */
    case 0x12a:
    case 0x12c:
    case 0x12d: {
        if (s->prefix[0] == dt_X86_PREFIX_REP ||
            s->prefix[0] == dt_X86_PREFIX_REPNE)
            return fd_dispatch_sse(s, op, info);
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;

        info->x86.modrm = modrm;
        info->x86.op_count = 2;

        if (op == 0x12a) {
            info->id = (s->prefix[2] == dt_X86_PREFIX_OPSIZE)
                     ? dt_X86_INS_CVTPI2PD : dt_X86_INS_CVTPI2PS;
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = 16;
            info->x86.operands[0].reg = fd_reg_xmm[reg & 0xf];
            if (mod_val == 3) {
                info->x86.operands[1].type = dt_X86_OP_REG;
                info->x86.operands[1].size = 8;
                info->x86.operands[1].reg = fd_reg_mmx[rm & 7];
            } else {
                info->x86.operands[1].type = dt_X86_OP_MEM;
                info->x86.operands[1].size = 8;
                info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
                info->x86.operands[1].avx_zero_opmask = 0;
                fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw,
                                   NULL, NULL);
            }
        } else {
            int is_pd = s->prefix[2] == dt_X86_PREFIX_OPSIZE;
            info->id = (op == 0x12c)
                     ? (is_pd ? dt_X86_INS_CVTTPD2PI : dt_X86_INS_CVTTPS2PI)
                     : (is_pd ? dt_X86_INS_CVTPD2PI : dt_X86_INS_CVTPS2PI);
            info->x86.operands[0].type = dt_X86_OP_REG;
            info->x86.operands[0].size = 8;
            info->x86.operands[0].reg = fd_reg_mmx[reg & 7];
            if (mod_val == 3) {
                info->x86.operands[1].type = dt_X86_OP_REG;
                info->x86.operands[1].size = 16;
                info->x86.operands[1].reg = fd_reg_xmm[rm & 0xf];
            } else {
                info->x86.operands[1].type = dt_X86_OP_MEM;
                info->x86.operands[1].size = is_pd ? 16 : 8;
                info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
                info->x86.operands[1].avx_zero_opmask = 0;
                fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw,
                                   NULL, NULL);
            }
        }
        info->x86.operands[0].access = dt_CS_AC_WRITE;
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- 0F AE: FXSAVE/FXRSTOR/LFENCE/MFENCE/SFENCE ----- */
    case 0x1ae: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        info->x86.modrm = modrm;
        if (mod_val == 3) {
            /* Fence instructions (no memory operand) */
            info->x86.op_count = 0;
            if (op_ext == 5)      info->id = dt_X86_INS_LFENCE;
            else if (op_ext == 6) info->id = dt_X86_INS_MFENCE;
            else if (op_ext == 7) info->id = dt_X86_INS_SFENCE;
            else                  info->id = dt_X86_INS_LFENCE;
        } else {
            /* Memory forms: FXSAVE/FXRSTOR/LDMXCSR/STMXCSR/etc. */
            info->x86.op_count = 1;
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = (op_ext == 2 || op_ext == 3) ? 4 : 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, modrm & 7, NULL, NULL);
            if (op_ext == 0)      info->id = dt_X86_INS_FXSAVE;
            else if (op_ext == 1) info->id = dt_X86_INS_FXRSTOR;
            else if (op_ext == 2) info->id = dt_X86_INS_LDMXCSR;
            else if (op_ext == 3) info->id = dt_X86_INS_STMXCSR;
            else                  info->id = dt_X86_INS_LFENCE;
            info->x86.operands[0].access = (op_ext == 0 || op_ext == 3)
                                          ? dt_CS_AC_WRITE : dt_CS_AC_READ;
        }
        return 1;
    }

    case 0x1a2: /* CPUID */
        info->id = dt_X86_INS_CPUID;
        info->x86.op_count = 0;
        return 1;

    case 0x177: /* EMMS */
        info->id = dt_X86_INS_EMMS;
        info->x86.op_count = 0;
        return 1;

    /* ----- BT r/m, reg (0x0f 0xa3) ----- */
    case 0x1a3: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        int size = s->rex_w ? 64 : s->dflag;

        info->x86.modrm = modrm;
        info->id = dt_X86_INS_BT;
        info->x86.op_count = 2;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[0], size, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = size / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = dt_CS_AC_READ;
        opnd_write_reg(&info->x86.operands[1], size, reg);
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- SHLD/SHRD r/m, reg, imm8|CL (0F A4/A5/AC/AD) ----- */
    case 0x1a4:
    case 0x1a5:
    case 0x1ac:
    case 0x1ad: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        int uses_cl = (op == 0x1a5 || op == 0x1ad);

        info->x86.modrm = modrm;
        info->id = (op == 0x1a4 || op == 0x1a5) ? dt_X86_INS_SHLD : dt_X86_INS_SHRD;
        info->x86.op_count = 3;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[0], s->dflag, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = s->dflag / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = dt_CS_AC_READ | dt_CS_AC_WRITE;
        opnd_write_reg(&info->x86.operands[1], s->dflag, reg);
        info->x86.operands[1].access = dt_CS_AC_READ;
        if (uses_cl)
            opnd_write_reg8(&info->x86.operands[2], 1, 0);
        else
            opnd_write_imm(&info->x86.operands[2], 8, (uint8_t)fd_read_imm8(s));
        info->x86.operands[2].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- BT/BTS/BTR/BTC (0x0f 0xba /4-/7) ----- */
    case 0x1ba: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        int op_ext  = (modrm >> 3) & 7;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        if (op_ext < 4 || op_ext > 7) return 0;
        info->x86.modrm = modrm;
        static const unsigned int bt_insn[] = {
            0, 0, 0, 0, dt_X86_INS_BT, dt_X86_INS_BTS, dt_X86_INS_BTR, dt_X86_INS_BTC,
        };
        info->id = bt_insn[op_ext];
        info->x86.op_count = 2;
        if (mod_val == 3) {
            if (s->has_rex && s->rex_w)
                opnd_write_reg(&info->x86.operands[0], 64, rm);
            else
                opnd_write_reg(&info->x86.operands[0], s->dflag, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            if (s->has_rex && s->rex_w)
                info->x86.operands[0].size = 8;
            else
                info->x86.operands[0].size = s->dflag / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = dt_CS_AC_READ;
        int8_t bit_imm = (int8_t)fd_read_imm8(s);
        opnd_write_imm(&info->x86.operands[1], 8, (uint8_t)bit_imm);
        info->x86.operands[1].access = 0;
        return 1;
    }

    /* ----- BTS r/m, r (0x0f 0xab) ----- */
    case 0x1ab: {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        int size = (s->has_rex && s->rex_w) ? 64 : s->dflag;

        info->x86.modrm = modrm;
        info->id = dt_X86_INS_BTS;
        info->x86.op_count = 2;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[0], size, rm);
        } else {
            info->x86.operands[0].type = dt_X86_OP_MEM;
            info->x86.operands[0].size = size / 8;
            info->x86.operands[0].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[0].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[0], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[0].access = dt_CS_AC_READ | dt_CS_AC_WRITE;
        opnd_write_reg(&info->x86.operands[1], size, reg);
        info->x86.operands[1].access = dt_CS_AC_READ;
        return 1;
    }

    /* ----- XADD r/m8, r8 (0F C0) / XADD r/m, r (0F C1) ----- */
    case 0x1c0:
        return decode_reg_reg_alu8(s, info, dt_X86_INS_XADD, 0);
    case 0x1c1:
        return decode_reg_reg_alu(s, info, dt_X86_INS_XADD, 0);

    case 0x1b6: /* MOVZX Gv, Eb */
    case 0x1b7: /* MOVZX Gv, Ew */
    {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg  = ((modrm >> 3) & 7) | s->rex_r;
        rm   = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        int src_size = (op == 0x1b6) ? 8 : 16;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_MOVZX;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], s->dflag, reg);
        info->x86.operands[0].access = 0;
        if (mod_val == 3) {
            if (src_size == 8)
                opnd_write_reg8(&info->x86.operands[1], rm, s->has_rex);
            else
                opnd_write_reg(&info->x86.operands[1], src_size, rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = src_size / 8;
            info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[1].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[1].access = 0;
        return 1;
    }

    case 0x1be: /* MOVSX Gv, Eb */
    case 0x1bf: /* MOVSX Gv, Ew */
    {
        modrm = fd_read_byte(s);
        if (modrm < 0) return 0;
        int mod_val = (modrm >> 6) & 3;
        reg  = ((modrm >> 3) & 7) | s->rex_r;
        rm   = (modrm & 7) | s->rex_b;
        int rm_raw = modrm & 7;
        int src_size = (op == 0x1be) ? 8 : 16;
        info->x86.modrm = modrm;
        info->id = dt_X86_INS_MOVSX;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], s->dflag, reg);
        info->x86.operands[0].access = 0;
        if (mod_val == 3) {
            if (src_size == 8)
                opnd_write_reg8(&info->x86.operands[1], rm, s->has_rex);
            else
                opnd_write_reg(&info->x86.operands[1], src_size, rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = src_size / 8;
            info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[1].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw, NULL, NULL);
        }
        info->x86.operands[1].access = 0;
        return 1;
    }

    case 0x105: /* SYSCALL */
        info->id = dt_X86_INS_SYSCALL;
        info->x86.op_count = 0;
        return 1;

    case 0x10b: /* UD2 */
        info->id = dt_X86_INS_UD2;
        info->x86.op_count = 0;
        return 1;

    case 0x1b9: /* UD1 r32, r/m32 */
    case 0x1ff: /* UD0 r32, r/m32 */
    {
        int mod_val;
        int rm_raw;

        if (s->prefix[0] || s->prefix[2] || s->rex_w) {
            return 0;
        }
        modrm = fd_read_byte(s);
        if (modrm < 0) {
            return 0;
        }
        mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm = (modrm & 7) | s->rex_b;
        rm_raw = modrm & 7;
        info->x86.modrm = modrm;
        info->id = op == 0x1b9 ? dt_X86_INS_UD1 : dt_X86_INS_UD0;
        info->x86.op_count = 2;
        opnd_write_reg(&info->x86.operands[0], 32, reg);
        info->x86.operands[0].access = 0;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[1], 32, rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = 4;
            info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[1].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw,
                               NULL, NULL);
        }
        info->x86.operands[1].access = 0;
        return 1;
    }

    case 0x180 ... 0x18f: /* Jcc rel32 */
    {
        static const unsigned int jcc_tab[] = {
            dt_X86_INS_JO, dt_X86_INS_JNO, dt_X86_INS_JB, dt_X86_INS_JAE,
            dt_X86_INS_JE, dt_X86_INS_JNE, dt_X86_INS_JBE, dt_X86_INS_JA,
            dt_X86_INS_JS, dt_X86_INS_JNS, dt_X86_INS_JP, dt_X86_INS_JNP,
            dt_X86_INS_JL, dt_X86_INS_JGE, dt_X86_INS_JLE, dt_X86_INS_JG,
        };
        info->id = jcc_tab[op & 0xf];
        info->x86.op_count = 1;
        int32_t rel32 = (int32_t)fd_read_imm32(s);
        target = s->address + s->pos + rel32;
        opnd_write_imm(&info->x86.operands[0], s->mode ? 64 : s->dflag, target);
        info->x86.operands[0].access = 0;
        return 1;
    }

    case 0xc503f0: /* VEX.F2.0F3A.F0 /r ib: RORX Gv, Ev, Ib */
    {
        int width = s->rex_w ? 64 : 32;
        int mod_val;
        int rm_raw;
        int imm;

        if (s->vex_v != 0 || s->vex_l) {
            return 0;
        }
        modrm = fd_read_byte(s);
        if (modrm < 0) {
            return 0;
        }
        mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm = (modrm & 7) | s->rex_b;
        rm_raw = modrm & 7;

        info->x86.modrm = modrm;
        info->id = dt_X86_INS_RORX;
        info->x86.op_count = 3;
        opnd_write_reg(&info->x86.operands[0], width, reg);
        info->x86.operands[0].access = 0;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[1], width, rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = width / 8;
            info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[1].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw,
                               NULL, NULL);
        }
        info->x86.operands[1].access = 0;
        imm = fd_read_byte(s);
        if (imm < 0) {
            return 0;
        }
        opnd_write_imm(&info->x86.operands[2], 8, (uint8_t)imm);
        info->x86.operands[2].access = 0;
        return 1;
    }

    case 0xc403f7: /* VEX.F2.0F38.F7 /r: SHRX Gv, Ev, Gv */
    {
        int width = s->rex_w ? 64 : 32;
        int mod_val;
        int rm_raw;

        if (s->vex_l) {
            return 0;
        }
        modrm = fd_read_byte(s);
        if (modrm < 0) {
            return 0;
        }
        mod_val = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | s->rex_r;
        rm = (modrm & 7) | s->rex_b;
        rm_raw = modrm & 7;

        info->x86.modrm = modrm;
        info->id = dt_X86_INS_SHRX;
        info->x86.op_count = 3;
        opnd_write_reg(&info->x86.operands[0], width, reg);
        info->x86.operands[0].access = 0;
        if (mod_val == 3) {
            opnd_write_reg(&info->x86.operands[1], width, rm);
        } else {
            info->x86.operands[1].type = dt_X86_OP_MEM;
            info->x86.operands[1].size = width / 8;
            info->x86.operands[1].avx_bcast = dt_X86_AVX_BCAST_INVALID;
            info->x86.operands[1].avx_zero_opmask = 0;
            fd_decode_mem_addr(s, &info->x86.operands[1], mod_val, rm_raw,
                               NULL, NULL);
        }
        info->x86.operands[1].access = 0;
        opnd_write_reg(&info->x86.operands[2], width, s->vex_v);
        info->x86.operands[2].access = 0;
        return 1;
    }

    /* SSE instructions — dispatched to fast_decoder_sse.c */
    case 0x110 ... 0x11b:
    case 0x11d:
    case 0x120 ... 0x129:
    case 0x12b ... 0x12b:
    case 0x12e ... 0x141:
    case 0x150 ... 0x176:
    case 0x178 ... 0x17f:
    case 0x1a0 ... 0x1a1:   /* between Jcc rel32 and CPUID */
    case 0x1a6 ... 0x1aa:   /* between explicit BT/SHLD/SHRD and BTS(0x1AB) */
    case 0x1b2 ... 0x1b2:   /* between CMPXCHG and explicit BTR */
    case 0x1b4 ... 0x1b5:   /* between explicit BTR and MOVZX */
    case 0x1c2 ... 0x1c2:   /* CMPPS and neighbors */
    case 0x1c4 ... 0x1c6:   /* after explicit MOVNTI */
    case 0x1d0 ... 0x1fe:   /* after explicit BSWAP */
        return fd_dispatch_sse(s, op, info);

    /* SSE 3-byte instructions (0F 38 xx / 0F 3A xx) */
    case 0x13800 ... 0x13fff:
        return fd_dispatch_sse(s, op, info);
    case 0xc40000 ... 0xc403f6:
    case 0xc403f8 ... 0xc4ffff:
        return fd_dispatch_sse(s, op, info);

    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

typedef enum FDDecodeFlags {
    FD_DECODE_FULL = 0,
    FD_DECODE_PRIMARY = 1 << 0,
} FDDecodeFlags;

static void fd_init_primary_info(struct la_dt_insn *info)
{
    memset(&info->x86, 0, sizeof(info->x86));
    info->size = 0;
    info->address = 0;
    info->id = dt_X86_INS_INVALID;
}

static int fast_decoder_get_internal(const uint8_t *code, size_t code_size,
                      uint64_t address,
                      struct la_dt_insn *info,
                      int mode, FDDecodeFlags flags)
{
    FDState s;
    memset(&s, 0, sizeof(s));
    s.code      = code;
    s.code_size = code_size;
    s.pos       = 0;
    s.address   = address;
    s.mode      = mode;

    /* Parse prefixes */
    int b = parse_prefixes(&s);
    if (b < 0)
        return 0;

    /* Determine sizes */
    determine_sizes(&s);

    /* Parse opcode */
    int op = b;
    int first_opcode_byte = b;
    if (op == 0xc4) {
        int vex2 = fd_read_byte(&s);
        int vex3 = fd_read_byte(&s);
        if (vex2 < 0 || vex3 < 0) return 0;
        int map = vex2 & 0x1f;
        int opcode = fd_read_byte(&s);
        if (opcode < 0) return 0;
        if (map != 2 && map != 3) return 0;
        s.rex_r = ((~vex2 >> 7) & 1) << 3;
        s.rex_x = ((~vex2 >> 6) & 1) << 3;
        s.rex_b = ((~vex2 >> 5) & 1) << 3;
        s.rex_w = (vex3 >> 7) & 1;
        s.rex = 0x40 | (s.rex_w << 3) | (s.rex_r >> 1) |
                (s.rex_x >> 2) | (s.rex_b >> 3);
        s.has_rex = 1;
        s.vex_v = (~vex3 >> 3) & 0xf;
        s.vex_l = (vex3 >> 2) & 1;
        op = (map == 2 ? 0xc40000 : 0xc50000) |
             ((vex3 & 3) << 8) | opcode;
        first_opcode_byte = 0xc4;
    } else if (op == 0x0f) {
        int second = fd_read_byte(&s);
        if (second < 0) return 0;
        if (second == 0x38 || second == 0x3a) {
            /* Three-byte opcode: 0F 38 XX or 0F 3A XX */
            int third = fd_read_byte(&s);
            if (third < 0) return 0;
            op = 0x10000 | (second << 8) | third;
        } else {
            op = 0x100 | second;
        }
    }

    if (flags & FD_DECODE_PRIMARY) {
        fd_init_primary_info(info);
    } else {
        memset(info, 0, sizeof(struct la_dt_insn));
    }

    /* Fill common fields */
    info->address            = address;
    info->x86.prefix[0]      = s.prefix[0];
    info->x86.prefix[1]      = s.prefix[1];
    info->x86.prefix[2]      = s.prefix[2];
    info->x86.prefix[3]      = s.prefix[3];
    if ((op & 0xff0000) == 0xc40000 ||
        (op & 0xff0000) == 0xc50000) {
        info->x86.opcode[0] = first_opcode_byte;
        info->x86.opcode[1] = code[1];
        info->x86.opcode[2] = code[2];
    } else if (op < 0x10000) {
        info->x86.opcode[0]      = first_opcode_byte;
        info->x86.opcode[1]      = (op >= 0x100) ? (op & 0xff) : 0;
    } else {
        /* Capstone: 3-byte opcode stores only final byte in opcode[1] */
        info->x86.opcode[0] = first_opcode_byte;
        info->x86.opcode[1] = op & 0xff;
    }
    info->x86.rex            = s.rex;
    info->x86.addr_size      = s.aflag / 8;
    info->x86.avx_cc         = dt_X86_AVX_CC_INVALID;


    /* Dispatch instruction-specific decoding */
    if (!dispatch_instruction(&s, op, info))
        return 0;

    /* Fill final size and raw bytes */
    info->size = s.pos;
    if (!(flags & FD_DECODE_PRIMARY)) {
        int copy_len = s.pos < 24 ? s.pos : 24;
        memcpy(info->bytes, code, copy_len);
    }

    return 1;
}

int fast_decoder_get(const uint8_t *code, size_t code_size,
                      uint64_t address,
                      struct la_dt_insn *info,
                      int mode)
{
    return fast_decoder_get_internal(code, code_size, address, info, mode,
                                     FD_DECODE_FULL);
}

int fast_decoder_get_primary(const uint8_t *code, size_t code_size,
                      uint64_t address,
                      struct la_dt_insn *info,
                      int mode)
{
    return fast_decoder_get_internal(code, code_size, address, info, mode,
                                     FD_DECODE_PRIMARY);
}

#include "fast_decoder_ft.inc.c"

int fast_decoder_get_template(const uint8_t *code, size_t code_size,
                              uint64_t address,
                              FastDecodedTemplate *decoded,
                              int mode)
{
    decoded->tmpl = NULL;
    if (!fast_decoder_get_internal(code, code_size, address, &decoded->info,
                                   mode, FD_DECODE_PRIMARY)) {
        return 0;
    }
    {
        int copy_len = decoded->info.size < 24 ? decoded->info.size : 24;

        memset(decoded->info.bytes, 0, sizeof(decoded->info.bytes));
        memcpy(decoded->info.bytes, code, copy_len);
    }
    decoded->tmpl = fast_template_find_decoded(&decoded->info);
    return 1;
}

int fast_decoder_get_ft(const uint8_t *code, size_t code_size,
                        uint64_t address, FastDecodedFT *decoded,
                        int mode)
{
    decoded->tmpl = NULL;
    decoded->fields_valid = false;
    decoded->is_tb_ending = false;
    decoded->direct_fields = false;
    decoded->field_source = FT_FIELD_SOURCE_NONE;
    if (fd_ft_try_direct(code, code_size, address, decoded, mode)) {
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  fd_compare — field-by-field compare with Capstone output           */
/* ------------------------------------------------------------------ */

static int fd_debug_enabled(void)
{
    static int checked = 0, val = 0;
    if (!checked) {
        val = getenv("LATX_FD_DEBUG") != NULL;
        checked = 1;
    }
    return val;
}

int fd_compare(const struct la_dt_insn *fd, const struct la_dt_insn *cs, uint64_t pc)
{
    int errs = 0;

    if (fd->id != cs->id) {
        fprintf(stderr, "[FD] id mismatch at 0x%lx: fast=%d capstone=%d\n",
                (unsigned long)pc, fd->id, cs->id);
        errs++;
    }
    if (fd->size != cs->size) {
        fprintf(stderr, "[FD] size mismatch at 0x%lx: fast=%d capstone=%d\n",
                (unsigned long)pc, fd->size, cs->size);
        errs++;
    }
    if (fd->x86.op_count != cs->x86.op_count) {
        fprintf(stderr, "[FD] op_count mismatch at 0x%lx: fast=%d capstone=%d\n",
                (unsigned long)pc, fd->x86.op_count, cs->x86.op_count);
        errs++;
    }
    if (memcmp(fd->x86.opcode, cs->x86.opcode, sizeof(fd->x86.opcode))) {
        fprintf(stderr, "[FD] opcode mismatch at 0x%lx: fast=%02x/%02x/%02x/%02x cs=%02x/%02x/%02x/%02x\n",
                (unsigned long)pc,
                fd->x86.opcode[0], fd->x86.opcode[1], fd->x86.opcode[2], fd->x86.opcode[3],
                cs->x86.opcode[0], cs->x86.opcode[1], cs->x86.opcode[2], cs->x86.opcode[3]);
        errs++;
    }
    if (fd->x86.rex != cs->x86.rex) {
        fprintf(stderr, "[FD] rex mismatch at 0x%lx: fast=0x%02x capstone=0x%02x\n",
                (unsigned long)pc, fd->x86.rex, cs->x86.rex);
        errs++;
    }
    if (fd->x86.addr_size != cs->x86.addr_size) {
        fprintf(stderr, "[FD] addr_size mismatch at 0x%lx: fast=%d capstone=%d\n",
                (unsigned long)pc, fd->x86.addr_size, cs->x86.addr_size);
        errs++;
    }
    if (fd->x86.modrm != cs->x86.modrm) {
        fprintf(stderr, "[FD] modrm mismatch at 0x%lx: fast=0x%02x capstone=0x%02x\n",
                (unsigned long)pc, fd->x86.modrm, cs->x86.modrm);
        errs++;
    }

    /* Operand comparison */
    int n = fd->x86.op_count < cs->x86.op_count ? fd->x86.op_count : cs->x86.op_count;
    for (int i = 0; i < n; i++) {
        const dt_cs_x86_op *fo = &fd->x86.operands[i];
        const dt_cs_x86_op *co = &cs->x86.operands[i];
        if (fo->type != co->type) {
            fprintf(stderr, "[FD] opnd[%d] type mismatch at 0x%lx: fast=%d capstone=%d\n",
                    i, (unsigned long)pc, fo->type, co->type);
            errs++;
            continue;
        }
        if (fo->size != co->size) {
            fprintf(stderr, "[FD] opnd[%d] size mismatch at 0x%lx: fast=%d capstone=%d\n",
                    i, (unsigned long)pc, fo->size, co->size);
            errs++;
        }
        if (fo->type == dt_X86_OP_REG && fo->reg != co->reg) {
            fprintf(stderr, "[FD] opnd[%d] reg mismatch at 0x%lx: fast=%d capstone=%d\n",
                    i, (unsigned long)pc, fo->reg, co->reg);
            errs++;
        }
        if (fo->type == dt_X86_OP_IMM) {
            uint64_t mask = fo->size >= 8 ? UINT64_MAX :
                            ((1ULL << (fo->size * 8)) - 1);
            uint64_t fimm = (uint64_t)fo->imm & mask;
            uint64_t cimm = (uint64_t)co->imm & mask;
            if (fimm != cimm) {
            fprintf(stderr, "[FD] opnd[%d] imm mismatch at 0x%lx: fast=0x%lx capstone=0x%lx\n",
                    i, (unsigned long)pc, (unsigned long)fo->imm, (unsigned long)co->imm);
            errs++;
            }
        }
        if (fo->type == dt_X86_OP_MEM) {
            if (fo->mem.base != co->mem.base) {
                fprintf(stderr, "[FD] opnd[%d] mem.base mismatch at 0x%lx: fast=%d capstone=%d\n",
                        i, (unsigned long)pc, fo->mem.base, co->mem.base);
                errs++;
            }
            if (fo->mem.index != co->mem.index) {
                fprintf(stderr, "[FD] opnd[%d] mem.index mismatch at 0x%lx: fast=%d capstone=%d\n",
                        i, (unsigned long)pc, fo->mem.index, co->mem.index);
                errs++;
            }
            if (fo->mem.scale != co->mem.scale) {
                fprintf(stderr, "[FD] opnd[%d] mem.scale mismatch at 0x%lx: fast=%d capstone=%d\n",
                        i, (unsigned long)pc, fo->mem.scale, co->mem.scale);
                errs++;
            }
            if (fo->mem.disp != co->mem.disp) {
                fprintf(stderr, "[FD] opnd[%d] mem.disp mismatch at 0x%lx: fast=%ld capstone=%ld\n",
                        i, (unsigned long)pc, (long)fo->mem.disp, (long)co->mem.disp);
                errs++;
            }
        }
    }

    /* Compare prefix[3] (address size) — translator uses this */
    if (fd->x86.prefix[3] != cs->x86.prefix[3]) {
        fprintf(stderr, "[FD] prefix[3] mismatch at 0x%lx: fast=0x%02x capstone=0x%02x\n",
                (unsigned long)pc, fd->x86.prefix[3], cs->x86.prefix[3]);
        errs++;
    }
    /* Compare address */
    if (fd->address != cs->address) {
        fprintf(stderr, "[FD] address mismatch at 0x%lx: fast=0x%lx capstone=0x%lx\n",
                (unsigned long)pc, (unsigned long)fd->address, (unsigned long)cs->address);
        errs++;
    }
    if (errs && fd_debug_enabled()) {
        fprintf(stderr, "[FD] debug: pref=%02x/%02x/%02x/%02x\n",
                fd->x86.prefix[0], fd->x86.prefix[1],
                fd->x86.prefix[2], fd->x86.prefix[3]);
    }

    return errs;
}
