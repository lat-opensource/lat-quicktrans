/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Core LA encoding and register mapping helpers. */

static inline uint32_t ft_gpr3(uint32_t opcode, int rd, int rj, int rk)
{
    return opcode | rd | (rj << 5) | (rk << 10);
}

static inline void ft_emit_raw(uint32_t **out, uint32_t insn)
{
    ft_la_emit_u32(out, insn);
}

static inline void ft_emit_zero_extend_atomic_old(uint32_t **out, int reg,
                                                   int width)
{
    if (width == 8) {
        FT_LA_BSTRPICK_D_EMIT(out, reg, reg, 7, 0);
    } else if (width == 16) {
        FT_LA_BSTRPICK_D_EMIT(out, reg, reg, 15, 0);
    } else if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(out, reg, reg, 31, 0);
    }
}

#define FT_FLAG2(op, rj, rk) \
    do { \
        if (!fields->skip_flags) { \
            ft_emit_raw(&out, ft_gpr2((op), (rj), (rk))); \
        } \
    } while (0)

#define FT_FLAG1I(op, rj, imm) \
    do { \
        if (!fields->skip_flags) { \
            ft_emit_raw(&out, ft_gpr1_imm((op), (rj), (imm))); \
        } \
    } while (0)

#define FT_MTFLAG(rj, mask) \
    do { \
        if (!fields->skip_flags) { \
            FT_LA_X86MTFLAG_EMIT(&out, (rj), (mask)); \
        } \
    } while (0)

#define FT_MFFLAG(rd, mask) \
    do { \
        if (!fields->skip_flags) { \
            FT_LA_X86MFFLAG_EMIT(&out, (rd), (mask)); \
        } \
    } while (0)

static inline uint32_t ft_gpr3_imm12(uint32_t opcode, int rd, int rj, int imm)
{
    return opcode | rd | (rj << 5) | (((uint32_t)imm & 0xfff) << 10);
}

static inline uint32_t ft_gpr2(uint32_t opcode, int rj, int rk)
{
    return opcode | (rj << 5) | (rk << 10);
}

static inline uint32_t ft_gpr2_rd_rj(uint32_t opcode, int rd, int rj)
{
    return opcode | rd | (rj << 5);
}

static inline uint32_t ft_gpr1_imm(uint32_t opcode, int rj, int imm)
{
    return opcode | (rj << 5) | (((uint32_t)imm & 0x3f) << 10);
}

static inline uint32_t ft_gpr2_imm20(uint32_t opcode, int rd, int imm)
{
    return opcode | rd | (((uint32_t)imm & 0xfffff) << 5);
}

static inline uint32_t ft_x86mfflag(int rd, int mask)
{
    return FT_LA_OPCODE_X86MFFLAG | rd | (((uint32_t)mask & 0xff) << 10);
}

static inline uint32_t ft_x86mtflag(int rj, int mask)
{
    return FT_LA_OPCODE_X86MTFLAG | rj | (((uint32_t)mask & 0xff) << 10);
}

static inline uint32_t ft_x86mttop(int top)
{
    return FT_LA_OPCODE_X86MTTOP | (((uint32_t)top & 0x7) << 5);
}

static inline uint32_t ft_x86mftop(int rd)
{
    return FT_LA_OPCODE_X86MFTOP | rd;
}

static inline uint32_t ft_fcmp_cond(uint32_t opcode, int cd, int fj, int fk,
                                    int cond)
{
    return opcode | (cd & 0x7) | (fj << 5) | (fk << 10) |
           (((uint32_t)cond & 0x1f) << 15);
}

static inline uint32_t ft_movcf2gr(int rd, int cj)
{
    return FT_LA_OPCODE_MOVCF2GR | rd | ((cj & 0x7) << 5);
}

static inline uint32_t ft_bstrins_w(int rd, int rj, int msb, int lsb)
{
    return FT_LA_OPCODE_BSTRINS_W | rd | (rj << 5) |
           (((uint32_t)lsb & 0x1f) << 10) |
           (((uint32_t)msb & 0x1f) << 16);
}

static inline uint32_t ft_gr2scr(int scr, int rj)
{
    return FT_LA_OPCODE_GR2SCR | (scr & 0x1f) | (rj << 5);
}

static inline uint32_t ft_branch2(uint32_t opcode, int rj, int rd, int off)
{
    return opcode | rd | (rj << 5) | (((uint32_t)off & 0xffff) << 10);
}

static inline uint32_t ft_b26(int off)
{
    return FT_LA_OPCODE_B | (((uint32_t)off & 0xffff) << 10) |
           (((uint32_t)off >> 16) & 0x3ff);
}

static inline uint32_t ft_jirl(int rd, int rj, int off)
{
    return FT_LA_OPCODE_JIRL | rd | (rj << 5) | (((uint32_t)off & 0xffff) << 10);
}

static inline uint32_t ft_bstrpick_d(int rd, int rj, int msb, int lsb)
{
    return 0x00c00000u | rd | (rj << 5) |
           (((uint32_t)lsb & 0x3f) << 10) |
           (((uint32_t)msb & 0x3f) << 16);
}

static inline uint32_t ft_bstrins_d(int rd, int rj, int msb, int lsb)
{
    return 0x00800000u | rd | (rj << 5) |
           (((uint32_t)lsb & 0x3f) << 10) |
           (((uint32_t)msb & 0x3f) << 16);
}

static inline int ft_gpr(int x86_index)
{
    return reg_gpr_map[x86_index];
}

static inline bool ft_omit_gpr_zext32(const FastTemplateFields *fields)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    return fields->omit_zext32;
#else
    (void)fields;
    return false;
#endif
}

static inline int ft_xmm(int x86_index)
{
    return reg_xmm_map[x86_index];
}

static inline int ft_mmx(int x86_index)
{
    return reg_fpr_map[x86_index];
}

enum {
    /* reg_ftemp_map[FTEMP0], disjoint from MMX f0-f7 and XMM f16-f31. */
    ft_vscratch = 8,
};
