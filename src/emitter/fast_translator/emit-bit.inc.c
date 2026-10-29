/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Bit test and bit modify emit helpers. */

static int ft_count_bits_width(FastTemplateKind kind)
{
    switch (kind) {
    case FT_LZCNT_R64_RM64:
    case FT_TZCNT_R64_RM64:
    case FT_POPCNT_R64_RM64:
        return 64;
    case FT_LZCNT_R16_RM16:
    case FT_TZCNT_R16_RM16:
    case FT_POPCNT_R16_RM16:
        return 16;
    case FT_LZCNT_R32_RM32:
    case FT_TZCNT_R32_RM32:
    case FT_POPCNT_R32_RM32:
        return 32;
    default:
        return 0;
    }
}

static bool ft_count_bits_load_src(uint32_t **out,
                                   const FastTemplateFields *fields,
                                   target_ulong pc, int width, int *src)
{
    int value;

    if (width == 64) {
        if (!ft_rex_w(fields) || !ft_emit_load_rm64(out, fields, pc, &value)) {
            return false;
        }
        *src = value;
        return true;
    }
    if (ft_rex_w(fields)) {
        return false;
    }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if ((width == 16 && fields->prefix2 != dt_X86_PREFIX_OPSIZE) ||
        (width == 32 && fields->prefix2 == dt_X86_PREFIX_OPSIZE)) {
        return false;
    }
    if (!(width == 16 ? ft_emit_load_rm16_zext(out, fields, pc, la_t1) :
                       ft_emit_load_rm32_zext(out, fields, pc, la_t1))) {
        return false;
    }
#else
    if (width == 16) {
        if (fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
            !ft_emit_load_rm16(out, fields, pc, &value)) {
            return false;
        }
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, value, 15, 0);
    } else {
        if (fields->prefix2 == dt_X86_PREFIX_OPSIZE ||
            !ft_emit_load_rm32(out, fields, pc, &value)) {
            return false;
        }
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, value, 31, 0);
    }
#endif
    *src = la_t1;
    return true;
}

static void ft_count_bits_store_dst(uint32_t **out,
                                    const FastTemplateFields *fields,
                                    int dst, int value, int width)
{
    if (width == 64) {
        FT_LA_OR_EMIT(out, ft_gpr(dst), value, la_zero);
    } else if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(dst), value, 31, 0);
    } else {
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst), value, 15, 0);
    }
}

static void ft_count_bits_set_zf_from_zero(uint32_t **out, int value)
{
    FT_LA_BNE_EMIT(out, value, la_zero, 3);
    FT_LA_ORI_EMIT(out, la_t4, la_zero, 0xfff);
    FT_LA_X86MTFLAG_EMIT(out, la_t4, ZF_USEDEF_BIT);
}

static void ft_count_bits_set_cf_from_zero(uint32_t **out, int value)
{
    FT_LA_BNE_EMIT(out, value, la_zero, 3);
    FT_LA_ORI_EMIT(out, la_t4, la_zero, 0xfff);
    FT_LA_X86MTFLAG_EMIT(out, la_t4, CF_USEDEF_BIT);
}

static void ft_emit_popcnt_value(uint32_t **out, int result, int src,
                                 int width)
{
    FT_LA_OR_EMIT(out, result, src, la_zero);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    ft_emit_li64(out, la_t4, width == 16 ? 0x5555ull :
                               width == 32 ? 0x55555555ull :
                                             0x5555555555555555ull);
#else
    ft_emit_li64(out, la_t4, 0x5555555555555555ull);
#endif
    FT_LA_SRLI_D_EMIT(out, la_t3, result, 1);
    FT_LA_AND_EMIT(out, la_t3, la_t3, la_t4);
    FT_LA_SUB_D_EMIT(out, result, result, la_t3);

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    ft_emit_li64(out, la_t4, width == 16 ? 0x3333ull :
                               width == 32 ? 0x33333333ull :
                                             0x3333333333333333ull);
#else
    ft_emit_li64(out, la_t4, 0x3333333333333333ull);
#endif
    FT_LA_AND_EMIT(out, la_t3, result, la_t4);
    FT_LA_SRLI_D_EMIT(out, result, result, 2);
    FT_LA_AND_EMIT(out, result, result, la_t4);
    FT_LA_ADD_D_EMIT(out, result, result, la_t3);

    FT_LA_SRLI_D_EMIT(out, la_t3, result, 4);
    FT_LA_ADD_D_EMIT(out, result, result, la_t3);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    ft_emit_li64(out, la_t4, width == 16 ? 0x0f0full :
                               width == 32 ? 0x0f0f0f0full :
                                             0x0f0f0f0f0f0f0f0full);
#else
    ft_emit_li64(out, la_t4, 0x0f0f0f0f0f0f0f0full);
#endif
    FT_LA_AND_EMIT(out, result, result, la_t4);

    FT_LA_SRLI_D_EMIT(out, la_t3, result, 8);
    FT_LA_ADD_D_EMIT(out, result, result, la_t3);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (width != 16)
#endif
    {
        FT_LA_SRLI_D_EMIT(out, la_t3, result, 16);
        FT_LA_ADD_D_EMIT(out, result, result, la_t3);
    }
    if (width == 64) {
        FT_LA_SRLI_D_EMIT(out, la_t3, result, 32);
        FT_LA_ADD_D_EMIT(out, result, result, la_t3);
    }
    FT_LA_ANDI_EMIT(out, result, result, width == 64 ? 0x7f :
                                  width == 32 ? 0x3f : 0x1f);
}

static int ft_emit_count_bits_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int width = ft_count_bits_width(fields->kind);
    int dst = ft_modrm_reg_index(fields);
    int src;
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    int result = la_t2;
    bool direct_result = false;
#else
#define result la_t2
#endif
    bool is_lzcnt;
    bool is_tzcnt;
    bool is_popcnt;

    (void)tb;

    if (!width || dst >= GPR_NUM ||
        !ft_count_bits_load_src(&out, fields, pc, width, &src)) {
        return 0;
    }

#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    if (fields->skip_flags && width != 16) {
        result = ft_gpr(dst);
        direct_result = true;
    }
#endif

    is_lzcnt = fields->kind == FT_LZCNT_R64_RM64 ||
               fields->kind == FT_LZCNT_R32_RM32 ||
               fields->kind == FT_LZCNT_R16_RM16;
    is_tzcnt = fields->kind == FT_TZCNT_R64_RM64 ||
               fields->kind == FT_TZCNT_R32_RM32 ||
               fields->kind == FT_TZCNT_R16_RM16;
    is_popcnt = fields->kind == FT_POPCNT_R64_RM64 ||
                fields->kind == FT_POPCNT_R32_RM32 ||
                fields->kind == FT_POPCNT_R16_RM16;

    if (is_lzcnt) {
        FT_LA_CLZ_D_EMIT(&out, result, src);
        if (width != 64) {
            FT_LA_ADDI_D_EMIT(&out, result, result, -(64 - width));
        }
    } else if (is_tzcnt) {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (width == 32) {
            FT_LA_CTZ_W_EMIT(&out, result, src);
        } else
#endif
        {
            FT_LA_CTZ_D_EMIT(&out, result, src);
            if (width != 64) {
                FT_LA_BNE_EMIT(&out, src, la_zero, 2);
                FT_LA_ORI_EMIT(&out, result, la_zero, width);
            }
        }
    } else if (is_popcnt) {
        ft_emit_popcnt_value(&out, result, src, width);
    } else {
        return 0;
    }

    if (!fields->skip_flags) {
        if (is_popcnt) {
            FT_LA_X86MTFLAG_EMIT(&out, la_zero,
                                 CF_USEDEF_BIT | PF_USEDEF_BIT |
                                 AF_USEDEF_BIT | ZF_USEDEF_BIT |
                                 SF_USEDEF_BIT | OF_USEDEF_BIT);
            ft_count_bits_set_zf_from_zero(&out, src);
        } else {
            FT_LA_X86MTFLAG_EMIT(&out, la_zero,
                                 CF_USEDEF_BIT | ZF_USEDEF_BIT);
            ft_count_bits_set_cf_from_zero(&out, src);
            ft_count_bits_set_zf_from_zero(&out, result);
        }
    }

#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    if (!direct_result) {
        ft_count_bits_store_dst(&out, fields, dst, result, width);
    }
#else
    ft_count_bits_store_dst(&out, fields, dst, result, width);
#undef result
#endif
    return (out - code);
}

static int ft_emit_andn_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int width = fields->kind == FT_ANDN_R64_R_RM ? 64 : 32;
    int dst = fields->reg;
    int src1 = fields->imm;
    int src2;

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM || src1 < 0 || src1 >= GPR_NUM) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &src2)) {
            return 0;
        }
        FT_LA_ANDN_EMIT(&out, ft_gpr(dst), src2, ft_gpr(src1));
    } else {
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(&out, fields, pc, &src2)) {
            return 0;
        }
        FT_LA_ANDN_EMIT(&out, ft_gpr(dst), src2, ft_gpr(src1));
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }

    if (!fields->skip_flags) {
        FT_LA_X86MTFLAG_EMIT(&out, la_zero,
                             CF_USEDEF_BIT | ZF_USEDEF_BIT |
                             SF_USEDEF_BIT | OF_USEDEF_BIT);
        FT_LA_SRLI_D_EMIT(&out, la_t4, ft_gpr(dst), width - 1);
        FT_LA_SLLI_D_EMIT(&out, la_t4, la_t4, 7);
        FT_LA_X86MTFLAG_EMIT(&out, la_t4, SF_USEDEF_BIT);
        ft_count_bits_set_zf_from_zero(&out, ft_gpr(dst));
    }
    return (out - code);
}

static int ft_emit_mulx_template(const FastTemplateFields *fields,
                                 TranslationBlock *tb, target_ulong pc,
                                 uint32_t *code)
{
    uint32_t *out = code;
    int width = fields->kind == FT_MULX_R64_R_RM ? 64 : 32;
    int dst_hi = fields->reg;
    int dst_lo = fields->imm;
    int src;

    (void)tb;

    if (dst_hi < 0 || dst_hi >= GPR_NUM ||
        dst_lo < 0 || dst_lo >= GPR_NUM) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        /* Finish both products before overwriting an aliased input.  When
         * both destinations coincide, x86 keeps the high product. */
        int lo = ft_gpr(dst_lo);
        int hi = ft_gpr(dst_hi);
        bool direct_lo = lo != src && lo != ft_gpr(rdx_index) && lo != hi;

        FT_LA_MUL_D_EMIT(&out, direct_lo ? lo : la_t2,
                         src, ft_gpr(rdx_index));
        FT_LA_MULH_DU_EMIT(&out, hi, src, ft_gpr(rdx_index));
        if (!direct_lo && lo != hi) {
            FT_LA_OR_EMIT(&out, lo, la_t2, la_zero);
        }
    } else {
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        /* Word multiplies ignore stale high input bits.  Keep both results
         * in temporaries so every source/destination overlap is safe. */
        FT_LA_MUL_W_EMIT(&out, la_t2, src, ft_gpr(rdx_index));
        FT_LA_MULH_WU_EMIT(&out, la_t3, src, ft_gpr(rdx_index));
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst_lo), la_t2, 31, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst_hi), la_t3, 31, 0);
    }
    return (out - code);
}

static void ft_bls_set_cf_from_nonzero(uint32_t **out, int value)
{
    FT_LA_BEQ_EMIT(out, value, la_zero, 3);
    FT_LA_ORI_EMIT(out, la_t4, la_zero, 0xfff);
    FT_LA_X86MTFLAG_EMIT(out, la_t4, CF_USEDEF_BIT);
}

static int ft_emit_bls_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int width = fields->kind == FT_BLS_R64_RM ? 64 : 32;
    int ext = (fields->modrm >> 3) & 7;
    int dst = fields->reg;
    int src;

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM || ext < 1 || ext > 3) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (!fields->skip_flags && src == ft_gpr(dst)) {
#else
        if (src == ft_gpr(dst)) {
#endif
            FT_LA_OR_EMIT(&out, la_t3, src, la_zero);
            src = la_t3;
        }
        /* BLSI uses -src below; src - 1 is only needed by BLSR/BLSMSK. */
        if (ext != 3) {
            FT_LA_ADDI_D_EMIT(&out, la_t2, src, -1);
        }
    } else {
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        /* BLS flags are defined from the 32-bit source, not stale high bits. */
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (!fields->skip_flags) {
            FT_LA_BSTRPICK_D_EMIT(&out, la_t3, src, 31, 0);
            src = la_t3;
        }
        if (ext != 3) {
            FT_LA_ADDI_W_EMIT(&out, la_t2, src, -1);
        }
#else
        FT_LA_BSTRPICK_D_EMIT(&out, la_t3, src, 31, 0);
        src = la_t3;
        if (ext != 3) {
            FT_LA_ADDI_W_EMIT(&out, la_t2, src, -1);
        }
#endif
    }

    if (ext == 1) {
        FT_LA_AND_EMIT(&out, ft_gpr(dst), la_t2, src);
    } else if (ext == 2) {
        FT_LA_XOR_EMIT(&out, ft_gpr(dst), la_t2, src);
    } else {
        if (width == 64) {
            FT_LA_SUB_D_EMIT(&out, la_t2, la_zero, src);
        } else {
            FT_LA_SUB_W_EMIT(&out, la_t2, la_zero, src);
        }
        FT_LA_AND_EMIT(&out, ft_gpr(dst), la_t2, src);
    }
    if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }

    if (!fields->skip_flags) {
        FT_LA_X86MTFLAG_EMIT(&out, la_zero,
                             CF_USEDEF_BIT | ZF_USEDEF_BIT |
                             SF_USEDEF_BIT | OF_USEDEF_BIT);
        if (ext == 3) {
            ft_bls_set_cf_from_nonzero(&out, src);
        } else {
            ft_count_bits_set_cf_from_zero(&out, src);
        }
        if (ext != 2) {
            ft_count_bits_set_zf_from_zero(&out, ft_gpr(dst));
        }
        FT_LA_SRLI_D_EMIT(&out, la_t4, ft_gpr(dst), width - 1);
        FT_LA_SLLI_D_EMIT(&out, la_t4, la_t4, 7);
        FT_LA_X86MTFLAG_EMIT(&out, la_t4, SF_USEDEF_BIT);
    }
    return (out - code);
}

static int ft_emit_bextr_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int width = fields->kind == FT_BEXTR_R64_RM_R ? 64 : 32;
    int dst = fields->reg;
    int ctrl = fields->imm;
    int src;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    const int count = la_t2;
#else
    const int count = la_t0;
#endif

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM || ctrl < 0 || ctrl >= GPR_NUM) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
    } else {
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
    }

    if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(&out, la_t4, src, 31, 0);
        src = la_t4;
    }
#if !defined(QUICKTRANS_LATU) || defined(CONFIG_SOFTMMU)
    else if (src == la_t0) {
        FT_LA_OR_EMIT(&out, la_t4, src, la_zero);
        src = la_t4;
    }
#endif
    FT_LA_BSTRPICK_D_EMIT(&out, count, ft_gpr(ctrl), 7, 0);
    FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(ctrl), 15, 8);
    FT_LA_SRL_D_EMIT(&out, ft_gpr(dst), src, count);
    FT_LA_SLTUI_EMIT(&out, la_t4, count, width);
    FT_LA_MASKEQZ_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t4);

    ft_emit_li64(&out, la_t3, UINT64_MAX);
    FT_LA_SLL_D_EMIT(&out, la_t3, la_t3, la_t1);
    FT_LA_SLTUI_EMIT(&out, la_t4, la_t1, width);
    FT_LA_MASKEQZ_EMIT(&out, la_t3, la_t3, la_t4);
    FT_LA_ANDN_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t3);
#if !defined(QUICKTRANS_LATU) || defined(CONFIG_SOFTMMU)
    if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }
#endif

    if (!fields->skip_flags) {
        FT_LA_X86MTFLAG_EMIT(&out, la_zero,
                             CF_USEDEF_BIT | ZF_USEDEF_BIT |
                             OF_USEDEF_BIT);
        ft_count_bits_set_zf_from_zero(&out, ft_gpr(dst));
    }
    return (out - code);
}

static int ft_emit_bzhi_template(const FastTemplateFields *fields,
                                 TranslationBlock *tb, target_ulong pc,
                                 uint32_t *code)
{
    uint32_t *out = code;
    int width = fields->kind == FT_BZHI_R64_RM_R ? 64 : 32;
    int dst = fields->reg;
    int ctrl = fields->imm;
    int src;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    const int count = la_t2;
#else
    const int count = la_t0;
#endif

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM || ctrl < 0 || ctrl >= GPR_NUM) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
    } else {
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
    }

#if !defined(QUICKTRANS_LATU) || defined(CONFIG_SOFTMMU)
    if (src == la_t0) {
        FT_LA_OR_EMIT(&out, la_t4, src, la_zero);
        src = la_t4;
    }
#endif
    FT_LA_BSTRPICK_D_EMIT(&out, count, ft_gpr(ctrl), 7, 0);
    ft_emit_li64(&out, la_t1, UINT64_MAX);
    FT_LA_SLL_D_EMIT(&out, la_t1, la_t1, count);
    FT_LA_SLTUI_EMIT(&out, la_t3, count, width);
    FT_LA_MASKEQZ_EMIT(&out, la_t1, la_t1, la_t3);
    FT_LA_ANDN_EMIT(&out, ft_gpr(dst), src, la_t1);
    if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }

    if (!fields->skip_flags) {
        FT_LA_X86MTFLAG_EMIT(&out, la_zero,
                             CF_USEDEF_BIT | ZF_USEDEF_BIT |
                             SF_USEDEF_BIT | OF_USEDEF_BIT);
        FT_LA_XORI_EMIT(&out, la_t3, la_t3, 1);
        FT_LA_X86MTFLAG_EMIT(&out, la_t3, CF_USEDEF_BIT);
        ft_count_bits_set_zf_from_zero(&out, ft_gpr(dst));
        FT_LA_SRLI_D_EMIT(&out, la_t4, ft_gpr(dst), width - 1);
        FT_LA_SLLI_D_EMIT(&out, la_t4, la_t4, 7);
        FT_LA_X86MTFLAG_EMIT(&out, la_t4, SF_USEDEF_BIT);
    }
    return (out - code);
}

static int ft_emit_sarx_template(const FastTemplateFields *fields,
                                 TranslationBlock *tb, target_ulong pc,
                                 uint32_t *code)
{
    uint32_t *out = code;
    int width = fields->kind == FT_SARX_R64_RM_R ? 64 : 32;
    int dst = fields->reg;
    int count = fields->imm;
    int src;

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM || count < 0 || count >= GPR_NUM) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_SRA_D_EMIT(&out, ft_gpr(dst), src, ft_gpr(count));
    } else {
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_SRA_W_EMIT(&out, ft_gpr(dst), src, ft_gpr(count));
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }
    return out - code;
}

static int ft_emit_shlx_template(const FastTemplateFields *fields,
                                 TranslationBlock *tb, target_ulong pc,
                                 uint32_t *code)
{
    uint32_t *out = code;
    int width = fields->kind == FT_SHLX_R64_RM_R ? 64 : 32;
    int dst = fields->reg;
    int count = fields->imm;
    int src;

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM || count < 0 || count >= GPR_NUM) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_SLL_D_EMIT(&out, ft_gpr(dst), src, ft_gpr(count));
    } else {
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_SLL_W_EMIT(&out, ft_gpr(dst), src, ft_gpr(count));
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }
    return out - code;
}

static int ft_emit_pext_template(const FastTemplateFields *fields,
                                 TranslationBlock *tb, target_ulong pc,
                                 uint32_t *code)
{
    uint32_t *out = code;
    FastBranchLabel done = { 0 };
    FastBranchLabel loop = { 0 };
    FastBranchFixup done_fixup;
    int width = fields->kind == FT_PEXT_R64_R_RM ? 64 : 32;
    int dst = fields->reg;
    int src = fields->imm;
    int mask;
    int value = la_t1;

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM || src < 0 || src >= GPR_NUM) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &mask)) {
            return 0;
        }
    } else {
        if (ft_rex_w(fields)) {
            return 0;
        }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (fields->modrm_mod != 3) {
            if (!ft_emit_load_rm32_zext(&out, fields, pc, la_t0)) {
                return 0;
            }
            mask = la_t0;
        } else
#endif
        if (!ft_emit_load_rm32(&out, fields, pc, &mask)) {
            return 0;
        }
    }

    /* Keep both inputs before writing dst, because PEXT operands may alias. */
#ifdef QUICKTRANS_LATU
    /* dst is written only after the loop; the source need not be copied.
     * Word shifts consume only its low 32 bits. */
    value = ft_gpr(src);
    if (width == 32) {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (fields->modrm_mod == 3)
#endif
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, mask, 31, 0);
    } else {
#if !defined(CONFIG_SOFTMMU)
        if (mask != la_t0)
#endif
        FT_LA_OR_EMIT(&out, la_t0, mask, la_zero);
    }
#else
    FT_LA_OR_EMIT(&out, la_t0, mask, la_zero);
    FT_LA_OR_EMIT(&out, la_t1, ft_gpr(src), la_zero);
    if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, la_t0, 31, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, la_t1, 31, 0);
    }
#endif
    FT_LA_OR_EMIT(&out, la_t2, la_zero, la_zero);
    FT_LA_OR_EMIT(&out, la_t3, la_zero, la_zero);
    ft_emit_branch_placeholder(&out, &done_fixup, FT_BRANCH_BEQ, la_t0,
                               la_zero, &done);

    ft_bind_branch_label(&loop, out);
    if (width == 64) {
        FT_LA_CTZ_D_EMIT(&out, la_t4, la_t0);
        FT_LA_SRL_D_EMIT(&out, la_t4, value, la_t4);
        FT_LA_ANDI_EMIT(&out, la_t4, la_t4, 1);
        FT_LA_SLL_D_EMIT(&out, la_t4, la_t4, la_t3);
        FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t4);
        FT_LA_ADDI_D_EMIT(&out, la_t3, la_t3, 1);
        FT_LA_ADDI_D_EMIT(&out, la_t4, la_t0, -1);
    } else {
        FT_LA_CTZ_W_EMIT(&out, la_t4, la_t0);
        FT_LA_SRL_W_EMIT(&out, la_t4, value, la_t4);
        FT_LA_ANDI_EMIT(&out, la_t4, la_t4, 1);
        FT_LA_SLL_W_EMIT(&out, la_t4, la_t4, la_t3);
        FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t4);
        FT_LA_ADDI_W_EMIT(&out, la_t3, la_t3, 1);
        FT_LA_ADDI_W_EMIT(&out, la_t4, la_t0, -1);
    }
    FT_LA_AND_EMIT(&out, la_t0, la_t0, la_t4);
    {
        FastBranchFixup loop_fixup;

        ft_emit_branch_placeholder(&out, &loop_fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &loop);
        ft_resolve_branch_fixup(&loop_fixup);
    }

    ft_bind_branch_label(&done, out);
    ft_resolve_branch_fixup(&done_fixup);
    if (width == 64) {
        FT_LA_OR_EMIT(&out, ft_gpr(dst), la_t2, la_zero);
    } else {
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), la_t2, 31, 0);
    }
    return out - code;
}

static int ft_emit_pdep_template(const FastTemplateFields *fields,
                                 TranslationBlock *tb, target_ulong pc,
                                 uint32_t *code)
{
    uint32_t *out = code;
    FastBranchLabel done = { 0 };
    FastBranchLabel loop = { 0 };
    FastBranchFixup done_fixup;
    int width = fields->kind == FT_PDEP_R64_R_RM ? 64 : 32;
    int dst = fields->reg;
    int src = fields->imm;
    int mask;

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM || src < 0 || src >= GPR_NUM) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &mask)) {
            return 0;
        }
    } else {
        if (ft_rex_w(fields)) {
            return 0;
        }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (fields->modrm_mod != 3) {
            if (!ft_emit_load_rm32_zext(&out, fields, pc, la_t0)) {
                return 0;
            }
            mask = la_t0;
        } else
#endif
        if (!ft_emit_load_rm32(&out, fields, pc, &mask)) {
            return 0;
        }
    }

    /* Preserve inputs before writing dst because PDEP operands may alias. */
#ifdef QUICKTRANS_LATU
    if (width == 32) {
#if !defined(CONFIG_SOFTMMU)
        if (fields->modrm_mod == 3)
#endif
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, mask, 31, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(src), 31, 0);
    } else {
#if !defined(CONFIG_SOFTMMU)
        if (mask != la_t0)
#endif
        FT_LA_OR_EMIT(&out, la_t0, mask, la_zero);
        FT_LA_OR_EMIT(&out, la_t1, ft_gpr(src), la_zero);
    }
#else
    FT_LA_OR_EMIT(&out, la_t0, mask, la_zero);
    FT_LA_OR_EMIT(&out, la_t1, ft_gpr(src), la_zero);
    if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, la_t0, 31, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, la_t1, 31, 0);
    }
#endif
    FT_LA_OR_EMIT(&out, la_t2, la_zero, la_zero);
    ft_emit_branch_placeholder(&out, &done_fixup, FT_BRANCH_BEQ, la_t0,
                               la_zero, &done);

    ft_bind_branch_label(&loop, out);
    if (width == 64) {
        FT_LA_CTZ_D_EMIT(&out, la_t3, la_t0);
        FT_LA_ANDI_EMIT(&out, la_t4, la_t1, 1);
        FT_LA_SRLI_D_EMIT(&out, la_t1, la_t1, 1);
        FT_LA_SLL_D_EMIT(&out, la_t4, la_t4, la_t3);
        FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t4);
        FT_LA_ADDI_D_EMIT(&out, la_t4, la_t0, -1);
    } else {
        FT_LA_CTZ_W_EMIT(&out, la_t3, la_t0);
        FT_LA_ANDI_EMIT(&out, la_t4, la_t1, 1);
        FT_LA_SRLI_W_EMIT(&out, la_t1, la_t1, 1);
        FT_LA_SLL_W_EMIT(&out, la_t4, la_t4, la_t3);
        FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t4);
        FT_LA_ADDI_W_EMIT(&out, la_t4, la_t0, -1);
    }
    FT_LA_AND_EMIT(&out, la_t0, la_t0, la_t4);
    {
        FastBranchFixup loop_fixup;

        ft_emit_branch_placeholder(&out, &loop_fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &loop);
        ft_resolve_branch_fixup(&loop_fixup);
    }

    ft_bind_branch_label(&done, out);
    ft_resolve_branch_fixup(&done_fixup);
    if (width == 64) {
        FT_LA_OR_EMIT(&out, ft_gpr(dst), la_t2, la_zero);
    } else {
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), la_t2, 31, 0);
    }
    return out - code;
}

static void ft_emit_btx_cf(uint32_t **out, const FastTemplateFields *fields,
                           int value, int bit, int width)
{
    if (fields->skip_flags) {
        return;
    }
    if (width == 64) {
        FT_LA_SRL_D_EMIT(out, la_t1, value, bit);
    } else {
        FT_LA_SRL_W_EMIT(out, la_t1, value, bit);
    }
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 1);
    if (!fields->skip_flags) {
        FT_LA_X86MTFLAG_EMIT(out, la_t1, 0x1);
    }
}

static bool ft_emit_locked_btx(uint32_t **out,
                               const FastTemplateFields *fields,
                               target_ulong pc, int ext, int width,
                               bool bit_is_reg, int bit_value)
{
    FastBranchLabel aligned = { 0 };
    FastBranchLabel retry = { 0 };
    FastBranchLabel done = { 0 };
    FastBranchFixup aligned_fixup;
    FastBranchFixup retry_fixup;
    FastBranchFixup done_fixup;
    int log2_width = width == 64 ? 6 : width == 32 ? 5 : 4;
    int log2_bytes = log2_width - 3;
    int addr;

    if (ext < 5 || ext > 7 || fields->modrm_mod == 3 ||
        !ft_emit_rmw_addr(out, fields, pc, &addr, la_t4)) {
        return false;
    }
    if (addr != la_t4) {
        FT_LA_OR_EMIT(out, la_t4, addr, la_zero);
    }
    addr = la_t4;

    if (bit_is_reg) {
        if (width == 64) {
            FT_LA_OR_EMIT(out, la_t0, ft_gpr(bit_value), la_zero);
        } else {
            int shift = 64 - width;

            FT_LA_SLLI_D_EMIT(out, la_t0, ft_gpr(bit_value), shift);
            FT_LA_SRAI_D_EMIT(out, la_t0, la_t0, shift);
        }
        FT_LA_SRAI_D_EMIT(out, la_t3, la_t0, log2_width);
        FT_LA_SLLI_D_EMIT(out, la_t3, la_t3, log2_bytes);
        FT_LA_ADD_D_EMIT(out, addr, addr, la_t3);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, width - 1);
    } else {
        FT_LA_ADDI_D_EMIT(out, la_t0, la_zero,
                          bit_value & (width - 1));
    }

    /* Use one aligned 64-bit CAS, as the legacy LL/SC path does. */
    FT_LA_ANDI_EMIT(out, la_t3, addr, 7);
    FT_LA_BSTRINS_D_EMIT(out, addr, la_zero, 2, 0);
    FT_LA_SLLI_D_EMIT(out, la_t3, la_t3, 3);
    FT_LA_ADD_D_EMIT(out, la_t0, la_t0, la_t3);
    FT_LA_SRLI_D_EMIT(out, la_t3, la_t0, 6);
    ft_emit_branch_placeholder(out, &aligned_fixup, FT_BRANCH_BEQ,
                               la_t3, la_zero, &aligned);
    FT_LA_ANDI_EMIT(out, la_t0, la_t0, 63);
    FT_LA_ADDI_D_EMIT(out, addr, addr, 8);
    ft_bind_branch_label(&aligned, *out);
    ft_resolve_branch_fixup(&aligned_fixup);

    FT_LA_LD_D_EMIT(out, la_t3, addr, 0);
    ft_bind_branch_label(&retry, *out);
    FT_LA_ORI_EMIT(out, la_t2, la_zero, 1);
    FT_LA_SLL_D_EMIT(out, la_t2, la_t2, la_t0);
    if (ext == 5) {
        FT_LA_OR_EMIT(out, la_t2, la_t3, la_t2);
    } else if (ext == 6) {
        FT_LA_NOR_EMIT(out, la_t2, la_t2, la_zero);
        FT_LA_AND_EMIT(out, la_t2, la_t3, la_t2);
    } else {
        FT_LA_XOR_EMIT(out, la_t2, la_t3, la_t2);
    }
    FT_LA_OR_EMIT(out, la_t1, la_t3, la_zero);
    ft_emit_atomic_op(out, fields, FT_LA_OPCODE_AMCAS_DB_D, la_t1, la_t2, addr);
    ft_emit_branch_placeholder(out, &done_fixup, FT_BRANCH_BEQ,
                               la_t1, la_t3, &done);
    FT_LA_OR_EMIT(out, la_t3, la_t1, la_zero);
    ft_emit_branch_placeholder(out, &retry_fixup, FT_BRANCH_B,
                               0, 0, &retry);
    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&done_fixup);
    ft_resolve_branch_fixup(&retry_fixup);
    ft_emit_btx_cf(out, fields, la_t3, la_t0, 64);
    return true;
}

static int ft_emit_btx_imm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int ext = (fields->modrm >> 3) & 7;
    bool is_16 = fields->prefix2 == dt_X86_PREFIX_OPSIZE;
    bool is64 = ft_rex_w(fields);
    int width = is64 ? 64 : is_16 ? 16 : 32;
    int bit = fields->imm & (width - 1);

    (void)tb;

    if (ext < 4 || ext > 7) {
        return 0;
    }
    if (fields->prefix0 == dt_X86_PREFIX_LOCK) {
        return ft_emit_locked_btx(&out, fields, pc, ext, width, false,
                                  fields->imm) ? out - code : 0;
    }
    if (fields->modrm_mod == 3) {
        int dst = ft_modrm_rm_index(fields);

        if (dst >= GPR_NUM) {
            return 0;
        }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (!fields->skip_flags) {
            FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(dst), bit, bit);
            FT_LA_X86MTFLAG_EMIT(&out, la_t0, 0x1);
        }
#else
        if (is64) {
            FT_LA_SRLI_D_EMIT(&out, la_t0, ft_gpr(dst), bit);
        } else {
            FT_LA_SRLI_W_EMIT(&out, la_t0, ft_gpr(dst), bit);
        }
        FT_LA_ANDI_EMIT(&out, la_t0, la_t0, 1);
        if (!fields->skip_flags) {
            FT_LA_X86MTFLAG_EMIT(&out, la_t0, 0x1);
        }
#endif
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (ext == 4 && fields->skip_flags) {
            FT_LA_NOP_EMIT(&out);
        }
        if (ext == 6) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_zero, bit, bit);
        } else if ((ext == 5 || ext == 7) && bit < 12) {
            ft_emit_raw(&out, ft_gpr3_imm12(ext == 5 ? FT_LA_OPCODE_ORI :
                                                     FT_LA_OPCODE_XORI,
                                           ft_gpr(dst), ft_gpr(dst), 1u << bit));
        } else
#endif
        if (ext == 5) {
            ft_emit_li64(&out, la_t1, 1ull << bit);
            FT_LA_OR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t1);
        } else if (ext == 6) {
            ft_emit_li64(&out, la_t1, 1ull << bit);
            FT_LA_NOR_EMIT(&out, la_t2, la_t1, la_zero);
            FT_LA_AND_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t2);
        } else if (ext == 7) {
            ft_emit_li64(&out, la_t1, 1ull << bit);
            FT_LA_XOR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t1);
        }
        if (ext >= 5 && width == 32) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        }
    } else {
        int addr;
        int mem_offset;

        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        mem_offset = ft_mem_access_offset(fields, addr);
        ft_emit_raw(&out,
                    ft_gpr3_imm12(width == 64 ? FT_LA_OPCODE_LD_D :
                                  width == 16 ? FT_LA_OPCODE_LD_HU :
                                                FT_LA_OPCODE_LD_WU,
                                  la_t2, addr, mem_offset));
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (ext != 4) {
            bool uses_mask = ext >= 5 && ext != 6 && bit >= 12;
            bool clobbers_addr = (addr == la_t1 && !fields->skip_flags) ||
                                 (addr == la_t0 && uses_mask);

            if (ext >= 5 && clobbers_addr) {
                FT_LA_OR_EMIT(&out, la_t4, addr, la_zero);
                addr = la_t4;
            }
            if (!fields->skip_flags) {
                FT_LA_BSTRPICK_D_EMIT(&out, la_t1, la_t2, bit, bit);
                FT_LA_X86MTFLAG_EMIT(&out, la_t1, 0x1);
            }
            if (ext >= 5) {
                if (ext == 6) {
                    FT_LA_BSTRINS_D_EMIT(&out, la_t2, la_zero, bit, bit);
                } else if (bit < 12) {
                    ft_emit_raw(&out, ft_gpr3_imm12(ext == 5 ? FT_LA_OPCODE_ORI :
                                                            FT_LA_OPCODE_XORI,
                                                   la_t2, la_t2, 1u << bit));
                } else {
                    ft_emit_li64(&out, la_t0, 1ull << bit);
                    ft_emit_raw(&out, ft_gpr3(ext == 5 ? FT_LA_OPCODE_OR :
                                                       FT_LA_OPCODE_XOR,
                                             la_t2, la_t2, la_t0));
                }
                ft_emit_raw(&out,
                            ft_gpr3_imm12(width == 64 ? FT_LA_OPCODE_ST_D :
                                          width == 16 ? FT_LA_OPCODE_ST_H :
                                                        FT_LA_OPCODE_ST_W,
                                          la_t2, addr, mem_offset));
            }
            return out - code;
        }
#endif
        /* The address helper may use t0 or t1, both needed below. */
        if (addr == la_t0 || addr == la_t1) {
            FT_LA_OR_EMIT(&out, la_t4, addr, la_zero);
            addr = la_t4;
        }
        if (is64) {
            FT_LA_SRLI_D_EMIT(&out, la_t1, la_t2, bit);
        } else {
            FT_LA_SRLI_W_EMIT(&out, la_t1, la_t2, bit);
        }
        FT_LA_ANDI_EMIT(&out, la_t1, la_t1, 1);
        if (!fields->skip_flags) {
            FT_LA_X86MTFLAG_EMIT(&out, la_t1, 0x1);
        }
        if (ext >= 5) {
            ft_emit_li64(&out, la_t0, 1ull << bit);
            if (ext == 5) {
                FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t0);
            } else if (ext == 6) {
                FT_LA_NOR_EMIT(&out, la_t0, la_t0, la_zero);
                FT_LA_AND_EMIT(&out, la_t2, la_t2, la_t0);
            } else {
                FT_LA_XOR_EMIT(&out, la_t2, la_t2, la_t0);
            }
            ft_emit_raw(&out,
                        ft_gpr3_imm12(width == 64 ? FT_LA_OPCODE_ST_D :
                                      width == 16 ? FT_LA_OPCODE_ST_H :
                                                    FT_LA_OPCODE_ST_W,
                                      la_t2, addr, mem_offset));
        }
    }
    return (out - code);
}

static int ft_emit_btx_reg_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int ext;
    int val_reg;
    int addr = -1;
    int mem_offset = 0;
    bool is_16 = fields->prefix2 == dt_X86_PREFIX_OPSIZE;
    bool is64 = ft_rex_w(fields);
    int width = is64 ? 64 : is_16 ? 16 : 32;
    int log2_width = width == 64 ? 6 : width == 16 ? 4 : 5;
    int log2_bytes = log2_width - 3;
    int bit_idx = ft_modrm_reg_index(fields);

    (void)tb;

    if (fields->id == dt_X86_INS_BT) {
        ext = 4;
    } else if (fields->id == dt_X86_INS_BTS) {
        ext = 5;
    } else if (fields->id == dt_X86_INS_BTR) {
        ext = 6;
    } else if (fields->id == dt_X86_INS_BTC) {
        ext = 7;
    } else {
        return 0;
    }

    if (bit_idx >= GPR_NUM) {
        return 0;
    }
    if (fields->prefix0 == dt_X86_PREFIX_LOCK) {
        return ft_emit_locked_btx(&out, fields, pc, ext, width, true,
                                  bit_idx) ? out - code : 0;
    }
    if (fields->modrm_mod == 3) {
        val_reg = ft_modrm_rm_index(fields);
        if (val_reg >= GPR_NUM) {
            return 0;
        }
        val_reg = ft_gpr(val_reg);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (ext == 4 && width != 16) {
            /* SRL.D/W already uses the low six/five count bits. */
            ft_emit_btx_cf(&out, fields, val_reg, ft_gpr(bit_idx), width);
            if (out == code) {
                FT_LA_NOP_EMIT(&out);
            }
            return out - code;
        }
#endif
        FT_LA_ANDI_EMIT(&out, la_t0, ft_gpr(bit_idx), width - 1);
    } else {
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        mem_offset = ft_mem_access_offset(fields, addr);
        if (width != 64) {
            int shift = 64 - width;

            FT_LA_SLLI_D_EMIT(&out, la_t4, ft_gpr(bit_idx), shift);
            FT_LA_SRAI_D_EMIT(&out, la_t4, la_t4, shift);
        }
        /* Keep the final address in t4 across CF and mask generation. */
        FT_LA_SRAI_D_EMIT(&out, la_t4,
                          width == 64 ? ft_gpr(bit_idx) : la_t4,
                          log2_width);
        FT_LA_ALSL_D_EMIT(&out, la_t4, la_t4, addr, log2_bytes - 1);
        addr = la_t4;
        FT_LA_ANDI_EMIT(&out, la_t0, ft_gpr(bit_idx), width - 1);
        ft_emit_raw(&out,
                    ft_gpr3_imm12(width == 64 ? FT_LA_OPCODE_LD_D :
                                  width == 16 ? FT_LA_OPCODE_LD_HU :
                                                FT_LA_OPCODE_LD_WU,
                                  la_t3, addr, mem_offset));
        val_reg = la_t3;
    }

    ft_emit_btx_cf(&out, fields, val_reg, la_t0, width);
    if (ext >= 5) {
        int modify_reg = val_reg;

        FT_LA_ORI_EMIT(&out, la_t1, la_zero, 1);
        ft_emit_raw(&out,
                    ft_gpr3(width == 64 ? FT_LA_OPCODE_SLL_D :
                                          FT_LA_OPCODE_SLL_W,
                            la_t2, la_t1, la_t0));
        if (ext == 6) {
            FT_LA_ANDN_EMIT(&out, modify_reg, modify_reg, la_t2);
        } else if (ext == 5) {
            FT_LA_OR_EMIT(&out, modify_reg, modify_reg, la_t2);
        } else if (ext == 7) {
            FT_LA_XOR_EMIT(&out, modify_reg, modify_reg, la_t2);
        }
        if (addr >= 0) {
            ft_emit_raw(&out,
                        ft_gpr3_imm12(width == 64 ? FT_LA_OPCODE_ST_D :
                                      width == 16 ? FT_LA_OPCODE_ST_H :
                                                    FT_LA_OPCODE_ST_W,
                                      modify_reg, addr, mem_offset));
        } else if (width == 32) {
            FT_LA_BSTRPICK_D_EMIT(&out, modify_reg, modify_reg, 31, 0);
        }
    }
    return (out - code);
}
