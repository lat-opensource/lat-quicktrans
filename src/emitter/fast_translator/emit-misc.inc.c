/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Zero words are success only for legacy LATS no-code instructions.
 * Keep this check on the zero-result branch of callers: ordinary emitters
 * still return zero on failure. LATU keeps its existing one-word NOPs.
 */
static inline bool ft_emit_zero_code_allowed(const FastTemplateFields *fields)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    switch (fields->kind) {
    case FT_ENDBR32:
    case FT_ENDBR64:
        return true;
    case FT_PAUSE:
        return option_pause != 0;
    case FT_NOP_MULTI:
        if (fields->id == dt_X86_INS_FSETPM) {
            return true;
        }
        /* FNOP shares this template, but its soft-FPU legacy handler
         * performs an exception check. Do not classify it as no-code.
         */
        if (fields->id != dt_X86_INS_NOP) {
            return false;
        }
#ifdef CONFIG_LATX_TU
        return option_pause != 0;
#else
        return true;
#endif
    default:
        return false;
    }
#else
    (void)fields;
    return false;
#endif
}

static int ft_emit_nop_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    (void)pc;

#ifdef QUICKTRANS_LATU
    /* Legacy LATU rejects FSETPM in both hard- and soft-FPU modes. */
    if (fields->id == dt_X86_INS_FSETPM) {
        return 0;
    }
#endif
    if (ft_emit_zero_code_allowed(fields)) {
        return 0;
    }
    FT_LA_ORI_EMIT(&out, la_zero, la_zero, 0);
    return (out - code);
}

static int ft_emit_prefetchw_template(const FastTemplateFields *fields,
                                      TranslationBlock *tb, target_ulong pc,
                                      uint32_t *code)
{
    uint32_t *out = code;
    int addr;

    (void)tb;
    if (fields->modrm_mod == 3 || fields->modrm_reg != 1 ||
        fields->prefix0 != 0 || fields->prefix2 != 0 ||
        !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
        return 0;
    }
    FT_LA_PRELD_EMIT(&out, 8, addr, ft_mem_access_offset(fields, addr));
    return (out - code);
}

static int ft_emit_prefetch_read_template(const FastTemplateFields *fields,
                                          TranslationBlock *tb, target_ulong pc,
                                          uint32_t *code)
{
    uint32_t *out = code;
    int addr;
    int modrm_reg;

    (void)tb;
    switch (fields->kind) {
    case FT_PREFETCHNTA:
        modrm_reg = 0;
        break;
    case FT_PREFETCHT0:
        modrm_reg = 1;
        break;
    case FT_PREFETCHT1:
        modrm_reg = 2;
        break;
    case FT_PREFETCHT2:
        modrm_reg = 3;
        break;
    default:
        return 0;
    }
    if (fields->modrm_mod == 3 || fields->modrm_reg != modrm_reg ||
        fields->prefix0 != 0 || fields->prefix2 != 0 ||
        !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
        return 0;
    }
    FT_LA_PRELD_EMIT(&out, 0, addr, ft_mem_access_offset(fields, addr));
    return (out - code);
}

static int ft_emit_fence_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)fields;
    (void)tb;
    (void)pc;

    FT_LA_DBAR_EMIT(&out, 0);
    return (out - code);
}

static int ft_emit_cache_flush_template(const FastTemplateFields *fields,
                                        TranslationBlock *tb,
                                        target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int expected_prefix2;

    (void)tb;
    (void)pc;
    expected_prefix2 = fields->kind == FT_CLFLUSHOPT ?
                       dt_X86_PREFIX_OPSIZE : 0;
    if (fields->modrm_mod == 3 || fields->modrm_reg != 7 ||
        fields->prefix0 != 0 || fields->prefix2 != expected_prefix2) {
        return 0;
    }
    FT_LA_IBAR_EMIT(&out, 0);
    return out - code;
}
