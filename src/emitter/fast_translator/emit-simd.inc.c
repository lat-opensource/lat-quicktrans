/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

static void ft_emit_lats_simd_fpe_check_ex(uint32_t **out,
                                           TranslationBlock *tb,
                                           target_ulong pc,
                                           bool suppress_precision);

static void ft_emit_lats_simd_fpe_check(uint32_t **out,
                                        TranslationBlock *tb,
                                        target_ulong pc);

static bool ft_lats_simd_fpe_enabled(TranslationBlock *tb);

static int ft_emit_pextrw_r32_xmm_imm8_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;
    (void)pc;

    if (ft_rex_w(fields) || fields->modrm_mod != 3) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    src = ft_modrm_rm_index(fields);
    if (dst >= GPR_NUM || src >= XMM_NUM) {
        return 0;
    }
    ft_emit_raw(&out, FT_LA_OPCODE_VPICKVE2GR_HU | ft_gpr(dst) |
                (ft_xmm(src) << 5) | (((uint32_t)fields->imm & 7) << 10));
    return (out - code);
}

static int ft_emit_pextrw_sse41_rm16_xmm_imm8_template(
    const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc,
    uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;
    if (ft_rex_w(fields)) {
        return 0;
    }
    src = ft_modrm_reg_index(fields);
    if (src >= XMM_NUM) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_LA_VPICKVE2GR_HU_EMIT(&out, ft_gpr(dst), ft_xmm(src),
                                 fields->imm & 7);
    } else {
        FT_LA_VPICKVE2GR_HU_EMIT(&out, la_t4, ft_xmm(src), fields->imm & 7);
        if (!ft_emit_store_rm16(&out, fields, pc, la_t4)) {
            return 0;
        }
    }
    return out - code;
}

static int ft_emit_pextrw_r32_mmx_imm8_template(const FastTemplateFields *fields,
                                                 TranslationBlock *tb,
                                                 target_ulong pc,
                                                 uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PEXTRW || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || fields->modrm_mod != 3) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    src = fields->modrm_rm;
    if (dst >= GPR_NUM || src >= 8) {
        return 0;
    }

    /* PEXTRW with no 66 prefix reads an MMX register; REX.W is ignored. */
    FT_LA_VPICKVE2GR_HU_EMIT(&out, ft_gpr(dst), ft_mmx(src),
                             fields->imm & 3);
    return out - code;
}

static int ft_emit_pinsrw_mmx_rm16_imm8_template(
    const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc,
    uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;

    if (fields->id != dt_X86_INS_PINSRW || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || fields->modrm_reg >= 8) {
        return 0;
    }
    dst = fields->modrm_reg;

    if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
        return 0;
    }

    /* REX.W is ignored, but REX.X/B were used while decoding the address. */
    FT_LA_VINSGR2VR_H_EMIT(&out, ft_mmx(dst), src, fields->imm & 3);
    return out - code;
}

static int ft_emit_movd_xmm_r32_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;
    (void)pc;

    if (ft_rex_w(fields)) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    if (dst >= XMM_NUM) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
        src = ft_gpr(src);
    } else if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
        return 0;
    }
    /* Like legacy MOVD, finish a potentially faulting load before changing
     * the architectural destination register. */
    ft_emit_raw(&out, FT_LA_OPCODE_VANDI_B | ft_xmm(dst) |
                (ft_xmm(dst) << 5));
    ft_emit_raw(&out, FT_LA_OPCODE_VINSGR2VR_W | ft_xmm(dst) |
                (src << 5));
    return (out - code);
}

static int ft_emit_movd_r32_xmm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;
    (void)pc;

    if (ft_rex_w(fields)) {
        return 0;
    }
    src = ft_modrm_reg_index(fields);
    if (src >= XMM_NUM) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        ft_emit_raw(&out, FT_LA_OPCODE_VPICKVE2GR_WU | ft_gpr(dst) |
                    (ft_xmm(src) << 5));
    } else {
        FT_LA_VPICKVE2GR_WU_EMIT(&out, la_t0, ft_xmm(src), 0);
        if (!ft_emit_store_rm32(&out, fields, pc, la_t0, true)) {
            return 0;
        }
    }
    return (out - code);
}

static int ft_emit_movd_mmx_rm32_template(const FastTemplateFields *fields,
                                          TranslationBlock *tb,
                                          target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;

    if (fields->id != dt_X86_INS_MOVD || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || ft_rex_w(fields)) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    if (dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
        src = ft_gpr(src);
    } else if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
        return 0;
    }
    FT_LA_BSTRPICK_D_EMIT(&out, la_t0, src, 31, 0);
    FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(dst), la_t0);
    return (out - code);
}

static int ft_emit_movd_rm32_mmx_template(const FastTemplateFields *fields,
                                          TranslationBlock *tb,
                                          target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int src;

    (void)tb;

    if (fields->id != dt_X86_INS_MOVD || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || ft_rex_w(fields)) {
        return 0;
    }
    src = ft_modrm_reg_index(fields);
    if (src >= 8) {
        return 0;
    }
    FT_LA_MOVFR2GR_D_EMIT(&out, la_t0, ft_mmx(src));
    if (!ft_emit_store_rm32(&out, fields, pc, la_t0,
                            !ft_omit_gpr_zext32(fields))) {
        return 0;
    }
    return (out - code);
}

static int ft_emit_movq_mmx_rm64_gpr_template(
    const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc,
    uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;

    if (fields->id != dt_X86_INS_MOVQ || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || !ft_rex_w(fields)) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    if (dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
        src = ft_gpr(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_LD_D_EMIT(&out, la_t0, addr,
                        ft_mem_access_offset(fields, addr));
        src = la_t0;
    }
    FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_pmovmskb_r32_xmm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;
    (void)pc;

    if (fields->modrm_mod != 3) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    src = ft_modrm_rm_index(fields);
    if (dst >= GPR_NUM || src >= XMM_NUM) {
        return 0;
    }
    if (fields->id == dt_X86_INS_MOVMSKPD) {
        ft_emit_raw(&out, FT_LA_OPCODE_VMSKLTZ_D | ft_vscratch |
                    (ft_xmm(src) << 5));
    } else if (fields->id == dt_X86_INS_MOVMSKPS) {
        ft_emit_raw(&out, FT_LA_OPCODE_VMSKLTZ_W | ft_vscratch |
                    (ft_xmm(src) << 5));
    } else {
        ft_emit_raw(&out, FT_LA_OPCODE_VMSKLTZ_B | ft_vscratch |
                    (ft_xmm(src) << 5));
    }
    ft_emit_raw(&out, FT_LA_OPCODE_MOVFR2GR_D | ft_gpr(dst) |
                (ft_vscratch << 5));
    /* VMSKLTZ zeroes the bits above its 2/4/16-bit sign mask. */
    return (out - code);
}

static int ft_emit_pmovmskb_r32_mmx_template(const FastTemplateFields *fields,
                                              TranslationBlock *tb,
                                              target_ulong pc,
                                              uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PMOVMSKB || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || fields->modrm_mod != 3) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    src = fields->modrm_rm;
    if (dst >= GPR_NUM || src >= 8) {
        return 0;
    }

    /* The no-0x66 form reads MMX; only its eight low byte sign bits count. */
    ft_emit_raw(&out, FT_LA_OPCODE_VMSKLTZ_B | ft_vscratch |
                (ft_mmx(src) << 5));
    ft_emit_raw(&out, FT_LA_OPCODE_MOVFR2GR_D | ft_gpr(dst) |
                (ft_vscratch << 5));
    FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 7, 0);
    return (out - code);
}

static bool ft_emit_xmmm_src(uint32_t **out, const FastTemplateFields *fields,
                             target_ulong pc, int *src)
{
    if (fields->modrm_mod == 3) {
        int rm = ft_modrm_rm_index(fields);

        if (rm >= XMM_NUM) {
            return false;
        }
        *src = ft_xmm(rm);
        return true;
    }

    int addr;

    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        return false;
    }
    FT_LA_VLD_EMIT(out, ft_vscratch, addr,
                   ft_mem_access_offset(fields, addr));
    *src = ft_vscratch;
    return true;
}

static bool ft_emit_xmmm_src_bytes(uint32_t **out,
                                   const FastTemplateFields *fields,
                                   target_ulong pc, int bytes, int *src)
{
    int addr;
    int offset;

    if (bytes == 16) {
        return ft_emit_xmmm_src(out, fields, pc, src);
    }
    if (fields->modrm_mod == 3) {
        int rm = ft_modrm_rm_index(fields);

        if (rm >= XMM_NUM) {
            return false;
        }
        *src = ft_xmm(rm);
        return true;
    }
    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        return false;
    }

    offset = ft_mem_access_offset(fields, addr);
    FT_LA_VXOR_V_EMIT(out, ft_vscratch, ft_vscratch, ft_vscratch);
    switch (bytes) {
    case 2:
        FT_LA_LD_HU_EMIT(out, la_t0, addr, offset);
        FT_LA_VINSGR2VR_H_EMIT(out, ft_vscratch, la_t0, 0);
        break;
    case 4:
        FT_LA_LD_WU_EMIT(out, la_t0, addr, offset);
        FT_LA_VINSGR2VR_W_EMIT(out, ft_vscratch, la_t0, 0);
        break;
    case 8:
        FT_LA_FLD_D_EMIT(out, ft_vscratch, addr, offset);
        break;
    default:
        return false;
    }
    *src = ft_vscratch;
    return true;
}

static void ft_emit_blendps(uint32_t **out, int dst, int src, int imm)
{
    if (imm & 0x1) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, src, 0x00);
    }
    if (imm & 0x2) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, src, 0x11);
    }
    if (imm & 0x4) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, src, 0x22);
    }
    if (imm & 0x8) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, src, 0x33);
    }
}

static void ft_emit_blendpd(uint32_t **out, int dst, int src, int imm)
{
    if (imm & 0x1) {
        FT_LA_VEXTRINS_D_EMIT(out, dst, src, 0x00);
    }
    if (imm & 0x2) {
        FT_LA_VEXTRINS_D_EMIT(out, dst, src, 0x11);
    }
}

static void ft_emit_pblendw(uint32_t **out, int dst, int src, int imm)
{
    if (imm == 0xff) {
        FT_LA_VAND_V_EMIT(out, dst, src, src);
        return;
    }
    if ((imm & 0x0f) == 0x0f) {
        FT_LA_VEXTRINS_D_EMIT(out, dst, src, 0x00);
        imm &= ~0x0f;
    }
    if ((imm & 0xf0) == 0xf0) {
        FT_LA_VEXTRINS_D_EMIT(out, dst, src, 0x11);
        imm &= ~0xf0;
    }
    if ((imm & 0x03) == 0x03) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, src, 0x00);
        imm &= ~0x03;
    }
    if ((imm & 0x0c) == 0x0c) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, src, 0x11);
        imm &= ~0x0c;
    }
    if ((imm & 0x30) == 0x30) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, src, 0x22);
        imm &= ~0x30;
    }
    if ((imm & 0xc0) == 0xc0) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, src, 0x33);
        imm &= ~0xc0;
    }
    if (imm & 0x01) {
        FT_LA_VEXTRINS_H_EMIT(out, dst, src, 0x00);
    }
    if (imm & 0x02) {
        FT_LA_VEXTRINS_H_EMIT(out, dst, src, 0x11);
    }
    if (imm & 0x04) {
        FT_LA_VEXTRINS_H_EMIT(out, dst, src, 0x22);
    }
    if (imm & 0x08) {
        FT_LA_VEXTRINS_H_EMIT(out, dst, src, 0x33);
    }
    if (imm & 0x10) {
        FT_LA_VEXTRINS_H_EMIT(out, dst, src, 0x44);
    }
    if (imm & 0x20) {
        FT_LA_VEXTRINS_H_EMIT(out, dst, src, 0x55);
    }
    if (imm & 0x40) {
        FT_LA_VEXTRINS_H_EMIT(out, dst, src, 0x66);
    }
    if (imm & 0x80) {
        FT_LA_VEXTRINS_H_EMIT(out, dst, src, 0x77);
    }
}

static int ft_emit_blend_imm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int imm = fields->imm & 0xff;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }
    switch (fields->id) {
    case dt_X86_INS_BLENDPS:
        ft_emit_blendps(&out, ft_xmm(dst), src, imm);
        break;
    case dt_X86_INS_BLENDPD:
        ft_emit_blendpd(&out, ft_xmm(dst), src, imm);
        break;
    case dt_X86_INS_PBLENDW:
        ft_emit_pblendw(&out, ft_xmm(dst), src, imm);
        break;
    default:
        return 0;
    }
    if (out == code) {
        FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst), ft_xmm(dst));
    }
    return (out - code);
}

static int ft_emit_blendv_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }
    if (fields->id == dt_X86_INS_BLENDVPS) {
        FT_LA_VSLTI_W_EMIT(&out, ft_vscratch + 1, ft_xmm(0), 0);
    } else if (fields->id == dt_X86_INS_BLENDVPD) {
        FT_LA_VSLTI_D_EMIT(&out, ft_vscratch + 1, ft_xmm(0), 0);
    } else if (fields->id == dt_X86_INS_PBLENDVB) {
        FT_LA_VSLTI_B_EMIT(&out, ft_vscratch + 1, ft_xmm(0), 0);
    } else {
        return 0;
    }
    FT_LA_VBITSEL_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst), src,
                         ft_vscratch + 1);
    return (out - code);
}

static int ft_emit_pshufb_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int zero = ft_vscratch + 1;
    int src_t1 = ft_vscratch + 2;
    int src_t2 = ft_vscratch + 3;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_PSHUFB) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }

    FT_LA_VREPLGR2VR_D_EMIT(&out, zero, la_zero);
    FT_LA_VANDI_B_EMIT(&out, src_t2, src, 0x0f);
    FT_LA_VANDI_B_EMIT(&out, src_t1, src, 0x80);
    FT_LA_VSRLI_B_EMIT(&out, src_t1, src_t1, 3);
    FT_LA_VADD_B_EMIT(&out, src_t1, src_t2, src_t1);
    FT_LA_VSHUF_B_EMIT(&out, ft_xmm(dst), zero, ft_xmm(dst), src_t1);
    return (out - code);
}

static bool ft_emit_mmxm64_src(uint32_t **out,
                               const FastTemplateFields *fields,
                               target_ulong pc, int *src)
{
    if (fields->modrm_mod == 3) {
        if (fields->modrm_rm >= 8) {
            return false;
        }
        *src = ft_mmx(fields->modrm_rm);
        return true;
    }
    {
        int addr;

        if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
            return false;
        }
        FT_LA_FLD_D_EMIT(out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        *src = ft_vscratch;
        return true;
    }
}

static int ft_emit_palignr_mmx_template(const FastTemplateFields *fields,
                                        TranslationBlock *tb,
                                        target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;
    int imm = fields->imm & 0xff;

    (void)tb;

    if (fields->id != dt_X86_INS_PALIGNR || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (imm >= 16) {
        FT_LA_MOVGR2FR_D_EMIT(&out, ft_mmx(dst), la_zero);
        return out - code;
    }

    if (imm >= 8) {
        FT_LA_VINSGR2VR_D_EMIT(&out, ft_mmx(dst), la_zero, 1);
        FT_LA_VBSRL_V_EMIT(&out, ft_mmx(dst), ft_mmx(dst), imm - 8);
        return out - code;
    }
    if (!ft_emit_mmxm64_src(&out, fields, pc, &src)) {
        return 0;
    }
    if (imm == 0) {
        FT_LA_FMOV_D_EMIT(&out, ft_mmx(dst), src);
    } else {
        int joined = ft_vscratch + 1;

        FT_LA_VOR_V_EMIT(&out, joined, src, src);
        FT_LA_VEXTRINS_D_EMIT(&out, joined, ft_mmx(dst), 0x10);
        FT_LA_VBSRL_V_EMIT(&out, ft_mmx(dst), joined, imm);
    }
    return out - code;
}

static int ft_emit_pshufb_mmx_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;
    int zero = ft_vscratch + 1;
    int control = ft_vscratch + 2;
    int high = ft_vscratch + 3;

    (void)tb;

    if (fields->id != dt_X86_INS_PSHUFB || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8 ||
        !ft_emit_mmxm64_src(&out, fields, pc, &src)) {
        return 0;
    }
    FT_LA_VREPLGR2VR_D_EMIT(&out, zero, la_zero);
    FT_LA_VANDI_B_EMIT(&out, control, src, 0x07);
    FT_LA_VANDI_B_EMIT(&out, high, src, 0x80);
    FT_LA_VSRLI_B_EMIT(&out, high, high, 3);
    FT_LA_VADD_B_EMIT(&out, control, control, high);
    FT_LA_VSHUF_B_EMIT(&out, ft_mmx(dst), zero, ft_mmx(dst), control);
    return out - code;
}

static int ft_emit_simd_madd_mmx_template(const FastTemplateFields *fields,
                                          TranslationBlock *tb,
                                          target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;

    if (fields->prefix0 != 0 || fields->prefix2 != 0 || dst >= 8 ||
        !ft_emit_mmxm64_src(&out, fields, pc, &src)) {
        return 0;
    }
    if (fields->id == dt_X86_INS_PMULHRSW) {
        FT_LA_VMULWEV_W_H_EMIT(&out, ft_vscratch + 1, ft_mmx(dst), src);
        FT_LA_VMULWOD_W_H_EMIT(&out, ft_vscratch + 2, ft_mmx(dst), src);
        FT_LA_VSRAI_W_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1, 14);
        FT_LA_VSRAI_W_EMIT(&out, ft_vscratch + 2, ft_vscratch + 2, 14);
        FT_LA_VADDI_WU_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1, 1);
        FT_LA_VADDI_WU_EMIT(&out, ft_vscratch + 2, ft_vscratch + 2, 1);
        FT_LA_VSRANI_H_W_EMIT(&out, ft_vscratch + 2, ft_vscratch + 1, 1);
        FT_LA_VSHUF4I_W_EMIT(&out, ft_vscratch + 2, ft_vscratch + 2, 0xd8);
        FT_LA_VSHUF4I_H_EMIT(&out, ft_mmx(dst), ft_vscratch + 2, 0xd8);
    } else if (fields->id == dt_X86_INS_PMADDUBSW) {
        FT_LA_VXOR_V_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1,
                          ft_vscratch + 1);
        FT_LA_VABSD_B_EMIT(&out, ft_vscratch + 3, src, ft_vscratch + 1);
        FT_LA_VMADDWEV_H_BU_EMIT(&out, ft_vscratch + 1, ft_mmx(dst),
                                 ft_vscratch + 3);
        FT_LA_VXOR_V_EMIT(&out, ft_vscratch + 2, ft_vscratch + 2,
                          ft_vscratch + 2);
        FT_LA_VMADDWOD_H_BU_EMIT(&out, ft_vscratch + 2, ft_mmx(dst),
                                 ft_vscratch + 3);
        FT_LA_ORI_EMIT(&out, la_t0, la_zero, 1);
        FT_LA_VREPLGR2VR_B_EMIT(&out, ft_vscratch + 3, la_t0);
        FT_LA_VSIGNCOV_B_EMIT(&out, ft_vscratch + 4, src,
                              ft_vscratch + 3);
        FT_LA_VMULWEV_H_B_EMIT(&out, ft_vscratch + 5,
                               ft_vscratch + 4, ft_vscratch + 3);
        FT_LA_VMULWOD_H_B_EMIT(&out, ft_vscratch + 3,
                               ft_vscratch + 4, ft_vscratch + 3);
        FT_LA_VMUL_H_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1,
                          ft_vscratch + 5);
        FT_LA_VMUL_H_EMIT(&out, ft_vscratch + 2, ft_vscratch + 2,
                          ft_vscratch + 3);
        FT_LA_VSADD_H_EMIT(&out, ft_mmx(dst), ft_vscratch + 2,
                           ft_vscratch + 1);
    } else {
        return 0;
    }
    return out - code;
}

static int ft_emit_simd_bin_mmx_template(const FastTemplateFields *fields,
                                         TranslationBlock *tb,
                                         target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;

    if (fields->prefix0 != 0 || fields->prefix2 != 0 || dst >= 8 ||
        !ft_emit_mmxm64_src(&out, fields, pc, &src)) {
        return 0;
    }
    switch (fields->id) {
    case dt_X86_INS_PSIGNB:
        FT_LA_VSIGNCOV_B_EMIT(&out, ft_mmx(dst), src, ft_mmx(dst));
        break;
    case dt_X86_INS_PSIGNW:
        FT_LA_VSIGNCOV_H_EMIT(&out, ft_mmx(dst), src, ft_mmx(dst));
        break;
    case dt_X86_INS_PSIGND:
        FT_LA_VSIGNCOV_W_EMIT(&out, ft_mmx(dst), src, ft_mmx(dst));
        break;
    case dt_X86_INS_PABSB:
        FT_LA_VXOR_V_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1,
                          ft_vscratch + 1);
        FT_LA_VABSD_B_EMIT(&out, ft_mmx(dst), src, ft_vscratch + 1);
        break;
    case dt_X86_INS_PABSW:
        FT_LA_VXOR_V_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1,
                          ft_vscratch + 1);
        FT_LA_VABSD_H_EMIT(&out, ft_mmx(dst), src, ft_vscratch + 1);
        break;
    case dt_X86_INS_PABSD:
        FT_LA_VXOR_V_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1,
                          ft_vscratch + 1);
        FT_LA_VABSD_W_EMIT(&out, ft_mmx(dst), src, ft_vscratch + 1);
        break;
    default:
        return 0;
    }
    return out - code;
}

static int ft_emit_phadd_sub_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int even = ft_vscratch + 1;
    int odd = ft_vscratch + 2;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }

    switch (fields->id) {
    case dt_X86_INS_PHADDW:
    case dt_X86_INS_PHADDSW:
    case dt_X86_INS_PHSUBW:
    case dt_X86_INS_PHSUBSW:
        FT_LA_VPICKEV_H_EMIT(&out, even, src, ft_xmm(dst));
        FT_LA_VPICKOD_H_EMIT(&out, odd, src, ft_xmm(dst));
        if (fields->id == dt_X86_INS_PHADDW) {
            FT_LA_VADD_H_EMIT(&out, ft_xmm(dst), even, odd);
        } else if (fields->id == dt_X86_INS_PHADDSW) {
            FT_LA_VSADD_H_EMIT(&out, ft_xmm(dst), even, odd);
        } else if (fields->id == dt_X86_INS_PHSUBW) {
            FT_LA_VSUB_H_EMIT(&out, ft_xmm(dst), even, odd);
        } else {
            FT_LA_VSSUB_H_EMIT(&out, ft_xmm(dst), even, odd);
        }
        break;
    case dt_X86_INS_PHADDD:
    case dt_X86_INS_PHSUBD:
        FT_LA_VPICKEV_W_EMIT(&out, even, src, ft_xmm(dst));
        FT_LA_VPICKOD_W_EMIT(&out, odd, src, ft_xmm(dst));
        if (fields->id == dt_X86_INS_PHADDD) {
            FT_LA_VADD_W_EMIT(&out, ft_xmm(dst), even, odd);
        } else {
            FT_LA_VSUB_W_EMIT(&out, ft_xmm(dst), even, odd);
        }
        break;
    default:
        return 0;
    }

    return (out - code);
}

static int ft_emit_phadd_sub_mmx_template(const FastTemplateFields *fields,
                                          TranslationBlock *tb,
                                          target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;
    int even = ft_vscratch + 1;
    int odd = ft_vscratch + 2;

    (void)tb;

    if (fields->prefix0 != 0 || fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        if (fields->modrm_rm >= 8) {
            return 0;
        }
        src = ft_mmx(fields->modrm_rm);
    } else {
        int addr;

        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }
    switch (fields->id) {
    case dt_X86_INS_PHADDW:
    case dt_X86_INS_PHADDSW:
    case dt_X86_INS_PHSUBW:
    case dt_X86_INS_PHSUBSW:
        FT_LA_VPICKEV_H_EMIT(&out, even, src, ft_mmx(dst));
        FT_LA_VPICKOD_H_EMIT(&out, odd, src, ft_mmx(dst));
        if (fields->id == dt_X86_INS_PHADDW) {
            FT_LA_VADD_H_EMIT(&out, ft_mmx(dst), even, odd);
        } else if (fields->id == dt_X86_INS_PHADDSW) {
            FT_LA_VSADD_H_EMIT(&out, ft_mmx(dst), even, odd);
        } else if (fields->id == dt_X86_INS_PHSUBW) {
            FT_LA_VSUB_H_EMIT(&out, ft_mmx(dst), even, odd);
        } else {
            FT_LA_VSSUB_H_EMIT(&out, ft_mmx(dst), even, odd);
        }
        break;
    case dt_X86_INS_PHADDD:
    case dt_X86_INS_PHSUBD:
        FT_LA_VPICKEV_W_EMIT(&out, even, src, ft_mmx(dst));
        FT_LA_VPICKOD_W_EMIT(&out, odd, src, ft_mmx(dst));
        if (fields->id == dt_X86_INS_PHADDD) {
            FT_LA_VADD_W_EMIT(&out, ft_mmx(dst), even, odd);
        } else {
            FT_LA_VSUB_W_EMIT(&out, ft_mmx(dst), even, odd);
        }
        break;
    default:
        return 0;
    }
    FT_LA_VPICKEV_W_EMIT(&out, ft_mmx(dst), ft_mmx(dst), ft_mmx(dst));
    return out - code;
}

static int ft_emit_hadd_sub_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int even = ft_vscratch + 1;
    int odd = ft_vscratch + 2;
    bool fpe = ft_lats_simd_fpe_enabled(tb);
    int result;

    if (dst >= XMM_NUM) {
        return 0;
    }
    result = fpe ? ft_vscratch + 3 : ft_xmm(dst);
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }

    switch (fields->id) {
    case dt_X86_INS_HADDPS:
    case dt_X86_INS_HSUBPS:
        if (fields->prefix0 != 0xf2) {
            return 0;
        }
        FT_LA_VPICKEV_W_EMIT(&out, even, src, ft_xmm(dst));
        FT_LA_VPICKOD_W_EMIT(&out, odd, src, ft_xmm(dst));
        if (fields->id == dt_X86_INS_HADDPS) {
            FT_LA_VFADD_S_EMIT(&out, result, even, odd);
        } else {
            FT_LA_VFSUB_S_EMIT(&out, result, even, odd);
        }
        break;
    case dt_X86_INS_HADDPD:
    case dt_X86_INS_HSUBPD:
        if (fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
            return 0;
        }
        FT_LA_VPICKEV_D_EMIT(&out, even, src, ft_xmm(dst));
        FT_LA_VPICKOD_D_EMIT(&out, odd, src, ft_xmm(dst));
        if (fields->id == dt_X86_INS_HADDPD) {
            FT_LA_VFADD_D_EMIT(&out, result, even, odd);
        } else {
            FT_LA_VFSUB_D_EMIT(&out, result, even, odd);
        }
        break;
    default:
        return 0;
    }

    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    if (fpe) {
        FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), result, result);
    }

    return (out - code);
}

static int ft_emit_movdup_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM) {
        return 0;
    }
    if (!ft_emit_xmmm_src_bytes(&out, fields, pc,
                                fields->id == dt_X86_INS_MOVDDUP ? 8 : 16,
                                &src)) {
        return 0;
    }

    switch (fields->id) {
    case dt_X86_INS_MOVDDUP:
        if (fields->prefix0 != 0xf2) {
            return 0;
        }
        FT_LA_VREPLVEI_D_EMIT(&out, ft_xmm(dst), src, 0);
        break;
    case dt_X86_INS_MOVSLDUP:
        if (fields->prefix0 != 0xf3) {
            return 0;
        }
        FT_LA_VPACKEV_W_EMIT(&out, ft_xmm(dst), src, src);
        break;
    case dt_X86_INS_MOVSHDUP:
        if (fields->prefix0 != 0xf3) {
            return 0;
        }
        FT_LA_VPACKOD_W_EMIT(&out, ft_xmm(dst), src, src);
        break;
    default:
        return 0;
    }

    return (out - code);
}

static int ft_emit_psadbw_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_PSADBW) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }

    FT_LA_VABSD_BU_EMIT(&out, ft_xmm(dst), ft_xmm(dst), src);
    FT_LA_VHADDW_HU_BU_EMIT(&out, ft_xmm(dst), ft_xmm(dst), ft_xmm(dst));
    FT_LA_VHADDW_WU_HU_EMIT(&out, ft_xmm(dst), ft_xmm(dst), ft_xmm(dst));
    FT_LA_VHADDW_DU_WU_EMIT(&out, ft_xmm(dst), ft_xmm(dst), ft_xmm(dst));
    return (out - code);
}

static int ft_emit_mpsadbw_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int temp1 = ft_vscratch + 1;
    int temp2 = ft_vscratch + 2;
    int temp3 = ft_vscratch + 3;
    int imm = fields->imm & 0xff;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_MPSADBW) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }

    FT_LA_VREPLVEI_W_EMIT(&out, temp1, src, imm & 3);
    FT_LA_VMEPATMSK_V_EMIT(&out, temp2, 1, imm & 0x4);
    FT_LA_VMEPATMSK_V_EMIT(&out, temp3, 2, imm & 0x4);
    FT_LA_VSHUF_B_EMIT(&out, temp2, ft_xmm(dst), ft_xmm(dst), temp2);
    FT_LA_VSHUF_B_EMIT(&out, temp3, ft_xmm(dst), ft_xmm(dst), temp3);
    FT_LA_VABSD_BU_EMIT(&out, temp2, temp2, temp1);
    FT_LA_VABSD_BU_EMIT(&out, temp3, temp3, temp1);
    FT_LA_VHADDW_HU_BU_EMIT(&out, temp2, temp2, temp2);
    FT_LA_VHADDW_WU_HU_EMIT(&out, temp2, temp2, temp2);
    FT_LA_VHADDW_HU_BU_EMIT(&out, temp3, temp3, temp3);
    FT_LA_VHADDW_WU_HU_EMIT(&out, ft_xmm(dst), temp3, temp3);
    FT_LA_VSRLNI_H_W_EMIT(&out, ft_xmm(dst), temp2, 0);
    return (out - code);
}

static int ft_pmovx_src_bytes(int id)
{
    switch (id) {
    case dt_X86_INS_PMOVSXBQ:
    case dt_X86_INS_VPMOVSXBQ:
    case dt_X86_INS_PMOVZXBQ:
    case dt_X86_INS_VPMOVZXBQ:
        return 2;
    case dt_X86_INS_PMOVSXBD:
    case dt_X86_INS_VPMOVSXBD:
    case dt_X86_INS_PMOVZXBD:
    case dt_X86_INS_VPMOVZXBD:
    case dt_X86_INS_PMOVSXWQ:
    case dt_X86_INS_PMOVZXWQ:
        return 4;
    case dt_X86_INS_PMOVSXBW:
    case dt_X86_INS_PMOVZXBW:
    case dt_X86_INS_PMOVSXWD:
    case dt_X86_INS_PMOVZXWD:
    case dt_X86_INS_PMOVSXDQ:
    case dt_X86_INS_PMOVZXDQ:
        return 8;
    default:
        return 0;
    }
}

static bool ft_pmovx_is_vex(int id)
{
    return id == dt_X86_INS_VPMOVSXBD ||
           id == dt_X86_INS_VPMOVSXBQ ||
           id == dt_X86_INS_VPMOVZXBD ||
           id == dt_X86_INS_VPMOVZXBQ;
}

static int ft_emit_pmovx_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int bytes = ft_pmovx_src_bytes(fields->id);

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || bytes == 0) {
        return 0;
    }
    if (!ft_pmovx_is_vex(fields->id) &&
        fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
        return 0;
    }
    if (!ft_emit_xmmm_src_bytes(&out, fields, pc, bytes, &src)) {
        return 0;
    }

#if (defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)) || \
    (defined(QUICKTRANS_LATU) && !defined(CONFIG_LATX_AVX_OPT))
    /* LATU without guest AVX keeps only the architectural low 128 bits.
     * option_enable_lasx is gated by the host startup capability check. */
    if (option_enable_lasx) {
        switch (fields->id) {
        case dt_X86_INS_PMOVSXBD:
            FT_LA_VEXT2XV_W_B_EMIT(&out, ft_xmm(dst), src);
            return (out - code);
        case dt_X86_INS_PMOVZXBD:
            FT_LA_VEXT2XV_WU_BU_EMIT(&out, ft_xmm(dst), src);
            return (out - code);
        case dt_X86_INS_PMOVSXBQ:
            FT_LA_VEXT2XV_D_B_EMIT(&out, ft_xmm(dst), src);
            return (out - code);
        case dt_X86_INS_PMOVZXBQ:
            FT_LA_VEXT2XV_DU_BU_EMIT(&out, ft_xmm(dst), src);
            return (out - code);
        case dt_X86_INS_PMOVSXWQ:
            FT_LA_VEXT2XV_D_H_EMIT(&out, ft_xmm(dst), src);
            return (out - code);
        case dt_X86_INS_PMOVZXWQ:
            FT_LA_VEXT2XV_DU_HU_EMIT(&out, ft_xmm(dst), src);
            return (out - code);
        default:
            break;
        }
    }
#endif

    switch (fields->id) {
    case dt_X86_INS_PMOVSXBW:
        FT_LA_VSLLWIL_H_B_EMIT(&out, ft_xmm(dst), src, 0);
        break;
    case dt_X86_INS_PMOVZXBW:
        FT_LA_VSLLWIL_HU_BU_EMIT(&out, ft_xmm(dst), src, 0);
        break;
    case dt_X86_INS_PMOVSXBD:
    case dt_X86_INS_VPMOVSXBD:
        FT_LA_VSLLWIL_H_B_EMIT(&out, ft_xmm(dst), src, 0);
        FT_LA_VSLLWIL_W_H_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
        break;
    case dt_X86_INS_PMOVZXBD:
    case dt_X86_INS_VPMOVZXBD:
        FT_LA_VSLLWIL_HU_BU_EMIT(&out, ft_xmm(dst), src, 0);
        FT_LA_VSLLWIL_WU_HU_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
        break;
    case dt_X86_INS_PMOVSXBQ:
    case dt_X86_INS_VPMOVSXBQ:
        FT_LA_VSLLWIL_H_B_EMIT(&out, ft_xmm(dst), src, 0);
        FT_LA_VSLLWIL_W_H_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
        FT_LA_VSLLWIL_D_W_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
        break;
    case dt_X86_INS_PMOVZXBQ:
    case dt_X86_INS_VPMOVZXBQ:
        FT_LA_VSLLWIL_HU_BU_EMIT(&out, ft_xmm(dst), src, 0);
        FT_LA_VSLLWIL_WU_HU_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
        FT_LA_VSLLWIL_DU_WU_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
        break;
    case dt_X86_INS_PMOVSXWD:
        FT_LA_VSLLWIL_W_H_EMIT(&out, ft_xmm(dst), src, 0);
        break;
    case dt_X86_INS_PMOVZXWD:
        FT_LA_VSLLWIL_WU_HU_EMIT(&out, ft_xmm(dst), src, 0);
        break;
    case dt_X86_INS_PMOVSXWQ:
        FT_LA_VSLLWIL_W_H_EMIT(&out, ft_xmm(dst), src, 0);
        FT_LA_VSLLWIL_D_W_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
        break;
    case dt_X86_INS_PMOVZXWQ:
        FT_LA_VSLLWIL_WU_HU_EMIT(&out, ft_xmm(dst), src, 0);
        FT_LA_VSLLWIL_DU_WU_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
        break;
    case dt_X86_INS_PMOVSXDQ:
        FT_LA_VSLLWIL_D_W_EMIT(&out, ft_xmm(dst), src, 0);
        break;
    case dt_X86_INS_PMOVZXDQ:
        FT_LA_VSLLWIL_DU_WU_EMIT(&out, ft_xmm(dst), src, 0);
        break;
    default:
        return 0;
    }

    return (out - code);
}

static int ft_emit_ptest_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int temp = ft_vscratch + 1;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_PTEST) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }

    FT_LA_X86MTFLAG_EMIT(&out, la_zero, 0x3f);
    FT_LA_VAND_V_EMIT(&out, temp, src, ft_xmm(dst));
    FT_LA_VSETEQZ_V_EMIT(&out, 0, temp);
    FT_LA_BCEQZ_EMIT(&out, 0, 3);
    FT_LA_ORI_EMIT(&out, la_t4, la_zero, 0xfff);
    FT_LA_X86MTFLAG_EMIT(&out, la_t4, ZF_USEDEF_BIT);

    FT_LA_VANDN_V_EMIT(&out, temp, ft_xmm(dst), src);
    FT_LA_VSETEQZ_V_EMIT(&out, 0, temp);
    FT_LA_BCEQZ_EMIT(&out, 0, 3);
    FT_LA_ORI_EMIT(&out, la_t4, la_zero, 0xfff);
    FT_LA_X86MTFLAG_EMIT(&out, la_t4, CF_USEDEF_BIT);
    return (out - code);
}

static int ft_emit_insertps_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int imm = fields->imm & 0xff;
    int count_s = (imm >> 6) & 3;
    int count_d = (imm >> 4) & 3;
    int zmask = imm & 0xf;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_INSERTPS) {
        return 0;
    }
    if (!ft_emit_xmmm_src_bytes(&out, fields, pc, 4, &src)) {
        return 0;
    }
    if (fields->modrm_mod != 3) {
        count_s = 0;
    }

    FT_LA_VEXTRINS_W_EMIT(&out, ft_xmm(dst), src,
                          (count_d << 4) | count_s);
    if (zmask) {
        FT_LA_VXOR_V_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1,
                          ft_vscratch + 1);
    }
    for (int i = 0; i < 4; ++i) {
        if (zmask & (1 << i)) {
            FT_LA_VEXTRINS_W_EMIT(&out, ft_xmm(dst), ft_vscratch + 1,
                                  i << 4);
        }
    }
    return (out - code);
}

static int ft_emit_extractps_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int src = ft_modrm_reg_index(fields);
    int imm = fields->imm & 3;

    if (src >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_EXTRACTPS) {
        return 0;
    }

    if (fields->modrm_mod == 3) {
        int dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_LA_VPICKVE2GR_WU_EMIT(&out, ft_gpr(dst), ft_xmm(src), imm);
    } else {
        FT_LA_VPICKVE2GR_WU_EMIT(&out, la_t1, ft_xmm(src), imm);
        if (!ft_emit_store_rm32(&out, fields, pc, la_t1, false)) {
            return 0;
        }
    }
    return (out - code);
}

static int ft_emit_pshufw_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;

    (void)tb;

    if (dst >= 8 || fields->id != dt_X86_INS_PSHUFW) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VSHUF4I_H_EMIT(&out, ft_mmx(dst), src, fields->imm & 0xff);
    return (out - code);
}

static int ft_emit_pshift_mmx_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_rm_index(fields);
    int ext = (fields->modrm >> 3) & 7;
    int imm = fields->imm & 0xff;
    int max_count;
    uint32_t opcode;

    (void)tb;
    (void)pc;

    if (fields->prefix0 != 0 || fields->prefix2 != 0 ||
        fields->modrm_mod != 3 || dst >= 8) {
        return 0;
    }
    if (fields->opcode1 == 0x71) {
        max_count = 15;
        if (ext == 2 && fields->id == dt_X86_INS_PSRLW) {
            opcode = FT_LA_OPCODE_VSRLI_H;
        } else if (ext == 4 && fields->id == dt_X86_INS_PSRAW) {
            opcode = FT_LA_OPCODE_VSRAI_H;
        } else if (ext == 6 && fields->id == dt_X86_INS_PSLLW) {
            opcode = FT_LA_OPCODE_VSLLI_H;
        } else {
            return 0;
        }
    } else if (fields->opcode1 == 0x72) {
        max_count = 31;
        if (ext == 2 && fields->id == dt_X86_INS_PSRLD) {
            opcode = FT_LA_OPCODE_VSRLI_W;
        } else if (ext == 4 && fields->id == dt_X86_INS_PSRAD) {
            opcode = FT_LA_OPCODE_VSRAI_W;
        } else if (ext == 6 && fields->id == dt_X86_INS_PSLLD) {
            opcode = FT_LA_OPCODE_VSLLI_W;
        } else {
            return 0;
        }
    } else if (fields->opcode1 == 0x73) {
        max_count = 63;
        if (ext == 2 && fields->id == dt_X86_INS_PSRLQ) {
            opcode = FT_LA_OPCODE_VSRLI_D;
        } else if (ext == 6 && fields->id == dt_X86_INS_PSLLQ) {
            opcode = FT_LA_OPCODE_VSLLI_D;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
    if (imm > max_count) {
        if (ext == 4) {
            imm = max_count;
        } else {
            FT_LA_VXOR_V_EMIT(&out, ft_mmx(dst), ft_mmx(dst), ft_mmx(dst));
            return out - code;
        }
    }
    ft_emit_raw(&out, opcode | ft_mmx(dst) | (ft_mmx(dst) << 5) |
                ((uint32_t)imm << 10));
    return out - code;
}

static int ft_emit_psub_mmx_template(const FastTemplateFields *fields,
                                     TranslationBlock *tb,
                                     target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->prefix0 != 0 || fields->prefix2 != 0 || dst >= 8 ||
        (fields->id != dt_X86_INS_PSUBB &&
         fields->id != dt_X86_INS_PSUBW &&
         fields->id != dt_X86_INS_PSUBD &&
         fields->id != dt_X86_INS_PSUBQ)) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    switch (fields->id) {
    case dt_X86_INS_PSUBB:
        FT_LA_VSUB_B_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
        break;
    case dt_X86_INS_PSUBW:
        FT_LA_VSUB_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
        break;
    case dt_X86_INS_PSUBD:
        FT_LA_VSUB_W_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
        break;
    default:
        FT_LA_VSUB_D_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
        break;
    }
    return out - code;
}

static int ft_emit_psubs_mmx_template(const FastTemplateFields *fields,
                                      TranslationBlock *tb,
                                      target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;

    if (fields->prefix0 != 0 || fields->prefix2 != 0 || dst >= 8 ||
        (fields->id != dt_X86_INS_PSUBSB &&
         fields->id != dt_X86_INS_PSUBSW)) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = ft_modrm_rm_index(fields);
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    if (fields->id == dt_X86_INS_PSUBSB) {
        FT_LA_VSSUB_B_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    } else {
        FT_LA_VSSUB_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    }
    return out - code;
}

static int ft_emit_psubusb_mmx_template(const FastTemplateFields *fields,
                                        TranslationBlock *tb,
                                        target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PSUBUSB || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VSSUB_BU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_psubusw_mmx_template(const FastTemplateFields *fields,
                                        TranslationBlock *tb,
                                        target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PSUBUSW || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VSSUB_HU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_paddus_mmx_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PADDUSB &&
        fields->id != dt_X86_INS_PADDUSW &&
        fields->id != dt_X86_INS_PADDSB &&
        fields->id != dt_X86_INS_PADDSW) {
        return 0;
    }
    if (fields->prefix0 != 0 || fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    if (fields->id == dt_X86_INS_PADDUSB) {
        FT_LA_VSADD_BU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    } else if (fields->id == dt_X86_INS_PADDUSW) {
        FT_LA_VSADD_HU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    } else if (fields->id == dt_X86_INS_PADDSB) {
        FT_LA_VSADD_B_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    } else {
        FT_LA_VSADD_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    }
    return (out - code);
}

static int ft_emit_pavg_mmx_template(const FastTemplateFields *fields,
                                     TranslationBlock *tb,
                                     target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if ((fields->id != dt_X86_INS_PAVGB &&
         fields->id != dt_X86_INS_PAVGW) || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    if (fields->id == dt_X86_INS_PAVGB) {
        FT_LA_VAVGR_BU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    } else {
        FT_LA_VAVGR_HU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    }
    return (out - code);
}

static int ft_emit_pand_mmx_template(const FastTemplateFields *fields,
                                     TranslationBlock *tb,
                                     target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;
    bool is_pandn = fields->id == dt_X86_INS_PANDN;

    (void)tb;
    (void)pc;

    if ((fields->id != dt_X86_INS_PAND && !is_pandn) || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    if (is_pandn) {
        FT_LA_VANDN_V_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    } else {
        FT_LA_VAND_V_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    }
    return (out - code);
}

static int ft_emit_por_mmx_template(const FastTemplateFields *fields,
                                    TranslationBlock *tb,
                                    target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_POR || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VOR_V_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_pxor_mmx_template(const FastTemplateFields *fields,
                                     TranslationBlock *tb,
                                     target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PXOR || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VXOR_V_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_psadbw_mmx_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PSADBW || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VABSD_BU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    FT_LA_VHADDW_HU_BU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), ft_mmx(dst));
    FT_LA_VHADDW_WU_HU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), ft_mmx(dst));
    FT_LA_VHADDW_DU_WU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), ft_mmx(dst));
    return (out - code);
}

static int ft_emit_pcmpgt_mmx_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PCMPGTB &&
        fields->id != dt_X86_INS_PCMPGTW &&
        fields->id != dt_X86_INS_PCMPGTD) {
        return 0;
    }
    if (fields->prefix0 != 0 || fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    switch (fields->id) {
    case dt_X86_INS_PCMPGTB:
        FT_LA_VSLT_B_EMIT(&out, ft_mmx(dst), src, ft_mmx(dst));
        break;
    case dt_X86_INS_PCMPGTW:
        FT_LA_VSLT_H_EMIT(&out, ft_mmx(dst), src, ft_mmx(dst));
        break;
    case dt_X86_INS_PCMPGTD:
        FT_LA_VSLT_W_EMIT(&out, ft_mmx(dst), src, ft_mmx(dst));
        break;
    default:
        return 0;
    }
    return (out - code);
}

static int ft_emit_pcmpeq_mmx_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PCMPEQB &&
        fields->id != dt_X86_INS_PCMPEQW &&
        fields->id != dt_X86_INS_PCMPEQD) {
        return 0;
    }
    if (fields->prefix0 != 0 || fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    switch (fields->id) {
    case dt_X86_INS_PCMPEQB:
        FT_LA_VSEQ_B_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
        break;
    case dt_X86_INS_PCMPEQW:
        FT_LA_VSEQ_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
        break;
    case dt_X86_INS_PCMPEQD:
        FT_LA_VSEQ_W_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
        break;
    default:
        return 0;
    }
    return (out - code);
}

static int ft_emit_pmullw_mmx_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PMULLW || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VMUL_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_pmulh_mmx_template(const FastTemplateFields *fields,
                                      TranslationBlock *tb,
                                      target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;
    bool is_unsigned = fields->kind == FT_PMULHUW_MMX_MMXM64;

    (void)tb;
    (void)pc;

    if (fields->id != (is_unsigned ? dt_X86_INS_PMULHUW :
                                     dt_X86_INS_PMULHW) ||
        fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    if (is_unsigned) {
        FT_LA_VMUH_HU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    } else {
        FT_LA_VMUH_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    }
    return (out - code);
}

static int ft_emit_psra_mmx_template(const FastTemplateFields *fields,
                                     TranslationBlock *tb,
                                     target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;
    /* Preserve a memory source in scratch until count replication. */
    int valid_count = ft_vscratch + 3;
    int count = ft_vscratch + 1;
    int sign = ft_vscratch + 2;
    bool is_psrad = fields->id == dt_X86_INS_PSRAD;

    (void)tb;
    (void)pc;

    if ((fields->id != dt_X86_INS_PSRAW && !is_psrad) ||
        fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VREPLVEI_D_EMIT(&out, valid_count, src, 0);
    FT_LA_VSLEI_DU_EMIT(&out, valid_count, valid_count,
                        is_psrad ? 31 : 15);
    if (is_psrad) {
        FT_LA_VREPLVEI_W_EMIT(&out, count, src, 0);
        FT_LA_VSRAI_W_EMIT(&out, sign, ft_mmx(dst), 31);
        FT_LA_VSRA_W_EMIT(&out, ft_mmx(dst), ft_mmx(dst), count);
    } else {
        FT_LA_VREPLVEI_H_EMIT(&out, count, src, 0);
        FT_LA_VSRAI_H_EMIT(&out, sign, ft_mmx(dst), 15);
        FT_LA_VSRA_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), count);
    }
    FT_LA_VBITSEL_V_EMIT(&out, ft_mmx(dst), sign, ft_mmx(dst),
                         valid_count);
    return (out - code);
}

static int ft_emit_packsswb_mmx_template(const FastTemplateFields *fields,
                                         TranslationBlock *tb,
                                         target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PACKSSWB || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VPACKEV_D_EMIT(&out, ft_mmx(dst), src, ft_mmx(dst));
    FT_LA_VSAT_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), 7);
    FT_LA_VPICKEV_B_EMIT(&out, ft_mmx(dst), ft_mmx(dst), ft_mmx(dst));
    return (out - code);
}

static int ft_emit_packssdw_mmx_template(const FastTemplateFields *fields,
                                         TranslationBlock *tb,
                                         target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PACKSSDW || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VPACKEV_D_EMIT(&out, ft_mmx(dst), src, ft_mmx(dst));
    FT_LA_VSSRANI_H_W_EMIT(&out, ft_mmx(dst), ft_mmx(dst), 0);
    return (out - code);
}

static int ft_emit_packuswb_mmx_template(const FastTemplateFields *fields,
                                         TranslationBlock *tb,
                                         target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PACKUSWB || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VPACKEV_D_EMIT(&out, ft_mmx(dst), src, ft_mmx(dst));
    FT_LA_VSSRANI_BU_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), 0);
    return (out - code);
}

static int ft_emit_pmaddwd_mmx_template(const FastTemplateFields *fields,
                                        TranslationBlock *tb,
                                        target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PMADDWD || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VXOR_V_EMIT(&out, ft_vscratch + 1, ft_vscratch + 1,
                      ft_vscratch + 1);
    FT_LA_VMADDWEV_W_H_EMIT(&out, ft_vscratch + 1, ft_mmx(dst), src);
    FT_LA_VMADDWOD_W_H_EMIT(&out, ft_vscratch + 1, ft_mmx(dst), src);
    FT_LA_VBSLL_V_EMIT(&out, ft_mmx(dst), ft_vscratch + 1, 0);
    return (out - code);
}

static int ft_emit_pmuludq_mmx_template(const FastTemplateFields *fields,
                                        TranslationBlock *tb,
                                        target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;

    if (fields->id != dt_X86_INS_PMULUDQ || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VMULWEV_D_WU_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_pmaxsw_mmx_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PMAXSW || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VMAX_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_pminsw_mmx_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PMINSW || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VMIN_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_padd_mmx_template(const FastTemplateFields *fields,
                                     TranslationBlock *tb,
                                     target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;
    bool is_paddb = fields->id == dt_X86_INS_PADDB;
    bool is_paddq = fields->id == dt_X86_INS_PADDQ;

    (void)tb;
    (void)pc;

    if ((fields->id != dt_X86_INS_PADDD && !is_paddb && !is_paddq) ||
        fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    if (is_paddb) {
        FT_LA_VADD_B_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    } else if (is_paddq) {
        FT_LA_VADD_D_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    } else {
        FT_LA_VADD_W_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    }
    return (out - code);
}

static int ft_emit_paddw_mmx_template(const FastTemplateFields *fields,
                                      TranslationBlock *tb,
                                      target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_PADDW || fields->prefix0 != 0 ||
        fields->prefix2 != 0 || dst >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        src = fields->modrm_rm;
        if (src >= 8) {
            return 0;
        }
        src = ft_mmx(src);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_VADD_H_EMIT(&out, ft_mmx(dst), ft_mmx(dst), src);
    return (out - code);
}

static int ft_emit_movdq2q_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->modrm_reg;
    int src = ft_modrm_rm_index(fields);

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_MOVDQ2Q ||
        fields->modrm_mod != 3 ||
        dst >= 8 || src >= XMM_NUM) {
        return 0;
    }
    FT_LA_FMOV_D_EMIT(&out, ft_mmx(dst), ft_xmm(src));
    return (out - code);
}

static int ft_emit_movq2dq_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src = fields->modrm_rm;

    (void)tb;
    (void)pc;

    if (fields->id != dt_X86_INS_MOVQ2DQ ||
        fields->modrm_mod != 3 ||
        dst >= XMM_NUM || src >= 8) {
        return 0;
    }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_LATX_AVX_OPT)
    if (option_enable_lasx) {
        FT_LA_XVPICKVE_D_EMIT(&out, ft_xmm(dst), ft_mmx(src), 0);
        return out - code;
    }
#endif
    FT_LA_VANDI_B_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
    FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_mmx(src), 0);
    return (out - code);
}

static int ft_emit_movq_rm64_mmx_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int src = ft_modrm_reg_index(fields);

    (void)tb;

    if (fields->id != dt_X86_INS_MOVQ || !ft_rex_w(fields) || src >= 8) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        int dst = ft_modrm_rm_index(fields);

        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_LA_MOVFR2GR_D_EMIT(&out, ft_gpr(dst), ft_mmx(src));
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_FST_D_EMIT(&out, ft_mmx(src), addr,
                         ft_mem_access_offset(fields, addr));
    }
    return (out - code);
}

static int ft_emit_movq_mmxm64_mmx_template(const FastTemplateFields *fields,
                                            TranslationBlock *tb,
                                            target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int src = ft_modrm_reg_index(fields);

    (void)tb;

    if ((fields->id != dt_X86_INS_MOVQ &&
         fields->id != dt_X86_INS_MOVNTQ) ||
        src >= 8 ||
        (fields->id == dt_X86_INS_MOVNTQ && fields->modrm_mod == 3)) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        int dst = ft_modrm_rm_index(fields);

        if (dst >= 8) {
            return 0;
        }
        FT_LA_FMOV_D_EMIT(&out, ft_mmx(dst), ft_mmx(src));
    } else {
        int addr;

        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_FST_D_EMIT(&out, ft_mmx(src), addr,
                         ft_mem_access_offset(fields, addr));
    }
    return (out - code);
}

static int ft_emit_phminposuw_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int temp = ft_vscratch + 1;
    int temp1 = ft_vscratch + 2;
    int temp2 = ft_vscratch + 3;

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_LATX_AVX_OPT)
    /* No guest YMM state in this configuration; startup gates host LASX. */
    bool lasx = option_enable_lasx;
#else
    bool lasx = false;
#endif

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_PHMINPOSUW) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }

    FT_LA_VSRLI_D_EMIT(&out, temp, src, 0x10);
    FT_LA_VMIN_HU_EMIT(&out, temp, temp, src);
    FT_LA_VSRLI_D_EMIT(&out, temp, temp, 0x10);
    FT_LA_VMIN_HU_EMIT(&out, temp, temp, src);
    FT_LA_VSRLI_D_EMIT(&out, temp, temp, 0x10);
    FT_LA_VMIN_HU_EMIT(&out, temp, temp, src);
    if (lasx) {
        FT_LA_XVPICKVE_D_EMIT(&out, temp2, temp, 1);
    } else {
        FT_LA_VANDI_B_EMIT(&out, temp2, temp2, 0);
        FT_LA_VEXTRINS_D_EMIT(&out, temp2, temp, 1);
    }
    FT_LA_VMIN_HU_EMIT(&out, temp, temp, temp2);
    if (lasx) {
        FT_LA_XVREPLVE0_H_EMIT(&out, temp, temp);
    } else {
        FT_LA_VREPLVEI_H_EMIT(&out, temp, temp, 0);
    }
    FT_LA_VSEQ_H_EMIT(&out, temp1, src, temp);
    FT_LA_VFRSTPI_H_EMIT(&out, temp2, temp1, 0);
    FT_LA_VPACKEV_H_EMIT(&out, ft_xmm(dst), temp2, temp);
    if (lasx) {
        FT_LA_XVPICKVE_W_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
    } else {
        FT_LA_VINSGR2VR_D_EMIT(&out, ft_xmm(dst), la_zero, 1);
        FT_LA_VINSGR2VR_W_EMIT(&out, ft_xmm(dst), la_zero, 1);
    }
    return (out - code);
}

static int ft_emit_cvtdq2pd_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src = ft_modrm_rm_index(fields);
    bool fpe = ft_lats_simd_fpe_enabled(tb);
    int result;

    if (fields->prefix0 != 0xf3 || fields->modrm_mod != 3 ||
        dst >= XMM_NUM || src >= XMM_NUM) {
        return 0;
    }
    result = fpe ? ft_vscratch : ft_xmm(dst);
    FT_LA_VFFINTL_D_W_EMIT(&out, result, ft_xmm(src));
    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    if (fpe) {
        FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), result, result);
    }
    return (out - code);
}

static int ft_emit_cvtpi2pd_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;

    if (fields->prefix2 != dt_X86_PREFIX_OPSIZE || ft_rex_w(fields) ||
        dst >= XMM_NUM) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        int rm = ft_modrm_rm_index(fields);

        if (rm >= 8) {
            return 0;
        }
        src = ft_mmx(rm);
    } else {
        int addr;

        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

    FT_LA_FFINT_D_W_EMIT(&out, ft_vscratch + 1, src);
    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    FT_LA_VSHUF4I_W_EMIT(&out, ft_vscratch, src, 0x55);
    FT_LA_FFINT_D_W_EMIT(&out, ft_vscratch, ft_vscratch);
    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch + 1, 0);
    FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0x10);
    return (out - code);
}

static int ft_emit_cvtsi2sx_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    bool is_double = fields->kind == FT_CVTSI2SD_XMM_RM;
    bool is_64 = ft_rex_w(fields);

    if (fields->prefix0 != (is_double ? 0xf2 : 0xf3) || dst >= XMM_NUM) {
        return 0;
    }
    if (is_64) {
        if (!ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
    } else if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
        return 0;
    }

    FT_LA_MOVGR2FR_D_EMIT(&out, ft_vscratch, src);
    if (is_double) {
        if (is_64) {
            FT_LA_FFINT_D_L_EMIT(&out, ft_vscratch, ft_vscratch);
        } else {
            FT_LA_FFINT_D_W_EMIT(&out, ft_vscratch, ft_vscratch);
        }
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
    } else {
        if (is_64) {
            FT_LA_FFINT_S_L_EMIT(&out, ft_vscratch, ft_vscratch);
        } else {
            FT_LA_FFINT_S_W_EMIT(&out, ft_vscratch, ft_vscratch);
        }
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        FT_LA_VEXTRINS_W_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
    }
    return (out - code);
}

static bool ft_emit_cvtsx2si_convert(uint32_t **out, bool is_double,
                                     bool is_64, bool trunc, int src, int result)
{
    if (is_double) {
        if (is_64) {
            if (trunc) {
                FT_LA_FTINTRZ_L_D_EMIT(out, result, src);
            } else {
                FT_LA_FTINT_L_D_EMIT(out, result, src);
            }
        } else if (trunc) {
            FT_LA_FTINTRZ_W_D_EMIT(out, result, src);
        } else {
            FT_LA_FTINT_W_D_EMIT(out, result, src);
        }
    } else if (is_64) {
        if (trunc) {
            FT_LA_FTINTRZ_L_S_EMIT(out, result, src);
        } else {
            FT_LA_FTINT_L_S_EMIT(out, result, src);
        }
    } else if (trunc) {
        FT_LA_FTINTRZ_W_S_EMIT(out, result, src);
    } else {
        FT_LA_FTINT_W_S_EMIT(out, result, src);
    }
    return true;
}

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
static void ft_emit_cvtsx2si_optimized(uint32_t **out, int src, int dst,
                                      bool is_double, bool is_64, bool trunc)
{
    int result = ft_vscratch + 2;
    int limit = ft_vscratch + 1;

    /* Preserve memory-loaded src in ft_vscratch until after comparison. */
    ft_emit_cvtsx2si_convert(out, is_double, is_64, trunc, src, result);
    if (is_double && !is_64 && !trunc) {
        FastBranchLabel down_zero = { 0 }, upward = { 0 }, ready = { 0 };
        FastBranchFixup down_fix, up_fix, nearest_fix, upward_fix;
        ft_emit_load_env(out, la_t1, lsenv_offset_of_mxcsr(lsenv),
                         FT_LA_OPCODE_LD_WU);
        FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t1, 13, 13);
        ft_emit_branch_placeholder(out, &down_fix, FT_BRANCH_BNE,
                                   la_t2, la_zero, &down_zero);
        FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t1, 14, 14);
        ft_emit_branch_placeholder(out, &up_fix, FT_BRANCH_BNE,
                                   la_t2, la_zero, &upward);
        ft_emit_li64(out, la_t0, 0x41dfffffffe00000ULL);
        ft_emit_branch_placeholder(out, &nearest_fix, FT_BRANCH_BEQ,
                                   la_zero, la_zero, &ready);
        ft_bind_branch_label(&upward, *out);
        ft_emit_li64(out, la_t0, 0x41dfffffffc00001ULL);
        ft_emit_branch_placeholder(out, &upward_fix, FT_BRANCH_BEQ,
                                   la_zero, la_zero, &ready);
        ft_bind_branch_label(&down_zero, *out);
        ft_emit_li64(out, la_t0, 0x41e0000000000000ULL);
        ft_bind_branch_label(&ready, *out);
        ft_resolve_branch_fixup(&down_fix);
        ft_resolve_branch_fixup(&up_fix);
        ft_resolve_branch_fixup(&nearest_fix);
        ft_resolve_branch_fixup(&upward_fix);
    } else {
        ft_emit_li64(out, la_t0, is_double ?
                     (is_64 ? 0x43e0000000000000ULL : 0x41e0000000000000ULL) :
                     (is_64 ? 0x5f000000 : 0x4f000000));
    }
    if (is_double) {
        FT_LA_MOVGR2FR_D_EMIT(out, limit, la_t0);
        FT_LA_FCMP_COND_D_EMIT(out, 0, limit, src, 0x0e);
    } else {
        FT_LA_MOVGR2FR_W_EMIT(out, limit, la_t0);
        FT_LA_FCMP_COND_S_EMIT(out, 0, limit, src, 0x0e);
    }
    FT_LA_MOVCF2GR_EMIT(out, la_t0, 0);
    FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, is_64 ? 63 : 31);
    FT_LA_MOVFR2GR_D_EMIT(out, dst, result);
    FT_LA_MASKNEZ_EMIT(out, dst, dst, la_t0);
    FT_LA_OR_EMIT(out, dst, dst, la_t0);
    if (!is_64) {
        FT_LA_BSTRPICK_D_EMIT(out, dst, dst, 31, 0);
    }
}
#endif

static int ft_emit_cvtsx2si_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    bool is_64 = ft_rex_w(fields);
    bool is_double = fields->kind == FT_CVTTSD2SI_GPR_XMMM ||
                     fields->kind == FT_CVTSD2SI_GPR_XMMM;
    bool trunc = fields->kind == FT_CVTTSS2SI_GPR_XMMM ||
                 fields->kind == FT_CVTTSD2SI_GPR_XMMM;

    if (fields->prefix0 != (is_double ? 0xf2 : 0xf3) || dst >= GPR_NUM) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        int rm = ft_modrm_rm_index(fields);

        if (rm >= XMM_NUM) {
            return 0;
        }
        src = ft_xmm(rm);
    } else {
        int addr;

        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        if (is_double) {
            FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                             ft_mem_access_offset(fields, addr));
        } else {
            FT_LA_FLD_S_EMIT(&out, ft_vscratch, addr,
                             ft_mem_access_offset(fields, addr));
        }
        src = ft_vscratch;
    }

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (option_cvt_opt) {
        ft_emit_cvtsx2si_optimized(&out, src, ft_gpr(dst), is_double, is_64, trunc);
        return out - code;
    }
    if (!trunc && !option_set_rounding_opt) {
        /* Old unoptimized CVT temporarily uses MXCSR rounding. */
        FT_LA_MOVFCSR2GR_EMIT(&out, la_t3, 3);
        ft_emit_load_env(&out, la_t1, lsenv_offset_of_mxcsr(lsenv),
                         FT_LA_OPCODE_LD_WU);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, la_t1, 14, 13);
        FT_LA_ANDI_EMIT(&out, la_t2, la_t1, 1);
        FT_LA_SLLI_D_EMIT(&out, la_t2, la_t2, 1);
        FT_LA_XOR_EMIT(&out, la_t1, la_t1, la_t2);
        FT_LA_OR_EMIT(&out, la_t0, la_t3, la_zero);
        FT_LA_BSTRINS_W_EMIT(&out, la_t0, la_t1, 9, 8);
        FT_LA_MOVGR2FCSR_EMIT(&out, 3, la_t0);
    }
#endif
    ft_emit_cvtsx2si_convert(&out, is_double, is_64, trunc, src, ft_vscratch);
    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    if (ft_fast_masked_v_enabled()) {
        /* LATS handles invalid conversions in its masked-V exception path. */
        FT_LA_MOVFR2GR_D_EMIT(&out, ft_gpr(dst), ft_vscratch);
    } else {
        FT_LA_MOVFCSR2GR_EMIT(&out, la_t0, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, la_t0, 28, 28);
        FT_LA_SLLI_D_EMIT(&out, la_t1, la_t0, is_64 ? 63 : 31);
        FT_LA_MOVFR2GR_D_EMIT(&out, ft_gpr(dst), ft_vscratch);
        FT_LA_MASKNEZ_EMIT(&out, la_t0, ft_gpr(dst), la_t0);
        FT_LA_OR_EMIT(&out, ft_gpr(dst), la_t1, la_t0);
    }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (!trunc && !option_set_rounding_opt) {
        FT_LA_MOVGR2FCSR_EMIT(&out, 3, la_t3);
    }
#endif
    if (!is_64) {
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }
    return (out - code);
}

static int ft_emit_cvt_fp_xmm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    bool fpe = ft_lats_simd_fpe_enabled(tb);
    int result;

    if (dst >= XMM_NUM) {
        return 0;
    }
    result = fpe ? ft_vscratch + 1 : ft_xmm(dst);

    switch (fields->id) {
    case dt_X86_INS_CVTDQ2PD:
        if (fields->prefix0 != 0xf3 ||
            !ft_emit_xmmm_src_bytes(&out, fields, pc, 8, &src)) {
            return 0;
        }
        FT_LA_VFFINTL_D_W_EMIT(&out, result, src);
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        if (fpe) {
            FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), result, result);
        }
        break;
    case dt_X86_INS_CVTDQ2PS:
        if (fields->prefix0 != 0 || fields->prefix2 != 0 ||
            !ft_emit_xmmm_src(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_VFFINT_S_W_EMIT(&out, result, src);
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        if (fpe) {
            FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), result, result);
        }
        break;
    case dt_X86_INS_CVTPD2PS:
        if (fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
            !ft_emit_xmmm_src(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_VFCVT_S_D_EMIT(&out, result, src, src);
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        FT_LA_VINSGR2VR_D_EMIT(&out, result, la_zero, 1);
        if (fpe) {
            FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), result, result);
        }
        break;
    case dt_X86_INS_CVTPS2PD:
        if (fields->prefix0 != 0 || fields->prefix2 != 0 ||
            !ft_emit_xmmm_src_bytes(&out, fields, pc, 8, &src)) {
            return 0;
        }
        FT_LA_FCVT_D_S_EMIT(&out, ft_vscratch + 1, src);
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        FT_LA_VSHUF4I_W_EMIT(&out, ft_vscratch, src, 0x55);
        FT_LA_FCVT_D_S_EMIT(&out, ft_vscratch, ft_vscratch);
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch + 1, 0);
        FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0x10);
        break;
    case dt_X86_INS_CVTSD2SS:
        if (fields->prefix0 != 0xf2 ||
            !ft_emit_xmmm_src_bytes(&out, fields, pc, 8, &src)) {
            return 0;
        }
        FT_LA_FCVT_S_D_EMIT(&out, ft_vscratch, src);
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        FT_LA_VEXTRINS_W_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
        break;
    case dt_X86_INS_CVTSS2SD:
        if (fields->prefix0 != 0xf3 ||
            !ft_emit_xmmm_src_bytes(&out, fields, pc, 4, &src)) {
            return 0;
        }
        FT_LA_FCVT_D_S_EMIT(&out, ft_vscratch, src);
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
        break;
    default:
        return 0;
    }
    return (out - code);
}

static void ft_emit_cvt_fp2i_fix_invalid(uint32_t **out, int temp, int src,
                                         bool is_double, bool trunc)
{
    int invalid = ft_vscratch + 2;
    int overflow = ft_vscratch + 3;
    int mask = ft_vscratch + 4;

    FT_LA_VLDI_EMIT(out, invalid, 0x1380);
    if (is_double) {
#ifdef QUICKTRANS_LATU
        if (!trunc) {
            FastBranchLabel down_zero = { 0 }, upward = { 0 }, ready = { 0 };
            FastBranchFixup down_fix, up_fix, nearest_fix, upward_fix;

            /* Match legacy's rounding-dependent positive overflow bound. */
            ft_emit_load_env(out, la_t1, lsenv_offset_of_mxcsr(lsenv),
                             FT_LA_OPCODE_LD_WU);
            FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t1, 13, 13);
            ft_emit_branch_placeholder(out, &down_fix, FT_BRANCH_BNE,
                                       la_t2, la_zero, &down_zero);
            FT_LA_BSTRPICK_D_EMIT(out, la_t2, la_t1, 14, 14);
            ft_emit_branch_placeholder(out, &up_fix, FT_BRANCH_BNE,
                                       la_t2, la_zero, &upward);
            ft_emit_li64(out, la_t0, 0x41dfffffffe00000ULL);
            ft_emit_branch_placeholder(out, &nearest_fix, FT_BRANCH_BEQ,
                                       la_zero, la_zero, &ready);
            ft_bind_branch_label(&upward, *out);
            ft_emit_li64(out, la_t0, 0x41dfffffffc00001ULL);
            ft_emit_branch_placeholder(out, &upward_fix, FT_BRANCH_BEQ,
                                       la_zero, la_zero, &ready);
            ft_bind_branch_label(&down_zero, *out);
            ft_emit_li64(out, la_t0, 0x41e0000000000000ULL);
            ft_bind_branch_label(&ready, *out);
            ft_resolve_branch_fixup(&down_fix);
            ft_resolve_branch_fixup(&up_fix);
            ft_resolve_branch_fixup(&nearest_fix);
            ft_resolve_branch_fixup(&upward_fix);
        } else
#endif
        {
            ft_emit_li64(out, la_t0,
                         trunc ? 0x41E0000000000000ULL :
                                 0x41dfffffffe00000ULL);
        }
        FT_LA_VREPLGR2VR_D_EMIT(out, overflow, la_t0);
        FT_LA_VFCMP_COND_D_EMIT(out, mask, overflow, src, 0x0e);
        FT_LA_VSHUF4I_W_EMIT(out, mask, mask, 0x88);
    } else {
        FT_LA_VLDI_EMIT(out, overflow, 0x134f);
        FT_LA_VFCMP_COND_S_EMIT(out, mask, overflow, src, 0x0e);
    }
    FT_LA_VBITSEL_V_EMIT(out, temp, temp, invalid, mask);
}

static void ft_emit_lats_simd_fpe_check_ex(uint32_t **out,
                                           TranslationBlock *tb,
                                           target_ulong pc,
                                           bool suppress_precision)
{
#if defined(CONFIG_SOFTMMU) && defined(HF_SIGFPE_ON_MASK)
    FastBranchLabel no_exception = { 0 };
    FastBranchLabel raise_exception = { 0 };
    FastBranchFixup no_exception_fixup;
    FastBranchFixup fast_masked_fixup;
    bool fast_masked = option_fast_masked_v;
    int mxcsr_offset = lsenv_offset_of_mxcsr(lsenv);

    if (!option_sigfpe || !tb || !(tb->flags & HF_SIGFPE_ON_MASK)) {
        return;
    }

    if (fast_masked) {
        ft_emit_load_env(out, la_t0, lsenv_offset_of_excp_divz(lsenv),
                         FT_LA_OPCODE_LD_WU);
        ft_emit_branch_placeholder(out, &fast_masked_fixup, FT_BRANCH_BNE,
                                   la_t0, la_zero, &raise_exception);
    }

    /*
     * FCSR2 cause bits 28:24 are V/Z/O/U/I.  Match them against the
     * corresponding unmasked MXCSR exceptions before committing a result.
     */
    ft_emit_load_env(out, la_t0, mxcsr_offset, FT_LA_OPCODE_LD_WU);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t0, 12, 12);
    FT_LA_BSTRPICK_D_EMIT(out, la_t3, la_t0, 11, 11);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_t3, 1, 1);
    FT_LA_BSTRPICK_D_EMIT(out, la_t3, la_t0, 10, 10);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_t3, 2, 2);
    FT_LA_BSTRPICK_D_EMIT(out, la_t3, la_t0, 9, 9);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_t3, 3, 3);
    FT_LA_BSTRPICK_D_EMIT(out, la_t3, la_t0, 7, 7);
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_t3, 4, 4);
    FT_LA_NOR_EMIT(out, la_t1, la_zero, la_t1);
    FT_LA_ANDI_EMIT(out, la_t1, la_t1, 0x1f);

    FT_LA_MOVFCSR2GR_EMIT(out, la_t2, 2);
    FT_LA_SRLI_W_EMIT(out, la_t2, la_t2, 24);
    FT_LA_ANDI_EMIT(out, la_t2, la_t2, 0x1f);
    if (suppress_precision) {
        FT_LA_ANDI_EMIT(out, la_t2, la_t2, 0x1e);
    }
    FT_LA_AND_EMIT(out, la_t3, la_t2, la_t1);
    ft_emit_branch_placeholder(out, &no_exception_fixup, FT_BRANCH_BEQ,
                               la_t3, la_zero, &no_exception);

    /* Copy the raised exception flags into MXCSR before delivering SIGFPE. */
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t2, 4, 4);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 0, 0);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t2, 3, 3);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 2, 2);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t2, 2, 2);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 3, 3);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t2, 1, 1);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 4, 4);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t2, 0, 0);
    FT_LA_BSTRINS_D_EMIT(out, la_t0, la_t1, 5, 5);
    ft_emit_store_env(out, la_t0, mxcsr_offset, FT_LA_OPCODE_ST_W);

    ft_bind_branch_label(&raise_exception, *out);
    if (fast_masked) {
        ft_resolve_branch_fixup(&fast_masked_fixup);
    }

    ft_emit_raise_exception(out, pc, EXCP00_DIVZ);

    ft_bind_branch_label(&no_exception, *out);
    ft_resolve_branch_fixup(&no_exception_fixup);
#else
    (void)out;
    (void)tb;
    (void)pc;
    (void)suppress_precision;
#endif
}

static bool ft_lats_simd_fpe_enabled(TranslationBlock *tb)
{
#if defined(CONFIG_SOFTMMU) && defined(HF_SIGFPE_ON_MASK)
    return option_sigfpe && tb && (tb->flags & HF_SIGFPE_ON_MASK);
#else
    (void)tb;
    return false;
#endif
}

static void ft_emit_lats_simd_fpe_check(uint32_t **out,
                                        TranslationBlock *tb,
                                        target_ulong pc)
{
    ft_emit_lats_simd_fpe_check_ex(out, tb, pc, false);
}

static int ft_emit_cvtpi2ps_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;

    if (fields->prefix0 != 0 || fields->prefix2 != 0 ||
        ft_rex_w(fields) || dst >= XMM_NUM) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        int rm = ft_modrm_rm_index(fields);

        if (rm >= 8) {
            return 0;
        }
        src = ft_mmx(rm);
    } else {
        int addr;

        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        src = ft_vscratch;
    }

#ifdef QUICKTRANS_LATU
    /* Only the low two integers belong to the MMX/m64 source. Replicate
     * them so stale upper host lanes cannot raise extra exceptions. */
    FT_LA_VREPLVEI_D_EMIT(&out, ft_vscratch, src, 0);
    src = ft_vscratch;
#endif
    FT_LA_VFFINT_S_W_EMIT(&out, ft_vscratch, src);
    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
    return (out - code);
}

/* Match the legacy per-element conversions: a masked invalid lane must
 * not suppress precision flags raised by another, valid lane. */
static void ft_emit_cvt_fp2i_lanes(uint32_t **out, TranslationBlock *tb,
                                  target_ulong pc, int src, int dst,
                                  bool is_double, bool trunc, int lanes)
{
    int result = ft_vscratch + 1;
    int input = ft_vscratch + 2;
    int converted = ft_vscratch + 3;

    for (int lane = 0; lane < lanes; ++lane) {
        int operand = src;
        int lane_result = lane ? converted : result;
        if (lane) {
            if (is_double) {
                FT_LA_VREPLVEI_D_EMIT(out, input, src, lane);
            } else {
                FT_LA_VREPLVEI_W_EMIT(out, input, src, lane);
            }
            operand = input;
        }
        if (is_double) {
            if (trunc) {
                FT_LA_FTINTRZ_W_D_EMIT(out, lane_result, operand);
            } else {
                FT_LA_FTINT_W_D_EMIT(out, lane_result, operand);
            }
        } else if (trunc) {
            FT_LA_FTINTRZ_W_S_EMIT(out, lane_result, operand);
        } else {
            FT_LA_FTINT_W_S_EMIT(out, lane_result, operand);
        }
        ft_emit_lats_simd_fpe_check(out, tb, pc);
        /* Lane zero is already in place; later lanes overwrite the
         * remaining words before the architectural destination is updated. */
        if (lane) {
            FT_LA_VEXTRINS_W_EMIT(out, result, converted, lane << 4);
        }
    }
    FT_LA_VAND_V_EMIT(out, dst, result, result);
}

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
/* LATX_CVT_OPT=0 uses the legacy per-element conversion and Cause.V
 * correction instead of the packed conversion/overflow-bound sequence.
 * Keep the source intact until all elements have been read (dst may alias). */
static void ft_emit_cvt_fp2i_unoptimized(uint32_t **out, int src, int dst,
                                        bool is_double, bool trunc, int lanes)
{
    int result = ft_vscratch + 1;
    int input = ft_vscratch + 2;
    int converted = ft_vscratch + 3;

    for (int lane = 0; lane < lanes; ++lane) {
        int operand = src;
        if (lane) {
            if (is_double) {
                FT_LA_VREPLVEI_D_EMIT(out, input, src, lane);
            } else {
                FT_LA_VREPLVEI_W_EMIT(out, input, src, lane);
            }
            operand = input;
        }
        if (is_double) {
            if (trunc) {
                FT_LA_FTINTRZ_W_D_EMIT(out, converted, operand);
            } else {
                FT_LA_FTINT_W_D_EMIT(out, converted, operand);
            }
        } else if (trunc) {
            FT_LA_FTINTRZ_W_S_EMIT(out, converted, operand);
        } else {
            FT_LA_FTINT_W_S_EMIT(out, converted, operand);
        }
        FT_LA_MOVFCSR2GR_EMIT(out, la_t0, 0);
        FT_LA_BSTRPICK_D_EMIT(out, la_t0, la_t0, 28, 28);
        FT_LA_MOVFR2GR_D_EMIT(out, la_t1, converted);
        FT_LA_SLLI_D_EMIT(out, la_t2, la_t0, 31);
        FT_LA_MASKNEZ_EMIT(out, la_t1, la_t1, la_t0);
        FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);
        FT_LA_VINSGR2VR_W_EMIT(out, result, la_t1, lane);
    }
    FT_LA_VAND_V_EMIT(out, dst, result, result);
}
#endif

static bool ft_emit_cvt_fp2i_core(uint32_t **out,
                                  const FastTemplateFields *fields,
                                  TranslationBlock *tb, target_ulong pc,
                                  int src, int dst_vec)
{
    bool is_double = fields->id == dt_X86_INS_CVTPD2DQ ||
                     fields->id == dt_X86_INS_CVTTPD2DQ ||
                     fields->id == dt_X86_INS_CVTPD2PI ||
                     fields->id == dt_X86_INS_CVTTPD2PI;
    bool trunc = fields->id == dt_X86_INS_CVTTPD2DQ ||
                 fields->id == dt_X86_INS_CVTTPS2DQ ||
                 fields->id == dt_X86_INS_CVTTPD2PI ||
                 fields->id == dt_X86_INS_CVTTPS2PI;
    int temp = ft_vscratch + 1;

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (!option_cvt_opt) {
        bool mmx = fields->id == dt_X86_INS_CVTPS2PI ||
                   fields->id == dt_X86_INS_CVTTPS2PI ||
                   fields->id == dt_X86_INS_CVTPD2PI ||
                   fields->id == dt_X86_INS_CVTTPD2PI;
        ft_emit_cvt_fp2i_unoptimized(out, src, dst_vec, is_double, trunc,
                                     (is_double || mmx) ? 2 : 4);
        return true;
    }
#endif

    if (ft_fast_masked_v_enabled() &&
        fields->id != dt_X86_INS_CVTPS2DQ) {
        bool mmx = fields->id == dt_X86_INS_CVTPS2PI ||
                   fields->id == dt_X86_INS_CVTTPS2PI ||
                   fields->id == dt_X86_INS_CVTPD2PI ||
                   fields->id == dt_X86_INS_CVTTPD2PI;
        ft_emit_cvt_fp2i_lanes(out, tb, pc, src, dst_vec,
                               is_double, trunc, (is_double || mmx) ? 2 : 4);
        return true;
    }

    if (is_double) {
        if (trunc) {
            FT_LA_VFTINTRZ_W_D_EMIT(out, temp, src, src);
        } else {
            FT_LA_VFTINT_W_D_EMIT(out, temp, src, src);
        }
    } else if (trunc) {
        FT_LA_VFTINTRZ_W_S_EMIT(out, temp, src);
    } else {
        FT_LA_VFTINT_W_S_EMIT(out, temp, src);
    }

    ft_emit_lats_simd_fpe_check(out, tb, pc);
    if (!ft_fast_masked_v_enabled()) {
        ft_emit_cvt_fp2i_fix_invalid(out, temp, src, is_double, trunc);
    }
    FT_LA_VAND_V_EMIT(out, dst_vec, temp, temp);
    return true;
}

static int ft_emit_cvt_fp2i_xmm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    bool is_double = fields->id == dt_X86_INS_CVTPD2DQ ||
                     fields->id == dt_X86_INS_CVTTPD2DQ;

    if (dst >= XMM_NUM ||
        !(fields->id == dt_X86_INS_CVTPD2DQ ||
          fields->id == dt_X86_INS_CVTPS2DQ ||
          fields->id == dt_X86_INS_CVTTPD2DQ ||
          fields->id == dt_X86_INS_CVTTPS2DQ)) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }
    if (!ft_emit_cvt_fp2i_core(&out, fields, tb, pc, src, ft_xmm(dst))) {
        return 0;
    }
    if (is_double) {
        FT_LA_VINSGR2VR_D_EMIT(&out, ft_xmm(dst), la_zero, 1);
    }
    return (out - code);
}

static int ft_emit_cvt_fp2i_mmx_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    bool is_double = fields->id == dt_X86_INS_CVTPD2PI ||
                     fields->id == dt_X86_INS_CVTTPD2PI;

    if (dst >= 8 || !(fields->id == dt_X86_INS_CVTPD2PI ||
          fields->id == dt_X86_INS_CVTPS2PI ||
          fields->id == dt_X86_INS_CVTTPD2PI ||
          fields->id == dt_X86_INS_CVTTPS2PI)) {
        return 0;
    }
    /* The LATS soft-FPU entry already initializes TOP/tag and loads MMX.
     * Hardware x87 TOP/tag instructions are redundant in that mode. */
#if defined(CONFIG_LATX_OPT_NOFP) && !defined(QUICKTRANS_LATU)
    if (!(option_soft_fpu && ft_fast_masked_v_enabled()))
#endif
    {
        ft_emit_store_env(&out, la_zero, lsenv_offset_of_top(lsenv),
                          FT_LA_OPCODE_ST_W);
        FT_LA_X86MTTOP_EMIT(&out, 0);
        FT_LA_X86SETTM_EMIT(&out);
    }
    if (!ft_emit_xmmm_src_bytes(&out, fields, pc, is_double ? 16 : 8, &src)) {
        return 0;
    }
    if (!is_double) {
        /* CVT{T}PS2PI consumes only the low two single-precision lanes. */
        FT_LA_VREPLVEI_D_EMIT(&out, ft_vscratch, src, 0);
        src = ft_vscratch;
    }
    if (!ft_emit_cvt_fp2i_core(&out, fields, tb, pc, src, ft_vscratch)) {
        return 0;
    }
    FT_LA_VEXTRINS_D_EMIT(&out, ft_mmx(dst), ft_vscratch, 0);
    return (out - code);
}

static bool ft_cmp_predicate_info(int pred, int *cond, bool *swap)
{
    *swap = false;
    switch (pred & 7) {
    case 0:
        *cond = FCMP_COND_CEQ;
        return true;
    case 1:
        *cond = FCMP_COND_SLT;
        return true;
    case 2:
        *cond = FCMP_COND_SLE;
        return true;
    case 3:
        *cond = FCMP_COND_CUN;
        return true;
    case 4:
        *cond = FCMP_COND_CUNE;
        return true;
    case 5:
        *cond = FCMP_COND_SULE;
        *swap = true;
        return true;
    case 6:
        *cond = FCMP_COND_SULT;
        *swap = true;
        return true;
    case 7:
        *cond = FCMP_COND_COR;
        return true;
    default:
        return false;
    }
}

static int ft_emit_cmp_xmm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int lhs;
    int rhs;
    int cond;
    bool swap;
    bool is_double;
    bool is_scalar;
    bool fpe = ft_lats_simd_fpe_enabled(tb);

    if (dst >= XMM_NUM || !ft_cmp_predicate_info(fields->imm, &cond, &swap)) {
        return 0;
    }

    switch (fields->id) {
    case dt_X86_INS_CMPPD:
        is_double = true;
        is_scalar = false;
        if (fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
            return 0;
        }
        break;
    case dt_X86_INS_CMPPS:
        is_double = false;
        is_scalar = false;
        if (fields->prefix0 != 0 || fields->prefix2 != 0) {
            return 0;
        }
        break;
    case dt_X86_INS_CMPSD:
        is_double = true;
        is_scalar = true;
        if (fields->prefix0 != 0xf2) {
            return 0;
        }
        break;
    case dt_X86_INS_CMPSS:
        is_double = false;
        is_scalar = true;
        if (fields->prefix0 != 0xf3) {
            return 0;
        }
        break;
    default:
        return 0;
    }

    if (is_scalar) {
        int scalar_lhs = ft_vscratch + 1;
        int scalar_rhs = ft_vscratch + 2;
        int scalar_result = ft_vscratch + 3;

        if (!ft_emit_xmmm_src_bytes(&out, fields, pc, is_double ? 8 : 4, &src)) {
            return 0;
        }
        lhs = ft_xmm(dst);
        rhs = src;
        if (swap) {
            int tmp = lhs;

            lhs = rhs;
            rhs = tmp;
        }
        /* VEXTRINS selects a vector element, so make both lanes scalar. */
        if (is_double) {
            FT_LA_VREPLVEI_D_EMIT(&out, scalar_lhs, lhs, 0);
            FT_LA_VREPLVEI_D_EMIT(&out, scalar_rhs, rhs, 0);
            FT_LA_VFCMP_COND_D_EMIT(&out, scalar_result, scalar_lhs,
                                    scalar_rhs, cond);
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
            FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), scalar_result, 0);
        } else {
            FT_LA_VREPLVEI_W_EMIT(&out, scalar_lhs, lhs, 0);
            FT_LA_VREPLVEI_W_EMIT(&out, scalar_rhs, rhs, 0);
            FT_LA_VFCMP_COND_S_EMIT(&out, scalar_result, scalar_lhs,
                                    scalar_rhs, cond);
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
            FT_LA_VEXTRINS_W_EMIT(&out, ft_xmm(dst), scalar_result, 0);
        }
        return (out - code);
    }

    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }
    lhs = ft_xmm(dst);
    rhs = src;
    if (swap) {
        int tmp = lhs;

        lhs = rhs;
        rhs = tmp;
    }
    if (is_double) {
        FT_LA_VFCMP_COND_D_EMIT(&out,
                                fpe ? ft_vscratch + 1 : ft_xmm(dst),
                                lhs, rhs, cond);
    } else {
        FT_LA_VFCMP_COND_S_EMIT(&out,
                                fpe ? ft_vscratch + 1 : ft_xmm(dst),
                                lhs, rhs, cond);
    }
    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    if (fpe) {
        FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), ft_vscratch + 1,
                         ft_vscratch + 1);
    }
    return (out - code);
}

static void ft_emit_round_probe(uint32_t **out, int temp, int src,
                                bool is_double, uint8_t imm)
{
    if (imm & 0x08) {
        if (is_double) {
            FT_LA_VFCMP_COND_D_EMIT(out, temp, src, src, 0x08);
        } else {
            FT_LA_VFCMP_COND_S_EMIT(out, temp, src, src, 0x08);
        }
    } else {
        if (is_double) {
            FT_LA_VFRINT_D_EMIT(out, temp, src);
        } else {
            FT_LA_VFRINT_S_EMIT(out, temp, src);
        }
    }
}

static void ft_emit_round_by_imm(uint32_t **out, int dst, int src,
                                 bool is_double, uint8_t imm)
{
    switch (imm & 0x03) {
    case 0:
        if (is_double) {
            FT_LA_VFRINTRNE_D_EMIT(out, dst, src);
        } else {
            FT_LA_VFRINTRNE_S_EMIT(out, dst, src);
        }
        break;
    case 1:
        if (is_double) {
            FT_LA_VFRINTRM_D_EMIT(out, dst, src);
        } else {
            FT_LA_VFRINTRM_S_EMIT(out, dst, src);
        }
        break;
    case 2:
        if (is_double) {
            FT_LA_VFRINTRP_D_EMIT(out, dst, src);
        } else {
            FT_LA_VFRINTRP_S_EMIT(out, dst, src);
        }
        break;
    case 3:
        if (is_double) {
            FT_LA_VFRINTRZ_D_EMIT(out, dst, src);
        } else {
            FT_LA_VFRINTRZ_S_EMIT(out, dst, src);
        }
        break;
    }
}

static bool ft_emit_round_core(uint32_t **out, int dst, int src,
                               bool is_double, uint8_t imm)
{
    int mxcsr_offset = lsenv_offset_of_mxcsr(lsenv);

    if (!ft_fits_simm12(mxcsr_offset)) {
        return false;
    }

    ft_emit_round_probe(out, ft_vscratch + 3, src, is_double, imm);
    FT_LA_MOVFCSR2GR_EMIT(out, la_t1, 0);
    FT_LA_BSTRPICK_W_EMIT(out, la_t2, la_t1, 31, 0);
    FT_LA_BSTRINS_W_EMIT(out, la_t1, la_zero, 4, 0);

    if (imm & 0x04) {
        ft_emit_load_env(out, la_t3, mxcsr_offset, FT_LA_OPCODE_LD_WU);
        FT_LA_BSTRPICK_W_EMIT(out, la_t4, la_t3, 14, 13);
        FT_LA_ANDI_EMIT(out, la_t3, la_t4, 0x01);
        FT_LA_BEQ_EMIT(out, la_t3, la_zero, 2);
        FT_LA_XORI_EMIT(out, la_t4, la_t4, 0x02);
        FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t4, 9, 8);
        FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t1);
        if (is_double) {
            FT_LA_VFRINT_D_EMIT(out, dst, src);
        } else {
            FT_LA_VFRINT_S_EMIT(out, dst, src);
        }
    } else {
        FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t1);
        ft_emit_round_by_imm(out, dst, src, is_double, imm);
    }

    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t2);
    return true;
}

static void ft_emit_round_save_precision_flag(uint32_t **out)
{
    FT_LA_MOVFCSR2GR_EMIT(out, la_t0, 2);
    FT_LA_BSTRPICK_W_EMIT(out, la_t0, la_t0, FCSR_OFF_FLAGS_I,
                          FCSR_OFF_FLAGS_I);
}

static void ft_emit_round_restore_precision_flag(uint32_t **out)
{
    FT_LA_MOVFCSR2GR_EMIT(out, la_t1, 2);
    FT_LA_BSTRINS_W_EMIT(out, la_t1, la_t0, FCSR_OFF_FLAGS_I,
                         FCSR_OFF_FLAGS_I);
    FT_LA_MOVGR2FCSR_EMIT(out, 2, la_t1);
}

static int ft_emit_round_xmm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int round_dst;
    int round_src;
    uint8_t imm = fields->imm & 0xff;
    bool is_double;
    bool is_scalar;
    bool fpe = ft_lats_simd_fpe_enabled(tb);

    if (dst >= XMM_NUM || fields->prefix0 != 0 ||
        fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
        return 0;
    }

    switch (fields->id) {
    case dt_X86_INS_ROUNDPD:
        is_double = true;
        is_scalar = false;
        break;
    case dt_X86_INS_ROUNDPS:
        is_double = false;
        is_scalar = false;
        break;
    case dt_X86_INS_ROUNDSD:
        is_double = true;
        is_scalar = true;
        break;
    case dt_X86_INS_ROUNDSS:
        is_double = false;
        is_scalar = true;
        break;
    default:
        return 0;
    }

    if (is_scalar) {
        if (!ft_emit_xmmm_src_bytes(&out, fields, pc, is_double ? 8 : 4, &src)) {
            return 0;
        }
        round_src = ft_vscratch + 1;
        round_dst = ft_vscratch + 2;
        if (is_double) {
            FT_LA_VREPLVEI_D_EMIT(&out, round_src, src, 0);
        } else {
            FT_LA_VREPLVEI_W_EMIT(&out, round_src, src, 0);
        }
        if (imm & 0x08) {
            ft_emit_round_save_precision_flag(&out);
        }
        if (!ft_emit_round_core(&out, round_dst, round_src, is_double, imm)) {
            return 0;
        }
        if (imm & 0x08) {
            ft_emit_round_restore_precision_flag(&out);
        }
        ft_emit_lats_simd_fpe_check_ex(&out, tb, pc, imm & 0x08);
        if (is_double) {
            FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), round_dst, 0);
        } else {
            FT_LA_VEXTRINS_W_EMIT(&out, ft_xmm(dst), round_dst, 0);
        }
        return (out - code);
    }

    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }
    round_dst = fpe ? ft_vscratch + 1 : ft_xmm(dst);
    if (imm & 0x08) {
        ft_emit_round_save_precision_flag(&out);
    }
    if (!ft_emit_round_core(&out, round_dst, src, is_double, imm)) {
        return 0;
    }
    if (imm & 0x08) {
        ft_emit_round_restore_precision_flag(&out);
    }
    ft_emit_lats_simd_fpe_check_ex(&out, tb, pc, imm & 0x08);
    if (fpe) {
        FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), round_dst, round_dst);
    }
    return (out - code);
}

static void ft_emit_dpps_lane_select(uint32_t **out, int lhs, int rhs,
                                     int dst, int src, uint8_t imm)
{
    FT_LA_VANDI_B_EMIT(out, lhs, lhs, 0);
    FT_LA_VANDI_B_EMIT(out, rhs, rhs, 0);
    if (imm & 0x10) {
        FT_LA_VEXTRINS_W_EMIT(out, lhs, dst, 0x00);
        FT_LA_VEXTRINS_W_EMIT(out, rhs, src, 0x00);
    }
    if (imm & 0x20) {
        FT_LA_VEXTRINS_W_EMIT(out, lhs, dst, 0x11);
        FT_LA_VEXTRINS_W_EMIT(out, rhs, src, 0x11);
    }
    if (imm & 0x40) {
        FT_LA_VEXTRINS_W_EMIT(out, lhs, dst, 0x22);
        FT_LA_VEXTRINS_W_EMIT(out, rhs, src, 0x22);
    }
    if (imm & 0x80) {
        FT_LA_VEXTRINS_W_EMIT(out, lhs, dst, 0x33);
        FT_LA_VEXTRINS_W_EMIT(out, rhs, src, 0x33);
    }
}

static void ft_emit_dppd_lane_select(uint32_t **out, int lhs, int rhs,
                                     int dst, int src, uint8_t imm)
{
    FT_LA_VANDI_B_EMIT(out, lhs, lhs, 0);
    FT_LA_VANDI_B_EMIT(out, rhs, rhs, 0);
    if (imm & 0x10) {
        FT_LA_VEXTRINS_D_EMIT(out, lhs, dst, 0x00);
        FT_LA_VEXTRINS_D_EMIT(out, rhs, src, 0x00);
    }
    if (imm & 0x20) {
        FT_LA_VEXTRINS_D_EMIT(out, lhs, dst, 0x11);
        FT_LA_VEXTRINS_D_EMIT(out, rhs, src, 0x11);
    }
}

static void ft_emit_dpps_result_mask(uint32_t **out, int dst, int sum,
                                     uint8_t imm)
{
    FT_LA_VANDI_B_EMIT(out, dst, dst, 0);
    if (imm & 0x01) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, sum, 0x00);
    }
    if (imm & 0x02) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, sum, 0x11);
    }
    if (imm & 0x04) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, sum, 0x22);
    }
    if (imm & 0x08) {
        FT_LA_VEXTRINS_W_EMIT(out, dst, sum, 0x33);
    }
}

static void ft_emit_dppd_binary_x86_nan(uint32_t **out, int result,
                                        int lhs, int rhs, int quiet,
                                        bool is_multiply)
{
    int lhs_nan = ft_vscratch + 3;
    int rhs_nan = ft_vscratch + 4;
    int quiet_mask = ft_vscratch + 7;

    FT_LA_VFCMP_COND_D_EMIT(out, lhs_nan, lhs, lhs, 0x08);
    FT_LA_VFCMP_COND_D_EMIT(out, rhs_nan, rhs, rhs, 0x08);
    if (is_multiply) {
        FT_LA_VFMUL_D_EMIT(out, result, lhs, rhs);
    } else {
        FT_LA_VFADD_D_EMIT(out, result, lhs, rhs);
    }
    FT_LA_VBITSEL_V_EMIT(out, result, result, rhs, rhs_nan);
    FT_LA_VBITSEL_V_EMIT(out, result, result, lhs, lhs_nan);
    FT_LA_VOR_V_EMIT(out, rhs_nan, rhs_nan, lhs_nan);
    FT_LA_VAND_V_EMIT(out, quiet_mask, quiet, rhs_nan);
    FT_LA_VOR_V_EMIT(out, result, result, quiet_mask);
}

static int ft_emit_dp_xmm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    int lhs = ft_vscratch + 1;
    int rhs = ft_vscratch + 2;
    uint8_t imm = fields->imm & 0xff;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix0 != 0 ||
        fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        (fields->id != dt_X86_INS_DPPS && fields->id != dt_X86_INS_DPPD)) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }

    if (fields->id == dt_X86_INS_DPPD) {
        int product = ft_vscratch + 5;
        int quiet = ft_vscratch + 6;
        int high_sum = ft_vscratch;

        ft_emit_dppd_lane_select(&out, lhs, rhs, ft_xmm(dst), src, imm);
        ft_emit_li64(&out, la_t0, 0x0008000000000000ULL);
        FT_LA_VREPLGR2VR_D_EMIT(&out, quiet, la_t0);
        ft_emit_dppd_binary_x86_nan(&out, product, lhs, rhs, quiet, true);
        ft_emit_lats_simd_fpe_check(&out, tb, pc);
        FT_LA_VPACKOD_D_EMIT(&out, rhs, product, product);
        FT_LA_VPACKEV_D_EMIT(&out, lhs, product, product);
        if (!(imm & 0x03)) {
            /* DPPD still performs the add when both result lanes are masked. */
            ft_emit_dppd_binary_x86_nan(&out, product, lhs, rhs, quiet,
                                        false);
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
        }
        if (imm & 0x01) {
            ft_emit_dppd_binary_x86_nan(&out, product, lhs, rhs, quiet,
                                        false);
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
        }
        if (imm & 0x02) {
            ft_emit_dppd_binary_x86_nan(&out, high_sum, rhs, lhs, quiet,
                                        false);
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
        }

        /* Commit only after every operation that can raise an FP exception. */
        FT_LA_VANDI_B_EMIT(&out, lhs, lhs, 0);
        if (imm & 0x01) {
            FT_LA_VEXTRINS_D_EMIT(&out, lhs, product, 0x00);
        }
        if (imm & 0x02) {
            FT_LA_VEXTRINS_D_EMIT(&out, lhs, high_sum, 0x11);
        }
        FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), lhs, lhs);
        return (out - code);
    }

    int rhs_nan = ft_vscratch + 3;

    ft_emit_dpps_lane_select(&out, lhs, rhs, ft_xmm(dst), src, imm);
    FT_LA_VFMUL_S_EMIT(&out, lhs, lhs, rhs);
    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    FT_LA_VPACKOD_W_EMIT(&out, rhs, lhs, lhs);
    FT_LA_VPACKEV_W_EMIT(&out, lhs, lhs, lhs);
    if (imm & 0xa0) {
        FT_LA_VFCMP_COND_S_EMIT(&out, rhs_nan, rhs, rhs, 0x08);
        FT_LA_VSRLI_D_EMIT(&out, rhs_nan, rhs_nan, 32);
    }
    FT_LA_VFADD_S_EMIT(&out, lhs, lhs, rhs);
    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    if (imm & 0xa0) {
        FT_LA_VBITSEL_V_EMIT(&out, lhs, lhs, rhs, rhs_nan);
    }
    FT_LA_VPACKOD_D_EMIT(&out, rhs, lhs, lhs);
    FT_LA_VPACKEV_D_EMIT(&out, lhs, lhs, lhs);
    if (imm & 0xc0) {
        FT_LA_VFCMP_COND_S_EMIT(&out, rhs_nan, rhs, rhs, 0x08);
        FT_LA_VANDI_B_EMIT(&out, ft_vscratch, ft_vscratch, 0);
        FT_LA_VEXTRINS_D_EMIT(&out, ft_vscratch, rhs_nan, 0x11);
    }
    FT_LA_VFADD_S_EMIT(&out, lhs, lhs, rhs);
    ft_emit_lats_simd_fpe_check(&out, tb, pc);
    if (imm & 0xc0) {
        FT_LA_VBITSEL_V_EMIT(&out, lhs, lhs, rhs, ft_vscratch);
    }
    ft_emit_dpps_result_mask(&out, ft_xmm(dst), lhs, imm);
    return (out - code);
}

static void ft_emit_pclmul_ctz_loop(uint32_t **out, int lhs, int rhs,
                                    int res_lo, int res_hi, int shift,
                                    int tmp)
{
    FastBranchLabel zero = { 0 };
    FastBranchLabel loop = { 0 };
    FastBranchFixup zero_fixup;

    FT_LA_OR_EMIT(out, res_lo, la_zero, la_zero);
    FT_LA_OR_EMIT(out, res_hi, la_zero, la_zero);
    ft_emit_branch_placeholder(out, &zero_fixup, FT_BRANCH_BEQ, lhs,
                               la_zero, &zero);

    ft_bind_branch_label(&loop, *out);
    FT_LA_CTZ_D_EMIT(out, shift, lhs);
    FT_LA_SLL_D_EMIT(out, tmp, rhs, shift);
    FT_LA_XOR_EMIT(out, res_lo, res_lo, tmp);
    FT_LA_ADDI_D_EMIT(out, tmp, la_zero, 64);
    FT_LA_SUB_D_EMIT(out, tmp, tmp, shift);
    FT_LA_SRL_D_EMIT(out, tmp, rhs, tmp);
    FT_LA_SLTU_EMIT(out, shift, la_zero, shift);
    FT_LA_SUB_D_EMIT(out, shift, la_zero, shift);
    FT_LA_AND_EMIT(out, tmp, tmp, shift);
    FT_LA_XOR_EMIT(out, res_hi, res_hi, tmp);
    FT_LA_ADDI_D_EMIT(out, tmp, lhs, -1);
    FT_LA_AND_EMIT(out, lhs, lhs, tmp);
    {
        FastBranchFixup loop_fixup;

        ft_emit_branch_placeholder(out, &loop_fixup, FT_BRANCH_BNE, lhs,
                                   la_zero, &loop);
        ft_resolve_branch_fixup(&loop_fixup);
    }

    ft_bind_branch_label(&zero, *out);
    ft_resolve_branch_fixup(&zero_fixup);
}

static int ft_emit_pclmulqdq_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src;
    uint8_t imm = fields->imm & 0xff;

    (void)tb;
    (void)pc;

    if (dst >= XMM_NUM || fields->prefix0 != 0 ||
        fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_PCLMULQDQ) {
        return 0;
    }
    if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
        return 0;
    }

    FT_LA_VPICKVE2GR_DU_EMIT(&out, la_t0, ft_xmm(dst), imm & 0x01);
    FT_LA_VPICKVE2GR_DU_EMIT(&out, la_t1, src, (imm >> 4) & 0x01);
    ft_emit_pclmul_ctz_loop(&out, la_t0, la_t1, la_t2, la_t3, la_t4,
                            la_r21);
    FT_LA_VANDI_B_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
    FT_LA_VINSGR2VR_D_EMIT(&out, ft_xmm(dst), la_t2, 0);
    FT_LA_VINSGR2VR_D_EMIT(&out, ft_xmm(dst), la_t3, 1);
    return (out - code);
}

static int ft_emit_fma132_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    int src1 = fields->vex_v;
    int src2;

    (void)tb;

    if (dst >= XMM_NUM || src1 < 0 || src1 >= XMM_NUM) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        int rm = ft_modrm_rm_index(fields);

        if (rm >= XMM_NUM) {
            return 0;
        }
        src2 = ft_xmm(rm);
    } else {
        int addr;

        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_VLD_EMIT(&out, ft_vscratch, addr,
                       ft_mem_access_offset(fields, addr));
        src2 = ft_vscratch;
    }

    switch (fields->id) {
    case dt_X86_INS_VFMADD132PS:
        FT_LA_VFMADD_S_EMIT(&out, ft_xmm(dst), ft_xmm(dst), src2,
                             ft_xmm(src1));
        break;
    case dt_X86_INS_VFMADD132PD:
        FT_LA_VFMADD_D_EMIT(&out, ft_xmm(dst), ft_xmm(dst), src2,
                             ft_xmm(src1));
        break;
    case dt_X86_INS_VFMSUB132PS:
        FT_LA_VFMSUB_S_EMIT(&out, ft_xmm(dst), ft_xmm(dst), src2,
                             ft_xmm(src1));
        break;
    case dt_X86_INS_VFMSUB132PD:
        FT_LA_VFMSUB_D_EMIT(&out, ft_xmm(dst), ft_xmm(dst), src2,
                             ft_xmm(src1));
        break;
    default:
        return 0;
    }
    return (out - code);
}

static bool ft_emit_helper_mem_src_to_scratch(uint32_t **out,
                                              const FastTemplateFields *fields,
                                              target_ulong pc, int dst,
                                              bool avoid_xmm0,
                                              int *scratch_xmm)
{
    int addr;
    int scratch = (dst + 1) % XMM_NUM;

    if (avoid_xmm0 && scratch == 0) {
        scratch = (scratch + 1) % XMM_NUM;
    }

    ft_emit_host_stack_begin(out);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -32);
    FT_LA_VST_EMIT(out, ft_xmm(scratch), la_sp, 16);
    ft_emit_host_stack_end(out);
    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        ft_emit_host_stack_begin(out);
        FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 32);
        ft_emit_host_stack_end(out);
        return false;
    }
    FT_LA_VLD_EMIT(out, ft_xmm(scratch), addr,
                   ft_mem_access_offset(fields, addr));
    *scratch_xmm = scratch;
    return true;
}

static void ft_emit_helper_mem_src_restore(uint32_t **out, int scratch_xmm)
{
    ft_emit_host_stack_begin(out);
    FT_LA_VLD_EMIT(out, ft_xmm(scratch_xmm), la_sp, 16);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 32);
    ft_emit_host_stack_end(out);
}

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
/* Keep the memory operand independent of guest XMM state.  Load before
 * changing the host stack so a guest read fault sees the original context. */
static bool ft_emit_latu_crypto_mem_helper(uint32_t **out,
                                            const FastTemplateFields *fields,
                                            target_ulong pc, int dst,
                                            void *func, bool sha, bool has_imm)
{
    int addr;

    if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
        return false;
    }
    FT_LA_VLD_EMIT(out, ft_vscratch, addr,
                   ft_mem_access_offset(fields, addr));
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, -16);
    FT_LA_VST_EMIT(out, ft_vscratch, la_sp, 0);
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_xmm_env_addr(out, la_a1, dst);
    if (sha) {
        ft_emit_xmm_env_addr(out, la_a2, dst);
        FT_LA_OR_EMIT(out, la_a3, la_sp, la_zero);
    } else {
        FT_LA_OR_EMIT(out, la_a2, la_sp, la_zero);
        if (has_imm) {
            ft_emit_li64(out, la_a3, (uint64_t)(uint32_t)fields->imm);
        }
    }
    ft_emit_host_call_via(out, func, sha ? 0xf : 0x7,
                          sha && fields->id == dt_X86_INS_SHA256RNDS2 ?
                          la_t4 : la_t0);
    ft_emit_crypto_helper_epilogue(out, false);
    FT_LA_ADDI_D_EMIT(out, la_sp, la_sp, 16);
    return true;
}
#endif

static bool ft_aes_round_helper(unsigned int id, void **func)
{
    switch (id) {
    case dt_X86_INS_AESENC:
        *func = (void *)helper_aesenc_xmm;
        return true;
    case dt_X86_INS_AESENCLAST:
        *func = (void *)helper_aesenclast_xmm;
        return true;
    case dt_X86_INS_AESDEC:
        *func = (void *)helper_aesdec_xmm;
        return true;
    case dt_X86_INS_AESDECLAST:
        *func = (void *)helper_aesdeclast_xmm;
        return true;
    default:
        return false;
    }
}

static bool ft_emit_aes_helper_src(uint32_t **out,
                                   const FastTemplateFields *fields,
                                   target_ulong pc, int dst, void *func,
                                   bool has_imm, bool lats_aes_round)
{
    if (fields->modrm_mod == 3) {
        int rm = ft_modrm_rm_index(fields);

        if (rm >= XMM_NUM) {
            return false;
        }
        if (has_imm) {
            ft_emit_call_xmm_helper_imm(out, func, dst, rm, fields->imm);
        } else {
            ft_emit_call_xmm_helper3(out, func, dst,
                                     lats_aes_round ? dst : rm,
                                     lats_aes_round ? rm : 0);
        }
        return true;
    }

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    return ft_emit_latu_crypto_mem_helper(out, fields, pc, dst, func,
                                          false, has_imm);
#else
    int scratch;

    if (!ft_emit_helper_mem_src_to_scratch(out, fields, pc, dst, false,
                                           &scratch)) {
        return false;
    }
    if (has_imm) {
        ft_emit_call_xmm_helper_imm(out, func, dst, scratch, fields->imm);
    } else {
        ft_emit_call_xmm_helper3(out, func, dst,
                                 lats_aes_round ? dst : scratch,
                                 lats_aes_round ? scratch : 0);
    }
    ft_emit_helper_mem_src_restore(out, scratch);
    return true;
#endif
}

static bool ft_sha_helper(unsigned int id, int imm, void **func)
{
    switch (id) {
    case dt_X86_INS_SHA1NEXTE:
        *func = (void *)helper_sha1nexte;
        return true;
    case dt_X86_INS_SHA1MSG1:
        *func = (void *)helper_sha1msg1;
        return true;
    case dt_X86_INS_SHA1MSG2:
        *func = (void *)helper_sha1msg2;
        return true;
    case dt_X86_INS_SHA256RNDS2:
        *func = ft_host_sha256rnds2_helper();
        return true;
    case dt_X86_INS_SHA256MSG1:
        *func = (void *)helper_sha256msg1;
        return true;
    case dt_X86_INS_SHA256MSG2:
        *func = (void *)helper_sha256msg2;
        return true;
    case dt_X86_INS_SHA1RNDS4:
        switch (imm) {
        case 0:
            *func = (void *)helper_sha1rnds4_f0;
            return true;
        case 1:
            *func = (void *)helper_sha1rnds4_f1;
            return true;
        case 2:
            *func = (void *)helper_sha1rnds4_f2;
            return true;
        case 3:
            *func = (void *)helper_sha1rnds4_f3;
            return true;
        default:
            return false;
        }
    default:
        return false;
    }
}

static bool ft_emit_sha_helper_src(uint32_t **out,
                                   const FastTemplateFields *fields,
                                   target_ulong pc, int dst, void *func)
{
    bool sha256rnds2 = fields->id == dt_X86_INS_SHA256RNDS2;

    if (fields->modrm_mod == 3) {
        int src = ft_modrm_rm_index(fields);

        if (src >= XMM_NUM) {
            return false;
        }
        ft_emit_call_sha_reg_helper(out, func, dst, src, sha256rnds2);
        return true;
    }

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    return ft_emit_latu_crypto_mem_helper(out, fields, pc, dst, func,
                                          true, false);
#else
    int scratch;

    if (!ft_emit_helper_mem_src_to_scratch(out, fields, pc, dst,
                                           sha256rnds2, &scratch)) {
        return false;
    }
    ft_emit_call_sha_reg_helper(out, func, dst, scratch, sha256rnds2);
    ft_emit_helper_mem_src_restore(out, scratch);
    return true;
#endif
}

static int ft_emit_sha_template(const FastTemplateFields *fields,
                                TranslationBlock *tb, target_ulong pc,
                                uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    void *func;

    (void)tb;

    if (fields->prefix0 != 0 || fields->prefix2 != 0 || dst >= XMM_NUM ||
        !ft_sha_helper(fields->id, fields->imm, &func) ||
        !ft_emit_sha_helper_src(&out, fields, pc, dst, func)) {
        return 0;
    }
    return out - code;
}

#ifndef QUICKTRANS_LATU
#include "crypto/aes.h"

static void ft_emit_aes_table(uint32_t **out, int reg, const void *table)
{
    ft_emit_li64(out, reg, (uintptr_t)table);
#ifdef CONFIG_SOFTMMU
    if (hamt_enabled() && hamt_mode_dmw()) {
        FT_LA_LU52I_D_EMIT(out, reg, reg, 0x900);
    }
#endif
}

static bool ft_emit_aes_round_inline(uint32_t **out,
                                    const FastTemplateFields *fields,
                                    target_ulong pc, int dst)
{
    bool decrypt = fields->id == dt_X86_INS_AESDEC ||
                   fields->id == dt_X86_INS_AESDECLAST;
    bool last = fields->id == dt_X86_INS_AESENCLAST ||
                fields->id == dt_X86_INS_AESDECLAST;
    int key;
    int table = ft_scratch_avoid3(-1, -1, -1);
    int word = ft_scratch_avoid3(table, -1, -1);
    int byte = ft_scratch_avoid3(table, word, -1);
    int value = ft_scratch_avoid3(table, word, byte);
    int result = ft_vscratch + 1;
    int state = ft_xmm(dst);
#ifdef CONFIG_SOFTMMU
    /* LATS maps t0-t2 to scratch registers a4, a5 and a7, not guest GPRs.
     * Load the memory operand before assigning the four table registers. */
    const int tables[4] = { la_a0, la_a1, la_a2, la_a3 };
    if (!last) {
        table = tables[0];
        word = la_t0;
        byte = la_t1;
        value = la_t2;
    }
#endif

    if (!ft_emit_xmmm_src(out, fields, pc, &key)) {
        return false;
    }
    ft_emit_aes_table(out, table, last ?
                      (const void *)(decrypt ? AES_isbox : AES_sbox) :
                      (const void *)(decrypt ? AES_Td0 : AES_Te0));
#ifdef CONFIG_SOFTMMU
    if (!last) {
        ft_emit_aes_table(out, tables[1], decrypt ? AES_Td1 : AES_Te1);
        ft_emit_aes_table(out, tables[2], decrypt ? AES_Td2 : AES_Te2);
        ft_emit_aes_table(out, tables[3], decrypt ? AES_Td3 : AES_Te3);
    }
#endif
    /* Keep the original state and round key intact even when they alias. */
    for (int column = 0; column < 4; ++column) {
        for (int row = 0; row < 4; ++row) {
            int pos = column * 4 + row;
            int index = (pos * (decrypt ? 13 : 5)) & 15;
            FT_LA_VPICKVE2GR_BU_EMIT(out, byte, state, index);
            if (last) {
                FT_LA_LDX_BU_EMIT(out, value, table, byte);
                FT_LA_VINSGR2VR_B_EMIT(out, result, value, pos);
            } else {
                int term = row == 0 ? word : value;
#ifdef CONFIG_SOFTMMU
                FT_LA_ALSL_D_EMIT(out, term, byte, tables[row], 1);
#else
                FT_LA_ALSL_D_EMIT(out, term, byte, table, 1);
#endif
                FT_LA_LD_W_EMIT(out, term, term, 0);
                if (row != 0) {
#ifndef CONFIG_SOFTMMU
                    FT_LA_ROTRI_W_EMIT(out, value, value, row * 8);
#endif
                    FT_LA_XOR_EMIT(out, word, word, value);
                }
            }
        }
        if (!last) {
            FT_LA_REVB_2H_EMIT(out, word, word);
            FT_LA_ROTRI_W_EMIT(out, word, word, 16);
            FT_LA_VINSGR2VR_W_EMIT(out, result, word, column);
        }
    }
    FT_LA_VXOR_V_EMIT(out, state, result, key);
    return true;
}

static bool ft_emit_aeskeygen_inline(uint32_t **out,
                                     const FastTemplateFields *fields,
                                     target_ulong pc, int dst)
{
    int src;
    int table = ft_scratch_avoid3(-1, -1, -1);
    int value = ft_scratch_avoid3(table, -1, -1);
    int result = ft_vscratch + 1;

    if (!ft_emit_xmmm_src(out, fields, pc, &src)) {
        return false;
    }
    ft_emit_aes_table(out, table, AES_sbox);
    for (int half = 0; half < 2; ++half) {
        for (int byte = 0; byte < 4; ++byte) {
            FT_LA_VPICKVE2GR_BU_EMIT(out, value, src, half * 8 + byte + 4);
            FT_LA_LDX_BU_EMIT(out, value, table, value);
            FT_LA_VINSGR2VR_B_EMIT(out, result, value, half * 8 + byte);
        }
        FT_LA_VPICKVE2GR_WU_EMIT(out, value, result, half * 2);
        FT_LA_ROTRI_W_EMIT(out, value, value, 8);
        FT_LA_XORI_EMIT(out, value, value, fields->imm);
        FT_LA_VINSGR2VR_W_EMIT(out, result, value, half * 2 + 1);
    }
    FT_LA_VOR_V_EMIT(out, ft_xmm(dst), result, result);
    return true;
}
#endif

#include "emit-vpaes-entry.inc.c"

static int ft_emit_aes_round_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);
    void *func;
#ifdef QUICKTRANS_LATU
    const bool lats_aes_round = false;
#else
    const bool lats_aes_round = true;
#endif

    (void)tb;

    if (fields->prefix2 != dt_X86_PREFIX_OPSIZE || dst >= XMM_NUM) {
        return 0;
    }
    if (!ft_aes_round_helper(fields->id, &func)) {
        return 0;
    }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    !defined(CONFIG_LATX_AVX_OPT)
    if (option_vpaes) {
        return ft_emit_latu_vpaes(&out, fields, pc, dst) ? out - code : 0;
    }
#endif
#ifndef QUICKTRANS_LATU
    unsigned int mask = fields->id == dt_X86_INS_AESDEC ? 1 :
                        fields->id == dt_X86_INS_AESDECLAST ? 2 :
                        fields->id == dt_X86_INS_AESENC ? 4 : 8;
    if (option_aes_opt & mask) {
        return ft_emit_aes_round_inline(&out, fields, pc, dst) ? out - code : 0;
    }
#endif
    if (!ft_emit_aes_helper_src(&out, fields, pc, dst, func, false,
                                lats_aes_round)) {
        return 0;
    }
    return (out - code);
}

#ifndef QUICKTRANS_LATU
static bool ft_emit_aesimc_inline(uint32_t **out,
                                 const FastTemplateFields *fields,
                                 target_ulong pc, int dst)
{
    int src;
    int table = ft_scratch_avoid3(-1, -1, -1);
    int word = ft_scratch_avoid3(table, -1, -1);
    int byte = ft_scratch_avoid3(table, word, -1);
    int value = ft_scratch_avoid3(table, word, byte);
    int result = ft_vscratch + 1;

    if (!ft_emit_xmmm_src(out, fields, pc, &src)) {
        return false;
    }
    ft_emit_li64(out, table, (uintptr_t)AES_imc_rot);
#ifdef CONFIG_SOFTMMU
    if (hamt_enabled() && hamt_mode_dmw()) {
        FT_LA_LU52I_D_EMIT(out, table, table, 0x900);
    }
#endif
    /* Avoid serializing source reads behind partial writes when dst == src. */
    for (int column = 0; column < 4; ++column) {
        for (int row = 0; row < 4; ++row) {
            int term = row == 0 ? word : value;
            FT_LA_VPICKVE2GR_BU_EMIT(out, byte, src, column * 4 + row);
            FT_LA_ALSL_D_EMIT(out, term, byte, table, 1);
            FT_LA_LD_W_EMIT(out, term, term, 0);
            if (row != 0) {
                FT_LA_ROTRI_W_EMIT(out, value, value, 32 - row * 8);
                FT_LA_XOR_EMIT(out, word, word, value);
            }
        }
        FT_LA_VINSGR2VR_W_EMIT(out, result, word, column);
    }
    FT_LA_VOR_V_EMIT(out, ft_xmm(dst), result, result);
    return true;
}
#endif

static int ft_emit_aesimc_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);

    (void)tb;

    if (fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_AESIMC || dst >= XMM_NUM) {
        return 0;
    }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    !defined(CONFIG_LATX_AVX_OPT)
    if (option_vpaes) {
        return ft_emit_latu_vpaes(&out, fields, pc, dst) ? out - code : 0;
    }
#endif
#ifndef QUICKTRANS_LATU
    if (option_aes_opt & 0x10) {
        return ft_emit_aesimc_inline(&out, fields, pc, dst) ? out - code : 0;
    }
#endif
    if (!ft_emit_aes_helper_src(&out, fields, pc, dst,
                                (void *)helper_aesimc_xmm, false, false)) {
        return 0;
    }
    return (out - code);
}

static int ft_emit_aeskeygen_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = ft_modrm_reg_index(fields);

    (void)tb;

    if (fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
        fields->id != dt_X86_INS_AESKEYGENASSIST || dst >= XMM_NUM ||
        fields->imm < 0 || fields->imm > 0xff) {
        return 0;
    }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    !defined(CONFIG_LATX_AVX_OPT)
    if (option_vpaes) {
        return ft_emit_latu_vpaes(&out, fields, pc, dst) ? out - code : 0;
    }
#endif
#ifndef QUICKTRANS_LATU
    if (option_aes_opt & 0x20) {
        return ft_emit_aeskeygen_inline(&out, fields, pc, dst) ? out - code : 0;
    }
#endif
    if (!ft_emit_aes_helper_src(&out, fields, pc, dst,
                                (void *)helper_aeskeygenassist_xmm, true,
                                false)) {
        return 0;
    }
    return (out - code);
}
