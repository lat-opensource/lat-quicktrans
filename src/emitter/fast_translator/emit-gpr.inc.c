/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* MOV r32 always clears the high half, including an aliased destination. */
static void ft_emit_mov_imm32(uint32_t **out, int dst, uint32_t value)
{
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    if (value <= 0xfff) {
        FT_LA_ORI_EMIT(out, dst, la_zero, value);
        return;
    }
    FT_LA_LU12I_W_EMIT(out, dst, ft_simm20_field(value >> 12));
    if (value & 0xfff) {
        FT_LA_ORI_EMIT(out, dst, dst, value & 0xfff);
    }
    if (value & 0x80000000u) {
        FT_LA_BSTRPICK_D_EMIT(out, dst, dst, 31, 0);
    }
#else
    ft_emit_li32_two(out, dst, value);
    FT_LA_BSTRPICK_D_EMIT(out, dst, dst, 31, 0);
#endif
}

static int ft_emit_mov_reg_imm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    (void)pc;

    switch (fields->kind) {
    case FT_MOV_R8_IMM8:
        if (fields->imm < 0 || fields->imm > 0xff) {
            return 0;
        }
        if (fields->rex < 0 && fields->reg >= 4 && fields->reg < 8) {
            int base = fields->reg & 3;

            FT_LA_ORI_EMIT(&out, la_t0, la_zero, fields->imm);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(base), la_t0, 15, 8);
            return (out - code);
        }
        if (fields->reg < 0 || fields->reg >= GPR_NUM) {
            return 0;
        }
        FT_LA_ORI_EMIT(&out, la_t0, la_zero, fields->imm);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(fields->reg), la_t0, 7, 0);
        break;
    case FT_MOV_R16_IMM16:
        if (fields->reg < 0 || fields->reg >= GPR_NUM ||
            fields->imm < 0 || fields->imm > 0xffff) {
            return 0;
        }
        if (fields->imm & 0xf000) {
            ft_emit_raw(&out, ft_gpr2_imm20(FT_LA_OPCODE_LU12I_W, la_t0,
                                            (uint32_t)fields->imm >> 12));
            FT_LA_ORI_EMIT(&out, la_t0, la_t0, fields->imm & 0xfff);
        } else {
            FT_LA_ORI_EMIT(&out, la_t0, la_zero, fields->imm & 0xfff);
        }
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(fields->reg), la_t0, 15, 0);
        break;
    case FT_MOV_R32_IMM32:
        if (fields->reg < 0 || fields->reg >= GPR_NUM) {
            return 0;
        }
        ft_emit_mov_imm32(&out, ft_gpr(fields->reg), (uint32_t)fields->imm);
        break;
    case FT_MOV_R64_IMM64:
        if (!ft_rex_w(fields) || fields->reg < 0 ||
            fields->reg >= GPR_NUM) {
            return 0;
        }
        ft_emit_li64(&out, ft_gpr(fields->reg), fields->imm64);
        break;
    default:
        return 0;
    }

    return (out - code);
}

static int ft_emit_mov_moffs_template(const FastTemplateFields *fields,
                                      TranslationBlock *tb, target_ulong pc,
                                      uint32_t *code)
{
    uint32_t *out = code;
    int addr = la_t0;
    int bytes = fields->alu_width / 8;
    bool aligned;

    (void)tb;

    if (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) {
        return 0;
    }
    if (!ft_emit_guest_addr(&out, addr, fields->imm64)) {
        return 0;
    }
    aligned = fields->segment < 0 && (fields->imm64 & (bytes - 1)) == 0;
    if (fields->segment >= 0) {
        int seg_offset = offsetof(CPUX86State, segs[fields->segment].base);

        if (!ft_fits_simm12(seg_offset)) {
            return 0;
        }
        ft_emit_load_env(&out, la_t1, seg_offset, FT_LA_OPCODE_LD_D);
        FT_LA_ADD_D_EMIT(&out, addr, addr, la_t1);
    }

    if (fields->kind == FT_MOV_ACC_MOFFS) {
        if (!aligned && bytes > 1) {
            FT_LA_LD_BU_EMIT(&out, la_t1, addr, 0);
            for (int i = 1; i < bytes; ++i) {
                FT_LA_LD_BU_EMIT(&out, la_t2, addr, i);
                FT_LA_SLLI_D_EMIT(&out, la_t2, la_t2, i * 8);
                FT_LA_OR_EMIT(&out, la_t1, la_t1, la_t2);
            }
            if (bytes < 4) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t1,
                                     fields->alu_width - 1, 0);
            } else {
                FT_LA_OR_EMIT(&out, ft_gpr(rax_index), la_t1, la_zero);
            }
            return out - code;
        }
        switch (fields->alu_width) {
        case 8:
            FT_LA_LD_BU_EMIT(&out, la_t1, addr, 0);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t1, 7, 0);
            break;
        case 16:
            FT_LA_LD_HU_EMIT(&out, la_t1, addr, 0);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t1, 15, 0);
            break;
        case 32:
            FT_LA_LD_WU_EMIT(&out, ft_gpr(rax_index), addr, 0);
            break;
        case 64:
            FT_LA_LD_D_EMIT(&out, ft_gpr(rax_index), addr, 0);
            break;
        default:
            return 0;
        }
    } else if (fields->kind == FT_MOV_MOFFS_ACC) {
        if (ft_emit_data_store(&out, pc, addr, 0, ft_gpr(rax_index), bytes)) {
            return out - code;
        }
        if (!aligned && bytes > 1) {
            FT_LA_ST_B_EMIT(&out, ft_gpr(rax_index), addr, 0);
            for (int i = 1; i < bytes; ++i) {
                FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(rax_index), i * 8);
                FT_LA_ST_B_EMIT(&out, la_t1, addr, i);
            }
            return out - code;
        }
        switch (fields->alu_width) {
        case 8:
            FT_LA_ST_B_EMIT(&out, ft_gpr(rax_index), addr, 0);
            break;
        case 16:
            FT_LA_ST_H_EMIT(&out, ft_gpr(rax_index), addr, 0);
            break;
        case 32:
            FT_LA_ST_W_EMIT(&out, ft_gpr(rax_index), addr, 0);
            break;
        case 64:
            FT_LA_ST_D_EMIT(&out, ft_gpr(rax_index), addr, 0);
            break;
        default:
            return 0;
        }
    } else {
        return 0;
    }

    return out - code;
}

static int ft_emit_bswap_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    (void)pc;

    if (fields->reg < 0 || fields->reg >= GPR_NUM) {
        return 0;
    }
    if (fields->kind == FT_BSWAP_R32) {
        if (ft_rex_w(fields)) {
            return 0;
        }
        FT_LA_REVB_2W_EMIT(&out, ft_gpr(fields->reg), ft_gpr(fields->reg));
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(fields->reg),
                              ft_gpr(fields->reg), 31, 0);
    } else {
        if (!ft_rex_w(fields)) {
            return 0;
        }
        FT_LA_REVB_D_EMIT(&out, ft_gpr(fields->reg), ft_gpr(fields->reg));
    }
    return (out - code);
}

static int ft_emit_rdrand_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst = fields->reg;

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM) {
        return 0;
    }

    FT_LA_RDTIME_D_EMIT(&out, la_t2, la_t3);
    ft_emit_li64(&out, la_t3, pc);
    FT_LA_XOR_EMIT(&out, la_t2, la_t2, la_t3);

    switch (fields->kind) {
    case FT_RDRAND_R64:
        if (!ft_rex_w(fields)) {
            return 0;
        }
        FT_LA_OR_EMIT(&out, ft_gpr(dst), la_t2, la_zero);
        break;
    case FT_RDRAND_R32:
        if (ft_rex_w(fields)) {
            return 0;
        }
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), la_t2, 31, 0);
        break;
    case FT_RDRAND_R16:
        if (ft_rex_w(fields)) {
            return 0;
        }
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 15, 0);
        break;
    default:
        return 0;
    }

    if (!fields->skip_flags) {
        FT_LA_X86MTFLAG_EMIT(&out, la_zero,
                             CF_USEDEF_BIT | PF_USEDEF_BIT |
                             AF_USEDEF_BIT | ZF_USEDEF_BIT |
                             SF_USEDEF_BIT | OF_USEDEF_BIT);
        FT_LA_ORI_EMIT(&out, la_t4, la_zero, 0xfff);
        FT_LA_X86MTFLAG_EMIT(&out, la_t4, CF_USEDEF_BIT);
    }
    return (out - code);
}

#ifdef QUICKTRANS_LATU
static void ft_emit_latu_store_seg(uint32_t **out, int seg);
#endif

static int ft_emit_mov_segment_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int seg = fields->reg;
    int selector_offset;

    (void)tb;

    if (seg < es_index || seg > gs_index) {
        return 0;
    }
    if (fields->kind == FT_MOV_SEG_RM && seg == cs_index) {
        return 0;
    }

    selector_offset = offsetof(CPUX86State, segs[seg].selector);

    if (fields->kind == FT_MOV_RM_SEG) {
        ft_emit_load_env(&out, la_t0, selector_offset, FT_LA_OPCODE_LD_WU);

        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

            if (dst < 0 || dst >= GPR_NUM) {
                return 0;
            }
            if (fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
            } else if (ft_rex_w(fields)) {
                FT_LA_OR_EMIT(&out, ft_gpr(dst), la_t0, la_zero);
            } else {
                FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), la_t0, 31, 0);
            }
            return (out - code);
        }

        if (!ft_emit_store_rm16(&out, fields, pc, la_t0)) {
            return 0;
        }
        return (out - code);
    }

    if (fields->kind == FT_MOV_SEG_RM) {
        int src;

        if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
#ifdef QUICKTRANS_LATU
        FT_LA_BSTRPICK_D_EMIT(&out, la_t2, src, 15, 0);
        ft_emit_latu_store_seg(&out, seg);
#else
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, src, 15, 0);
        ft_emit_store_env(&out, la_t0, selector_offset, FT_LA_OPCODE_ST_W);
#endif
        return (out - code);
    }

    return 0;
}

static int ft_movbe_width(FastTemplateKind kind)
{
    switch (kind) {
    case FT_MOVBE_R64_M64:
    case FT_MOVBE_M64_R64:
        return 64;
    case FT_MOVBE_R16_M16:
    case FT_MOVBE_M16_R16:
        return 16;
    case FT_MOVBE_R32_M32:
    case FT_MOVBE_M32_R32:
        return 32;
    default:
        return 0;
    }
}

static bool ft_movbe_is_store(FastTemplateKind kind)
{
    return kind == FT_MOVBE_M64_R64 ||
           kind == FT_MOVBE_M32_R32 ||
           kind == FT_MOVBE_M16_R16;
}

static void ft_emit_movbe_reverse(uint32_t **out, int dst, int src, int width)
{
    if (width == 64) {
        FT_LA_REVB_D_EMIT(out, dst, src);
    } else if (width == 32) {
        FT_LA_REVB_2W_EMIT(out, dst, src);
        FT_LA_BSTRPICK_D_EMIT(out, dst, dst, 31, 0);
    } else {
        FT_LA_REVB_2H_EMIT(out, dst, src);
        FT_LA_BSTRPICK_D_EMIT(out, dst, dst, 15, 0);
    }
}

static int ft_emit_movbe_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int width = ft_movbe_width(fields->kind);
    int reg = ft_modrm_reg_index(fields);
    bool is_store = ft_movbe_is_store(fields->kind);
    int value;

    (void)tb;

    if (!width || reg >= GPR_NUM || fields->modrm_mod == 3) {
        return 0;
    }
    if ((width == 64) != ft_rex_w(fields)) {
        return 0;
    }
    if (width == 16 && fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
        return 0;
    }
    if (width == 32 && fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
        return 0;
    }

    if (is_store) {
        ft_emit_movbe_reverse(&out, la_t2, ft_gpr(reg), width);
        if (width == 64) {
            if (!ft_emit_store_rm64(&out, fields, pc, la_t2)) {
                return 0;
            }
        } else if (width == 32) {
            if (!ft_emit_store_rm32(&out, fields, pc, la_t2, false)) {
                return 0;
            }
        } else if (!ft_emit_store_rm16(&out, fields, pc, la_t2)) {
            return 0;
        }
        return (out - code);
    }

    if (width == 64) {
        if (!ft_emit_load_rm64(&out, fields, pc, &value)) {
            return 0;
        }
    } else if (width == 32) {
        if (!ft_emit_load_rm32(&out, fields, pc, &value)) {
            return 0;
        }
    } else if (!ft_emit_load_rm16(&out, fields, pc, &value)) {
        return 0;
    }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    if (width == 32 || width == 64) {
        /* Reverse already writes the complete zero-extended r32 result. */
        ft_emit_movbe_reverse(&out, ft_gpr(reg), value, width);
        return out - code;
    }
#endif
    ft_emit_movbe_reverse(&out, la_t2, value, width);
    if (width == 64) {
        FT_LA_OR_EMIT(&out, ft_gpr(reg), la_t2, la_zero);
    } else if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(reg), la_t2, 31, 0);
    } else {
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(reg), la_t2, 15, 0);
    }
    return (out - code);
}

static int ft_crc32_source_width(FastTemplateKind kind)
{
    switch (kind) {
    case FT_CRC32_R_RM8:
        return 8;
    case FT_CRC32_R_RM16:
        return 16;
    case FT_CRC32_R_RM32:
        return 32;
    case FT_CRC32_R_RM64:
        return 64;
    default:
        return 0;
    }
}

static int ft_emit_crc32_template(const FastTemplateFields *fields,
                                  TranslationBlock *tb, target_ulong pc,
                                  uint32_t *code)
{
    uint32_t *out = code;
    int width = ft_crc32_source_width(fields->kind);
    int dst = ft_modrm_reg_index(fields);
    int src;

    (void)tb;

    if (!width || dst >= GPR_NUM ||
        fields->prefix0 != dt_X86_PREFIX_REPNE) {
        return 0;
    }
    if ((width == 16 &&
         (ft_rex_w(fields) || fields->prefix2 != dt_X86_PREFIX_OPSIZE)) ||
        (width == 32 &&
         (ft_rex_w(fields) || fields->prefix2 == dt_X86_PREFIX_OPSIZE)) ||
        (width == 64 &&
         (!ft_rex_w(fields) || fields->prefix2 == dt_X86_PREFIX_OPSIZE)) ||
        (width == 8 && fields->prefix2 == dt_X86_PREFIX_OPSIZE)) {
        return 0;
    }

    switch (width) {
    case 8:
        if (!ft_emit_load_rm8(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_CRCC_W_B_W_EMIT(&out, ft_gpr(dst), src, ft_gpr(dst));
        break;
    case 16:
        if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_CRCC_W_H_W_EMIT(&out, ft_gpr(dst), src, ft_gpr(dst));
        break;
    case 32:
        if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_CRCC_W_W_W_EMIT(&out, ft_gpr(dst), src, ft_gpr(dst));
        break;
    case 64:
        if (!ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_CRCC_W_D_W_EMIT(&out, ft_gpr(dst), src, ft_gpr(dst));
        break;
    default:
        return 0;
    }
    FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    return out - code;
}

static int ft_emit_adx_template(const FastTemplateFields *fields,
                                TranslationBlock *tb, target_ulong pc,
                                uint32_t *code)
{
    uint32_t *out = code;
    int width;
    int dst = ft_modrm_reg_index(fields);
    int src;
    bool is_adox;

    (void)tb;

    switch (fields->kind) {
    case FT_ADCX_R32_RM32:
        width = 32;
        is_adox = false;
        break;
    case FT_ADCX_R64_RM64:
        width = 64;
        is_adox = false;
        break;
    case FT_ADOX_R32_RM32:
        width = 32;
        is_adox = true;
        break;
    case FT_ADOX_R64_RM64:
        width = 64;
        is_adox = true;
        break;
    default:
        return 0;
    }

    if (dst >= GPR_NUM || (width == 64) != ft_rex_w(fields) ||
        (is_adox && (fields->id != dt_X86_INS_ADOX ||
                     fields->prefix0 != dt_X86_PREFIX_REP ||
                     fields->prefix2 != 0)) ||
        (!is_adox && (fields->id != dt_X86_INS_ADCX ||
                      fields->prefix0 != 0 ||
                      fields->prefix2 != dt_X86_PREFIX_OPSIZE))) {
        return 0;
    }
    if (width == 64) {
        if (!ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
    } else if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
        return 0;
    }

    /* A memory source may live in t0, which holds saved flags below. */
    if (src == la_t0) {
        FT_LA_OR_EMIT(&out, la_t2, src, la_zero);
        src = la_t2;
    }
    FT_LA_X86MFFLAG_EMIT(&out, la_t0, 0x3f);
    FT_LA_BSTRPICK_D_EMIT(&out, la_t1, la_t0,
                          is_adox ? 11 : 0, is_adox ? 11 : 0);
    if (is_adox) {
        FT_LA_X86MTFLAG_EMIT(&out, la_t1, CF_USEDEF_BIT);
    }
    if (width == 64) {
        FT_LA_ADD_D_EMIT(&out, la_t3, ft_gpr(dst), src);
        FT_LA_ADD_D_EMIT(&out, la_t3, la_t3, la_t1);
        FT_LA_X86ADC_D_EMIT(&out, ft_gpr(dst), src);
        FT_LA_OR_EMIT(&out, ft_gpr(dst), la_t3, la_zero);
    } else {
        FT_LA_ADD_W_EMIT(&out, la_t3, ft_gpr(dst), src);
        FT_LA_ADD_W_EMIT(&out, la_t3, la_t3, la_t1);
        FT_LA_X86ADC_W_EMIT(&out, ft_gpr(dst), src);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), la_t3, 31, 0);
    }

    if (is_adox) {
        FT_LA_X86MFFLAG_EMIT(&out, la_t1, CF_USEDEF_BIT);
        FT_LA_BSTRINS_D_EMIT(&out, la_t0, la_t1, 11, 11);
        FT_LA_X86MTFLAG_EMIT(&out, la_t0, 0x3f);
    } else {
        FT_LA_X86MTFLAG_EMIT(&out, la_t0,
                             PF_USEDEF_BIT | AF_USEDEF_BIT | ZF_USEDEF_BIT |
                             SF_USEDEF_BIT | OF_USEDEF_BIT);
    }
    return out - code;
}

static int ft_emit_rdtsc_template(const FastTemplateFields *fields,
                                  TranslationBlock *tb, target_ulong pc,
                                  uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;

#ifdef CONFIG_SOFTMMU
    if (fields->kind != FT_RDTSC && fields->kind != FT_RDTSCP) {
        return 0;
    }

#if !defined(QUICKTRANS_LATU) && !defined(CONFIG_LATX_RR)
    if (option_opt_rdtsc_rdtscp) {
        /* Match the old LATS CONFIG_TSC_X25 scaling. */
        FT_LA_RDTIME_D_EMIT(&out, la_t2, la_t3);
        FT_LA_SLLI_D_EMIT(&out, la_t3, la_t2, 4);
        FT_LA_ADD_D_EMIT(&out, la_t3, la_t3, la_t2);
        FT_LA_SLLI_D_EMIT(&out, la_t2, la_t2, 3);
        FT_LA_ADD_D_EMIT(&out, la_t2, la_t2, la_t3);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(edx_index), la_t2, 63, 32);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(eax_index), la_t2, 31, 0);
    } else
#endif
    {
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        if (!ft_emit_lats_nofp_helper(&out, (void *)helper_rdtsc)) {
            ft_emit_helper_prologue(&out);
            ft_emit_cpu_env_ptr(&out, la_a0);
            ft_emit_host_call(&out, (void *)helper_rdtsc, 1u << 0);
            ft_emit_helper_epilogue(&out);
        }
    }
    if (fields->kind == FT_RDTSCP) {
        ft_emit_load_env(&out, ft_gpr(ecx_index),
                         offsetof(CPUX86State, tsc_aux),
                         FT_LA_OPCODE_LD_WU);
    }
#else
    (void)pc;

    switch (fields->kind) {
    case FT_RDTSC:
        FT_LA_RDTIME_D_EMIT(&out, la_t2, la_zero);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(edx_index), la_t2, 63, 32);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(eax_index), la_t2, 31, 0);
        break;
    case FT_RDTSCP:
        FT_LA_RDTIME_D_EMIT(&out, la_t2, la_t3);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(edx_index), la_t2, 63, 32);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(eax_index), la_t2, 31, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(ecx_index), la_t3, 31, 0);
        break;
    default:
        return 0;
    }
#endif

    return (out - code);
}

static int ft_emit_movnti_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int src = ft_modrm_reg_index(fields);

    (void)tb;

    if (src >= GPR_NUM || fields->modrm_mod == 3) {
        return 0;
    }

    if (ft_rex_w(fields)) {
        if (!ft_emit_store_rm64(&out, fields, pc, ft_gpr(src))) {
            return 0;
        }
    } else {
        if (!ft_emit_store_rm32(&out, fields, pc, ft_gpr(src), false)) {
            return 0;
        }
    }

    return (out - code);
}

static int ft_emit_movsxd_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int src;
    int width;

    switch (fields->kind) {
    case FT_MOVSXD_R64_RM32:
        width = 64;
        break;
    case FT_MOVSXD_R32_RM32:
        width = 32;
        break;
    case FT_MOVSXD_R16_RM16:
        width = 16;
        break;
    default:
        return 0;
    }

    if ((width == 64) != ft_rex_w(fields) ||
        (!ft_rex_w(fields) &&
         (width == 16) !=
             (fields->prefix2 == dt_X86_PREFIX_OPSIZE))) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    if (dst >= GPR_NUM) {
        return 0;
    }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    if (width == 64 && fields->modrm_mod != 3) {
        int addr;

        if (ft_rip_relative_mem(fields)) {
            target_ulong target = pc + fields->size + fields->disp;

            /* Keep the byte-load path and its delayed destination write. */
            if ((target & 3) == 0) {
                if (!ft_emit_guest_addr(&out, la_t1, target)) {
                    return 0;
                }
                FT_LA_LD_W_EMIT(&out, ft_gpr(dst), la_t1, 0);
                return out - code;
            }
        } else {
            if (!ft_emit_mem_addr(&out, fields, &addr)) {
                return 0;
            }
            /* LD.W already sign-extends the loaded dword to 64 bits. */
            FT_LA_LD_W_EMIT(&out, ft_gpr(dst), addr,
                             ft_mem_access_offset(fields, addr));
            return out - code;
        }
    }
#endif
    if (width == 16) {
        if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), src, 15, 0);
    } else {
        if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        if (width == 64) {
            FT_LA_ADDI_W_EMIT(&out, ft_gpr(dst), src, 0);
        } else {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), src, 31, 0);
        }
    }
    return (out - code);
}

static int ft_emit_movsx8_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int addr;
    bool is64 = fields->kind == FT_MOVSX_R64_RM8;
    bool is16 = fields->kind == FT_MOVSX_R16_RM8;

    if (is64 != ft_rex_w(fields) ||
        (is16 && fields->prefix2 != dt_X86_PREFIX_OPSIZE) ||
        (!is16 && !is64 &&
         fields->prefix2 == dt_X86_PREFIX_OPSIZE)) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    if (dst >= GPR_NUM) {
        return 0;
    }
    if (is16) {
        if (fields->modrm_mod == 3) {
            bool src_high8 = ft_modrm_rm_is_high8(fields);
            int src = src_high8 ? ft_modrm_rm_high8_base_index(fields) :
                                  ft_modrm_rm_index(fields);

            if (src >= GPR_NUM) {
                return 0;
            }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
            if (src_high8) {
                FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(src), 15, 8);
                FT_LA_EXT_W_B_EMIT(&out, la_t0, la_t0);
            } else {
                FT_LA_EXT_W_B_EMIT(&out, la_t0, ft_gpr(src));
            }
#else
            if (src_high8) {
                FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(src), 15, 8);
            } else {
                FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(src), 7, 0);
            }
            FT_LA_SLLI_D_EMIT(&out, la_t0, la_t0, 56);
            FT_LA_SRAI_D_EMIT(&out, la_t0, la_t0, 56);
#endif
        } else if (ft_rip_relative_mem(fields)) {
            target_ulong target = pc + fields->size + fields->disp;

            if (!ft_emit_guest_addr(&out, la_t0, target)) {
                return 0;
            }
            FT_LA_LD_B_EMIT(&out, la_t0, la_t0, 0);
        } else {
            if (!ft_emit_mem_addr(&out, fields, &addr)) {
                return 0;
            }
            FT_LA_LD_B_EMIT(&out, la_t0, addr,
                             ft_mem_access_offset(fields, addr));
        }
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
        return out - code;
    }
    if (fields->modrm_mod == 3) {
        int src;

        if (!ft_emit_load_rm8(&out, fields, pc, &src)) {
            return 0;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        FT_LA_EXT_W_B_EMIT(&out, ft_gpr(dst), src);
#else
        FT_LA_SLLI_D_EMIT(&out, ft_gpr(dst), src, 56);
        FT_LA_SRAI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 56);
#endif
    } else if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;

        if (!ft_emit_guest_addr(&out, la_t0, target)) {
            return 0;
        }
        FT_LA_LD_B_EMIT(&out, ft_gpr(dst), la_t0, 0);
    } else {
        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_LD_B_EMIT(&out, ft_gpr(dst), addr,
                         ft_mem_access_offset(fields, addr));
    }
#if !defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    FT_LA_OR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_zero);
#endif
    if (!is64) {
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }
    return (out - code);
}

static int ft_emit_movsx16_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int addr;
    bool is64 = fields->kind == FT_MOVSX_R64_RM16;
    bool is16 = fields->kind == FT_MOVSX_R16_RM16;

    if (is64 != ft_rex_w(fields) ||
        (is16 && fields->prefix2 != dt_X86_PREFIX_OPSIZE) ||
        (!is16 && !is64 &&
         fields->prefix2 == dt_X86_PREFIX_OPSIZE)) {
        return 0;
    }
    dst = ft_modrm_reg_index(fields);
    if (dst >= GPR_NUM) {
        return 0;
    }
    if (is16) {
        if (fields->modrm_mod == 3) {
            int src = ft_modrm_rm_index(fields);

            if (src >= GPR_NUM) {
                return 0;
            }
            FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(src), 15, 0);
        } else if (ft_rip_relative_mem(fields)) {
            target_ulong target = pc + fields->size + fields->disp;

            if (!ft_emit_guest_addr(&out, la_t0, target)) {
                return 0;
            }
            FT_LA_LD_H_EMIT(&out, la_t0, la_t0, 0);
        } else {
            if (!ft_emit_mem_addr(&out, fields, &addr)) {
                return 0;
            }
            FT_LA_LD_H_EMIT(&out, la_t0, addr,
                             ft_mem_access_offset(fields, addr));
        }
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
        return out - code;
    }
    if (fields->modrm_mod == 3) {
        int src = ft_modrm_rm_index(fields);

        if (src >= GPR_NUM) {
            return 0;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        FT_LA_EXT_W_H_EMIT(&out, ft_gpr(dst), ft_gpr(src));
#else
        FT_LA_SLLI_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 48);
        FT_LA_SRAI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 48);
#endif
    } else if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;

        if (!ft_emit_guest_addr(&out, la_t0, target)) {
            return 0;
        }
        FT_LA_LD_H_EMIT(&out, ft_gpr(dst), la_t0, 0);
    } else {
        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_LD_H_EMIT(&out, ft_gpr(dst), addr,
                         ft_mem_access_offset(fields, addr));
    }
#if !defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    FT_LA_OR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_zero);
#endif
    if (!is64) {
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }
    return (out - code);
}

static int ft_emit_movzx16_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    target_ulong target;
    int dst;

    dst = ft_modrm_reg_index(fields);
    if (dst >= GPR_NUM) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        int src = ft_modrm_rm_index(fields);

        if (src >= GPR_NUM) {
            return 0;
        }
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 15, 0);
    } else if (ft_rip_relative_mem(fields)) {
        target = pc + fields->size + fields->disp;
        if (!ft_emit_guest_addr(&out, la_t0, target)) {
            return 0;
        }
        FT_LA_LD_HU_EMIT(&out, ft_gpr(dst), la_t0, 0);
    } else {
        int addr;

        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        FT_LA_LD_HU_EMIT(&out, ft_gpr(dst), addr,
                          ft_mem_access_offset(fields, addr));
    }
    return (out - code);
}

static int ft_emit_movzx8_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    bool is16 = fields->kind == FT_MOVZX_R16_RM8;

    dst = ft_modrm_reg_index(fields);
    if (dst >= GPR_NUM) {
        return 0;
    }
    if (fields->modrm_mod == 3) {
        bool src_high8 = ft_modrm_rm_is_high8(fields);
        int src = src_high8 ? ft_modrm_rm_high8_base_index(fields) :
                              ft_modrm_rm_index(fields);

        if (src >= GPR_NUM) {
            return 0;
        }
        if (is16) {
            if (!src_high8 && src == dst) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_zero, 15, 8);
                return out - code;
            }
            if (src_high8) {
                FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(src), 15, 8);
            } else {
                FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(src), 7, 0);
            }
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
        } else if (src_high8) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 15, 8);
        } else {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 7, 0);
        }
        return (out - code);
    }

    {
        int addr;

        if (ft_rip_relative_mem(fields)) {
            target_ulong target = pc + fields->size + fields->disp;

            if (!ft_emit_guest_addr(&out, la_t0, target)) {
                return 0;
            }
            if (is16) {
                FT_LA_LD_BU_EMIT(&out, la_t0, la_t0, 0);
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
            } else {
                FT_LA_LD_BU_EMIT(&out, ft_gpr(dst), la_t0, 0);
            }
            return (out - code);
        }
        if (!ft_emit_mem_addr(&out, fields, &addr)) {
            return 0;
        }
        if (is16) {
            FT_LA_LD_BU_EMIT(&out, la_t0, addr,
                             ft_mem_access_offset(fields, addr));
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
        } else {
            FT_LA_LD_BU_EMIT(&out, ft_gpr(dst), addr,
                             ft_mem_access_offset(fields, addr));
        }
    }
    return (out - code);
}

static int ft_emit_sign_extend_acc_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    switch (fields->kind) {
    case FT_CDQE:
        if (!ft_rex_w(fields)) {
            return 0;
        }
        FT_LA_ADDI_W_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index), 0);
        break;
    case FT_CQO:
        if (!ft_rex_w(fields)) {
            return 0;
        }
        FT_LA_SRAI_D_EMIT(&out, ft_gpr(rdx_index), ft_gpr(rax_index), 63);
        break;
    case FT_CBW:
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        FT_LA_EXT_W_B_EMIT(&out, la_t0, ft_gpr(rax_index));
#else
        FT_LA_SLLI_D_EMIT(&out, la_t0, ft_gpr(rax_index), 56);
        FT_LA_SRAI_D_EMIT(&out, la_t0, la_t0, 56);
#endif
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t0, 15, 0);
        break;
    case FT_CWDE:
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        FT_LA_EXT_W_H_EMIT(&out, la_t0, ft_gpr(rax_index));
#else
        FT_LA_SLLI_D_EMIT(&out, la_t0, ft_gpr(rax_index), 48);
        FT_LA_SRAI_D_EMIT(&out, la_t0, la_t0, 48);
#endif
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), la_t0, 31, 0);
        break;
    case FT_CWD:
        FT_LA_SLLI_D_EMIT(&out, la_t0, ft_gpr(rax_index), 48);
        FT_LA_SRAI_D_EMIT(&out, la_t0, la_t0, 63);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rdx_index), la_t0, 15, 0);
        break;
    case FT_CDQ:
        FT_LA_SRAI_W_EMIT(&out, ft_gpr(rdx_index),
                          ft_gpr(rax_index), 31);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rdx_index),
                              ft_gpr(rdx_index), 31, 0);
        break;
    default:
        return 0;
    }
    return (out - code);
}

static int ft_emit_xlat_template(const FastTemplateFields *fields,
                                 TranslationBlock *tb, target_ulong pc,
                                 uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    (void)pc;

    if (fields->prefix0 != 0 ||
        (fields->prefix2 != 0 && fields->prefix2 != dt_X86_PREFIX_OPSIZE) ||
        fields->segment >= 0) {
        return 0;
    }

    FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(rax_index), 7, 0);
    if (fields->addr32) {
        FT_LA_ADD_D_EMIT(&out, la_t0, ft_gpr(rbx_index), la_t0);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, la_t0, 31, 0);
        FT_LA_LD_BU_EMIT(&out, la_t0, la_t0, 0);
    } else {
        FT_LA_LDX_BU_EMIT(&out, la_t0, ft_gpr(rbx_index), la_t0);
    }
    FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t0, 7, 0);
    return (out - code);
}

static int ft_emit_xchg_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    switch (fields->kind) {
    case FT_XCHG_RM64_R64:
    case FT_XCHG_RM32_R32:
    {
        int dst;
        int src;
        bool is64 = fields->kind == FT_XCHG_RM64_R64;
        bool is16 = !is64 && fields->prefix2 == dt_X86_PREFIX_OPSIZE;

        if (is64 != ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            dst = ft_modrm_rm_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_OR_EMIT(&out, la_t1, ft_gpr(dst), la_zero);
            if (is16) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 15, 0);
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(src), la_t1, 15, 0);
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
            } else if (!is64) {
                FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 31, 0);
                FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(src), la_t1, 31, 0);
#endif
            } else {
                FT_LA_OR_EMIT(&out, ft_gpr(dst), ft_gpr(src), la_zero);
                if (!is64) {
                    FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst),
                                          ft_gpr(dst), 31, 0);
                    FT_LA_OR_EMIT(&out, ft_gpr(src), la_t1, la_zero);
                    FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(src),
                                          ft_gpr(src), 31, 0);
                } else {
                    FT_LA_OR_EMIT(&out, ft_gpr(src), la_t1, la_zero);
                }
            }
        } else {
            int addr;

            if (!ft_emit_rmw_addr(&out, fields, pc, &addr, la_t4)) {
                return 0;
            }
            ft_preserve_cmpxchg_addr(&out, &addr);
            if (is64) {
                FT_LA_AMSWAP_DB_D_EMIT(&out, la_t1, ft_gpr(src), addr);
                FT_LA_OR_EMIT(&out, ft_gpr(src), la_t1, la_zero);
            } else if (is16) {
                FT_LA_BSTRPICK_D_EMIT(&out, la_t2, ft_gpr(src), 15, 0);
                FT_LA_AMSWAP_DB_H_EMIT(&out, la_t1, la_t2, addr);
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(src), la_t1, 15, 0);
            } else {
                FT_LA_AMSWAP_DB_W_EMIT(&out, la_t1, ft_gpr(src), addr);
                FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(src), la_t1, 31, 0);
            }
        }
        break;
    }
    case FT_XCHG_RM8_R8:
    {
        int addr;
        int src_reg;
        int src_val;
        int dst_val;

        if (ft_rex_w(fields)) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            if (!ft_emit_load_rm8(&out, fields, pc, &dst_val)) {
                return 0;
            }
            FT_LA_OR_EMIT(&out, la_t2, dst_val, la_zero);
            if (ft_modrm_reg_is_high8(fields)) {
                src_reg = ft_modrm_reg_high8_base_index(fields);
                if (src_reg >= GPR_NUM) {
                    return 0;
                }
                FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(src_reg), 8);
            } else {
                src_reg = ft_modrm_reg_index(fields);
                if (src_reg >= GPR_NUM) {
                    return 0;
                }
                FT_LA_OR_EMIT(&out, la_t1, ft_gpr(src_reg), la_zero);
            }
            if (!ft_emit_store_rm8(&out, fields, pc, la_t1)) {
                return 0;
            }
            if (ft_modrm_reg_is_high8(fields)) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(src_reg), la_t2, 15, 8);
            } else {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(src_reg), la_t2, 7, 0);
            }
            break;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            src_reg = ft_modrm_reg_high8_base_index(fields);
            if (src_reg >= GPR_NUM) {
                return 0;
            }
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(src_reg), 8);
        } else {
            src_reg = ft_modrm_reg_index(fields);
            if (src_reg >= GPR_NUM) {
                return 0;
            }
            FT_LA_OR_EMIT(&out, la_t1, ft_gpr(src_reg), la_zero);
        }
        FT_LA_ANDI_EMIT(&out, la_t2, la_t1, 0xff);
        src_val = la_t2;
        if (!ft_emit_rmw_addr(&out, fields, pc, &addr, la_t4)) {
            return 0;
        }
        ft_preserve_cmpxchg_addr(&out, &addr);
        FT_LA_AMSWAP_DB_B_EMIT(&out, la_t1, src_val, addr);
        if (ft_modrm_reg_is_high8(fields)) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(src_reg), la_t1, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(src_reg), la_t1, 7, 0);
        }
        break;
    }
    case FT_XCHG_R64_RAX:
    case FT_XCHG_R32_EAX:
    {
        int reg;

        if ((fields->kind == FT_XCHG_R64_RAX) != ft_rex_w(fields)) {
            return 0;
        }
        reg = ft_rex_base_from_opcode(fields->rex, fields->opcode0);
        if (reg <= 0 || reg >= GPR_NUM) {
            return 0;
        }
        FT_LA_OR_EMIT(&out, la_t1, ft_gpr(reg), la_zero);
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (!ft_rex_w(fields)) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(reg), ft_gpr(rax_index), 31, 0);
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), la_t1, 31, 0);
            break;
        }
#endif
        FT_LA_OR_EMIT(&out, ft_gpr(reg), ft_gpr(rax_index), la_zero);
        if (!ft_rex_w(fields)) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(reg),
                                  ft_gpr(reg), 31, 0);
        }
        FT_LA_OR_EMIT(&out, ft_gpr(rax_index), la_t1, la_zero);
        if (!ft_rex_w(fields)) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index),
                                  ft_gpr(rax_index), 31, 0);
        }
        break;
    }
    case FT_XCHG_R16_AX:
    {
        int reg = ft_rex_base_from_opcode(fields->rex, fields->opcode0);

        if (ft_rex_w(fields) || reg <= 0 || reg >= GPR_NUM) {
            return 0;
        }
        FT_LA_OR_EMIT(&out, la_t1, ft_gpr(rax_index), la_zero);
        FT_LA_OR_EMIT(&out, la_t2, ft_gpr(reg), la_zero);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 15, 0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(reg), la_t1, 15, 0);
        break;
    }
    default:
        return 0;
    }

    return (out - code);
}

static int ft_emit_not_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;

    if ((fields->kind == FT_NOT_RM64) != ft_rex_w(fields) ||
        fields->modrm_reg != 2) {
        return 0;
    }

    if (fields->prefix0 == dt_X86_PREFIX_LOCK) {
        FastBranchLabel retry = { 0 };
        FastBranchLabel done = { 0 };
        FastBranchFixup retry_fixup;
        FastBranchFixup done_fixup;
        int width = fields->kind == FT_NOT_RM64 ? 64 :
                    fields->kind == FT_NOT_RM32 ? 32 :
                    fields->kind == FT_NOT_RM16 ? 16 : 8;
        int addr;
        int old;

        if (fields->modrm_mod == 3 ||
            !ft_emit_rmw_addr(&out, fields, pc, &addr, la_t4)) {
            return 0;
        }
        ft_preserve_cmpxchg_addr(&out, &addr);
        if (width == 32 || width == 64) {
            FT_LA_ADDI_D_EMIT(&out, la_t2, la_zero, -1);
            ft_emit_raw(&out,
                        ft_gpr3(width == 64 ? FT_LA_OPCODE_AMXOR_DB_D :
                                              FT_LA_OPCODE_AMXOR_DB_W,
                                addr == la_t0 ? la_t1 : la_t0,
                                addr, la_t2));
            return out - code;
        }

        old = addr == la_t0 ? la_t3 : la_t0;
        if (width == 8) {
            FT_LA_LD_BU_EMIT(&out, old, addr, 0);
        } else {
            FT_LA_LD_HU_EMIT(&out, old, addr, 0);
        }
        ft_bind_branch_label(&retry, out);
        FT_LA_NOR_EMIT(&out, la_t2, old, la_zero);
        FT_LA_OR_EMIT(&out, la_t1, old, la_zero);
        ft_emit_raw(&out,
                    ft_gpr3(width == 8 ? FT_LA_OPCODE_AMCAS_DB_B :
                                         FT_LA_OPCODE_AMCAS_DB_H,
                            la_t1, addr, la_t2));
        ft_emit_zero_extend_atomic_old(&out, la_t1, width);
        ft_emit_branch_placeholder(&out, &done_fixup, FT_BRANCH_BEQ,
                                   la_t1, old, &done);
        FT_LA_OR_EMIT(&out, old, la_t1, la_zero);
        ft_emit_branch_placeholder(&out, &retry_fixup, FT_BRANCH_B,
                                   0, 0, &retry);
        ft_bind_branch_label(&done, out);
        ft_resolve_branch_fixup(&done_fixup);
        ft_resolve_branch_fixup(&retry_fixup);
        return out - code;
    }

    switch (fields->kind) {
    case FT_NOT_RM8:
        if (!ft_emit_load_rm8(&out, fields, pc, &dst)) {
            return 0;
        }
        FT_LA_NOR_EMIT(&out, la_t2, dst, la_zero);
        if (!ft_emit_store_rm8(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    case FT_NOT_RM16:
        if (!ft_emit_load_rm16(&out, fields, pc, &dst)) {
            return 0;
        }
        FT_LA_NOR_EMIT(&out, la_t2, dst, la_zero);
        if (!ft_emit_store_rm16(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    case FT_NOT_RM32:
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (fields->modrm_mod == 3) {
            dst = ft_modrm_rm_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_NOR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_zero);
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
            break;
        }
#endif
        if (!ft_emit_load_rm32(&out, fields, pc, &dst)) {
            return 0;
        }
        FT_LA_NOR_EMIT(&out, la_t2, dst, la_zero);
        if (!ft_emit_store_rm32(&out, fields, pc, la_t2, true)) {
            return 0;
        }
        break;
    case FT_NOT_RM64:
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (fields->modrm_mod == 3) {
            dst = ft_modrm_rm_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_NOR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_zero);
            break;
        }
#endif
        if (!ft_emit_load_rm64(&out, fields, pc, &dst)) {
            return 0;
        }
        FT_LA_NOR_EMIT(&out, la_t2, dst, la_zero);
        if (!ft_emit_store_rm64(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    default:
        return 0;
    }

    return (out - code);
}

static int ft_emit_neg_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int src;

    if (fields->prefix0 == dt_X86_PREFIX_LOCK) {
        FastBranchLabel retry = { 0 };
        FastBranchLabel done = { 0 };
        FastBranchFixup retry_fixup;
        FastBranchFixup done_fixup;
        int width = fields->kind == FT_NEG_RM64 ? 64 :
                    fields->kind == FT_NEG_RM32 ? 32 :
                    fields->kind == FT_NEG_RM16 ? 16 :
                    fields->kind == FT_NEG_RM8 ? 8 : 0;
        uint32_t flag_op = width == 64 ? FT_LA_OPCODE_X86SUB_D :
                           width == 32 ? FT_LA_OPCODE_X86SUB_W :
                           width == 16 ? FT_LA_OPCODE_X86SUB_H :
                                         FT_LA_OPCODE_X86SUB_B;
        uint32_t cas_op = width == 64 ? FT_LA_OPCODE_AMCAS_DB_D :
                          width == 32 ? FT_LA_OPCODE_AMCAS_DB_W :
                          width == 16 ? FT_LA_OPCODE_AMCAS_DB_H :
                                        FT_LA_OPCODE_AMCAS_DB_B;
        int addr;
        int old;

        if (!width || (width == 64) != ft_rex_w(fields) ||
            fields->modrm_reg != 3 || fields->modrm_mod == 3 ||
            !ft_emit_rmw_addr(&out, fields, pc, &addr, la_t4)) {
            return 0;
        }
        ft_preserve_cmpxchg_addr(&out, &addr);
        old = addr == la_t0 ? la_t3 : la_t0;
        if (width == 64) {
            FT_LA_LD_D_EMIT(&out, old, addr, 0);
        } else if (width == 32) {
            FT_LA_LD_WU_EMIT(&out, old, addr, 0);
        } else if (width == 16) {
            FT_LA_LD_HU_EMIT(&out, old, addr, 0);
        } else {
            FT_LA_LD_BU_EMIT(&out, old, addr, 0);
        }
        ft_bind_branch_label(&retry, out);
        ft_emit_raw(&out,
                    ft_gpr3(width == 64 ? FT_LA_OPCODE_SUB_D :
                                          FT_LA_OPCODE_SUB_W,
                            la_t2, la_zero, old));
        FT_LA_OR_EMIT(&out, la_t1, old, la_zero);
        ft_emit_raw(&out, ft_gpr3(cas_op, la_t1, addr, la_t2));
        ft_emit_zero_extend_atomic_old(&out, la_t1, width);
        ft_emit_branch_placeholder(&out, &done_fixup, FT_BRANCH_BEQ,
                                   la_t1, old, &done);
        FT_LA_OR_EMIT(&out, old, la_t1, la_zero);
        ft_emit_branch_placeholder(&out, &retry_fixup, FT_BRANCH_B,
                                   0, 0, &retry);
        ft_bind_branch_label(&done, out);
        ft_resolve_branch_fixup(&done_fixup);
        ft_resolve_branch_fixup(&retry_fixup);
        if (!fields->skip_flags) {
            ft_emit_raw(&out, ft_gpr2(flag_op, la_zero, old));
        }
        return out - code;
    }

    switch (fields->kind) {
    case FT_NEG_RM64:
        if (!ft_rex_w(fields) || fields->modrm_reg != 3 ||
            !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

            /* The flag-only X86SUB accepts zero as its left operand, as in
             * the LOCK path above. Read the source before writing dst. */
            FT_FLAG2(FT_LA_OPCODE_X86SUB_D, la_zero, src);
            FT_LA_SUB_D_EMIT(&out, ft_gpr(dst), la_zero, src);
            break;
        }
#endif
        FT_LA_OR_EMIT(&out, la_t1, la_zero, la_zero);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, la_t1, src);
        FT_LA_SUB_D_EMIT(&out, la_t2, la_zero, src);
        if (!ft_emit_store_rm64(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    case FT_NEG_RM32:
        if (ft_rex_w(fields) || fields->modrm_reg != 3 ||
            !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

            /* The flag-only X86SUB accepts zero as its left operand, as in
             * the LOCK path above. Read the source before writing dst. */
            FT_FLAG2(FT_LA_OPCODE_X86SUB_W, la_zero, src);
            FT_LA_SUB_W_EMIT(&out, ft_gpr(dst), la_zero, src);
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
            break;
        }
#endif
        FT_LA_OR_EMIT(&out, la_t1, la_zero, la_zero);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_W, la_t1, src);
        FT_LA_SUB_W_EMIT(&out, la_t2, la_zero, src);
        if (!ft_emit_store_rm32(&out, fields, pc, la_t2, true)) {
            return 0;
        }
        break;
    case FT_NEG_RM16:
        if (ft_rex_w(fields) || fields->modrm_reg != 3 ||
            !ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_OR_EMIT(&out, la_t1, la_zero, la_zero);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_H, la_t1, src);
        FT_LA_SUB_W_EMIT(&out, la_t2, la_zero, src);
        if (!ft_emit_store_rm16(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    case FT_NEG_RM8:
        if (ft_rex_w(fields) || fields->modrm_reg != 3 ||
            !ft_emit_load_rm8(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_OR_EMIT(&out, la_t1, la_zero, la_zero);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_B, la_t1, src);
        FT_LA_SUB_W_EMIT(&out, la_t2, la_zero, src);
        if (!ft_emit_store_rm8(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    default:
        return 0;
    }

    return (out - code);
}

static int ft_emit_inc_dec_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    bool is_inc;
    bool is_64;
    bool is_16;

    switch (fields->kind) {
    case FT_INC_RM32:
    case FT_DEC_RM32:
    case FT_INC_RM64:
    case FT_DEC_RM64:
    case FT_INC_RM16:
    case FT_DEC_RM16:
        is_inc = fields->kind == FT_INC_RM32 ||
                 fields->kind == FT_INC_RM64 ||
                 fields->kind == FT_INC_RM16;
        is_64 = fields->kind == FT_INC_RM64 ||
                fields->kind == FT_DEC_RM64;
        is_16 = fields->kind == FT_INC_RM16 ||
                fields->kind == FT_DEC_RM16;

        if (ft_rex_w(fields) != is_64 ||
            fields->modrm_reg != (is_inc ? 0 : 1)) {
            return 0;
        }
        if (fields->prefix0 == dt_X86_PREFIX_LOCK) {
            int addr;
            uint32_t atomic_op = is_64 ? FT_LA_OPCODE_AMADD_DB_D :
                                 is_16 ? FT_LA_OPCODE_AMADD_DB_H :
                                         FT_LA_OPCODE_AMADD_DB_W;

            if (fields->modrm_mod == 3 ||
                !ft_emit_rmw_addr(&out, fields, pc, &addr, la_t4)) {
                return 0;
            }
            ft_preserve_cmpxchg_addr(&out, &addr);
            FT_LA_ADDI_D_EMIT(&out, la_t2, la_zero, is_inc ? 1 : -1);
            ft_emit_raw(&out, ft_gpr3(atomic_op, la_t1, addr, la_t2));
            if (!fields->skip_flags) {
                ft_emit_raw(&out,
                            ft_gpr2(is_inc ?
                                    (is_64 ? FT_LA_OPCODE_X86INC_D :
                                     is_16 ? FT_LA_OPCODE_X86INC_H :
                                             FT_LA_OPCODE_X86INC_W) :
                                    (is_64 ? FT_LA_OPCODE_X86DEC_D :
                                     is_16 ? FT_LA_OPCODE_X86DEC_H :
                                             FT_LA_OPCODE_X86DEC_W),
                                    la_t1, la_zero));
            }
            break;
        }
        if (!(is_64 ? ft_emit_load_rm64(&out, fields, pc, &dst) :
              is_16 ? ft_emit_load_rm16(&out, fields, pc, &dst) :
                      ft_emit_load_rm32(&out, fields, pc, &dst))) {
            return 0;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (fields->modrm_mod == 3 && !is_16) {
            /* INC/DEC preserve CF. skip_flags only drops their dead defs. */
            if (!fields->skip_flags) {
                ft_emit_raw(&out,
                            ft_gpr2(is_inc ? (is_64 ? FT_LA_OPCODE_X86INC_D :
                                                     FT_LA_OPCODE_X86INC_W) :
                                            (is_64 ? FT_LA_OPCODE_X86DEC_D :
                                                     FT_LA_OPCODE_X86DEC_W),
                                    dst, la_zero));
            }
            ft_emit_raw(&out,
                        ft_gpr3_imm12(is_64 ? FT_LA_OPCODE_ADDI_D :
                                              FT_LA_OPCODE_ADDI_W,
                                      dst, dst, is_inc ? 1 : -1));
            if (!is_64) {
                FT_LA_BSTRPICK_D_EMIT(&out, dst, dst, 31, 0);
            }
            break;
        }
#endif
        ft_emit_raw(&out,
                    ft_gpr2(is_inc ? (is_64 ? FT_LA_OPCODE_X86INC_D :
                                      is_16 ? FT_LA_OPCODE_X86INC_H :
                                              FT_LA_OPCODE_X86INC_W) :
                                     (is_64 ? FT_LA_OPCODE_X86DEC_D :
                                      is_16 ? FT_LA_OPCODE_X86DEC_H :
                                              FT_LA_OPCODE_X86DEC_W),
                            dst, la_zero));
        if (is_16) {
            FT_LA_ADDI_W_EMIT(&out, la_t2, dst, is_inc ? 1 : -1);
            if (!ft_emit_store_rm16(&out, fields, pc, la_t2)) {
                return 0;
            }
            break;
        }
        ft_emit_raw(&out,
                    ft_gpr3_imm12(is_64 ? FT_LA_OPCODE_ADDI_D :
                                          FT_LA_OPCODE_ADDI_W,
                                  dst, dst, is_inc ? 1 : -1));
        if (!(is_64 ? ft_emit_store_rm64(&out, fields, pc, dst) :
                      ft_emit_store_rm32(&out, fields, pc, dst, true))) {
            return 0;
        }
        break;
    case FT_INC_RM8:
    case FT_DEC_RM8:
        is_inc = fields->kind == FT_INC_RM8;

        if (ft_rex_w(fields) ||
            fields->modrm_reg != (is_inc ? 0 : 1)) {
            return 0;
        }
        if (fields->prefix0 == dt_X86_PREFIX_LOCK) {
            int addr;

            if (fields->modrm_mod == 3 ||
                !ft_emit_rmw_addr(&out, fields, pc, &addr, la_t4)) {
                return 0;
            }
            ft_preserve_cmpxchg_addr(&out, &addr);
            FT_LA_ADDI_D_EMIT(&out, la_t2, la_zero, is_inc ? 1 : -1);
            FT_LA_AMADD_DB_B_EMIT(&out, la_t1, la_t2, addr);
            if (!fields->skip_flags) {
                ft_emit_raw(&out,
                            ft_gpr2(is_inc ? FT_LA_OPCODE_X86INC_B :
                                             FT_LA_OPCODE_X86DEC_B,
                                    la_t1, la_zero));
            }
            break;
        }
        if (!ft_emit_load_rm8(&out, fields, pc, &dst)) {
            return 0;
        }
        ft_emit_raw(&out,
                    ft_gpr2(is_inc ? FT_LA_OPCODE_X86INC_B :
                                     FT_LA_OPCODE_X86DEC_B,
                            dst, la_zero));
        FT_LA_ADDI_W_EMIT(&out, la_t2, dst, is_inc ? 1 : -1);
        if (!ft_emit_store_rm8(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    default:
        return 0;
    }

    return (out - code);
}

static int ft_emit_load_far_pointer_template(const FastTemplateFields *fields,
                                             TranslationBlock *tb,
                                             target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int addr;
    int dst = ft_modrm_reg_index(fields);
    int width = fields->alu_width;
    int seg = fields->kind == FT_LDS ? ds_index : es_index;

    (void)tb;
    if (dst < 0 || dst >= GPR_NUM || fields->modrm_mod == 3 ||
        !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
        return 0;
    }
    int off = ft_mem_access_offset(fields, addr);
    if (width == 16) {
        FT_LA_LD_HU_EMIT(&out, la_t0, addr, off);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
    } else {
        FT_LA_LD_WU_EMIT(&out, ft_gpr(dst), addr, off);
    }
    ft_emit_helper_prologue(&out);
    if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
        return 0;
    }
    off = ft_mem_access_offset(fields, addr);
    ft_emit_cpu_env_ptr(&out, la_a0);
    FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, seg);
    FT_LA_LD_HU_EMIT(&out, la_a2, addr, off + width / 8);
    ft_emit_host_call(&out, (void *)helper_load_seg, 1u << 0);
    ft_emit_helper_epilogue(&out);
    ft_emit_li64(&out, la_t0, pc + fields->size);
    return ft_emit_helper_indirect_exit(&out, tb, code, la_t0, false);
}
