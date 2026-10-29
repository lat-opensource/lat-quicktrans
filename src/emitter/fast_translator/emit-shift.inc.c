/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

static int ft_shift_width(const FastTemplateFields *fields)
{
    if (fields->opcode0 == 0xc0 || fields->opcode0 == 0xd0 ||
        fields->opcode0 == 0xd2) {
        return 8;
    }
    if (ft_rex_w(fields)) {
        return 64;
    }
    return fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;
}

static uint32_t ft_rcl_rcr_x86_op(bool is_rcl, int width)
{
    if (is_rcl) {
        switch (width) {
        case 8:
            return FT_LA_OPCODE_X86RCL_B;
        case 16:
            return FT_LA_OPCODE_X86RCL_H;
        case 32:
            return FT_LA_OPCODE_X86RCL_W;
        case 64:
            return FT_LA_OPCODE_X86RCL_D;
        default:
            return 0;
        }
    }

    switch (width) {
    case 8:
        return FT_LA_OPCODE_X86RCR_B;
    case 16:
        return FT_LA_OPCODE_X86RCR_H;
    case 32:
        return FT_LA_OPCODE_X86RCR_W;
    case 64:
        return FT_LA_OPCODE_X86RCR_D;
    default:
        return 0;
    }
}

static void ft_emit_store_shift_reg(uint32_t **out, int dst, int value,
                                    int width, bool high8)
{
    if (width == 8) {
        if (high8) {
            FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst), value, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst), value, 7, 0);
        }
    } else if (width == 16) {
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst), value, 15, 0);
    } else if (width == 32) {
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(dst), value, 31, 0);
    } else {
        FT_LA_OR_EMIT(out, ft_gpr(dst), value, la_zero);
    }
}

static void ft_emit_shift_imm_flags(uint32_t **out,
                                    const FastTemplateFields *fields,
                                    uint32_t imm_op, uint32_t reg_op,
                                    int src, int width, int count)
{
    if (fields->skip_flags) {
        return;
    }

    if ((width == 8 && count >= 8) || (width == 16 && count >= 16)) {
        /* x86SLLI/SLRI/SRAI B/H cannot encode this count. */
        FT_LA_ADDI_D_EMIT(out, la_t1, la_zero, count);
        ft_emit_raw(out, ft_gpr2(reg_op, src, la_t1));
    } else {
        ft_emit_raw(out, ft_gpr1_imm(imm_op, src, count));
    }
}

static int ft_emit_rcl_rcr_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int ext = (fields->modrm >> 3) & 7;
    bool is_rcl = ext == 2;
    bool is_cl = fields->kind == FT_SHIFT_RM_CL;
    int width = ft_shift_width(fields);
    int mask = width == 64 ? 63 : 31;
    int ring = width + 1;
    int dst = -1;
    int src;
    int result = la_t0;
    int count_reg = la_t3;
    uint32_t *count_zero_branch = NULL;
    uint32_t x86_op = ft_rcl_rcr_x86_op(is_rcl, width);
    bool high8 = false;
    bool is_mem = fields->modrm_mod != 3;

    if ((ext != 2 && ext != 3) || !x86_op) {
        return 0;
    }

    if (is_mem) {
        switch (width) {
        case 8:
            if (!ft_emit_load_rm8(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        case 16:
            if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        case 32:
            if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        case 64:
            if (!ft_emit_load_rm64(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        default:
            return 0;
        }
    } else {
        dst = ft_modrm_rm_index(fields);
        if (width == 8 && ft_modrm_rm_is_high8(fields)) {
            dst = ft_modrm_rm_high8_base_index(fields);
            high8 = true;
        }
        if (dst < 0 || dst >= GPR_NUM) {
            return 0;
        }

        src = ft_gpr(dst);
        if (width == 8 && high8) {
            FT_LA_SRLI_D_EMIT(&out, la_t0, ft_gpr(dst), 8);
            src = la_t0;
        }
    }

    if (is_cl) {
        FT_LA_BSTRPICK_D_EMIT(&out, count_reg, ft_gpr(rcx_index), 7, 0);
        FT_LA_ANDI_EMIT(&out, count_reg, count_reg, mask);
        if (width < 32) {
            FT_LA_ORI_EMIT(&out, la_t4, la_zero, ring);
            FT_LA_MOD_DU_EMIT(&out, count_reg, count_reg, la_t4);
        }
        if (!is_mem && width == 32) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        }
        count_zero_branch = out;
        FT_LA_BEQ_EMIT(&out, count_reg, la_zero, 0);
    } else {
        int count = fields->kind == FT_SHIFT_RM_ONE ? 1 :
                    fields->imm & mask;

        if (width < 32) {
            count %= ring;
        }
        if (count == 0) {
            /* A zero-count r32 rotate still zero-extends its register write. */
            if (!is_mem && width == 32) {
                FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                      31, 0);
            }
            FT_LA_OR_EMIT(&out, la_zero, la_zero, la_zero);
            return (out - code);
        }
        FT_LA_ORI_EMIT(&out, count_reg, la_zero, count);
    }

    if (width == 64) {
        FT_LA_OR_EMIT(&out, la_t2, src, la_zero);
    } else {
        FT_LA_BSTRPICK_D_EMIT(&out, la_t2, src, width - 1, 0);
    }
    FT_LA_X86MFFLAG_EMIT(&out, la_t1, CF_USEDEF_BIT);
    FT_LA_ANDI_EMIT(&out, la_t1, la_t1, 1);
    FT_FLAG2(x86_op, src, count_reg);

    if (width == 64) {
        if (is_rcl) {
            FT_LA_SLL_D_EMIT(&out, result, la_t2, count_reg);
            FT_LA_ADDI_D_EMIT(&out, la_t4, count_reg, -1);
            FT_LA_SLL_D_EMIT(&out, la_t1, la_t1, la_t4);
            FT_LA_OR_EMIT(&out, result, result, la_t1);
            FT_LA_BEQ_EMIT(&out, la_t4, la_zero, 4);
            FT_LA_ORI_EMIT(&out, la_t4, la_zero, 65);
            FT_LA_SUB_D_EMIT(&out, la_t4, la_t4, count_reg);
            FT_LA_SRL_D_EMIT(&out, la_t4, la_t2, la_t4);
            FT_LA_OR_EMIT(&out, result, result, la_t4);
        } else {
            FT_LA_SRL_D_EMIT(&out, result, la_t2, count_reg);
            FT_LA_ORI_EMIT(&out, la_t4, la_zero, 64);
            FT_LA_SUB_D_EMIT(&out, la_t4, la_t4, count_reg);
            FT_LA_SLL_D_EMIT(&out, la_t1, la_t1, la_t4);
            FT_LA_OR_EMIT(&out, result, result, la_t1);
            FT_LA_ADDI_D_EMIT(&out, la_t4, count_reg, -1);
            FT_LA_BEQ_EMIT(&out, la_t4, la_zero, 4);
            FT_LA_ORI_EMIT(&out, la_t4, la_zero, 65);
            FT_LA_SUB_D_EMIT(&out, la_t4, la_t4, count_reg);
            FT_LA_SLL_D_EMIT(&out, la_t4, la_t2, la_t4);
            FT_LA_OR_EMIT(&out, result, result, la_t4);
        }
    } else {
        FT_LA_SLLI_D_EMIT(&out, la_t1, la_t1, width);
        FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t1);
        FT_LA_ORI_EMIT(&out, la_t4, la_zero, ring);
        FT_LA_SUB_D_EMIT(&out, la_t4, la_t4, count_reg);
        if (is_rcl) {
            FT_LA_SLL_D_EMIT(&out, result, la_t2, count_reg);
            FT_LA_SRL_D_EMIT(&out, la_t4, la_t2, la_t4);
        } else {
            FT_LA_SRL_D_EMIT(&out, result, la_t2, count_reg);
            FT_LA_SLL_D_EMIT(&out, la_t4, la_t2, la_t4);
        }
        FT_LA_OR_EMIT(&out, result, result, la_t4);
    }

    if (is_mem) {
        switch (width) {
        case 8:
            if (!ft_emit_store_rm8(&out, fields, pc, result)) {
                return 0;
            }
            break;
        case 16:
            if (!ft_emit_store_rm16(&out, fields, pc, result)) {
                return 0;
            }
            break;
        case 32:
            if (!ft_emit_store_rm32(&out, fields, pc, result, false)) {
                return 0;
            }
            break;
        case 64:
            if (!ft_emit_store_rm64(&out, fields, pc, result)) {
                return 0;
            }
            break;
        default:
            return 0;
        }
    } else {
        ft_emit_store_shift_reg(&out, dst, result, width, high8);
    }
    if (count_zero_branch) {
        *count_zero_branch = FT_LA_BEQ(count_reg, la_zero,
                                       out - count_zero_branch);
    }
    return (out - code);
}

static int ft_emit_shift_imm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int ext = (fields->modrm >> 3) & 7;
    int count_mask = ft_rex_w(fields) ? 63 : 31;
    int count = fields->kind == FT_SHIFT_RM_ONE ? 1 :
                fields->imm & count_mask;

    if (ext == 2 || ext == 3) {
        return ft_emit_rcl_rcr_template(fields, tb, pc, code);
    }
    if (ext == 6) {
        ext = 4;
    }

    /* A zero-count r32 write still clears the destination's upper half. */
    if (count == 0) {
        bool is_r32 = fields->opcode0 != 0xc0 &&
                      fields->opcode0 != 0xd0 &&
                      !ft_rex_w(fields) &&
                      fields->prefix2 != dt_X86_PREFIX_OPSIZE;

        if (fields->modrm_mod == 3 && is_r32) {
            dst = ft_modrm_rm_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        } else {
            FT_LA_ORI_EMIT(&out, la_zero, la_zero, 0);
        }
        return (out - code);
    }

    if (fields->modrm_mod != 3) {
        int width = (fields->opcode0 == 0xc0 ||
                     fields->opcode0 == 0xd0) ? 8 :
                    ft_rex_w(fields) ? 64 :
                    fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;
        int src;
        int result = la_t2;
        uint32_t x86_op;
        uint32_t x86_reg_op;
        uint32_t data_op;

        switch (width) {
        case 8:
            if (!ft_emit_load_rm8(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        case 16:
            if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        case 32:
            if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        case 64:
            if (!ft_emit_load_rm64(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        default:
            return 0;
        }
        switch (ext) {
        case 0:
        case 1:
        {
            int rotate_count = count;

            if (width < 64) {
                rotate_count %= width;
            }
            switch (width) {
            case 8:
                x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTLI_B :
                                    FT_LA_OPCODE_X86ROTRI_B;
                data_op = FT_LA_OPCODE_ROTRI_B;
                break;
            case 16:
                x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTLI_H :
                                    FT_LA_OPCODE_X86ROTRI_H;
                data_op = FT_LA_OPCODE_ROTRI_H;
                break;
            case 32:
                x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTLI_W :
                                    FT_LA_OPCODE_X86ROTRI_W;
                data_op = FT_LA_OPCODE_ROTRI_W;
                break;
            case 64:
                x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTLI_D :
                                    FT_LA_OPCODE_X86ROTRI_D;
                data_op = FT_LA_OPCODE_ROTRI_D;
                break;
            default:
                return 0;
            }
            FT_FLAG1I(x86_op, src, rotate_count);
            ft_emit_raw(&out,
                        ft_gpr3_imm12(data_op, result, src,
                                      ext == 0 ? width - rotate_count :
                                                 rotate_count));
            break;
        }
        case 4:
            x86_op = width == 64 ? FT_LA_OPCODE_X86SLLI_D :
                     width == 32 ? FT_LA_OPCODE_X86SLLI_W :
                     width == 16 ? FT_LA_OPCODE_X86SLLI_H :
                                   FT_LA_OPCODE_X86SLLI_B;
            x86_reg_op = width == 64 ? FT_LA_OPCODE_X86SLL_D :
                         width == 32 ? FT_LA_OPCODE_X86SLL_W :
                         width == 16 ? FT_LA_OPCODE_X86SLL_H :
                                       FT_LA_OPCODE_X86SLL_B;
            data_op = width == 64 ? FT_LA_OPCODE_SLLI_D :
                                    FT_LA_OPCODE_SLLI_W;
            ft_emit_shift_imm_flags(&out, fields, x86_op, x86_reg_op,
                                    src, width, count);
            ft_emit_raw(&out, ft_gpr3_imm12(data_op, result, src, count));
            break;
        case 5:
            if (width < 32) {
                FT_LA_BSTRPICK_D_EMIT(&out, result, src, width - 1, 0);
                src = result;
            }
            x86_op = width == 64 ? FT_LA_OPCODE_X86SRLI_D :
                     width == 32 ? FT_LA_OPCODE_X86SRLI_W :
                     width == 16 ? FT_LA_OPCODE_X86SRLI_H :
                                   FT_LA_OPCODE_X86SRLI_B;
            x86_reg_op = width == 64 ? FT_LA_OPCODE_X86SRL_D :
                         width == 32 ? FT_LA_OPCODE_X86SRL_W :
                         width == 16 ? FT_LA_OPCODE_X86SRL_H :
                                       FT_LA_OPCODE_X86SRL_B;
            data_op = width == 64 ? FT_LA_OPCODE_SRLI_D :
                                    FT_LA_OPCODE_SRLI_W;
            ft_emit_shift_imm_flags(&out, fields, x86_op, x86_reg_op,
                                    src, width, count);
            ft_emit_raw(&out, ft_gpr3_imm12(data_op, result, src, count));
            break;
        case 7:
            x86_op = width == 64 ? FT_LA_OPCODE_X86SRAI_D :
                     width == 32 ? FT_LA_OPCODE_X86SRAI_W :
                     width == 16 ? FT_LA_OPCODE_X86SRAI_H :
                                   FT_LA_OPCODE_X86SRAI_B;
            x86_reg_op = width == 64 ? FT_LA_OPCODE_X86SRA_D :
                         width == 32 ? FT_LA_OPCODE_X86SRA_W :
                         width == 16 ? FT_LA_OPCODE_X86SRA_H :
                                       FT_LA_OPCODE_X86SRA_B;
            data_op = width == 64 ? FT_LA_OPCODE_SRAI_D :
                                    FT_LA_OPCODE_SRAI_W;
            ft_emit_shift_imm_flags(&out, fields, x86_op, x86_reg_op,
                                    src, width, count);
            ft_emit_raw(&out, ft_gpr3_imm12(data_op, result, src, count));
            break;
        default:
            return 0;
        }
        switch (width) {
        case 8:
            if (!ft_emit_store_rm8(&out, fields, pc, result)) {
                return 0;
            }
            break;
        case 16:
            if (!ft_emit_store_rm16(&out, fields, pc, result)) {
                return 0;
            }
            break;
        case 32:
            if (!ft_emit_store_rm32(&out, fields, pc, result, false)) {
                return 0;
            }
            break;
        case 64:
            if (!ft_emit_store_rm64(&out, fields, pc, result)) {
                return 0;
            }
            break;
        default:
            return 0;
        }
        return (out - code);
    }

    if ((ext != 0 && ext != 1 && ext != 4 && ext != 5 && ext != 7) ||
        fields->modrm_mod != 3) {
        return 0;
    }
    dst = ft_modrm_rm_index(fields);
    if (dst >= GPR_NUM) {
        return 0;
    }
    if (ext == 0 || ext == 1) {
        int width = (fields->opcode0 == 0xc0 ||
                     fields->opcode0 == 0xd0) ? 8 :
                    ft_rex_w(fields) ? 64 :
                    fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;
        int rotate_count = count;
        int src = ft_gpr(dst);
        int result = ft_gpr(dst);
        uint32_t x86_op;
        uint32_t rot_op;

        if (width < 64) {
            rotate_count %= width;
        }
        if (width == 8 && ft_modrm_rm_is_high8(fields)) {
            dst = ft_modrm_rm_high8_base_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_SRLI_D_EMIT(&out, la_t0, ft_gpr(dst), 8);
            src = la_t0;
            result = la_t0;
        } else if (width < 32) {
            result = la_t0;
        }
        switch (width) {
        case 8:
            x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTLI_B :
                                FT_LA_OPCODE_X86ROTRI_B;
            rot_op = FT_LA_OPCODE_ROTRI_B;
            break;
        case 16:
            x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTLI_H :
                                FT_LA_OPCODE_X86ROTRI_H;
            rot_op = FT_LA_OPCODE_ROTRI_H;
            break;
        case 32:
            x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTLI_W :
                                FT_LA_OPCODE_X86ROTRI_W;
            rot_op = FT_LA_OPCODE_ROTRI_W;
            break;
        case 64:
            x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTLI_D :
                                FT_LA_OPCODE_X86ROTRI_D;
            rot_op = FT_LA_OPCODE_ROTRI_D;
            break;
        default:
            return 0;
        }
        FT_FLAG1I(x86_op, src, rotate_count);
        ft_emit_raw(&out,
                    ft_gpr3_imm12(rot_op, result, src,
                                  ext == 0 ? width - rotate_count :
                                             rotate_count));
        if (width == 8) {
            if (ft_modrm_rm_is_high8(fields)) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 8);
            } else {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 7, 0);
            }
        } else if (width == 16) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 0);
        } else if (width == 32) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        }
        return (out - code);
    }

    {
        int width = (fields->opcode0 == 0xc0 ||
                     fields->opcode0 == 0xd0) ? 8 :
                    ft_rex_w(fields) ? 64 :
                    fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;
        int src = ft_gpr(dst);
        int result = ft_gpr(dst);
        uint32_t x86_op;
        uint32_t x86_reg_op;
        uint32_t data_op;

        if (width == 8 && ft_modrm_rm_is_high8(fields)) {
            dst = ft_modrm_rm_high8_base_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_SRLI_D_EMIT(&out, la_t0, ft_gpr(dst), 8);
            src = la_t0;
            result = la_t0;
        } else if (width < 32) {
            src = ft_gpr(dst);
            result = la_t0;
        }
        if (width < 32 && ext == 5) {
            FT_LA_BSTRPICK_D_EMIT(&out, result, src, width - 1, 0);
            src = result;
        } else if (width == 8 && ext == 7) {
            FT_LA_EXT_W_B_EMIT(&out, result, src);
            src = result;
        } else if (width == 16 && ext == 7) {
            FT_LA_EXT_W_H_EMIT(&out, result, src);
            src = result;
        }
        switch (width) {
        case 8:
            x86_op = ext == 4 ? FT_LA_OPCODE_X86SLLI_B :
                     ext == 5 ? FT_LA_OPCODE_X86SRLI_B :
                                FT_LA_OPCODE_X86SRAI_B;
            x86_reg_op = ext == 4 ? FT_LA_OPCODE_X86SLL_B :
                         ext == 5 ? FT_LA_OPCODE_X86SRL_B :
                                    FT_LA_OPCODE_X86SRA_B;
            data_op = ext == 4 ? FT_LA_OPCODE_SLLI_W :
                      ext == 5 ? FT_LA_OPCODE_SRLI_W :
                                 FT_LA_OPCODE_SRAI_W;
            break;
        case 16:
            x86_op = ext == 4 ? FT_LA_OPCODE_X86SLLI_H :
                     ext == 5 ? FT_LA_OPCODE_X86SRLI_H :
                                FT_LA_OPCODE_X86SRAI_H;
            x86_reg_op = ext == 4 ? FT_LA_OPCODE_X86SLL_H :
                         ext == 5 ? FT_LA_OPCODE_X86SRL_H :
                                    FT_LA_OPCODE_X86SRA_H;
            data_op = ext == 4 ? FT_LA_OPCODE_SLLI_W :
                      ext == 5 ? FT_LA_OPCODE_SRLI_W :
                                 FT_LA_OPCODE_SRAI_W;
            break;
        case 32:
            x86_op = ext == 4 ? FT_LA_OPCODE_X86SLLI_W :
                     ext == 5 ? FT_LA_OPCODE_X86SRLI_W :
                                FT_LA_OPCODE_X86SRAI_W;
            x86_reg_op = ext == 4 ? FT_LA_OPCODE_X86SLL_W :
                         ext == 5 ? FT_LA_OPCODE_X86SRL_W :
                                    FT_LA_OPCODE_X86SRA_W;
            data_op = ext == 4 ? FT_LA_OPCODE_SLLI_W :
                      ext == 5 ? FT_LA_OPCODE_SRLI_W :
                                 FT_LA_OPCODE_SRAI_W;
            break;
        case 64:
            x86_op = ext == 4 ? FT_LA_OPCODE_X86SLLI_D :
                     ext == 5 ? FT_LA_OPCODE_X86SRLI_D :
                                FT_LA_OPCODE_X86SRAI_D;
            x86_reg_op = ext == 4 ? FT_LA_OPCODE_X86SLL_D :
                         ext == 5 ? FT_LA_OPCODE_X86SRL_D :
                                    FT_LA_OPCODE_X86SRA_D;
            data_op = ext == 4 ? FT_LA_OPCODE_SLLI_D :
                      ext == 5 ? FT_LA_OPCODE_SRLI_D :
                                 FT_LA_OPCODE_SRAI_D;
            break;
        default:
            return 0;
        }
        ft_emit_shift_imm_flags(&out, fields, x86_op, x86_reg_op,
                                src, width, count);
        ft_emit_raw(&out, ft_gpr3_imm12(data_op, result, src, count));
        if (width == 8) {
            if (ft_modrm_rm_is_high8(fields)) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 8);
            } else {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 7, 0);
            }
        } else if (width == 16) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 0);
        } else if (width == 32) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        }
    }

    return (out - code);
}

static int ft_emit_rotate64_imm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    bool is_rol = fields->kind == FT_ROL_RM64_IMM8;
    int dst;
    int count = fields->imm & 63;

    if (!ft_rex_w(fields) || fields->modrm_reg != (is_rol ? 0 : 1) ||
        fields->modrm_mod != 3) {
        return 0;
    }
    if (count == 0) {
        FT_LA_ORI_EMIT(&out, la_zero, la_zero, 0);
        return (out - code);
    }
    dst = ft_modrm_rm_index(fields);
    if (dst >= GPR_NUM) {
        return 0;
    }
    if (is_rol) {
        FT_FLAG1I(FT_LA_OPCODE_X86ROTLI_D, ft_gpr(dst), count);
        FT_LA_ROTRI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 64 - count);
    } else {
        FT_FLAG1I(FT_LA_OPCODE_X86ROTRI_D, ft_gpr(dst), count);
        FT_LA_ROTRI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), count);
    }
    return (out - code);
}

static int ft_emit_rorx_template(const FastTemplateFields *fields,
                                 TranslationBlock *tb, target_ulong pc,
                                 uint32_t *code)
{
    uint32_t *out = code;
    int width = fields->kind == FT_RORX_R64_RM64_IMM8 ? 64 : 32;
    int dst = fields->reg;
    int src;
    int count = fields->imm & (width - 1);

    (void)tb;

    if (dst < 0 || dst >= GPR_NUM) {
        return 0;
    }
    if (width == 64) {
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_ROTRI_D_EMIT(&out, ft_gpr(dst), src, count);
    } else {
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_ROTRI_W_EMIT(&out, ft_gpr(dst), src, count);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }

    return out - code;
}

static int ft_emit_shrx_template(const FastTemplateFields *fields,
                                 TranslationBlock *tb, target_ulong pc,
                                 uint32_t *code)
{
    uint32_t *out = code;
    int width = fields->kind == FT_SHRX_R64_RM_R ? 64 : 32;
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
        FT_LA_SRL_D_EMIT(&out, ft_gpr(dst), src, ft_gpr(count));
    } else {
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_SRL_W_EMIT(&out, ft_gpr(dst), src, ft_gpr(count));
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
    }

    return out - code;
}

static int ft_emit_shift_cl_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int dst;
    int ext = (fields->modrm >> 3) & 7;
    int count = ft_gpr(rcx_index);

    if (ext == 2 || ext == 3) {
        return ft_emit_rcl_rcr_template(fields, tb, pc, code);
    }
    if (ext == 6) {
        ext = 4;
    }

    if (fields->modrm_mod != 3) {
        int width = fields->opcode0 == 0xd2 ? 8 :
                    ft_rex_w(fields) ? 64 :
                    fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;
        int src;
        int result = la_t2;
        uint32_t x86_op;
        uint32_t data_op;
        uint32_t *count_zero_branch = NULL;

        switch (width) {
        case 8:
            if (!ft_emit_load_rm8(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        case 16:
            if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        case 32:
            if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        case 64:
            if (!ft_emit_load_rm64(&out, fields, pc, &src)) {
                return 0;
            }
            break;
        default:
            return 0;
        }

        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(rcx_index), 7, 0);
        count = la_t1;
        if (ext == 0 || ext == 1) {
            uint32_t rot_op;
            int count_mask = width == 64 ? 63 : 31;
            int rotate_mask = width - 1;

            switch (width) {
            case 8:
                x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTL_B :
                                    FT_LA_OPCODE_X86ROTR_B;
                rot_op = FT_LA_OPCODE_ROTR_B;
                break;
            case 16:
                x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTL_H :
                                    FT_LA_OPCODE_X86ROTR_H;
                rot_op = FT_LA_OPCODE_ROTR_H;
                break;
            case 32:
                x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTL_W :
                                    FT_LA_OPCODE_X86ROTR_W;
                rot_op = FT_LA_OPCODE_ROTR_W;
                break;
            case 64:
                x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTL_D :
                                    FT_LA_OPCODE_X86ROTR_D;
                rot_op = FT_LA_OPCODE_ROTR_D;
                break;
            default:
                return 0;
            }
            FT_LA_ANDI_EMIT(&out, la_t3, count, rotate_mask);
            FT_LA_ANDI_EMIT(&out, la_t4, count, count_mask);
            count_zero_branch = out;
            FT_LA_BEQ_EMIT(&out, la_t4, la_zero, 0);
            FT_FLAG2(x86_op, src, count);
            if (ext == 0) {
                FT_LA_SUB_D_EMIT(&out, la_t3, la_zero, la_t3);
            }
            ft_emit_raw(&out, ft_gpr3(rot_op, result, src, la_t3));
            if (!fields->skip_flags && width < 32) {
                int cf_bit = ext == 0 ? 0 : width - 1;

                FT_LA_BSTRPICK_D_EMIT(&out, la_t4, result,
                                      cf_bit, cf_bit);
                FT_MTFLAG(la_t4, CF_USEDEF_BIT);
            }
        } else {
            if (width < 32 && ext == 5) {
                FT_LA_BSTRPICK_D_EMIT(&out, result, src, width - 1, 0);
                src = result;
            } else if (width == 8 && ext == 7) {
                FT_LA_EXT_W_B_EMIT(&out, result, src);
                src = result;
            } else if (width == 16 && ext == 7) {
                FT_LA_EXT_W_H_EMIT(&out, result, src);
                src = result;
            }
            switch (width) {
            case 8:
                x86_op = ext == 4 ? FT_LA_OPCODE_X86SLL_B :
                         ext == 5 ? FT_LA_OPCODE_X86SRL_B :
                                    FT_LA_OPCODE_X86SRA_B;
                data_op = ext == 4 ? FT_LA_OPCODE_SLL_W :
                          ext == 5 ? FT_LA_OPCODE_SRL_W :
                                     FT_LA_OPCODE_SRA_W;
                break;
            case 16:
                x86_op = ext == 4 ? FT_LA_OPCODE_X86SLL_H :
                         ext == 5 ? FT_LA_OPCODE_X86SRL_H :
                                    FT_LA_OPCODE_X86SRA_H;
                data_op = ext == 4 ? FT_LA_OPCODE_SLL_W :
                          ext == 5 ? FT_LA_OPCODE_SRL_W :
                                     FT_LA_OPCODE_SRA_W;
                break;
            case 32:
                x86_op = ext == 4 ? FT_LA_OPCODE_X86SLL_W :
                         ext == 5 ? FT_LA_OPCODE_X86SRL_W :
                                    FT_LA_OPCODE_X86SRA_W;
                data_op = ext == 4 ? FT_LA_OPCODE_SLL_W :
                          ext == 5 ? FT_LA_OPCODE_SRL_W :
                                     FT_LA_OPCODE_SRA_W;
                break;
            case 64:
                x86_op = ext == 4 ? FT_LA_OPCODE_X86SLL_D :
                         ext == 5 ? FT_LA_OPCODE_X86SRL_D :
                                    FT_LA_OPCODE_X86SRA_D;
                data_op = ext == 4 ? FT_LA_OPCODE_SLL_D :
                          ext == 5 ? FT_LA_OPCODE_SRL_D :
                                     FT_LA_OPCODE_SRA_D;
                break;
            default:
                return 0;
            }
            FT_FLAG2(x86_op, src, count);
            ft_emit_raw(&out, ft_gpr3(data_op, result, src, count));
        }

        switch (width) {
        case 8:
            if (!ft_emit_store_rm8(&out, fields, pc, result)) {
                return 0;
            }
            break;
        case 16:
            if (!ft_emit_store_rm16(&out, fields, pc, result)) {
                return 0;
            }
            break;
        case 32:
            if (!ft_emit_store_rm32(&out, fields, pc, result, false)) {
                return 0;
            }
            break;
        case 64:
            if (!ft_emit_store_rm64(&out, fields, pc, result)) {
                return 0;
            }
            break;
        default:
            return 0;
        }
        if (ext == 0 || ext == 1) {
            *count_zero_branch = FT_LA_BEQ(la_t4, la_zero,
                                           out - count_zero_branch);
        }
        return (out - code);
    }

    if ((ext != 0 && ext != 1 && ext != 4 && ext != 5 && ext != 7) ||
        fields->modrm_mod != 3) {
        return 0;
    }
    dst = ft_modrm_rm_index(fields);
    if (dst >= GPR_NUM) {
        return 0;
    }
    if (ext == 0 || ext == 1) {
        int width = fields->opcode0 == 0xd2 ? 8 :
                    ft_rex_w(fields) ? 64 :
                    fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;
        int src = ft_gpr(dst);
        int result = ft_gpr(dst);
        uint32_t x86_op;
        uint32_t rot_op;
        uint32_t *count_zero_branch;
        uint32_t *count_zero_target = NULL;
        int count_mask = width == 64 ? 63 : 31;

        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(rcx_index), 7, 0);
        if (width == 8 && ft_modrm_rm_is_high8(fields)) {
            dst = ft_modrm_rm_high8_base_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_SRLI_D_EMIT(&out, la_t0, ft_gpr(dst), 8);
            src = la_t0;
            result = la_t0;
        } else if (width < 32) {
            result = la_t0;
        }
        switch (width) {
        case 8:
            x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTL_B :
                                FT_LA_OPCODE_X86ROTR_B;
            rot_op = FT_LA_OPCODE_ROTR_B;
            FT_LA_ANDI_EMIT(&out, la_t2, la_t1, 7);
            break;
        case 16:
            x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTL_H :
                                FT_LA_OPCODE_X86ROTR_H;
            rot_op = FT_LA_OPCODE_ROTR_H;
            FT_LA_ANDI_EMIT(&out, la_t2, la_t1, 15);
            break;
        case 32:
            x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTL_W :
                                FT_LA_OPCODE_X86ROTR_W;
            rot_op = FT_LA_OPCODE_ROTR_W;
            FT_LA_ANDI_EMIT(&out, la_t2, la_t1, 31);
            break;
        case 64:
            x86_op = ext == 0 ? FT_LA_OPCODE_X86ROTL_D :
                                FT_LA_OPCODE_X86ROTR_D;
            rot_op = FT_LA_OPCODE_ROTR_D;
            FT_LA_ANDI_EMIT(&out, la_t2, la_t1, 63);
            break;
        default:
            return 0;
        }
        FT_LA_ANDI_EMIT(&out, la_t3, la_t1, count_mask);
        count_zero_branch = out;
        FT_LA_BEQ_EMIT(&out, la_t3, la_zero, 0);
        FT_FLAG2(x86_op, src, la_t1);
        if (ext == 0) {
            FT_LA_SUB_D_EMIT(&out, la_t2, la_zero, la_t2);
        }
        ft_emit_raw(&out, ft_gpr3(rot_op, result, src, la_t2));
        if (!fields->skip_flags && width < 32) {
            int cf_bit = ext == 0 ? 0 : width - 1;

            FT_LA_BSTRPICK_D_EMIT(&out, la_t3, result,
                                  cf_bit, cf_bit);
            FT_MTFLAG(la_t3, CF_USEDEF_BIT);
        }
        if (width == 8) {
            if (ft_modrm_rm_is_high8(fields)) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 8);
            } else {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 7, 0);
            }
        } else if (width == 16) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 0);
        } else if (width == 32) {
            count_zero_target = out;
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        }
        *count_zero_branch = FT_LA_BEQ(la_t3, la_zero,
                                       (width == 32 ? count_zero_target : out) -
                                       count_zero_branch);
        return (out - code);
    }

    {
        int width = fields->opcode0 == 0xd2 ? 8 :
                    ft_rex_w(fields) ? 64 :
                    fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;
        int src = ft_gpr(dst);
        int result = ft_gpr(dst);
        uint32_t x86_op;
        uint32_t data_op;

        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(rcx_index), 7, 0);
        count = la_t1;
        if (width == 8 && ft_modrm_rm_is_high8(fields)) {
            dst = ft_modrm_rm_high8_base_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_SRLI_D_EMIT(&out, la_t0, ft_gpr(dst), 8);
            src = la_t0;
            result = la_t0;
        } else if (width < 32) {
            src = ft_gpr(dst);
            result = la_t0;
        }
        if (width < 32 && ext == 5) {
            FT_LA_BSTRPICK_D_EMIT(&out, result, src, width - 1, 0);
            src = result;
        } else if (width == 8 && ext == 7) {
            FT_LA_EXT_W_B_EMIT(&out, result, src);
            src = result;
        } else if (width == 16 && ext == 7) {
            FT_LA_EXT_W_H_EMIT(&out, result, src);
            src = result;
        }
        switch (width) {
        case 8:
            x86_op = ext == 4 ? FT_LA_OPCODE_X86SLL_B :
                     ext == 5 ? FT_LA_OPCODE_X86SRL_B :
                                FT_LA_OPCODE_X86SRA_B;
            data_op = ext == 4 ? FT_LA_OPCODE_SLL_W :
                      ext == 5 ? FT_LA_OPCODE_SRL_W :
                                 FT_LA_OPCODE_SRA_W;
            break;
        case 16:
            x86_op = ext == 4 ? FT_LA_OPCODE_X86SLL_H :
                     ext == 5 ? FT_LA_OPCODE_X86SRL_H :
                                FT_LA_OPCODE_X86SRA_H;
            data_op = ext == 4 ? FT_LA_OPCODE_SLL_W :
                      ext == 5 ? FT_LA_OPCODE_SRL_W :
                                 FT_LA_OPCODE_SRA_W;
            break;
        case 32:
            x86_op = ext == 4 ? FT_LA_OPCODE_X86SLL_W :
                     ext == 5 ? FT_LA_OPCODE_X86SRL_W :
                                FT_LA_OPCODE_X86SRA_W;
            data_op = ext == 4 ? FT_LA_OPCODE_SLL_W :
                      ext == 5 ? FT_LA_OPCODE_SRL_W :
                                 FT_LA_OPCODE_SRA_W;
            break;
        case 64:
            x86_op = ext == 4 ? FT_LA_OPCODE_X86SLL_D :
                     ext == 5 ? FT_LA_OPCODE_X86SRL_D :
                                FT_LA_OPCODE_X86SRA_D;
            data_op = ext == 4 ? FT_LA_OPCODE_SLL_D :
                      ext == 5 ? FT_LA_OPCODE_SRL_D :
                                 FT_LA_OPCODE_SRA_D;
            break;
        default:
            return 0;
        }
        FT_FLAG2(x86_op, src, count);
        ft_emit_raw(&out, ft_gpr3(data_op, result, src, count));
        if (width == 8) {
            if (ft_modrm_rm_is_high8(fields)) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 8);
            } else {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 7, 0);
            }
        } else if (width == 16) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 0);
        } else if (width == 32) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        }
    }

    return (out - code);
}

static int ft_shld_shrd_width(const FastTemplateFields *fields)
{
    if (ft_rex_w(fields)) {
        return 64;
    }
    if (fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
        return 16;
    }
    return 32;
}

static uint32_t ft_shld_shrd_x86_op(bool is_shld, bool is_imm, int width)
{
    if (is_shld) {
        if (is_imm) {
            return width == 64 ? FT_LA_OPCODE_X86SLLI_D :
                   width == 32 ? FT_LA_OPCODE_X86SLLI_W :
                                 FT_LA_OPCODE_X86SLLI_H;
        }
        return width == 64 ? FT_LA_OPCODE_X86SLL_D :
               width == 32 ? FT_LA_OPCODE_X86SLL_W :
                             FT_LA_OPCODE_X86SLL_H;
    }
    if (is_imm) {
        return width == 64 ? FT_LA_OPCODE_X86SRLI_D :
               width == 32 ? FT_LA_OPCODE_X86SRLI_W :
                             FT_LA_OPCODE_X86SRLI_H;
    }
    return width == 64 ? FT_LA_OPCODE_X86SRL_D :
           width == 32 ? FT_LA_OPCODE_X86SRL_W :
                         FT_LA_OPCODE_X86SRL_H;
}

static uint32_t ft_shld_shrd_x86_and_op(int width)
{
    return width == 64 ? FT_LA_OPCODE_X86AND_D :
           width == 32 ? FT_LA_OPCODE_X86AND_W :
                         FT_LA_OPCODE_X86AND_H;
}

static void ft_emit_mask_to_width(uint32_t **out, int dst, int src, int width)
{
    if (width == 64) {
        FT_LA_OR_EMIT(out, dst, src, la_zero);
    } else {
        FT_LA_BSTRPICK_D_EMIT(out, dst, src, width - 1, 0);
    }
}

static bool ft_emit_load_shld_shrd_rm(uint32_t **out,
                                     const FastTemplateFields *fields,
                                     target_ulong pc, int width, int *value)
{
    return width == 64 ? ft_emit_load_rm64(out, fields, pc, value) :
           width == 32 ? ft_emit_load_rm32(out, fields, pc, value) :
                         ft_emit_load_rm16(out, fields, pc, value);
}

static bool ft_emit_store_shld_shrd_rm(uint32_t **out,
                                      const FastTemplateFields *fields,
                                      target_ulong pc, int width, int value)
{
    return width == 64 ? ft_emit_store_rm64(out, fields, pc, value) :
           width == 32 ? ft_emit_store_rm32(out, fields, pc, value, true) :
                         ft_emit_store_rm16(out, fields, pc, value);
}

static void ft_emit_toggle_of_from_bit0(uint32_t **out, int flags,
                                        int value, int temp)
{
    FT_LA_ANDI_EMIT(out, temp, value, 1);
    FT_LA_SLLI_D_EMIT(out, temp, temp, 11);
    FT_LA_XOR_EMIT(out, flags, flags, temp);
}

static int ft_emit_shld_shrd_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    bool is_shld = fields->kind == FT_SHLD_RM_R_IMM8 ||
                   fields->kind == FT_SHLD_RM_R_CL;
    bool is_imm = fields->kind == FT_SHLD_RM_R_IMM8 ||
                  fields->kind == FT_SHRD_RM_R_IMM8;
    int width = ft_shld_shrd_width(fields);
    int mask = width == 64 ? 63 : 31;
    int src = ft_modrm_reg_index(fields);
    int dst_value;
    uint32_t x86_op;
    uint32_t *count_zero_branch = NULL;

    if (src >= GPR_NUM ||
        !ft_emit_load_shld_shrd_rm(&out, fields, pc, width, &dst_value)) {
        return 0;
    }

    x86_op = ft_shld_shrd_x86_op(is_shld, is_imm, width);
    ft_emit_mask_to_width(&out, la_t0, dst_value, width);
    ft_emit_mask_to_width(&out, la_t1, ft_gpr(src), width);

    if (is_imm) {
        int count = fields->imm & mask;
        int other_count;

        if (count == 0 || count >= width) {
            return 0;
        }
        other_count = width - count;
        if (is_shld) {
            FT_LA_SLLI_D_EMIT(&out, la_t2, la_t0, count);
            FT_LA_SRLI_D_EMIT(&out, la_t1, la_t1, other_count);
        } else {
            FT_LA_SRLI_D_EMIT(&out, la_t2, la_t0, count);
            FT_LA_SLLI_D_EMIT(&out, la_t1, la_t1, other_count);
        }
        FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t1);
        if (!fields->skip_flags) {
            ft_emit_raw(&out, ft_gpr1_imm(x86_op, la_t0, count));
            FT_LA_X86MFFLAG_EMIT(&out, la_t1, 0x21);
            if (!is_shld && count == 1) {
                ft_emit_toggle_of_from_bit0(&out, la_t1, ft_gpr(src), la_t3);
            }
            ft_emit_raw(&out, ft_gpr2(ft_shld_shrd_x86_and_op(width),
                                      la_t2, la_t2));
            FT_LA_X86MTFLAG_EMIT(&out, la_t1, 0x21);
        }
    } else {
        FT_LA_BSTRPICK_D_EMIT(&out, la_t3, ft_gpr(rcx_index), 7, 0);
        FT_LA_ANDI_EMIT(&out, la_t4, la_t3, mask);
        count_zero_branch = out;
        FT_LA_BEQ_EMIT(&out, la_t4, la_zero, 0);
        FT_LA_ADDI_D_EMIT(&out, la_t3, la_zero, width);
        FT_LA_SUB_D_EMIT(&out, la_t3, la_t3, la_t4);
        if (is_shld) {
            FT_LA_SLL_D_EMIT(&out, la_t2, la_t0, la_t4);
            FT_LA_SRL_D_EMIT(&out, la_t1, la_t1, la_t3);
        } else {
            FT_LA_SRL_D_EMIT(&out, la_t2, la_t0, la_t4);
            FT_LA_SLL_D_EMIT(&out, la_t1, la_t1, la_t3);
        }
        FT_LA_OR_EMIT(&out, la_t2, la_t2, la_t1);
        if (!fields->skip_flags) {
            ft_emit_raw(&out, ft_gpr2(x86_op, la_t0, la_t4));
            FT_LA_X86MFFLAG_EMIT(&out, la_t1, 0x21);
            if (!is_shld) {
                FT_LA_ADDI_D_EMIT(&out, la_t3, la_t4, -1);
                FT_LA_MASKNEZ_EMIT(&out, la_t3, ft_gpr(src), la_t3);
                ft_emit_toggle_of_from_bit0(&out, la_t1, la_t3, la_t3);
            }
            ft_emit_raw(&out, ft_gpr2(ft_shld_shrd_x86_and_op(width),
                                      la_t2, la_t2));
            FT_LA_X86MTFLAG_EMIT(&out, la_t1, 0x21);
        }
    }

    if (!ft_emit_store_shld_shrd_rm(&out, fields, pc, width, la_t2)) {
        return 0;
    }
    if (count_zero_branch) {
        *count_zero_branch = FT_LA_BEQ(la_t4, la_zero,
                                       out - count_zero_branch);
    }
    return (out - code);
}

static int ft_emit_shr_rm_imm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int lhs;
    int count = fields->kind == FT_SHR_RM8_ONE ? 1 : fields->imm & 31;

    switch (fields->kind) {
    case FT_SHR_RM8_IMM8:
    case FT_SHR_RM8_ONE:
        if (fields->modrm_reg != 5 ||
            count <= 0 || count >= 8 ||
            !ft_emit_load_rm8(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG1I(FT_LA_OPCODE_X86SRLI_B, lhs, count);
        FT_LA_SRLI_W_EMIT(&out, la_t2, lhs, count);
        if (!ft_emit_store_rm8(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    case FT_SHR_RM16_IMM8:
        if (ft_rex_w(fields) || fields->modrm_reg != 5 ||
            count <= 0 || count >= 16 ||
            !ft_emit_load_rm16(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG1I(FT_LA_OPCODE_X86SRLI_H, lhs, count);
        FT_LA_SRLI_W_EMIT(&out, la_t2, lhs, count);
        if (!ft_emit_store_rm16(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    default:
        return 0;
    }

    return (out - code);
}
