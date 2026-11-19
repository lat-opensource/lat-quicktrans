/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Main FastTemplateFields emitter dispatch. */

/* Emit a boolean condition from the preserved operands of an instptn head. */
static bool ft_emit_direct_condition(uint32_t **out,
                                     const FastTemplateFields *fields,
                                     int result)
{
    int lhs;
    int rhs = la_zero;
    int work_lhs;
    int work_rhs = la_zero;
    int width = fields->direct_cmp_width;
#ifdef CONFIG_SOFTMMU
    int tmp0 = la_a0;
    int tmp1 = la_a1;
    int tmp2 = la_a2;
#else
    int tmp0 = la_t0;
    int tmp1 = la_t1;
    int tmp2 = la_t2;
#endif

    if (fields->direct_cmp_lhs_gpr < 0 || width == 0) {
        return false;
    }
    lhs = ft_gpr(fields->direct_cmp_lhs_gpr);
    if (fields->direct_cmp_rhs_gpr >= 0) {
        rhs = ft_gpr(fields->direct_cmp_rhs_gpr);
    }
    work_lhs = lhs;
    if (fields->direct_branch_kind == FT_DIRECT_BRANCH_BIT_SET ||
        fields->direct_branch_kind == FT_DIRECT_BRANCH_BIT_CLEAR) {
        if (fields->direct_bit_index_gpr >= 0) {
            FT_LA_ANDI_EMIT(out, tmp0,
                            ft_gpr(fields->direct_bit_index_gpr), width - 1);
            FT_LA_SRL_D_EMIT(out, tmp1, lhs, tmp0);
        } else {
            FT_LA_SRLI_D_EMIT(out, tmp1, lhs,
                              fields->direct_bit_index_imm & (width - 1));
        }
        FT_LA_ANDI_EMIT(out, result, tmp1, 1);
        if (fields->direct_branch_kind == FT_DIRECT_BRANCH_BIT_CLEAR) {
            FT_LA_XORI_EMIT(out, result, result, 1);
        }
        return true;
    }
    if (width < 64) {
        bool signed_compare =
            fields->direct_branch_kind == FT_DIRECT_BRANCH_LT ||
            fields->direct_branch_kind == FT_DIRECT_BRANCH_GE ||
            fields->direct_branch_kind == FT_DIRECT_BRANCH_LE ||
            fields->direct_branch_kind == FT_DIRECT_BRANCH_GT;
        int shift = 64 - width;

        if (signed_compare) {
            FT_LA_SLLI_D_EMIT(out, tmp0, lhs, shift);
            FT_LA_SRAI_D_EMIT(out, tmp0, tmp0, shift);
        } else {
            FT_LA_BSTRPICK_D_EMIT(out, tmp0, lhs, width - 1, 0);
        }
        work_lhs = tmp0;
        if (fields->direct_cmp_rhs_gpr >= 0) {
            if (signed_compare) {
                FT_LA_SLLI_D_EMIT(out, tmp1, rhs, shift);
                FT_LA_SRAI_D_EMIT(out, tmp1, tmp1, shift);
            } else {
                FT_LA_BSTRPICK_D_EMIT(out, tmp1, rhs, width - 1, 0);
            }
            work_rhs = tmp1;
        }
    } else {
        work_rhs = rhs;
    }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    /* Comparing with zero needs no temporary XOR result. */
    if (fields->direct_cmp_rhs_gpr < 0) {
        if (fields->direct_branch_kind == FT_DIRECT_BRANCH_EQ) {
            FT_LA_SLTUI_EMIT(out, result, work_lhs, 1);
            return true;
        }
        if (fields->direct_branch_kind == FT_DIRECT_BRANCH_NE) {
            FT_LA_SLTU_EMIT(out, result, la_zero, work_lhs);
            return true;
        }
    }
#endif
    switch (fields->direct_branch_kind) {
    case FT_DIRECT_BRANCH_EQ:
    case FT_DIRECT_BRANCH_NE:
        FT_LA_XOR_EMIT(out, tmp2, work_lhs, work_rhs);
        FT_LA_SLTU_EMIT(out, result, la_zero, tmp2);
        if (fields->direct_branch_kind == FT_DIRECT_BRANCH_EQ) {
            FT_LA_XORI_EMIT(out, result, result, 1);
        }
        return true;
    case FT_DIRECT_BRANCH_LT:
        FT_LA_SLT_EMIT(out, result, work_lhs, work_rhs); return true;
    case FT_DIRECT_BRANCH_GE:
        FT_LA_SLT_EMIT(out, result, work_lhs, work_rhs);
        FT_LA_XORI_EMIT(out, result, result, 1); return true;
    case FT_DIRECT_BRANCH_LTU:
        FT_LA_SLTU_EMIT(out, result, work_lhs, work_rhs); return true;
    case FT_DIRECT_BRANCH_GEU:
        FT_LA_SLTU_EMIT(out, result, work_lhs, work_rhs);
        FT_LA_XORI_EMIT(out, result, result, 1); return true;
    case FT_DIRECT_BRANCH_LE:
        FT_LA_SLT_EMIT(out, result, work_rhs, work_lhs);
        FT_LA_XORI_EMIT(out, result, result, 1); return true;
    case FT_DIRECT_BRANCH_GT:
        FT_LA_SLT_EMIT(out, result, work_rhs, work_lhs); return true;
    case FT_DIRECT_BRANCH_LEU:
        FT_LA_SLTU_EMIT(out, result, work_rhs, work_lhs);
        FT_LA_XORI_EMIT(out, result, result, 1); return true;
    case FT_DIRECT_BRANCH_GTU:
        FT_LA_SLTU_EMIT(out, result, work_rhs, work_lhs); return true;
    case FT_DIRECT_BRANCH_ALWAYS:
        FT_LA_ADDI_D_EMIT(out, result, la_zero, 1); return true;
    case FT_DIRECT_BRANCH_NEVER:
        FT_LA_OR_EMIT(out, result, la_zero, la_zero); return true;
    default:
        return false;
    }
}

static int emit_template_fields_uncached(const FastTemplateFields *fields,
                                         TranslationBlock *tb,
                                         target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

#ifdef QUICKTRANS_LATU
    if (ft_emit_zero_code_allowed(fields)) {
        return 0;
    }
#endif
    if (fields->instptn_skip) {
        FT_LA_NOP_EMIT(&out);
        return out - code;
    }
    if (fields->alu_op == FT_ALU_SBB &&
        fields->direct_cmp_lhs_gpr >= 0) {
        int width = fields->alu_width;
        int dst = fields->modrm_rm_index;
#ifdef CONFIG_SOFTMMU
        int result = la_a3;
        int value = la_a2;
#else
        int result = la_t0;
        int value = la_t1;
#endif

        if (dst >= GPR_NUM ||
            !ft_emit_direct_condition(&out, fields, result)) {
            return 0;
        }
        if (!fields->skip_flags) {
            ft_emit_raw(&out, ft_gpr2(ft_alu_x86_op(FT_ALU_SUB, width),
                                      la_zero, result));
        }
        if (width == 64) {
            FT_LA_SUB_D_EMIT(&out, ft_gpr(dst), la_zero, result);
        } else if (width == 32) {
            FT_LA_SUB_W_EMIT(&out, ft_gpr(dst), la_zero, result);
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        } else if (width == 16) {
            FT_LA_SUB_D_EMIT(&out, value, la_zero, result);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), value, 15, 0);
        } else if (width == 8 && !ft_modrm_rm_is_high8(fields)) {
            FT_LA_SUB_D_EMIT(&out, value, la_zero, result);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), value, 7, 0);
        } else {
            return 0;
        }
        return out - code;
    }
    if (fields->alu_op != FT_ALU_NONE) {
        if (!ft_emit_alu_template(&out, fields, pc)) {
            return 0;
        }
        if (out == code && fields->skip_flags) {
            FT_LA_NOP_EMIT(&out);
        }
        return out - code;
    }

    if (fast_template_emit_fns[fields->kind]) {
        return fast_template_emit_fns[fields->kind](fields, tb, pc, code);
    }

    switch (fields->kind) {
    case FT_SALC:
        FT_LA_X86MFFLAG_EMIT(&out, la_t0, CF_USEDEF_BIT);
        FT_LA_SUB_D_EMIT(&out, la_t0, la_zero, la_t0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t0, 7, 0);
        break;
    case FT_ARPL:
    {
        int src = ft_modrm_reg_index(fields);
        int dst;

        if (src < 0 || src >= GPR_NUM ||
            !ft_emit_load_rm16(&out, fields, pc, &dst)) {
            return 0;
        }
        FT_LA_ANDI_EMIT(&out, la_t0, ft_gpr(src), 3);
        FT_LA_ANDI_EMIT(&out, la_t1, dst, 3);
        FastBranchLabel done = { 0 };
        FastBranchFixup done_fixup;

        FT_LA_SLTU_EMIT(&out, la_t2, la_t1, la_t0);
        FT_LA_X86MTFLAG_EMIT(&out, la_zero, ZF_USEDEF_BIT);
        ft_emit_branch_placeholder(&out, &done_fixup, FT_BRANCH_BEQ,
                                   la_t2, la_zero, &done);
        FT_LA_ORI_EMIT(&out, la_t3, la_zero, 0xfff);
        FT_LA_X86MTFLAG_EMIT(&out, la_t3, ZF_USEDEF_BIT);
        FT_LA_OR_EMIT(&out, la_t1, dst, la_zero);
        FT_LA_BSTRINS_D_EMIT(&out, la_t1, la_t0, 1, 0);
        if (!ft_emit_store_rm16(&out, fields, pc, la_t1)) {
            return 0;
        }
        ft_bind_branch_label(&done, out);
        ft_resolve_branch_fixup(&done_fixup);
        break;
    }
    case FT_XOR_RM_GPR_ZERO:
    {
        int reg;
        int rm;
        bool is16;

        if ((fields->modrm & 0xc0) != 0xc0) {
            return 0;
        }
        reg = fields->modrm_reg | (ft_rex_r(fields) << 3);
        rm = fields->modrm_rm | (ft_rex_b(fields) << 3);
        if (reg != rm || rm >= GPR_NUM) {
            return 0;
        }
        is16 = !ft_rex_w(fields) && fields->prefix2 == dt_X86_PREFIX_OPSIZE;
        if (is16) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rm), la_zero, 15, 0);
            ft_emit_raw(&out, ft_gpr2(FT_LA_OPCODE_X86XOR_H, la_zero,
                                      la_zero));
        } else {
            FT_LA_OR_EMIT(&out, ft_gpr(rm), la_zero, la_zero);
            ft_emit_raw(&out, ft_gpr2(ft_rex_w(fields) ?
                                      FT_LA_OPCODE_X86XOR_D :
                                      FT_LA_OPCODE_X86XOR_W,
                                      la_zero, la_zero));
        }
        break;
    }
    case FT_MOV_RM64_R64:
    {
        int src;

        if (!ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
        if (!ft_emit_store_rm64(&out, fields, pc, ft_gpr(src))) {
            return 0;
        }
        break;
    }
    case FT_MOV_R64_RM64:
    {
        int dst;
        int base;

        if (!ft_rex_w(fields)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int src = ft_modrm_rm_index(fields);
            if (src >= GPR_NUM) {
                return 0;
            }
            FT_LA_OR_EMIT(&out, ft_gpr(dst), ft_gpr(src), la_zero);
        } else {
            if (!fields->addr32 && fields->segment < 0 &&
                fields->modrm_mod == 0 &&
                fields->modrm_rm == 5) {
                int src;

                if (!ft_emit_load_rm64(&out, fields, pc, &src)) {
                    return 0;
                }
                FT_LA_OR_EMIT(&out, ft_gpr(dst), src, la_zero);
                break;
            }
            if (fields->segment >= 0 ||
                fields->modrm_rm == 4 ||
                !ft_fits_simm12(fields->disp)) {
                if (!ft_emit_mem_addr(&out, fields, &base)) {
                    return 0;
                }
                FT_LA_LD_D_EMIT(&out, ft_gpr(dst), base,
                                       ft_mem_access_offset(fields, base));
                break;
            }
            if (!ft_base_from_modrm_sib(fields, &base) ||
                !ft_fits_simm12(fields->disp)) {
                return 0;
            }
            FT_LA_LD_D_EMIT(&out, ft_gpr(dst), ft_gpr(base),
                                   fields->disp);
        }
        break;
    }
    case FT_MOV_R32_RM32:
    {
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
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 31, 0);
        } else {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            FT_LA_LD_WU_EMIT(&out, ft_gpr(dst), addr,
                              ft_mem_access_offset(fields, addr));
        }
        break;
    }
    case FT_CMOV_R64_RM64:
    case FT_CMOV_R32_RM32:
    case FT_CMOV_R16_RM16:
    {
        int dst;
        int src;
        int cond;
        int id = 0;
#ifdef CONFIG_SOFTMMU
        int direct_result = la_a3;
#else
        int direct_result = la_t2;
#endif

        if (!ft_cmov_opcode_info(fields->opcode1, &cond, &id)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (fields->kind == FT_CMOV_R64_RM64) {
            if (!ft_rex_w(fields) ||
                !ft_emit_load_rm64(&out, fields, pc, &src)) {
                return 0;
            }
        } else if (fields->kind == FT_CMOV_R16_RM16) {
            if (ft_rex_w(fields) ||
                !ft_emit_load_rm16(&out, fields, pc, &src)) {
                return 0;
            }
        } else {
            if (ft_rex_w(fields) ||
                !ft_emit_load_rm32(&out, fields, pc, &src)) {
                return 0;
            }
        }
#ifndef CONFIG_SOFTMMU
        /* Direct conditions use t0-t2, including the memory-load result t0.
         * Keep the source live until the conditional destination write. */
        if (fields->direct_cmp_lhs_gpr >= 0 && fields->modrm_mod != 3) {
            FT_LA_OR_EMIT(&out, la_t3, src, la_zero);
            src = la_t3;
        }
#endif
        if (fields->kind == FT_CMOV_R32_RM32) {
            if (fields->direct_cmp_lhs_gpr >= 0) {
                if (!ft_emit_direct_condition(&out, fields, direct_result)) return 0;
            } else {
                direct_result = la_t2;
                ft_emit_raw(&out, FT_LA_OPCODE_SETX86J | direct_result | (cond << 10));
            }
            FT_LA_BEQ_EMIT(&out, direct_result, la_zero, 2);
            FT_LA_OR_EMIT(&out, ft_gpr(dst), src, la_zero);
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        } else if (fields->kind == FT_CMOV_R16_RM16) {
            if (fields->direct_cmp_lhs_gpr >= 0) {
                if (!ft_emit_direct_condition(&out, fields, direct_result)) return 0;
            } else {
                direct_result = la_t2;
                ft_emit_raw(&out, FT_LA_OPCODE_SETX86J | direct_result | (cond << 10));
            }
            FT_LA_BEQ_EMIT(&out, direct_result, la_zero, 2);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), src, 15, 0);
        } else {
            if (fields->direct_cmp_lhs_gpr >= 0) {
                if (!ft_emit_direct_condition(&out, fields, direct_result)) return 0;
            } else {
                direct_result = la_t2;
                ft_emit_raw(&out, FT_LA_OPCODE_SETX86J | direct_result | (cond << 10));
            }
            FT_LA_BEQ_EMIT(&out, direct_result, la_zero, 2);
            FT_LA_OR_EMIT(&out, ft_gpr(dst), src, la_zero);
        }
        break;
    }
    case FT_SETCC_RM8:
    {
        int cond;
        int id;
#ifdef CONFIG_SOFTMMU
        int direct_result = la_a3;
#else
        int direct_result = la_t0;
#endif

        if (!ft_setcc_opcode_info(fields->opcode1, &cond, &id)) {
            return 0;
        }
        if (fields->direct_float_result) {
            FT_LA_OR_EMIT(&out, direct_result,
#ifdef CONFIG_SOFTMMU
                          la_a4,
#else
                          la_t2,
#endif
                          la_zero);
        } else if (fields->direct_cmp_lhs_gpr >= 0) {
            if (!ft_emit_direct_condition(&out, fields, direct_result)) return 0;
        } else {
            direct_result = la_t0;
            ft_emit_raw(&out, FT_LA_OPCODE_SETX86J | direct_result | (cond << 10));
        }
        if (!ft_emit_store_rm8(&out, fields, pc, direct_result)) {
            return 0;
        }
        break;
    }
    case FT_BSF_R64_RM64:
    case FT_BSF_R32_RM32:
    case FT_BSF_R16_RM16:
    case FT_BSR_R64_RM64:
    case FT_BSR_R32_RM32:
    case FT_BSR_R16_RM16:
    {
        int dst;
        int src;
        int flag_src;
        int cond;
        int result = la_t0;
        bool is_64 = fields->kind == FT_BSF_R64_RM64 ||
                     fields->kind == FT_BSR_R64_RM64;
        bool is_16 = fields->kind == FT_BSF_R16_RM16 ||
                     fields->kind == FT_BSR_R16_RM16;
        bool is_bsr = fields->kind == FT_BSR_R64_RM64 ||
                      fields->kind == FT_BSR_R32_RM32 ||
                      fields->kind == FT_BSR_R16_RM16;

        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (is_64) {
            if (!ft_rex_w(fields) ||
                !ft_emit_load_rm64(&out, fields, pc, &src)) {
                return 0;
            }
        } else if (is_16) {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
            if (ft_rex_w(fields) ||
                !ft_emit_load_rm16_zext(&out, fields, pc, la_t2)) {
                return 0;
            }
#else
            if (ft_rex_w(fields) ||
                !ft_emit_load_rm16(&out, fields, pc, &src)) {
                return 0;
            }
            FT_LA_BSTRPICK_D_EMIT(&out, la_t2, src, 15, 0);
#endif
            src = la_t2;
        } else {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
            if (ft_rex_w(fields) ||
                !ft_emit_load_rm32_zext(&out, fields, pc, la_t2)) {
                return 0;
            }
#else
            if (ft_rex_w(fields) ||
                !ft_emit_load_rm32(&out, fields, pc, &src)) {
                return 0;
            }
            FT_LA_BSTRPICK_D_EMIT(&out, la_t2, src, 31, 0);
#endif
            src = la_t2;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        /* Scan results fit in six bits; write r32/r64 without a copy. */
        if (!is_16) {
            result = ft_gpr(dst);
        }
#endif
        flag_src = src;
        if (!fields->skip_flags
#ifdef QUICKTRANS_LATU
            && (src == result || src == ft_gpr(dst))
#endif
        ) {
            flag_src = ft_scratch_avoid3(src, ft_gpr(dst), la_t0);
            FT_LA_OR_EMIT(&out, flag_src, src, la_zero);
        }
        cond = src;
        FT_LA_BEQ_EMIT(&out, cond, la_zero,
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
                       (is_bsr ? 3 : 2) + (result == la_t0));
#else
                       (is_bsr ? 4 : 2) + (result == la_t0));
#endif
        ft_emit_raw(&out, ft_gpr2_rd_rj(is_bsr ? FT_LA_OPCODE_CLZ_D : FT_LA_OPCODE_CTZ_D, result, src));
        if (is_bsr) {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
            /* Nonzero input: CLZ is in [0,63], so 63 - CLZ == CLZ ^ 63. */
            FT_LA_XORI_EMIT(&out, result, result, 63);
#else
            FT_LA_ADDI_D_EMIT(&out, result, result, -63);
            FT_LA_SUB_D_EMIT(&out, result, la_zero, result);
#endif
        }
        if (is_64 && result != ft_gpr(dst)) {
            FT_LA_OR_EMIT(&out, ft_gpr(dst), result, la_zero);
        } else if (is_16) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
        } else if (!is_64 && result != ft_gpr(dst)) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), result, 31, 0);
        }
        if (!fields->skip_flags) {
            FT_LA_X86MTFLAG_EMIT(&out, la_zero, ZF_USEDEF_BIT);
            ft_count_bits_set_zf_from_zero(&out, flag_src);
        }
        break;
    }
    case FT_MUL_RM64:
    {
        int src;

        if (!ft_rex_w(fields) || fields->modrm_reg != 4 ||
            !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (src == ft_gpr(rdx_index)) {
            FT_LA_OR_EMIT(&out, la_t0, src, la_zero);
            src = la_t0;
        }
#else
        FT_LA_OR_EMIT(&out, la_t0, src, la_zero);
        src = la_t0;
#endif
        FT_FLAG2(FT_LA_OPCODE_X86MUL_DU, src, ft_gpr(rax_index));
        FT_LA_MULH_DU_EMIT(&out, ft_gpr(rdx_index),
                         ft_gpr(rax_index), src);
        FT_LA_MUL_D_EMIT(&out, ft_gpr(rax_index),
                         ft_gpr(rax_index), src);
        break;
    }
    case FT_MUL_RM32:
    {
        int src;

        if (ft_rex_w(fields) || fields->modrm_reg != 4) {
            return 0;
        }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (!ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        /* Consume inputs before either implicit destination is overwritten. */
        FT_FLAG2(FT_LA_OPCODE_X86MUL_WU, ft_gpr(rax_index), src);
        FT_LA_MULW_D_WU_EMIT(&out, la_t0, ft_gpr(rax_index), src);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), la_t0, 31, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rdx_index), la_t0, 63, 32);
#else
        if (fields->modrm_mod == 3) {
            src = ft_modrm_rm_index(fields);
            if (src >= GPR_NUM) {
                return 0;
            }
            FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(src), 31, 0);
        } else {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            FT_LA_LD_WU_EMIT(&out, la_t1, addr,
                                   ft_mem_access_offset(fields, addr));
        }
        FT_LA_BSTRPICK_D_EMIT(&out, la_t2, ft_gpr(rax_index), 31, 0);
#ifdef QUICKTRANS_LATU
        FT_LA_MUL_D_EMIT(&out, la_t0, la_t2, la_t1);
#else
        FT_LA_OR_EMIT(&out, la_t0, la_t2, la_zero);
        FT_LA_MUL_D_EMIT(&out, la_t0, la_t0, la_t1);
#endif
        FT_LA_SRLI_D_EMIT(&out, ft_gpr(rdx_index), la_t0, 32);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), la_t0, 31, 0);
        FT_FLAG2(FT_LA_OPCODE_X86MUL_WU, la_t2, la_t1);
#endif
        break;
    }
    case FT_MUL_RM16:
    {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (ft_rex_w(fields) || fields->modrm_reg != 4 ||
            !ft_emit_load_rm16_zext(&out, fields, pc, la_t1)) {
            return 0;
        }
#else
        int src;

        if (ft_rex_w(fields) || fields->modrm_reg != 4 ||
            !ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, src, 15, 0);
#endif
        FT_LA_BSTRPICK_D_EMIT(&out, la_t2, ft_gpr(rax_index), 15, 0);
        FT_FLAG2(FT_LA_OPCODE_X86MUL_HU, la_t2, la_t1);
        FT_LA_MUL_D_EMIT(&out, la_t0, la_t2, la_t1);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t0, 15, 0);
        FT_LA_SRLI_D_EMIT(&out, la_t1, la_t0, 16);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rdx_index), la_t1, 15, 0);
        break;
    }
    case FT_DIV_RM8:
        if (!ft_emit_div_rm8(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_DIV_RM32:
        if (!ft_emit_div_rm32(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_DIV_RM16:
        if (!ft_emit_div_rm16(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_DIV_RM64:
        if (!ft_emit_div_rm64(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_IDIV_RM8:
        if (!ft_emit_idiv_rm8(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_IDIV_RM16:
        if (!ft_emit_idiv_rm16(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_IDIV_RM32:
        if (!ft_emit_idiv_rm32(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_IDIV_RM64:
        if (!ft_emit_idiv_rm64(&out, fields, pc)) {
            return 0;
        }
        break;
    case FT_MOV_RM16_R16:
    {
        int src;

        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
        if (!ft_emit_store_rm16(&out, fields, pc, ft_gpr(src))) {
            return 0;
        }
        break;
    }
    case FT_MOV_R16_RM16:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || !ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), src, 15, 0);
        break;
    }
    case FT_MOV_RM32_R32:
    {
        int src;

        if (ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 31, 0);
        } else
#endif
        if (!ft_emit_store_rm32(&out, fields, pc, ft_gpr(src), true)) {
            return 0;
        }
        break;
    }
    case FT_MOV_RM32_IMM32:
    {
        int dst_or_base;
        bool rip_unaligned = false;
        int mem_width = fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 2 : 4;

        if (ft_rex_w(fields) || fields->modrm_reg != 0) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            dst_or_base = ft_modrm_rm_index(fields);
            if (dst_or_base >= GPR_NUM) {
                return 0;
            }
            if (fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
                if (!ft_emit_li32(&out, la_t0, (uint16_t)fields->imm)) {
                    return 0;
                }
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst_or_base), la_t0, 15, 0);
            } else {
                ft_emit_mov_imm32(&out, ft_gpr(dst_or_base),
                                  (uint32_t)fields->imm,
                                  ft_omit_gpr_zext32(fields));
            }
        } else {
            int value_reg;

            if (!fields->addr32 && fields->segment < 0 &&
                fields->modrm_mod == 0 &&
                fields->modrm_rm == 5) {
                target_ulong target = pc + fields->size + fields->disp;

                if (!ft_emit_guest_addr(&out, la_t1, target)) {
                    return 0;
                }
                dst_or_base = la_t1;
                rip_unaligned = target & (mem_width - 1);
            } else {
                if (!ft_emit_mem_addr(&out, fields, &dst_or_base)) {
                    return 0;
                }
            }
            value_reg = dst_or_base == la_t0 ? la_t2 : la_t0;
            if (!ft_emit_li32(&out, value_reg, (uint32_t)fields->imm)) {
                return 0;
            }
            if (rip_unaligned) {
                if (!ft_emit_store_addr_bytes(&out, pc, dst_or_base, 0,
                                              value_reg, mem_width)) {
                    return 0;
                }
            } else {
                ft_emit_raw(&out, ft_gpr3_imm12(
                    mem_width == 2 ? FT_LA_OPCODE_ST_H : FT_LA_OPCODE_ST_W,
                    value_reg, dst_or_base,
                    ft_mem_access_offset(fields, dst_or_base)));
            }
        }
        break;
    }
    case FT_MOV_RM64_IMM32:
    {
        int dst_or_base;
        bool rip_unaligned = false;

        if (!ft_rex_w(fields) || fields->modrm_reg != 0) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            dst_or_base = ft_modrm_rm_index(fields);
            if (dst_or_base >= GPR_NUM) {
                return 0;
            }
            ft_emit_li64(&out, ft_gpr(dst_or_base),
                         (uint64_t)(int64_t)(int32_t)fields->imm);
        } else {
            int value_reg;

            if (!fields->addr32 && fields->segment < 0 &&
                fields->modrm_mod == 0 &&
                fields->modrm_rm == 5) {
                target_ulong target = pc + fields->size + fields->disp;

                if (!ft_emit_guest_addr(&out, la_t1, target)) {
                    return 0;
                }
                dst_or_base = la_t1;
                rip_unaligned = target & 7;
            } else {
                if (!ft_emit_mem_addr(&out, fields, &dst_or_base)) {
                    return 0;
                }
            }
            value_reg = dst_or_base == la_t0 ? la_t2 : la_t0;
            ft_emit_li64(&out, value_reg,
                         (uint64_t)(int64_t)(int32_t)fields->imm);
            if (rip_unaligned) {
                if (!ft_emit_store_addr_bytes(&out, pc, dst_or_base, 0,
                                              value_reg, 8)) {
                    return 0;
                }
            } else {
                FT_LA_ST_D_EMIT(&out, value_reg, dst_or_base,
                                ft_mem_access_offset(fields, dst_or_base));
            }
        }
        break;
    }
    case FT_LEA_R64_M:
    {
        target_ulong target;
        int dst;

        if (!ft_rex_w(fields) || fields->modrm_mod == 3) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 0 && fields->modrm_rm == 4 &&
            !ft_sib_has_index(fields) && (fields->sib & 7) == 5) {
            if (!ft_emit_li32(&out, ft_gpr(dst), (uint32_t)fields->disp)) {
                return 0;
            }
            break;
        }

        if (fields->modrm_mod == 0 && fields->modrm_rm == 5) {
            target = fields->addr32 ? (uint32_t)fields->disp :
                                      pc + fields->size + fields->disp;
            if (!ft_emit_guest_addr(&out, ft_gpr(dst), target)) {
                return 0;
            }
            if (fields->addr32) {
                FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                      31, 0);
            }
            break;
        }

        if (fields->modrm_rm == 4 && ft_sib_has_index(fields)) {
            int base;
            int index = ft_sib_index_index(fields);
            int scale = ft_sib_scale(fields);
            bool no_base = fields->modrm_mod == 0 &&
                           (fields->sib & 7) == 5;

            if (index >= GPR_NUM) {
                return 0;
            }
            if (!no_base) {
                if (!ft_base_from_modrm_sib_with_index(fields, &base)) {
                    return 0;
                }
                if (scale) {
                    FT_LA_ALSL_D_EMIT(&out, ft_gpr(dst), ft_gpr(index),
                                     ft_gpr(base), scale - 1);
                } else {
                    FT_LA_ADD_D_EMIT(&out, ft_gpr(dst), ft_gpr(base),
                                     ft_gpr(index));
                }
            } else if (scale) {
                FT_LA_SLLI_D_EMIT(&out, ft_gpr(dst), ft_gpr(index), scale);
            } else {
                FT_LA_OR_EMIT(&out, ft_gpr(dst), ft_gpr(index), la_zero);
            }
            if (ft_fits_simm12(fields->disp)) {
                if (fields->disp) {
                    FT_LA_ADDI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                     fields->disp);
                }
            } else {
                if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->disp)) {
                    return 0;
                }
                FT_LA_ADD_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t1);
            }
            if (fields->addr32) {
                FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                      31, 0);
            }
            break;
        }

        {
            int base;

            if (!ft_base_from_modrm_sib(fields, &base)) {
                return 0;
            }
            if (ft_fits_simm12(fields->disp)) {
                FT_LA_ADDI_D_EMIT(&out, ft_gpr(dst), ft_gpr(base),
                                       fields->disp);
            } else {
                if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->disp)) {
                    return 0;
                }
                FT_LA_ADD_D_EMIT(&out, ft_gpr(dst), ft_gpr(base), la_t1);
            }
        }
        if (fields->addr32) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        }
        break;
    }
    case FT_LEA_R32_M:
    case FT_LEA_R16_M:
    {
        target_ulong target;
        int dst;
        int result;
        bool is16 = fields->kind == FT_LEA_R16_M;

        if (ft_rex_w(fields) || fields->modrm_mod == 3 ||
            (is16 ? fields->prefix2 != dt_X86_PREFIX_OPSIZE :
                    fields->prefix2 == dt_X86_PREFIX_OPSIZE)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        result = is16 ? la_t2 : ft_gpr(dst);

        if (fields->modrm_mod == 0 && fields->modrm_rm == 4 &&
            !ft_sib_has_index(fields) && (fields->sib & 7) == 5) {
            if (!ft_emit_li32(&out, result, (uint32_t)fields->disp)) {
                return 0;
            }
            if (is16) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 0);
            }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
            else {
                /* li32 sign-extends; LEA32 must clear the high word. */
                FT_LA_BSTRPICK_D_EMIT(&out, result, result, 31, 0);
            }
#endif
            break;
        }

        if (fields->modrm_mod == 0 && fields->modrm_rm == 5) {
            target = fields->addr32 ? (uint32_t)fields->disp :
                                      pc + fields->size + fields->disp;
            if (!ft_emit_guest_addr(&out, result, target)) {
                return 0;
            }
            if (is16) {
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 0);
            } else {
                FT_LA_BSTRPICK_D_EMIT(&out, result, result, 31, 0);
            }
            break;
        }

        if (fields->modrm_rm == 4 && ft_sib_has_index(fields)) {
            int base;
            int index = ft_sib_index_index(fields);
            int scale = ft_sib_scale(fields);
            bool no_base = fields->modrm_mod == 0 &&
                           (fields->sib & 7) == 5;

            if (index >= GPR_NUM) {
                return 0;
            }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
            if (!no_base) {
                if (!ft_base_from_modrm_sib_with_index(fields, &base)) {
                    return 0;
                }
                /* Consume both address operands before writing an alias. */
                if (scale) {
                    FT_LA_ALSL_D_EMIT(&out, result, ft_gpr(index),
                                     ft_gpr(base), scale - 1);
                } else {
                    FT_LA_ADD_D_EMIT(&out, result, ft_gpr(base),
                                     ft_gpr(index));
                }
                if (ft_fits_simm12(fields->disp)) {
                    if (fields->disp) {
                        FT_LA_ADDI_D_EMIT(&out, result, result,
                                         fields->disp);
                    }
                } else {
                    if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->disp)) {
                        return 0;
                    }
                    FT_LA_ADD_D_EMIT(&out, result, result, la_t1);
                }
                if (is16) {
                    FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 0);
                } else {
                    FT_LA_BSTRPICK_D_EMIT(&out, result, result, 31, 0);
                }
                break;
            }
#endif
            if (scale) {
                FT_LA_SLLI_D_EMIT(&out, la_t0, ft_gpr(index),
                                       scale);
                if (!no_base) {
                    if (!ft_base_from_modrm_sib_with_index(fields, &base)) {
                        return 0;
                    }
                    FT_LA_ADD_D_EMIT(&out, la_t0, ft_gpr(base), la_t0);
                }
            } else {
                if (no_base) {
                    FT_LA_OR_EMIT(&out, la_t0, ft_gpr(index), la_zero);
                } else {
                    if (!ft_base_from_modrm_sib_with_index(fields, &base)) {
                        return 0;
                    }
                    FT_LA_ADD_D_EMIT(&out, la_t0, ft_gpr(base),
                                     ft_gpr(index));
                }
            }
            if (ft_fits_simm12(fields->disp)) {
                FT_LA_ADDI_D_EMIT(&out, result, la_t0,
                                       fields->disp);
            } else {
                if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->disp)) {
                    return 0;
                }
                FT_LA_ADD_D_EMIT(&out, result, la_t0, la_t1);
            }
        } else {
            int base;

            if (!ft_base_from_modrm_sib(fields, &base)) {
                return 0;
            }
            if (ft_fits_simm12(fields->disp)) {
                FT_LA_ADDI_D_EMIT(&out, result, ft_gpr(base),
                                       fields->disp);
            } else {
                if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->disp)) {
                    return 0;
                }
                FT_LA_ADD_D_EMIT(&out, result, ft_gpr(base), la_t1);
            }
        }
        if (is16) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), result, 15, 0);
        } else {
            FT_LA_BSTRPICK_D_EMIT(&out, result, result, 31, 0);
        }
        break;
    }
    case FT_ADD_R64_IMM8:
    {
        int dst;

        if (!ft_rex_w(fields) || fields->modrm_mod != 3 ||
            fields->modrm_reg != 0) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (!ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86ADD_D, ft_gpr(dst), la_t0);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                               fields->imm);
        break;
    }
    case FT_ADD_R64_IMM32:
    {
        int dst;

        if (!ft_rex_w(fields) || fields->modrm_mod != 3 ||
            fields->modrm_reg != 0) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (!ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86ADD_D, ft_gpr(dst), la_t0);
        if (ft_fits_simm12(fields->imm)) {
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                   fields->imm);
        } else {
            FT_LA_ADD_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t0);
        }
        break;
    }
    case FT_SUB_EAX_IMM32:
        if (!ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_W, ft_gpr(rax_index), la_t0);
        if (ft_fits_simm12(-(int64_t)fields->imm)) {
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rax_index),
                               ft_gpr(rax_index),
                               (int)(-(int64_t)fields->imm));
        } else {
            FT_LA_SUB_W_EMIT(&out, ft_gpr(rax_index),
                              ft_gpr(rax_index), la_t0);
        }
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index), 31, 0);
        break;
    case FT_SUB_AL_IMM8:
        if (fields->imm < 0 || fields->imm > 0xff) {
            return 0;
        }
        if (!ft_emit_li32(&out, la_t0, (uint16_t)fields->imm)) {
            return 0;
        }
        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(rax_index), 7, 0);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_B, la_t1, la_t0);
        FT_LA_SUB_W_EMIT(&out, la_t2, la_t1, la_t0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 7, 0);
        break;
    case FT_SUB_AX_IMM16:
        if (fields->imm < 0 || fields->imm > 0xffff) {
            return 0;
        }
        if (!ft_emit_li32(&out, la_t0, (uint16_t)fields->imm)) {
            return 0;
        }
        FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(rax_index), 15, 0);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_H, la_t1, la_t0);
        FT_LA_SUB_W_EMIT(&out, la_t2, la_t1, la_t0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 15, 0);
        break;
    case FT_SUB_R64_IMM32:
    {
        int dst;

        if (!ft_rex_w(fields) || fields->modrm_mod != 3 ||
            fields->modrm_reg != 5) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (!ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, ft_gpr(dst), la_t0);
        if (ft_fits_simm12(-(int64_t)fields->imm)) {
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                   -fields->imm);
        } else {
            FT_LA_SUB_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t0);
        }
        break;
    }
    case FT_SUB_R64_IMM8:
    {
        int dst;

        if (!ft_rex_w(fields) || fields->modrm_mod != 3 ||
            fields->modrm_reg != 5) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        ft_emit_li64(&out, la_t0, (uint64_t)(int64_t)fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, ft_gpr(dst), la_t0);
        if (ft_fits_simm12(-(int64_t)fields->imm)) {
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                   -fields->imm);
        } else {
            FT_LA_SUB_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t0);
        }
        break;
    }
    case FT_TEST_RM16_IMM16:
    {
        int lhs;

        if (fields->modrm_reg != 0 ||
            !ft_emit_load_rm16(&out, fields, pc, &lhs) ||
            !ft_emit_li32(&out, la_t1, (uint16_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_H, lhs, la_t1);
        break;
    }
    case FT_TEST_AL_IMM8:
        if (fields->imm < 0 || fields->imm > 0xff) {
            return 0;
        }
        FT_LA_ORI_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86AND_B, ft_gpr(rax_index), la_t1);
        break;
    case FT_ADD_AL_IMM8:
    case FT_ADC_AL_IMM8:
    {
        bool is_adc = fields->kind == FT_ADC_AL_IMM8;

        if (fields->imm < 0 || fields->imm > 0xff) {
            return 0;
        }
        FT_LA_ORI_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(rax_index), 7, 0);
        if (is_adc) {
            FT_LA_ADC_B_EMIT(&out, la_t2, la_t0, la_t1);
            FT_LA_X86ADC_B_EMIT(&out, la_t0, la_t1);
        } else {
            FT_LA_X86ADD_B_EMIT(&out, la_t0, la_t1);
            FT_LA_ADD_W_EMIT(&out, la_t2, la_t0, la_t1);
        }
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 7, 0);
        break;
    }
    case FT_TEST_EAX_IMM32:
        if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_W, ft_gpr(rax_index), la_t1);
        break;
    case FT_TEST_RAX_IMM32:
        if (!ft_rex_w(fields) ||
            !ft_emit_li32(&out, la_t1, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_D, ft_gpr(rax_index), la_t1);
        break;
    case FT_CMP_RM64_IMM8:
    {
        int lhs;

        if (!ft_rex_w(fields) || fields->modrm_reg != 7 ||
            !ft_emit_load_rm64(&out, fields, pc, &lhs) ||
            !ft_fits_simm12(fields->imm)) {
            return 0;
        }
        FT_LA_ADDI_D_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, lhs, la_t1);
        break;
    }
    case FT_CMP_RM64_IMM32:
    {
        int lhs;

        if (!ft_rex_w(fields) || fields->modrm_reg != 7 ||
            !ft_emit_load_rm64(&out, fields, pc, &lhs)) {
            return 0;
        }
        if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, lhs, la_t1);
        break;
    }
    case FT_CMP_RM16_IMM8:
    {
        int lhs;

        if (fields->modrm_reg != 7 ||
            !ft_emit_load_rm16(&out, fields, pc, &lhs) ||
            !ft_fits_simm12(fields->imm)) {
            return 0;
        }
        FT_LA_ADDI_D_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_H, lhs, la_t1);
        break;
    }
    case FT_CMP_RM16_IMM16:
    {
        int lhs;

        if (fields->modrm_reg != 7 ||
            !ft_emit_load_rm16(&out, fields, pc, &lhs)) {
            return 0;
        }
        if (!ft_emit_li32(&out, la_t1, (uint16_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_H, lhs, la_t1);
        break;
    }
    case FT_CMP_RM16_R16:
    {
        int lhs;
        int rhs;

        if (!ft_emit_load_rm16(&out, fields, pc, &lhs)) {
            return 0;
        }
        rhs = ft_modrm_reg_index(fields);
        if (rhs >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_H, lhs, ft_gpr(rhs));
        break;
    }
    case FT_CMP_R16_RM16:
    {
        int lhs;
        int rhs;

        lhs = ft_modrm_reg_index(fields);
        if (lhs >= GPR_NUM || !ft_emit_load_rm16(&out, fields, pc, &rhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_H, ft_gpr(lhs), rhs);
        break;
    }
    case FT_CMP_AL_IMM8:
        FT_LA_ADDI_D_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(rax_index), 7, 0);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_B, la_t0, la_t1);
        break;
    case FT_CMP_AX_IMM16:
        if (!ft_emit_li32(&out, la_t1, (uint16_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_H, ft_gpr(rax_index), la_t1);
        break;
    case FT_CMP_EAX_IMM32:
        if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_W, ft_gpr(rax_index), la_t1);
        break;
    case FT_CMP_RAX_IMM32:
        if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, ft_gpr(rax_index), la_t1);
        break;
    case FT_CMP_RM8_IMM8:
    {
        int lhs;

        if (fields->modrm_reg != 7 ||
            !ft_emit_load_rm8(&out, fields, pc, &lhs) ||
            !ft_fits_simm12(fields->imm)) {
            return 0;
        }
        if (fields->rex < 0 && fields->modrm_mod == 3 &&
            fields->modrm_rm >= 4) {
            return 0;
        }
        FT_LA_ADDI_D_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_B, lhs, la_t1);
        break;
    }
    case FT_CMP_RM32_IMM8:
    {
        int lhs;

        if (ft_rex_w(fields) || fields->modrm_reg != 7 ||
            !ft_emit_load_rm32(&out, fields, pc, &lhs) ||
            !ft_fits_simm12(fields->imm)) {
            return 0;
        }
        FT_LA_ADDI_D_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86SUB_W, lhs, la_t1);
        break;
    }
    case FT_CMP_RM8_R8:
    case FT_CMP_R8_RM8:
    {
        int lhs;
        int rhs;

        if (fields->kind == FT_CMP_R8_RM8) {
            if (ft_modrm_reg_is_high8(fields)) {
                lhs = ft_modrm_reg_high8_base_index(fields);
                FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(lhs), 8);
                lhs = la_t1;
            } else {
                lhs = ft_modrm_reg_index(fields);
                if (lhs >= GPR_NUM) {
                    return 0;
                }
                lhs = ft_gpr(lhs);
            }
            if (!ft_emit_load_rm8(&out, fields, pc, &rhs)) {
                return 0;
            }
            FT_FLAG2(FT_LA_OPCODE_X86SUB_B, lhs, rhs);
            break;
        }
        if (!ft_emit_load_rm8(&out, fields, pc, &lhs)) {
            return 0;
        }
        rhs = ft_modrm_reg_index(fields);
        if (fields->rex < 0 && fields->modrm_reg >= 4) {
            return 0;
        }
        if (fields->rex < 0 && fields->modrm_mod == 3 &&
            fields->modrm_rm >= 4) {
            return 0;
        }
        if (rhs >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_B, lhs, ft_gpr(rhs));
        break;
    }
    case FT_TEST_RM64_R64:
    {
        int lhs;
        int rhs;

        if (!ft_rex_w(fields) || !ft_emit_load_rm64(&out, fields, pc, &lhs)) {
            return 0;
        }
        rhs = ft_modrm_reg_index(fields);
        if (rhs >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_D, lhs, ft_gpr(rhs));
        break;
    }
    case FT_TEST_RM64_IMM32:
    {
        int lhs;

        if (!ft_rex_w(fields) || fields->modrm_reg != 0 ||
            !ft_emit_load_rm64(&out, fields, pc, &lhs) ||
            !ft_emit_li32(&out, la_t1, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_D, lhs, la_t1);
        break;
    }
    case FT_ADD_R64_RM64:
    case FT_ADC_R64_RM64:
    {
        int dst;
        int src;
        bool is_adc = fields->kind == FT_ADC_R64_RM64;

        if (!ft_rex_w(fields) || !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (is_adc) {
            FT_LA_OR_EMIT(&out, la_t3, ft_gpr(dst), la_zero);
            FT_LA_ADC_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
            FT_LA_X86ADC_D_EMIT(&out, la_t3, src);
        } else {
            FT_FLAG2(FT_LA_OPCODE_X86ADD_D, ft_gpr(dst), src);
            FT_LA_ADD_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        }
        break;
    }
    case FT_ADD_R32_RM32:
    case FT_ADC_R32_RM32:
    {
        int dst;
        int src;
        bool is_adc = fields->kind == FT_ADC_R32_RM32;

        if (ft_rex_w(fields) || !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (is_adc) {
            FT_LA_OR_EMIT(&out, la_t3, ft_gpr(dst), la_zero);
            FT_LA_ADC_W_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
            FT_LA_X86ADC_W_EMIT(&out, la_t3, src);
        } else {
            FT_FLAG2(FT_LA_OPCODE_X86ADD_W, ft_gpr(dst), src);
            FT_LA_ADD_W_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        }
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        break;
    }
    case FT_ADD_R16_RM16:
    case FT_ADC_R16_RM16:
    {
        int dst;
        int src;
        bool is_adc = fields->kind == FT_ADC_R16_RM16;

        if (!ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (is_adc) {
            FT_LA_OR_EMIT(&out, la_t3, ft_gpr(dst), la_zero);
            FT_LA_ADC_H_EMIT(&out, la_t2, ft_gpr(dst), src);
            FT_LA_X86ADC_H_EMIT(&out, la_t3, src);
        } else {
            FT_FLAG2(FT_LA_OPCODE_X86ADD_H, ft_gpr(dst), src);
            FT_LA_ADD_W_EMIT(&out, la_t2, ft_gpr(dst), src);
        }
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 15, 0);
        break;
    }
    case FT_ADD_EAX_IMM32:
        if (!ft_emit_li32(&out, la_t1, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86ADD_W, ft_gpr(rax_index), la_t1);
        FT_LA_ADD_W_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index),
                         la_t1);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index), 31, 0);
        break;
    case FT_ADD_AX_IMM16:
        if (!ft_emit_li32(&out, la_t1, (uint16_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86ADD_H, ft_gpr(rax_index), la_t1);
        FT_LA_ADD_W_EMIT(&out, la_t2, ft_gpr(rax_index), la_t1);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 15, 0);
        break;
    case FT_ADD_RAX_IMM32:
        if (!ft_rex_w(fields) ||
            !ft_emit_li32(&out, la_t1, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86ADD_D, ft_gpr(rax_index), la_t1);
        FT_LA_ADD_D_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index),
                         la_t1);
        break;
    case FT_ADD_RM64_R64:
    case FT_ADC_RM64_R64:
    {
        int lhs;
        int src;
        bool is_adc = fields->kind == FT_ADC_RM64_R64;

        if (!ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
        if (!ft_emit_load_rm64(&out, fields, pc, &lhs)) {
            return 0;
        }
        if (is_adc) {
            int result = fields->modrm_mod == 3 ? lhs : la_t2;

            FT_LA_OR_EMIT(&out, la_t3, lhs, la_zero);
            FT_LA_ADC_D_EMIT(&out, result, lhs, ft_gpr(src));
            FT_LA_X86ADC_D_EMIT(&out, la_t3, ft_gpr(src));
            if (!ft_emit_store_rm64(&out, fields, pc, result)) {
                return 0;
            }
        } else {
            FT_LA_X86ADD_D_EMIT(&out, lhs, ft_gpr(src));
            FT_LA_ADD_D_EMIT(&out, lhs, lhs, ft_gpr(src));
            if (fields->modrm_mod == 3) {
                if (!ft_emit_store_rm64(&out, fields, pc, lhs)) {
                    return 0;
                }
            } else {
                FT_LA_OR_EMIT(&out, la_t2, lhs, la_zero);
                if (!ft_emit_store_rm64(&out, fields, pc, la_t2)) {
                    return 0;
                }
            }
        }
        break;
    }
    case FT_SBB_RM32_R32:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || fields->modrm_mod != 3) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        src = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM || src >= GPR_NUM) {
            return 0;
        }
        FT_LA_OR_EMIT(&out, la_t1, ft_gpr(dst), la_zero);
        FT_LA_SBC_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), ft_gpr(src));
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        FT_FLAG2(FT_LA_OPCODE_X86SBC_W, la_t1, ft_gpr(src));
        break;
    }
    case FT_SUB_RM64_R64:
    {
        int lhs;
        int dst;
        int src;

        if (!ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm64(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, lhs, ft_gpr(src));
        FT_LA_SUB_D_EMIT(&out, lhs, lhs, ft_gpr(src));
        if (fields->modrm_mod == 3) {
            dst = ft_modrm_rm_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            if (!ft_emit_store_rm64(&out, fields, pc, lhs)) {
                return 0;
            }
        } else {
            FT_LA_OR_EMIT(&out, la_t2, lhs, la_zero);
            if (!ft_emit_store_rm64(&out, fields, pc, la_t2)) {
                return 0;
            }
        }
        break;
    }
    case FT_SUB_R64_RM64:
    {
        int dst;
        int src;

        if (!ft_rex_w(fields) || !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, ft_gpr(dst), src);
        FT_LA_SUB_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        break;
    }
    case FT_SUB_R32_RM32:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_W, ft_gpr(dst), src);
        FT_LA_SUB_W_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        break;
    }
    case FT_SUB_R16_RM16:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || !ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_H, ft_gpr(dst), src);
        FT_LA_SUB_W_EMIT(&out, la_t2, ft_gpr(dst), src);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 15, 0);
        break;
    }
    case FT_SUB_R8_RM8:
    {
        int dst;
        int src;
        int dst_value;

        if (ft_rex_w(fields) || !ft_emit_load_rm8(&out, fields, pc, &src)) {
            return 0;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            dst = ft_modrm_reg_high8_base_index(fields);
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(dst), 8);
            dst_value = la_t1;
        } else {
            dst = ft_modrm_reg_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            dst_value = ft_gpr(dst);
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_B, dst_value, src);
        FT_LA_SUB_W_EMIT(&out, la_t2, dst_value, src);
        if (ft_modrm_reg_is_high8(fields)) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 7, 0);
        }
        break;
    }
    case FT_AND_R64_IMM8:
    {
        int dst;

        if (!ft_rex_w(fields) || fields->modrm_mod != 3 ||
            fields->modrm_reg != 4) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        ft_emit_li64(&out, la_t0, (uint64_t)(int64_t)fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86AND_D, ft_gpr(dst), la_t0);
        FT_LA_AND_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t0);
        break;
    }
    case FT_AND_RM64_R64:
    {
        int lhs;
        int src;

        if (!ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm64(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_D, lhs, ft_gpr(src));
        FT_LA_AND_EMIT(&out, lhs, lhs, ft_gpr(src));
        if (fields->modrm_mod == 3) {
            if (!ft_emit_store_rm64(&out, fields, pc, lhs)) {
                return 0;
            }
        } else {
            FT_LA_OR_EMIT(&out, la_t2, lhs, la_zero);
            if (!ft_emit_store_rm64(&out, fields, pc, la_t2)) {
                return 0;
            }
        }
        break;
    }
    case FT_AND_RM32_R32:
    {
        int lhs;
        int src;

        if (ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm32(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_W, lhs, ft_gpr(src));
        FT_LA_AND_EMIT(&out, lhs, lhs, ft_gpr(src));
        if (fields->modrm_mod == 3) {
            FT_LA_BSTRPICK_D_EMIT(&out, lhs, lhs, 31, 0);
        } else {
            FT_LA_OR_EMIT(&out, la_t2, lhs, la_zero);
        }
        if (!ft_emit_store_rm32(&out, fields, pc,
                                fields->modrm_mod == 3 ? lhs :
                                la_t2, false)) {
            return 0;
        }
        break;
    }
    case FT_AND_R64_RM64:
    {
        int dst;
        int src;

        if (!ft_rex_w(fields) || !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_D, ft_gpr(dst), src);
        FT_LA_AND_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        break;
    }
    case FT_AND_R32_RM32:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_W, ft_gpr(dst), src);
        FT_LA_AND_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        break;
    }
    case FT_CMP_RM64_R64:
    {
        int lhs;
        int rhs;

        if (!ft_rex_w(fields) || !ft_emit_load_rm64(&out, fields, pc, &lhs)) {
            return 0;
        }
        rhs = ft_modrm_reg_index(fields);
        if (rhs >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, lhs, ft_gpr(rhs));
        break;
    }
    case FT_CMP_RM32_R32:
    {
        int lhs;
        int rhs;

        if (ft_rex_w(fields) || !ft_emit_load_rm32(&out, fields, pc, &lhs)) {
            return 0;
        }
        rhs = ft_modrm_reg_index(fields);
        if (rhs >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_W, lhs, ft_gpr(rhs));
        break;
    }
    case FT_CMP_R64_RM64:
    {
        int lhs;
        int rhs;

        if (!ft_rex_w(fields) || !ft_emit_load_rm64(&out, fields, pc, &rhs)) {
            return 0;
        }
        lhs = ft_modrm_reg_index(fields);
        if (lhs >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_D, ft_gpr(lhs), rhs);
        break;
    }
    case FT_CMP_R32_RM32:
    {
        int lhs;
        int rhs;

        if (ft_rex_w(fields) || !ft_emit_load_rm32(&out, fields, pc, &rhs)) {
            return 0;
        }
        lhs = ft_modrm_reg_index(fields);
        if (lhs >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_W, ft_gpr(lhs), rhs);
        break;
    }
    case FT_TEST_RM32_R32:
    {
        int lhs;
        int rhs;

        if (ft_rex_w(fields) || !ft_emit_load_rm32(&out, fields, pc, &lhs)) {
            return 0;
        }
        rhs = ft_modrm_reg_index(fields);
        if (rhs >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_W, lhs, ft_gpr(rhs));
        break;
    }
    case FT_TEST_RM32_IMM32:
    {
        int lhs;

        if (ft_rex_w(fields) || fields->modrm_reg != 0 ||
            !ft_emit_load_rm32(&out, fields, pc, &lhs) ||
            !ft_emit_li32(&out, la_t1, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_W, lhs, la_t1);
        break;
    }
    case FT_TEST_RM16_R16:
    {
        int lhs;
        int rhs;

        if (!ft_emit_load_rm16(&out, fields, pc, &lhs)) {
            return 0;
        }
        rhs = ft_modrm_reg_index(fields);
        if (rhs >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_H, lhs, ft_gpr(rhs));
        break;
    }
    case FT_OR_RM64_R64:
    {
        int lhs;
        int src;

        if (!ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm64(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_D, lhs, ft_gpr(src));
        FT_LA_OR_EMIT(&out, lhs, lhs, ft_gpr(src));
        if (fields->modrm_mod == 3) {
            if (!ft_emit_store_rm64(&out, fields, pc, lhs)) {
                return 0;
            }
        } else {
            FT_LA_OR_EMIT(&out, la_t2, lhs, la_zero);
            if (!ft_emit_store_rm64(&out, fields, pc, la_t2)) {
                return 0;
            }
        }
        break;
    }
    case FT_OR_RM32_R32:
    {
        int lhs;
        int src;

        if (ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm32(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_W, lhs, ft_gpr(src));
        FT_LA_OR_EMIT(&out, lhs, lhs, ft_gpr(src));
        if (fields->modrm_mod == 3) {
            FT_LA_BSTRPICK_D_EMIT(&out, lhs, lhs, 31, 0);
        } else {
            FT_LA_OR_EMIT(&out, la_t2, lhs, la_zero);
        }
        if (!ft_emit_store_rm32(&out, fields, pc,
                                fields->modrm_mod == 3 ? lhs :
                                la_t2, false)) {
            return 0;
        }
        break;
    }
    case FT_OR_RM8_R8:
    {
        int lhs;
        int rhs;

        if (ft_rex_w(fields) || !ft_emit_load_rm8(&out, fields, pc, &lhs)) {
            return 0;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            rhs = ft_modrm_reg_high8_base_index(fields);
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(rhs), 8);
            rhs = la_t1;
        } else {
            rhs = ft_modrm_reg_index(fields);
            if (rhs >= GPR_NUM) {
                return 0;
            }
            rhs = ft_gpr(rhs);
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_B, lhs, rhs);
        FT_LA_OR_EMIT(&out, la_t2, lhs, rhs);
        if (!ft_emit_store_rm8(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    }
    case FT_OR_R64_RM64:
    {
        int dst;
        int src;

        if (!ft_rex_w(fields) || !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_D, ft_gpr(dst), src);
        FT_LA_OR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        break;
    }
    case FT_OR_R32_RM32:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_W, ft_gpr(dst), src);
        FT_LA_OR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        break;
    }
    case FT_OR_R16_RM16:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || !ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_H, ft_gpr(dst), src);
        FT_LA_OR_EMIT(&out, la_t2, ft_gpr(dst), src);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 15, 0);
        break;
    }
    case FT_OR_R8_RM8:
    {
        int dst;
        int src;
        int dst_value;

        if (ft_rex_w(fields) || !ft_emit_load_rm8(&out, fields, pc, &src)) {
            return 0;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            dst = ft_modrm_reg_high8_base_index(fields);
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(dst), 8);
            dst_value = la_t1;
        } else {
            dst = ft_modrm_reg_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            dst_value = ft_gpr(dst);
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_B, dst_value, src);
        FT_LA_OR_EMIT(&out, la_t2, dst_value, src);
        if (ft_modrm_reg_is_high8(fields)) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 7, 0);
        }
        break;
    }
    case FT_OR_RM8_IMM8:
    {
        int lhs;

        if (fields->modrm_reg != 1 ||
            !ft_emit_load_rm8(&out, fields, pc, &lhs) ||
            fields->imm < 0 || fields->imm > 0xff) {
            return 0;
        }
        FT_LA_ORI_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86OR_B, lhs, la_t1);
        FT_LA_OR_EMIT(&out, la_t2, lhs, la_t1);
        if (!ft_emit_store_rm8(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    }
    case FT_XOR_RM64_R64:
    {
        int lhs;
        int src;

        if (!ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm64(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_D, lhs, ft_gpr(src));
        FT_LA_XOR_EMIT(&out, lhs, lhs, ft_gpr(src));
        if (fields->modrm_mod == 3) {
            if (!ft_emit_store_rm64(&out, fields, pc, lhs)) {
                return 0;
            }
        } else {
            FT_LA_OR_EMIT(&out, la_t2, lhs, la_zero);
            if (!ft_emit_store_rm64(&out, fields, pc, la_t2)) {
                return 0;
            }
        }
        break;
    }
    case FT_XOR_RM32_R32:
    {
        int lhs;
        int src;

        if (ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm32(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_W, lhs, ft_gpr(src));
        FT_LA_XOR_EMIT(&out, lhs, lhs, ft_gpr(src));
        if (fields->modrm_mod == 3) {
            FT_LA_BSTRPICK_D_EMIT(&out, lhs, lhs, 31, 0);
        } else {
            FT_LA_OR_EMIT(&out, la_t2, lhs, la_zero);
        }
        if (!ft_emit_store_rm32(&out, fields, pc,
                                fields->modrm_mod == 3 ? lhs :
                                la_t2, false)) {
            return 0;
        }
        break;
    }
    case FT_XOR_R64_RM64:
    {
        int dst;
        int src;

        if (!ft_rex_w(fields) || !ft_emit_load_rm64(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_D, ft_gpr(dst), src);
        FT_LA_XOR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        break;
    }
    case FT_XOR_R32_RM32:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || !ft_emit_load_rm32(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_W, ft_gpr(dst), src);
        FT_LA_XOR_EMIT(&out, ft_gpr(dst), ft_gpr(dst), src);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        break;
    }
    case FT_XOR_R16_RM16:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || !ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_H, ft_gpr(dst), src);
        FT_LA_XOR_EMIT(&out, la_t2, ft_gpr(dst), src);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 15, 0);
        break;
    }
    case FT_XOR_R8_RM8:
    {
        int dst;
        int src;
        int dst_value;

        if (ft_rex_w(fields) || !ft_emit_load_rm8(&out, fields, pc, &src)) {
            return 0;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            dst = ft_modrm_reg_high8_base_index(fields);
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(dst), 8);
            dst_value = la_t1;
        } else {
            dst = ft_modrm_reg_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            dst_value = ft_gpr(dst);
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_B, dst_value, src);
        FT_LA_XOR_EMIT(&out, la_t2, dst_value, src);
        if (ft_modrm_reg_is_high8(fields)) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 7, 0);
        }
        break;
    }
    case FT_SUB_RM32_R32:
    {
        int lhs;
        int src;

        if (ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm32(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_W, lhs, ft_gpr(src));
        FT_LA_SUB_W_EMIT(&out, lhs, lhs, ft_gpr(src));
        if (fields->modrm_mod == 3) {
            FT_LA_BSTRPICK_D_EMIT(&out, lhs, lhs, 31, 0);
        } else {
            FT_LA_OR_EMIT(&out, la_t2, lhs, la_zero);
        }
        if (!ft_emit_store_rm32(&out, fields, pc,
                                fields->modrm_mod == 3 ? lhs :
                                la_t2, false)) {
            return 0;
        }
        break;
    }
    case FT_SUB_RM16_R16:
    {
        int lhs;
        int src;

        if (ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm16(&out, fields, pc, &lhs)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_H, lhs, ft_gpr(src));
        FT_LA_SUB_W_EMIT(&out, la_t2, lhs, ft_gpr(src));
        if (!ft_emit_store_rm16(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    }
    case FT_SUB_RM8_R8:
    {
        int lhs;
        int rhs;

        if (ft_rex_w(fields) || !ft_emit_load_rm8(&out, fields, pc, &lhs)) {
            return 0;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            rhs = ft_modrm_reg_high8_base_index(fields);
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(rhs), 8);
            rhs = la_t1;
        } else {
            rhs = ft_modrm_reg_index(fields);
            if (rhs >= GPR_NUM) {
                return 0;
            }
            rhs = ft_gpr(rhs);
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_B, lhs, rhs);
        FT_LA_SUB_W_EMIT(&out, la_t2, lhs, rhs);
        if (!ft_emit_store_rm8(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    }
    case FT_TEST_RM8_R8:
    {
        int lhs;
        int rhs;

        if (ft_rex_w(fields) || !ft_emit_load_rm8(&out, fields, pc, &lhs)) {
            return 0;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            rhs = ft_modrm_reg_high8_base_index(fields);
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(rhs), 8);
            rhs = la_t1;
        } else {
            rhs = ft_modrm_reg_index(fields);
            if (rhs >= GPR_NUM) {
                return 0;
            }
            rhs = ft_gpr(rhs);
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_B, lhs, rhs);
        break;
    }
    case FT_ADD_RM8_R8:
    case FT_ADC_RM8_R8:
    case FT_AND_RM8_R8:
    case FT_XOR_RM8_R8:
    {
        int lhs;
        int rhs;
        uint32_t x86_op = fields->kind == FT_ADD_RM8_R8 ? FT_LA_OPCODE_X86ADD_B :
                          fields->kind == FT_ADC_RM8_R8 ? FT_LA_OPCODE_X86ADC_B :
                          fields->kind == FT_AND_RM8_R8 ? FT_LA_OPCODE_X86AND_B :
                                                           FT_LA_OPCODE_X86XOR_B;
        uint32_t data_op = fields->kind == FT_ADD_RM8_R8 ? FT_LA_OPCODE_ADD_W :
                           fields->kind == FT_ADC_RM8_R8 ? FT_LA_OPCODE_ADC_B :
                           fields->kind == FT_AND_RM8_R8 ? FT_LA_OPCODE_AND :
                                                            FT_LA_OPCODE_XOR;

        if (ft_rex_w(fields) || !ft_emit_load_rm8(&out, fields, pc, &lhs)) {
            return 0;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            rhs = ft_modrm_reg_high8_base_index(fields);
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(rhs), 8);
            rhs = la_t1;
        } else {
            rhs = ft_modrm_reg_index(fields);
            if (rhs >= GPR_NUM) {
                return 0;
            }
            rhs = ft_gpr(rhs);
        }
        if (fields->kind == FT_ADC_RM8_R8) {
            FT_LA_OR_EMIT(&out, la_t3, lhs, la_zero);
            ft_emit_raw(&out, ft_gpr3(data_op, la_t2, lhs, rhs));
            ft_emit_raw(&out, ft_gpr2(x86_op, la_t3, rhs));
        } else {
            ft_emit_raw(&out, ft_gpr2(x86_op, lhs, rhs));
            ft_emit_raw(&out, ft_gpr3(data_op, la_t2, lhs, rhs));
        }
        if (!ft_emit_store_rm8(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    }
    case FT_AND_RM8_IMM8:
    {
        int lhs;

        if (fields->modrm_reg != 4 ||
            !ft_emit_load_rm8(&out, fields, pc, &lhs) ||
            fields->imm < 0 || fields->imm > 0xff) {
            return 0;
        }
        FT_LA_ORI_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86AND_B, lhs, la_t1);
        FT_LA_AND_EMIT(&out, la_t2, lhs, la_t1);
        if (!ft_emit_store_rm8(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    }
    case FT_MOV_RM8_R8:
    {
        bool src_high8;
        int src;

        if (ft_rex_w(fields)) {
            return 0;
        }
        src_high8 = ft_modrm_reg_is_high8(fields);
        src = src_high8 ? ft_modrm_reg_high8_base_index(fields) :
                          ft_modrm_reg_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);
            int value_reg = ft_gpr(src);

            if (src_high8) {
                FT_LA_BSTRPICK_D_EMIT(&out, la_t0, value_reg, 15, 8);
                value_reg = la_t0;
            }
            if (ft_modrm_rm_is_high8(fields)) {
                dst = ft_modrm_rm_high8_base_index(fields);
                FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), value_reg, 15, 8);
                break;
            }
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), value_reg, 7, 0);
        } else if (!fields->addr32 && fields->segment < 0 &&
                   fields->modrm_mod == 0 &&
                   fields->modrm_rm == 5) {
            target_ulong target = pc + fields->size + fields->disp;

            if (!ft_emit_guest_addr(&out, la_t1, target)) {
                return 0;
            }
            if (src_high8) {
                FT_LA_BSTRPICK_D_EMIT(&out, la_t0, ft_gpr(src), 15, 8);
                if (!ft_emit_data_store(&out, pc, la_t1, 0, la_t0, 1)) {
                    FT_LA_ST_B_EMIT(&out, la_t0, la_t1, 0);
                }
            } else {
                if (!ft_emit_data_store(&out, pc, la_t1, 0,
                                        ft_gpr(src), 1)) {
                    FT_LA_ST_B_EMIT(&out, ft_gpr(src), la_t1, 0);
                }
            }
        } else {
            int addr;
            int value_reg;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            if (src_high8) {
                value_reg = addr == la_t0 ? la_t2 : la_t0;
                FT_LA_BSTRPICK_D_EMIT(&out, value_reg, ft_gpr(src), 15, 8);
                int offset = ft_mem_access_offset(fields, addr);

                if (!ft_emit_data_store(&out, pc, addr, offset,
                                        value_reg, 1)) {
                    FT_LA_ST_B_EMIT(&out, value_reg, addr, offset);
                }
            } else {
                int offset = ft_mem_access_offset(fields, addr);

                if (!ft_emit_data_store(&out, pc, addr, offset,
                                        ft_gpr(src), 1)) {
                    FT_LA_ST_B_EMIT(&out, ft_gpr(src), addr, offset);
                }
            }
        }
        break;
    }
    case FT_MOV_R8_RM8:
    {
        int dst;
        int src;

        if (ft_rex_w(fields) || !ft_emit_load_rm8(&out, fields, pc, &src)) {
            return 0;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            dst = ft_modrm_reg_high8_base_index(fields);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), src, 15, 8);
        } else {
            dst = ft_modrm_reg_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), src, 7, 0);
        }
        break;
    }
    case FT_ADD_R8_RM8:
    case FT_ADC_R8_RM8:
    case FT_AND_R8_RM8:
    {
        int dst;
        int src;
        int dst_value;
        bool is_and = fields->kind == FT_AND_R8_RM8;
        bool is_adc = fields->kind == FT_ADC_R8_RM8;

        if (ft_rex_w(fields) || !ft_emit_load_rm8(&out, fields, pc, &src)) {
            return 0;
        }
        if (ft_modrm_reg_is_high8(fields)) {
            dst = ft_modrm_reg_high8_base_index(fields);
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(dst), 8);
            dst_value = la_t1;
        } else {
            dst = ft_modrm_reg_index(fields);
            if (dst >= GPR_NUM) {
                return 0;
            }
            dst_value = ft_gpr(dst);
        }
        if (is_adc) {
            FT_LA_OR_EMIT(&out, la_t3, dst_value, la_zero);
            FT_LA_ADC_B_EMIT(&out, la_t2, dst_value, src);
            FT_LA_X86ADC_B_EMIT(&out, la_t3, src);
        } else {
            ft_emit_raw(&out, ft_gpr2(is_and ? FT_LA_OPCODE_X86AND_B : FT_LA_OPCODE_X86ADD_B,
                             dst_value, src));
            ft_emit_raw(&out, ft_gpr3(is_and ? FT_LA_OPCODE_AND : FT_LA_OPCODE_ADD_W, la_t2,
                             dst_value, src));
        }
        if (ft_modrm_reg_is_high8(fields)) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t2, 7, 0);
        }
        break;
    }
    case FT_TEST_RM8_IMM8:
    {
        int lhs;

        if (fields->modrm_reg != 0 ||
            !ft_emit_load_rm8(&out, fields, pc, &lhs) ||
            fields->imm < 0 || fields->imm > 0xff) {
            return 0;
        }
        FT_LA_ORI_EMIT(&out, la_t1, la_zero, fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86AND_B, lhs, la_t1);
        break;
    }
    case FT_ADD_RM32_R32:
    case FT_ADC_RM32_R32:
    {
        int src;
        bool is_adc = fields->kind == FT_ADC_RM32_R32;

        if (ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

            if (dst >= GPR_NUM) {
                return 0;
            }
            if (is_adc) {
                FT_LA_OR_EMIT(&out, la_t3, ft_gpr(dst), la_zero);
                FT_LA_ADC_W_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                 ft_gpr(src));
                FT_LA_X86ADC_W_EMIT(&out, la_t3, ft_gpr(src));
            } else {
                FT_LA_X86ADD_W_EMIT(&out, ft_gpr(dst), ft_gpr(src));
                FT_LA_ADD_W_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                 ft_gpr(src));
            }
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        } else {
            int lhs;
            int base;
            bool rip = !fields->addr32 && fields->modrm_mod == 0 &&
                       fields->modrm_rm == 5;

            if (!ft_emit_load_rm32(&out, fields, pc, &lhs)) {
                return 0;
            }
            if (is_adc) {
                FT_LA_OR_EMIT(&out, la_t3, lhs, la_zero);
                FT_LA_ADC_W_EMIT(&out, lhs, lhs, ft_gpr(src));
                FT_LA_X86ADC_W_EMIT(&out, la_t3, ft_gpr(src));
            } else {
                FT_LA_X86ADD_W_EMIT(&out, lhs, ft_gpr(src));
                FT_LA_ADD_W_EMIT(&out, lhs, lhs, ft_gpr(src));
            }
            if (rip) {
                target_ulong target = pc + fields->size + fields->disp;

                if (!ft_emit_guest_addr(&out, la_t1, target)) {
                    return 0;
                }
                FT_LA_ST_W_EMIT(&out, lhs, la_t1, 0);
            } else {
                if (!ft_base_from_modrm_sib(fields, &base) ||
                    !ft_fits_simm12(fields->disp)) {
                    return 0;
                }
                FT_LA_ST_W_EMIT(&out, lhs, ft_gpr(base),
                                       fields->disp);
            }
        }
        break;
    }
    case FT_ADD_RM16_R16:
    case FT_ADC_RM16_R16:
    {
        int lhs;
        int src;
        bool is_adc = fields->kind == FT_ADC_RM16_R16;

        if (ft_rex_w(fields)) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        if (src >= GPR_NUM || !ft_emit_load_rm16(&out, fields, pc, &lhs)) {
            return 0;
        }
        if (is_adc) {
            FT_LA_OR_EMIT(&out, la_t3, lhs, la_zero);
            FT_LA_ADC_H_EMIT(&out, la_t2, lhs, ft_gpr(src));
            FT_LA_X86ADC_H_EMIT(&out, la_t3, ft_gpr(src));
        } else {
            FT_LA_X86ADD_H_EMIT(&out, lhs, ft_gpr(src));
            FT_LA_ADD_W_EMIT(&out, la_t2, lhs, ft_gpr(src));
        }
        if (!ft_emit_store_rm16(&out, fields, pc, la_t2)) {
            return 0;
        }
        break;
    }
    case FT_ADD_R32_IMM8:
    {
        int dst;

        if (ft_rex_w(fields) || fields->modrm_mod != 3 ||
            fields->modrm_reg != 0 || fields->imm < 0) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        FT_LA_ORI_EMIT(&out, la_t0, la_zero, fields->imm);
        FT_FLAG2(FT_LA_OPCODE_X86ADD_W, ft_gpr(dst), la_t0);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                               fields->imm);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        break;
    }
    case FT_AND_R32_IMM8:
    {
        int dst;

        if (ft_rex_w(fields) || fields->modrm_mod != 3 ||
            fields->modrm_reg != 4) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (!ft_emit_li32(&out, la_t0, (uint32_t)(int32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_W, ft_gpr(dst), la_t0);
        FT_LA_AND_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t0);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        break;
    }
    case FT_SUB_R32_IMM8:
    {
        int dst;

        if (ft_rex_w(fields) || fields->modrm_mod != 3 ||
            fields->modrm_reg != 5) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= GPR_NUM) {
            return 0;
        }
        if (!ft_emit_li32(&out, la_t0, (uint32_t)(int32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86SUB_W, ft_gpr(dst), la_t0);
        if (ft_fits_simm12(-(int64_t)fields->imm)) {
            FT_LA_ADDI_W_EMIT(&out, ft_gpr(dst), ft_gpr(dst),
                                   -fields->imm);
        } else {
            FT_LA_SUB_W_EMIT(&out, ft_gpr(dst), ft_gpr(dst), la_t0);
        }
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        break;
    }
    case FT_AND_EAX_IMM32:
        if (!ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_W, ft_gpr(rax_index), la_t0);
        FT_LA_AND_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index),
                         la_t0);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index), 31, 0);
        break;
    case FT_AND_AX_IMM16:
        if (!ft_emit_li32(&out, la_t0, (uint16_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_H, ft_gpr(rax_index), la_t0);
        FT_LA_AND_EMIT(&out, la_t2, ft_gpr(rax_index), la_t0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 15, 0);
        break;
    case FT_AND_RAX_IMM32:
        if (!ft_rex_w(fields) ||
            !ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_D, ft_gpr(rax_index), la_t0);
        FT_LA_AND_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index),
                         la_t0);
        break;
    case FT_AND_AL_IMM8:
        if (!ft_emit_li32(&out, la_t0, (uint8_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86AND_B, ft_gpr(rax_index), la_t0);
        FT_LA_AND_EMIT(&out, la_t2, ft_gpr(rax_index), la_t0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 7, 0);
        break;
    case FT_OR_AL_IMM8:
        if (!ft_emit_li32(&out, la_t0, (uint8_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_B, ft_gpr(rax_index), la_t0);
        FT_LA_OR_EMIT(&out, la_t2, ft_gpr(rax_index), la_t0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 7, 0);
        break;
    case FT_OR_AX_IMM16:
        if (!ft_emit_li32(&out, la_t0, (uint16_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_H, ft_gpr(rax_index), la_t0);
        FT_LA_OR_EMIT(&out, la_t2, ft_gpr(rax_index), la_t0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 15, 0);
        break;
    case FT_OR_EAX_IMM32:
        if (!ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_W, ft_gpr(rax_index), la_t0);
        FT_LA_OR_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index),
                         la_t0);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index), 31, 0);
        break;
    case FT_OR_RAX_IMM32:
        if (!ft_rex_w(fields) ||
            !ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86OR_D, ft_gpr(rax_index), la_t0);
        FT_LA_OR_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index),
                         la_t0);
        break;
    case FT_XOR_AL_IMM8:
        if (!ft_emit_li32(&out, la_t0, (uint8_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_B, ft_gpr(rax_index), la_t0);
        FT_LA_XOR_EMIT(&out, la_t2, ft_gpr(rax_index), la_t0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 7, 0);
        break;
    case FT_XOR_AX_IMM16:
        if (!ft_emit_li32(&out, la_t0, (uint16_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_H, ft_gpr(rax_index), la_t0);
        FT_LA_XOR_EMIT(&out, la_t2, ft_gpr(rax_index), la_t0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t2, 15, 0);
        break;
    case FT_XOR_EAX_IMM32:
        if (!ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_W, ft_gpr(rax_index), la_t0);
        FT_LA_XOR_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index),
                         la_t0);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index), 31, 0);
        break;
    case FT_XOR_RAX_IMM32:
        if (!ft_emit_li32(&out, la_t0, (uint32_t)fields->imm)) {
            return 0;
        }
        FT_FLAG2(FT_LA_OPCODE_X86XOR_D, ft_gpr(rax_index), la_t0);
        FT_LA_XOR_EMIT(&out, ft_gpr(rax_index), ft_gpr(rax_index),
                         la_t0);
        break;
    case FT_MOV_RM8_IMM8:
    {
        int dst_or_base;

        if (fields->modrm_reg != 0 ||
            fields->imm < 0 || fields->imm > 0xff) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            dst_or_base = ft_modrm_rm_index(fields);
            if ((fields->rex < 0 && fields->modrm_rm >= 4) ||
                dst_or_base >= GPR_NUM) {
                return 0;
            }
            FT_LA_ORI_EMIT(&out, la_t0, la_zero, fields->imm);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst_or_base), la_t0, 7, 0);
        } else if (!fields->addr32 && fields->modrm_mod == 0 &&
                   fields->modrm_rm == 5) {
            target_ulong target = pc + fields->size + fields->disp;

            if (!ft_emit_guest_addr(&out, la_t1, target)) {
                return 0;
            }
            FT_LA_ORI_EMIT(&out, la_t0, la_zero, fields->imm);
            FT_LA_ST_B_EMIT(&out, la_t0, la_t1, 0);
        } else {
            int addr;
            int value_reg;

            if (!ft_emit_mem_addr(&out, fields, &addr)) {
                return 0;
            }
            value_reg = addr == la_t0 ? la_t2 : la_t0;
            FT_LA_ORI_EMIT(&out, value_reg, la_zero, fields->imm);
            FT_LA_ST_B_EMIT(&out, value_reg, addr,
                                   ft_mem_access_offset(fields, addr));
        }
        break;
    }
    case FT_GRP1_RM32_IMM32:
        if (!ft_emit_grp1_rm_imm(&out, fields, pc,
                                 fields->prefix2 == dt_X86_PREFIX_OPSIZE ?
                                 16 : 32)) {
            return 0;
        }
        break;
    case FT_GRP1_RM64_IMM32:
        if (!ft_emit_grp1_rm_imm(&out, fields, pc, 64)) {
            return 0;
        }
        break;
    case FT_GRP1_RM64_IMM8:
        if (!ft_emit_grp1_rm_imm(&out, fields, pc, 64)) {
            return 0;
        }
        break;
    case FT_GRP1_RM32_IMM8:
        if (!ft_emit_grp1_rm_imm(&out, fields, pc, 32)) {
            return 0;
        }
        break;
    case FT_GRP1_RM16_IMM8:
        if (!ft_emit_grp1_rm_imm(&out, fields, pc, 16)) {
            return 0;
        }
        break;
    case FT_GRP1_RM8_IMM8:
        if (!ft_emit_grp1_rm_imm(&out, fields, pc, 8)) {
            return 0;
        }
        break;
    case FT_JRCXZ_REL8:
    {
        int count_reg;
        bool taken_if_equal;
#ifdef QUICKTRANS_LATU
        tb->lazypc[0] = ft_exit_target_pc(pc + fields->size) - tb->pc;
        tb->lazypc[1] = ft_exit_target_pc(fields->imm64) - tb->pc;
        tb->canlink[0] = 1;
        tb->canlink[1] = 1;
#endif
        if (fields->alu_width == 16) {
            FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(rcx_index), 15, 0);
        } else if (fields->alu_width == 32) {
            FT_LA_BSTRPICK_D_EMIT(&out, la_t1, ft_gpr(rcx_index), 31, 0);
        }
#ifdef QUICKTRANS_LATU
        /* LATU exits compare before using scratch registers. */
        count_reg = fields->alu_width < 64 ? la_t1 : ft_gpr(rcx_index);
        taken_if_equal = true;
#else
        /* LATS uses lhs as an exit scratch register; keep guest RCX intact. */
        FT_LA_SLTU_EMIT(&out, la_t0, la_zero,
                         fields->alu_width < 64 ? la_t1 : ft_gpr(rcx_index));
        FT_LA_XORI_EMIT(&out, la_t0, la_t0, 1);
        count_reg = la_t0;
        taken_if_equal = false;
#endif
        {
            int tu_emitted = ft_emit_tu_jcc_compare(tb, code, &out, pc,
                                                    fields, count_reg, la_zero,
                                                    taken_if_equal);

            if (tu_emitted) {
                return tu_emitted;
            }
            tu_emitted = ft_emit_tu_jcc_partial_compare(
                tb, code, &out, pc, fields, count_reg, la_zero, taken_if_equal);
            if (tu_emitted) {
                return tu_emitted;
            }
        }
        return ft_emit_jcc_exit_or_self_loop(tb, code, &out, pc, fields,
                                             count_reg, la_zero, taken_if_equal);
    }
    case FT_LOOP_REL8:
    case FT_LOOPE_REL8:
    case FT_LOOPNE_REL8:
#ifdef QUICKTRANS_LATU
        tb->lazypc[0] = ft_exit_target_pc(pc + fields->size) - tb->pc;
        tb->lazypc[1] = ft_exit_target_pc(fields->imm64) - tb->pc;
        tb->canlink[0] = 1;
        tb->canlink[1] = 1;
#endif
        if (fields->alu_width == 16) {
            FT_LA_ADDI_D_EMIT(&out, la_t1, ft_gpr(rcx_index), -1);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rcx_index), la_t1, 15, 0);
            FT_LA_BSTRPICK_D_EMIT(&out, la_t1, la_t1, 15, 0);
            FT_LA_SLTU_EMIT(&out, la_t0, la_zero, la_t1);
        } else {
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rcx_index),
                                   ft_gpr(rcx_index), -1);
            if (fields->alu_width == 32) {
                FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rcx_index),
                                      ft_gpr(rcx_index), 31, 0);
            }
            FT_LA_SLTU_EMIT(&out, la_t0, la_zero, ft_gpr(rcx_index));
        }
        if (fields->kind != FT_LOOP_REL8) {
            ft_emit_raw(&out, FT_LA_OPCODE_SETX86J | la_t2 |
                     ((fields->kind == FT_LOOPE_REL8 ? COND_E : COND_NE)
                      << 10));
            FT_LA_AND_EMIT(&out, la_t0, la_t0, la_t2);
        }
        {
            int tu_emitted = ft_emit_tu_jcc_compare(tb, code, &out, pc,
                                                    fields, la_t0, la_zero,
                                                    false);

            if (tu_emitted) {
                return tu_emitted;
            }
            tu_emitted = ft_emit_tu_jcc_partial_compare(
                tb, code, &out, pc, fields, la_t0, la_zero, false);
            if (tu_emitted) {
                return tu_emitted;
            }
        }
        return ft_emit_jcc_exit_or_self_loop(tb, code, &out, pc, fields,
                                             la_t0, la_zero, false);
    case FT_JCC_REL:
    {
        int cond_lhs;
        int cond_rhs = la_zero;
        bool taken_if_equal = false;
#ifdef CONFIG_SOFTMMU
        int tmp0 = la_a0;
        int tmp1 = la_a1;
        int tmp2 = la_a2;
#else
        int tmp0 = la_t0;
        int tmp1 = la_t1;
        int tmp2 = la_t2;
#endif

#ifdef QUICKTRANS_LATU
        tb->lazypc[0] = ft_exit_target_pc(pc + fields->size) - tb->pc;
        tb->lazypc[1] = ft_exit_target_pc(fields->imm64) - tb->pc;
        tb->canlink[0] = 1;
        tb->canlink[1] = 1;
#endif
        if (fields->direct_float_xx) {
#ifdef CONFIG_SOFTMMU
            FastDirectBranchKind kind = fields->direct_branch_kind;

            cond_lhs = la_a4;
            taken_if_equal = kind == FT_DIRECT_BRANCH_NE ||
                             kind == FT_DIRECT_BRANCH_GEU ||
                             kind == FT_DIRECT_BRANCH_GTU;
#ifdef CONFIG_LATX_TU
            /* TU link slots use integer branches. Read FCC at the Jcc so
             * integer scratch registers are free throughout the gap. */
            if (tb && tb->s_data && ft_tu_direct_jcc_enabled()) {
                FT_LA_MOVCF2GR_EMIT(&out, cond_lhs, ft_float_branch_fcc(kind));
            }
#endif
#else
            return 0;
#endif
        } else if (fields->direct_float_result) {
#ifdef CONFIG_SOFTMMU
            cond_lhs = la_a4;
#else
            cond_lhs = la_t2;
#endif
            cond_rhs = la_zero;
        } else if (fields->direct_cmp_lhs_gpr >= 0) {
            cond_lhs = ft_gpr(fields->direct_cmp_lhs_gpr);
            if (fields->direct_cmp_rhs_gpr >= 0) {
                cond_rhs = ft_gpr(fields->direct_cmp_rhs_gpr);
            }
            if (fields->direct_branch_kind == FT_DIRECT_BRANCH_BIT_SET ||
                fields->direct_branch_kind == FT_DIRECT_BRANCH_BIT_CLEAR) {
                int bit_width = fields->direct_cmp_width;

                if (fields->direct_bit_index_gpr >= 0) {
                    FT_LA_ANDI_EMIT(&out, tmp1,
                                    ft_gpr(fields->direct_bit_index_gpr),
                                    bit_width - 1);
                    FT_LA_SRL_D_EMIT(&out, tmp2, cond_lhs, tmp1);
                } else {
                    FT_LA_SRLI_D_EMIT(&out, tmp2, cond_lhs,
                                      fields->direct_bit_index_imm &
                                      (bit_width - 1));
                }
                FT_LA_ANDI_EMIT(&out, tmp2, tmp2, 1);
                cond_lhs = tmp2;
                cond_rhs = la_zero;
            } else if (fields->direct_cmp_width < 64) {
                bool signed_compare =
                    fields->direct_branch_kind == FT_DIRECT_BRANCH_LT ||
                    fields->direct_branch_kind == FT_DIRECT_BRANCH_GE ||
                    fields->direct_branch_kind == FT_DIRECT_BRANCH_LE ||
                    fields->direct_branch_kind == FT_DIRECT_BRANCH_GT;
                int shift = 64 - fields->direct_cmp_width;

                if (signed_compare) {
                    FT_LA_SLLI_D_EMIT(&out, tmp0, cond_lhs, shift);
                    FT_LA_SRAI_D_EMIT(&out, tmp0, tmp0, shift);
                } else {
                    FT_LA_BSTRPICK_D_EMIT(&out, tmp0, cond_lhs,
                                          fields->direct_cmp_width - 1, 0);
                }
                cond_lhs = tmp0;
                if (fields->direct_cmp_rhs_gpr >= 0) {
                    if (signed_compare) {
                        FT_LA_SLLI_D_EMIT(&out, tmp1, cond_rhs, shift);
                        FT_LA_SRAI_D_EMIT(&out, tmp1, tmp1, shift);
                    } else {
                        FT_LA_BSTRPICK_D_EMIT(&out, tmp1, cond_rhs,
                                              fields->direct_cmp_width - 1, 0);
                    }
                    cond_rhs = tmp1;
                }
            }
            switch (fields->direct_branch_kind) {
            case FT_DIRECT_BRANCH_EQ:
                taken_if_equal = true;
                break;
            case FT_DIRECT_BRANCH_NE:
                break;
            case FT_DIRECT_BRANCH_LT:
                FT_LA_SLT_EMIT(&out, tmp2, cond_lhs, cond_rhs);
                cond_lhs = tmp2;
                cond_rhs = la_zero;
                break;
            case FT_DIRECT_BRANCH_GE:
                FT_LA_SLT_EMIT(&out, tmp2, cond_lhs, cond_rhs);
                cond_lhs = tmp2;
                cond_rhs = la_zero;
                taken_if_equal = true;
                break;
            case FT_DIRECT_BRANCH_LTU:
                FT_LA_SLTU_EMIT(&out, tmp2, cond_lhs, cond_rhs);
                cond_lhs = tmp2;
                cond_rhs = la_zero;
                break;
            case FT_DIRECT_BRANCH_GEU:
                FT_LA_SLTU_EMIT(&out, tmp2, cond_lhs, cond_rhs);
                cond_lhs = tmp2;
                cond_rhs = la_zero;
                taken_if_equal = true;
                break;
            case FT_DIRECT_BRANCH_LE:
                FT_LA_SLT_EMIT(&out, tmp2, cond_rhs, cond_lhs);
                cond_lhs = tmp2;
                cond_rhs = la_zero;
                taken_if_equal = true;
                break;
            case FT_DIRECT_BRANCH_GT:
                FT_LA_SLT_EMIT(&out, tmp2, cond_rhs, cond_lhs);
                cond_lhs = tmp2;
                cond_rhs = la_zero;
                break;
            case FT_DIRECT_BRANCH_LEU:
                FT_LA_SLTU_EMIT(&out, tmp2, cond_rhs, cond_lhs);
                cond_lhs = tmp2;
                cond_rhs = la_zero;
                taken_if_equal = true;
                break;
            case FT_DIRECT_BRANCH_GTU:
                FT_LA_SLTU_EMIT(&out, tmp2, cond_rhs, cond_lhs);
                cond_lhs = tmp2;
                cond_rhs = la_zero;
                break;
            case FT_DIRECT_BRANCH_ALWAYS:
                cond_lhs = la_zero;
                cond_rhs = la_zero;
                taken_if_equal = true;
                break;
            case FT_DIRECT_BRANCH_NEVER:
                cond_lhs = la_zero;
                cond_rhs = la_zero;
                break;
            case FT_DIRECT_BRANCH_BIT_SET:
                break;
            case FT_DIRECT_BRANCH_BIT_CLEAR:
                taken_if_equal = true;
                break;
            default:
                break;
            }
        } else {
        /* Match the legacy system translator: SETX86J writes itemp0 (a4). */
#ifdef CONFIG_SOFTMMU
            cond_lhs = la_a4;
#else
            cond_lhs = la_t0;
#endif
            FT_LA_SETX86J_EMIT(&out, cond_lhs, fields->reg);
        }
        {
            int tu_emitted = ft_emit_tu_jcc_compare(
                tb, code, &out, pc, fields, cond_lhs, cond_rhs,
                taken_if_equal);

            if (tu_emitted) {
                return tu_emitted;
            }
            tu_emitted = ft_emit_tu_jcc_partial_compare(
                tb, code, &out, pc, fields, cond_lhs, cond_rhs,
                taken_if_equal);
            if (tu_emitted) {
                return tu_emitted;
            }
        }
        return ft_emit_jcc_exit_or_self_loop(tb, code, &out, pc, fields,
                                             cond_lhs, cond_rhs,
                                             taken_if_equal);
    }
    case FT_CALL_REL32:
    {
        target_ulong target = pc + fields->size + fields->imm;
        target_ulong ret_addr = pc + fields->size;
        int exit_emitted;

        ft_emit_li64(&out, la_t1, ret_addr);
#ifndef QUICKTRANS_LATU
        if (ft_tu_mode_enabled() &&
            ((pc ^ target) & TARGET_PAGE_MASK) != 0) {
            ft_emit_tu_native_return_metadata(tb, &out,
                                              (uintptr_t)tb->tc.ptr,
                                              ret_addr);
        } else {
#endif
            ft_emit_jrra_call_metadata(tb, &out, (uintptr_t)tb->tc.ptr,
                                       ret_addr, true);
#ifndef QUICKTRANS_LATU
        }
#endif
        FT_LA_ST_D_EMIT(&out, la_t1, ft_gpr(rsp_index), -8);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                               ft_gpr(rsp_index), -8);
#ifndef QUICKTRANS_LATU
        lsenv->tr_data->pc_next = ret_addr;
        ft_emit_lats_soft_ras_push(tb, &out, ret_addr);
#endif
        if (ft_tu_mode_enabled()) {
            int tu_emitted = 0;

            if (((pc ^ target) & TARGET_PAGE_MASK) != 0) {
                tu_emitted = ft_emit_tu_jmp_branch_or_zero(tb, code, &out,
                                                           target);
                if (tu_emitted) {
                    return tu_emitted;
                }
            }
        }
        exit_emitted = ft_emit_direct_link_exit(tb, &out, 0, target, la_t1);
        if (!exit_emitted) {
            return 0;
        }
        return out - code;
    }
    case FT_CALL_RM64:
    {
        target_ulong ret_addr = pc + fields->size;
        int target;

        if (!ft_emit_load_rm64(&out, fields, pc, &target)) {
            return 0;
        }
        FT_LA_OR_EMIT(&out, la_r21, target, la_zero);
        ft_emit_li64(&out, la_t1, ret_addr);
        ft_emit_jrra_call_metadata(tb, &out, (uintptr_t)tb->tc.ptr,
                                   ret_addr, false);
        FT_LA_ST_D_EMIT(&out, la_t1, ft_gpr(rsp_index), -8);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                               ft_gpr(rsp_index), -8);
#ifndef QUICKTRANS_LATU
        lsenv->tr_data->pc_next = ret_addr;
        ft_emit_lats_soft_ras_push(tb, &out, ret_addr);
#endif
#if defined(QUICKTRANS_LATU) && !defined(QUICKTRANS_LATU_MINIMAL_HOST)
        return (out - code) + latx_indirect_goto_macro_emit_for_fast(out);
#elif defined(QUICKTRANS_LATU)
        return 0;
#else
        return (out - code) +
               ft_emit_lats_indirect_lookup_exit(tb, &out, la_r21, la_t1,
                                                 false);
#endif
    }
    case FT_JMP_REL32:
    {
        target_ulong target = pc + fields->size + fields->imm;
        int tu_emitted = ft_emit_tu_jmp_branch_or_zero(tb, code, &out,
                                                       target);

        if (tu_emitted) {
            return tu_emitted;
        }
        return ft_emit_direct_link_exit(tb, &out, 0, target, la_t1);
    }
    case FT_JMP_RM64:
    {
        int target;

        if (!ft_emit_load_rm64(&out, fields, pc, &target)) {
            return 0;
        }
        FT_LA_OR_EMIT(&out, la_r21, target, la_zero);
#if defined(QUICKTRANS_LATU) && !defined(QUICKTRANS_LATU_MINIMAL_HOST)
        return (out - code) + latx_indirect_goto_macro_emit_for_fast(out);
#elif defined(QUICKTRANS_LATU)
        return 0;
#else
        return (out - code) +
               ft_emit_lats_indirect_lookup_exit(tb, &out, la_r21, la_t1,
                                                 false);
#endif
    }
    case FT_RET_IMM16:
#if defined(QUICKTRANS_LATU) && !defined(QUICKTRANS_LATU_MINIMAL_HOST)
        /* RET's unsigned imm16 plus the return address may exceed simm12. */
        if (!ft_fits_simm12(8 + fields->imm)) {
            int target = option_jr_ra_stack ? la_t1 : la_r21;

            FT_LA_LD_D_EMIT(&out, target, ft_gpr(rsp_index), 0);
            if (!ft_emit_li32(&out, la_t2, 8 + fields->imm)) {
                return 0;
            }
            FT_LA_ADD_D_EMIT(&out, ft_gpr(rsp_index),
                            ft_gpr(rsp_index), la_t2);
            if (option_jr_ra_stack) {
                FT_LA_JIRL_EMIT(&out, la_zero, target, 0);
                return out - code;
            }
            ft_prepare_ret_indirect_goto(tb, code);
            return (out - code) + latx_indirect_goto_macro_emit_for_fast(out);
        }
        if (option_jr_ra_stack) {
            FT_LA_LD_D_EMIT(&out, la_t1, ft_gpr(rsp_index), 0);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                               ft_gpr(rsp_index), 8 + fields->imm);
            FT_LA_JIRL_EMIT(&out, la_zero, la_t1, 0);
            return out - code;
        }
        ft_prepare_ret_indirect_goto(tb, code);
        return latx_ret_indirect_goto_macro_emit_for_fast(code, 8 + fields->imm);
#elif defined(QUICKTRANS_LATU)
        return 0;
#else
        FT_LA_LD_D_EMIT(&out, la_t1, ft_gpr(rsp_index), 0);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                               ft_gpr(rsp_index), 8 + fields->imm);
        ft_prepare_ret_indirect_goto(tb, code);
#ifndef QUICKTRANS_LATU
        ft_emit_lats_soft_ras_pop(tb, &out, la_t1);
#endif
        return (out - code) +
               ft_emit_lats_indirect_lookup_exit(tb, &out, la_t1, la_t2,
                                                 true);
#endif
    case FT_RET:
#if defined(QUICKTRANS_LATU) && !defined(QUICKTRANS_LATU_MINIMAL_HOST)
        if (option_jr_ra_stack) {
            FT_LA_LD_D_EMIT(&out, la_t1, ft_gpr(rsp_index), 0);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), 8);
            FT_LA_JIRL_EMIT(&out, la_zero, la_t1, 0);
            return out - code;
        }
        ft_prepare_ret_indirect_goto(tb, code);
        return latx_ret_indirect_goto_macro_emit_for_fast(code, 8);
#elif defined(QUICKTRANS_LATU)
        return 0;
#else
        FT_LA_LD_D_EMIT(&out, la_t1, ft_gpr(rsp_index), 0);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                               ft_gpr(rsp_index), 8);
        ft_prepare_ret_indirect_goto(tb, code);
#ifndef QUICKTRANS_LATU
        ft_emit_lats_soft_ras_pop(tb, &out, la_t1);
#endif
        return (out - code) +
               ft_emit_lats_indirect_lookup_exit(tb, &out, la_t1, la_t2,
                                                 true);
#endif
    case FT_MOVQ_XMM_RM64:
    {
        int dst;
        int addr;

        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int src = ft_modrm_rm_index(fields);

            if (src >= XMM_NUM) {
                return 0;
            }
            if (dst == src) {
                FT_LA_VINSGR2VR_D_EMIT(&out, ft_xmm(dst), la_zero, 1);
            } else {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_LATX_AVX_OPT)
                if (option_enable_lasx) {
                    FT_LA_XVPICKVE_D_EMIT(&out, ft_xmm(dst), ft_xmm(src), 0);
                    break;
                }
#endif
                FT_LA_VANDI_B_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
                FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_xmm(src), 0);
            }
        } else {
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                             ft_mem_access_offset(fields, addr));
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_LATX_AVX_OPT)
            if (option_enable_lasx) {
                FT_LA_XVPICKVE_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
                break;
            }
#endif
            FT_LA_VXOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst), ft_xmm(dst));
            FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
        }
        break;
    }
    case FT_MOVQ_MMX_RM64:
    {
        int dst;

        dst = ft_modrm_reg_index(fields);
        if (dst >= 8) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int src = ft_modrm_rm_index(fields);

            if (src >= 8) {
                return 0;
            }
            FT_LA_FMOV_D_EMIT(&out, ft_mmx(dst), ft_mmx(src));
        } else {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            FT_LA_FLD_D_EMIT(&out, ft_mmx(dst), addr,
                                   ft_mem_access_offset(fields, addr));
        }
        break;
    }
    case FT_MOVQ_RM64_XMM:
    {
        int src;
        int addr;

        src = ft_modrm_reg_index(fields);
        if (src >= XMM_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

            if (dst >= XMM_NUM) {
                return 0;
            }
            if (dst == src) {
                FT_LA_VINSGR2VR_D_EMIT(&out, ft_xmm(dst), la_zero, 1);
            } else {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_LATX_AVX_OPT)
                if (option_enable_lasx) {
                    FT_LA_XVPICKVE_D_EMIT(&out, ft_xmm(dst), ft_xmm(src), 0);
                    break;
                }
#endif
                FT_LA_VANDI_B_EMIT(&out, ft_xmm(dst), ft_xmm(dst), 0);
                FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_xmm(src), 0);
            }
        } else {
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            FT_LA_FST_D_EMIT(&out, ft_xmm(src), addr,
                             ft_mem_access_offset(fields, addr));
        }
        break;
    }
    case FT_MOVQ_XMM_R64:
    {
        int dst;
        int src;

        if (!ft_rex_w(fields) || fields->modrm_mod != 3) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        src = ft_modrm_rm_index(fields);
        if (dst >= XMM_NUM || src >= GPR_NUM) {
            return 0;
        }
        ft_emit_raw(&out, FT_LA_OPCODE_VANDI_B | ft_xmm(dst) | (ft_xmm(dst) << 5));
        ft_emit_raw(&out, FT_LA_OPCODE_VINSGR2VR_D | ft_xmm(dst) | (ft_gpr(src) << 5));
        break;
    }
    case FT_MOVQ_R64_XMM:
    {
        int dst;
        int src;

        if (!ft_rex_w(fields) || fields->modrm_mod != 3) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        dst = ft_modrm_rm_index(fields);
        if (src >= XMM_NUM || dst >= GPR_NUM) {
            return 0;
        }
        ft_emit_raw(&out, FT_LA_OPCODE_VPICKVE2GR_DU | ft_gpr(dst) | (ft_xmm(src) << 5));
        break;
    }
    case FT_PINSR_XMM_GPR_IMM8:
    {
        int addr;
        int dst;
        int src;
        int imm = fields->imm & 0xff;

        if (fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
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
        } else {
            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            src = la_t0;
            if (fields->id == dt_X86_INS_PINSRB && !ft_rex_w(fields)) {
                FT_LA_LD_BU_EMIT(&out, src, addr,
                                  ft_mem_access_offset(fields, addr));
            } else if (fields->id == dt_X86_INS_PINSRW &&
                       !ft_rex_w(fields)) {
                FT_LA_LD_HU_EMIT(&out, src, addr,
                                  ft_mem_access_offset(fields, addr));
            } else if (fields->id == dt_X86_INS_PINSRD &&
                       !ft_rex_w(fields)) {
                FT_LA_LD_WU_EMIT(&out, src, addr,
                                  ft_mem_access_offset(fields, addr));
            } else if (fields->id == dt_X86_INS_PINSRQ &&
                       ft_rex_w(fields)) {
                FT_LA_LD_D_EMIT(&out, src, addr,
                                 ft_mem_access_offset(fields, addr));
            } else {
                return 0;
            }
        }
        if (fields->id == dt_X86_INS_PINSRB && !ft_rex_w(fields)) {
            FT_LA_VINSGR2VR_B_EMIT(&out, ft_xmm(dst), src, imm & 0xf);
        } else if (fields->id == dt_X86_INS_PINSRW && !ft_rex_w(fields)) {
            FT_LA_VINSGR2VR_H_EMIT(&out, ft_xmm(dst), src, imm & 0x7);
        } else if (fields->id == dt_X86_INS_PINSRD && !ft_rex_w(fields)) {
            FT_LA_VINSGR2VR_W_EMIT(&out, ft_xmm(dst), src, imm & 0x3);
        } else if (fields->id == dt_X86_INS_PINSRQ && ft_rex_w(fields)) {
            FT_LA_VINSGR2VR_D_EMIT(&out, ft_xmm(dst), src, imm & 0x1);
        } else {
            return 0;
        }
        break;
    }
    case FT_PEXTR_GPR_XMM_IMM8:
    {
        int dst;
        int src;
        int value;
        int imm = fields->imm & 0xff;

        if (fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
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
            value = ft_gpr(dst);
        } else {
            value = la_t4;
        }
        if (fields->id == dt_X86_INS_PEXTRB && !ft_rex_w(fields)) {
            FT_LA_VPICKVE2GR_BU_EMIT(&out, value, ft_xmm(src),
                                     imm & 0xf);
        } else if (fields->id == dt_X86_INS_PEXTRD && !ft_rex_w(fields)) {
            FT_LA_VPICKVE2GR_WU_EMIT(&out, value, ft_xmm(src),
                                     imm & 0x3);
        } else if (fields->id == dt_X86_INS_PEXTRQ && ft_rex_w(fields)) {
            FT_LA_VPICKVE2GR_DU_EMIT(&out, value, ft_xmm(src),
                                     imm & 0x1);
        } else {
            return 0;
        }
        if (fields->modrm_mod != 3) {
            if (fields->id == dt_X86_INS_PEXTRB) {
                if (!ft_emit_store_rm8(&out, fields, pc, value)) {
                    return 0;
                }
            } else if (fields->id == dt_X86_INS_PEXTRD) {
                if (!ft_emit_store_rm32(&out, fields, pc, value, false)) {
                    return 0;
                }
            } else if (!ft_emit_store_rm64(&out, fields, pc, value)) {
                return 0;
            }
        }
        break;
    }
    case FT_PEXTRQ_R64_XMM_IMM8:
    {
        int dst;
        int src;

        if (!ft_rex_w(fields)) {
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
            ft_emit_raw(&out, FT_LA_OPCODE_VPICKVE2GR_DU | ft_gpr(dst) | (ft_xmm(src) << 5) |
                     (((uint32_t)fields->imm & 1) << 10));
        } else {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            ft_emit_raw(&out, FT_LA_OPCODE_VPICKVE2GR_DU | la_t4 | (ft_xmm(src) << 5) |
                     (((uint32_t)fields->imm & 1) << 10));
#ifdef QUICKTRANS_LATU
            /* Match LATU's native-width store, including unaligned accesses. */
            FT_LA_ST_D_EMIT(&out, la_t4, addr,
                            ft_mem_access_offset(fields, addr));
#else
            if (!ft_emit_store_addr64_bytes(&out, addr,
                                            ft_mem_access_offset(fields, addr),
                                            la_t4)) {
                return 0;
            }
#endif
        }
        break;
    }
    case FT_ADDPD_XMM_XMM:
    case FT_MULPD_XMM_XMM:
    {
        int dst;
        int src;

        if (fields->modrm_mod != 3) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        src = ft_modrm_rm_index(fields);
        if (dst >= XMM_NUM || src >= XMM_NUM) {
            return 0;
        }
        ft_emit_raw(&out, ft_gpr3(fields->kind == FT_ADDPD_XMM_XMM ?
                         FT_LA_OPCODE_VFADD_D : FT_LA_OPCODE_VFMUL_D,
                         ft_xmm(dst), ft_xmm(dst), ft_xmm(src)));
        break;
    }
    case FT_UNPCKPD_XMM_XMMM:
    {
        int dst;
        int src;

        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM ||
            fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
            fields->prefix0 != 0 ||
            (fields->opcode1 != 0x14 && fields->opcode1 != 0x15)) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            src = ft_modrm_rm_index(fields);
            if (src >= XMM_NUM) {
                return 0;
            }
            src = ft_xmm(src);
        } else {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            FT_LA_VLD_EMIT(&out, ft_vscratch, addr,
                           ft_mem_access_offset(fields, addr));
            src = ft_vscratch;
        }
        FT_LA_VSHUF4I_D_EMIT(&out, ft_xmm(dst), src,
                              fields->opcode1 == 0x14 ? 0x8 : 0xd);
        break;
    }
    case FT_MOVAPD_XMM_M128:
    {
        int dst;
        int addr;

        if (fields->modrm_mod == 3 ||
            !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }
        FT_LA_VLD_EMIT(&out, ft_xmm(dst), addr,
                               ft_mem_access_offset(fields, addr));
        break;
    }
    case FT_MOV128_XMM_XMMM:
    {
        int dst;

        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int src = ft_modrm_rm_index(fields);

            if (src >= XMM_NUM) {
                return 0;
            }
            FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(src),
                             ft_xmm(src));
        } else {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            FT_LA_VLD_EMIT(&out, ft_xmm(dst), addr,
                                   ft_mem_access_offset(fields, addr));
        }
        break;
    }
    case FT_MOV128_XMMM_XMM:
    {
        int src;

        src = ft_modrm_reg_index(fields);
        if (src >= XMM_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

            if (dst >= XMM_NUM) {
                return 0;
            }
            FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(src),
                             ft_xmm(src));
        } else {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            if (!ft_emit_store_xmm128_as_gpr(&out, ft_xmm(src), addr,
                                             ft_mem_access_offset(fields,
                                                                  addr))) {
                return 0;
            }
        }
        break;
    }
    case FT_PACK_XMM_XMM:
    {
        int dst;
        int src;
        int scratch;
        int scratch2;

        if (ft_rex_w(fields) || fields->prefix0 != 0 ||
            fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM ||
            !ft_emit_xmmm_src(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_xmm(dst);
        scratch = src == ft_vscratch ? ft_vscratch + 1 : ft_vscratch;
        scratch2 = scratch + 1;
        if (fields->id == dt_X86_INS_PACKSSWB) {
            if (dst == src) {
                FT_LA_VSAT_H_EMIT(&out, dst, dst, 7);
                FT_LA_VPICKEV_B_EMIT(&out, dst, dst, dst);
            } else {
                FT_LA_VSAT_H_EMIT(&out, dst, dst, 7);
                FT_LA_VSAT_H_EMIT(&out, scratch, src, 7);
                FT_LA_VPICKEV_B_EMIT(&out, dst, scratch, dst);
            }
        } else if (fields->id == dt_X86_INS_PACKSSDW) {
            if (dst == src) {
                FT_LA_VSSRANI_H_W_EMIT(&out, dst, dst, 0);
            } else {
#ifdef QUICKTRANS_LATU
                ft_emit_raw(&out, ft_gpr2_rd_rj(FT_LA_OPCODE_VSAT_W | (15u << 10), dst, dst));
                ft_emit_raw(&out, ft_gpr2_rd_rj(FT_LA_OPCODE_VSAT_W | (15u << 10), scratch, src));
                ft_emit_raw(&out, ft_gpr3(FT_LA_OPCODE_VPICKEV_H, dst, scratch, dst));
#else
                FT_LA_VSSRANI_H_W_EMIT(&out, dst, dst, 0);
                FT_LA_VSSRANI_H_W_EMIT(&out, scratch, src, 0);
                FT_LA_VEXTRINS_D_EMIT(&out, dst, scratch, 0x10);
#endif
            }
        } else if (fields->id == dt_X86_INS_PACKUSWB) {
            if (dst == src) {
                FT_LA_VSSRANI_BU_H_EMIT(&out, dst, dst, 0);
                FT_LA_VEXTRINS_D_EMIT(&out, dst, dst, 0x10);
            } else {
                FT_LA_VSSRANI_BU_H_EMIT(&out, dst, dst, 0);
                FT_LA_VSSRANI_BU_H_EMIT(&out, scratch, src, 0);
                FT_LA_VEXTRINS_D_EMIT(&out, dst, scratch, 0x10);
            }
        } else if (fields->id == dt_X86_INS_PACKUSDW) {
            if (dst == src) {
#ifdef QUICKTRANS_LATU
                FT_LA_VMAXI_W_EMIT(&out, dst, dst, 0);
#else
                FT_LA_VSLTI_W_EMIT(&out, scratch, dst, 0);
                FT_LA_VANDN_V_EMIT(&out, dst, scratch, dst);
#endif
                FT_LA_VSSRANI_HU_W_EMIT(&out, dst, dst, 0);
                FT_LA_VEXTRINS_D_EMIT(&out, dst, dst, 0x10);
            } else {
#ifdef QUICKTRANS_LATU
                FT_LA_VMAXI_W_EMIT(&out, dst, dst, 0);
#else
                FT_LA_VSLTI_W_EMIT(&out, scratch, dst, 0);
                FT_LA_VANDN_V_EMIT(&out, dst, scratch, dst);
#endif
#ifdef QUICKTRANS_LATU
                ft_emit_raw(&out, ft_gpr2_rd_rj(FT_LA_OPCODE_VSAT_WU | (15u << 10), dst, dst));
#else
                FT_LA_VSSRANI_HU_W_EMIT(&out, dst, dst, 0);
#endif
#ifdef QUICKTRANS_LATU
                FT_LA_VMAXI_W_EMIT(&out, scratch2, src, 0);
#else
                FT_LA_VSLTI_W_EMIT(&out, scratch2, src, 0);
                FT_LA_VANDN_V_EMIT(&out, scratch2, scratch2, src);
#endif
#ifdef QUICKTRANS_LATU
                ft_emit_raw(&out, ft_gpr2_rd_rj(FT_LA_OPCODE_VSAT_WU | (15u << 10), scratch2, scratch2));
                ft_emit_raw(&out, ft_gpr3(FT_LA_OPCODE_VPICKEV_H, dst, scratch2, dst));
#else
                FT_LA_VSSRANI_HU_W_EMIT(&out, scratch2, scratch2, 0);
                FT_LA_VEXTRINS_D_EMIT(&out, dst, scratch2, 0x10);
#endif
            }
        } else {
            return 0;
        }
        break;
    }
    case FT_MASKMOVDQU_XMM_XMM:
    {
        int src;
        int mask;
        int addr;
        int zero = ft_vscratch;
        int mem_mask = ft_vscratch + 1;
        int mem_data = ft_vscratch + 2;

        if (fields->prefix0 != 0 ||
            fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
            fields->opcode1 != 0xf7 || fields->modrm_mod != 3) {
            return 0;
        }
        src = ft_modrm_reg_index(fields);
        mask = ft_modrm_rm_index(fields);
        if (src >= XMM_NUM || mask >= XMM_NUM) {
            return 0;
        }
        addr = ft_gpr(rdi_index);
        if (fields->addr32) {
            FT_LA_BSTRPICK_D_EMIT(&out, la_t0, addr, 31, 0);
            addr = la_t0;
        }

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        (void)zero;
        FT_LA_VSLTI_B_EMIT(&out, mem_mask, ft_xmm(mask), 0);
        FT_LA_VLD_EMIT(&out, mem_data, addr, 0);
        FT_LA_VBITSEL_V_EMIT(&out, mem_data, mem_data, ft_xmm(src),
                            mem_mask);
#else
        FT_LA_VXOR_V_EMIT(&out, zero, zero, zero);
        FT_LA_VANDI_B_EMIT(&out, mem_mask, ft_xmm(mask), 0x80);
        FT_LA_VSEQ_B_EMIT(&out, mem_mask, mem_mask, zero);
        FT_LA_VLD_EMIT(&out, mem_data, addr, 0);
        FT_LA_VAND_V_EMIT(&out, mem_data, mem_data, mem_mask);
        FT_LA_VNOR_V_EMIT(&out, mem_mask, mem_mask, zero);
        FT_LA_VAND_V_EMIT(&out, mem_mask, ft_xmm(src), mem_mask);
        FT_LA_VOR_V_EMIT(&out, mem_data, mem_data, mem_mask);
#endif
        FT_LA_VST_EMIT(&out, mem_data, addr, 0);
        break;
    }
    case FT_MASKMOVQ_MMX_MMX:
    {
        int src;
        int mask;
        int addr;
        int zero = ft_vscratch;
        int mem_mask = ft_vscratch + 1;
        int mem_data = ft_vscratch + 2;

        if (fields->prefix0 != 0 || fields->prefix2 != 0 ||
            fields->opcode1 != 0xf7 || fields->modrm_mod != 3) {
            return 0;
        }
        src = fields->modrm_reg;
        mask = fields->modrm_rm;
        if (src >= 8 || mask >= 8) {
            return 0;
        }
        addr = ft_gpr(rdi_index);
        if (fields->addr32) {
            FT_LA_BSTRPICK_D_EMIT(&out, la_t0, addr, 31, 0);
            addr = la_t0;
        }

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        (void)zero;
        FT_LA_VSLTI_B_EMIT(&out, mem_mask, ft_mmx(mask), 0);
        FT_LA_FLD_D_EMIT(&out, mem_data, addr, 0);
        FT_LA_VBITSEL_V_EMIT(&out, mem_data, mem_data, ft_mmx(src),
                            mem_mask);
#else
        FT_LA_VXOR_V_EMIT(&out, zero, zero, zero);
        FT_LA_VANDI_B_EMIT(&out, mem_mask, ft_mmx(mask), 0x80);
        FT_LA_VSEQ_B_EMIT(&out, mem_mask, mem_mask, zero);
        FT_LA_FLD_D_EMIT(&out, mem_data, addr, 0);
        FT_LA_VAND_V_EMIT(&out, mem_data, mem_data, mem_mask);
        FT_LA_VNOR_V_EMIT(&out, mem_mask, mem_mask, zero);
        FT_LA_VAND_V_EMIT(&out, mem_mask, ft_mmx(src), mem_mask);
        FT_LA_VOR_V_EMIT(&out, mem_data, mem_data, mem_mask);
#endif
        FT_LA_FST_D_EMIT(&out, mem_data, addr, 0);
        break;
    }
    case FT_SIMD_MADD_XMM_XMM:
    {
        int dst;
        int src;
        int scratch;

        if (ft_rex_w(fields) || fields->prefix0 != 0 ||
            fields->prefix2 != dt_X86_PREFIX_OPSIZE) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM ||
            !ft_emit_xmmm_src(&out, fields, pc, &src)) {
            return 0;
        }
        dst = ft_xmm(dst);
        if (fields->id == dt_X86_INS_PMADDWD) {
            scratch = src == ft_vscratch ? ft_vscratch + 1 : ft_vscratch;
#ifdef QUICKTRANS_LATU
            FT_LA_VMULWEV_W_H_EMIT(&out, scratch, dst, src);
            FT_LA_VMULWOD_W_H_EMIT(&out, scratch + 1, dst, src);
            FT_LA_VADD_W_EMIT(&out, dst, scratch, scratch + 1);
#else
            FT_LA_VXOR_V_EMIT(&out, scratch, scratch, scratch);
            FT_LA_VMADDWEV_W_H_EMIT(&out, scratch, dst, src);
            FT_LA_VMADDWOD_W_H_EMIT(&out, scratch, dst, src);
            FT_LA_VBSLL_V_EMIT(&out, dst, scratch, 0);
#endif
        } else if (fields->id == dt_X86_INS_PMULHRSW) {
            int even = src == ft_vscratch ? ft_vscratch + 1 : ft_vscratch;
            int odd = even + 1;

            FT_LA_VMULWEV_W_H_EMIT(&out, even, dst, src);
            FT_LA_VMULWOD_W_H_EMIT(&out, odd, dst, src);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
            FT_LA_VSRARNI_H_W_EMIT(&out, odd, even, 15);
#else
            FT_LA_VSRAI_W_EMIT(&out, even, even, 14);
            FT_LA_VSRAI_W_EMIT(&out, odd, odd, 14);
            FT_LA_VADDI_WU_EMIT(&out, even, even, 1);
            FT_LA_VADDI_WU_EMIT(&out, odd, odd, 1);
            FT_LA_VSRANI_H_W_EMIT(&out, odd, even, 1);
#endif
            FT_LA_VSHUF4I_W_EMIT(&out, odd, odd,
                                 0xd8);
            FT_LA_VSHUF4I_H_EMIT(&out, dst, odd, 0xd8);
        } else if (fields->id == dt_X86_INS_PMADDUBSW) {
            int base = src == ft_vscratch ? ft_vscratch + 1 : ft_vscratch;

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
            FT_LA_VMULWEV_H_BU_B_EMIT(&out, base, dst, src);
            FT_LA_VMULWOD_H_BU_B_EMIT(&out, base + 1, dst, src);
            FT_LA_VSADD_H_EMIT(&out, dst, base, base + 1);
#else
            FT_LA_VXOR_V_EMIT(&out, base, base, base);
            FT_LA_VABSD_B_EMIT(&out, base + 2, src, base);
            FT_LA_VMADDWEV_H_BU_EMIT(&out, base, dst, base + 2);
            FT_LA_VXOR_V_EMIT(&out, base + 1, base + 1, base + 1);
            FT_LA_VMADDWOD_H_BU_EMIT(&out, base + 1, dst, base + 2);
            FT_LA_ORI_EMIT(&out, la_t0, la_zero, 1);
            FT_LA_VREPLGR2VR_B_EMIT(&out, base + 2, la_t0);
            FT_LA_VSIGNCOV_B_EMIT(&out, base + 3, src, base + 2);
            FT_LA_VMULWEV_H_B_EMIT(&out, base + 4, base + 3, base + 2);
            FT_LA_VMULWOD_H_B_EMIT(&out, base + 2, base + 3, base + 2);
            FT_LA_VMUL_H_EMIT(&out, base, base, base + 4);
            FT_LA_VMUL_H_EMIT(&out, base + 1, base + 1, base + 2);
            FT_LA_VSADD_H_EMIT(&out, dst, base + 1, base);
#endif
        } else {
            return 0;
        }
        break;
    }
    case FT_PXOR_XMM_XMMM:
    case FT_PADD_XMM_XMMM:
    case FT_PADDQ_XMM_XMMM:
    case FT_PMULUDQ_XMM_XMMM:
    case FT_PCMPEQB_XMM_XMMM:
    case FT_SIMD_BIN_XMM_XMMM:
    case FT_PUNPCK_XMM_XMMM:
    {
        int dst;
        int src;
        uint32_t la_opcode;
        int id = 0;
        bool reverse_operands = false;
        bool simd_fpe = false;
        bool fpe = ft_lats_simd_fpe_enabled(tb);

        if (fields->kind == FT_PUNPCK_XMM_XMMM &&
            fields->prefix0 == 0 && fields->prefix2 == 0 &&
            ((fields->opcode1 >= 0x60 && fields->opcode1 <= 0x62) ||
             (fields->opcode1 >= 0x68 && fields->opcode1 <= 0x6a))) {
            bool high = fields->opcode1 >= 0x68;
            uint8_t opcode = high ? fields->opcode1 - 8 : fields->opcode1;

            if (!ft_punpck_opcode_info(fields->prefix2, opcode,
                                       &la_opcode, &id)) {
                return 0;
            }
            dst = ft_modrm_reg_index(fields);
            if (dst >= 8) {
                return 0;
            }
            if (fields->modrm_mod == 3) {
                int src_index = ft_modrm_rm_index(fields);

                if (src_index >= 8) {
                    return 0;
                }
                src = ft_mmx(src_index);
            } else {
                int addr;
                int offset;

                if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                    return 0;
                }
                offset = ft_mem_access_offset(fields, addr);
                if (high) {
                    FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr, offset);
                } else {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
                    /* The MMX result interleaves only the low 32 source bits. */
                    FT_LA_FLD_S_EMIT(&out, ft_vscratch, addr, offset);
#else
                    FT_LA_VXOR_V_EMIT(&out, ft_vscratch, ft_vscratch,
                                      ft_vscratch);
                    FT_LA_LD_WU_EMIT(&out, la_t0, addr, offset);
                    FT_LA_VINSGR2VR_W_EMIT(&out, ft_vscratch, la_t0, 0);
#endif
                }
                src = ft_vscratch;
            }
            ft_emit_raw(&out, ft_gpr3(la_opcode, ft_mmx(dst), src,
                                      ft_mmx(dst)));
            if (high) {
                FT_LA_VEXTRINS_D_EMIT(&out, ft_mmx(dst), ft_mmx(dst), 0x01);
            }
            break;
        }

        if (fields->kind == FT_SIMD_BIN_XMM_XMMM &&
            fields->prefix0 == 0 && fields->prefix2 == 0 &&
            ((fields->opcode1 == 0xd1 &&
              fields->id == dt_X86_INS_PSRLW) ||
             (fields->opcode1 == 0xd2 &&
              fields->id == dt_X86_INS_PSRLD) ||
             (fields->opcode1 == 0xd3 &&
              fields->id == dt_X86_INS_PSRLQ) ||
             (fields->opcode1 == 0xf1 &&
              fields->id == dt_X86_INS_PSLLW) ||
             (fields->opcode1 == 0xf2 &&
              fields->id == dt_X86_INS_PSLLD) ||
             (fields->opcode1 == 0xf3 &&
              fields->id == dt_X86_INS_PSLLQ))) {
            int mmx_dst = ft_modrm_reg_index(fields);
            /* Keep the mask separate from a memory source in scratch. */
            int mask = ft_vscratch + 3;
            int count = ft_vscratch + 1;
            bool is_left = fields->opcode1 >= 0xf1;
            bool is_word = fields->opcode1 == 0xd1 ||
                           fields->opcode1 == 0xf1;
            bool is_dword = fields->opcode1 == 0xd2 ||
                            fields->opcode1 == 0xf2;

            if (mmx_dst >= 8) {
                return 0;
            }
            if (fields->modrm_mod == 3) {
                int src_index = ft_modrm_rm_index(fields);

                if (src_index >= 8) {
                    return 0;
                }
                src = ft_mmx(src_index);
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
            /* MMX consumes only the low 64 bits of the mask. */
            int mask_src = src;
#else
            FT_LA_VREPLVEI_D_EMIT(&out, mask, src, 0);
            int mask_src = mask;
#endif
            if (is_word) {
                FT_LA_VSLEI_DU_EMIT(&out, mask, mask_src, 15);
                ft_emit_raw(&out, FT_LA_OPCODE_VREPLVEI_H | count |
                            (src << 5));
                ft_emit_raw(&out, ft_gpr3(is_left ? FT_LA_OPCODE_VSLL_H :
                                                     FT_LA_OPCODE_VSRL_H,
                                          ft_mmx(mmx_dst), ft_mmx(mmx_dst),
                                          count));
            } else if (is_dword) {
                FT_LA_VSLEI_DU_EMIT(&out, mask, mask_src, 31);
                ft_emit_raw(&out, FT_LA_OPCODE_VREPLVEI_W | count |
                            (src << 5));
                ft_emit_raw(&out, ft_gpr3(is_left ? FT_LA_OPCODE_VSLL_W :
                                                     FT_LA_OPCODE_VSRL_W,
                                          ft_mmx(mmx_dst), ft_mmx(mmx_dst),
                                          count));
            } else {
                FT_LA_VSRLI_D_EMIT(&out, mask, mask_src, 6);
                FT_LA_VSEQI_D_EMIT(&out, mask, mask, 0);
                ft_emit_raw(&out, FT_LA_OPCODE_VREPLVEI_D | count |
                            (src << 5));
                ft_emit_raw(&out, ft_gpr3(is_left ? FT_LA_OPCODE_VSLL_D :
                                                     FT_LA_OPCODE_VSRL_D,
                                          ft_mmx(mmx_dst), ft_mmx(mmx_dst),
                                          count));
            }
            FT_LA_VAND_V_EMIT(&out, ft_mmx(mmx_dst), ft_mmx(mmx_dst),
                              mask);
            goto simd_bin_done;
        }

        if (fields->kind == FT_SIMD_BIN_XMM_XMMM &&
            fields->prefix0 == 0 && fields->prefix2 == 0 &&
            ((fields->opcode1 == 0xda &&
              fields->id == dt_X86_INS_PMINUB) ||
             (fields->opcode1 == 0xde &&
              fields->id == dt_X86_INS_PMAXUB))) {
            int mmx_dst = ft_modrm_reg_index(fields);

            if (mmx_dst >= 8) {
                return 0;
            }
            if (fields->modrm_mod == 3) {
                int src_index = ft_modrm_rm_index(fields);

                if (src_index >= 8) {
                    return 0;
                }
                src = ft_mmx(src_index);
            } else {
                int addr;

                if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                    return 0;
                }
                FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                                 ft_mem_access_offset(fields, addr));
                src = ft_vscratch;
            }
            ft_emit_raw(&out, ft_gpr3(fields->id == dt_X86_INS_PMINUB ?
                                      FT_LA_OPCODE_VMIN_BU :
                                      FT_LA_OPCODE_VMAX_BU,
                                      ft_mmx(mmx_dst), ft_mmx(mmx_dst),
                                      src));
            goto simd_bin_done;
        }

        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }
        if (!ft_emit_xmmm_src(&out, fields, pc, &src)) {
            return 0;
        }
        if (fields->kind == FT_PADD_XMM_XMMM) {
            if (!ft_padd_opcode_info(fields->opcode1, &la_opcode, &id)) {
                return 0;
            }
        } else if (fields->kind == FT_PCMPEQB_XMM_XMMM) {
            if (!ft_pcmpeq_opcode_info(fields->opcode1, &la_opcode, &id)) {
                return 0;
            }
        } else if (fields->kind == FT_SIMD_BIN_XMM_XMMM) {
            if (!ft_simd_bin_opcode_info(fields->prefix0, fields->prefix2,
                                         fields->opcode1,
                                         &la_opcode, &id,
                                         &reverse_operands)) {
                return 0;
            }
            simd_fpe = id == dt_X86_INS_ADDPD ||
                       id == dt_X86_INS_ADDPS ||
                       id == dt_X86_INS_SUBPD ||
                       id == dt_X86_INS_SUBPS ||
                       id == dt_X86_INS_MULPD ||
                       id == dt_X86_INS_MULPS ||
                       id == dt_X86_INS_DIVPD ||
                       id == dt_X86_INS_DIVPS;
        } else if (fields->kind == FT_PUNPCK_XMM_XMMM) {
            if (!ft_punpck_opcode_info(fields->prefix2, fields->opcode1,
                                       &la_opcode, &id)) {
                return 0;
            }
        } else {
            la_opcode = fields->kind == FT_PXOR_XMM_XMMM ? FT_LA_OPCODE_VXOR_V :
                        fields->kind == FT_PADDQ_XMM_XMMM ? FT_LA_OPCODE_VADD_D :
                        fields->kind == FT_PMULUDQ_XMM_XMMM ?
                        FT_LA_OPCODE_VMULWEV_D_WU : FT_LA_OPCODE_VSEQ_B;
        }
        if (fields->kind == FT_PXOR_XMM_XMMM && src == ft_xmm(dst)) {
            FT_LA_VXOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst),
                              ft_xmm(dst));
            goto simd_bin_done;
        }
        if (id == dt_X86_INS_ADDSUBPD || id == dt_X86_INS_ADDSUBPS) {
            int src_add = ft_vscratch;
            int src_sub = ft_vscratch + 1;
            int dst_add = ft_vscratch + 2;
            int dst_sub = ft_vscratch + 3;
            bool is_pd = id == dt_X86_INS_ADDSUBPD;

#ifdef QUICKTRANS_LATU
            /* Read a memory scratch source before replacing it with src_add. */
            FT_LA_VSHUF4I_W_EMIT(&out, src_sub, src, is_pd ? 0x44 : 0x88);
            FT_LA_VSHUF4I_W_EMIT(&out, src_add, src, is_pd ? 0xee : 0xdd);
            FT_LA_VSHUF4I_W_EMIT(&out, dst_add, ft_xmm(dst), is_pd ? 0xee : 0xdd);
            FT_LA_VSHUF4I_W_EMIT(&out, dst_sub, ft_xmm(dst), is_pd ? 0x44 : 0x88);
#else
            FT_LA_VOR_V_EMIT(&out, src_add, src, src);
            FT_LA_VOR_V_EMIT(&out, src_sub, src, src);
            FT_LA_VOR_V_EMIT(&out, dst_add, ft_xmm(dst), ft_xmm(dst));
            FT_LA_VOR_V_EMIT(&out, dst_sub, ft_xmm(dst), ft_xmm(dst));
            FT_LA_VPERMI_W_EMIT(&out, src_add, src_add, is_pd ? 0xee : 0xf5);
            FT_LA_VPERMI_W_EMIT(&out, dst_add, dst_add, is_pd ? 0xee : 0xf5);
            FT_LA_VPERMI_W_EMIT(&out, src_sub, src_sub, is_pd ? 0x44 : 0xa0);
            FT_LA_VPERMI_W_EMIT(&out, dst_sub, dst_sub, is_pd ? 0x44 : 0xa0);
#endif
            ft_emit_raw(&out, ft_gpr3(is_pd ? FT_LA_OPCODE_VFSUB_D :
                                             FT_LA_OPCODE_VFSUB_S,
                                      dst_sub, dst_sub, src_sub));
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
            ft_emit_raw(&out, ft_gpr3(is_pd ? FT_LA_OPCODE_VFADD_D :
                                             FT_LA_OPCODE_VFADD_S,
                                      fpe ? dst_add : ft_xmm(dst),
                                      dst_add, src_add));
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
            if (is_pd) {
                FT_LA_VEXTRINS_D_EMIT(&out,
                                      fpe ? dst_add : ft_xmm(dst),
                                      dst_sub, 0);
            } else {
#ifdef QUICKTRANS_LATU
                FT_LA_VILVL_W_EMIT(&out, fpe ? dst_add : ft_xmm(dst),
                                   fpe ? dst_add : ft_xmm(dst), dst_sub);
#else
                FT_LA_VEXTRINS_W_EMIT(&out,
                                      fpe ? dst_add : ft_xmm(dst),
                                      dst_sub, 0);
                FT_LA_VBSRL_V_EMIT(&out, dst_sub, dst_sub, 8);
                FT_LA_VEXTRINS_W_EMIT(&out,
                                      fpe ? dst_add : ft_xmm(dst),
                                      dst_sub, 0x2 << 4);
#endif
            }
            if (fpe) {
                FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), dst_add, dst_add);
            }
            goto simd_bin_done;
        }
        if (id == dt_X86_INS_SQRTPD || id == dt_X86_INS_SQRTPS ||
            id == dt_X86_INS_RCPPS || id == dt_X86_INS_RSQRTPS) {
            bool check = fpe && (id == dt_X86_INS_SQRTPD ||
                                 id == dt_X86_INS_SQRTPS);
            int result = check ? ft_vscratch + 7 : ft_xmm(dst);

            ft_emit_raw(&out, ft_gpr2_rd_rj(la_opcode, result, src));
            if (check) {
                ft_emit_lats_simd_fpe_check(&out, tb, pc);
                FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), result, result);
            }
            goto simd_bin_done;
        }
        if (id == dt_X86_INS_PSLLW || id == dt_X86_INS_PSLLD ||
            id == dt_X86_INS_PSLLQ || id == dt_X86_INS_PSRLW ||
            id == dt_X86_INS_PSRLD || id == dt_X86_INS_PSRLQ ||
            id == dt_X86_INS_PSRAW || id == dt_X86_INS_PSRAD) {
            /* Keep the mask separate from a memory source in scratch. */
            int mask = ft_vscratch + 3;
            int count = ft_vscratch + 1;
            int sign = ft_vscratch + 2;
            int max_count = (id == dt_X86_INS_PSLLW ||
                             id == dt_X86_INS_PSRLW ||
                             id == dt_X86_INS_PSRAW) ? 15 :
                            (id == dt_X86_INS_PSLLD ||
                             id == dt_X86_INS_PSRLD ||
                             id == dt_X86_INS_PSRAD) ? 31 : 63;
            bool is_arith = id == dt_X86_INS_PSRAW ||
                            id == dt_X86_INS_PSRAD;
            uint32_t repl_op = (max_count == 15) ? FT_LA_OPCODE_VREPLVEI_H :
                               (max_count == 31) ? FT_LA_OPCODE_VREPLVEI_W :
                                                    FT_LA_OPCODE_VREPLVEI_D;
            uint32_t sign_op = (max_count == 15) ? FT_LA_OPCODE_VSRAI_H :
                               (max_count == 31) ? FT_LA_OPCODE_VSRAI_W : 0;

            FT_LA_VREPLVEI_D_EMIT(&out, mask, src, 0);
            if (max_count == 63) {
                /* VSLEI.DU has only a 5-bit immediate.  A qword shift
                 * count is valid iff its bits above bit 5 are all zero. */
                FT_LA_VSRLI_D_EMIT(&out, mask, mask, 6);
                FT_LA_VSEQI_D_EMIT(&out, mask, mask, 0);
            } else {
                FT_LA_VSLEI_DU_EMIT(&out, mask, mask, max_count);
            }
            ft_emit_raw(&out, repl_op | count | (src << 5));
            if (is_arith) {
                ft_emit_raw(&out, sign_op | sign | (ft_xmm(dst) << 5) |
                            (((uint32_t)max_count) << 10));
            }
            ft_emit_raw(&out, ft_gpr3(la_opcode, ft_xmm(dst), ft_xmm(dst),
                                      count));
            if (is_arith) {
                FT_LA_VBITSEL_V_EMIT(&out, ft_xmm(dst), sign, ft_xmm(dst),
                                     mask);
            } else {
                FT_LA_VAND_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst), mask);
            }
            goto simd_bin_done;
        }
        if (id == dt_X86_INS_MINPD || id == dt_X86_INS_MINPS ||
            id == dt_X86_INS_MAXPD || id == dt_X86_INS_MAXPS) {
            int mask = src == ft_vscratch ? ft_vscratch + 1 : ft_vscratch;
            bool is_pd = id == dt_X86_INS_MINPD || id == dt_X86_INS_MAXPD;
            bool is_min = id == dt_X86_INS_MINPD || id == dt_X86_INS_MINPS;
            int lhs = is_min ? src : ft_xmm(dst);
            int rhs = is_min ? ft_xmm(dst) : src;

            if (src == ft_xmm(dst) && !ft_lats_simd_fpe_enabled(tb)) {
                goto simd_bin_done;
            }
            if (is_pd) {
                FT_LA_VFCMP_COND_D_EMIT(&out, mask, lhs, rhs, 0x0f);
            } else {
                FT_LA_VFCMP_COND_S_EMIT(&out, mask, lhs, rhs, 0x0f);
            }
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
            FT_LA_VBITSEL_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst), src, mask);
            goto simd_bin_done;
        }
        if (id == dt_X86_INS_PABSB || id == dt_X86_INS_PABSW ||
            id == dt_X86_INS_PABSD) {
#ifdef QUICKTRANS_LATU
            ft_emit_raw(&out, ft_gpr3(la_opcode, ft_xmm(dst), src, src));
#else
            /* A separate zero preserves an aliased source without a copy. */
            int zero = ft_vscratch + 1;
            FT_LA_VANDI_B_EMIT(&out, zero, zero, 0);
            ft_emit_raw(&out, ft_gpr3(la_opcode, ft_xmm(dst), src, zero));
#endif
            goto simd_bin_done;
        }
        if (simd_fpe) {
            int result = fpe ? ft_vscratch + 7 : ft_xmm(dst);

            if (reverse_operands) {
                ft_emit_raw(&out, ft_gpr3(la_opcode, result, src,
                                          ft_xmm(dst)));
            } else {
                ft_emit_raw(&out, ft_gpr3(la_opcode, result, ft_xmm(dst),
                                          src));
            }
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
            if (fpe) {
                FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), result, result);
            }
        } else if (fields->kind == FT_PUNPCK_XMM_XMMM || reverse_operands) {
            ft_emit_raw(&out, ft_gpr3(la_opcode, ft_xmm(dst), src, ft_xmm(dst)));
        } else {
            ft_emit_raw(&out, ft_gpr3(la_opcode, ft_xmm(dst), ft_xmm(dst), src));
        }
simd_bin_done:
        break;
    }
    case FT_PSRLQ_XMM_IMM8:
    case FT_PSLLQ_XMM_IMM8:
    {
        int dst;
        int ext = (fields->modrm >> 3) & 7;
        int imm = fields->imm & 0xff;

        if (fields->modrm_mod != 3 ||
            (ext != 2 && ext != 6) ||
            fields->imm < 0 || fields->imm > 255) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }
        if (imm > 63) {
            FT_LA_VXOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst),
                              ft_xmm(dst));
            break;
        }
        ft_emit_raw(&out, (ext == 2 ? FT_LA_OPCODE_VSRLI_D : FT_LA_OPCODE_VSLLI_D) |
                 ft_xmm(dst) | (ft_xmm(dst) << 5) |
                 ((uint32_t)imm << 10));
        break;
    }
    case FT_PSHIFT_XMM_IMM8:
    {
        int dst;
        int ext = (fields->modrm >> 3) & 7;
        int imm = fields->imm & 0xff;
        int max_count;
        uint32_t opcode;

        if (fields->modrm_mod != 3 ||
            (ext != 2 && ext != 4 && ext != 6)) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }

        if (fields->opcode1 == 0x71) {
            max_count = 15;
            opcode = ext == 2 ? FT_LA_OPCODE_VSRLI_H :
                     ext == 4 ? FT_LA_OPCODE_VSRAI_H :
                                FT_LA_OPCODE_VSLLI_H;
        } else if (fields->opcode1 == 0x72) {
            max_count = 31;
            opcode = ext == 2 ? FT_LA_OPCODE_VSRLI_W :
                     ext == 4 ? FT_LA_OPCODE_VSRAI_W :
                                FT_LA_OPCODE_VSLLI_W;
        } else if (fields->opcode1 == 0x73) {
            max_count = 63;
            if (ext == 4) {
                return 0;
            }
            opcode = ext == 2 ? FT_LA_OPCODE_VSRLI_D :
                                FT_LA_OPCODE_VSLLI_D;
        } else {
            return 0;
        }

        if (imm > max_count) {
            if (ext == 4) {
                imm = max_count;
            } else {
                FT_LA_VXOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst),
                                  ft_xmm(dst));
                break;
            }
        }
        ft_emit_raw(&out, opcode | ft_xmm(dst) | (ft_xmm(dst) << 5) |
                    ((uint32_t)imm << 10));
        break;
    }
    case FT_SHUF_XMM_XMMM_IMM8:
    {
        int dst;
        int src;
        int imm = fields->imm & 0xff;

        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            src = ft_modrm_rm_index(fields);
            if (src >= XMM_NUM) {
                return 0;
            }
            src = ft_xmm(src);
        } else {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            FT_LA_VLD_EMIT(&out, ft_vscratch, addr,
                                   ft_mem_access_offset(fields, addr));
            src = ft_vscratch;
        }
        if (fields->opcode1 == 0x70 && fields->prefix0 == 0 &&
            fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
            fields->id == dt_X86_INS_PSHUFD) {
            FT_LA_VSHUF4I_W_EMIT(&out, ft_xmm(dst), src, imm);
            break;
        }
        if (fields->opcode1 == 0x70 && fields->prefix2 == 0 &&
            (fields->prefix0 == dt_X86_PREFIX_REPNE ||
             fields->prefix0 == dt_X86_PREFIX_REP) &&
            (fields->id == dt_X86_INS_PSHUFLW ||
             fields->id == dt_X86_INS_PSHUFHW)) {
            int keep = ft_vscratch + 1;

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
            bool low = fields->id == dt_X86_INS_PSHUFLW;

            if (ft_xmm(dst) == src) {
                FT_LA_VSHUF4I_H_EMIT(&out, keep, src, imm);
                FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), keep,
                                      low ? 0x00 : 0x11);
            } else {
                FT_LA_VSHUF4I_H_EMIT(&out, ft_xmm(dst), src, imm);
                FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), src,
                                      low ? 0x11 : 0x00);
            }
#else
            FT_LA_VOR_V_EMIT(&out, keep, src, src);
            if (fields->id == dt_X86_INS_PSHUFLW) {
                FT_LA_VBSRL_V_EMIT(&out, keep, keep, 8);
                FT_LA_VSHUF4I_H_EMIT(&out, ft_xmm(dst), src, imm);
                FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), keep, 0x1 << 4);
            } else {
                FT_LA_VSHUF4I_H_EMIT(&out, ft_xmm(dst), src, imm);
                FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), keep, 0);
            }
#endif
            break;
        }
        if (fields->opcode1 == 0xc6 && fields->prefix0 == 0 &&
            fields->prefix2 == 0 &&
            fields->id == dt_X86_INS_SHUFPS) {
            FT_LA_VSHUF4I_W_EMIT(&out, ft_vscratch + 1, src, imm >> 4);
            FT_LA_VSHUF4I_W_EMIT(&out, ft_vscratch, ft_xmm(dst), imm);
            FT_LA_VPICKEV_D_EMIT(&out, ft_xmm(dst), ft_vscratch + 1,
                                 ft_vscratch);
            break;
        }
        if (fields->opcode1 == 0xc6 && fields->prefix0 == 0 &&
            fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
            fields->id == dt_X86_INS_SHUFPD) {
            static const uint8_t shufpd_imm[4] = { 0x8, 0x9, 0xc, 0xd };

            FT_LA_VSHUF4I_D_EMIT(&out, ft_xmm(dst), src,
                                 shufpd_imm[imm & 3]);
            break;
        }
        return 0;
    }
    case FT_PSRLDQ_XMM_IMM8:
    case FT_PSLLDQ_XMM_IMM8:
    {
        int dst;
        int imm = fields->imm & 0xff;

        if (fields->modrm_reg !=
            (fields->kind == FT_PSRLDQ_XMM_IMM8 ? 3 : 7)) {
            return 0;
        }
        dst = ft_modrm_rm_index(fields);
        if (fields->modrm_mod != 3 || dst >= XMM_NUM) {
            return 0;
        }
        if (imm > 15) {
            FT_LA_VXOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst),
                             ft_xmm(dst));
        } else if (imm == 0) {
            if (ft_emit_zero_code_allowed(fields)) {
                break;
            }
            ft_emit_raw(&out, FT_LA_OPCODE_VORI_B | ft_xmm(dst) | (ft_xmm(dst) << 5));
        } else {
            ft_emit_raw(&out, (fields->kind == FT_PSRLDQ_XMM_IMM8 ?
                      FT_LA_OPCODE_VBSRL_V : FT_LA_OPCODE_VBSLL_V) |
                     ft_xmm(dst) | (ft_xmm(dst) << 5) |
                     ((uint32_t)imm << 10));
        }
        break;
    }
    case FT_PALIGNR_XMM_XMMM_IMM8:
    {
        int dst;
        int src;
        int imm = fields->imm & 0xff;

        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }
        if (imm >= 32) {
            FT_LA_VXOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst),
                             ft_xmm(dst));
            break;
        }
        if (imm >= 16) {
            ft_emit_raw(&out, FT_LA_OPCODE_VBSRL_V | ft_xmm(dst) | (ft_xmm(dst) << 5) |
                     ((uint32_t)(imm - 16) << 10));
            break;
        }
        if (fields->modrm_mod == 3) {
            src = ft_modrm_rm_index(fields);
            if (src >= XMM_NUM) {
                return 0;
            }
            src = ft_xmm(src);
        } else {
            int addr;

            if (!ft_emit_mem_addr(&out, fields, &addr)) {
                return 0;
            }
            FT_LA_VLD_EMIT(&out, ft_vscratch, addr,
                                   ft_mem_access_offset(fields, addr));
            src = ft_vscratch;
        }
        if (imm == 0) {
            ft_emit_raw(&out, FT_LA_OPCODE_VORI_B | ft_xmm(dst) | (src << 5));
        } else {
            ft_emit_raw(&out, FT_LA_OPCODE_VBSRL_V | ft_vscratch | (src << 5) |
                     ((uint32_t)imm << 10));
            ft_emit_raw(&out, FT_LA_OPCODE_VBSLL_V | ft_xmm(dst) | (ft_xmm(dst) << 5) |
                     ((uint32_t)(16 - imm) << 10));
            FT_LA_VOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst),
                             ft_vscratch);
        }
        break;
    }
    case FT_MOVLPS_XMM_M64:
    case FT_MOVLPD_XMM_M64:
    {
        int reg = ft_modrm_reg_index(fields);
        int addr;

        if (reg >= XMM_NUM || fields->modrm_mod == 3) {
            return 0;
        }
        if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
            return 0;
        }
        FT_LA_FLD_D_EMIT(&out, ft_vscratch, addr,
                         ft_mem_access_offset(fields, addr));
        FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(reg), ft_vscratch, 0);
        break;
    }
    case FT_MOVHPS_XMM_M64:
    {
        int reg = ft_modrm_reg_index(fields);

        if (reg >= XMM_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int rm = ft_modrm_rm_index(fields);
            uint32_t imm;

            if (rm >= XMM_NUM) {
                return 0;
            }
            if (fields->opcode1 == 0x12) {
                imm = 1;      /* MOVHLPS: src high qword -> dst low qword. */
            } else if (fields->opcode1 == 0x16) {
                imm = 16;     /* MOVLHPS: src low qword -> dst high qword. */
            } else {
                return 0;
            }
            ft_emit_raw(&out, FT_LA_OPCODE_VEXTRINS_D | ft_xmm(reg) |
                        (ft_xmm(rm) << 5) | (imm << 10));
        } else if (fields->opcode1 == 0x17) {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            FT_LA_VPICKVE2GR_DU_EMIT(&out, la_t4, ft_xmm(reg), 1);
#ifdef QUICKTRANS_LATU
            /* Match LATU's native-width store, including unaligned accesses. */
            FT_LA_ST_D_EMIT(&out, la_t4, addr,
                            ft_mem_access_offset(fields, addr));
#else
            if (!ft_emit_store_addr64_bytes(&out, addr,
                                            ft_mem_access_offset(fields, addr),
                                            la_t4)) {
                return 0;
            }
#endif
        } else {
            int src;

            if (fields->opcode1 != 0x16 ||
                !ft_emit_load_rm64(&out, fields, pc, &src)) {
                return 0;
            }
            FT_LA_VINSGR2VR_D_EMIT(&out, ft_xmm(reg), src, 1);
        }
        break;
    }
    case FT_STMXCSR_M32:
    {
        int offset = offsetof(CPUX86State, mxcsr);

        if (fields->modrm_mod == 3 ||
            fields->modrm_reg != 3 ||
            !ft_fits_simm12(offset)) {
            return 0;
        }
        ft_emit_load_env(&out, la_t1, offset, FT_LA_OPCODE_LD_WU);
#ifndef QUICKTRANS_LATU
        /* LATU legacy STMXCSR reads the saved value only. Its soft x87
         * fast arithmetic also uses FCSR, so merging flags leaks x87 state. */
        ft_emit_mxcsr_flags_from_fcsr(&out, la_t1);
        ft_emit_store_env(&out, la_t1, offset, FT_LA_OPCODE_ST_W);
#endif
        if (!ft_emit_store_rm32(&out, fields, pc, la_t1, false)) {
            return 0;
        }
        break;
    }
    case FT_MOVSD_XMM_M64:
    {
        int dst;
        bool is_double = fields->prefix0 == dt_X86_PREFIX_REPNE;

        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int src = ft_modrm_rm_index(fields);

            if (src >= XMM_NUM) {
                return 0;
            }
            ft_emit_raw(&out, (is_double ? FT_LA_OPCODE_VEXTRINS_D :
                               FT_LA_OPCODE_VEXTRINS_W) |
                     ft_xmm(dst) | (ft_xmm(src) << 5));
            break;
        } else {
            int addr;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            ft_emit_raw(&out, ft_gpr3_imm12(is_double ? FT_LA_OPCODE_FLD_D :
                                            FT_LA_OPCODE_FLD_S,
                                   ft_vscratch, addr,
                                   ft_mem_access_offset(fields, addr)));
            if (option_enable_lasx) {
                if (is_double) {
                    FT_LA_XVPICKVE_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
                } else {
                    FT_LA_XVPICKVE_W_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
                }
            } else {
                FT_LA_VXOR_V_EMIT(&out, ft_xmm(dst), ft_xmm(dst),
                                   ft_xmm(dst));
                if (is_double) {
                    FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
                } else {
                    FT_LA_VEXTRINS_W_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
                }
            }
        }
        break;
    }
    case FT_MOVSD_M64_XMM:
    {
        int src;
        bool is_double = fields->prefix0 == dt_X86_PREFIX_REPNE;

        src = ft_modrm_reg_index(fields);
        if (src >= XMM_NUM) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

            if (dst >= XMM_NUM) {
                return 0;
            }
            ft_emit_raw(&out, (is_double ? FT_LA_OPCODE_VEXTRINS_D :
                               FT_LA_OPCODE_VEXTRINS_W) |
                     ft_xmm(dst) | (ft_xmm(src) << 5));
        } else {
            int addr;
#ifndef QUICKTRANS_LATU
            int value = la_t4;
#endif
            int offset;

            if (!ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
                return 0;
            }
            offset = ft_mem_access_offset(fields, addr);
            if (is_double) {
#ifdef QUICKTRANS_LATU
                FT_LA_FST_D_EMIT(&out, ft_xmm(src), addr, offset);
#else
                FT_LA_VPICKVE2GR_DU_EMIT(&out, value, ft_xmm(src), 0);
                if (!ft_emit_store_addr64_bytes(&out, addr, offset, value)) {
                    return 0;
                }
#endif
            } else {
                FT_LA_FST_S_EMIT(&out, ft_xmm(src), addr, offset);
            }
        }
        break;
    }
    case FT_SIMD_SCALAR_BIN_XMM_XMMM:
    {
        int dst;
        int src;
        int id;
        uint32_t la_opcode;
        bool is_double = fields->prefix0 == dt_X86_PREFIX_REPNE;
        bool scalar_noop = false;
        bool simd_fpe;
        bool scalar_direct = false;
        int scalar_result = ft_vscratch;

        if (!ft_simd_scalar_bin_opcode_info(fields->prefix0,
                                            fields->opcode1, &la_opcode,
                                            &id)) {
            return 0;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= XMM_NUM) {
            return 0;
        }
#ifdef QUICKTRANS_LATU
        /* These scalar operations only consume the low element. Match the
         * legacy load without zeroing unused scratch lanes or using a GPR. */
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
#else
        if (!ft_emit_xmmm_src_bytes(&out, fields, pc,
                                     is_double ? 8 : 4, &src)) {
            return 0;
        }
#endif
        simd_fpe = id != dt_X86_INS_RCPSS &&
                   id != dt_X86_INS_RSQRTSS;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    !defined(CONFIG_LATX_AVX_OPT)
        if (fields->scalar_direct_dst &&
            ft_scalar_direct_dst_candidate(fields)) {
            scalar_direct = true;
            scalar_result = ft_xmm(dst);
        }
#endif
        /* Normally preserve the upper XMM lanes by inserting the scalar
         * result. The bounded LATU analysis can prove those lanes unused.
         * The low result is computed in either case, including its traps.
         */
        switch (id) {
        case dt_X86_INS_SQRTSD:
            FT_LA_FSQRT_D_EMIT(&out, scalar_result, src);
            break;
        case dt_X86_INS_SQRTSS:
            FT_LA_FSQRT_S_EMIT(&out, scalar_result, src);
            break;
        case dt_X86_INS_RCPSS:
            FT_LA_FRECIP_S_EMIT(&out, ft_vscratch, src);
            break;
        case dt_X86_INS_RSQRTSS:
            FT_LA_FRSQRT_S_EMIT(&out, ft_vscratch, src);
            break;
        case dt_X86_INS_ADDSD:
            FT_LA_FADD_D_EMIT(&out, scalar_result, ft_xmm(dst), src);
            break;
        case dt_X86_INS_ADDSS:
            FT_LA_FADD_S_EMIT(&out, scalar_result, ft_xmm(dst), src);
            break;
        case dt_X86_INS_SUBSD:
            FT_LA_FSUB_D_EMIT(&out, scalar_result, ft_xmm(dst), src);
            break;
        case dt_X86_INS_MULSD:
            FT_LA_FMUL_D_EMIT(&out, scalar_result, ft_xmm(dst), src);
            break;
        case dt_X86_INS_SUBSS:
            FT_LA_FSUB_S_EMIT(&out, scalar_result, ft_xmm(dst), src);
            break;
        case dt_X86_INS_MULSS:
            FT_LA_FMUL_S_EMIT(&out, scalar_result, ft_xmm(dst), src);
            break;
        case dt_X86_INS_DIVSD:
            FT_LA_FDIV_D_EMIT(&out, scalar_result, ft_xmm(dst), src);
            break;
        case dt_X86_INS_DIVSS:
            FT_LA_FDIV_S_EMIT(&out, scalar_result, ft_xmm(dst), src);
            break;
        case dt_X86_INS_MINSD:
            if (src == ft_xmm(dst) && !ft_lats_simd_fpe_enabled(tb)) {
                scalar_noop = true;
                break;
            }
            FT_LA_FCMP_COND_D_EMIT(&out, 0, ft_xmm(dst), src, 0x03);
            FT_LA_FSEL_EMIT(&out, ft_vscratch, src, ft_xmm(dst), 0);
            break;
        case dt_X86_INS_MINSS:
            if (src == ft_xmm(dst) && !ft_lats_simd_fpe_enabled(tb)) {
                scalar_noop = true;
                break;
            }
            FT_LA_FCMP_COND_S_EMIT(&out, 0, ft_xmm(dst), src, 0x03);
            FT_LA_FSEL_EMIT(&out, ft_vscratch, src, ft_xmm(dst), 0);
            break;
        case dt_X86_INS_MAXSD:
            if (src == ft_xmm(dst) && !ft_lats_simd_fpe_enabled(tb)) {
                scalar_noop = true;
                break;
            }
            FT_LA_FCMP_COND_D_EMIT(&out, 0, src, ft_xmm(dst), 0x03);
            FT_LA_FSEL_EMIT(&out, ft_vscratch, src, ft_xmm(dst), 0);
            break;
        case dt_X86_INS_MAXSS:
            if (src == ft_xmm(dst) && !ft_lats_simd_fpe_enabled(tb)) {
                scalar_noop = true;
                break;
            }
            FT_LA_FCMP_COND_S_EMIT(&out, 0, src, ft_xmm(dst), 0x03);
            FT_LA_FSEL_EMIT(&out, ft_vscratch, src, ft_xmm(dst), 0);
            break;
        default:
            return 0;
        }
        if (scalar_noop) {
            break;
        }
        if (simd_fpe) {
            ft_emit_lats_simd_fpe_check(&out, tb, pc);
        }
        if (scalar_direct) {
            break;
        }
        if (is_double) {
            if (option_enable_lasx) {
                FT_LA_XVINSVE0_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
                break;
            }
            FT_LA_VEXTRINS_D_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
        } else {
            if (option_enable_lasx) {
                FT_LA_XVINSVE0_W_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
                break;
            }
            FT_LA_VEXTRINS_W_EMIT(&out, ft_xmm(dst), ft_vscratch, 0);
        }
        break;
    }
    case FT_SIMD_SCALAR_CMP_XMM_XMMM:
    {
        int lhs;
        int rhs;
        int id;
        bool is_double;
        bool qnan;
        int cueq;
        int cult;
#ifdef CONFIG_SOFTMMU
        int eq = la_a0;
        int lt = la_a1;
        int unordered = la_a2;
        int flags = la_a3;
#else
        int eq = la_t0;
        int lt = la_t1;
        int unordered = la_t2;
        int flags = la_t3;
#endif

        if (!ft_simd_scalar_cmp_opcode_info(fields->prefix0,
                                            fields->prefix2,
                                            fields->opcode1,
                                            &is_double, &qnan, &id)) {
            return 0;
        }
        cueq = FCMP_COND_CUEQ + (qnan ? 1 : 0);
        cult = FCMP_COND_CULT + (qnan ? 1 : 0);
        lhs = ft_modrm_reg_index(fields);
        if (lhs >= XMM_NUM) {
            return 0;
        }
        /* Keep the double-width load schedule: omitting its scratch clear
         * reduced code size but regressed the measured execution latency. */
        if (is_double ? !ft_emit_xmmm_src_bytes(&out, fields, pc, 8, &rhs)
                      : !ft_emit_xmmm_low_src(&out, fields, pc, 4, &rhs)) {
            return 0;
        }
        if (is_double) {
            FT_LA_FCMP_COND_D_EMIT(&out, 0, ft_xmm(lhs), rhs, cueq);
        } else {
            FT_LA_FCMP_COND_S_EMIT(&out, 0, ft_xmm(lhs), rhs, cueq);
        }
        if (is_double) {
            FT_LA_FCMP_COND_D_EMIT(&out, 2, ft_xmm(lhs), rhs, cult);
        } else {
            FT_LA_FCMP_COND_S_EMIT(&out, 2, ft_xmm(lhs), rhs, cult);
        }
        FT_LA_MOVCF2GR_EMIT(&out, eq, 0);
        FT_LA_MOVCF2GR_EMIT(&out, lt, 2);
        FT_LA_AND_EMIT(&out, unordered, lt, eq);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (fields->modrm_mod != 3 && !fields->direct_float_xx &&
            fields->direct_branch_kind == FT_DIRECT_BRANCH_NONE) {
            FT_LA_BSTRINS_W_EMIT(&out, lt, eq, 6, 6);
            FT_LA_BSTRINS_W_EMIT(&out, lt, unordered, 2, 2);
            FT_LA_X86MTFLAG_EMIT(&out, lt, 0x3f);
            break;
        }
#endif
        FT_LA_OR_EMIT(&out, flags, lt, la_zero);
        FT_LA_BSTRINS_W_EMIT(&out, flags, eq, 6, 6);
        FT_LA_BSTRINS_W_EMIT(&out, flags, unordered, 2, 2);
        FT_LA_X86MTFLAG_EMIT(&out, flags, 0x3f);
        if (fields->direct_float_xx) {
#ifdef CONFIG_SOFTMMU
            /* EQ/NE and B/AE can reuse the comparisons above. BE/A need
             * unordered-or-less-or-equal after the guest flags are saved. */
            if (fields->direct_branch_kind == FT_DIRECT_BRANCH_LEU ||
                fields->direct_branch_kind == FT_DIRECT_BRANCH_GTU) {
                int cond = FCMP_COND_CULE + (qnan ? 1 : 0);

                if (is_double) {
                    FT_LA_FCMP_COND_D_EMIT(&out, 0, ft_xmm(lhs), rhs, cond);
                } else {
                    FT_LA_FCMP_COND_S_EMIT(&out, 0, ft_xmm(lhs), rhs, cond);
                }
            }
#else
            return 0;
#endif
        } else if (fields->direct_branch_kind != FT_DIRECT_BRANCH_NONE) {
            switch (fields->direct_branch_kind) {
            case FT_DIRECT_BRANCH_EQ: break;
            case FT_DIRECT_BRANCH_NE: FT_LA_XORI_EMIT(&out, unordered, eq, 1); break;
            case FT_DIRECT_BRANCH_LTU: FT_LA_OR_EMIT(&out, unordered, lt, la_zero); break;
            case FT_DIRECT_BRANCH_GEU: FT_LA_XORI_EMIT(&out, unordered, lt, 1); break;
            case FT_DIRECT_BRANCH_LEU: FT_LA_OR_EMIT(&out, unordered, lt, eq); break;
            case FT_DIRECT_BRANCH_GTU:
                FT_LA_OR_EMIT(&out, unordered, lt, eq);
                FT_LA_XORI_EMIT(&out, unordered, unordered, 1);
                break;
            case FT_DIRECT_BRANCH_BIT_SET: break;
            case FT_DIRECT_BRANCH_BIT_CLEAR: FT_LA_XORI_EMIT(&out, unordered, unordered, 1); break;
            default: return 0;
            }
            if (fields->direct_branch_kind == FT_DIRECT_BRANCH_EQ) {
                FT_LA_OR_EMIT(&out, unordered, eq, la_zero);
            }
#ifdef CONFIG_SOFTMMU
            FT_LA_OR_EMIT(&out, la_a4, unordered, la_zero);
#endif
            break;
        }
        break;
    }
    case FT_STOSQ_REP:
        FT_LA_BEQ_EMIT(&out, ft_gpr(rcx_index), la_zero, 5);
        FT_LA_ST_D_EMIT(&out, ft_gpr(rax_index),
                               ft_gpr(rdi_index), 0);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rdi_index),
                               ft_gpr(rdi_index), 8);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rcx_index),
                               ft_gpr(rcx_index), -1);
        FT_LA_BNE_EMIT(&out, ft_gpr(rcx_index), la_zero, -3);
        break;
    case FT_UNSUPPORTED:
    default:
        return 0;
    }

    if (out == code && fields->skip_flags) {
        FT_LA_NOP_EMIT(&out);
    }

    return out - code;

}
