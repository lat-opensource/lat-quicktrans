/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Atomic, cmpxchg, and integer division emit helpers. */

static void ft_emit_flag2_if_live(uint32_t **out,
                                  const FastTemplateFields *fields,
                                  uint32_t op, int rj, int rk)
{
    if (!fields->skip_flags) {
        ft_emit_raw(out, ft_gpr2(op, rj, rk));
    }
}

static bool ft_emit_imul_unary(uint32_t **out,
                               const FastTemplateFields *fields,
                               target_ulong pc)
{
    int src;

    switch (fields->kind) {
    case FT_IMUL_RM8:
        if (ft_rex_w(fields) || fields->modrm_reg != 5 ||
            !ft_emit_load_rm8(out, fields, pc, &src)) {
            return false;
        }
        FT_LA_EXT_W_B_EMIT(out, la_t1, src);
        FT_LA_EXT_W_B_EMIT(out, la_t2, ft_gpr(rax_index));
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_B,
                              la_t2, la_t1);
        FT_LA_MUL_W_EMIT(out, la_t0, la_t2, la_t1);
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t0, 15, 0);
        return true;
    case FT_IMUL_RM16:
        if (ft_rex_w(fields) || fields->modrm_reg != 5 ||
            !ft_emit_load_rm16(out, fields, pc, &src)) {
            return false;
        }
        FT_LA_EXT_W_H_EMIT(out, la_t1, src);
        FT_LA_EXT_W_H_EMIT(out, la_t2, ft_gpr(rax_index));
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_H,
                              la_t2, la_t1);
        FT_LA_MUL_W_EMIT(out, la_t0, la_t2, la_t1);
        FT_LA_SRLI_D_EMIT(out, la_t1, la_t0, 16);
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rdx_index), la_t1, 15, 0);
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t0, 15, 0);
        return true;
    case FT_IMUL_RM32:
        if (ft_rex_w(fields) || fields->modrm_reg != 5 ||
            !ft_emit_load_rm32(out, fields, pc, &src)) {
            return false;
        }
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_W,
                              ft_gpr(rax_index), src);
        FT_LA_MULW_D_W_EMIT(out, la_t0, ft_gpr(rax_index), src);
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rax_index), la_t0, 31, 0);
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rdx_index), la_t0, 63, 32);
        return true;
    case FT_IMUL_RM64:
        if (!ft_rex_w(fields) || fields->modrm_reg != 5 ||
            !ft_emit_load_rm64(out, fields, pc, &src)) {
            return false;
        }
        /* Only RDX is overwritten before the low product consumes src. */
        if (src == ft_gpr(rdx_index)) {
            FT_LA_OR_EMIT(out, la_t0, src, la_zero);
            src = la_t0;
        }
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_D,
                              ft_gpr(rax_index), src);
        FT_LA_MULH_D_EMIT(out, ft_gpr(rdx_index), ft_gpr(rax_index), src);
        FT_LA_MUL_D_EMIT(out, ft_gpr(rax_index), ft_gpr(rax_index), src);
        return true;
    default:
        return false;
    }
}

static int ft_emit_imul_unary_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    return ft_emit_imul_unary(&out, fields, pc) ?
           (out - code) : 0;
}

static int ft_emit_mul_unary_template(const FastTemplateFields *fields,
                                      TranslationBlock *tb, target_ulong pc,
                                      uint32_t *code)
{
    uint32_t *out = code;
    int src;

    if (fields->kind != FT_MUL_RM8 || ft_rex_w(fields) ||
        fields->modrm_reg != 4 ||
        !ft_emit_load_rm8(&out, fields, pc, &src)) {
        return 0;
    }

    FT_LA_BSTRPICK_D_EMIT(&out, la_t1, src, 7, 0);
    FT_LA_BSTRPICK_D_EMIT(&out, la_t2, ft_gpr(rax_index), 7, 0);
    ft_emit_flag2_if_live(&out, fields, FT_LA_OPCODE_X86MUL_BU,
                          la_t2, la_t1);
    FT_LA_MUL_W_EMIT(&out, la_t0, la_t2, la_t1);
    FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t0, 15, 0);
    return out - code;
}

static bool ft_emit_imul_rm(uint32_t **out, const FastTemplateFields *fields,
                            target_ulong pc)
{
    int dst;
    int src;

    switch (fields->kind) {
    case FT_IMUL_R64_RM64:
        if (!ft_rex_w(fields)) {
            return false;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM || !ft_emit_load_rm64(out, fields, pc, &src)) {
            return false;
        }
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_D,
                              ft_gpr(dst), src);
        FT_LA_MUL_D_EMIT(out, ft_gpr(dst), ft_gpr(dst), src);
        return true;
    case FT_IMUL_R32_RM32:
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(out, fields, pc, &src)) {
            return false;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return false;
        }
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_W,
                              ft_gpr(dst), src);
        FT_LA_MUL_W_EMIT(out, ft_gpr(dst), ft_gpr(dst), src);
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        return true;
    case FT_IMUL_R64_RM64_IMM32:
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(out, fields, pc, &src)) {
            return false;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return false;
        }
        ft_emit_li64(out, la_t1, (uint64_t)(int64_t)(int32_t)fields->imm);
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_D,
                              src, la_t1);
        FT_LA_MUL_D_EMIT(out, ft_gpr(dst), src, la_t1);
        return true;
    case FT_IMUL_R64_RM64_IMM8:
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(out, fields, pc, &src)) {
            return false;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return false;
        }
        FT_LA_ADDI_D_EMIT(out, la_t1, la_zero, (int8_t)fields->imm);
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_D,
                              src, la_t1);
        FT_LA_MUL_D_EMIT(out, ft_gpr(dst), src, la_t1);
        return true;
    case FT_IMUL_R32_RM32_IMM32:
    case FT_IMUL_R32_RM32_IMM8:
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(out, fields, pc, &src) ||
            !ft_emit_li32(out, la_t1, (uint32_t)fields->imm)) {
            return false;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return false;
        }
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_W,
                              src, la_t1);
        FT_LA_MUL_W_EMIT(out, ft_gpr(dst), src, la_t1);
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(dst), ft_gpr(dst), 31, 0);
        return true;
    case FT_IMUL_R16_RM16:
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm16(out, fields, pc, &src)) {
            return false;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return false;
        }
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_H,
                              src, ft_gpr(dst));
        FT_LA_MUL_W_EMIT(out, la_t0, src, ft_gpr(dst));
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst), la_t0, 15, 0);
        return true;
    case FT_IMUL_R16_RM16_IMM16:
    case FT_IMUL_R16_RM16_IMM8:
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm16(out, fields, pc, &src)) {
            return false;
        }
        dst = ft_modrm_reg_index(fields);
        if (dst >= GPR_NUM) {
            return false;
        }
        if (fields->kind == FT_IMUL_R16_RM16_IMM8) {
            FT_LA_ADDI_D_EMIT(out, la_t1, la_zero, (int8_t)fields->imm);
        } else {
            ft_emit_li64(out, la_t1,
                         (uint64_t)(int64_t)(int16_t)fields->imm);
        }
        FT_LA_EXT_W_H_EMIT(out, la_t2, src);
        ft_emit_flag2_if_live(out, fields, FT_LA_OPCODE_X86MUL_H,
                              la_t2, la_t1);
        FT_LA_MUL_W_EMIT(out, la_t0, la_t2, la_t1);
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst), la_t0, 15, 0);
        return true;
    default:
        return false;
    }
}

static int ft_emit_imul_rm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    return ft_emit_imul_rm(&out, fields, pc) ?
           (out - code) : 0;
}

static bool ft_emit_xadd_rm(uint32_t **out, const FastTemplateFields *fields,
                            target_ulong pc)
{
    bool is64 = fields->kind == FT_XADD_RM64_R64;
    bool is16 = fields->prefix2 == dt_X86_PREFIX_OPSIZE;
    bool is8 = fields->opcode1 == 0xc0;
    int width = is64 ? 64 : is16 ? 16 : is8 ? 8 : 32;
    int src = ft_modrm_reg_index(fields);
    int addr;

    if (src >= GPR_NUM || fields->modrm_mod == 3 ||
        !ft_emit_rmw_addr(out, fields, pc, &addr, la_t3)) {
        return false;
    }

    if (width == 32 || width == 64) {
        int old = addr == la_t0 ? la_t4 : la_t0;

        /* AM* traps on 3A6000 when rd aliases the address register. */
        ft_emit_raw(out,
                    ft_gpr3(ft_atomic_opcode(fields,
                                             is64 ? FT_LA_OPCODE_AMADD_DB_D :
                                                    FT_LA_OPCODE_AMADD_DB_W),
                            old, addr, ft_gpr(src)));
        if (!fields->skip_flags) {
            ft_emit_raw(out, ft_gpr2(is64 ? FT_LA_OPCODE_X86ADD_D : FT_LA_OPCODE_X86ADD_W,
                                old, ft_gpr(src)));
        }
        FT_LA_OR_EMIT(out, ft_gpr(src), old, la_zero);
        if (!is64) {
            FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(src), ft_gpr(src), 31, 0);
        }
    } else if (width == 16) {
        int old;

        ft_preserve_cmpxchg_addr(out, &addr);
        old = la_t1;
        FT_LA_BSTRPICK_D_EMIT(out, la_t2, ft_gpr(src), 15, 0);
        ft_emit_atomic_op(out, fields, FT_LA_OPCODE_AMADD_DB_H,
                           old, la_t2, addr);
        if (!fields->skip_flags) {
            FT_LA_X86ADD_H_EMIT(out, old, la_t2);
        }
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(src), old, 15, 0);
    } else {
        /* src may be high-8 (AH/CH/DH/BH) when !REX. */
        bool src_high8 = ft_modrm_reg_is_high8(fields);
        int src_base = src_high8 ?
                       ft_modrm_reg_high8_base_index(fields) : src;
        int old = la_t1;
        int src_value = la_t2;

        if (src_base >= GPR_NUM) {
            return false;
        }
        ft_preserve_cmpxchg_addr(out, &addr);
        if (src_high8) {
            FT_LA_SRLI_D_EMIT(out, src_value, ft_gpr(src_base), 8);
            FT_LA_ANDI_EMIT(out, src_value, src_value, 0xff);
        } else {
            FT_LA_ANDI_EMIT(out, src_value, ft_gpr(src_base), 0xff);
        }
        ft_emit_atomic_op(out, fields, FT_LA_OPCODE_AMADD_DB_B,
                           old, src_value, addr);
        if (!fields->skip_flags) {
            FT_LA_X86ADD_B_EMIT(out, old, src_value);
        }
        if (src_high8) {
            FT_LA_BSTRINS_D_EMIT(out, ft_gpr(src_base), old, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(out, ft_gpr(src_base), old, 7, 0);
        }
    }

    return true;
}

static bool ft_emit_cmpxchg_rm(uint32_t **out,
                               const FastTemplateFields *fields,
                               target_ulong pc)
{
    bool is64 = fields->kind == FT_CMPXCHG_RM64_R64;
    bool is16 = fields->kind == FT_CMPXCHG_RM16_R16;
    bool is8 = fields->kind == FT_CMPXCHG_RM8_R8;
    int src = ft_modrm_reg_index(fields);
    int addr;

    if (src >= GPR_NUM || fields->modrm_mod == 3 ||
        !ft_emit_rmw_addr(out, fields, pc, &addr, la_t4)) {
        return false;
    }
    ft_preserve_cmpxchg_addr(out, &addr);

    if (is8) {
        bool src_high8 = ft_modrm_reg_is_high8(fields);
        int src_base = src_high8 ?
                       ft_modrm_reg_high8_base_index(fields) : src;

        if (src_base >= GPR_NUM) {
            return false;
        }
        if (src_high8) {
            FT_LA_SRLI_D_EMIT(out, la_t2, ft_gpr(src_base), 8);
            FT_LA_ANDI_EMIT(out, la_t2, la_t2, 0xff);
        } else {
            FT_LA_ANDI_EMIT(out, la_t2, ft_gpr(src_base), 0xff);
        }
        FT_LA_ANDI_EMIT(out, la_t1, ft_gpr(rax_index), 0xff);
        ft_emit_atomic_op(out, fields, FT_LA_OPCODE_AMCAS_DB_B,
                           la_t1, la_t2, addr);
        if (!fields->skip_flags) {
            FT_LA_X86SUB_B_EMIT(out, ft_gpr(rax_index), la_t1);
        }
        FT_LA_ANDI_EMIT(out, la_t3, ft_gpr(rax_index), 0xff);
        FT_LA_XOR_EMIT(out, la_t3, la_t1, la_t3);
        FT_LA_BEQ_EMIT(out, la_t3, la_zero, 2);
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t1, 7, 0);
        return true;
    }

    if (is16) {
        FT_LA_BSTRPICK_D_EMIT(out, la_t2, ft_gpr(src), 15, 0);
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(rax_index), 15, 0);
        ft_emit_atomic_op(out, fields, FT_LA_OPCODE_AMCAS_DB_H,
                           la_t1, la_t2, addr);
        if (!fields->skip_flags) {
            FT_LA_X86SUB_H_EMIT(out, ft_gpr(rax_index), la_t1);
        }
        FT_LA_BSTRPICK_D_EMIT(out, la_t3, ft_gpr(rax_index), 15, 0);
        FT_LA_XOR_EMIT(out, la_t3, la_t1, la_t3);
        FT_LA_BEQ_EMIT(out, la_t3, la_zero, 2);
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t1, 15, 0);
        return true;
    }

    if (is64) {
        FT_LA_OR_EMIT(out, la_t1, ft_gpr(rax_index), la_zero);
        FT_LA_OR_EMIT(out, la_t2, ft_gpr(src), la_zero);
        ft_emit_atomic_op(out, fields, FT_LA_OPCODE_AMCAS_DB_D,
                           la_t1, la_t2, addr);
        FT_LA_X86SUB_D_EMIT(out, ft_gpr(rax_index), la_t1);
        FT_LA_XOR_EMIT(out, la_t3, la_t1, ft_gpr(rax_index));
        FT_LA_BEQ_EMIT(out, la_t3, la_zero, 2);
        FT_LA_OR_EMIT(out, ft_gpr(rax_index), la_t1, la_zero);
    } else {
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(rax_index), 31, 0);
        FT_LA_BSTRPICK_D_EMIT(out, la_t2, ft_gpr(src), 31, 0);
        ft_emit_atomic_op(out, fields, FT_LA_OPCODE_AMCAS_DB_W,
                           la_t1, la_t2, addr);
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t1, 31, 0);
        FT_LA_X86SUB_W_EMIT(out, ft_gpr(rax_index), la_t1);
        FT_LA_BSTRPICK_D_EMIT(out, la_t3, ft_gpr(rax_index), 31, 0);
        FT_LA_XOR_EMIT(out, la_t3, la_t1, la_t3);
        FT_LA_BEQ_EMIT(out, la_t3, la_zero, 3);
        FT_LA_OR_EMIT(out, ft_gpr(rax_index), la_t1, la_zero);
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rax_index), ft_gpr(rax_index), 31,
                                  0);
    }
    return true;
}

static bool ft_emit_cmpxchg8b(uint32_t **out,
                              const FastTemplateFields *fields,
                              target_ulong pc)
{
    FastBranchLabel mismatch = { 0 };
    FastBranchLabel done = { 0 };
    FastBranchFixup mismatch_fixup;
    FastBranchFixup done_fixup;
    int addr;

    if (fields->modrm_mod == 3 ||
        !ft_emit_rmw_addr(out, fields, pc, &addr, la_t4)) {
        return false;
    }
    ft_preserve_cmpxchg_addr(out, &addr);

    /* CMPXCHG8B compares EDX:EAX with m64 and exchanges ECX:EBX on match. */
    FT_LA_BSTRPICK_D_EMIT(out, la_t3, ft_gpr(rdx_index), 31, 0);
    FT_LA_SLLI_D_EMIT(out, la_t3, la_t3, 32);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(rax_index), 31, 0);
    FT_LA_OR_EMIT(out, la_t3, la_t3, la_t1);

    FT_LA_BSTRPICK_D_EMIT(out, la_t2, ft_gpr(rcx_index), 31, 0);
    FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, 32);
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(rbx_index), 31, 0);
    FT_LA_OR_EMIT(out, la_t2, la_t2, la_t1);

    FT_LA_OR_EMIT(out, la_t1, la_t3, la_zero);
    ft_emit_atomic_op(out, fields, FT_LA_OPCODE_AMCAS_DB_D, la_t1, la_t2, addr);
    FT_LA_XOR_EMIT(out, la_t2, la_t1, la_t3);

    if (!fields->skip_flags) {
        FT_LA_X86MTFLAG_EMIT(out, la_zero, ZF_USEDEF_BIT);
    }
    ft_emit_branch_placeholder(out, &mismatch_fixup, FT_BRANCH_BNE,
                               la_t2, la_zero, &mismatch);
    if (!fields->skip_flags) {
        FT_LA_ORI_EMIT(out, la_t4, la_zero, 0xfff);
        FT_LA_X86MTFLAG_EMIT(out, la_t4, ZF_USEDEF_BIT);
    }
    ft_emit_branch_placeholder(out, &done_fixup, FT_BRANCH_B, 0, 0, &done);

    ft_bind_branch_label(&mismatch, *out);
    ft_resolve_branch_fixup(&mismatch_fixup);
    FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rax_index), la_t1, 31, 0);
    FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rdx_index), la_t1, 63, 32);

    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&done_fixup);
    return true;
}

static bool ft_emit_cmpxchg16b(uint32_t **out,
                               const FastTemplateFields *fields,
                               target_ulong pc)
{
    FastBranchLabel retry = { 0 };
    FastBranchLabel mismatch = { 0 };
    FastBranchLabel done = { 0 };
    FastBranchFixup mismatch_lo_fixup;
    FastBranchFixup mismatch_hi_fixup;
    FastBranchFixup done_fixup;
    int addr;

    if (fields->modrm_mod == 3 ||
        !ft_emit_rmw_addr(out, fields, pc, &addr, la_t4)) {
        return false;
    }
    ft_preserve_cmpxchg_addr(out, &addr);

    /* CMPXCHG16B compares RDX:RAX with m128 and exchanges RCX:RBX. */
    ft_bind_branch_label(&retry, *out);
    FT_LA_LL_D_EMIT(out, la_t1, addr, 0);
    FT_LA_LD_D_EMIT(out, la_t2, addr, 8);
    ft_emit_branch_placeholder(out, &mismatch_lo_fixup, FT_BRANCH_BNE,
                               la_t1, ft_gpr(rax_index), &mismatch);
    ft_emit_branch_placeholder(out, &mismatch_hi_fixup, FT_BRANCH_BNE,
                               la_t2, ft_gpr(rdx_index), &mismatch);
    FT_LA_OR_EMIT(out, la_t3, ft_gpr(rbx_index), la_zero);
    FT_LA_SC_Q_EMIT(out, la_t3, ft_gpr(rcx_index), addr);
    {
        FastBranchFixup retry_fixup;

        ft_emit_branch_placeholder(out, &retry_fixup, FT_BRANCH_BEQ,
                                   la_t3, la_zero, &retry);
        ft_resolve_branch_fixup(&retry_fixup);
    }

    if (!fields->skip_flags) {
        FT_LA_ORI_EMIT(out, la_t4, la_zero, 0xfff);
        FT_LA_X86MTFLAG_EMIT(out, la_t4, ZF_USEDEF_BIT);
    }
    ft_emit_branch_placeholder(out, &done_fixup, FT_BRANCH_B, 0, 0, &done);

    ft_bind_branch_label(&mismatch, *out);
    ft_resolve_branch_fixup(&mismatch_lo_fixup);
    ft_resolve_branch_fixup(&mismatch_hi_fixup);
    FT_LA_DBAR_EMIT(out, 0);
    if (!fields->skip_flags) {
        FT_LA_X86MTFLAG_EMIT(out, la_zero, ZF_USEDEF_BIT);
    }
    FT_LA_OR_EMIT(out, ft_gpr(rax_index), la_t1, la_zero);
    FT_LA_OR_EMIT(out, ft_gpr(rdx_index), la_t2, la_zero);

    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&done_fixup);
    return true;
}

static bool ft_emit_cmpxchg_reg(uint32_t **out,
                                const FastTemplateFields *fields)
{
    bool is64 = fields->kind == FT_CMPXCHG_RM64_R64;
    bool is16 = fields->kind == FT_CMPXCHG_RM16_R16;
    bool is8 = fields->kind == FT_CMPXCHG_RM8_R8;
    int dst = ft_modrm_rm_index(fields);
    int src = ft_modrm_reg_index(fields);

    if (dst >= GPR_NUM || src >= GPR_NUM ||
        fields->modrm_mod != 3) {
        return false;
    }

    if (is8) {
        bool dst_high8 = ft_modrm_rm_is_high8(fields);
        bool src_high8 = ft_modrm_reg_is_high8(fields);
        int dst_base = dst_high8 ?
                       ft_modrm_rm_high8_base_index(fields) : dst;
        int src_base = src_high8 ?
                       ft_modrm_reg_high8_base_index(fields) : src;

        if (dst_base >= GPR_NUM || src_base >= GPR_NUM) {
            return false;
        }
        if (dst_high8) {
            FT_LA_SRLI_D_EMIT(out, la_t1, ft_gpr(dst_base), 8);
            FT_LA_ANDI_EMIT(out, la_t1, la_t1, 0xff);
        } else {
            FT_LA_ANDI_EMIT(out, la_t1, ft_gpr(dst_base), 0xff);
        }
        if (src_high8) {
            FT_LA_SRLI_D_EMIT(out, la_t2, ft_gpr(src_base), 8);
            FT_LA_ANDI_EMIT(out, la_t2, la_t2, 0xff);
        } else {
            FT_LA_ANDI_EMIT(out, la_t2, ft_gpr(src_base), 0xff);
        }
        if (!fields->skip_flags) {
            FT_LA_X86SUB_B_EMIT(out, ft_gpr(rax_index), la_t1);
        }
        FT_LA_ANDI_EMIT(out, la_t3, ft_gpr(rax_index), 0xff);
        FT_LA_XOR_EMIT(out, la_t3, la_t1, la_t3);
        FT_LA_BEQ_EMIT(out, la_t3, la_zero, 3);
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t1, 7, 0);
        FT_LA_B_EMIT(out, 2);
        if (dst_high8) {
            FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst_base), la_t2, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst_base), la_t2, 7, 0);
        }
    } else if (is16) {
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(dst), 15, 0);
        FT_LA_BSTRPICK_D_EMIT(out, la_t2, ft_gpr(src), 15, 0);
        if (!fields->skip_flags) {
            FT_LA_X86SUB_H_EMIT(out, ft_gpr(rax_index), la_t1);
        }
        FT_LA_BSTRPICK_D_EMIT(out, la_t3, ft_gpr(rax_index), 15, 0);
        FT_LA_XOR_EMIT(out, la_t3, la_t1, la_t3);
        FT_LA_BEQ_EMIT(out, la_t3, la_zero, 3);
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t1, 15, 0);
        FT_LA_B_EMIT(out, 2);
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst), la_t2, 15, 0);
    } else if (is64) {
        FT_LA_OR_EMIT(out, la_t1, ft_gpr(dst), la_zero);
        if (!fields->skip_flags) {
            FT_LA_X86SUB_D_EMIT(out, ft_gpr(rax_index), la_t1);
        }
        FT_LA_XOR_EMIT(out, la_t3, la_t1, ft_gpr(rax_index));
        FT_LA_BEQ_EMIT(out, la_t3, la_zero, 3);
        FT_LA_OR_EMIT(out, ft_gpr(rax_index), la_t1, la_zero);
        FT_LA_B_EMIT(out, 2);
        FT_LA_OR_EMIT(out, ft_gpr(dst), ft_gpr(src), la_zero);
    } else {
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(dst), 31, 0);
        if (!fields->skip_flags) {
            FT_LA_X86SUB_W_EMIT(out, ft_gpr(rax_index), la_t1);
        }
        FT_LA_BSTRPICK_D_EMIT(out, la_t3, ft_gpr(rax_index), 31, 0);
        FT_LA_XOR_EMIT(out, la_t3, la_t1, la_t3);
        FT_LA_BEQ_EMIT(out, la_t3, la_zero, 4);
        FT_LA_OR_EMIT(out, ft_gpr(rax_index), la_t1, la_zero);
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rax_index),
                               ft_gpr(rax_index), 31, 0);
        FT_LA_B_EMIT(out, 2);
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(dst), ft_gpr(src), 31, 0);
    }
    return true;
}

static int ft_emit_cmpxchg_rm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    if (fields->modrm_mod == 3) {
        return ft_emit_cmpxchg_reg(&out, fields) ?
               (out - code) : 0;
    }
    return ft_emit_cmpxchg_rm(&out, fields, pc) ?
           (out - code) : 0;
}

static int ft_emit_cmpxchg8b_template(const FastTemplateFields *fields,
                                      TranslationBlock *tb,
                                      target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    return ft_emit_cmpxchg8b(&out, fields, pc) ? (out - code) : 0;
}

static int ft_emit_cmpxchg16b_template(const FastTemplateFields *fields,
                                       TranslationBlock *tb,
                                       target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    return ft_emit_cmpxchg16b(&out, fields, pc) ? (out - code) : 0;
}

static int ft_emit_xadd_rm_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    return ft_emit_xadd_rm(&out, fields, pc) ?
           (out - code) : 0;
}

static int ft_emit_xadd_reg_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    (void)pc;

    switch (fields->kind) {
    case FT_XADD_R8_R8:
    {
        int dst_base = ft_modrm_reg_index(fields);
        int src_base = ft_modrm_rm_index(fields);
        bool src_high8 = ft_modrm_rm_is_high8(fields);
        bool dst_high8 = ft_modrm_reg_is_high8(fields);

        if (src_high8) {
            src_base = ft_modrm_rm_high8_base_index(fields);
        }
        if (dst_high8) {
            dst_base = ft_modrm_reg_high8_base_index(fields);
        }
        if (dst_base >= GPR_NUM || src_base >= GPR_NUM) {
            return 0;
        }
        if (src_high8) {
            FT_LA_SRLI_D_EMIT(&out, la_t0, ft_gpr(src_base), 8);
            FT_LA_ANDI_EMIT(&out, la_t0, la_t0, 0xff);
        } else {
            FT_LA_ANDI_EMIT(&out, la_t0, ft_gpr(src_base), 0xff);
        }
        if (dst_high8) {
            FT_LA_SRLI_D_EMIT(&out, la_t1, ft_gpr(dst_base), 8);
            FT_LA_ANDI_EMIT(&out, la_t1, la_t1, 0xff);
        } else {
            FT_LA_ANDI_EMIT(&out, la_t1, ft_gpr(dst_base), 0xff);
        }
        if (!fields->skip_flags) {
            FT_LA_X86ADD_B_EMIT(&out, la_t1, la_t0);
        }
        FT_LA_ADD_W_EMIT(&out, la_t2, la_t1, la_t0);
        if (dst_high8) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst_base), la_t0, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst_base), la_t0, 7, 0);
        }
        if (src_high8) {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(src_base), la_t2, 15, 8);
        } else {
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(src_base), la_t2, 7, 0);
        }
        return (out - code);
    }
    case FT_XADD_R16_R16:
    {
        int dst = ft_modrm_reg_index(fields);
        int src = ft_modrm_rm_index(fields);

        if (dst >= GPR_NUM || src >= GPR_NUM) {
            return 0;
        }
        if (!fields->skip_flags) {
            FT_LA_X86ADD_H_EMIT(&out, ft_gpr(src), ft_gpr(dst));
        }
        FT_LA_ADD_W_EMIT(&out, la_t0, ft_gpr(src), ft_gpr(dst));
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 15, 0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(src), la_t0, 15, 0);
        return (out - code);
    }
    case FT_XADD_R32_R32:
    {
        int dst = ft_modrm_reg_index(fields);
        int src = ft_modrm_rm_index(fields);

        if (dst >= GPR_NUM || src >= GPR_NUM) {
            return 0;
        }
        if (!fields->skip_flags) {
            FT_LA_X86ADD_W_EMIT(&out, ft_gpr(src), ft_gpr(dst));
        }
        FT_LA_ADD_W_EMIT(&out, la_t0, ft_gpr(src), ft_gpr(dst));
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (src == dst && fields->prefix0 != dt_X86_PREFIX_LOCK &&
            fields->segment < 0 && (tb->flags & HF_CS64_MASK)) {
            /* With aliased operands the final sum overwrites the old value.
             * Flags above still use the original two low32 operands.
             */
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(src), la_t0, 31, 0);
            return (out - code);
        }
#endif
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(dst), ft_gpr(src), 31, 0);
        FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(src), la_t0, 31, 0);
        return (out - code);
    }
    case FT_XADD_R64_R64:
    {
        int dst = ft_modrm_reg_index(fields);
        int src = ft_modrm_rm_index(fields);

        if (dst >= GPR_NUM || src >= GPR_NUM) {
            return 0;
        }
        if (!fields->skip_flags) {
            FT_LA_X86ADD_D_EMIT(&out, ft_gpr(src), ft_gpr(dst));
        }
        FT_LA_ADD_D_EMIT(&out, la_t0, ft_gpr(src), ft_gpr(dst));
        FT_LA_OR_EMIT(&out, ft_gpr(dst), ft_gpr(src), la_zero);
        FT_LA_OR_EMIT(&out, ft_gpr(src), la_t0, la_zero);
        return (out - code);
    }
    default:
        return 0;
    }
}

static bool ft_emit_div_rm32(uint32_t **out, const FastTemplateFields *fields,
                             target_ulong pc)
{
    int src;

    if (ft_rex_w(fields) || fields->modrm_reg != 6) {
        return false;
    }

    if (fields->instptn_div_kind == FT_INSTPTN_DIV_XOR_DIV32) {
        FT_LA_OR_EMIT(out, ft_gpr(rdx_index), la_zero, la_zero);
    }

    /* The skipped producer precedes all divisor addressing and faults. */
    if (!ft_emit_load_rm32(out, fields, pc, &src)) {
        return false;
    }

    FT_LA_OR_EMIT(out, la_t0, src, la_zero);
    FT_LA_BSTRPICK_D_EMIT(out, la_t0, la_t0, 31, 0);
    {
        FastBranchLabel nonzero = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &nonzero);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&nonzero, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(rdx_index), 31, 0);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 32);
    FT_LA_BSTRPICK_D_EMIT(out, la_t2, ft_gpr(rax_index), 31, 0);
    FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);
    FT_LA_MOD_DU_EMIT(out, ft_gpr(rdx_index), la_t1, la_t0);
    FT_LA_DIV_DU_EMIT(out, ft_gpr(rax_index), la_t1, la_t0);
    FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rdx_index), ft_gpr(rdx_index), 31, 0);
    FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rax_index), ft_gpr(rax_index), 31, 0);
    return true;
}

static bool ft_emit_div_rm16(uint32_t **out, const FastTemplateFields *fields,
                             target_ulong pc)
{
    int src;

    if (ft_rex_w(fields) || fields->modrm_reg != 6 ||
        !ft_emit_load_rm16(out, fields, pc, &src)) {
        return false;
    }
    FT_LA_BSTRPICK_D_EMIT(out, la_t0, src, 15, 0);
    {
        FastBranchLabel nonzero = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &nonzero);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&nonzero, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(rdx_index), 15, 0);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 16);
    FT_LA_BSTRPICK_D_EMIT(out, la_t2, ft_gpr(rax_index), 15, 0);
    FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);
    FT_LA_DIV_DU_EMIT(out, la_t2, la_t1, la_t0);
    FT_LA_SRLI_D_EMIT(out, la_t3, la_t2, 16);
    {
        FastBranchLabel quotient_fits = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BEQ, la_t3,
                                   la_zero, &quotient_fits);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&quotient_fits, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    FT_LA_MOD_DU_EMIT(out, la_t3, la_t1, la_t0);
    FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t2, 15, 0);
    FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rdx_index), la_t3, 15, 0);
    return true;
}

static bool ft_emit_div_rm8(uint32_t **out, const FastTemplateFields *fields,
                            target_ulong pc)
{
    int src;

    if (ft_rex_w(fields) || fields->modrm_reg != 6 ||
        !ft_emit_load_rm8(out, fields, pc, &src)) {
        return false;
    }
    FT_LA_BSTRPICK_D_EMIT(out, la_t0, src, 7, 0);
    {
        FastBranchLabel nonzero = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &nonzero);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&nonzero, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(rax_index), 15, 0);
    FT_LA_DIV_DU_EMIT(out, la_t2, la_t1, la_t0);
    FT_LA_SRLI_D_EMIT(out, la_t3, la_t2, 8);
    {
        FastBranchLabel quotient_fits = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BEQ, la_t3,
                                   la_zero, &quotient_fits);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&quotient_fits, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    FT_LA_MOD_DU_EMIT(out, la_t3, la_t1, la_t0);
    FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t2, 7, 0);
    FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t3, 15, 8);
    return true;
}

static bool ft_emit_idiv_rm8(uint32_t **out, const FastTemplateFields *fields,
                             target_ulong pc)
{
    int src;

    if (ft_rex_w(fields) || fields->modrm_reg != 7 ||
        !ft_emit_load_rm8(out, fields, pc, &src)) {
        return false;
    }

    FT_LA_SLLI_D_EMIT(out, la_t0, src, 56);
    FT_LA_SRAI_D_EMIT(out, la_t0, la_t0, 56);
    {
        FastBranchLabel nonzero = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &nonzero);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&nonzero, *out);
        ft_resolve_branch_fixup(&fixup);
    }

    FT_LA_SLLI_D_EMIT(out, la_t1, ft_gpr(rax_index), 48);
    FT_LA_SRAI_D_EMIT(out, la_t1, la_t1, 48);
    FT_LA_MOD_D_EMIT(out, la_t2, la_t1, la_t0);
    FT_LA_DIV_D_EMIT(out, la_t3, la_t1, la_t0);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t3, 56);
    FT_LA_SRAI_D_EMIT(out, la_t4, la_t4, 56);
    {
        FastBranchLabel quotient_fits = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BEQ, la_t3,
                                   la_t4, &quotient_fits);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&quotient_fits, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t3, 7, 0);
    FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t2, 15, 8);
    return true;
}

static bool ft_emit_idiv_rm16(uint32_t **out, const FastTemplateFields *fields,
                              target_ulong pc)
{
    int src;

    if (ft_rex_w(fields) || fields->modrm_reg != 7 ||
        !ft_emit_load_rm16(out, fields, pc, &src)) {
        return false;
    }

    FT_LA_SLLI_D_EMIT(out, la_t0, src, 48);
    FT_LA_SRAI_D_EMIT(out, la_t0, la_t0, 48);
    {
        FastBranchLabel nonzero = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &nonzero);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&nonzero, *out);
        ft_resolve_branch_fixup(&fixup);
    }

    FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(rdx_index), 15, 0);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 16);
    FT_LA_BSTRPICK_D_EMIT(out, la_t2, ft_gpr(rax_index), 15, 0);
    FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 32);
    FT_LA_SRAI_D_EMIT(out, la_t1, la_t1, 32);

    FT_LA_MOD_D_EMIT(out, la_t2, la_t1, la_t0);
    FT_LA_DIV_D_EMIT(out, la_t3, la_t1, la_t0);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t3, 48);
    FT_LA_SRAI_D_EMIT(out, la_t4, la_t4, 48);
    {
        FastBranchLabel quotient_fits = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BEQ, la_t3,
                                   la_t4, &quotient_fits);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&quotient_fits, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t3, 15, 0);
    FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rdx_index), la_t2, 15, 0);
    return true;
}

static bool ft_emit_idiv_rm32(uint32_t **out, const FastTemplateFields *fields,
                              target_ulong pc)
{
    int src;

    if (ft_rex_w(fields) || fields->modrm_reg != 7) {
        return false;
    }

    if (fields->instptn_div_kind == FT_INSTPTN_DIV_CDQ_IDIV32) {
        FT_LA_SRAI_W_EMIT(out, ft_gpr(rdx_index), ft_gpr(rax_index), 31);
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rdx_index), ft_gpr(rdx_index), 31, 0);
    }

    /* The skipped producer precedes all divisor addressing and faults. */
    if (!ft_emit_load_rm32(out, fields, pc, &src)) {
        return false;
    }

    FT_LA_OR_EMIT(out, la_t0, src, la_zero);
    FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, 32);
    FT_LA_SRAI_D_EMIT(out, la_t0, la_t0, 32);
    {
        FastBranchLabel nonzero = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &nonzero);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&nonzero, *out);
        ft_resolve_branch_fixup(&fixup);
    }

    FT_LA_BSTRPICK_D_EMIT(out, la_t1, ft_gpr(rdx_index), 31, 0);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 32);
    FT_LA_BSTRPICK_D_EMIT(out, la_t2, ft_gpr(rax_index), 31, 0);
    FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);

    FT_LA_MOD_D_EMIT(out, la_t2, la_t1, la_t0);
    FT_LA_DIV_D_EMIT(out, la_t3, la_t1, la_t0);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t3, 32);
    FT_LA_SRAI_D_EMIT(out, la_t4, la_t4, 32);
    {
        FastBranchLabel quotient_fits = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BEQ, la_t3,
                                   la_t4, &quotient_fits);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&quotient_fits, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rdx_index), la_t2, 31, 0);
    FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rax_index), la_t3, 31, 0);
    return true;
}

static void ft_emit_unsigned_div64_core(uint32_t **out)
{
    FT_LA_BNE_EMIT(out, ft_gpr(rdx_index), la_zero, 4);
    FT_LA_MOD_DU_EMIT(out, ft_gpr(rdx_index),
                        ft_gpr(rax_index), la_t0);
    FT_LA_DIV_DU_EMIT(out, ft_gpr(rax_index),
                        ft_gpr(rax_index), la_t0);
    FT_LA_B_EMIT(out, 23);

    FT_LA_ADDI_D_EMIT(out, la_t4, la_zero, 65);
    FT_LA_OR_EMIT(out, la_t1, la_zero, la_zero);
    FT_LA_OR_EMIT(out, la_t2, la_zero, la_zero);

    FT_LA_ADDI_D_EMIT(out, la_t4, la_t4, -1);
    FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 1);
    FT_LA_SLTU_EMIT(out, la_t3, ft_gpr(rdx_index), la_t0);
    FT_LA_BNE_EMIT(out, la_t3, la_zero, 8);
    FT_LA_SLTU_EMIT(out, la_t3, ft_gpr(rax_index), la_t2);
    FT_LA_BNE_EMIT(out, ft_gpr(rdx_index), la_t0, 2);
    FT_LA_BNE_EMIT(out, la_t3, la_zero, 5);

    FT_LA_ADDI_D_EMIT(out, la_t1, la_t1, 1);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rdx_index), ft_gpr(rdx_index),
                        la_t3);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rax_index), ft_gpr(rax_index),
                        la_t2);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rdx_index), ft_gpr(rdx_index),
                        la_t0);

    FT_LA_BEQ_EMIT(out, la_t4, la_zero, 6);
    FT_LA_SRLI_D_EMIT(out, la_t2, la_t2, 1);
    FT_LA_SLLI_D_EMIT(out, la_t3, la_t0, 63);
    FT_LA_OR_EMIT(out, la_t2, la_t2, la_t3);
    FT_LA_SRLI_D_EMIT(out, la_t0, la_t0, 1);
    FT_LA_B_EMIT(out, -16);

    FT_LA_OR_EMIT(out, ft_gpr(rdx_index), la_zero,
                        ft_gpr(rax_index));
    FT_LA_OR_EMIT(out, ft_gpr(rax_index), la_zero, la_t1);
}

static bool ft_emit_div_rm64(uint32_t **out, const FastTemplateFields *fields,
                             target_ulong pc)
{
    int src;

    if (!ft_rex_w(fields) || fields->modrm_reg != 6) {
        return false;
    }

    if (fields->instptn_div_kind == FT_INSTPTN_DIV_XOR_DIV64) {
        FT_LA_OR_EMIT(out, ft_gpr(rdx_index), la_zero, la_zero);
    }

    /* The skipped producer precedes all divisor addressing and faults. */
    if (!ft_emit_load_rm64(out, fields, pc, &src)) {
        return false;
    }

    FT_LA_OR_EMIT(out, la_t0, src, la_zero);
    {
        FastBranchLabel nonzero = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &nonzero);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&nonzero, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    ft_emit_unsigned_div64_core(out);
    return true;
}

static bool ft_emit_idiv_rm64(uint32_t **out, const FastTemplateFields *fields,
                              target_ulong pc)
{
    int src;

    if (!ft_rex_w(fields) || fields->modrm_reg != 7) {
        return false;
    }

    if (fields->instptn_div_kind == FT_INSTPTN_DIV_CQO_IDIV64) {
        FT_LA_SRAI_D_EMIT(out, ft_gpr(rdx_index), ft_gpr(rax_index), 63);
    }

    /* The skipped producer precedes all divisor addressing and faults. */
    if (!ft_emit_load_rm64(out, fields, pc, &src)) {
        return false;
    }

    FT_LA_OR_EMIT(out, la_t0, src, la_zero);
    {
        FastBranchLabel nonzero = { 0 };
        FastBranchFixup fixup;

        ft_emit_branch_placeholder(out, &fixup, FT_BRANCH_BNE, la_t0,
                                   la_zero, &nonzero);
        ft_emit_raise_exception(out, pc, EXCP00_DIVZ);
        ft_bind_branch_label(&nonzero, *out);
        ft_resolve_branch_fixup(&fixup);
    }
    FT_LA_OR_EMIT(out, la_t1, la_zero, la_zero);

    FT_LA_BGE_EMIT(out, ft_gpr(rdx_index), la_zero, 7);
    FT_LA_XORI_EMIT(out, la_t1, la_t1, 1);
    FT_LA_XORI_EMIT(out, la_t1, la_t1, 2);
    FT_LA_BNE_EMIT(out, ft_gpr(rax_index), la_zero, 2);
    FT_LA_ADDI_D_EMIT(out, ft_gpr(rdx_index),
                              ft_gpr(rdx_index), -1);
    FT_LA_NOR_EMIT(out, ft_gpr(rdx_index), ft_gpr(rdx_index),
                        la_zero);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rax_index), la_zero,
                        ft_gpr(rax_index));

    FT_LA_BGE_EMIT(out, la_t0, la_zero, 3);
    FT_LA_SUB_D_EMIT(out, la_t0, la_zero, la_t0);
    FT_LA_XORI_EMIT(out, la_t1, la_t1, 1);

    FT_LA_BNE_EMIT(out, ft_gpr(rdx_index), la_zero, 10);
    FT_LA_MOD_DU_EMIT(out, ft_gpr(rdx_index),
                        ft_gpr(rax_index), la_t0);
    FT_LA_DIV_DU_EMIT(out, ft_gpr(rax_index),
                        ft_gpr(rax_index), la_t0);
    FT_LA_ANDI_EMIT(out, la_t4, la_t1, 2);
    FT_LA_BEQ_EMIT(out, la_t4, la_zero, 2);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rdx_index), la_zero,
                        ft_gpr(rdx_index));
    FT_LA_ANDI_EMIT(out, la_t4, la_t1, 1);
    FT_LA_BEQ_EMIT(out, la_t4, la_zero, 31);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rax_index), la_zero,
                        ft_gpr(rax_index));
    FT_LA_B_EMIT(out, 29);

    FT_LA_ADDI_D_EMIT(out, la_r21, la_zero, 65);
    FT_LA_OR_EMIT(out, la_t3, la_zero, la_zero);
    FT_LA_OR_EMIT(out, la_t2, la_zero, la_zero);

    FT_LA_ADDI_D_EMIT(out, la_r21, la_r21, -1);
    FT_LA_SLLI_D_EMIT(out, la_t3, la_t3, 1);
    FT_LA_SLTU_EMIT(out, la_t4, ft_gpr(rdx_index), la_t0);
    FT_LA_BNE_EMIT(out, la_t4, la_zero, 8);
    FT_LA_SLTU_EMIT(out, la_t4, ft_gpr(rax_index), la_t2);
    FT_LA_BNE_EMIT(out, ft_gpr(rdx_index), la_t0, 2);
    FT_LA_BNE_EMIT(out, la_t4, la_zero, 5);

    FT_LA_ADDI_D_EMIT(out, la_t3, la_t3, 1);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rdx_index), ft_gpr(rdx_index),
                        la_t4);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rax_index), ft_gpr(rax_index),
                        la_t2);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rdx_index), ft_gpr(rdx_index),
                        la_t0);

    FT_LA_BEQ_EMIT(out, la_r21, la_zero, 6);
    FT_LA_SRLI_D_EMIT(out, la_t2, la_t2, 1);
    FT_LA_SLLI_D_EMIT(out, la_t4, la_t0, 63);
    FT_LA_OR_EMIT(out, la_t2, la_t2, la_t4);
    FT_LA_SRLI_D_EMIT(out, la_t0, la_t0, 1);
    FT_LA_B_EMIT(out, -16);

    FT_LA_ANDI_EMIT(out, la_t4, la_t1, 2);
    FT_LA_OR_EMIT(out, ft_gpr(rdx_index), la_zero,
                        ft_gpr(rax_index));
    FT_LA_BEQ_EMIT(out, la_t4, la_zero, 2);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rdx_index), la_zero,
                        ft_gpr(rax_index));
    FT_LA_ANDI_EMIT(out, la_t4, la_t1, 1);
    FT_LA_OR_EMIT(out, ft_gpr(rax_index), la_zero, la_t3);
    FT_LA_BEQ_EMIT(out, la_t4, la_zero, 2);
    FT_LA_SUB_D_EMIT(out, ft_gpr(rax_index), la_zero, la_t3);
    return true;
}
