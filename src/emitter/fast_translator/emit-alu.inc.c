/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Generic ALU FastTemplateFields emit helpers. */

static uint32_t ft_alu_x86_op(FastAluOp op, int width)
{
    switch (op) {
    case FT_ALU_ADD:
        return width == 64 ? FT_LA_OPCODE_X86ADD_D :
               width == 32 ? FT_LA_OPCODE_X86ADD_W :
               width == 16 ? FT_LA_OPCODE_X86ADD_H : FT_LA_OPCODE_X86ADD_B;
    case FT_ALU_OR:
        return width == 64 ? FT_LA_OPCODE_X86OR_D :
               width == 32 ? FT_LA_OPCODE_X86OR_W :
               width == 16 ? FT_LA_OPCODE_X86OR_H : FT_LA_OPCODE_X86OR_B;
    case FT_ALU_ADC:
        return width == 64 ? FT_LA_OPCODE_X86ADC_D :
               width == 32 ? FT_LA_OPCODE_X86ADC_W :
               width == 16 ? FT_LA_OPCODE_X86ADC_H : FT_LA_OPCODE_X86ADC_B;
    case FT_ALU_SBB:
        return width == 64 ? FT_LA_OPCODE_X86SBC_D :
               width == 32 ? FT_LA_OPCODE_X86SBC_W :
               width == 16 ? FT_LA_OPCODE_X86SBC_H : FT_LA_OPCODE_X86SBC_B;
    case FT_ALU_AND:
    case FT_ALU_TEST:
        return width == 64 ? FT_LA_OPCODE_X86AND_D :
               width == 32 ? FT_LA_OPCODE_X86AND_W :
               width == 16 ? FT_LA_OPCODE_X86AND_H : FT_LA_OPCODE_X86AND_B;
    case FT_ALU_SUB:
    case FT_ALU_CMP:
        return width == 64 ? FT_LA_OPCODE_X86SUB_D :
               width == 32 ? FT_LA_OPCODE_X86SUB_W :
               width == 16 ? FT_LA_OPCODE_X86SUB_H : FT_LA_OPCODE_X86SUB_B;
    case FT_ALU_XOR:
        return width == 64 ? FT_LA_OPCODE_X86XOR_D :
               width == 32 ? FT_LA_OPCODE_X86XOR_W :
               width == 16 ? FT_LA_OPCODE_X86XOR_H : FT_LA_OPCODE_X86XOR_B;
    default:
        return 0;
    }
}

static uint32_t ft_alu_data_op(FastAluOp op, int width)
{
    switch (op) {
    case FT_ALU_ADD:
        return width == 64 ? FT_LA_OPCODE_ADD_D : FT_LA_OPCODE_ADD_W;
    case FT_ALU_OR:
        return FT_LA_OPCODE_OR;
    case FT_ALU_ADC:
        return width == 64 ? FT_LA_OPCODE_ADC_D :
               width == 32 ? FT_LA_OPCODE_ADC_W :
               width == 16 ? FT_LA_OPCODE_ADC_H : FT_LA_OPCODE_ADC_B;
    case FT_ALU_SBB:
        return width == 64 ? FT_LA_OPCODE_SBC_D :
               width == 32 ? FT_LA_OPCODE_SBC_W :
               width == 16 ? FT_LA_OPCODE_SBC_H : FT_LA_OPCODE_SBC_B;
    case FT_ALU_AND:
        return FT_LA_OPCODE_AND;
    case FT_ALU_SUB:
        return width == 64 ? FT_LA_OPCODE_SUB_D : FT_LA_OPCODE_SUB_W;
    case FT_ALU_XOR:
        return FT_LA_OPCODE_XOR;
    default:
        return 0;
    }
}

static bool ft_alu_writes_dst(FastAluOp op)
{
    return op != FT_ALU_CMP && op != FT_ALU_TEST;
}

static bool ft_alu_uses_cf(FastAluOp op)
{
    return op == FT_ALU_ADC || op == FT_ALU_SBB;
}

static bool ft_emit_alu_flag(uint32_t **out,
                             const FastTemplateFields *fields,
                             FastAluOp op, int width, int lhs, int rhs)
{
    uint32_t x86_op = ft_alu_x86_op(op, width);

    if (!x86_op) {
        return false;
    }
    if (!fields->skip_flags) {
        ft_emit_raw(out, ft_gpr2(x86_op, lhs, rhs));
    }
    return true;
}

static bool ft_emit_alu_load_rm(uint32_t **out,
                                const FastTemplateFields *fields,
                                target_ulong pc, int width, int *value)
{
    switch (width) {
    case 64:
        return ft_rex_w(fields) && ft_emit_load_rm64(out, fields, pc, value);
    case 32:
        return !ft_rex_w(fields) && ft_emit_load_rm32(out, fields, pc, value);
    case 16:
        return !ft_rex_w(fields) && ft_emit_load_rm16(out, fields, pc, value);
    case 8:
        return !ft_rex_w(fields) && ft_emit_load_rm8(out, fields, pc, value);
    default:
        return false;
    }
}

static bool ft_emit_alu_store_rm(uint32_t **out,
                                 const FastTemplateFields *fields,
                                 target_ulong pc, int width, int value)
{
    if (width == 64 && fields->modrm_mod == 3 &&
        fields->modrm_rm_index < GPR_NUM &&
        value == ft_gpr(fields->modrm_rm_index)) {
        return true;
    }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    /* Ordinary register RM_R results already reside in their destination. */
    if (width == 32 && fields->modrm_mod == 3 &&
#ifdef QUICKTRANS_LATU
        fields->alu_op == FT_ALU_ADD &&
#endif
        fields->alu_form == FT_ALU_FORM_RM_R &&
        !ft_alu_uses_cf(fields->alu_op) &&
        fields->modrm_rm_index < GPR_NUM &&
        value == ft_gpr(fields->modrm_rm_index)) {
        if (!ft_omit_gpr_zext32(fields)) {
            FT_LA_BSTRPICK_D_EMIT(out, value, value, 31, 0);
        }
        return true;
    }
#endif
    switch (width) {
    case 64:
        return ft_emit_store_rm64(out, fields, pc, value);
    case 32:
        /* false omits only the helper's final clear; its OR copy remains. */
        return ft_emit_store_rm32(out, fields, pc, value,
                                  fields->modrm_mod == 3 &&
                                  !ft_omit_gpr_zext32(fields));
    case 16:
        return ft_emit_store_rm16(out, fields, pc, value);
    case 8:
        return ft_emit_store_rm8(out, fields, pc, value);
    default:
        return false;
    }
}

static bool ft_emit_alu_modrm_reg_value(uint32_t **out,
                                        const FastTemplateFields *fields,
                                        int width, int scratch, int *value)
{
    int reg;

    if (width == 8 && ft_modrm_reg_is_high8(fields)) {
        reg = ft_modrm_reg_high8_base_index(fields);
        if (reg >= GPR_NUM) {
            return false;
        }
        FT_LA_SRLI_D_EMIT(out, scratch, ft_gpr(reg), 8);
        *value = scratch;
        return true;
    }

    reg = ft_modrm_reg_index(fields);
    if (reg >= GPR_NUM) {
        return false;
    }
    *value = ft_gpr(reg);
    return true;
}

static bool ft_emit_alu_store_modrm_reg(uint32_t **out,
                                        const FastTemplateFields *fields,
                                        int width, int value)
{
    int reg;

    if (width == 8 && ft_modrm_reg_is_high8(fields)) {
        reg = ft_modrm_reg_high8_base_index(fields);
        if (reg >= GPR_NUM) {
            return false;
        }
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(reg), value, 15, 8);
        return true;
    }

    reg = ft_modrm_reg_index(fields);
    if (reg >= GPR_NUM) {
        return false;
    }
    switch (width) {
    case 64:
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
#ifdef QUICKTRANS_LATU
        if (value == ft_gpr(reg)) {
#else
        if (fields->modrm_mod == 3 &&
            fields->alu_form == FT_ALU_FORM_R_RM &&
            !ft_alu_uses_cf(fields->alu_op) && value == ft_gpr(reg)) {
#endif
            return true;
        }
#endif
        FT_LA_OR_EMIT(out, ft_gpr(reg), value, la_zero);
        return true;
    case 32:
        /* Removing this instruction is valid only when it is a pure
         * high-half clear; otherwise it also copies the result. */
        if (value == ft_gpr(reg) && ft_omit_gpr_zext32(fields)) {
            return true;
        }
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(reg), value, 31, 0);
        return true;
    case 16:
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(reg), value, 15, 0);
        return true;
    case 8:
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(reg), value, 7, 0);
        return true;
    default:
        return false;
    }
}

static bool ft_emit_alu_imm(uint32_t **out, const FastTemplateFields *fields,
                            int width, int *imm_reg)
{
    uint32_t imm;

    switch (width) {
    case 64:
        ft_emit_li64(out, la_t1, (uint64_t)(int64_t)fields->imm);
        *imm_reg = la_t1;
        return true;
    case 32:
        if (!ft_emit_li32(out, la_t1, (uint32_t)fields->imm)) {
            return false;
        }
        *imm_reg = la_t1;
        return true;
    case 16:
        if (!ft_emit_li32(out, la_t1, (uint32_t)(uint16_t)fields->imm)) {
            return false;
        }
        *imm_reg = la_t1;
        return true;
    case 8:
        imm = (uint8_t)fields->imm;
        if (!ft_emit_li32(out, la_t1, imm)) {
            return false;
        }
        *imm_reg = la_t1;
        return true;
    default:
        return false;
    }
}

static bool ft_emit_alu_data(uint32_t **out, const FastTemplateFields *fields,
                             FastAluOp op, int width, int result,
                             int lhs, int rhs)
{
    uint32_t data_op = ft_alu_data_op(op, width);
    int flag_lhs = lhs;
    int flag_rhs = rhs;

    if (!ft_alu_writes_dst(op)) {
        return ft_emit_alu_flag(out, fields, op, width, lhs, rhs);
    }
    if (!data_op) {
        return false;
    }
    if (ft_alu_uses_cf(op)) {
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        /* Dead output flags do not need the old lhs; ADC/SBC still use CF. */
        if (!fields->skip_flags || fields->modrm_mod != 3 ||
            (width != 32 && width != 64) ||
            (fields->alu_form != FT_ALU_FORM_RM_R &&
             fields->alu_form != FT_ALU_FORM_R_RM)) {
#endif
#ifdef QUICKTRANS_LATU
            if (op != FT_ALU_ADC || result == lhs)
#endif
            {
                flag_lhs = la_t3;
                FT_LA_OR_EMIT(out, flag_lhs, lhs, la_zero);
            }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        }
#endif
        if (!fields->skip_flags &&
            (op == FT_ALU_SBB || (op == FT_ALU_ADC && result == rhs))) {
            FT_LA_OR_EMIT(out, la_t4, rhs, la_zero);
            flag_rhs = la_t4;
        }
        ft_emit_raw(out, ft_gpr3(data_op, result, lhs, rhs));
        if (!ft_emit_alu_flag(out, fields, op, width, flag_lhs,
                              flag_rhs)) {
            return false;
        }
        if (op == FT_ALU_SBB && !fields->skip_flags) {
            /* LoongArch X86SBC does not provide the x86 auxiliary flag. */
            FT_LA_XOR_EMIT(out, la_t3, la_t3, la_t4);
            FT_LA_XOR_EMIT(out, la_t3, la_t3, result);
            FT_LA_ANDI_EMIT(out, la_t3, la_t3, 0x10);
            FT_LA_X86MTFLAG_EMIT(out, la_t3, AF_USEDEF_BIT);
        }
        return true;
    }
    if (!ft_emit_alu_flag(out, fields, op, width, lhs, rhs)) {
        return false;
    }
    ft_emit_raw(out, ft_gpr3(data_op, result, lhs, rhs));
    return true;
}

static uint32_t ft_locked_alu_opcode(FastAluOp op, int width)
{
    if (op == FT_ALU_ADD || op == FT_ALU_ADC || op == FT_ALU_SUB ||
        op == FT_ALU_SBB) {
        return width == 64 ? FT_LA_OPCODE_AMADD_DB_D :
               width == 32 ? FT_LA_OPCODE_AMADD_DB_W :
               width == 16 ? FT_LA_OPCODE_AMADD_DB_H :
               width == 8 ? FT_LA_OPCODE_AMADD_DB_B : 0;
    }
    if (width != 32 && width != 64) {
        return 0;
    }
    switch (op) {
    case FT_ALU_AND:
        return width == 64 ? FT_LA_OPCODE_AMAND_DB_D :
                             FT_LA_OPCODE_AMAND_DB_W;
    case FT_ALU_OR:
        return width == 64 ? FT_LA_OPCODE_AMOR_DB_D :
                             FT_LA_OPCODE_AMOR_DB_W;
    case FT_ALU_XOR:
        return width == 64 ? FT_LA_OPCODE_AMXOR_DB_D :
                             FT_LA_OPCODE_AMXOR_DB_W;
    default:
        return 0;
    }
}

static bool ft_emit_locked_alu(uint32_t **out,
                               const FastTemplateFields *fields,
                               target_ulong pc)
{
    uint32_t atomic_op = ft_locked_alu_opcode(fields->alu_op,
                                               fields->alu_width);
    bool small_logic = fields->alu_width < 32 &&
                       (fields->alu_op == FT_ALU_AND ||
                        fields->alu_op == FT_ALU_OR ||
                        fields->alu_op == FT_ALU_XOR);
    int addr;
    int rhs;
    int value;
    int old;

    if ((!atomic_op && !small_logic) || fields->modrm_mod == 3 ||
        (fields->alu_form != FT_ALU_FORM_RM_R &&
         fields->alu_form != FT_ALU_FORM_RM_IMM) ||
        !ft_emit_rmw_addr(out, fields, pc, &addr, la_t4)) {
        return false;
    }
    ft_preserve_cmpxchg_addr(out, &addr);
    if (fields->alu_form == FT_ALU_FORM_RM_R) {
        if (!ft_emit_alu_modrm_reg_value(out, fields, fields->alu_width,
                                         la_t1, &rhs)) {
            return false;
        }
    } else if (!ft_emit_alu_imm(out, fields, fields->alu_width, &rhs)) {
        return false;
    }

    if (small_logic) {
        FastBranchLabel retry = { 0 };
        FastBranchLabel done = { 0 };
        FastBranchFixup retry_fixup;
        FastBranchFixup done_fixup;
        uint32_t data_op = ft_alu_data_op(fields->alu_op,
                                          fields->alu_width);
        int desired = la_t2;
        int expected;

        old = addr == la_t0 ? la_t3 : la_t0;
        expected = old == la_t3 ? la_t4 : la_t3;
        if (fields->alu_width == 8) {
            FT_LA_LD_BU_EMIT(out, old, addr, 0);
        } else {
            FT_LA_LD_HU_EMIT(out, old, addr, 0);
        }
        ft_bind_branch_label(&retry, *out);
        ft_emit_raw(out, ft_gpr3(data_op, desired, old, rhs));
        FT_LA_OR_EMIT(out, expected, old, la_zero);
        ft_emit_raw(out,
                    ft_gpr3(ft_atomic_opcode(fields,
                                             fields->alu_width == 8 ?
                                             FT_LA_OPCODE_AMCAS_DB_B :
                                             FT_LA_OPCODE_AMCAS_DB_H),
                            expected, addr, desired));
        ft_emit_zero_extend_atomic_old(out, expected, fields->alu_width);
        ft_emit_branch_placeholder(out, &done_fixup, FT_BRANCH_BEQ,
                                   expected, old, &done);
        FT_LA_OR_EMIT(out, old, expected, la_zero);
        ft_emit_branch_placeholder(out, &retry_fixup, FT_BRANCH_B,
                                   0, 0, &retry);
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&done_fixup);
        ft_resolve_branch_fixup(&retry_fixup);
        return ft_emit_alu_flag(out, fields, fields->alu_op,
                                fields->alu_width, old, rhs);
    }

    value = rhs;
    if (fields->alu_op == FT_ALU_SUB) {
        value = la_t2;
        FT_LA_SUB_D_EMIT(out, value, la_zero, rhs);
    } else if (fields->alu_op == FT_ALU_ADC ||
               fields->alu_op == FT_ALU_SBB) {
        value = la_t2;
        ft_emit_raw(out,
                    ft_gpr3(ft_alu_data_op(fields->alu_op,
                                           fields->alu_width),
                            value, la_zero, rhs));
    }
    old = addr == la_t0 ? la_t3 : la_t0;
    ft_emit_raw(out, ft_gpr3(ft_atomic_opcode(fields, atomic_op),
                            old, addr, value));
    if (fields->alu_op == FT_ALU_SBB && !fields->skip_flags) {
        uint32_t add_op = fields->alu_width == 64 ?
                          FT_LA_OPCODE_ADD_D : FT_LA_OPCODE_ADD_W;

        ft_emit_raw(out, ft_gpr3(add_op, la_t2, old, value));
        if (!ft_emit_alu_flag(out, fields, fields->alu_op,
                              fields->alu_width, old, rhs)) {
            return false;
        }
        FT_LA_XOR_EMIT(out, la_t4, old, rhs);
        FT_LA_XOR_EMIT(out, la_t4, la_t4, la_t2);
        FT_LA_ANDI_EMIT(out, la_t4, la_t4, 0x10);
        FT_LA_X86MTFLAG_EMIT(out, la_t4, AF_USEDEF_BIT);
        return true;
    }
    return ft_emit_alu_flag(out, fields, fields->alu_op,
                            fields->alu_width, old, rhs);
}

/* Logical immediates can also perform the 32-bit destination zero-extension.
 * Use this only when the existing flag analysis has discarded all flags. */
static bool ft_emit_and_imm_reg(uint32_t **out,
                                const FastTemplateFields *fields)
{
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    int width = fields->alu_width;
    int dst;
    uint64_t mask;
    uint64_t inverse;

    if (fields->alu_op != FT_ALU_AND || !fields->skip_flags ||
        fields->prefix0 == dt_X86_PREFIX_LOCK ||
        (width != 32 && width != 64)) {
        return false;
    }
    if (fields->alu_form == FT_ALU_FORM_ACC_IMM) {
        dst = rax_index;
    } else if (fields->alu_form == FT_ALU_FORM_RM_IMM &&
               fields->modrm_mod == 3) {
        dst = ft_modrm_rm_index(fields);
    } else {
        return false;
    }
    if (dst >= GPR_NUM) {
        return false;
    }
    dst = ft_gpr(dst);
    mask = width == 32 ? (uint32_t)fields->imm : (uint64_t)fields->imm;
    if (mask <= 0xfff) {
        FT_LA_ANDI_EMIT(out, dst, dst, mask);
        return true;
    }
    if (mask == UINT64_MAX) {
        /* Keep the ordinary nonempty emission contract for AND r64,-1. */
        return false;
    }
    if ((mask & (mask + 1)) == 0) {
        FT_LA_BSTRPICK_D_EMIT(out, dst, dst,
                             63 - __builtin_clzll(mask), 0);
        return true;
    }
    inverse = ~mask;
    if (width == 32) {
        inverse &= UINT32_MAX;
    }
    if ((inverse & (inverse + 1)) == 0) {
        FT_LA_BSTRINS_D_EMIT(out, dst, la_zero,
                            __builtin_ctzll(mask) - 1, 0);
        if (width == 32) {
            FT_LA_BSTRPICK_D_EMIT(out, dst, dst, 31, 0);
        }
        return true;
    }
#else
    (void)out;
    (void)fields;
#endif
    return false;
}

/* Keep the existing flag computation whenever any flag is live. */
static bool ft_emit_logic_imm_reg(uint32_t **out,
                              const FastTemplateFields *fields)
{
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    int width = fields->alu_width;
    int dst;
    uint64_t imm = width == 32 ? (uint32_t)fields->imm :
                                 (uint64_t)fields->imm;

    if (!fields->skip_flags || (width != 32 && width != 64) ||
        imm > 0xfff) {
        return false;
    }
    if (fields->alu_form == FT_ALU_FORM_ACC_IMM) {
        dst = rax_index;
    } else if (fields->alu_form == FT_ALU_FORM_RM_IMM &&
               fields->modrm_mod == 3) {
        dst = ft_modrm_rm_index(fields);
    } else {
        return false;
    }
    if (dst >= GPR_NUM) {
        return false;
    }
    dst = ft_gpr(dst);
    if (fields->alu_op == FT_ALU_OR) {
        FT_LA_ORI_EMIT(out, dst, dst, imm);
    } else {
        FT_LA_XORI_EMIT(out, dst, dst, imm);
    }
    if (width == 32 && !ft_omit_gpr_zext32(fields)) {
        FT_LA_BSTRPICK_D_EMIT(out, dst, dst, 31, 0);
    }
    return true;
#else
    (void)out;
    (void)fields;
    return false;
#endif
}

/* Register immediates need no temporary when flags are already dead. */
static bool ft_emit_addsub_imm_reg(uint32_t **out,
                                  const FastTemplateFields *fields)
{
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    int width = fields->alu_width;
    int dst;
    int64_t addend;

    if (!fields->skip_flags || (width != 32 && width != 64)) {
        return false;
    }
    if (fields->alu_form == FT_ALU_FORM_ACC_IMM) {
        dst = rax_index;
    } else if (fields->alu_form == FT_ALU_FORM_RM_IMM &&
               fields->modrm_mod == 3) {
        dst = ft_modrm_rm_index(fields);
    } else {
        return false;
    }
    addend = fields->alu_op == FT_ALU_ADD ? fields->imm :
                                            -(int64_t)fields->imm;
    if (dst >= GPR_NUM || !ft_fits_simm12(addend)) {
        return false;
    }
    dst = ft_gpr(dst);
    if (width == 64) {
        FT_LA_ADDI_D_EMIT(out, dst, dst, addend);
    } else {
        FT_LA_ADDI_W_EMIT(out, dst, dst, addend);
        if (!ft_omit_gpr_zext32(fields)) {
            FT_LA_BSTRPICK_D_EMIT(out, dst, dst, 31, 0);
        }
    }
    return true;
#else
    (void)out;
    (void)fields;
    return false;
#endif
}

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
/* Commit flags only after a non-LOCK memory destination has been written.
 * A store fault must retain the input CF for signal return and retry.
 * Keep the address and both inputs live instead of recalculating an address
 * that can overwrite the flag operands in t0/t1. */
static bool ft_emit_carry_memory(uint32_t **out,
                                  const FastTemplateFields *fields,
                                  target_ulong pc)
{
    int addr, rhs;
    int width = fields->alu_width;
    uint32_t data_op = ft_alu_data_op(fields->alu_op, width);

    if (!ft_emit_rmw_addr(out, fields, pc, &addr, la_t4)) {
        return false;
    }
    ft_preserve_cmpxchg_addr(out, &addr);
    switch (width) {
    case 8: FT_LA_LD_BU_EMIT(out, la_t3, addr, 0); break;
    case 16: FT_LA_LD_HU_EMIT(out, la_t3, addr, 0); break;
    case 32: FT_LA_LD_WU_EMIT(out, la_t3, addr, 0); break;
    case 64: FT_LA_LD_D_EMIT(out, la_t3, addr, 0); break;
    default: return false;
    }
    if (fields->alu_form == FT_ALU_FORM_RM_R) {
        if (!ft_emit_alu_modrm_reg_value(out, fields, width, la_t1, &rhs)) {
            return false;
        }
    } else if (!ft_emit_alu_imm(out, fields, width, &rhs)) {
        return false;
    }
    ft_emit_raw(out, ft_gpr3(data_op, la_t2, la_t3, rhs));
    switch (width) {
    case 8: FT_LA_ST_B_EMIT(out, la_t2, addr, 0); break;
    case 16: FT_LA_ST_H_EMIT(out, la_t2, addr, 0); break;
    case 32: FT_LA_ST_W_EMIT(out, la_t2, addr, 0); break;
    case 64: FT_LA_ST_D_EMIT(out, la_t2, addr, 0); break;
    }
    if (!ft_emit_alu_flag(out, fields, fields->alu_op, width, la_t3, rhs)) {
        return false;
    }
    if (fields->alu_op == FT_ALU_SBB && !fields->skip_flags) {
        FT_LA_XOR_EMIT(out, la_t3, la_t3, rhs);
        FT_LA_XOR_EMIT(out, la_t3, la_t3, la_t2);
        FT_LA_ANDI_EMIT(out, la_t3, la_t3, 0x10);
        FT_LA_X86MTFLAG_EMIT(out, la_t3, AF_USEDEF_BIT);
    }
    return true;
}
#endif

static bool ft_emit_alu_template(uint32_t **out,
                                 const FastTemplateFields *fields,
                                 target_ulong pc)
{
    FastAluOp op = fields->alu_op;
    int width = fields->alu_width;
    int lhs;
    int rhs;
    int result;

    if (op == FT_ALU_NONE || fields->alu_form == FT_ALU_FORM_NONE) {
        return false;
    }
    if (fields->prefix0 == dt_X86_PREFIX_LOCK) {
        return ft_emit_locked_alu(out, fields, pc);
    }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (ft_alu_uses_cf(op) && fields->modrm_mod != 3 &&
        (fields->alu_form == FT_ALU_FORM_RM_R ||
         fields->alu_form == FT_ALU_FORM_RM_IMM)) {
        return ft_emit_carry_memory(out, fields, pc);
    }
#endif
    switch (fields->alu_form) {
    case FT_ALU_FORM_RM_R:
        if (!ft_emit_alu_load_rm(out, fields, pc, width, &lhs) ||
            !ft_emit_alu_modrm_reg_value(out, fields, width, la_t1, &rhs)) {
            return false;
        }
        result = fields->modrm_mod == 3 && width >= 32 ?
                 lhs : la_t2;
        if (!ft_emit_alu_data(out, fields, op, width, result, lhs, rhs)) {
            return false;
        }
        if (ft_alu_writes_dst(op)) {
            if (!ft_emit_alu_store_rm(out, fields, pc, width, result)) {
                return false;
            }
        }
        return true;

    case FT_ALU_FORM_R_RM:
        if (!ft_emit_alu_load_rm(out, fields, pc, width, &rhs) ||
            !ft_emit_alu_modrm_reg_value(out, fields, width, la_t1, &lhs)) {
            return false;
        }
        result = width >= 32 && !ft_modrm_reg_is_high8(fields) ?
                 lhs : la_t2;
        if (!ft_emit_alu_data(out, fields, op, width, result, lhs, rhs)) {
            return false;
        }
        if (ft_alu_writes_dst(op)) {
            if (!ft_emit_alu_store_modrm_reg(out, fields, width, result)) {
                return false;
            }
        }
        return true;

    case FT_ALU_FORM_RM_IMM:
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if ((op == FT_ALU_OR || op == FT_ALU_XOR) &&
            ft_emit_logic_imm_reg(out, fields)) {
            return true;
        }
#endif
        if (op == FT_ALU_AND && ft_emit_and_imm_reg(out, fields)) {
            return true;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if ((op == FT_ALU_ADD || op == FT_ALU_SUB) &&
            ft_emit_addsub_imm_reg(out, fields)) {
            return true;
        }
#else
        if (fields->skip_flags && width == 64 && fields->modrm_mod == 3 &&
            (op == FT_ALU_ADD || op == FT_ALU_SUB)) {
            int64_t addend = op == FT_ALU_ADD ? fields->imm :
                                               -(int64_t)fields->imm;
            int dst = ft_modrm_rm_index(fields);

            if (dst < GPR_NUM && ft_fits_simm12(addend)) {
                FT_LA_ADDI_D_EMIT(out, ft_gpr(dst), ft_gpr(dst), addend);
                return true;
            }
        }
#endif
        if (!ft_emit_alu_load_rm(out, fields, pc, width, &lhs) ||
            !ft_emit_alu_imm(out, fields, width, &rhs)) {
            return false;
        }
        result = fields->modrm_mod == 3 && width >= 32 ?
                 lhs : la_t2;
        if (!ft_emit_alu_data(out, fields, op, width, result, lhs, rhs)) {
            return false;
        }
        if (ft_alu_writes_dst(op)) {
            if (!ft_emit_alu_store_rm(out, fields, pc, width, result)) {
                return false;
            }
        }
        return true;

    case FT_ALU_FORM_ACC_IMM:
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if ((op == FT_ALU_OR || op == FT_ALU_XOR) &&
            ft_emit_logic_imm_reg(out, fields)) {
            return true;
        }
#endif
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if ((op == FT_ALU_ADD || op == FT_ALU_SUB) &&
            ft_emit_addsub_imm_reg(out, fields)) {
            return true;
        }
#endif
        if (op == FT_ALU_AND && ft_emit_and_imm_reg(out, fields)) {
            return true;
        }
        if (!ft_emit_alu_imm(out, fields, width, &rhs)) {
            return false;
        }
        if (width == 8) {
#ifdef QUICKTRANS_LATU
            lhs = ft_gpr(rax_index);
#else
            FT_LA_BSTRPICK_D_EMIT(out, la_t0, ft_gpr(rax_index), 7, 0);
            lhs = la_t0;
#endif
            result = la_t2;
        } else if (width == 16) {
#ifdef QUICKTRANS_LATU
            lhs = ft_gpr(rax_index);
#else
            FT_LA_BSTRPICK_D_EMIT(out, la_t0, ft_gpr(rax_index), 15, 0);
            lhs = la_t0;
#endif
            result = la_t2;
        } else {
            lhs = ft_gpr(rax_index);
            result = ft_gpr(rax_index);
        }
        if (!ft_emit_alu_data(out, fields, op, width, result, lhs, rhs)) {
            return false;
        }
        if (!ft_alu_writes_dst(op)) {
            return true;
        }
        if (width == 8) {
            FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), result, 7, 0);
        } else if (width == 16) {
            FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), result, 15, 0);
        } else if (width == 32 && !ft_omit_gpr_zext32(fields)) {
            FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rax_index),
                                     ft_gpr(rax_index), 31, 0);
        }
        return true;

    default:
        return false;
    }
}
