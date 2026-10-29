/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Group-1 r/m immediate emit helpers. */

static bool ft_emit_grp1_rm_imm(uint32_t **out,
                                const FastTemplateFields *fields,
                                target_ulong pc, int width)
{
    int ext = (fields->modrm >> 3) & 7;
    int lhs;
    int result;
    bool writes_dst = ext != 7;
    uint32_t x86_op;
    uint32_t data_op = 0;

    if (!ft_grp1_ext_supported(ext)) {
        return false;
    }

    switch (width) {
    case 64:
        if (!ft_rex_w(fields) ||
            !ft_emit_load_rm64(out, fields, pc, &lhs)) {
            return false;
        }
        ft_emit_li64(out, la_t1, (uint64_t)(int64_t)fields->imm);
        switch (ext) {
        case 0:
            x86_op = FT_LA_OPCODE_X86ADD_D;
            data_op = FT_LA_OPCODE_ADD_D;
            break;
        case 1:
            x86_op = FT_LA_OPCODE_X86OR_D;
            data_op = FT_LA_OPCODE_OR;
            break;
        case 2:
            x86_op = FT_LA_OPCODE_X86ADC_D;
            data_op = FT_LA_OPCODE_ADC_D;
            break;
        case 3:
            x86_op = FT_LA_OPCODE_X86SBC_D;
            data_op = FT_LA_OPCODE_SBC_D;
            break;
        case 4:
            x86_op = FT_LA_OPCODE_X86AND_D;
            data_op = FT_LA_OPCODE_AND;
            break;
        case 6:
            x86_op = FT_LA_OPCODE_X86XOR_D;
            data_op = FT_LA_OPCODE_XOR;
            break;
        case 5:
        case 7:
            x86_op = FT_LA_OPCODE_X86SUB_D;
            data_op = FT_LA_OPCODE_SUB_D;
            break;
        default:
            return false;
        }
        result = fields->modrm_mod == 3 ? lhs : la_t2;
        if (ext == 2 || ext == 3) {
            FT_LA_OR_EMIT(out, la_t3, lhs, la_zero);
            ft_emit_raw(out, ft_gpr3(data_op, result, lhs, la_t1));
            ft_emit_raw(out, ft_gpr2(x86_op, la_t3, la_t1));
            return ft_emit_store_rm64(out, fields, pc, result);
        }
        ft_emit_raw(out, ft_gpr2(x86_op, lhs, la_t1));
        if (!writes_dst) {
            return true;
        }
        ft_emit_raw(out, ft_gpr3(data_op, result, lhs, la_t1));
        return ft_emit_store_rm64(out, fields, pc, result);

    case 32:
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm32(out, fields, pc, &lhs) ||
            !ft_emit_li32(out, la_t1, (uint32_t)(int32_t)fields->imm)) {
            return false;
        }
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t1, 31, 0);
        switch (ext) {
        case 0:
            x86_op = FT_LA_OPCODE_X86ADD_W;
            data_op = FT_LA_OPCODE_ADD_W;
            break;
        case 1:
            x86_op = FT_LA_OPCODE_X86OR_W;
            data_op = FT_LA_OPCODE_OR;
            break;
        case 2:
            x86_op = FT_LA_OPCODE_X86ADC_W;
            data_op = FT_LA_OPCODE_ADC_W;
            break;
        case 3:
            x86_op = FT_LA_OPCODE_X86SBC_W;
            data_op = FT_LA_OPCODE_SBC_W;
            break;
        case 4:
            x86_op = FT_LA_OPCODE_X86AND_W;
            data_op = FT_LA_OPCODE_AND;
            break;
        case 6:
            x86_op = FT_LA_OPCODE_X86XOR_W;
            data_op = FT_LA_OPCODE_XOR;
            break;
        case 5:
        case 7:
            x86_op = FT_LA_OPCODE_X86SUB_W;
            data_op = FT_LA_OPCODE_SUB_W;
            break;
        default:
            return false;
        }
        result = fields->modrm_mod == 3 ? lhs : la_t2;
        if (ext == 2 || ext == 3) {
            FT_LA_OR_EMIT(out, la_t3, lhs, la_zero);
            ft_emit_raw(out, ft_gpr3(data_op, result, lhs, la_t1));
            if (fields->modrm_mod == 3) {
                FT_LA_BSTRPICK_D_EMIT(out, result, result, 31, 0);
            }
            ft_emit_raw(out, ft_gpr2(x86_op, la_t3, la_t1));
            return ft_emit_store_rm32(out, fields, pc, result, false);
        }
        ft_emit_raw(out, ft_gpr2(x86_op, lhs, la_t1));
        if (!writes_dst) {
            return true;
        }
        ft_emit_raw(out, ft_gpr3(data_op, result, lhs, la_t1));
        if (fields->modrm_mod == 3) {
            FT_LA_BSTRPICK_D_EMIT(out, result, result, 31, 0);
        }
        return ft_emit_store_rm32(out, fields, pc, result, false);

    case 16:
        if (ft_rex_w(fields) ||
            !ft_emit_load_rm16(out, fields, pc, &lhs) ||
            !ft_emit_li32(out, la_t1,
                          (uint32_t)(uint16_t)(int16_t)fields->imm)) {
            return false;
        }
        switch (ext) {
        case 0:
            x86_op = FT_LA_OPCODE_X86ADD_H;
            data_op = FT_LA_OPCODE_ADD_W;
            break;
        case 1:
            x86_op = FT_LA_OPCODE_X86OR_H;
            data_op = FT_LA_OPCODE_OR;
            break;
        case 2:
            x86_op = FT_LA_OPCODE_X86ADC_H;
            data_op = FT_LA_OPCODE_ADC_H;
            break;
        case 3:
            x86_op = FT_LA_OPCODE_X86SBC_H;
            data_op = FT_LA_OPCODE_SBC_H;
            break;
        case 4:
            x86_op = FT_LA_OPCODE_X86AND_H;
            data_op = FT_LA_OPCODE_AND;
            break;
        case 6:
            x86_op = FT_LA_OPCODE_X86XOR_H;
            data_op = FT_LA_OPCODE_XOR;
            break;
        case 5:
        case 7:
            x86_op = FT_LA_OPCODE_X86SUB_H;
            data_op = FT_LA_OPCODE_SUB_W;
            break;
        default:
            return false;
        }
        if (ext == 2 || ext == 3) {
            FT_LA_OR_EMIT(out, la_t3, lhs, la_zero);
            ft_emit_raw(out, ft_gpr3(data_op, la_t2, lhs, la_t1));
            ft_emit_raw(out, ft_gpr2(x86_op, la_t3, la_t1));
            return ft_emit_store_rm16(out, fields, pc, la_t2);
        }
        ft_emit_raw(out, ft_gpr2(x86_op, lhs, la_t1));
        if (!writes_dst) {
            return true;
        }
        ft_emit_raw(out, ft_gpr3(data_op, la_t2, lhs, la_t1));
        return ft_emit_store_rm16(out, fields, pc, la_t2);

    case 8:
        if (!ft_emit_load_rm8(out, fields, pc, &lhs)) {
            return false;
        }
        if (!ft_emit_li32(out, la_t1, (uint32_t)(uint8_t)fields->imm)) {
            return false;
        }
        switch (ext) {
        case 0:
            x86_op = FT_LA_OPCODE_X86ADD_B;
            data_op = FT_LA_OPCODE_ADD_W;
            break;
        case 1:
            x86_op = FT_LA_OPCODE_X86OR_B;
            data_op = FT_LA_OPCODE_OR;
            break;
        case 2:
            x86_op = FT_LA_OPCODE_X86ADC_B;
            data_op = FT_LA_OPCODE_ADC_B;
            break;
        case 3:
            x86_op = FT_LA_OPCODE_X86SBC_B;
            data_op = FT_LA_OPCODE_SBC_B;
            break;
        case 4:
            x86_op = FT_LA_OPCODE_X86AND_B;
            data_op = FT_LA_OPCODE_AND;
            break;
        case 6:
            x86_op = FT_LA_OPCODE_X86XOR_B;
            data_op = FT_LA_OPCODE_XOR;
            break;
        case 5:
        case 7:
            x86_op = FT_LA_OPCODE_X86SUB_B;
            data_op = FT_LA_OPCODE_SUB_W;
            break;
        default:
            return false;
        }
        if (ext == 2 || ext == 3) {
            FT_LA_OR_EMIT(out, la_t3, lhs, la_zero);
            ft_emit_raw(out, ft_gpr3(data_op, la_t2, lhs, la_t1));
            ft_emit_raw(out, ft_gpr2(x86_op, la_t3, la_t1));
            return ft_emit_store_rm8(out, fields, pc, la_t2);
        }
        ft_emit_raw(out, ft_gpr2(x86_op, lhs, la_t1));
        if (!writes_dst) {
            return true;
        }
        ft_emit_raw(out, ft_gpr3(data_op, la_t2, lhs, la_t1));
        if (!ft_emit_store_rm8(out, fields, pc, la_t2)) {
            return false;
        }
        return true;

    default:
        return false;
    }
}
