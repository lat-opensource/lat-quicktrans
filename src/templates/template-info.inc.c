/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Fast template semantic metadata used by fields and primary translation. */

typedef struct FastTemplateAluInfo {
    FastAluOp op;
    FastAluForm form;
    uint8_t width;
} FastTemplateAluInfo;

#define FT_ALU_INFO(_kind, _op, _form, _width) \
    [_kind] = { (_op), (_form), (_width) }

static const FastTemplateAluInfo ft_template_alu_table[FT_KIND_COUNT] = {
    FT_ALU_INFO(FT_ADD_RM64_R64, FT_ALU_ADD, FT_ALU_FORM_RM_R, 64),
    FT_ALU_INFO(FT_ADD_RM32_R32, FT_ALU_ADD, FT_ALU_FORM_RM_R, 32),
    FT_ALU_INFO(FT_ADD_RM16_R16, FT_ALU_ADD, FT_ALU_FORM_RM_R, 16),
    FT_ALU_INFO(FT_ADD_RM8_R8, FT_ALU_ADD, FT_ALU_FORM_RM_R, 8),
    FT_ALU_INFO(FT_ADD_R64_RM64, FT_ALU_ADD, FT_ALU_FORM_R_RM, 64),
    FT_ALU_INFO(FT_ADD_R32_RM32, FT_ALU_ADD, FT_ALU_FORM_R_RM, 32),
    FT_ALU_INFO(FT_ADD_R16_RM16, FT_ALU_ADD, FT_ALU_FORM_R_RM, 16),
    FT_ALU_INFO(FT_ADD_R8_RM8, FT_ALU_ADD, FT_ALU_FORM_R_RM, 8),
    FT_ALU_INFO(FT_ADD_R64_IMM32, FT_ALU_ADD, FT_ALU_FORM_RM_IMM, 64),
    FT_ALU_INFO(FT_ADD_R64_IMM8, FT_ALU_ADD, FT_ALU_FORM_RM_IMM, 64),
    FT_ALU_INFO(FT_ADD_R32_IMM8, FT_ALU_ADD, FT_ALU_FORM_RM_IMM, 32),
    FT_ALU_INFO(FT_ADD_RAX_IMM32, FT_ALU_ADD, FT_ALU_FORM_ACC_IMM, 64),
    FT_ALU_INFO(FT_ADD_EAX_IMM32, FT_ALU_ADD, FT_ALU_FORM_ACC_IMM, 32),
    FT_ALU_INFO(FT_ADD_AX_IMM16, FT_ALU_ADD, FT_ALU_FORM_ACC_IMM, 16),
    FT_ALU_INFO(FT_ADD_AL_IMM8, FT_ALU_ADD, FT_ALU_FORM_ACC_IMM, 8),

    FT_ALU_INFO(FT_OR_RM64_R64, FT_ALU_OR, FT_ALU_FORM_RM_R, 64),
    FT_ALU_INFO(FT_OR_RM32_R32, FT_ALU_OR, FT_ALU_FORM_RM_R, 32),
    FT_ALU_INFO(FT_OR_RM8_R8, FT_ALU_OR, FT_ALU_FORM_RM_R, 8),
    FT_ALU_INFO(FT_OR_R64_RM64, FT_ALU_OR, FT_ALU_FORM_R_RM, 64),
    FT_ALU_INFO(FT_OR_R32_RM32, FT_ALU_OR, FT_ALU_FORM_R_RM, 32),
    FT_ALU_INFO(FT_OR_R16_RM16, FT_ALU_OR, FT_ALU_FORM_R_RM, 16),
    FT_ALU_INFO(FT_OR_R8_RM8, FT_ALU_OR, FT_ALU_FORM_R_RM, 8),
    FT_ALU_INFO(FT_OR_RM8_IMM8, FT_ALU_OR, FT_ALU_FORM_RM_IMM, 8),
    FT_ALU_INFO(FT_OR_RAX_IMM32, FT_ALU_OR, FT_ALU_FORM_ACC_IMM, 64),
    FT_ALU_INFO(FT_OR_EAX_IMM32, FT_ALU_OR, FT_ALU_FORM_ACC_IMM, 32),
    FT_ALU_INFO(FT_OR_AX_IMM16, FT_ALU_OR, FT_ALU_FORM_ACC_IMM, 16),
    FT_ALU_INFO(FT_OR_AL_IMM8, FT_ALU_OR, FT_ALU_FORM_ACC_IMM, 8),

    FT_ALU_INFO(FT_ADC_RM64_R64, FT_ALU_ADC, FT_ALU_FORM_RM_R, 64),
    FT_ALU_INFO(FT_ADC_RM32_R32, FT_ALU_ADC, FT_ALU_FORM_RM_R, 32),
    FT_ALU_INFO(FT_ADC_RM16_R16, FT_ALU_ADC, FT_ALU_FORM_RM_R, 16),
    FT_ALU_INFO(FT_ADC_RM8_R8, FT_ALU_ADC, FT_ALU_FORM_RM_R, 8),
    FT_ALU_INFO(FT_ADC_R64_RM64, FT_ALU_ADC, FT_ALU_FORM_R_RM, 64),
    FT_ALU_INFO(FT_ADC_R32_RM32, FT_ALU_ADC, FT_ALU_FORM_R_RM, 32),
    FT_ALU_INFO(FT_ADC_R16_RM16, FT_ALU_ADC, FT_ALU_FORM_R_RM, 16),
    FT_ALU_INFO(FT_ADC_R8_RM8, FT_ALU_ADC, FT_ALU_FORM_R_RM, 8),
    FT_ALU_INFO(FT_ADC_AL_IMM8, FT_ALU_ADC, FT_ALU_FORM_ACC_IMM, 8),

    FT_ALU_INFO(FT_SBB_RM32_R32, FT_ALU_SBB, FT_ALU_FORM_RM_R, 32),

    FT_ALU_INFO(FT_AND_RM64_R64, FT_ALU_AND, FT_ALU_FORM_RM_R, 64),
    FT_ALU_INFO(FT_AND_RM32_R32, FT_ALU_AND, FT_ALU_FORM_RM_R, 32),
    FT_ALU_INFO(FT_AND_RM8_R8, FT_ALU_AND, FT_ALU_FORM_RM_R, 8),
    FT_ALU_INFO(FT_AND_R64_RM64, FT_ALU_AND, FT_ALU_FORM_R_RM, 64),
    FT_ALU_INFO(FT_AND_R32_RM32, FT_ALU_AND, FT_ALU_FORM_R_RM, 32),
    FT_ALU_INFO(FT_AND_R8_RM8, FT_ALU_AND, FT_ALU_FORM_R_RM, 8),
    FT_ALU_INFO(FT_AND_R64_IMM8, FT_ALU_AND, FT_ALU_FORM_RM_IMM, 64),
    FT_ALU_INFO(FT_AND_R32_IMM8, FT_ALU_AND, FT_ALU_FORM_RM_IMM, 32),
    FT_ALU_INFO(FT_AND_RM8_IMM8, FT_ALU_AND, FT_ALU_FORM_RM_IMM, 8),
    FT_ALU_INFO(FT_AND_RAX_IMM32, FT_ALU_AND, FT_ALU_FORM_ACC_IMM, 64),
    FT_ALU_INFO(FT_AND_EAX_IMM32, FT_ALU_AND, FT_ALU_FORM_ACC_IMM, 32),
    FT_ALU_INFO(FT_AND_AX_IMM16, FT_ALU_AND, FT_ALU_FORM_ACC_IMM, 16),
    FT_ALU_INFO(FT_AND_AL_IMM8, FT_ALU_AND, FT_ALU_FORM_ACC_IMM, 8),

    FT_ALU_INFO(FT_SUB_RM64_R64, FT_ALU_SUB, FT_ALU_FORM_RM_R, 64),
    FT_ALU_INFO(FT_SUB_RM32_R32, FT_ALU_SUB, FT_ALU_FORM_RM_R, 32),
    FT_ALU_INFO(FT_SUB_RM16_R16, FT_ALU_SUB, FT_ALU_FORM_RM_R, 16),
    FT_ALU_INFO(FT_SUB_RM8_R8, FT_ALU_SUB, FT_ALU_FORM_RM_R, 8),
    FT_ALU_INFO(FT_SUB_R64_RM64, FT_ALU_SUB, FT_ALU_FORM_R_RM, 64),
    FT_ALU_INFO(FT_SUB_R32_RM32, FT_ALU_SUB, FT_ALU_FORM_R_RM, 32),
    FT_ALU_INFO(FT_SUB_R16_RM16, FT_ALU_SUB, FT_ALU_FORM_R_RM, 16),
    FT_ALU_INFO(FT_SUB_R8_RM8, FT_ALU_SUB, FT_ALU_FORM_R_RM, 8),
    FT_ALU_INFO(FT_SUB_R64_IMM32, FT_ALU_SUB, FT_ALU_FORM_RM_IMM, 64),
    FT_ALU_INFO(FT_SUB_R64_IMM8, FT_ALU_SUB, FT_ALU_FORM_RM_IMM, 64),
    FT_ALU_INFO(FT_SUB_R32_IMM8, FT_ALU_SUB, FT_ALU_FORM_RM_IMM, 32),
    FT_ALU_INFO(FT_SUB_EAX_IMM32, FT_ALU_SUB, FT_ALU_FORM_ACC_IMM, 32),
    FT_ALU_INFO(FT_SUB_AX_IMM16, FT_ALU_SUB, FT_ALU_FORM_ACC_IMM, 16),
    FT_ALU_INFO(FT_SUB_AL_IMM8, FT_ALU_SUB, FT_ALU_FORM_ACC_IMM, 8),

    FT_ALU_INFO(FT_XOR_RM64_R64, FT_ALU_XOR, FT_ALU_FORM_RM_R, 64),
    FT_ALU_INFO(FT_XOR_RM32_R32, FT_ALU_XOR, FT_ALU_FORM_RM_R, 32),
    FT_ALU_INFO(FT_XOR_RM8_R8, FT_ALU_XOR, FT_ALU_FORM_RM_R, 8),
    FT_ALU_INFO(FT_XOR_R64_RM64, FT_ALU_XOR, FT_ALU_FORM_R_RM, 64),
    FT_ALU_INFO(FT_XOR_R32_RM32, FT_ALU_XOR, FT_ALU_FORM_R_RM, 32),
    FT_ALU_INFO(FT_XOR_R16_RM16, FT_ALU_XOR, FT_ALU_FORM_R_RM, 16),
    FT_ALU_INFO(FT_XOR_R8_RM8, FT_ALU_XOR, FT_ALU_FORM_R_RM, 8),
    FT_ALU_INFO(FT_XOR_RAX_IMM32, FT_ALU_XOR, FT_ALU_FORM_ACC_IMM, 64),
    FT_ALU_INFO(FT_XOR_EAX_IMM32, FT_ALU_XOR, FT_ALU_FORM_ACC_IMM, 32),
    FT_ALU_INFO(FT_XOR_AX_IMM16, FT_ALU_XOR, FT_ALU_FORM_ACC_IMM, 16),
    FT_ALU_INFO(FT_XOR_AL_IMM8, FT_ALU_XOR, FT_ALU_FORM_ACC_IMM, 8),

    FT_ALU_INFO(FT_CMP_RM64_R64, FT_ALU_CMP, FT_ALU_FORM_RM_R, 64),
    FT_ALU_INFO(FT_CMP_RM32_R32, FT_ALU_CMP, FT_ALU_FORM_RM_R, 32),
    FT_ALU_INFO(FT_CMP_RM16_R16, FT_ALU_CMP, FT_ALU_FORM_RM_R, 16),
    FT_ALU_INFO(FT_CMP_RM8_R8, FT_ALU_CMP, FT_ALU_FORM_RM_R, 8),
    FT_ALU_INFO(FT_CMP_R64_RM64, FT_ALU_CMP, FT_ALU_FORM_R_RM, 64),
    FT_ALU_INFO(FT_CMP_R32_RM32, FT_ALU_CMP, FT_ALU_FORM_R_RM, 32),
    FT_ALU_INFO(FT_CMP_R16_RM16, FT_ALU_CMP, FT_ALU_FORM_R_RM, 16),
    FT_ALU_INFO(FT_CMP_R8_RM8, FT_ALU_CMP, FT_ALU_FORM_R_RM, 8),
    FT_ALU_INFO(FT_CMP_RM64_IMM32, FT_ALU_CMP, FT_ALU_FORM_RM_IMM, 64),
    FT_ALU_INFO(FT_CMP_RM64_IMM8, FT_ALU_CMP, FT_ALU_FORM_RM_IMM, 64),
    FT_ALU_INFO(FT_CMP_RM32_IMM8, FT_ALU_CMP, FT_ALU_FORM_RM_IMM, 32),
    FT_ALU_INFO(FT_CMP_RM16_IMM16, FT_ALU_CMP, FT_ALU_FORM_RM_IMM, 16),
    FT_ALU_INFO(FT_CMP_RM16_IMM8, FT_ALU_CMP, FT_ALU_FORM_RM_IMM, 16),
    FT_ALU_INFO(FT_CMP_RM8_IMM8, FT_ALU_CMP, FT_ALU_FORM_RM_IMM, 8),
    FT_ALU_INFO(FT_CMP_RAX_IMM32, FT_ALU_CMP, FT_ALU_FORM_ACC_IMM, 64),
    FT_ALU_INFO(FT_CMP_EAX_IMM32, FT_ALU_CMP, FT_ALU_FORM_ACC_IMM, 32),
    FT_ALU_INFO(FT_CMP_AX_IMM16, FT_ALU_CMP, FT_ALU_FORM_ACC_IMM, 16),
    FT_ALU_INFO(FT_CMP_AL_IMM8, FT_ALU_CMP, FT_ALU_FORM_ACC_IMM, 8),

    FT_ALU_INFO(FT_TEST_RM64_R64, FT_ALU_TEST, FT_ALU_FORM_RM_R, 64),
    FT_ALU_INFO(FT_TEST_RM32_R32, FT_ALU_TEST, FT_ALU_FORM_RM_R, 32),
    FT_ALU_INFO(FT_TEST_RM16_R16, FT_ALU_TEST, FT_ALU_FORM_RM_R, 16),
    FT_ALU_INFO(FT_TEST_RM8_R8, FT_ALU_TEST, FT_ALU_FORM_RM_R, 8),
    FT_ALU_INFO(FT_TEST_RM64_IMM32, FT_ALU_TEST, FT_ALU_FORM_RM_IMM, 64),
    FT_ALU_INFO(FT_TEST_RM32_IMM32, FT_ALU_TEST, FT_ALU_FORM_RM_IMM, 32),
    FT_ALU_INFO(FT_TEST_RM16_IMM16, FT_ALU_TEST, FT_ALU_FORM_RM_IMM, 16),
    FT_ALU_INFO(FT_TEST_RM8_IMM8, FT_ALU_TEST, FT_ALU_FORM_RM_IMM, 8),
    FT_ALU_INFO(FT_TEST_RAX_IMM32, FT_ALU_TEST, FT_ALU_FORM_ACC_IMM, 64),
    FT_ALU_INFO(FT_TEST_EAX_IMM32, FT_ALU_TEST, FT_ALU_FORM_ACC_IMM, 32),
    FT_ALU_INFO(FT_TEST_AL_IMM8, FT_ALU_TEST, FT_ALU_FORM_ACC_IMM, 8),
};

#undef FT_ALU_INFO

static bool ft_template_alu_info(FastTemplateKind kind, FastAluOp *op,
                                 FastAluForm *form, uint8_t *width)
{
    const FastTemplateAluInfo *info;

    *op = FT_ALU_NONE;
    *form = FT_ALU_FORM_NONE;
    *width = 0;
    if (kind <= FT_UNSUPPORTED || kind >= FT_KIND_COUNT) {
        return false;
    }

    info = &ft_template_alu_table[kind];
    if (info->op == FT_ALU_NONE) {
        return false;
    }

    *op = info->op;
    *form = info->form;
    *width = info->width;
    return true;
}

static bool ft_fill_group1_alu_info(FastTemplateFields *fields)
{
    static const FastAluOp ops[8] = {
        FT_ALU_ADD, FT_ALU_OR, FT_ALU_ADC, FT_ALU_SBB,
        FT_ALU_AND, FT_ALU_SUB, FT_ALU_XOR, FT_ALU_CMP,
    };
    static const int ids[8] = {
        dt_X86_INS_ADD, dt_X86_INS_OR, dt_X86_INS_ADC, dt_X86_INS_SBB,
        dt_X86_INS_AND, dt_X86_INS_SUB, dt_X86_INS_XOR, dt_X86_INS_CMP,
    };
    uint8_t width;
    int ext;

    switch (fields->kind) {
    case FT_GRP1_RM64_IMM8:
    case FT_GRP1_RM64_IMM32:
        width = 64;
        break;
    case FT_GRP1_RM32_IMM8:
    case FT_GRP1_RM32_IMM32:
        width = fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;
        break;
    case FT_GRP1_RM16_IMM8:
        width = 16;
        break;
    case FT_GRP1_RM8_IMM8:
        width = 8;
        break;
    default:
        return false;
    }

    ext = fields->modrm_reg;
    if (ext < 0 || ext >= 8) {
        return false;
    }
    fields->alu_op = ops[ext];
    fields->alu_form = FT_ALU_FORM_RM_IMM;
    fields->alu_width = width;
    fields->id = ids[ext];
    return true;
}

static bool ft_alu_opcode_info(uint8_t opcode, FastAluOp *op, int *id)
{
    switch (opcode & 0xf8) {
    case 0x00:
        *op = FT_ALU_ADD;
        *id = dt_X86_INS_ADD;
        return true;
    case 0x08:
        *op = FT_ALU_OR;
        *id = dt_X86_INS_OR;
        return true;
    case 0x10:
        *op = FT_ALU_ADC;
        *id = dt_X86_INS_ADC;
        return true;
    case 0x18:
        *op = FT_ALU_SBB;
        *id = dt_X86_INS_SBB;
        return true;
    case 0x20:
        *op = FT_ALU_AND;
        *id = dt_X86_INS_AND;
        return true;
    case 0x28:
        *op = FT_ALU_SUB;
        *id = dt_X86_INS_SUB;
        return true;
    case 0x30:
        *op = FT_ALU_XOR;
        *id = dt_X86_INS_XOR;
        return true;
    case 0x38:
        *op = FT_ALU_CMP;
        *id = dt_X86_INS_CMP;
        return true;
    default:
        *op = FT_ALU_NONE;
        *id = dt_X86_INS_INVALID;
        return false;
    }
}

static uint8_t ft_alu_opcode_width(const FastTemplateFields *fields)
{
    if ((fields->opcode0 & 1) == 0) {
        return 8;
    }
    if (fields->rex >= 0 && (fields->rex & 8)) {
        return 64;
    }
    if (fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
        return 16;
    }
    return 32;
}

static bool ft_fill_generic_alu_info(FastTemplateFields *fields)
{
    if (fields->kind == FT_ALU_RM_R || fields->kind == FT_ALU_R_RM) {
        FastAluOp op;
        int id;

        if (!ft_alu_opcode_info(fields->opcode0, &op, &id)) {
            return false;
        }
        fields->alu_op = op;
        fields->alu_form = fields->kind == FT_ALU_RM_R ?
                           FT_ALU_FORM_RM_R : FT_ALU_FORM_R_RM;
        fields->alu_width = ft_alu_opcode_width(fields);
        fields->id = id;
        return true;
    }

    if (fields->kind != FT_ALU_ACC_IMM) {
        return fields->alu_op != FT_ALU_NONE;
    }

    fields->alu_form = FT_ALU_FORM_ACC_IMM;
    fields->alu_width = ((fields->opcode0 & 1) == 0 ||
                         fields->opcode0 == 0xa8) ? 8 :
                        (fields->rex >= 0 && (fields->rex & 8)) ? 64 :
                        fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;

    switch (fields->opcode0) {
    case 0x04:
    case 0x05:
        fields->alu_op = FT_ALU_ADD;
        fields->id = dt_X86_INS_ADD;
        return true;
    case 0x0c:
    case 0x0d:
        fields->alu_op = FT_ALU_OR;
        fields->id = dt_X86_INS_OR;
        return true;
    case 0x14:
    case 0x15:
        fields->alu_op = FT_ALU_ADC;
        fields->id = dt_X86_INS_ADC;
        return true;
    case 0x1c:
    case 0x1d:
        fields->alu_op = FT_ALU_SBB;
        fields->id = dt_X86_INS_SBB;
        return true;
    case 0x24:
    case 0x25:
        fields->alu_op = FT_ALU_AND;
        fields->id = dt_X86_INS_AND;
        return true;
    case 0x2c:
    case 0x2d:
        fields->alu_op = FT_ALU_SUB;
        fields->id = dt_X86_INS_SUB;
        return true;
    case 0x34:
    case 0x35:
        fields->alu_op = FT_ALU_XOR;
        fields->id = dt_X86_INS_XOR;
        return true;
    case 0x3c:
    case 0x3d:
        fields->alu_op = FT_ALU_CMP;
        fields->id = dt_X86_INS_CMP;
        return true;
    case 0xa8:
    case 0xa9:
        fields->alu_op = FT_ALU_TEST;
        fields->id = dt_X86_INS_TEST;
        return true;
    default:
        fields->alu_op = FT_ALU_NONE;
        fields->alu_form = FT_ALU_FORM_NONE;
        fields->alu_width = 0;
        return false;
    }
}
