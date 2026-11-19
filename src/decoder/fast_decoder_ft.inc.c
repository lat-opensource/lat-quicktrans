/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/*
 * Fast-translator cooperation path for fast_decoder.c.
 *
 * This file is included by fast_decoder.c so it can reuse the decoder's
 * internal FDState, prefix scanner, and byte readers without exporting them.
 */

enum {
    FD_FT_SEG_ES = 0,
    FD_FT_SEG_CS = 1,
    FD_FT_SEG_SS = 2,
    FD_FT_SEG_DS = 3,
    FD_FT_SEG_FS = 4,
    FD_FT_SEG_GS = 5,
};

typedef enum FastDecoderFTMatch {
    FD_FT_NO_MATCH,
    FD_FT_MATCH,
    FD_FT_REJECT,
} FastDecoderFTMatch;

enum {
    FD_FT_FAMILY_GPR = 1u << 0,
    FD_FT_FAMILY_CONTROL = 1u << 1,
    FD_FT_FAMILY_X87 = 1u << 2,
    FD_FT_FAMILY_SSE = 1u << 3,
    FD_FT_FAMILY_HOT_GPR = 1u << 4,
    FD_FT_FAMILY_HOT_CONTROL = 1u << 5,
};

static inline bool fd_ft_jcc_opcode_info(uint8_t cc, int *cond, int *id);

static int fd_ft_prefix_seg_index(uint8_t prefix)
{
    switch (prefix) {
    case dt_X86_PREFIX_ES:
        return FD_FT_SEG_ES;
    case dt_X86_PREFIX_CS:
        return FD_FT_SEG_CS;
    case dt_X86_PREFIX_SS:
        return FD_FT_SEG_SS;
    case dt_X86_PREFIX_DS:
        return FD_FT_SEG_DS;
    case dt_X86_PREFIX_FS:
        return FD_FT_SEG_FS;
    case dt_X86_PREFIX_GS:
        return FD_FT_SEG_GS;
    default:
        return -1;
    }
}

static inline uint16_t fd_ft_read_u16(const uint8_t *code)
{
    return (uint16_t)code[0] | ((uint16_t)code[1] << 8);
}

static inline uint32_t fd_ft_read_u32(const uint8_t *code)
{
    return (uint32_t)code[0] | ((uint32_t)code[1] << 8) |
           ((uint32_t)code[2] << 16) | ((uint32_t)code[3] << 24);
}

static inline int32_t fd_ft_read_i32(const uint8_t *code)
{
    return (int32_t)fd_ft_read_u32(code);
}

static inline uint64_t fd_ft_read_u64(const uint8_t *code)
{
    return (uint64_t)fd_ft_read_u32(code) |
           ((uint64_t)fd_ft_read_u32(code + 4) << 32);
}

static inline bool fd_ft_is_legacy_prefix(uint8_t byte)
{
    switch (byte) {
    case 0xf0:
    case 0xf2:
    case 0xf3:
    case 0x2e:
    case 0x36:
    case 0x3e:
    case 0x26:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
        return true;
    default:
        return false;
    }
}

static inline void fd_ft_init_state(FDState *s, const uint8_t *code,
                                    size_t code_size, uint64_t address,
                                    int mode)
{
    s->code = code;
    s->pos = 0;
    s->code_size = (int)code_size;
    s->address = address;
    s->mode = mode;
    s->prefix[0] = 0;
    s->prefix[1] = 0;
    s->prefix[2] = 0;
    s->prefix[3] = 0;
    s->rex = 0;
    s->rex_w = 0;
    s->rex_r = 0;
    s->rex_x = 0;
    s->rex_b = 0;
    s->has_rex = false;
    s->vex_v = 0;
    s->vex_l = 0;
    s->aflag = 0;
    s->dflag = 0;
}

#include "../templates/template-info.inc.c"

static void fd_ft_init_fields(FastTemplateFields *fields,
                              FastTemplateKind kind, const FDState *s,
                              uint64_t address, uint8_t opcode0,
                              uint8_t opcode1, int id)
{
    fields->kind = kind;
    fields->modrm = -1;
    ft_fields_set_rex(fields, s->has_rex ? s->rex : -1);
    fields->sib = 0;
    fields->segment = s->prefix[1] ?
                      fd_ft_prefix_seg_index(s->prefix[1]) : -1;
    fields->disp = 0;
    fields->imm = 0;
    fields->imm64 = 0;
    fields->reg = 0;
    fields->size = 0;
    fields->address = address;
    fields->id = id;
    fields->vex_v = -1;
    fields->opcode0 = opcode0;
    fields->prefix0 = s->prefix[0];
    fields->prefix2 = s->prefix[2];
    fields->opcode1 = opcode1;
    fields->alu_op = FT_ALU_NONE;
    fields->alu_form = FT_ALU_FORM_NONE;
    fields->alu_width = 0;
    fields->direct_cmp_lhs_gpr = -1;
    fields->direct_cmp_rhs_gpr = -1;
    fields->direct_bit_index_gpr = -1;
    fields->direct_bit_index_imm = -1;
    fields->instptn_div_kind = 0;
    fields->pattern_inputs = 0;
    fields->instptn_skip = false;
    fields->atomic_no_barrier = false;
    fields->direct_float_result = false;
    fields->direct_float_xx = false;
    fields->addr32 = s->aflag == 32;
    fields->skip_flags = false;
    fields->omit_zext32 = false;
    fields->scalar_direct_dst = false;
    fields->direct_branch_kind = FT_DIRECT_BRANCH_NONE;
}

static void fd_ft_set_alu(FastTemplateFields *fields, FastAluOp op,
                          FastAluForm form, uint8_t width)
{
    fields->alu_op = op;
    fields->alu_form = form;
    fields->alu_width = width;
}

static bool fd_ft_read_modrm(FDState *s, FastTemplateFields *fields)
{
    int modrm = fd_read_byte(s);
    int mod;
    int rm;
    int base;

    if (modrm < 0) {
        return false;
    }

    ft_fields_set_modrm(fields, modrm);
    mod = (modrm >> 6) & 3;
    rm = modrm & 7;
    base = rm;

    if (mod != 3 && rm == 4) {
        int sib = fd_read_byte(s);

        if (sib < 0) {
            return false;
        }
        fields->sib = sib;
        base = sib & 7;
    }

    if (mod == 0) {
        if ((rm == 5 && fields->sib == 0) ||
            (rm == 4 && (base & 7) == 5)) {
            if (s->pos + 4 > s->code_size) {
                return false;
            }
            fields->disp = fd_ft_read_i32(&s->code[s->pos]);
            s->pos += 4;
        }
    } else if (mod == 1) {
        int disp = fd_read_byte(s);

        if (disp < 0) {
            return false;
        }
        fields->disp = (int8_t)disp;
    } else if (mod == 2) {
        if (s->pos + 4 > s->code_size) {
            return false;
        }
        fields->disp = fd_ft_read_i32(&s->code[s->pos]);
        s->pos += 4;
    }
    return true;
}

static bool fd_ft_finish_direct(FastDecodedFT *decoded, FDState *s,
                                FastTemplateKind kind, bool is_tb_ending)
{
    decoded->tmpl = &fast_templates[kind];
    decoded->fields.kind = kind;
    decoded->fields.size = s->pos;
    decoded->fields_valid = true;
    decoded->is_tb_ending = is_tb_ending;
    decoded->direct_fields = true;
    decoded->field_source = FT_FIELD_SOURCE_SPECIALIZED;
    return true;
}

static inline FastDecoderFTMatch fd_ft_finish_match(FastDecodedFT *decoded,
                                                    FDState *s,
                                                    FastTemplateKind kind,
                                                    bool is_tb_ending)
{
    return fd_ft_finish_direct(decoded, s, kind, is_tb_ending) ?
           FD_FT_MATCH : FD_FT_REJECT;
}

static bool fd_ft_read_simm_at(const uint8_t *code, size_t code_size,
                               int offset, int size, int64_t *value)
{
    if (offset < 0 || size <= 0 || (size_t)(offset + size) > code_size) {
        return false;
    }
    switch (size) {
    case 1:
        *value = (int8_t)code[offset];
        return true;
    case 2:
        *value = (int16_t)fd_ft_read_u16(code + offset);
        return true;
    case 4:
        *value = fd_ft_read_i32(code + offset);
        return true;
    case 8:
        *value = (int64_t)fd_ft_read_u64(code + offset);
        return true;
    default:
        return false;
    }
}

static inline FastDecoderFTMatch fd_ft_try_hot_gpr(
    FDState *s, uint8_t opcode0, uint64_t address, FastDecodedFT *decoded)
{
    if (opcode0 == 0x89 || opcode0 == 0x8b || opcode0 == 0x8d) {
        FastTemplateKind kind;
        int id = opcode0 == 0x8d ? dt_X86_INS_LEA : dt_X86_INS_MOV;

        if (opcode0 == 0x89) {
            kind = s->rex_w ? FT_MOV_RM64_R64 :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_MOV_RM16_R16 :
                   FT_MOV_RM32_R32;
        } else if (opcode0 == 0x8b) {
            kind = s->rex_w ? FT_MOV_R64_RM64 :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_MOV_R16_RM16 :
                   FT_MOV_R32_RM32;
        } else {
            kind = s->rex_w ? FT_LEA_R64_M :
                   s->prefix[2] == dt_X86_PREFIX_OPSIZE ? FT_LEA_R16_M :
                                                             FT_LEA_R32_M;
        }
        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0, id);
        if (!fd_ft_read_modrm(s, &decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (opcode0 < 0x40 && (opcode0 & 0x04) == 0) {
        FastTemplateKind kind = (opcode0 & 0x02) ? FT_ALU_R_RM :
                                                 FT_ALU_RM_R;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_INVALID);
        if (!fd_ft_read_modrm(s, &decoded->fields) ||
            !ft_fill_generic_alu_info(&decoded->fields)) {
            return FD_FT_REJECT;
        }
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    if (opcode0 >= 0x50 && opcode0 <= 0x5f) {
        bool pop = opcode0 >= 0x58;
        FastTemplateKind kind = s->prefix[2] == dt_X86_PREFIX_OPSIZE ?
                                (pop ? FT_POP_R16 : FT_PUSH_R16) :
                                (pop ? FT_POP_R64 : FT_PUSH_R64);

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          pop ? dt_X86_INS_POP : dt_X86_INS_PUSH);
        decoded->fields.alu_width =
            s->prefix[2] == dt_X86_PREFIX_OPSIZE ? 16 :
            s->mode ? 64 : 32;
        decoded->fields.reg = (opcode0 & 7) | (s->rex_b ? 8 : 0);
        return fd_ft_finish_match(decoded, s, kind, false);
    }

    return FD_FT_NO_MATCH;
}

static inline FastDecoderFTMatch fd_ft_try_hot_control(
    FDState *s, uint8_t opcode0, uint8_t opcode1, bool two_byte,
    uint64_t address, FastDecodedFT *decoded)
{
    if ((two_byte && opcode1 >= 0x80 && opcode1 <= 0x8f) ||
        (!two_byte && opcode0 >= 0x70 && opcode0 <= 0x7f)) {
        uint8_t cc = two_byte ? opcode1 & 0xf : opcode0 & 0xf;
        int cond;
        int id;

        fd_ft_init_fields(&decoded->fields, FT_JCC_REL, s, address,
                          opcode0, two_byte ? opcode1 : 0,
                          dt_X86_INS_INVALID);
        if (!fd_ft_jcc_opcode_info(cc, &cond, &id)) {
            return FD_FT_REJECT;
        }
        if (two_byte) {
            int rel32;

            if (s->pos + 4 > s->code_size) {
                return FD_FT_REJECT;
            }
            rel32 = fd_ft_read_i32(&s->code[s->pos]);
            s->pos += 4;
            decoded->fields.imm64 = address + s->pos + rel32;
        } else {
            int rel8;

            if (s->pos >= s->code_size) {
                return FD_FT_REJECT;
            }
            rel8 = (int8_t)s->code[s->pos++];
            decoded->fields.imm64 = address + s->pos + rel8;
        }
        decoded->fields.reg = cond;
        decoded->fields.id = id;
        return fd_ft_finish_match(decoded, s, FT_JCC_REL, true);
    }

    if (!two_byte && (opcode0 == 0xe8 || opcode0 == 0xe9 ||
                      opcode0 == 0xeb)) {
        int rel;
        FastTemplateKind kind = opcode0 == 0xe8 ? FT_CALL_REL32 :
                                                  FT_JMP_REL32;
        int id = opcode0 == 0xe8 ? dt_X86_INS_CALL : dt_X86_INS_JMP;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0, id);
        if (opcode0 == 0xeb) {
            if (s->pos >= s->code_size) {
                return FD_FT_REJECT;
            }
            rel = (int8_t)s->code[s->pos++];
        } else {
            if (s->pos + 4 > s->code_size) {
                return FD_FT_REJECT;
            }
            rel = fd_ft_read_i32(&s->code[s->pos]);
            s->pos += 4;
        }
        decoded->fields.imm = rel;
        return fd_ft_finish_match(decoded, s, kind, true);
    }

    if (!two_byte && (opcode0 == 0xc3 || opcode0 == 0xc2)) {
        FastTemplateKind kind = opcode0 == 0xc3 ? FT_RET : FT_RET_IMM16;

        fd_ft_init_fields(&decoded->fields, kind, s, address, opcode0, 0,
                          dt_X86_INS_RET);
        if (opcode0 == 0xc2) {
            if (s->pos + 2 > s->code_size) {
                return FD_FT_REJECT;
            }
            decoded->fields.imm = fd_ft_read_u16(&s->code[s->pos]);
            s->pos += 2;
        }
        return fd_ft_finish_match(decoded, s, kind, true);
    }

    return FD_FT_NO_MATCH;
}

#include "fast_decoder_ft_gpr.inc.c"
#include "fast_decoder_ft_control.inc.c"
#include "fast_decoder_ft_x87.inc.c"
#include "fast_decoder_ft_sse.inc.c"

static const uint8_t fd_ft_one_byte_dispatch[256] = {
    [0x00 ... 0x03] = FD_FT_FAMILY_HOT_GPR,
    [0x04 ... 0x07] = FD_FT_FAMILY_GPR,
    [0x08 ... 0x0b] = FD_FT_FAMILY_HOT_GPR,
    [0x0c ... 0x0f] = FD_FT_FAMILY_GPR,
    [0x10 ... 0x13] = FD_FT_FAMILY_HOT_GPR,
    [0x14 ... 0x17] = FD_FT_FAMILY_GPR,
    [0x18 ... 0x1b] = FD_FT_FAMILY_HOT_GPR,
    [0x1c ... 0x1f] = FD_FT_FAMILY_GPR,
    [0x20 ... 0x23] = FD_FT_FAMILY_HOT_GPR,
    [0x24 ... 0x27] = FD_FT_FAMILY_GPR,
    [0x28 ... 0x2b] = FD_FT_FAMILY_HOT_GPR,
    [0x2c ... 0x2f] = FD_FT_FAMILY_GPR,
    [0x30 ... 0x33] = FD_FT_FAMILY_HOT_GPR,
    [0x34 ... 0x37] = FD_FT_FAMILY_GPR,
    [0x38 ... 0x3b] = FD_FT_FAMILY_HOT_GPR,
    [0x3c ... 0x3f] = FD_FT_FAMILY_GPR,
    [0x40 ... 0x4f] = FD_FT_FAMILY_GPR,
    [0x50 ... 0x5f] = FD_FT_FAMILY_HOT_GPR,
    [0x60 ... 0x63] = FD_FT_FAMILY_GPR,
    [0x6c ... 0x6f] = FD_FT_FAMILY_CONTROL,
    [0x68] = FD_FT_FAMILY_CONTROL,
    [0x69] = FD_FT_FAMILY_GPR,
    [0x6a] = FD_FT_FAMILY_CONTROL,
    [0x6b] = FD_FT_FAMILY_GPR,
    [0x70 ... 0x7f] = FD_FT_FAMILY_HOT_CONTROL,
    [0x80 ... 0x88] = FD_FT_FAMILY_GPR,
    [0x89] = FD_FT_FAMILY_HOT_GPR,
    [0x8a] = FD_FT_FAMILY_GPR,
    [0x8b] = FD_FT_FAMILY_HOT_GPR,
    [0x8c] = FD_FT_FAMILY_GPR,
    [0x8d] = FD_FT_FAMILY_HOT_GPR,
    [0x8e ... 0x8f] = FD_FT_FAMILY_GPR,
    [0x90] = FD_FT_FAMILY_GPR | FD_FT_FAMILY_CONTROL,
    [0x91 ... 0x99] = FD_FT_FAMILY_GPR,
    [0x9a] = FD_FT_FAMILY_CONTROL,
    [0x9b ... 0x9f] = FD_FT_FAMILY_CONTROL,
    [0xa0 ... 0xa3] = FD_FT_FAMILY_GPR,
    [0xa4 ... 0xaf] = FD_FT_FAMILY_GPR,
    [0xb0 ... 0xbf] = FD_FT_FAMILY_GPR,
    [0xc0 ... 0xc1] = FD_FT_FAMILY_GPR,
    [0xc2 ... 0xc3] = FD_FT_FAMILY_HOT_CONTROL,
    [0xc4] = FD_FT_FAMILY_GPR | FD_FT_FAMILY_CONTROL | FD_FT_FAMILY_SSE,
    [0xc5] = FD_FT_FAMILY_GPR | FD_FT_FAMILY_CONTROL,
    [0xc6 ... 0xc7] = FD_FT_FAMILY_GPR,
    [0xc8 ... 0xc9] = FD_FT_FAMILY_GPR,
    [0xca ... 0xcf] = FD_FT_FAMILY_CONTROL,
    [0xd0 ... 0xd3] = FD_FT_FAMILY_GPR,
    [0xd4 ... 0xd7] = FD_FT_FAMILY_GPR,
    [0xd8 ... 0xdf] = FD_FT_FAMILY_X87,
    [0xe0 ... 0xe3] = FD_FT_FAMILY_CONTROL,
    [0xe4 ... 0xe7] = FD_FT_FAMILY_CONTROL,
    [0xe8 ... 0xe9] = FD_FT_FAMILY_HOT_CONTROL,
    [0xea] = FD_FT_FAMILY_CONTROL,
    [0xeb] = FD_FT_FAMILY_HOT_CONTROL,
    [0xec ... 0xef] = FD_FT_FAMILY_CONTROL,
    [0xf1] = FD_FT_FAMILY_CONTROL,
    [0xf4] = FD_FT_FAMILY_CONTROL,
    [0xf5] = FD_FT_FAMILY_CONTROL,
    [0xf6] = FD_FT_FAMILY_GPR,
    [0xf7] = FD_FT_FAMILY_GPR,
    [0xf8 ... 0xf9] = FD_FT_FAMILY_CONTROL,
    [0xfa ... 0xfb] = FD_FT_FAMILY_CONTROL,
    [0xfc ... 0xfd] = FD_FT_FAMILY_CONTROL,
    [0xfe] = FD_FT_FAMILY_GPR,
    [0xff] = FD_FT_FAMILY_GPR | FD_FT_FAMILY_CONTROL,
};

static const uint8_t fd_ft_two_byte_extra_dispatch[256] = {
    [0x00] = FD_FT_FAMILY_CONTROL,
    [0x02] = FD_FT_FAMILY_CONTROL,
    [0x03] = FD_FT_FAMILY_CONTROL,
    [0x40 ... 0x4f] = FD_FT_FAMILY_GPR,
    [0x80 ... 0x8f] = FD_FT_FAMILY_HOT_CONTROL,
    [0x90 ... 0x9f] = FD_FT_FAMILY_CONTROL,
    [0xc8 ... 0xcf] = FD_FT_FAMILY_GPR,
    [0x01] = FD_FT_FAMILY_CONTROL,
    [0x05] = FD_FT_FAMILY_CONTROL,
    [0x06] = FD_FT_FAMILY_CONTROL,
    [0x07] = FD_FT_FAMILY_CONTROL,
    [0x08] = FD_FT_FAMILY_CONTROL,
    [0x09] = FD_FT_FAMILY_CONTROL,
    [0x0b] = FD_FT_FAMILY_CONTROL,
    [0x0d] = FD_FT_FAMILY_CONTROL,
    [0x18] = FD_FT_FAMILY_CONTROL,
    [0x1a ... 0x1b] = FD_FT_FAMILY_CONTROL,
    [0x1c] = FD_FT_FAMILY_CONTROL,
    [0x1e] = FD_FT_FAMILY_CONTROL,
    [0x1f] = FD_FT_FAMILY_GPR,
    [0x31] = FD_FT_FAMILY_CONTROL,
    [0x30] = FD_FT_FAMILY_CONTROL,
    [0x32] = FD_FT_FAMILY_CONTROL,
    [0x33] = FD_FT_FAMILY_CONTROL,
    [0x34] = FD_FT_FAMILY_CONTROL,
    [0x35] = FD_FT_FAMILY_CONTROL,
    [0x38] = FD_FT_FAMILY_GPR,
    [0xa3] = FD_FT_FAMILY_GPR,
    [0xa4] = FD_FT_FAMILY_GPR,
    [0xa5] = FD_FT_FAMILY_GPR,
    [0xab] = FD_FT_FAMILY_GPR,
    [0xac] = FD_FT_FAMILY_GPR,
    [0xad] = FD_FT_FAMILY_GPR,
    [0xaf] = FD_FT_FAMILY_GPR,
    [0xb0] = FD_FT_FAMILY_GPR,
    [0xb1] = FD_FT_FAMILY_GPR,
    [0xb2] = FD_FT_FAMILY_CONTROL,
    [0xb3] = FD_FT_FAMILY_GPR,
    [0xb4] = FD_FT_FAMILY_CONTROL,
    [0xb5] = FD_FT_FAMILY_CONTROL,
    [0xb6] = FD_FT_FAMILY_GPR,
    [0xb7] = FD_FT_FAMILY_GPR,
    [0xb8] = FD_FT_FAMILY_GPR,
    [0xba] = FD_FT_FAMILY_GPR,
    [0xb9] = FD_FT_FAMILY_CONTROL,
    [0xbb] = FD_FT_FAMILY_GPR,
    [0xbc] = FD_FT_FAMILY_GPR,
    [0xbd] = FD_FT_FAMILY_GPR,
    [0xbe] = FD_FT_FAMILY_GPR,
    [0xbf] = FD_FT_FAMILY_GPR,
    [0xc0] = FD_FT_FAMILY_GPR,
    [0xc1] = FD_FT_FAMILY_GPR,
    [0xc3] = FD_FT_FAMILY_GPR,
    [0xc7] = FD_FT_FAMILY_GPR,
    [0xff] = FD_FT_FAMILY_CONTROL,
    [0xa2] = FD_FT_FAMILY_CONTROL,
    [0xa0] = FD_FT_FAMILY_GPR,
    [0xa1] = FD_FT_FAMILY_GPR,
    [0xa8] = FD_FT_FAMILY_GPR,
    [0xa9] = FD_FT_FAMILY_GPR,
    [0xaa] = FD_FT_FAMILY_CONTROL,
    [0xae] = FD_FT_FAMILY_CONTROL,
};

static inline uint8_t fd_ft_dispatch_mask(bool two_byte, uint8_t opcode0,
                                          uint8_t opcode1)
{
    if (two_byte) {
        uint8_t extra = fd_ft_two_byte_extra_dispatch[opcode1];

        return extra == FD_FT_FAMILY_HOT_CONTROL ? extra :
               FD_FT_FAMILY_SSE | extra;
    }

    return fd_ft_one_byte_dispatch[opcode0];
}

static inline bool fd_ft_dispatch_try(FDState *s, uint8_t opcode0,
                                      uint8_t opcode1, bool two_byte,
                                      uint64_t address,
                                      FastDecodedFT *decoded,
                                      uint8_t family_mask)
{
    FastDecoderFTMatch match;
    FDState saved_state;

    switch (family_mask) {
    case FD_FT_FAMILY_GPR:
        return fd_ft_try_gpr(s, opcode0, opcode1, two_byte, address,
                             decoded) == FD_FT_MATCH;
    case FD_FT_FAMILY_CONTROL:
        return fd_ft_try_control(s, opcode0, opcode1, two_byte, address,
                                 decoded) == FD_FT_MATCH;
    case FD_FT_FAMILY_X87:
        return fd_ft_try_x87(s, opcode0, opcode1, two_byte, address,
                             decoded) == FD_FT_MATCH;
    case FD_FT_FAMILY_SSE:
        return fd_ft_try_sse(s, opcode0, opcode1, two_byte, address,
                             decoded) == FD_FT_MATCH;
    case FD_FT_FAMILY_HOT_GPR:
        return fd_ft_try_hot_gpr(s, opcode0, address, decoded) ==
               FD_FT_MATCH;
    case FD_FT_FAMILY_HOT_CONTROL:
        return fd_ft_try_hot_control(s, opcode0, opcode1, two_byte, address,
                                     decoded) == FD_FT_MATCH;
    default:
        break;
    }

    saved_state = *s;
    if (family_mask & FD_FT_FAMILY_GPR) {
        match = fd_ft_try_gpr(s, opcode0, opcode1, two_byte, address,
                              decoded);
        if (match != FD_FT_NO_MATCH) {
            return match == FD_FT_MATCH;
        }
        *s = saved_state;
    }
    if (family_mask & FD_FT_FAMILY_CONTROL) {
        match = fd_ft_try_control(s, opcode0, opcode1, two_byte, address,
                                  decoded);
        if (match != FD_FT_NO_MATCH) {
            return match == FD_FT_MATCH;
        }
        *s = saved_state;
    }
    if (family_mask & FD_FT_FAMILY_X87) {
        match = fd_ft_try_x87(s, opcode0, opcode1, two_byte, address,
                              decoded);
        if (match != FD_FT_NO_MATCH) {
            return match == FD_FT_MATCH;
        }
        *s = saved_state;
    }
    if (family_mask & FD_FT_FAMILY_SSE) {
        match = fd_ft_try_sse(s, opcode0, opcode1, two_byte, address,
                              decoded);
        if (match != FD_FT_NO_MATCH) {
            return match == FD_FT_MATCH;
        }
    }
    return false;
}

static bool fd_ft_try_direct(const uint8_t *code, size_t code_size,
                             uint64_t address, FastDecodedFT *decoded,
                             int mode)
{
    FDState s;
    int first;
    uint8_t opcode0;
    uint8_t opcode1 = 0;
    bool two_byte = false;

    fd_ft_init_state(&s, code, code_size, address, mode);

    if (mode && code_size > 0 &&
        !fd_ft_is_legacy_prefix(code[0])) {
        first = code[0];
        if (first >= 0x40 && first <= 0x4f) {
            if (code_size < 2 ||
                fd_ft_is_legacy_prefix(code[1]) ||
                (code[1] >= 0x40 && code[1] <= 0x4f)) {
                first = parse_prefixes(&s);
                if (first < 0) {
                    return false;
                }
                determine_sizes(&s);
            } else {
                s.rex = first;
                s.has_rex = 1;
                s.rex_w = (first >> 3) & 1;
                s.rex_r = (first & 0x4) << 1;
                s.rex_x = (first & 0x2) << 2;
                s.rex_b = (first & 0x1) << 3;
                first = code[1];
                s.pos = 2;
                s.dflag = s.rex_w ? 64 : 32;
                s.aflag = 64;
            }
        } else {
            s.pos = 1;
            s.dflag = 32;
            s.aflag = 64;
        }
    } else {
        first = parse_prefixes(&s);
        if (first < 0) {
            return false;
        }
        determine_sizes(&s);
    }

    opcode0 = first;
    if (opcode0 == 0x0f) {
        int second = fd_read_byte(&s);

        if (second < 0) {
            return false;
        }
        opcode1 = second;
        two_byte = true;
    }

    return fd_ft_dispatch_try(&s, opcode0, opcode1, two_byte, address,
                              decoded,
                              fd_ft_dispatch_mask(two_byte, opcode0,
                                                  opcode1));
}
