/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */
#include "quicktrans/quicktrans.h"

#include <string.h>

#include "quicktrans/detail/fast_decoder.h"

static void qt_copy_insn(const struct la_dt_insn *src, QuickTransInsn *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->address = src->address;
    dst->size = src->size;
    dst->id = (uint16_t)src->id;
    dst->op_count = src->x86.op_count;
    memcpy(dst->bytes, src->bytes, sizeof(dst->bytes));
}

static void qt_copy_fields(const FastTemplateFields *src,
                           QuickTransTemplateFields *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->kind = src->kind;
    dst->rex = src->rex;
    dst->modrm = src->modrm;
    dst->sib = src->sib;
    dst->segment = src->segment;
    dst->rex_bits = src->rex_bits;
    dst->modrm_mod = src->modrm_mod;
    dst->modrm_reg = src->modrm_reg;
    dst->modrm_rm = src->modrm_rm;
    dst->modrm_reg_index = src->modrm_reg_index;
    dst->modrm_rm_index = src->modrm_rm_index;
    dst->disp = src->disp;
    dst->imm = src->imm;
    dst->imm64 = src->imm64;
    dst->reg = src->reg;
    dst->size = src->size;
    dst->address = src->address;
    dst->id = src->id;
    dst->vex_v = src->vex_v;
    dst->opcode0 = src->opcode0;
    dst->prefix0 = src->prefix0;
    dst->prefix2 = src->prefix2;
    dst->opcode1 = src->opcode1;
    dst->alu_op = src->alu_op;
    dst->alu_form = src->alu_form;
    dst->alu_width = src->alu_width;
    dst->addr32 = src->addr32;
    dst->skip_flags = src->skip_flags;
}

QuickTransStatus quicktrans_decode(const uint8_t *code, size_t code_size,
                                   uint64_t address, QuickTransMode mode,
                                   QuickTransInsn *out)
{
    struct la_dt_insn info;

    if (!code || !out) {
        return QUICKTRANS_INVALID_ARGUMENT;
    }
    if (!fast_decoder_get(code, code_size, address, &info,
                          mode == QUICKTRANS_MODE_64)) {
        return QUICKTRANS_UNSUPPORTED;
    }
    qt_copy_insn(&info, out);
    return QUICKTRANS_OK;
}

QuickTransStatus quicktrans_decode_template(const uint8_t *code,
                                            size_t code_size,
                                            uint64_t address,
                                            QuickTransMode mode,
                                            QuickTransDecoded *out)
{
    struct la_dt_insn info;
    FastDecodedFT decoded;

    if (!code || !out) {
        return QUICKTRANS_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    if (!fast_decoder_get(code, code_size, address, &info,
                          mode == QUICKTRANS_MODE_64)) {
        return QUICKTRANS_UNSUPPORTED;
    }
    if (!fast_decoder_get_ft(code, code_size, address, &decoded,
                             mode == QUICKTRANS_MODE_64)) {
        return QUICKTRANS_UNSUPPORTED;
    }
    qt_copy_insn(&info, &out->insn);
    out->template_kind = decoded.tmpl ? decoded.tmpl->kind : 0;
    out->has_template = decoded.tmpl != NULL;
    out->fields_valid = decoded.fields_valid;
    out->is_tb_ending = decoded.is_tb_ending;
    out->direct_fields = decoded.direct_fields;
    if (decoded.fields_valid) {
        qt_copy_fields(&decoded.fields, &out->fields);
        out->insn.address = decoded.fields.address;
        out->insn.size = decoded.fields.size;
        out->insn.id = decoded.fields.id;
    }
    return QUICKTRANS_OK;
}

const char *quicktrans_status_name(QuickTransStatus status)
{
    switch (status) {
    case QUICKTRANS_OK:
        return "ok";
    case QUICKTRANS_UNSUPPORTED:
        return "unsupported";
    case QUICKTRANS_INVALID_ARGUMENT:
        return "invalid_argument";
    default:
        return "unknown";
    }
}
