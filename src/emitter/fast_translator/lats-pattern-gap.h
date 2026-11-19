/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 * SPDX-License-Identifier: MIT
 */

#ifndef QUICKTRANS_LATS_PATTERN_GAP_H
#define QUICKTRANS_LATS_PATTERN_GAP_H

/* LATS sys-inst-ptn.c scans the end of a block backwards. Only these
 * opcodes may separate a producer from its final conditional branch. */
static inline bool ft_lats_pattern_gap(const FastTemplateFields *f)
{
    /* The fast decoder aliases MOVABS to MOV, and ENDBR/RDSSP to NOP.
     * These are distinct opcodes in the LATS legacy scanner. */
    if (f->kind == FT_MOV_R64_IMM64 ||
        ((f->kind == FT_MOV_ACC_MOFFS || f->kind == FT_MOV_MOFFS_ACC) && !f->addr32) ||
        (f->opcode0 == 0x0f && f->opcode1 == 0x1e)) {
        return false;
    }
    switch (f->id) {
    case dt_X86_INS_ADDSD: case dt_X86_INS_ADDSS:
    case dt_X86_INS_LEA: case dt_X86_INS_MOV: case dt_X86_INS_MOVAPD:
    case dt_X86_INS_MOVHPS: case dt_X86_INS_MOVLPS: case dt_X86_INS_MOVSD:
    case dt_X86_INS_MOVSS: case dt_X86_INS_MOVSX: case dt_X86_INS_MOVSXD:
    case dt_X86_INS_MOVZX: case dt_X86_INS_MULPS: case dt_X86_INS_MULSD:
    case dt_X86_INS_MULSS: case dt_X86_INS_NOP: case dt_X86_INS_PSHUFD:
    case dt_X86_INS_PUNPCKLWD: case dt_X86_INS_PUSH:
        return true;
    default:
        return false;
    }
}

#endif
