/*
 * SPDX-FileCopyrightText: 2021-2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FAST_DECODER_H
#define FAST_DECODER_H

#include <stddef.h>
#include <stdint.h>
#include "x86.h"
#include "latx-disassemble-trace.h"
#include "fast-template.h"

/* Decode context shared with SSE decoder */
typedef struct {
    const uint8_t *code;
    int pos;
    int code_size;
    uint64_t address;
    int mode;

    uint8_t prefix[4];
    uint8_t rex;
    int rex_w, rex_r, rex_x, rex_b;
    int has_rex;
    int vex_v;
    int vex_l;

    int aflag;
    int dflag;
} FDState;

typedef struct FastDecodedTemplate {
    struct la_dt_insn info;
    const FastTemplateDesc *tmpl;
} FastDecodedTemplate;

int fast_decoder_get(const uint8_t *code, size_t code_size,
                      uint64_t address,
                      struct la_dt_insn *info,
                      int mode);
int fast_decoder_get_primary(const uint8_t *code, size_t code_size,
                      uint64_t address,
                      struct la_dt_insn *info,
                      int mode);
int fast_decoder_get_template(const uint8_t *code, size_t code_size,
                              uint64_t address,
                              FastDecodedTemplate *decoded,
                              int mode);
int fast_decoder_get_ft(const uint8_t *code, size_t code_size,
                        uint64_t address, FastDecodedFT *decoded,
                        int mode);

int fd_compare(const struct la_dt_insn *fd, const struct la_dt_insn *cs, uint64_t pc);

/* Helpers exported for SSE/FPU decoders */
int fd_read_byte_s(FDState *s);
uint32_t fd_read_imm32_s(FDState *s);
dt_x86_reg fd_reg_gpr(int num, FDState *s);
dt_x86_reg fd_reg_xmm_export(int num);
dt_x86_reg fd_reg_mmx_export(int num);
dt_x86_reg fd_reg_by_size(int num, int size_bits);
int fd_decode_mem_addr_s(FDState *s, void *opnd, int mod_val, int rm_raw);
int fd_decode_mem_addr(FDState *s, dt_cs_x86_op *opnd, int mod, int rm,
                       int *out_base, int *out_index);

/* SSE/FPU handlers */
int fd_dispatch_sse(FDState *s, int op, struct la_dt_insn *info);

#endif
