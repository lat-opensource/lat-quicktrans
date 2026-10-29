/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FAST_TRANSLATOR_H
#define FAST_TRANSLATOR_H

#include "qemu/osdep.h"
#include "exec/exec-all.h"
#include "translate.h"
#include "fast-template.h"
#include "profile.h"
#include "../quicktrans.h"

typedef struct FastTranslatorTuInsnMeta {
    FastTemplateFields fields;
    uint8_t eflag_use;
    uint8_t eflag_def;
    bool terminal_exit;
    bool uses_x87_top;
} FastTranslatorTuInsnMeta;

typedef struct FastTranslatorTuTbMeta {
    TranslationBlock *tb;
    uint16_t icount;
    uint8_t eflag_use;
    uint8_t eflag_def;
    uint8_t eflag_in;
    uint8_t eflag_out;
    FastTranslatorTuInsnMeta insns[TCG_MAX_INSNS];
} FastTranslatorTuTbMeta;

typedef struct LatxFastTranslatorBenchStats {
    int64_t total_ns;
    int64_t fetch_ns;
    int64_t decode_ns;
    int64_t field_ns;
    int64_t constraint_ns;
    int64_t x87_ns;
    int64_t debug_ns;
    int64_t emit_ns;
    int64_t exit_ns;
    int64_t update_ns;
    uint64_t insns;
    uint64_t code_nr;
} LatxFastTranslatorBenchStats;

bool latx_fast_decode_translate_tb_primary(CPUArchState *env,
                                           TranslationBlock *tb,
                                           int max_insns,
                                           int *code_size,
                                           int *search_size);
/* In LATS builds, false with *code_size < 0 is a retryable code-buffer
 * or TB-size error from accel/tcg/internal.h, not a decode/emit miss.
 * The sample-bench entry uses the same convention. */
bool latx_fast_decode_translate_tb_primary_ex(CPUArchState *env,
                                              TranslationBlock *tb,
                                              int max_insns,
                                              int *code_size,
                                              int *search_size,
                                              QuickTransFailure *failure);
bool latx_fast_decode_tb_for_tu_explore(CPUArchState *env,
                                        TranslationBlock *tb,
                                        int max_insns,
                                        FastTranslatorTuTbMeta *tu_meta);
uint8_t latx_fast_analyze_tu_tb_flags(FastTranslatorTuTbMeta *tu_meta,
                                      uint8_t live_out);
bool latx_fast_translate_tu_tb_cached(CPUArchState *env,
                                      TranslationBlock *tb,
                                      FastTranslatorTuTbMeta *tu_meta,
                                      int *code_size);
bool latx_fast_patch_tu_tb_branches(TranslationBlock *tb);
bool latx_fast_translate_sample_for_bench(CPUArchState *env,
                                          TranslationBlock *tb,
                                          const uint8_t *bytes,
                                          int len,
                                          target_ulong pc,
                                          int *code_size,
                                          LatxFastTranslatorBenchStats *stats,
                                          bool detail_stats);

#endif
