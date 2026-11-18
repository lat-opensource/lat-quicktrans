/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

#include "quicktrans/detail/fast-translator.h"
#include "quicktrans/stats.h"

/* Newer LATS stores TU metadata separately from the hot TB header. */
#ifdef QUICKTRANS_LATS_SPLIT_TB_ABI
#define FT_TU_DATA(tb) ((tb)->s_data)
#else
#define FT_TU_DATA(tb) (tb)
#endif

static bool ft_primary_fail(QuickTransFailure *failure,
                            QuickTransFailureStage stage,
                            QuickTransFailureReason reason,
                            target_ulong pc, const uint8_t *bytes,
                            size_t byte_count, uint16_t instruction_id,
                            int template_kind, int instruction_index)
{
    quicktrans_failure_record(failure, stage, reason, pc, bytes, byte_count,
                              instruction_id, template_kind,
                              instruction_index);
    return false;
}

#ifndef QUICKTRANS_ENABLE_LEGACY_LATX_TRANSLATOR

bool latx_fast_decode_translate_tb_primary_ex(CPUArchState *env,
                                              TranslationBlock *tb,
                                              int max_insns,
                                              int *code_size,
                                              int *search_size,
                                              QuickTransFailure *failure)
{
    (void)env;
    (void)tb;
    (void)max_insns;
    (void)code_size;
    (void)search_size;
    quicktrans_failure_record(failure, QUICKTRANS_FAILURE_STAGE_TEMPLATE,
                              QUICKTRANS_FAILURE_REASON_MODE_UNSUPPORTED,
                              0, NULL, 0, 0, -1, -1);
    return false;
}

bool latx_fast_decode_translate_tb_primary(CPUArchState *env,
                                           TranslationBlock *tb,
                                           int max_insns,
                                           int *code_size,
                                           int *search_size)
{
    return latx_fast_decode_translate_tb_primary_ex(
        env, tb, max_insns, code_size, search_size, NULL);
}

bool latx_fast_decode_tb_for_tu_explore(CPUArchState *env,
                                        TranslationBlock *tb,
                                        int max_insns,
                                        FastTranslatorTuTbMeta *tu_meta)
{
    (void)env;
    (void)tb;
    (void)max_insns;
    (void)tu_meta;
    return false;
}

uint8_t latx_fast_analyze_tu_tb_flags(FastTranslatorTuTbMeta *tu_meta,
                                      uint8_t live_out)
{
    (void)tu_meta;
    return live_out;
}

bool latx_fast_translate_tu_tb_cached(CPUArchState *env,
                                      TranslationBlock *tb,
                                      FastTranslatorTuTbMeta *tu_meta,
                                      int *code_size)
{
    (void)env;
    (void)tb;
    (void)tu_meta;
    (void)code_size;
    return false;
}

bool latx_fast_translate_sample_for_bench(CPUArchState *env,
                                          TranslationBlock *tb,
                                          const uint8_t *bytes,
                                          int len,
                                          target_ulong pc,
                                          int *code_size,
                                          LatxFastTranslatorBenchStats *stats,
                                          bool detail_stats)
{
    (void)env;
    (void)tb;
    (void)bytes;
    (void)len;
    (void)pc;
    (void)code_size;
    (void)stats;
    (void)detail_stats;
    return false;
}

#else

#include "common.h"
#include "quicktrans/detail/fast_decoder.h"
#ifndef QUICKTRANS_LATU
#include "quicktrans/detail/code-space.h"
#define FT_LA_CHECK_SPACE(out, bytes) ft_code_space_check(out, bytes)
#endif
#include "quicktrans/detail/fast-la-emit.h"
#include "ir1.h"
#include "latx-options.h"
#ifndef QUICKTRANS_LATU
#include "latx-misc.h"
#include "latx-ras.h"
#include "latx-static-codes.h"
#include "translate.h"
#endif
#include "lsenv.h"
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
#include "ts.h"
#endif
#include "reg-map.h"
#include "tu.h"
#include "exec/cpu_ldst.h"
#include "exec/cpu-common.h"
#include "exec/helper-proto.h"
#include "exec/translate-all.h"
#include "qemu/bswap.h"
#ifndef QUICKTRANS_LATU
#include "qemu/cacheinfo.h"
#endif
#include "tcg/tcg-internal.h"
#include "tcg/tcg.h"
#ifndef QUICKTRANS_LATU
#include "tcg/tcg-split-tb.h"
#include "accel/tcg/internal.h"
#endif
#include "tcg/insn-start-words.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>

#ifndef CODEIS64
#define CODEIS64 1
#endif

static inline void ft_fetch_x86_bytes(CPUArchState *env, target_ulong pc,
                                      uint8_t *bytes, int len)
{
    int offset = 0;

    if (len >= 8) {
        stq_le_p(bytes, cpu_ldq_code(env, pc));
        offset = 8;
    }
    if (len - offset >= 4) {
        stl_le_p(bytes + offset, cpu_ldl_code(env, pc + offset));
        offset += 4;
    }
    if (len - offset >= 2) {
        stw_le_p(bytes + offset, cpu_lduw_code(env, pc + offset));
        offset += 2;
    }
    if (len != offset) {
        bytes[offset] = cpu_ldub_code(env, pc + offset);
    }
}

static inline int ft_fetch_x86_window(CPUArchState *env, target_ulong pc,
                                      uint8_t bytes[15])
{
    int page_bytes = TARGET_PAGE_SIZE - (pc & (TARGET_PAGE_SIZE - 1));
    int len = MIN(15, page_bytes);

    ft_fetch_x86_bytes(env, pc, bytes, len);
    return len;
}

static bool ft_primary_fail_decoded(CPUArchState *env,
                                    QuickTransFailure *failure,
                                    QuickTransFailureStage stage,
                                    QuickTransFailureReason reason,
                                    target_ulong report_pc,
                                    const FastTemplateFields *fields,
                                    int instruction_index)
{
    uint8_t bytes[QUICKTRANS_FAILURE_MAX_BYTES];
    size_t byte_count = 0;

    if (failure && fields) {
        int fetched = ft_fetch_x86_window(env, fields->address, bytes);

        byte_count = MIN((size_t)fields->size, (size_t)fetched);
    }
    return ft_primary_fail(failure, stage, reason, report_pc,
                           byte_count ? bytes : NULL,
                           byte_count, fields ? fields->id : 0,
                           fields ? fields->kind : FT_UNSUPPORTED,
                           instruction_index);
}

static bool ft_decode_x86_window(CPUArchState *env, target_ulong pc,
                                 uint8_t bytes[15], int decode_mode,
                                 FastDecodedFT *decoded, int *fetched)
{
    int len = ft_fetch_x86_window(env, pc, bytes);

    if (fast_decoder_get_ft(bytes, len, pc, decoded, decode_mode)) {
        *fetched = len;
        return true;
    }
    if (len < 15) {
        ft_fetch_x86_bytes(env, pc + len, bytes + len, 15 - len);
        len = 15;
    }
    *fetched = len;
    return fast_decoder_get_ft(bytes, len, pc, decoded, decode_mode);
}

#ifndef QUICKTRANS_LATU
static bool ft_decode_x86_host_window(const uint8_t *host_start,
                                      target_ulong start_pc,
                                      target_ulong pc, uint8_t bytes[15],
                                      int decode_mode,
                                      FastDecodedFT *decoded, int *fetched)
{
    const uint8_t *host_code;
    int page_bytes;
    int len;

    if (!host_start || (start_pc & TARGET_PAGE_MASK) !=
                       (pc & TARGET_PAGE_MASK)) {
        return false;
    }

    page_bytes = TARGET_PAGE_SIZE - (pc & (TARGET_PAGE_SIZE - 1));
    len = MIN(15, page_bytes);
    host_code = host_start + (pc - start_pc);
    *fetched = len;
    (void)bytes;
    return fast_decoder_get_ft(host_code, len, pc, decoded, decode_mode);
}
#endif

static bool ft_decode_x86_primary_window(CPUArchState *env,
                                         const uint8_t *host_start,
                                         target_ulong start_pc,
                                         target_ulong pc, uint8_t bytes[15],
                                         int decode_mode,
                                         FastDecodedFT *decoded, int *fetched,
                                         bool *page_boundary)
{
    *page_boundary = false;
#ifndef QUICKTRANS_LATU
    if (ft_decode_x86_host_window(host_start, start_pc, pc, bytes,
                                  decode_mode, decoded, fetched)) {
        return true;
    }
#ifdef CONFIG_SOFTMMU
    /* Keep code-page locking and retry handling in the host's fetch API. */
    int len = MIN(15, TARGET_PAGE_SIZE -
                     (pc & (TARGET_PAGE_SIZE - 1)));
    *fetched = 0;
    if ((pc & TARGET_PAGE_MASK) != (start_pc & TARGET_PAGE_MASK)) {
        bytes[0] = latxs_cpu_read_code_via_qemu(env, pc);
        if (lsenv->tr_data->deadlock_avoidance) {
            return false;
        }
        ft_fetch_x86_bytes(env, pc + 1, bytes + 1, len - 1);
    } else {
        ft_fetch_x86_bytes(env, pc, bytes, len);
    }
    *fetched = len;
    if (fast_decoder_get_ft(bytes, len, pc, decoded, decode_mode)) {
        return true;
    }
    if (len < 15) {
        /* Execute preceding instructions before fetching a new code page. */
        if (pc != start_pc) {
            *page_boundary = true;
            return false;
        }
        bytes[len] = latxs_cpu_read_code_via_qemu(env, pc + len);
        if (lsenv->tr_data->deadlock_avoidance) {
            return false;
        }
        ft_fetch_x86_bytes(env, pc + len + 1, bytes + len + 1,
                           14 - len);
        *fetched = 15;
        return fast_decoder_get_ft(bytes, 15, pc, decoded, decode_mode);
    }
    return false;
#endif
#else
    (void)host_start;
    (void)start_pc;
#endif
    return ft_decode_x86_window(env, pc, bytes, decode_mode, decoded, fetched);
}

static ADDR ft_context_switch_ret0_target(void)
{
#ifdef QUICKTRANS_LATU
    return (ADDR)context_switch_native_to_bt_ret_0;
#else
    CPUState *cpu = current_cpu;
    CPUArchState *env = cpu ? cpu->env_ptr : NULL;
    int mtcc_id = env ? curr_mtcc(env) : 0;

    return (ADDR)GET_SC_TABLE(mtcc_id, cs_native_to_bt_ret_0);
#endif
}

#ifndef QUICKTRANS_LATU
static ADDR ft_context_switch_retn_target(int succ_id)
{
    CPUState *cpu = current_cpu;
    CPUArchState *env = cpu ? cpu->env_ptr : NULL;
    int mtcc_id = env ? curr_mtcc(env) : 0;

    if (succ_id) {
        return (ADDR)GET_SC_TABLE_OFFSET(mtcc_id, cs_native_to_bt_ret_n1,
                                         lsenv->tr_data->tcg_region_offset);
    }
    return (ADDR)GET_SC_TABLE_OFFSET(mtcc_id, cs_native_to_bt_ret_n0,
                                     lsenv->tr_data->tcg_region_offset);
}

static ADDR ft_intb_lookup_target(TranslationBlock *tb)
{
    CPUState *cpu = current_cpu;
    CPUArchState *env = cpu ? cpu->env_ptr : NULL;
    int mtcc_id = env ? curr_mtcc(env) : 0;
    int fid = fsht_flags_to_id(tb->flags);

    if (option_flaged_sht && fid >= 0) {
        return (ADDR)GET_SC_TABLE_OFFSET(
            mtcc_id, intb_fsht_lookup[fid],
            lsenv->tr_data->tcg_region_offset);
    }
    return (ADDR)GET_SC_TABLE_OFFSET(mtcc_id, intb_lookup,
                                     lsenv->tr_data->tcg_region_offset);
}
#endif

static void ft_set_insn_start_data(int index, target_ulong pc)
{
#ifdef QUICKTRANS_LATU
    tcg_ctx->gen_insn_data[index][0] = pc;
#if TARGET_INSN_START_WORDS > 1
    tcg_ctx->gen_insn_data[index][1] = 0;
#endif
#else
    if (!tcg_ctx->gen_insn_data) {
        return;
    }
    tcg_ctx->gen_insn_data[index * TARGET_INSN_START_WORDS] = pc;
#if TARGET_INSN_START_WORDS > 1
    tcg_ctx->gen_insn_data[index * TARGET_INSN_START_WORDS + 1] = 0;
#endif
#endif
}

static void ft_set_insn_end_off(int index, int end_off)
{
    tcg_ctx->gen_insn_end_off[index] = end_off;
}

static bool ft_system_primary_insn_supported(const FastTemplateFields *fields)
{
    (void)fields;
    return true;
}

static int ft_lsenv_offset_of_mode_fpu(ENV *env)
{
#ifdef CONFIG_LATX_OPT_NOFP
    return lsenv_offset_of_nofp(env);
#else
    return lsenv_offset_of_mode_fpu(env);
#endif
}

#ifndef QUICKTRANS_LATU
static bool ft_lazy_mxcsr_enabled(void)
{
    return option_lazy_mxcsr != 0;
}
#endif

/* Translation-time mapping of the LATS option; no guest-side option load. */
static bool ft_fast_masked_v_enabled(void)
{
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    return option_fast_masked_v != 0;
#else
    return false;
#endif
}

static int ft_lsenv_offset_of_tr_selector(ENV *env)
{
    CPUX86State *cpu = (CPUX86State *)env->cpu_state;

    return (int)((ADDR)&cpu->tr.selector - (ADDR)env->cpu_state);
}

static int ft_lsenv_offset_of_ldtr_selector(ENV *env)
{
    CPUX86State *cpu = (CPUX86State *)env->cpu_state;

    return (int)((ADDR)&cpu->ldt.selector - (ADDR)env->cpu_state);
}

static int ft_lsenv_offset_of_idtr_base(ENV *env)
{
    CPUX86State *cpu = (CPUX86State *)env->cpu_state;

    return (int)((ADDR)&cpu->idt.base - (ADDR)env->cpu_state);
}

static int ft_lsenv_offset_of_idtr_limit(ENV *env)
{
    CPUX86State *cpu = (CPUX86State *)env->cpu_state;

    return (int)((ADDR)&cpu->idt.limit - (ADDR)env->cpu_state);
}

static int ft_lsenv_offset_of_gdtr_base(ENV *env)
{
    CPUX86State *cpu = (CPUX86State *)env->cpu_state;

    return (int)((ADDR)&cpu->gdt.base - (ADDR)env->cpu_state);
}

static int ft_lsenv_offset_of_gdtr_limit(ENV *env)
{
    CPUX86State *cpu = (CPUX86State *)env->cpu_state;

    return (int)((ADDR)&cpu->gdt.limit - (ADDR)env->cpu_state);
}

static int ft_lsenv_offset_of_cr0(ENV *env)
{
    CPUX86State *cpu = (CPUX86State *)env->cpu_state;

    return (int)((ADDR)&cpu->cr[0] - (ADDR)env->cpu_state);
}

static int ft_lsenv_offset_of_hflags(ENV *env)
{
    CPUX86State *cpu = (CPUX86State *)env->cpu_state;

    return (int)((ADDR)&cpu->hflags - (ADDR)env->cpu_state);
}

static uint8_t *ft_encode_sleb128(uint8_t *p, int64_t val)
{
    int more, byte;

    do {
        byte = val & 0x7f;
        val >>= 7;
        more = !((val == 0 && (byte & 0x40) == 0) ||
                 (val == -1 && (byte & 0x40) != 0));
        if (more) {
            byte |= 0x80;
        }
        *p++ = byte;
    } while (more);

    return p;
}

#define FT_WITH_RSP_MERGE 1
#define FT_SPECIALIZED_NAME ft_encode_search
#include "encode-search-body.inc.c"
#undef FT_SPECIALIZED_NAME
#undef FT_WITH_RSP_MERGE

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && defined(LATX_QUICKTRANS_RSP_SEARCH_ABI)
#define FT_WITH_RSP_MERGE 0
#define FT_SPECIALIZED_NAME ft_encode_search_no_rsp
#include "encode-search-body.inc.c"
#undef FT_SPECIALIZED_NAME
#undef FT_WITH_RSP_MERGE
#endif

static int64_t ft_bench_now_ns(void)
{
#if defined(__loongarch__)
    uint64_t ticks;

    __asm__ volatile("rdtime.d %0, $r0" : "=r"(ticks) :: "memory");
    return (int64_t)(ticks * 10);
#else
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
#endif
}

typedef struct FtPrimaryStageStats {
    uint64_t tb;
    uint64_t insns;
    uint64_t total_ns;
    uint64_t decode_ns;
    uint64_t analyze_ns;
    uint64_t emit_ns;
    uint64_t search_ns;
    uint64_t kind[FT_KIND_COUNT];
    uint64_t kind_words[FT_KIND_COUNT];
    uint64_t kind_emit_ns[FT_KIND_COUNT];
} FtPrimaryStageStats;

static FtPrimaryStageStats ft_primary_stage_stats;

static void ft_primary_stage_stats_dump(void)
{
#ifdef CONFIG_LATX_DEBUG
    const FtPrimaryStageStats *s = &ft_primary_stage_stats;
    uint64_t remaining[FT_KIND_COUNT];
    uint64_t emitted_words = 0;
    uint64_t measured = s->decode_ns + s->analyze_ns + s->emit_ns +
                        s->search_ns;
    uint64_t other = s->total_ns > measured ? s->total_ns - measured : 0;

    if (!s->tb) {
        return;
    }
    fprintf(stderr,
            "[FT-PRIMARY-STAGES] tb=%" PRIu64
            " total_ns=%" PRIu64 " ns_per_tb=%.2f"
            " decode_ns=%" PRIu64 " analyze_ns=%" PRIu64
            " emit_ns=%" PRIu64 " search_ns=%" PRIu64
            " other_ns=%" PRIu64 "\n",
            s->tb, s->total_ns, (double)s->total_ns / s->tb,
            s->decode_ns, s->analyze_ns, s->emit_ns, s->search_ns, other);
    memcpy(remaining, s->kind, sizeof(remaining));
    fprintf(stderr, "[FT-PRIMARY-KINDS] insns=%" PRIu64 " top=", s->insns);
    for (int rank = 0; rank < 20; ++rank) {
        uint64_t best_count = 0;
        int best_kind = -1;

        for (int kind = 0; kind < FT_KIND_COUNT; ++kind) {
            if (remaining[kind] > best_count) {
                best_count = remaining[kind];
                best_kind = kind;
            }
        }
        if (best_kind < 0) {
            break;
        }
        fprintf(stderr, "%s%d:%" PRIu64, rank ? "," : "", best_kind,
                best_count);
        remaining[best_kind] = 0;
    }
    fputc('\n', stderr);

    for (int kind = 0; kind < FT_KIND_COUNT; ++kind) {
        emitted_words += s->kind_words[kind];
    }
    memcpy(remaining, s->kind_words, sizeof(remaining));
    fprintf(stderr, "[FT-PRIMARY-KIND-WORDS] total=%" PRIu64 " top=",
            emitted_words);
    for (int rank = 0; rank < 20; ++rank) {
        uint64_t best_words = 0;
        int best_kind = -1;

        for (int kind = 0; kind < FT_KIND_COUNT; ++kind) {
            if (remaining[kind] > best_words) {
                best_words = remaining[kind];
                best_kind = kind;
            }
        }
        if (best_kind < 0) {
            break;
        }
        fprintf(stderr, "%s%d:%" PRIu64 "/%.2f",
                rank ? "," : "", best_kind, best_words,
                s->kind[best_kind] ?
                    (double)best_words / s->kind[best_kind] : 0.0);
        remaining[best_kind] = 0;
    }
    fputc('\n', stderr);

    memcpy(remaining, s->kind_emit_ns, sizeof(remaining));
    fprintf(stderr, "[FT-PRIMARY-KIND-EMIT-NS] top=");
    for (int rank = 0; rank < 20; ++rank) {
        uint64_t best_ns = 0;
        int best_kind = -1;

        for (int kind = 0; kind < FT_KIND_COUNT; ++kind) {
            if (remaining[kind] > best_ns) {
                best_ns = remaining[kind];
                best_kind = kind;
            }
        }
        if (best_kind < 0) {
            break;
        }
        fprintf(stderr, "%s%d:%" PRIu64 "/%.2f",
                rank ? "," : "", best_kind, best_ns,
                s->kind[best_kind] ?
                    (double)best_ns / s->kind[best_kind] : 0.0);
        remaining[best_kind] = 0;
    }
    fputc('\n', stderr);
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static bool ft_primary_stage_stats_enabled(void)
{
#ifdef CONFIG_LATX_DEBUG
    static bool initialized;
    static bool enabled;

    if (!initialized) {
        enabled = getenv("LATX_FT_PRIMARY_STAGE_STATS") != NULL;
        if (enabled) {
            atexit(ft_primary_stage_stats_dump);
        }
        initialized = true;
    }
    return enabled;
#else
    return false;
#endif
}

static uint64_t ft_primary_stage_stats_interval(void)
{
#ifdef CONFIG_LATX_DEBUG
    static bool initialized;
    static uint64_t interval;

    if (!initialized) {
        const char *value = getenv("LATX_FT_PRIMARY_STAGE_INTERVAL");

        interval = value && value[0] ? strtoull(value, NULL, 0) : 1000;
        initialized = true;
    }
    return interval;
#else
    return 0;
#endif
}

static void ft_primary_stage_stats_record(int64_t total_ns,
                                          int64_t decode_ns,
                                          int64_t analyze_ns,
                                          int64_t emit_ns,
                                          int64_t search_ns)
{
#ifdef CONFIG_LATX_DEBUG
    ft_primary_stage_stats.tb++;
    ft_primary_stage_stats.total_ns += total_ns;
    ft_primary_stage_stats.decode_ns += decode_ns;
    ft_primary_stage_stats.analyze_ns += analyze_ns;
    ft_primary_stage_stats.emit_ns += emit_ns;
    ft_primary_stage_stats.search_ns += search_ns;
    if (ft_primary_stage_stats_interval() &&
        ft_primary_stage_stats.tb % ft_primary_stage_stats_interval() == 0) {
        ft_primary_stage_stats_dump();
    }
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static inline void ft_primary_tb_trace(const TranslationBlock *tb,
                                       const FastTemplateFields *fields,
                                       int icount, int emitted)
{
#ifdef CONFIG_LATX_DEBUG
    static bool initialized;
    static bool enabled;

    if (!initialized) {
        enabled = getenv("LATX_FT_PRIMARY_TB_TRACE") != NULL;
        initialized = true;
    }
    if (enabled) {
        fprintf(stderr,
                "[FT-PRIMARY-TB] pc=0x%" PRIx64
                " x86_insns=%d x86_bytes=%u la_insns=%d templates=",
                tb->pc, icount, tb->size, emitted);
        for (int i = 0; i < icount; ++i) {
            int start = i == 0 ? 0 : tcg_ctx->gen_insn_end_off[i - 1];
            int end = tcg_ctx->gen_insn_end_off[i];

            fprintf(stderr, "%s%d:%d", i ? "," : "", fields[i].kind,
                    (end - start) >> 2);
        }
        fputc('\n', stderr);
    }
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static bool ft_primary_sample_trace_enabled(void)
{
#ifdef CONFIG_LATX_DEBUG
    static bool initialized;
    static bool enabled;

    if (!initialized) {
        enabled = getenv("LATX_FT_PRIMARY_SAMPLE_TRACE") != NULL;
        initialized = true;
    }
    return enabled;
#else
    return false;
#endif
}

static void ft_primary_sample_trace(CPUArchState *env,
                                    const FastTemplateFields *fields)
{
#ifdef CONFIG_LATX_DEBUG
    uint8_t bytes[15];

    if (!fields || fields->size == 0 || fields->size > sizeof(bytes)) {
        return;
    }
    ft_fetch_x86_bytes(env, fields->address, bytes, fields->size);
    fprintf(stderr,
            "[FT-PRIMARY-SAMPLE] pc=0x%" PRIx64
            " kind=%d size=%u bytes=",
            fields->address, fields->kind, fields->size);
    for (int i = 0; i < fields->size; ++i) {
        fprintf(stderr, "%02x", bytes[i]);
    }
    fputc('\n', stderr);
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

typedef struct FastTemplateRuntimeInfo {
    uint8_t eflag_use;
    bool terminal_exit;
    bool uses_x87_top;
    bool no_eflags;
} FastTemplateRuntimeInfo;

#define FT_EMIT_PROFILE_TABLE_BITS 14
#define FT_EMIT_PROFILE_TABLE_SIZE (1u << FT_EMIT_PROFILE_TABLE_BITS)
#define FT_EMIT_PROFILE_MAX_WORDS 16

typedef struct FtEmitCacheKey {
    uint64_t word[7];
} FtEmitCacheKey;

typedef struct FtEmitProfileEntry {
    uint64_t hash;
    FtEmitCacheKey key;
    uint32_t code[FT_EMIT_PROFILE_MAX_WORDS];
    uint8_t words;
    bool used;
} FtEmitProfileEntry;

typedef struct FtEmitProfileStats {
    FtEmitProfileEntry *table;
    uint64_t tb;
    uint64_t candidates;
    uint64_t hits;
    uint64_t unique;
    uint64_t collisions;
    uint64_t unstable;
    uint64_t too_long;
    uint64_t full;
    uint64_t kind_candidates[FT_KIND_COUNT];
    uint64_t kind_hits[FT_KIND_COUNT];
} FtEmitProfileStats;

#ifdef CONFIG_LATX_DEBUG
static FtEmitProfileStats ft_emit_profile_stats;
#endif

static FtEmitCacheKey ft_emit_cache_key(const FastTemplateFields *fields)
{
    FtEmitCacheKey key = {
        .word = {
            (uint64_t)(uint16_t)fields->kind |
                ((uint64_t)(uint16_t)fields->rex << 16) |
                ((uint64_t)(uint16_t)fields->modrm << 32) |
                ((uint64_t)(uint8_t)fields->reg << 48) |
                ((uint64_t)(uint8_t)fields->segment << 56),
            (uint64_t)fields->sib |
                ((uint64_t)fields->prefix0 << 8) |
                ((uint64_t)fields->prefix2 << 16) |
                ((uint64_t)fields->opcode0 << 24) |
                ((uint64_t)fields->opcode1 << 32) |
                ((uint64_t)fields->size << 40) |
                ((uint64_t)fields->id << 48),
            fields->imm64,
            (uint64_t)(uint32_t)fields->disp |
                ((uint64_t)(uint32_t)fields->imm << 32),
            (uint64_t)fields->rex_bits |
                ((uint64_t)fields->modrm_mod << 8) |
                ((uint64_t)fields->modrm_reg << 16) |
                ((uint64_t)fields->modrm_rm << 24) |
                ((uint64_t)fields->modrm_reg_index << 32) |
                ((uint64_t)fields->modrm_rm_index << 40) |
                ((uint64_t)(uint8_t)fields->vex_v << 48) |
                ((uint64_t)fields->alu_op << 56),
            (uint64_t)fields->alu_form |
                ((uint64_t)fields->alu_width << 8) |
                ((uint64_t)(uint8_t)fields->direct_cmp_lhs_gpr << 16) |
                ((uint64_t)(uint8_t)fields->direct_cmp_rhs_gpr << 24) |
                ((uint64_t)fields->addr32 << 32) |
                ((uint64_t)fields->skip_flags << 33) |
                ((uint64_t)fields->direct_branch_kind << 34) |
                ((uint64_t)fields->direct_cmp_width << 40) |
                ((uint64_t)(uint8_t)fields->direct_bit_index_gpr << 48) |
                ((uint64_t)(uint8_t)fields->direct_bit_index_imm << 56),
            (uint64_t)fields->instptn_div_kind |
                ((uint64_t)fields->instptn_skip << 8) |
                ((uint64_t)fields->direct_float_result << 9) |
                ((uint64_t)fields->direct_float_xx << 10) |
                ((uint64_t)fields->omit_zext32 << 11) |
                ((uint64_t)fields->scalar_direct_dst << 12),
        },
    };

    return key;
}

static inline uint64_t ft_emit_profile_hash_value(uint64_t hash,
                                                  uint64_t value)
{
    hash ^= value;
    return hash * UINT64_C(1099511628211);
}

static uint64_t ft_emit_profile_hash(const FtEmitCacheKey *key)
{
    uint64_t hash = UINT64_C(1469598103934665603);

    for (unsigned i = 0; i < ARRAY_SIZE(key->word); ++i) {
        hash = ft_emit_profile_hash_value(hash, key->word[i]);
    }
    hash ^= hash >> 33;
    hash *= UINT64_C(0xff51afd7ed558ccd);
    hash ^= hash >> 33;
    hash *= UINT64_C(0xc4ceb9fe1a85ec53);
    hash ^= hash >> 33;
    return hash ? hash : 1;
}

static bool ft_emit_profile_candidate(const FastTemplateFields *fields,
                                      const FastTemplateRuntimeInfo *meta)
{
    if (meta->terminal_exit || meta->uses_x87_top || fields->segment >= 0) {
        return false;
    }
    if (fields->alu_op != FT_ALU_NONE) {
        return fields->alu_form == FT_ALU_FORM_ACC_IMM ||
               fields->modrm_mod == 3;
    }
    switch (fields->kind) {
    case FT_XOR_RM_GPR_ZERO:
    case FT_MOV_RM64_R64:
    case FT_MOV_R64_RM64:
    case FT_MOV_R32_RM32:
    case FT_MOV_RM32_R32:
    case FT_MOV_R8_RM8:
    case FT_MOV_R16_RM16:
    case FT_MOV_RM16_R16:
    case FT_MOV_RM8_R8:
        return fields->modrm_mod == 3;
    case FT_MOV_R8_IMM8:
    case FT_MOV_R16_IMM16:
    case FT_MOV_R32_IMM32:
    case FT_MOV_R64_IMM64:
        return true;
    default:
        return false;
    }
}

static void ft_emit_profile_dump(void)
{
#ifdef CONFIG_LATX_DEBUG
    FtEmitProfileStats *s = &ft_emit_profile_stats;
    uint64_t remaining[FT_KIND_COUNT];

    fprintf(stderr,
            "[FT-EMIT-CACHE-PROFILE] tb=%" PRIu64
            " candidates=%" PRIu64
            " hits=%" PRIu64 " hit_rate=%.4f unique=%" PRIu64
            " collisions=%" PRIu64 " unstable=%" PRIu64
            " too_long=%" PRIu64 " full=%" PRIu64 "\n",
            s->tb, s->candidates, s->hits,
            s->candidates ? (double)s->hits / s->candidates : 0.0,
            s->unique, s->collisions, s->unstable, s->too_long, s->full);
    memcpy(remaining, s->kind_candidates, sizeof(remaining));
    fprintf(stderr, "[FT-EMIT-CACHE-KINDS] top=");
    for (int rank = 0; rank < 20; ++rank) {
        uint64_t best_count = 0;
        int best_kind = -1;

        for (int kind = 0; kind < FT_KIND_COUNT; ++kind) {
            if (remaining[kind] > best_count) {
                best_count = remaining[kind];
                best_kind = kind;
            }
        }
        if (best_kind < 0) {
            break;
        }
        fprintf(stderr, "%s%d:%" PRIu64 "/%" PRIu64 "/%.4f",
                rank ? "," : "", best_kind, s->kind_hits[best_kind],
                best_count, (double)s->kind_hits[best_kind] / best_count);
        remaining[best_kind] = 0;
    }
    fputc('\n', stderr);
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static bool ft_emit_profile_enabled(void)
{
#ifdef CONFIG_LATX_DEBUG
    static bool initialized;
    static bool enabled;

    if (!initialized) {
        enabled = getenv("LATX_FT_EMIT_CACHE_PROFILE") != NULL;
        if (enabled) {
            ft_emit_profile_stats.table =
                calloc(FT_EMIT_PROFILE_TABLE_SIZE,
                       sizeof(*ft_emit_profile_stats.table));
            enabled = ft_emit_profile_stats.table != NULL;
            if (enabled) {
                atexit(ft_emit_profile_dump);
            }
        }
        initialized = true;
    }
    if (enabled) {
        ft_emit_profile_stats.tb++;
        if (ft_emit_profile_stats.tb % 1000 == 0) {
            ft_emit_profile_dump();
        }
    }
    return enabled;
#else
    return false;
#endif
}

static void ft_emit_profile_record(const FastTemplateFields *fields,
                                   const FastTemplateRuntimeInfo *meta,
                                   const uint32_t *code, int words)
{
#ifdef CONFIG_LATX_DEBUG
    FtEmitProfileStats *s = &ft_emit_profile_stats;
    FtEmitCacheKey key;
    uint64_t hash;
    unsigned index;

    if (!ft_emit_profile_candidate(fields, meta)) {
        return;
    }
    s->candidates++;
    s->kind_candidates[fields->kind]++;
    if (words > FT_EMIT_PROFILE_MAX_WORDS) {
        s->too_long++;
        return;
    }

    key = ft_emit_cache_key(fields);
    hash = ft_emit_profile_hash(&key);
    index = hash & (FT_EMIT_PROFILE_TABLE_SIZE - 1);
    for (unsigned probe = 0; probe < FT_EMIT_PROFILE_TABLE_SIZE; ++probe) {
        FtEmitProfileEntry *entry = &s->table[index];

        if (!entry->used) {
            entry->used = true;
            entry->hash = hash;
            entry->key = key;
            entry->words = words;
            memcpy(entry->code, code, words * sizeof(*code));
            s->unique++;
            return;
        }
        if (entry->hash == hash &&
            memcmp(&entry->key, &key, sizeof(key)) == 0) {
            s->hits++;
            s->kind_hits[fields->kind]++;
            if (entry->words != words ||
                memcmp(entry->code, code, words * sizeof(*code)) != 0) {
                s->unstable++;
            }
            return;
        }
        s->collisions++;
        index = (index + 1) & (FT_EMIT_PROFILE_TABLE_SIZE - 1);
    }
    s->full++;
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static unsigned long ft_debug_live_limit(void)
{
#ifdef CONFIG_LATX_DEBUG
    static bool initialized;
    static unsigned long limit = 32;

    if (!initialized) {
        const char *value = getenv("LATX_FT_DEBUG_LIVE_MAX");

        if (value && value[0]) {
            limit = strtoul(value, NULL, 0);
        }
        initialized = true;
    }
    return limit;
#else
    return 0;
#endif
}

static void ft_debug_dump_live_regs(CPUArchState *env, target_ulong pc,
                                    const char *phase, unsigned long condition)
{
#ifdef CONFIG_LATX_DEBUG
    static unsigned long count;

    if (count++ >= ft_debug_live_limit()) {
        return;
    }

    fprintf(stderr,
            "[FT-STATE] phase=%s pc=0x%lx eip=0x%lx cc_src=0x%lx "
            "cc_op=%u cond=0x%lx eflags=0x%lx rsp=0x%lx rbp=0x%lx rsi=0x%lx "
            "rdi=0x%lx r13=0x%lx rax=0x%lx rbx=0x%lx rcx=0x%lx "
            "rdx=0x%lx r8=0x%lx r9=0x%lx r10=0x%lx r11=0x%lx "
            "\n",
            phase,
            (unsigned long)pc,
            (unsigned long)env->eip,
            (unsigned long)env->cc_src,
            env->cc_op,
            condition,
            (unsigned long)env->eflags,
            (unsigned long)env->regs[esp_index],
            (unsigned long)env->regs[ebp_index],
            (unsigned long)env->regs[esi_index],
            (unsigned long)env->regs[edi_index],
            (unsigned long)env->regs[r13_index],
            (unsigned long)env->regs[eax_index],
            (unsigned long)env->regs[ebx_index],
            (unsigned long)env->regs[ecx_index],
            (unsigned long)env->regs[edx_index],
            (unsigned long)env->regs[r8_index],
            (unsigned long)env->regs[r9_index],
            (unsigned long)env->regs[r10_index],
            (unsigned long)env->regs[r11_index]);
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static void ft_debug_dump_live_entry(CPUArchState *env, target_ulong pc)
{
#ifdef CONFIG_LATX_DEBUG
    ft_debug_dump_live_regs(env, pc, "entry", 0);
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static void ft_debug_dump_live_exit(CPUArchState *env, target_ulong pc,
                                    unsigned long condition)
{
#ifdef CONFIG_LATX_DEBUG
    ft_debug_dump_live_regs(env, pc, "exit", condition);
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

#ifdef CONFIG_LATX_DEBUG
static bool fast_template_emit_constraints_ok(const FastTemplateFields *fields);
#endif
#include "template-class.inc.c"

#include "template-info.inc.c"

/* These diagnostics are process-startup settings, like the primary trace
 * options above. Cache the parsed bits, not environment-owned pointers.
 * Relaxed atomics avoid races between simultaneous first translations. */
enum {
    FT_STARTUP_READY = 1u,
    FT_STARTUP_EXIT_CLEANUP = 2u,
    FT_STARTUP_TU_TRACE = 4u,
    FT_STARTUP_TU_DIRECT_TRACE = 8u,
    FT_STARTUP_TB_KIND_TRACE = 16u,
};

static unsigned int ft_startup_flags(void)
{
    static unsigned int cached;
    unsigned int flags = __atomic_load_n(&cached, __ATOMIC_RELAXED);

    if (flags == 0) {
        flags = FT_STARTUP_READY;
#ifndef CONFIG_SOFTMMU
        if (quicktrans_profile_exit_cleanup_required() ||
            quicktrans_stats_requested() ||
            getenv("LATX_TRANSLATOR_STATS") != NULL
#ifdef CONFIG_LATX_DEBUG
            || getenv("LATX_FT_TU_STATS") != NULL
            || getenv("LATX_FT_TU_DIRECT_STATS") != NULL
#endif
            ) {
            flags |= FT_STARTUP_EXIT_CLEANUP;
        }
#endif
#ifdef CONFIG_LATX_DEBUG
        if (getenv("LATX_FT_TU_TRACE") != NULL) {
            flags |= FT_STARTUP_TU_TRACE;
        }
        if (getenv("LATX_FT_TU_DIRECT_TRACE") != NULL) {
            flags |= FT_STARTUP_TU_DIRECT_TRACE;
        }
        if (getenv("LATX_FT_TB_KIND_TRACE") != NULL) {
            flags |= FT_STARTUP_TB_KIND_TRACE;
        }
#endif
        __atomic_store_n(&cached, flags, __ATOMIC_RELAXED);
    }
    return flags;
}

#include "emit-core.inc.c"

static void ft_emit_load_env(uint32_t **out, int dst, int offset,
                             uint32_t load_op);
static void ft_emit_save_condition_flags(uint32_t **out);
static void ft_emit_restore_condition_flags(uint32_t **out);
static void ft_emit_save_fprs_to_env(uint32_t **out);
static void ft_emit_save_xmms_to_env(uint32_t **out);
static void ft_emit_xmm_env_addr(uint32_t **out, int dst, int xmm);
static int ft_emit_helper_indirect_exit(uint32_t **out, TranslationBlock *tb,
                                        uint32_t *code, int target,
                                        bool is_ret);

#include "operand-address.inc.c"

#define FAST_TEMPLATE_SKIP_FIELD_FILL
#include "fields.inc.c"
#undef FAST_TEMPLATE_SKIP_FIELD_FILL

#include "emit-env.inc.c"

#include "emit-host-abi.inc.c"

#include "emit-exit.inc.c"

#include "emit-memory.inc.c"

#include "emit-grp1.inc.c"

#include "emit-alu.inc.c"

#include "emit-bit.inc.c"

#include "emit-atomic-div.inc.c"

#include "emit-gpr.inc.c"
#include "emit-shift.inc.c"
#include "emit-stack.inc.c"
#include "emit-flags.inc.c"
#include "emit-string.inc.c"
#include "emit-misc.inc.c"
#include "emit-helper.inc.c"
#include "emit-simd.inc.c"

#include "emit-x87-helper.inc.c"
#include "emit-x87.inc.c"
#include "emit-dispatch.inc.c"

#include "analyze-xmm-high.inc.c"
#include "emit-template.inc.c"
#include "emit-pattern-cache.inc.c"
#include "emit-rsp-merge.inc.c"

/* Share unchanged XMM state only across consecutive soft x87 helpers.
 * The entry snapshot remains authoritative throughout the shared region. */
static bool ft_x87_can_share_context(const FastTemplateFields *fields)
{
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_X87_SIGNAL_ABI) && !defined(CONFIG_SOFTMMU)
    if (option_soft_fpu != 2 || option_softfpu_fast) return false;
    switch (fields->kind) {
    case FT_X87_FRNDINT: case FT_X87_FSQRT: case FT_X87_F2XM1:
    case FT_X87_FSCALE: case FT_X87_FSIN: case FT_X87_FPREM:
    case FT_X87_FPREM1: case FT_X87_FTST: case FT_X87_FXAM:
        return true;
    case FT_X87_FCOM_REG:
        return fields->modrm_mod == 3;
    case FT_X87_FIST_M16: case FT_X87_FIST_M32:
        return fields->modrm_mod != 3 && fields->modrm_reg == 2;
    case FT_X87_FST_M32: case FT_X87_FST_M64:
        return fields->modrm_mod != 3;
    case FT_X87_BIN_M32: case FT_X87_BIN_M64:
    case FT_X87_FI_BIN_M16: case FT_X87_FI_BIN_M32:
        return fields->modrm_mod != 3 && fields->modrm_reg != 2 &&
               fields->modrm_reg != 3;
    case FT_X87_FCOM_M32: case FT_X87_FCOM_M64:
        return fields->modrm_mod != 3 && fields->modrm_reg == 2;
    case FT_X87_BIN_REG:
        return fields->modrm_mod == 3 &&
            (fields->id == dt_X86_INS_FADD || fields->id == dt_X86_INS_FMUL ||
             fields->id == dt_X86_INS_FSUB || fields->id == dt_X86_INS_FSUBR ||
             fields->id == dt_X86_INS_FDIV || fields->id == dt_X86_INS_FDIVR);
    default:
        return false;
    }
#else
    (void)fields;
    return false;
#endif
}

static int ft_emit_x87_shared_context(const FastTemplateFields *fields,
                                      uint32_t *code, bool first, bool last)
{
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_X87_SIGNAL_ABI) && !defined(CONFIG_SOFTMMU)
    uint32_t *out = code;
    if (first) {
        /* Eligible x87 instructions preserve guest GPRs and integer flags.
         * Keep one authoritative snapshot until the shared region ends;
         * FST restores call-clobbered address operands when needed. */
        ft_emit_save_gprs_to_env(&out);
        ft_emit_save_xmms_to_env(&out);
        ft_emit_save_condition_flags(&out);
        FT_LA_ORI_EMIT(&out, la_t0, la_zero, 1);
        ft_emit_store_env(&out, la_t0,
                         offsetof(CPUX86State, qt_helper_env_saved),
                         FT_LA_OPCODE_ST_B);
    }
    bool integer_store = fields->kind == FT_X87_FIST_M16 ||
                         fields->kind == FT_X87_FIST_M32;
    bool store = fields->kind == FT_X87_FST_M32 ||
                 fields->kind == FT_X87_FST_M64 || integer_store;
    bool integer = fields->kind == FT_X87_FI_BIN_M16 ||
                   fields->kind == FT_X87_FI_BIN_M32;
    bool compare = fields->kind == FT_X87_FCOM_M32 ||
                   fields->kind == FT_X87_FCOM_M64;
    bool memory = integer || compare || fields->kind == FT_X87_BIN_M32 ||
                  fields->kind == FT_X87_BIN_M64;
    int width = fields->kind == FT_X87_FI_BIN_M16 ? 16 :
                fields->kind == FT_X87_BIN_M64 ||
                fields->kind == FT_X87_FCOM_M64 ? 64 : 32;
    if (store || memory) {
        int base;
        bool preserved_base = !fields->addr32 && fields->segment < 0 &&
            ft_supported_base_disp_addr(fields->rex, fields->modrm, fields->sib) &&
            ft_base_from_modrm_sib(fields, &base) &&
            ft_gpr(base) >= la_s0 && ft_gpr(base) <= la_s7;
        if (!first && !preserved_base) {
            for (int i = 0; i < GPR_NUM; ++i) {
                if (ft_gpr(i) < la_s0 || ft_gpr(i) > la_s7)
                    ft_emit_load_env(&out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i),
                                     FT_LA_OPCODE_LD_D);
            }
        }
        int addr;
        if (!ft_emit_rip_or_mem_addr(&out, fields, fields->address, &addr)) return 0;
        int offset = ft_mem_access_offset(fields, addr);
        if (store) {
            FT_LA_ADDI_D_EMIT(&out, la_a1, addr, offset);
            ft_emit_host_stack_begin(&out);
            FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
            FT_LA_ST_D_EMIT(&out, la_a1, la_sp, 0);
            ft_emit_host_stack_end(&out);
        } else {
            if (width == 16) FT_LA_LD_H_EMIT(&out, la_a1, addr, offset);
            else if (integer) FT_LA_LD_W_EMIT(&out, la_a1, addr, offset);
            else if (width == 32) FT_LA_LD_WU_EMIT(&out, la_a1, addr, offset);
            else FT_LA_LD_D_EMIT(&out, la_a1, addr, offset);
            if (compare && !ft_emit_x87_mark_denormal_operand(&out, la_a1, width == 64))
                return 0;
            ft_emit_cpu_env_ptr(&out, la_a0);
            void *convert = integer ? (void *)helper_fildl_FT0 :
                compare ? (width == 32 ? (void *)helper_flds_FT0 : (void *)helper_fldl_FT0) :
                width == 32 ? (void *)ft_x87_memory_flds : (void *)ft_x87_memory_fldl;
            ft_emit_host_call(&out, convert, 1u << 0);
        }
    }
    ft_emit_cpu_env_ptr(&out, la_a0);
    void *helper;
    if (store) {
        helper = integer_store ?
            (fields->kind == FT_X87_FIST_M16 ? (void *)ft_x87_helper_fist : (void *)ft_x87_helper_fistl) :
            (fields->kind == FT_X87_FST_M32 ? (void *)ft_x87_helper_fsts : (void *)ft_x87_helper_fstl);
    } else if (memory) {
        static void *const helpers[8] = {
            (void *)ft_soft_memory_fadd, (void *)ft_soft_memory_fmul,
            NULL, NULL, (void *)ft_soft_memory_fsub, (void *)ft_soft_memory_fsubr,
            (void *)ft_soft_memory_fdiv, (void *)ft_soft_memory_fdivr,
        };
        helper = compare ? (void *)helper_fcom_ST0_FT0 : helpers[fields->modrm_reg];
    } else if (fields->kind == FT_X87_BIN_REG) {
        int op;
        switch (fields->id) {
        case dt_X86_INS_FADD: op = FT_X87_REG_ADD; break;
        case dt_X86_INS_FMUL: op = FT_X87_REG_MUL; break;
        case dt_X86_INS_FSUB: op = FT_X87_REG_SUB; break;
        case dt_X86_INS_FSUBR: op = FT_X87_REG_SUBR; break;
        case dt_X86_INS_FDIV: op = FT_X87_REG_DIV; break;
        case dt_X86_INS_FDIVR: op = FT_X87_REG_DIVR; break;
        default: return 0;
        }
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->modrm & 7);
        helper = (void *)ft_x87_binary_helpers[fields->opcode0 != 0xd8][op];
    } else if (fields->kind == FT_X87_FCOM_REG) {
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->modrm & 7);
        FT_LA_ADDI_D_EMIT(&out, la_a2, la_zero, fields->id == dt_X86_INS_FUCOM);
        helper = (void *)ft_x87_helper_compare_reg;
    } else {
        switch (fields->kind) {
        case FT_X87_FRNDINT: helper = (void *)ft_x87_frndint_soft; break;
        case FT_X87_FSQRT: helper = (void *)ft_soft_fsqrt; break;
        case FT_X87_F2XM1: helper = (void *)ft_soft_f2xm1; break;
        case FT_X87_FSCALE: helper = (void *)ft_soft_fscale; break;
        case FT_X87_FSIN: helper = (void *)ft_soft_fsin; break;
        case FT_X87_FPREM: helper = (void *)ft_soft_fprem; break;
        case FT_X87_FPREM1: helper = (void *)ft_soft_fprem1; break;
        case FT_X87_FTST: helper = (void *)ft_x87_helper_ftst; break;
        case FT_X87_FXAM: helper = (void *)helper_fxam_ST0_softfpu; break;
        default: return 0;
        }
    }
    ft_emit_host_call(&out, helper, 1u << 0);
    if (store) {
        ft_emit_host_stack_begin(&out);
        FT_LA_LD_D_EMIT(&out, la_a1, la_sp, 0);
        FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
        ft_emit_host_stack_end(&out);
        int store_width = integer_store ?
            (fields->kind == FT_X87_FIST_M16 ? 16 : 32) :
            (fields->kind == FT_X87_FST_M32 ? 32 : 64);
        ft_emit_x87_soft_store(&out, la_a1, la_a0, store_width);
    }
    if (last) {
        ft_emit_restore_condition_flags(&out);
        ft_emit_load_xmms_from_env(&out);
        int first_gpr = 0;
        while (first_gpr < 8 && ft_gpr(first_gpr) == la_s0 + first_gpr) ++first_gpr;
        for (int i = first_gpr; i < GPR_NUM; ++i)
            ft_emit_load_env(&out, ft_gpr(i), lsenv_offset_of_gpr(lsenv, i), FT_LA_OPCODE_LD_D);
        ft_emit_store_env(&out, la_zero,
                         offsetof(CPUX86State, qt_helper_env_saved),
                         FT_LA_OPCODE_ST_B);
    }
    return out - code;
#else
    (void)fields; (void)code; (void)first; (void)last;
    return 0;
#endif
}

#ifdef CONFIG_LATX_DEBUG
#include "constraints.inc.c"
#endif

/* Fast translator primary TB pipelines. */

typedef struct FastTemplateEflagMasks {
    uint8_t use;
    uint8_t def;
} FastTemplateEflagMasks;

static int ft_tu_decode_mode(const TranslationBlock *tb)
{
    return (tb->flags & HF_CS64_MASK) ? 1 : 0;
}

#define FT_EFLAGS_ALL (CF_USEDEF_BIT | PF_USEDEF_BIT | AF_USEDEF_BIT | \
                       ZF_USEDEF_BIT | SF_USEDEF_BIT | OF_USEDEF_BIT)

static const FastTemplateRuntimeInfo *ft_template_runtime_info(
    FastTemplateKind kind);
static FastTemplateEflagMasks ft_template_eflag_masks(
    const FastTemplateFields *fields,
    const FastTemplateRuntimeInfo *meta);
static bool ft_primary_trace_opt_enabled(void);
static uint8_t ft_analyze_tb_flags(FastTemplateFields *fields,
                                   const FastTemplateRuntimeInfo **meta,
                                   int count, unsigned int candidates,
                                   bool analyze_gpr_high,
                                   bool analyze_xmm_high);
static bool ft_direct_alu_result_gpr(const FastTemplateFields *alu, int *dst)
{
    if (alu->alu_width == 8) {
        if ((alu->alu_form == FT_ALU_FORM_RM_R ||
             alu->alu_form == FT_ALU_FORM_RM_IMM) &&
            ft_modrm_rm_is_high8(alu)) {
            return false;
        }
        if (alu->alu_form == FT_ALU_FORM_R_RM &&
            ft_modrm_reg_is_high8(alu)) {
            return false;
        }
    }
    switch (alu->alu_form) {
    case FT_ALU_FORM_RM_R:
    case FT_ALU_FORM_RM_IMM:
        if (alu->modrm_mod != 3 || alu->modrm_rm_index >= GPR_NUM) {
            return false;
        }
        *dst = alu->modrm_rm_index;
        return true;
    case FT_ALU_FORM_R_RM:
        if (alu->modrm_reg_index >= GPR_NUM) {
            return false;
        }
        *dst = alu->modrm_reg_index;
        return true;
    case FT_ALU_FORM_ACC_IMM:
        *dst = rax_index;
        return true;
    default:
        return false;
    }
}

static bool ft_direct_result_jcc_kind(FastAluOp op, int jcc_id,
                                      FastDirectBranchKind *kind)
{
    if (jcc_id == dt_X86_INS_JE || jcc_id == dt_X86_INS_JNE) {
        *kind = jcc_id == dt_X86_INS_JE ? FT_DIRECT_BRANCH_EQ :
                                          FT_DIRECT_BRANCH_NE;
        return true;
    }
    switch (op) {
    case FT_ALU_ADD:
        if (jcc_id == dt_X86_INS_JNS) {
            *kind = FT_DIRECT_BRANCH_GE;
            return true;
        }
        break;
    case FT_ALU_SUB:
        if (jcc_id == dt_X86_INS_JS || jcc_id == dt_X86_INS_JNS) {
            *kind = jcc_id == dt_X86_INS_JS ? FT_DIRECT_BRANCH_LT :
                                              FT_DIRECT_BRANCH_GE;
            return true;
        }
        break;
    case FT_ALU_AND:
    case FT_ALU_OR:
    case FT_ALU_XOR:
        switch (jcc_id) {
        case dt_X86_INS_JS:  *kind = FT_DIRECT_BRANCH_LT; return true;
        case dt_X86_INS_JNS: *kind = FT_DIRECT_BRANCH_GE; return true;
        case dt_X86_INS_JLE: *kind = FT_DIRECT_BRANCH_LE; return true;
        case dt_X86_INS_JG:  *kind = FT_DIRECT_BRANCH_GT; return true;
        case dt_X86_INS_JO:
        case dt_X86_INS_JB:  *kind = FT_DIRECT_BRANCH_NEVER; return true;
        case dt_X86_INS_JNO:
        case dt_X86_INS_JAE: *kind = FT_DIRECT_BRANCH_ALWAYS; return true;
        case dt_X86_INS_JBE: *kind = FT_DIRECT_BRANCH_EQ; return true;
        case dt_X86_INS_JA:  *kind = FT_DIRECT_BRANCH_NE; return true;
        default: break;
        }
        break;
    default:
        break;
    }
    return false;
}

static void ft_analyze_direct_jcc_pair(FastTemplateFields *test,
                                       FastTemplateFields *jcc, bool gap);
static bool ft_primary_debug_live_enabled(void);
static void ft_primary_debug_emit_live_regs(uint32_t **out, target_ulong pc);
static void ft_primary_debug_dump_code(target_ulong pc,
                                       const FastTemplateFields *fields,
                                       const uint32_t *code, int count);
static void ft_primary_update_last_info(TranslationBlock *tb,
                                        const FastTemplateFields *fields);

static const FastTemplateRuntimeInfo ft_template_runtime_table[FT_KIND_COUNT] = {
    [FT_MOV_RM64_R64] = { .no_eflags = true },
    [FT_MOV_R64_RM64] = { .no_eflags = true },
    [FT_LEA_R64_M] = { .no_eflags = true },
    [FT_POP_R64] = { .no_eflags = true },
    [FT_PUSH_R64] = { .no_eflags = true },
    [FT_PUSH_SEG64] = { .no_eflags = true },
    [FT_POP_SEG64] = { .no_eflags = true },
    [FT_PUSH_SEG16] = { .no_eflags = true },
    [FT_POP_SEG16] = { .no_eflags = true },
    [FT_MOVZX_R32_RM8] = { .no_eflags = true },
    [FT_MOV_R32_IMM32] = { .no_eflags = true },
    [FT_MOV_R32_RM32] = { .no_eflags = true },
    [FT_MOV_RM32_R32] = { .no_eflags = true },
    [FT_CMP_XMM_XMMM_IMM8] = { .no_eflags = true },
    [FT_JCC_REL] = {
        .terminal_exit = true,
    },
    [FT_JRCXZ_REL8] = { .terminal_exit = true },
    [FT_LOOP_REL8] = { .terminal_exit = true },
    [FT_LOOPE_REL8] = {
        .eflag_use = ZF_USEDEF_BIT,
        .terminal_exit = true,
    },
    [FT_LOOPNE_REL8] = {
        .eflag_use = ZF_USEDEF_BIT,
        .terminal_exit = true,
    },
    [FT_CALL_REL32] = {
        .terminal_exit = true,
        .no_eflags = true,
    },
    [FT_CALL_RM64] = { .terminal_exit = true },
    [FT_JMP_REL32] = {
        .terminal_exit = true,
        .no_eflags = true,
    },
    [FT_JMP_RM64] = { .terminal_exit = true },
    [FT_RET] = {
        .terminal_exit = true,
        .no_eflags = true,
    },
    [FT_RET_IMM16] = { .terminal_exit = true },
    [FT_HELPER_SYSCALL] = { .terminal_exit = true },
    [FT_IO] = { .no_eflags = true },
    [FT_SALC] = { .eflag_use = CF_USEDEF_BIT },
    [FT_STRING_IO] = { .no_eflags = true },
    [FT_HELPER_SYSENTER] = { .terminal_exit = true },
    [FT_HELPER_SYSEXIT] = { .terminal_exit = true },
    [FT_HELPER_SYSRET] = { .terminal_exit = true },
    [FT_RSM] = { .terminal_exit = true },
    [FT_XSETBV] = { .terminal_exit = true },
    [FT_CLTS] = { .terminal_exit = true },
    [FT_INVLPG] = { .terminal_exit = true },
    [FT_WRMSR] = { .terminal_exit = true },
    [FT_HELPER_GPF] = { .terminal_exit = true },
    [FT_HELPER_INT] = { .terminal_exit = true },
    [FT_HELPER_INT3] = { .terminal_exit = true },
    [FT_HELPER_INTO] = { .eflag_use = OF_USEDEF_BIT },
    [FT_HELPER_IRET] = { .terminal_exit = true },
    [FT_HELPER_IRETD] = { .terminal_exit = true },
    [FT_HELPER_IRETQ] = { .terminal_exit = true },
    [FT_HELPER_LJMP] = { .terminal_exit = true },
    [FT_HELPER_LCALL] = { .terminal_exit = true },
    [FT_HELPER_RETFQ] = { .terminal_exit = true },
    [FT_LDS] = { .terminal_exit = true },
    [FT_LES] = { .terminal_exit = true },
    [FT_LSS] = { .terminal_exit = true },
    [FT_HELPER_UD0] = { .terminal_exit = true },
    [FT_HELPER_UD1] = { .terminal_exit = true },
    [FT_HELPER_UD2] = { .terminal_exit = true },
    [FT_HELPER_FXSAVE] = { .uses_x87_top = true },
    [FT_HELPER_FXRSTOR] = { .uses_x87_top = true },
    [FT_HELPER_XSAVE] = { .uses_x87_top = true },
    [FT_HELPER_XRSTOR] = {
        .terminal_exit = true,
        .uses_x87_top = true,
    },
    [FT_HELPER_XSAVEOPT] = { .uses_x87_top = true },
    [FT_HELPER_FNSAVE] = { .uses_x87_top = true },
    [FT_HELPER_FRSTOR] = { .uses_x87_top = true },
    [FT_HELPER_FLDENV] = { .uses_x87_top = true },
    [FT_HELPER_FNSTENV] = { .uses_x87_top = true },
    [FT_X87_FCMOVCC] = {
        .eflag_use = CF_USEDEF_BIT | PF_USEDEF_BIT | AF_USEDEF_BIT |
                     ZF_USEDEF_BIT | SF_USEDEF_BIT | OF_USEDEF_BIT,
        .uses_x87_top = true,
    },
    [FT_LAHF] = {
        .eflag_use = CF_USEDEF_BIT | PF_USEDEF_BIT | AF_USEDEF_BIT |
                     ZF_USEDEF_BIT | SF_USEDEF_BIT | OF_USEDEF_BIT,
    },
    [FT_PUSHFQ] = {
        .eflag_use = CF_USEDEF_BIT | PF_USEDEF_BIT | AF_USEDEF_BIT |
                     ZF_USEDEF_BIT | SF_USEDEF_BIT | OF_USEDEF_BIT,
    },
    [FT_FNINIT] = { .uses_x87_top = true },
    [FT_X87_FLD1] = { .uses_x87_top = true },
    [FT_X87_FLD_CONST] = { .uses_x87_top = true },
    [FT_X87_FLD_M32] = { .uses_x87_top = true },
    [FT_X87_FLD_M64] = { .uses_x87_top = true },
    [FT_X87_FLD_REG] = { .uses_x87_top = true },
    [FT_X87_UNARY] = { .uses_x87_top = true },
    [FT_X87_TOP_ADJ] = { .uses_x87_top = true },
    [FT_X87_FTST] = { .uses_x87_top = true },
    [FT_X87_FXCH] = { .uses_x87_top = true },
    [FT_X87_FCOM_REG] = { .uses_x87_top = true },
    [FT_X87_FCOMP_REG] = { .uses_x87_top = true },
    [FT_X87_FUCOMPP] = { .uses_x87_top = true },
    [FT_X87_FCOMI_REG] = { .uses_x87_top = true },
    [FT_X87_FCOMIP_REG] = { .uses_x87_top = true },
    [FT_X87_F2XM1] = { .uses_x87_top = true },
    [FT_X87_FRNDINT] = { .uses_x87_top = true },
    [FT_X87_FSCALE] = { .uses_x87_top = true },
    [FT_X87_FSIN] = { .uses_x87_top = true },
    [FT_X87_FCOS] = { .uses_x87_top = true },
    [FT_X87_FSINCOS] = { .uses_x87_top = true },
    [FT_X87_FPTAN] = { .uses_x87_top = true },
    [FT_X87_FPATAN] = { .uses_x87_top = true },
    [FT_X87_FPREM] = { .uses_x87_top = true },
    [FT_X87_FPREM1] = { .uses_x87_top = true },
    [FT_X87_FYL2X] = { .uses_x87_top = true },
    [FT_X87_FYL2XP1] = { .uses_x87_top = true },
    [FT_X87_FBLD] = { .uses_x87_top = true },
    [FT_X87_FBSTP] = { .uses_x87_top = true },
    [FT_X87_FXAM] = { .uses_x87_top = true },
    [FT_X87_FXTRACT] = { .uses_x87_top = true },
    [FT_X87_FSQRT] = { .uses_x87_top = true },
    [FT_X87_FIST_M16] = { .uses_x87_top = true },
    [FT_X87_FIST_M32] = { .uses_x87_top = true },
    [FT_X87_FI_BIN_M16] = { .uses_x87_top = true },
    [FT_X87_FI_BIN_M32] = { .uses_x87_top = true },
    [FT_X87_FILD_M16] = { .uses_x87_top = true },
    [FT_X87_FILD_M32] = { .uses_x87_top = true },
    [FT_X87_FILD_M64] = { .uses_x87_top = true },
    [FT_X87_FISTP_M16] = { .uses_x87_top = true },
    [FT_X87_FISTP_M32] = { .uses_x87_top = true },
    [FT_X87_FISTP_M64] = { .uses_x87_top = true },
    [FT_X87_FISTTP_M16] = { .uses_x87_top = true },
    [FT_X87_FISTTP_M32] = { .uses_x87_top = true },
    [FT_X87_FISTTP_M64] = { .uses_x87_top = true },
    [FT_X87_FST_M32] = { .uses_x87_top = true },
    [FT_X87_FST_M64] = { .uses_x87_top = true },
    [FT_X87_FLD_M80] = { .uses_x87_top = true },
    [FT_X87_FSTP_M32] = { .uses_x87_top = true },
    [FT_X87_FSTP_M64] = { .uses_x87_top = true },
    [FT_X87_FSTP_M80] = { .uses_x87_top = true },
    [FT_X87_FSTP_REG] = { .uses_x87_top = true },
    [FT_X87_FST_REG] = { .uses_x87_top = true },
    [FT_X87_BIN_REG] = { .uses_x87_top = true },
    [FT_X87_BIN_M32] = { .uses_x87_top = true },
    [FT_X87_BIN_M64] = { .uses_x87_top = true },
    [FT_X87_FCOM_M32] = { .uses_x87_top = true },
    [FT_X87_FCOM_M64] = { .uses_x87_top = true },
    [FT_X87_FADDP] = { .uses_x87_top = true },
    [FT_X87_FSUBP] = { .uses_x87_top = true },
    [FT_X87_FSUBRP] = { .uses_x87_top = true },
    [FT_X87_FMULP] = { .uses_x87_top = true },
    [FT_X87_FDIVP] = { .uses_x87_top = true },
    [FT_X87_FDIVRP] = { .uses_x87_top = true },
    [FT_X87_FFREE] = { .uses_x87_top = true },
    [FT_X87_FCOMPP] = { .uses_x87_top = true },
    [FT_X87_FSTSW_AX] = { .uses_x87_top = true },
    [FT_X87_FNSTSW_M16] = { .uses_x87_top = true },
};

/* Apply legacy LATU no-op policy after shared decoding, before metadata. */
static void ft_apply_latu_legacy_policy(FastDecodedFT *decoded)
{
#ifdef QUICKTRANS_LATU
    if (!decoded->fields_valid || !decoded->tmpl) {
        return;
    }
    switch (decoded->fields.id) {
    case dt_X86_INS_INSD:
#ifdef CONFIG_LATX_TU
        decoded->tmpl = NULL;
        decoded->fields_valid = false;
        return;
#endif
        /* Without TU the legacy handler succeeds without side effects. */
        /* fall through */
    case dt_X86_INS_INT1:
    case dt_X86_INS_LCALL:
    case dt_X86_INS_ARPL:
    case dt_X86_INS_CLI:
    case dt_X86_INS_STI:
    case dt_X86_INS_SIDT:
    case dt_X86_INS_SLDT:
    case dt_X86_INS_INSB:
    case dt_X86_INS_OUTSB:
    case dt_X86_INS_OUTSD:
        decoded->fields.kind = FT_NOP_MULTI;
        decoded->tmpl = &fast_templates[FT_NOP_MULTI];
        decoded->is_tb_ending = false;
        break;
    default:
        break;
    }
#else
    (void)decoded;
#endif
}

static bool latx_fast_translate_sample_for_bench_impl(CPUArchState *env,
                                          TranslationBlock *tb,
                                          const uint8_t *bytes,
                                          int len,
                                          target_ulong pc,
                                          int *code_size,
                                          LatxFastTranslatorBenchStats *stats,
                                          bool detail_stats
#ifndef QUICKTRANS_LATU
                                          , FtCodeSpace *space
#endif
                                          )
{
    uint32_t *code = (uint32_t *)tb->tc.ptr;
    const uint8_t *inst_cache = bytes;
    FastDecodedFT decoded;
    const FastTemplateDesc *tmpl;
    const FastTemplateRuntimeInfo *meta;
    FastTemplateFields *fields;
    int emitted = 0;
    bool x87_top_active = false;
    int insn_emitted;
    bool terminal_exit;
    int64_t start = stats ? ft_bench_now_ns() : 0;
    int64_t stage_start;

    detail_stats = detail_stats && stats;
    (void)env;
    if (len <= 0 || len > 15) {
        return false;
    }

    stage_start = detail_stats ? ft_bench_now_ns() : 0;
    if (!fast_decoder_get_ft(inst_cache, len, pc, &decoded, CODEIS64)) {
        return false;
    }
    if (detail_stats) {
        stats->decode_ns += ft_bench_now_ns() - stage_start;
    }

    ft_apply_latu_legacy_policy(&decoded);
    tmpl = decoded.tmpl;
    meta = ft_template_runtime_info(tmpl ? tmpl->kind : FT_UNSUPPORTED);
    if (!tmpl || (ft_template_is_helper(tmpl->kind) &&
                  !ft_template_primary_helper_allowed(tmpl->kind))) {
        return false;
    }

    stage_start = detail_stats ? ft_bench_now_ns() : 0;
    if (!decoded.fields_valid) {
        return false;
    }
    fields = &decoded.fields;
    fields->skip_flags = false;
    fields->omit_zext32 = false;
    fields->scalar_direct_dst = false;
    fields->atomic_no_barrier = false;
    if (detail_stats) {
        stats->field_ns += ft_bench_now_ns() - stage_start;
    }

#ifdef CONFIG_LATX_DEBUG
    stage_start = detail_stats ? ft_bench_now_ns() : 0;
    if (!fast_template_emit_constraints_ok(fields)) {
        return false;
    }
    if (detail_stats) {
        stats->constraint_ns += ft_bench_now_ns() - stage_start;
    }
#endif

    stage_start = detail_stats ? ft_bench_now_ns() : 0;
    tb->icount = 1;
    tb->size = fields->size;
    ft_primary_update_last_info(tb, fields);
    if (detail_stats) {
        stats->update_ns += ft_bench_now_ns() - stage_start;
    }

    stage_start = detail_stats ? ft_bench_now_ns() : 0;
#ifndef QUICKTRANS_LATU
    ft_code_space_activate(space);
#endif
    if (ft_template_uses_mmx(fields)) {
        uint32_t *out = code + emitted;

        ft_emit_enter_mmx(&out);
        emitted = out - code;
    }
    if (!option_soft_fpu && !x87_top_active && meta->uses_x87_top) {
        uint32_t *out = code + emitted;
        int top_emitted = ft_emit_x87_top_load(&out);

        if (!top_emitted) {
            return false;
        }
        emitted += top_emitted;
        x87_top_active = true;
    }
    if (detail_stats) {
        stats->x87_ns += ft_bench_now_ns() - stage_start;
    }

    stage_start = detail_stats ? ft_bench_now_ns() : 0;
    {
        uint32_t *out = code + emitted;

        if (ft_primary_debug_live_enabled()) {
            ft_primary_debug_emit_live_regs(&out, fields->address);
        }
        emitted = out - code;
    }
    if (detail_stats) {
        stats->debug_ns += ft_bench_now_ns() - stage_start;
    }

    stage_start = detail_stats ? ft_bench_now_ns() : 0;
    insn_emitted = emit_template_fields(fields, tb, fields->address,
                                        code + emitted);
    if (!insn_emitted && !ft_emit_zero_code_allowed(fields)) {
        return false;
    }
    emitted += insn_emitted;
    ft_primary_debug_dump_code(fields->address, fields, code, emitted);
    if (detail_stats) {
        stats->emit_ns += ft_bench_now_ns() - stage_start;
    }

    stage_start = detail_stats ? ft_bench_now_ns() : 0;
    terminal_exit = meta->terminal_exit;
    if (!option_soft_fpu && x87_top_active && terminal_exit) {
        uint32_t *out = code + emitted;
        int top_emitted = ft_emit_x87_top_save(&out);

        if (!top_emitted) {
            return false;
        }
        emitted += top_emitted;
        x87_top_active = false;
    }
    ft_set_insn_start_data(0, fields->address);
    ft_set_insn_end_off(0, emitted << 2);
    if (detail_stats) {
        stats->update_ns += ft_bench_now_ns() - stage_start;
    }

    stage_start = detail_stats ? ft_bench_now_ns() : 0;
    if (!terminal_exit) {
        uint32_t *out = code + emitted;
        int exit_emitted;

        if (!option_soft_fpu && x87_top_active) {
            int top_emitted = ft_emit_x87_top_save(&out);

            if (!top_emitted) {
                return false;
            }
            emitted += top_emitted;
        }

        exit_emitted =
            ft_emit_direct_link_exit(tb, &out, 0, tb->pc + tb->size, la_t1);
        if (!exit_emitted) {
            return false;
        }
        emitted += exit_emitted;
        ft_set_insn_end_off(0, emitted << 2);
    }
    *code_size = emitted * 4;
    if (stats) {
        if (detail_stats) {
            stats->exit_ns += ft_bench_now_ns() - stage_start;
        }
        stats->total_ns += ft_bench_now_ns() - start;
        stats->insns++;
        stats->code_nr += emitted;
    }
    return true;
}

static const FastTemplateRuntimeInfo *ft_template_runtime_info(
    FastTemplateKind kind)
{
    static const FastTemplateRuntimeInfo empty;

    if ((unsigned)kind >= FT_KIND_COUNT) {
        return &empty;
    }
    return &ft_template_runtime_table[kind];
}

static uint8_t ft_jcc_eflag_use(int id)
{
    switch (id) {
    case dt_X86_INS_JO:
    case dt_X86_INS_JNO:
    case dt_X86_INS_SETO:
    case dt_X86_INS_SETNO:
    case dt_X86_INS_CMOVO:
    case dt_X86_INS_CMOVNO:
        return OF_USEDEF_BIT;
    case dt_X86_INS_JB:
    case dt_X86_INS_JAE:
    case dt_X86_INS_SETB:
    case dt_X86_INS_SETAE:
    case dt_X86_INS_CMOVB:
    case dt_X86_INS_CMOVAE:
        return CF_USEDEF_BIT;
    case dt_X86_INS_JE:
    case dt_X86_INS_JNE:
    case dt_X86_INS_SETE:
    case dt_X86_INS_SETNE:
    case dt_X86_INS_CMOVE:
    case dt_X86_INS_CMOVNE:
        return ZF_USEDEF_BIT;
    case dt_X86_INS_JBE:
    case dt_X86_INS_JA:
    case dt_X86_INS_SETBE:
    case dt_X86_INS_SETA:
    case dt_X86_INS_CMOVBE:
    case dt_X86_INS_CMOVA:
        return CF_USEDEF_BIT | ZF_USEDEF_BIT;
    case dt_X86_INS_JS:
    case dt_X86_INS_JNS:
    case dt_X86_INS_SETS:
    case dt_X86_INS_SETNS:
    case dt_X86_INS_CMOVS:
    case dt_X86_INS_CMOVNS:
        return SF_USEDEF_BIT;
    case dt_X86_INS_JP:
    case dt_X86_INS_JNP:
    case dt_X86_INS_SETP:
    case dt_X86_INS_SETNP:
    case dt_X86_INS_CMOVP:
    case dt_X86_INS_CMOVNP:
        return PF_USEDEF_BIT;
    case dt_X86_INS_JL:
    case dt_X86_INS_JGE:
    case dt_X86_INS_SETL:
    case dt_X86_INS_SETGE:
    case dt_X86_INS_CMOVL:
    case dt_X86_INS_CMOVGE:
        return OF_USEDEF_BIT | SF_USEDEF_BIT;
    case dt_X86_INS_JLE:
    case dt_X86_INS_JG:
    case dt_X86_INS_SETLE:
    case dt_X86_INS_SETG:
    case dt_X86_INS_CMOVLE:
    case dt_X86_INS_CMOVG:
        return OF_USEDEF_BIT | SF_USEDEF_BIT | ZF_USEDEF_BIT;
    default:
        return 0;
    }
}

static bool ft_rotate_imm_has_zero_effective_count(
    const FastTemplateFields *fields)
{
    int width;
    int count;

    if (fields->kind != FT_SHIFT_RM_IMM8 &&
        fields->kind != FT_ROL_RM64_IMM8 &&
        fields->kind != FT_ROR_RM64_IMM8) {
        return false;
    }

    width = ft_shift_width(fields);
    count = fields->imm & (width == 64 ? 63 : 31);
    if (fields->id == dt_X86_INS_RCL || fields->id == dt_X86_INS_RCR) {
        if (width < 32) {
            count %= width + 1;
        }
    }
    return count == 0;
}

static FastTemplateEflagMasks ft_template_eflag_masks(
    const FastTemplateFields *fields,
    const FastTemplateRuntimeInfo *meta)
{
    FastTemplateEflagMasks masks = {
        .use = meta ? meta->eflag_use : 0,
        .def = 0,
    };

    if (meta && meta->no_eflags) {
        return masks;
    }

    switch (fields->alu_op) {
    case FT_ALU_ADC:
    case FT_ALU_SBB:
        masks.use |= CF_USEDEF_BIT;
        masks.def |= FT_EFLAGS_ALL;
        return masks;
    case FT_ALU_ADD:
    case FT_ALU_AND:
    case FT_ALU_CMP:
    case FT_ALU_OR:
    case FT_ALU_SUB:
    case FT_ALU_TEST:
    case FT_ALU_XOR:
        masks.def |= FT_EFLAGS_ALL;
        return masks;
    default:
        break;
    }

    switch (fields->kind) {
    case FT_GRP1_RM64_IMM8:
    case FT_GRP1_RM32_IMM8:
    case FT_GRP1_RM16_IMM8:
    case FT_GRP1_RM8_IMM8:
    case FT_GRP1_RM32_IMM32:
    case FT_GRP1_RM64_IMM32:
    {
        int ext = fields->modrm_reg;

        if (ext == 2 || ext == 3) {
            masks.use |= CF_USEDEF_BIT;
        }
        if (ext >= 0 && ext <= 7) {
            masks.def |= FT_EFLAGS_ALL;
        }
        return masks;
    }
    default:
        break;
    }

    if ((fields->kind == FT_JCC_REL || fields->kind == FT_SETCC_RM8) &&
        fields->direct_float_result) {
        masks.use = 0;
        return masks;
    }
    if ((fields->kind == FT_JCC_REL || fields->kind == FT_SETCC_RM8 ||
         fields->kind == FT_CMOV_R64_RM64 ||
         fields->kind == FT_CMOV_R32_RM32 ||
         fields->kind == FT_CMOV_R16_RM16) &&
        fields->direct_cmp_lhs_gpr >= 0) {
        masks.use = 0;
        return masks;
    }

    switch (fields->id) {
    case dt_X86_INS_ARPL:
        masks.def |= ZF_USEDEF_BIT;
        break;
    case dt_X86_INS_AAA:
    case dt_X86_INS_AAS:
        masks.use |= AF_USEDEF_BIT;
        masks.def |= CF_USEDEF_BIT | AF_USEDEF_BIT;
        break;
    case dt_X86_INS_DAA:
    case dt_X86_INS_DAS:
        masks.use |= CF_USEDEF_BIT | AF_USEDEF_BIT;
        masks.def |= CF_USEDEF_BIT | PF_USEDEF_BIT | AF_USEDEF_BIT |
                     ZF_USEDEF_BIT | SF_USEDEF_BIT;
        break;
    case dt_X86_INS_AAD:
    case dt_X86_INS_AAM:
        masks.def |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_SALC:
        masks.use |= CF_USEDEF_BIT;
        break;
    case dt_X86_INS_FCOMI:
    case dt_X86_INS_FCOMIP:
    case dt_X86_INS_FUCOMI:
    case dt_X86_INS_FUCOMIP:
        masks.def |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_LAR:
    case dt_X86_INS_LSL:
    case dt_X86_INS_VERR:
    case dt_X86_INS_VERW:
        masks.def |= ZF_USEDEF_BIT;
        break;
    case dt_X86_INS_ADCX:
        masks.use |= CF_USEDEF_BIT;
        masks.def |= CF_USEDEF_BIT;
        break;
    case dt_X86_INS_ADOX:
        masks.use |= OF_USEDEF_BIT;
        masks.def |= OF_USEDEF_BIT;
        break;
    case dt_X86_INS_ADC:
    case dt_X86_INS_SBB:
        masks.use |= CF_USEDEF_BIT;
        masks.def |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_ADD:
    case dt_X86_INS_AND:
    case dt_X86_INS_CMP:
    case dt_X86_INS_CMPSB:
    case dt_X86_INS_CMPSD:
    case dt_X86_INS_CMPSQ:
    case dt_X86_INS_CMPSW:
    case dt_X86_INS_NEG:
    case dt_X86_INS_OR:
    case dt_X86_INS_SCASB:
    case dt_X86_INS_SCASD:
    case dt_X86_INS_SCASQ:
    case dt_X86_INS_SCASW:
    case dt_X86_INS_SUB:
    case dt_X86_INS_TEST:
    case dt_X86_INS_XADD:
    case dt_X86_INS_XOR:
        masks.def |= FT_EFLAGS_ALL;
        if ((fields->prefix0 == dt_X86_PREFIX_REP ||
             fields->prefix0 == dt_X86_PREFIX_REPNE) &&
            (fields->id == dt_X86_INS_CMPSB ||
             fields->id == dt_X86_INS_CMPSW ||
             fields->id == dt_X86_INS_CMPSD ||
             fields->id == dt_X86_INS_CMPSQ ||
             fields->id == dt_X86_INS_SCASB ||
             fields->id == dt_X86_INS_SCASW ||
             fields->id == dt_X86_INS_SCASD ||
             fields->id == dt_X86_INS_SCASQ)) {
            masks.use |= FT_EFLAGS_ALL;
        }
        break;
    case dt_X86_INS_INC:
    case dt_X86_INS_DEC:
        masks.def |= FT_EFLAGS_ALL & ~CF_USEDEF_BIT;
        break;
    case dt_X86_INS_BSF:
    case dt_X86_INS_BSR:
        masks.def |= ZF_USEDEF_BIT;
        break;
    case dt_X86_INS_BT:
    case dt_X86_INS_BTC:
    case dt_X86_INS_BTR:
    case dt_X86_INS_BTS:
    case dt_X86_INS_CLC:
    case dt_X86_INS_STC:
        masks.def |= CF_USEDEF_BIT;
        break;
    case dt_X86_INS_CMC:
        masks.use |= CF_USEDEF_BIT;
        masks.def |= CF_USEDEF_BIT;
        break;
    case dt_X86_INS_ROL:
    case dt_X86_INS_ROR:
    case dt_X86_INS_RCL:
    case dt_X86_INS_RCR:
        if (ft_rotate_imm_has_zero_effective_count(fields)) {
            break;
        }
        if (fields->id == dt_X86_INS_RCL || fields->id == dt_X86_INS_RCR) {
            masks.use |= CF_USEDEF_BIT;
        }
        masks.def |= CF_USEDEF_BIT | OF_USEDEF_BIT;
        break;
    case dt_X86_INS_SAL:
    case dt_X86_INS_SAR:
    case dt_X86_INS_SHL:
    case dt_X86_INS_SHR:
        if (fields->kind == FT_SHIFT_RM_IMM8 &&
            (fields->imm & (ft_rex_w(fields) ? 63 : 31)) == 0) {
            break;
        }
        masks.def |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_SHLD:
    case dt_X86_INS_SHRD:
        if ((fields->kind == FT_SHLD_RM_R_IMM8 ||
             fields->kind == FT_SHRD_RM_R_IMM8) &&
            (fields->imm & (ft_rex_w(fields) ? 63 : 31)) == 0) {
            break;
        }
        masks.def |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_LAHF:
    case dt_X86_INS_PUSHF:
    case dt_X86_INS_PUSHFD:
    case dt_X86_INS_PUSHFQ:
        masks.use |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_POPF:
    case dt_X86_INS_POPFD:
    case dt_X86_INS_POPFQ:
        masks.def |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_SAHF:
        masks.def |= CF_USEDEF_BIT | PF_USEDEF_BIT | AF_USEDEF_BIT |
                     ZF_USEDEF_BIT | SF_USEDEF_BIT;
        break;
    case dt_X86_INS_IMUL:
    case dt_X86_INS_MUL:
        masks.def |= CF_USEDEF_BIT | OF_USEDEF_BIT;
        break;
    case dt_X86_INS_CMPXCHG:
    case dt_X86_INS_DIV:
    case dt_X86_INS_IDIV:
        masks.def |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_CMPXCHG8B:
    case dt_X86_INS_CMPXCHG16B:
        masks.def |= ZF_USEDEF_BIT;
        break;
    case dt_X86_INS_LZCNT:
    case dt_X86_INS_TZCNT:
        masks.def |= CF_USEDEF_BIT | ZF_USEDEF_BIT;
        break;
    case dt_X86_INS_POPCNT:
        masks.def |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_RDRAND:
        masks.def |= FT_EFLAGS_ALL;
        break;
    case dt_X86_INS_BZHI:
        masks.def |= CF_USEDEF_BIT | ZF_USEDEF_BIT |
                     SF_USEDEF_BIT | OF_USEDEF_BIT;
        break;
    case dt_X86_INS_ANDN:
    case dt_X86_INS_BEXTR:
    case dt_X86_INS_BLSI:
    case dt_X86_INS_BLSR:
    case dt_X86_INS_BLSMSK:
        masks.def |= CF_USEDEF_BIT | ZF_USEDEF_BIT |
                     SF_USEDEF_BIT | OF_USEDEF_BIT;
        break;
    default:
        masks.use |= ft_jcc_eflag_use(fields->id);
        break;
    }

    if (fields->kind == FT_SHIFT_RM_CL ||
        fields->kind == FT_SHLD_RM_R_CL ||
        fields->kind == FT_SHRD_RM_R_CL) {
        masks.use |= masks.def;
    }

    return masks;
}

/* Match the legacy option_instptn bit assignment (INSTPTN_OPC_* >> 4). */
#define FT_INSTPTN_CMP_JCC          (1ULL << 0)
#define FT_INSTPTN_TEST_JCC         (1ULL << 1)
#define FT_INSTPTN_BT_JCC           (1ULL << 2)
#define FT_INSTPTN_CQO_IDIV         (1ULL << 3)
#define FT_INSTPTN_CMP_SBB          (1ULL << 4)
#define FT_INSTPTN_COMISD_JCC       (1ULL << 5)
#define FT_INSTPTN_COMISS_JCC       (1ULL << 6)
#define FT_INSTPTN_UCOMISD_JCC      (1ULL << 7)
#define FT_INSTPTN_UCOMISS_JCC      (1ULL << 8)
#define FT_INSTPTN_XOR_DIV          (1ULL << 9)
#define FT_INSTPTN_CDQ_IDIV         (1ULL << 10)
#define FT_INSTPTN_CMP_XX_JCC       (1ULL << 11)
#define FT_INSTPTN_TEST_XX_JCC      (1ULL << 12)
#define FT_INSTPTN_BT_XX_JCC        (1ULL << 13)
#define FT_INSTPTN_COMISD_XX_JCC    (1ULL << 14)
#define FT_INSTPTN_COMISS_XX_JCC    (1ULL << 15)
#define FT_INSTPTN_UCOMISD_XX_JCC   (1ULL << 16)
#define FT_INSTPTN_UCOMISS_XX_JCC   (1ULL << 17)
#define FT_INSTPTN_CMP_XXCC_CON     (1ULL << 18)
#define FT_INSTPTN_TEST_XXCC_CON    (1ULL << 19)
#define FT_INSTPTN_UCOMISD_SETA     (1ULL << 20)
#define FT_INSTPTN_ADD_JCC          (1ULL << 21)
#define FT_INSTPTN_SUB_JCC          (1ULL << 22)
#define FT_INSTPTN_AND_JCC          (1ULL << 23)
#define FT_INSTPTN_OR_JCC           (1ULL << 24)
#define FT_INSTPTN_OR_XX_JCC        (1ULL << 25)
#define FT_INSTPTN_XOR_JCC          (1ULL << 26)
#define FT_INSTPTN_XOR_XX_JCC       (1ULL << 27)
#define FT_INSTPTN_SAR_JCC          (1ULL << 28)
#define FT_INSTPTN_AND_XX_JCC       (1ULL << 29)
#define FT_INSTPTN_SHR_JCC          (1ULL << 30)
#define FT_INSTPTN_SUB_XX_JCC       (1ULL << 31)
#define FT_INSTPTN_SHR_XX_JCC       (1ULL << 32)
#define FT_INSTPTN_DEC_JCC          (1ULL << 33)

static bool ft_instptn_enabled(uint64_t bit)
{
#ifdef QUICKTRANS_LATU
    /* LATU and LATS share bits 0..20, but not the later assignments.
     * LATU-only MOVAPS/NEG slots must not select unrelated QT patterns.
     * QT extensions with no LATU bit remain enabled by the default full
     * mask only; a partial mask selects only its named legacy patterns. */
    uint32_t mask = (uint32_t)option_instptn;
    if (bit <= FT_INSTPTN_UCOMISD_SETA) {
        return (mask & bit) != 0;
    }
    switch (bit) {
    case FT_INSTPTN_SUB_JCC:
        return (mask & (1u << 21)) != 0;
    case FT_INSTPTN_SHR_JCC:
        return (mask & (1u << 24)) != 0;
    case FT_INSTPTN_AND_JCC:
        return (mask & (1u << 25)) != 0;
    default:
        return mask == 0x3ffffffu;
    }
#else
    return (option_instptn & bit) != 0;
#endif
}

static void ft_analyze_direct_jcc_gap(
    FastTemplateFields *fields, const FastTemplateRuntimeInfo **meta,
    int count);
static void ft_analyze_direct_xxcc(
    FastTemplateFields *fields, const FastTemplateRuntimeInfo **meta,
    int count);
static void ft_analyze_div_patterns(FastTemplateFields *fields, int count);
static void ft_analyze_float_jcc(FastTemplateFields *fields, int count);
static void ft_analyze_float_xx_jcc(FastTemplateFields *fields,
                                    const FastTemplateRuntimeInfo **meta,
                                    int count);
static void ft_analyze_ucomisd_seta(FastTemplateFields *fields, int count);
static void ft_analyze_cmp_sbb(FastTemplateFields *fields, int count);

enum {
    FT_ANALYZE_XXCC = 1,
    FT_ANALYZE_DIV = 2,
    FT_ANALYZE_FLOAT = 4,
    FT_ANALYZE_SBB = 8,
    FT_ANALYZE_RSP = 16,
    FT_ANALYZE_XMM_HIGH = 32,
    FT_ANALYZE_ALL = 63,
};

#define FT_WITH_RSP_MERGE 1
#define FT_SPECIALIZED_NAME ft_analysis_candidates
#include "analysis-candidates-body.inc.c"
#undef FT_SPECIALIZED_NAME
#undef FT_WITH_RSP_MERGE

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && defined(LATX_QUICKTRANS_RSP_SEARCH_ABI)
#define FT_WITH_RSP_MERGE 0
#define FT_SPECIALIZED_NAME ft_analysis_candidates_no_rsp
#include "analysis-candidates-body.inc.c"
#undef FT_SPECIALIZED_NAME
#undef FT_WITH_RSP_MERGE
#endif

#include "analyze-gpr-high.inc.c"

static uint8_t ft_analyze_tb_flags(FastTemplateFields *fields,
                                   const FastTemplateRuntimeInfo **meta,
                                   int count, unsigned int candidates,
                                   bool analyze_gpr_high,
                                   bool analyze_xmm_high)
{
    uint8_t pending = FT_EFLAGS_ALL;
    bool trace_opt = ft_primary_trace_opt_enabled();
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    uint32_t need_hi = FT_GPR_HIGH_ALL;
#else
    (void)analyze_gpr_high;
#endif
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    !defined(CONFIG_LATX_AVX_OPT)
    uint64_t need_xmm_lanes = FT_XMM_LANES_ALL;
    analyze_xmm_high &= (candidates & FT_ANALYZE_XMM_HIGH) != 0;
#else
    (void)analyze_xmm_high;
#endif

#ifdef QUICKTRANS_LATU
    /* One TB-level gate avoids scans when all patterns are disabled. */
    if (option_instptn) {
#endif
    if (count > 1 && fields[count - 1].kind == FT_JCC_REL) {
        ft_analyze_direct_jcc_pair(&fields[count - 2], &fields[count - 1],
                                   false);
        if (fields[count - 1].direct_cmp_lhs_gpr < 0) {
            ft_analyze_direct_jcc_gap(fields, meta, count);
        }
    }
    if (candidates & FT_ANALYZE_XXCC) {
        ft_analyze_direct_xxcc(fields, meta, count);
    }
    if (candidates & FT_ANALYZE_DIV) {
        ft_analyze_div_patterns(fields, count);
    }
    if (candidates & FT_ANALYZE_FLOAT) {
        ft_analyze_float_jcc(fields, count);
        ft_analyze_float_xx_jcc(fields, meta, count);
        if (candidates & FT_ANALYZE_XXCC) {
            ft_analyze_ucomisd_seta(fields, count);
        }
    }
    if (candidates & FT_ANALYZE_SBB) {
        ft_analyze_cmp_sbb(fields, count);
    }
#ifdef QUICKTRANS_LATU
    }
#endif
    for (int i = count - 1; i >= 0; --i) {
        FastTemplateEflagMasks masks;
        uint8_t live_def;

        masks = ft_template_eflag_masks(&fields[i], meta[i]);
        live_def = masks.def & pending;
        fields[i].skip_flags = live_def == 0 && (masks.use == 0
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
            /* Keep the input carry live even when all outputs are dead. */
            || (masks.use == CF_USEDEF_BIT &&
                (fields[i].alu_op == FT_ALU_ADC ||
                 fields[i].alu_op == FT_ALU_SBB) &&
                fields[i].modrm_mod == 3 &&
                fields[i].prefix0 != dt_X86_PREFIX_LOCK &&
                (fields[i].alu_width == 32 || fields[i].alu_width == 64) &&
                (fields[i].alu_form == FT_ALU_FORM_RM_R ||
                 fields[i].alu_form == FT_ALU_FORM_R_RM))
#endif
        );
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        /* Pattern marking above must finish before deriving GPR demands. */
        ft_analyze_gpr_high_step(&fields[i], meta[i], &need_hi,
                                 analyze_gpr_high);
#else
        fields[i].omit_zext32 = false;
#endif
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    !defined(CONFIG_LATX_AVX_OPT)
        /* Share O7's ordinary64/TF/debug/POPF policy, not its GPR state. */
        if (analyze_xmm_high) {
            ft_analyze_xmm_high_step(&fields[i], meta[i], &need_xmm_lanes,
                                     true);
        } else {
            fields[i].scalar_direct_dst = false;
        }
#else
        fields[i].scalar_direct_dst = false;
#endif
        if (trace_opt) {
            fprintf(stderr,
                    "[FT-OPT] pc=0x%lx id=%d kind=%d alu=%u form=%u "
                    "width=%u mod=%u rm=%u reg=%u imm=%d direct_lhs=%d "
                    "direct_rhs=%d direct_kind=%u bit_reg=%d bit_imm=%d "
                    "instptn=0x%llx use=0x%x def=0x%x pending_before=0x%x "
                    "float_result=%d float_xx=%d "
                    "live_def=0x%x skip=%d omit_zext32=%d scalar_direct_dst=%d\n",
                    (unsigned long)fields[i].address, fields[i].id,
                    fields[i].kind, fields[i].alu_op, fields[i].alu_form,
                    fields[i].alu_width, fields[i].modrm_mod,
                    fields[i].modrm_rm_index, fields[i].modrm_reg_index,
                    fields[i].imm, fields[i].direct_cmp_lhs_gpr,
                    fields[i].direct_cmp_rhs_gpr,
                    fields[i].direct_branch_kind,
                    fields[i].direct_bit_index_gpr,
                    fields[i].direct_bit_index_imm,
#ifdef QUICKTRANS_LATU
                    (unsigned long long)(uint32_t)option_instptn,
#else
                    (unsigned long long)option_instptn,
#endif
                    masks.use, masks.def, pending,
                    fields[i].direct_float_result,
                    fields[i].direct_float_xx, live_def,
                    fields[i].skip_flags, fields[i].omit_zext32,
                    fields[i].scalar_direct_dst);
        }
        pending &= ~masks.def;
        pending |= masks.use;
    }
    return pending;
}

static bool ft_direct_jcc_kind(int id, FastDirectBranchKind *kind)
{
    switch (id) {
    case dt_X86_INS_JE:  *kind = FT_DIRECT_BRANCH_EQ; return true;
    case dt_X86_INS_JNE: *kind = FT_DIRECT_BRANCH_NE; return true;
    case dt_X86_INS_JL:  *kind = FT_DIRECT_BRANCH_LT; return true;
    case dt_X86_INS_JGE: *kind = FT_DIRECT_BRANCH_GE; return true;
    case dt_X86_INS_JB:  *kind = FT_DIRECT_BRANCH_LTU; return true;
    case dt_X86_INS_JAE: *kind = FT_DIRECT_BRANCH_GEU; return true;
    case dt_X86_INS_JLE: *kind = FT_DIRECT_BRANCH_LE; return true;
    case dt_X86_INS_JG:  *kind = FT_DIRECT_BRANCH_GT; return true;
    case dt_X86_INS_JBE: *kind = FT_DIRECT_BRANCH_LEU; return true;
    case dt_X86_INS_JA:  *kind = FT_DIRECT_BRANCH_GTU; return true;
    default: return false;
    }
}

static bool ft_direct_alu_reg_operands(const FastTemplateFields *alu,
                                       int *lhs, int *rhs)
{
    if (alu->alu_form == FT_ALU_FORM_RM_R && alu->modrm_mod == 3 &&
        alu->modrm_rm_index < GPR_NUM && alu->modrm_reg_index < GPR_NUM &&
        !(alu->alu_width == 8 &&
          (ft_modrm_rm_is_high8(alu) || ft_modrm_reg_is_high8(alu)))) {
        *lhs = alu->modrm_rm_index;
        *rhs = alu->modrm_reg_index;
        return true;
    }
    return false;
}

static void ft_analyze_cmp_sbb(FastTemplateFields *fields, int count)
{
    for (int i = 0; i + 1 < count; ++i) {
        FastTemplateFields *cmp = &fields[i];
        FastTemplateFields *sbb = &fields[i + 1];
        int lhs;
        int rhs;

        if (cmp->alu_op != FT_ALU_CMP || sbb->alu_op != FT_ALU_SBB ||
            sbb->alu_form != FT_ALU_FORM_RM_R || sbb->modrm_mod != 3 ||
            sbb->modrm_rm_index != sbb->modrm_reg_index ||
            sbb->modrm_rm_index >= GPR_NUM ||
            (sbb->alu_width == 8 && ft_modrm_rm_is_high8(sbb)) ||
            !ft_direct_alu_reg_operands(cmp, &lhs, &rhs) ||
            !ft_instptn_enabled(FT_INSTPTN_CMP_SBB)) {
            continue;
        }
        cmp->instptn_skip = true;
        sbb->direct_cmp_lhs_gpr = lhs;
        sbb->direct_cmp_rhs_gpr = rhs;
        sbb->direct_cmp_width = cmp->alu_width;
        sbb->direct_branch_kind = FT_DIRECT_BRANCH_LTU;
    }
}

static void ft_analyze_ucomisd_seta(FastTemplateFields *fields, int count)
{
    for (int i = 0; i + 1 < count; ++i) {
        FastTemplateFields *head = &fields[i];
        FastTemplateFields *tail = &fields[i + 1];
        int cond;
        int id;

        if (head->kind != FT_SIMD_SCALAR_CMP_XMM_XMMM ||
            head->id != dt_X86_INS_UCOMISD ||
            tail->kind != FT_SETCC_RM8 ||
            !ft_setcc_opcode_info(tail->opcode1, &cond, &id) ||
            id != dt_X86_INS_SETA ||
            !ft_instptn_enabled(FT_INSTPTN_UCOMISD_SETA)) {
            continue;
        }
        head->direct_branch_kind = FT_DIRECT_BRANCH_GTU;
        tail->direct_float_result = true;
    }
}

static bool ft_float_jcc_kind(int id, FastDirectBranchKind *kind)
{
    switch (id) {
    case dt_X86_INS_JE:  *kind = FT_DIRECT_BRANCH_EQ; return true;
    case dt_X86_INS_JNE: *kind = FT_DIRECT_BRANCH_NE; return true;
    case dt_X86_INS_JB:  *kind = FT_DIRECT_BRANCH_LTU; return true;
    case dt_X86_INS_JAE: *kind = FT_DIRECT_BRANCH_GEU; return true;
    case dt_X86_INS_JBE: *kind = FT_DIRECT_BRANCH_LEU; return true;
    case dt_X86_INS_JA:  *kind = FT_DIRECT_BRANCH_GTU; return true;
    case dt_X86_INS_JP:  *kind = FT_DIRECT_BRANCH_BIT_SET; return true;
    case dt_X86_INS_JNP: *kind = FT_DIRECT_BRANCH_BIT_CLEAR; return true;
    default: return false;
    }
}

static void ft_analyze_float_jcc(FastTemplateFields *fields, int count)
{
    if (count < 2) return;
    FastTemplateFields *head = &fields[count - 2];
    FastTemplateFields *tail = &fields[count - 1];
    FastDirectBranchKind kind;
    uint64_t bit;

    if (head->kind != FT_SIMD_SCALAR_CMP_XMM_XMMM ||
        tail->kind != FT_JCC_REL || !ft_float_jcc_kind(tail->id, &kind)) {
        return;
    }
    switch (head->id) {
    case dt_X86_INS_COMISD: bit = FT_INSTPTN_COMISD_JCC; break;
    case dt_X86_INS_COMISS: bit = FT_INSTPTN_COMISS_JCC; break;
    case dt_X86_INS_UCOMISD: bit = FT_INSTPTN_UCOMISD_JCC; break;
    case dt_X86_INS_UCOMISS: bit = FT_INSTPTN_UCOMISS_JCC; break;
    default: return;
    }
    if (!ft_instptn_enabled(bit)) return;
    head->direct_branch_kind = kind;
    tail->direct_float_result = true;
}

static bool ft_float_gap_preserves_xmm(const FastTemplateFields *f)
{
    switch (f->kind) {
    case FT_NOP_MULTI:
    case FT_MOV_RM64_R64:
    case FT_MOV_RM32_R32:
    case FT_MOV_R64_RM64:
    case FT_MOV_R32_RM32:
    case FT_MOV_R32_IMM32:
    case FT_LEA_R64_M:
        return true;
    default:
        return false;
    }
}

static void ft_analyze_float_xx_jcc(FastTemplateFields *fields,
                                    const FastTemplateRuntimeInfo **meta,
                                    int count)
{
#ifndef CONFIG_SOFTMMU
    (void)fields;
    (void)meta;
    (void)count;
    return;
#else
    for (int tail = 1; tail < count; ++tail) {
        FastTemplateFields *jcc = &fields[tail];
        FastDirectBranchKind kind;
        if (jcc->kind != FT_JCC_REL || !ft_float_jcc_kind(jcc->id, &kind))
            continue;
        int first = tail > 4 ? tail - 4 : 0;
        for (int head = tail - 1; head >= first; --head) {
            FastTemplateFields *cmp = &fields[head];
            bool is_double, qnan;
            int id;
            uint64_t bit;
            if (cmp->kind != FT_SIMD_SCALAR_CMP_XMM_XMMM ||
                !ft_simd_scalar_cmp_opcode_info(cmp->prefix0, cmp->prefix2,
                                                 cmp->opcode1, &is_double,
                                                 &qnan, &id))
                continue;
            switch (id) {
            case dt_X86_INS_COMISD: bit = FT_INSTPTN_COMISD_XX_JCC; break;
            case dt_X86_INS_COMISS: bit = FT_INSTPTN_COMISS_XX_JCC; break;
            case dt_X86_INS_UCOMISD: bit = FT_INSTPTN_UCOMISD_XX_JCC; break;
            case dt_X86_INS_UCOMISS: bit = FT_INSTPTN_UCOMISS_XX_JCC; break;
            default: continue;
            }
            if (!ft_instptn_enabled(bit))
                continue;
            (void)is_double;
            (void)qnan;
            bool safe = true;
            for (int gap = head + 1; gap < tail; ++gap) {
                FastTemplateEflagMasks masks = ft_template_eflag_masks(&fields[gap], meta[gap]);
                if (masks.use || masks.def || (meta[gap] && meta[gap]->terminal_exit) ||
                    !ft_float_gap_preserves_xmm(&fields[gap])) {
                    safe = false;
                    break;
                }
            }
            if (!safe)
                continue;
            /*
             * The comparison still runs here, including its exception check.
             * System-mode a4 is a legacy pattern temporary, not a guest GPR.
             * The restricted gap above contains no emitter that clobbers it.
             */
            cmp->direct_float_xx = true;
            cmp->direct_branch_kind = kind;
            jcc->direct_float_xx = true;
            jcc->direct_branch_kind = kind;
            break;
        }
    }
#endif
}

static void ft_analyze_div_patterns(FastTemplateFields *fields, int count)
{
    for (int i = 0; i + 1 < count; ++i) {
        FastTemplateFields *head = &fields[i];
        FastTemplateFields *tail = &fields[i + 1];
        uint8_t kind = FT_INSTPTN_DIV_NONE;
        uint64_t bit = 0;

        if (head->kind == FT_CQO && tail->kind == FT_IDIV_RM64) {
            kind = FT_INSTPTN_DIV_CQO_IDIV64;
            bit = FT_INSTPTN_CQO_IDIV;
        } else if (head->kind == FT_CDQ && tail->kind == FT_IDIV_RM32) {
            kind = FT_INSTPTN_DIV_CDQ_IDIV32;
            bit = FT_INSTPTN_CDQ_IDIV;
        } else if (head->alu_op == FT_ALU_XOR &&
                   head->alu_form == FT_ALU_FORM_RM_R &&
                   head->modrm_mod == 3 &&
                   head->modrm_rm_index == rdx_index &&
                   head->modrm_reg_index == rdx_index) {
            if (head->alu_width == 32 && tail->kind == FT_DIV_RM32) {
                kind = FT_INSTPTN_DIV_XOR_DIV32;
            } else if (head->alu_width == 64 && tail->kind == FT_DIV_RM64) {
                kind = FT_INSTPTN_DIV_XOR_DIV64;
            }
            bit = FT_INSTPTN_XOR_DIV;
        }
        if (kind && ft_instptn_enabled(bit)) {
            head->instptn_skip = true;
            tail->instptn_div_kind = kind;
        }
    }
}

static bool ft_direct_xxcc_kind(const FastTemplateFields *fields,
                                 FastDirectBranchKind *kind)
{
    int id = fields->id;

    if (fields->kind == FT_SETCC_RM8) {
        int cond;

        if (!ft_setcc_opcode_info(fields->opcode1, &cond, &id)) {
            return false;
        }
    }
    switch (id) {
    case dt_X86_INS_SETE: case dt_X86_INS_CMOVE:
        *kind = FT_DIRECT_BRANCH_EQ; return true;
    case dt_X86_INS_SETNE: case dt_X86_INS_CMOVNE:
        *kind = FT_DIRECT_BRANCH_NE; return true;
    case dt_X86_INS_SETL: case dt_X86_INS_CMOVL:
        *kind = FT_DIRECT_BRANCH_LT; return true;
    case dt_X86_INS_SETGE: case dt_X86_INS_CMOVGE:
        *kind = FT_DIRECT_BRANCH_GE; return true;
    case dt_X86_INS_SETB: case dt_X86_INS_CMOVB:
        *kind = FT_DIRECT_BRANCH_LTU; return true;
    case dt_X86_INS_SETAE: case dt_X86_INS_CMOVAE:
        *kind = FT_DIRECT_BRANCH_GEU; return true;
    case dt_X86_INS_SETLE: case dt_X86_INS_CMOVLE:
        *kind = FT_DIRECT_BRANCH_LE; return true;
    case dt_X86_INS_SETG: case dt_X86_INS_CMOVG:
        *kind = FT_DIRECT_BRANCH_GT; return true;
    case dt_X86_INS_SETBE: case dt_X86_INS_CMOVBE:
        *kind = FT_DIRECT_BRANCH_LEU; return true;
    case dt_X86_INS_SETA: case dt_X86_INS_CMOVA:
        *kind = FT_DIRECT_BRANCH_GTU; return true;
    case dt_X86_INS_SETS: case dt_X86_INS_CMOVS:
        *kind = FT_DIRECT_BRANCH_LT; return true;
    case dt_X86_INS_SETNS: case dt_X86_INS_CMOVNS:
        *kind = FT_DIRECT_BRANCH_GE; return true;
    case dt_X86_INS_SETO: case dt_X86_INS_CMOVO:
        *kind = FT_DIRECT_BRANCH_NEVER; return true;
    case dt_X86_INS_SETNO: case dt_X86_INS_CMOVNO:
        *kind = FT_DIRECT_BRANCH_ALWAYS; return true;
    default:
        return false;
    }
}

static bool ft_is_xxcc_consumer(const FastTemplateFields *fields)
{
    return fields->kind == FT_SETCC_RM8 ||
           fields->kind == FT_CMOV_R64_RM64 ||
           fields->kind == FT_CMOV_R32_RM32 ||
           fields->kind == FT_CMOV_R16_RM16;
}

static bool ft_direct_gap_is_safe(
    const FastTemplateFields *fields, const FastTemplateRuntimeInfo *meta,
    int lhs, int rhs);

/* Legacy condition chains contain only consecutive SETcc/CMOVcc.
 * Require each intervening consumer to use the same comparison and leave
 * its operands intact. Memory consumers remain excluded for faults.
 */
static bool ft_xxcc_gap_is_safe(const FastTemplateFields *fields,
                                int lhs, int rhs)
{
    int dst;

    if (!ft_is_xxcc_consumer(fields) || fields->modrm_mod != 3 ||
        fields->direct_cmp_lhs_gpr != lhs ||
        fields->direct_cmp_rhs_gpr != rhs) {
        return false;
    }
    if (fields->kind == FT_SETCC_RM8) {
        if (ft_modrm_rm_is_high8(fields)) {
            return false;
        }
        dst = fields->modrm_rm_index;
    } else {
        dst = fields->modrm_reg_index;
    }
    return dst != lhs && (rhs < 0 || dst != rhs);
}

static void ft_analyze_direct_xxcc(
    FastTemplateFields *fields, const FastTemplateRuntimeInfo **meta,
    int count)
{
    for (int tail = 1; tail < count; ++tail) {
        FastDirectBranchKind kind;
        int first;

        /* A faulting consumer can resume in a new TB without its producer.
         * Keep the architectural flags for memory SETcc/CMOVcc operands. */
        if (!ft_is_xxcc_consumer(&fields[tail]) ||
            fields[tail].modrm_mod != 3 ||
            !ft_direct_xxcc_kind(&fields[tail], &kind)) {
            continue;
        }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        /* This QT extension uses the default full pattern mask only. Reuse
         * an adjacent 64-bit integer result, never a scratch register or a
         * deferred RSP value. No new TB scan or memory dependency is needed.
         */
        if (tail + 1 < count && fields[tail].kind == FT_SETCC_RM8 &&
            fields[tail].modrm_mod == 3 && fields[tail].prefix0 == 0 &&
            (kind == FT_DIRECT_BRANCH_EQ || kind == FT_DIRECT_BRANCH_NE) &&
            (uint32_t)option_instptn == 0x3ffffffu) {
            const FastTemplateFields *producer = &fields[tail - 1];
            const FastTemplateFields *kill = &fields[tail + 1];
            int result = -1;

            /* Bound newly dead flags to three non-faulting instructions.
             * A memory/helper gap must not expose omitted flags to a signal.
             */
            bool kills_flags = kill->prefix0 == 0 &&
                (kill->alu_width == 32 || kill->alu_width == 64) &&
                (kill->alu_form == FT_ALU_FORM_ACC_IMM ||
                 kill->modrm_mod == 3) &&
                (kill->alu_op == FT_ALU_ADD || kill->alu_op == FT_ALU_SUB ||
                 kill->alu_op == FT_ALU_AND || kill->alu_op == FT_ALU_OR ||
                 kill->alu_op == FT_ALU_XOR || kill->alu_op == FT_ALU_CMP ||
                 kill->alu_op == FT_ALU_TEST);
            if (kills_flags && producer->prefix0 == 0 &&
                producer->alu_width == 64 &&
                (producer->alu_form == FT_ALU_FORM_ACC_IMM ||
                 producer->modrm_mod == 3) &&
                (producer->alu_op == FT_ALU_ADD ||
                 producer->alu_op == FT_ALU_SUB ||
                 producer->alu_op == FT_ALU_AND ||
                 producer->alu_op == FT_ALU_OR ||
                 producer->alu_op == FT_ALU_XOR) &&
                ft_direct_alu_result_gpr(producer, &result) &&
                result != rsp_index) {
                fields[tail].direct_cmp_lhs_gpr = result;
                fields[tail].direct_cmp_rhs_gpr = -1;
                fields[tail].direct_cmp_width = 64;
                fields[tail].direct_branch_kind = kind;
                continue;
            }
        }
#endif
        first = tail > 4 ? tail - 4 : 0;
        for (int head = tail - 1; head >= first; --head) {
            FastTemplateFields *alu = &fields[head];
            int tail_id = fields[tail].id;
            int unused_cond;

            if (fields[tail].kind == FT_SETCC_RM8 &&
                !ft_setcc_opcode_info(fields[tail].opcode1,
                                      &unused_cond, &tail_id)) {
                continue;
            }
            uint64_t option_bit;
            int lhs = -1;
            int rhs = -1;
            bool safe = true;

            if (alu->alu_op == FT_ALU_CMP) {
                option_bit = FT_INSTPTN_CMP_XXCC_CON;
                if (!ft_direct_alu_reg_operands(alu, &lhs, &rhs)) {
                    continue;
                }
                switch (tail_id) {
                case dt_X86_INS_SETE: case dt_X86_INS_SETNE:
                case dt_X86_INS_SETL: case dt_X86_INS_SETGE:
                case dt_X86_INS_SETB: case dt_X86_INS_SETAE:
                case dt_X86_INS_SETLE: case dt_X86_INS_SETG:
                case dt_X86_INS_SETBE: case dt_X86_INS_SETA:
                case dt_X86_INS_CMOVE: case dt_X86_INS_CMOVNE:
                case dt_X86_INS_CMOVL: case dt_X86_INS_CMOVGE:
                case dt_X86_INS_CMOVB: case dt_X86_INS_CMOVAE:
                case dt_X86_INS_CMOVLE: case dt_X86_INS_CMOVG:
                case dt_X86_INS_CMOVBE: case dt_X86_INS_CMOVA:
                    break;
                default:
                    continue;
                }
            } else if (alu->alu_op == FT_ALU_TEST) {
                option_bit = FT_INSTPTN_TEST_XXCC_CON;
                if (!ft_direct_alu_reg_operands(alu, &lhs, &rhs) ||
                    lhs != rhs) {
                    continue;
                }
                rhs = -1;
                switch (tail_id) {
                case dt_X86_INS_SETE: case dt_X86_INS_SETNE:
                case dt_X86_INS_SETS: case dt_X86_INS_SETNS:
                case dt_X86_INS_SETLE: case dt_X86_INS_SETG:
                case dt_X86_INS_SETO: case dt_X86_INS_SETNO:
                case dt_X86_INS_SETB: case dt_X86_INS_SETAE:
                case dt_X86_INS_SETBE: case dt_X86_INS_SETA:
                case dt_X86_INS_CMOVE: case dt_X86_INS_CMOVNE:
                case dt_X86_INS_CMOVS: case dt_X86_INS_CMOVNS:
                case dt_X86_INS_CMOVLE: case dt_X86_INS_CMOVG:
                case dt_X86_INS_CMOVO: case dt_X86_INS_CMOVNO:
                case dt_X86_INS_CMOVB: case dt_X86_INS_CMOVAE:
                case dt_X86_INS_CMOVBE: case dt_X86_INS_CMOVA:
                    break;
                default:
                    continue;
                }
            } else {
                continue;
            }
            if (!ft_instptn_enabled(option_bit)) {
                break;
            }
            for (int gap = head + 1; gap < tail; ++gap) {
                if (!ft_xxcc_gap_is_safe(&fields[gap], lhs, rhs)) {
                    safe = false;
                    break;
                }
            }
            if (safe) {
                fields[tail].direct_cmp_lhs_gpr = lhs;
                fields[tail].direct_cmp_rhs_gpr = rhs;
                fields[tail].direct_cmp_width = alu->alu_width;
                fields[tail].direct_branch_kind = kind;
                break;
            }
        }
    }
}

static bool ft_gap_writes_gpr(const FastTemplateFields *fields, int reg)
{
    int dst = -1;

    switch (fields->kind) {
    case FT_MOV_R32_IMM32:
        dst = fields->reg;
        break;
    case FT_MOV_R64_RM64:
    case FT_MOV_R32_RM32:
    case FT_LEA_R64_M:
        dst = fields->modrm_reg_index;
        break;
    case FT_MOV_RM64_R64:
    case FT_MOV_RM32_R32:
        if (fields->modrm_mod != 3) {
            return false;
        }
        dst = fields->modrm_rm_index;
        break;
    default:
        return true;
    }
    return dst == reg;
}

static bool ft_direct_gap_is_safe(
    const FastTemplateFields *fields, const FastTemplateRuntimeInfo *meta,
    int lhs, int rhs)
{
    FastTemplateEflagMasks masks = ft_template_eflag_masks(fields, meta);

    /* Folding may make the producer's flags dead. A memory fault in the
     * gap can restart at that access in a new TB, where the consumer needs
     * the architectural flags again. LEA does not access memory. */
    switch (fields->kind) {
    case FT_MOV_R64_RM64:
    case FT_MOV_R32_RM32:
    case FT_MOV_RM64_R64:
    case FT_MOV_RM32_R32:
        if (fields->modrm_mod != 3) {
            return false;
        }
        break;
    default:
        break;
    }
    if (masks.use || masks.def || (meta && meta->terminal_exit)) {
        return false;
    }
    return !ft_gap_writes_gpr(fields, lhs) &&
           (rhs < 0 || !ft_gap_writes_gpr(fields, rhs));
}

static void ft_analyze_direct_jcc_gap(
    FastTemplateFields *fields, const FastTemplateRuntimeInfo **meta,
    int count)
{
    FastTemplateFields *jcc = &fields[count - 1];
    int first = count > 5 ? count - 5 : 0;

    if (jcc->kind != FT_JCC_REL) {
        return;
    }
    for (int head = count - 3; head >= first; --head) {
        FastTemplateFields trial;
        bool safe = true;

        /* The pair matcher reads only kind/id and updates these six fields.
         * Avoid copying the complete decoded instruction for every miss. */
        trial.kind = jcc->kind;
        trial.id = jcc->id;
        trial.direct_cmp_lhs_gpr = jcc->direct_cmp_lhs_gpr;
        trial.direct_cmp_rhs_gpr = jcc->direct_cmp_rhs_gpr;
        trial.direct_cmp_width = jcc->direct_cmp_width;
        trial.direct_branch_kind = jcc->direct_branch_kind;
        trial.direct_bit_index_gpr = jcc->direct_bit_index_gpr;
        trial.direct_bit_index_imm = jcc->direct_bit_index_imm;
        ft_analyze_direct_jcc_pair(&fields[head], &trial, true);
        if (trial.direct_cmp_lhs_gpr < 0) {
            continue;
        }
        for (int gap = head + 1; gap < count - 1; ++gap) {
            if (!ft_direct_gap_is_safe(&fields[gap], meta[gap],
                                       trial.direct_cmp_lhs_gpr,
                                       trial.direct_cmp_rhs_gpr) ||
                (trial.direct_bit_index_gpr >= 0 &&
                 ft_gap_writes_gpr(&fields[gap],
                                   trial.direct_bit_index_gpr))) {
                safe = false;
                break;
            }
        }
        if (safe) {
            jcc->direct_cmp_lhs_gpr = trial.direct_cmp_lhs_gpr;
            jcc->direct_cmp_rhs_gpr = trial.direct_cmp_rhs_gpr;
            jcc->direct_cmp_width = trial.direct_cmp_width;
            jcc->direct_branch_kind = trial.direct_branch_kind;
            jcc->direct_bit_index_gpr = trial.direct_bit_index_gpr;
            jcc->direct_bit_index_imm = trial.direct_bit_index_imm;
            return;
        }
    }
}

static void ft_analyze_direct_jcc_pair(FastTemplateFields *alu,
                                       FastTemplateFields *jcc, bool gap)
{
    FastDirectBranchKind kind = FT_DIRECT_BRANCH_NONE;
    uint64_t option_bit = 0;
    int lhs = -1;
    int rhs = -1;

    if (jcc->kind != FT_JCC_REL) {
        return;
    }

    if (ft_alu_writes_dst(alu->alu_op) &&
        ft_direct_result_jcc_kind(alu->alu_op, jcc->id, &kind) &&
        ft_direct_alu_result_gpr(alu, &lhs)) {
        switch (alu->alu_op) {
        case FT_ALU_ADD: option_bit = FT_INSTPTN_ADD_JCC; break;
        case FT_ALU_SUB: option_bit = FT_INSTPTN_SUB_JCC; break;
        case FT_ALU_AND: option_bit = FT_INSTPTN_AND_JCC; break;
        case FT_ALU_OR:  option_bit = FT_INSTPTN_OR_JCC; break;
        case FT_ALU_XOR: option_bit = FT_INSTPTN_XOR_JCC; break;
        default: return;
        }
        rhs = -1;
    } else if ((alu->kind == FT_DEC_RM8 || alu->kind == FT_DEC_RM16 ||
                alu->kind == FT_DEC_RM32 || alu->kind == FT_DEC_RM64) &&
               alu->modrm_mod == 3 && alu->modrm_rm_index < GPR_NUM &&
               !(alu->kind == FT_DEC_RM8 && ft_modrm_rm_is_high8(alu)) &&
               (jcc->id == dt_X86_INS_JE || jcc->id == dt_X86_INS_JNE)) {
        lhs = alu->modrm_rm_index;
        rhs = -1;
        kind = jcc->id == dt_X86_INS_JE ? FT_DIRECT_BRANCH_EQ :
                                          FT_DIRECT_BRANCH_NE;
        option_bit = FT_INSTPTN_DEC_JCC;
    } else if ((alu->kind == FT_SHIFT_RM_ONE ||
                alu->kind == FT_SHIFT_RM_IMM8) &&
               alu->modrm_mod == 3 && alu->modrm_rm_index < GPR_NUM &&
               alu->modrm_reg != 6 &&
               (alu->modrm_reg == 5 || alu->modrm_reg == 7) &&
               (alu->kind == FT_SHIFT_RM_ONE ||
                (alu->imm & (ft_rex_w(alu) ? 63 : 31)) != 0) &&
               !(ft_shift_width(alu) == 8 && ft_modrm_rm_is_high8(alu))) {
        bool zero_branch = jcc->id == dt_X86_INS_JE ||
                           jcc->id == dt_X86_INS_JNE;
        bool sign_branch = alu->modrm_reg == 7 &&
                           (jcc->id == dt_X86_INS_JS ||
                            jcc->id == dt_X86_INS_JNS);

        if (!zero_branch && !sign_branch) {
            return;
        }
        lhs = alu->modrm_rm_index;
        rhs = -1;
        if (jcc->id == dt_X86_INS_JE) kind = FT_DIRECT_BRANCH_EQ;
        if (jcc->id == dt_X86_INS_JNE) kind = FT_DIRECT_BRANCH_NE;
        if (jcc->id == dt_X86_INS_JS) kind = FT_DIRECT_BRANCH_LT;
        if (jcc->id == dt_X86_INS_JNS) kind = FT_DIRECT_BRANCH_GE;
        option_bit = alu->modrm_reg == 7 ? FT_INSTPTN_SAR_JCC :
                                           FT_INSTPTN_SHR_JCC;
    } else if (alu->id == dt_X86_INS_BT &&
               (jcc->id == dt_X86_INS_JB || jcc->id == dt_X86_INS_JAE) &&
               alu->modrm_mod == 3 && alu->modrm_rm_index < GPR_NUM) {
        lhs = alu->modrm_rm_index;
        rhs = -1;
        if (alu->kind == FT_BTX_RM_R && alu->modrm_reg_index < GPR_NUM) {
            jcc->direct_bit_index_gpr = alu->modrm_reg_index;
        } else if (alu->kind == FT_BTX_RM32_IMM8) {
            jcc->direct_bit_index_imm = alu->imm;
        } else {
            return;
        }
        kind = jcc->id == dt_X86_INS_JB ? FT_DIRECT_BRANCH_BIT_SET :
                                          FT_DIRECT_BRANCH_BIT_CLEAR;
        option_bit = FT_INSTPTN_BT_JCC;
    } else if (!ft_direct_jcc_kind(jcc->id, &kind)) {
        return;
    } else if (alu->alu_op == FT_ALU_CMP && ft_direct_alu_reg_operands(alu, &lhs, &rhs)) {
        /* CMP lhs, rhs maps directly to signed/unsigned LA comparisons. */
        option_bit = FT_INSTPTN_CMP_JCC;
    } else if (alu->alu_op == FT_ALU_CMP && alu->imm == 0 &&
               (kind == FT_DIRECT_BRANCH_EQ || kind == FT_DIRECT_BRANCH_NE)) {
        if (alu->alu_form == FT_ALU_FORM_ACC_IMM) {
            lhs = rax_index;
        } else if (alu->alu_form == FT_ALU_FORM_RM_IMM &&
                   alu->modrm_mod == 3 && alu->modrm_rm_index < GPR_NUM &&
                   !(alu->alu_width == 8 && ft_modrm_rm_is_high8(alu))) {
            lhs = alu->modrm_rm_index;
        }
        option_bit = FT_INSTPTN_CMP_JCC;
    } else if (alu->alu_op == FT_ALU_TEST &&
               (kind == FT_DIRECT_BRANCH_EQ || kind == FT_DIRECT_BRANCH_NE) &&
               ft_direct_alu_reg_operands(alu, &lhs, &rhs) && lhs == rhs) {
        rhs = -1;
        option_bit = FT_INSTPTN_TEST_JCC;
    } else {
        return;
    }

    if (gap) {
        switch (option_bit) {
        case FT_INSTPTN_CMP_JCC: option_bit = FT_INSTPTN_CMP_XX_JCC; break;
        case FT_INSTPTN_TEST_JCC: option_bit = FT_INSTPTN_TEST_XX_JCC; break;
        case FT_INSTPTN_BT_JCC: option_bit = FT_INSTPTN_BT_XX_JCC; break;
        case FT_INSTPTN_OR_JCC: option_bit = FT_INSTPTN_OR_XX_JCC; break;
        case FT_INSTPTN_XOR_JCC: option_bit = FT_INSTPTN_XOR_XX_JCC; break;
        case FT_INSTPTN_AND_JCC: option_bit = FT_INSTPTN_AND_XX_JCC; break;
        case FT_INSTPTN_SUB_JCC: option_bit = FT_INSTPTN_SUB_XX_JCC; break;
        case FT_INSTPTN_SHR_JCC: option_bit = FT_INSTPTN_SHR_XX_JCC; break;
        default: option_bit = 0; break;
        }
    }
    if (lhs < 0 || option_bit == 0 || !ft_instptn_enabled(option_bit)) {
        return;
    }
    jcc->direct_cmp_lhs_gpr = lhs;
    jcc->direct_cmp_rhs_gpr = rhs;
    if (alu->alu_width) {
        jcc->direct_cmp_width = alu->alu_width;
    } else if (alu->id == dt_X86_INS_BT) {
        jcc->direct_cmp_width = ft_rex_w(alu) ? 64 :
                                alu->prefix2 == dt_X86_PREFIX_OPSIZE ? 16 : 32;
    } else if (alu->kind == FT_DEC_RM8) {
        jcc->direct_cmp_width = 8;
    } else if (alu->kind == FT_DEC_RM16) {
        jcc->direct_cmp_width = 16;
    } else if (alu->kind == FT_DEC_RM32) {
        jcc->direct_cmp_width = 32;
    } else if (alu->kind == FT_DEC_RM64) {
        jcc->direct_cmp_width = 64;
    } else {
        jcc->direct_cmp_width = ft_shift_width(alu);
    }
    jcc->direct_branch_kind = kind;
}

static bool ft_template_uses_x87_top(FastTemplateKind kind)
{
    return ft_template_runtime_info(kind)->uses_x87_top;
}

static bool ft_template_uses_mmx(const FastTemplateFields *fields)
{
    FastTemplateKind kind = fields->kind;

    if (kind == FT_PUNPCK_XMM_XMMM) {
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        /* UNPCKLPS/HPS (0f 14/15) have no 66 prefix but operate on XMM. */
        return fields->prefix0 == 0 && fields->prefix2 == 0 &&
               ((fields->opcode1 >= 0x60 && fields->opcode1 <= 0x62) ||
                (fields->opcode1 >= 0x68 && fields->opcode1 <= 0x6a));
#else
        return fields->prefix0 == 0 && fields->prefix2 == 0;
#endif
    }
    if (kind == FT_SIMD_BIN_XMM_XMMM &&
        fields->prefix0 == 0 && fields->prefix2 == 0) {
        switch (fields->id) {
        case dt_X86_INS_PSRLW:
        case dt_X86_INS_PSRLD:
        case dt_X86_INS_PSRLQ:
        case dt_X86_INS_PSLLW:
        case dt_X86_INS_PSLLD:
        case dt_X86_INS_PSLLQ:
        case dt_X86_INS_PMINUB:
        case dt_X86_INS_PMAXUB:
            return true;
        default:
            break;
        }
    }
    if (kind >= FT_PSHUFW_MMX_MMXM_IMM8 &&
        kind <= FT_MOVQ2DQ_XMM_MMX) {
        return true;
    }

    switch (kind) {
    case FT_MOVQ_MMX_RM64:
    case FT_MOVQ_RM64_MMX:
    case FT_MOVQ_MMXM64_MMX:
    case FT_MOVD_MMX_RM32:
    case FT_MOVD_RM32_MMX:
    case FT_MOVQ_MMX_RM64_GPR:
    case FT_PEXTRW_R32_MMX_IMM8:
    case FT_PINSRW_MMX_RM16_IMM8:
    case FT_CVTPI2PD_XMM_MMX:
    case FT_CVTPI2PS_XMM_MMX:
    case FT_CVT_FP2I_MMX_XMMM:
    case FT_PMOVMSKB_R32_MMX:
    case FT_MASKMOVQ_MMX_MMX:
    case FT_PALIGNR_MMX_MMXM64_IMM8:
    case FT_PSHUFB_MMX_MMXM64:
    case FT_PHADD_SUB_MMX_MMXM64:
    case FT_SIMD_MADD_MMX_MMXM64:
    case FT_SIMD_BIN_MMX_MMXM64:
        return true;
    default:
        return false;
    }
}

static bool ft_mmx_entry_required(bool mmx_active)
{
#if defined(CONFIG_LATX_OPT_NOFP) && !defined(QUICKTRANS_LATU)
    return !mmx_active;
#else
    (void)mmx_active;
    return true;
#endif
}

typedef struct FtDebugSkipConfig {
    bool enabled;
    bool skip_all;
    bool has_range;
    bool has_kind;
    bool has_id;
    bool has_ids;
    bool has_pc;
    bool has_from;
    bool skip_x87;
    bool skip_simd;
    target_ulong range_start;
    target_ulong range_end;
    FastTemplateKind kind;
    int id;
    int ids[64];
    size_t id_count;
    target_ulong pc;
    target_ulong from;
} FtDebugSkipConfig;

static const FtDebugSkipConfig *ft_debug_skip_config(void)
{
#ifdef CONFIG_LATX_DEBUG
    static FtDebugSkipConfig cfg;
    static bool initialized;

    if (!initialized) {
        const char *skip_from = getenv("LATX_FT_DEBUG_SKIP_FROM");
        const char *skip_kind = getenv("LATX_FT_DEBUG_SKIP_KIND");
        const char *skip_id = getenv("LATX_FT_DEBUG_SKIP_ID");
        const char *skip_ids = getenv("LATX_FT_DEBUG_SKIP_IDS");
        const char *skip_pc = getenv("LATX_FT_DEBUG_SKIP_PC");
        const char *skip_range_start =
            getenv("LATX_FT_DEBUG_SKIP_RANGE_START");
        const char *skip_range_end = getenv("LATX_FT_DEBUG_SKIP_RANGE_END");

        cfg.skip_all = getenv("LATX_FT_DEBUG_SKIP_ALL") != NULL;
        cfg.has_range = skip_range_start != NULL && skip_range_end != NULL;
        cfg.has_kind = skip_kind != NULL;
        cfg.has_id = skip_id != NULL;
        cfg.has_ids = skip_ids != NULL;
        cfg.has_pc = skip_pc != NULL;
        cfg.has_from = skip_from != NULL;
        cfg.skip_x87 = getenv("LATX_FT_DEBUG_SKIP_X87") != NULL;
        cfg.skip_simd = getenv("LATX_FT_DEBUG_SKIP_SIMD") != NULL;

        if (cfg.has_range) {
            cfg.range_start = strtoull(skip_range_start, NULL, 0);
            cfg.range_end = strtoull(skip_range_end, NULL, 0);
        }
        if (cfg.has_kind) {
            cfg.kind = (FastTemplateKind)atoi(skip_kind);
        }
        if (cfg.has_id) {
            cfg.id = atoi(skip_id);
        }
        if (cfg.has_ids) {
            const char *cursor = skip_ids;

            while (*cursor && cfg.id_count < ARRAY_SIZE(cfg.ids)) {
                char *end;
                long value = strtol(cursor, &end, 0);

                if (end == cursor) {
                    break;
                }
                cfg.ids[cfg.id_count++] = value;
                cursor = *end == ',' ? end + 1 : end;
            }
            cfg.has_ids = cfg.id_count != 0;
        }
        if (cfg.has_pc) {
            cfg.pc = (target_ulong)strtoull(skip_pc, NULL, 0);
        }
        if (cfg.has_from) {
            cfg.from = (target_ulong)strtoull(skip_from, NULL, 0);
        }
        cfg.enabled = cfg.skip_all || cfg.has_range || cfg.has_kind ||
                      cfg.has_id || cfg.has_ids || cfg.has_pc || cfg.has_from ||
                      cfg.skip_x87 || cfg.skip_simd;
        initialized = true;
    }
    return &cfg;
#else
    static const FtDebugSkipConfig disabled;
    return &disabled;
#endif
}

static bool ft_debug_skip_template(FastTemplateKind kind, int id,
                                   target_ulong pc)
{
#ifdef CONFIG_LATX_DEBUG
    const FtDebugSkipConfig *cfg = ft_debug_skip_config();

    if (!cfg->enabled) {
        return false;
    }
    if (cfg->skip_all) {
        return true;
    }
    if (cfg->has_range && pc >= cfg->range_start && pc < cfg->range_end) {
        return true;
    }
    if (cfg->has_kind && kind == cfg->kind) {
        return true;
    }
    if (cfg->has_id && id == cfg->id) {
        return true;
    }
    if (cfg->has_ids) {
        for (size_t i = 0; i < cfg->id_count; i++) {
            if (id == cfg->ids[i]) {
                return true;
            }
        }
    }
    if (cfg->has_pc && pc == cfg->pc) {
        return true;
    }
    if (cfg->has_from && pc >= cfg->from) {
        return true;
    }
    if (cfg->skip_x87 && ft_template_uses_x87_top(kind)) {
        return true;
    }
    if (cfg->skip_simd &&
        ((kind >= FT_MOVQ_XMM_RM64 && kind <= FT_FMA132_XMM_XMMM) ||
         kind == FT_HELPER_PCMPISTRI ||
         kind == FT_HELPER_PCMPISTRM ||
         kind == FT_HELPER_PCMPESTRI ||
         kind == FT_HELPER_PCMPESTRM ||
         kind == FT_HELPER_LDMXCSR ||
         kind == FT_HELPER_FXSAVE ||
         kind == FT_HELPER_FXRSTOR ||
         kind == FT_HELPER_FNSAVE ||
         kind == FT_HELPER_FRSTOR ||
         kind == FT_HELPER_FLDENV ||
         kind == FT_HELPER_FNSTENV)) {
        return true;
    }
    return false;
#else
    return false;
#endif
}

typedef struct FtDebugSplitConfig {
    bool enabled;
    bool has_kind;
    bool has_pc;
    FastTemplateKind kind;
    target_ulong pc;
} FtDebugSplitConfig;

static const FtDebugSplitConfig *ft_debug_split_config(void)
{
#ifdef CONFIG_LATX_DEBUG
    static bool initialized;
    static FtDebugSplitConfig cfg;

    if (!initialized) {
        const char *kind_env = getenv("LATX_FT_DEBUG_SPLIT_BEFORE_KIND");
        const char *pc_env = getenv("LATX_FT_DEBUG_SPLIT_BEFORE_PC");

        cfg.has_kind = kind_env != NULL;
        cfg.has_pc = pc_env != NULL;
        if (cfg.has_kind) {
            cfg.kind = (FastTemplateKind)atoi(kind_env);
        }
        if (cfg.has_pc) {
            cfg.pc = (target_ulong)strtoull(pc_env, NULL, 0);
        }
        cfg.enabled = cfg.has_kind || cfg.has_pc;
        initialized = true;
    }
    return &cfg;
#else
    static const FtDebugSplitConfig disabled;
    return &disabled;
#endif
}

static bool ft_debug_split_before_template(FastTemplateKind kind,
                                           target_ulong pc)
{
#ifdef CONFIG_LATX_DEBUG
    const FtDebugSplitConfig *cfg = ft_debug_split_config();

    if (!cfg->enabled) {
        return false;
    }
    if (cfg->has_kind && kind == cfg->kind) {
        return true;
    }
    if (cfg->has_pc && pc == cfg->pc) {
        return true;
    }
    return false;
#else
    return false;
#endif
}

static bool ft_primary_trace_enabled(void)
{
#ifdef CONFIG_LATX_DEBUG
    static int enabled = -1;

    if (enabled < 0) {
        enabled = getenv("LATX_FAST_TRANSLATOR_TRACE") != NULL;
    }
    return enabled;
#else
    return false;
#endif
}

static bool ft_primary_trace_opt_enabled(void)
{
#ifdef CONFIG_LATX_DEBUG
    static int enabled = -1;

    if (enabled < 0) {
        enabled = getenv("LATX_FAST_TRANSLATOR_TRACE_OPT") != NULL;
    }
    return enabled;
#else
    return false;
#endif
}

#ifdef CONFIG_LATX_DEBUG
static int ft_primary_debug_live_initialized;
static target_ulong ft_primary_debug_live_target;
#endif

static bool ft_primary_debug_live_enabled(void)
{
#ifdef CONFIG_LATX_DEBUG
    if (!ft_primary_debug_live_initialized) {
        const char *env_pc = getenv("LATX_FT_DEBUG_LIVE_PC");

        ft_primary_debug_live_target =
            env_pc ? (target_ulong)strtoull(env_pc, NULL, 0) : 0;
        ft_primary_debug_live_initialized = 1;
    }
    return ft_primary_debug_live_target != 0;
#else
    return false;
#endif
}

static target_ulong ft_primary_debug_live_pc(void)
{
#ifdef CONFIG_LATX_DEBUG
    if (!ft_primary_debug_live_initialized) {
        (void)ft_primary_debug_live_enabled();
    }
    return ft_primary_debug_live_target;
#else
    return 0;
#endif
}

#ifdef CONFIG_LATX_DEBUG
static bool ft_primary_debug_code_initialized;
static target_ulong ft_primary_debug_code_pc;
static target_ulong ft_primary_debug_code_low12;
static bool ft_primary_debug_code_has_low12;
static unsigned int ft_primary_debug_code_remaining;
#endif

static void ft_primary_debug_code_init(void)
{
#ifdef CONFIG_LATX_DEBUG
    const char *value;

    if (ft_primary_debug_code_initialized) {
        return;
    }
    value = getenv("LATX_FT_DEBUG_CODE_PC");
    ft_primary_debug_code_pc =
        value && value[0] ? strtoull(value, NULL, 0) : 0;
    value = getenv("LATX_FT_DEBUG_CODE_LOW12");
    ft_primary_debug_code_has_low12 = value && value[0];
    ft_primary_debug_code_low12 = ft_primary_debug_code_has_low12 ?
        strtoull(value, NULL, 0) & 0xfff : 0;
    value = getenv("LATX_FT_DEBUG_CODE_MAX");
    ft_primary_debug_code_remaining =
        value && value[0] ? strtoul(value, NULL, 0) : 4;
    ft_primary_debug_code_initialized = true;
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static bool ft_primary_debug_code_enabled(void)
{
#ifdef CONFIG_LATX_DEBUG
    ft_primary_debug_code_init();
    return (ft_primary_debug_code_pc != 0 ||
            ft_primary_debug_code_has_low12) &&
           ft_primary_debug_code_remaining != 0;
#else
    return false;
#endif
}

static void ft_primary_debug_dump_code(target_ulong pc,
                                       const FastTemplateFields *fields,
                                       const uint32_t *code, int count)
{
#ifdef CONFIG_LATX_DEBUG
    ft_primary_debug_code_init();
    bool pc_matches = ft_primary_debug_code_pc &&
                      pc == ft_primary_debug_code_pc;
    bool low12_matches = ft_primary_debug_code_has_low12 &&
                         (pc & 0xfff) == ft_primary_debug_code_low12;

    if ((!pc_matches && !low12_matches) ||
        !ft_primary_debug_code_remaining || !fields || !code || count <= 0) {
        return;
    }

    fprintf(stderr, "[FT-CODE] pc=0x%lx kind=%d cond=%d words=%d",\
            (unsigned long)pc, fields->kind, fields->reg, count);
    for (int i = 0; i < count; i++) {
        fprintf(stderr, " %08x", code[i]);
    }
    fputc('\n', stderr);
    ft_primary_debug_code_remaining--;
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static void ft_primary_debug_emit_live_regs(uint32_t **out, target_ulong pc)
{
#ifdef CONFIG_LATX_DEBUG
    target_ulong debug_pc = ft_primary_debug_live_pc();

    if (!debug_pc || debug_pc != pc) {
        return;
    }

    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_li64(out, la_a1, pc);
    ft_emit_host_call(out, (void *)ft_debug_dump_live_entry, 1u << 0);
    ft_emit_helper_epilogue(out);
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static void ft_primary_debug_emit_exit_state(uint32_t **out, target_ulong pc,
                                             int condition_reg)
{
#ifdef CONFIG_LATX_DEBUG
    if (!ft_primary_debug_live_enabled() ||
        ft_primary_debug_live_pc() != pc) {
        return;
    }

    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_li64(out, la_a1, pc);
    FT_LA_OR_EMIT(out, la_a2, condition_reg, la_zero);
    ft_emit_host_call(out, (void *)ft_debug_dump_live_exit, 0x7);
    ft_emit_helper_epilogue(out);
#else
    /* Diagnostic instrumentation is absent from release builds. */
#endif
}

static void ft_primary_update_last_info(TranslationBlock *tb,
                                        const FastTemplateFields *fields)
{
#if defined(CONFIG_LATX_TU) || defined(CONFIG_LATX_AOT)
    target_ulong next_pc;
    target_ulong target_pc = 0;
    int8_t last_ir1_type = (int8_t)IR1_TYPE_NORMAL;

    if (!tb || !tb->s_data || tb->icount == 0) {
        return;
    }

    next_pc = fields->address + fields->size;
    switch (fields->kind) {
    case FT_JCC_REL:
    case FT_JRCXZ_REL8:
    case FT_LOOP_REL8:
    case FT_LOOPE_REL8:
    case FT_LOOPNE_REL8:
        last_ir1_type = (int8_t)IR1_TYPE_BRANCH;
        target_pc = fields->imm64;
        break;
    case FT_CALL_REL32:
    case FT_HELPER_LCALL:
        last_ir1_type = (int8_t)IR1_TYPE_CALL;
        target_pc = next_pc + fields->imm;
        break;
    case FT_CALL_RM64:
        last_ir1_type = (int8_t)IR1_TYPE_CALLIN;
        break;
    case FT_JMP_REL32:
        last_ir1_type = (int8_t)IR1_TYPE_JUMP;
        target_pc = next_pc + fields->imm;
        break;
    case FT_JMP_RM64:
    case FT_HELPER_LJMP:
        last_ir1_type = (int8_t)IR1_TYPE_JUMPIN;
        break;
    case FT_RET:
    case FT_RET_IMM16:
    case FT_HELPER_IRET:
    case FT_HELPER_IRETD:
    case FT_HELPER_IRETQ:
    case FT_HELPER_RETFQ:
        last_ir1_type = (int8_t)IR1_TYPE_RET;
        break;
    case FT_HELPER_SYSCALL:
    case FT_RSM:
    case FT_HELPER_UD0:
    case FT_HELPER_UD1:
    case FT_HELPER_UD2:
    case FT_HELPER_GPF:
    case FT_HELPER_INT:
    case FT_HELPER_INT3:
        last_ir1_type = (int8_t)IR1_TYPE_SYSCALL;
        break;
    default:
        break;
    }
#ifdef QUICKTRANS_LATU
    tb->s_data->next_pc = next_pc;
    tb->s_data->target_pc = target_pc;
#else
    FT_TU_DATA(tb)->x86_next_pc = next_pc;
    FT_TU_DATA(tb)->x86_target_pc = target_pc;
#endif
    tb->s_data->last_ir1_type = last_ir1_type;
#else
    (void)tb;
    (void)fields;
#endif
}

bool latx_fast_decode_tb_for_tu_explore(CPUArchState *env,
                                        TranslationBlock *tb,
                                        int max_insns,
                                        FastTranslatorTuTbMeta *tu_meta)
{
#if defined(CONFIG_LATX_TU)
    target_ulong start_pc = tb->pc;
    target_ulong pc = start_pc;
    FastTemplateFields fields_buf[TCG_MAX_INSNS];
    const FastTemplateRuntimeInfo *meta_buf[TCG_MAX_INSNS];
    int icount = 0;
    unsigned int analysis_candidates = 0;
    bool trace = (ft_startup_flags() & FT_STARTUP_TU_TRACE) != 0;
    int decode_mode = ft_tu_decode_mode(tb);

    if (max_insns == 1) {
        max_insns = TCG_MAX_INSNS;
    }
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    /* An SS load inhibits interrupts only through the next instruction. */
    if (tb->flags & HF_INHIBIT_IRQ_MASK) {
        max_insns = 1;
    }
#endif
    if (!tu_meta) {
        return false;
    }
    memset(tu_meta, 0, sizeof(*tu_meta));
    tu_meta->tb = tb;

    for (;;) {
        uint8_t inst_cache[15];
        FastDecodedFT decoded;
        const FastTemplateDesc *tmpl;
        const FastTemplateRuntimeInfo *meta;
        FastTemplateFields *fields;
        int max_insn_len = sizeof(inst_cache);
        bool is_ending;

        if (icount >= max_insns || max_insn_len <= 0) {
            if (ft_primary_trace_enabled()) {
                fprintf(stderr,
                        "[FT] fd-primary early-stop icount=%d max=%d "
                        "pc=0x%lx len=%d\n",
                        icount, max_insns, (unsigned long)pc, max_insn_len);
            }
            return false;
        }
        if (!ft_decode_x86_window(env, pc, inst_cache, decode_mode, &decoded,
                                  &max_insn_len)) {
            if (trace) {
                fprintf(stderr,
                        "[FT-TU] decode-fail index=%d pc=0x%lx max_len=%d "
                        "mode=%d codeis64=%d bool=0x%x flags=0x%x bytes=",
                        icount, (unsigned long)pc, max_insn_len,
                        decode_mode, CODEIS64, tb->bool_flags, tb->flags);
                for (int j = 0; j < max_insn_len; ++j) {
                    fprintf(stderr, "%02x", inst_cache[j]);
                }
                fprintf(stderr, "\n");
            }
            return false;
        }

        ft_apply_latu_legacy_policy(&decoded);
        tmpl = decoded.tmpl;
        meta = ft_template_runtime_info(tmpl ? tmpl->kind : FT_UNSUPPORTED);
        if (!tmpl || (ft_template_is_helper(tmpl->kind) &&
                      !ft_template_primary_helper_allowed(tmpl->kind))) {
            if (trace) {
                fprintf(stderr,
                        "[FT-TU] miss-insn index=%d pc=0x%lx id=%d "
                        "size=%u kind=%d helper=%d\n",
                        icount, (unsigned long)pc, decoded.fields.id,
                        decoded.fields.size, tmpl ? tmpl->kind : FT_UNSUPPORTED,
                        tmpl ? ft_template_is_helper(tmpl->kind) : 0);
            }
            return false;
        }
        if (ft_debug_skip_template(tmpl->kind, decoded.fields.id,
                                   decoded.fields.address)) {
            return false;
        }
        if (icount > 0 &&
            ft_debug_split_before_template(tmpl->kind,
                                           decoded.fields.address)) {
            break;
        }
        if (!decoded.fields_valid) {
            if (trace) {
                fprintf(stderr,
                        "[FT-TU] field-fail index=%d pc=0x%lx id=%d "
                        "size=%u kind=%d\n",
                        icount, (unsigned long)decoded.fields.address,
                        decoded.fields.id, decoded.fields.size, tmpl->kind);
            }
            return false;
        }
        fields = &decoded.fields;
        fields->skip_flags = false;
        fields->omit_zext32 = false;
        fields->scalar_direct_dst = false;
        fields->atomic_no_barrier = false;
#ifdef CONFIG_LATX_DEBUG
        if (!fast_template_emit_constraints_ok(fields)) {
            return false;
        }
#endif

        analysis_candidates |= ft_analysis_candidates(fields);
        fields_buf[icount] = *fields;
        meta_buf[icount] = meta;
        if (trace) {
            fprintf(stderr,
                    "[FT-TU] pc=0x%lx size=%u id=%d kind=%d "
                    "mode=%d codeis64=%d end=%d term=%d\n",
                    (unsigned long)fields->address, fields->size, fields->id,
                    tmpl->kind, decode_mode, CODEIS64,
                    decoded.is_tb_ending ? 1 : 0,
                    meta->terminal_exit ? 1 : 0);
        }
        {
            FastTemplateEflagMasks masks =
                ft_template_eflag_masks(&fields_buf[icount], meta);
            FastTranslatorTuInsnMeta *insn = &tu_meta->insns[icount];

            insn->fields = fields_buf[icount];
            insn->eflag_use = masks.use;
            insn->eflag_def = masks.def;
            insn->terminal_exit = meta->terminal_exit;
            insn->uses_x87_top = meta->uses_x87_top;
            tu_meta->eflag_use |= masks.use & ~tu_meta->eflag_def;
            tu_meta->eflag_def |= masks.def;
        }
        tb->icount = icount + 1;
        tb->size = fields->address + fields->size - start_pc;
        is_ending = decoded.is_tb_ending;
        icount++;
        pc = fields->address + fields->size;

        if (meta->terminal_exit || is_ending || icount == max_insns) {
            ft_primary_update_last_info(tb, fields);
            break;
        }
    }

    tu_meta->icount = icount;
    tu_meta->eflag_in = ft_analyze_tb_flags(fields_buf, meta_buf, icount,
                                           analysis_candidates, false, false);
    tu_meta->eflag_out = FT_EFLAGS_ALL;
    for (int i = 0; i < icount; ++i) {
        tu_meta->insns[i].fields = fields_buf[i];
    }
    return icount > 0;
#else
    (void)env;
    (void)tb;
    (void)max_insns;
    (void)tu_meta;
    return false;
#endif
}

uint8_t latx_fast_analyze_tu_tb_flags(FastTranslatorTuTbMeta *tu_meta,
                                      uint8_t live_out)
{
    uint8_t pending = live_out;
    bool trace_opt = ft_primary_trace_opt_enabled();
    int count;

    if (!tu_meta) {
        return FT_EFLAGS_ALL;
    }
    count = tu_meta->icount;
    if (count > TCG_MAX_INSNS) {
        count = TCG_MAX_INSNS;
    }
    for (int i = count - 1; i >= 0; --i) {
        FastTranslatorTuInsnMeta *insn = &tu_meta->insns[i];
        FastTemplateFields *fields = &insn->fields;
        uint8_t live_def = insn->eflag_def & pending;

        fields->skip_flags = live_def == 0 && insn->eflag_use == 0;
        fields->scalar_direct_dst = false;
        if (trace_opt) {
            fprintf(stderr,
                    "[FT-OPT] pc=0x%lx id=%d kind=%d alu=%u form=%u "
                    "width=%u mod=%u rm=%u reg=%u imm=%d direct_lhs=%d "
                    "direct_rhs=%d "
                    "use=0x%x def=0x%x pending_before=0x%x "
                    "live_def=0x%x skip=%d\n",
                    (unsigned long)fields->address, fields->id,
                    fields->kind, fields->alu_op, fields->alu_form,
                    fields->alu_width, fields->modrm_mod,
                    fields->modrm_rm_index, fields->modrm_reg_index,
                    fields->imm, fields->direct_cmp_lhs_gpr,
                    fields->direct_cmp_rhs_gpr, insn->eflag_use,
                    insn->eflag_def, pending, live_def, fields->skip_flags);
        }
        pending &= ~insn->eflag_def;
        pending |= insn->eflag_use;
    }
    tu_meta->eflag_in = pending;
    tu_meta->eflag_out = live_out;
    return pending;
}

bool latx_fast_translate_tu_tb_cached(CPUArchState *env,
                                      TranslationBlock *tb,
                                      FastTranslatorTuTbMeta *tu_meta,
                                      int *code_size)
{
#if defined(CONFIG_LATX_TU)
    uint32_t *code = (uint32_t *)tb->tc.ptr;
    int emitted = 0;
    bool x87_top_active = false;
    bool mmx_active = false;
    int count;
    bool tu_trace = (ft_startup_flags() & FT_STARTUP_TU_TRACE) != 0;

    (void)env;
    if (!tb || !tu_meta || !code_size || tu_meta->icount == 0) {
        return false;
    }

    count = tu_meta->icount;
    if (count > TCG_MAX_INSNS) {
        return false;
    }
    tb->icount = count;

    for (int i = 0; i < count; ++i) {
        FastTranslatorTuInsnMeta *insn = &tu_meta->insns[i];
        FastTemplateFields *fields = &insn->fields;
        int insn_emitted;

        /* TU metadata may outlive the CPU thread state used to decode it. */
        fields->atomic_no_barrier = false;
        fields->omit_zext32 = false;
        fields->scalar_direct_dst = false;

        if (ft_template_uses_mmx(fields) &&
            ft_mmx_entry_required(mmx_active)) {
            uint32_t *out = code + emitted;

            ft_emit_enter_mmx(&out);
            emitted = out - code;
            mmx_active = true;
        }
        if (!option_soft_fpu && !x87_top_active && insn->uses_x87_top) {
            uint32_t *out = code + emitted;
            int top_emitted = ft_emit_x87_top_load(&out);

            if (!top_emitted) {
                return false;
            }
            emitted += top_emitted;
            x87_top_active = true;
        }

        {
            uint32_t *out = code + emitted;

            if (ft_primary_debug_live_enabled()) {
                ft_primary_debug_emit_live_regs(&out, fields->address);
            }
            emitted = out - code;
        }

        if (tu_trace) {
            fprintf(stderr,
                    "[FT-TU-EMIT] start index=%d pc=0x%lx id=%d kind=%d "
                    "out=%p\n",
                    i, (unsigned long)fields->address, fields->id,
                    fields->kind, code + emitted);
        }
        insn_emitted = emit_template_fields(fields, tb, fields->address,
                                            code + emitted);
        if (!insn_emitted && !ft_emit_zero_code_allowed(fields)) {
            fprintf(stderr,
                    "[FT] tu-cached emit-fail index=%d pc=0x%lx id=%d "
                    "size=%u kind=%d\n",
                    i, (unsigned long)fields->address, fields->id,
                    fields->size, fields->kind);
            return false;
        }

        emitted += insn_emitted;
        if (fields->kind == FT_EMMS) {
            mmx_active = false;
        }
        if (tu_trace) {
            fprintf(stderr,
                    "[FT-TU-EMIT] done index=%d pc=0x%lx emitted=%d "
                    "total=%d\n",
                    i, (unsigned long)fields->address, insn_emitted,
                    emitted);
        }
        ft_primary_debug_dump_code(fields->address, fields, code, emitted);
        if (!option_soft_fpu && x87_top_active && insn->terminal_exit) {
            uint32_t *out = code + emitted;
            int top_emitted = ft_emit_x87_top_save(&out);

            if (!top_emitted) {
                return false;
            }
            emitted += top_emitted;
            x87_top_active = false;
        }

        ft_set_insn_start_data(i, fields->address);
        ft_set_insn_end_off(i, emitted << 2);

        if (insn->terminal_exit) {
            *code_size = emitted * 4;
            return true;
        }
    }

    {
        uint32_t *out = code + emitted;
        int exit_emitted;

        if (!option_soft_fpu && x87_top_active) {
            int top_emitted = ft_emit_x87_top_save(&out);

            if (!top_emitted) {
                if (ft_primary_trace_enabled()) {
                    fprintf(stderr, "[FT] fd-primary x87-save-fail pc=0x%lx\n",
                            (unsigned long)(tb->pc + tb->size));
                }
                return false;
            }
            emitted += top_emitted;
        }

        exit_emitted =
            ft_emit_direct_link_exit(tb, &out, 0, tb->pc + tb->size, la_t1);

        if (!exit_emitted) {
            if (ft_primary_trace_enabled()) {
                fprintf(stderr,
                        "[FT] fd-primary exit-fail pc=0x%lx next=0x%lx "
                        "icount=%d size=%u emitted=%d\n",
                        (unsigned long)tb->pc,
                        (unsigned long)(tb->pc + tb->size),
                        tb->icount, tb->size, emitted);
            }
            return false;
        }
        emitted += exit_emitted;
    }
    if (emitted <= 0 || tb->icount <= 0) {
        if (ft_primary_trace_enabled()) {
            fprintf(stderr,
                    "[FT] fd-primary empty-output pc=0x%lx icount=%d "
                    "emitted=%d\n",
                    (unsigned long)tb->pc, tb->icount, emitted);
        }
        return false;
    }
    ft_set_insn_end_off(tb->icount - 1, emitted << 2);
    *code_size = emitted * 4;
    return true;
#else
    (void)env;
    (void)tb;
    (void)tu_meta;
    (void)code_size;
    return false;
#endif
}

#ifndef QUICKTRANS_LATU
static bool ft_patch_lats_tu_branch(uint32_t *branch, uint32_t *target)
{
    uint32_t insn = *branch;
    uint32_t opcode = insn & 0xfc000000;
    int rj = (insn >> 5) & 0x1f;
    int rd = insn & 0x1f;

    switch (opcode) {
    case FT_LA_OPCODE_B:
        ft_patch_branch_to(branch, FT_BRANCH_B, 0, 0, target);
        return true;
    case FT_LA_OPCODE_BEQ:
        ft_patch_branch_to(branch, FT_BRANCH_BEQ, rj, rd, target);
        return true;
    case FT_LA_OPCODE_BNE:
        ft_patch_branch_to(branch, FT_BRANCH_BNE, rj, rd, target);
        return true;
    default:
        return false;
    }
}
#endif

bool latx_fast_patch_tu_tb_branches(TranslationBlock *tb)
{
#if defined(CONFIG_LATX_TU) && !defined(QUICKTRANS_LATU)
    for (int index = 0; index < 2; ++index) {
        TranslationBlock *successor;
        uint32_t *branch;

        if (FT_TU_DATA(tb)->tu_jmp[index] == TB_JMP_RESET_OFFSET_INVALID) {
            continue;
        }
        successor = tb->s_data->next_tb[index];
        if (!successor || !successor->tc.ptr) {
            return false;
        }
        branch = (uint32_t *)((uintptr_t)tb->tc.ptr + FT_TU_DATA(tb)->tu_jmp[index]);
        if (!ft_patch_lats_tu_branch(branch, (uint32_t *)successor->tc.ptr)) {
            return false;
        }
        if (ft_startup_flags() & FT_STARTUP_TU_DIRECT_TRACE) {
            fprintf(stderr,
                    "[FT-TU-PATCH] pc=0x%lx slot=%d branch=%p target=%p "
                    "word=%08x delta=%td\n",
                    (unsigned long)tb->pc, index, branch, successor->tc.ptr,
                    *branch, (uint32_t *)successor->tc.ptr - branch);
        }
    }
#else
    (void)tb;
#endif
    return true;
}

#define FT_WITH_RSP_MERGE 1
#define FT_SPECIALIZED_NAME latx_fast_decode_translate_tb_primary_ex_impl
#define FT_SEARCH_NAME ft_encode_search
#define FT_CANDIDATES_NAME ft_analysis_candidates
#include "primary-translate-body.inc.c"
#undef FT_SPECIALIZED_NAME
#undef FT_WITH_RSP_MERGE
#undef FT_SEARCH_NAME
#undef FT_CANDIDATES_NAME

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && defined(LATX_QUICKTRANS_RSP_SEARCH_ABI)
#define FT_WITH_RSP_MERGE 0
#define FT_SPECIALIZED_NAME latx_fast_decode_translate_tb_primary_ex_impl_no_rsp
#define FT_SEARCH_NAME ft_encode_search_no_rsp
#define FT_CANDIDATES_NAME ft_analysis_candidates_no_rsp
#include "primary-translate-body.inc.c"
#undef FT_SPECIALIZED_NAME
#undef FT_WITH_RSP_MERGE
#undef FT_SEARCH_NAME
#undef FT_CANDIDATES_NAME
#endif

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && defined(LATX_QUICKTRANS_RSP_SEARCH_ABI)
/* Selected once while parsing startup options, before any TB is translated. */
static bool (*ft_primary_selected)(CPUArchState *, TranslationBlock *, int,
                                   int *, int *, QuickTransFailure *) =
    latx_fast_decode_translate_tb_primary_ex_impl;
#endif

#ifdef QUICKTRANS_LATU
void latx_fast_set_rsp_merge(bool enabled)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && defined(LATX_QUICKTRANS_RSP_SEARCH_ABI)
    ft_primary_selected = enabled ? latx_fast_decode_translate_tb_primary_ex_impl
                                 : latx_fast_decode_translate_tb_primary_ex_impl_no_rsp;
#else
    (void)enabled;
#endif
}
#endif

#ifndef QUICKTRANS_LATU
static void ft_tb_code_space_init(FtCodeSpace *space, TranslationBlock *tb)
{
    uintptr_t start = (uintptr_t)tcg_splitwx_to_rw(tb->tc.ptr);
    uintptr_t end = (uintptr_t)tcg_ctx->code_gen_highwater;

    ft_code_space_init(space, (uintptr_t)tb->tc.ptr,
                       end > start ? end - start : 0);
}

static int ft_code_space_error(int error)
{
    return error == FT_CODE_TB_TOO_LARGE ? __GENCODE_ERR_TB_TOO_LARGE
                                       : __GENCODE_ERR_BUFFER_OVERFLOW;
}
#endif

bool latx_fast_translate_sample_for_bench(CPUArchState *env,
                                          TranslationBlock *tb,
                                          const uint8_t *bytes, int len,
                                          target_ulong pc, int *code_size,
                                          LatxFastTranslatorBenchStats *stats,
                                          bool detail_stats)
{
#ifndef QUICKTRANS_LATU
    FtCodeSpace space;
    int error;
    bool ok;

    if (!tb || !code_size) {
        return false;
    }
    *code_size = 0;
    ft_tb_code_space_init(&space, tb);
    error = setjmp(space.unwind);
    if (unlikely(error)) {
        ft_code_space_clear();
        *code_size = ft_code_space_error(error);
        return false;
    }
    ok = latx_fast_translate_sample_for_bench_impl(
        env, tb, bytes, len, pc, code_size, stats, detail_stats, &space);
    ft_code_space_clear();
    return ok;
#else
    return latx_fast_translate_sample_for_bench_impl(
        env, tb, bytes, len, pc, code_size, stats, detail_stats);
#endif
}

bool latx_fast_decode_translate_tb_primary_ex(CPUArchState *env,
                                              TranslationBlock *tb,
                                              int max_insns,
                                              int *code_size,
                                              int *search_size,
                                              QuickTransFailure *failure)
{
#ifndef QUICKTRANS_LATU
    FtCodeSpace space;
    int error;
    bool ok;

    if (!tb || !code_size) {
        return false;
    }
    *code_size = 0;
    ft_tb_code_space_init(&space, tb);
    error = setjmp(space.unwind);
    if (unlikely(error)) {
        ft_code_space_clear();
        *code_size = ft_code_space_error(error);
        return false;
    }
    ok = latx_fast_decode_translate_tb_primary_ex_impl(
        env, tb, max_insns, code_size, search_size, failure, &space);
    ft_code_space_clear();
    return ok;
#elif defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && defined(LATX_QUICKTRANS_RSP_SEARCH_ABI)
    return ft_primary_selected(
        env, tb, max_insns, code_size, search_size, failure);
#else
    return latx_fast_decode_translate_tb_primary_ex_impl(
        env, tb, max_insns, code_size, search_size, failure);
#endif
}

bool latx_fast_decode_translate_tb_primary(CPUArchState *env,
                                           TranslationBlock *tb,
                                           int max_insns,
                                           int *code_size,
                                           int *search_size)
{
    return latx_fast_decode_translate_tb_primary_ex(
        env, tb, max_insns, code_size, search_size, NULL);
}

#endif
