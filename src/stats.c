/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */
#include "quicktrans/stats.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define QT_STATS_INSN_COUNT (UINT16_MAX + 1u)
#define QT_STATS_TEMPLATE_CAPACITY 1024
#define QT_STATS_TOP_LIMIT 32

typedef struct QuickTransTemplateCount {
    int32_t kind;
    uint64_t count;
    bool used;
} QuickTransTemplateCount;

typedef struct QuickTransStatsSample {
    QuickTransStatsOutcome outcome;
    QuickTransFailure failure;
} QuickTransStatsSample;

typedef struct QuickTransCountEntry {
    int64_t key;
    uint64_t count;
} QuickTransCountEntry;

struct QuickTransStats {
    _Atomic uint64_t attempted;
    _Atomic uint64_t success;
    _Atomic uint64_t fallback;
    _Atomic uint64_t failed;
    atomic_flag failure_lock;
    uint64_t stage_reason[QUICKTRANS_FAILURE_STAGE_COUNT]
                         [QUICKTRANS_FAILURE_REASON_COUNT];
    uint64_t *instruction_counts;
    QuickTransTemplateCount template_counts[QT_STATS_TEMPLATE_CAPACITY];
    QuickTransStatsSample *samples;
    size_t sample_count;
    size_t sample_limit;
};

static bool qt_stats_env_enabled(const char *value)
{
    return value != NULL &&
           (!strcmp(value, "1") || !strcasecmp(value, "true") ||
            !strcasecmp(value, "yes") || !strcasecmp(value, "on"));
}

static void qt_stats_lock(QuickTransStats *stats)
{
    while (atomic_flag_test_and_set_explicit(&stats->failure_lock,
                                             memory_order_acquire)) {
    }
}

static void qt_stats_unlock(QuickTransStats *stats)
{
    atomic_flag_clear_explicit(&stats->failure_lock, memory_order_release);
}

static size_t qt_stats_template_slot(int32_t kind)
{
    return ((uint32_t)kind * UINT32_C(2654435761)) %
           QT_STATS_TEMPLATE_CAPACITY;
}

static void qt_stats_record_template(QuickTransStats *stats, int32_t kind)
{
    size_t start = qt_stats_template_slot(kind);

    for (size_t i = 0; i < QT_STATS_TEMPLATE_CAPACITY; i++) {
        QuickTransTemplateCount *entry =
            &stats->template_counts[(start + i) % QT_STATS_TEMPLATE_CAPACITY];

        if (!entry->used) {
            entry->used = true;
            entry->kind = kind;
            entry->count = 1;
            return;
        }
        if (entry->kind == kind) {
            entry->count++;
            return;
        }
    }
}

QuickTransStats *quicktrans_stats_create(size_t sample_limit)
{
    QuickTransStats *stats = calloc(1, sizeof(*stats));

    if (stats == NULL) {
        return NULL;
    }
    stats->instruction_counts =
        calloc(QT_STATS_INSN_COUNT, sizeof(*stats->instruction_counts));
    if (stats->instruction_counts == NULL) {
        free(stats);
        return NULL;
    }
    if (sample_limit != 0) {
        stats->samples = calloc(sample_limit, sizeof(*stats->samples));
        if (stats->samples == NULL) {
            free(stats->instruction_counts);
            free(stats);
            return NULL;
        }
    }
    stats->sample_limit = sample_limit;
    atomic_flag_clear_explicit(&stats->failure_lock, memory_order_relaxed);
    return stats;
}

bool quicktrans_stats_requested(void)
{
    return qt_stats_env_enabled(getenv(QUICKTRANS_STATS_ENV));
}

QuickTransStats *quicktrans_stats_create_from_env(void)
{
    if (!quicktrans_stats_requested()) {
        return NULL;
    }
    return quicktrans_stats_create(QUICKTRANS_STATS_DEFAULT_SAMPLE_LIMIT);
}

void quicktrans_stats_reset(QuickTransStats *stats)
{
    if (stats == NULL) {
        return;
    }

    atomic_flag_clear_explicit(&stats->failure_lock, memory_order_relaxed);
    atomic_store_explicit(&stats->attempted, 0, memory_order_relaxed);
    atomic_store_explicit(&stats->success, 0, memory_order_relaxed);
    atomic_store_explicit(&stats->fallback, 0, memory_order_relaxed);
    atomic_store_explicit(&stats->failed, 0, memory_order_relaxed);
    memset(stats->stage_reason, 0, sizeof(stats->stage_reason));
    memset(stats->instruction_counts, 0,
           QT_STATS_INSN_COUNT * sizeof(*stats->instruction_counts));
    memset(stats->template_counts, 0, sizeof(stats->template_counts));
    if (stats->samples != NULL) {
        memset(stats->samples, 0,
               stats->sample_limit * sizeof(*stats->samples));
    }
    stats->sample_count = 0;
}

void quicktrans_stats_destroy(QuickTransStats *stats)
{
    if (stats == NULL) {
        return;
    }
    free(stats->samples);
    free(stats->instruction_counts);
    free(stats);
}

void quicktrans_stats_record(QuickTransStats *stats,
                             QuickTransStatsOutcome outcome,
                             const QuickTransFailure *failure)
{
    if (stats == NULL) {
        return;
    }

    atomic_fetch_add_explicit(&stats->attempted, 1, memory_order_relaxed);
    if (outcome == QUICKTRANS_STATS_OUTCOME_SUCCESS) {
        atomic_fetch_add_explicit(&stats->success, 1, memory_order_relaxed);
        return;
    }
    if (outcome == QUICKTRANS_STATS_OUTCOME_FALLBACK) {
        atomic_fetch_add_explicit(&stats->fallback, 1, memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&stats->failed, 1, memory_order_relaxed);
    }
    if (failure == NULL) {
        return;
    }

    qt_stats_lock(stats);
    if (failure->stage > QUICKTRANS_FAILURE_STAGE_NONE &&
        failure->stage < QUICKTRANS_FAILURE_STAGE_COUNT &&
        failure->reason > QUICKTRANS_FAILURE_REASON_NONE &&
        failure->reason < QUICKTRANS_FAILURE_REASON_COUNT) {
        stats->stage_reason[failure->stage][failure->reason]++;
    }
    stats->instruction_counts[failure->instruction_id]++;
    qt_stats_record_template(stats, failure->template_kind);
    if (stats->sample_count < stats->sample_limit) {
        stats->samples[stats->sample_count].outcome = outcome;
        stats->samples[stats->sample_count].failure = *failure;
        stats->sample_count++;
    }
    qt_stats_unlock(stats);
}

static const char *qt_stats_outcome_name(QuickTransStatsOutcome outcome)
{
    switch (outcome) {
    case QUICKTRANS_STATS_OUTCOME_SUCCESS: return "success";
    case QUICKTRANS_STATS_OUTCOME_FALLBACK: return "fallback";
    case QUICKTRANS_STATS_OUTCOME_FAILED: return "failed";
    default: return "unknown";
    }
}

static int qt_stats_compare_counts(const void *left, const void *right)
{
    const QuickTransCountEntry *a = left;
    const QuickTransCountEntry *b = right;

    if (a->count != b->count) {
        return a->count < b->count ? 1 : -1;
    }
    return a->key > b->key ? 1 : a->key < b->key ? -1 : 0;
}

static void qt_stats_dump_instruction_counts(const QuickTransStats *stats,
                                             FILE *stream)
{
    QuickTransCountEntry *entries =
        malloc(QT_STATS_INSN_COUNT * sizeof(*entries));
    size_t count = 0;

    if (entries == NULL) {
        return;
    }
    for (size_t i = 0; i < QT_STATS_INSN_COUNT; i++) {
        if (stats->instruction_counts[i] != 0) {
            entries[count].key = i;
            entries[count].count = stats->instruction_counts[i];
            count++;
        }
    }
    qsort(entries, count, sizeof(*entries), qt_stats_compare_counts);
    if (count > QT_STATS_TOP_LIMIT) {
        count = QT_STATS_TOP_LIMIT;
    }
    for (size_t i = 0; i < count; i++) {
        fprintf(stream, "[QT-STATS] instruction id=%lld count=%llu\n",
                (long long)entries[i].key,
                (unsigned long long)entries[i].count);
    }
    free(entries);
}

static void qt_stats_dump_template_counts(const QuickTransStats *stats,
                                          FILE *stream)
{
    QuickTransCountEntry entries[QT_STATS_TEMPLATE_CAPACITY];
    size_t count = 0;

    for (size_t i = 0; i < QT_STATS_TEMPLATE_CAPACITY; i++) {
        if (stats->template_counts[i].used) {
            entries[count].key = stats->template_counts[i].kind;
            entries[count].count = stats->template_counts[i].count;
            count++;
        }
    }
    qsort(entries, count, sizeof(*entries), qt_stats_compare_counts);
    if (count > QT_STATS_TOP_LIMIT) {
        count = QT_STATS_TOP_LIMIT;
    }
    for (size_t i = 0; i < count; i++) {
        fprintf(stream, "[QT-STATS] template kind=%lld count=%llu\n",
                (long long)entries[i].key,
                (unsigned long long)entries[i].count);
    }
}

static void qt_stats_dump_sample(const QuickTransStatsSample *sample,
                                 size_t index, FILE *stream)
{
    const QuickTransFailure *failure = &sample->failure;
    size_t byte_count = failure->byte_count;

    if (byte_count > QUICKTRANS_FAILURE_MAX_BYTES) {
        byte_count = QUICKTRANS_FAILURE_MAX_BYTES;
    }

    fprintf(stream,
            "[QT-STATS] sample index=%zu outcome=%s stage=%s reason=%s "
            "pc=0x%llx bytes=",
            index, qt_stats_outcome_name(sample->outcome),
            quicktrans_failure_stage_name(failure->stage),
            quicktrans_failure_reason_name(failure->reason),
            (unsigned long long)failure->pc);
    for (size_t i = 0; i < byte_count; i++) {
        fprintf(stream, "%02x", failure->bytes[i]);
    }
    fprintf(stream, " id=%u kind=%d instruction_index=%d\n",
            failure->instruction_id, failure->template_kind,
            failure->instruction_index);
}

void quicktrans_stats_dump(const QuickTransStats *stats, FILE *stream)
{
    uint64_t attempted;
    uint64_t success;
    uint64_t fallback;
    uint64_t failed;
    QuickTransStats *mutable_stats = (QuickTransStats *)stats;

    if (stats == NULL || stream == NULL) {
        return;
    }
    attempted = atomic_load_explicit(&stats->attempted, memory_order_relaxed);
    success = atomic_load_explicit(&stats->success, memory_order_relaxed);
    fallback = atomic_load_explicit(&stats->fallback, memory_order_relaxed);
    failed = atomic_load_explicit(&stats->failed, memory_order_relaxed);
    fprintf(stream,
            "[QT-STATS] summary attempted=%llu success=%llu fallback=%llu "
            "failed=%llu accounted=%llu\n",
            (unsigned long long)attempted, (unsigned long long)success,
            (unsigned long long)fallback, (unsigned long long)failed,
            (unsigned long long)(success + fallback + failed));

    qt_stats_lock(mutable_stats);
    for (int stage = QUICKTRANS_FAILURE_STAGE_FETCH;
         stage < QUICKTRANS_FAILURE_STAGE_COUNT; stage++) {
        for (int reason = QUICKTRANS_FAILURE_REASON_INSN_LIMIT;
             reason < QUICKTRANS_FAILURE_REASON_COUNT; reason++) {
            uint64_t count = stats->stage_reason[stage][reason];

            if (count != 0) {
                fprintf(stream,
                        "[QT-STATS] miss stage=%s reason=%s count=%llu\n",
                        quicktrans_failure_stage_name(stage),
                        quicktrans_failure_reason_name(reason),
                        (unsigned long long)count);
            }
        }
    }
    qt_stats_dump_instruction_counts(stats, stream);
    qt_stats_dump_template_counts(stats, stream);
    for (size_t i = 0; i < stats->sample_count; i++) {
        qt_stats_dump_sample(&stats->samples[i], i, stream);
    }
    qt_stats_unlock(mutable_stats);
    fflush(stream);
}
