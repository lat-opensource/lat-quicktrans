/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef QUICKTRANS_STATS_H
#define QUICKTRANS_STATS_H

#include "quicktrans.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QUICKTRANS_STATS_ENV "LATX_QUICKTRANS_STATS"
#define QUICKTRANS_STATS_DEFAULT_SAMPLE_LIMIT 16

typedef enum QuickTransStatsOutcome {
    QUICKTRANS_STATS_OUTCOME_SUCCESS = 0,
    QUICKTRANS_STATS_OUTCOME_FALLBACK,
    QUICKTRANS_STATS_OUTCOME_FAILED,
} QuickTransStatsOutcome;

typedef struct QuickTransStats QuickTransStats;

QUICKTRANS_API bool quicktrans_stats_requested(void);
QUICKTRANS_API QuickTransStats *quicktrans_stats_create(size_t sample_limit);
QUICKTRANS_API QuickTransStats *quicktrans_stats_create_from_env(void);
QUICKTRANS_API void quicktrans_stats_reset(QuickTransStats *stats);
QUICKTRANS_API void quicktrans_stats_destroy(QuickTransStats *stats);

QUICKTRANS_API void quicktrans_stats_record(
    QuickTransStats *stats, QuickTransStatsOutcome outcome,
    const QuickTransFailure *failure);

QUICKTRANS_API void quicktrans_stats_dump(const QuickTransStats *stats,
                                          FILE *stream);

#ifdef __cplusplus
}
#endif

#endif
