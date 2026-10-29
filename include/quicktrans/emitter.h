/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef QUICKTRANS_EMITTER_H
#define QUICKTRANS_EMITTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#if defined(QUICKTRANS_BUILD)
#define QUICKTRANS_EMITTER_API __declspec(dllexport)
#else
#define QUICKTRANS_EMITTER_API __declspec(dllimport)
#endif
#else
#define QUICKTRANS_EMITTER_API __attribute__((visibility("default")))
#endif

typedef struct QuickTransEmitter {
    uint32_t *begin;
    uint32_t *cursor;
    uint32_t *end;
    bool overflow;
} QuickTransEmitter;

QUICKTRANS_EMITTER_API void quicktrans_emitter_init(
    QuickTransEmitter *emitter, uint32_t *buffer, size_t insn_capacity);
QUICKTRANS_EMITTER_API bool quicktrans_emitter_emit_u32(
    QuickTransEmitter *emitter, uint32_t insn);
QUICKTRANS_EMITTER_API size_t quicktrans_emitter_count(
    const QuickTransEmitter *emitter);

#ifdef __cplusplus
}
#endif

#endif
