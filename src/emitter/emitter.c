/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */
#include "quicktrans/emitter.h"

void quicktrans_emitter_init(QuickTransEmitter *emitter, uint32_t *buffer,
                             size_t insn_capacity)
{
    if (!emitter) {
        return;
    }
    emitter->begin = buffer;
    emitter->cursor = buffer;
    emitter->end = buffer ? buffer + insn_capacity : 0;
    emitter->overflow = false;
}

bool quicktrans_emitter_emit_u32(QuickTransEmitter *emitter, uint32_t insn)
{
    if (!emitter || !emitter->cursor || emitter->cursor >= emitter->end) {
        if (emitter) {
            emitter->overflow = true;
        }
        return false;
    }
    *emitter->cursor++ = insn;
    return true;
}

size_t quicktrans_emitter_count(const QuickTransEmitter *emitter)
{
    if (!emitter || !emitter->begin || !emitter->cursor) {
        return 0;
    }
    return (size_t)(emitter->cursor - emitter->begin);
}
