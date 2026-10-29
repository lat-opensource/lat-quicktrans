/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */
#include "quicktrans/quicktrans.h"
#include "quicktrans/detail/profile.h"

#include <string.h>

bool quicktrans_profile_exit_cleanup_required(void)
{
#ifdef QUICKTRANS_PROFILE_GENERATE
    return true;
#else
    return false;
#endif
}

void quicktrans_failure_clear(QuickTransFailure *failure)
{
    if (failure != NULL) {
        memset(failure, 0, sizeof(*failure));
        failure->template_kind = -1;
        failure->instruction_index = -1;
    }
}

void quicktrans_failure_record(QuickTransFailure *failure,
                               QuickTransFailureStage stage,
                               QuickTransFailureReason reason, uint64_t pc,
                               const uint8_t *bytes, size_t byte_count,
                               uint16_t instruction_id, int32_t template_kind,
                               int32_t instruction_index)
{
    if (failure == NULL) {
        return;
    }

    quicktrans_failure_clear(failure);
    failure->stage = stage;
    failure->reason = reason;
    failure->pc = pc;
    failure->instruction_id = instruction_id;
    failure->template_kind = template_kind;
    failure->instruction_index = instruction_index;
    if (bytes == NULL) {
        return;
    }
    if (byte_count > QUICKTRANS_FAILURE_MAX_BYTES) {
        byte_count = QUICKTRANS_FAILURE_MAX_BYTES;
    }
    memcpy(failure->bytes, bytes, byte_count);
    failure->byte_count = byte_count;
}

const char *quicktrans_failure_stage_name(QuickTransFailureStage stage)
{
    switch (stage) {
    case QUICKTRANS_FAILURE_STAGE_NONE: return "none";
    case QUICKTRANS_FAILURE_STAGE_FETCH: return "fetch";
    case QUICKTRANS_FAILURE_STAGE_DECODE: return "decode";
    case QUICKTRANS_FAILURE_STAGE_TEMPLATE: return "template";
    case QUICKTRANS_FAILURE_STAGE_CONSTRAINT: return "constraint";
    case QUICKTRANS_FAILURE_STAGE_EMIT: return "emit";
    case QUICKTRANS_FAILURE_STAGE_EXIT: return "exit";
    default: return "unknown";
    }
}

const char *quicktrans_failure_reason_name(QuickTransFailureReason reason)
{
    switch (reason) {
    case QUICKTRANS_FAILURE_REASON_NONE: return "none";
    case QUICKTRANS_FAILURE_REASON_INSN_LIMIT: return "insn-limit";
    case QUICKTRANS_FAILURE_REASON_DECODE_FAILED: return "decode-failed";
    case QUICKTRANS_FAILURE_REASON_TEMPLATE_MISSING: return "template-missing";
    case QUICKTRANS_FAILURE_REASON_HELPER_UNSUPPORTED:
        return "helper-unsupported";
    case QUICKTRANS_FAILURE_REASON_DEBUG_SKIP: return "debug-skip";
    case QUICKTRANS_FAILURE_REASON_FIELDS_INVALID: return "fields-invalid";
    case QUICKTRANS_FAILURE_REASON_MODE_UNSUPPORTED: return "mode-unsupported";
    case QUICKTRANS_FAILURE_REASON_CONSTRAINT_REJECTED:
        return "constraint-rejected";
    case QUICKTRANS_FAILURE_REASON_X87_TOP_LOAD: return "x87-top-load";
    case QUICKTRANS_FAILURE_REASON_INSN_EMIT: return "insn-emit";
    case QUICKTRANS_FAILURE_REASON_X87_TOP_STORE: return "x87-top-store";
    case QUICKTRANS_FAILURE_REASON_DIRECT_EXIT: return "direct-exit";
    case QUICKTRANS_FAILURE_REASON_EMPTY_OUTPUT: return "empty-output";
    case QUICKTRANS_FAILURE_REASON_SEARCH_ALLOC: return "search-alloc";
    case QUICKTRANS_FAILURE_REASON_SEARCH_ENCODE: return "search-encode";
    default: return "unknown";
    }
}
