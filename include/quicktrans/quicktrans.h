/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef QUICKTRANS_H
#define QUICKTRANS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#if defined(QUICKTRANS_BUILD)
#define QUICKTRANS_API __declspec(dllexport)
#else
#define QUICKTRANS_API __declspec(dllimport)
#endif
#else
#define QUICKTRANS_API __attribute__((visibility("default")))
#endif

#define QUICKTRANS_MAX_INSN_BYTES 24
#define QUICKTRANS_FAILURE_MAX_BYTES 15

typedef enum QuickTransStatus {
    QUICKTRANS_OK = 0,
    QUICKTRANS_UNSUPPORTED = 1,
    QUICKTRANS_INVALID_ARGUMENT = 2,
} QuickTransStatus;

typedef enum QuickTransMode {
    QUICKTRANS_MODE_32 = 0,
    QUICKTRANS_MODE_64 = 1,
} QuickTransMode;

typedef enum QuickTransFailureStage {
    QUICKTRANS_FAILURE_STAGE_NONE = 0,
    QUICKTRANS_FAILURE_STAGE_FETCH,
    QUICKTRANS_FAILURE_STAGE_DECODE,
    QUICKTRANS_FAILURE_STAGE_TEMPLATE,
    QUICKTRANS_FAILURE_STAGE_CONSTRAINT,
    QUICKTRANS_FAILURE_STAGE_EMIT,
    QUICKTRANS_FAILURE_STAGE_EXIT,
    QUICKTRANS_FAILURE_STAGE_COUNT,
} QuickTransFailureStage;

typedef enum QuickTransFailureReason {
    QUICKTRANS_FAILURE_REASON_NONE = 0,
    QUICKTRANS_FAILURE_REASON_INSN_LIMIT,
    QUICKTRANS_FAILURE_REASON_DECODE_FAILED,
    QUICKTRANS_FAILURE_REASON_TEMPLATE_MISSING,
    QUICKTRANS_FAILURE_REASON_HELPER_UNSUPPORTED,
    QUICKTRANS_FAILURE_REASON_DEBUG_SKIP,
    QUICKTRANS_FAILURE_REASON_FIELDS_INVALID,
    QUICKTRANS_FAILURE_REASON_MODE_UNSUPPORTED,
    QUICKTRANS_FAILURE_REASON_CONSTRAINT_REJECTED,
    QUICKTRANS_FAILURE_REASON_X87_TOP_LOAD,
    QUICKTRANS_FAILURE_REASON_INSN_EMIT,
    QUICKTRANS_FAILURE_REASON_X87_TOP_STORE,
    QUICKTRANS_FAILURE_REASON_DIRECT_EXIT,
    QUICKTRANS_FAILURE_REASON_EMPTY_OUTPUT,
    QUICKTRANS_FAILURE_REASON_SEARCH_ALLOC,
    QUICKTRANS_FAILURE_REASON_SEARCH_ENCODE,
    QUICKTRANS_FAILURE_REASON_COUNT,
} QuickTransFailureReason;

typedef struct QuickTransFailure {
    QuickTransFailureStage stage;
    QuickTransFailureReason reason;
    uint64_t pc;
    uint8_t bytes[QUICKTRANS_FAILURE_MAX_BYTES];
    uint8_t byte_count;
    uint16_t instruction_id;
    int32_t template_kind;
    int32_t instruction_index;
} QuickTransFailure;

typedef struct QuickTransInsn {
    uint64_t address;
    uint16_t size;
    uint16_t id;
    uint8_t bytes[QUICKTRANS_MAX_INSN_BYTES];
    uint8_t op_count;
} QuickTransInsn;

typedef struct QuickTransTemplateFields {
    int kind;
    int16_t rex;
    int16_t modrm;
    uint8_t sib;
    int8_t segment;
    uint8_t rex_bits;
    uint8_t modrm_mod;
    uint8_t modrm_reg;
    uint8_t modrm_rm;
    uint8_t modrm_reg_index;
    uint8_t modrm_rm_index;
    int32_t disp;
    int32_t imm;
    uint64_t imm64;
    int8_t reg;
    uint8_t size;
    uint64_t address;
    uint16_t id;
    int8_t vex_v;
    uint8_t opcode0;
    uint8_t prefix0;
    uint8_t prefix2;
    uint8_t opcode1;
    uint8_t alu_op;
    uint8_t alu_form;
    uint8_t alu_width;
    bool addr32;
    bool skip_flags;
} QuickTransTemplateFields;

typedef struct QuickTransDecoded {
    QuickTransInsn insn;
    QuickTransTemplateFields fields;
    int template_kind;
    bool has_template;
    bool fields_valid;
    bool is_tb_ending;
    bool direct_fields;
} QuickTransDecoded;

QUICKTRANS_API QuickTransStatus quicktrans_decode(const uint8_t *code,
                                                  size_t code_size,
                                                  uint64_t address,
                                                  QuickTransMode mode,
                                                  QuickTransInsn *out);

QUICKTRANS_API QuickTransStatus quicktrans_decode_template(
    const uint8_t *code, size_t code_size, uint64_t address,
    QuickTransMode mode, QuickTransDecoded *out);

QUICKTRANS_API const char *quicktrans_status_name(QuickTransStatus status);

QUICKTRANS_API void quicktrans_failure_clear(QuickTransFailure *failure);

QUICKTRANS_API void quicktrans_failure_record(
    QuickTransFailure *failure, QuickTransFailureStage stage,
    QuickTransFailureReason reason, uint64_t pc, const uint8_t *bytes,
    size_t byte_count, uint16_t instruction_id, int32_t template_kind,
    int32_t instruction_index);

QUICKTRANS_API const char *quicktrans_failure_stage_name(
    QuickTransFailureStage stage);

QUICKTRANS_API const char *quicktrans_failure_reason_name(
    QuickTransFailureReason reason);

#ifdef __cplusplus
}
#endif

#endif
