/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/*
 * Fast decoder template classification.
 *
 * This file owns the fast_decoder -> fast_translator template boundary:
 * raw bytes are decoded by fast_decoder, then matched to FastTemplateDesc
 * without constructing IR1_INST.
 */

#include <stdint.h>

#ifdef CONFIG_TARGET
#include "common.h"
#endif
#include "quicktrans/detail/fast_decoder.h"
#include "quicktrans/detail/fast-la-emit.h"
#include "quicktrans/detail/latx-disassemble-trace.h"

enum {
    es_index = 0,
    cs_index = 1,
    ss_index = 2,
    ds_index = 3,
    fs_index = 4,
    gs_index = 5,
};

enum {
    COND_A = 0,
    COND_AE = 1,
    COND_B = 2,
    COND_BE = 3,
    COND_E = 4,
    COND_NE = 5,
    COND_G = 6,
    COND_GE = 7,
    COND_L = 8,
    COND_LE = 9,
    COND_S = 10,
    COND_NS = 11,
    COND_O = 12,
    COND_NO = 13,
    COND_PE = 14,
    COND_PO = 15,
};

enum {
    la_zero = 0,
};

const FastTemplateDesc fast_templates[FT_KIND_COUNT] = {
    /* Directly decoded legacy far loads still need their runtime kind. */
    [FT_LDS] = { .id = dt_X86_INS_LDS, .kind = FT_LDS,
                 .meta_flags = FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_LES] = { .id = dt_X86_INS_LES, .kind = FT_LES,
                 .meta_flags = FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_LSS] = { .id = dt_X86_INS_LSS, .kind = FT_LSS,
                 .meta_flags = FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_XOR_RM_GPR_ZERO] =
        { 2, 0, 0, 0x31, 0x00, 2, { 0x31, 0xc0 }, { 0xff, 0xff },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_XOR,
          FT_XOR_RM_GPR_ZERO, FT_TM_NO_EXTRA_CONSTRAINTS | FT_TM_READS_RAW_MODRM },
    [FT_MOV_RM64_R64] =
        { 3, 0, 0, 0x89, 0x00, 1, { 0x48, 0x89, 0xc0 },
          { 0xf8, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOV, FT_MOV_RM64_R64 },
    [FT_MOV_R64_RM64] =
        { 5, 0, 0, 0x8b, 0x00, 1, { 0x48, 0x8b, 0x44, 0x24, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0 }, 0x48, 0x44, 4, 1, -1, 0,
          dt_X86_INS_MOV, FT_MOV_R64_RM64 },
    [FT_LEA_R64_M] =
        { 7, 0, 0, 0x8d, 0x00, 2, { 0x48, 0x8d, 0x05 },
          { 0xff, 0xff, 0xff, 0, 0, 0, 0 }, 0x48, 0x05, 3, 4, -1,
          0, dt_X86_INS_LEA, FT_LEA_R64_M },
    [FT_ADD_R64_IMM8] =
        { 4, 0, 0, 0x83, 0x00, 3, { 0x48, 0x83, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0 }, 0x48, 0xc0, -1, 0, 3, 1,
          dt_X86_INS_ADD, FT_ADD_R64_IMM8 },
    [FT_SUB_EAX_IMM32] =
        { 5, 0, 0, 0x2d, 0x00, 4, { 0x2d },
          { 0xff, 0, 0, 0, 0 }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_SUB, FT_SUB_EAX_IMM32 },
    [FT_TEST_RM16_IMM16] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0xf7, 0x00, 3,
          { 0x66, 0xf7, 0x03 }, { 0xff, 0xff, 0xff, 0, 0 },
          -1, 0x03, -1, 0, 3, 2, dt_X86_INS_TEST,
          FT_TEST_RM16_IMM16 },
    [FT_TEST_AL_IMM8] =
        { 2, 0, 0, 0xa8, 0x00, 1, { 0xa8, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_TEST, FT_TEST_AL_IMM8 },
    [FT_TEST_EAX_IMM32] =
        { 5, 0, 0, 0xa9, 0x00, 1, { 0xa9, 0, 0, 0, 0 },
          { 0xff, 0, 0, 0, 0 }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_TEST, FT_TEST_EAX_IMM32 },
    [FT_TEST_RAX_IMM32] =
        { 6, 0, 0, 0xa9, 0x00, 1, { 0x48, 0xa9, 0, 0, 0, 0 },
          { 0xff, 0xff, 0, 0, 0, 0 }, 0x48, -1, -1, 0, 2, 4,
          dt_X86_INS_TEST, FT_TEST_RAX_IMM32 },
    [FT_ADD_AL_IMM8] =
        { 2, 0, 0, 0x04, 0x00, 5, { 0x04, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_ADD, FT_ADD_AL_IMM8 },
    [FT_ADC_AL_IMM8] =
        { 2, 0, 0, 0x14, 0x00, 5, { 0x14, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_ADC, FT_ADC_AL_IMM8 },
    [FT_JCC_REL] =
        { 6, 0, 0, 0x0f, 0x85, 6, { 0x0f, 0x85 },
          { 0xff, 0xff, 0, 0, 0, 0 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_JNE, FT_JCC_REL, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_PUSH_IMM32] =
        { 5, 0, 0, 0x68, 0x00, 4, { 0x68 }, { 0xff, 0, 0, 0, 0 },
          -1, -1, -1, 0, 1, 4, dt_X86_INS_PUSH, FT_PUSH_IMM32 },
    [FT_PUSH_IMM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x68, 0x00, 4,
          { 0x66, 0x68, 0, 0 }, { 0xff, 0xff, 0, 0 },
          -1, -1, -1, 0, 2, 2, dt_X86_INS_PUSH, FT_PUSH_IMM16 },
    [FT_PUSH_IMM8] =
        { 2, 0, 0, 0x6a, 0x00, 4, { 0x6a, 0 }, { 0xff, 0 },
          -1, -1, -1, 0, 1, 1, dt_X86_INS_PUSH, FT_PUSH_IMM8, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_RET_IMM16] =
        { 3, 0, 0, 0xc2, 0x00, 36, { 0xc2 }, { 0xff, 0, 0 },
          -1, -1, -1, 0, 1, 2, dt_X86_INS_RET, FT_RET_IMM16, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_IMUL_R64_RM64] =
        { 4, 0, 0, 0x0f, 0xaf, 3,
          { 0x48, 0x0f, 0xaf, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_IMUL, FT_IMUL_R64_RM64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_IMUL_R64_RM64_IMM32] =
        { 7, 0, 0, 0x69, 0x00, 4,
          { 0x48, 0x69, 0xc0, 0, 0, 0, 0 },
          { 0xff, 0xff, 0xc0, 0, 0, 0, 0 }, 0x48, 0xc0, -1, 0, 3, 4,
          dt_X86_INS_IMUL, FT_IMUL_R64_RM64_IMM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_IMUL_R32_RM32] =
        { 3, 0, 0, 0x0f, 0xaf, 3,
          { 0x0f, 0xaf, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_IMUL, FT_IMUL_R32_RM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_IMUL_R32_RM32_IMM32] =
        { 6, 0, 0, 0x69, 0x00, 4,
          { 0x69, 0xc0, 0, 0, 0, 0 },
          { 0xff, 0xc0, 0, 0, 0, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_IMUL, FT_IMUL_R32_RM32_IMM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_IMUL_R32_RM32_IMM8] =
        { 3, 0, 0, 0x6b, 0x00, 4,
          { 0x6b, 0xc0, 0 },
          { 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, 2, 1,
          dt_X86_INS_IMUL, FT_IMUL_R32_RM32_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_IMUL_R64_RM64_IMM8] =
        { 4, 0, 0, 0x6b, 0x00, 4,
          { 0x48, 0x6b, 0xc0, 0 },
          { 0xf8, 0xff, 0xc0, 0 }, 0x48, 0xc0, -1, 0, 3, 1,
          dt_X86_INS_IMUL, FT_IMUL_R64_RM64_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_IMUL_R16_RM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xaf, 3,
          { 0x66, 0x0f, 0xaf, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_IMUL, FT_IMUL_R16_RM16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_IMUL_R16_RM16_IMM16] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x69, 0x00, 4,
          { 0x66, 0x69, 0xc0, 0, 0 },
          { 0xff, 0xff, 0xc0, 0, 0 }, -1, 0xc0, -1, 0, 3, 2,
          dt_X86_INS_IMUL, FT_IMUL_R16_RM16_IMM16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_IMUL_R16_RM16_IMM8] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x6b, 0x00, 4,
          { 0x66, 0x6b, 0xc0, 0 },
          { 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, 3, 1,
          dt_X86_INS_IMUL, FT_IMUL_R16_RM16_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CDQE] =
        { 2, 0, 0, 0x98, 0x00, 1, { 0x48, 0x98 },
          { 0xff, 0xff }, 0x48, -1, -1, 0, -1, 0,
          dt_X86_INS_CDQE, FT_CDQE, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CQO] =
        { 2, 0, 0, 0x99, 0x00, 1, { 0x48, 0x99 },
          { 0xff, 0xff }, 0x48, -1, -1, 0, -1, 0,
          dt_X86_INS_CQO, FT_CQO, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CBW] =
        { 2, 0, dt_X86_PREFIX_OPSIZE, 0x98, 0x00, 3, { 0x66, 0x98 },
          { 0xff, 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_CBW, FT_CBW, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CWDE] =
        { 1, 0, 0, 0x98, 0x00, 3, { 0x98 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_CWDE, FT_CWDE, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CWD] =
        { 2, 0, dt_X86_PREFIX_OPSIZE, 0x99, 0x00, 3, { 0x66, 0x99 },
          { 0xff, 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_CWD, FT_CWD, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CDQ] =
        { 1, 0, 0, 0x99, 0x00, 2, { 0x99 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_CDQ, FT_CDQ, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_XLATB] =
        { 1, 0, 0, 0xd7, 0x00, 1, { 0xd7 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_XLATB, FT_XLATB,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MOVSX_R64_RM8] =
        { 6, 0, 0, 0x0f, 0xbe, 2,
          { 0x4c, 0x0f, 0xbe, 0x44, 0x24, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xff, 0 }, 0x4c, 0x44, 5, 1,
          -1, 0, dt_X86_INS_MOVSX, FT_MOVSX_R64_RM8 },
    [FT_MOVSX_R32_RM8] =
        { 3, 0, 0, 0x0f, 0xbe, 2,
          { 0x0f, 0xbe, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVSX, FT_MOVSX_R32_RM8 },
    [FT_MOVSX_R16_RM8] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xbe, 2,
          { 0x66, 0x0f, 0xbe, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVSX, FT_MOVSX_R16_RM8 },
    [FT_MOVSX_R64_RM16] =
        { 4, 0, 0, 0x0f, 0xbf, 2,
          { 0x48, 0x0f, 0xbf, 0xc0 },
          { 0xf8, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVSX, FT_MOVSX_R64_RM16 },
    [FT_MOVSX_R32_RM16] =
        { 3, 0, 0, 0x0f, 0xbf, 2,
          { 0x0f, 0xbf, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVSX, FT_MOVSX_R32_RM16 },
    [FT_MOVSX_R16_RM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xbf, 2,
          { 0x66, 0x0f, 0xbf, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVSX, FT_MOVSX_R16_RM16 },
    [FT_MOVQ_XMM_RM64] =
        { 5, dt_X86_PREFIX_REP, 0, 0x0f, 0x7e, 2,
          { 0xf3, 0x0f, 0x7e, 0x43, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0 }, -1, 0x43, 4, 1, -1, 0,
          dt_X86_INS_MOVQ, FT_MOVQ_XMM_RM64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MOVQ_MMX_RM64] =
        { 3, 0, 0, 0x0f, 0x6f, 2,
          { 0x0f, 0x6f, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_MOVQ,
          FT_MOVQ_MMX_RM64 },
    [FT_MOVQ_RM64_XMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xd6, 1,
          { 0x66, 0x0f, 0xd6, 0x43, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0 }, -1, 0x43, 4, 1, -1, 0,
          dt_X86_INS_MOVQ, FT_MOVQ_RM64_XMM, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MOVQ_RM64_MMX] =
        { 4, 0, 0, 0x0f, 0x7e, 2,
          { 0x48, 0x0f, 0x7e, 0xc0 }, { 0xf8, 0xff, 0xff, 0xc0 },
          0x48, 0xc0, -1, 0, -1, 0, dt_X86_INS_MOVQ,
          FT_MOVQ_RM64_MMX,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOVQ_MMXM64_MMX] =
        { 3, 0, 0, 0x0f, 0x7f, 2,
          { 0x0f, 0x7f, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_MOVQ,
          FT_MOVQ_MMXM64_MMX,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOVD_XMM_R32] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x6e, 2,
          { 0x66, 0x0f, 0x6e, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVD, FT_MOVD_XMM_R32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOVD_R32_XMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x7e, 1,
          { 0x66, 0x0f, 0x7e, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVD, FT_MOVD_R32_XMM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOVD_MMX_RM32] =
        { 3, 0, 0, 0x0f, 0x6e, 2,
          { 0x0f, 0x6e, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_MOVD,
          FT_MOVD_MMX_RM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOVD_RM32_MMX] =
        { 3, 0, 0, 0x0f, 0x7e, 1,
          { 0x0f, 0x7e, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_MOVD,
          FT_MOVD_RM32_MMX,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOVQ_MMX_RM64_GPR] =
        { 4, 0, 0, 0x0f, 0x6e, 2,
          { 0x48, 0x0f, 0x6e, 0xc0 }, { 0xf8, 0xff, 0xff, 0xc0 },
          0x48, 0xc0, -1, 0, -1, 0, dt_X86_INS_MOVQ,
          FT_MOVQ_MMX_RM64_GPR,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOVQ_XMM_R64] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x6e, 2,
          { 0x66, 0x48, 0x0f, 0x6e, 0xc0 },
          { 0xff, 0xf8, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_MOVQ, FT_MOVQ_XMM_R64 },
    [FT_MOVQ_R64_XMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x7e, 2,
          { 0x66, 0x48, 0x0f, 0x7e, 0xc0 },
          { 0xff, 0xf8, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_MOVQ, FT_MOVQ_R64_XMM },
    [FT_PEXTRQ_R64_XMM_IMM8] =
        { 7, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 2,
          { 0x66, 0x48, 0x0f, 0x3a, 0x16, 0xc0, 0 },
          { 0xff, 0xf8, 0xff, 0xff, 0xff, 0xc0, 0 }, 0x48, 0xc0,
          -1, 0, 6, 1, dt_X86_INS_PEXTRQ, FT_PEXTRQ_R64_XMM_IMM8 },
    [FT_PEXTRW_R32_XMM_IMM8] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xc5, 1,
          { 0x66, 0x0f, 0xc5, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, 4, 1,
          dt_X86_INS_PEXTRW, FT_PEXTRW_R32_XMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_ONLY },
    [FT_PEXTRW_SSE41_RM16_XMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 2,
          { 0x66, 0x0f, 0x3a, 0x15, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, 5, 1,
          dt_X86_INS_PEXTRW, FT_PEXTRW_SSE41_RM16_XMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PEXTRW_R32_MMX_IMM8] =
        { 4, 0, 0, 0x0f, 0xc5, 1,
          { 0x0f, 0xc5, 0xc0, 0 }, { 0xff, 0xff, 0xc0, 0 },
          -1, 0xc0, -1, 0, 3, 1,
          dt_X86_INS_PEXTRW, FT_PEXTRW_R32_MMX_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY },
    [FT_PINSRW_MMX_RM16_IMM8] =
        { 4, 0, 0, 0x0f, 0xc4, 1,
          { 0x0f, 0xc4, 0xc0, 0 }, { 0xff, 0xff, 0xc0, 0 },
          -1, 0xc0, -1, 0, 3, 1,
          dt_X86_INS_PINSRW, FT_PINSRW_MMX_RM16_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PEXTR_GPR_XMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x14, 2,
          { 0x66, 0x0f, 0x3a, 0x14, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, 5, 1,
          dt_X86_INS_PEXTRB, FT_PEXTR_GPR_XMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8 |
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PINSR_XMM_GPR_IMM8] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xc4, 1,
          { 0x66, 0x0f, 0xc4, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, 4, 1,
          dt_X86_INS_PINSRW, FT_PINSR_XMM_GPR_IMM8 },
    [FT_CVTDQ2PD_XMM_XMM] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0xe6, 1,
          { 0xf3, 0x0f, 0xe6, 0xe0 }, { 0xff, 0xff, 0xff, 0xff },
          -1, 0xe0, -1, 0, -1, 0, dt_X86_INS_CVTDQ2PD,
          FT_CVTDQ2PD_XMM_XMM, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CVTPI2PD_XMM_MMX] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x2a, 4,
          { 0x66, 0x0f, 0x2a, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTPI2PD,
          FT_CVTPI2PD_XMM_MMX },
    [FT_CVTSI2SS_XMM_RM] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0x2a, 2,
          { 0xf3, 0x0f, 0x2a, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTSI2SS,
          FT_CVTSI2SS_XMM_RM },
    [FT_CVTSI2SD_XMM_RM] =
        { 4, dt_X86_PREFIX_REPNE, 0, 0x0f, 0x2a, 2,
          { 0xf2, 0x0f, 0x2a, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTSI2SD,
          FT_CVTSI2SD_XMM_RM },
    [FT_CVTTSS2SI_GPR_XMMM] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0x2c, 2,
          { 0xf3, 0x0f, 0x2c, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTTSS2SI,
          FT_CVTTSS2SI_GPR_XMMM },
    [FT_CVTSS2SI_GPR_XMMM] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0x2d, 2,
          { 0xf3, 0x0f, 0x2d, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTSS2SI,
          FT_CVTSS2SI_GPR_XMMM },
    [FT_CVTTSD2SI_GPR_XMMM] =
        { 4, dt_X86_PREFIX_REPNE, 0, 0x0f, 0x2c, 2,
          { 0xf2, 0x0f, 0x2c, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTTSD2SI,
          FT_CVTTSD2SI_GPR_XMMM },
    [FT_CVTSD2SI_GPR_XMMM] =
        { 4, dt_X86_PREFIX_REPNE, 0, 0x0f, 0x2d, 2,
          { 0xf2, 0x0f, 0x2d, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTSD2SI,
          FT_CVTSD2SI_GPR_XMMM },
    [FT_CVT_FP_XMM_XMMM] =
        { 3, 0, 0, 0x0f, 0x5a, 1,
          { 0x0f, 0x5a, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTPS2PD,
          FT_CVT_FP_XMM_XMMM },
    [FT_CVTPI2PS_XMM_MMX] =
        { 3, 0, 0, 0x0f, 0x2a, 4,
          { 0x0f, 0x2a, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTPI2PS,
          FT_CVTPI2PS_XMM_MMX },
    [FT_CVT_FP2I_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x5b, 1,
          { 0x66, 0x0f, 0x5b, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTPS2DQ,
          FT_CVT_FP2I_XMM_XMMM },
    [FT_CVT_FP2I_MMX_XMMM] =
        { 3, 0, 0, 0x0f, 0x2d, 4,
          { 0x0f, 0x2d, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CVTPS2PI,
          FT_CVT_FP2I_MMX_XMMM },
    [FT_EMMS] =
        { 2, 0, 0, 0x0f, 0x77, 6, { 0x0f, 0x77 },
          { 0xff, 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_EMMS, FT_EMMS, FT_TM_CONSTRAINTS_DECLARED },
    [FT_ADDPD_XMM_XMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x58, 1,
          { 0x66, 0x0f, 0x58, 0xc1 }, { 0xff, 0xff, 0xff, 0xff },
          -1, 0xc1, -1, 0, -1, 0, dt_X86_INS_ADDPD,
          FT_ADDPD_XMM_XMM, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MULPD_XMM_XMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x59, 1,
          { 0x66, 0x0f, 0x59, 0xc1 }, { 0xff, 0xff, 0xff, 0xff },
          -1, 0xc1, -1, 0, -1, 0, dt_X86_INS_MULPD,
          FT_MULPD_XMM_XMM, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_UNPCKPD_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x14, 1,
          { 0x66, 0x0f, 0x14, 0xc0 }, { 0xff, 0xff, 0xfe, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_UNPCKLPD,
          FT_UNPCKPD_XMM_XMMM },
    [FT_MOVAPD_XMM_M128] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x28, 2,
          { 0x66, 0x0f, 0x28, 0x04, 0x01 },
          { 0xff, 0xff, 0xff, 0xff, 0xff }, -1, 0x04, -1, 0,
          -1, 0, dt_X86_INS_MOVAPD, FT_MOVAPD_XMM_M128, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MOV128_XMM_XMMM] =
        { 3, 0, 0, 0x0f, 0x28, 1, { 0x0f, 0x28, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVAPS, FT_MOV128_XMM_XMMM, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MOV128_XMMM_XMM] =
        { 3, 0, 0, 0x0f, 0x29, 1, { 0x0f, 0x29, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVAPS, FT_MOV128_XMMM_XMM, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_PXOR_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xef, 1,
          { 0x66, 0x0f, 0xef, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PXOR,
          FT_PXOR_XMM_XMMM },
    [FT_PADD_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xfc, 1,
          { 0x66, 0x0f, 0xfc, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDB,
          FT_PADD_XMM_XMMM },
    [FT_PADDQ_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xd4, 1,
          { 0x66, 0x0f, 0xd4, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDQ,
          FT_PADDQ_XMM_XMMM },
    [FT_PMULUDQ_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xf4, 1,
          { 0x66, 0x0f, 0xf4, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMULUDQ,
          FT_PMULUDQ_XMM_XMMM },
    [FT_PCMPEQB_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x74, 1,
          { 0x66, 0x0f, 0x74, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PCMPEQB,
          FT_PCMPEQB_XMM_XMMM },
    [FT_PMOVMSKB_R32_XMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xd7, 3,
          { 0x66, 0x0f, 0xd7, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMOVMSKB,
          FT_PMOVMSKB_R32_XMM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY },
    [FT_PMOVMSKB_R32_MMX] =
        { 3, 0, 0, 0x0f, 0xd7, 3,
          { 0x0f, 0xd7, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMOVMSKB,
          FT_PMOVMSKB_R32_MMX,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY },
    [FT_MASKMOVDQU_XMM_XMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xf7, 1,
          { 0x66, 0x0f, 0xf7, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_MASKMOVDQU,
          FT_MASKMOVDQU_XMM_XMM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY,
          FT_TM_ADDR_REG },
    [FT_MASKMOVQ_MMX_MMX] =
        { 3, 0, 0, 0x0f, 0xf7, 1,
          { 0x0f, 0xf7, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_MASKMOVQ,
          FT_MASKMOVQ_MMX_MMX,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY,
          FT_TM_ADDR_REG },
    [FT_SIMD_BIN_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x66, 1,
          { 0x66, 0x0f, 0x66, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PCMPGTD,
          FT_SIMD_BIN_XMM_XMMM },
    [FT_PUNPCK_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x60, 1,
          { 0x66, 0x0f, 0x60, 0xc0 }, { 0xff, 0xff, 0xf0, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PUNPCKLBW,
          FT_PUNPCK_XMM_XMMM },
    [FT_PACK_XMM_XMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x63, 1,
          { 0x66, 0x0f, 0x63, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PACKSSWB,
          FT_PACK_XMM_XMM },
    [FT_SIMD_MADD_XMM_XMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xf5, 1,
          { 0x66, 0x0f, 0xf5, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMADDWD,
          FT_SIMD_MADD_XMM_XMM, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSRLQ_XMM_IMM8] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x73, 1,
          { 0x66, 0x0f, 0x73, 0xd0, 0 },
          { 0xff, 0xff, 0xff, 0xf8, 0 }, -1, 0xd0, -1, 0, -1, 0,
          dt_X86_INS_PSRLQ, FT_PSRLQ_XMM_IMM8 },
    [FT_PSLLQ_XMM_IMM8] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x73, 1,
          { 0x66, 0x0f, 0x73, 0xf0, 0 },
          { 0xff, 0xff, 0xff, 0xf8, 0 }, -1, 0xf0, -1, 0, -1, 0,
          dt_X86_INS_PSLLQ, FT_PSLLQ_XMM_IMM8 },
    [FT_PSHIFT_XMM_IMM8] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x71, 1,
          { 0x66, 0x0f, 0x71, 0xd0, 0 },
          { 0xff, 0xff, 0xfc, 0xc0, 0 }, -1, 0xd0, -1, 0, -1, 0,
          dt_X86_INS_PSRLW, FT_PSHIFT_XMM_IMM8 },
    [FT_PALIGNR_XMM_XMMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 5,
          { 0x66, 0x0f, 0x3a, 0x0f, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PALIGNR, FT_PALIGNR_XMM_XMMM_IMM8 },
    [FT_PALIGNR_MMX_MMXM64_IMM8] =
        { 5, 0, 0, 0x0f, 0x3a, 5,
          { 0x0f, 0x3a, 0x0f, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PALIGNR, FT_PALIGNR_MMX_MMXM64_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SHUF_XMM_XMMM_IMM8] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x70, 2,
          { 0x66, 0x0f, 0x70, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_PSHUFD, FT_SHUF_XMM_XMMM_IMM8 },
    [FT_BLEND_XMM_XMMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 2,
          { 0x66, 0x0f, 0x3a, 0x0c, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_BLENDPS, FT_BLEND_XMM_XMMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_BLENDV_XMM_XMMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x38, 2,
          { 0x66, 0x0f, 0x38, 0x10, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PBLENDVB, FT_BLENDV_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSHUFB_XMM_XMMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x38, 5,
          { 0x66, 0x0f, 0x38, 0x00, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PSHUFB, FT_PSHUFB_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSHUFB_MMX_MMXM64] =
        { 4, 0, 0, 0x0f, 0x38, 5,
          { 0x0f, 0x38, 0x00, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PSHUFB, FT_PSHUFB_MMX_MMXM64,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PHADD_SUB_XMM_XMMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x38, 3,
          { 0x66, 0x0f, 0x38, 0x01, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PHADDW, FT_PHADD_SUB_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PHADD_SUB_MMX_MMXM64] =
        { 4, 0, 0, 0x0f, 0x38, 3,
          { 0x0f, 0x38, 0x01, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PHADDW, FT_PHADD_SUB_MMX_MMXM64,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SIMD_MADD_MMX_MMXM64] =
        { 4, 0, 0, 0x0f, 0x38, 3,
          { 0x0f, 0x38, 0x04, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PMADDUBSW, FT_SIMD_MADD_MMX_MMXM64,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SIMD_BIN_MMX_MMXM64] =
        { 4, 0, 0, 0x0f, 0x38, 3,
          { 0x0f, 0x38, 0x08, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PSIGNB, FT_SIMD_BIN_MMX_MMXM64,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_HADD_SUB_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x7c, 3,
          { 0x66, 0x0f, 0x7c, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_HADDPD, FT_HADD_SUB_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOVDUP_XMM_XMMM] =
        { 4, dt_X86_PREFIX_REPNE, 0, 0x0f, 0x12, 1,
          { 0xf2, 0x0f, 0x12, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_MOVDDUP, FT_MOVDUP_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSADBW_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xf6, 4,
          { 0x66, 0x0f, 0xf6, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PSADBW, FT_PSADBW_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MPSADBW_XMM_XMMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 12,
          { 0x66, 0x0f, 0x3a, 0x42, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_MPSADBW, FT_MPSADBW_XMM_XMMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PMOVX_XMM_XMMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x38, 4,
          { 0x66, 0x0f, 0x38, 0x20, 0xc0 },
          { 0xff, 0xff, 0xff, 0xf0, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PMOVSXBW, FT_PMOVX_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PTEST_XMM_XMMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x38, 10,
          { 0x66, 0x0f, 0x38, 0x17, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PTEST, FT_PTEST_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_INSERTPS_XMM_XMMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 6,
          { 0x66, 0x0f, 0x3a, 0x21, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_INSERTPS, FT_INSERTPS_XMM_XMMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_EXTRACTPS_RM32_XMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 6,
          { 0x66, 0x0f, 0x3a, 0x17, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_EXTRACTPS, FT_EXTRACTPS_RM32_XMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSHUFW_MMX_MMXM_IMM8] =
        { 4, 0, 0, 0x0f, 0x70, 1,
          { 0x0f, 0x70, 0xc0, 0 },
          { 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PSHUFW, FT_PSHUFW_MMX_MMXM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSHIFT_MMX_IMM8] =
        { 4, 0, 0, 0x0f, 0x71, 1,
          { 0x0f, 0x71, 0xd0, 0 },
          { 0xff, 0xfc, 0xc0, 0 }, -1, 0xd0, -1, 0,
          -1, 0, dt_X86_INS_PSRLW, FT_PSHIFT_MMX_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG },
    [FT_PSUBB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xf8, 2,
          { 0x0f, 0xf8, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSUBB,
          FT_PSUBB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSUBW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xf9, 2,
          { 0x0f, 0xf9, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSUBW,
          FT_PSUBW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSUBD_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xfa, 2,
          { 0x0f, 0xfa, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSUBD,
          FT_PSUBD_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSUBQ_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xfb, 2,
          { 0x0f, 0xfb, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSUBQ,
          FT_PSUBQ_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSUBSB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xe8, 2,
          { 0x0f, 0xe8, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSUBSB,
          FT_PSUBSB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSUBSW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xe9, 2,
          { 0x0f, 0xe9, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSUBSW,
          FT_PSUBSW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSUBUSB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xd8, 2,
          { 0x0f, 0xd8, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSUBUSB,
          FT_PSUBUSB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSUBUSW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xd9, 2,
          { 0x0f, 0xd9, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSUBUSW,
          FT_PSUBUSW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PADDSB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xec, 2,
          { 0x0f, 0xec, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDSB,
          FT_PADDSB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PADDSW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xed, 2,
          { 0x0f, 0xed, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDSW,
          FT_PADDSW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PADDUSB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xdc, 2,
          { 0x0f, 0xdc, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDUSB,
          FT_PADDUSB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PADDUSW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xdd, 2,
          { 0x0f, 0xdd, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDUSW,
          FT_PADDUSW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PAVGB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xe0, 2,
          { 0x0f, 0xe0, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PAVGB,
          FT_PAVGB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PAVGW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xe3, 2,
          { 0x0f, 0xe3, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PAVGW,
          FT_PAVGW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PAND_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xdb, 2,
          { 0x0f, 0xdb, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PAND,
          FT_PAND_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PANDN_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xdf, 2,
          { 0x0f, 0xdf, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PANDN,
          FT_PANDN_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_POR_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xeb, 2,
          { 0x0f, 0xeb, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_POR,
          FT_POR_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PXOR_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xef, 2,
          { 0x0f, 0xef, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PXOR,
          FT_PXOR_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSADBW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xf6, 2,
          { 0x0f, 0xf6, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSADBW,
          FT_PSADBW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PCMPGTB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0x64, 2,
          { 0x0f, 0x64, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PCMPGTB,
          FT_PCMPGTB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PCMPGTW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0x65, 2,
          { 0x0f, 0x65, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PCMPGTW,
          FT_PCMPGTW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PCMPGTD_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0x66, 2,
          { 0x0f, 0x66, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PCMPGTD,
          FT_PCMPGTD_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PCMPEQB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0x74, 2,
          { 0x0f, 0x74, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PCMPEQB,
          FT_PCMPEQB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PCMPEQW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0x75, 2,
          { 0x0f, 0x75, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PCMPEQW,
          FT_PCMPEQW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PCMPEQD_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0x76, 2,
          { 0x0f, 0x76, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PCMPEQD,
          FT_PCMPEQD_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PMULLW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xd5, 2,
          { 0x0f, 0xd5, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMULLW,
          FT_PMULLW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PMULHW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xe5, 2,
          { 0x0f, 0xe5, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMULHW,
          FT_PMULHW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PMULHUW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xe4, 2,
          { 0x0f, 0xe4, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMULHUW,
          FT_PMULHUW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSRAW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xe1, 2,
          { 0x0f, 0xe1, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSRAW,
          FT_PSRAW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSRAD_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xe2, 2,
          { 0x0f, 0xe2, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PSRAD,
          FT_PSRAD_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PACKSSDW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0x6b, 2,
          { 0x0f, 0x6b, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PACKSSDW,
          FT_PACKSSDW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PACKSSWB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0x63, 2,
          { 0x0f, 0x63, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PACKSSWB,
          FT_PACKSSWB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PACKUSWB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0x67, 2,
          { 0x0f, 0x67, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PACKUSWB,
          FT_PACKUSWB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PMADDWD_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xf5, 2,
          { 0x0f, 0xf5, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMADDWD,
          FT_PMADDWD_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PMULUDQ_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xf4, 2,
          { 0x0f, 0xf4, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMULUDQ,
          FT_PMULUDQ_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PMAXSW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xee, 2,
          { 0x0f, 0xee, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMAXSW,
          FT_PMAXSW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PMINSW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xea, 2,
          { 0x0f, 0xea, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PMINSW,
          FT_PMINSW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PADDB_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xfc, 2,
          { 0x0f, 0xfc, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDB,
          FT_PADDB_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PADDW_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xfd, 2,
          { 0x0f, 0xfd, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDW,
          FT_PADDW_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PADDD_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xfe, 2,
          { 0x0f, 0xfe, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDD,
          FT_PADDD_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PADDQ_MMX_MMXM64] =
        { 3, 0, 0, 0x0f, 0xd4, 2,
          { 0x0f, 0xd4, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_PADDQ,
          FT_PADDQ_MMX_MMXM64, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOVDQ2Q_MMX_XMM] =
        { 4, dt_X86_PREFIX_REPNE, 0, 0x0f, 0xd6, 1,
          { 0xf2, 0x0f, 0xd6, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_MOVDQ2Q, FT_MOVDQ2Q_MMX_XMM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY },
    [FT_MOVQ2DQ_XMM_MMX] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0xd6, 2,
          { 0xf3, 0x0f, 0xd6, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_MOVQ2DQ, FT_MOVQ2DQ_XMM_MMX,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY },
    [FT_PHMINPOSUW_XMM_XMMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x38, 15,
          { 0x66, 0x0f, 0x38, 0x41, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PHMINPOSUW, FT_PHMINPOSUW_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CMP_XMM_XMMM_IMM8] =
        { 4, 0, 0, 0x0f, 0xc2, 6,
          { 0x0f, 0xc2, 0xc0, 0 },
          { 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_CMPPS, FT_CMP_XMM_XMMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_ROUND_XMM_XMMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 22,
          { 0x66, 0x0f, 0x3a, 0x08, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xfc, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_ROUNDPS, FT_ROUND_XMM_XMMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_DP_XMM_XMMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 14,
          { 0x66, 0x0f, 0x3a, 0x40, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xfe, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_DPPS, FT_DP_XMM_XMMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PCLMULQDQ_XMM_XMMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 24,
          { 0x66, 0x0f, 0x3a, 0x44, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PCLMULQDQ, FT_PCLMULQDQ_XMM_XMMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_AES_ROUND_XMM_XMMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x38, 8,
          { 0x66, 0x0f, 0x38, 0xdc, 0xc0 },
          { 0xff, 0xff, 0xff, 0xfc, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_AESENC, FT_AES_ROUND_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_AESIMC_XMM_XMMM] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x38, 2,
          { 0x66, 0x0f, 0x38, 0xdb, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_AESIMC, FT_AESIMC_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_AESKEYGEN_XMM_XMMM_IMM8] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 4,
          { 0x66, 0x0f, 0x3a, 0xdf, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_AESKEYGENASSIST,
          FT_AESKEYGEN_XMM_XMMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SHA_XMM_XMMM] =
        { 4, 0, 0, 0x0f, 0x38, 0,
          { 0x0f, 0x38, 0xc8, 0xc0 },
          { 0xff, 0xff, 0xf8, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SHA1NEXTE, FT_SHA_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SHA1RNDS4_XMM_XMMM_IMM8] =
        { 5, 0, 0, 0x0f, 0x3a, 0,
          { 0x0f, 0x3a, 0xcc, 0xc0, 0 },
          { 0xff, 0xff, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, 4, 1,
          dt_X86_INS_SHA1RNDS4, FT_SHA1RNDS4_XMM_XMMM_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PSRLDQ_XMM_IMM8] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x73, 1,
          { 0x66, 0x0f, 0x73, 0xd8, 0 },
          { 0xff, 0xff, 0xff, 0xf8, 0 }, -1, 0xd8, -1, 0, -1, 0,
          dt_X86_INS_PSRLDQ, FT_PSRLDQ_XMM_IMM8 },
    [FT_PSLLDQ_XMM_IMM8] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x73, 1,
          { 0x66, 0x0f, 0x73, 0xf8, 0 },
          { 0xff, 0xff, 0xff, 0xf8, 0 }, -1, 0xf8, -1, 0, -1, 0,
          dt_X86_INS_PSLLDQ, FT_PSLLDQ_XMM_IMM8 },
    [FT_MOVLPS_XMM_M64] =
        { 4, 0, 0, 0x0f, 0x12, 2, { 0x0f, 0x12, 0x44, 0x24 },
          { 0xff, 0xff, 0xff, 0xff }, -1, 0x44, 4, 1, -1, 0,
          dt_X86_INS_MOVLPS, FT_MOVLPS_XMM_M64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_MOVLPD_XMM_M64] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x12, 2,
          { 0x66, 0x0f, 0x12, 0x44, 0x24 },
          { 0xff, 0xff, 0xff, 0xff, 0 }, -1, 0x44, 4, 1, -1, 0,
          dt_X86_INS_MOVLPD, FT_MOVLPD_XMM_M64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_MOVHPS_XMM_M64] =
        { 5, 0, 0, 0x0f, 0x16, 2, { 0x0f, 0x16, 0x44, 0x24, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0 }, -1, 0x44, 4, 1, -1, 0,
          dt_X86_INS_MOVHPS, FT_MOVHPS_XMM_M64 },
    [FT_STMXCSR_M32] =
        { 4, 0, 0, 0x0f, 0xae, 1, { 0x0f, 0xae, 0x18 },
          { 0xff, 0xff, 0x38 }, -1, 0x18, -1, 0, -1, 0,
          dt_X86_INS_STMXCSR, FT_STMXCSR_M32 },
    [FT_MOVSD_XMM_M64] =
        { 4, dt_X86_PREFIX_REPNE, 0, 0x0f, 0x10, 2,
          { 0xf2, 0x0f, 0x10, 0x0e }, { 0xff, 0xff, 0xff, 0xff },
          -1, 0x0e, -1, 0, -1, 0, dt_X86_INS_MOVSD,
          FT_MOVSD_XMM_M64 },
    [FT_MOVSD_M64_XMM] =
        { 6, dt_X86_PREFIX_REPNE, 0, 0x0f, 0x11, 1,
          { 0xf2, 0x0f, 0x11, 0x4c, 0x24, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0xff, 0 }, -1, 0x4c, 5, 1,
          -1, 0, dt_X86_INS_MOVSD, FT_MOVSD_M64_XMM },
    [FT_SIMD_SCALAR_BIN_XMM_XMMM] =
        { 4, dt_X86_PREFIX_REPNE, 0, 0x0f, 0x58, 1,
          { 0xf2, 0x0f, 0x58, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_ADDSD,
          FT_SIMD_SCALAR_BIN_XMM_XMMM },
    [FT_SIMD_SCALAR_CMP_XMM_XMMM] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x2f, 1,
          { 0x66, 0x0f, 0x2f, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_COMISD,
          FT_SIMD_SCALAR_CMP_XMM_XMMM },
    [FT_FMA132_XMM_XMMM] =
        { 5, 0, 0, 0xc4, 0x98, 1,
          { 0xc4, 0xe2, 0x71, 0x98, 0xc0 },
          { 0xff, 0x1f, 0x03, 0xfe, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_VFMADD132PS, FT_FMA132_XMM_XMMM,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SUB_R64_IMM32] =
        { 7, 0, 0, 0x81, 0x00, 3,
          { 0x48, 0x81, 0xec, 0, 0, 0, 0 },
          { 0xff, 0xff, 0xff, 0, 0, 0, 0 }, 0x48, 0xec, -1, 0, 3,
          4, dt_X86_INS_SUB, FT_SUB_R64_IMM32 },
    [FT_ALU_ACC_IMM] =
        { 6, 0, 0, 0x2d, 0x00, 0, { 0x48, 0x2d, 0, 0, 0, 0 },
          { 0xf8, 0xff, 0, 0, 0, 0 }, 0x48, -1, -1, 0, 2, 4,
          dt_X86_INS_INVALID, FT_ALU_ACC_IMM },
    [FT_ALU_RM_R] =
        { 2, 0, 0, 0x19, 0x00, 0, { 0x19, 0xc0 },
          { 0xff, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_INVALID, FT_ALU_RM_R },
    [FT_ALU_R_RM] =
        { 2, 0, 0, 0x1b, 0x00, 0, { 0x1b, 0xc0 },
          { 0xff, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_INVALID, FT_ALU_R_RM },
    [FT_POP_R64] =
        { 1, 0, 0, 0x58, 0x00, 2, { 0x58 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_POP, FT_POP_R64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_PUSH_R64] =
        { 1, 0, 0, 0x50, 0x00, 2, { 0x50 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_PUSH, FT_PUSH_R64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_POP_R16] =
        { 2, 0, dt_X86_PREFIX_OPSIZE, 0x58, 0x00, 2,
          { 0x66, 0x58 }, { 0xff, 0xf8 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_POP, FT_POP_R16 },
    [FT_PUSH_R16] =
        { 2, 0, dt_X86_PREFIX_OPSIZE, 0x50, 0x00, 2,
          { 0x66, 0x50 }, { 0xff, 0xf8 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_PUSH, FT_PUSH_R16 },
    [FT_PUSH_RM64] =
        { 2, 0, 0, 0xff, 0x00, 2, { 0xff, 0x30 },
          { 0xff, 0x38 }, -1, 0x30, -1, 0, -1, 0,
          dt_X86_INS_PUSH, FT_PUSH_RM64 },
    [FT_POP_RM64] =
        { 2, 0, 0, 0x8f, 0x00, 2, { 0x8f, 0x00 },
          { 0xff, 0x38 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_POP, FT_POP_RM64 },
    [FT_PUSH_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0xff, 0x00, 2,
          { 0x66, 0xff, 0x30 }, { 0xff, 0xff, 0x38 },
          -1, 0x30, -1, 0, -1, 0, dt_X86_INS_PUSH, FT_PUSH_RM16 },
    [FT_POP_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x8f, 0x00, 2,
          { 0x66, 0x8f, 0x00 }, { 0xff, 0xff, 0x38 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_POP, FT_POP_RM16 },
    [FT_PUSH_SEG64] =
        { 2, 0, 0, 0x0f, 0xa0, 2, { 0x0f, 0xa0 }, { 0xff, 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_PUSH, FT_PUSH_SEG64,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_POP_SEG64] =
        { 2, 0, 0, 0x0f, 0xa1, 2, { 0x0f, 0xa1 }, { 0xff, 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_POP, FT_POP_SEG64,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_PUSH_SEG16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xa0, 2,
          { 0x66, 0x0f, 0xa0 }, { 0xff, 0xff, 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_PUSH, FT_PUSH_SEG16,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_POP_SEG16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xa1, 2,
          { 0x66, 0x0f, 0xa1 }, { 0xff, 0xff, 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_POP, FT_POP_SEG16,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_ENDBR64] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0x1e, 1,
          { 0xf3, 0x0f, 0x1e, 0xfa }, { 0xff, 0xff, 0xff, 0xff },
          -1, 0xfa, -1, 0, -1, 0, dt_X86_INS_NOP, FT_ENDBR64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_ENDBR32] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0x1e, 1,
          { 0xf3, 0x0f, 0x1e, 0xfb }, { 0xff, 0xff, 0xff, 0xff },
          -1, 0xfb, -1, 0, -1, 0, dt_X86_INS_NOP, FT_ENDBR32, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_RET] =
        { 1, 0, 0, 0xc3, 0x00, 36, { 0xc3 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_RET, FT_RET, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_WAIT] =
        { 1, 0, 0, 0x9b, 0x00, 1, { 0x9b }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_WAIT, FT_WAIT,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_PAUSE] =
        { 2, dt_X86_PREFIX_REP, 0, 0x90, 0x00, 1,
          { 0xf3, 0x90 }, { 0xff, 0xff }, -1, -1, -1, 0,
          -1, 0, dt_X86_INS_PAUSE, FT_PAUSE,
          FT_TM_NO_EXTRA_CONSTRAINTS | FT_TM_PREFIX0_REP },
    [FT_PREFETCH] =
        { 3, 0, 0, 0x0f, 0x0d, 1, { 0x0f, 0x0d, 0x00 },
          { 0xff, 0xff, 0x38 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_PREFETCH, FT_PREFETCH,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_PREFETCHW] =
        { 3, 0, 0, 0x0f, 0x0d, 1, { 0x0f, 0x0d, 0x08 },
          { 0xff, 0xff, 0x38 }, -1, 0x08, -1, 0, -1, 0,
          dt_X86_INS_PREFETCHW, FT_PREFETCHW,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_PREFETCHT0] =
        { 3, 0, 0, 0x0f, 0x18, 1, { 0x0f, 0x18, 0x08 },
          { 0xff, 0xff, 0x38 }, -1, 0x08, -1, 0, -1, 0,
          dt_X86_INS_PREFETCHT0, FT_PREFETCHT0,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_PREFETCHNTA] =
        { 3, 0, 0, 0x0f, 0x18, 1, { 0x0f, 0x18, 0x00 },
          { 0xff, 0xff, 0x38 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_PREFETCHNTA, FT_PREFETCHNTA,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_PREFETCHT1] =
        { 3, 0, 0, 0x0f, 0x18, 1, { 0x0f, 0x18, 0x10 },
          { 0xff, 0xff, 0x38 }, -1, 0x10, -1, 0, -1, 0,
          dt_X86_INS_PREFETCHT1, FT_PREFETCHT1,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_PREFETCHT2] =
        { 3, 0, 0, 0x0f, 0x18, 1, { 0x0f, 0x18, 0x18 },
          { 0xff, 0xff, 0x38 }, -1, 0x18, -1, 0, -1, 0,
          dt_X86_INS_PREFETCHT2, FT_PREFETCHT2,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_CLDEMOTE] =
        { 3, 0, 0, 0x0f, 0x1c, 1, { 0x0f, 0x1c, 0x00 },
          { 0xff, 0xff, 0x38 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_CLDEMOTE, FT_CLDEMOTE,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          0, 0 },
    [FT_BNDMOV] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x1a, 1,
          { 0x66, 0x0f, 0x1a, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_BNDMOV, FT_BNDMOV, FT_TM_CONSTRAINTS_DECLARED,
          0, 0 },
    [FT_CLFLUSH] =
        { 3, 0, 0, 0x0f, 0xae, 1, { 0x0f, 0xae, 0x38 },
          { 0xff, 0xff, 0x38 }, -1, 0x38, -1, 0, -1, 0,
          dt_X86_INS_CLFLUSH, FT_CLFLUSH,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          0, 7 },
    [FT_CLFLUSHOPT] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xae, 1,
          { 0x66, 0x0f, 0xae, 0x38 }, { 0xff, 0xff, 0xff, 0x38 },
          -1, 0x38, -1, 0, -1, 0,
          dt_X86_INS_CLFLUSHOPT, FT_CLFLUSHOPT,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          0, 7 },
    [FT_LFENCE] =
        { 3, 0, 0, 0x0f, 0xae, 1, { 0x0f, 0xae, 0xe8 },
          { 0xff, 0xff, 0xf8 }, -1, 0xe8, -1, 0, -1, 0,
          dt_X86_INS_LFENCE, FT_LFENCE,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          0, 5 },
    [FT_MFENCE] =
        { 3, 0, 0, 0x0f, 0xae, 1, { 0x0f, 0xae, 0xf0 },
          { 0xff, 0xff, 0xf8 }, -1, 0xf0, -1, 0, -1, 0,
          dt_X86_INS_MFENCE, FT_MFENCE,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          0, 6 },
    [FT_SFENCE] =
        { 3, 0, 0, 0x0f, 0xae, 1, { 0x0f, 0xae, 0xf8 },
          { 0xff, 0xff, 0xf8 }, -1, 0xf8, -1, 0, -1, 0,
          dt_X86_INS_SFENCE, FT_SFENCE,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          0, 7 },
    [FT_FNINIT] =
        { 2, 0, 0, 0xdb, 0xe3, 1, { 0xdb, 0xe3 }, { 0xff, 0xff },
          -1, 0xe3, -1, 0, -1, 0, dt_X86_INS_FNINIT, FT_FNINIT, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_FNCLEX] =
        { 2, 0, 0, 0xdb, 0xe2, 5, { 0xdb, 0xe2 }, { 0xff, 0xff },
          -1, 0xe2, -1, 0, -1, 0, dt_X86_INS_FNCLEX, FT_FNCLEX, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FLD1] =
        { 2, 0, 0, 0xd9, 0xe8, 4, { 0xd9, 0xe8 }, { 0xff, 0xff },
          -1, 0xe8, -1, 0, -1, 0, dt_X86_INS_FLD1, FT_X87_FLD1,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FLD_CONST] =
        { 2, 0, 0, 0xd9, 0xe8, 4, { 0xd9, 0xe8 }, { 0xff, 0xf8 },
          -1, 0xe8, -1, 0, -1, 0, dt_X86_INS_FLD1,
          FT_X87_FLD_CONST, FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FLD_M32] =
        { 2, 0, 0, 0xd9, 0x00, 1, { 0xd9, 0x00 }, { 0xff, 0x38 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_FLD, FT_X87_FLD_M32,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FLD_M64] =
        { 2, 0, 0, 0xdd, 0x00, 1, { 0xdd, 0x00 }, { 0xff, 0x38 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_FLD, FT_X87_FLD_M64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FLD_REG] =
        { 2, 0, 0, 0xd9, 0xc0, 1, { 0xd9, 0xc0 }, { 0xff, 0xf8 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_FLD, FT_X87_FLD_REG,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_UNARY] =
        { 2, 0, 0, 0xd9, 0xe0, 1, { 0xd9, 0xe0 }, { 0xff, 0xfe },
          -1, 0xe0, -1, 0, -1, 0, dt_X86_INS_FCHS, FT_X87_UNARY,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_TOP_ADJ] =
        { 2, 0, 0, 0xd9, 0xf6, 4, { 0xd9, 0xf6 }, { 0xff, 0xfe },
          -1, 0xf6, -1, 0, -1, 0, dt_X86_INS_FDECSTP, FT_X87_TOP_ADJ,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FTST] =
        { 2, 0, 0, 0xd9, 0xe4, 6, { 0xd9, 0xe4 }, { 0xff, 0xff },
          -1, 0xe4, -1, 0, -1, 0, dt_X86_INS_FTST, FT_X87_FTST,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FXCH] =
        { 2, 0, 0, 0xd9, 0xc8, 4, { 0xd9, 0xc8 }, { 0xff, 0xf8 },
          -1, 0xc8, -1, 0, -1, 0, dt_X86_INS_FXCH, FT_X87_FXCH,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FCOM_REG] =
        { 2, 0, 0, 0xd8, 0xd0, 8, { 0xd8, 0xd0 }, { 0xff, 0xf8 },
          -1, 0xd0, -1, 0, -1, 0, dt_X86_INS_FCOM, FT_X87_FCOM_REG,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FCOMP_REG] =
        { 2, 0, 0, 0xd8, 0xd8, 9, { 0xd8, 0xd8 }, { 0xff, 0xf8 },
          -1, 0xd8, -1, 0, -1, 0, dt_X86_INS_FCOMP, FT_X87_FCOMP_REG,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FUCOMPP] =
        { 2, 0, 0, 0xda, 0xe9, 3, { 0xda, 0xe9 }, { 0xff, 0xff },
          -1, 0xe9, -1, 0, -1, 0, dt_X86_INS_FUCOMPP, FT_X87_FUCOMPP,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FCOMI_REG] =
        { 2, 0, 0, 0xdb, 0xe8, 7, { 0xdb, 0xe8 }, { 0xff, 0xf0 },
          -1, 0xe8, -1, 0, -1, 0, dt_X86_INS_FUCOMI, FT_X87_FCOMI_REG,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FCOMIP_REG] =
        { 2, 0, 0, 0xdf, 0xe8, 10, { 0xdf, 0xe8 }, { 0xff, 0xf0 },
          -1, 0xe8, -1, 0, -1, 0, dt_X86_INS_FUCOMIP, FT_X87_FCOMIP_REG,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FCMOVCC] =
        { 2, 0, 0, 0xda, 0xc0, 1, { 0xda, 0xc0 }, { 0xfe, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_FCMOVB, FT_X87_FCMOVCC,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_F2XM1] =
        { 2, 0, 0, 0xd9, 0xf0, 1, { 0xd9, 0xf0 }, { 0xff, 0xff },
          -1, 0xf0, -1, 0, -1, 0, dt_X86_INS_F2XM1, FT_X87_F2XM1,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FRNDINT] =
        { 2, 0, 0, 0xd9, 0xfc, 1, { 0xd9, 0xfc }, { 0xff, 0xff },
          -1, 0xfc, -1, 0, -1, 0, dt_X86_INS_FRNDINT, FT_X87_FRNDINT,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FSCALE] =
        { 2, 0, 0, 0xd9, 0xfd, 1, { 0xd9, 0xfd }, { 0xff, 0xff },
          -1, 0xfd, -1, 0, -1, 0, dt_X86_INS_FSCALE, FT_X87_FSCALE,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FSIN] =
        { 2, 0, 0, 0xd9, 0xfe, 1, { 0xd9, 0xfe }, { 0xff, 0xff },
          -1, 0xfe, -1, 0, -1, 0, dt_X86_INS_FSIN, FT_X87_FSIN,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FCOS] =
        { 2, 0, 0, 0xd9, 0xff, 1, { 0xd9, 0xff }, { 0xff, 0xff },
          -1, 0xff, -1, 0, -1, 0, dt_X86_INS_FCOS, FT_X87_FCOS,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FSINCOS] =
        { 2, 0, 0, 0xd9, 0xfb, 1, { 0xd9, 0xfb }, { 0xff, 0xff },
          -1, 0xfb, -1, 0, -1, 0, dt_X86_INS_FSINCOS, FT_X87_FSINCOS,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FPTAN] =
        { 2, 0, 0, 0xd9, 0xf2, 1, { 0xd9, 0xf2 }, { 0xff, 0xff },
          -1, 0xf2, -1, 0, -1, 0, dt_X86_INS_FPTAN, FT_X87_FPTAN,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FPATAN] =
        { 2, 0, 0, 0xd9, 0xf3, 1, { 0xd9, 0xf3 }, { 0xff, 0xff },
          -1, 0xf3, -1, 0, -1, 0, dt_X86_INS_FPATAN, FT_X87_FPATAN,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FPREM] =
        { 2, 0, 0, 0xd9, 0xf8, 1, { 0xd9, 0xf8 }, { 0xff, 0xff },
          -1, 0xf8, -1, 0, -1, 0, dt_X86_INS_FPREM, FT_X87_FPREM,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FPREM1] =
        { 2, 0, 0, 0xd9, 0xf5, 1, { 0xd9, 0xf5 }, { 0xff, 0xff },
          -1, 0xf5, -1, 0, -1, 0, dt_X86_INS_FPREM1, FT_X87_FPREM1,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FYL2X] =
        { 2, 0, 0, 0xd9, 0xf1, 1, { 0xd9, 0xf1 }, { 0xff, 0xff },
          -1, 0xf1, -1, 0, -1, 0, dt_X86_INS_FYL2X, FT_X87_FYL2X,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FYL2XP1] =
        { 2, 0, 0, 0xd9, 0xf9, 1, { 0xd9, 0xf9 }, { 0xff, 0xff },
          -1, 0xf9, -1, 0, -1, 0, dt_X86_INS_FYL2XP1, FT_X87_FYL2XP1,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FBLD] =
        { 2, 0, 0, 0xdf, 0x00, 1, { 0xdf, 0x20 }, { 0xff, 0x38 },
          -1, 0x20, -1, 0, -1, 0, dt_X86_INS_FBLD, FT_X87_FBLD,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FBSTP] =
        { 2, 0, 0, 0xdf, 0x00, 1, { 0xdf, 0x30 }, { 0xff, 0x38 },
          -1, 0x30, -1, 0, -1, 0, dt_X86_INS_FBSTP, FT_X87_FBSTP,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FXAM] =
        { 2, 0, 0, 0xd9, 0xe5, 1, { 0xd9, 0xe5 }, { 0xff, 0xff },
          -1, 0xe5, -1, 0, -1, 0, dt_X86_INS_FXAM, FT_X87_FXAM,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FXTRACT] =
        { 2, 0, 0, 0xd9, 0xf4, 1, { 0xd9, 0xf4 }, { 0xff, 0xff },
          -1, 0xf4, -1, 0, -1, 0, dt_X86_INS_FXTRACT, FT_X87_FXTRACT,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FSQRT] =
        { 2, 0, 0, 0xd9, 0xfa, 1, { 0xd9, 0xfa }, { 0xff, 0xff },
          -1, 0xfa, -1, 0, -1, 0, dt_X86_INS_FSQRT, FT_X87_FSQRT,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FIST_M16] =
        { 2, 0, 0, 0xdf, 0x00, 1, { 0xdf, 0x10 }, { 0xff, 0x38 },
          -1, 0x10, -1, 0, -1, 0, dt_X86_INS_FIST, FT_X87_FIST_M16,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FIST_M32] =
        { 2, 0, 0, 0xdb, 0x00, 3, { 0xdb, 0x10 }, { 0xff, 0x38 },
          -1, 0x10, -1, 0, -1, 0, dt_X86_INS_FIST, FT_X87_FIST_M32,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FI_BIN_M16] =
        { 2, 0, 0, 0xde, 0x00, 1, { 0xde, 0x00 }, { 0xff, 0x00 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_FIADD,
          FT_X87_FI_BIN_M16, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FI_BIN_M32] =
        { 2, 0, 0, 0xda, 0x00, 1, { 0xda, 0x00 }, { 0xff, 0x00 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_FIADD,
          FT_X87_FI_BIN_M32, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FILD_M16] =
        { 2, 0, 0, 0xdf, 0x00, 1, { 0xdf, 0x00 }, { 0xff, 0x38 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_FILD, FT_X87_FILD_M16,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FILD_M32] =
        { 2, 0, 0, 0xdb, 0x00, 1, { 0xdb, 0x00 }, { 0xff, 0x38 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_FILD, FT_X87_FILD_M32,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FILD_M64] =
        { 2, 0, 0, 0xdf, 0x00, 1, { 0xdf, 0x28 }, { 0xff, 0x38 },
          -1, 0x28, -1, 0, -1, 0, dt_X86_INS_FILD, FT_X87_FILD_M64,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FISTP_M16] =
        { 2, 0, 0, 0xdf, 0x00, 1, { 0xdf, 0x18 }, { 0xff, 0x38 },
          -1, 0x18, -1, 0, -1, 0, dt_X86_INS_FISTP, FT_X87_FISTP_M16,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FISTP_M32] =
        { 2, 0, 0, 0xdb, 0x00, 1, { 0xdb, 0x18 }, { 0xff, 0x38 },
          -1, 0x18, -1, 0, -1, 0, dt_X86_INS_FISTP, FT_X87_FISTP_M32,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FISTP_M64] =
        { 2, 0, 0, 0xdf, 0x00, 1, { 0xdf, 0x38 }, { 0xff, 0x38 },
          -1, 0x38, -1, 0, -1, 0, dt_X86_INS_FISTP, FT_X87_FISTP_M64,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FISTTP_M16] =
        { 2, 0, 0, 0xdf, 0x00, 1, { 0xdf, 0x08 }, { 0xff, 0x38 },
          -1, 0x08, -1, 0, -1, 0, dt_X86_INS_FISTTP, FT_X87_FISTTP_M16,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FISTTP_M32] =
        { 2, 0, 0, 0xdb, 0x00, 1, { 0xdb, 0x08 }, { 0xff, 0x38 },
          -1, 0x08, -1, 0, -1, 0, dt_X86_INS_FISTTP, FT_X87_FISTTP_M32,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FISTTP_M64] =
        { 2, 0, 0, 0xdd, 0x00, 1, { 0xdd, 0x08 }, { 0xff, 0x38 },
          -1, 0x08, -1, 0, -1, 0, dt_X86_INS_FISTTP, FT_X87_FISTTP_M64,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FST_M32] =
        { 2, 0, 0, 0xd9, 0x00, 1, { 0xd9, 0x10 }, { 0xff, 0x38 },
          -1, 0x10, -1, 0, -1, 0, dt_X86_INS_FST, FT_X87_FST_M32,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FST_M64] =
        { 2, 0, 0, 0xdd, 0x00, 1, { 0xdd, 0x10 }, { 0xff, 0x38 },
          -1, 0x10, -1, 0, -1, 0, dt_X86_INS_FST, FT_X87_FST_M64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FLD_M80] =
        { 2, 0, 0, 0xdb, 0x00, 1, { 0xdb, 0x28 }, { 0xff, 0x38 },
          -1, 0x28, -1, 0, -1, 0, dt_X86_INS_FLD, FT_X87_FLD_M80,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FSTP_M32] =
        { 2, 0, 0, 0xd9, 0x00, 1, { 0xd9, 0x18 }, { 0xff, 0x38 },
          -1, 0x18, -1, 0, -1, 0, dt_X86_INS_FSTP, FT_X87_FSTP_M32,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FSTP_M64] =
        { 2, 0, 0, 0xdd, 0x00, 1, { 0xdd, 0x18 }, { 0xff, 0x38 },
          -1, 0x18, -1, 0, -1, 0, dt_X86_INS_FSTP, FT_X87_FSTP_M64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FSTP_M80] =
        { 2, 0, 0, 0xdb, 0x00, 1, { 0xdb, 0x38 }, { 0xff, 0x38 },
          -1, 0x38, -1, 0, -1, 0, dt_X86_INS_FSTP, FT_X87_FSTP_M80,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FSTP_REG] =
        { 2, 0, 0, 0xdd, 0xd8, 1, { 0xdd, 0xd8 }, { 0xff, 0xf8 },
          -1, 0xd8, -1, 0, -1, 0, dt_X86_INS_FSTP, FT_X87_FSTP_REG,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FST_REG] =
        { 2, 0, 0, 0xdd, 0xd0, 1, { 0xdd, 0xd0 }, { 0xff, 0xf8 },
          -1, 0xd0, -1, 0, -1, 0, dt_X86_INS_FST, FT_X87_FST_REG,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_BIN_REG] =
        { 2, 0, 0, 0xd8, 0xc0, 1, { 0xd8, 0xc0 }, { 0xfb, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_FADD, FT_X87_BIN_REG,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_BIN_M32] =
        { 2, 0, 0, 0xd8, 0x00, 1, { 0xd8, 0x00 }, { 0xff, 0x38 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_FADD, FT_X87_BIN_M32,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_BIN_M64] =
        { 2, 0, 0, 0xdc, 0x00, 1, { 0xdc, 0x00 }, { 0xff, 0x38 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_FADD, FT_X87_BIN_M64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FCOM_M32] =
        { 2, 0, 0, 0xd8, 0x10, 1, { 0xd8, 0x10 }, { 0xff, 0x38 },
          -1, 0x10, -1, 0, -1, 0, dt_X86_INS_FCOM, FT_X87_FCOM_M32, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FCOM_M64] =
        { 2, 0, 0, 0xdc, 0x10, 1, { 0xdc, 0x10 }, { 0xff, 0x38 },
          -1, 0x10, -1, 0, -1, 0, dt_X86_INS_FCOM, FT_X87_FCOM_M64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FADDP] =
        { 2, 0, 0, 0xde, 0xc0, 1, { 0xde, 0xc0 }, { 0xff, 0xf8 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_FADDP, FT_X87_FADDP, FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FSUBP] =
        { 2, 0, 0, 0xde, 0xe8, 1, { 0xde, 0xe8 }, { 0xff, 0xf8 },
          -1, 0xe8, -1, 0, -1, 0, dt_X86_INS_FSUBP, FT_X87_FSUBP, FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FSUBRP] =
        { 2, 0, 0, 0xde, 0xe0, 1, { 0xde, 0xe0 }, { 0xff, 0xf8 },
          -1, 0xe0, -1, 0, -1, 0, dt_X86_INS_FSUBR, FT_X87_FSUBRP, FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FMULP] =
        { 2, 0, 0, 0xde, 0xc8, 1, { 0xde, 0xc8 }, { 0xff, 0xf8 },
          -1, 0xc8, -1, 0, -1, 0, dt_X86_INS_FMULP, FT_X87_FMULP, FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FDIVP] =
        { 2, 0, 0, 0xde, 0xf8, 1, { 0xde, 0xf8 }, { 0xff, 0xf8 },
          -1, 0xf8, -1, 0, -1, 0, dt_X86_INS_FDIVP, FT_X87_FDIVP, FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FDIVRP] =
        { 2, 0, 0, 0xde, 0xf0, 1, { 0xde, 0xf0 }, { 0xff, 0xf8 },
          -1, 0xf0, -1, 0, -1, 0, dt_X86_INS_FDIVR, FT_X87_FDIVRP, FT_TM_CONSTRAINTS_DECLARED },
    [FT_X87_FFREE] =
        { 2, 0, 0, 0xdd, 0xc0, 1, { 0xdd, 0xc0 }, { 0xff, 0xff },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_FFREE, FT_X87_FFREE, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FCOMPP] =
        { 2, 0, 0, 0xde, 0xd9, 1, { 0xde, 0xd9 }, { 0xff, 0xff },
          -1, 0xd9, -1, 0, -1, 0, dt_X86_INS_FCOMPP, FT_X87_FCOMPP, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FSTSW_AX] =
        { 2, 0, 0, 0xdf, 0xe0, 1, { 0xdf, 0xe0 }, { 0xff, 0xff },
          -1, 0xe0, -1, 0, -1, 0, dt_X86_INS_FST, FT_X87_FSTSW_AX, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_X87_FNSTSW_M16] =
        { 2, 0, 0, 0xdd, 0x00, 2, { 0xdd, 0x38 }, { 0xff, 0x38 },
          -1, 0x38, -1, 0, -1, 0, dt_X86_INS_FNSTSW,
          FT_X87_FNSTSW_M16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_X87_FLDCW_M16] =
        { 2, 0, 0, 0xd9, 0x00, 16, { 0xd9, 0x28 }, { 0xff, 0x38 },
          -1, 0x28, -1, 0, -1, 0, dt_X86_INS_FLDCW,
          FT_X87_FLDCW_M16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_X87_FNSTCW_M16] =
        { 2, 0, 0, 0xd9, 0x00, 2, { 0xd9, 0x38 }, { 0xff, 0x38 },
          -1, 0x38, -1, 0, -1, 0, dt_X86_INS_FNSTCW,
          FT_X87_FNSTCW_M16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_LEAVE] =
        { 1, 0, 0, 0xc9, 0x00, 3, { 0xc9 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_LEAVE, FT_LEAVE,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_ENTER_ZERO_LEVEL1] =
        { 4, 0, 0, 0xc8, 0x00, 3, { 0xc8, 0, 0, 1 },
          { 0xff, 0xff, 0xff, 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_ENTER, FT_ENTER_ZERO_LEVEL1,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_ENTER] =
        { 4, 0, 0, 0xc8, 0x00, 3, { 0xc8 }, { 0xff },
          -1, -1, -1, 0, 1, 3, dt_X86_INS_ENTER, FT_ENTER,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_ENTER16] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0xc8, 0x00, 3, { 0x66, 0xc8 },
          { 0xff, 0xff }, -1, -1, -1, 0, 2, 3,
          dt_X86_INS_ENTER, FT_ENTER16, FT_TM_CONSTRAINTS_DECLARED },
    [FT_MOV_RM64_IMM32] =
        { 7, 0, 0, 0xc7, 0x00, 2, { 0x48, 0xc7, 0xc0 },
          { 0xff, 0xff, 0xf8, 0, 0, 0, 0 }, 0x48, 0xc0, -1, 0, 3,
          4, dt_X86_INS_MOV, FT_MOV_RM64_IMM32 },
    [FT_ADD_R64_IMM32] =
        { 7, 0, 0, 0x81, 0x00, 3,
          { 0x48, 0x81, 0xc4, 0, 0, 0, 0 },
          { 0xff, 0xff, 0xff, 0, 0, 0, 0 }, 0x48, 0xc4, -1, 0, 3,
          4, dt_X86_INS_ADD, FT_ADD_R64_IMM32 },
    [FT_SUB_R64_IMM8] =
        { 4, 0, 0, 0x83, 0x00, 3, { 0x48, 0x83, 0xec, 0 },
          { 0xff, 0xff, 0xff, 0 }, 0x48, 0xec, -1, 0, 3, 1,
          dt_X86_INS_SUB, FT_SUB_R64_IMM8 },
    [FT_MOVZX_R32_RM16] =
        { 5, 0, 0, 0x0f, 0xb7, 1, { 0x0f, 0xb7, 0x54, 0x24, 0 },
          { 0xff, 0xff, 0xff, 0xff, 0 }, -1, 0x54, 4, 1, -1, 0,
          dt_X86_INS_MOVZX, FT_MOVZX_R32_RM16, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MOVZX_R16_RM8] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xb6, 3,
          { 0x66, 0x0f, 0xb6, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVZX, FT_MOVZX_R16_RM8, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MOVZX_R32_RM8] =
        { 3, 0, 0, 0x0f, 0xb6, 1, { 0x0f, 0xb6, 0x03 },
          { 0xff, 0xff, 0xff }, -1, 0x03, -1, 0, -1, 0,
          dt_X86_INS_MOVZX, FT_MOVZX_R32_RM8, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CMP_RM64_IMM8] =
        { 5, 0, 0, 0x83, 0x00, 1, { 0x48, 0x83, 0x7f, 0, 0 },
          { 0xff, 0xff, 0xff, 0, 0 }, 0x48, 0x7f, -1, 0, -1, 0,
          dt_X86_INS_CMP, FT_CMP_RM64_IMM8 },
    [FT_TEST_RM64_R64] =
        { 3, 0, 0, 0x85, 0x00, 1, { 0x48, 0x85, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_TEST, FT_TEST_RM64_R64 },
    [FT_TEST_RM64_IMM32] =
        { 7, 0, 0, 0xf7, 0x00, 1, { 0x48, 0xf7, 0xc0, 0, 0, 0, 0 },
          { 0xff, 0xff, 0xf8, 0, 0, 0, 0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_TEST, FT_TEST_RM64_IMM32 },
    [FT_ADD_R64_RM64] =
        { 7, 0, 0, 0x03, 0x00, 3, { 0x48, 0x03, 0x05 },
          { 0xff, 0xff, 0xff, 0, 0, 0, 0 }, 0x48, 0x05, -1, 0,
          -1, 0, dt_X86_INS_ADD, FT_ADD_R64_RM64 },
    [FT_ADD_R32_RM32] =
        { 2, 0, 0, 0x03, 0x00, 3, { 0x03, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_ADD_R32_RM32 },
    [FT_ADD_R16_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x03, 0x00, 3,
          { 0x66, 0x03, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_ADD, FT_ADD_R16_RM16 },
    [FT_ADC_R64_RM64] =
        { 7, 0, 0, 0x13, 0x00, 3, { 0x48, 0x13, 0x05 },
          { 0xff, 0xff, 0xff, 0, 0, 0, 0 }, 0x48, 0x05, -1, 0,
          -1, 0, dt_X86_INS_ADC, FT_ADC_R64_RM64 },
    [FT_ADC_R32_RM32] =
        { 2, 0, 0, 0x13, 0x00, 3, { 0x13, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADC, FT_ADC_R32_RM32 },
    [FT_ADC_R16_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x13, 0x00, 3,
          { 0x66, 0x13, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_ADC, FT_ADC_R16_RM16 },
    [FT_ADD_AX_IMM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x05, 0x00, 2,
          { 0x66, 0x05, 0, 0 }, { 0xff, 0xff, 0, 0 },
          -1, -1, -1, 0, 2, 2, dt_X86_INS_ADD,
          FT_ADD_AX_IMM16 },
    [FT_ADD_EAX_IMM32] =
        { 5, 0, 0, 0x05, 0x00, 2, { 0x05, 0, 0, 0, 0 },
          { 0xff, 0, 0, 0, 0 }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_ADD, FT_ADD_EAX_IMM32 },
    [FT_ADD_RAX_IMM32] =
        { 6, 0, 0, 0x05, 0x00, 2, { 0x48, 0x05, 0, 0, 0, 0 },
          { 0xff, 0xff, 0, 0, 0, 0 }, 0x48, -1, -1, 0, 2, 4,
          dt_X86_INS_ADD, FT_ADD_RAX_IMM32 },
    [FT_ADC_RM8_R8] =
        { 2, 0, 0, 0x10, 0x00, 4, { 0x10, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADC, FT_ADC_RM8_R8 },
    [FT_ADC_RM64_R64] =
        { 3, 0, 0, 0x11, 0x00, 4, { 0x48, 0x11, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADC, FT_ADC_RM64_R64 },
    [FT_ADC_RM32_R32] =
        { 2, 0, 0, 0x11, 0x00, 4, { 0x11, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADC, FT_ADC_RM32_R32 },
    [FT_ADC_RM16_R16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x11, 0x00, 4,
          { 0x66, 0x11, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_ADC, FT_ADC_RM16_R16 },
    [FT_SBB_RM32_R32] =
        { 2, 0, 0, 0x19, 0x00, 4, { 0x19, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SBB, FT_SBB_RM32_R32 },
    [FT_SUB_RM64_R64] =
        { 3, 0, 0, 0x29, 0x00, 2, { 0x48, 0x29, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SUB, FT_SUB_RM64_R64 },
    [FT_SUB_R64_RM64] =
        { 3, 0, 0, 0x2b, 0x00, 2, { 0x48, 0x2b, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SUB, FT_SUB_R64_RM64 },
    [FT_SUB_R32_RM32] =
        { 2, 0, 0, 0x2b, 0x00, 2, { 0x2b, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SUB, FT_SUB_R32_RM32 },
    [FT_SUB_R16_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x2b, 0x00, 2,
          { 0x66, 0x2b, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_SUB, FT_SUB_R16_RM16 },
    [FT_SUB_R8_RM8] =
        { 2, 0, 0, 0x2a, 0x00, 2, { 0x2a, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SUB, FT_SUB_R8_RM8 },
    [FT_AND_R64_IMM8] =
        { 4, 0, 0, 0x83, 0x00, 3, { 0x48, 0x83, 0xe0, 0 },
          { 0xff, 0xff, 0xff, 0 }, 0x48, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_AND, FT_AND_R64_IMM8 },
    [FT_AND_RM8_R8] =
        { 2, 0, 0, 0x20, 0x00, 2, { 0x20, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_AND, FT_AND_RM8_R8 },
    [FT_AND_RM8_IMM8] =
        { 3, 0, 0, 0x80, 0x00, 2, { 0x80, 0xe0, 0 },
          { 0xff, 0xf8, 0 }, -1, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_AND, FT_AND_RM8_IMM8 },
    [FT_AND_RM64_R64] =
        { 3, 0, 0, 0x21, 0x00, 2, { 0x48, 0x21, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_AND, FT_AND_RM64_R64 },
    [FT_AND_RM32_R32] =
        { 2, 0, 0, 0x21, 0x00, 2, { 0x21, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_AND, FT_AND_RM32_R32 },
    [FT_AND_R64_RM64] =
        { 3, 0, 0, 0x23, 0x00, 2, { 0x48, 0x23, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_AND, FT_AND_R64_RM64 },
    [FT_AND_R32_RM32] =
        { 2, 0, 0, 0x23, 0x00, 2, { 0x23, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_AND, FT_AND_R32_RM32 },
    [FT_AND_R8_RM8] =
        { 2, 0, 0, 0x22, 0x00, 4, { 0x22, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_AND, FT_AND_R8_RM8 },
    [FT_AND_AL_IMM8] =
        { 2, 0, 0, 0x24, 0x00, 3, { 0x24, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_AND, FT_AND_AL_IMM8 },
    [FT_GRP1_RM64_IMM8] =
        { 4, 0, 0, 0x83, 0x00, 2, { 0x48, 0x83, 0xc0, 0 },
          { 0xff, 0xff, 0xc0, 0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_GRP1_RM64_IMM8 },
    [FT_GRP1_RM32_IMM8] =
        { 3, 0, 0, 0x83, 0x00, 2, { 0x83, 0xc0, 0 },
          { 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_GRP1_RM32_IMM8 },
    [FT_GRP1_RM16_IMM8] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x83, 0x00, 2,
          { 0x66, 0x83, 0xc0, 0 }, { 0xff, 0xff, 0xc0, 0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_ADD,
          FT_GRP1_RM16_IMM8 },
    [FT_GRP1_RM8_IMM8] =
        { 3, 0, 0, 0x80, 0x00, 2, { 0x80, 0xc0, 0 },
          { 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_GRP1_RM8_IMM8 },
    [FT_CMP_RM64_R64] =
        { 3, 0, 0, 0x39, 0x00, 1, { 0x48, 0x39, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_CMP, FT_CMP_RM64_R64 },
    [FT_CMP_RM32_R32] =
        { 2, 0, 0, 0x39, 0x00, 1, { 0x39, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_CMP, FT_CMP_RM32_R32 },
    [FT_CMP_RM16_R16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x39, 0x00, 1,
          { 0x66, 0x39, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_CMP, FT_CMP_RM16_R16 },
    [FT_TEST_RM32_R32] =
        { 2, 0, 0, 0x85, 0x00, 1, { 0x85, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_TEST, FT_TEST_RM32_R32 },
    [FT_TEST_RM32_IMM32] =
        { 6, 0, 0, 0xf7, 0x00, 1, { 0xf7, 0xc0, 0, 0, 0, 0 },
          { 0xff, 0xf8, 0, 0, 0, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_TEST, FT_TEST_RM32_IMM32 },
    [FT_TEST_RM16_R16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x85, 0x00, 1,
          { 0x66, 0x85, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_TEST, FT_TEST_RM16_R16 },
    [FT_OR_RM64_R64] =
        { 3, 0, 0, 0x09, 0x00, 2, { 0x48, 0x09, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_OR, FT_OR_RM64_R64 },
    [FT_OR_RM32_R32] =
        { 2, 0, 0, 0x09, 0x00, 2, { 0x09, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_OR, FT_OR_RM32_R32 },
    [FT_OR_RM8_R8] =
        { 2, 0, 0, 0x08, 0x00, 2, { 0x08, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_OR, FT_OR_RM8_R8 },
    [FT_OR_R64_RM64] =
        { 3, 0, 0, 0x0b, 0x00, 2, { 0x48, 0x0b, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_OR, FT_OR_R64_RM64 },
    [FT_OR_R32_RM32] =
        { 2, 0, 0, 0x0b, 0x00, 2, { 0x0b, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_OR, FT_OR_R32_RM32 },
    [FT_OR_R16_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x0b, 0x00, 2,
          { 0x66, 0x0b, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_OR, FT_OR_R16_RM16 },
    [FT_OR_R8_RM8] =
        { 2, 0, 0, 0x0a, 0x00, 2, { 0x0a, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_OR, FT_OR_R8_RM8 },
    [FT_OR_RM8_IMM8] =
        { 3, 0, 0, 0x80, 0x00, 2, { 0x80, 0xc8, 0 },
          { 0xff, 0xf8, 0 }, -1, 0xc8, -1, 0, -1, 0,
          dt_X86_INS_OR, FT_OR_RM8_IMM8 },
    [FT_OR_AL_IMM8] =
        { 2, 0, 0, 0x0c, 0x00, 3, { 0x0c, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_OR, FT_OR_AL_IMM8 },
    [FT_OR_AX_IMM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0d, 0x00, 3,
          { 0x66, 0x0d, 0, 0 }, { 0xff, 0xff, 0, 0 },
          -1, -1, -1, 0, 2, 2, dt_X86_INS_OR, FT_OR_AX_IMM16 },
    [FT_OR_EAX_IMM32] =
        { 5, 0, 0, 0x0d, 0x00, 3, { 0x0d, 0, 0, 0, 0 },
          { 0xff, 0, 0, 0, 0 }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_OR, FT_OR_EAX_IMM32 },
    [FT_OR_RAX_IMM32] =
        { 6, 0, 0, 0x0d, 0x00, 2, { 0x48, 0x0d, 0, 0, 0, 0 },
          { 0xff, 0xff, 0, 0, 0, 0 }, 0x48, -1, -1, 0, 2, 4,
          dt_X86_INS_OR, FT_OR_RAX_IMM32 },
    [FT_SUB_RM32_R32] =
        { 2, 0, 0, 0x29, 0x00, 2, { 0x29, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SUB, FT_SUB_RM32_R32 },
    [FT_SUB_RM16_R16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x29, 0x00, 2,
          { 0x66, 0x29, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_SUB, FT_SUB_RM16_R16 },
    [FT_SUB_RM8_R8] =
        { 2, 0, 0, 0x28, 0x00, 2, { 0x28, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SUB, FT_SUB_RM8_R8 },
    [FT_SHIFT_RM_IMM8] =
        { 3, 0, 0, 0xc1, 0x00, 2, { 0xc1, 0xe0, 0 },
          { 0xff, 0xf8, 0 }, -1, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_SHL, FT_SHIFT_RM_IMM8,
          FT_TM_READS_RAW_MODRM | FT_TM_READS_RAW_IMM8 },
    [FT_SHIFT_RM_CL] =
        { 2, 0, 0, 0xd3, 0x00, 2, { 0xd3, 0xe0 },
          { 0xff, 0xf8 }, -1, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_SHL, FT_SHIFT_RM_CL, FT_TM_READS_RAW_MODRM },
    [FT_SHIFT_RM_ONE] =
        { 2, 0, 0, 0xd1, 0x00, 2, { 0xd1, 0xe0 },
          { 0xff, 0xf8 }, -1, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_SHL, FT_SHIFT_RM_ONE, FT_TM_READS_RAW_MODRM },
    [FT_SHR_RM8_IMM8] =
        { 3, 0, 0, 0xc0, 0x00, 3, { 0xc0, 0xe8, 0 },
          { 0xff, 0xf8, 0 }, -1, 0xe8, -1, 0, -1, 0,
          dt_X86_INS_SHR, FT_SHR_RM8_IMM8,
          FT_TM_READS_RAW_MODRM | FT_TM_READS_RAW_IMM8 },
    [FT_SHR_RM8_ONE] =
        { 2, 0, 0, 0xd0, 0x00, 2, { 0xd0, 0xe8 },
          { 0xff, 0xf8 }, -1, 0xe8, -1, 0, -1, 0,
          dt_X86_INS_SHR, FT_SHR_RM8_ONE, FT_TM_READS_RAW_MODRM },
    [FT_SHR_RM16_IMM8] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0xc1, 0x00, 3,
          { 0x66, 0xc1, 0xe8, 0 }, { 0xff, 0xff, 0xf8, 0 },
          -1, 0xe8, -1, 0, -1, 0, dt_X86_INS_SHR,
          FT_SHR_RM16_IMM8,
          FT_TM_READS_RAW_MODRM | FT_TM_READS_RAW_IMM8 },
    [FT_SHLD_RM_R_IMM8] =
        { 4, 0, 0, 0x0f, 0xa4, 8, { 0x0f, 0xa4, 0xc0, 0 },
          { 0xff, 0xff, 0x00, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SHLD, FT_SHLD_RM_R_IMM8,
          FT_TM_CONSTRAINTS_DECLARED |
          FT_TM_IMM_U8 | FT_TM_READS_RAW_MODRM | FT_TM_READS_RAW_IMM8 },
    [FT_SHLD_RM_R_CL] =
        { 3, 0, 0, 0x0f, 0xa5, 10, { 0x0f, 0xa5, 0xc0 },
          { 0xff, 0xff, 0x00 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SHLD, FT_SHLD_RM_R_CL,
          FT_TM_CONSTRAINTS_DECLARED |
          FT_TM_READS_RAW_MODRM },
    [FT_SHRD_RM_R_IMM8] =
        { 4, 0, 0, 0x0f, 0xac, 8, { 0x0f, 0xac, 0xc0, 0 },
          { 0xff, 0xff, 0x00, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SHRD, FT_SHRD_RM_R_IMM8,
          FT_TM_CONSTRAINTS_DECLARED |
          FT_TM_IMM_U8 | FT_TM_READS_RAW_MODRM | FT_TM_READS_RAW_IMM8 },
    [FT_SHRD_RM_R_CL] =
        { 3, 0, 0, 0x0f, 0xad, 10, { 0x0f, 0xad, 0xc0 },
          { 0xff, 0xff, 0x00 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SHRD, FT_SHRD_RM_R_CL,
          FT_TM_CONSTRAINTS_DECLARED |
          FT_TM_READS_RAW_MODRM },
    [FT_ADD_R32_IMM8] =
        { 4, 0, 0, 0x83, 0x00, 4, { 0x41, 0x83, 0xc0, 0 },
          { 0xf0, 0xff, 0xff, 0 }, 0x41, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_ADD_R32_IMM8 },
    [FT_SUB_R32_IMM8] =
        { 3, 0, 0, 0x83, 0x00, 3, { 0x83, 0xe8, 0 },
          { 0xff, 0xff, 0 }, -1, 0xe8, -1, 0, -1, 0,
          dt_X86_INS_SUB, FT_SUB_R32_IMM8 },
    [FT_SUB_AL_IMM8] =
        { 2, 0, 0, 0x2c, 0x00, 3, { 0x2c, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_SUB, FT_SUB_AL_IMM8 },
    [FT_SUB_AX_IMM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x2d, 0x00, 3,
          { 0x66, 0x2d, 0, 0 }, { 0xff, 0xff, 0, 0 },
          -1, -1, -1, 0, 2, 2, dt_X86_INS_SUB, FT_SUB_AX_IMM16 },
    [FT_AND_EAX_IMM32] =
        { 5, 0, 0, 0x25, 0x00, 3, { 0x25, 0, 0, 0, 0 },
          { 0xff, 0, 0, 0, 0 }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_AND, FT_AND_EAX_IMM32 },
    [FT_AND_AX_IMM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x25, 0x00, 3,
          { 0x66, 0x25, 0, 0 }, { 0xff, 0xff, 0, 0 },
          -1, -1, -1, 0, 2, 2, dt_X86_INS_AND,
          FT_AND_AX_IMM16 },
    [FT_AND_RAX_IMM32] =
        { 6, 0, 0, 0x25, 0x00, 2, { 0x48, 0x25, 0, 0, 0, 0 },
          { 0xff, 0xff, 0, 0, 0, 0 }, 0x48, -1, -1, 0, 2, 4,
          dt_X86_INS_AND, FT_AND_RAX_IMM32 },
    [FT_XOR_AL_IMM8] =
        { 2, 0, 0, 0x34, 0x00, 3, { 0x34, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_XOR, FT_XOR_AL_IMM8 },
    [FT_XOR_AX_IMM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x35, 0x00, 3,
          { 0x66, 0x35, 0, 0 }, { 0xff, 0xff, 0, 0 },
          -1, -1, -1, 0, 2, 2, dt_X86_INS_XOR,
          FT_XOR_AX_IMM16 },
    [FT_XOR_EAX_IMM32] =
        { 5, 0, 0, 0x35, 0x00, 3, { 0x35, 0, 0, 0, 0 },
          { 0xff, 0, 0, 0, 0 }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_XOR, FT_XOR_EAX_IMM32 },
    [FT_XOR_RAX_IMM32] =
        { 6, 0, 0, 0x35, 0x00, 3, { 0x48, 0x35, 0, 0, 0, 0 },
          { 0xff, 0xff, 0, 0, 0, 0 }, 0x48, -1, -1, 0, 2, 4,
          dt_X86_INS_XOR, FT_XOR_RAX_IMM32 },
    [FT_CMP_R64_RM64] =
        { 3, 0, 0, 0x3b, 0x00, 2, { 0x48, 0x3b, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_CMP, FT_CMP_R64_RM64 },
    [FT_CMP_R32_RM32] =
        { 2, 0, 0, 0x3b, 0x00, 2, { 0x3b, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_CMP, FT_CMP_R32_RM32 },
    [FT_CMP_R16_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x3b, 0x00, 1,
          { 0x66, 0x3b, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_CMP, FT_CMP_R16_RM16 },
    [FT_MOVSXD_R64_RM32] =
        { 3, 0, 0, 0x63, 0x00, 1, { 0x48, 0x63, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVSXD, FT_MOVSXD_R64_RM32 },
    [FT_MOVSXD_R32_RM32] =
        { 2, 0, 0, 0x63, 0x00, 1, { 0x63, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOVSXD, FT_MOVSXD_R32_RM32 },
    [FT_MOVSXD_R16_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x63, 0x00, 1,
          { 0x66, 0x63, 0xc0 }, { 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_MOVSXD,
          FT_MOVSXD_R16_RM16 },
    [FT_NEG_RM64] =
        { 3, 0, 0, 0xf7, 0x00, 3, { 0x48, 0xf7, 0xd8 },
          { 0xff, 0xff, 0xf8 }, 0x48, 0xd8, -1, 0, -1, 0,
          dt_X86_INS_NEG, FT_NEG_RM64, FT_TM_READS_RAW_MODRM },
    [FT_NEG_RM32] =
        { 2, 0, 0, 0xf7, 0x00, 4, { 0xf7, 0xd8 },
          { 0xff, 0xf8 }, -1, 0xd8, -1, 0, -1, 0,
          dt_X86_INS_NEG, FT_NEG_RM32, FT_TM_READS_RAW_MODRM },
    [FT_NEG_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0xf7, 0x00, 4,
          { 0x66, 0xf7, 0xd8 }, { 0xff, 0xff, 0xf8 }, -1, 0xd8,
          -1, 0, -1, 0, dt_X86_INS_NEG, FT_NEG_RM16,
          FT_TM_READS_RAW_MODRM },
    [FT_NEG_RM8] =
        { 2, 0, 0, 0xf6, 0x00, 4, { 0xf6, 0xd8 },
          { 0xff, 0xf8 }, -1, 0xd8, -1, 0, -1, 0,
          dt_X86_INS_NEG, FT_NEG_RM8, FT_TM_READS_RAW_MODRM },
    [FT_INC_RM64] =
        { 3, 0, 0, 0xff, 0x00, 3, { 0x48, 0xff, 0xc0 },
          { 0xf8, 0xff, 0xf8 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_INC, FT_INC_RM64 },
    [FT_DEC_RM64] =
        { 3, 0, 0, 0xff, 0x00, 3, { 0x48, 0xff, 0xc8 },
          { 0xf8, 0xff, 0xf8 }, 0x48, 0xc8, -1, 0, -1, 0,
          dt_X86_INS_DEC, FT_DEC_RM64 },
    [FT_INC_RM32] =
        { 2, 0, 0, 0xff, 0x00, 3, { 0xff, 0xc0 },
          { 0xff, 0xf8 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_INC, FT_INC_RM32 },
    [FT_DEC_RM32] =
        { 2, 0, 0, 0xff, 0x00, 2, { 0xff, 0xc8 },
          { 0xff, 0xf8 }, -1, 0xc8, -1, 0, -1, 0,
          dt_X86_INS_DEC, FT_DEC_RM32 },
    [FT_INC_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0xff, 0x00, 3,
          { 0x66, 0xff, 0xc0 }, { 0xff, 0xff, 0xf8 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_INC, FT_INC_RM16 },
    [FT_DEC_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0xff, 0x00, 3,
          { 0x66, 0xff, 0xc8 }, { 0xff, 0xff, 0xf8 }, -1, 0xc8,
          -1, 0, -1, 0, dt_X86_INS_DEC, FT_DEC_RM16 },
    [FT_INC_RM8] =
        { 2, 0, 0, 0xfe, 0x00, 3, { 0xfe, 0xc0 },
          { 0xff, 0xf8 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_INC, FT_INC_RM8 },
    [FT_DEC_RM8] =
        { 2, 0, 0, 0xfe, 0x00, 3, { 0xfe, 0xc8 },
          { 0xff, 0xf8 }, -1, 0xc8, -1, 0, -1, 0,
          dt_X86_INS_DEC, FT_DEC_RM8 },
    [FT_NOT_RM64] =
        { 3, 0, 0, 0xf7, 0x00, 2, { 0x48, 0xf7, 0xd0 },
          { 0xff, 0xff, 0xf8 }, 0x48, 0xd0, -1, 0, -1, 0,
          dt_X86_INS_NOT, FT_NOT_RM64 },
    [FT_NOT_RM32] =
        { 2, 0, 0, 0xf7, 0x00, 3, { 0xf7, 0xd0 },
          { 0xff, 0xf8 }, -1, 0xd0, -1, 0, -1, 0,
          dt_X86_INS_NOT, FT_NOT_RM32 },
    [FT_NOT_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0xf7, 0x00, 2,
          { 0x66, 0xf7, 0xd0 }, { 0xff, 0xff, 0xf8 }, -1, 0xd0,
          -1, 0, -1, 0, dt_X86_INS_NOT, FT_NOT_RM16 },
    [FT_NOT_RM8] =
        { 2, 0, 0, 0xf6, 0x00, 2, { 0xf6, 0xd0 },
          { 0xff, 0xf8 }, -1, 0xd0, -1, 0, -1, 0,
          dt_X86_INS_NOT, FT_NOT_RM8 },
    [FT_XCHG_RM64_R64] =
        { 3, 0, 0, 0x87, 0x00, 3, { 0x48, 0x87, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XCHG, FT_XCHG_RM64_R64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_XCHG_RM32_R32] =
        { 2, 0, 0, 0x87, 0x00, 5, { 0x87, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XCHG, FT_XCHG_RM32_R32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_XCHG_RM8_R8] =
        { 2, 0, 0, 0x86, 0x00, 5, { 0x86, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XCHG, FT_XCHG_RM8_R8,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_XCHG_R64_RAX] =
        { 2, 0, 0, 0x90, 0x00, 3, { 0x48, 0x90 },
          { 0xff, 0xf8 }, 0x48, -1, -1, 0, -1, 0,
          dt_X86_INS_XCHG, FT_XCHG_R64_RAX },
    [FT_XCHG_R32_EAX] =
        { 1, 0, 0, 0x90, 0x00, 5, { 0x90 },
          { 0xf8 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_XCHG, FT_XCHG_R32_EAX },
    [FT_XCHG_R16_AX] =
        { 2, 0, dt_X86_PREFIX_OPSIZE, 0x90, 0x00, 5,
          { 0x66, 0x90 }, { 0xff, 0xf8 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_XCHG, FT_XCHG_R16_AX },
    [FT_MOV_R8_IMM8] =
        { 2, 0, 0, 0xb0, 0x00, 2, { 0xb0, 0 },
          { 0xf8, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_MOV, FT_MOV_R8_IMM8, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MOV_R16_IMM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0xb8, 0x00, 2,
          { 0x66, 0xb8, 0, 0 }, { 0xff, 0xf8, 0, 0 },
          -1, -1, -1, 0, 2, 2, dt_X86_INS_MOV,
          FT_MOV_R16_IMM16, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_MOV_R32_IMM32] =
        { 5, 0, 0, 0xb8, 0x00, 3, { 0xb8, 0, 0, 0, 0 },
          { 0xf8, 0, 0, 0, 0 }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_MOV, FT_MOV_R32_IMM32,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_MOV_R32_RM32] =
        { 7, 0, 0, 0x8b, 0x00, 1, { 0x44, 0x8b, 0x05 },
          { 0xf0, 0xff, 0xff, 0, 0, 0, 0 }, 0x44, 0x05, -1, 0,
          -1, 0, dt_X86_INS_MOV, FT_MOV_R32_RM32 },
    [FT_ADD_R8_RM8] =
        { 2, 0, 0, 0x02, 0x00, 4, { 0x02, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_ADD_R8_RM8 },
    [FT_ADC_R8_RM8] =
        { 2, 0, 0, 0x12, 0x00, 4, { 0x12, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADC, FT_ADC_R8_RM8 },
    [FT_MOV_RM16_R16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x89, 0x00, 2,
          { 0x66, 0x89, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_MOV, FT_MOV_RM16_R16 },
    [FT_MOV_R8_RM8] =
        { 2, 0, 0, 0x8a, 0x00, 2, { 0x8a, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOV, FT_MOV_R8_RM8 },
    [FT_MOV_R16_RM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x8b, 0x00, 2,
          { 0x66, 0x8b, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_MOV, FT_MOV_R16_RM16 },
    [FT_MOV_RM_SEG] =
        { 2, 0, 0, 0x8c, 0x00, 2, { 0x8c, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOV, FT_MOV_RM_SEG, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MOV_SEG_RM] =
        { 2, 0, 0, 0x8e, 0x00, 2, { 0x8e, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOV, FT_MOV_SEG_RM, FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CMP_RM16_IMM8] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x83, 0x00, 2,
          { 0x66, 0x83, 0xf8, 0 }, { 0xff, 0xff, 0xff, 0 }, -1,
          0xf8, -1, 0, -1, 0, dt_X86_INS_CMP, FT_CMP_RM16_IMM8 },
    [FT_CMP_RM16_IMM16] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x81, 0x00, 2,
          { 0x66, 0x81, 0xf8, 0, 0 }, { 0xff, 0xff, 0xff, 0, 0 },
          -1, 0xf8, -1, 0, -1, 0, dt_X86_INS_CMP,
          FT_CMP_RM16_IMM16 },
    [FT_MOV_RM32_R32] =
        { 2, 0, 0, 0x89, 0x00, 2, { 0x89, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOV, FT_MOV_RM32_R32 },
    [FT_CMP_AL_IMM8] =
        { 2, 0, 0, 0x3c, 0x00, 3, { 0x3c, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_CMP, FT_CMP_AL_IMM8 },
    [FT_ADD_RM8_R8] =
        { 2, 0, 0, 0x00, 0x00, 4, { 0x00, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_ADD_RM8_R8 },
    [FT_ADD_RM32_R32] =
        { 2, 0, 0, 0x01, 0x00, 4, { 0x01, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_ADD_RM32_R32 },
    [FT_ADD_RM16_R16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x01, 0x00, 2,
          { 0x66, 0x01, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_ADD, FT_ADD_RM16_R16 },
    [FT_AND_R32_IMM8] =
        { 3, 0, 0, 0x83, 0x00, 4, { 0x83, 0xe0, 0 },
          { 0xff, 0xff, 0 }, -1, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_AND, FT_AND_R32_IMM8 },
    [FT_TEST_RM8_R8] =
        { 2, 0, 0, 0x84, 0x00, 1, { 0x84, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_TEST, FT_TEST_RM8_R8 },
    [FT_MOV_RM8_R8] =
        { 2, 0, 0, 0x88, 0x00, 1, { 0x88, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOV, FT_MOV_RM8_R8 },
    [FT_CMP_RM8_IMM8] =
        { 3, 0, 0, 0x80, 0x00, 2, { 0x80, 0xf8, 0 },
          { 0xff, 0xff, 0 }, -1, 0xf8, -1, 0, -1, 0,
          dt_X86_INS_CMP, FT_CMP_RM8_IMM8 },
    [FT_ADD_RM64_R64] =
        { 3, 0, 0, 0x01, 0x00, 3, { 0x48, 0x01, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_ADD_RM64_R64 },
    [FT_XOR_RM64_R64] =
        { 3, 0, 0, 0x31, 0x00, 2, { 0x48, 0x31, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XOR, FT_XOR_RM64_R64 },
    [FT_XOR_RM32_R32] =
        { 2, 0, 0, 0x31, 0x00, 2, { 0x31, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XOR, FT_XOR_RM32_R32 },
    [FT_XOR_RM8_R8] =
        { 2, 0, 0, 0x30, 0x00, 2, { 0x30, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XOR, FT_XOR_RM8_R8 },
    [FT_XOR_R64_RM64] =
        { 3, 0, 0, 0x33, 0x00, 2, { 0x48, 0x33, 0xc0 },
          { 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XOR, FT_XOR_R64_RM64 },
    [FT_XOR_R32_RM32] =
        { 2, 0, 0, 0x33, 0x00, 2, { 0x33, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XOR, FT_XOR_R32_RM32 },
    [FT_XOR_R16_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0x33, 0x00, 2,
          { 0x66, 0x33, 0xc0 }, { 0xff, 0xff, 0xc0 }, -1, 0xc0,
          -1, 0, -1, 0, dt_X86_INS_XOR, FT_XOR_R16_RM16 },
    [FT_XOR_R8_RM8] =
        { 2, 0, 0, 0x32, 0x00, 2, { 0x32, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XOR, FT_XOR_R8_RM8 },
    [FT_CMP_RM8_R8] =
        { 2, 0, 0, 0x38, 0x00, 1, { 0x38, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_CMP, FT_CMP_RM8_R8 },
    [FT_CMP_R8_RM8] =
        { 2, 0, 0, 0x3a, 0x00, 1, { 0x3a, 0xc0 },
          { 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_CMP, FT_CMP_R8_RM8 },
    [FT_MOV_RM32_IMM32] =
        { 6, 0, 0, 0xc7, 0x00, 2, { 0xc7, 0xc0, 0, 0, 0, 0 },
          { 0xff, 0xf8, 0, 0, 0, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOV, FT_MOV_RM32_IMM32 },
    [FT_CMP_RM32_IMM8] =
        { 3, 0, 0, 0x83, 0x00, 2, { 0x83, 0xf8, 0 },
          { 0xff, 0xff, 0 }, -1, 0xf8, -1, 0, -1, 0,
          dt_X86_INS_CMP, FT_CMP_RM32_IMM8 },
    [FT_GRP1_RM32_IMM32] =
        { 6, 0, 0, 0x81, 0x00, 4, { 0x81, 0xc0, 0, 0, 0, 0 },
          { 0xff, 0xc0, 0, 0, 0, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_ADD, FT_GRP1_RM32_IMM32 },
    [FT_GRP1_RM64_IMM32] =
        { 7, 0, 0, 0x81, 0x00, 4, { 0x48, 0x81, 0xc0, 0, 0, 0, 0 },
          { 0xff, 0xff, 0xc0, 0, 0, 0, 0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_ADD, FT_GRP1_RM64_IMM32 },
    [FT_CMP_EAX_IMM32] =
        { 5, 0, 0, 0x3d, 0x00, 2, { 0x3d, 0, 0, 0, 0 },
          { 0xff, 0, 0, 0, 0 }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_CMP, FT_CMP_EAX_IMM32 },
    [FT_CMP_AX_IMM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x3d, 0x00, 2,
          { 0x66, 0x3d, 0, 0 }, { 0xff, 0xff, 0, 0 },
          -1, -1, -1, 0, 2, 2, dt_X86_INS_CMP,
          FT_CMP_AX_IMM16 },
    [FT_MOV_RM8_IMM8] =
        { 3, 0, 0, 0xc6, 0x00, 2, { 0xc6, 0xc0, 0 },
          { 0xff, 0xf8, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_MOV, FT_MOV_RM8_IMM8 },
    [FT_TEST_RM8_IMM8] =
        { 3, 0, 0, 0xf6, 0x00, 2, { 0xf6, 0xc0, 0 },
          { 0xff, 0xf8, 0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_TEST, FT_TEST_RM8_IMM8 },
    [FT_NOP_MULTI] =
        { 3, 0, 0, 0x0f, 0x1f, 1, { 0x0f, 0x1f, 0x00 },
          { 0xff, 0xff, 0xc0 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_NOP, FT_NOP_MULTI, FT_TM_CONSTRAINTS_DECLARED },
    [FT_CMP_RAX_IMM32] =
        { 6, 0, 0, 0x3d, 0x00, 2, { 0x48, 0x3d, 0, 0, 0, 0 },
          { 0xff, 0xff, 0, 0, 0, 0 }, 0x48, -1, -1, 0, 2, 4,
          dt_X86_INS_CMP, FT_CMP_RAX_IMM32 },
    [FT_MOV_R64_IMM64] =
        { 10, 0, 0, 0xb8, 0x00, 4, { 0x48, 0xb8 },
          { 0xf8, 0xf8 }, 0x48, -1, -1, 0, 2, 8,
          dt_X86_INS_MOV, FT_MOV_R64_IMM64,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_LEA_R32_M] =
        { 3, 0, 0, 0x8d, 0x00, 4, { 0x8d, 0x04, 0x12 },
          { 0xff, 0xff, 0xff }, -1, 0x04, -1, 0, -1, 0,
          dt_X86_INS_LEA, FT_LEA_R32_M },
    [FT_LEA_R16_M] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x8d, 0x00, 4,
          { 0x66, 0x8d, 0x04, 0x12 }, { 0xff, 0xff, 0xff, 0xff },
          -1, 0x04, -1, 0, -1, 0, dt_X86_INS_LEA, FT_LEA_R16_M },
    [FT_CALL_REL32] =
        { 5, 0, 0, 0xe8, 0x00, 6, { 0xe8 },
          { 0xff }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_CALL, FT_CALL_REL32,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_CALL_RM64] =
        { 2, 0, 0, 0xff, 0x00, 0, { 0xff, 0xd0 },
          { 0xff, 0xf8 }, -1, 0xd0, -1, 0, -1, 0,
          dt_X86_INS_CALL, FT_CALL_RM64 },
    [FT_JMP_REL32] =
        { 5, 0, 0, 0xe9, 0x00, 4, { 0xe9 },
          { 0xff }, -1, -1, -1, 0, 1, 4,
          dt_X86_INS_JMP, FT_JMP_REL32,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_JMP_RM64] =
        { 2, 0, 0, 0xff, 0x00, 0, { 0xff, 0xe0 },
          { 0xff, 0xf8 }, -1, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_JMP, FT_JMP_RM64 },
    [FT_CMP_RM64_IMM32] =
        { 7, 0, 0, 0x81, 0x00, 3, { 0x48, 0x81, 0xf8, 0, 0, 0, 0 },
          { 0xf8, 0xff, 0xf8, 0, 0, 0, 0 }, 0x48, 0xf8, -1, 0, 3, 4,
          dt_X86_INS_CMP, FT_CMP_RM64_IMM32 },
    [FT_CMOV_R64_RM64] =
        { 4, 0, 0, 0x0f, 0x40, 4, { 0x48, 0x0f, 0x40, 0xc0 },
          { 0xf8, 0xff, 0xf0, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_CMOVO, FT_CMOV_R64_RM64, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CMOV_R32_RM32] =
        { 3, 0, 0, 0x0f, 0x40, 5, { 0x0f, 0x40, 0xc0 },
          { 0xff, 0xf0, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_CMOVO, FT_CMOV_R32_RM32, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CMOV_R16_RM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x40, 5,
          { 0x66, 0x0f, 0x40, 0xc0 }, { 0xff, 0xff, 0xf0, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_CMOVO, FT_CMOV_R16_RM16,
          FT_TM_NO_EXTRA_CONSTRAINTS | FT_TM_FORBIDS_REX_W },
    [FT_SETCC_RM8] =
        { 3, 0, 0, 0x0f, 0x90, 2, { 0x0f, 0x90, 0xc0 },
          { 0xff, 0xf0, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_SETO, FT_SETCC_RM8,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_BTX_RM32_IMM8] =
        { 4, 0, 0, 0x0f, 0xba, 5, { 0x0f, 0xba, 0xe0, 0 },
          { 0xff, 0xff, 0xc0, 0 }, -1, 0xe0, -1, 0, 3, 1,
          dt_X86_INS_BT, FT_BTX_RM32_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_IMM_U8 |
          FT_TM_MODRM_REG_EXT_MASK,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT,
          -1, 0, 0xf0 },
    [FT_BTX_RM_R] =
        { 3, 0, 0, 0x0f, 0xa3, 0, { 0x0f, 0xa3, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_BT, FT_BTX_RM_R,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_JRCXZ_REL8] =
        { 2, 0, 0, 0xe3, 0x00, 6, { 0xe3, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_JRCXZ, FT_JRCXZ_REL8,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_LOOP_REL8] =
        { 2, 0, 0, 0xe2, 0x00, 8, { 0xe2, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_LOOP, FT_LOOP_REL8, FT_TM_CONSTRAINTS_DECLARED },
    [FT_LOOPE_REL8] =
        { 2, 0, 0, 0xe1, 0x00, 10, { 0xe1, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_LOOPE, FT_LOOPE_REL8, FT_TM_CONSTRAINTS_DECLARED },
    [FT_LOOPNE_REL8] =
        { 2, 0, 0, 0xe0, 0x00, 10, { 0xe0, 0 },
          { 0xff, 0 }, -1, -1, -1, 0, 1, 1,
          dt_X86_INS_LOOPNE, FT_LOOPNE_REL8, FT_TM_CONSTRAINTS_DECLARED },
    [FT_CLD] =
        { 1, 0, 0, 0xfc, 0x00, 1, { 0xfc }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_CLD, FT_CLD, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_STD] =
        { 1, 0, 0, 0xfd, 0x00, 1, { 0xfd }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_STD, FT_STD, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_CLC] =
        { 1, 0, 0, 0xf8, 0x00, 1, { 0xf8 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_CLC, FT_CLC,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_STC] =
        { 1, 0, 0, 0xf9, 0x00, 2, { 0xf9 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_STC, FT_STC,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_CMC] =
        { 1, 0, 0, 0xf5, 0x00, 3, { 0xf5 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_CMC, FT_CMC,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_LAHF] =
        { 1, 0, 0, 0x9f, 0x00, 4, { 0x9f }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_LAHF, FT_LAHF,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_SAHF] =
        { 1, 0, 0, 0x9e, 0x00, 3, { 0x9e }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_SAHF, FT_SAHF,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_PUSHFQ] =
        { 1, 0, 0, 0x9c, 0x00, 4, { 0x9c }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_PUSHFQ, FT_PUSHFQ,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_POPFQ] =
        { 1, 0, 0, 0x9d, 0x00, 7, { 0x9d }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_POPFQ, FT_POPFQ,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_BSF_R64_RM64] =
        { 4, 0, 0, 0x0f, 0xbc, 0, { 0x48, 0x0f, 0xbc, 0xc0 },
          { 0xf8, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_BSF, FT_BSF_R64_RM64 },
    [FT_BSF_R32_RM32] =
        { 3, 0, 0, 0x0f, 0xbc, 0, { 0x0f, 0xbc, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_BSF, FT_BSF_R32_RM32 },
    [FT_BSF_R16_RM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xbc, 0,
          { 0x66, 0x0f, 0xbc, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_BSF, FT_BSF_R16_RM16 },
    [FT_BSR_R64_RM64] =
        { 4, 0, 0, 0x0f, 0xbd, 0, { 0x48, 0x0f, 0xbd, 0xc0 },
          { 0xf8, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_BSR, FT_BSR_R64_RM64 },
    [FT_BSR_R32_RM32] =
        { 3, 0, 0, 0x0f, 0xbd, 0, { 0x0f, 0xbd, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_BSR, FT_BSR_R32_RM32 },
    [FT_BSR_R16_RM16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xbd, 0,
          { 0x66, 0x0f, 0xbd, 0xc0 }, { 0xff, 0xff, 0xff, 0xc0 },
          -1, 0xc0, -1, 0, -1, 0, dt_X86_INS_BSR, FT_BSR_R16_RM16 },
    [FT_LZCNT_R64_RM64] =
        { 5, dt_X86_PREFIX_REP, 0, 0x0f, 0xbd, 0,
          { 0xf3, 0x48, 0x0f, 0xbd, 0xc0 },
          { 0xff, 0xf8, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_LZCNT, FT_LZCNT_R64_RM64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_PREFIX0_REP,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_LZCNT_R32_RM32] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0xbd, 0,
          { 0xf3, 0x0f, 0xbd, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_LZCNT, FT_LZCNT_R32_RM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_PREFIX0_REP,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_LZCNT_R16_RM16] =
        { 5, dt_X86_PREFIX_REP, dt_X86_PREFIX_OPSIZE, 0x0f, 0xbd, 0,
          { 0x66, 0xf3, 0x0f, 0xbd, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_LZCNT, FT_LZCNT_R16_RM16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_PREFIX0_REP,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_TZCNT_R64_RM64] =
        { 5, dt_X86_PREFIX_REP, 0, 0x0f, 0xbc, 0,
          { 0xf3, 0x48, 0x0f, 0xbc, 0xc0 },
          { 0xff, 0xf8, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_TZCNT, FT_TZCNT_R64_RM64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_PREFIX0_REP,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_TZCNT_R32_RM32] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0xbc, 0,
          { 0xf3, 0x0f, 0xbc, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_TZCNT, FT_TZCNT_R32_RM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_PREFIX0_REP,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_TZCNT_R16_RM16] =
        { 5, dt_X86_PREFIX_REP, dt_X86_PREFIX_OPSIZE, 0x0f, 0xbc, 0,
          { 0x66, 0xf3, 0x0f, 0xbc, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_TZCNT, FT_TZCNT_R16_RM16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_PREFIX0_REP,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_POPCNT_R64_RM64] =
        { 5, dt_X86_PREFIX_REP, 0, 0x0f, 0xb8, 0,
          { 0xf3, 0x48, 0x0f, 0xb8, 0xc0 },
          { 0xff, 0xf8, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_POPCNT, FT_POPCNT_R64_RM64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_PREFIX0_REP,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_POPCNT_R32_RM32] =
        { 4, dt_X86_PREFIX_REP, 0, 0x0f, 0xb8, 0,
          { 0xf3, 0x0f, 0xb8, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_POPCNT, FT_POPCNT_R32_RM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_PREFIX0_REP,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_POPCNT_R16_RM16] =
        { 5, dt_X86_PREFIX_REP, dt_X86_PREFIX_OPSIZE, 0x0f, 0xb8, 0,
          { 0x66, 0xf3, 0x0f, 0xb8, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_POPCNT, FT_POPCNT_R16_RM16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_PREFIX0_REP,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_BSWAP_R32] =
        { 2, 0, 0, 0x0f, 0xc8, 2, { 0x0f, 0xc8 },
          { 0xff, 0xf8 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_BSWAP, FT_BSWAP_R32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_OPCODE_REG_VALID },
    [FT_BSWAP_R64] =
        { 3, 0, 0, 0x0f, 0xc8, 1, { 0x48, 0x0f, 0xc8 },
          { 0xf8, 0xff, 0xf8 }, 0x48, -1, -1, 0, -1, 0,
          dt_X86_INS_BSWAP, FT_BSWAP_R64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_OPCODE_REG_VALID },
    [FT_MOVBE_R64_M64] =
        { 5, 0, 0, 0x0f, 0xf0, 1, { 0x48, 0x0f, 0x38, 0xf0, 0x00 },
          { 0xf8, 0xff, 0xff, 0xff, 0xc0 }, 0x48, 0x00, -1, 0,
          -1, 0, dt_X86_INS_MOVBE, FT_MOVBE_R64_M64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_MOVBE_R32_M32] =
        { 4, 0, 0, 0x0f, 0xf0, 1, { 0x0f, 0x38, 0xf0, 0x00 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_MOVBE, FT_MOVBE_R32_M32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_MOVBE_R16_M16] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xf0, 1,
          { 0x66, 0x0f, 0x38, 0xf0, 0x00 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0x00, -1, 0,
          -1, 0, dt_X86_INS_MOVBE, FT_MOVBE_R16_M16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_MOVBE_M64_R64] =
        { 5, 0, 0, 0x0f, 0xf1, 1, { 0x48, 0x0f, 0x38, 0xf1, 0x00 },
          { 0xf8, 0xff, 0xff, 0xff, 0xc0 }, 0x48, 0x00, -1, 0,
          -1, 0, dt_X86_INS_MOVBE, FT_MOVBE_M64_R64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_MOVBE_M32_R32] =
        { 4, 0, 0, 0x0f, 0xf1, 1, { 0x0f, 0x38, 0xf1, 0x00 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_MOVBE, FT_MOVBE_M32_R32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_MOVBE_M16_R16] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xf1, 1,
          { 0x66, 0x0f, 0x38, 0xf1, 0x00 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0x00, -1, 0,
          -1, 0, dt_X86_INS_MOVBE, FT_MOVBE_M16_R16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_CRC32_R_RM8] =
        { 5, dt_X86_PREFIX_REPNE, 0, 0x0f, 0xf0, 1,
          { 0xf2, 0x0f, 0x38, 0xf0, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_CRC32, FT_CRC32_R_RM8,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CRC32_R_RM16] =
        { 6, dt_X86_PREFIX_REPNE, dt_X86_PREFIX_OPSIZE, 0x0f, 0xf1, 1,
          { 0xf2, 0x66, 0x0f, 0x38, 0xf1, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_CRC32, FT_CRC32_R_RM16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CRC32_R_RM32] =
        { 5, dt_X86_PREFIX_REPNE, 0, 0x0f, 0xf1, 1,
          { 0xf2, 0x0f, 0x38, 0xf1, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_CRC32, FT_CRC32_R_RM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CRC32_R_RM64] =
        { 6, dt_X86_PREFIX_REPNE, 0, 0x0f, 0xf1, 1,
          { 0xf2, 0x48, 0x0f, 0x38, 0xf1, 0xc0 },
          { 0xff, 0xf8, 0xff, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_CRC32, FT_CRC32_R_RM64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_ADCX_R32_RM32] =
        { 5, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xf6, 1,
          { 0x66, 0x0f, 0x38, 0xf6, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_ADCX, FT_ADCX_R32_RM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_ADCX_R64_RM64] =
        { 6, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xf6, 1,
          { 0x66, 0x48, 0x0f, 0x38, 0xf6, 0xc0 },
          { 0xff, 0xf8, 0xff, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_ADCX, FT_ADCX_R64_RM64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_ADOX_R32_RM32] =
        { 5, dt_X86_PREFIX_REP, 0, 0x0f, 0xf6, 1,
          { 0xf3, 0x0f, 0x38, 0xf6, 0xc0 },
          { 0xff, 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_ADOX, FT_ADOX_R32_RM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_ADOX_R64_RM64] =
        { 6, dt_X86_PREFIX_REP, 0, 0x0f, 0xf6, 1,
          { 0xf3, 0x48, 0x0f, 0x38, 0xf6, 0xc0 },
          { 0xff, 0xf8, 0xff, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_ADOX, FT_ADOX_R64_RM64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_RDRAND_R64] =
        { 4, 0, 0, 0x0f, 0xc7, 4, { 0x48, 0x0f, 0xc7, 0xf0 },
          { 0xf8, 0xff, 0xff, 0xf8 }, 0x48, 0xf0, -1, 0,
          -1, 0, dt_X86_INS_RDRAND, FT_RDRAND_R64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_MODRM_REG_ONLY | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG, 6 },
    [FT_RDRAND_R32] =
        { 3, 0, 0, 0x0f, 0xc7, 4, { 0x0f, 0xc7, 0xf0 },
          { 0xff, 0xff, 0xf8 }, -1, 0xf0, -1, 0, -1, 0,
          dt_X86_INS_RDRAND, FT_RDRAND_R32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_ONLY | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG, 6 },
    [FT_RDRAND_R16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xc7, 4,
          { 0x66, 0x0f, 0xc7, 0xf0 },
          { 0xff, 0xff, 0xff, 0xf8 }, -1, 0xf0, -1, 0,
          -1, 0, dt_X86_INS_RDRAND, FT_RDRAND_R16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_ONLY | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG, 6 },
    [FT_RDTSC] =
        { 2, 0, 0, 0x0f, 0x31, 3, { 0x0f, 0x31 },
          { 0xff, 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_RDTSC, FT_RDTSC,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_RDTSCP] =
        { 3, 0, 0, 0x0f, 0x01, 4, { 0x0f, 0x01, 0xf9 },
          { 0xff, 0xff, 0xff }, -1, 0xf9, -1, 0, -1, 0,
          dt_X86_INS_RDTSCP, FT_RDTSCP,
          FT_TM_CONSTRAINTS_DECLARED },
    [FT_XGETBV] =
        { 3, 0, 0, 0x0f, 0x01, 0, { 0x0f, 0x01, 0xd0 },
          { 0xff, 0xff, 0xff }, -1, 0xd0, -1, 0, -1, 0,
          dt_X86_INS_XGETBV, FT_XGETBV,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_ANDN_R64_R_RM] =
        { 5, 0, 0, 0xc4, 0xf2, 4, { 0xc4, 0xe2, 0x80, 0xf2, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_ANDN, FT_ANDN_R64_R_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_ANDN_R32_R_RM] =
        { 5, 0, 0, 0xc4, 0xf2, 4, { 0xc4, 0xe2, 0x00, 0xf2, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_ANDN, FT_ANDN_R32_R_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MULX_R64_R_RM] =
        { 5, 0, 0, 0xc4, 0xf6, 4, { 0xc4, 0xe2, 0x83, 0xf6, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_MULX, FT_MULX_R64_R_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MULX_R32_R_RM] =
        { 5, 0, 0, 0xc4, 0xf6, 4, { 0xc4, 0xe2, 0x03, 0xf6, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_MULX, FT_MULX_R32_R_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_BLS_R64_RM] =
        { 5, 0, 0, 0xc4, 0xf3, 4, { 0xc4, 0xe2, 0x80, 0xf3, 0xc8 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc8, -1, 0,
          -1, 0, dt_X86_INS_BLSI, FT_BLS_R64_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_MODRM_REG_EXT_MASK,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, -1, 0, (1u << 1) |
          (1u << 2) | (1u << 3) },
    [FT_BLS_R32_RM] =
        { 5, 0, 0, 0xc4, 0xf3, 4, { 0xc4, 0xe2, 0x00, 0xf3, 0xc8 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc8, -1, 0,
          -1, 0, dt_X86_INS_BLSI, FT_BLS_R32_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_EXT_MASK,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, -1, 0, (1u << 1) |
          (1u << 2) | (1u << 3) },
    [FT_BEXTR_R64_RM_R] =
        { 5, 0, 0, 0xc4, 0xf7, 4, { 0xc4, 0xe2, 0x80, 0xf7, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_BEXTR, FT_BEXTR_R64_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_BEXTR_R32_RM_R] =
        { 5, 0, 0, 0xc4, 0xf7, 4, { 0xc4, 0xe2, 0x00, 0xf7, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_BEXTR, FT_BEXTR_R32_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SHLX_R64_RM_R] =
        { 5, 0, 0, 0xc4, 0xf7, 4, { 0xc4, 0xe2, 0x81, 0xf7, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_SHLX, FT_SHLX_R64_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SHLX_R32_RM_R] =
        { 5, 0, 0, 0xc4, 0xf7, 4, { 0xc4, 0xe2, 0x01, 0xf7, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_SHLX, FT_SHLX_R32_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SARX_R64_RM_R] =
        { 5, 0, 0, 0xc4, 0xf7, 4, { 0xc4, 0xe2, 0x82, 0xf7, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_SARX, FT_SARX_R64_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SARX_R32_RM_R] =
        { 5, 0, 0, 0xc4, 0xf7, 4, { 0xc4, 0xe2, 0x02, 0xf7, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_SARX, FT_SARX_R32_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SHRX_R64_RM_R] =
        { 5, 0, 0, 0xc4, 0xf7, 4, { 0xc4, 0xe2, 0x83, 0xf7, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_SHRX, FT_SHRX_R64_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_SHRX_R32_RM_R] =
        { 5, 0, 0, 0xc4, 0xf7, 4, { 0xc4, 0xe2, 0x03, 0xf7, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_SHRX, FT_SHRX_R32_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_BZHI_R64_RM_R] =
        { 5, 0, 0, 0xc4, 0xf5, 4, { 0xc4, 0xe2, 0x80, 0xf5, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_BZHI, FT_BZHI_R64_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_BZHI_R32_RM_R] =
        { 5, 0, 0, 0xc4, 0xf5, 4, { 0xc4, 0xe2, 0x00, 0xf5, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_BZHI, FT_BZHI_R32_RM_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PEXT_R64_R_RM] =
        { 5, 0, 0, 0xc4, 0xf5, 4, { 0xc4, 0xe2, 0x82, 0xf5, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PEXT, FT_PEXT_R64_R_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PEXT_R32_R_RM] =
        { 5, 0, 0, 0xc4, 0xf5, 4, { 0xc4, 0xe2, 0x02, 0xf5, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PEXT, FT_PEXT_R32_R_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PDEP_R64_R_RM] =
        { 5, 0, 0, 0xc4, 0xf5, 4, { 0xc4, 0xe2, 0x83, 0xf5, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PDEP, FT_PDEP_R64_R_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_PDEP_R32_R_RM] =
        { 5, 0, 0, 0xc4, 0xf5, 4, { 0xc4, 0xe2, 0x03, 0xf5, 0xc0 },
          { 0xff, 0x1f, 0x87, 0xff, 0xc0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_PDEP, FT_PDEP_R32_R_RM,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_IMUL_RM8] =
        { 2, 0, 0, 0xf6, 0x00, 7, { 0xf6, 0xe8 },
          { 0xff, 0xf8 }, -1, 0xe8, -1, 0, -1, 0,
          dt_X86_INS_IMUL, FT_IMUL_RM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT,
          5 },
    [FT_IMUL_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0xf7, 0x00, 7,
          { 0x66, 0xf7, 0xe8 }, { 0xff, 0xff, 0xf8 }, -1, 0xe8,
          -1, 0, -1, 0, dt_X86_INS_IMUL, FT_IMUL_RM16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT,
          5 },
    [FT_IMUL_RM32] =
        { 2, 0, 0, 0xf7, 0x00, 7, { 0xf7, 0xe8 },
          { 0xff, 0xf8 }, -1, 0xe8, -1, 0, -1, 0,
          dt_X86_INS_IMUL, FT_IMUL_RM32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT,
          5 },
    [FT_IMUL_RM64] =
        { 3, 0, 0, 0xf7, 0x00, 7, { 0x48, 0xf7, 0xe8 },
          { 0xf8, 0xff, 0xf8 }, 0x48, 0xe8, -1, 0, -1, 0,
          dt_X86_INS_IMUL, FT_IMUL_RM64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT,
          5 },
    [FT_MUL_RM8] =
        { 2, 0, 0, 0xf6, 0x00, 4, { 0xf6, 0xe0 },
          { 0xff, 0xf8 }, -1, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_MUL, FT_MUL_RM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT,
          4 },
    [FT_MUL_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0xf7, 0x00, 4,
          { 0x66, 0xf7, 0xe0 }, { 0xff, 0xff, 0xf8 }, -1, 0xe0,
          -1, 0, -1, 0, dt_X86_INS_MUL, FT_MUL_RM16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT,
          5 },
    [FT_MUL_RM32] =
        { 2, 0, 0, 0xf7, 0x00, 7, { 0xf7, 0xe0 },
          { 0xff, 0xf8 }, -1, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_MUL, FT_MUL_RM32 },
    [FT_ROL_RM64_IMM8] =
        { 4, 0, 0, 0xc1, 0x00, 3, { 0x48, 0xc1, 0xc0, 0 },
          { 0xf8, 0xff, 0xf8, 0 }, 0x48, 0xc0, -1, 0, 3, 1,
          dt_X86_INS_ROL, FT_ROL_RM64_IMM8,
          FT_TM_READS_RAW_MODRM | FT_TM_READS_RAW_IMM8 },
    [FT_ROR_RM64_IMM8] =
        { 4, 0, 0, 0xc1, 0x00, 3, { 0x48, 0xc1, 0xc8, 0 },
          { 0xf8, 0xff, 0xf8, 0 }, 0x48, 0xc8, -1, 0, 3, 1,
          dt_X86_INS_ROR, FT_ROR_RM64_IMM8,
          FT_TM_READS_RAW_MODRM | FT_TM_READS_RAW_IMM8 },
    [FT_RORX_R64_RM64_IMM8] =
        { 6, 0, 0, 0xc4, 0xf0, 5, { 0xc4, 0xe3, 0xfb, 0xf0, 0xc0, 0 },
          { 0xff, 0x1f, 0x7f, 0xff, 0xc0, 0 }, 0x48, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_RORX, FT_RORX_R64_RM64_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_RORX_R32_RM32_IMM8] =
        { 6, 0, 0, 0xc4, 0xf0, 5, { 0xc4, 0xe3, 0x7b, 0xf0, 0xc0, 0 },
          { 0xff, 0x1f, 0x7f, 0xff, 0xc0, 0 }, -1, 0xc0, -1, 0,
          -1, 0, dt_X86_INS_RORX, FT_RORX_R32_RM32_IMM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_MUL_RM64] =
        { 3, 0, 0, 0xf7, 0x00, 4, { 0x48, 0xf7, 0xe0 },
          { 0xf8, 0xff, 0xf8 }, 0x48, 0xe0, -1, 0, -1, 0,
          dt_X86_INS_MUL, FT_MUL_RM64 },
    [FT_DIV_RM8] =
        { 2, 0, 0, 0xf6, 0x00, 6, { 0xf6, 0xf0 },
          { 0xff, 0xf8 }, -1, 0xf0, -1, 0, -1, 0,
          dt_X86_INS_DIV, FT_DIV_RM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT,
          6 },
    [FT_DIV_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0xf7, 0x00, 0,
          { 0x66, 0xf7, 0xf0 }, { 0xff, 0xff, 0xf8 },
          -1, 0xf0, -1, 0, -1, 0, dt_X86_INS_DIV, FT_DIV_RM16 },
    [FT_DIV_RM32] =
        { 2, 0, 0, 0xf7, 0x00, 0, { 0xf7, 0xf0 },
          { 0xff, 0xf8 }, -1, 0xf0, -1, 0, -1, 0,
          dt_X86_INS_DIV, FT_DIV_RM32 },
    [FT_DIV_RM64] =
        { 3, 0, 0, 0xf7, 0x00, 0, { 0x48, 0xf7, 0xf0 },
          { 0xf8, 0xff, 0xf8 }, 0x48, 0xf0, -1, 0, -1, 0,
          dt_X86_INS_DIV, FT_DIV_RM64 },
    [FT_IDIV_RM8] =
        { 2, 0, 0, 0xf6, 0x00, 7, { 0xf6, 0xf8 },
          { 0xff, 0xf8 }, -1, 0xf8, -1, 0, -1, 0,
          dt_X86_INS_IDIV, FT_IDIV_RM8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT,
          7 },
    [FT_IDIV_RM16] =
        { 3, 0, dt_X86_PREFIX_OPSIZE, 0xf7, 0x00, 0,
          { 0x66, 0xf7, 0xf8 }, { 0xff, 0xff, 0xf8 },
          -1, 0xf8, -1, 0, -1, 0, dt_X86_INS_IDIV, FT_IDIV_RM16 },
    [FT_IDIV_RM32] =
        { 2, 0, 0, 0xf7, 0x00, 0, { 0xf7, 0xf8 },
          { 0xff, 0xf8 }, -1, 0xf8, -1, 0, -1, 0,
          dt_X86_INS_IDIV, FT_IDIV_RM32 },
    [FT_IDIV_RM64] =
        { 3, 0, 0, 0xf7, 0x00, 0, { 0x48, 0xf7, 0xf8 },
          { 0xf8, 0xff, 0xf8 }, 0x48, 0xf8, -1, 0, -1, 0,
          dt_X86_INS_IDIV, FT_IDIV_RM64 },
    [FT_CMPXCHG_RM8_R8] =
        { 3, 0, 0, 0x0f, 0xb0, 0, { 0x0f, 0xb0, 0x00 },
          { 0xff, 0xff, 0x00 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_CMPXCHG, FT_CMPXCHG_RM8_R8,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CMPXCHG_RM16_R16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xb1, 0,
          { 0x66, 0x0f, 0xb1, 0x00 },
          { 0xff, 0xff, 0xff, 0x00 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_CMPXCHG, FT_CMPXCHG_RM16_R16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CMPXCHG_RM32_R32] =
        { 3, 0, 0, 0x0f, 0xb1, 0, { 0x0f, 0xb1, 0x00 },
          { 0xff, 0xff, 0x00 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_CMPXCHG, FT_CMPXCHG_RM32_R32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CMPXCHG_RM64_R64] =
        { 4, 0, 0, 0x0f, 0xb1, 0, { 0x48, 0x0f, 0xb1, 0x00 },
          { 0xf8, 0xff, 0xff, 0x00 }, 0x48, 0x00, -1, 0, -1, 0,
          dt_X86_INS_CMPXCHG, FT_CMPXCHG_RM64_R64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_CMPXCHG8B] =
        { 3, 0, 0, 0x0f, 0xc7, 4, { 0x0f, 0xc7, 0x08 },
          { 0xff, 0xff, 0x38 }, -1, 0x08, -1, 0, -1, 0,
          dt_X86_INS_CMPXCHG8B, FT_CMPXCHG8B,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_CMPXCHG16B] =
        { 4, 0, 0, 0x0f, 0xc7, 4, { 0x48, 0x0f, 0xc7, 0x08 },
          { 0xf8, 0xff, 0xff, 0x38 }, 0x48, 0x08, -1, 0, -1, 0,
          dt_X86_INS_CMPXCHG16B, FT_CMPXCHG16B,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_MODRM_MEM_ONLY | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_XADD_R8_R8] =
        { 3, 0, 0, 0x0f, 0xc0, 0, { 0x0f, 0xc0, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XADD, FT_XADD_R8_R8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_ONLY },
    [FT_XADD_R16_R16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xc1, 0,
          { 0x66, 0x0f, 0xc1, 0xc0 },
          { 0xff, 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XADD, FT_XADD_R16_R16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_ONLY },
    [FT_XADD_R32_R32] =
        { 3, 0, 0, 0x0f, 0xc1, 0, { 0x0f, 0xc1, 0xc0 },
          { 0xff, 0xff, 0xc0 }, -1, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XADD, FT_XADD_R32_R32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_REG_ONLY },
    [FT_XADD_R64_R64] =
        { 4, 0, 0, 0x0f, 0xc1, 0, { 0x48, 0x0f, 0xc1, 0xc0 },
          { 0xf8, 0xff, 0xff, 0xc0 }, 0x48, 0xc0, -1, 0, -1, 0,
          dt_X86_INS_XADD, FT_XADD_R64_R64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_MODRM_REG_ONLY },
    [FT_XADD_RM8_R8] =
        { 3, 0, 0, 0x0f, 0xc0, 0, { 0x0f, 0xc0, 0x00 },
          { 0xff, 0xff, 0x00 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_XADD, FT_XADD_RM8_R8,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_XADD_RM16_R16] =
        { 4, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0xc1, 0,
          { 0x66, 0x0f, 0xc1, 0x00 }, { 0xff, 0xff, 0xff, 0x00 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_XADD,
          FT_XADD_RM16_R16,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_XADD_RM32_R32] =
        { 3, 0, 0, 0x0f, 0xc1, 0, { 0x0f, 0xc1, 0x00 },
          { 0xff, 0xff, 0x00 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_XADD, FT_XADD_RM32_R32,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_FORBIDS_REX_W |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_XADD_RM64_R64] =
        { 4, 0, 0, 0x0f, 0xc1, 0, { 0x48, 0x0f, 0xc1, 0x00 },
          { 0xf8, 0xff, 0xff, 0x00 }, 0x48, 0x00, -1, 0, -1, 0,
          dt_X86_INS_XADD, FT_XADD_RM64_R64,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_STRING] =
        { 1, 0, 0, 0xa4, 0x00, 0, { 0xa4 }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_MOVSB,
          FT_STRING, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_STOSQ_REP] =
        { 3, dt_X86_PREFIX_REP, 0, 0xab, 0x00, 5,
          { 0xf3, 0x48, 0xab }, { 0xff, 0xff, 0xff },
          0x48, -1, -1, 0, -1, 0, dt_X86_INS_STOSQ,
          FT_STOSQ_REP,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_PREFIX0_REP },
    [FT_LAR] =
        { 0, 0, 0, 0x0f, 0x02, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_LAR, FT_LAR,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, -1 },
    [FT_LSL] =
        { 0, 0, 0, 0x0f, 0x03, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_LSL, FT_LSL,
          FT_TM_CONSTRAINTS_DECLARED,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT },
    [FT_LGDT] =
        { 0, 0, 0, 0x0f, 0x01, 0, { 0 }, { 0 },
          -1, 0x10, -1, 0, -1, 0, dt_X86_INS_LGDT, FT_LGDT,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 2 },
    [FT_LIDT] =
        { 0, 0, 0, 0x0f, 0x01, 0, { 0 }, { 0 },
          -1, 0x18, -1, 0, -1, 0, dt_X86_INS_LIDT, FT_LIDT,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 3 },
    [FT_SGDT] =
        { 0, 0, 0, 0x0f, 0x01, 0, { 0 }, { 0 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_SGDT, FT_SGDT,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 0 },
    [FT_SIDT] =
        { 0, 0, 0, 0x0f, 0x01, 0, { 0 }, { 0 },
          -1, 0x08, -1, 0, -1, 0, dt_X86_INS_SIDT, FT_SIDT,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_LLDT] =
        { 0, 0, 0, 0x0f, 0x00, 0, { 0 }, { 0 },
          -1, 0x10, -1, 0, -1, 0, dt_X86_INS_LLDT, FT_LLDT,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, 2 },
    [FT_LTR] =
        { 0, 0, 0, 0x0f, 0x00, 0, { 0 }, { 0 },
          -1, 0x18, -1, 0, -1, 0, dt_X86_INS_LTR, FT_LTR,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, 3 },
    [FT_SLDT] =
        { 0, 0, 0, 0x0f, 0x00, 0, { 0 }, { 0 },
          -1, 0x00, -1, 0, -1, 0, dt_X86_INS_SLDT, FT_SLDT,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, 0 },
    [FT_STR] =
        { 0, 0, 0, 0x0f, 0x00, 0, { 0 }, { 0 },
          -1, 0x08, -1, 0, -1, 0, dt_X86_INS_STR, FT_STR,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, 1 },
    [FT_SMSW] =
        { 0, 0, 0, 0x0f, 0x01, 0, { 0 }, { 0 },
          -1, 0x20, -1, 0, -1, 0, dt_X86_INS_SMSW, FT_SMSW,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, 4 },
    [FT_CLTS] =
        { 0, 0, 0, 0x0f, 0x06, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_CLTS, FT_CLTS,
          FT_TM_CONSTRAINTS_DECLARED, 0, -1 },
    [FT_INVD] =
        { 0, 0, 0, 0x0f, 0x08, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_INVD, FT_INVD,
          FT_TM_CONSTRAINTS_DECLARED, 0, -1 },
    [FT_WBINVD] =
        { 0, 0, 0, 0x0f, 0x09, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_WBINVD, FT_WBINVD,
          FT_TM_CONSTRAINTS_DECLARED, 0, -1 },
    [FT_INVLPG] =
        { 0, 0, 0, 0x0f, 0x01, 0, { 0 }, { 0 },
          -1, 0x38, -1, 0, -1, 0, dt_X86_INS_INVLPG, FT_INVLPG,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID |
          FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 7 },
    [FT_RDPMC] =
        { 0, 0, 0, 0x0f, 0x33, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_RDPMC, FT_RDPMC,
          FT_TM_CONSTRAINTS_DECLARED, 0, -1 },
    [FT_RDMSR] =
        { 0, 0, 0, 0x0f, 0x32, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_RDMSR, FT_RDMSR,
          FT_TM_CONSTRAINTS_DECLARED, 0, -1 },
    [FT_WRMSR] =
        { 0, 0, 0, 0x0f, 0x30, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_WRMSR, FT_WRMSR,
          FT_TM_CONSTRAINTS_DECLARED, 0, -1 },
    [FT_SWAPGS] =
        { 0, 0, 0, 0x0f, 0x01, 0, { 0x0f, 0x01, 0xf8 },
          { 0xff, 0xff, 0xff }, -1, 0x38, -1, 0, -1, 0,
          dt_X86_INS_SWAPGS, FT_SWAPGS,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG, 7 },
    [FT_VERR] =
        { 0, 0, 0, 0x0f, 0x00, 0, { 0 }, { 0 },
          -1, 0x20, -1, 0, -1, 0, dt_X86_INS_VERR, FT_VERR,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, 4 },
    [FT_VERW] =
        { 0, 0, 0, 0x0f, 0x00, 0, { 0 }, { 0 },
          -1, 0x28, -1, 0, -1, 0, dt_X86_INS_VERW, FT_VERW,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_REG | FT_TM_ADDR_RIP | FT_TM_ADDR_BASE |
          FT_TM_ADDR_LEA | FT_TM_ADDR_SEGMENT, 5 },
    [FT_MOVNTI_M_R] =
        { 3, 0, 0, 0x0f, 0xc3, 0, { 0x0f, 0xc3, 0x00 },
          { 0xff, 0xff, 0x00 }, -1, 0x00, -1, 0, -1, 0,
          dt_X86_INS_MOVNTI, FT_MOVNTI_M_R,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT },
    [FT_HELPER_CPUID] =
        { 2, 0, 0, 0x0f, 0xa2, 0, { 0x0f, 0xa2 },
          { 0xff, 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_CPUID, FT_HELPER_CPUID, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HLT] =
        { 1, 0, 0, 0xf4, 0, 0, { 0xf4 },
          { 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_HLT, FT_HLT, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_SYSCALL] =
        { 2, 0, 0, 0x0f, 0x05, 0, { 0x0f, 0x05 },
          { 0xff, 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_SYSCALL, FT_HELPER_SYSCALL, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_GPF] =
        { 0, 0, 0, 0, 0, 0, { 0 }, { 0 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_IN, FT_HELPER_GPF, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_INT] =
        { 2, 0, 0, 0xcd, 0, 0, { 0xcd, 0 }, { 0xff, 0 },
          -1, -1, 1, 1, -1, 0, dt_X86_INS_INT, FT_HELPER_INT,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_INT3] =
        { 1, 0, 0, 0xcc, 0, 0, { 0xcc }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_INT3, FT_HELPER_INT3,
          FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_IRET] =
        { 2, 0, dt_X86_PREFIX_OPSIZE, 0xcf, 0, 0,
          { 0x66, 0xcf }, { 0xff, 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_IRET, FT_HELPER_IRET, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_IRETD] =
        { 1, 0, 0, 0xcf, 0, 0, { 0xcf }, { 0xff },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_IRETD, FT_HELPER_IRETD,
          FT_TM_NO_EXTRA_CONSTRAINTS | FT_TM_FORBIDS_REX_W },
    [FT_HELPER_IRETQ] =
        { 2, 0, 0, 0xcf, 0, 0, { 0x48, 0xcf }, { 0xff, 0xff },
          0x48, -1, -1, 0, -1, 0, dt_X86_INS_IRETQ, FT_HELPER_IRETQ,
          FT_TM_NO_EXTRA_CONSTRAINTS | FT_TM_REQUIRES_REX_W },
    [FT_HELPER_LJMP] =
        { 0, 0, 0, 0xff, 0, 0, { 0 }, { 0 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_LJMP, FT_HELPER_LJMP,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_REQUIRES_REX_W |
          FT_TM_MODRM_MEM_ONLY | FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 5 },
    [FT_HELPER_RETFQ] =
        { 0, 0, 0, 0xcb, 0, 0, { 0 }, { 0 }, 0x48, -1, -1, 0, -1, 0,
          dt_X86_INS_RETFQ, FT_HELPER_RETFQ,
          FT_TM_NO_EXTRA_CONSTRAINTS | FT_TM_REQUIRES_REX_W },
    [FT_HELPER_UD0] =
        { 3, 0, 0, 0x0f, 0xff, 0, { 0x0f, 0xff, 0x00 },
          { 0xff, 0xff, 0x00 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_UD0, FT_HELPER_UD0, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_UD1] =
        { 3, 0, 0, 0x0f, 0xb9, 0, { 0x0f, 0xb9, 0x00 },
          { 0xff, 0xff, 0x00 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_UD1, FT_HELPER_UD1, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_UD2] =
        { 2, 0, 0, 0x0f, 0x0b, 0, { 0x0f, 0x0b },
          { 0xff, 0xff }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_UD2, FT_HELPER_UD2, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_PCMPISTRI] =
        { 0, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 0, { 0 },
          { 0 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_PCMPISTRI, FT_HELPER_PCMPISTRI, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_PCMPISTRM] =
        { 0, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 0, { 0 },
          { 0 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_PCMPISTRM, FT_HELPER_PCMPISTRM, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_PCMPESTRI] =
        { 0, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 0, { 0 },
          { 0 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_PCMPESTRI, FT_HELPER_PCMPESTRI, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_PCMPESTRM] =
        { 0, 0, dt_X86_PREFIX_OPSIZE, 0x0f, 0x3a, 0, { 0 },
          { 0 }, -1, -1, -1, 0, -1, 0,
          dt_X86_INS_PCMPESTRM, FT_HELPER_PCMPESTRM, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_LDMXCSR] =
        { 0, 0, 0, 0x0f, 0xae, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_LDMXCSR,
          FT_HELPER_LDMXCSR, FT_TM_NO_EXTRA_CONSTRAINTS },
    [FT_HELPER_FXSAVE] =
        { 0, 0, 0, 0x0f, 0xae, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_FXSAVE,
          FT_HELPER_FXSAVE,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 0 },
    [FT_HELPER_FXRSTOR] =
        { 0, 0, 0, 0x0f, 0xae, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_FXRSTOR,
          FT_HELPER_FXRSTOR,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 1 },
    [FT_HELPER_FNSAVE] =
        { 0, 0, 0, 0xdd, 0, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_FNSAVE,
          FT_HELPER_FNSAVE,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 6 },
    [FT_HELPER_FRSTOR] =
        { 0, 0, 0, 0xdd, 0, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_FRSTOR,
          FT_HELPER_FRSTOR,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 4 },
    [FT_HELPER_FLDENV] =
        { 0, 0, 0, 0xd9, 0, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_FLDENV,
          FT_HELPER_FLDENV,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 4 },
    [FT_HELPER_FNSTENV] =
        { 0, 0, 0, 0xd9, 0, 0, { 0 }, { 0 },
          -1, -1, -1, 0, -1, 0, dt_X86_INS_FNSTENV,
          FT_HELPER_FNSTENV,
          FT_TM_CONSTRAINTS_DECLARED | FT_TM_MODRM_MEM_ONLY |
          FT_TM_MODRM_REG_EXT_VALID,
          FT_TM_ADDR_RIP | FT_TM_ADDR_BASE | FT_TM_ADDR_LEA |
          FT_TM_ADDR_SEGMENT, 6 },
};

static inline int ft_modrm_mod(int modrm)
{
    return (modrm >> 6) & 3;
}

static inline int ft_rex_b(const FastTemplateFields *fields)
{
    return fields->rex_bits & 1;
}

static inline int ft_rex_r(const FastTemplateFields *fields)
{
    return (fields->rex_bits >> 2) & 1;
}

static inline int ft_modrm_reg_index(const FastTemplateFields *fields)
{
    return fields->modrm_reg_index;
}

static inline int ft_modrm_rm_index(const FastTemplateFields *fields)
{
    return fields->modrm_rm_index;
}

static int ft_x86_gpr_index(dt_x86_reg reg)
{
    switch (reg) {
    case dt_X86_REG_AL:
    case dt_X86_REG_AX:
    case dt_X86_REG_EAX:
    case dt_X86_REG_RAX:
        return 0;
    case dt_X86_REG_CL:
    case dt_X86_REG_CX:
    case dt_X86_REG_ECX:
    case dt_X86_REG_RCX:
        return 1;
    case dt_X86_REG_DL:
    case dt_X86_REG_DX:
    case dt_X86_REG_EDX:
    case dt_X86_REG_RDX:
        return 2;
    case dt_X86_REG_BL:
    case dt_X86_REG_BX:
    case dt_X86_REG_EBX:
    case dt_X86_REG_RBX:
        return 3;
    case dt_X86_REG_SPL:
    case dt_X86_REG_SP:
    case dt_X86_REG_ESP:
    case dt_X86_REG_RSP:
        return 4;
    case dt_X86_REG_BPL:
    case dt_X86_REG_BP:
    case dt_X86_REG_EBP:
    case dt_X86_REG_RBP:
        return 5;
    case dt_X86_REG_SIL:
    case dt_X86_REG_SI:
    case dt_X86_REG_ESI:
    case dt_X86_REG_RSI:
        return 6;
    case dt_X86_REG_DIL:
    case dt_X86_REG_DI:
    case dt_X86_REG_EDI:
    case dt_X86_REG_RDI:
        return 7;
    case dt_X86_REG_R8:
    case dt_X86_REG_R8D:
    case dt_X86_REG_R8W:
    case dt_X86_REG_R8B:
        return 8;
    case dt_X86_REG_R9:
    case dt_X86_REG_R9D:
    case dt_X86_REG_R9W:
    case dt_X86_REG_R9B:
        return 9;
    case dt_X86_REG_R10:
    case dt_X86_REG_R10D:
    case dt_X86_REG_R10W:
    case dt_X86_REG_R10B:
        return 10;
    case dt_X86_REG_R11:
    case dt_X86_REG_R11D:
    case dt_X86_REG_R11W:
    case dt_X86_REG_R11B:
        return 11;
    case dt_X86_REG_R12:
    case dt_X86_REG_R12D:
    case dt_X86_REG_R12W:
    case dt_X86_REG_R12B:
        return 12;
    case dt_X86_REG_R13:
    case dt_X86_REG_R13D:
    case dt_X86_REG_R13W:
    case dt_X86_REG_R13B:
        return 13;
    case dt_X86_REG_R14:
    case dt_X86_REG_R14D:
    case dt_X86_REG_R14W:
    case dt_X86_REG_R14B:
        return 14;
    case dt_X86_REG_R15:
    case dt_X86_REG_R15D:
    case dt_X86_REG_R15W:
    case dt_X86_REG_R15B:
        return 15;
    default:
        return -1;
    }
}

static int ft_x86_xmm_index(dt_x86_reg reg)
{
    if (reg >= dt_X86_REG_XMM0 && reg <= dt_X86_REG_XMM15) {
        return reg - dt_X86_REG_XMM0;
    }
    return -1;
}

static int ft_x86_seg_index(dt_x86_reg reg)
{
    switch (reg) {
    case dt_X86_REG_ES:
        return es_index;
    case dt_X86_REG_CS:
        return cs_index;
    case dt_X86_REG_SS:
        return ss_index;
    case dt_X86_REG_DS:
        return ds_index;
    case dt_X86_REG_FS:
        return fs_index;
    case dt_X86_REG_GS:
        return gs_index;
    default:
        return -1;
    }
}

static int ft_prefix_seg_index(uint8_t prefix)
{
    switch (prefix) {
    case dt_X86_PREFIX_ES:
        return es_index;
    case dt_X86_PREFIX_CS:
        return cs_index;
    case dt_X86_PREFIX_SS:
        return ss_index;
    case dt_X86_PREFIX_DS:
        return ds_index;
    case dt_X86_PREFIX_FS:
        return fs_index;
    case dt_X86_PREFIX_GS:
        return gs_index;
    default:
        return -1;
    }
}

static int ft_sib_scale_bits(int scale)
{
    switch (scale) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
        return 2;
    case 8:
        return 3;
    default:
        return -1;
    }
}

static int ft_ir1_sib_byte(const struct la_dt_insn *info)
{
    const dt_x86_op_mem *mem = NULL;
    int i;

    if ((info->x86.modrm & 7) != 4 || ft_modrm_mod(info->x86.modrm) == 3) {
        return 0;
    }
    for (i = 0; i < info->x86.op_count; i++) {
        if (info->x86.operands[i].type == dt_X86_OP_MEM) {
            mem = &info->x86.operands[i].mem;
            break;
        }
    }
    if (mem) {
        int base = ft_x86_gpr_index(mem->base);
        int index = ft_x86_gpr_index(mem->index);
        int scale = ft_sib_scale_bits(mem->scale ? mem->scale : 1);
        int sib_base;
        int sib_index;

        if (scale < 0) {
            return 0;
        }
        sib_base = base >= 0 ? (base & 7) : 5;
        sib_index = index >= 0 ? (index & 7) : 4;
        return (scale << 6) | (sib_index << 3) | sib_base;
    }
    return 0;
}

static bool ft_supported_base_disp_addr(int rex, int modrm, int sib)
{
    int mod = ft_modrm_mod(modrm);
    int rex_x = rex >= 0 ? ((rex >> 1) & 1) : 0;

    if (mod == 3 || (mod == 0 && (modrm & 7) == 5)) {
        return false;
    }
    if ((modrm & 7) == 4) {
        if (((sib >> 3) & 7) != 4 || rex_x) {
            return false;
        }
        return mod != 0 || (sib & 7) != 5;
    }
    return true;
}

static bool ft_supported_base_disp_or_rip_addr(int rex, int modrm, int sib)
{
    int mod = ft_modrm_mod(modrm);

    if (mod == 0 && (modrm & 7) == 5) {
        return true;
    }
    return ft_supported_base_disp_addr(rex, modrm, sib);
}

static bool ft_supported_lea_addr(int rex, int modrm, int sib)
{
    (void)rex;
    (void)sib;
    return ft_modrm_mod(modrm) != 3;
}

static bool ft_xor_same_reg_modrm(int rex, int modrm)
{
    int reg;
    int rm;

    if ((modrm & 0xc0) != 0xc0) {
        return false;
    }
    reg = ((modrm >> 3) & 7) | (rex >= 0 ? ((rex >> 2) & 1) << 3 : 0);
    rm = (modrm & 7) | (rex >= 0 ? (rex & 1) << 3 : 0);
    return reg == rm && rm < 16;
}

static inline bool ft_grp1_ext_supported(int ext)
{
    return ext >= 0 && ext <= 7;
}

static bool ft_mov128_opcode_supported(uint8_t prefix0, uint8_t prefix2,
                                       uint8_t opcode, bool *store)
{
    if (prefix0 == 0 && (prefix2 == 0 || prefix2 == 0x66) &&
        (opcode == 0x10 || opcode == 0x11 ||
         opcode == 0x28 || opcode == 0x29)) {
        *store = opcode == 0x11 || opcode == 0x29;
        return true;
    }
    if (prefix0 == 0 && prefix2 == 0x66 &&
        (opcode == 0x6f || opcode == 0x7f)) {
        *store = opcode == 0x7f;
        return true;
    }
    if (prefix0 == 0xf3 && prefix2 == 0 &&
        (opcode == 0x6f || opcode == 0x7f)) {
        *store = opcode == 0x7f;
        return true;
    }
    return false;
}

static bool ft_scalar_mov_opcode_info(const struct la_dt_insn *info,
                                      int *rex, uint8_t *prefix,
                                      uint8_t *opcode, int *modrm)
{
    if ((info->x86.prefix[0] != 0xf2 && info->x86.prefix[0] != 0xf3) ||
        info->x86.opcode[0] != 0x0f ||
        (info->x86.opcode[1] != 0x10 &&
         info->x86.opcode[1] != 0x11)) {
        return false;
    }
    *rex = info->x86.rex ? info->x86.rex : -1;
    *prefix = info->x86.prefix[0];
    *opcode = info->x86.opcode[1];
    *modrm = info->x86.modrm;
    return true;
}

static bool ft_punpck_opcode_info(uint8_t prefix2, uint8_t opcode,
                                  uint32_t *la_opcode, int *id)
{
    *la_opcode = 0;
    switch (opcode) {
    case 0x14:
        if (prefix2 != 0) {
            return false;
        }
        *id = dt_X86_INS_UNPCKLPS;
        return true;
    case 0x15:
        if (prefix2 != 0) {
            return false;
        }
        *id = dt_X86_INS_UNPCKHPS;
        return true;
    case 0x60:
        *id = dt_X86_INS_PUNPCKLBW;
        return true;
    case 0x61:
        *id = dt_X86_INS_PUNPCKLWD;
        return true;
    case 0x62:
        *id = dt_X86_INS_PUNPCKLDQ;
        return true;
    case 0x6c:
        *id = dt_X86_INS_PUNPCKLQDQ;
        return true;
    case 0x68:
        *id = dt_X86_INS_PUNPCKHBW;
        return true;
    case 0x69:
        *id = dt_X86_INS_PUNPCKHWD;
        return true;
    case 0x6a:
        *id = dt_X86_INS_PUNPCKHDQ;
        return true;
    case 0x6d:
        *id = dt_X86_INS_PUNPCKHQDQ;
        return true;
    default:
        return false;
    }
}

static bool ft_padd_opcode_info(uint8_t opcode, uint32_t *la_opcode, int *id)
{
    *la_opcode = 0;
    switch (opcode) {
    case 0xfc:
        *id = dt_X86_INS_PADDB;
        return true;
    case 0xfd:
        *id = dt_X86_INS_PADDW;
        return true;
    case 0xfe:
        *id = dt_X86_INS_PADDD;
        return true;
    case 0xd4:
        *id = dt_X86_INS_PADDQ;
        return true;
    default:
        return false;
    }
}

static bool ft_pcmpeq_opcode_info(uint8_t opcode, uint32_t *la_opcode, int *id)
{
    *la_opcode = 0;
    switch (opcode) {
    case 0x74:
        *id = dt_X86_INS_PCMPEQB;
        return true;
    case 0x75:
        *id = dt_X86_INS_PCMPEQW;
        return true;
    case 0x76:
        *id = dt_X86_INS_PCMPEQD;
        return true;
    case 0x29:
        *id = dt_X86_INS_PCMPEQQ;
        return true;
    default:
        return false;
    }
}

static bool ft_simd_bin_opcode_info(uint8_t prefix0, uint8_t prefix2,
                                    uint8_t opcode,
                                    uint32_t *la_opcode, int *id,
                                    bool *reverse_operands)
{
    bool is_double = prefix2 == 0x66;

    *la_opcode = 0;
    *reverse_operands = false;
    switch (opcode) {
    case 0x51:
        if (prefix0 != 0) {
            return false;
        }
        *id = is_double ? dt_X86_INS_SQRTPD : dt_X86_INS_SQRTPS;
        return true;
    case 0x52:
        if (prefix0 != 0 || is_double) {
            return false;
        }
        *id = dt_X86_INS_RSQRTPS;
        return true;
    case 0x53:
        if (prefix0 != 0 || is_double) {
            return false;
        }
        *id = dt_X86_INS_RCPPS;
        return true;
    case 0x58:
        *id = is_double ? dt_X86_INS_ADDPD : dt_X86_INS_ADDPS;
        return true;
    case 0x59:
        *id = is_double ? dt_X86_INS_MULPD : dt_X86_INS_MULPS;
        return true;
    case 0x5c:
        *id = is_double ? dt_X86_INS_SUBPD : dt_X86_INS_SUBPS;
        return true;
    case 0x5d:
        *id = is_double ? dt_X86_INS_MINPD : dt_X86_INS_MINPS;
        return true;
    case 0x5e:
        *id = is_double ? dt_X86_INS_DIVPD : dt_X86_INS_DIVPS;
        return true;
    case 0x5f:
        *id = is_double ? dt_X86_INS_MAXPD : dt_X86_INS_MAXPS;
        return true;
    case 0x54:
        *id = is_double ? dt_X86_INS_ANDPD : dt_X86_INS_ANDPS;
        return true;
    case 0x55:
        *id = is_double ? dt_X86_INS_ANDNPD : dt_X86_INS_ANDNPS;
        return true;
    case 0x56:
        *id = is_double ? dt_X86_INS_ORPD : dt_X86_INS_ORPS;
        return true;
    case 0x57:
        *id = is_double ? dt_X86_INS_XORPD : dt_X86_INS_XORPS;
        return true;
    case 0x66:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PCMPGTD;
        *reverse_operands = true;
        return true;
    case 0x64:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PCMPGTB;
        *reverse_operands = true;
        return true;
    case 0x65:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PCMPGTW;
        *reverse_operands = true;
        return true;
    case 0x37:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PCMPGTQ;
        *reverse_operands = true;
        return true;
    case 0xd0:
        if (prefix2 == 0x66) {
            *id = dt_X86_INS_ADDSUBPD;
            return true;
        }
        if (prefix0 == 0xf2) {
            *id = dt_X86_INS_ADDSUBPS;
            return true;
        }
        return false;
    case 0x1c:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PABSB;
        return true;
    case 0x1d:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PABSW;
        return true;
    case 0x1e:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PABSD;
        return true;
    case 0x08:
        if (prefix0 != 0 || !is_double) {
            return false;
        }
        *id = dt_X86_INS_PSIGNB;
        *reverse_operands = true;
        return true;
    case 0x09:
        if (prefix0 != 0 || !is_double) {
            return false;
        }
        *id = dt_X86_INS_PSIGNW;
        *reverse_operands = true;
        return true;
    case 0x0a:
        if (prefix0 != 0 || !is_double) {
            return false;
        }
        *id = dt_X86_INS_PSIGND;
        *reverse_operands = true;
        return true;
    case 0xd1:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PSRLW;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRLW;
        return true;
    case 0xd2:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRLD;
        return true;
    case 0xd3:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PSRLQ;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRLQ;
        return true;
    case 0xe1:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRAW;
        return true;
    case 0xe2:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSRAD;
        return true;
    case 0xf1:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSLLW;
        return true;
    case 0xf2:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSLLD;
        return true;
    case 0xf3:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSLLQ;
        return true;
    case 0xda:
        if (prefix0 == 0 && prefix2 == 0) {
            *id = dt_X86_INS_PMINUB;
            return true;
        }
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINUB;
        return true;
    case 0xd9:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBUSW;
        return true;
    case 0xd8:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBUSB;
        return true;
    case 0xf8:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBB;
        return true;
    case 0xf9:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBW;
        return true;
    case 0xfa:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBD;
        return true;
    case 0xfb:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBQ;
        return true;
    case 0xe8:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBSB;
        return true;
    case 0xe9:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PSUBSW;
        return true;
    case 0xec:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PADDSB;
        return true;
    case 0xed:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PADDSW;
        return true;
    case 0xdc:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PADDUSB;
        return true;
    case 0xdd:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PADDUSW;
        return true;
    case 0xdb:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PAND;
        return true;
    case 0xdf:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PANDN;
        return true;
    case 0xeb:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_POR;
        return true;
    case 0xe0:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PAVGB;
        return true;
    case 0xe3:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PAVGW;
        return true;
    case 0xd5:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULLW;
        return true;
    case 0xe5:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULHW;
        return true;
    case 0xe4:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULHUW;
        return true;
    case 0x40:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULLD;
        return true;
    case 0x28:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMULDQ;
        return true;
    case 0xde:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXUB;
        return true;
    case 0xee:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXSW;
        return true;
    case 0xea:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINSW;
        return true;
    case 0x38:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINSB;
        return true;
    case 0x39:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINSD;
        return true;
    case 0x3a:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINUW;
        return true;
    case 0x3b:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMINUD;
        return true;
    case 0x3c:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXSB;
        return true;
    case 0x3d:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXSD;
        return true;
    case 0x3e:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXUW;
        return true;
    case 0x3f:
        if (!is_double) {
            return false;
        }
        *id = dt_X86_INS_PMAXUD;
        return true;
    default:
        return false;
    }
}

static bool ft_simd_scalar_bin_opcode_info(uint8_t prefix, uint8_t opcode,
                                           uint32_t *la_opcode, int *id)
{
    bool is_double = prefix == 0xf2;

    *la_opcode = 0;
    if (prefix != 0xf2 && prefix != 0xf3) {
        return false;
    }
    switch (opcode) {
    case 0x51:
        *id = is_double ? dt_X86_INS_SQRTSD : dt_X86_INS_SQRTSS;
        return true;
    case 0x52:
        if (is_double) {
            return false;
        }
        *id = dt_X86_INS_RSQRTSS;
        return true;
    case 0x53:
        if (is_double) {
            return false;
        }
        *id = dt_X86_INS_RCPSS;
        return true;
    case 0x58:
        *id = is_double ? dt_X86_INS_ADDSD : dt_X86_INS_ADDSS;
        return true;
    case 0x5c:
        *id = is_double ? dt_X86_INS_SUBSD : dt_X86_INS_SUBSS;
        return true;
    case 0x5d:
        *id = is_double ? dt_X86_INS_MINSD : dt_X86_INS_MINSS;
        return true;
    case 0x59:
        *id = is_double ? dt_X86_INS_MULSD : dt_X86_INS_MULSS;
        return true;
    case 0x5e:
        *id = is_double ? dt_X86_INS_DIVSD : dt_X86_INS_DIVSS;
        return true;
    case 0x5f:
        *id = is_double ? dt_X86_INS_MAXSD : dt_X86_INS_MAXSS;
        return true;
    default:
        return false;
    }
}

static bool ft_simd_scalar_cmp_opcode_info(uint8_t prefix0, uint8_t prefix2,
                                           uint8_t opcode, bool *is_double,
                                           bool *qnan, int *id)
{
    if (opcode != 0x2f && opcode != 0x2e) {
        return false;
    }
    *qnan = opcode == 0x2f;
    if (prefix2 == 0x66) {
        *is_double = true;
        *id = *qnan ? dt_X86_INS_COMISD : dt_X86_INS_UCOMISD;
        return true;
    }
    if (prefix0 == 0 && prefix2 == 0) {
        *is_double = false;
        *id = *qnan ? dt_X86_INS_COMISS : dt_X86_INS_UCOMISS;
        return true;
    }
    return false;
}

static bool fast_template_raw_matches(const FastTemplateDesc *tmpl,
                                      const struct la_dt_insn *info)
{
    int len = tmpl->len;

    if (len > (int)sizeof(tmpl->raw)) {
        len = sizeof(tmpl->raw);
    }
    for (int i = 0; i < len; ++i) {
        if (((info->bytes[i] ^ tmpl->raw[i]) & tmpl->raw_mask[i]) != 0) {
            return false;
        }
    }
    return true;
}

static bool fast_template_x87_memory_kind(FastTemplateKind kind)
{
    switch (kind) {
    case FT_X87_FLD_M32:
    case FT_X87_FLD_M64:
    case FT_X87_FIST_M16:
    case FT_X87_FIST_M32:
    case FT_X87_FI_BIN_M16:
    case FT_X87_FI_BIN_M32:
    case FT_X87_FILD_M16:
    case FT_X87_FILD_M32:
    case FT_X87_FILD_M64:
    case FT_X87_FISTP_M16:
    case FT_X87_FISTP_M32:
    case FT_X87_FISTP_M64:
    case FT_X87_FISTTP_M16:
    case FT_X87_FISTTP_M32:
    case FT_X87_FISTTP_M64:
    case FT_X87_FBLD:
    case FT_X87_FBSTP:
    case FT_X87_FST_M32:
    case FT_X87_FST_M64:
    case FT_X87_FLD_M80:
    case FT_X87_FSTP_M32:
    case FT_X87_FSTP_M64:
    case FT_X87_FSTP_M80:
    case FT_X87_BIN_M32:
    case FT_X87_BIN_M64:
    case FT_X87_FCOM_M32:
    case FT_X87_FCOM_M64:
    case FT_X87_FLDCW_M16:
    case FT_X87_FNSTCW_M16:
    case FT_X87_FNSTSW_M16:
        return true;
    default:
        return false;
    }
}

static bool ft_decoded_id_is_cmovcc(int id)
{
    return id >= dt_X86_INS_CMOVA && id <= dt_X86_INS_CMOVS;
}

static bool ft_decoded_id_is_setcc(int id)
{
    return id >= dt_X86_INS_SETAE && id <= dt_X86_INS_SETS;
}

static bool ft_decoded_has_opsize_prefix(const struct la_dt_insn *info)
{
    if (info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE) {
        return true;
    }

    for (uint8_t i = 0; i < info->size && i < sizeof(info->bytes); ++i) {
        uint8_t b = info->bytes[i];

        if (b == 0x66) {
            return true;
        }
        if (b == 0xf0 || b == 0xf2 || b == 0xf3 ||
            b == 0x2e || b == 0x36 || b == 0x3e ||
            b == 0x26 || b == 0x64 || b == 0x65 || b == 0x67 ||
            (b >= 0x40 && b <= 0x4f)) {
            continue;
        }
        break;
    }
    return false;
}

#include "template-info.inc.c"

#define ft_ir1_sib_byte fd_template_fields_ir1_sib_byte
#define ft_sib_scale_bits fd_template_fields_sib_scale_bits
#define ft_grp1_ext_supported fd_template_fields_grp1_ext_supported
#define ft_punpck_opcode_info fd_template_fields_punpck_opcode_info
#define ft_padd_opcode_info fd_template_fields_padd_opcode_info
#define ft_pcmpeq_opcode_info fd_template_fields_pcmpeq_opcode_info
#define ft_simd_bin_opcode_info fd_template_fields_simd_bin_opcode_info
#define ft_simd_scalar_bin_opcode_info \
    fd_template_fields_simd_scalar_bin_opcode_info
#define ft_simd_scalar_cmp_opcode_info \
    fd_template_fields_simd_scalar_cmp_opcode_info
static int fd_template_fields_sib_scale_bits(int scale);
#include "fields.inc.c"
#undef ft_simd_scalar_cmp_opcode_info
#undef ft_simd_scalar_bin_opcode_info
#undef ft_simd_bin_opcode_info
#undef ft_pcmpeq_opcode_info
#undef ft_padd_opcode_info
#undef ft_punpck_opcode_info
#undef ft_grp1_ext_supported
#undef ft_sib_scale_bits
#undef ft_ir1_sib_byte


const FastTemplateDesc *fast_template_find_decoded(
    const struct la_dt_insn *info)
{
    uint8_t len = info->size;
    int rex = info->x86.rex ? info->x86.rex : -1;
    uint8_t opcode0 = info->x86.opcode[0];
    uint8_t opcode1 = info->x86.opcode[1];
    int modrm = info->x86.modrm;
    int sib = ft_ir1_sib_byte(info);
    bool mov128_store;
    int scalar_rex;
    uint8_t scalar_prefix;
    uint8_t scalar_opcode;
    int scalar_modrm;
    bool opsize = ft_decoded_has_opsize_prefix(info);

    if (info->x86.prefix[1] == 0x64) {
        if (opcode0 == 0xc6 && ((modrm >> 3) & 7) == 0) {
            return &fast_templates[FT_MOV_RM8_IMM8];
        }
        if (opcode0 == 0x88) {
            return &fast_templates[FT_MOV_RM8_R8];
        }
        if (opcode0 == 0xc7 && ((modrm >> 3) & 7) == 0) {
            return &fast_templates[FT_MOV_RM32_IMM32];
        }
        if (opcode0 == 0x80 && ((modrm >> 3) & 7) == 7) {
            return &fast_templates[FT_CMP_RM8_IMM8];
        }
        if (rex >= 0 && (rex & 8) && opcode0 == 0x83 &&
            ((modrm >> 3) & 7) == 7) {
            return &fast_templates[FT_CMP_RM64_IMM8];
        }
        if (rex >= 0 && (rex & 8) && opcode0 == 0x8b) {
            return &fast_templates[FT_MOV_R64_RM64];
        }
        if (rex >= 0 && (rex & 8) && opcode0 == 0x89) {
            return &fast_templates[FT_MOV_RM64_R64];
        }
    }

    if ((opcode0 >= 0x70 && opcode0 <= 0x7f) ||
        (opcode0 == 0x0f && opcode1 >= 0x80 && opcode1 <= 0x8f)) {
        return &fast_templates[FT_JCC_REL];
    }
    switch (opcode0) {
    case 0x04:
    case 0x05:
    case 0x0c:
    case 0x0d:
    case 0x14:
    case 0x15:
    case 0x1c:
    case 0x1d:
    case 0x24:
    case 0x25:
    case 0x2c:
    case 0x2d:
    case 0x34:
    case 0x35:
    case 0x3c:
    case 0x3d:
    case 0xa8:
    case 0xa9:
        return &fast_templates[FT_ALU_ACC_IMM];
    default:
        break;
    }

    switch (info->id) {
    case dt_X86_INS_CPUID:
        return &fast_templates[FT_HELPER_CPUID];
    case dt_X86_INS_HLT:
        return &fast_templates[FT_HLT];
    case dt_X86_INS_SYSCALL:
        return &fast_templates[FT_HELPER_SYSCALL];
    case dt_X86_INS_UD0:
        if (opcode0 == 0x0f && opcode1 == 0xff &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            (info->x86.rex & 0x08) == 0) {
            return &fast_templates[FT_HELPER_UD0];
        }
        return NULL;
    case dt_X86_INS_UD1:
        if (opcode0 == 0x0f && opcode1 == 0xb9 &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            (info->x86.rex & 0x08) == 0) {
            return &fast_templates[FT_HELPER_UD1];
        }
        return NULL;
    case dt_X86_INS_UD2:
        return &fast_templates[FT_HELPER_UD2];
    case dt_X86_INS_RDTSC:
        return &fast_templates[FT_RDTSC];
    case dt_X86_INS_RDTSCP:
        return &fast_templates[FT_RDTSCP];
    case dt_X86_INS_XGETBV:
        return &fast_templates[FT_XGETBV];
    case dt_X86_INS_PAUSE:
        return &fast_templates[FT_PAUSE];
    case dt_X86_INS_PREFETCH:
        if (opcode0 == 0x0f && opcode1 == 0x0d &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 0 &&
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_PREFETCH];
        }
        break;
    case dt_X86_INS_PREFETCHW:
        if (opcode0 == 0x0f && opcode1 == 0x0d &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 1 &&
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_PREFETCHW];
        }
        break;
    case dt_X86_INS_PREFETCHT0:
        if (opcode0 == 0x0f && opcode1 == 0x18 &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 1 &&
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_PREFETCHT0];
        }
        break;
    case dt_X86_INS_PREFETCHNTA:
        if (opcode0 == 0x0f && opcode1 == 0x18 &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 0 &&
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_PREFETCHNTA];
        }
        break;
    case dt_X86_INS_PREFETCHT1:
        if (opcode0 == 0x0f && opcode1 == 0x18 &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 2 &&
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_PREFETCHT1];
        }
        break;
    case dt_X86_INS_PREFETCHT2:
        if (opcode0 == 0x0f && opcode1 == 0x18 &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 3 &&
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_PREFETCHT2];
        }
        break;
    case dt_X86_INS_CLDEMOTE:
        if (opcode0 == 0x0f && opcode1 == 0x1c &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 0) {
            return &fast_templates[FT_CLDEMOTE];
        }
        break;
    case dt_X86_INS_CLFLUSH:
        if (opcode0 == 0x0f && opcode1 == 0xae &&
            info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 7) {
            return &fast_templates[FT_CLFLUSH];
        }
        break;
    case dt_X86_INS_CLFLUSHOPT:
        if (opcode0 == 0x0f && opcode1 == 0xae &&
            info->x86.prefix[0] == 0 &&
            info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 7) {
            return &fast_templates[FT_CLFLUSHOPT];
        }
        break;
    case dt_X86_INS_LFENCE:
        if (opcode0 == 0x0f && opcode1 == 0xae &&
            ft_modrm_mod(modrm) == 3 && ((modrm >> 3) & 7) == 5) {
            return &fast_templates[FT_LFENCE];
        }
        break;
    case dt_X86_INS_MFENCE:
        if (opcode0 == 0x0f && opcode1 == 0xae &&
            ft_modrm_mod(modrm) == 3 && ((modrm >> 3) & 7) == 6) {
            return &fast_templates[FT_MFENCE];
        }
        break;
    case dt_X86_INS_SFENCE:
        if (opcode0 == 0x0f && opcode1 == 0xae &&
            ft_modrm_mod(modrm) == 3 && ((modrm >> 3) & 7) == 7) {
            return &fast_templates[FT_SFENCE];
        }
        break;
    case dt_X86_INS_CMPXCHG:
        if ((ft_modrm_mod(modrm) == 3 ||
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib)))) {
            if (opcode1 == 0xb0 || opcode0 == 0xb0) {
                return &fast_templates[FT_CMPXCHG_RM8_R8];
            }
            if (opcode1 == 0xb1 || opcode0 == 0xb1) {
                if (rex >= 0 && (rex & 8)) {
                    return &fast_templates[FT_CMPXCHG_RM64_R64];
                }
                return opsize ? &fast_templates[FT_CMPXCHG_RM16_R16] :
                                &fast_templates[FT_CMPXCHG_RM32_R32];
            }
        }
        break;
    case dt_X86_INS_CMPXCHG8B:
        if (opcode0 == 0x0f && opcode1 == 0xc7 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 1 &&
            !(rex >= 0 && (rex & 8)) &&
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_CMPXCHG8B];
        }
        break;
    case dt_X86_INS_CMPXCHG16B:
        if (opcode0 == 0x0f && opcode1 == 0xc7 &&
            ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 1 &&
            rex >= 0 && (rex & 8) &&
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_CMPXCHG16B];
        }
        break;
    case dt_X86_INS_XADD:
        if (ft_modrm_mod(modrm) == 3) {
            /* register form: xadd r, r — no LOCK needed */
            if (opcode1 == 0xc0) {
                return &fast_templates[FT_XADD_R8_R8];
            }
            if (rex >= 0 && (rex & 8)) {
                return &fast_templates[FT_XADD_R64_R64];
            }
            return opsize ? &fast_templates[FT_XADD_R16_R16] :
                            &fast_templates[FT_XADD_R32_R32];
        }
        /* memory forms: with or without LOCK */
        if (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
            ft_supported_lea_addr(rex, modrm, sib)) {
            if (opcode1 == 0xc0) {
                return &fast_templates[FT_XADD_RM8_R8];
            }
            if (opcode1 == 0xc1) {
                return (rex >= 0 && (rex & 8)) ?
                       &fast_templates[FT_XADD_RM64_R64] :
                       &fast_templates[FT_XADD_RM32_R32];
            }
        }
        break;
    case dt_X86_INS_PCMPISTRI:
        return &fast_templates[FT_HELPER_PCMPISTRI];
    case dt_X86_INS_PCMPISTRM:
        return &fast_templates[FT_HELPER_PCMPISTRM];
    case dt_X86_INS_PCMPESTRI:
        return &fast_templates[FT_HELPER_PCMPESTRI];
    case dt_X86_INS_PCMPESTRM:
        return &fast_templates[FT_HELPER_PCMPESTRM];
    case dt_X86_INS_SHA1NEXTE:
    case dt_X86_INS_SHA1MSG1:
    case dt_X86_INS_SHA1MSG2:
    case dt_X86_INS_SHA256RNDS2:
    case dt_X86_INS_SHA256MSG1:
    case dt_X86_INS_SHA256MSG2:
        if (info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            (ft_modrm_mod(modrm) == 3 ||
             ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_SHA_XMM_XMMM];
        }
        break;
    case dt_X86_INS_SHA1RNDS4:
        if (info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
            (ft_modrm_mod(modrm) == 3 ||
             ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_SHA1RNDS4_XMM_XMMM_IMM8];
        }
        break;
    case dt_X86_INS_LDMXCSR:
        return &fast_templates[FT_HELPER_LDMXCSR];
    case dt_X86_INS_FXSAVE:
    case dt_X86_INS_FXSAVE64:
        if (ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 0) {
            return &fast_templates[FT_HELPER_FXSAVE];
        }
        break;
    case dt_X86_INS_FXRSTOR:
    case dt_X86_INS_FXRSTOR64:
        if (ft_modrm_mod(modrm) != 3 && ((modrm >> 3) & 7) == 1) {
            return &fast_templates[FT_HELPER_FXRSTOR];
        }
        break;
    case dt_X86_INS_FNSAVE:
        if (opcode0 == 0xdd && ft_modrm_mod(modrm) != 3 &&
            ((modrm >> 3) & 7) == 6) {
            return &fast_templates[FT_HELPER_FNSAVE];
        }
        break;
    case dt_X86_INS_FRSTOR:
        if (opcode0 == 0xdd && ft_modrm_mod(modrm) != 3 &&
            ((modrm >> 3) & 7) == 4) {
            return &fast_templates[FT_HELPER_FRSTOR];
        }
        break;
    case dt_X86_INS_FLDENV:
        if (opcode0 == 0xd9 && ft_modrm_mod(modrm) != 3 &&
            ((modrm >> 3) & 7) == 4) {
            return &fast_templates[FT_HELPER_FLDENV];
        }
        break;
    case dt_X86_INS_FNSTENV:
        if (opcode0 == 0xd9 && ft_modrm_mod(modrm) != 3 &&
            ((modrm >> 3) & 7) == 6) {
            return &fast_templates[FT_HELPER_FNSTENV];
        }
        break;
    case dt_X86_INS_MOVNTI:
        return &fast_templates[FT_MOVNTI_M_R];
    case dt_X86_INS_STOSQ:
    case dt_X86_INS_MOVSB:
    case dt_X86_INS_MOVSW:
    case dt_X86_INS_MOVSQ:
    case dt_X86_INS_STOSB:
    case dt_X86_INS_STOSW:
    case dt_X86_INS_STOSD:
    case dt_X86_INS_LODSB:
    case dt_X86_INS_LODSW:
    case dt_X86_INS_LODSD:
    case dt_X86_INS_LODSQ:
    case dt_X86_INS_CMPSB:
    case dt_X86_INS_CMPSW:
    case dt_X86_INS_CMPSQ:
    case dt_X86_INS_SCASB:
    case dt_X86_INS_SCASW:
    case dt_X86_INS_SCASD:
    case dt_X86_INS_SCASQ:
        return &fast_templates[FT_STRING];
    case dt_X86_INS_MOVSD:
        if (opcode0 == 0xa5) {
            return &fast_templates[FT_STRING];
        }
        break;
    case dt_X86_INS_CMPSD:
        if (opcode0 == 0xa7) {
            return &fast_templates[FT_STRING];
        }
        break;
    default:
        break;
    }

    if (opcode0 == 0x31 && ft_xor_same_reg_modrm(rex, info->x86.modrm)) {
        return &fast_templates[FT_XOR_RM_GPR_ZERO];
    }
    if (opcode0 == 0xc9) {
        return &fast_templates[FT_LEAVE];
    }
    if (opcode0 == 0xc8) {
        if (!opsize && len == 4 && info->bytes[1] == 0 &&
            info->bytes[2] == 0 && info->bytes[3] == 1) {
            return &fast_templates[FT_ENTER_ZERO_LEVEL1];
        }
        if (opsize && len == 5) {
            return &fast_templates[FT_ENTER16];
        }
        if (!opsize && len == 4) {
            return &fast_templates[FT_ENTER];
        }
    }
    if (opcode0 == 0x9b) {
        return &fast_templates[FT_WAIT];
    }
    if (opcode0 == 0xdb && modrm == 0xe3) {
        return &fast_templates[FT_FNINIT];
    }
    if (opcode0 == 0xdb && modrm == 0xe2) {
        return &fast_templates[FT_FNCLEX];
    }
    if (opcode0 == 0xd9 && modrm == 0xe8) {
        return &fast_templates[FT_X87_FLD1];
    }
    if (opcode0 == 0xd9 && modrm >= 0xe9 && modrm <= 0xee &&
        (info->id == dt_X86_INS_FLDL2T ||
         info->id == dt_X86_INS_FLDL2E ||
         info->id == dt_X86_INS_FLDPI ||
         info->id == dt_X86_INS_FLDLG2 ||
         info->id == dt_X86_INS_FLDLN2 ||
         info->id == dt_X86_INS_FLDZ)) {
        return &fast_templates[FT_X87_FLD_CONST];
    }
    if (opcode0 == 0xd9 && modrm >= 0xc0 && modrm <= 0xc7 &&
        info->id == dt_X86_INS_FLD) {
        return &fast_templates[FT_X87_FLD_REG];
    }
    if (opcode0 == 0xd9 && (modrm == 0xe0 || modrm == 0xe1) &&
        (info->id == dt_X86_INS_FCHS || info->id == dt_X86_INS_FABS)) {
        return &fast_templates[FT_X87_UNARY];
    }
    if (opcode0 == 0xd9 && (modrm == 0xf6 || modrm == 0xf7) &&
        (info->id == dt_X86_INS_FDECSTP ||
         info->id == dt_X86_INS_FINCSTP)) {
        return &fast_templates[FT_X87_TOP_ADJ];
    }
    if (opcode0 == 0xd9 && modrm == 0xe4 &&
        info->id == dt_X86_INS_FTST) {
        return &fast_templates[FT_X87_FTST];
    }
    if (opcode0 == 0xd9 && modrm >= 0xc8 && modrm <= 0xcf &&
        info->id == dt_X86_INS_FXCH) {
        return &fast_templates[FT_X87_FXCH];
    }
    if (opcode0 == 0xd8 && modrm >= 0xd0 && modrm <= 0xd7 &&
        info->id == dt_X86_INS_FCOM) {
        return &fast_templates[FT_X87_FCOM_REG];
    }
    if (opcode0 == 0xd8 && modrm >= 0xd8 && modrm <= 0xdf &&
        info->id == dt_X86_INS_FCOMP) {
        return &fast_templates[FT_X87_FCOMP_REG];
    }
    if (opcode0 == 0xdd && modrm >= 0xe0 && modrm <= 0xe7 &&
        info->id == dt_X86_INS_FUCOM) {
        return &fast_templates[FT_X87_FCOM_REG];
    }
    if (opcode0 == 0xdd && modrm >= 0xe8 && modrm <= 0xef &&
        info->id == dt_X86_INS_FUCOMP) {
        return &fast_templates[FT_X87_FCOMP_REG];
    }
    if (opcode0 == 0xdd && modrm >= 0xd8 && modrm <= 0xdf &&
        info->id == dt_X86_INS_FSTP) {
        return &fast_templates[FT_X87_FSTP_REG];
    }
    if (opcode0 == 0xdd && modrm >= 0xd0 && modrm <= 0xd7 &&
        info->id == dt_X86_INS_FST) {
        return &fast_templates[FT_X87_FST_REG];
    }
    if (opcode0 == 0xda && modrm == 0xe9 &&
        info->id == dt_X86_INS_FUCOMPP) {
        return &fast_templates[FT_X87_FUCOMPP];
    }
    if (opcode0 == 0xdb && modrm >= 0xe8 && modrm <= 0xf7 &&
        (info->id == dt_X86_INS_FUCOMI ||
         info->id == dt_X86_INS_FCOMI)) {
        return &fast_templates[FT_X87_FCOMI_REG];
    }
    if (opcode0 == 0xdf && modrm >= 0xe8 && modrm <= 0xf7 &&
        (info->id == dt_X86_INS_FUCOMIP ||
         info->id == dt_X86_INS_FCOMIP)) {
        return &fast_templates[FT_X87_FCOMIP_REG];
    }
    if ((opcode0 == 0xda || opcode0 == 0xdb) &&
        modrm >= 0xc0 && modrm <= 0xdf &&
        (info->id == dt_X86_INS_FCMOVB ||
         info->id == dt_X86_INS_FCMOVBE ||
         info->id == dt_X86_INS_FCMOVE ||
         info->id == dt_X86_INS_FCMOVNB ||
         info->id == dt_X86_INS_FCMOVNBE ||
         info->id == dt_X86_INS_FCMOVNE ||
         info->id == dt_X86_INS_FCMOVNU ||
         info->id == dt_X86_INS_FCMOVU)) {
        return &fast_templates[FT_X87_FCMOVCC];
    }
    if (opcode0 == 0xd9 && modrm == 0xf0 &&
        info->id == dt_X86_INS_F2XM1) {
        return &fast_templates[FT_X87_F2XM1];
    }
    if (opcode0 == 0xd9 && modrm == 0xfc &&
        info->id == dt_X86_INS_FRNDINT) {
        return &fast_templates[FT_X87_FRNDINT];
    }
    if (opcode0 == 0xd9 && modrm == 0xfd &&
        info->id == dt_X86_INS_FSCALE) {
        return &fast_templates[FT_X87_FSCALE];
    }
    if (opcode0 == 0xd9 && modrm == 0xfe &&
        info->id == dt_X86_INS_FSIN) {
        return &fast_templates[FT_X87_FSIN];
    }
    if (opcode0 == 0xd9 && modrm == 0xff &&
        info->id == dt_X86_INS_FCOS) {
        return &fast_templates[FT_X87_FCOS];
    }
    if (opcode0 == 0xd9 && modrm == 0xfb &&
        info->id == dt_X86_INS_FSINCOS) {
        return &fast_templates[FT_X87_FSINCOS];
    }
    if (opcode0 == 0xd9 && modrm == 0xf2 &&
        info->id == dt_X86_INS_FPTAN) {
        return &fast_templates[FT_X87_FPTAN];
    }
    if (opcode0 == 0xd9 && modrm == 0xf3 &&
        info->id == dt_X86_INS_FPATAN) {
        return &fast_templates[FT_X87_FPATAN];
    }
    if (opcode0 == 0xd9 && modrm == 0xf8 &&
        info->id == dt_X86_INS_FPREM) {
        return &fast_templates[FT_X87_FPREM];
    }
    if (opcode0 == 0xd9 && modrm == 0xf5 &&
        info->id == dt_X86_INS_FPREM1) {
        return &fast_templates[FT_X87_FPREM1];
    }
    if (opcode0 == 0xd9 && modrm == 0xf1 &&
        info->id == dt_X86_INS_FYL2X) {
        return &fast_templates[FT_X87_FYL2X];
    }
    if (opcode0 == 0xd9 && modrm == 0xf9 &&
        info->id == dt_X86_INS_FYL2XP1) {
        return &fast_templates[FT_X87_FYL2XP1];
    }
    if (opcode0 == 0xdf && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 4 &&
        info->id == dt_X86_INS_FBLD) {
        return &fast_templates[FT_X87_FBLD];
    }
    if (opcode0 == 0xdf && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 6 &&
        info->id == dt_X86_INS_FBSTP) {
        return &fast_templates[FT_X87_FBSTP];
    }
    if (opcode0 == 0xd9 && modrm == 0xe5 &&
        info->id == dt_X86_INS_FXAM) {
        return &fast_templates[FT_X87_FXAM];
    }
    if (opcode0 == 0xd9 && modrm == 0xf4 &&
        info->id == dt_X86_INS_FXTRACT) {
        return &fast_templates[FT_X87_FXTRACT];
    }
    if (opcode0 == 0xd9 && modrm == 0xfa) {
        return &fast_templates[FT_X87_FSQRT];
    }
    if (opcode0 == 0xd9 && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 0) {
        return &fast_templates[FT_X87_FLD_M32];
    }
    if (opcode0 == 0xdd && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 0) {
        return &fast_templates[FT_X87_FLD_M64];
    }
    if (opcode0 == 0xdf && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 2) {
        return &fast_templates[FT_X87_FIST_M16];
    }
    if (opcode0 == 0xdb && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 2) {
        return &fast_templates[FT_X87_FIST_M32];
    }
    if (opcode0 == 0xda && ft_modrm_mod(modrm) != 3) {
        return &fast_templates[FT_X87_FI_BIN_M32];
    }
    if (opcode0 == 0xde && ft_modrm_mod(modrm) != 3) {
        return &fast_templates[FT_X87_FI_BIN_M16];
    }
    if (opcode0 == 0xdf && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 0) {
        return &fast_templates[FT_X87_FILD_M16];
    }
    if (opcode0 == 0xdb && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 0) {
        return &fast_templates[FT_X87_FILD_M32];
    }
    if (opcode0 == 0xdf && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 5) {
        return &fast_templates[FT_X87_FILD_M64];
    }
    if (opcode0 == 0xdf && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 3) {
        return &fast_templates[FT_X87_FISTP_M16];
    }
    if (opcode0 == 0xdb && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 3) {
        return &fast_templates[FT_X87_FISTP_M32];
    }
    if (opcode0 == 0xdf && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 7) {
        return &fast_templates[FT_X87_FISTP_M64];
    }
    if (opcode0 == 0xdf && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 1) {
        return &fast_templates[FT_X87_FISTTP_M16];
    }
    if (opcode0 == 0xdb && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 1) {
        return &fast_templates[FT_X87_FISTTP_M32];
    }
    if (opcode0 == 0xdd && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 1) {
        return &fast_templates[FT_X87_FISTTP_M64];
    }
    if (opcode0 == 0xd9 && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 2) {
        return &fast_templates[FT_X87_FST_M32];
    }
    if (opcode0 == 0xdd && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 2) {
        return &fast_templates[FT_X87_FST_M64];
    }
    if (opcode0 == 0xd9 && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 3) {
        return &fast_templates[FT_X87_FSTP_M32];
    }
    if (opcode0 == 0xd9 && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 5 &&
        info->id == dt_X86_INS_FLDCW) {
        return &fast_templates[FT_X87_FLDCW_M16];
    }
    if (opcode0 == 0xd9 && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 7 &&
        info->id == dt_X86_INS_FNSTCW) {
        return &fast_templates[FT_X87_FNSTCW_M16];
    }
    if (opcode0 == 0xdd && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 7 &&
        info->id == dt_X86_INS_FNSTSW) {
        return &fast_templates[FT_X87_FNSTSW_M16];
    }
    if (opcode0 == 0xdd && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 3) {
        return &fast_templates[FT_X87_FSTP_M64];
    }
    if (opcode0 == 0xdb && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 5) {
        return &fast_templates[FT_X87_FLD_M80];
    }
    if (opcode0 == 0xdb && ft_modrm_mod(modrm) != 3 &&
        ((modrm >> 3) & 7) == 7) {
        return &fast_templates[FT_X87_FSTP_M80];
    }
    if (opcode0 == 0xd8 && ft_modrm_mod(modrm) != 3 &&
        (((modrm >> 3) & 7) == 0 || ((modrm >> 3) & 7) == 1 ||
         ((modrm >> 3) & 7) >= 4)) {
        return &fast_templates[FT_X87_BIN_M32];
    }
    if (opcode0 == 0xdc && ft_modrm_mod(modrm) != 3 &&
        (((modrm >> 3) & 7) == 0 || ((modrm >> 3) & 7) == 1 ||
         ((modrm >> 3) & 7) >= 4)) {
        return &fast_templates[FT_X87_BIN_M64];
    }
    if (opcode0 == 0xd8 && modrm >= 0xc0 &&
        (((modrm >> 3) & 7) == 0 || ((modrm >> 3) & 7) == 1 ||
         ((modrm >> 3) & 7) >= 4)) {
        return &fast_templates[FT_X87_BIN_REG];
    }
    if (opcode0 == 0xdc && modrm >= 0xc0 &&
        (((modrm >> 3) & 7) == 0 || ((modrm >> 3) & 7) == 1 ||
         ((modrm >> 3) & 7) >= 4)) {
        return &fast_templates[FT_X87_BIN_REG];
    }
    if (opcode0 == 0xd8 && ft_modrm_mod(modrm) != 3 &&
        (((modrm >> 3) & 7) == 2 || ((modrm >> 3) & 7) == 3)) {
        return &fast_templates[FT_X87_FCOM_M32];
    }
    if (opcode0 == 0xdc && ft_modrm_mod(modrm) != 3 &&
        (((modrm >> 3) & 7) == 2 || ((modrm >> 3) & 7) == 3)) {
        return &fast_templates[FT_X87_FCOM_M64];
    }
    if (opcode0 == 0xdd && modrm >= 0xc0 && modrm <= 0xc7) {
        return &fast_templates[FT_X87_FFREE];
    }
    if (opcode0 == 0xde && modrm >= 0xc0 && modrm <= 0xc7) {
        return &fast_templates[FT_X87_FADDP];
    }
    if (opcode0 == 0xde && modrm >= 0xe8 && modrm <= 0xef) {
        return &fast_templates[FT_X87_FSUBP];
    }
    if (opcode0 == 0xde && modrm >= 0xe0 && modrm <= 0xe7) {
        return &fast_templates[FT_X87_FSUBRP];
    }
    if (opcode0 == 0xde && modrm >= 0xc8 && modrm <= 0xcf) {
        return &fast_templates[FT_X87_FMULP];
    }
    if (opcode0 == 0xde && modrm >= 0xf8 && modrm <= 0xff) {
        return &fast_templates[FT_X87_FDIVP];
    }
    if (opcode0 == 0xde && modrm >= 0xf0 && modrm <= 0xf7) {
        return &fast_templates[FT_X87_FDIVRP];
    }
    if (opcode0 == 0xde && modrm == 0xd9) {
        return &fast_templates[FT_X87_FCOMPP];
    }
    if (opcode0 == 0xdf && modrm == 0xe0) {
        return &fast_templates[FT_X87_FSTSW_AX];
    }
    if (info->id == dt_X86_INS_INC && opcode0 == 0xff) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_INC_RM64] :
               opsize ? &fast_templates[FT_INC_RM16] :
               &fast_templates[FT_INC_RM32];
    }
    if (info->id == dt_X86_INS_DEC && opcode0 == 0xff) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_DEC_RM64] :
               opsize ? &fast_templates[FT_DEC_RM16] :
               &fast_templates[FT_DEC_RM32];
    }
    if (info->id == dt_X86_INS_INC && opcode0 == 0xfe) {
        return &fast_templates[FT_INC_RM8];
    }
    if (info->id == dt_X86_INS_DEC && opcode0 == 0xfe) {
        return &fast_templates[FT_DEC_RM8];
    }
    if (opcode0 == 0xff && ((modrm >> 3) & 7) == 2 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CALL_RM64];
    }
    if (opcode0 == 0xff && ((modrm >> 3) & 7) == 4 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_JMP_RM64];
    }
    if (opcode0 == 0xff && ((modrm >> 3) & 7) == 6 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return opsize ? &fast_templates[FT_PUSH_RM16] :
               &fast_templates[FT_PUSH_RM64];
    }
    if (opcode0 == 0x8f && ((modrm >> 3) & 7) == 0 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return opsize ? &fast_templates[FT_POP_RM16] :
               &fast_templates[FT_POP_RM64];
    }
    if (opcode0 == 0xff && ((modrm >> 3) & 7) == 0 &&
        ft_modrm_mod(modrm) == 3) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_INC_RM64] :
               opsize ? &fast_templates[FT_INC_RM16] :
               &fast_templates[FT_INC_RM32];
    }
    if (opcode0 == 0xff && ((modrm >> 3) & 7) == 1 &&
        ft_modrm_mod(modrm) == 3) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_DEC_RM64] :
               opsize ? &fast_templates[FT_DEC_RM16] :
               &fast_templates[FT_DEC_RM32];
    }
    if (opcode0 == 0xfe && ((modrm >> 3) & 7) == 0) {
        return &fast_templates[FT_INC_RM8];
    }
    if (opcode0 == 0xfe && ((modrm >> 3) & 7) == 1) {
        return &fast_templates[FT_DEC_RM8];
    }
    if (info->id == dt_X86_INS_MOV && opcode0 == 0xc7 &&
        ((modrm >> 3) & 7) == 0 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return info->x86.operands[0].size == 8 ?
               &fast_templates[FT_MOV_RM64_IMM32] :
               &fast_templates[FT_MOV_RM32_IMM32];
    }
    if (info->id == dt_X86_INS_MOV && opcode0 == 0xc6 &&
        ((modrm >> 3) & 7) == 0 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV_RM8_IMM8];
    }
    if (info->id == dt_X86_INS_NOP && opcode0 == 0x0f && opcode1 == 0x1e &&
        modrm == 0xfb && info->x86.prefix[0] == dt_X86_PREFIX_REP) {
        return &fast_templates[FT_ENDBR32];
    }
    if (info->id == dt_X86_INS_NOP) {
        return &fast_templates[FT_NOP_MULTI];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x98) {
        return &fast_templates[FT_CDQE];
    }
    if (opcode0 == 0x98) {
        return info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
               &fast_templates[FT_CBW] : &fast_templates[FT_CWDE];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x99) {
        return &fast_templates[FT_CQO];
    }
    if (opcode0 == 0x99) {
        return info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
               &fast_templates[FT_CWD] : &fast_templates[FT_CDQ];
    }
    if (opcode0 == 0xd7 && info->id == dt_X86_INS_XLATB &&
        info->x86.prefix[0] == 0 && info->x86.prefix[1] == 0 &&
        (info->x86.prefix[2] == 0 ||
         info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE)) {
        return &fast_templates[FT_XLATB];
    }
    if (opcode0 == 0x04) {
        return &fast_templates[FT_ADD_AL_IMM8];
    }
    if (opcode0 == 0x14) {
        return &fast_templates[FT_ADC_AL_IMM8];
    }
    if (opcode0 == 0x0c) {
        return &fast_templates[FT_OR_AL_IMM8];
    }
    if (opcode0 == 0x0d) {
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_OR_AX_IMM16];
        }
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_OR_RAX_IMM32] :
                                         &fast_templates[FT_OR_EAX_IMM32];
    }
    if (opcode0 == 0x05) {
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_ADD_AX_IMM16];
        }
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_ADD_RAX_IMM32] :
                                         &fast_templates[FT_ADD_EAX_IMM32];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x89) {
        if ((modrm & 0xc0) == 0xc0) {
            return &fast_templates[FT_MOV_RM64_R64];
        }
        if (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
            ft_supported_lea_addr(rex, modrm, sib)) {
            return &fast_templates[FT_MOV_RM64_R64];
        }
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0xc7 &&
        ((modrm >> 3) & 7) == 0 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV_RM64_IMM32];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x8b &&
        (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV_R64_RM64];
    }
    if (!(rex >= 0 && (rex & 8)) && info->x86.prefix[2] != 0x66 &&
        opcode0 == 0x8b &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV_R32_RM32];
    }
    if (!(rex >= 0 && (rex & 8)) && info->x86.prefix[2] != 0x66 &&
        opcode0 == 0x89 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV_RM32_R32];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x89 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV_RM16_R16];
    }
    if (opcode0 == 0x88 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV_RM8_R8];
    }
    if (opcode0 == 0x8a &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV_R8_RM8];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x8b &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV_R16_RM16];
    }
    if ((opcode0 == 0x8c || opcode0 == 0x8e) &&
        ((modrm >> 3) & 7) < 6 &&
        !(opcode0 == 0x8e && ((modrm >> 3) & 7) == 1) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return opcode0 == 0x8c ? &fast_templates[FT_MOV_RM_SEG] :
                                 &fast_templates[FT_MOV_SEG_RM];
    }
    if (info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE &&
        opcode0 == 0x0f && opcode1 == 0xb6 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVZX_R16_RM8];
    }
    if (opcode0 == 0x0f && opcode1 == 0xb6 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVZX_R32_RM8];
    }
    if (opcode0 == 0x0f && opcode1 == 0xb7 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVZX_R32_RM16];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x8d) {
        if (ft_supported_lea_addr(rex, modrm, sib)) {
            return &fast_templates[FT_LEA_R64_M];
        }
    }
    if (opcode0 == 0x8d && info->x86.prefix[2] == 0x66 &&
        !(rex >= 0 && (rex & 8))) {
        if (ft_supported_lea_addr(rex, modrm, sib)) {
            return &fast_templates[FT_LEA_R16_M];
        }
    }
    if (opcode0 == 0x8d && info->x86.prefix[2] == 0 &&
        !(rex >= 0 && (rex & 8))) {
        if (ft_supported_lea_addr(rex, modrm, sib)) {
            return &fast_templates[FT_LEA_R32_M];
        }
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x39 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CMP_RM16_R16];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x3b &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CMP_R16_RM16];
    }
    if (opcode0 == 0x39 && info->x86.prefix[2] != 0x66 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_CMP_RM64_R64] :
                                         &fast_templates[FT_CMP_RM32_R32];
    }
    if (opcode0 == 0x3b && info->x86.prefix[2] != 0x66 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_CMP_R64_RM64] :
                                         &fast_templates[FT_CMP_R32_RM32];
    }
    if (opcode0 == 0x85 && info->x86.prefix[2] != 0x66 &&
        !(rex >= 0 && (rex & 8)) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_TEST_RM32_R32];
    }
    if (opcode0 == 0x85 && (rex >= 0 && (rex & 8)) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_TEST_RM64_R64];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x85 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_TEST_RM16_R16];
    }
    if (opcode0 == 0x84 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_TEST_RM8_R8];
    }
    if (info->x86.prefix[2] == 0x66 &&
        (opcode0 == 0x39 || opcode0 == 0x3b) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return opcode0 == 0x39 ? &fast_templates[FT_CMP_RM16_R16] :
                                 &fast_templates[FT_CMP_R16_RM16];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x81 &&
        ((modrm >> 3) & 7) == 7 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CMP_RM16_IMM16];
    }
    if (opcode0 == 0xa8) {
        return &fast_templates[FT_TEST_AL_IMM8];
    }
    if (opcode0 == 0xa9) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_TEST_RAX_IMM32] :
                                         &fast_templates[FT_TEST_EAX_IMM32];
    }
    if (info->id == dt_X86_INS_MUL && opcode0 == 0xf6 &&
        ((modrm >> 3) & 7) == 4 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MUL_RM8];
    }
    if (info->id == dt_X86_INS_MUL && opcode0 == 0xf7) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_MUL_RM64] :
               opsize ? &fast_templates[FT_MUL_RM16] :
                                         &fast_templates[FT_MUL_RM32];
    }
    if (info->id == dt_X86_INS_IMUL && opcode0 == 0xf6 &&
        ((modrm >> 3) & 7) == 5 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_IMUL_RM8];
    }
    if (info->id == dt_X86_INS_IMUL && opcode0 == 0xf7 &&
        ((modrm >> 3) & 7) == 5 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (opsize) {
            return &fast_templates[FT_IMUL_RM16];
        }
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_IMUL_RM64] :
               &fast_templates[FT_IMUL_RM32];
    }
    if (info->id == dt_X86_INS_IDIV && opcode0 == 0xf6 &&
        ((modrm >> 3) & 7) == 7 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_IDIV_RM8];
    }
    if (opcode0 == 0xf7 && ((modrm >> 3) & 7) == 0 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_TEST_RM64_IMM32] :
                                         &fast_templates[FT_TEST_RM32_IMM32];
    }
    if ((opcode0 == 0xf6 || opcode0 == 0xf7) && ((modrm >> 3) & 7) == 3 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return opcode0 == 0xf6 ? &fast_templates[FT_NEG_RM8] :
               (rex >= 0 && (rex & 8)) ? &fast_templates[FT_NEG_RM64] :
               info->x86.prefix[2] == 0x66 ? &fast_templates[FT_NEG_RM16] :
               &fast_templates[FT_NEG_RM32];
    }
    if (opcode0 == 0xf7 && (rex >= 0 && (rex & 8)) &&
        ((modrm >> 3) & 7) == 4 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MUL_RM64];
    }
    if (opcode0 == 0xf6 && ((modrm >> 3) & 7) == 6 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_DIV_RM8];
    }
    if (opcode0 == 0xf7 && ((modrm >> 3) & 7) == 6 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_DIV_RM64] :
               info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
                                         &fast_templates[FT_DIV_RM16] :
                                         &fast_templates[FT_DIV_RM32];
    }
    if (opcode0 == 0xf7 && ((modrm >> 3) & 7) == 7 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_IDIV_RM64] :
               info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
                                         &fast_templates[FT_IDIV_RM16] :
                                         &fast_templates[FT_IDIV_RM32];
    }
    if (opcode0 == 0xf7 && ((modrm >> 3) & 7) == 2 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_NOT_RM64] :
               info->x86.prefix[2] == 0x66 ? &fast_templates[FT_NOT_RM16] :
               &fast_templates[FT_NOT_RM32];
    }
    if (opcode0 == 0xf6 && ((modrm >> 3) & 7) == 2 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_NOT_RM8];
    }
    if (opcode0 == 0xf6 && ((modrm >> 3) & 7) == 0 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_TEST_RM8_IMM8];
    }
    if ((opcode0 == 0x86 || opcode0 == 0x87) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return opcode0 == 0x86 ? &fast_templates[FT_XCHG_RM8_R8] :
               (rex >= 0 && (rex & 8)) ? &fast_templates[FT_XCHG_RM64_R64] :
               &fast_templates[FT_XCHG_RM32_R32];
    }
    if (opcode0 == 0x09 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_OR_RM64_R64] :
                                         &fast_templates[FT_OR_RM32_R32];
    }
    if (opcode0 == 0x08 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_OR_RM8_R8];
    }
    if (opcode0 == 0x80 && ft_grp1_ext_supported((modrm >> 3) & 7) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_GRP1_RM8_IMM8];
    }
    if (opcode0 == 0x80 && ((modrm >> 3) & 7) == 1 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_OR_RM8_IMM8];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x0b &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_OR_R16_RM16];
    }
    if (opcode0 == 0x0b &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_OR_R64_RM64] :
                                         &fast_templates[FT_OR_R32_RM32];
    }
    if (opcode0 == 0x21 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_AND_RM64_R64] :
                                         &fast_templates[FT_AND_RM32_R32];
    }
    if (opcode0 == 0x20 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_AND_RM8_R8];
    }
    if (opcode0 == 0x80 && ((modrm >> 3) & 7) == 4 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_AND_RM8_IMM8];
    }
    if (opcode0 == 0x23 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_AND_R64_RM64] :
                                         &fast_templates[FT_AND_R32_RM32];
    }
    if (opcode0 == 0x22 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_AND_R8_RM8];
    }
    if (opcode0 == 0x29 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_SUB_RM16_R16];
        }
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_SUB_RM64_R64] :
                                         &fast_templates[FT_SUB_RM32_R32];
    }
    if (opcode0 == 0x28 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_SUB_RM8_R8];
    }
    if (opcode0 == 0x10 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_ADC_RM8_R8];
    }
    if (opcode0 == 0x11 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_ADC_RM16_R16];
        }
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_ADC_RM64_R64] :
                                         &fast_templates[FT_ADC_RM32_R32];
    }
    if ((opcode0 == 0x18 || opcode0 == 0x19 ||
         opcode0 == 0x1a || opcode0 == 0x1b) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (opcode0 == 0x18 || opcode0 == 0x19) ?
               &fast_templates[FT_ALU_RM_R] :
               &fast_templates[FT_ALU_R_RM];
    }
    if (opcode0 == 0x2b &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_SUB_R16_RM16];
        }
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_SUB_R64_RM64] :
                                         &fast_templates[FT_SUB_R32_RM32];
    }
    if (opcode0 == 0x2a &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_SUB_R8_RM8];
    }
    if (opcode0 == 0x3a &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CMP_R8_RM8];
    }
    if (opcode0 == 0x0a &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_OR_R8_RM8];
    }
    if (opcode0 == 0x38 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CMP_RM8_R8];
    }
    if (opcode0 == 0x01 && info->x86.prefix[2] != 0x66 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_ADD_RM64_R64] :
                                         &fast_templates[FT_ADD_RM32_R32];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x03 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_ADD_R16_RM16];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x01 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_ADD_RM16_R16];
    }
    if (opcode0 == 0x03 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_ADD_R64_RM64] :
                                         &fast_templates[FT_ADD_R32_RM32];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0x13 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_ADC_R16_RM16];
    }
    if (opcode0 == 0x13 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_ADC_R64_RM64] :
                                         &fast_templates[FT_ADC_R32_RM32];
    }
    if (opcode0 == 0x00 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_ADD_RM8_R8];
    }
    if (opcode0 == 0x02 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_ADD_R8_RM8];
    }
    if (opcode0 == 0x12 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_ADC_R8_RM8];
    }
    if (opcode0 == 0x31 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_XOR_RM64_R64] :
                                         &fast_templates[FT_XOR_RM32_R32];
    }
    if (opcode0 == 0x30 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_XOR_RM8_R8];
    }
    if (opcode0 == 0x33 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_XOR_R16_RM16];
        }
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_XOR_R64_RM64] :
                                         &fast_templates[FT_XOR_R32_RM32];
    }
    if (opcode0 == 0x32 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_XOR_R8_RM8];
    }
    if (opcode0 == 0x35) {
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_XOR_AX_IMM16];
        }
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_XOR_RAX_IMM32] :
                                         &fast_templates[FT_XOR_EAX_IMM32];
    }
    if (opcode0 == 0x34) {
        return &fast_templates[FT_XOR_AL_IMM8];
    }
    if (opcode0 == 0x2c) {
        return &fast_templates[FT_SUB_AL_IMM8];
    }
    if (opcode0 == 0x2d && info->x86.prefix[2] == 0x66) {
        return &fast_templates[FT_SUB_AX_IMM16];
    }
    if (opcode0 == 0x63 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (rex >= 0 && (rex & 8)) {
            return &fast_templates[FT_MOVSXD_R64_RM32];
        }
        return info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
               &fast_templates[FT_MOVSXD_R16_RM16] :
               &fast_templates[FT_MOVSXD_R32_RM32];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x0f && opcode1 == 0xbe &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVSX_R64_RM8];
    }
    if (!(rex >= 0 && (rex & 8)) &&
        info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE &&
        opcode0 == 0x0f && opcode1 == 0xbe &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVSX_R16_RM8];
    }
    if (!(rex >= 0 && (rex & 8)) &&
        info->x86.prefix[2] != dt_X86_PREFIX_OPSIZE &&
        opcode0 == 0x0f && opcode1 == 0xbe &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVSX_R32_RM8];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x0f && opcode1 == 0xbf &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVSX_R64_RM16];
    }
    if (!(rex >= 0 && (rex & 8)) &&
        info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE &&
        opcode0 == 0x0f && opcode1 == 0xbf &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVSX_R16_RM16];
    }
    if (!(rex >= 0 && (rex & 8)) &&
        info->x86.prefix[2] != dt_X86_PREFIX_OPSIZE &&
        opcode0 == 0x0f && opcode1 == 0xbf &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVSX_R32_RM16];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x0f && opcode1 == 0xaf &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_IMUL_R64_RM64];
    }
    if (info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE &&
        opcode0 == 0x0f && opcode1 == 0xaf &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_IMUL_R16_RM16];
    }
    if (!(rex >= 0 && (rex & 8)) && opcode0 == 0x0f && opcode1 == 0xaf &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_IMUL_R32_RM32];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x69 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_IMUL_R64_RM64_IMM32];
    }
    if (opcode0 == 0x69 && !(rex >= 0 && (rex & 8)) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_IMUL_R32_RM32_IMM32];
    }
    if (opcode0 == 0x6b && (rex >= 0 && (rex & 8)) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_IMUL_R64_RM64_IMM8];
    }
    if (opcode0 == 0x6b && !(rex >= 0 && (rex & 8)) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_IMUL_R32_RM32_IMM8];
    }
    if (opcode0 == 0x0f && opcode1 >= 0x40 && opcode1 <= 0x4f &&
        ft_decoded_id_is_cmovcc(info->id) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_CMOV_R64_RM64] :
               ft_decoded_has_opsize_prefix(info) ?
               &fast_templates[FT_CMOV_R16_RM16] :
               &fast_templates[FT_CMOV_R32_RM32];
    }
    if (opcode0 == 0x0f && opcode1 >= 0x90 && opcode1 <= 0x9f &&
        ft_decoded_id_is_setcc(info->id) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_SETCC_RM8];
    }
    if (opcode0 == 0x0f && (opcode1 == 0xbc || opcode1 == 0xbd) &&
        (info->id == dt_X86_INS_BSF || info->id == dt_X86_INS_BSR) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (opcode1 == 0xbc) {
            return (rex >= 0 && (rex & 8)) ?
                   &fast_templates[FT_BSF_R64_RM64] :
                   ft_decoded_has_opsize_prefix(info) ?
                   &fast_templates[FT_BSF_R16_RM16] :
                   &fast_templates[FT_BSF_R32_RM32];
        }
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_BSR_R64_RM64] :
               ft_decoded_has_opsize_prefix(info) ?
               &fast_templates[FT_BSR_R16_RM16] :
               &fast_templates[FT_BSR_R32_RM32];
    }
    if (opcode0 == 0x0f && opcode1 == 0xbd &&
        info->id == dt_X86_INS_LZCNT &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (rex >= 0 && (rex & 8)) {
            return &fast_templates[FT_LZCNT_R64_RM64];
        }
        return info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
               &fast_templates[FT_LZCNT_R16_RM16] :
               &fast_templates[FT_LZCNT_R32_RM32];
    }
    if (opcode0 == 0x0f && opcode1 == 0xbc &&
        info->id == dt_X86_INS_TZCNT &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (rex >= 0 && (rex & 8)) {
            return &fast_templates[FT_TZCNT_R64_RM64];
        }
        return info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
               &fast_templates[FT_TZCNT_R16_RM16] :
               &fast_templates[FT_TZCNT_R32_RM32];
    }
    if (opcode0 == 0x0f && opcode1 == 0xb8 &&
        info->id == dt_X86_INS_POPCNT &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (rex >= 0 && (rex & 8)) {
            return &fast_templates[FT_POPCNT_R64_RM64];
        }
        return info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
               &fast_templates[FT_POPCNT_R16_RM16] :
               &fast_templates[FT_POPCNT_R32_RM32];
    }
    if (opcode0 == 0x0f && (opcode1 == 0xa3 || opcode1 == 0xab ||
                            opcode1 == 0xb3 || opcode1 == 0xbb) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_BTX_RM_R];
    }
    if (opcode0 == 0x0f && opcode1 == 0xba &&
        ((modrm >> 3) & 7) >= 4 && ((modrm >> 3) & 7) <= 7 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_BTX_RM32_IMM8];
    }
    if ((opcode0 == 0xc0 || opcode0 == 0xc1 ||
         opcode0 == 0xd0 || opcode0 == 0xd1 ||
         opcode0 == 0xd2 || opcode0 == 0xd3) &&
        (((modrm >> 3) & 7) == 0 || ((modrm >> 3) & 7) == 1 ||
         ((modrm >> 3) & 7) == 2 || ((modrm >> 3) & 7) == 3) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (opcode0 == 0xc0 || opcode0 == 0xc1) ?
               &fast_templates[FT_SHIFT_RM_IMM8] :
               (opcode0 == 0xd0 || opcode0 == 0xd1) ?
               &fast_templates[FT_SHIFT_RM_ONE] :
               &fast_templates[FT_SHIFT_RM_CL];
    }
    if (opcode0 == 0xc1 && (rex >= 0 && (rex & 8)) &&
        ((modrm >> 3) & 7) == 0 && ft_modrm_mod(modrm) == 3) {
        return &fast_templates[FT_ROL_RM64_IMM8];
    }
    if (opcode0 == 0xc1 && (rex >= 0 && (rex & 8)) &&
        ((modrm >> 3) & 7) == 1 && ft_modrm_mod(modrm) == 3) {
        return &fast_templates[FT_ROR_RM64_IMM8];
    }
    if (info->id == dt_X86_INS_RORX && len >= 6 &&
        info->bytes[0] == 0xc4 && (info->bytes[1] & 0x1f) == 3 &&
        (info->bytes[2] & 0x7f) == 0x7b && info->bytes[3] == 0xf0 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_RORX_R64_RM64_IMM8] :
               &fast_templates[FT_RORX_R32_RM32_IMM8];
    }
    if (opcode0 == 0xc0 && ((modrm >> 3) & 7) == 5 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_SHR_RM8_IMM8];
    }
    if (opcode0 == 0xd0 && ((modrm >> 3) & 7) == 5 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_SHR_RM8_ONE];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 == 0xc1 &&
        ((modrm >> 3) & 7) == 5 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_SHR_RM16_IMM8];
    }
    if (opcode0 == 0x0f && (opcode1 == 0xa4 || opcode1 == 0xa5 ||
                            opcode1 == 0xac || opcode1 == 0xad) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (opcode1 == 0xa4) {
            return &fast_templates[FT_SHLD_RM_R_IMM8];
        }
        if (opcode1 == 0xa5) {
            return &fast_templates[FT_SHLD_RM_R_CL];
        }
        if (opcode1 == 0xac) {
            return &fast_templates[FT_SHRD_RM_R_IMM8];
        }
        return &fast_templates[FT_SHRD_RM_R_CL];
    }
    if ((opcode0 == 0xc0 || opcode0 == 0xc1 ||
         opcode0 == 0xd0 || opcode0 == 0xd1 ||
         opcode0 == 0xd2 || opcode0 == 0xd3) &&
        (((modrm >> 3) & 7) == 4 || ((modrm >> 3) & 7) == 5 ||
         ((modrm >> 3) & 7) == 6 || ((modrm >> 3) & 7) == 7) &&
        (ft_modrm_mod(modrm) == 3 ||
         (((modrm >> 3) & 7) != 2 && ((modrm >> 3) & 7) != 3 &&
          (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
           ft_supported_lea_addr(rex, modrm, sib))))) {
        return (opcode0 == 0xc0 || opcode0 == 0xc1) ?
               &fast_templates[FT_SHIFT_RM_IMM8] :
               (opcode0 == 0xd0 || opcode0 == 0xd1) ?
               &fast_templates[FT_SHIFT_RM_ONE] :
               &fast_templates[FT_SHIFT_RM_CL];
    }
    if (opcode0 == 0x25) {
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_AND_AX_IMM16];
        }
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_AND_RAX_IMM32] :
                                         &fast_templates[FT_AND_EAX_IMM32];
    }
    if (opcode0 == 0x24) {
        return &fast_templates[FT_AND_AL_IMM8];
    }
    if (info->id == dt_X86_INS_BSWAP && opcode0 == 0x0f &&
        opcode1 >= 0xc8 && opcode1 <= 0xcf) {
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_BSWAP_R64] :
                                         &fast_templates[FT_BSWAP_R32];
    }
    if (info->id == dt_X86_INS_MOVBE && opcode0 == 0x0f &&
        (opcode1 == 0xf0 || opcode1 == 0xf1) &&
        ft_modrm_mod(modrm) != 3 &&
        (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        bool is_store = opcode1 == 0xf1;

        if (rex >= 0 && (rex & 8)) {
            return is_store ? &fast_templates[FT_MOVBE_M64_R64] :
                              &fast_templates[FT_MOVBE_R64_M64];
        }
        if (info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE) {
            return is_store ? &fast_templates[FT_MOVBE_M16_R16] :
                              &fast_templates[FT_MOVBE_R16_M16];
        }
        return is_store ? &fast_templates[FT_MOVBE_M32_R32] :
                          &fast_templates[FT_MOVBE_R32_M32];
    }
    if (info->id == dt_X86_INS_CRC32 && opcode0 == 0x0f &&
        (opcode1 == 0xf0 || opcode1 == 0xf1) &&
        info->x86.prefix[0] == dt_X86_PREFIX_REPNE &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (opcode1 == 0xf0) {
            return &fast_templates[FT_CRC32_R_RM8];
        }
        if (rex >= 0 && (rex & 8)) {
            return &fast_templates[FT_CRC32_R_RM64];
        }
        return info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
               &fast_templates[FT_CRC32_R_RM16] :
               &fast_templates[FT_CRC32_R_RM32];
    }
    if (opcode0 == 0x0f && opcode1 == 0xf6 &&
        ((info->id == dt_X86_INS_ADCX && info->x86.prefix[0] == 0 &&
          info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE) ||
         (info->id == dt_X86_INS_ADOX &&
          info->x86.prefix[0] == dt_X86_PREFIX_REP &&
          info->x86.prefix[2] == 0)) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        bool is_64 = rex >= 0 && (rex & 8);

        if (info->id == dt_X86_INS_ADCX) {
            return is_64 ? &fast_templates[FT_ADCX_R64_RM64] :
                           &fast_templates[FT_ADCX_R32_RM32];
        }
        return is_64 ? &fast_templates[FT_ADOX_R64_RM64] :
                       &fast_templates[FT_ADOX_R32_RM32];
    }
    if (info->id == dt_X86_INS_RDRAND && opcode0 == 0x0f &&
        opcode1 == 0xc7 && ft_modrm_mod(modrm) == 3 &&
        ((modrm >> 3) & 7) == 6) {
        if (rex >= 0 && (rex & 8)) {
            return &fast_templates[FT_RDRAND_R64];
        }
        return info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
               &fast_templates[FT_RDRAND_R16] :
               &fast_templates[FT_RDRAND_R32];
    }
    if (info->id == dt_X86_INS_ANDN && info->size >= 5 &&
        info->bytes[0] == 0xc4 && info->bytes[3] == 0xf2 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_ANDN_R64_R_RM] :
               &fast_templates[FT_ANDN_R32_R_RM];
    }
    if (info->id == dt_X86_INS_MULX && info->size >= 5 &&
        info->bytes[0] == 0xc4 && (info->bytes[1] & 0x1f) == 2 &&
        info->bytes[3] == 0xf6 && (info->bytes[2] & 7) == 3 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_MULX_R64_R_RM] :
               &fast_templates[FT_MULX_R32_R_RM];
    }
    if ((info->id == dt_X86_INS_BLSR ||
         info->id == dt_X86_INS_BLSMSK ||
         info->id == dt_X86_INS_BLSI) &&
        info->size >= 5 && info->bytes[0] == 0xc4 &&
        info->bytes[3] == 0xf3 &&
        (((modrm >> 3) & 7) >= 1 && ((modrm >> 3) & 7) <= 3) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_BLS_R64_RM] :
               &fast_templates[FT_BLS_R32_RM];
    }
    if (info->id == dt_X86_INS_BEXTR && info->size >= 5 &&
        info->bytes[0] == 0xc4 && info->bytes[3] == 0xf7 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_BEXTR_R64_RM_R] :
               &fast_templates[FT_BEXTR_R32_RM_R];
    }
    if (info->id == dt_X86_INS_SARX && info->size >= 5 &&
        info->bytes[0] == 0xc4 && info->bytes[3] == 0xf7 &&
        (info->bytes[2] & 3) == 2 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_SARX_R64_RM_R] :
               &fast_templates[FT_SARX_R32_RM_R];
    }
    if (info->id == dt_X86_INS_SHLX && info->size >= 5 &&
        info->bytes[0] == 0xc4 && (info->bytes[1] & 0x1f) == 2 &&
        info->bytes[3] == 0xf7 && (info->bytes[2] & 7) == 1 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_SHLX_R64_RM_R] :
               &fast_templates[FT_SHLX_R32_RM_R];
    }
    if (info->id == dt_X86_INS_SHRX && info->size >= 5 &&
        info->bytes[0] == 0xc4 && (info->bytes[1] & 0x1f) == 2 &&
        info->bytes[3] == 0xf7 && (info->bytes[2] & 7) == 3 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_SHRX_R64_RM_R] :
               &fast_templates[FT_SHRX_R32_RM_R];
    }
    if (info->id == dt_X86_INS_BZHI && info->size >= 5 &&
        info->bytes[0] == 0xc4 && info->bytes[3] == 0xf5 &&
        (info->bytes[2] & 7) == 0 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_BZHI_R64_RM_R] :
               &fast_templates[FT_BZHI_R32_RM_R];
    }
    if (info->id == dt_X86_INS_PEXT && info->size >= 5 &&
        info->bytes[0] == 0xc4 && info->bytes[3] == 0xf5 &&
        (info->bytes[2] & 7) == 2 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_PEXT_R64_R_RM] :
               &fast_templates[FT_PEXT_R32_R_RM];
    }
    if (info->id == dt_X86_INS_PDEP && info->size >= 5 &&
        info->bytes[0] == 0xc4 && info->bytes[3] == 0xf5 &&
        (info->bytes[2] & 7) == 3 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_PDEP_R64_R_RM] :
               &fast_templates[FT_PDEP_R32_R_RM];
    }
    if ((info->id == dt_X86_INS_VFMADD132PS ||
         info->id == dt_X86_INS_VFMADD132PD ||
         info->id == dt_X86_INS_VFMSUB132PS ||
         info->id == dt_X86_INS_VFMSUB132PD) &&
        info->size >= 5 && info->bytes[0] == 0xc4 &&
        (info->bytes[3] == 0x98 || info->bytes[3] == 0x9a) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_FMA132_XMM_XMMM];
    }
    if (opcode0 == 0x3d) {
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_CMP_AX_IMM16];
        }
        return (rex >= 0 && (rex & 8)) ? &fast_templates[FT_CMP_RAX_IMM32] :
                                         &fast_templates[FT_CMP_EAX_IMM32];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_MOVQ &&
        info->x86.prefix[0] != 0xf3 &&
        info->x86.prefix[2] != 0x66 &&
        opcode1 == 0x6f &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVQ_MMX_RM64];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_MOVQ &&
        info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 &&
        opcode1 == 0x7f &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVQ_MMXM64_MMX];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_ADDPD &&
        info->x86.prefix[2] == 0x66 &&
        opcode1 == 0x58 &&
        ft_modrm_mod(modrm) == 3) {
        return &fast_templates[FT_ADDPD_XMM_XMM];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_CVTPI2PD &&
        info->x86.prefix[2] == 0x66 &&
        opcode1 == 0x2a &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CVTPI2PD_XMM_MMX];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_CVTSI2SS &&
        info->x86.prefix[0] == 0xf3 &&
        opcode1 == 0x2a &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CVTSI2SS_XMM_RM];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_CVTSI2SD &&
        info->x86.prefix[0] == 0xf2 &&
        opcode1 == 0x2a &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CVTSI2SD_XMM_RM];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_CVTTSS2SI &&
        info->x86.prefix[0] == 0xf3 &&
        opcode1 == 0x2c &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CVTTSS2SI_GPR_XMMM];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_CVTSS2SI &&
        info->x86.prefix[0] == 0xf3 &&
        opcode1 == 0x2d &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CVTSS2SI_GPR_XMMM];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_CVTTSD2SI &&
        info->x86.prefix[0] == 0xf2 &&
        opcode1 == 0x2c &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CVTTSD2SI_GPR_XMMM];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_CVTSD2SI &&
        info->x86.prefix[0] == 0xf2 &&
        opcode1 == 0x2d &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_CVTSD2SI_GPR_XMMM];
    }
    if (opcode0 == 0x0f &&
        (info->id == dt_X86_INS_CVTDQ2PD ||
         info->id == dt_X86_INS_CVTDQ2PS ||
         info->id == dt_X86_INS_CVTPD2PS ||
         info->id == dt_X86_INS_CVTPS2PD ||
         info->id == dt_X86_INS_CVTSD2SS ||
         info->id == dt_X86_INS_CVTSS2SD) &&
        (opcode1 == 0x5a || opcode1 == 0x5b || opcode1 == 0xe6)) {
        int cvt_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, cvt_sib) ||
            ft_supported_lea_addr(rex, modrm, cvt_sib)) {
            return &fast_templates[FT_CVT_FP_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0x2a &&
        info->id == dt_X86_INS_CVTPI2PS) {
        int cvt_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, cvt_sib) ||
            ft_supported_lea_addr(rex, modrm, cvt_sib)) {
            return &fast_templates[FT_CVTPI2PS_XMM_MMX];
        }
    }
    if (opcode0 == 0x0f &&
        (info->id == dt_X86_INS_CVTPD2DQ ||
         info->id == dt_X86_INS_CVTPS2DQ ||
         info->id == dt_X86_INS_CVTTPD2DQ ||
         info->id == dt_X86_INS_CVTTPS2DQ) &&
        (opcode1 == 0x5b || opcode1 == 0xe6)) {
        int cvt_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, cvt_sib) ||
            ft_supported_lea_addr(rex, modrm, cvt_sib)) {
            return &fast_templates[FT_CVT_FP2I_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f &&
        (info->id == dt_X86_INS_CVTPD2PI ||
         info->id == dt_X86_INS_CVTPS2PI ||
         info->id == dt_X86_INS_CVTTPD2PI ||
         info->id == dt_X86_INS_CVTTPS2PI) &&
        (opcode1 == 0x2c || opcode1 == 0x2d)) {
        int cvt_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, cvt_sib) ||
            ft_supported_lea_addr(rex, modrm, cvt_sib)) {
            return &fast_templates[FT_CVT_FP2I_MMX_XMMM];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0x77 &&
        info->id == dt_X86_INS_EMMS) {
        return &fast_templates[FT_EMMS];
    }
    if (opcode0 == 0x0f &&
        (info->id == dt_X86_INS_MOVAPD ||
         info->id == dt_X86_INS_MOVDQA ||
         info->id == dt_X86_INS_MOVDQU ||
         info->id == dt_X86_INS_MOVUPD ||
         info->id == dt_X86_INS_MOVAPS ||
         info->id == dt_X86_INS_MOVUPS) &&
        ft_mov128_opcode_supported(info->x86.prefix[0],
                                   info->x86.prefix[2],
                                   opcode1, &mov128_store) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return mov128_store ? &fast_templates[FT_MOV128_XMMM_XMM] :
                              &fast_templates[FT_MOV128_XMM_XMMM];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_LDDQU &&
        info->x86.prefix[0] == 0xf2 &&
        opcode1 == 0xf0 &&
        ft_modrm_mod(modrm) != 3 &&
        (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV128_XMM_XMMM];
    }
    if (opcode0 == 0x0f &&
        info->id == dt_X86_INS_MOVNTDQA &&
        info->x86.prefix[2] == 0x66 &&
        opcode1 == 0x2a &&
        ft_modrm_mod(modrm) != 3 &&
        (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV128_XMM_XMMM];
    }
    if (opcode0 == 0x0f &&
        (info->id == dt_X86_INS_MOVLPS ||
         info->id == dt_X86_INS_MOVLPD) &&
        (opcode1 == 0x12 || opcode1 == 0x13) &&
        ft_modrm_mod(modrm) != 3 &&
        (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (opcode1 == 0x12) {
            return info->id == dt_X86_INS_MOVLPD ?
                   &fast_templates[FT_MOVLPD_XMM_M64] :
                   &fast_templates[FT_MOVLPS_XMM_M64];
        }
        return &fast_templates[FT_MOVQ_RM64_XMM];
    }
    if (opcode0 == 0x0f &&
        (info->id == dt_X86_INS_MOVHPS ||
         info->id == dt_X86_INS_MOVHPD ||
         info->id == dt_X86_INS_MOVHLPS ||
         info->id == dt_X86_INS_MOVLHPS) &&
        (opcode1 == 0x12 || opcode1 == 0x16 || opcode1 == 0x17) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOVHPS_XMM_M64];
    }
    if (opcode0 == 0x0f &&
        (info->id == dt_X86_INS_MOVNTDQ ||
         info->id == dt_X86_INS_MOVNTPD ||
         info->id == dt_X86_INS_MOVNTPS) &&
        (opcode1 == 0x2b || opcode1 == 0xe7) &&
        ft_modrm_mod(modrm) != 3 &&
        (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_MOV128_XMMM_XMM];
    }
    scalar_rex = rex;
    scalar_modrm = modrm;
    if (ft_scalar_mov_opcode_info(info, &scalar_rex, &scalar_prefix,
                                  &scalar_opcode, &scalar_modrm) &&
        (ft_modrm_mod(scalar_modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(scalar_rex, scalar_modrm, sib) ||
         ft_supported_lea_addr(scalar_rex, scalar_modrm, sib))) {
        return scalar_opcode == 0x10 ?
               &fast_templates[FT_MOVSD_XMM_M64] :
               &fast_templates[FT_MOVSD_M64_XMM];
    }
    if (opcode0 == 0x0f &&
        (info->x86.prefix[0] == 0 || info->x86.prefix[0] == 0xf2) &&
        (info->x86.prefix[2] == 0 || info->x86.prefix[2] == 0x66) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        uint32_t la_opcode;
        int id;
        bool reverse_operands;

        if (ft_simd_bin_opcode_info(info->x86.prefix[0],
                                    info->x86.prefix[2], opcode1,
                                    &la_opcode, &id, &reverse_operands) &&
            info->id == id) {
            return &fast_templates[FT_SIMD_BIN_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        uint32_t la_opcode;
        int id;
        bool is_double;
        bool qnan;

        if (ft_simd_scalar_bin_opcode_info(info->x86.prefix[0], opcode1,
                                           &la_opcode, &id) &&
            info->id == id) {
            return &fast_templates[FT_SIMD_SCALAR_BIN_XMM_XMMM];
        }
        if (ft_simd_scalar_cmp_opcode_info(info->x86.prefix[0],
                                           info->x86.prefix[2], opcode1,
                                           &is_double, &qnan, &id) &&
            info->id == id) {
            return &fast_templates[FT_SIMD_SCALAR_CMP_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && info->id == dt_X86_INS_MOVQ) {
        if (info->x86.prefix[0] == 0 &&
            info->x86.prefix[2] == 0 &&
            rex >= 0 && (rex & 8) &&
            opcode1 == 0x6e &&
            (ft_modrm_mod(modrm) == 3 ||
             ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_MOVQ_MMX_RM64_GPR];
        }
        if (info->x86.prefix[0] == 0 &&
            info->x86.prefix[2] == 0 &&
            rex >= 0 && (rex & 8) &&
            opcode1 == 0x7e &&
            (ft_modrm_mod(modrm) == 3 ||
             ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_MOVQ_RM64_MMX];
        }
        if (info->x86.prefix[2] == 0x66 && rex >= 0 && (rex & 8) &&
            ft_modrm_mod(modrm) == 3) {
            if (opcode1 == 0x6e) {
                return &fast_templates[FT_MOVQ_XMM_R64];
            }
            if (opcode1 == 0x7e) {
                return &fast_templates[FT_MOVQ_R64_XMM];
            }
        }
        if (info->x86.prefix[0] == 0xf3 &&
            opcode1 == 0x7e &&
            (ft_modrm_mod(modrm) == 3 ||
             ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_MOVQ_XMM_RM64];
        }
        if (info->x86.prefix[2] == 0x66 &&
            opcode1 == 0xd6 &&
            ft_modrm_mod(modrm) != 3 &&
            (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
            ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_MOVQ_RM64_XMM];
        }
    }
    if (info->id == dt_X86_INS_PEXTRQ && info->size >= 7 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_PEXTRQ_R64_XMM_IMM8];
    }
    if (info->id == dt_X86_INS_PEXTRW && info->size >= 5 &&
        info->x86.prefix[2] == 0x66) {
        if (opcode0 == 0x0f && opcode1 == 0x3a &&
            info->bytes[info->size - 3] == 0x15 &&
            (ft_modrm_mod(modrm) == 3 ||
             ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
             ft_supported_lea_addr(rex, modrm, sib))) {
            return &fast_templates[FT_PEXTRW_SSE41_RM16_XMM_IMM8];
        }
        if (ft_modrm_mod(modrm) == 3) {
            return &fast_templates[FT_PEXTRW_R32_XMM_IMM8];
        }
    }
    if (info->id == dt_X86_INS_PEXTRW && info->size >= 4 &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
        opcode0 == 0x0f && opcode1 == 0xc5 &&
        ft_modrm_mod(modrm) == 3) {
        return &fast_templates[FT_PEXTRW_R32_MMX_IMM8];
    }
    if (info->id == dt_X86_INS_PINSRW && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 && opcode0 == 0x0f && opcode1 == 0xc4 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_PINSRW_MMX_RM16_IMM8];
    }
    if (info->x86.prefix[2] == 0x66 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib)) &&
        ((opcode0 == 0x0f && opcode1 == 0x14 &&
          info->id == dt_X86_INS_PEXTRB) ||
         (opcode0 == 0x0f && opcode1 == 0x16 &&
          (info->id == dt_X86_INS_PEXTRD ||
           info->id == dt_X86_INS_PEXTRQ)))) {
        return &fast_templates[FT_PEXTR_GPR_XMM_IMM8];
    }
    if (info->x86.prefix[2] == 0x66 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib)) &&
        ((opcode0 == 0x0f && opcode1 == 0xc4 &&
          info->id == dt_X86_INS_PINSRW) ||
         (opcode0 == 0x0f && opcode1 == 0x20 &&
          info->id == dt_X86_INS_PINSRB) ||
         (opcode0 == 0x0f && opcode1 == 0x22 &&
          (info->id == dt_X86_INS_PINSRD ||
           info->id == dt_X86_INS_PINSRQ)))) {
        return &fast_templates[FT_PINSR_XMM_GPR_IMM8];
    }
    if (opcode0 == 0x0f && opcode1 == 0x50 &&
        (info->id == dt_X86_INS_MOVMSKPS ||
         info->id == dt_X86_INS_MOVMSKPD) &&
        ft_modrm_mod(modrm) == 3) {
        return &fast_templates[FT_PMOVMSKB_R32_XMM];
    }
    if (opcode0 == 0x0f && info->id == dt_X86_INS_MOVD &&
        info->x86.prefix[2] == 0x66 && !(rex >= 0 && (rex & 8)) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (opcode1 == 0x6e) {
            return &fast_templates[FT_MOVD_XMM_R32];
        }
        if (opcode1 == 0x7e) {
            return &fast_templates[FT_MOVD_R32_XMM];
        }
    }
    if (opcode0 == 0x0f && info->id == dt_X86_INS_MOVD &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
        !(rex >= 0 && (rex & 8)) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (opcode1 == 0x6e) {
            return &fast_templates[FT_MOVD_MMX_RM32];
        }
        if (opcode1 == 0x7e) {
            return &fast_templates[FT_MOVD_RM32_MMX];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib)) &&
        ((opcode1 == 0x58 && info->id == dt_X86_INS_ADDPS) ||
         (opcode1 == 0x59 && info->id == dt_X86_INS_MULPS) ||
         (opcode1 == 0x54 && info->id == dt_X86_INS_ANDPS) ||
         (opcode1 == 0x55 && info->id == dt_X86_INS_ANDNPS))) {
        return &fast_templates[FT_SIMD_BIN_XMM_XMMM];
    }
    if (opcode0 == 0x0f && opcode1 == 0xd7 &&
        info->id == dt_X86_INS_PMOVMSKB && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 && ft_modrm_mod(modrm) == 3) {
        return &fast_templates[FT_PMOVMSKB_R32_MMX];
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        uint32_t punpck_la_opcode;
        int punpck_id;

        if (info->id == dt_X86_INS_PXOR && opcode1 == 0xef) {
            return &fast_templates[FT_PXOR_XMM_XMMM];
        }
        if ((info->id == dt_X86_INS_PADDB ||
             info->id == dt_X86_INS_PADDW ||
             info->id == dt_X86_INS_PADDD ||
             info->id == dt_X86_INS_PADDQ) &&
            ft_padd_opcode_info(opcode1, &punpck_la_opcode, &punpck_id) &&
            info->id == punpck_id) {
            return &fast_templates[FT_PADD_XMM_XMMM];
        }
        if (info->id == dt_X86_INS_PMULUDQ && opcode1 == 0xf4) {
            return &fast_templates[FT_PMULUDQ_XMM_XMMM];
        }
        if ((info->id == dt_X86_INS_PCMPEQB ||
             info->id == dt_X86_INS_PCMPEQW ||
             info->id == dt_X86_INS_PCMPEQD ||
             info->id == dt_X86_INS_PCMPEQQ) &&
            ft_pcmpeq_opcode_info(opcode1, &punpck_la_opcode,
                                  &punpck_id) &&
            info->id == punpck_id) {
            return &fast_templates[FT_PCMPEQB_XMM_XMMM];
        }
        if (info->id == dt_X86_INS_PMOVMSKB && opcode1 == 0xd7) {
            return &fast_templates[FT_PMOVMSKB_R32_XMM];
        }
        if (info->id == dt_X86_INS_MASKMOVDQU && opcode1 == 0xf7 &&
            ft_modrm_mod(modrm) == 3) {
            return &fast_templates[FT_MASKMOVDQU_XMM_XMM];
        }
        {
            bool reverse_operands;

            if (ft_simd_bin_opcode_info(info->x86.prefix[0],
                                        info->x86.prefix[2], opcode1,
                                        &punpck_la_opcode, &punpck_id,
                                        &reverse_operands)) {
                if (info->id == punpck_id ||
                    (opcode1 == 0x54 &&
                     (info->id == dt_X86_INS_ANDPS ||
                      info->id == dt_X86_INS_ANDPD)) ||
                    (opcode1 == 0x55 &&
                     (info->id == dt_X86_INS_ANDNPS ||
                      info->id == dt_X86_INS_ANDNPD))) {
                    return &fast_templates[FT_SIMD_BIN_XMM_XMMM];
                }
            }
        }
        if (info->x86.prefix[0] == 0 &&
            ft_punpck_opcode_info(info->x86.prefix[2], opcode1,
                                  &punpck_la_opcode, &punpck_id) &&
            info->id == punpck_id) {
            return &fast_templates[FT_PUNPCK_XMM_XMMM];
        }
        if (info->x86.prefix[0] == 0 &&
            info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE &&
            ((opcode1 == 0x63 && info->id == dt_X86_INS_PACKSSWB) ||
             (opcode1 == 0x67 && info->id == dt_X86_INS_PACKUSWB) ||
             (opcode1 == 0x6b && info->id == dt_X86_INS_PACKSSDW) ||
             (opcode1 == 0x2b && info->id == dt_X86_INS_PACKUSDW))) {
            return &fast_templates[FT_PACK_XMM_XMM];
        }
        if (info->x86.prefix[0] == 0 &&
            info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE &&
            ((opcode1 == 0xf5 && info->id == dt_X86_INS_PMADDWD) ||
             (opcode1 == 0x0b && info->id == dt_X86_INS_PMULHRSW) ||
             (opcode1 == 0x04 && info->id == dt_X86_INS_PMADDUBSW)) &&
            (ft_modrm_mod(modrm) == 3 ||
             ft_supported_base_disp_or_rip_addr(rex, modrm,
                                                ft_ir1_sib_byte(info)) ||
             ft_supported_lea_addr(rex, modrm, ft_ir1_sib_byte(info)))) {
            return &fast_templates[FT_SIMD_MADD_XMM_XMM];
        }
        if (info->x86.op_count >= 2 &&
            (opcode1 == 0x71 || opcode1 == 0x72 || opcode1 == 0x73) &&
            (((modrm >> 3) & 7) == 2 || ((modrm >> 3) & 7) == 4 ||
             ((modrm >> 3) & 7) == 6)) {
            switch (info->id) {
            case dt_X86_INS_PSRLW:
            case dt_X86_INS_PSRLD:
            case dt_X86_INS_PSRLQ:
            case dt_X86_INS_PSRAW:
            case dt_X86_INS_PSRAD:
            case dt_X86_INS_PSLLW:
            case dt_X86_INS_PSLLD:
            case dt_X86_INS_PSLLQ:
                return &fast_templates[FT_PSHIFT_XMM_IMM8];
            default:
                break;
            }
        }
        if (info->x86.op_count >= 2 && opcode1 == 0x73 &&
            ft_modrm_mod(modrm) == 3) {
            if (((modrm >> 3) & 7) == 3 &&
                info->id == dt_X86_INS_PSRLDQ) {
                return &fast_templates[FT_PSRLDQ_XMM_IMM8];
            }
            if (((modrm >> 3) & 7) == 7 &&
                info->id == dt_X86_INS_PSLLDQ) {
                return &fast_templates[FT_PSLLDQ_XMM_IMM8];
            }
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 &&
        (opcode1 == 0x14 || opcode1 == 0x15) &&
        (info->id == dt_X86_INS_UNPCKLPS ||
         info->id == dt_X86_INS_UNPCKHPS) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        uint32_t punpck_la_opcode;
        int punpck_id;

        if (ft_punpck_opcode_info(info->x86.prefix[2], opcode1,
                                  &punpck_la_opcode, &punpck_id) &&
            info->id == punpck_id) {
            return &fast_templates[FT_PUNPCK_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0x66 &&
        (opcode1 == 0x14 || opcode1 == 0x15) &&
        (info->id == dt_X86_INS_UNPCKLPD ||
         info->id == dt_X86_INS_UNPCKHPD) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_UNPCKPD_XMM_XMMM];
    }
    if (opcode0 == 0x0f && info->size >= 4 &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (opcode1 == 0xc6 && info->x86.prefix[0] == 0 &&
            ((info->x86.prefix[2] == 0 &&
              info->id == dt_X86_INS_SHUFPS) ||
             (info->x86.prefix[2] == 0x66 &&
              info->id == dt_X86_INS_SHUFPD))) {
            return &fast_templates[FT_SHUF_XMM_XMMM_IMM8];
        }
        if (opcode1 == 0x70 && info->x86.prefix[2] == 0 &&
            ((info->x86.prefix[0] == 0xf2 &&
              info->id == dt_X86_INS_PSHUFLW) ||
             (info->x86.prefix[0] == 0xf3 &&
              info->id == dt_X86_INS_PSHUFHW))) {
            return &fast_templates[FT_SHUF_XMM_XMMM_IMM8];
        }
        if (opcode1 == 0x70 && info->x86.prefix[0] == 0 &&
            info->x86.prefix[2] == 0x66 &&
            info->id == dt_X86_INS_PSHUFD) {
            return &fast_templates[FT_SHUF_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f &&
        ((opcode1 == 0x3a && info->x86.opcode[2] == 0x0f) ||
         opcode1 == 0x0f) &&
        info->x86.prefix[2] == 0x66 &&
        info->id == dt_X86_INS_PALIGNR) {
        int palignr_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, palignr_sib) ||
            ft_supported_lea_addr(rex, modrm, palignr_sib)) {
            return &fast_templates[FT_PALIGNR_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0x3a &&
        info->x86.opcode[2] == 0x0f && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 && info->id == dt_X86_INS_PALIGNR) {
        int palignr_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, palignr_sib) ||
            ft_supported_lea_addr(rex, modrm, palignr_sib)) {
            return &fast_templates[FT_PALIGNR_MMX_MMXM64_IMM8];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        (((opcode1 == 0x3a &&
           (info->x86.opcode[2] == 0x0c ||
            info->x86.opcode[2] == 0x0d ||
            info->x86.opcode[2] == 0x0e)) ||
          opcode1 == 0x0c || opcode1 == 0x0d || opcode1 == 0x0e) &&
         (info->id == dt_X86_INS_BLENDPS ||
          info->id == dt_X86_INS_BLENDPD ||
          info->id == dt_X86_INS_PBLENDW))) {
        int blend_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, blend_sib) ||
            ft_supported_lea_addr(rex, modrm, blend_sib)) {
            return &fast_templates[FT_BLEND_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        (((opcode1 == 0x38 &&
           (info->x86.opcode[2] == 0x10 ||
            info->x86.opcode[2] == 0x14 ||
            info->x86.opcode[2] == 0x15)) ||
          opcode1 == 0x10 || opcode1 == 0x14 || opcode1 == 0x15) &&
         (info->id == dt_X86_INS_PBLENDVB ||
          info->id == dt_X86_INS_BLENDVPS ||
          info->id == dt_X86_INS_BLENDVPD))) {
        int blendv_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, blendv_sib) ||
            ft_supported_lea_addr(rex, modrm, blendv_sib)) {
            return &fast_templates[FT_BLENDV_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        ((opcode1 == 0x38 && info->x86.opcode[2] == 0x00) ||
         opcode1 == 0x00) &&
        info->id == dt_X86_INS_PSHUFB) {
        int pshufb_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pshufb_sib) ||
            ft_supported_lea_addr(rex, modrm, pshufb_sib)) {
            return &fast_templates[FT_PSHUFB_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        (((opcode1 == 0x38 &&
           (info->x86.opcode[2] == 0x01 ||
            info->x86.opcode[2] == 0x02 ||
            info->x86.opcode[2] == 0x03 ||
            info->x86.opcode[2] == 0x05 ||
            info->x86.opcode[2] == 0x06 ||
            info->x86.opcode[2] == 0x07)) ||
          opcode1 == 0x01 || opcode1 == 0x02 || opcode1 == 0x03 ||
          opcode1 == 0x05 || opcode1 == 0x06 || opcode1 == 0x07) &&
         (info->id == dt_X86_INS_PHADDW ||
          info->id == dt_X86_INS_PHADDD ||
          info->id == dt_X86_INS_PHADDSW ||
          info->id == dt_X86_INS_PHSUBW ||
          info->id == dt_X86_INS_PHSUBD ||
          info->id == dt_X86_INS_PHSUBSW))) {
        int phadd_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, phadd_sib) ||
            ft_supported_lea_addr(rex, modrm, phadd_sib)) {
            return &fast_templates[FT_PHADD_SUB_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 && opcode1 == 0x38 &&
        (info->x86.opcode[2] == 0x01 ||
         info->x86.opcode[2] == 0x02 ||
         info->x86.opcode[2] == 0x03 ||
         info->x86.opcode[2] == 0x05 ||
         info->x86.opcode[2] == 0x06 ||
         info->x86.opcode[2] == 0x07) &&
        (info->id == dt_X86_INS_PHADDW ||
         info->id == dt_X86_INS_PHADDD ||
         info->id == dt_X86_INS_PHADDSW ||
         info->id == dt_X86_INS_PHSUBW ||
         info->id == dt_X86_INS_PHSUBD ||
         info->id == dt_X86_INS_PHSUBSW)) {
        int phadd_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, phadd_sib) ||
            ft_supported_lea_addr(rex, modrm, phadd_sib)) {
            return &fast_templates[FT_PHADD_SUB_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 && opcode1 == 0x38 &&
        info->x86.opcode[2] == 0x00 && info->id == dt_X86_INS_PSHUFB) {
        return &fast_templates[FT_PSHUFB_MMX_MMXM64];
    }
    if (opcode0 == 0x0f && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 && opcode1 == 0x38 &&
        ((info->x86.opcode[2] == 0x04 &&
          info->id == dt_X86_INS_PMADDUBSW) ||
         (info->x86.opcode[2] == 0x0b &&
          info->id == dt_X86_INS_PMULHRSW))) {
        return &fast_templates[FT_SIMD_MADD_MMX_MMXM64];
    }
    if (opcode0 == 0x0f && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 && opcode1 == 0x38 &&
        ((info->x86.opcode[2] == 0x08 && info->id == dt_X86_INS_PSIGNB) ||
         (info->x86.opcode[2] == 0x09 && info->id == dt_X86_INS_PSIGNW) ||
         (info->x86.opcode[2] == 0x0a && info->id == dt_X86_INS_PSIGND) ||
         (info->x86.opcode[2] == 0x1c && info->id == dt_X86_INS_PABSB) ||
         (info->x86.opcode[2] == 0x1d && info->id == dt_X86_INS_PABSW) ||
         (info->x86.opcode[2] == 0x1e && info->id == dt_X86_INS_PABSD))) {
        return &fast_templates[FT_SIMD_BIN_MMX_MMXM64];
    }
    if (opcode0 == 0x0f &&
        (opcode1 == 0x7c || opcode1 == 0x7d) &&
        ((info->x86.prefix[2] == 0x66 &&
          (info->id == dt_X86_INS_HADDPD ||
           info->id == dt_X86_INS_HSUBPD)) ||
         (info->x86.prefix[0] == 0xf2 &&
          (info->id == dt_X86_INS_HADDPS ||
           info->id == dt_X86_INS_HSUBPS)))) {
        int hadd_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, hadd_sib) ||
            ft_supported_lea_addr(rex, modrm, hadd_sib)) {
            return &fast_templates[FT_HADD_SUB_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f &&
        ((opcode1 == 0x12 &&
          ((info->x86.prefix[0] == 0xf2 &&
            info->id == dt_X86_INS_MOVDDUP) ||
           (info->x86.prefix[0] == 0xf3 &&
            info->id == dt_X86_INS_MOVSLDUP))) ||
         (opcode1 == 0x16 && info->x86.prefix[0] == 0xf3 &&
          info->id == dt_X86_INS_MOVSHDUP))) {
        int movdup_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, movdup_sib) ||
            ft_supported_lea_addr(rex, modrm, movdup_sib)) {
            return &fast_templates[FT_MOVDUP_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xf6 &&
        info->x86.prefix[2] == 0x66 &&
        info->id == dt_X86_INS_PSADBW) {
        int psadbw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, psadbw_sib) ||
            ft_supported_lea_addr(rex, modrm, psadbw_sib)) {
            return &fast_templates[FT_PSADBW_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xf6 &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
        info->id == dt_X86_INS_PSADBW) {
        int psadbw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, psadbw_sib) ||
            ft_supported_lea_addr(rex, modrm, psadbw_sib)) {
            return &fast_templates[FT_PSADBW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xd5 &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
        info->id == dt_X86_INS_PMULLW) {
        int pmullw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pmullw_sib) ||
            ft_supported_lea_addr(rex, modrm, pmullw_sib)) {
            return &fast_templates[FT_PMULLW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && (opcode1 == 0xe4 || opcode1 == 0xe5) &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
        info->id == (opcode1 == 0xe4 ? dt_X86_INS_PMULHUW :
                                        dt_X86_INS_PMULHW)) {
        int pmulh_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pmulh_sib) ||
            ft_supported_lea_addr(rex, modrm, pmulh_sib)) {
            return &fast_templates[opcode1 == 0xe4 ?
                                   FT_PMULHUW_MMX_MMXM64 :
                                   FT_PMULHW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f &&
        ((opcode1 == 0xe1 && info->id == dt_X86_INS_PSRAW) ||
         (opcode1 == 0xe2 && info->id == dt_X86_INS_PSRAD)) &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
        info->x86.op_count >= 2) {
        int psra_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, psra_sib) ||
            ft_supported_lea_addr(rex, modrm, psra_sib)) {
            return &fast_templates[opcode1 == 0xe1 ?
                                   FT_PSRAW_MMX_MMXM64 :
                                   FT_PSRAD_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xf7 &&
        info->id == dt_X86_INS_MASKMOVQ &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
        ft_modrm_mod(modrm) == 3) {
        return &fast_templates[FT_MASKMOVQ_MMX_MMX];
    }
    if (opcode0 == 0x0f && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 &&
        ((opcode1 == 0x74 && info->id == dt_X86_INS_PCMPEQB) ||
         (opcode1 == 0x75 && info->id == dt_X86_INS_PCMPEQW) ||
         (opcode1 == 0x76 && info->id == dt_X86_INS_PCMPEQD) ||
         (opcode1 == 0x64 && info->id == dt_X86_INS_PCMPGTB) ||
         (opcode1 == 0x65 && info->id == dt_X86_INS_PCMPGTW) ||
         (opcode1 == 0x66 && info->id == dt_X86_INS_PCMPGTD))) {
        int pcmp_sib = ft_ir1_sib_byte(info);
        FastTemplateKind kind = opcode1 == 0x74 ? FT_PCMPEQB_MMX_MMXM64 :
                                opcode1 == 0x75 ? FT_PCMPEQW_MMX_MMXM64 :
                                opcode1 == 0x76 ? FT_PCMPEQD_MMX_MMXM64 :
                                opcode1 == 0x64 ? FT_PCMPGTB_MMX_MMXM64 :
                                opcode1 == 0x65 ? FT_PCMPGTW_MMX_MMXM64 :
                                                  FT_PCMPGTD_MMX_MMXM64;

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pcmp_sib) ||
            ft_supported_lea_addr(rex, modrm, pcmp_sib)) {
            return &fast_templates[kind];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        ((opcode1 == 0x3a && info->x86.opcode[2] == 0x42) ||
         opcode1 == 0x42) &&
        info->id == dt_X86_INS_MPSADBW) {
        int mpsadbw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, mpsadbw_sib) ||
            ft_supported_lea_addr(rex, modrm, mpsadbw_sib)) {
            return &fast_templates[FT_MPSADBW_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        (((opcode1 == 0x38 &&
           ((info->x86.opcode[2] >= 0x20 && info->x86.opcode[2] <= 0x25) ||
            (info->x86.opcode[2] >= 0x30 && info->x86.opcode[2] <= 0x35))) ||
          (opcode1 >= 0x20 && opcode1 <= 0x25) ||
          (opcode1 >= 0x30 && opcode1 <= 0x35)) &&
         (info->id == dt_X86_INS_PMOVSXBW ||
          info->id == dt_X86_INS_PMOVSXBD ||
          info->id == dt_X86_INS_PMOVSXBQ ||
          info->id == dt_X86_INS_PMOVSXWD ||
          info->id == dt_X86_INS_PMOVSXWQ ||
          info->id == dt_X86_INS_PMOVSXDQ ||
          info->id == dt_X86_INS_PMOVZXBW ||
          info->id == dt_X86_INS_PMOVZXBD ||
          info->id == dt_X86_INS_PMOVZXBQ ||
          info->id == dt_X86_INS_PMOVZXWD ||
          info->id == dt_X86_INS_PMOVZXWQ ||
          info->id == dt_X86_INS_PMOVZXDQ))) {
        int pmovx_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pmovx_sib) ||
            ft_supported_lea_addr(rex, modrm, pmovx_sib)) {
            return &fast_templates[FT_PMOVX_XMM_XMMM];
        }
    }
    if (info->id == dt_X86_INS_VPMOVSXBD ||
        info->id == dt_X86_INS_VPMOVSXBQ ||
        info->id == dt_X86_INS_VPMOVZXBD ||
        info->id == dt_X86_INS_VPMOVZXBQ) {
        int pmovx_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pmovx_sib) ||
            ft_supported_lea_addr(rex, modrm, pmovx_sib)) {
            return &fast_templates[FT_PMOVX_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        ((opcode1 == 0x38 && info->x86.opcode[2] == 0x17) ||
         opcode1 == 0x17) &&
        info->id == dt_X86_INS_PTEST) {
        int ptest_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, ptest_sib) ||
            ft_supported_lea_addr(rex, modrm, ptest_sib)) {
            return &fast_templates[FT_PTEST_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        ((opcode1 == 0x3a && info->x86.opcode[2] == 0x21) ||
         opcode1 == 0x21) &&
        info->id == dt_X86_INS_INSERTPS) {
        int insertps_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, insertps_sib) ||
            ft_supported_lea_addr(rex, modrm, insertps_sib)) {
            return &fast_templates[FT_INSERTPS_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        ((opcode1 == 0x3a && info->x86.opcode[2] == 0x17) ||
         opcode1 == 0x17) &&
        info->id == dt_X86_INS_EXTRACTPS) {
        int extractps_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, extractps_sib) ||
            ft_supported_lea_addr(rex, modrm, extractps_sib)) {
            return &fast_templates[FT_EXTRACTPS_RM32_XMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0x70 &&
        info->id == dt_X86_INS_PSHUFW) {
        int pshufw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pshufw_sib) ||
            ft_supported_lea_addr(rex, modrm, pshufw_sib)) {
            return &fast_templates[FT_PSHUFW_MMX_MMXM_IMM8];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[0] == 0 &&
        info->x86.prefix[2] == 0 &&
        (opcode1 == 0x71 || opcode1 == 0x72 || opcode1 == 0x73) &&
        ft_modrm_mod(modrm) == 3) {
        int ext = (modrm >> 3) & 7;
        bool valid = (opcode1 == 0x71 &&
                      ((ext == 2 && info->id == dt_X86_INS_PSRLW) ||
                       (ext == 4 && info->id == dt_X86_INS_PSRAW) ||
                       (ext == 6 && info->id == dt_X86_INS_PSLLW))) ||
                     (opcode1 == 0x72 &&
                      ((ext == 2 && info->id == dt_X86_INS_PSRLD) ||
                       (ext == 4 && info->id == dt_X86_INS_PSRAD) ||
                       (ext == 6 && info->id == dt_X86_INS_PSLLD))) ||
                     (opcode1 == 0x73 &&
                      ((ext == 2 && info->id == dt_X86_INS_PSRLQ) ||
                       (ext == 6 && info->id == dt_X86_INS_PSLLQ)));

        if (valid) {
            return &fast_templates[FT_PSHIFT_MMX_IMM8];
        }
    }
    if (opcode0 == 0x0f && opcode1 >= 0xf8 && opcode1 <= 0xfb &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
        ((opcode1 == 0xf8 && info->id == dt_X86_INS_PSUBB) ||
         (opcode1 == 0xf9 && info->id == dt_X86_INS_PSUBW) ||
         (opcode1 == 0xfa && info->id == dt_X86_INS_PSUBD) ||
         (opcode1 == 0xfb && info->id == dt_X86_INS_PSUBQ))) {
        int psub_sib = ft_ir1_sib_byte(info);
        FastTemplateKind kind = opcode1 == 0xf8 ? FT_PSUBB_MMX_MMXM64 :
                                opcode1 == 0xf9 ? FT_PSUBW_MMX_MMXM64 :
                                opcode1 == 0xfa ? FT_PSUBD_MMX_MMXM64 :
                                                  FT_PSUBQ_MMX_MMXM64;

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, psub_sib) ||
            ft_supported_lea_addr(rex, modrm, psub_sib)) {
            return &fast_templates[kind];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xd8 &&
        info->id == dt_X86_INS_PSUBUSB &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int psubusb_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, psubusb_sib) ||
            ft_supported_lea_addr(rex, modrm, psubusb_sib)) {
            return &fast_templates[FT_PSUBUSB_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && (opcode1 == 0xe8 || opcode1 == 0xe9) &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0 &&
        ((opcode1 == 0xe8 && info->id == dt_X86_INS_PSUBSB) ||
         (opcode1 == 0xe9 && info->id == dt_X86_INS_PSUBSW))) {
        int psubs_sib = ft_ir1_sib_byte(info);
        FastTemplateKind kind = opcode1 == 0xe8 ? FT_PSUBSB_MMX_MMXM64 :
                                                  FT_PSUBSW_MMX_MMXM64;

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, psubs_sib) ||
            ft_supported_lea_addr(rex, modrm, psubs_sib)) {
            return &fast_templates[kind];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xd9 &&
        info->id == dt_X86_INS_PSUBUSW &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int psubusw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, psubusw_sib) ||
            ft_supported_lea_addr(rex, modrm, psubusw_sib)) {
            return &fast_templates[FT_PSUBUSW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xdc &&
        info->id == dt_X86_INS_PADDUSB &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int paddusb_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, paddusb_sib) ||
            ft_supported_lea_addr(rex, modrm, paddusb_sib)) {
            return &fast_templates[FT_PADDUSB_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xdd &&
        info->id == dt_X86_INS_PADDUSW &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int paddusw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, paddusw_sib) ||
            ft_supported_lea_addr(rex, modrm, paddusw_sib)) {
            return &fast_templates[FT_PADDUSW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f &&
        ((opcode1 == 0xec && info->id == dt_X86_INS_PADDSB) ||
         (opcode1 == 0xed && info->id == dt_X86_INS_PADDSW)) &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int padds_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, padds_sib) ||
            ft_supported_lea_addr(rex, modrm, padds_sib)) {
            return &fast_templates[opcode1 == 0xec ?
                                   FT_PADDSB_MMX_MMXM64 :
                                   FT_PADDSW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f &&
        ((opcode1 == 0xe0 && info->id == dt_X86_INS_PAVGB) ||
         (opcode1 == 0xe3 && info->id == dt_X86_INS_PAVGW)) &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int pavg_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pavg_sib) ||
            ft_supported_lea_addr(rex, modrm, pavg_sib)) {
            return &fast_templates[opcode1 == 0xe0 ?
                                   FT_PAVGB_MMX_MMXM64 :
                                   FT_PAVGW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f &&
        ((opcode1 == 0xdb && info->id == dt_X86_INS_PAND) ||
         (opcode1 == 0xdf && info->id == dt_X86_INS_PANDN)) &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int pand_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pand_sib) ||
            ft_supported_lea_addr(rex, modrm, pand_sib)) {
            return &fast_templates[opcode1 == 0xdb ?
                                   FT_PAND_MMX_MMXM64 :
                                   FT_PANDN_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xeb &&
        info->id == dt_X86_INS_POR &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int por_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, por_sib) ||
            ft_supported_lea_addr(rex, modrm, por_sib)) {
            return &fast_templates[FT_POR_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xef &&
        info->id == dt_X86_INS_PXOR &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int pxor_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pxor_sib) ||
            ft_supported_lea_addr(rex, modrm, pxor_sib)) {
            return &fast_templates[FT_PXOR_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f &&
        ((opcode1 == 0x63 && info->id == dt_X86_INS_PACKSSWB) ||
         (opcode1 == 0x67 && info->id == dt_X86_INS_PACKUSWB) ||
         (opcode1 == 0x6b && info->id == dt_X86_INS_PACKSSDW)) &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int pack_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pack_sib) ||
            ft_supported_lea_addr(rex, modrm, pack_sib)) {
            return opcode1 == 0x63 ?
                   &fast_templates[FT_PACKSSWB_MMX_MMXM64] :
                   opcode1 == 0x67 ?
                   &fast_templates[FT_PACKUSWB_MMX_MMXM64] :
                   &fast_templates[FT_PACKSSDW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xf5 &&
        info->id == dt_X86_INS_PMADDWD &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int pmaddwd_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pmaddwd_sib) ||
            ft_supported_lea_addr(rex, modrm, pmaddwd_sib)) {
            return &fast_templates[FT_PMADDWD_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xf4 &&
        info->id == dt_X86_INS_PMULUDQ &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int pmuludq_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pmuludq_sib) ||
            ft_supported_lea_addr(rex, modrm, pmuludq_sib)) {
            return &fast_templates[FT_PMULUDQ_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xee &&
        info->id == dt_X86_INS_PMAXSW &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int pmaxsw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pmaxsw_sib) ||
            ft_supported_lea_addr(rex, modrm, pmaxsw_sib)) {
            return &fast_templates[FT_PMAXSW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xea &&
        info->id == dt_X86_INS_PMINSW &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int pminsw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pminsw_sib) ||
            ft_supported_lea_addr(rex, modrm, pminsw_sib)) {
            return &fast_templates[FT_PMINSW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f &&
        ((opcode1 == 0xd4 && info->id == dt_X86_INS_PADDQ) ||
         (opcode1 == 0xfc && info->id == dt_X86_INS_PADDB) ||
         (opcode1 == 0xfe && info->id == dt_X86_INS_PADDD)) &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int padd_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, padd_sib) ||
            ft_supported_lea_addr(rex, modrm, padd_sib)) {
            return &fast_templates[opcode1 == 0xd4 ?
                                   FT_PADDQ_MMX_MMXM64 :
                                   opcode1 == 0xfc ?
                                   FT_PADDB_MMX_MMXM64 :
                                   FT_PADDD_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xfd &&
        info->id == dt_X86_INS_PADDW &&
        info->x86.prefix[0] == 0 && info->x86.prefix[2] == 0) {
        int paddw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, paddw_sib) ||
            ft_supported_lea_addr(rex, modrm, paddw_sib)) {
            return &fast_templates[FT_PADDW_MMX_MMXM64];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xd6 &&
        ft_modrm_mod(modrm) == 3 &&
        info->id == dt_X86_INS_MOVDQ2Q) {
        return &fast_templates[FT_MOVDQ2Q_MMX_XMM];
    }
    if (opcode0 == 0x0f && opcode1 == 0xd6 &&
        ft_modrm_mod(modrm) == 3 &&
        info->id == dt_X86_INS_MOVQ2DQ) {
        return &fast_templates[FT_MOVQ2DQ_XMM_MMX];
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        ((opcode1 == 0x38 && info->x86.opcode[2] == 0x41) ||
         opcode1 == 0x41) &&
        info->id == dt_X86_INS_PHMINPOSUW) {
        int phminposuw_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, phminposuw_sib) ||
            ft_supported_lea_addr(rex, modrm, phminposuw_sib)) {
            return &fast_templates[FT_PHMINPOSUW_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xc2 &&
        (info->id == dt_X86_INS_CMPPS ||
         info->id == dt_X86_INS_CMPPD ||
         info->id == dt_X86_INS_CMPSS ||
         info->id == dt_X86_INS_CMPSD)) {
        int cmp_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, cmp_sib) ||
            ft_supported_lea_addr(rex, modrm, cmp_sib)) {
            return &fast_templates[FT_CMP_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        ((opcode1 == 0x3a &&
          info->x86.opcode[2] >= 0x08 && info->x86.opcode[2] <= 0x0b) ||
         (opcode1 >= 0x08 && opcode1 <= 0x0b)) &&
        (info->id == dt_X86_INS_ROUNDPS ||
         info->id == dt_X86_INS_ROUNDPD ||
         info->id == dt_X86_INS_ROUNDSS ||
         info->id == dt_X86_INS_ROUNDSD)) {
        int round_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, round_sib) ||
            ft_supported_lea_addr(rex, modrm, round_sib)) {
            return &fast_templates[FT_ROUND_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        ((opcode1 == 0x3a &&
          (info->x86.opcode[2] == 0x40 || info->x86.opcode[2] == 0x41)) ||
         opcode1 == 0x40 || opcode1 == 0x41) &&
        (info->id == dt_X86_INS_DPPS || info->id == dt_X86_INS_DPPD)) {
        int dp_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, dp_sib) ||
            ft_supported_lea_addr(rex, modrm, dp_sib)) {
            return &fast_templates[FT_DP_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        ((opcode1 == 0x3a && info->x86.opcode[2] == 0x44) ||
         opcode1 == 0x44) &&
        info->id == dt_X86_INS_PCLMULQDQ) {
        int pclmul_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, pclmul_sib) ||
            ft_supported_lea_addr(rex, modrm, pclmul_sib)) {
            return &fast_templates[FT_PCLMULQDQ_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        opcode1 >= 0xdc && opcode1 <= 0xdf &&
        (info->id == dt_X86_INS_AESENC ||
         info->id == dt_X86_INS_AESENCLAST ||
         info->id == dt_X86_INS_AESDEC ||
         info->id == dt_X86_INS_AESDECLAST)) {
        int aes_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, aes_sib) ||
            ft_supported_lea_addr(rex, modrm, aes_sib)) {
            return &fast_templates[FT_AES_ROUND_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        opcode1 == 0xdb && info->id == dt_X86_INS_AESIMC) {
        int aes_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, aes_sib) ||
            ft_supported_lea_addr(rex, modrm, aes_sib)) {
            return &fast_templates[FT_AESIMC_XMM_XMMM];
        }
    }
    if (opcode0 == 0x0f && info->x86.prefix[2] == 0x66 &&
        opcode1 == 0xdf && info->id == dt_X86_INS_AESKEYGENASSIST) {
        int aes_sib = ft_ir1_sib_byte(info);

        if (ft_modrm_mod(modrm) == 3 ||
            ft_supported_base_disp_or_rip_addr(rex, modrm, aes_sib) ||
            ft_supported_lea_addr(rex, modrm, aes_sib)) {
            return &fast_templates[FT_AESKEYGEN_XMM_XMMM_IMM8];
        }
    }
    if (opcode0 == 0x0f && opcode1 == 0xae &&
        info->id == dt_X86_INS_STMXCSR &&
        ((modrm >> 3) & 7) == 3 && ft_modrm_mod(modrm) != 3 &&
        (ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_STMXCSR_M32];
    }
    if (opcode0 == 0x80 && ft_grp1_ext_supported((modrm >> 3) & 7) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return &fast_templates[FT_GRP1_RM8_IMM8];
    }
    if (opcode0 == 0x83 && ft_grp1_ext_supported((modrm >> 3) & 7) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        if (rex >= 0 && (rex & 8)) {
            return &fast_templates[FT_GRP1_RM64_IMM8];
        }
        if (info->x86.prefix[2] == 0x66) {
            return &fast_templates[FT_GRP1_RM16_IMM8];
        }
        return &fast_templates[FT_GRP1_RM32_IMM8];
    }
    if (opcode0 == 0x81 && ft_grp1_ext_supported((modrm >> 3) & 7) &&
        (ft_modrm_mod(modrm) == 3 ||
         ft_supported_base_disp_or_rip_addr(rex, modrm, sib) ||
         ft_supported_lea_addr(rex, modrm, sib))) {
        return (rex >= 0 && (rex & 8)) ?
               &fast_templates[FT_GRP1_RM64_IMM32] :
               &fast_templates[FT_GRP1_RM32_IMM32];
    }
    if (opcode0 == 0x83 && !(rex >= 0 && (rex & 8)) &&
        ft_modrm_mod(modrm) == 3 && ((modrm >> 3) & 7) == 5) {
        return &fast_templates[FT_SUB_R32_IMM8];
    }
    if (rex >= 0 && (rex & 8) && opcode0 >= 0xb8 && opcode0 <= 0xbf &&
        (len == 10 || (info->x86.prefix[2] == 0x66 && len == 11))) {
        return &fast_templates[FT_MOV_R64_IMM64];
    }
    if (!(rex >= 0 && (rex & 8)) && opcode0 >= 0xb8 && opcode0 <= 0xbf &&
        len == (rex >= 0 ? 6 : 5)) {
        return &fast_templates[FT_MOV_R32_IMM32];
    }
    if (opcode0 >= 0xb0 && opcode0 <= 0xb7 &&
        len == (rex >= 0 ? 3 : 2)) {
        return &fast_templates[FT_MOV_R8_IMM8];
    }
    if (info->x86.prefix[2] == 0x66 && opcode0 >= 0xb8 && opcode0 <= 0xbf &&
        len == (rex >= 0 ? 5 : 4)) {
        return &fast_templates[FT_MOV_R16_IMM16];
    }
    if (rex >= 0 && (rex & 8) && opcode0 == 0x81 &&
        ft_modrm_mod(modrm) == 3) {
        switch ((modrm >> 3) & 7) {
        case 0:
            return &fast_templates[FT_GRP1_RM64_IMM32];
        case 4:
            return &fast_templates[FT_GRP1_RM64_IMM32];
        case 5:
            return &fast_templates[FT_GRP1_RM64_IMM32];
        case 7:
            return &fast_templates[FT_CMP_RM64_IMM32];
        default:
            break;
        }
    }
    if (opcode0 == 0x68 && info->id == dt_X86_INS_PUSH) {
        return info->x86.prefix[2] == dt_X86_PREFIX_OPSIZE ?
               &fast_templates[FT_PUSH_IMM16] :
               &fast_templates[FT_PUSH_IMM32];
    }
    if (opcode0 == 0x6a) {
        return &fast_templates[FT_PUSH_IMM8];
    }
    if (opcode0 == 0xe3) {
        return &fast_templates[FT_JRCXZ_REL8];
    }
    if (opcode0 == 0xe2) {
        return &fast_templates[FT_LOOP_REL8];
    }
    if (opcode0 == 0xe1) {
        return &fast_templates[FT_LOOPE_REL8];
    }
    if (opcode0 == 0xe0) {
        return &fast_templates[FT_LOOPNE_REL8];
    }
    if (opcode0 >= 0x91 && opcode0 <= 0x97 &&
        len == (info->x86.rex ? 2 :
                opsize ? 2 : 1)) {
        return opsize ? &fast_templates[FT_XCHG_R16_AX] :
               (rex >= 0 && (rex & 8)) ? &fast_templates[FT_XCHG_R64_RAX] :
               &fast_templates[FT_XCHG_R32_EAX];
    }
    if (opcode0 == 0xe8 || opcode0 == 0xe9 || opcode0 == 0xeb) {
        return opcode0 == 0xe8 ? &fast_templates[FT_CALL_REL32] :
                                 &fast_templates[FT_JMP_REL32];
    }
    if (opcode0 >= 0x50 && opcode0 <= 0x57 &&
        len == (info->x86.rex ? 2 :
                opsize ? 2 : 1)) {
        return opsize ? &fast_templates[FT_PUSH_R16] :
               &fast_templates[FT_PUSH_R64];
    }
    if (opcode0 >= 0x58 && opcode0 <= 0x5f &&
        len == (info->x86.rex ? 2 :
                opsize ? 2 : 1)) {
        return opsize ? &fast_templates[FT_POP_R16] :
               &fast_templates[FT_POP_R64];
    }

    for (size_t i = 0; i < ARRAY_SIZE(fast_templates); i++) {
        const FastTemplateDesc *tmpl = &fast_templates[i];
        if (tmpl->kind != FT_UNSUPPORTED &&
            len == tmpl->len &&
            info->x86.prefix[0] == tmpl->prefix0 &&
            info->x86.prefix[2] == tmpl->prefix2 &&
            info->x86.opcode[0] == tmpl->opcode0 &&
            info->x86.opcode[1] == tmpl->opcode1 &&
            !(fast_template_x87_memory_kind(tmpl->kind) &&
              ft_modrm_mod(info->x86.modrm) == 3) &&
            fast_template_raw_matches(tmpl, info)) {
            return tmpl;
        }
    }
    return NULL;
}
