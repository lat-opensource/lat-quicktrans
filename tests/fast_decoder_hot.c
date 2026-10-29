/*
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fast_decoder.h"

static int failures;

#define CHECK(condition, message)                                             \
    do {                                                                      \
        if (!(condition)) {                                                   \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, message);     \
            failures++;                                                       \
        }                                                                     \
    } while (0)

static FastDecodedFT decode(const uint8_t *code, size_t size, uint64_t pc,
                            int *matched)
{
    FastDecodedFT decoded;

    *matched = fast_decoder_get_ft(code, size, pc, &decoded, 1);
    return decoded;
}

static FastDecodedFT decode32(const uint8_t *code, size_t size, uint64_t pc,
                              int *matched)
{
    FastDecodedFT decoded;

    *matched = fast_decoder_get_ft(code, size, pc, &decoded, 0);
    return decoded;
}

/* The absence of 0x67 does not imply 64-bit addressing in an ELF32 TB. */
static void test_default_32bit_address_size(void)
{
    static const uint8_t absolute_store[] = {
        0xc7, 0x05, 0x00, 0x00, 0x08, 0x60, 0x78, 0x56, 0x34, 0x12
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode32(absolute_store, sizeof(absolute_store),
                       0x61000005, &matched);
    CHECK(matched, "ELF32 absolute MOV must decode");
    CHECK(decoded.fields.addr32, "ELF32 default address size must be 32");
    CHECK(decoded.fields.disp == 0x60080000,
          "ELF32 absolute MOV displacement changed");
    decoded = decode(absolute_store, sizeof(absolute_store),
                     0x61000005, &matched);
    CHECK(matched, "ELF64 RIP-relative MOV must decode");
    CHECK(!decoded.fields.addr32, "ELF64 default address size must be 64");
}

static void test_hot_gpr(void)
{
    static const uint8_t mov64[] = { 0x48, 0x89, 0xd8 };
    static const uint8_t alu64[] = { 0x48, 0x01, 0xd8 };
    static const uint8_t sib_disp[] = { 0x48, 0x8b, 0x44, 0x8d, 0x7f };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(mov64, sizeof(mov64), 0x1000, &matched);
    CHECK(matched, "REX MOV must decode");
    CHECK(decoded.fields.kind == FT_MOV_RM64_R64, "wrong MOV template");
    CHECK(decoded.fields.size == sizeof(mov64), "wrong MOV size");
    CHECK(decoded.fields.rex == 0x48, "wrong MOV REX");

    decoded = decode(alu64, sizeof(alu64), 0x1000, &matched);
    CHECK(matched, "REX ALU must decode");
    CHECK(decoded.fields.kind == FT_ALU_RM_R, "wrong ALU template");
    CHECK(decoded.fields.alu_op == FT_ALU_ADD, "wrong ALU operation");
    CHECK(decoded.fields.alu_width == 64, "wrong ALU width");

    decoded = decode(sib_disp, sizeof(sib_disp), 0x1000, &matched);
    CHECK(matched, "SIB+disp MOV must decode");
    CHECK(decoded.fields.kind == FT_MOV_R64_RM64, "wrong SIB MOV template");
    CHECK(decoded.fields.sib == 0x8d, "wrong SIB byte");
    CHECK(decoded.fields.disp == 0x7f, "wrong disp8");
}

static void test_mov_imm8_rex_registers(void)
{
    static const dt_x86_reg legacy_regs[] = {
        dt_X86_REG_AH, dt_X86_REG_CH, dt_X86_REG_DH, dt_X86_REG_BH,
    };
    static const dt_x86_reg rex_regs[] = {
        dt_X86_REG_SPL, dt_X86_REG_BPL, dt_X86_REG_SIL, dt_X86_REG_DIL,
    };
    size_t i;

    for (i = 0; i < sizeof(legacy_regs) / sizeof(legacy_regs[0]); ++i) {
        uint8_t legacy_code[] = { (uint8_t)(0xb4 + i), 0x01 };
        uint8_t rex_code[] = { 0x40, (uint8_t)(0xb4 + i), 0x01 };
        struct la_dt_insn info = { 0 };

        CHECK(fast_decoder_get_primary(legacy_code, sizeof(legacy_code),
                                       0x1000, &info, 1),
              "legacy MOV r8, imm8 must decode");
        CHECK(info.id == dt_X86_INS_MOV,
              "legacy MOV r8, imm8 has wrong id");
        CHECK(info.x86.operands[0].reg == legacy_regs[i],
              "legacy MOV r8, imm8 selected wrong register");

        info = (struct la_dt_insn) { 0 };
        CHECK(fast_decoder_get_primary(rex_code, sizeof(rex_code),
                                       0x1000, &info, 1),
              "REX MOV r8, imm8 must decode");
        CHECK(info.id == dt_X86_INS_MOV,
              "REX MOV r8, imm8 has wrong id");
        CHECK(info.x86.operands[0].reg == rex_regs[i],
              "REX MOV r8, imm8 selected wrong register");
    }
}

static void test_mov_moffs(void)
{
    static const uint8_t load8[] = {
        0xa0, 0x20, 0x5c, 0x42, 0x00, 0x58, 0x00, 0x00, 0x00,
    };
    static const uint8_t load16[] = {
        0x66, 0xa1, 0x20, 0x5c, 0x42, 0x00, 0x58, 0x00, 0x00, 0x00,
    };
    static const uint8_t load32[] = {
        0xa1, 0x20, 0x5c, 0x42, 0x00, 0x58, 0x00, 0x00, 0x00,
    };
    static const uint8_t load64[] = {
        0x48, 0xa1, 0x20, 0x5c, 0x42, 0x00, 0x58, 0x00, 0x00, 0x00,
    };
    static const uint8_t store8[] = {
        0xa2, 0x20, 0x5c, 0x42, 0x00, 0x58, 0x00, 0x00, 0x00,
    };
    static const uint8_t store64[] = {
        0x48, 0xa3, 0x20, 0x5c, 0x42, 0x00, 0x58, 0x00, 0x00, 0x00,
    };
    static const uint8_t addr32[] = {
        0x67, 0x48, 0xa1, 0x20, 0x5c, 0x42, 0x00,
    };
    static const uint8_t truncated[] = {
        0x48, 0xa1, 0x20, 0x5c, 0x42, 0x00,
    };
    static const struct {
        const uint8_t *code;
        size_t size;
        FastTemplateKind kind;
        int width;
    } cases[] = {
        { load8, sizeof(load8), FT_MOV_ACC_MOFFS, 8 },
        { load16, sizeof(load16), FT_MOV_ACC_MOFFS, 16 },
        { load32, sizeof(load32), FT_MOV_ACC_MOFFS, 32 },
        { load64, sizeof(load64), FT_MOV_ACC_MOFFS, 64 },
        { store8, sizeof(store8), FT_MOV_MOFFS_ACC, 8 },
        { store64, sizeof(store64), FT_MOV_MOFFS_ACC, 64 },
        { addr32, sizeof(addr32), FT_MOV_ACC_MOFFS, 64 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        FastDecodedFT decoded;
        int matched;

        decoded = decode(cases[i].code, cases[i].size, 0x1000, &matched);
        CHECK(matched, "MOV moffs must decode");
        CHECK(decoded.fields.kind == cases[i].kind,
              "MOV moffs selected wrong template");
        CHECK(decoded.fields.id == dt_X86_INS_MOV,
              "MOV moffs selected wrong instruction id");
        CHECK(decoded.fields.alu_width == cases[i].width,
              "MOV moffs selected wrong operand width");
        CHECK(decoded.fields.size == cases[i].size,
              "MOV moffs consumed wrong size");
        CHECK(decoded.fields.imm64 == UINT64_C(0x5800425c20) ||
              decoded.fields.imm64 == UINT64_C(0x425c20),
              "MOV moffs decoded wrong absolute address");
    }

    {
        int matched;

        decode(truncated, sizeof(truncated), 0x1000, &matched);
        CHECK(!matched, "truncated MOV moffs64 must reject");
    }
}

static void test_hot_control(void)
{
    static const uint8_t jcc[] = { 0x75, 0xfe };
    static const uint8_t prefixed_jcc[] = { 0x3e, 0x75, 0x5f };
    static const uint8_t prefixed_near_jcc[] = {
        0x3e, 0x0f, 0x85, 0xf9, 0xff, 0xff, 0xff,
    };
    static const uint8_t call[] = { 0xe8, 0x01, 0x00, 0x00, 0x00 };
    static const uint8_t ret[] = { 0xc3 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(jcc, sizeof(jcc), 0x1000, &matched);
    CHECK(matched, "short JCC must decode");
    CHECK(decoded.fields.kind == FT_JCC_REL, "wrong JCC template");
    CHECK(decoded.fields.imm64 == 0x1000, "wrong JCC target");
    CHECK(decoded.is_tb_ending, "JCC must end the TB");

    decoded = decode(prefixed_jcc, sizeof(prefixed_jcc), 0x1000, &matched);
    CHECK(matched, "prefixed short JCC must decode");
    CHECK(decoded.fields.size == sizeof(prefixed_jcc),
          "prefixed short JCC consumed wrong size");
    CHECK(decoded.fields.imm64 == 0x1062,
          "wrong prefixed short JCC target");

    decoded = decode(prefixed_near_jcc, sizeof(prefixed_near_jcc),
                     0x1000, &matched);
    CHECK(matched, "prefixed near JCC must decode");
    CHECK(decoded.fields.size == sizeof(prefixed_near_jcc),
          "prefixed near JCC consumed wrong size");
    CHECK(decoded.fields.imm64 == 0x1000,
          "wrong prefixed near JCC target");

    decoded = decode(call, sizeof(call), 0x2000, &matched);
    CHECK(matched, "direct CALL must decode");
    CHECK(decoded.fields.kind == FT_CALL_REL32, "wrong CALL template");
    CHECK(decoded.fields.imm == 1, "wrong CALL displacement");
    CHECK(decoded.is_tb_ending, "CALL must end the TB");

    decoded = decode(ret, sizeof(ret), 0x3000, &matched);
    CHECK(matched, "RET must decode");
    CHECK(decoded.fields.kind == FT_RET, "wrong RET template");
    CHECK(decoded.is_tb_ending, "RET must end the TB");
}

static void test_legacy_control_helpers(void)
{
    static const uint8_t in_dx[] = { 0xec };
    static const uint8_t out_imm[] = { 0xe6, 0x80 };
    static const uint8_t int_imm[] = { 0xcd, 0x81 };
    static const uint8_t int3[] = { 0xcc };
    static const uint8_t iret[] = { 0x66, 0xcf };
    static const uint8_t iretd[] = { 0xcf };
    static const uint8_t iretq[] = { 0x48, 0xcf };
    static const uint8_t ljmp[] = {
        0x48, 0xff, 0x2d, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t retfq[] = { 0x48, 0xcb };
    static const uint8_t retfq_imm[] = { 0x48, 0xca, 0x34, 0x12 };
    static const uint8_t truncated_out[] = { 0xe6 };
    static const uint8_t truncated_int[] = { 0xcd };
    static const uint8_t truncated_ljmp[] = { 0x48, 0xff };
    static const uint8_t near_ljmp_reg[] = { 0x48, 0xff, 0xe8 };
    static const uint8_t non64_retf[] = { 0xcb };
    static const struct {
        const uint8_t *code;
        size_t size;
        FastTemplateKind kind;
        int id;
    } cases[] = {
        { in_dx, sizeof(in_dx), FT_IO, dt_X86_INS_IN },
        { out_imm, sizeof(out_imm), FT_IO, dt_X86_INS_OUT },
        { int_imm, sizeof(int_imm), FT_HELPER_INT, dt_X86_INS_INT },
        { int3, sizeof(int3), FT_HELPER_INT3, dt_X86_INS_INT3 },
        { iret, sizeof(iret), FT_HELPER_IRET, dt_X86_INS_IRET },
        { iretd, sizeof(iretd), FT_HELPER_IRETD, dt_X86_INS_IRETD },
        { iretq, sizeof(iretq), FT_HELPER_IRETQ, dt_X86_INS_IRETQ },
        { ljmp, sizeof(ljmp), FT_HELPER_LJMP, dt_X86_INS_LJMP },
        { retfq, sizeof(retfq), FT_HELPER_RETFQ, dt_X86_INS_RETFQ },
        { retfq_imm, sizeof(retfq_imm), FT_HELPER_RETFQ,
          dt_X86_INS_RETFQ },
    };
    FastDecodedFT decoded;
    int matched;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        decoded = decode(cases[i].code, cases[i].size, 0x1000, &matched);
        CHECK(matched, "legacy control instruction must decode");
        CHECK(decoded.fields.kind == cases[i].kind,
              "legacy control instruction selected wrong template");
        CHECK(decoded.fields.id == cases[i].id,
              "legacy control instruction selected wrong id");
        CHECK(decoded.fields.size == cases[i].size,
              "legacy control instruction consumed wrong size");
        CHECK(decoded.is_tb_ending == (cases[i].kind != FT_IO),
              "legacy control instruction has wrong TB ending state");
    }

    decoded = decode(int_imm, sizeof(int_imm), 0x1000, &matched);
    CHECK(decoded.fields.imm == 0x81, "INT immediate must be preserved");
    decoded = decode(retfq_imm, sizeof(retfq_imm), 0x1000, &matched);
    CHECK(decoded.fields.imm == 0x1234, "RETFQ addend must be preserved");
    decoded = decode(ljmp, sizeof(ljmp), 0x1000, &matched);
    CHECK(decoded.fields.modrm_reg == 5, "LJMP must preserve ModRM extension");
    CHECK(decoded.fields.disp == 0x12345678,
          "LJMP must preserve displacement");

    decode(truncated_out, sizeof(truncated_out), 0x1000, &matched);
    CHECK(!matched, "truncated OUT immediate must reject");
    decode(truncated_int, sizeof(truncated_int), 0x1000, &matched);
    CHECK(!matched, "truncated INT must reject");
    decode(truncated_ljmp, sizeof(truncated_ljmp), 0x1000, &matched);
    CHECK(!matched, "truncated LJMP must reject");
    decode(near_ljmp_reg, sizeof(near_ljmp_reg), 0x1000, &matched);
    CHECK(!matched, "register far JMP must reject");
    CHECK(fast_decoder_get_ft(non64_retf, sizeof(non64_retf), 0x1000,
                              &decoded, 0),
          "32-bit RETF must decode");
    CHECK(decoded.fields.kind == FT_HELPER_RETFQ &&
          decoded.fields.id == dt_X86_INS_RETF,
          "32-bit RETF must use the protected return helper");
}

static void test_legacy_32bit_instructions(void)
{
    static const uint8_t aaa[] = { 0x37 };
    static const uint8_t aad[] = { 0xd5, 0x0a };
    static const uint8_t aam[] = { 0xd4, 0x0a };
    static const uint8_t aas[] = { 0x3f };
    static const uint8_t daa[] = { 0x27 };
    static const uint8_t das[] = { 0x2f };
    static const uint8_t salc[] = { 0xd6 };
    static const uint8_t arpl[] = { 0x63, 0xd8 };
    static const uint8_t into_insn[] = { 0xce };
    static const uint8_t pushal[] = { 0x60 };
    static const uint8_t popal[] = { 0x61 };
    static const uint8_t pushaw[] = { 0x66, 0x60 };
    static const uint8_t popaw[] = { 0x66, 0x61 };
    static const uint8_t pushfd[] = { 0x9c };
    static const uint8_t popfd[] = { 0x9d };
    static const uint8_t pushf[] = { 0x66, 0x9c };
    static const uint8_t popf[] = { 0x66, 0x9d };
    static const uint8_t push_eax[] = { 0x50 };
    static const uint8_t pop_eax[] = { 0x58 };
    static const uint8_t push_imm32[] = { 0x68, 1, 2, 3, 4 };
    static const uint8_t push_imm8[] = { 0x6a, 0x80 };
    static const uint8_t push_rm32[] = { 0xff, 0x30 };
    static const uint8_t pop_rm32[] = { 0x8f, 0x00 };
    static const uint8_t lds[] = { 0xc5, 0x00 };
    static const uint8_t les[] = { 0xc4, 0x00 };
    static const uint8_t leave32[] = { 0xc9 };
    static const uint8_t lss[] = { 0x0f, 0xb2, 0x00 };
    static const uint8_t bound[] = { 0x62, 0x00 };
    static const uint8_t fsetpm[] = { 0xdb, 0xe4 };
    static const uint8_t jecxz[] = { 0xe3, 0x00 };
    static const uint8_t jcxz[] = { 0x67, 0xe3, 0x00 };
    static const uint8_t ljmp[] = { 0xea, 1, 2, 3, 4, 0x23, 0 };
    static const uint8_t retf[] = { 0xcb };
    static const struct {
        const uint8_t *code;
        size_t size;
        FastTemplateKind kind;
        int id;
        int width;
    } cases[] = {
        { aaa, sizeof(aaa), FT_HELPER_BCD, dt_X86_INS_AAA, 0 },
        { aad, sizeof(aad), FT_HELPER_BCD, dt_X86_INS_AAD, 0 },
        { aam, sizeof(aam), FT_HELPER_BCD, dt_X86_INS_AAM, 0 },
        { aas, sizeof(aas), FT_HELPER_BCD, dt_X86_INS_AAS, 0 },
        { daa, sizeof(daa), FT_HELPER_BCD, dt_X86_INS_DAA, 0 },
        { das, sizeof(das), FT_HELPER_BCD, dt_X86_INS_DAS, 0 },
        { salc, sizeof(salc), FT_SALC, dt_X86_INS_SALC, 0 },
        { arpl, sizeof(arpl), FT_ARPL, dt_X86_INS_ARPL, 0 },
        { into_insn, sizeof(into_insn), FT_HELPER_INTO, dt_X86_INS_INTO, 0 },
        { pushal, sizeof(pushal), FT_PUSHA, dt_X86_INS_PUSHAL, 32 },
        { popal, sizeof(popal), FT_POPA, dt_X86_INS_POPAL, 32 },
        { pushaw, sizeof(pushaw), FT_PUSHA, dt_X86_INS_PUSHAW, 16 },
        { popaw, sizeof(popaw), FT_POPA, dt_X86_INS_POPAW, 16 },
        { pushfd, sizeof(pushfd), FT_PUSHFQ, dt_X86_INS_PUSHFD, 32 },
        { popfd, sizeof(popfd), FT_POPFQ, dt_X86_INS_POPFD, 32 },
        { pushf, sizeof(pushf), FT_PUSHFQ, dt_X86_INS_PUSHF, 16 },
        { popf, sizeof(popf), FT_POPFQ, dt_X86_INS_POPF, 16 },
        { push_eax, sizeof(push_eax), FT_PUSH_R64, dt_X86_INS_PUSH, 32 },
        { pop_eax, sizeof(pop_eax), FT_POP_R64, dt_X86_INS_POP, 32 },
        { push_imm32, sizeof(push_imm32), FT_PUSH_IMM32, dt_X86_INS_PUSH, 32 },
        { push_imm8, sizeof(push_imm8), FT_PUSH_IMM8, dt_X86_INS_PUSH, 32 },
        { push_rm32, sizeof(push_rm32), FT_PUSH_RM64, dt_X86_INS_PUSH, 32 },
        { pop_rm32, sizeof(pop_rm32), FT_POP_RM64, dt_X86_INS_POP, 32 },
        { lds, sizeof(lds), FT_LDS, dt_X86_INS_LDS, 32 },
        { les, sizeof(les), FT_LES, dt_X86_INS_LES, 32 },
        { lss, sizeof(lss), FT_LSS, dt_X86_INS_LSS, 0 },
        { leave32, sizeof(leave32), FT_LEAVE, dt_X86_INS_LEAVE, 32 },
        { bound, sizeof(bound), FT_NOP_MULTI, dt_X86_INS_BOUND, 0 },
        { fsetpm, sizeof(fsetpm), FT_NOP_MULTI, dt_X86_INS_FSETPM, 0 },
        { jecxz, sizeof(jecxz), FT_JRCXZ_REL8, dt_X86_INS_JECXZ, 0 },
        { jcxz, sizeof(jcxz), FT_JRCXZ_REL8, dt_X86_INS_JCXZ, 0 },
        { ljmp, sizeof(ljmp), FT_HELPER_LJMP, dt_X86_INS_LJMP, 32 },
        { retf, sizeof(retf), FT_HELPER_RETFQ, dt_X86_INS_RETF, 32 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        FastDecodedFT decoded;
        int matched;

        decoded = decode32(cases[i].code, cases[i].size, 0x1000, &matched);
        if (!matched || decoded.fields.kind != cases[i].kind ||
            decoded.fields.id != cases[i].id) {
            fprintf(stderr, "legacy32 case %zu: matched=%d kind=%d/%d id=%d/%d\n",
                    i, matched, decoded.fields.kind, cases[i].kind,
                    decoded.fields.id, cases[i].id);
        }
        CHECK(matched, "legacy 32-bit instruction must decode");
        if (cases[i].kind == FT_LDS || cases[i].kind == FT_LES ||
            cases[i].kind == FT_LSS) {
            CHECK(decoded.tmpl->kind == cases[i].kind,
                  "far pointer descriptor must preserve terminal metadata");
        }
        CHECK(decoded.fields.kind == cases[i].kind,
              "legacy 32-bit instruction selected wrong template");
        CHECK(decoded.fields.id == cases[i].id,
              "legacy 32-bit instruction selected wrong id");
        CHECK(decoded.fields.size == cases[i].size,
              "legacy 32-bit instruction consumed wrong size");
        if (cases[i].width) {
            CHECK(decoded.fields.alu_width == cases[i].width,
                  "legacy 32-bit instruction selected wrong width");
        }
    }
}

static void test_bndmov(void)
{
    static const uint8_t reg_load[] = { 0x66, 0x0f, 0x1a, 0xc1 };
    static const uint8_t mem_load[] = {
        0x66, 0x0f, 0x1a, 0x54, 0x88, 0x20,
    };
    static const uint8_t mem_store[] = {
        0x66, 0x0f, 0x1b, 0x9d, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t missing_prefix[] = { 0x0f, 0x1a, 0xc1 };
    static const uint8_t extended_bnd[] = { 0x66, 0x44, 0x0f, 0x1a, 0xc1 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg_load, sizeof(reg_load), 0x1000, &matched);
    CHECK(matched, "BNDMOV register form must decode");
    CHECK(decoded.fields.kind == FT_BNDMOV, "wrong BNDMOV template");
    CHECK(decoded.fields.id == dt_X86_INS_BNDMOV,
          "wrong BNDMOV instruction id");
    CHECK(decoded.fields.size == sizeof(reg_load),
          "wrong BNDMOV register size");

    decoded = decode(mem_load, sizeof(mem_load), 0x1000, &matched);
    CHECK(matched, "BNDMOV memory load must decode");
    CHECK(decoded.fields.size == sizeof(mem_load),
          "wrong BNDMOV memory-load size");
    CHECK(decoded.fields.sib == 0x88, "wrong BNDMOV SIB");
    CHECK(decoded.fields.disp == 0x20, "wrong BNDMOV disp8");

    decoded = decode(mem_store, sizeof(mem_store), 0x1000, &matched);
    CHECK(matched, "BNDMOV memory store must decode");
    CHECK(decoded.fields.size == sizeof(mem_store),
          "wrong BNDMOV memory-store size");
    CHECK(decoded.fields.disp == 0x12345678, "wrong BNDMOV disp32");

    decoded = decode(missing_prefix, sizeof(missing_prefix), 0x1000,
                     &matched);
    CHECK(!matched, "BNDMOV without 66 prefix must reject");
    decoded = decode(extended_bnd, sizeof(extended_bnd), 0x1000, &matched);
    CHECK(!matched, "BNDMOV with REX.R must reject");
}

static void test_prefetch(void)
{
    static const uint8_t base[] = { 0x0f, 0x0d, 0x00 };
    static const uint8_t sib_disp[] = { 0x0f, 0x0d, 0x44, 0x88, 0x20 };
    static const uint8_t prefetchw[] = { 0x0f, 0x0d, 0x08 };
    static const uint8_t register_form[] = { 0x0f, 0x0d, 0xc0 };
    static const uint8_t opsize_prefix[] = { 0x66, 0x0f, 0x0d, 0x00 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(base, sizeof(base), 0x1000, &matched);
    CHECK(matched, "PREFETCH base form must decode");
    CHECK(decoded.fields.kind == FT_PREFETCH, "wrong PREFETCH template");
    CHECK(decoded.fields.id == dt_X86_INS_PREFETCH,
          "wrong PREFETCH instruction id");

    decoded = decode(sib_disp, sizeof(sib_disp), 0x1000, &matched);
    CHECK(matched, "PREFETCH SIB+disp form must decode");
    CHECK(decoded.fields.size == sizeof(sib_disp), "wrong PREFETCH size");
    CHECK(decoded.fields.sib == 0x88, "wrong PREFETCH SIB");
    CHECK(decoded.fields.disp == 0x20, "wrong PREFETCH displacement");

    decoded = decode(prefetchw, sizeof(prefetchw), 0x1000, &matched);
    CHECK(matched, "PREFETCHW must remain supported");
    CHECK(decoded.fields.kind == FT_PREFETCHW,
          "PREFETCHW selected wrong template");

    decoded = decode(register_form, sizeof(register_form), 0x1000, &matched);
    CHECK(!matched, "PREFETCH register form must reject");
    decoded = decode(opsize_prefix, sizeof(opsize_prefix), 0x1000, &matched);
    CHECK(!matched, "PREFETCH with 66 prefix must reject");
}

static void test_legacy_nop_instructions(void)
{
    static const uint8_t lcall[] = {
        0x9a, 0x78, 0x56, 0x34, 0x12, 0x33, 0x00,
    };
    static const uint8_t int1[] = { 0xf1 };
    static const uint8_t cli[] = { 0xfa };
    static const uint8_t sti[] = { 0xfb };
    static const uint8_t xgetbv[] = { 0x0f, 0x01, 0xd0 };
    static const uint8_t rdtscp[] = { 0x0f, 0x01, 0xf9 };
    static const uint8_t monitor[] = { 0x0f, 0x01, 0xc8 };
    static const uint8_t truncated_lcall[] = { 0x9a, 0, 0, 0 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(int1, sizeof(int1), 0x1000, &matched);
    CHECK(matched && decoded.fields.kind == FT_HELPER_UD2 &&
          decoded.fields.id == dt_X86_INS_INT1 && decoded.is_tb_ending,
          "INT1 must raise the legacy-path illegal-instruction exception");
    decoded = decode(cli, sizeof(cli), 0x1000, &matched);
    CHECK(matched && decoded.fields.kind == FT_HELPER_GPF &&
          decoded.fields.id == dt_X86_INS_CLI && decoded.is_tb_ending,
          "CLI must raise #GP in the user-mode test context");
    decoded = decode(sti, sizeof(sti), 0x1000, &matched);
    CHECK(matched && decoded.fields.kind == FT_HELPER_GPF &&
          decoded.fields.id == dt_X86_INS_STI && decoded.is_tb_ending,
          "STI must raise #GP in the user-mode test context");

    CHECK(fast_decoder_get_ft(lcall, sizeof(lcall), 0x1000,
                              &decoded, 0),
          "32-bit immediate LCALL must decode");
    CHECK(decoded.fields.kind == FT_HELPER_LCALL &&
          decoded.fields.id == dt_X86_INS_LCALL && decoded.is_tb_ending,
          "LCALL must use a terminal helper template");
    CHECK(decoded.fields.imm64 == 0x12345678 && decoded.fields.imm == 0x33,
          "LCALL offset and selector must be preserved");

    decode(truncated_lcall, sizeof(truncated_lcall), 0x1000, &matched);
    CHECK(!matched, "truncated LCALL must reject");
    decoded = decode(xgetbv, sizeof(xgetbv), 0x1000, &matched);
    CHECK(matched && decoded.fields.kind == FT_XGETBV,
          "SIDT decoding must not shadow XGETBV");
    decoded = decode(rdtscp, sizeof(rdtscp), 0x1000, &matched);
    CHECK(matched && decoded.fields.kind == FT_RDTSCP,
          "SIDT decoding must not shadow RDTSCP");
    decoded = decode(monitor, sizeof(monitor), 0x1000, &matched);
    CHECK(!matched || decoded.fields.id != dt_X86_INS_SIDT,
          "SIDT decoding must not shadow MONITOR");
}

static void test_string_io(void)
{
    static const uint8_t insb[] = { 0x6c };
    static const uint8_t insw[] = { 0x66, 0x6d };
    static const uint8_t insd[] = { 0x6d };
    static const uint8_t outsb[] = { 0x6e };
    static const uint8_t outsw[] = { 0x66, 0x6f };
    static const uint8_t outsd[] = { 0x6f };
    static const uint8_t rep_insd_addr32[] = { 0x67, 0xf3, 0x6d };
    static const struct {
        const uint8_t *code;
        size_t size;
        int id;
    } cases[] = {
        { insb, sizeof(insb), dt_X86_INS_INSB },
        { insw, sizeof(insw), dt_X86_INS_INSW },
        { insd, sizeof(insd), dt_X86_INS_INSD },
        { outsb, sizeof(outsb), dt_X86_INS_OUTSB },
        { outsw, sizeof(outsw), dt_X86_INS_OUTSW },
        { outsd, sizeof(outsd), dt_X86_INS_OUTSD },
    };
    FastDecodedFT decoded;
    int matched;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        decoded = decode(cases[i].code, cases[i].size, 0x1000, &matched);
        CHECK(matched, "string I/O instruction must decode");
        CHECK(decoded.fields.kind == FT_STRING_IO,
              "string I/O instruction selected wrong template");
        CHECK(decoded.fields.id == cases[i].id,
              "string I/O instruction selected wrong id");
        CHECK(decoded.fields.size == cases[i].size,
              "string I/O instruction consumed wrong size");
        CHECK(!decoded.is_tb_ending,
              "string I/O instruction must not end the TB");
    }

    decoded = decode(rep_insd_addr32, sizeof(rep_insd_addr32),
                     0x1000, &matched);
    CHECK(matched && decoded.fields.kind == FT_STRING_IO,
          "REP INSD with addr32 must decode");
    CHECK(decoded.fields.prefix0 == dt_X86_PREFIX_REP,
          "REP INSD must retain the REP prefix");
    CHECK(decoded.fields.addr32,
          "REP INSD must retain the address-size prefix");
}

static void test_xsetbv(void)
{
    static const uint8_t xsetbv[] = { 0x0f, 0x01, 0xd1 };
    static const uint8_t prefixed[] = { 0x66, 0x0f, 0x01, 0xd1 };
    static const uint8_t rex[] = { 0x48, 0x0f, 0x01, 0xd1 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(xsetbv, sizeof(xsetbv), 0x30000, &matched);
    CHECK(matched, "XSETBV must decode");
    CHECK(decoded.fields.kind == FT_XSETBV, "wrong XSETBV template");
    CHECK(decoded.fields.id == dt_X86_INS_XSETBV,
          "wrong XSETBV instruction id");
    CHECK(decoded.is_tb_ending, "XSETBV must end the translation block");

    (void)decode(prefixed, sizeof(prefixed), 0x30000, &matched);
    CHECK(!matched, "XSETBV operand-size prefix must reject");
    (void)decode(rex, sizeof(rex), 0x30000, &matched);
    CHECK(!matched, "XSETBV REX prefix must reject");
}

static void test_ud0(void)
{
    static const uint8_t reg_form[] = { 0x0f, 0xff, 0xc1 };
    static const uint8_t rex_reg_form[] = { 0x45, 0x0f, 0xff, 0xc1 };
    static const uint8_t mem_form[] = {
        0x0f, 0xff, 0x84, 0x88, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t truncated[] = { 0x0f, 0xff };
    static const uint8_t opsize_prefix[] = { 0x66, 0x0f, 0xff, 0xc1 };
    static const uint8_t rex_w[] = { 0x48, 0x0f, 0xff, 0xc1 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg_form, sizeof(reg_form), 0x1000, &matched);
    CHECK(matched, "UD0 register form must decode");
    CHECK(decoded.fields.kind == FT_HELPER_UD0, "wrong UD0 template");
    CHECK(decoded.fields.id == dt_X86_INS_UD0, "wrong UD0 instruction id");
    CHECK(decoded.fields.size == sizeof(reg_form), "wrong UD0 register size");
    CHECK(decoded.is_tb_ending, "UD0 must end the TB");

    decoded = decode(rex_reg_form, sizeof(rex_reg_form), 0x1000, &matched);
    CHECK(matched, "UD0 REX register form must decode");
    CHECK(decoded.fields.rex == 0x45, "wrong UD0 REX byte");

    decoded = decode(mem_form, sizeof(mem_form), 0x1000, &matched);
    CHECK(matched, "UD0 memory form must decode");
    CHECK(decoded.fields.kind == FT_HELPER_UD0, "wrong UD0 memory template");
    CHECK(decoded.fields.sib == 0x88, "wrong UD0 SIB byte");
    CHECK(decoded.fields.disp == 0x12345678, "wrong UD0 displacement");
    CHECK(decoded.fields.size == sizeof(mem_form), "wrong UD0 memory size");

    decode(truncated, sizeof(truncated), 0x1000, &matched);
    CHECK(!matched, "truncated UD0 must reject");
    decode(opsize_prefix, sizeof(opsize_prefix), 0x1000, &matched);
    CHECK(!matched, "operand-size-prefixed UD0 must reject");
    decode(rex_w, sizeof(rex_w), 0x1000, &matched);
    CHECK(!matched, "REX.W UD0 must reject");
}

static void test_ud1(void)
{
    static const uint8_t reg_form[] = { 0x0f, 0xb9, 0xc1 };
    static const uint8_t rex_reg_form[] = { 0x45, 0x0f, 0xb9, 0xc1 };
    static const uint8_t mem_form[] = {
        0x0f, 0xb9, 0x84, 0x88, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t truncated[] = { 0x0f, 0xb9 };
    static const uint8_t opsize_prefix[] = { 0x66, 0x0f, 0xb9, 0xc1 };
    static const uint8_t rex_w[] = { 0x48, 0x0f, 0xb9, 0xc1 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg_form, sizeof(reg_form), 0x1000, &matched);
    CHECK(matched, "UD1 register form must decode");
    CHECK(decoded.fields.kind == FT_HELPER_UD1, "wrong UD1 template");
    CHECK(decoded.fields.id == dt_X86_INS_UD1, "wrong UD1 instruction id");
    CHECK(decoded.fields.size == sizeof(reg_form), "wrong UD1 register size");
    CHECK(decoded.is_tb_ending, "UD1 must end the TB");

    decoded = decode(rex_reg_form, sizeof(rex_reg_form), 0x1000, &matched);
    CHECK(matched, "UD1 REX register form must decode");
    CHECK(decoded.fields.rex == 0x45, "wrong UD1 REX byte");

    decoded = decode(mem_form, sizeof(mem_form), 0x1000, &matched);
    CHECK(matched, "UD1 memory form must decode");
    CHECK(decoded.fields.kind == FT_HELPER_UD1, "wrong UD1 memory template");
    CHECK(decoded.fields.sib == 0x88, "wrong UD1 SIB byte");
    CHECK(decoded.fields.disp == 0x12345678, "wrong UD1 displacement");
    CHECK(decoded.fields.size == sizeof(mem_form), "wrong UD1 memory size");

    decode(truncated, sizeof(truncated), 0x1000, &matched);
    CHECK(!matched, "truncated UD1 must reject");
    decode(opsize_prefix, sizeof(opsize_prefix), 0x1000, &matched);
    CHECK(!matched, "operand-size-prefixed UD1 must reject");
    decode(rex_w, sizeof(rex_w), 0x1000, &matched);
    CHECK(!matched, "REX.W UD1 must reject");
}

static void test_remaining_hot_paths(void)
{
    static const uint8_t lea[] = { 0x8d, 0x44, 0x8d, 0x7f };
    static const uint8_t push_r8[] = { 0x41, 0x50 };
    static const uint8_t pop_r9[] = { 0x41, 0x59 };
    static const uint8_t near_jcc[] = {
        0x0f, 0x85, 0xfa, 0xff, 0xff, 0xff,
    };
    static const uint8_t short_jmp[] = { 0xeb, 0xfe };
    static const uint8_t near_jmp[] = { 0xe9, 0x78, 0x56, 0x34, 0x12 };
    static const uint8_t ret_imm[] = { 0xc2, 0x08, 0x00 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(lea, sizeof(lea), 0x1000, &matched);
    CHECK(matched, "LEA must decode");
    CHECK(decoded.fields.kind == FT_LEA_R32_M, "wrong LEA template");
    CHECK(decoded.fields.sib == 0x8d, "wrong LEA SIB byte");
    CHECK(decoded.fields.disp == 0x7f, "wrong LEA displacement");

    decoded = decode(push_r8, sizeof(push_r8), 0x1000, &matched);
    CHECK(matched, "REX.B PUSH must decode");
    CHECK(decoded.fields.kind == FT_PUSH_R64, "wrong PUSH template");
    CHECK(decoded.fields.reg == 8, "wrong extended PUSH register");

    decoded = decode(pop_r9, sizeof(pop_r9), 0x1000, &matched);
    CHECK(matched, "REX.B POP must decode");
    CHECK(decoded.fields.kind == FT_POP_R64, "wrong POP template");
    CHECK(decoded.fields.reg == 9, "wrong extended POP register");

    decoded = decode(near_jcc, sizeof(near_jcc), 0x1000, &matched);
    CHECK(matched, "near JCC must decode");
    CHECK(decoded.fields.kind == FT_JCC_REL, "wrong near JCC template");
    CHECK(decoded.fields.imm64 == 0x1000, "wrong near JCC target");
    CHECK(decoded.is_tb_ending, "near JCC must end the TB");

    decoded = decode(short_jmp, sizeof(short_jmp), 0x2000, &matched);
    CHECK(matched, "short JMP must decode");
    CHECK(decoded.fields.kind == FT_JMP_REL32, "wrong short JMP template");
    CHECK(decoded.fields.imm == -2, "wrong short JMP displacement");
    CHECK(decoded.is_tb_ending, "short JMP must end the TB");

    decoded = decode(near_jmp, sizeof(near_jmp), 0x2000, &matched);
    CHECK(matched, "near JMP must decode");
    CHECK(decoded.fields.kind == FT_JMP_REL32, "wrong near JMP template");
    CHECK(decoded.fields.imm == 0x12345678, "wrong near JMP displacement");
    CHECK(decoded.is_tb_ending, "near JMP must end the TB");

    decoded = decode(ret_imm, sizeof(ret_imm), 0x3000, &matched);
    CHECK(matched, "RET imm16 must decode");
    CHECK(decoded.fields.kind == FT_RET_IMM16, "wrong RET imm16 template");
    CHECK(decoded.fields.imm == 8, "wrong RET immediate");
    CHECK(decoded.is_tb_ending, "RET imm16 must end the TB");
}

static void test_segment_push_pop(void)
{
    static const uint8_t push_fs[] = { 0x0f, 0xa0 };
    static const uint8_t pop_fs16[] = { 0x66, 0x0f, 0xa1 };
    static const uint8_t push_gs16[] = { 0x66, 0x0f, 0xa8 };
    static const uint8_t pop_gs[] = { 0x0f, 0xa9 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(push_fs, sizeof(push_fs), 0x1000, &matched);
    CHECK(matched, "PUSH FS must decode");
    CHECK(decoded.fields.kind == FT_PUSH_SEG64, "wrong PUSH FS template");
    CHECK(decoded.fields.reg == 4, "PUSH FS must select FS");
    CHECK(decoded.fields.size == sizeof(push_fs), "wrong PUSH FS size");

    decoded = decode(pop_fs16, sizeof(pop_fs16), 0x1000, &matched);
    CHECK(matched, "16-bit POP FS must decode");
    CHECK(decoded.fields.kind == FT_POP_SEG16, "wrong POP FS template");
    CHECK(decoded.fields.reg == 4, "POP FS must select FS");
    CHECK(decoded.fields.size == sizeof(pop_fs16), "wrong POP FS size");

    decoded = decode(push_gs16, sizeof(push_gs16), 0x1000, &matched);
    CHECK(matched, "16-bit PUSH GS must decode");
    CHECK(decoded.fields.kind == FT_PUSH_SEG16, "wrong PUSH GS template");
    CHECK(decoded.fields.reg == 5, "PUSH GS must select GS");
    CHECK(decoded.fields.size == sizeof(push_gs16), "wrong PUSH GS size");

    decoded = decode(pop_gs, sizeof(pop_gs), 0x1000, &matched);
    CHECK(matched, "POP GS must decode");
    CHECK(decoded.fields.kind == FT_POP_SEG64, "wrong POP GS template");
    CHECK(decoded.fields.reg == 5, "POP GS must select GS");
    CHECK(decoded.fields.size == sizeof(pop_gs), "wrong POP GS size");
}

static void test_mov_segment_register(void)
{
    static const uint8_t mov_ax_ss[] = { 0x66, 0x8c, 0xd0 };
    static const uint8_t mov_fs_ax[] = { 0x8e, 0xe0 };
    static const uint8_t mov_cs_ax[] = { 0x8e, 0xc8 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(mov_ax_ss, sizeof(mov_ax_ss), 0x30000, &matched);
    CHECK(matched, "MOV AX,SS must decode");
    CHECK(decoded.fields.kind == FT_MOV_RM_SEG,
          "wrong MOV AX,SS template");
    CHECK(decoded.fields.reg == 2,
          "MOV AX,SS selected the wrong segment register");

    decoded = decode(mov_fs_ax, sizeof(mov_fs_ax), 0x30000, &matched);
    CHECK(matched, "MOV FS,AX must decode");
    CHECK(decoded.fields.kind == FT_MOV_SEG_RM,
          "wrong MOV FS,AX template");
    CHECK(decoded.fields.reg == 4,
          "MOV FS,AX selected the wrong segment register");

    (void)decode(mov_cs_ax, sizeof(mov_cs_ax), 0x30000, &matched);
    CHECK(!matched, "MOV CS,AX must be rejected");
}

static void test_hot_group1_immediate(void)
{
    static const uint8_t add32[] = { 0x83, 0xc0, 0x7f };
    static const uint8_t cmp64[] = { 0x48, 0x83, 0xf8, 0xff };
    static const uint8_t or8[] = { 0x80, 0x08, 0x80 };
    static const uint8_t sub16[] = { 0x66, 0x81, 0xe8, 0x34, 0x12 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(add32, sizeof(add32), 0x1000, &matched);
    CHECK(matched, "32-bit Group-1 immediate must decode");
    CHECK(decoded.fields.kind == FT_GRP1_RM32_IMM8,
          "wrong 32-bit Group-1 template");
    CHECK(decoded.fields.alu_op == FT_ALU_ADD, "wrong Group-1 ADD operation");
    CHECK(decoded.fields.imm == 0x7f, "wrong Group-1 imm8");

    decoded = decode(cmp64, sizeof(cmp64), 0x1000, &matched);
    CHECK(matched, "REX.W Group-1 immediate must decode");
    CHECK(decoded.fields.kind == FT_GRP1_RM64_IMM8,
          "wrong 64-bit Group-1 template");
    CHECK(decoded.fields.alu_op == FT_ALU_CMP, "wrong Group-1 CMP operation");
    CHECK(decoded.fields.imm == -1, "Group-1 0x83 immediate must sign extend");

    decoded = decode(or8, sizeof(or8), 0x1000, &matched);
    CHECK(matched, "byte Group-1 immediate must decode");
    CHECK(decoded.fields.kind == FT_GRP1_RM8_IMM8,
          "wrong byte Group-1 template");
    CHECK(decoded.fields.alu_op == FT_ALU_OR, "wrong Group-1 OR operation");
    CHECK(decoded.fields.imm == 0x80, "Group-1 0x80 immediate must stay unsigned");

    decoded = decode(sub16, sizeof(sub16), 0x1000, &matched);
    CHECK(matched, "operand-size Group-1 immediate must decode");
    CHECK(decoded.fields.kind == FT_GRP1_RM32_IMM32,
          "wrong operand-size Group-1 template");
    CHECK(decoded.fields.alu_width == 16, "wrong Group-1 operand width");
    CHECK(decoded.fields.imm == 0x1234, "wrong Group-1 imm16");
}

static void test_prefix_fallback(void)
{
    static const uint8_t opsize[] = { 0x66, 0x89, 0xd8 };
    static const uint8_t repeated_rex[] = { 0x40, 0x48, 0x89, 0xd8 };
    static const uint8_t addr32[] = {
        0x67, 0x48, 0x8b, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(opsize, sizeof(opsize), 0x1000, &matched);
    CHECK(matched, "legacy operand-size prefix must fall back and decode");
    CHECK(decoded.fields.kind == FT_MOV_RM16_R16, "wrong 16-bit MOV");

    decoded = decode(repeated_rex, sizeof(repeated_rex), 0x1000, &matched);
    CHECK(matched, "repeated REX must fall back and decode");
    CHECK(decoded.fields.kind == FT_MOV_RM64_R64, "wrong repeated-REX MOV");
    CHECK(decoded.fields.size == sizeof(repeated_rex), "wrong repeated-REX size");

    decoded = decode(addr32, sizeof(addr32), 0x1000, &matched);
    CHECK(matched, "address-size prefix must fall back and decode");
    CHECK(decoded.fields.addr32, "address-size prefix was lost");
}

static void test_mmx_packssdw_rexw(void)
{
    static const uint8_t packssdw[] = {
        0x48, 0x0f, 0x6b, 0xb4, 0x33, 0x7f, 0xf4, 0x01, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(packssdw, sizeof(packssdw), 0x30014, &matched);
    CHECK(matched, "REX.W MMX PACKSSDW must decode");
    CHECK(decoded.fields.kind == FT_PACKSSDW_MMX_MMXM64,
          "wrong MMX PACKSSDW template");
    CHECK(decoded.fields.rex == 0x48, "REX.W prefix was lost");
    CHECK(decoded.fields.modrm_reg == 6, "wrong MMX destination");
    CHECK(decoded.fields.size == sizeof(packssdw), "wrong MMX PACKSSDW size");

    CHECK(fast_decoder_get_primary(packssdw, sizeof(packssdw), 0x30014,
                                   &info, 1),
          "primary MMX PACKSSDW must decode");
    CHECK(info.id == dt_X86_INS_PACKSSDW, "wrong primary PACKSSDW id");
    CHECK(info.x86.operands[0].type == dt_X86_OP_REG,
          "primary PACKSSDW destination must be a register");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_MM6,
          "REX.W must not turn MM6 into XMM6");
    CHECK(info.x86.operands[0].size == 8,
          "primary PACKSSDW destination must stay 64-bit MMX");
}

static void test_mmx_phadd_sub_rexw(void)
{
    static const struct {
        uint8_t opcode;
        int id;
    } cases[] = {
        { 0x01, dt_X86_INS_PHADDW },
        { 0x02, dt_X86_INS_PHADDD },
        { 0x03, dt_X86_INS_PHADDSW },
        { 0x05, dt_X86_INS_PHSUBW },
        { 0x06, dt_X86_INS_PHSUBD },
        { 0x07, dt_X86_INS_PHSUBSW },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t code[] = { 0x48, 0x0f, 0x38, cases[i].opcode, 0xc8 };
        FastDecodedFT decoded;
        struct la_dt_insn info;
        int matched;

        decoded = decode(code, sizeof(code), 0x3002e, &matched);
        CHECK(matched, "REX.W MMX PHADD/PHSUB must decode");
        CHECK(decoded.fields.kind == FT_PHADD_SUB_MMX_MMXM64,
              "wrong MMX PHADD/PHSUB template");
        CHECK(decoded.fields.id == cases[i].id,
              "wrong MMX PHADD/PHSUB instruction id");
        CHECK(decoded.fields.rex == 0x48,
              "MMX PHADD/PHSUB REX.W prefix was lost");
        CHECK(decoded.fields.modrm_reg == 1 &&
              decoded.fields.modrm_rm == 0,
              "wrong MMX PHADD/PHSUB registers");
        CHECK(decoded.fields.size == sizeof(code),
              "wrong MMX PHADD/PHSUB size");

        CHECK(fast_decoder_get_primary(code, sizeof(code), 0x3002e,
                                       &info, 1),
              "primary REX.W MMX PHADD/PHSUB must decode");
        CHECK(info.id == cases[i].id,
              "wrong primary MMX PHADD/PHSUB instruction id");
        CHECK(info.x86.operands[0].reg == dt_X86_REG_MM1 &&
              info.x86.operands[1].reg == dt_X86_REG_MM0,
              "REX.W must not extend MMX PHADD/PHSUB registers");
    }

    {
        static const uint8_t memory[] = {
            0x4b, 0x0f, 0x38, 0x01, 0x8c, 0x98,
            0x78, 0x56, 0x34, 0x12,
        };
        FastDecodedFT decoded;
        int matched;

        decoded = decode(memory, sizeof(memory), 0x30000, &matched);
        CHECK(matched, "REX.WXB MMX PHADDW memory source must decode");
        CHECK(decoded.fields.kind == FT_PHADD_SUB_MMX_MMXM64,
              "wrong MMX PHADDW memory template");
        CHECK(decoded.fields.modrm_reg == 1,
              "REX.R must not extend the MMX destination");
        CHECK(decoded.fields.rex == 0x4b && decoded.fields.sib == 0x98,
              "REX.B/X or SIB byte was lost for MMX PHADDW memory");
        CHECK(decoded.fields.disp == 0x12345678,
              "wrong MMX PHADDW memory displacement");
    }
}

static void test_mmx_ssse3_rexw(void)
{
    static const struct {
        uint8_t opcode;
        int id;
        FastTemplateKind kind;
    } cases[] = {
        { 0x00, dt_X86_INS_PSHUFB, FT_PSHUFB_MMX_MMXM64 },
        { 0x04, dt_X86_INS_PMADDUBSW, FT_SIMD_MADD_MMX_MMXM64 },
        { 0x08, dt_X86_INS_PSIGNB, FT_SIMD_BIN_MMX_MMXM64 },
        { 0x09, dt_X86_INS_PSIGNW, FT_SIMD_BIN_MMX_MMXM64 },
        { 0x0a, dt_X86_INS_PSIGND, FT_SIMD_BIN_MMX_MMXM64 },
        { 0x0b, dt_X86_INS_PMULHRSW, FT_SIMD_MADD_MMX_MMXM64 },
        { 0x1c, dt_X86_INS_PABSB, FT_SIMD_BIN_MMX_MMXM64 },
        { 0x1d, dt_X86_INS_PABSW, FT_SIMD_BIN_MMX_MMXM64 },
        { 0x1e, dt_X86_INS_PABSD, FT_SIMD_BIN_MMX_MMXM64 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t code[] = { 0x48, 0x0f, 0x38, cases[i].opcode, 0xd4 };
        FastDecodedFT decoded;
        struct la_dt_insn info;
        int matched;

        decoded = decode(code, sizeof(code), 0x30000, &matched);
        CHECK(matched, "REX.W SSSE3 MMX instruction must decode");
        CHECK(decoded.fields.kind == cases[i].kind,
              "wrong SSSE3 MMX template");
        CHECK(decoded.fields.id == cases[i].id,
              "wrong SSSE3 MMX instruction id");
        CHECK(decoded.fields.modrm_reg == 2 && decoded.fields.modrm_rm == 4,
              "wrong SSSE3 MMX registers");

        CHECK(fast_decoder_get_primary(code, sizeof(code), 0x30000,
                                       &info, 1),
              "primary REX.W SSSE3 MMX instruction must decode");
        CHECK(info.id == cases[i].id,
              "wrong primary SSSE3 MMX instruction id");
        CHECK(info.x86.operands[0].reg == dt_X86_REG_MM2 &&
              info.x86.operands[1].reg == dt_X86_REG_MM4,
              "REX.W must not extend SSSE3 MMX registers");
    }

    {
        static const uint8_t psignw_memory[] = {
            0x4b, 0x0f, 0x38, 0x09, 0x84, 0x17,
            0x2d, 0x57, 0x00, 0x00,
        };
        FastDecodedFT decoded;
        struct la_dt_insn info;
        int matched;

        decoded = decode(psignw_memory, sizeof(psignw_memory), 0x300dc,
                         &matched);
        CHECK(matched, "REX.WXB MMX PSIGNW memory source must decode");
        CHECK(decoded.fields.kind == FT_SIMD_BIN_MMX_MMXM64,
              "wrong MMX PSIGNW memory template");
        CHECK(decoded.fields.modrm_reg == 0 && decoded.fields.rex == 0x4b,
              "REX.R must not extend MMX PSIGNW destination");
        CHECK(decoded.fields.sib == 0x17 && decoded.fields.disp == 0x572d,
              "wrong MMX PSIGNW memory address fields");
        CHECK(fast_decoder_get_primary(psignw_memory,
                                       sizeof(psignw_memory), 0x300dc,
                                       &info, 1),
              "primary MMX PSIGNW memory source must decode");
        CHECK(info.x86.operands[0].reg == dt_X86_REG_MM0 &&
              info.x86.operands[1].type == dt_X86_OP_MEM &&
              info.x86.operands[1].size == 8,
              "primary MMX PSIGNW memory width must be 64-bit");
    }
}

static void test_mmx_palignr_rexw(void)
{
    static const uint8_t immediates[] = { 0, 7, 8, 15, 16, 0x80 };
    size_t i;

    for (i = 0; i < sizeof(immediates); i++) {
        uint8_t code[] = { 0x48, 0x0f, 0x3a, 0x0f, 0xd4, immediates[i] };
        FastDecodedFT decoded;
        struct la_dt_insn info;
        int matched;

        decoded = decode(code, sizeof(code), 0x30000, &matched);
        CHECK(matched, "REX.W MMX PALIGNR must decode");
        CHECK(decoded.fields.kind == FT_PALIGNR_MMX_MMXM64_IMM8,
              "wrong MMX PALIGNR template");
        CHECK(decoded.fields.modrm_reg == 2 && decoded.fields.modrm_rm == 4,
              "REX.W must not extend MMX PALIGNR registers");
        CHECK(decoded.fields.imm == immediates[i],
              "wrong MMX PALIGNR immediate");

        CHECK(fast_decoder_get_primary(code, sizeof(code), 0x30000,
                                       &info, 1),
              "primary REX.W MMX PALIGNR must decode");
        CHECK(info.id == dt_X86_INS_PALIGNR && info.x86.op_count == 3,
              "wrong primary MMX PALIGNR instruction");
        CHECK(info.x86.operands[0].reg == dt_X86_REG_MM2 &&
              info.x86.operands[1].reg == dt_X86_REG_MM4,
              "wrong primary MMX PALIGNR registers");
        CHECK(info.x86.operands[2].imm == immediates[i],
              "wrong primary MMX PALIGNR immediate");
    }

    {
        static const uint8_t memory[] = {
            0x48, 0x0f, 0x3a, 0x0f, 0xa4, 0x41,
            0x02, 0x07, 0x00, 0x00, 0x80,
        };
        FastDecodedFT decoded;
        struct la_dt_insn info;
        int matched;

        decoded = decode(memory, sizeof(memory), 0x3013c, &matched);
        CHECK(matched, "REX.W MMX PALIGNR memory source must decode");
        CHECK(decoded.fields.kind == FT_PALIGNR_MMX_MMXM64_IMM8,
              "wrong memory MMX PALIGNR template");
        CHECK(decoded.fields.modrm_reg == 4 && decoded.fields.sib == 0x41 &&
              decoded.fields.disp == 0x702 && decoded.fields.imm == 0x80,
              "wrong memory MMX PALIGNR fields");
        CHECK(fast_decoder_get_primary(memory, sizeof(memory), 0x3013c,
                                       &info, 1),
              "primary memory MMX PALIGNR must decode");
        CHECK(info.x86.operands[0].reg == dt_X86_REG_MM4 &&
              info.x86.operands[1].type == dt_X86_OP_MEM &&
              info.x86.operands[1].size == 8 &&
              info.x86.operands[2].imm == 0x80,
              "primary memory MMX PALIGNR operands must be 64-bit");
    }
}

static void test_pmulhrsw_xmm_memory(void)
{
    static const uint8_t code[] = {
        0x66, 0x42, 0x0f, 0x38, 0x0b, 0xac, 0x0e,
        0x7b, 0x9a, 0x01, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(code, sizeof(code), 0x30061, &matched);
    CHECK(matched, "PMULHRSW XMM memory source must decode");
    CHECK(decoded.fields.kind == FT_SIMD_MADD_XMM_XMM,
          "wrong PMULHRSW XMM memory template");
    CHECK(decoded.fields.id == dt_X86_INS_PMULHRSW &&
          decoded.fields.modrm_reg_index == 5 &&
          decoded.fields.sib == 0x0e && decoded.fields.disp == 0x19a7b,
          "wrong PMULHRSW XMM memory fields");

    CHECK(fast_decoder_get_primary(code, sizeof(code), 0x30061, &info, 1),
          "primary PMULHRSW XMM memory source must decode");
    CHECK(info.id == dt_X86_INS_PMULHRSW &&
          info.x86.operands[0].reg == dt_X86_REG_XMM5 &&
          info.x86.operands[1].type == dt_X86_OP_MEM &&
          info.x86.operands[1].size == 16,
          "primary PMULHRSW XMM memory operands must be 128-bit");
}

static void test_xmm_qword_shift_large_count(void)
{
    static const uint8_t psrlq[] = { 0x66, 0x41, 0x0f, 0x73, 0xd1, 0xb2 };
    static const uint8_t psllq[] = { 0x66, 0x41, 0x0f, 0x73, 0xf1, 0xff };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(psrlq, sizeof(psrlq), 0x30000, &matched);
    CHECK(matched, "REX.B PSRLQ must decode");
    CHECK(decoded.fields.kind == FT_PSRLQ_XMM_IMM8,
          "wrong PSRLQ large-count template");
    CHECK(decoded.fields.modrm_rm_index == 9, "wrong PSRLQ XMM destination");
    CHECK(decoded.fields.imm == 0xb2, "wrong PSRLQ large count");

    decoded = decode(psllq, sizeof(psllq), 0x30000, &matched);
    CHECK(matched, "REX.B PSLLQ must decode");
    CHECK(decoded.fields.kind == FT_PSLLQ_XMM_IMM8,
          "wrong PSLLQ large-count template");
    CHECK(decoded.fields.modrm_rm_index == 9, "wrong PSLLQ XMM destination");
    CHECK(decoded.fields.imm == 0xff, "wrong PSLLQ large count");
}

static void test_pdep(void)
{
    static const uint8_t pdep32_mem[] = {
        0xc4, 0x02, 0x43, 0xf5, 0xa4, 0x02, 0x25, 0x17, 0x00, 0x00,
    };
    static const uint8_t pdep64_reg[] = {
        0xc4, 0x62, 0xc3, 0xf5, 0xe6,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(pdep32_mem, sizeof(pdep32_mem), 0x30014, &matched);
    CHECK(matched, "PDEP r32 memory form must decode");
    CHECK(decoded.fields.kind == FT_PDEP_R32_R_RM,
          "wrong PDEP r32 template");
    CHECK(decoded.fields.reg == 12, "wrong PDEP r32 destination");
    CHECK(decoded.fields.imm == 7, "wrong PDEP r32 source");
    CHECK(decoded.fields.size == sizeof(pdep32_mem), "wrong PDEP r32 size");

    CHECK(fast_decoder_get_primary(pdep32_mem, sizeof(pdep32_mem), 0x30014,
                                   &info, 1),
          "primary PDEP r32 memory form must decode");
    CHECK(info.id == dt_X86_INS_PDEP, "wrong primary PDEP r32 id");

    decoded = decode(pdep64_reg, sizeof(pdep64_reg), 0x30014, &matched);
    CHECK(matched, "PDEP r64 register form must decode");
    CHECK(decoded.fields.kind == FT_PDEP_R64_R_RM,
          "wrong PDEP r64 template");
    CHECK(decoded.fields.reg == 12, "wrong PDEP r64 destination");
    CHECK(decoded.fields.imm == 7, "wrong PDEP r64 source");
}

static void test_mmx_pextrw_rexw(void)
{
    static const uint8_t pextrw[] = { 0x48, 0x0f, 0xc5, 0xfc, 0x55 };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(pextrw, sizeof(pextrw), 0x30000, &matched);
    CHECK(matched, "REX.W MMX PEXTRW must decode");
    CHECK(decoded.fields.kind == FT_PEXTRW_R32_MMX_IMM8,
          "wrong MMX PEXTRW template");
    CHECK(decoded.fields.rex == 0x48, "REX.W prefix was lost");
    CHECK(decoded.fields.modrm_reg == 7, "wrong MMX PEXTRW destination");
    CHECK(decoded.fields.modrm_rm == 4, "wrong MMX PEXTRW source");
    CHECK(decoded.fields.imm == 0x55, "wrong MMX PEXTRW immediate");

    CHECK(fast_decoder_get_primary(pextrw, sizeof(pextrw), 0x30000,
                                   &info, 1),
          "primary MMX PEXTRW must decode");
    CHECK(info.id == dt_X86_INS_PEXTRW, "wrong primary MMX PEXTRW id");
    CHECK(info.x86.operands[1].type == dt_X86_OP_REG,
          "primary MMX PEXTRW source must be a register");
    CHECK(info.x86.operands[1].reg == dt_X86_REG_MM4,
          "REX.W must not turn MM4 into XMM4");
    CHECK(info.x86.operands[1].size == 8,
          "primary MMX PEXTRW source must stay 64-bit MMX");
}

static void test_sse41_pextrw_extended_registers(void)
{
    static const uint8_t pextrw[] = {
        0x66, 0x45, 0x0f, 0x3a, 0x15, 0xd1, 0xde,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(pextrw, sizeof(pextrw), 0x3017d, &matched);
    CHECK(matched, "SSE4.1 PEXTRW must decode");
    CHECK(decoded.fields.kind == FT_PEXTRW_SSE41_RM16_XMM_IMM8,
          "wrong SSE4.1 PEXTRW template");
    CHECK(decoded.fields.modrm_reg == 2, "wrong PEXTRW source bits");
    CHECK(decoded.fields.modrm_rm == 1, "wrong PEXTRW destination bits");
    CHECK(decoded.fields.rex == 0x45, "PEXTRW REX prefix was lost");
    CHECK(decoded.fields.imm == 0xde, "wrong PEXTRW immediate");

    CHECK(fast_decoder_get_primary(pextrw, sizeof(pextrw), 0x3017d,
                                   &info, 1),
          "primary SSE4.1 PEXTRW must decode");
    CHECK(info.id == dt_X86_INS_PEXTRW, "wrong primary PEXTRW id");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_R9D,
          "wrong primary PEXTRW destination");
    CHECK(info.x86.operands[1].reg == dt_X86_REG_XMM10,
          "wrong primary PEXTRW source");
}

static void test_sse41_pextrw_memory_destination(void)
{
    static const uint8_t pextrw[] = {
        0x66, 0x45, 0x0f, 0x3a, 0x15, 0x94, 0xbe,
        0xdf, 0xba, 0x01, 0x00, 0x06,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(pextrw, sizeof(pextrw), 0x302dd, &matched);
    CHECK(matched, "SSE4.1 memory PEXTRW must decode");
    CHECK(decoded.fields.kind == FT_PEXTRW_SSE41_RM16_XMM_IMM8,
          "wrong memory PEXTRW template");
    CHECK(decoded.fields.modrm_mod == 2, "memory PEXTRW lost ModRM mode");
    CHECK(decoded.fields.modrm_reg == 2, "memory PEXTRW source bits");
    CHECK(decoded.fields.modrm_rm == 4, "memory PEXTRW base marker");
    CHECK(decoded.fields.sib == 0xbe, "memory PEXTRW SIB");
    CHECK(decoded.fields.disp == 0x1badf, "memory PEXTRW displacement");
    CHECK(decoded.fields.imm == 6, "memory PEXTRW immediate");

    CHECK(fast_decoder_get_primary(pextrw, sizeof(pextrw), 0x302dd,
                                   &info, 1),
          "primary SSE4.1 memory PEXTRW must decode");
    CHECK(info.id == dt_X86_INS_PEXTRW, "wrong primary memory PEXTRW id");
    CHECK(info.x86.operands[0].type == dt_X86_OP_MEM,
          "primary PEXTRW destination must be memory");
    CHECK(info.x86.operands[0].size == 2,
          "primary PEXTRW destination must be 16-bit memory");
    CHECK(info.x86.operands[1].reg == dt_X86_REG_XMM10,
          "wrong primary memory PEXTRW source");
}

static void test_pextr_memory_destinations(void)
{
    static const uint8_t pextrb[] = {
        0x66, 0x0f, 0x3a, 0x14, 0x3c, 0x8d, 0xa4, 0xec, 0xf7, 0xff, 0x4b,
    };
    static const uint8_t pextrd[] = {
        0x66, 0x44, 0x0f, 0x3a, 0x16, 0x54, 0x24, 0x20, 0x03,
    };
    static const uint8_t pextrq[] = {
        0x66, 0x4c, 0x0f, 0x3a, 0x16, 0x4d, 0x10, 0x01,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(pextrb, sizeof(pextrb), 0x300b9, &matched);
    CHECK(matched, "PEXTRB memory destination must decode");
    CHECK(decoded.fields.kind == FT_PEXTR_GPR_XMM_IMM8,
          "wrong PEXTRB memory template");
    CHECK(decoded.fields.modrm_mod != 3, "PEXTRB destination is not memory");
    CHECK(decoded.fields.imm == 0x4b, "wrong PEXTRB immediate");
    CHECK(fast_decoder_get_primary(pextrb, sizeof(pextrb), 0x300b9,
                                   &info, 1),
          "primary PEXTRB memory destination must decode");
    CHECK(info.x86.operands[0].type == dt_X86_OP_MEM,
          "primary PEXTRB destination must be memory");

    decoded = decode(pextrd, sizeof(pextrd), 0x30000, &matched);
    CHECK(matched, "PEXTRD memory destination must decode");
    CHECK(decoded.fields.kind == FT_PEXTR_GPR_XMM_IMM8,
          "wrong PEXTRD memory template");
    CHECK(fast_decoder_get_primary(pextrd, sizeof(pextrd), 0x30000,
                                   &info, 1),
          "primary PEXTRD memory destination must decode");
    CHECK(info.x86.operands[0].type == dt_X86_OP_MEM &&
          info.x86.operands[0].size == 4,
          "primary PEXTRD destination width is wrong");

    decoded = decode(pextrq, sizeof(pextrq), 0x30000, &matched);
    CHECK(matched, "PEXTRQ memory destination must decode");
    CHECK(decoded.fields.kind == FT_PEXTRQ_R64_XMM_IMM8,
          "wrong PEXTRQ memory template");
}

static void test_lea_r16_addr32(void)
{
    static const uint8_t lea[] = {
        0x66, 0x67, 0x8d, 0x84, 0x31, 0x8c, 0x80, 0x00, 0x00,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(lea, sizeof(lea), 0x30000, &matched);
    CHECK(matched, "address-size LEA r16 must decode");
    CHECK(decoded.fields.kind == FT_LEA_R16_M, "wrong LEA r16 template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "LEA operand-size prefix was lost");
    CHECK(decoded.fields.addr32, "LEA address-size prefix was lost");
    CHECK(decoded.fields.modrm_reg == 0, "wrong LEA r16 destination");
    CHECK(decoded.fields.size == sizeof(lea), "wrong LEA r16 size");
}

static void test_lea_r64_addr32(void)
{
    static const uint8_t lea[] = {
        0x67, 0x4d, 0x8d, 0xa4, 0x94, 0x53, 0x74, 0x00, 0x00,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(lea, sizeof(lea), 0x30000, &matched);
    CHECK(matched, "address-size LEA r64 must decode");
    CHECK(decoded.fields.kind == FT_LEA_R64_M, "wrong LEA r64 template");
    CHECK(decoded.fields.addr32, "LEA r64 address-size prefix was lost");
    CHECK(decoded.fields.rex == 0x4d, "LEA r64 REX prefix was lost");
    CHECK(decoded.fields.modrm_reg == 4, "wrong LEA r64 destination");
    CHECK(decoded.fields.sib == 0x94, "wrong LEA r64 SIB byte");
    CHECK(decoded.fields.disp == 0x7453, "wrong LEA r64 displacement");
    CHECK(decoded.fields.size == sizeof(lea), "wrong LEA r64 size");
}

static void test_movsx_r16_memory(void)
{
    static const uint8_t movsx[] = {
        0x66, 0x44, 0x0f, 0xbe, 0xa6, 0x7e, 0x49, 0x02, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(movsx, sizeof(movsx), 0x30000, &matched);
    CHECK(matched, "MOVSX r16, m8 must decode");
    CHECK(decoded.fields.kind == FT_MOVSX_R16_RM8,
          "wrong MOVSX r16, m8 template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "MOVSX r16 operand-size prefix was lost");
    CHECK(decoded.fields.rex == 0x44, "MOVSX r16 REX prefix was lost");
    CHECK(decoded.fields.modrm_reg == 4, "wrong MOVSX r16 destination");
    CHECK(decoded.fields.disp == 0x2497e, "wrong MOVSX r16 displacement");

    CHECK(fast_decoder_get_primary(movsx, sizeof(movsx), 0x30000,
                                   &info, 1),
          "primary MOVSX r16, m8 must decode");
    CHECK(info.id == dt_X86_INS_MOVSX, "wrong primary MOVSX r16 id");
    CHECK(info.x86.operands[0].size == 2,
          "primary MOVSX r16 destination must stay word-sized");
    CHECK(info.x86.operands[1].type == dt_X86_OP_MEM,
          "primary MOVSX r16 source must be memory");
    CHECK(info.x86.operands[1].size == 1,
          "primary MOVSX r16 source must stay byte-sized");
}

static void test_movsxd_non_rex_widths(void)
{
    static const uint8_t movsxd16[] = { 0x66, 0x63, 0xc1 };
    static const uint8_t movsxd32[] = { 0x63, 0xc1 };
    static const uint8_t movsxd64_opsize[] = { 0x66, 0x48, 0x63, 0xc1 };
    FastDecodedFT decoded;

    CHECK(fast_decoder_get_ft(movsxd16, sizeof(movsxd16), 0x1000,
                              &decoded, 1),
          "MOVSXD r16, r16 must decode in primary mode");
    CHECK(decoded.fields.id == dt_X86_INS_MOVSXD,
          "wrong MOVSXD r16 id");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "MOVSXD r16 must preserve the operand-size prefix");
    CHECK(decoded.fields.size == sizeof(movsxd16),
          "wrong MOVSXD r16 size");

    CHECK(fast_decoder_get_ft(movsxd32, sizeof(movsxd32), 0x1000,
                              &decoded, 1),
          "MOVSXD r32, r32 must decode in primary mode");
    CHECK(decoded.fields.id == dt_X86_INS_MOVSXD,
          "wrong MOVSXD r32 id");
    CHECK(decoded.fields.prefix2 != dt_X86_PREFIX_OPSIZE,
          "MOVSXD r32 must not gain an operand-size prefix");
    CHECK(decoded.fields.size == sizeof(movsxd32),
          "wrong MOVSXD r32 size");

    CHECK(fast_decoder_get_ft(movsxd64_opsize,
                              sizeof(movsxd64_opsize), 0x1000,
                              &decoded, 1),
          "REX.W MOVSXD with operand-size prefix must decode");
    CHECK(decoded.fields.kind == FT_MOVSXD_R64_RM32,
          "REX.W must override the MOVSXD operand-size prefix");
    CHECK(decoded.fields.size == sizeof(movsxd64_opsize),
          "wrong prefixed MOVSXD r64 size");
}

static void test_movq_xmmm64_xmm_register(void)
{
    static const uint8_t movq[] = { 0x66, 0x49, 0x0f, 0xd6, 0xee };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(movq, sizeof(movq), 0x30000, &matched);
    CHECK(matched, "MOVQ xmm/m64, xmm register form must decode");
    CHECK(decoded.fields.kind == FT_MOVQ_RM64_XMM,
          "wrong MOVQ xmm/m64, xmm template");
    CHECK(decoded.fields.id == dt_X86_INS_MOVQ, "wrong MOVQ id");
    CHECK(decoded.fields.rex == 0x49, "MOVQ REX.WB prefix was lost");
    CHECK(decoded.fields.modrm_reg == 5, "wrong MOVQ source register");
    CHECK(decoded.fields.modrm_rm == 6, "wrong MOVQ destination register");
}

static void test_cvttps2pi_mmx_rexwx_memory(void)
{
    static const uint8_t cvttps2pi[] = {
        0x4a, 0x0f, 0x2c, 0x8c, 0x5f, 0xe7, 0x56, 0x00, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(cvttps2pi, sizeof(cvttps2pi), 0x30000, &matched);
    CHECK(matched, "REX.WX CVTTPS2PI mm, m64 must decode");
    CHECK(decoded.fields.kind == FT_CVT_FP2I_MMX_XMMM,
          "wrong CVTTPS2PI template");
    CHECK(decoded.fields.id == dt_X86_INS_CVTTPS2PI,
          "wrong CVTTPS2PI id");
    CHECK(decoded.fields.rex == 0x4a, "CVTTPS2PI REX.WX was lost");
    CHECK(decoded.fields.sib == 0x5f, "wrong CVTTPS2PI SIB byte");
    CHECK(decoded.fields.disp == 0x56e7,
          "wrong CVTTPS2PI displacement");

    CHECK(fast_decoder_get_primary(cvttps2pi, sizeof(cvttps2pi), 0x30000,
                                   &info, 1),
          "primary REX.WX CVTTPS2PI mm, m64 must decode");
    CHECK(info.id == dt_X86_INS_CVTTPS2PI,
          "wrong primary CVTTPS2PI id");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_MM1,
          "primary CVTTPS2PI destination must stay MM1");
    CHECK(info.x86.operands[1].type == dt_X86_OP_MEM,
          "primary CVTTPS2PI source must be memory");
    CHECK(info.x86.operands[1].size == 8,
          "primary CVTTPS2PI source must stay qword-sized");
}

static void test_xchg_rm16_r16_lock_rexr_memory(void)
{
    static const uint8_t xchg[] = {
        0x66, 0xf0, 0x44, 0x87, 0x0c, 0x75, 0xc8, 0x34, 0x03, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(xchg, sizeof(xchg), 0x30000, &matched);
    CHECK(matched, "LOCK XCHG r/m16, r9w must decode");
    CHECK(decoded.fields.kind == FT_XCHG_RM32_R32,
          "wrong XCHG r/m16 template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "XCHG operand-size prefix was lost");
    CHECK(decoded.fields.rex == 0x44, "XCHG REX.R prefix was lost");
    CHECK(decoded.fields.modrm_reg_index == 9,
          "wrong XCHG r9w source register");
    CHECK(decoded.fields.sib == 0x75, "wrong XCHG SIB byte");
    CHECK(decoded.fields.disp == 0x334c8,
          "wrong XCHG displacement");

    CHECK(fast_decoder_get_primary(xchg, sizeof(xchg), 0x30000, &info, 1),
          "primary LOCK XCHG r/m16, r9w must decode");
    CHECK(info.id == dt_X86_INS_XCHG, "wrong primary XCHG id");
    CHECK(info.x86.operands[0].type == dt_X86_OP_MEM,
          "primary XCHG destination must be memory");
    CHECK(info.x86.operands[0].size == 2,
          "primary XCHG destination must stay word-sized");
    CHECK(info.x86.operands[1].reg == dt_X86_REG_R9W,
          "primary XCHG source must stay R9W");
}

static void test_xchg_rm16_r16_rexr_register(void)
{
    static const uint8_t xchg[] = { 0x66, 0x44, 0x87, 0xc0 };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(xchg, sizeof(xchg), 0x30000, &matched);
    CHECK(matched, "XCHG ax, r8w must decode");
    CHECK(decoded.fields.kind == FT_XCHG_RM32_R32,
          "wrong XCHG ax, r8w template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "XCHG ax, r8w operand-size prefix was lost");
    CHECK(decoded.fields.rex == 0x44, "XCHG ax, r8w REX.R prefix was lost");
    CHECK(decoded.fields.modrm == 0xc0, "wrong XCHG ax, r8w ModRM byte");
    CHECK(decoded.fields.modrm_reg_index == 8,
          "wrong XCHG ax, r8w source register");

    CHECK(fast_decoder_get_primary(xchg, sizeof(xchg), 0x30000, &info, 1),
          "primary XCHG ax, r8w must decode");
    CHECK(info.id == dt_X86_INS_XCHG, "wrong primary XCHG ax, r8w id");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_AX,
          "primary XCHG destination must stay AX");
    CHECK(info.x86.operands[1].reg == dt_X86_REG_R8W,
          "primary XCHG source must stay R8W");
}

static void test_cmpsd_nlt_rexrx_memory(void)
{
    static const uint8_t cmpsd[] = {
        0xf2, 0x46, 0x0f, 0xc2, 0x9c, 0x96, 0x41, 0x10, 0x00, 0x00,
        0x05,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(cmpsd, sizeof(cmpsd), 0x30000, &matched);
    CHECK(matched, "CMPSD xmm11, m64, 5 must decode");
    CHECK(decoded.fields.kind == FT_CMP_XMM_XMMM_IMM8,
          "wrong CMPSD template");
    CHECK(decoded.fields.id == dt_X86_INS_CMPSD, "wrong CMPSD id");
    CHECK(decoded.fields.prefix0 == dt_X86_PREFIX_REPNE,
          "CMPSD F2 prefix was lost");
    CHECK(decoded.fields.rex == 0x46, "CMPSD REX.RX prefix was lost");
    CHECK(decoded.fields.modrm_reg_index == 11,
          "wrong CMPSD xmm11 destination");
    CHECK(decoded.fields.sib == 0x96, "wrong CMPSD SIB byte");
    CHECK(decoded.fields.disp == 0x1041, "wrong CMPSD displacement");
    CHECK(decoded.fields.imm == 5, "wrong CMPSD predicate");

    CHECK(fast_decoder_get_primary(cmpsd, sizeof(cmpsd), 0x30000, &info, 1),
          "primary CMPSD xmm11, m64, 5 must decode");
    CHECK(info.id == dt_X86_INS_CMPSD, "wrong primary CMPSD id");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_XMM11,
          "primary CMPSD destination must stay XMM11");
    CHECK(info.x86.operands[1].type == dt_X86_OP_MEM,
          "primary CMPSD source must be memory");
    CHECK(info.x86.operands[1].size == 8,
          "primary CMPSD source must stay qword-sized");
    CHECK(info.x86.operands[2].imm == 5,
          "primary CMPSD predicate must stay 5");
}

static void test_xlatb_ignored_opsize_prefix(void)
{
    static const uint8_t xlatb[] = { 0x66, 0xd7 };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(xlatb, sizeof(xlatb), 0x30000, &matched);
    CHECK(matched, "operand-size XLATB must decode");
    CHECK(decoded.fields.kind == FT_XLATB, "wrong operand-size XLATB template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "XLATB operand-size prefix was lost");
    CHECK(decoded.fields.size == sizeof(xlatb), "wrong operand-size XLATB size");

    CHECK(fast_decoder_get_primary(xlatb, sizeof(xlatb), 0x30000,
                                   &info, 1),
          "primary operand-size XLATB must decode");
    CHECK(info.id == dt_X86_INS_XLATB, "wrong primary operand-size XLATB id");
}

static void test_mmx_pmovmskb_rexr(void)
{
    static const uint8_t pmovmskb[] = { 0x44, 0x0f, 0xd7, 0xdb };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(pmovmskb, sizeof(pmovmskb), 0x30000, &matched);
    CHECK(matched, "REX.R MMX PMOVMSKB must decode");
    CHECK(decoded.fields.kind == FT_PMOVMSKB_R32_MMX,
          "wrong MMX PMOVMSKB template");
    CHECK(decoded.fields.modrm_reg_index == 11,
          "REX.R must extend the PMOVMSKB destination");
    CHECK(decoded.fields.modrm_rm == 3,
          "REX.B must not extend the MMX PMOVMSKB source");

    CHECK(fast_decoder_get_primary(pmovmskb, sizeof(pmovmskb), 0x30000,
                                   &info, 1),
          "primary REX.R MMX PMOVMSKB must decode");
    CHECK(info.id == dt_X86_INS_PMOVMSKB, "wrong primary MMX PMOVMSKB id");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_R11D,
          "wrong primary MMX PMOVMSKB destination");
    CHECK(info.x86.operands[1].reg == dt_X86_REG_MM3,
          "wrong primary MMX PMOVMSKB source");
    CHECK(info.x86.operands[1].size == 8,
          "primary PMOVMSKB source must stay 64-bit MMX");
}

static void test_mmx_pand_rexwb_memory(void)
{
    static const uint8_t pand[] = {
        0x49, 0x0f, 0xdb, 0xbc, 0x78, 0xb5, 0x51, 0x00, 0x00,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(pand, sizeof(pand), 0x30000, &matched);
    CHECK(matched, "REX.WB MMX PAND memory source must decode");
    CHECK(decoded.fields.kind == FT_PAND_MMX_MMXM64,
          "wrong MMX PAND template");
    CHECK(decoded.fields.id == dt_X86_INS_PAND, "wrong MMX PAND id");
    CHECK(decoded.fields.rex == 0x49, "MMX PAND REX.WB was lost");
    CHECK(decoded.fields.sib == 0x78, "wrong MMX PAND SIB byte");
    CHECK(decoded.fields.disp == 0x51b5, "wrong MMX PAND displacement");
    CHECK(decoded.fields.size == sizeof(pand), "wrong MMX PAND size");
}

static void test_mmx_psrad_rexw(void)
{
    static const uint8_t psrad[] = { 0x48, 0x0f, 0xe2, 0xf4 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(psrad, sizeof(psrad), 0x30000, &matched);
    CHECK(matched, "REX.W MMX PSRAD must decode");
    CHECK(decoded.fields.kind == FT_PSRAD_MMX_MMXM64,
          "wrong MMX PSRAD template");
    CHECK(decoded.fields.id == dt_X86_INS_PSRAD, "wrong MMX PSRAD id");
    CHECK(decoded.fields.rex == 0x48, "MMX PSRAD REX.W was lost");
    CHECK(decoded.fields.size == sizeof(psrad), "wrong MMX PSRAD size");
}

static void test_mmx_paddq_rexw(void)
{
    static const uint8_t paddq[] = { 0x48, 0x0f, 0xd4, 0xe9 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(paddq, sizeof(paddq), 0x30000, &matched);
    CHECK(matched, "REX.W MMX PADDQ must decode");
    CHECK(decoded.fields.kind == FT_PADDQ_MMX_MMXM64,
          "wrong MMX PADDQ template");
    CHECK(decoded.fields.id == dt_X86_INS_PADDQ, "wrong MMX PADDQ id");
    CHECK(decoded.fields.rex == 0x48, "MMX PADDQ REX.W was lost");
    CHECK(decoded.fields.size == sizeof(paddq), "wrong MMX PADDQ size");
}

static void test_mmx_movq_r64(void)
{
    static const uint8_t movq[] = { 0x48, 0x0f, 0x6e, 0xef };
    static const uint8_t movq_mem[] = {
        0x48, 0x0f, 0x6e, 0x35, 0x20, 0x00, 0x00, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(movq, sizeof(movq), 0x30000, &matched);
    CHECK(matched, "REX.W MOVQ mm, r64 must decode");
    CHECK(decoded.fields.kind == FT_MOVQ_MMX_RM64_GPR,
          "wrong MMX MOVQ r64 template");
    CHECK(decoded.fields.id == dt_X86_INS_MOVQ, "wrong MMX MOVQ r64 id");
    CHECK(decoded.fields.modrm_reg == 5, "wrong MMX MOVQ destination");
    CHECK(decoded.fields.modrm_rm_index == 7, "wrong MMX MOVQ source");

    CHECK(fast_decoder_get_primary(movq, sizeof(movq), 0x30000, &info, 1),
          "primary REX.W MOVQ mm, r64 must decode");
    CHECK(info.id == dt_X86_INS_MOVQ, "wrong primary MMX MOVQ r64 id");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_MM5,
          "wrong primary MMX MOVQ destination");
    CHECK(info.x86.operands[1].reg == dt_X86_REG_RDI,
          "wrong primary MMX MOVQ source");
    CHECK(info.x86.operands[1].size == 8,
          "primary MMX MOVQ source must stay 64-bit");

    decoded = decode(movq_mem, sizeof(movq_mem), 0x30000, &matched);
    CHECK(matched, "REX.W MOVQ mm, m64 must decode");
    CHECK(decoded.fields.kind == FT_MOVQ_MMX_RM64_GPR,
          "wrong MMX MOVQ m64 template");
    CHECK(decoded.fields.modrm_reg == 6, "wrong MMX MOVQ memory destination");
    CHECK(decoded.fields.disp == 0x20, "wrong MMX MOVQ memory displacement");

    CHECK(fast_decoder_get_primary(movq_mem, sizeof(movq_mem), 0x30000,
                                   &info, 1),
          "primary REX.W MOVQ mm, m64 must decode");
    CHECK(info.x86.operands[1].type == dt_X86_OP_MEM,
          "primary MMX MOVQ source must be memory");
    CHECK(info.x86.operands[1].size == 8,
          "primary MMX MOVQ memory source must stay 64-bit");
}

static void test_movq_xmm_rm64_rexwx_memory(void)
{
    static const uint8_t movq[] = {
        0x66, 0x4a, 0x0f, 0x6e, 0xb4, 0x6b, 0x77, 0xa8, 0x02, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(movq, sizeof(movq), 0x30000, &matched);
    CHECK(matched, "REX.W MOVQ xmm, m64 indexed memory form must decode");
    CHECK(decoded.fields.kind == FT_MOVQ_XMM_RM64,
          "MOVQ xmm, m64 must use the memory template");
    CHECK(decoded.fields.id == dt_X86_INS_MOVQ, "wrong MOVQ xmm, m64 id");
    CHECK(decoded.fields.rex == 0x4a, "MOVQ xmm, m64 REX.WX was lost");
    CHECK(decoded.fields.modrm_reg_index == 6,
          "wrong MOVQ xmm, m64 destination register");
    CHECK(decoded.fields.modrm_rm_index == 4,
          "wrong MOVQ xmm, m64 SIB ModRM register");
    CHECK(decoded.fields.sib == 0x6b, "wrong MOVQ xmm, m64 SIB byte");
    CHECK(decoded.fields.disp == 0x2a877,
          "wrong MOVQ xmm, m64 displacement");

    CHECK(fast_decoder_get_primary(movq, sizeof(movq), 0x30000, &info, 1),
          "primary MOVQ xmm, m64 indexed memory form must decode");
    CHECK(info.id == dt_X86_INS_MOVQ, "wrong primary MOVQ xmm, m64 id");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_XMM6,
          "wrong primary MOVQ xmm, m64 destination");
    CHECK(info.x86.operands[1].type == dt_X86_OP_MEM,
          "primary MOVQ xmm, m64 source must be memory");
    CHECK(info.x86.operands[1].size == 8,
          "primary MOVQ xmm, m64 source must stay 64-bit");
}

static void test_idiv_rm8(void)
{
    static const uint8_t idiv_mem[] = {
        0xf6, 0x3c, 0x25, 0x20, 0x03, 0x04, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(idiv_mem, sizeof(idiv_mem), 0x30000, &matched);
    CHECK(matched, "IDIV r/m8 memory form must decode");
    CHECK(decoded.fields.kind == FT_IDIV_RM8, "wrong IDIV r/m8 template");
    CHECK(decoded.fields.id == dt_X86_INS_IDIV, "wrong IDIV r/m8 id");
    CHECK(decoded.fields.modrm_reg == 7, "wrong IDIV r/m8 extension");
    CHECK(decoded.fields.disp == 0x40320, "wrong IDIV r/m8 address");

    CHECK(fast_decoder_get_primary(idiv_mem, sizeof(idiv_mem), 0x30000,
                                   &info, 1),
          "primary IDIV r/m8 memory form must decode");
    CHECK(info.id == dt_X86_INS_IDIV, "wrong primary IDIV r/m8 id");
    CHECK(info.x86.operands[0].type == dt_X86_OP_MEM,
          "primary IDIV r/m8 operand must be memory");
    CHECK(info.x86.operands[0].size == 1,
          "primary IDIV r/m8 operand must stay byte-sized");
}

static void test_idiv_rm16(void)
{
    static const uint8_t idiv_mem[] = {
        0x66, 0xf7, 0x3c, 0x25, 0xe0, 0x02, 0x04, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(idiv_mem, sizeof(idiv_mem), 0x30000, &matched);
    CHECK(matched, "IDIV r/m16 memory form must decode");
    CHECK(decoded.fields.kind == FT_IDIV_RM16, "wrong IDIV r/m16 template");
    CHECK(decoded.fields.id == dt_X86_INS_IDIV, "wrong IDIV r/m16 id");
    CHECK(decoded.fields.modrm_reg == 7, "wrong IDIV r/m16 extension");
    CHECK(decoded.fields.disp == 0x402e0, "wrong IDIV r/m16 address");

    CHECK(fast_decoder_get_primary(idiv_mem, sizeof(idiv_mem), 0x30000,
                                   &info, 1),
          "primary IDIV r/m16 memory form must decode");
    CHECK(info.id == dt_X86_INS_IDIV, "wrong primary IDIV r/m16 id");
}

static void test_div_rm8(void)
{
    static const uint8_t div_mem[] = {
        0xf6, 0x34, 0x25, 0x80, 0x03, 0x04, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(div_mem, sizeof(div_mem), 0x30000, &matched);
    CHECK(matched, "DIV r/m8 memory form must decode");
    CHECK(decoded.fields.kind == FT_DIV_RM8, "wrong DIV r/m8 template");
    CHECK(decoded.fields.id == dt_X86_INS_DIV, "wrong DIV r/m8 id");
    CHECK(decoded.fields.modrm_reg == 6, "wrong DIV r/m8 extension");
    CHECK(decoded.fields.disp == 0x40380, "wrong DIV r/m8 address");

    CHECK(fast_decoder_get_primary(div_mem, sizeof(div_mem), 0x30000,
                                   &info, 1),
          "primary DIV r/m8 memory form must decode");
    CHECK(info.id == dt_X86_INS_DIV, "wrong primary DIV r/m8 id");
    CHECK(info.x86.operands[0].type == dt_X86_OP_MEM,
          "primary DIV r/m8 operand must be memory");
    CHECK(info.x86.operands[0].size == 1,
          "primary DIV r/m8 operand must stay byte-sized");
}

static void test_pinsrw_mmx_memory(void)
{
    static const uint8_t pinsrw[] = {
        0x4b, 0x0f, 0xc4, 0x84, 0x31, 0xe7, 0x1f, 0x00, 0x00, 0x87,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(pinsrw, sizeof(pinsrw), 0x30000, &matched);
    CHECK(matched, "REX.W PINSRW mm, m16 must decode");
    CHECK(decoded.fields.kind == FT_PINSRW_MMX_RM16_IMM8,
          "wrong MMX PINSRW template");
    CHECK(decoded.fields.id == dt_X86_INS_PINSRW, "wrong MMX PINSRW id");
    CHECK(decoded.fields.rex == 0x4b, "MMX PINSRW REX was lost");
    CHECK(decoded.fields.disp == 0x1fe7, "wrong MMX PINSRW displacement");
    CHECK(decoded.fields.imm == 0x87, "wrong MMX PINSRW immediate");

    CHECK(fast_decoder_get_primary(pinsrw, sizeof(pinsrw), 0x30000,
                                   &info, 1),
          "primary REX.W PINSRW mm, m16 must decode");
    CHECK(info.id == dt_X86_INS_PINSRW, "wrong primary MMX PINSRW id");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_MM0,
          "primary MMX PINSRW destination must stay MM0");
    CHECK(info.x86.operands[0].size == 8,
          "primary MMX PINSRW destination must stay 64-bit");
    CHECK(info.x86.operands[1].type == dt_X86_OP_MEM,
          "primary MMX PINSRW source must be memory");
    CHECK(info.x86.operands[1].size == 2,
          "primary MMX PINSRW source must stay word-sized");

    CHECK(fast_decoder_get(pinsrw, sizeof(pinsrw), 0x30000, &info, 1),
          "generic REX.W PINSRW mm, m16 must decode");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_MM0,
          "generic MMX PINSRW destination must stay MM0");
    CHECK(info.x86.operands[0].size == 8,
          "generic MMX PINSRW destination must stay 64-bit");
    CHECK(info.x86.operands[1].type == dt_X86_OP_MEM,
          "generic MMX PINSRW source must be memory");
    CHECK(info.x86.operands[1].size == 2,
          "generic MMX PINSRW source must stay word-sized");
}

static void test_mmx_psrld_rexw_memory(void)
{
    static const uint8_t psrld[] = {
        0x4a, 0x0f, 0xd2, 0x94, 0x16, 0x43, 0x41, 0x00, 0x00,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(psrld, sizeof(psrld), 0x30000, &matched);
    CHECK(matched, "REX.WX MMX PSRLD memory source must decode");
    CHECK(decoded.fields.kind == FT_SIMD_BIN_XMM_XMMM,
          "wrong MMX PSRLD template");
    CHECK(decoded.fields.id == dt_X86_INS_PSRLD, "wrong MMX PSRLD id");
    CHECK(decoded.fields.rex == 0x4a, "MMX PSRLD REX.WX was lost");
    CHECK(decoded.fields.sib == 0x16, "wrong MMX PSRLD SIB byte");
    CHECK(decoded.fields.disp == 0x4143, "wrong MMX PSRLD displacement");
}

static void test_mmx_pmaxub_rexw_memory(void)
{
    static const uint8_t pmaxub[] = {
        0x4b, 0x0f, 0xde, 0x84, 0x59, 0xd2, 0x1c, 0x01, 0x00,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(pmaxub, sizeof(pmaxub), 0x30000, &matched);
    CHECK(matched, "REX.WXB MMX PMAXUB memory source must decode");
    CHECK(decoded.fields.kind == FT_SIMD_BIN_XMM_XMMM,
          "wrong MMX PMAXUB template");
    CHECK(decoded.fields.id == dt_X86_INS_PMAXUB, "wrong MMX PMAXUB id");
    CHECK(decoded.fields.rex == 0x4b, "MMX PMAXUB REX.WXB was lost");
    CHECK(decoded.fields.sib == 0x59, "wrong MMX PMAXUB SIB byte");
    CHECK(decoded.fields.disp == 0x11cd2, "wrong MMX PMAXUB displacement");
}

static void test_mmx_pmulhuw_rexw_memory(void)
{
    static const uint8_t pmulhuw[] = {
        0x4b, 0x0f, 0xe4, 0x94, 0x0d, 0x99, 0xff, 0x00, 0x00,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(pmulhuw, sizeof(pmulhuw), 0x30000, &matched);
    CHECK(matched, "REX.WXB MMX PMULHUW memory source must decode");
    CHECK(decoded.fields.kind == FT_PMULHUW_MMX_MMXM64,
          "wrong MMX PMULHUW template");
    CHECK(decoded.fields.id == dt_X86_INS_PMULHUW, "wrong MMX PMULHUW id");
    CHECK(decoded.fields.rex == 0x4b, "MMX PMULHUW REX.WXB was lost");
    CHECK(decoded.fields.sib == 0x0d, "wrong MMX PMULHUW SIB byte");
    CHECK(decoded.fields.disp == 0xff99, "wrong MMX PMULHUW displacement");
}

static void test_mmx_pslld_rexw_memory(void)
{
    static const uint8_t pslld[] = {
        0x48, 0x0f, 0xf2, 0x1c, 0x9d, 0x1c, 0xe2, 0xfe, 0xff,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(pslld, sizeof(pslld), 0x30000, &matched);
    CHECK(matched, "REX.W MMX PSLLD memory count must decode");
    CHECK(decoded.fields.kind == FT_SIMD_BIN_XMM_XMMM,
          "wrong MMX PSLLD template");
    CHECK(decoded.fields.id == dt_X86_INS_PSLLD, "wrong MMX PSLLD id");
    CHECK(decoded.fields.rex == 0x48, "MMX PSLLD REX.W was lost");
    CHECK(decoded.fields.sib == 0x9d, "wrong MMX PSLLD SIB byte");
    CHECK(decoded.fields.disp == (int32_t)0xfffee21c,
          "wrong MMX PSLLD displacement");
}

static void test_mmx_paddb_rexw(void)
{
    static const uint8_t paddb[] = { 0x48, 0x0f, 0xfc, 0xea };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(paddb, sizeof(paddb), 0x30000, &matched);
    CHECK(matched, "REX.W MMX PADDB must decode");
    CHECK(decoded.fields.kind == FT_PADDB_MMX_MMXM64,
          "wrong MMX PADDB template");
    CHECK(decoded.fields.id == dt_X86_INS_PADDB, "wrong MMX PADDB id");
    CHECK(decoded.fields.rex == 0x48, "MMX PADDB REX.W was lost");
}

static void test_blsr_r32(void)
{
    static const uint8_t blsr[] = { 0xc4, 0xe2, 0x78, 0xf3, 0xc9 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(blsr, sizeof(blsr), 0x30000, &matched);
    CHECK(matched, "VEX BLSR r32 must decode");
    CHECK(decoded.fields.kind == FT_BLS_R32_RM, "wrong BLSR r32 template");
    CHECK(decoded.fields.id == dt_X86_INS_BLSR, "wrong BLSR r32 id");
    CHECK(decoded.fields.reg == 0, "wrong BLSR r32 destination register");
}

static void test_mul_r16_rexb(void)
{
    static const uint8_t mul[] = { 0x66, 0x41, 0xf7, 0xe6 };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(mul, sizeof(mul), 0x30000, &matched);
    CHECK(matched, "REX.B MUL r16 must decode");
    CHECK(decoded.fields.kind == FT_MUL_RM16, "wrong MUL r16 template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "MUL r16 operand-size prefix was lost");
    CHECK(decoded.fields.modrm_rm_index == 14,
          "REX.B must extend the MUL r16 source");
    CHECK(decoded.fields.size == sizeof(mul), "wrong MUL r16 size");

    CHECK(fast_decoder_get_primary(mul, sizeof(mul), 0x30000, &info, 1),
          "primary REX.B MUL r16 must decode");
    CHECK(info.id == dt_X86_INS_MUL, "wrong primary MUL r16 id");
    CHECK(info.x86.op_count == 1,
          "primary MUL r16 must have one explicit operand");
    CHECK(info.x86.operands[0].reg == dt_X86_REG_R14W,
          "primary MUL r16 source must be R14W");
    CHECK(info.x86.operands[0].size == 2,
          "primary MUL r16 source must stay 16-bit");
}

static void test_mul_rm32_rexx_rexb_memory(void)
{
    static const uint8_t mul[] = {
        0x43, 0xf7, 0xa4, 0x09, 0x7e, 0xc4, 0x03, 0x00,
    };
    FastDecodedFT decoded;
    struct la_dt_insn info;
    int matched;

    decoded = decode(mul, sizeof(mul), 0x30000, &matched);
    CHECK(matched, "MUL r/m32 indexed memory form must decode");
    CHECK(decoded.fields.kind == FT_MUL_RM32, "wrong MUL r/m32 template");
    CHECK(decoded.fields.id == dt_X86_INS_MUL, "wrong MUL r/m32 id");
    CHECK(decoded.fields.rex == 0x43, "MUL r/m32 REX.X/B prefix was lost");
    CHECK(decoded.fields.modrm_rm_index == 12,
          "wrong MUL r/m32 extended ModRM register");
    CHECK(decoded.fields.sib == 0x09, "wrong MUL r/m32 SIB byte");
    CHECK(decoded.fields.disp == 0x3c47e, "wrong MUL r/m32 displacement");

    CHECK(fast_decoder_get_primary(mul, sizeof(mul), 0x30000, &info, 1),
          "primary MUL r/m32 indexed memory form must decode");
    CHECK(info.id == dt_X86_INS_MUL, "wrong primary MUL r/m32 id");
    CHECK(info.x86.operands[0].type == dt_X86_OP_MEM,
          "primary MUL r/m32 source must be memory");
    CHECK(info.x86.operands[0].size == 4,
          "primary MUL r/m32 source must stay dword-sized");
}

static void test_x87_fsave_restore(void)
{
    static const uint8_t fnsave_rip[] = {
        0xdd, 0x35, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t frstor_rip[] = {
        0xdd, 0x25, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t fnsave_abs[] = {
        0xdd, 0x34, 0x25, 0x00, 0x00, 0x05, 0x00,
    };
    static const uint8_t frstor_abs[] = {
        0xdd, 0x24, 0x25, 0x00, 0x00, 0x05, 0x00,
    };
    static const uint8_t fnsave_16_abs[] = {
        0x66, 0xdd, 0x34, 0x25, 0x00, 0x00, 0x05, 0x00,
    };
    static const uint8_t frstor_16_abs[] = {
        0x66, 0xdd, 0x24, 0x25, 0x00, 0x00, 0x05, 0x00,
    };
    static const uint8_t fnstsw_abs[] = {
        0xdd, 0x3c, 0x25, 0x44, 0x02, 0x02, 0x00,
    };
    static const uint8_t fst_st5[] = { 0xdd, 0xd5 };
    static const uint8_t faddp_st2[] = { 0xde, 0xc2 };
    static const uint8_t fsubr_st0_st3[] = { 0xd8, 0xeb };
    static const uint8_t fsubr_st1_st0[] = { 0xdc, 0xe1 };
    static const uint8_t fsub_m32[] = { 0xd8, 0x64, 0x24, 0x08 };
    static const uint8_t fsubr_m64[] = { 0xdc, 0x6c, 0x24, 0x08 };
    static const uint8_t fnop[] = { 0xd9, 0xd0 };
    static const uint8_t fstpnce_st2[] = { 0xd9, 0xda };
    static const uint8_t ffreep_st0[] = { 0xdf, 0xc0 };
    static const uint8_t fcomp_m32_r8_disp[] = {
        0x41, 0xd8, 0x98, 0x32, 0x01, 0x00, 0x00,
    };
    static const uint8_t fcomp_m64_r8_index[] = {
        0x42, 0xdc, 0x9c, 0x86, 0xc7, 0x98, 0x01, 0x00,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(fnsave_rip, sizeof(fnsave_rip), 0x30000, &matched);
    CHECK(matched, "FNSAVE m108 must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_HELPER_FNSAVE,
          "wrong FNSAVE template");
    CHECK(decoded.fields.id == dt_X86_INS_FNSAVE,
          "wrong FNSAVE instruction id");
    CHECK(decoded.fields.modrm_reg == 6,
          "wrong FNSAVE ModRM extension");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong FNSAVE displacement");

    decoded = decode(frstor_rip, sizeof(frstor_rip), 0x30000, &matched);
    CHECK(matched, "FRSTOR m108 must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_HELPER_FRSTOR,
          "wrong FRSTOR template");
    CHECK(decoded.fields.id == dt_X86_INS_FRSTOR,
          "wrong FRSTOR instruction id");
    CHECK(decoded.fields.modrm_reg == 4,
          "wrong FRSTOR ModRM extension");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong FRSTOR displacement");

    decoded = decode(fnsave_abs, sizeof(fnsave_abs), 0x415069, &matched);
    CHECK(matched, "FNSAVE m108 with absolute SIB addressing must decode");
    CHECK(decoded.fields.kind == FT_HELPER_FNSAVE,
          "wrong absolute FNSAVE template");
    CHECK(decoded.fields.sib == 0x25, "wrong FNSAVE SIB byte");
    CHECK(decoded.fields.disp == 0x50000,
          "wrong absolute FNSAVE displacement");

    decoded = decode(frstor_abs, sizeof(frstor_abs), 0x41549a, &matched);
    CHECK(matched, "FRSTOR m108 with absolute SIB addressing must decode");
    CHECK(decoded.fields.kind == FT_HELPER_FRSTOR,
          "wrong absolute FRSTOR template");
    CHECK(decoded.fields.sib == 0x25, "wrong FRSTOR SIB byte");
    CHECK(decoded.fields.disp == 0x50000,
          "wrong absolute FRSTOR displacement");

    decoded = decode(fnsave_16_abs, sizeof(fnsave_16_abs), 0x415069,
                     &matched);
    CHECK(matched, "FNSAVE m94 must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_HELPER_FNSAVE,
          "wrong FNSAVE m94 template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "FNSAVE m94 operand-size prefix was lost");

    decoded = decode(frstor_16_abs, sizeof(frstor_16_abs), 0x41549a,
                     &matched);
    CHECK(matched, "FRSTOR m94 must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_HELPER_FRSTOR,
          "wrong FRSTOR m94 template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "FRSTOR m94 operand-size prefix was lost");

    decoded = decode(fnstsw_abs, sizeof(fnstsw_abs), 0x415313, &matched);
    CHECK(matched, "FNSTSW m16 with absolute SIB addressing must decode");
    CHECK(decoded.fields.kind == FT_X87_FNSTSW_M16,
          "wrong FNSTSW template");
    CHECK(decoded.fields.id == dt_X86_INS_FNSTSW,
          "wrong FNSTSW instruction id");
    CHECK(decoded.fields.modrm_reg == 7,
          "wrong FNSTSW ModRM extension");
    CHECK(decoded.fields.sib == 0x25, "wrong FNSTSW SIB byte");
    CHECK(decoded.fields.disp == 0x20244,
          "wrong absolute FNSTSW displacement");

    decoded = decode(fst_st5, sizeof(fst_st5), 0x30000, &matched);
    CHECK(matched, "FST ST(5) must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_FST_REG,
          "wrong FST ST(i) template");
    CHECK(decoded.fields.id == dt_X86_INS_FST,
          "wrong FST ST(i) instruction id");
    CHECK(decoded.fields.modrm == 0xd5, "wrong FST ST(5) ModRM byte");

    decoded = decode(faddp_st2, sizeof(faddp_st2), 0x30000, &matched);
    CHECK(matched, "FADDP ST(2), ST(0) must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_FADDP,
          "wrong FADDP ST(i) template");
    CHECK(decoded.fields.id == dt_X86_INS_FADDP,
          "wrong FADDP ST(i) instruction id");
    CHECK(decoded.fields.modrm == 0xc2,
          "wrong FADDP ST(2) ModRM byte");

    decoded = decode(fsubr_st0_st3, sizeof(fsubr_st0_st3), 0x30000,
                     &matched);
    CHECK(matched, "FSUBR ST(0), ST(3) must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_BIN_REG,
          "wrong FSUBR ST(0), ST(i) template");
    CHECK(decoded.fields.id == dt_X86_INS_FSUBR,
          "wrong FSUBR ST(0), ST(i) instruction id");
    CHECK(decoded.fields.modrm == 0xeb,
          "wrong FSUBR ST(0), ST(3) ModRM byte");

    decoded = decode(fsubr_st1_st0, sizeof(fsubr_st1_st0), 0x30000,
                     &matched);
    CHECK(matched, "FSUBR ST(1), ST(0) must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_BIN_REG,
          "wrong FSUBR ST(i), ST(0) template");
    CHECK(decoded.fields.id == dt_X86_INS_FSUBR,
          "wrong FSUBR ST(i), ST(0) instruction id");
    CHECK(decoded.fields.modrm == 0xe1,
          "wrong FSUBR ST(1), ST(0) ModRM byte");

    decoded = decode(fsub_m32, sizeof(fsub_m32), 0x30000, &matched);
    CHECK(matched, "FSUB m32 must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_BIN_M32,
          "wrong x87 m32 arithmetic template");
    CHECK(decoded.fields.id == dt_X86_INS_FSUB,
          "wrong FSUB m32 instruction id");

    decoded = decode(fsubr_m64, sizeof(fsubr_m64), 0x30000, &matched);
    CHECK(matched, "FSUBR m64 must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_BIN_M64,
          "wrong x87 m64 arithmetic template");
    CHECK(decoded.fields.id == dt_X86_INS_FSUBR,
          "wrong FSUBR m64 instruction id");

    decoded = decode(fnop, sizeof(fnop), 0x30000, &matched);
    CHECK(matched, "FNOP must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_NOP_MULTI, "wrong FNOP template");
    CHECK(decoded.fields.id == dt_X86_INS_FNOP, "wrong FNOP instruction id");

    decoded = decode(fstpnce_st2, sizeof(fstpnce_st2), 0x30000,
                     &matched);
    CHECK(matched, "FSTPNCE ST(2) must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_FSTP_REG,
          "wrong FSTPNCE ST(i) template");
    CHECK(decoded.fields.id == dt_X86_INS_FSTPNCE,
          "wrong FSTPNCE instruction id");
    CHECK(decoded.fields.modrm == 0xda, "wrong FSTPNCE ModRM byte");

    decoded = decode(ffreep_st0, sizeof(ffreep_st0), 0x30000, &matched);
    CHECK(matched, "FFREEP ST(0) must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_FFREE,
          "wrong FFREEP ST(i) template");
    CHECK(decoded.fields.id == dt_X86_INS_FFREEP,
          "wrong FFREEP instruction id");
    CHECK(decoded.fields.modrm == 0xc0, "wrong FFREEP ModRM byte");

    decoded = decode(fcomp_m32_r8_disp, sizeof(fcomp_m32_r8_disp),
                     0x3000a, &matched);
    CHECK(matched, "FCOMP m32 with REX.B must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_FCOM_M32,
          "wrong FCOMP m32 template");
    CHECK(decoded.fields.id == dt_X86_INS_FCOMP,
          "wrong FCOMP m32 instruction id");
    CHECK(decoded.fields.modrm_reg == 3,
          "wrong FCOMP m32 ModRM extension");
    CHECK(decoded.fields.modrm_rm_index == 8,
          "FCOMP m32 REX.B base was lost");
    CHECK(decoded.fields.disp == 0x132,
          "wrong FCOMP m32 displacement");

    decoded = decode(fcomp_m64_r8_index, sizeof(fcomp_m64_r8_index),
                     0x30014, &matched);
    CHECK(matched,
          "FCOMP m64 with REX.X must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_FCOM_M64,
          "wrong FCOMP m64 template");
    CHECK(decoded.fields.id == dt_X86_INS_FCOMP,
          "wrong FCOMP m64 instruction id");
    CHECK(decoded.fields.modrm_reg == 3,
          "wrong FCOMP m64 ModRM extension");
    CHECK((decoded.fields.rex_bits & 0x02) != 0,
          "FCOMP m64 REX.X prefix was lost");
    CHECK(decoded.fields.sib == 0x86,
          "wrong FCOMP m64 SIB byte");
    CHECK(decoded.fields.disp == 0x198c7,
          "wrong FCOMP m64 displacement");
}

static void test_xsave_family(void)
{
    static const uint8_t xsave[] = { 0x0f, 0xae, 0x20 };
    static const uint8_t xrstor[] = { 0x0f, 0xae, 0x28 };
    static const uint8_t xsaveopt[] = { 0x0f, 0xae, 0x30 };
    static const uint8_t register_form[] = { 0x0f, 0xae, 0xe0 };
    static const uint8_t prefixed[] = { 0x66, 0x0f, 0xae, 0x20 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(xsave, sizeof(xsave), 0x30000, &matched);
    CHECK(matched, "XSAVE memory form must decode");
    CHECK(decoded.fields.kind == FT_HELPER_XSAVE,
          "wrong XSAVE template");
    CHECK(decoded.fields.id == dt_X86_INS_XSAVE,
          "wrong XSAVE instruction id");
    CHECK(!decoded.is_tb_ending, "XSAVE must not end the translation block");

    decoded = decode(xrstor, sizeof(xrstor), 0x30000, &matched);
    CHECK(matched, "XRSTOR memory form must decode");
    CHECK(decoded.fields.kind == FT_HELPER_XRSTOR,
          "wrong XRSTOR template");
    CHECK(decoded.fields.id == dt_X86_INS_XRSTOR,
          "wrong XRSTOR instruction id");
    CHECK(decoded.is_tb_ending, "XRSTOR must end the translation block");

    decoded = decode(xsaveopt, sizeof(xsaveopt), 0x30000, &matched);
    CHECK(matched, "XSAVEOPT memory form must decode");
    CHECK(decoded.fields.kind == FT_HELPER_XSAVEOPT,
          "wrong XSAVEOPT template");
    CHECK(decoded.fields.id == dt_X86_INS_XSAVEOPT,
          "wrong XSAVEOPT instruction id");
    CHECK(!decoded.is_tb_ending,
          "XSAVEOPT must not end the translation block");

    (void)decode(register_form, sizeof(register_form), 0x30000, &matched);
    CHECK(!matched, "XSAVE register form must reject");
    (void)decode(prefixed, sizeof(prefixed), 0x30000, &matched);
    CHECK(!matched, "XSAVE operand-size prefix must reject");
}

static void test_x87_fist_m16(void)
{
    static const uint8_t fist_m16[] = {
        0x66, 0x43, 0xdf, 0x94, 0x31, 0x61, 0x9c, 0x00, 0x00,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(fist_m16, sizeof(fist_m16), 0x30014, &matched);
    CHECK(matched, "FIST m16 indexed memory form must decode");
    CHECK(decoded.fields.kind == FT_X87_FIST_M16,
          "wrong FIST m16 template");
    CHECK(decoded.fields.id == dt_X86_INS_FIST,
          "wrong FIST m16 instruction id");
    CHECK(decoded.fields.size == sizeof(fist_m16),
          "wrong FIST m16 instruction size");
    CHECK(decoded.fields.modrm_reg == 2,
          "wrong FIST m16 ModRM extension");
    CHECK(decoded.fields.rex == 0x43,
          "FIST m16 REX.X/B prefix was lost");
    CHECK(decoded.fields.modrm_rm_index == 12,
          "wrong FIST m16 extended ModRM register");
    CHECK(decoded.fields.sib == 0x31, "wrong FIST m16 SIB byte");
    CHECK(decoded.fields.disp == 0x9c61,
          "wrong FIST m16 displacement");
}

static void test_x87_fisttp_m64(void)
{
    static const uint8_t fisttp_m64[] = {
        0xdd, 0x0d, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(fisttp_m64, sizeof(fisttp_m64), 0x30000, &matched);
    CHECK(matched, "FISTTP m64 must decode for the fast translator");
    CHECK(decoded.fields.kind == FT_X87_FISTTP_M64,
          "wrong FISTTP m64 template");
    CHECK(decoded.fields.id == dt_X86_INS_FISTTP,
          "wrong FISTTP m64 instruction id");
    CHECK(decoded.fields.size == sizeof(fisttp_m64),
          "wrong FISTTP m64 instruction size");
    CHECK(decoded.fields.modrm_reg == 1,
          "wrong FISTTP m64 ModRM extension");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong FISTTP m64 displacement");
}

static void test_lar(void)
{
    static const uint8_t reg32[] = { 0x0f, 0x02, 0xd0 };
    static const uint8_t reg16[] = { 0x66, 0x0f, 0x02, 0xd8 };
    static const uint8_t reg64_ext[] = { 0x4c, 0x0f, 0x02, 0xc0 };
    static const uint8_t rip_mem[] = {
        0x0f, 0x02, 0x0d, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg32, sizeof(reg32), 0x30000, &matched);
    CHECK(matched, "LAR r32, r16 must decode");
    CHECK(decoded.fields.kind == FT_LAR, "wrong LAR r32 template");
    CHECK(decoded.fields.id == dt_X86_INS_LAR, "wrong LAR instruction id");
    CHECK(decoded.fields.modrm_reg_index == 2, "wrong LAR r32 destination");
    CHECK(decoded.fields.modrm_rm_index == 0, "wrong LAR register source");

    decoded = decode(reg16, sizeof(reg16), 0x30000, &matched);
    CHECK(matched, "LAR r16, r16 must decode");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "LAR operand-size prefix was lost");

    decoded = decode(reg64_ext, sizeof(reg64_ext), 0x30000, &matched);
    CHECK(matched, "LAR r64, r16 must decode");
    CHECK(decoded.fields.rex_bits == 0x4c, "LAR REX.W/R bits were lost");
    CHECK(decoded.fields.modrm_reg_index == 8,
          "wrong LAR extended destination");

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "LAR r32, m16 must decode");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong LAR RIP-relative source");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong LAR RIP-relative displacement");
}

static void test_lsl(void)
{
    static const uint8_t reg32[] = { 0x0f, 0x03, 0xd0 };
    static const uint8_t reg16[] = { 0x66, 0x0f, 0x03, 0xd8 };
    static const uint8_t reg64_ext[] = { 0x4c, 0x0f, 0x03, 0xc0 };
    static const uint8_t rip_mem[] = {
        0x0f, 0x03, 0x0d, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg32, sizeof(reg32), 0x30000, &matched);
    CHECK(matched, "LSL r32, r16 must decode");
    CHECK(decoded.fields.kind == FT_LSL, "wrong LSL r32 template");
    CHECK(decoded.fields.id == dt_X86_INS_LSL, "wrong LSL instruction id");
    CHECK(decoded.fields.modrm_reg_index == 2, "wrong LSL r32 destination");
    CHECK(decoded.fields.modrm_rm_index == 0, "wrong LSL register source");

    decoded = decode(reg16, sizeof(reg16), 0x30000, &matched);
    CHECK(matched, "LSL r16, r16 must decode");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "LSL operand-size prefix was lost");

    decoded = decode(reg64_ext, sizeof(reg64_ext), 0x30000, &matched);
    CHECK(matched, "LSL r64, r16 must decode");
    CHECK(decoded.fields.rex_bits == 0x4c, "LSL REX.W/R bits were lost");
    CHECK(decoded.fields.modrm_reg_index == 8,
          "wrong LSL extended destination");

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "LSL r32, m16 must decode");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong LSL RIP-relative source");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong LSL RIP-relative displacement");
}

static void test_sgdt(void)
{
    static const uint8_t rip_mem[] = {
        0x0f, 0x01, 0x05, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t base_mem[] = {
        0x0f, 0x01, 0x44, 0x88, 0x20,
    };
    static const uint8_t reg[] = { 0x0f, 0x01, 0xc0 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "SGDT RIP-relative memory must decode");
    CHECK(decoded.fields.kind == FT_SGDT, "wrong SGDT RIP template");
    CHECK(decoded.fields.id == dt_X86_INS_SGDT, "wrong SGDT instruction id");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong SGDT RIP-relative destination");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong SGDT RIP-relative displacement");

    decoded = decode(base_mem, sizeof(base_mem), 0x30000, &matched);
    CHECK(matched, "SGDT base-index memory must decode");
    CHECK(decoded.fields.kind == FT_SGDT, "wrong SGDT base-index template");

    decode(reg, sizeof(reg), 0x30000, &matched);
    CHECK(!matched, "SGDT register form must reject");
}

static void test_lgdt(void)
{
    static const uint8_t rip_mem[] = {
        0x0f, 0x01, 0x15, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t base_mem[] = {
        0x0f, 0x01, 0x54, 0x88, 0x20,
    };
    static const uint8_t reg[] = { 0x0f, 0x01, 0xd0 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "LGDT RIP-relative memory must decode");
    CHECK(decoded.fields.kind == FT_LGDT, "wrong LGDT RIP template");
    CHECK(decoded.fields.id == dt_X86_INS_LGDT, "wrong LGDT instruction id");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong LGDT RIP-relative source");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong LGDT RIP-relative displacement");

    decoded = decode(base_mem, sizeof(base_mem), 0x30000, &matched);
    CHECK(matched, "LGDT base-index memory must decode");
    CHECK(decoded.fields.kind == FT_LGDT, "wrong LGDT base-index template");

    decoded = decode(reg, sizeof(reg), 0x30000, &matched);
    CHECK(!matched || decoded.fields.kind != FT_LGDT,
          "LGDT register form must not select LGDT");
}

static void test_lidt(void)
{
    static const uint8_t rip_mem[] = {
        0x0f, 0x01, 0x1d, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t base_mem[] = {
        0x0f, 0x01, 0x5c, 0x88, 0x20,
    };
    static const uint8_t reg[] = { 0x0f, 0x01, 0xd8 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "LIDT RIP-relative memory must decode");
    CHECK(decoded.fields.kind == FT_LIDT, "wrong LIDT RIP template");
    CHECK(decoded.fields.id == dt_X86_INS_LIDT, "wrong LIDT instruction id");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong LIDT RIP-relative source");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong LIDT RIP-relative displacement");

    decoded = decode(base_mem, sizeof(base_mem), 0x30000, &matched);
    CHECK(matched, "LIDT base-index memory must decode");
    CHECK(decoded.fields.kind == FT_LIDT, "wrong LIDT base-index template");

    decoded = decode(reg, sizeof(reg), 0x30000, &matched);
    CHECK(!matched || decoded.fields.kind != FT_LIDT,
          "LIDT register form must not select LIDT");
}

static void test_sidt(void)
{
    static const uint8_t rip_mem[] = {
        0x0f, 0x01, 0x0d, 0x78, 0x56, 0x34, 0x12,
    };
    static const uint8_t base_mem[] = {
        0x0f, 0x01, 0x4c, 0x88, 0x20,
    };
    static const uint8_t reg[] = { 0x0f, 0x01, 0xc8 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "SIDT RIP-relative memory must decode");
    CHECK(decoded.fields.kind == FT_SIDT, "wrong SIDT RIP template");
    CHECK(decoded.fields.id == dt_X86_INS_SIDT, "wrong SIDT instruction id");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong SIDT RIP-relative destination");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong SIDT RIP-relative displacement");

    decoded = decode(base_mem, sizeof(base_mem), 0x30000, &matched);
    CHECK(matched, "SIDT base-index memory must decode");
    CHECK(decoded.fields.kind == FT_SIDT, "wrong SIDT base-index template");
    CHECK(decoded.fields.modrm_mod == 1 && decoded.fields.modrm_rm == 4,
          "wrong SIDT base-index destination");

    decode(reg, sizeof(reg), 0x30000, &matched);
    CHECK(!matched, "SIDT register form must reject");
}

static void test_sldt(void)
{
    static const uint8_t reg16[] = { 0x66, 0x0f, 0x00, 0xc0 };
    static const uint8_t reg32[] = { 0x0f, 0x00, 0xc0 };
    static const uint8_t reg64[] = { 0x48, 0x0f, 0x00, 0xc0 };
    static const uint8_t rip_mem[] = {
        0x0f, 0x00, 0x05, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg16, sizeof(reg16), 0x30000, &matched);
    CHECK(matched, "SLDT r16 must decode");
    CHECK(decoded.fields.kind == FT_SLDT, "wrong SLDT r16 template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "SLDT r16 must retain operand-size prefix");

    decoded = decode(reg32, sizeof(reg32), 0x30000, &matched);
    CHECK(matched, "SLDT r32 must decode");
    CHECK(decoded.fields.kind == FT_SLDT, "wrong SLDT r32 template");

    decoded = decode(reg64, sizeof(reg64), 0x30000, &matched);
    CHECK(matched, "SLDT r64 must decode");
    CHECK(decoded.fields.kind == FT_SLDT, "wrong SLDT r64 template");
    CHECK((decoded.fields.rex_bits & 8) != 0,
          "SLDT r64 must retain REX.W");

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "SLDT m16 must decode");
    CHECK(decoded.fields.kind == FT_SLDT, "wrong SLDT memory template");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong SLDT RIP-relative destination");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong SLDT RIP-relative displacement");
}

static void test_lldt(void)
{
    static const uint8_t reg[] = { 0x0f, 0x00, 0xd0 };
    static const uint8_t rip_mem[] = {
        0x0f, 0x00, 0x15, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg, sizeof(reg), 0x30000, &matched);
    CHECK(matched, "LLDT r16 must decode");
    CHECK(decoded.fields.kind == FT_LLDT, "wrong LLDT register template");
    CHECK(decoded.fields.id == dt_X86_INS_LLDT, "wrong LLDT instruction id");
    CHECK(decoded.fields.modrm_rm_index == 0, "wrong LLDT register source");

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "LLDT m16 must decode");
    CHECK(decoded.fields.kind == FT_LLDT, "wrong LLDT memory template");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong LLDT RIP-relative source");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong LLDT RIP-relative displacement");
}

static void test_ltr(void)
{
    static const uint8_t reg[] = { 0x0f, 0x00, 0xd8 };
    static const uint8_t rip_mem[] = {
        0x0f, 0x00, 0x1d, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg, sizeof(reg), 0x30000, &matched);
    CHECK(matched, "LTR r16 must decode");
    CHECK(decoded.fields.kind == FT_LTR, "wrong LTR register template");
    CHECK(decoded.fields.id == dt_X86_INS_LTR, "wrong LTR instruction id");
    CHECK(decoded.fields.modrm_rm_index == 0, "wrong LTR register source");

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "LTR m16 must decode");
    CHECK(decoded.fields.kind == FT_LTR, "wrong LTR memory template");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong LTR RIP-relative source");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong LTR RIP-relative displacement");
}

static void test_clts(void)
{
    static const uint8_t insn[] = { 0x0f, 0x06 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(insn, sizeof(insn), 0x30000, &matched);
    CHECK(matched, "CLTS must decode");
    CHECK(decoded.fields.kind == FT_CLTS, "wrong CLTS template");
    CHECK(decoded.fields.id == dt_X86_INS_CLTS, "wrong CLTS instruction id");
    CHECK(decoded.fields.size == sizeof(insn), "wrong CLTS instruction size");
    CHECK(decoded.is_tb_ending, "CLTS must end the translation block");
}

static void test_rsm(void)
{
    static const uint8_t insn[] = { 0x0f, 0xaa };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(insn, sizeof(insn), 0x30000, &matched);
    CHECK(matched, "RSM must decode");
    CHECK(decoded.fields.kind == FT_RSM, "wrong RSM template");
    CHECK(decoded.fields.id == dt_X86_INS_RSM, "wrong RSM instruction id");
    CHECK(decoded.fields.size == sizeof(insn), "wrong RSM instruction size");
    CHECK(decoded.is_tb_ending, "RSM must end the translation block");
}

static void test_invd(void)
{
    static const uint8_t insn[] = { 0x0f, 0x08 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(insn, sizeof(insn), 0x30000, &matched);
    CHECK(matched, "INVD must decode");
    CHECK(decoded.fields.kind == FT_INVD, "wrong INVD template");
    CHECK(decoded.fields.id == dt_X86_INS_INVD, "wrong INVD instruction id");
    CHECK(decoded.fields.size == sizeof(insn), "wrong INVD instruction size");
}

static void test_wbinvd(void)
{
    static const uint8_t insn[] = { 0x0f, 0x09 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(insn, sizeof(insn), 0x30000, &matched);
    CHECK(matched, "WBINVD must decode");
    CHECK(decoded.fields.kind == FT_WBINVD, "wrong WBINVD template");
    CHECK(decoded.fields.id == dt_X86_INS_WBINVD,
          "wrong WBINVD instruction id");
    CHECK(decoded.fields.size == sizeof(insn),
          "wrong WBINVD instruction size");
}

static void test_invlpg(void)
{
    static const uint8_t mem[] = {
        0x0f, 0x01, 0x7c, 0x24, 0x08,
    };
    static const uint8_t swapgs[] = { 0x0f, 0x01, 0xf8 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(mem, sizeof(mem), 0x30000, &matched);
    CHECK(matched, "INVLPG m8 must decode");
    CHECK(decoded.fields.kind == FT_INVLPG, "wrong INVLPG template");
    CHECK(decoded.fields.id == dt_X86_INS_INVLPG,
          "wrong INVLPG instruction id");
    CHECK(decoded.fields.modrm_mod == 1 && decoded.fields.modrm_reg == 7,
          "wrong INVLPG ModRM fields");
    CHECK(decoded.fields.disp == 8, "wrong INVLPG displacement");
    CHECK(decoded.is_tb_ending, "INVLPG must end the translation block");

    decoded = decode(swapgs, sizeof(swapgs), 0x30000, &matched);
    CHECK(!matched || decoded.fields.kind != FT_INVLPG,
          "INVLPG must not consume SWAPGS encoding");
}

static void test_rdpmc(void)
{
    static const uint8_t insn[] = { 0x0f, 0x33 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(insn, sizeof(insn), 0x30000, &matched);
    CHECK(matched, "RDPMC must decode");
    CHECK(decoded.fields.kind == FT_RDPMC, "wrong RDPMC template");
    CHECK(decoded.fields.id == dt_X86_INS_RDPMC,
          "wrong RDPMC instruction id");
    CHECK(decoded.fields.size == sizeof(insn),
          "wrong RDPMC instruction size");
}

static void test_rdmsr(void)
{
    static const uint8_t insn[] = { 0x0f, 0x32 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(insn, sizeof(insn), 0x30000, &matched);
    CHECK(matched, "RDMSR must decode");
    CHECK(decoded.fields.kind == FT_RDMSR, "wrong RDMSR template");
    CHECK(decoded.fields.id == dt_X86_INS_RDMSR,
          "wrong RDMSR instruction id");
    CHECK(decoded.fields.size == sizeof(insn),
          "wrong RDMSR instruction size");
}

static void test_wrmsr(void)
{
    static const uint8_t insn[] = { 0x0f, 0x30 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(insn, sizeof(insn), 0x30000, &matched);
    CHECK(matched, "WRMSR must decode");
    CHECK(decoded.fields.kind == FT_WRMSR, "wrong WRMSR template");
    CHECK(decoded.fields.id == dt_X86_INS_WRMSR,
          "wrong WRMSR instruction id");
    CHECK(decoded.fields.size == sizeof(insn),
          "wrong WRMSR instruction size");
    CHECK(decoded.is_tb_ending, "WRMSR must end the translation block");
}

static void test_swapgs(void)
{
    static const uint8_t insn[] = { 0x0f, 0x01, 0xf8 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(insn, sizeof(insn), 0x30000, &matched);
    CHECK(matched, "SWAPGS must decode");
    CHECK(decoded.fields.kind == FT_SWAPGS, "wrong SWAPGS template");
    CHECK(decoded.fields.id == dt_X86_INS_SWAPGS,
          "wrong SWAPGS instruction id");
    CHECK(decoded.fields.size == sizeof(insn),
          "wrong SWAPGS instruction size");
}

static void test_lfs(void)
{
    static const uint8_t lfs32[] = { 0x0f, 0xb4, 0x03 };
    static const uint8_t lfs16[] = { 0x66, 0x0f, 0xb4, 0x4b, 0x06 };
    static const uint8_t reg_form[] = { 0x0f, 0xb4, 0xc3 };
    static const uint8_t lfs64[] = { 0x48, 0x0f, 0xb4, 0x03 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(lfs32, sizeof(lfs32), 0x30000, &matched);
    CHECK(matched, "LFS r32,m16:32 must decode");
    CHECK(decoded.fields.kind == FT_LFS, "wrong LFS template");
    CHECK(decoded.fields.id == dt_X86_INS_LFS,
          "wrong LFS instruction id");
    CHECK(decoded.fields.modrm_reg_index == 0,
          "wrong LFS destination register");

    decoded = decode(lfs16, sizeof(lfs16), 0x30000, &matched);
    CHECK(matched, "LFS r16,m16:16 must decode");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "LFS operand-size prefix was lost");
    CHECK(decoded.fields.size == sizeof(lfs16),
          "wrong LFS instruction size");

    (void)decode(reg_form, sizeof(reg_form), 0x30000, &matched);
    CHECK(!matched, "LFS register source must be rejected");
    (void)decode(lfs64, sizeof(lfs64), 0x30000, &matched);
    CHECK(!matched, "LFS REX.W form is not supported by the old path");
}

static void test_lgs(void)
{
    static const uint8_t lgs32[] = { 0x0f, 0xb5, 0x13 };
    static const uint8_t lgs16[] = { 0x66, 0x0f, 0xb5, 0x53, 0x06 };
    static const uint8_t reg_form[] = { 0x0f, 0xb5, 0xd3 };
    static const uint8_t lgs64[] = { 0x48, 0x0f, 0xb5, 0x13 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(lgs32, sizeof(lgs32), 0x30000, &matched);
    CHECK(matched, "LGS r32,m16:32 must decode");
    CHECK(decoded.fields.kind == FT_LGS, "wrong LGS template");
    CHECK(decoded.fields.id == dt_X86_INS_LGS,
          "wrong LGS instruction id");
    CHECK(decoded.fields.modrm_reg_index == 2,
          "wrong LGS destination register");

    decoded = decode(lgs16, sizeof(lgs16), 0x30000, &matched);
    CHECK(matched, "LGS r16,m16:16 must decode");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "LGS operand-size prefix was lost");
    CHECK(decoded.fields.size == sizeof(lgs16),
          "wrong LGS instruction size");

    (void)decode(reg_form, sizeof(reg_form), 0x30000, &matched);
    CHECK(!matched, "LGS register source must be rejected");
    (void)decode(lgs64, sizeof(lgs64), 0x30000, &matched);
    CHECK(!matched, "LGS REX.W form is not supported by the old path");
}

static void test_lss(void)
{
    static const uint8_t lss32[] = { 0x0f, 0xb2, 0x13 };
    static const uint8_t lss16[] = { 0x66, 0x0f, 0xb2, 0x53, 0x06 };
    static const uint8_t reg_form[] = { 0x0f, 0xb2, 0xd3 };
    static const uint8_t lss64[] = { 0x48, 0x0f, 0xb2, 0x13 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(lss32, sizeof(lss32), 0x30000, &matched);
    CHECK(matched, "LSS r32,m16:32 must decode");
    CHECK(decoded.fields.kind == FT_LSS, "wrong LSS template");
    CHECK(decoded.fields.id == dt_X86_INS_LSS,
          "wrong LSS instruction id");
    CHECK(decoded.is_tb_ending, "LSS must end the translation block");

    decoded = decode(lss16, sizeof(lss16), 0x30000, &matched);
    CHECK(matched, "LSS r16,m16:16 must decode");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "LSS operand-size prefix was lost");
    CHECK(decoded.fields.size == sizeof(lss16),
          "wrong LSS instruction size");

    (void)decode(reg_form, sizeof(reg_form), 0x30000, &matched);
    CHECK(!matched, "LSS register source must be rejected");
    (void)decode(lss64, sizeof(lss64), 0x30000, &matched);
    CHECK(!matched, "LSS REX.W form is not supported by the old path");
}

static void test_clac(void)
{
    static const uint8_t clac[] = { 0x0f, 0x01, 0xca };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(clac, sizeof(clac), 0x30000, &matched);
    CHECK(matched, "CLAC must decode");
    CHECK(decoded.fields.kind == FT_CLAC, "wrong CLAC template");
    CHECK(decoded.fields.id == dt_X86_INS_CLAC,
          "wrong CLAC instruction id");
    CHECK(decoded.fields.size == sizeof(clac), "wrong CLAC size");
}

static void test_stac(void)
{
    static const uint8_t stac[] = { 0x0f, 0x01, 0xcb };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(stac, sizeof(stac), 0x30000, &matched);
    CHECK(matched, "STAC must decode");
    CHECK(decoded.fields.kind == FT_STAC, "wrong STAC template");
    CHECK(decoded.fields.id == dt_X86_INS_STAC,
          "wrong STAC instruction id");
    CHECK(decoded.fields.size == sizeof(stac), "wrong STAC size");
}

static void test_sysenter(void)
{
    static const uint8_t sysenter[] = { 0x0f, 0x34 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(sysenter, sizeof(sysenter), 0x30000, &matched);
    CHECK(matched, "SYSENTER must decode");
    CHECK(decoded.fields.kind == FT_HELPER_SYSENTER,
          "wrong SYSENTER template");
    CHECK(decoded.fields.id == dt_X86_INS_SYSENTER,
          "wrong SYSENTER instruction id");
    CHECK(decoded.is_tb_ending, "SYSENTER must end the translation block");
}

static void test_sysexit(void)
{
    static const uint8_t sysexit32[] = { 0x0f, 0x35 };
    static const uint8_t sysexit16[] = { 0x66, 0x0f, 0x35 };
    static const uint8_t sysexit64[] = { 0x48, 0x0f, 0x35 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(sysexit32, sizeof(sysexit32), 0x30000, &matched);
    CHECK(matched, "SYSEXIT default form must decode");
    CHECK(decoded.fields.kind == FT_HELPER_SYSEXIT,
          "wrong SYSEXIT template");
    CHECK(decoded.fields.id == dt_X86_INS_SYSEXIT,
          "wrong SYSEXIT instruction id");
    CHECK(decoded.is_tb_ending, "SYSEXIT must end the translation block");

    decoded = decode(sysexit16, sizeof(sysexit16), 0x30000, &matched);
    CHECK(matched, "SYSEXIT 16-bit form must decode");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "SYSEXIT operand-size prefix was lost");

    (void)decode(sysexit64, sizeof(sysexit64), 0x30000, &matched);
    CHECK(!matched, "SYSEXIT REX.W form is not supported by the old path");
}

static void test_sysret(void)
{
    static const uint8_t sysret32[] = { 0x0f, 0x07 };
    static const uint8_t sysret16[] = { 0x66, 0x0f, 0x07 };
    static const uint8_t sysret64[] = { 0x48, 0x0f, 0x07 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(sysret32, sizeof(sysret32), 0x30000, &matched);
    CHECK(matched, "SYSRET default form must decode");
    CHECK(decoded.fields.kind == FT_HELPER_SYSRET,
          "wrong SYSRET template");
    CHECK(decoded.fields.id == dt_X86_INS_SYSRET,
          "wrong SYSRET instruction id");
    CHECK(decoded.is_tb_ending, "SYSRET must end the translation block");

    decoded = decode(sysret16, sizeof(sysret16), 0x30000, &matched);
    CHECK(matched, "SYSRET 16-bit form must decode");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "SYSRET operand-size prefix was lost");

    decoded = decode(sysret64, sizeof(sysret64), 0x30000, &matched);
    CHECK(matched, "SYSRET REX.W form must decode");
    CHECK((decoded.fields.rex_bits & 8) != 0,
          "SYSRET REX.W bit was lost");
}

static void test_str(void)
{
    static const uint8_t reg16[] = { 0x66, 0x0f, 0x00, 0xc8 };
    static const uint8_t reg32[] = { 0x0f, 0x00, 0xc8 };
    static const uint8_t reg64[] = { 0x48, 0x0f, 0x00, 0xc8 };
    static const uint8_t rip_mem[] = {
        0x0f, 0x00, 0x0d, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg16, sizeof(reg16), 0x30000, &matched);
    CHECK(matched, "STR r16 must decode");
    CHECK(decoded.fields.kind == FT_STR, "wrong STR template");
    CHECK(decoded.fields.id == dt_X86_INS_STR, "wrong STR instruction id");
    CHECK(decoded.fields.modrm_rm_index == 0, "wrong STR register destination");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "STR r16 must retain operand-size prefix");

    decoded = decode(reg32, sizeof(reg32), 0x30000, &matched);
    CHECK(matched, "STR r32 must decode");
    CHECK(decoded.fields.kind == FT_STR, "wrong STR r32 template");
    CHECK(decoded.fields.prefix2 != dt_X86_PREFIX_OPSIZE,
          "STR r32 must use default operand size");

    decoded = decode(reg64, sizeof(reg64), 0x30000, &matched);
    CHECK(matched, "STR r64 must decode");
    CHECK(decoded.fields.kind == FT_STR, "wrong STR r64 template");
    CHECK((decoded.fields.rex_bits & 8) != 0,
          "STR r64 must retain REX.W");

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "STR m16 must decode");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong STR RIP-relative destination");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong STR RIP-relative displacement");
}

static void test_smsw(void)
{
    static const uint8_t reg16[] = { 0x66, 0x0f, 0x01, 0xe0 };
    static const uint8_t reg32[] = { 0x0f, 0x01, 0xe0 };
    static const uint8_t reg64[] = { 0x48, 0x0f, 0x01, 0xe0 };
    static const uint8_t rip_mem[] = {
        0x0f, 0x01, 0x25, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg16, sizeof(reg16), 0x30000, &matched);
    CHECK(matched, "SMSW r16 must decode");
    CHECK(decoded.fields.kind == FT_SMSW, "wrong SMSW r16 template");
    CHECK(decoded.fields.prefix2 == dt_X86_PREFIX_OPSIZE,
          "SMSW r16 must retain operand-size prefix");

    decoded = decode(reg32, sizeof(reg32), 0x30000, &matched);
    CHECK(matched, "SMSW r32 must decode");
    CHECK(decoded.fields.kind == FT_SMSW, "wrong SMSW r32 template");

    decoded = decode(reg64, sizeof(reg64), 0x30000, &matched);
    CHECK(matched, "SMSW r64 must decode");
    CHECK(decoded.fields.kind == FT_SMSW, "wrong SMSW r64 template");
    CHECK((decoded.fields.rex_bits & 8) != 0,
          "SMSW r64 must retain REX.W");

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "SMSW m16 must decode");
    CHECK(decoded.fields.kind == FT_SMSW, "wrong SMSW memory template");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong SMSW RIP-relative destination");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong SMSW RIP-relative displacement");
}

static void test_verr(void)
{
    static const uint8_t reg[] = { 0x0f, 0x00, 0xe0 };
    static const uint8_t rip_mem[] = {
        0x0f, 0x00, 0x25, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg, sizeof(reg), 0x30000, &matched);
    CHECK(matched, "VERR r16 must decode");
    CHECK(decoded.fields.kind == FT_VERR, "wrong VERR template");
    CHECK(decoded.fields.id == dt_X86_INS_VERR, "wrong VERR instruction id");
    CHECK(decoded.fields.modrm_rm_index == 0, "wrong VERR register source");

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "VERR m16 must decode");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong VERR RIP-relative source");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong VERR RIP-relative displacement");
}

static void test_verw(void)
{
    static const uint8_t reg[] = { 0x0f, 0x00, 0xe8 };
    static const uint8_t rip_mem[] = {
        0x0f, 0x00, 0x2d, 0x78, 0x56, 0x34, 0x12,
    };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(reg, sizeof(reg), 0x30000, &matched);
    CHECK(matched, "VERW r16 must decode");
    CHECK(decoded.fields.kind == FT_VERW, "wrong VERW template");
    CHECK(decoded.fields.id == dt_X86_INS_VERW, "wrong VERW instruction id");
    CHECK(decoded.fields.modrm_rm_index == 0, "wrong VERW register source");

    decoded = decode(rip_mem, sizeof(rip_mem), 0x30000, &matched);
    CHECK(matched, "VERW m16 must decode");
    CHECK(decoded.fields.modrm_mod == 0 && decoded.fields.modrm_rm == 5,
          "wrong VERW RIP-relative source");
    CHECK(decoded.fields.disp == 0x12345678,
          "wrong VERW RIP-relative displacement");
}

static void test_rejects(void)
{
    static const uint8_t truncated_rex[] = { 0x48 };
    static const uint8_t truncated_modrm[] = { 0x48, 0x8b };
    static const uint8_t truncated_group1_modrm[] = { 0x83 };
    static const uint8_t truncated_group1_imm[] = { 0x83, 0xc0 };
    static const uint8_t truncated_near_jcc[] = { 0x0f, 0x85, 0x00 };
    static const uint8_t truncated_short_jmp[] = { 0xeb };
    static const uint8_t truncated_ret_imm[] = { 0xc2, 0x08 };
    static const uint8_t unsupported[] = { 0x62 };
    FastDecodedFT decoded;
    int matched;

    decoded = decode(truncated_rex, sizeof(truncated_rex), 0x1000, &matched);
    (void)decoded;
    CHECK(!matched, "truncated REX must reject");

    decoded = decode(truncated_modrm, sizeof(truncated_modrm), 0x1000,
                     &matched);
    CHECK(!matched, "truncated ModRM must reject");

    decoded = decode(truncated_group1_modrm,
                     sizeof(truncated_group1_modrm), 0x1000, &matched);
    CHECK(!matched, "truncated Group-1 ModRM must reject");

    decoded = decode(truncated_group1_imm,
                     sizeof(truncated_group1_imm), 0x1000, &matched);
    CHECK(!matched, "truncated Group-1 immediate must reject");

    decoded = decode(truncated_near_jcc, sizeof(truncated_near_jcc), 0x1000,
                     &matched);
    CHECK(!matched, "truncated near JCC must reject");

    decoded = decode(truncated_short_jmp, sizeof(truncated_short_jmp), 0x1000,
                     &matched);
    CHECK(!matched, "truncated short JMP must reject");

    decoded = decode(truncated_ret_imm, sizeof(truncated_ret_imm), 0x1000,
                     &matched);
    CHECK(!matched, "truncated RET immediate must reject");

    decoded = decode(unsupported, sizeof(unsupported), 0x1000, &matched);
    CHECK(!matched, "unsupported opcode must reject");
}

/* Fetch-window reuse may expose every partial displacement length. */
static void test_sse_partial_displacements(void)
{
    static const struct { uint8_t code[10]; size_t size; } cases[] = {
        {{0x66,0x41,0x0f,0x12,0x86,0x78,0xff,0xff,0xff},9},
        {{0x66,0x0f,0x13,0x85,0x78,0xff,0xff,0xff},8},
        {{0x66,0x48,0x0f,0x6e,0x85,0x78,0xff,0xff,0xff},9},
        {{0x66,0x0f,0x7e,0x45,0x78},5},
        {{0x66,0x0f,0x63,0x05,0x78,0xff,0xff,0xff},8},
        {{0x66,0x0f,0x67,0x04,0x25,0x78,0xff,0xff,0xff},9},
        {{0x66,0x0f,0x6b,0x85,0x78,0xff,0xff,0xff},8},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        int matched;
        FastDecodedFT decoded = decode(cases[i].code, cases[i].size,
                                        0x404738, &matched);
        CHECK(matched, "complete SSE displacement must decode");
        CHECK(decoded.fields.size == cases[i].size,
              "complete SSE instruction length changed");
        for (size_t n = 1; n < cases[i].size; ++n) {
            decode(cases[i].code, n, 0x404738, &matched);
            CHECK(!matched, "incomplete SSE displacement must reject");
        }
    }
}

/* Reused output must publish complete status on both success and rejection. */
static void check_ft_status(const FastDecodedFT *decoded, bool matched,
                            bool terminal)
{
    CHECK((decoded->tmpl != NULL) == matched, "wrong reused template status");
    CHECK(decoded->fields_valid == matched, "wrong reused fields_valid");
    CHECK(decoded->is_tb_ending == terminal, "wrong reused TB-ending status");
    CHECK(decoded->direct_fields == matched, "wrong reused direct_fields");
    CHECK(decoded->field_source == (matched ? FT_FIELD_SOURCE_SPECIALIZED :
                                            FT_FIELD_SOURCE_NONE),
          "wrong reused field_source");
}

static void test_ft_reused_status(void)
{
    static const struct {
        uint8_t code[8];
        size_t size;
        bool terminal;
    } success[] = {
        {{0x89,0xd8},2,false},            /* hot GPR, both guest modes */
        {{0x75,0xfe},2,true},            /* hot control */
        {{0x83,0xc0,0x01},3,false},      /* general GPR */
        {{0x0f,0x01,0xd1},3,true},       /* control: XSETBV */
        {{0xd9,0xe8},2,false},           /* x87: FLD1 */
        {{0x66,0x0f,0xef,0xc0},4,false}, /* SSE: PXOR */
        {{0x66,0x0f,0x38,0x0b,0xc0},5,false}, /* three-byte PMULHRSW */
        {{0xc4,0xe2,0x78,0xf3,0xc9},5,false}, /* VEX BLSR */
    };
    static const struct {
        uint8_t code[8];
        size_t size;
        bool mode64_only;
    } reject[] = {
        {{0},0}, {{0x48},1,true}, {{0x48,0x8b},2,true},
        {{0x83},1}, {{0x83,0xc0},2}, {{0x0f,0x85,0},3},
        {{0xeb},1}, {{0xc2,0x08},2}, {{0x62},1},
        {{0x66,0x0f,0x01,0xd1},4}, /* illegal XSETBV prefix */
        {{0x48,0x0f,0x01,0xd1},4,true},
        {{0x66,0x0f,0x38},3}, {{0xc4,0xe2,0x78},3},
    };
    const unsigned char poison[] = {0xa5, 0x5a};

    for (int mode = 0; mode <= 1; ++mode) {
        for (size_t p = 0; p < sizeof(poison); ++p) {
            for (size_t i = 0; i < sizeof(success)/sizeof(success[0]); ++i) {
                if (i == 7 && !mode) {
                    continue; /* VEX BLSR fixture is supported in 64-bit mode. */
                }
                FastDecodedFT clean = {0}, reused;
                int matched = fast_decoder_get_ft(success[i].code,
                    success[i].size, 0x1000, &clean, mode);
                if (!matched) {
                    fprintf(stderr, "status fixture %zu mode %d rejected\n", i, mode);
                }
                CHECK(matched, "status success fixture must decode");
                check_ft_status(&clean, true, success[i].terminal);
                memset(&reused, poison[p], sizeof(reused));
                for (size_t j = 0; j < sizeof(reject)/sizeof(reject[0]); ++j) {
                    /* 0x48 is DEC EAX, not a REX prefix, in 32-bit mode. */
                    if (reject[j].mode64_only && !mode) {
                        continue;
                    }
                    matched = fast_decoder_get_ft(success[i].code,
                        success[i].size, 0x1000, &reused, mode);
                    CHECK(matched, "poisoned/reused success must decode");
                    check_ft_status(&reused, true, success[i].terminal);
                    CHECK(reused.tmpl == clean.tmpl &&
                          reused.fields.kind == clean.fields.kind &&
                          reused.fields.id == clean.fields.id &&
                          reused.fields.size == clean.fields.size &&
                          reused.fields.address == clean.fields.address,
                          "reusing output changed successful decode");
                    matched = fast_decoder_get_ft(reject[j].code,
                        reject[j].size, 0x1000, &reused, mode);
                    CHECK(!matched, "reused invalid input must reject");
                    check_ft_status(&reused, false, false);
                }
                matched = fast_decoder_get_ft(success[i].code,
                    success[i].size, 0x1000, &reused, mode);
                CHECK(matched, "success after final failure must decode");
                check_ft_status(&reused, true, success[i].terminal);
            }
            for (size_t j = 0; j < sizeof(reject)/sizeof(reject[0]); ++j) {
                /* 0x48 is DEC EAX, not a REX prefix, in 32-bit mode. */
                if (reject[j].mode64_only && !mode) {
                    continue;
                }
                FastDecodedFT decoded;
                memset(&decoded, poison[p], sizeof(decoded));
                CHECK(!fast_decoder_get_ft(reject[j].code, reject[j].size,
                      0x1000, &decoded, mode), "poisoned invalid input must reject");
                check_ft_status(&decoded, false, false);
            }
        }
    }
}

int main(void)
{
    test_ft_reused_status();
    test_default_32bit_address_size();
    test_sse_partial_displacements();
    test_hot_gpr();
    test_mov_imm8_rex_registers();
    test_mov_moffs();
    test_hot_control();
    test_legacy_control_helpers();
    test_legacy_32bit_instructions();
    test_bndmov();
    test_prefetch();
    test_legacy_nop_instructions();
    test_string_io();
    test_xsetbv();
    test_ud0();
    test_ud1();
    test_remaining_hot_paths();
    test_segment_push_pop();
    test_mov_segment_register();
    test_hot_group1_immediate();
    test_prefix_fallback();
    test_mmx_packssdw_rexw();
    test_mmx_phadd_sub_rexw();
    test_mmx_ssse3_rexw();
    test_mmx_palignr_rexw();
    test_pmulhrsw_xmm_memory();
    test_xmm_qword_shift_large_count();
    test_pdep();
    test_mmx_pextrw_rexw();
    test_sse41_pextrw_extended_registers();
    test_sse41_pextrw_memory_destination();
    test_pextr_memory_destinations();
    test_lea_r16_addr32();
    test_lea_r64_addr32();
    test_movsx_r16_memory();
    test_movsxd_non_rex_widths();
    test_movq_xmmm64_xmm_register();
    test_cvttps2pi_mmx_rexwx_memory();
    test_xchg_rm16_r16_lock_rexr_memory();
    test_xchg_rm16_r16_rexr_register();
    test_cmpsd_nlt_rexrx_memory();
    test_xlatb_ignored_opsize_prefix();
    test_mmx_pmovmskb_rexr();
    test_mmx_pand_rexwb_memory();
    test_mmx_psrad_rexw();
    test_mmx_paddq_rexw();
    test_mmx_movq_r64();
    test_movq_xmm_rm64_rexwx_memory();
    test_idiv_rm8();
    test_idiv_rm16();
    test_div_rm8();
    test_pinsrw_mmx_memory();
    test_mmx_psrld_rexw_memory();
    test_mmx_pmaxub_rexw_memory();
    test_mmx_pmulhuw_rexw_memory();
    test_mmx_pslld_rexw_memory();
    test_mmx_paddb_rexw();
    test_blsr_r32();
    test_mul_r16_rexb();
    test_mul_rm32_rexx_rexb_memory();
    test_x87_fsave_restore();
    test_xsave_family();
    test_x87_fist_m16();
    test_x87_fisttp_m64();
    test_lar();
    test_lsl();
    test_lgdt();
    test_lidt();
    test_sgdt();
    test_sidt();
    test_lldt();
    test_ltr();
    test_clts();
    test_rsm();
    test_invd();
    test_wbinvd();
    test_invlpg();
    test_rdpmc();
    test_rdmsr();
    test_wrmsr();
    test_swapgs();
    test_lfs();
    test_lgs();
    test_lss();
    test_clac();
    test_stac();
    test_sysenter();
    test_sysexit();
    test_sysret();
    test_sldt();
    test_str();
    test_smsw();
    test_verr();
    test_verw();
    test_rejects();
    return failures != 0;
}
