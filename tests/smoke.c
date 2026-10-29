/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */
#include "quicktrans/emitter.h"
#include "quicktrans/detail/fast-template.h"
#include "quicktrans/detail/x86.h"
#include "quicktrans/quicktrans.h"
#include "quicktrans/stats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int expect_ok(QuickTransStatus status, const char *what)
{
    if (status != QUICKTRANS_OK) {
        fprintf(stderr, "%s failed: %s\n", what,
                quicktrans_status_name(status));
        return 1;
    }
    return 0;
}

static int expect_stats_output(void)
{
    static const uint8_t sample_bytes[] = { 0x48, 0x89, 0xd8 };
    QuickTransFailure failure;
    QuickTransStats *stats;
    QuickTransStats *env_stats;
    FILE *stream;
    struct stat stream_stat;
    char output[8192];
    size_t output_size;

    setenv(QUICKTRANS_STATS_ENV, "0", 1);
    if (quicktrans_stats_requested()) {
        fprintf(stderr, "stats request accepted an explicit zero value\n");
        return 1;
    }
    env_stats = quicktrans_stats_create_from_env();
    if (env_stats != NULL) {
        fprintf(stderr, "stats were enabled for an explicit zero value\n");
        return 1;
    }
    setenv(QUICKTRANS_STATS_ENV, "1", 1);
    if (!quicktrans_stats_requested()) {
        fprintf(stderr, "stats request rejected an explicit one value\n");
        return 1;
    }
    env_stats = quicktrans_stats_create_from_env();
    if (env_stats == NULL) {
        fprintf(stderr, "stats were not enabled for an explicit one value\n");
        return 1;
    }
    quicktrans_stats_destroy(env_stats);

    stats = quicktrans_stats_create(2);
    stream = tmpfile();
    if (stats == NULL || stream == NULL) {
        fprintf(stderr, "could not allocate stats test state\n");
        quicktrans_stats_destroy(stats);
        if (stream != NULL) {
            fclose(stream);
        }
        return 1;
    }

    quicktrans_stats_record(stats, QUICKTRANS_STATS_OUTCOME_SUCCESS, NULL);
    quicktrans_failure_record(
        &failure, QUICKTRANS_FAILURE_STAGE_DECODE,
        QUICKTRANS_FAILURE_REASON_DECODE_FAILED, 0x5000, sample_bytes,
        sizeof(sample_bytes), 17, 23, 0);
    quicktrans_stats_record(stats, QUICKTRANS_STATS_OUTCOME_FALLBACK,
                            &failure);
    failure.pc = 0x5003;
    failure.instruction_index = 1;
    quicktrans_stats_record(stats, QUICKTRANS_STATS_OUTCOME_FAILED, &failure);
    failure.pc = 0x5006;
    failure.instruction_id = 18;
    failure.template_kind = 24;
    failure.instruction_index = 2;
    quicktrans_stats_record(stats, QUICKTRANS_STATS_OUTCOME_FALLBACK,
                            &failure);
    quicktrans_stats_dump(stats, stream);
    if (fstat(fileno(stream), &stream_stat) != 0 || stream_stat.st_size == 0) {
        fprintf(stderr, "stats dump did not flush its output\n");
        fclose(stream);
        quicktrans_stats_destroy(stats);
        return 1;
    }
    rewind(stream);
    output_size = fread(output, 1, sizeof(output) - 1, stream);
    output[output_size] = '\0';

    if (strstr(output,
               "summary attempted=4 success=1 fallback=2 failed=1 "
               "accounted=4") == NULL ||
        strstr(output,
               "miss stage=decode reason=decode-failed count=3") == NULL ||
        strstr(output, "instruction id=17 count=2") == NULL ||
        strstr(output, "instruction id=18 count=1") == NULL ||
        strstr(output, "template kind=23 count=2") == NULL ||
        strstr(output, "template kind=24 count=1") == NULL ||
        strstr(output, "sample index=0 outcome=fallback") == NULL ||
        strstr(output, "sample index=1 outcome=failed") == NULL ||
        strstr(output, "sample index=2") != NULL) {
        fprintf(stderr, "unexpected stats output:\n%s", output);
        fclose(stream);
        quicktrans_stats_destroy(stats);
        return 1;
    }

    fclose(stream);
    quicktrans_stats_reset(stats);
    stream = tmpfile();
    if (stream == NULL) {
        fprintf(stderr, "could not allocate reset stats stream\n");
        quicktrans_stats_destroy(stats);
        return 1;
    }
    quicktrans_stats_record(stats, QUICKTRANS_STATS_OUTCOME_SUCCESS, NULL);
    quicktrans_stats_dump(stats, stream);
    fflush(stream);
    rewind(stream);
    output_size = fread(output, 1, sizeof(output) - 1, stream);
    output[output_size] = '\0';
    if (strstr(output,
               "summary attempted=1 success=1 fallback=0 failed=0 "
               "accounted=1") == NULL ||
        strstr(output, "miss stage=") != NULL ||
        strstr(output, "sample index=") != NULL) {
        fprintf(stderr, "stats reset retained old data:\n%s", output);
        fclose(stream);
        quicktrans_stats_destroy(stats);
        return 1;
    }
    fclose(stream);
    quicktrans_stats_destroy(stats);
    return 0;
}

static int expect_fxsave_restore_templates(void)
{
    static const uint8_t fxsave_rsp[] = { 0x0f, 0xae, 0x44, 0x24, 0x40 };
    static const uint8_t fxrstor_rsp[] = { 0x0f, 0xae, 0x4c, 0x24, 0x40 };
    QuickTransDecoded save;
    QuickTransDecoded restore;

    if (expect_ok(quicktrans_decode_template(
                      fxsave_rsp, sizeof(fxsave_rsp), 0x4000,
                      QUICKTRANS_MODE_64, &save),
                  "decode template fxsave") ||
        expect_ok(quicktrans_decode_template(
                      fxrstor_rsp, sizeof(fxrstor_rsp), 0x5000,
                      QUICKTRANS_MODE_64, &restore),
                  "decode template fxrstor")) {
        return 1;
    }
    if (!save.has_template || !save.fields_valid || save.is_tb_ending ||
        save.fields.modrm_reg != 0 || save.fields.disp != 0x40 ||
        !restore.has_template || !restore.fields_valid ||
        !restore.is_tb_ending || restore.fields.modrm_reg != 1 ||
        restore.fields.disp != 0x40 ||
        save.template_kind == restore.template_kind) {
        fprintf(stderr, "invalid FXSAVE/FXRSTOR template metadata\n");
        return 1;
    }
    return 0;
}

static int expect_test_rm16_negative_imm_template(void)
{
    static const uint8_t test_dx_neg3[] = {
        0x66, 0xf7, 0xc2, 0xfd, 0xff,
    };
    QuickTransDecoded decoded;

    if (expect_ok(quicktrans_decode_template(
                      test_dx_neg3, sizeof(test_dx_neg3), 0x6000,
                      QUICKTRANS_MODE_64, &decoded),
                  "decode template test dx, -3")) {
        return 1;
    }
    if (!decoded.has_template || !decoded.fields_valid ||
        decoded.fields.modrm_mod != 3 || decoded.fields.modrm_reg != 0 ||
        decoded.fields.modrm_rm_index != 2 || decoded.fields.imm != -3) {
        fprintf(stderr, "invalid TEST r/m16, imm16 template metadata\n");
        return 1;
    }
    return 0;
}

static int expect_bzhi_template(void)
{
    static const uint8_t bzhi_edx_eax_ecx[] = {
        0xc4, 0xe2, 0x70, 0xf5, 0xd0,
    };
    QuickTransDecoded decoded;

    if (expect_ok(quicktrans_decode_template(
                      bzhi_edx_eax_ecx, sizeof(bzhi_edx_eax_ecx), 0x7000,
                      QUICKTRANS_MODE_64, &decoded),
                  "decode template bzhi edx, eax, ecx")) {
        return 1;
    }
    if (!decoded.has_template || !decoded.fields_valid ||
        decoded.fields.id != dt_X86_INS_BZHI ||
        decoded.fields.reg != 2 || decoded.fields.modrm_rm_index != 0 ||
        decoded.fields.imm != 1 || decoded.fields.vex_v != 1) {
        fprintf(stderr, "invalid BZHI template metadata\n");
        return 1;
    }
    return 0;
}

static int expect_cldemote_template(void)
{
    static const uint8_t cldemote_r11_r12[] = {
        0x43, 0x0f, 0x1c, 0x84, 0x23, 0xf0, 0x8c, 0x01, 0x00,
    };
    QuickTransDecoded decoded;

    if (expect_ok(quicktrans_decode_template(
                      cldemote_r11_r12, sizeof(cldemote_r11_r12), 0x30036,
                      QUICKTRANS_MODE_64, &decoded),
                  "decode template cldemote")) {
        return 1;
    }
    if (!decoded.has_template || !decoded.fields_valid ||
        decoded.fields.id != dt_X86_INS_CLDEMOTE ||
        decoded.fields.modrm_mod != 2 || decoded.fields.modrm_reg != 0 ||
        decoded.fields.disp != 0x18cf0 ||
        decoded.insn.size != sizeof(cldemote_r11_r12)) {
        fprintf(stderr, "invalid CLDEMOTE template metadata\n");
        return 1;
    }
    return 0;
}

static int expect_shl_rm32_one_sib_template(void)
{
    static const uint8_t shl_rdi_r11[] = {
        0x42, 0xd1, 0xb4, 0x5f, 0x4e, 0xed, 0x00, 0x00,
    };
    QuickTransInsn insn;
    QuickTransDecoded decoded;

    if (expect_ok(quicktrans_decode(shl_rdi_r11, sizeof(shl_rdi_r11),
                                    0x30052, QUICKTRANS_MODE_64, &insn),
                  "decode shl dword ptr [rdi+r11*2+0xed4e], 1")) {
        return 1;
    }
    if (insn.id != dt_X86_INS_SHL || insn.size != sizeof(shl_rdi_r11)) {
        fprintf(stderr, "invalid SHL r/m32, 1 decode metadata\n");
        return 1;
    }
    if (expect_ok(quicktrans_decode_template(
                      shl_rdi_r11, sizeof(shl_rdi_r11), 0x30052,
                      QUICKTRANS_MODE_64, &decoded),
                  "decode template shl dword ptr [rdi+r11*2+0xed4e], 1")) {
        return 1;
    }
    if (!decoded.has_template || !decoded.fields_valid ||
        decoded.fields.id != dt_X86_INS_SHL ||
        decoded.template_kind != FT_SHIFT_RM_ONE ||
        decoded.fields.modrm_mod != 2 || decoded.fields.modrm_reg != 6 ||
        decoded.fields.disp != 0xed4e ||
        decoded.insn.size != sizeof(shl_rdi_r11)) {
        fprintf(stderr, "invalid SHL r/m32, 1 template metadata\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    static const uint8_t mov_rax_rbx[] = { 0x48, 0x89, 0xd8 };
    static const uint8_t xor_eax_eax[] = { 0x31, 0xc0 };
    QuickTransInsn insn;
    QuickTransDecoded decoded;
    QuickTransEmitter emitter;
    uint32_t code[2];
    QuickTransFailure failure;
    uint8_t long_sample[QUICKTRANS_FAILURE_MAX_BYTES + 3];
    size_t i;

    if (expect_ok(quicktrans_decode(mov_rax_rbx, sizeof(mov_rax_rbx),
                                    0x1000, QUICKTRANS_MODE_64, &insn),
                  "decode mov")) {
        return 1;
    }
    if (insn.size != sizeof(mov_rax_rbx)) {
        fprintf(stderr, "unexpected mov size: %u\n", insn.size);
        return 1;
    }

    if (expect_ok(quicktrans_decode_template(xor_eax_eax, sizeof(xor_eax_eax),
                                             0x2000, QUICKTRANS_MODE_64,
                                             &decoded),
                  "decode template xor")) {
        return 1;
    }
    if (!decoded.has_template || !decoded.fields_valid) {
        fprintf(stderr, "xor template fields were not produced\n");
        return 1;
    }

    quicktrans_emitter_init(&emitter, code, 2);
    if (!quicktrans_emitter_emit_u32(&emitter, 0x03400000) ||
        quicktrans_emitter_count(&emitter) != 1) {
        fprintf(stderr, "emitter failed\n");
        return 1;
    }

    for (i = 0; i < sizeof(long_sample); i++) {
        long_sample[i] = (uint8_t)i;
    }
    quicktrans_failure_record(
        &failure, QUICKTRANS_FAILURE_STAGE_DECODE,
        QUICKTRANS_FAILURE_REASON_DECODE_FAILED, 0x3000, long_sample,
        sizeof(long_sample), 17, 23, 2);
    if (failure.stage != QUICKTRANS_FAILURE_STAGE_DECODE ||
        failure.reason != QUICKTRANS_FAILURE_REASON_DECODE_FAILED ||
        failure.pc != 0x3000 ||
        failure.byte_count != QUICKTRANS_FAILURE_MAX_BYTES ||
        memcmp(failure.bytes, long_sample, QUICKTRANS_FAILURE_MAX_BYTES) != 0 ||
        failure.instruction_id != 17 || failure.template_kind != 23 ||
        failure.instruction_index != 2 ||
        strcmp(quicktrans_failure_stage_name(failure.stage), "decode") != 0 ||
        strcmp(quicktrans_failure_reason_name(failure.reason),
               "decode-failed") != 0) {
        fprintf(stderr, "decode failure metadata is incomplete\n");
        return 1;
    }

    quicktrans_failure_record(&failure, QUICKTRANS_FAILURE_STAGE_EMIT,
                              QUICKTRANS_FAILURE_REASON_INSN_EMIT, 0x4000,
                              NULL, 7, 29, 31, 4);
    if (failure.stage != QUICKTRANS_FAILURE_STAGE_EMIT ||
        failure.reason != QUICKTRANS_FAILURE_REASON_INSN_EMIT ||
        failure.byte_count != 0 ||
        strcmp(quicktrans_failure_stage_name(failure.stage), "emit") != 0 ||
        strcmp(quicktrans_failure_reason_name(failure.reason), "insn-emit") !=
            0) {
        fprintf(stderr, "emit failure metadata is incomplete\n");
        return 1;
    }

    quicktrans_failure_clear(&failure);
    if (failure.stage != QUICKTRANS_FAILURE_STAGE_NONE ||
        failure.reason != QUICKTRANS_FAILURE_REASON_NONE ||
        failure.byte_count != 0 || failure.template_kind != -1 ||
        failure.instruction_index != -1) {
        fprintf(stderr, "failure clear did not restore defaults\n");
        return 1;
    }

    if (expect_stats_output()) {
        return 1;
    }
    if (expect_fxsave_restore_templates()) {
        return 1;
    }
    if (expect_test_rm16_negative_imm_template()) {
        return 1;
    }
    if (expect_bzhi_template()) {
        return 1;
    }
    if (expect_cldemote_template()) {
        return 1;
    }
    if (expect_shl_rm32_one_sib_template()) {
        return 1;
    }

    return 0;
}
