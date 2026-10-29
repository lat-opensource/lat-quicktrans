/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Zero words are success only for explicitly recognized no-code forms.
 * Ordinary emitters still return zero on failure. Never omit data accesses;
 * prefetch hints follow the explicitly selected legacy policy.
 */
static inline bool ft_emit_zero_code_allowed(const FastTemplateFields *fields)
{
#ifdef QUICKTRANS_LATU
    switch (fields->kind) {
    case FT_ENDBR32:
    case FT_ENDBR64:
    case FT_PAUSE:
        return true;
#ifndef CONFIG_SOFTMMU
    case FT_SHIFT_RM_IMM8:
        /* A zero-count r32 rotate preserves flags but still clears highs.
         * Only the ordinary-TB demand proof may remove that last effect.
         * Decoder/sample/TU defaults leave omit_zext32 false.
         */
        return fields->opcode0 == 0xc1 && fields->modrm_mod == 3 &&
               fields->modrm_reg <= 1 &&
               fields->id == (fields->modrm_reg == 0 ?
                              dt_X86_INS_ROL : dt_X86_INS_ROR) &&
               !ft_rex_w(fields) && fields->prefix2 == 0 &&
               fields->prefix0 != dt_X86_PREFIX_LOCK && fields->segment < 0 &&
               ft_modrm_rm_index(fields) < GPR_NUM &&
               (fields->imm & 31) == 0 && ft_omit_gpr_zext32(fields);
#endif
    case FT_PREFETCHNTA:
    case FT_PREFETCHT1:
    case FT_PREFETCHT2:
        /* Legacy LATU omits these hints; T0 and PREFETCHW still execute. */
        return fields->modrm_mod != 3 && fields->prefix0 == 0 &&
               fields->prefix2 == 0 &&
               fields->modrm_reg == (fields->kind == FT_PREFETCHNTA ? 0 :
                                      fields->kind == FT_PREFETCHT1 ? 2 : 3);
    case FT_PSRLDQ_XMM_IMM8:
    case FT_PSLLDQ_XMM_IMM8:
        return fields->modrm_mod == 3 && fields->prefix0 == 0 &&
               fields->prefix2 == dt_X86_PREFIX_OPSIZE &&
               fields->modrm_reg ==
                   (fields->kind == FT_PSRLDQ_XMM_IMM8 ? 3 : 7) &&
               ft_modrm_rm_index(fields) < XMM_NUM &&
               (fields->imm & 0xff) == 0;
    case FT_NOP_MULTI:
        return fields->id == dt_X86_INS_FNOP && !option_soft_fpu;
    case FT_MOV128_XMM_XMMM:
    case FT_MOV128_XMMM_XMM:
    case FT_MOVSD_XMM_M64:
    case FT_MOVSD_M64_XMM:
        return fields->modrm_mod == 3 &&
               ft_modrm_reg_index(fields) < XMM_NUM &&
               ft_modrm_reg_index(fields) == ft_modrm_rm_index(fields);
#ifndef CONFIG_SOFTMMU
    case FT_SIMD_BIN_XMM_XMMM:
    case FT_SIMD_SCALAR_BIN_XMM_XMMM:
        /* These emitters already skip same-register MIN/MAX when the LATS
         * explicit exception checks are disabled (as in this LATU build).
         * This does not imply hardware traps are disabled; preserve the
         * existing NaN/exception policy without introducing FP operations.
         */
        if (fields->opcode0 != 0x0f ||
            (fields->opcode1 != 0x5d && fields->opcode1 != 0x5f) ||
            fields->modrm_mod != 3 ||
            ft_modrm_reg_index(fields) >= XMM_NUM ||
            ft_modrm_reg_index(fields) != ft_modrm_rm_index(fields)) {
            return false;
        }
        if (fields->kind == FT_SIMD_BIN_XMM_XMMM) {
            return fields->prefix0 == 0 &&
                   (fields->prefix2 == 0 ||
                    fields->prefix2 == dt_X86_PREFIX_OPSIZE);
        }
        return fields->prefix2 == 0 &&
               (fields->prefix0 == dt_X86_PREFIX_REP ||
                fields->prefix0 == dt_X86_PREFIX_REPNE);
#endif
    case FT_BLEND_XMM_XMMM_IMM8:
        if (fields->modrm_mod != 3 ||
            fields->prefix2 != dt_X86_PREFIX_OPSIZE ||
            ft_modrm_reg_index(fields) >= XMM_NUM ||
            ft_modrm_rm_index(fields) >= XMM_NUM) {
            return false;
        }
        switch (fields->id) {
        case dt_X86_INS_BLENDPS:
            return !(fields->imm & 15);
        case dt_X86_INS_BLENDPD:
            return !(fields->imm & 3);
        case dt_X86_INS_PBLENDW:
            return !(fields->imm & 255);
        default:
            return false;
        }
    default:
        return false;
    }
#elif defined(CONFIG_SOFTMMU)
    switch (fields->kind) {
    case FT_ENDBR32:
    case FT_ENDBR64:
        return true;
    case FT_PAUSE:
        return option_pause != 0;
    case FT_NOP_MULTI:
        if (fields->id == dt_X86_INS_FSETPM) {
            return true;
        }
        /* FNOP shares this template, but its soft-FPU legacy handler
         * performs an exception check. Do not classify it as no-code.
         */
        if (fields->id != dt_X86_INS_NOP) {
            return false;
        }
#ifdef CONFIG_LATX_TU
        return option_pause != 0;
#else
        return true;
#endif
    default:
        return false;
    }
#else
    (void)fields;
    return false;
#endif
}

#ifdef QUICKTRANS_LATU
static int ft_emit_latu_bound(const FastTemplateFields *fields,
                              target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int addr;
    int source = ft_modrm_reg_index(fields);
    bool narrow = fields->prefix2 == dt_X86_PREFIX_OPSIZE;
    FastBranchLabel fault = {0}, done = {0};
    FastBranchFixup above, valid;
    if (fields->modrm_mod == 3 || source >= GPR_NUM ||
        !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
        return 0;
    }
    int value = ft_scratch_avoid3(addr, -1, -1);
    int low = ft_scratch_avoid3(addr, value, -1);
    int high = ft_scratch_avoid3(addr, value, low);
    int offset = ft_mem_access_offset(fields, addr);
    /* Form the base once so the second load cannot overflow imm12. */
    if (offset) {
        FT_LA_ADDI_D_EMIT(&out, high, addr, offset);
        addr = high;
        high = ft_scratch_avoid3(addr, value, low);
    }
    if (narrow) {
        FT_LA_EXT_W_H_EMIT(&out, value, ft_gpr(source));
        FT_LA_LD_H_EMIT(&out, low, addr, 0);
        FT_LA_LD_H_EMIT(&out, high, addr, 2);
    } else {
        FT_LA_SLLI_D_EMIT(&out, value, ft_gpr(source), 32);
        FT_LA_SRAI_D_EMIT(&out, value, value, 32);
        FT_LA_LD_W_EMIT(&out, low, addr, 0);
        FT_LA_LD_W_EMIT(&out, high, addr, 4);
    }
    ft_emit_branch_placeholder(&out, &above, FT_BRANCH_BLT, high, value, &fault);
    ft_emit_branch_placeholder(&out, &valid, FT_BRANCH_BGE, value, low, &done);
    ft_bind_branch_label(&fault, out);
    ft_resolve_branch_fixup(&above);
    ft_emit_raise_exception(&out, pc, EXCP05_BOUND);
    ft_bind_branch_label(&done, out);
    ft_resolve_branch_fixup(&valid);
    return out - code;
}
#endif

#ifdef QUICKTRANS_LATU
static int ft_emit_latu_wait(uint32_t *code)
{
    uint32_t *out = code;
    /* Match legacy WAIT's implemented OE/UE/PE cases, including the
     * host FCSR enables. Legacy IE/ZE handling remains unimplemented. */
    static const uint32_t left[] = { 0x7f7fffff, 0x00800000, 0x40000000 };
    static const uint32_t right[] = { 0x749dc5ae, 0x40400000, 0x40400000 };
    FastBranchLabel done = { 0 };
    FastBranchFixup done_fixup;

    ft_emit_load_env(&out, la_t0, lsenv_offset_of_control_word(lsenv),
                     FT_LA_OPCODE_LD_HU);
    ft_emit_load_env(&out, la_t1, lsenv_offset_of_status_word(lsenv),
                     FT_LA_OPCODE_LD_HU);
    FT_LA_ANDN_EMIT(&out, la_t1, la_t1, la_t0);
    FT_LA_ANDI_EMIT(&out, la_t1, la_t1, 0x38);
    ft_emit_branch_placeholder(&out, &done_fixup, FT_BRANCH_BEQ,
                               la_t1, la_zero, &done);
    for (int i = 0; i < 3; i++) {
        FastBranchLabel next = { 0 };
        FastBranchFixup next_fixup;
        FT_LA_ANDI_EMIT(&out, la_t0, la_t1, 1 << (i + 3));
        ft_emit_branch_placeholder(&out, &next_fixup, FT_BRANCH_BEQ,
                                   la_t0, la_zero, &next);
        ft_emit_li32(&out, la_t0, left[i]);
        FT_LA_MOVGR2FR_W_EMIT(&out, ft_vscratch, la_t0);
        ft_emit_li32(&out, la_t0, right[i]);
        FT_LA_MOVGR2FR_W_EMIT(&out, ft_vscratch + 1, la_t0);
        if (i == 0) {
            FT_LA_FADD_S_EMIT(&out, ft_vscratch, ft_vscratch, ft_vscratch + 1);
        } else {
            FT_LA_FDIV_S_EMIT(&out, ft_vscratch, ft_vscratch, ft_vscratch + 1);
        }
        ft_bind_branch_label(&next, out);
        ft_resolve_branch_fixup(&next_fixup);
    }
    ft_bind_branch_label(&done, out);
    ft_resolve_branch_fixup(&done_fixup);
    return out - code;
}
#endif

static int ft_emit_nop_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    (void)pc;

#ifdef QUICKTRANS_LATU
    if (fields->kind == FT_WAIT && !option_soft_fpu) {
        return ft_emit_latu_wait(code);
    }
    if (option_soft_fpu && (fields->kind == FT_WAIT ||
                            fields->id == dt_X86_INS_FNOP)) {
        FastBranchLabel done = { 0 };
        FastBranchFixup done_fixup;

        /* Legacy's soft WAIT/FNOP call helper_fwait, which checks ES.
         * Keep the ordinary no-pending-exception path out of the helper. */
        ft_emit_load_env(&out, la_t0, lsenv_offset_of_status_word(lsenv),
                         FT_LA_OPCODE_LD_HU);
        FT_LA_ANDI_EMIT(&out, la_t0, la_t0, 1u << 7); /* x87 ES */
        ft_emit_branch_placeholder(&out, &done_fixup, FT_BRANCH_BEQ,
                                   la_t0, la_zero, &done);
        ft_emit_helper_prologue(&out);
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_cpu_env_ptr(&out, la_a0);
        ft_emit_host_call(&out, (void *)helper_fwait, 1u << 0);
        ft_emit_helper_epilogue(&out);
        ft_bind_branch_label(&done, out);
        ft_resolve_branch_fixup(&done_fixup);
        return out - code;
    }
    if (fields->id == dt_X86_INS_BOUND) {
        return ft_emit_latu_bound(fields, pc, code);
    }
    /* Legacy LATU rejects FSETPM in both hard- and soft-FPU modes. */
    if (fields->id == dt_X86_INS_FSETPM) {
        return 0;
    }
#endif
    if (ft_emit_zero_code_allowed(fields)) {
        return 0;
    }
    FT_LA_ORI_EMIT(&out, la_zero, la_zero, 0);
    return (out - code);
}

static int ft_emit_prefetchw_template(const FastTemplateFields *fields,
                                      TranslationBlock *tb, target_ulong pc,
                                      uint32_t *code)
{
    uint32_t *out = code;
    int addr;

    (void)tb;
    if (fields->modrm_mod == 3 || fields->modrm_reg != 1 ||
        fields->prefix0 != 0 || fields->prefix2 != 0 ||
        !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
        return 0;
    }
    FT_LA_PRELD_EMIT(&out, 8, addr, ft_mem_access_offset(fields, addr));
    return (out - code);
}

static int ft_emit_prefetch_read_template(const FastTemplateFields *fields,
                                          TranslationBlock *tb, target_ulong pc,
                                          uint32_t *code)
{
    uint32_t *out = code;
    int addr;
    int modrm_reg;

    (void)tb;
#ifdef QUICKTRANS_LATU
    if (ft_emit_zero_code_allowed(fields)) {
        return 0;
    }
#endif
    switch (fields->kind) {
    case FT_PREFETCHNTA:
        modrm_reg = 0;
        break;
    case FT_PREFETCHT0:
        modrm_reg = 1;
        break;
    case FT_PREFETCHT1:
        modrm_reg = 2;
        break;
    case FT_PREFETCHT2:
        modrm_reg = 3;
        break;
    default:
        return 0;
    }
    if (fields->modrm_mod == 3 || fields->modrm_reg != modrm_reg ||
        fields->prefix0 != 0 || fields->prefix2 != 0 ||
        !ft_emit_rip_or_mem_addr(&out, fields, pc, &addr)) {
        return 0;
    }
    FT_LA_PRELD_EMIT(&out, 0, addr, ft_mem_access_offset(fields, addr));
    return (out - code);
}

static int ft_emit_fence_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)fields;
    (void)tb;
    (void)pc;

    FT_LA_DBAR_EMIT(&out, 0);
    return (out - code);
}

static int ft_emit_cache_flush_template(const FastTemplateFields *fields,
                                        TranslationBlock *tb,
                                        target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int expected_prefix2;

    (void)tb;
    (void)pc;
    expected_prefix2 = fields->kind == FT_CLFLUSHOPT ?
                       dt_X86_PREFIX_OPSIZE : 0;
    if (fields->modrm_mod == 3 || fields->modrm_reg != 7 ||
        fields->prefix0 != 0 || fields->prefix2 != expected_prefix2) {
        return 0;
    }
    FT_LA_IBAR_EMIT(&out, 0);
    return out - code;
}
