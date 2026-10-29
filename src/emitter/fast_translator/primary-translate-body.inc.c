/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 * SPDX-License-Identifier: MIT
 */

/* Included twice for LATU: compile out RSP merge work when disabled. */
static bool FT_SPECIALIZED_NAME(CPUArchState *env,
                                              TranslationBlock *tb,
                                              int max_insns,
                                              int *code_size,
                                              int *search_size,
                                              QuickTransFailure *failure
#ifndef QUICKTRANS_LATU
                                              , FtCodeSpace *space
#endif
                                              )
{
    uint32_t *code = (uint32_t *)tb->tc.ptr;
    target_ulong start_pc = tb->pc;
    target_ulong pc = start_pc;
    FastTemplateFields fields_buf[TCG_MAX_INSNS];
    const FastTemplateRuntimeInfo *meta_buf[TCG_MAX_INSNS];
    int emitted = 0;
    int icount = 0;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
    int rsp_pending = 0;
    int rsp_next_step = 0;
    bool rsp_next_step_valid = false;
    bool rsp_next_adjust_memory = false;
    bool rsp_next_overwrite = false;
    bool rsp_merge_enabled;
#endif
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    uint8_t fetch_cache[15];
    target_ulong fetch_cache_pc = 0;
    int fetch_cache_len = 0;
    /* Reuse only read-only, private, non-shadow code on the entry page.
     * Writable/shared aliases and later pages need the original fetch path. */
    int fetch_page_flags = page_get_flags(start_pc);
    bool fetch_cache_allowed =
        (fetch_page_flags & (PAGE_VALID | PAGE_READ | PAGE_EXEC)) ==
            (PAGE_VALID | PAGE_READ | PAGE_EXEC) &&
        !(fetch_page_flags & (PAGE_WRITE | PAGE_WRITE_ORG | PAGE_MEMSHARE)) &&
        !page_is_shadow_not_shmm(start_pc);
#endif
    unsigned int analysis_candidates = 0;
    bool x87_top_active = false;
    bool mmx_active = false;
    const bool atomic_no_barrier = ft_atomic_use_no_db(env, tb);
    const uint8_t *host_start = NULL;
    bool debug_skip = ft_debug_skip_config()->enabled;
    bool debug_split = ft_debug_split_config()->enabled;
    bool debug_trace = ft_primary_trace_enabled();
    bool debug_live = ft_primary_debug_live_enabled();
    bool debug_code = ft_primary_debug_code_enabled();
    bool analyze_gpr_high = false;
    bool sample_trace = ft_primary_sample_trace_enabled();
    bool stage_stats = ft_primary_stage_stats_enabled();
    bool emit_profile = stage_stats && ft_emit_profile_enabled();
    int decode_mode = ft_tu_decode_mode(tb);
    int64_t stage_total_start = stage_stats ? ft_bench_now_ns() : 0;
    int64_t stage_decode_ns = 0;
    int64_t stage_analyze_ns = 0;
    int64_t stage_emit_start = 0;
    int64_t stage_search_ns = 0;

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    /* No stale high halves may be exposed at per-instruction observers.
     * Restrict the new analysis to ordinary 64-bit-mode JIT TBs. */
    analyze_gpr_high = !debug_live && (tb->flags & HF_CS64_MASK) &&
                       !(tb->flags & HF_TF_MASK) &&
                       !(env->eflags & TF_MASK) &&
                       !env_cpu(env)->singlestep_enabled &&
                       !option_aot && !in_pre_translate &&
                       !(tb->bool_flags & (IS_AOT_TB | IS_TU_TB | IS_TU_JMP));
#endif

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
    rsp_merge_enabled = analyze_gpr_high && !debug_skip && !debug_split &&
        !(env_cpu(env)->tcg_cflags & CF_PARALLEL) &&
        !(tb_cflags(tb) & CF_PARALLEL) &&
        !(page_get_flags(start_pc) & PAGE_ANON);
#endif

#ifndef QUICKTRANS_LATU
    host_start = lsenv->tr_data->host_addr[0];
#endif

#ifdef QUICKTRANS_LATU
    if (max_insns == 1) {
        max_insns = TCG_MAX_INSNS;
    }
#endif
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    /* An SS load inhibits interrupts only through the next instruction. */
    if (tb->flags & HF_INHIBIT_IRQ_MASK) {
        max_insns = 1;
    }
#endif

    for (;;) {
        uint8_t inst_cache[15];
        const uint8_t *insn_bytes = inst_cache;
        FastDecodedFT decoded;
        const FastTemplateDesc *tmpl;
        const FastTemplateRuntimeInfo *meta;
        FastTemplateFields *fields;
        int max_insn_len = sizeof(inst_cache);
        bool is_ending;
        bool page_boundary;

        if (icount >= max_insns || max_insn_len <= 0) {
            return ft_primary_fail(
                failure, QUICKTRANS_FAILURE_STAGE_FETCH,
                QUICKTRANS_FAILURE_REASON_INSN_LIMIT, pc, NULL, 0, 0,
                FT_UNSUPPORTED, icount);
        }
        bool decode_ok = false;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        if (fetch_cache_allowed && pc >= fetch_cache_pc && pc - fetch_cache_pc < fetch_cache_len &&
            (pc & TARGET_PAGE_MASK) == (start_pc & TARGET_PAGE_MASK)) {
            int offset = pc - fetch_cache_pc;
            int available = fetch_cache_len - offset;
            decode_ok = fast_decoder_get_ft(fetch_cache + offset, available,
                                             pc, &decoded, decode_mode);
            if (decode_ok) {
                insn_bytes = fetch_cache + offset;
                max_insn_len = available;
                page_boundary = false;
            }
        }
#endif
        if (!decode_ok) {
            decode_ok = ft_decode_x86_primary_window(env, host_start, start_pc,
                          pc, inst_cache, decode_mode, &decoded,
                          &max_insn_len, &page_boundary);
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
            if (decode_ok && fetch_cache_allowed &&
                (pc & TARGET_PAGE_MASK) == (start_pc & TARGET_PAGE_MASK) &&
                max_insn_len <= TARGET_PAGE_SIZE - (pc & (TARGET_PAGE_SIZE - 1))) {
                memcpy(fetch_cache, inst_cache, max_insn_len);
                fetch_cache_pc = pc;
                fetch_cache_len = max_insn_len;
            }
#endif
        }
        if (!decode_ok) {
            if (page_boundary && icount) {
                ft_primary_update_last_info(tb, &fields_buf[icount - 1]);
                break;
            }
#if !defined(QUICKTRANS_LATU) && defined(CONFIG_SOFTMMU)
            if (lsenv->tr_data->deadlock_avoidance) {
                return false;
            }
#endif
            fprintf(stderr, "[FT] fd-primary decode-fail index=%d pc=0x%lx\n",
                    icount, (unsigned long)pc);
            if (debug_trace) {
                fprintf(stderr, "[FT] fd-primary bytes=");
                for (int j = 0; j < max_insn_len; ++j) {
                    fprintf(stderr, "%02x", insn_bytes[j]);
                }
                fprintf(stderr, "\n");
            }
            return ft_primary_fail(
                failure, QUICKTRANS_FAILURE_STAGE_DECODE,
                QUICKTRANS_FAILURE_REASON_DECODE_FAILED, pc, insn_bytes,
                max_insn_len, 0, FT_UNSUPPORTED, icount);
        }

        ft_apply_latu_legacy_policy(&decoded);
        tmpl = decoded.tmpl;
        meta = ft_template_runtime_info(tmpl ? tmpl->kind : FT_UNSUPPORTED);
        /* All classified helpers are primary-allowed; checked by
         * test-primary-helper-policy.py. Keep missing-template failure. */
        if (!tmpl) {
            fprintf(stderr,
                    "[FT] fd-primary miss-insn index=%d pc=0x%lx id=%d "
                    "size=%u kind=%d helper=%d\n",
                    icount, (unsigned long)pc,
                    decoded.fields.id, decoded.fields.size,
                    tmpl ? tmpl->kind : FT_UNSUPPORTED,
                    tmpl ? ft_template_is_helper(tmpl->kind) : 0);
            return ft_primary_fail(
                failure, QUICKTRANS_FAILURE_STAGE_TEMPLATE,
                tmpl ? QUICKTRANS_FAILURE_REASON_HELPER_UNSUPPORTED
                     : QUICKTRANS_FAILURE_REASON_TEMPLATE_MISSING,
                pc, insn_bytes,
                MIN((size_t)decoded.fields.size, sizeof(inst_cache)),
                decoded.fields.id, tmpl ? tmpl->kind : FT_UNSUPPORTED,
                icount);
        }
        if (debug_skip &&
            ft_debug_skip_template(tmpl->kind, decoded.fields.id,
                                   decoded.fields.address)) {
            return ft_primary_fail(
                failure, QUICKTRANS_FAILURE_STAGE_TEMPLATE,
                QUICKTRANS_FAILURE_REASON_DEBUG_SKIP, pc, insn_bytes,
                MIN((size_t)decoded.fields.size, sizeof(inst_cache)),
                decoded.fields.id, tmpl->kind, icount);
        }
        if (debug_split && icount > 0 &&
            ft_debug_split_before_template(tmpl->kind,
                                           decoded.fields.address)) {
            break;
        }
        if (!decoded.fields_valid) {
            fprintf(stderr,
                    "[FT] fd-primary field-fail index=%d pc=0x%lx id=%d "
                    "size=%u kind=%d\n",
                    icount, (unsigned long)decoded.fields.address,
                    decoded.fields.id, decoded.fields.size, tmpl->kind);
            return ft_primary_fail(
                failure, QUICKTRANS_FAILURE_STAGE_TEMPLATE,
                QUICKTRANS_FAILURE_REASON_FIELDS_INVALID, pc, insn_bytes,
                MIN((size_t)decoded.fields.size, sizeof(inst_cache)),
                decoded.fields.id, tmpl->kind, icount);
        }
        fields = &decoded.fields;
        if (!ft_system_primary_insn_supported(fields)) {
            return ft_primary_fail(
                failure, QUICKTRANS_FAILURE_STAGE_CONSTRAINT,
                QUICKTRANS_FAILURE_REASON_MODE_UNSUPPORTED, pc, insn_bytes,
                MIN((size_t)fields->size, sizeof(inst_cache)), fields->id,
                tmpl->kind, icount);
        }
        fields->skip_flags = false;
        fields->omit_zext32 = false;
        fields->scalar_direct_dst = false;
        fields->atomic_no_barrier = atomic_no_barrier;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        /* POPF can enable TF inside this TB, after the entry check above. */
        if (fields->id == dt_X86_INS_POPF ||
            fields->id == dt_X86_INS_POPFD ||
            fields->id == dt_X86_INS_POPFQ) {
            analyze_gpr_high = false;
        }
#endif
#ifdef CONFIG_LATX_DEBUG
        if (!fast_template_emit_constraints_ok(fields)) {
            fprintf(stderr,
                    "[FT] fd-primary constraint-fail index=%d "
                    "pc=0x%lx id=%d size=%u kind=%d modrm=%02x "
                    "rex=%02x disp=%ld imm=%ld\n",
                    icount, (unsigned long)fields->address, fields->id,
                    fields->size, tmpl->kind, fields->modrm,
                    fields->rex < 0 ? 0 : fields->rex,
                    (long)fields->disp, (long)fields->imm);
            return ft_primary_fail(
                failure, QUICKTRANS_FAILURE_STAGE_CONSTRAINT,
                QUICKTRANS_FAILURE_REASON_CONSTRAINT_REJECTED, pc,
                insn_bytes, MIN((size_t)fields->size, sizeof(inst_cache)),
                fields->id, tmpl->kind, icount);
        }
#endif

        if (sample_trace) {
            ft_primary_sample_trace(env, fields);
        }

        analysis_candidates |= FT_CANDIDATES_NAME(fields);
#ifdef QUICKTRANS_LATU
        _Static_assert(sizeof(*fields) % sizeof(uint64_t) == 0,
                       "Field copy requires complete 64-bit chunks");
#pragma GCC unroll 16
        for (unsigned offset = 0; offset < sizeof(*fields);
             offset += sizeof(uint64_t)) {
            /* memcpy permits object-representation copies without aliasing. */
            __builtin_memcpy((char *)&fields_buf[icount] + offset,
                             (const char *)fields + offset, sizeof(uint64_t));
        }
#else
        fields_buf[icount] = *fields;
#endif
        meta_buf[icount] = meta;
        if (stage_stats) {
            ft_primary_stage_stats.insns++;
            ft_primary_stage_stats.kind[tmpl->kind]++;
        }
        tb->icount = icount + 1;
        tb->size = fields->address + fields->size - start_pc;
        if (debug_trace) {
            fprintf(stderr, "[FT] fd-primary pc=0x%lx size=%u id=%d kind=%d\n",
                    (unsigned long)fields->address, fields->size, fields->id,
                    tmpl->kind);
        }

        is_ending = decoded.is_tb_ending;
        icount++;
        pc = fields->address + fields->size;

#if !defined(QUICKTRANS_LATU) && defined(CONFIG_SOFTMMU)
        is_ending |= (pc & TARGET_PAGE_MASK) !=
                     (start_pc & TARGET_PAGE_MASK);
#endif
        if (meta->terminal_exit || is_ending || icount == max_insns) {
            ft_primary_update_last_info(tb, fields);
            break;
        }
    }

    if (stage_stats) {
        int64_t now = ft_bench_now_ns();

        stage_decode_ns = now - stage_total_start;
        stage_emit_start = now;
    }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
    /* The existing decode pass records candidates; no additional TB scan. */
    rsp_merge_enabled &= (analysis_candidates & FT_ANALYZE_RSP) != 0;
#endif
    (void)ft_analyze_tb_flags(fields_buf, meta_buf, icount,
                             analysis_candidates, analyze_gpr_high,
                             analyze_gpr_high && !debug_skip && !debug_split);
    if (stage_stats) {
        int64_t now = ft_bench_now_ns();

        stage_analyze_ns = now - stage_emit_start;
        if (ft_startup_flags() & FT_STARTUP_TB_KIND_TRACE) {
            fprintf(stderr, "[FT-TB-KINDS] pc=0x%lx count=%d kinds=",
                    (unsigned long)start_pc, icount);
            for (int trace_i = 0; trace_i < icount; ++trace_i) {
                fprintf(stderr, "%s%d", trace_i ? "," : "",
                        fields_buf[trace_i].kind);
            }
            fputc('\n', stderr);
        }
        stage_emit_start = ft_bench_now_ns();
    }
#ifndef QUICKTRANS_LATU
    ft_code_space_activate(space);
#endif
    for (int i = 0; i < icount; ++i) {
        FastTemplateFields *fields = &fields_buf[i];
        const FastTemplateRuntimeInfo *meta = meta_buf[i];
        uint32_t *insn_code;
        int64_t kind_emit_start;
        int insn_emitted;
        bool rsp_elided = false;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
        bool rsp_direct = false;
        int rsp_before = rsp_pending;
        int rsp_step = rsp_merge_enabled ?
            (rsp_next_step_valid ? rsp_next_step : ft_rsp_merge_step(fields)) : 0;
        FastTemplateFields rsp_fields;
        bool rsp_adjust_memory = rsp_pending && rsp_next_adjust_memory;
        /* Lookahead used the same pending delta and x87 state now entering
         * this instruction. Reuse its classification and address decision. */
        rsp_next_step_valid = false;
        rsp_next_adjust_memory = false;
        if (rsp_adjust_memory) {
            rsp_fields = *fields;
            rsp_fields.disp += rsp_pending;
            fields = &rsp_fields;
        }
#endif

        if (ft_template_uses_mmx(fields) &&
            ft_mmx_entry_required(mmx_active)) {
            uint32_t *out = code + emitted;

            ft_emit_enter_mmx(&out);
            emitted = out - code;
            mmx_active = true;
        }
        if (!option_soft_fpu && !x87_top_active && meta->uses_x87_top) {
            uint32_t *out = code + emitted;
            int top_emitted;

            top_emitted = ft_emit_x87_top_load(&out);
            if (!top_emitted) {
                return ft_primary_fail_decoded(
                    env, failure, QUICKTRANS_FAILURE_STAGE_EMIT,
                    QUICKTRANS_FAILURE_REASON_X87_TOP_LOAD, fields->address,
                    fields, i);
            }
            emitted += top_emitted;
            x87_top_active = true;
        }

        {
            uint32_t *out = code + emitted;

            if (debug_live) {
                ft_primary_debug_emit_live_regs(&out, fields->address);
            }
            emitted = out - code;
        }

        insn_code = code + emitted;
        kind_emit_start = stage_stats ? ft_bench_now_ns() : 0;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
        insn_emitted = ft_rsp_merge_emit_register(fields, insn_code,
                                                   rsp_pending, rsp_step);
        rsp_direct = insn_emitted != 0;
        if (!rsp_direct) {
#endif
        if (!debug_live && ft_x87_can_share_context(fields)) {
            bool first = i == 0 ||
                !ft_x87_can_share_context(&fields_buf[i - 1]);
            bool last = i + 1 == icount ||
                !ft_x87_can_share_context(&fields_buf[i + 1]);

            if (first && last) {
                insn_emitted = emit_template_fields(fields, tb, fields->address,
                                                    insn_code);
            } else {
                insn_emitted = ft_emit_x87_shared_context(fields, insn_code,
                                                         first, last);
            }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
        } else if (fields->kind == FT_AES_ROUND_XMM_XMMM &&
                   fields->modrm_mod == 3 && !debug_live && !option_vpaes &&
                   (fields->id == dt_X86_INS_AESENC ||
                    fields->id == dt_X86_INS_AESENCLAST) &&
                   fields->prefix2 == dt_X86_PREFIX_OPSIZE && i > 0 &&
                   fields_buf[i - 1].kind == FT_AES_ROUND_XMM_XMMM &&
                   fields_buf[i - 1].modrm_mod == 3 &&
                   fields_buf[i - 1].id == fields->id) {
            /* The preceding register round leaves its table in t0.  No
             * helper, memory addressing or per-instruction observer can
             * intervene here.  RSP merging appends only ADDI_D to guest RSP
             * after an AES round, and cannot clobber t0.  New TBs, different
             * tables and every non-register-AES instruction take the normal
             * entry; no persistent cache or generic immediate reuse exists. */
            uint32_t *out = insn_code;
            int dst = ft_modrm_reg_index(fields);

            insn_emitted = dst < XMM_NUM &&
                ft_emit_latu_aes_encrypt(&out, fields, fields->address,
                                         dst, true) ? out - insn_code : 0;
#endif
        } else {
            insn_emitted = emit_template_fields(fields, tb, fields->address,
                                                insn_code);
        }
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
        }
        if (rsp_merge_enabled && (rsp_step || rsp_pending) &&
            (insn_emitted > 0 || ft_emit_zero_code_allowed(fields))) {
            if (rsp_pending && rsp_next_overwrite) {
                /* The checked full overwrite has committed. A memory load
                 * fault still uses rsp_before in its search record; a
                 * successful load replaces rather than adjusts RSP. */
                rsp_pending = 0;
            }
            int step = rsp_step;
            int after = rsp_pending + step;
            bool continues = false;
            /* No deferred RSP remains when adjustments cancel. The next
             * instruction can classify itself without a continuation check. */
            if (after && i + 1 < icount) {
                rsp_next_step = ft_rsp_merge_step(&fields_buf[i + 1]);
                rsp_next_step_valid = true;
                continues = ft_rsp_merge_can_continue(&fields_buf[i + 1], after,
                    x87_top_active, rsp_next_step, &rsp_next_adjust_memory,
                    &rsp_next_overwrite);
            }
            if (rsp_direct) {
                if (!continues && after) {
                    uint32_t *out = insn_code + insn_emitted;
                    FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                                      ft_gpr(rsp_index), after);
                    insn_emitted = out - insn_code;
                }
                rsp_pending = continues ? after : 0;
            } else if (step && (rsp_pending || continues)) {
                insn_emitted = ft_rsp_merge_apply(fields, insn_code,
                    insn_emitted, rsp_pending, after, !continues, step);
                if (insn_emitted < 0) {
                    return ft_primary_fail_decoded(env, failure,
                        QUICKTRANS_FAILURE_STAGE_EMIT,
                        QUICKTRANS_FAILURE_REASON_INSN_EMIT,
                        fields->address, fields, i);
                }
                rsp_elided = insn_emitted == 0;
                rsp_pending = continues ? after : 0;
            } else if (rsp_pending && !continues) {
                uint32_t *out = insn_code + insn_emitted;
                FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                                  ft_gpr(rsp_index), rsp_pending);
                insn_emitted = out - insn_code;
                rsp_pending = 0;
            }
        }
#endif
        if (!insn_emitted && !rsp_elided && !ft_emit_zero_code_allowed(fields)) {
            fprintf(stderr,
                    "[FT] fd-primary emit-fail index=%d pc=0x%lx id=%d "
                    "size=%u kind=%d\n",
                    i, (unsigned long)fields->address, fields->id,
                    fields->size,
                    fields->kind);
            return ft_primary_fail_decoded(
                env, failure, QUICKTRANS_FAILURE_STAGE_EMIT,
                QUICKTRANS_FAILURE_REASON_INSN_EMIT, fields->address,
                fields, i);
        }
        emitted += insn_emitted;
        if (fields->kind == FT_EMMS) {
            mmx_active = false;
        }
        if (stage_stats) {
            ft_primary_stage_stats.kind_emit_ns[fields->kind] +=
                ft_bench_now_ns() - kind_emit_start;
            ft_primary_stage_stats.kind_words[fields->kind] += insn_emitted;
            if (emit_profile) {
                ft_emit_profile_record(fields, meta, insn_code, insn_emitted);
            }
        }
        if (debug_code) {
            ft_primary_debug_dump_code(fields->address, fields, code, emitted);
        }
        if (!option_soft_fpu && x87_top_active && meta->terminal_exit) {
            uint32_t *out = code + emitted;
            int top_emitted = ft_emit_x87_top_save(&out);

            if (!top_emitted) {
                return ft_primary_fail_decoded(
                    env, failure, QUICKTRANS_FAILURE_STAGE_EXIT,
                    QUICKTRANS_FAILURE_REASON_X87_TOP_STORE,
                    fields->address, fields, i);
            }
            emitted += top_emitted;
            x87_top_active = false;
        }

#if defined(QUICKTRANS_LATU) && !FT_WITH_RSP_MERGE
        /* The specialized encoder writes literal zero RSP deltas. */
        tcg_ctx->gen_insn_data[i][0] = fields->address;
#else
        ft_set_insn_start_data(i, fields->address);
#endif
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
        tcg_ctx->gen_insn_data[i][1] = (target_ulong)(int64_t)rsp_before;
#endif
        ft_set_insn_end_off(i, emitted << 2);

        if (meta->terminal_exit) {
            int64_t search_start = stage_stats ? ft_bench_now_ns() : 0;

#ifndef QUICKTRANS_LATU
            tb->ir2_num = emitted;
#endif
            *code_size = emitted * 4;
#ifdef QUICKTRANS_LATU
            *search_size = FT_SEARCH_NAME(tb, fields_buf,
                                            (uint8_t *)(code + emitted), true);
#else
            if (option_split_search) {
                void *search_block = region_alloc_search_size(
                    tb, curr_mtcc(env),
                    (size_t)tb->icount * (TARGET_INSN_START_WORDS + 3) + 9);

                if (!search_block) {
                    *code_size = __GENCODE_ERR_AUX_DATA_OVERFLOW;
                    return false;
                }
                *search_size = 0;
                if (FT_SEARCH_NAME(tb, fields_buf, search_block, false) < 0) {
                    return ft_primary_fail_decoded(
                        env, failure, QUICKTRANS_FAILURE_STAGE_EXIT,
                        QUICKTRANS_FAILURE_REASON_SEARCH_ENCODE,
                        fields->address, fields, i);
                }
            } else {
                *search_size = FT_SEARCH_NAME(tb, fields_buf,
                                                (uint8_t *)(code + emitted),
                                                true);
            }
#endif
            if (stage_stats) {
                int64_t now = ft_bench_now_ns();

                stage_search_ns += now - search_start;
                ft_primary_stage_stats_record(
                    now - stage_total_start, stage_decode_ns,
                    stage_analyze_ns,
                    search_start - stage_emit_start, stage_search_ns);
            }
            if (*search_size < 0) {
                return ft_primary_fail_decoded(
                    env, failure, QUICKTRANS_FAILURE_STAGE_EXIT,
                    QUICKTRANS_FAILURE_REASON_SEARCH_ENCODE,
                    fields->address, fields, i);
            }
            ft_primary_tb_trace(tb, fields_buf, icount, emitted);
            return true;
        }
    }

    {
        uint32_t *out = code + emitted;
        int exit_emitted;

        if (!option_soft_fpu && x87_top_active) {
            int top_emitted = ft_emit_x87_top_save(&out);

            if (!top_emitted) {
                int last = icount - 1;
                FastTemplateFields *last_fields = &fields_buf[last];

                return ft_primary_fail_decoded(
                    env, failure, QUICKTRANS_FAILURE_STAGE_EXIT,
                    QUICKTRANS_FAILURE_REASON_X87_TOP_STORE,
                    last_fields->address, last_fields, last);
            }
            emitted += top_emitted;
        }

        exit_emitted =
            ft_emit_direct_link_exit(tb, &out, 0, tb->pc + tb->size, la_t1);

        if (!exit_emitted) {
            int last = icount - 1;
            FastTemplateFields *last_fields = &fields_buf[last];

            return ft_primary_fail_decoded(
                env, failure, QUICKTRANS_FAILURE_STAGE_EXIT,
                QUICKTRANS_FAILURE_REASON_DIRECT_EXIT,
                tb->pc + tb->size, last_fields, last);
        }
        emitted += exit_emitted;
    }
    if (emitted <= 0 || tb->icount <= 0) {
        int last = icount - 1;

        return ft_primary_fail_decoded(
            env, failure, QUICKTRANS_FAILURE_STAGE_EXIT,
            QUICKTRANS_FAILURE_REASON_EMPTY_OUTPUT, tb->pc + tb->size,
            last >= 0 ? &fields_buf[last] : NULL, last);
    }
    ft_set_insn_end_off(tb->icount - 1, emitted << 2);
#ifndef QUICKTRANS_LATU
    tb->ir2_num = emitted;
#endif
    *code_size = emitted * 4;
    {
        int64_t search_start = stage_stats ? ft_bench_now_ns() : 0;

#ifdef QUICKTRANS_LATU
    *search_size = FT_SEARCH_NAME(tb, fields_buf,
                                    (uint8_t *)(code + emitted), true);
#else
    if (option_split_search) {
        void *search_block = region_alloc_search_size(
            tb, curr_mtcc(env),
            (size_t)tb->icount * (TARGET_INSN_START_WORDS + 3) + 9);

        if (!search_block) {
            *code_size = __GENCODE_ERR_AUX_DATA_OVERFLOW;
            return false;
        }
        *search_size = 0;
        if (FT_SEARCH_NAME(tb, fields_buf, search_block, false) < 0) {
            int last = icount - 1;
            FastTemplateFields *last_fields = &fields_buf[last];

            return ft_primary_fail_decoded(
                env, failure, QUICKTRANS_FAILURE_STAGE_EXIT,
                QUICKTRANS_FAILURE_REASON_SEARCH_ENCODE,
                last_fields->address, last_fields, last);
        }
    } else {
        *search_size = FT_SEARCH_NAME(tb, fields_buf,
                                        (uint8_t *)(code + emitted),
                                        true);
    }
#endif
        if (stage_stats) {
            int64_t now = ft_bench_now_ns();

            stage_search_ns += now - search_start;
            ft_primary_stage_stats_record(
                now - stage_total_start, stage_decode_ns, stage_analyze_ns,
                search_start - stage_emit_start, stage_search_ns);
        }
    }
    if (*search_size < 0) {
        int last = icount - 1;
        FastTemplateFields *last_fields = &fields_buf[last];

        return ft_primary_fail_decoded(
            env, failure, QUICKTRANS_FAILURE_STAGE_EXIT,
            QUICKTRANS_FAILURE_REASON_SEARCH_ENCODE, last_fields->address,
            last_fields, last);
    }
    ft_primary_tb_trace(tb, fields_buf, icount, emitted);
    return true;
}

