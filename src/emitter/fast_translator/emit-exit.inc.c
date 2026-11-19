/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* TB exit, direct-link, and branch metadata emit helpers. */

typedef struct FastJccDirectExitLayout {
    int first_jmp_align;
    int exit0;
    int exit1;
    int total;
} FastJccDirectExitLayout;

typedef struct FastTuDirectEmitStats {
    uint64_t jcc_candidates;
    uint64_t jcc_ineligible;
    uint64_t jcc_emitted;
    uint64_t jcc_emit_fail;
    uint64_t jmp_candidates;
    uint64_t jmp_ineligible;
    uint64_t jmp_emitted;
    uint64_t jmp_emit_fail;
} FastTuDirectEmitStats;

static FastTuDirectEmitStats ft_tu_direct_emit_stats;

static void ft_tu_direct_emit_stats_dump(void)
{
    fprintf(stderr,
            "[FT-TU-DIRECT-STATS] emit "
            "jcc_candidates=%" PRIu64 " jcc_ineligible=%" PRIu64
            " jcc_emitted=%" PRIu64 " jcc_emit_fail=%" PRIu64
            " jmp_candidates=%" PRIu64 " jmp_ineligible=%" PRIu64
            " jmp_emitted=%" PRIu64 " jmp_emit_fail=%" PRIu64 "\n",
            ft_tu_direct_emit_stats.jcc_candidates,
            ft_tu_direct_emit_stats.jcc_ineligible,
            ft_tu_direct_emit_stats.jcc_emitted,
            ft_tu_direct_emit_stats.jcc_emit_fail,
            ft_tu_direct_emit_stats.jmp_candidates,
            ft_tu_direct_emit_stats.jmp_ineligible,
            ft_tu_direct_emit_stats.jmp_emitted,
            ft_tu_direct_emit_stats.jmp_emit_fail);
}

static bool ft_tu_direct_stats_enabled(void)
{
#ifdef CONFIG_LATX_DEBUG
    static bool initialized;
    static bool enabled;

    if (!initialized) {
        enabled = getenv("LATX_FT_TU_DIRECT_STATS") != NULL;
        if (enabled) {
            atexit(ft_tu_direct_emit_stats_dump);
        }
        initialized = true;
    }
    return enabled;
#else
    return false;
#endif
}

static void ft_prepare_direct_link_exit(TranslationBlock *tb, uint32_t *out,
                                        int succ_id,
                                        target_ulong exit_target);

static bool ft_tu_mode_enabled(void)
{
#ifdef QUICKTRANS_LATU
    static bool initialized;
    static bool enabled;

    if (!initialized) {
        const char *value = getenv("LATX_TU");

        enabled = value && value[0] && strcmp(value, "0");
        initialized = true;
    }
    return enabled;
#else
#ifdef QUICKTRANS_LATS_SPLIT_TB_ABI
    return jit_tu_enabled();
#else
    return option_tu != 0;
#endif
#endif
}

static int ft_code_accl_padding(uintptr_t tb_base, int counter, int ninst)
{
    int offset;
    int padding = 0;

    if (!qemu_icache_linesize || ninst >= (qemu_icache_linesize >> 2)) {
        return 0;
    }

    offset = (tb_base + ((uintptr_t)counter << 2)) &
             (qemu_icache_linesize - 1);
    while (offset > qemu_icache_linesize - (ninst << 2)) {
        padding++;
        ninst--;
    }

    return padding;
}

static FastJccDirectExitLayout ft_jcc_direct_exit_layout(uintptr_t tb_base,
                                                         int start_ir2)
{
    FastJccDirectExitLayout layout;
    int cur = 0;

    cur++; /* bne cond, zero, taken_exit */
    layout.first_jmp_align = cur;

    cur += ft_code_accl_padding(tb_base, start_ir2 + cur, 2);
    layout.exit0 = cur;
    cur += 2; /* pcaddu18i + jirl ret_id_0 */

    cur += ft_code_accl_padding(tb_base, start_ir2 + cur, 2);
    layout.exit1 = cur;
    cur += 2; /* pcaddu18i + jirl ret_id_1 */

    layout.total = cur;
    return layout;
}

static target_ulong ft_exit_target_pc(target_ulong pc)
{
#if defined(CONFIG_LATX_KZT)
    return (target_ulong)kzt_get_alternate_pc((uintptr_t)pc);
#else
    return pc;
#endif
}

#ifndef QUICKTRANS_LATU
static bool ft_debug_jcc_enabled(void)
{
#ifdef CONFIG_LATX_DEBUG
    static bool initialized;
    static bool enabled;

    if (!initialized) {
        enabled = getenv("LATX_FT_DEBUG_JCC") != NULL;
        initialized = true;
    }
    return enabled;
#else
    return false;
#endif
}

/*
 * LATS TB linking patches the fixed "b 2; nop" pair at jmp_insn_offset in
 * both linux-user and system mode.  The current TB address must be in a6
 * before that pair so the unlinked context-switch path sees the same layout
 * and state as the legacy translator.
 */
static void ft_emit_lats_tb_addr(uint32_t **out, TranslationBlock *tb)
{
    int64_t offset = ((intptr_t)tb - (intptr_t)*out) >> 2;

    if (int32_in_int20(offset)) {
        FT_LA_PCADDI_EMIT(out, la_a6, offset);
    } else if (split_tb_base_ok()) {
        ft_emit_li32_two(out, la_a6, (uint32_t)(uintptr_t)tb);
        FT_LA_LU32I_D_EMIT(out, la_a6, 0);
    } else {
        /* The normal system allocator uses one of the two compact forms. */
        ft_emit_li64(out, la_a6, (uintptr_t)tb);
    }
}

static void ft_emit_lats_static_jump(uint32_t **out, ADDR target,
                                     int scratch_reg)
{
    int64_t offset = ((intptr_t)target - (intptr_t)*out) >> 2;

    if (option_large_code_cache && !int32_in_int26(offset)) {
        int64_t upper = ((offset + (1 << 15)) >> 16) & 0xfffff;
        int16_t lower = offset;

        FT_LA_PCADDU18I_EMIT(out, scratch_reg, upper);
        FT_LA_JIRL_EMIT(out, la_zero, scratch_reg, lower);
    } else {
        FT_LA_B_EMIT(out, offset);
    }
}

static void ft_emit_lats_static_call(uint32_t **out, ADDR target,
                                     int scratch_reg, bool patchable)
{
    int64_t offset = ((intptr_t)target - (intptr_t)*out) >> 2;

    if (option_large_code_cache && !int32_in_int26(offset)) {
        int64_t upper = ((offset + (1 << 15)) >> 16) & 0xfffff;
        int16_t lower = offset;

        FT_LA_PCADDU18I_EMIT(out, scratch_reg, upper);
        FT_LA_JIRL_EMIT(out, la_ra, scratch_reg, lower);
    } else {
        FT_LA_BL_EMIT(out, offset);
        if (patchable) {
            /* TB link/unlink saves and restores an eight-byte slot.
             * Fixed helper calls use the legacy one-instruction BL. */
            FT_LA_NOP_EMIT(out);
        }
    }
}

static int ft_emit_tu_indirect_dispatch_exit(TranslationBlock *tb,
                                             uint32_t **out, int target_reg,
                                             int scratch_reg);

static void ft_emit_lats_direct_link_exit(TranslationBlock *tb,
                                          uint32_t **out, int succ_id,
                                          target_ulong target,
                                          int scratch_reg)
{
    uintptr_t off;
    ADDR cs_target = ft_context_switch_retn_target(succ_id);

    target = ft_exit_target_pc(target);
    tb->next_pc[succ_id] = target;
#ifdef CONFIG_SOFTMMU
    if (tb->flags & HF_INHIBIT_IRQ_MASK) {
        ft_emit_li64(out, la_a5, target);
        ft_emit_tu_indirect_dispatch_exit(tb, out, la_a5, la_a6);
        return;
    }
    /* A direct patch is valid only while the destination has the same
     * physical backing. A different virtual page can change independently
     * of this TB (e.g. a process-private copy of a shared code page).
     * Dispatch through the current mapping until QT emits page-check stubs.
     */
    if (((target ^ tb->pc) & TARGET_PAGE_MASK) ||
        ((target ^ (target + 15)) & TARGET_PAGE_MASK) ||
        !lsenv->tr_data->can_link) {
        tb->jmp_reset_offset[succ_id] = TB_JMP_OFFSET_INVALID;
        tb->jmp_insn_offset[succ_id] = TB_JMP_OFFSET_INVALID;
        ft_emit_li64(out, la_a5, target);
        ft_emit_store_env(out, la_a5, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_jump_epilogue(out, ft_context_switch_ret0_target(), scratch_reg);
        return;
    }
#endif
    if (!option_lazypc) {
        /*
         * t0-t7 hold mapped guest GPRs until the system epilogue saves
         * them.  The branch comparison may also live in scratch_reg.
         * Use a call-clobbered argument register for the eager PC store.
         */
        int pc_reg = la_a5;

        ft_emit_li64(out, pc_reg, target);
        ft_emit_store_env(out, pc_reg, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
    }
    tb->jmp_target_addr[succ_id] = 0;
    tb->link_opt[succ_id] = 0;

    ft_emit_lats_tb_addr(out, tb);
    while (ft_code_accl_padding((uintptr_t)tb->tc.ptr,
                                (*out - (uint32_t *)tb->tc.ptr), 2)) {
        FT_LA_NOP_EMIT(out);
    }
    off = (uintptr_t)*out - (uintptr_t)tb->tc.ptr;
    tb->jmp_insn_offset[succ_id] = off;
    tb->jmp_reset_offset[succ_id] = off + 8;
    if (option_link_opt) {
        tb->link_opt[succ_id] = 1;
        ft_emit_lats_static_call(out, cs_target, scratch_reg, true);
    } else {
        FT_LA_B_EMIT(out, 2);
        FT_LA_NOP_EMIT(out);
        ft_emit_lats_static_jump(out, cs_target, scratch_reg);
    }
    if (ft_debug_jcc_enabled()) {
        fprintf(stderr,
                "[FT-JCC] tb=%p exit=%d code=%p next=0x%lx static=%p "
                "region=0x%zx linkoff=0x%lx\n",
                tb, succ_id, *out, (unsigned long)tb->next_pc[succ_id],
                (void *)cs_target, lsenv->tr_data->tcg_region_offset[
                    curr_mtcc(current_cpu->env_ptr)], (unsigned long)off);
    }
}
#endif

#ifdef QUICKTRANS_LATU
static FastJccDirectExitLayout ft_prepare_jcc_direct_exit(TranslationBlock *tb,
                                                          uint32_t *out)
{
    FastJccDirectExitLayout layout;
    int start_ir2;

    if (!tb) {
        return (FastJccDirectExitLayout){ 0 };
    }

    start_ir2 = ((uintptr_t)out - (uintptr_t)tb->tc.ptr) >> 2;
    layout = ft_jcc_direct_exit_layout((uintptr_t)tb->tc.ptr, start_ir2);
    tb->first_jmp_align = (start_ir2 + layout.first_jmp_align) << 2;
    tb->jmp_target_arg[0] = (start_ir2 + layout.exit0) << 2;
    tb->jmp_reset_offset[0] = tb->jmp_target_arg[0] + B_STUB_SIZE;
    tb->jmp_target_arg[1] = (start_ir2 + layout.exit1) << 2;
    tb->jmp_reset_offset[1] = tb->jmp_target_arg[1] + B_STUB_SIZE;
    return layout;
}
#endif

#ifdef CONFIG_SOFTMMU
#ifdef CONFIG_LATX_TU
static bool ft_tu_direct_jcc_enabled(void);
#endif

/* Ordinary TB link slots accept native ordered branches. TU patches use
 * BEQ/BNE slots, so keep their existing integer predicate encoding. */
static bool ft_lats_native_order(const TranslationBlock *tb,
                                 const FastTemplateFields *f)
{
#ifdef CONFIG_LATX_TU
    if (tb && tb->s_data && ft_tu_direct_jcc_enabled()) return false;
#endif
    return f->direct_cmp_lhs_gpr >= 0 &&
           f->direct_branch_kind >= FT_DIRECT_BRANCH_LT &&
           f->direct_branch_kind <= FT_DIRECT_BRANCH_GTU;
}

static uint32_t ft_lats_order_branch(FastDirectBranchKind kind, int lhs,
                                     int rhs, int offset)
{
    switch (kind) {
    case FT_DIRECT_BRANCH_LT:  return FT_LA_BLT(lhs, rhs, offset);
    case FT_DIRECT_BRANCH_GE:  return FT_LA_BGE(lhs, rhs, offset);
    case FT_DIRECT_BRANCH_LTU: return FT_LA_BLTU(lhs, rhs, offset);
    case FT_DIRECT_BRANCH_GEU: return FT_LA_BGEU(lhs, rhs, offset);
    case FT_DIRECT_BRANCH_LE:  return FT_LA_BGE(rhs, lhs, offset);
    case FT_DIRECT_BRANCH_GT:  return FT_LA_BLT(rhs, lhs, offset);
    case FT_DIRECT_BRANCH_LEU: return FT_LA_BGEU(rhs, lhs, offset);
    case FT_DIRECT_BRANCH_GTU: return FT_LA_BLTU(rhs, lhs, offset);
    default: g_assert_not_reached();
    }
}

static int ft_float_branch_fcc(FastDirectBranchKind kind)
{
    /* FCC2 holds unordered-or-less. FCC0 holds the other predicates. */
    return kind == FT_DIRECT_BRANCH_LTU || kind == FT_DIRECT_BRANCH_GEU ? 2 : 0;
}
#endif

static int ft_emit_jcc_exit_or_self_loop(TranslationBlock *tb, uint32_t *code,
                                         uint32_t **out, target_ulong pc,
                                         const FastTemplateFields *fields,
                                         int lhs, int rhs,
                                         bool taken_if_equal)
{
#ifdef QUICKTRANS_LATU
    if (!ft_tu_mode_enabled() &&
        fields->imm64 == tb->pc && pc + fields->size == tb->pc + tb->size) {
        uint32_t *tb_code = (uint32_t *)tb->tc.ptr;

        if (taken_if_equal) {
            FT_LA_BNE_EMIT(out, lhs, rhs, 2);
        } else {
            FT_LA_BEQ_EMIT(out, lhs, rhs, 2);
        }
        FT_LA_B_EMIT(out, tb_code - *out);
        if (!ft_emit_direct_link_exit(tb, out, 0, pc + fields->size, la_t1)) {
            return 0;
        }
        return *out - code;
    }

    {
        uint32_t *start = *out;
        FastJccDirectExitLayout layout =
            ft_prepare_jcc_direct_exit(tb, *out);

        if (taken_if_equal) {
            FT_LA_BEQ_EMIT(out, lhs, rhs, layout.exit1);
        } else {
            FT_LA_BNE_EMIT(out, lhs, rhs, layout.exit1);
        }
        while (*out - start < layout.exit0) {
            FT_LA_NOP_EMIT(out);
        }
        ft_emit_jump_epilogue(out, context_switch_native_to_bt_ret_id_0,
                              la_t1);
        while (*out - start < layout.exit1) {
            FT_LA_NOP_EMIT(out);
        }
        ft_emit_jump_epilogue(out, context_switch_native_to_bt_ret_id_1,
                              la_t1);
        return *out - code;
    }
#else
    uint32_t *taken_branch;
    target_ulong next = pc + fields->size;
    target_ulong target = fields->imm64;

    if (!out || !code) {
        return 0;
    }

    taken_branch = (*out)++;
    ft_emit_lats_direct_link_exit(tb, out, 0, next, la_a4);
#ifdef CONFIG_SOFTMMU
    if (ft_lats_native_order(tb, fields)) {
        *taken_branch = ft_lats_order_branch(fields->direct_branch_kind, lhs, rhs,
                                             *out - taken_branch);
    } else if (fields->direct_float_xx && lhs != la_zero) {
        int fcc = ft_float_branch_fcc(fields->direct_branch_kind);
        int offset = *out - taken_branch;

        *taken_branch = taken_if_equal ? FT_LA_BCEQZ(fcc, offset) :
                                         FT_LA_BCNEZ(fcc, offset);
    } else
#endif
    if (taken_if_equal) {
        *taken_branch = FT_LA_BEQ(lhs, rhs, *out - taken_branch);
    } else {
        *taken_branch = FT_LA_BNE(lhs, rhs, *out - taken_branch);
    }
    ft_emit_lats_direct_link_exit(tb, out, 1, target, la_a4);
    return *out - code;
#endif
}

static void ft_emit_align_inst(uint32_t **out, uintptr_t base, int align,
                               uint32_t filling)
{
    int inst = ((uintptr_t)*out - base) >> 2;

    while (inst % align) {
        ft_emit_raw(out, filling);
        inst++;
    }
}

static void ft_emit_jrra_call_metadata(TranslationBlock *tb, uint32_t **out,
                                       uintptr_t base, target_ulong next_pc,
                                       bool direct_call)
{
#ifdef CONFIG_LATX_JRRA
    if (!tb) {
        return;
    }

    if (option_jr_ra_stack) {
        ft_emit_align_inst(out, base, 2, FT_LA_NOP());
#ifndef QUICKTRANS_LATS_RAS_DEST_ABI
        tb->return_target_ptr = (unsigned long *)*out;
#endif
#ifndef QUICKTRANS_LATS_SPLIT_TB_ABI
        tb->next_86_pc = next_pc;
#endif
        if (direct_call) {
            FT_LA_NOP_EMIT(out);
        } else {
            FT_LA_NOP_EMIT(out);
            FT_LA_NOP_EMIT(out);
        }
        FT_LA_GR2SCR_EMIT(out, 0, la_zero);
    }

    if (option_jr_ra) {
        ft_emit_align_inst(out, base, 2, FT_LA_NOP());
#ifndef QUICKTRANS_LATS_RAS_DEST_ABI
        tb->return_target_ptr = (unsigned long *)*out;
#endif
#ifndef QUICKTRANS_LATS_SPLIT_TB_ABI
        tb->next_86_pc = next_pc;
#endif
        FT_LA_NOP_EMIT(out);
        FT_LA_NOP_EMIT(out);
        FT_LA_NOP_EMIT(out);
        FT_LA_GR2SCR_EMIT(out, 0, la_zero);
    }
#else
    (void)tb;
    (void)out;
    (void)base;
    (void)next_pc;
    (void)direct_call;
#endif
}

static void ft_emit_tu_native_return_metadata(TranslationBlock *tb,
                                              uint32_t **out,
                                              uintptr_t base,
                                              target_ulong next_pc)
{
#ifdef CONFIG_LATX_TU
    if (!tb) {
        return;
    }

    ft_emit_align_inst(out, base, 2, FT_LA_NOP());
#ifndef QUICKTRANS_LATS_RAS_DEST_ABI
    tb->return_target_ptr = (unsigned long *)*out;
#endif
#ifndef QUICKTRANS_LATS_SPLIT_TB_ABI
    tb->next_86_pc = next_pc;
#endif
    FT_LA_NOP_EMIT(out);
    FT_LA_NOP_EMIT(out);
#else
    (void)tb;
    (void)out;
    (void)base;
    (void)next_pc;
#endif
}

static void ft_prepare_ret_indirect_goto(TranslationBlock *tb, uint32_t *code)
{
    if (!tb) {
        return;
    }

#ifdef QUICKTRANS_LATU
    tb->bool_flags |= IS_INDIRECT_JMP;
#elif defined(CONFIG_LATX_TU)
    if (tb->s_data) {
        tb->s_data->sys_eob_is_indir = 1;
    }
#ifndef QUICKTRANS_LATS_SPLIT_TB_ABI
    tb->jmp_indirect = ((uintptr_t)code - (uintptr_t)tb->tc.ptr) + 8;
#endif
#endif
}

#ifndef QUICKTRANS_LATU
static bool ft_lats_soft_ras_enabled(TranslationBlock *tb)
{
#ifdef QUICKTRANS_LATS_SPLIT_TB_ABI
    /* The host patches TP-based RAS sites, not the legacy slow-RAS layout. */
    (void)tb;
    return false;
#endif
    if (!option_soft_ras || !tb) {
        return false;
    }
#ifdef CONFIG_RAS_DISABLE_CPL0
    if (!(tb->flags & HF_CPL_MASK)) {
        return false;
    }
#endif
    return true;
}

static void ft_emit_lats_soft_ras_ptr(uint32_t **out, int reg)
{
    FT_LA_SCR2GR_EMIT(out, reg, 0);
#ifdef CONFIG_SOFTMMU
    if (hamt_enabled() && hamt_mode_dmw()) {
        FT_LA_LU52I_D_EMIT(out, reg, reg, -0x700);
    }
#endif
}

/* Keep this layout in sync with latxs_ras_link()'s CONFIG_RAS_SLOW patch. */
static void ft_emit_lats_soft_ras_push(TranslationBlock *tb, uint32_t **out,
                                       target_ulong return_pc)
{
    const int top_offset = (int)offsetof(Soft_RAS, top) -
                           (int)offsetof(Soft_RAS, stack);
    const int pc_offset = offsetof(RAS_Entry, pc);
    const int ptr_offset = offsetof(RAS_Entry, ptr);
    int ras_ptr = la_a0;
    int top = la_a1;
    int entry = la_a2;
    int guest_pc = la_a3;

    if (!ft_lats_soft_ras_enabled(tb)) {
        return;
    }

    ft_emit_li64(out, guest_pc, return_pc + tb->cs_base);
    ft_emit_lats_soft_ras_ptr(out, ras_ptr);
    FT_LA_LD_W_EMIT(out, top, ras_ptr, top_offset);
    FT_LA_ANDI_EMIT(out, top, top, RAS_SIZE - 1);
    FT_LA_ALSL_D_EMIT(out, entry, top, ras_ptr, 3);
    FT_LA_ST_D_EMIT(out, guest_pc, entry, pc_offset);

    tb->inst_ptr_offset = (uintptr_t)*out - (uintptr_t)tb->tc.ptr;
    FT_LA_B_EMIT(out, 0);
    FT_LA_NOP_EMIT(out);
    FT_LA_ST_D_EMIT(out, guest_pc, entry, ptr_offset);
    FT_LA_ADDI_D_EMIT(out, top, top, 0);
    FT_LA_ST_W_EMIT(out, top, ras_ptr, top_offset);
}

static void ft_emit_lats_soft_ras_pop(TranslationBlock *tb, uint32_t **out,
                                      int return_pc)
{
    const int top_offset = (int)offsetof(Soft_RAS, top) -
                           (int)offsetof(Soft_RAS, stack);
    const int pc_offset = offsetof(RAS_Entry, pc);
    const int ptr_offset = offsetof(RAS_Entry, ptr);
    FastBranchLabel miss = { 0 };
    FastBranchFixup pc_miss;
    FastBranchFixup ptr_miss;
#ifdef CONFIG_SOFTMMU
    FastBranchFixup interrupt_miss;
    bool check_interrupt = option_int_opt == 2 &&
                           !(tb->flags & HF_CPL_MASK);
#endif
    int ras_ptr = la_a0;
    int top = la_a1;
    int entry = la_a2;
    int expected_pc = la_a3;

    if (!ft_lats_soft_ras_enabled(tb)) {
        return;
    }

    ft_emit_lats_soft_ras_ptr(out, ras_ptr);
    FT_LA_LD_W_EMIT(out, top, ras_ptr, top_offset);
    FT_LA_ADDI_D_EMIT(out, top, top, -1);
    FT_LA_ALSL_D_EMIT(out, entry, top, ras_ptr, 3);
    FT_LA_LD_D_EMIT(out, expected_pc, entry, pc_offset);
    ft_emit_branch_placeholder(out, &pc_miss, FT_BRANCH_BNE, expected_pc,
                               return_pc, &miss);
    FT_LA_ST_W_EMIT(out, top, ras_ptr, top_offset);
#ifdef CONFIG_SOFTMMU
    if (check_interrupt) {
        const int int_offset =
            (int)offsetof(X86CPU, neg.icount_decr.u32) -
            (int)offsetof(X86CPU, env);

        ft_emit_load_env(out, expected_pc, int_offset, FT_LA_OPCODE_LD_W);
        ft_emit_branch_placeholder(out, &interrupt_miss, FT_BRANCH_BLT,
                                   expected_pc, la_zero, &miss);
    }
#endif
    FT_LA_LD_D_EMIT(out, entry, entry, ptr_offset);
    ft_emit_branch_placeholder(out, &ptr_miss, FT_BRANCH_BEQ, entry, la_zero,
                               &miss);
    FT_LA_JIRL_EMIT(out, la_zero, entry, 0);
    ft_bind_branch_label(&miss, *out);
    ft_resolve_branch_fixup(&pc_miss);
    ft_resolve_branch_fixup(&ptr_miss);
#ifdef CONFIG_SOFTMMU
    if (check_interrupt) {
        ft_resolve_branch_fixup(&interrupt_miss);
    }
#endif
}
#endif

static void ft_emit_jump_epilogue(uint32_t **out, ADDR target,
                                  int scratch_reg)
{
#ifdef QUICKTRANS_LATU
    ptrdiff_t insn_offset = ((uintptr_t)target - (uintptr_t)*out) >> 2;
    ptrdiff_t lower = (int16_t)insn_offset;
    ptrdiff_t upper = (insn_offset - lower) >> 16;

    FT_LA_PCADDU18I_EMIT(out, scratch_reg, upper);
    FT_LA_JIRL_EMIT(out, la_a0, scratch_reg, lower);
#else
#ifdef CONFIG_SOFTMMU
    /*
     * The static system epilogue saves all mapped guest GPRs.  Use a0 for
     * its target because the ret0 entry discards a0 before that save; t0/t1
     * are mapped to guest r8/r9 and must remain intact.
     */
    ft_emit_li64(out, la_a0, target);
    FT_LA_LU52I_D_EMIT(out, la_a0, la_a0, -0x700);
    FT_LA_JIRL_EMIT(out, la_zero, la_a0, 0);
#else
    ft_emit_li64(out, scratch_reg, target);
    FT_LA_JIRL_EMIT(out, la_a0, scratch_reg, 0);
#endif
#endif
}

static void ft_emit_far_jump_preserve_a0(uint32_t **out, ADDR target,
                                         int scratch_reg)
{
#ifdef QUICKTRANS_LATU
    ptrdiff_t insn_offset = ((uintptr_t)target - (uintptr_t)*out) >> 2;
    ptrdiff_t lower = (int16_t)insn_offset;
    ptrdiff_t upper = (insn_offset - lower) >> 16;

    FT_LA_PCADDU18I_EMIT(out, scratch_reg, upper);
    FT_LA_JIRL_EMIT(out, la_zero, scratch_reg, lower);
#else
    ft_emit_li64(out, scratch_reg, target);
    FT_LA_JIRL_EMIT(out, la_zero, scratch_reg, 0);
#endif
}

static void ft_prepare_tu_env_dispatch_exit(TranslationBlock *tb, int succ_id)
{
    if (!tb || succ_id < 0 || succ_id > 1) {
        return;
    }
#ifdef QUICKTRANS_LATU
    tb->canlink[succ_id] = LATX_CANLINK_EIP_STORED;
#else
    tb->jmp_reset_offset[succ_id] = TB_JMP_OFFSET_INVALID;
    tb->jmp_insn_offset[succ_id] = TB_JMP_OFFSET_INVALID;
#endif
}

static int ft_emit_tu_indirect_dispatch_exit(TranslationBlock *tb,
                                             uint32_t **out, int target_reg,
                                             int scratch_reg)
{
    uint32_t *start = *out;

    ft_prepare_tu_env_dispatch_exit(tb, 0);
    ft_emit_store_env(out, target_reg, lsenv_offset_of_eip(lsenv),
                      FT_LA_OPCODE_ST_D);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    if (tb->flags & HF_INHIBIT_IRQ_MASK) {
        /* Clear after successful execution, before returning to IRQ checks. */
        ft_emit_load_env(out, la_a7, ft_lsenv_offset_of_hflags(lsenv),
                         FT_LA_OPCODE_LD_WU);
        FT_LA_BSTRINS_D_EMIT(out, la_a7, la_zero,
                             HF_INHIBIT_IRQ_SHIFT, HF_INHIBIT_IRQ_SHIFT);
        ft_emit_store_env(out, la_a7, ft_lsenv_offset_of_hflags(lsenv),
                          FT_LA_OPCODE_ST_W);
    }
#endif
    ft_emit_jump_epilogue(out, ft_context_switch_ret0_target(), scratch_reg);
    return *out - start;
}

#ifndef QUICKTRANS_LATU
static int ft_emit_lats_indirect_lookup_exit(TranslationBlock *tb,
                                             uint32_t **out,
                                             int target_reg,
                                             int scratch_reg,
                                             bool is_ret)
{
    uint32_t *start = *out;
#ifdef CONFIG_SOFTMMU
    FastBranchLabel interrupt = { 0 };
    FastBranchFixup interrupt_fixup;
    bool check_interrupt = option_int_opt == 2 &&
                           (!is_ret || !(tb->flags & HF_CPL_MASK));

    if (tb->flags & HF_INHIBIT_IRQ_MASK) {
        return ft_emit_tu_indirect_dispatch_exit(tb, out, target_reg,
                                                 scratch_reg);
    }
#else
    (void)is_ret;
#endif

    /* intb_lookup uses a6 to identify the TB that produced this exit. */
    ft_emit_lats_tb_addr(out, tb);
    ft_prepare_tu_env_dispatch_exit(tb, 0);
    ft_emit_store_env(out, target_reg, lsenv_offset_of_eip(lsenv),
                      FT_LA_OPCODE_ST_D);
#ifdef CONFIG_SOFTMMU
    if (check_interrupt) {
        const int int_offset =
            (int)offsetof(X86CPU, neg.icount_decr.u32) -
            (int)offsetof(X86CPU, env);

        ft_emit_load_env(out, scratch_reg, int_offset, FT_LA_OPCODE_LD_W);
        ft_emit_branch_placeholder(out, &interrupt_fixup, FT_BRANCH_BLT,
                                   scratch_reg, la_zero, &interrupt);
    }
#endif
#ifdef QUICKTRANS_LATS_SPLIT_TB_ABI
    /* Current LATS lookup entries take the guest target in a1. */
    FT_LA_OR_EMIT(out, la_a1, target_reg, la_zero);
#endif
    ft_emit_lats_static_jump(out, ft_intb_lookup_target(tb), scratch_reg);
#ifdef CONFIG_SOFTMMU
    if (check_interrupt) {
        ft_bind_branch_label(&interrupt, *out);
        ft_resolve_branch_fixup(&interrupt_fixup);
        ft_emit_jump_epilogue(out, ft_context_switch_ret0_target(),
                              scratch_reg);
    }
#endif
    return *out - start;
}
#endif

static int ft_emit_tu_ret_dispatch_or_native(TranslationBlock *tb,
                                             uint32_t **out, int target_reg,
                                             int scratch_reg)
{
    uint32_t *start = *out;

    uintptr_t rx_base =
        (uintptr_t)tcg_splitwx_to_rx(tcg_ctx->code_gen_buffer);
    uintptr_t rx_end = rx_base + tcg_ctx->code_gen_buffer_size;
    uint32_t *bltu_fallback;
    uint32_t *bgeu_fallback;
    uint32_t *fallback;

    ft_emit_li64(out, scratch_reg, rx_base);
    bltu_fallback = *out;
    FT_LA_BLTU_EMIT(out, target_reg, scratch_reg, 0);
    ft_emit_li64(out, scratch_reg, rx_end);
    bgeu_fallback = *out;
    FT_LA_BGEU_EMIT(out, target_reg, scratch_reg, 0);
    FT_LA_JIRL_EMIT(out, la_zero, target_reg, 0);

    fallback = *out;
    *bltu_fallback =
        FT_LA_BLTU(target_reg, scratch_reg, fallback - bltu_fallback);
    *bgeu_fallback =
        FT_LA_BGEU(target_reg, scratch_reg, fallback - bgeu_fallback);

    ft_emit_tu_indirect_dispatch_exit(tb, out, target_reg, scratch_reg);
    return *out - start;
}

static void ft_prepare_direct_link_exit(TranslationBlock *tb, uint32_t *out,
                                        int succ_id, target_ulong exit_target)
{
    if (!tb) {
        return;
    }

#ifdef QUICKTRANS_LATU
    uintptr_t off = (uintptr_t)out - (uintptr_t)tb->tc.ptr;

    tb->lazypc[succ_id] = exit_target - tb->pc;
    tb->jmp_target_arg[succ_id] = off;
    tb->jmp_reset_offset[succ_id] = off + B_STUB_SIZE;
    /* TU-internal branches use tu_jmp and never reach this link slot. */
    tb->canlink[succ_id] = 1;
#else
    (void)out;
    tb->next_pc[succ_id] = exit_target;
    tb->jmp_reset_offset[succ_id] = TB_JMP_OFFSET_INVALID;
    tb->jmp_insn_offset[succ_id] = TB_JMP_OFFSET_INVALID;
    tb->jmp_target_addr[succ_id] = 0;
#endif
}

static void ft_emit_direct_link_reset_slot(uint32_t **out)
{
#ifdef QUICKTRANS_LATU
#if B_STUB_SIZE == 8
    FT_LA_B_EMIT(out, 2);
    FT_LA_NOP_EMIT(out);
#elif B_STUB_SIZE == 4
    FT_LA_B_EMIT(out, 1);
#elif B_STUB_SIZE != 0
#error Unsupported B_STUB_SIZE for fast direct-link slot
#endif
#else
    (void)out;
#endif
}

static int ft_emit_direct_link_exit(TranslationBlock *tb, uint32_t **out,
                                    int succ_id, target_ulong target,
                                    int scratch_reg)
{
    uint32_t *start = *out;
    target_ulong exit_target = ft_exit_target_pc(target);

#ifdef QUICKTRANS_LATU
    ft_prepare_direct_link_exit(tb, *out, succ_id, exit_target);
    ft_emit_direct_link_reset_slot(out);
    ft_emit_jump_epilogue(out,
                          succ_id ? context_switch_native_to_bt_ret_id_1 :
                                    context_switch_native_to_bt_ret_id_0,
                          scratch_reg);
#else
    ft_emit_lats_direct_link_exit(tb, out, succ_id, exit_target, scratch_reg);
#endif
    return *out - start;
}

static int ft_emit_tu_unlink_exit(TranslationBlock *tb, uint32_t **out,
                                  int succ_id, target_ulong target,
                                  int scratch_reg)
{
#ifdef QUICKTRANS_LATU
    uint32_t *start = *out;
    target_ulong exit_target = ft_exit_target_pc(target);
    ADDR epilogue = succ_id ? context_switch_native_to_bt_ret_id_1 :
                              context_switch_native_to_bt_ret_id_0;

    if (tb) {
        tb->lazypc[succ_id] = exit_target - tb->pc;
    }
    FT_LA_PCADDI_EMIT(out, la_a0, 0);
    ft_emit_far_jump_preserve_a0(out, epilogue, scratch_reg);
    return *out - start;
#else
    return ft_emit_direct_link_exit(tb, out, succ_id, target, scratch_reg);
#endif
}

static bool ft_tu_direct_jmp_enabled(void)
{
    static bool initialized;
    static bool enabled;

    if (!initialized) {
        enabled = getenv("LATX_FT_TU_DIRECT_JMP") != NULL ||
                  (ft_tu_mode_enabled() &&
                   getenv("LATX_FT_TU_DIRECT_JMP_DISABLE") == NULL);
        initialized = true;
    }
    return enabled;
}

static bool ft_tu_direct_jcc_enabled(void)
{
    static bool initialized;
    static bool enabled;

    if (!initialized) {
        enabled = getenv("LATX_FT_TU_DIRECT_JCC") != NULL ||
                  (ft_tu_mode_enabled() &&
                   getenv("LATX_FT_TU_DIRECT_JCC_DISABLE") == NULL);
        initialized = true;
    }
    return enabled;
}

static int ft_emit_tu_jcc_compare(TranslationBlock *tb,
                                  uint32_t *code,
                                  uint32_t **out,
                                  target_ulong pc,
                                  const FastTemplateFields *fields,
                                  int lhs, int rhs,
                                  bool taken_if_equal)
{
#if defined(CONFIG_LATX_TU)
    bool stats_enabled = ft_tu_direct_stats_enabled();
#ifdef QUICKTRANS_LATU
    int exit_emitted;

    if (stats_enabled) {
        ft_tu_direct_emit_stats.jcc_candidates++;
    }
    if (!ft_tu_direct_jcc_enabled() || !tb || !tb->s_data ||
        !tb->s_data->next_tb[TU_TB_INDEX_NEXT] ||
        !tb->s_data->next_tb[TU_TB_INDEX_TARGET] ||
        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] == TB_JMP_RESET_OFFSET_INVALID ||
        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] == TB_JMP_RESET_OFFSET_INVALID) {
        if (stats_enabled) {
            ft_tu_direct_emit_stats.jcc_ineligible++;
        }
        return 0;
    }
    if (taken_if_equal) {
        FT_LA_BEQ_EMIT(out, lhs, rhs, 0);
    } else {
        FT_LA_BNE_EMIT(out, lhs, rhs, 0);
    }
    FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] =
        (uintptr_t)(*out - 1) - (uintptr_t)tb->tc.ptr;
#ifndef QUICKTRANS_LATU_MINIMAL_HOST
    if (tu_bcc_jmp_retrying()) {
        FT_LA_NOP_EMIT(out);
    }
#endif
    FT_LA_B_EMIT(out, 0);
    FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] =
        (uintptr_t)(*out - 1) - (uintptr_t)tb->tc.ptr;
    FT_LA_NOP_EMIT(out);
    tb->tu_unlink.stub_offset = (uintptr_t)*out - (uintptr_t)tb->tc.ptr;
    tb->tu_unlink.rel_num = 2;
    set_use_tu_jmp(tb);
    exit_emitted = ft_emit_tu_unlink_exit(tb, out, 0, pc + fields->size,
                                          la_t1);
    if (!exit_emitted) {
        if (stats_enabled) {
            ft_tu_direct_emit_stats.jcc_emit_fail++;
        }
        return 0;
    }
    exit_emitted = ft_emit_tu_unlink_exit(tb, out, 1, fields->imm64, la_t1);
    if (!exit_emitted) {
        if (stats_enabled) {
            ft_tu_direct_emit_stats.jcc_emit_fail++;
        }
        return 0;
    }
    if (stats_enabled) {
        ft_tu_direct_emit_stats.jcc_emitted++;
    }
    return *out - code;
#else
    bool has_next;
    bool has_target;

    if (stats_enabled) {
        ft_tu_direct_emit_stats.jcc_candidates++;
    }
    if (!ft_tu_direct_jcc_enabled() || !tb || !tb->s_data) {
        return 0;
    }
    has_next = tb->s_data->next_tb[TU_TB_INDEX_NEXT] != NULL &&
               FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] != TB_JMP_RESET_OFFSET_INVALID;
    has_target = tb->s_data->next_tb[TU_TB_INDEX_TARGET] != NULL &&
                 FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] != TB_JMP_RESET_OFFSET_INVALID;
#ifdef CONFIG_SOFTMMU
    if (has_target && option_int_opt == 2 && fields->imm64 <= tb->pc) {
        has_target = false;
    }
#endif
    if (!has_next || !has_target) {
        if (stats_enabled) {
            ft_tu_direct_emit_stats.jcc_ineligible++;
        }
        return 0;
    }

    if (taken_if_equal) {
        FT_LA_BEQ_EMIT(out, lhs, rhs, 0);
    } else {
        FT_LA_BNE_EMIT(out, lhs, rhs, 0);
    }
    FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] =
        (uintptr_t)(*out - 1) - (uintptr_t)tb->tc.ptr;
    FT_LA_B_EMIT(out, 0);
    FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] =
        (uintptr_t)(*out - 1) - (uintptr_t)tb->tc.ptr;
    if (stats_enabled) {
        ft_tu_direct_emit_stats.jcc_emitted++;
    }
    return *out - code;
#endif
#else
    (void)tb;
    (void)code;
    (void)out;
    (void)pc;
    (void)fields;
    (void)lhs;
    (void)rhs;
    (void)taken_if_equal;
    return 0;
#endif
}

static int ft_emit_tu_jcc_partial_compare(TranslationBlock *tb,
                                          uint32_t *code,
                                          uint32_t **out,
                                          target_ulong pc,
                                          const FastTemplateFields *fields,
                                          int lhs, int rhs,
                                          bool taken_if_equal)
{
#if defined(CONFIG_LATX_TU)
#ifdef QUICKTRANS_LATU
    if (tb) {
        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] = TB_JMP_RESET_OFFSET_INVALID;
        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] = TB_JMP_RESET_OFFSET_INVALID;
    }
    return 0;
#else
    bool has_next;
    bool has_target;
    uint32_t *dispatch_branch;
    uint32_t *dispatch;

    if (!ft_tu_direct_jcc_enabled() || !tb || !tb->s_data) {
        if (tb) {
            FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] = TB_JMP_RESET_OFFSET_INVALID;
            FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] = TB_JMP_RESET_OFFSET_INVALID;
        }
        return 0;
    }
    has_next = tb->s_data->next_tb[TU_TB_INDEX_NEXT] != NULL &&
               FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] != TB_JMP_RESET_OFFSET_INVALID;
    has_target = tb->s_data->next_tb[TU_TB_INDEX_TARGET] != NULL &&
                 FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] != TB_JMP_RESET_OFFSET_INVALID;
#ifdef CONFIG_SOFTMMU
    if (has_target && option_int_opt == 2 && fields->imm64 <= tb->pc) {
        has_target = false;
    }
#endif
    if (has_next == has_target) {
        if (!has_next) {
            FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] = TB_JMP_RESET_OFFSET_INVALID;
            FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] = TB_JMP_RESET_OFFSET_INVALID;
        }
        return 0;
    }

    if (has_next) {
        FastBranchKind taken_kind = taken_if_equal ? FT_BRANCH_BEQ :
                                                    FT_BRANCH_BNE;

        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] = TB_JMP_RESET_OFFSET_INVALID;
        dispatch_branch = *out;
        if (taken_if_equal) {
            FT_LA_BEQ_EMIT(out, lhs, rhs, 0);
        } else {
            FT_LA_BNE_EMIT(out, lhs, rhs, 0);
        }
        FT_LA_B_EMIT(out, 0);
        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] =
            (uintptr_t)(*out - 1) - (uintptr_t)tb->tc.ptr;
        dispatch = *out;
        ft_patch_branch_to(dispatch_branch, taken_kind, lhs, rhs,
                           dispatch);
        ft_emit_direct_link_exit(tb, out, 1, fields->imm64, la_t1);
    } else {
        FastBranchKind not_taken_kind = taken_if_equal ? FT_BRANCH_BNE :
                                                        FT_BRANCH_BEQ;

        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_NEXT] = TB_JMP_RESET_OFFSET_INVALID;
        dispatch_branch = *out;
        if (taken_if_equal) {
            FT_LA_BNE_EMIT(out, lhs, rhs, 0);
        } else {
            FT_LA_BEQ_EMIT(out, lhs, rhs, 0);
        }
        FT_LA_B_EMIT(out, 0);
        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] =
            (uintptr_t)(*out - 1) - (uintptr_t)tb->tc.ptr;
        dispatch = *out;
        ft_patch_branch_to(dispatch_branch, not_taken_kind, lhs, rhs,
                           dispatch);
        ft_emit_direct_link_exit(tb, out, 0, pc + fields->size, la_t1);
    }
    return *out - code;
#endif
#else
    (void)tb;
    (void)code;
    (void)out;
    (void)pc;
    (void)fields;
    (void)lhs;
    (void)rhs;
    (void)taken_if_equal;
    return 0;
#endif
}

static int ft_emit_tu_jmp_branch_or_zero(TranslationBlock *tb,
                                         uint32_t *code,
                                         uint32_t **out,
                                         target_ulong target)
{
#if defined(CONFIG_LATX_TU)
    bool stats_enabled = ft_tu_direct_stats_enabled();
#ifdef QUICKTRANS_LATU
    int exit_emitted;

    if (stats_enabled) {
        ft_tu_direct_emit_stats.jmp_candidates++;
    }
    if (!ft_tu_direct_jmp_enabled() || !tb || !tb->s_data ||
        !tb->s_data->next_tb[TU_TB_INDEX_TARGET] ||
        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] == TB_JMP_RESET_OFFSET_INVALID) {
        if (stats_enabled) {
            ft_tu_direct_emit_stats.jmp_ineligible++;
        }
        return 0;
    }
    FT_LA_B_EMIT(out, 0);
    FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] =
        (uintptr_t)(*out - 1) - (uintptr_t)tb->tc.ptr;
    FT_LA_NOP_EMIT(out);
    tb->tu_unlink.stub_offset = (uintptr_t)*out - (uintptr_t)tb->tc.ptr;
    tb->tu_unlink.rel_num = 1;
    set_use_tu_jmp(tb);
    exit_emitted = ft_emit_tu_unlink_exit(tb, out, 0, target, la_t1);
    if (!exit_emitted) {
        if (stats_enabled) {
            ft_tu_direct_emit_stats.jmp_emit_fail++;
        }
        return 0;
    }
    if (stats_enabled) {
        ft_tu_direct_emit_stats.jmp_emitted++;
    }
    return *out - code;
#else

    if (stats_enabled) {
        ft_tu_direct_emit_stats.jmp_candidates++;
    }
    if (!ft_tu_direct_jmp_enabled() || !tb || !tb->s_data ||
        !tb->s_data->next_tb[TU_TB_INDEX_TARGET] ||
        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] == TB_JMP_RESET_OFFSET_INVALID) {
        if (tb) {
            FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] = TB_JMP_RESET_OFFSET_INVALID;
        }
        if (stats_enabled) {
            ft_tu_direct_emit_stats.jmp_ineligible++;
        }
        return 0;
    }
#ifdef CONFIG_SOFTMMU
    if (option_int_opt == 2 && target <= tb->pc) {
        FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] = TB_JMP_RESET_OFFSET_INVALID;
        if (stats_enabled) {
            ft_tu_direct_emit_stats.jmp_ineligible++;
        }
        return 0;
    }
#endif
    FT_LA_B_EMIT(out, 0);
    FT_TU_DATA(tb)->tu_jmp[TU_TB_INDEX_TARGET] =
        (uintptr_t)(*out - 1) - (uintptr_t)tb->tc.ptr;
    if (stats_enabled) {
        ft_tu_direct_emit_stats.jmp_emitted++;
    }
    return *out - code;
#endif
#else
    (void)tb;
    (void)code;
    (void)out;
    (void)target;
    return 0;
#endif
}
