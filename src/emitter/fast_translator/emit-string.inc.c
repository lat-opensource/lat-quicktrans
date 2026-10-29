/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* String instruction emit helpers. */

static void ft_patch_beq(uint32_t *branch, int rj, int rd, uint32_t *target)
{
    ft_patch_branch_to(branch, FT_BRANCH_BEQ, rj, rd, target);
}

static bool ft_string_width(const FastTemplateFields *fields, int *bytes)
{
    switch (fields->id) {
    case dt_X86_INS_MOVSB:
    case dt_X86_INS_STOSB:
    case dt_X86_INS_LODSB:
    case dt_X86_INS_CMPSB:
    case dt_X86_INS_SCASB:
    case dt_X86_INS_INSB:
    case dt_X86_INS_OUTSB:
        *bytes = 1;
        return true;
    case dt_X86_INS_MOVSW:
    case dt_X86_INS_STOSW:
    case dt_X86_INS_LODSW:
    case dt_X86_INS_CMPSW:
    case dt_X86_INS_SCASW:
    case dt_X86_INS_INSW:
    case dt_X86_INS_OUTSW:
        *bytes = 2;
        return true;
    case dt_X86_INS_MOVSD:
    case dt_X86_INS_STOSD:
    case dt_X86_INS_LODSD:
    case dt_X86_INS_CMPSD:
    case dt_X86_INS_SCASD:
    case dt_X86_INS_INSD:
    case dt_X86_INS_OUTSD:
        *bytes = 4;
        return true;
    case dt_X86_INS_MOVSQ:
    case dt_X86_INS_STOSQ:
    case dt_X86_INS_LODSQ:
    case dt_X86_INS_CMPSQ:
    case dt_X86_INS_SCASQ:
        *bytes = 8;
        return true;
    default:
        return false;
    }
}

static bool ft_string_is_movs(int id)
{
    return id == dt_X86_INS_MOVSB || id == dt_X86_INS_MOVSW ||
           id == dt_X86_INS_MOVSD || id == dt_X86_INS_MOVSQ;
}

static bool ft_string_is_stos(int id)
{
    return id == dt_X86_INS_STOSB || id == dt_X86_INS_STOSW ||
           id == dt_X86_INS_STOSD || id == dt_X86_INS_STOSQ;
}

static bool ft_string_is_lods(int id)
{
    return id == dt_X86_INS_LODSB || id == dt_X86_INS_LODSW ||
           id == dt_X86_INS_LODSD || id == dt_X86_INS_LODSQ;
}

static bool ft_string_is_cmps(int id)
{
    return id == dt_X86_INS_CMPSB || id == dt_X86_INS_CMPSW ||
           id == dt_X86_INS_CMPSD || id == dt_X86_INS_CMPSQ;
}

static bool ft_string_is_scas(int id)
{
    return id == dt_X86_INS_SCASB || id == dt_X86_INS_SCASW ||
           id == dt_X86_INS_SCASD || id == dt_X86_INS_SCASQ;
}

static bool ft_emit_string_addr_scratch(uint32_t **out, int dst, int base,
                                        int seg, bool addr32, int scratch)
{
#ifndef QUICKTRANS_LATU
    (void)addr32;
    (void)scratch;
#endif
    if (seg >= 0) {
        int seg_base_offset = offsetof(CPUX86State, segs[seg].base);

        if (!ft_fits_simm12(seg_base_offset)) {
            return false;
        }
        ft_emit_load_env(out, dst, seg_base_offset, FT_LA_OPCODE_LD_D);
#ifdef QUICKTRANS_LATU
        if (addr32) {
            FT_LA_BSTRPICK_D_EMIT(out, scratch, base, 31, 0);
            FT_LA_ADD_D_EMIT(out, dst, dst, scratch);
            return true;
        }
#endif
        FT_LA_ADD_D_EMIT(out, dst, dst, base);
        return true;
    }

#ifdef QUICKTRANS_LATU
    if (addr32) {
        FT_LA_BSTRPICK_D_EMIT(out, dst, base, 31, 0);
        return true;
    }
#endif
    FT_LA_OR_EMIT(out, dst, base, la_zero);
    return true;
}

static bool ft_emit_string_addr(uint32_t **out, int dst, int base, int seg,
                                bool addr32)
{
    return ft_emit_string_addr_scratch(out, dst, base, seg, addr32, la_t2);
}

static void ft_emit_string_load_bytes(uint32_t **out, int dst, int addr,
                                      int bytes)
{
    FT_LA_LD_BU_EMIT(out, dst, addr, 0);
    for (int i = 1; i < bytes; ++i) {
        FT_LA_LD_BU_EMIT(out, la_t2, addr, i);
        FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, i * 8);
        FT_LA_OR_EMIT(out, dst, dst, la_t2);
    }
}

#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
static bool ft_string_wide_access(int id)
{
#ifdef QUICKTRANS_LATU
    /* Legacy LATU uses native-width string accesses for all word widths. */
    if (id == dt_X86_INS_STOSW || id == dt_X86_INS_STOSD ||
        id == dt_X86_INS_LODSW || id == dt_X86_INS_LODSD ||
        id == dt_X86_INS_CMPSW || id == dt_X86_INS_CMPSD ||
        id == dt_X86_INS_SCASW || id == dt_X86_INS_SCASD) {
        return true;
    }
#endif
    return id == dt_X86_INS_MOVSW ||
           id == dt_X86_INS_MOVSD ||
           id == dt_X86_INS_LODSQ ||
           id == dt_X86_INS_STOSQ ||
           id == dt_X86_INS_CMPSQ ||
           id == dt_X86_INS_SCASQ;
}

/* The corresponding legacy translators use native-width accesses too.
 * Read the complete source before storing, including overlapping operands. */
static void ft_emit_string_load_wide(uint32_t **out, int dst, int addr,
                                     int bytes)
{
    if (bytes == 2) {
        FT_LA_LD_HU_EMIT(out, dst, addr, 0);
    } else if (bytes == 4) {
        FT_LA_LD_WU_EMIT(out, dst, addr, 0);
    } else {
        FT_LA_LD_D_EMIT(out, dst, addr, 0);
    }
}

static void ft_emit_string_store_wide(uint32_t **out, int src, int addr,
                                      int bytes)
{
    if (bytes == 2) {
        FT_LA_ST_H_EMIT(out, src, addr, 0);
    } else if (bytes == 4) {
        FT_LA_ST_W_EMIT(out, src, addr, 0);
    } else {
        FT_LA_ST_D_EMIT(out, src, addr, 0);
    }
}
#endif

static void ft_emit_string_store_acc(uint32_t **out, int bytes)
{
    switch (bytes) {
    case 1:
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t0, 7, 0);
        break;
    case 2:
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rax_index), la_t0, 15, 0);
        break;
    case 4:
        FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rax_index), la_t0, 31, 0);
        break;
    case 8:
        FT_LA_OR_EMIT(out, ft_gpr(rax_index), la_t0, la_zero);
        break;
    default:
        break;
    }
}

static void ft_emit_string_load_acc_low(uint32_t **out, int dst, int bytes)
{
    switch (bytes) {
    case 1:
        FT_LA_BSTRPICK_D_EMIT(out, dst, ft_gpr(rax_index), 7, 0);
        break;
    case 2:
        FT_LA_BSTRPICK_D_EMIT(out, dst, ft_gpr(rax_index), 15, 0);
        break;
    case 4:
        FT_LA_BSTRPICK_D_EMIT(out, dst, ft_gpr(rax_index), 31, 0);
        break;
    case 8:
        FT_LA_OR_EMIT(out, dst, ft_gpr(rax_index), la_zero);
        break;
    default:
        break;
    }
}

static uint32_t ft_string_x86sub_op(int bytes)
{
    switch (bytes) {
    case 1:
        return FT_LA_OPCODE_X86SUB_B;
    case 2:
        return FT_LA_OPCODE_X86SUB_H;
    case 4:
        return FT_LA_OPCODE_X86SUB_W;
    case 8:
        return FT_LA_OPCODE_X86SUB_D;
    default:
        return 0;
    }
}

static bool ft_emit_string_step(uint32_t **out, int bytes)
{
    return ft_emit_direction_step(out, la_t2, bytes);
}

static void ft_emit_string_adjust(uint32_t **out,
                                  const FastTemplateFields *fields,
                                  bool adjust_rsi, bool adjust_rdi)
{
    if (adjust_rsi) {
        FT_LA_SUB_D_EMIT(out, ft_gpr(rsi_index), ft_gpr(rsi_index), la_t2);
        if (fields->addr32) {
            FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rsi_index),
                                  ft_gpr(rsi_index), 31, 0);
        }
    }
    if (adjust_rdi) {
        FT_LA_SUB_D_EMIT(out, ft_gpr(rdi_index), ft_gpr(rdi_index), la_t2);
        if (fields->addr32) {
            FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(rdi_index),
                                  ft_gpr(rdi_index), 31, 0);
        }
    }
}

static bool ft_emit_string_body(uint32_t **out,
                                const FastTemplateFields *fields,
                                int bytes, TranslationBlock *tb)
{
    int id = fields->id;
#ifdef QUICKTRANS_LATU
    /* Address formation precedes the destination load into t1.  Keep t2
     * available for the direction step throughout ordinary string bodies. */
    const int addr_scratch = la_t1;
#else
    const int addr_scratch = la_t2;
#endif

    (void)tb;
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    /* Match legacy MOVSQ access width, loading the complete source before
     * storing so overlapping operands retain MOVSQ semantics.  Non-LATU
     * user-mode mixed-page handling remains on its existing path. */
    if (id == dt_X86_INS_MOVSQ) {
        bool long_mode = tb && (tb->flags & HF_CS64_MASK);
        bool flat64 = long_mode && !fields->addr32;
        int src = la_t3;
        int dst = la_t4;

        /* Long mode ignores DS/ES/SS/CS bases.  FS/GS still contribute
         * their base after the address-size truncation. */
        if (long_mode && fields->addr32) {
            if (fields->segment == fs_index || fields->segment == gs_index) {
                int offset = offsetof(CPUX86State,
                                      segs[fields->segment].base);
                if (!ft_fits_simm12(offset)) {
                    return false;
                }
                /* The env load may use src as scratch in the LATU ABI. */
                ft_emit_load_env(out, dst, offset, FT_LA_OPCODE_LD_D);
                FT_LA_BSTRPICK_D_EMIT(out, src, ft_gpr(rsi_index), 31, 0);
                FT_LA_ADD_D_EMIT(out, src, src, dst);
            } else {
                FT_LA_BSTRPICK_D_EMIT(out, src, ft_gpr(rsi_index), 31, 0);
            }
            FT_LA_LD_D_EMIT(out, la_t0, src, 0);
            FT_LA_BSTRPICK_D_EMIT(out, dst, ft_gpr(rdi_index), 31, 0);
            FT_LA_ST_D_EMIT(out, la_t0, dst, 0);
            return true;
        }
        if (flat64 && fields->segment != fs_index &&
            fields->segment != gs_index) {
            src = ft_gpr(rsi_index);
        } else if (!ft_emit_string_addr_scratch(out, src, ft_gpr(rsi_index),
                                               fields->segment, fields->addr32,
                                               addr_scratch)) {
            return false;
        }
        FT_LA_LD_D_EMIT(out, la_t0, src, 0);
        if (flat64) {
            dst = ft_gpr(rdi_index);
        } else if (!ft_emit_string_addr_scratch(out, dst, ft_gpr(rdi_index),
                                               es_index, fields->addr32,
                                               addr_scratch)) {
            return false;
        }
        FT_LA_ST_D_EMIT(out, la_t0, dst, 0);
        return true;
    }
#endif

    int src_addr = la_t3;
    int dst_addr = la_t4;
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
    bool direct_addr =
#ifndef QUICKTRANS_LATU
                       ft_string_wide_access(id) &&
#endif
                       tb && (tb->flags & HF_CS64_MASK) && !fields->addr32;

    /* In long mode only FS/GS retain a source segment base.  Keep all
     * other modes and address-size overrides on the existing path. */
    if (direct_addr) {
        if (fields->segment != fs_index && fields->segment != gs_index) {
            src_addr = ft_gpr(rsi_index);
        }
        dst_addr = ft_gpr(rdi_index);
    }
#endif

    if (ft_string_is_movs(id) || ft_string_is_cmps(id) ||
        ft_string_is_lods(id)) {
        if (src_addr == la_t3 &&
            !ft_emit_string_addr_scratch(out, src_addr, ft_gpr(rsi_index),
                                         fields->segment, fields->addr32,
                                         addr_scratch)) {
            return false;
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (ft_string_wide_access(id)) {
            ft_emit_string_load_wide(out,
                id == dt_X86_INS_LODSQ ? ft_gpr(rax_index) : la_t0,
                src_addr, bytes);
        } else
#endif
        ft_emit_string_load_bytes(out, la_t0, src_addr, bytes);
    }

    if (ft_string_is_movs(id) || ft_string_is_stos(id) ||
        ft_string_is_cmps(id) || ft_string_is_scas(id)) {
        if (dst_addr == la_t4 &&
            !ft_emit_string_addr_scratch(out, dst_addr, ft_gpr(rdi_index),
                                         es_index, fields->addr32,
                                         addr_scratch)) {
            return false;
        }
    }

    if (ft_string_is_movs(id)) {
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (ft_string_wide_access(id)) {
            ft_emit_string_store_wide(out, la_t0, dst_addr, bytes);
            return true;
        }
#endif
        return ft_emit_store_addr_bytes(out, fields->address, dst_addr, 0,
                                        la_t0, bytes);
    }
    if (ft_string_is_stos(id)) {
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (ft_string_wide_access(id)) {
            ft_emit_string_store_wide(out, ft_gpr(rax_index), dst_addr, bytes);
            return true;
        }
#endif
        return ft_emit_store_addr_bytes(out, fields->address, dst_addr, 0,
                                        ft_gpr(rax_index), bytes);
    }
    if (ft_string_is_lods(id)) {
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (id == dt_X86_INS_LODSQ) {
            return true;
        }
#endif
        ft_emit_string_store_acc(out, bytes);
        return true;
    }
    if (ft_string_is_cmps(id)) {
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (ft_string_wide_access(id)) {
            ft_emit_string_load_wide(out, la_t1, dst_addr, bytes);
        } else
#endif
        ft_emit_string_load_bytes(out, la_t1, dst_addr, bytes);
        if (!fields->skip_flags) {
            ft_emit_raw(out, ft_gpr2(ft_string_x86sub_op(bytes), la_t0,
                                    la_t1));
        }
        FT_LA_XOR_EMIT(out, la_t0, la_t0, la_t1);
        return true;
    }
    if (ft_string_is_scas(id)) {
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (ft_string_wide_access(id)) {
            ft_emit_string_load_wide(out, la_t1, dst_addr, bytes);
        } else
#endif
        ft_emit_string_load_bytes(out, la_t1, dst_addr, bytes);
        if (!fields->skip_flags) {
            ft_emit_raw(out, ft_gpr2(ft_string_x86sub_op(bytes),
                                    ft_gpr(rax_index), la_t1));
        }
#if defined(CONFIG_SOFTMMU) || defined(QUICKTRANS_LATU)
        if (id == dt_X86_INS_SCASQ) {
            FT_LA_XOR_EMIT(out, la_t0, ft_gpr(rax_index), la_t1);
            return true;
        }
#endif
        ft_emit_string_load_acc_low(out, la_t0, bytes);
        FT_LA_XOR_EMIT(out, la_t0, la_t0, la_t1);
        return true;
    }

    return false;
}

static int ft_emit_string_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int bytes;
    bool rep;
    bool cmp_loop;
    bool adjust_rsi;
    bool adjust_rdi;
    bool hoist_step = false;
    FastBranchLabel loop = { 0 };
    FastBranchLabel zero_count = { 0 };
    FastBranchFixup zero_count_fixup;

    (void)tb;
    (void)pc;

    if (!ft_string_width(fields, &bytes)) {
        return 0;
    }
    rep = fields->prefix0 == dt_X86_PREFIX_REP ||
          fields->prefix0 == dt_X86_PREFIX_REPNE;
    cmp_loop = ft_string_is_cmps(fields->id) || ft_string_is_scas(fields->id);
    if (fields->prefix0 == dt_X86_PREFIX_REPNE &&
        !cmp_loop) {
        return 0;
    }

    adjust_rsi = ft_string_is_movs(fields->id) ||
                 ft_string_is_lods(fields->id) ||
                 ft_string_is_cmps(fields->id);
    adjust_rdi = ft_string_is_movs(fields->id) ||
                 ft_string_is_stos(fields->id) ||
                 ft_string_is_cmps(fields->id) ||
                 ft_string_is_scas(fields->id);

    if (rep) {
#ifdef QUICKTRANS_LATU
        if (fields->addr32) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rcx_index),
                                ft_gpr(rcx_index), 31, 0);
        }
#endif
        ft_emit_branch_placeholder(&out, &zero_count_fixup, FT_BRANCH_BEQ,
                                   ft_gpr(rcx_index), la_zero, &zero_count);
    }

#ifdef QUICKTRANS_LATU
    /* Native-width accesses and t1 address scratch leave t2 intact,
     * including long-mode strings with a 32-bit address override. */
    hoist_step = rep && tb && (tb->flags & HF_CS64_MASK);
    if (hoist_step && !ft_emit_string_step(&out, bytes)) {
        return 0;
    }
#endif
    ft_bind_branch_label(&loop, out);
    if (!ft_emit_string_body(&out, fields, bytes, tb) ||
        (!hoist_step && !ft_emit_string_step(&out, bytes))) {
        return 0;
    }
    ft_emit_string_adjust(&out, fields, adjust_rsi, adjust_rdi);

    if (rep) {
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rcx_index), ft_gpr(rcx_index), -1);
        if (cmp_loop) {
            FT_LA_BEQ_EMIT(&out, ft_gpr(rcx_index), la_zero,
                           (out + 2) - out);
            if (fields->prefix0 == dt_X86_PREFIX_REP) {
                FastBranchFixup loop_fixup;

                ft_emit_branch_placeholder(&out, &loop_fixup, FT_BRANCH_BEQ,
                                           la_t0, la_zero, &loop);
                ft_resolve_branch_fixup(&loop_fixup);
            } else {
                FastBranchFixup loop_fixup;

                ft_emit_branch_placeholder(&out, &loop_fixup, FT_BRANCH_BNE,
                                           la_t0, la_zero, &loop);
                ft_resolve_branch_fixup(&loop_fixup);
            }
        } else {
            FastBranchFixup loop_fixup;

            ft_emit_branch_placeholder(&out, &loop_fixup, FT_BRANCH_BNE,
                                       ft_gpr(rcx_index), la_zero, &loop);
            ft_resolve_branch_fixup(&loop_fixup);
        }
        ft_bind_branch_label(&zero_count, out);
        ft_resolve_branch_fixup(&zero_count_fixup);
    }

    return (out - code);
}

static bool ft_string_is_ins(int id)
{
    return id == dt_X86_INS_INSB || id == dt_X86_INS_INSW ||
           id == dt_X86_INS_INSD;
}

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static void ft_emit_string_io_spill(uint32_t **out, int reg, bool store,
                                    bool host_context)
{
    if (!host_context) {
        ft_emit_host_stack_begin(out);
    }
    if (store) {
        FT_LA_ST_D_EMIT(out, reg, la_sp, 0);
    } else {
        FT_LA_LD_D_EMIT(out, reg, la_sp, 0);
    }
    if (!host_context) {
        ft_emit_host_stack_end(out);
    }
}
#endif

static int ft_emit_string_io_template(const FastTemplateFields *fields,
                                      TranslationBlock *tb, target_ulong pc,
                                      uint32_t *code)
{
    uint32_t *out = code;

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    bool is_in = ft_string_is_ins(fields->id);
    bool rep = fields->prefix0 == dt_X86_PREFIX_REP ||
               fields->prefix0 == dt_X86_PREFIX_REPNE;
    bool static_context;
    int bytes;
    FastBranchLabel loop = { 0 };
    FastBranchLabel cleanup = { 0 };
    FastBranchFixup zero_count_fixup;

    if (!tb || !ft_string_width(fields, &bytes)) {
        return 0;
    }

    if (ft_io_needs_permission_check(tb)) {
        static_context = ft_emit_nofp_helper_prologue(&out);
        ft_emit_li64(&out, la_t0, pc);
        ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                          FT_LA_OPCODE_ST_D);
        ft_emit_io_check(&out, fields, tb, bytes, static_context);
        ft_emit_nofp_helper_epilogue(&out, static_context);
    }

    ft_emit_host_stack_begin(&out);
    FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, -16);
    ft_emit_host_stack_end(&out);

    if (rep) {
        ft_emit_branch_placeholder(&out, &zero_count_fixup, FT_BRANCH_BEQ,
                                   ft_gpr(rcx_index), la_zero, &cleanup);
    }

    ft_bind_branch_label(&loop, out);
    if (is_in) {
        if (!ft_emit_string_addr(&out, la_t4, ft_gpr(rdi_index),
                                  es_index, fields->addr32) ||
            !ft_emit_store_addr_bytes(&out, fields->address, la_t4, 0,
                                      la_zero, bytes)) {
            return 0;
        }
    } else {
        if (!ft_emit_string_addr(&out, la_t3, ft_gpr(rsi_index),
                                 fields->segment, fields->addr32)) {
            return 0;
        }
        ft_emit_string_load_bytes(&out, la_t0, la_t3, bytes);
        ft_emit_string_io_spill(&out, la_t0, true, false);
    }

    static_context = ft_emit_nofp_helper_prologue(&out);
    ft_emit_li64(&out, la_t0, pc);
    ft_emit_store_env(&out, la_t0, lsenv_offset_of_eip(lsenv),
                      FT_LA_OPCODE_ST_D);
    ft_emit_io_can_do(&out, tb, true);
    ft_emit_cpu_env_ptr(&out, la_a0);
    ft_emit_io_port_arg(&out, fields);
    if (!is_in) {
        ft_emit_string_io_spill(&out, la_a2, false, static_context);
    }
    ft_emit_default_helper_call(&out,
                                is_in ? ft_io_in_helper(bytes) :
                                        ft_io_out_helper(bytes),
                                1u << 0, static_context);
    ft_emit_io_can_do(&out, tb, false);
    if (is_in) {
        ft_emit_string_io_spill(&out, la_a0, true, static_context);
    }
    ft_emit_io_breakpoint(&out, fields, tb, pc, bytes, static_context);
    ft_emit_nofp_helper_epilogue(&out, static_context);

    if (is_in) {
        ft_emit_string_io_spill(&out, la_t0, false, false);
        if (!ft_emit_string_addr(&out, la_t4, ft_gpr(rdi_index),
                                  es_index, fields->addr32) ||
            !ft_emit_store_addr_bytes(&out, fields->address, la_t4, 0,
                                      la_t0, bytes)) {
            return 0;
        }
    }
    if (!ft_emit_string_step(&out, bytes)) {
        return 0;
    }
    ft_emit_string_adjust(&out, fields, !is_in, is_in);

    if (rep) {
        FastBranchFixup loop_fixup;

        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rcx_index),
                          ft_gpr(rcx_index), -1);
        ft_emit_branch_placeholder(&out, &loop_fixup, FT_BRANCH_BNE,
                                   ft_gpr(rcx_index), la_zero, &loop);
        ft_resolve_branch_fixup(&loop_fixup);
        ft_bind_branch_label(&cleanup, out);
        ft_resolve_branch_fixup(&zero_count_fixup);
    }

    ft_emit_host_stack_begin(&out);
    FT_LA_ADDI_D_EMIT(&out, la_sp, la_sp, 16);
    ft_emit_host_stack_end(&out);
#else
    (void)fields;
    (void)tb;
    ft_emit_raise_exception(&out, pc, EXCP0D_GPF);
#endif
    return out - code;
}
