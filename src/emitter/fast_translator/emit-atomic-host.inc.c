/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
/* A vCPU waiting for an exclusive atomic step kicks its peers. Directly
 * linked Quicktrans blocks can otherwise spin indefinitely in guest code.
 * The ordinary ret-0 exit saves the guest PC from r21 and the full state. */
static int ft_emit_atomic_exit_poll(TranslationBlock *tb, uint32_t *code)
{
    uint32_t *out = code;
    FastBranchLabel run = { 0 };
    FastBranchFixup fix;
    int offset = (int)offsetof(X86CPU, neg.icount_decr.u32) -
                 (int)offsetof(X86CPU, env);

    uint32_t flags = tb_cflags(tb);
    if (!(flags & CF_PARALLEL) &&
        ((flags & CF_COUNT_MASK) == 1 ||
         (!close_latx_parallel &&
          !(tb->bool_flags & (IS_AOT_TB | IS_TU_TB | IS_TU_JMP))))) {
        return 0;
    }
    if (have_am() && have_scq()) {
        return 0;
    }
    ft_emit_load_env(&out, la_t0, offset, FT_LA_OPCODE_LD_W);
    ft_emit_branch_placeholder(&out, &fix, FT_BRANCH_BGE, la_t0, la_zero, &run);
    ft_emit_li64(&out, la_r21, tb->pc);
    ft_emit_far_jump_preserve_a0(&out, ft_context_switch_ret0_target(), la_t0);
    ft_bind_branch_label(&run, out);
    ft_resolve_branch_fixup(&fix);
    return out - code;
}

/* Re-execute one instruction with the other guest CPUs stopped. The caller
 * has saved the architectural registers and flags and supplied its guest PC. */
static void ft_retry_atomic(CPUArchState *env, target_ulong pc)
{
    env->eip = pc - env->segs[R_CS].base;
    cpu_loop_exit_atomic(env_cpu(env), 0);
}

static void ft_emit_require_serial(uint32_t **out, const FastTemplateFields *f)
{
    FastBranchLabel ready = { 0 };
    FastBranchFixup fix;

    if (f->atomic_no_barrier) {
        return;
    }
    /* Use a private temporary: the caller still needs its effective address
     * and operands on the returning path. */
    int offset = (int)offsetof(X86CPU, parent_obj.exclusive_context_count) -
                 (int)offsetof(X86CPU, env);
    ft_emit_li64(out, la_a0, offset);
    FT_LA_ADD_D_EMIT(out, la_a0, la_s8, la_a0);
    FT_LA_LD_W_EMIT(out, la_a0, la_a0, 0);
    ft_emit_branch_placeholder(out, &fix, FT_BRANCH_BNE, la_a0, la_zero, &ready);
    ft_emit_helper_prologue(out);
    ft_emit_cpu_env_ptr(out, la_a0);
    ft_emit_li64(out, la_a1, f->address);
    ft_emit_host_call(out, (void *)ft_retry_atomic, 0);
    FT_LA_BREAK_EMIT(out, 0);
    ft_bind_branch_label(&ready, *out);
    ft_resolve_branch_fixup(&fix);
}

typedef enum { FT_HOST_CAS, FT_HOST_SWAP, FT_HOST_ADD } FtHostAtomicOp;

/* rd receives the sign-extended original value, just like AM*. All operands
 * are guest GPRs or t0..t4. a0, a1, a7 and ra are outside those mappings. */
static void ft_emit_llsc_atomic(uint32_t **out, const FastTemplateFields *f,
                                FtHostAtomicOp op, int bits, int rd,
                                int value, int addr)
{
    FastBranchLabel cross = { 0 }, done = { 0 };
    FastBranchFixup cross_fix, done_fix;
    uint32_t *retry;
    const int base = la_a0, temp = la_a1, shift = la_a7, word = la_ra;

    FT_LA_DBAR_EMIT(out, 0);
    FT_LA_ANDI_EMIT(out, shift, addr, 7);
    if (bits > 8) {
        /* offset + operand bytes must fit inside one reservation. */
        FT_LA_SLTUI_EMIT(out, temp, shift, 8 - bits / 8 + 1);
        ft_emit_branch_placeholder(out, &cross_fix, FT_BRANCH_BEQ, temp,
                                   la_zero, &cross);
    }
    FT_LA_OR_EMIT(out, base, addr, la_zero);
    FT_LA_BSTRINS_D_EMIT(out, base, la_zero, 2, 0);
    FT_LA_SLLI_D_EMIT(out, shift, shift, 3);
    if (op == FT_HOST_CAS) {
        FT_LA_BSTRPICK_D_EMIT(out, temp, rd, bits - 1, 0);
    }
    retry = *out;
    FT_LA_LL_D_EMIT(out, word, base, 0);
    FT_LA_ROTR_D_EMIT(out, word, word, shift);
    FT_LA_BSTRPICK_D_EMIT(out, rd, word, bits - 1, 0);
    if (op == FT_HOST_ADD) {
        FT_LA_ADD_D_EMIT(out, temp, rd, value);
    } else if (op == FT_HOST_CAS) {
        /* Complete the write cycle on mismatch using the unchanged word. */
        FT_LA_BNE_EMIT(out, rd, temp, 2);
    }
    FT_LA_BSTRINS_D_EMIT(out, word, op == FT_HOST_ADD ? temp : value,
                         bits - 1, 0);
    FT_LA_SUB_D_EMIT(out, shift, la_zero, shift);
    FT_LA_ROTR_D_EMIT(out, word, word, shift);
    FT_LA_SUB_D_EMIT(out, shift, la_zero, shift);
    FT_LA_SC_D_EMIT(out, word, base, 0);
    FT_LA_BEQ_EMIT(out, word, la_zero, retry - *out);
    if (bits > 8) {
        ft_emit_branch_placeholder(out, &done_fix, FT_BRANCH_B, 0, 0, &done);
        ft_bind_branch_label(&cross, *out);
        ft_resolve_branch_fixup(&cross_fix);
        /* The operand straddles two reservation words. Use the original
         * operand width while running in QEMU's serialized context. */
        ft_emit_require_serial(out, f);
        if (op == FT_HOST_CAS) {
            FT_LA_BSTRPICK_D_EMIT(out, temp, rd, bits - 1, 0);
        }
        uint32_t ld = bits == 64 ? FT_LA_OPCODE_LD_D :
                      bits == 32 ? FT_LA_OPCODE_LD_WU : FT_LA_OPCODE_LD_HU;
        uint32_t st = bits == 64 ? FT_LA_OPCODE_ST_D :
                      bits == 32 ? FT_LA_OPCODE_ST_W : FT_LA_OPCODE_ST_H;
        ft_emit_raw(out, ft_gpr3_imm12(ld, rd, addr, 0));
        if (op == FT_HOST_CAS) {
            FT_LA_OR_EMIT(out, word, rd, la_zero);
            FT_LA_BNE_EMIT(out, rd, temp, 2);
            FT_LA_OR_EMIT(out, word, value, la_zero);
        } else if (op == FT_HOST_ADD) {
            FT_LA_ADD_D_EMIT(out, word, rd, value);
        }
        ft_emit_raw(out, ft_gpr3_imm12(st, op == FT_HOST_SWAP ? value : word,
                                       addr, 0));
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&done_fix);
    }
    if (bits < 64) {
        FT_LA_SLLI_D_EMIT(out, rd, rd, 64 - bits);
        FT_LA_SRAI_D_EMIT(out, rd, rd, 64 - bits);
    }
    FT_LA_DBAR_EMIT(out, 0);
}
#endif

static void ft_emit_atomic_op(uint32_t **out, const FastTemplateFields *fields,
                              uint32_t opcode, int rd, int value, int addr)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    if (!have_am()) {
        int bits;
        FtHostAtomicOp op;

        switch (opcode) {
        case FT_LA_OPCODE_AMCAS_DB_B:
        case FT_LA_OPCODE_AMCAS_DB_H:
        case FT_LA_OPCODE_AMCAS_DB_W:
        case FT_LA_OPCODE_AMCAS_DB_D:
            op = FT_HOST_CAS;
            bits = opcode == FT_LA_OPCODE_AMCAS_DB_B ? 8 :
                   opcode == FT_LA_OPCODE_AMCAS_DB_H ? 16 :
                   opcode == FT_LA_OPCODE_AMCAS_DB_W ? 32 : 64;
            break;
        case FT_LA_OPCODE_AMADD_DB_B:
        case FT_LA_OPCODE_AMADD_DB_H:
            op = FT_HOST_ADD;
            bits = opcode == FT_LA_OPCODE_AMADD_DB_B ? 8 : 16;
            break;
        case FT_LA_OPCODE_AMSWAP_DB_B:
        case FT_LA_OPCODE_AMSWAP_DB_H:
            op = FT_HOST_SWAP;
            bits = opcode == FT_LA_OPCODE_AMSWAP_DB_B ? 8 : 16;
            break;
        default:
            /* Base-ISA word and doubleword AM operations still work. */
            goto native;
        }
        ft_emit_llsc_atomic(out, fields, op, bits, rd, value, addr);
        return;
    }
native:
#endif
    ft_emit_raw(out, ft_gpr3(ft_atomic_opcode(fields, opcode), rd, addr, value));
}
