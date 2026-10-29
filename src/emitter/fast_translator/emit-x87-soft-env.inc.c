/* SPDX-License-Identifier: MIT */

/* Keep the system helpers for cross-page accesses and legacy IRQ13 mode.
 * A same-page access faults before changing architectural state. */
typedef struct FtSoftEnv {
    FastBranchLabel slow, done;
    FastBranchFixup guard[8], finish;
    unsigned count;
    bool active;
} FtSoftEnv;

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static void ft_soft_fisttp_memory(CPUX86State *env, target_ulong addr, int width)
{
    uintptr_t ra = GETPC();
    if (width == 16) {
        cpu_stw_data_ra(env, addr, ft_x87_helper_fistt(env), ra);
    } else if (width == 32) {
        cpu_stl_data_ra(env, addr, ft_x87_helper_fisttl(env), ra);
    } else {
        cpu_stq_data_ra(env, addr, ft_x87_helper_fisttll(env), ra);
    }
    helper_fpop(env);
}

static void ft_soft_env_guard(uint32_t **out, FtSoftEnv *s,
                              int branch, int lhs, int rhs)
{
    assert(s->count < ARRAY_SIZE(s->guard));
    ft_emit_branch_placeholder(out, &s->guard[s->count++], branch,
                               lhs, rhs, &s->slow);
}

static void ft_emit_soft_memory_call(uint32_t **out, const FastTemplateFields *f,
                                     target_ulong pc, FtSoftEnv *s)
{
    if (!option_soft_fpu || !option_soft_fpu_fast || f->modrm_mod == 3) return;
    void *helper;
    int width = 0;
    switch (f->kind) {
    case FT_X87_FBLD: helper = (void *)helper_fbld_ST0; break;
    case FT_X87_FBSTP: helper = (void *)helper_fbst_ST0; break;
    case FT_X87_FISTTP_M16: width = 16; break;
    case FT_X87_FISTTP_M32: width = 32; break;
    case FT_X87_FISTTP_M64: width = 64; break;
    default: return;
    }
    memset(s, 0, sizeof(*s));
    if (width) helper = (void *)ft_soft_fisttp_memory;
    int addr;
    uint32_t *start = *out;
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) { *out = start; return; }
#ifdef CONFIG_LATX_OPT_NOFP
    FT_LA_LD_W_EMIT(out, la_t4, la_s0, lsenv_offset_of_nofp(lsenv));
    ft_soft_env_guard(out, s, FT_BRANCH_BNE, la_t4, la_zero);
#endif
    /* a2 survives the shared prologue; a1 receives the guest virtual address. */
    bool expected_static = scs_enabled();
    int preserved = expected_static ? la_a2 : la_a3;
    FT_LA_ADDI_D_EMIT(out, preserved, addr, ft_mem_access_offset(f, addr));
    bool static_context = ft_emit_nofp_helper_prologue(out);
    FT_LA_OR_EMIT(out, la_a1, preserved, la_zero);
    ft_emit_cpu_env_ptr(out, la_a0);
    if (width) FT_LA_ORI_EMIT(out, la_a2, la_zero, width);
    ft_emit_default_helper_call(out, helper, 1u << 0, static_context);
    if (f->kind == FT_X87_FBSTP) {
        ft_emit_cpu_env_ptr(out, la_a0);
        ft_emit_default_helper_call(out, (void *)helper_fpop, 1u << 0, static_context);
    }
    ft_emit_nofp_helper_epilogue(out, static_context);
    ft_emit_branch_placeholder(out, &s->finish, FT_BRANCH_B, 0, 0, &s->done);
    ft_bind_branch_label(&s->slow, *out);
    for (unsigned i = 0; i < s->count; ++i) ft_resolve_branch_fixup(&s->guard[i]);
    s->active = true;
}

/* Full tag word for FNSTENV/FNSAVE, compressed tag byte for FXSAVE.
 * t4 is the guest address and must survive all state operations. */
static void ft_soft_env_tags(uint32_t **out, bool compressed)
{
    FT_LA_OR_EMIT(out, la_t0, la_zero, la_zero);
    for (int i = 7; i >= 0; --i) {
        FT_LA_SLLI_D_EMIT(out, la_t0, la_t0, compressed ? 1 : 2);
        FT_LA_LD_BU_EMIT(out, la_t1, la_s0,
                         lsenv_offset_of_tag_word(lsenv) + i);
        if (compressed) {
            FT_LA_XORI_EMIT(out, la_t1, la_t1, 1);
            FT_LA_OR_EMIT(out, la_t0, la_t0, la_t1);
            continue;
        }
        FastBranchLabel empty = {0}, special = {0}, valid = {0}, done = {0};
        FastBranchFixup f[7];
        ft_emit_branch_placeholder(out, &f[0], FT_BRANCH_BNE,
                                   la_t1, la_zero, &empty);
        FT_LA_LD_D_EMIT(out, la_t2, la_s0, lsenv_offset_of_fpr(lsenv, i));
        FT_LA_LD_HU_EMIT(out, la_t1, la_s0, lsenv_offset_of_fpr(lsenv, i) + 8);
        FT_LA_BSTRPICK_D_EMIT(out, la_t1, la_t1, 14, 0);
        ft_emit_branch_placeholder(out, &f[1], FT_BRANCH_BNE,
                                   la_t1, la_zero, &valid);
        ft_emit_branch_placeholder(out, &f[2], FT_BRANCH_BNE,
                                   la_t2, la_zero, &special);
        FT_LA_ORI_EMIT(out, la_t0, la_t0, 1);
        ft_emit_branch_placeholder(out, &f[3], FT_BRANCH_B, 0, 0, &done);
        ft_bind_branch_label(&valid, *out);
        ft_emit_li32(out, la_t3, 0x7fff);
        ft_emit_branch_placeholder(out, &f[4], FT_BRANCH_BEQ,
                                   la_t1, la_t3, &special);
        ft_emit_branch_placeholder(out, &f[5], FT_BRANCH_BLT,
                                   la_t2, la_zero, &done);
        ft_bind_branch_label(&special, *out);
        FT_LA_ORI_EMIT(out, la_t0, la_t0, 2);
        ft_emit_branch_placeholder(out, &f[6], FT_BRANCH_B, 0, 0, &done);
        ft_bind_branch_label(&empty, *out);
        FT_LA_ORI_EMIT(out, la_t0, la_t0, 3);
        ft_bind_branch_label(&done, *out);
        for (int j = 0; j < ARRAY_SIZE(f); ++j) ft_resolve_branch_fixup(&f[j]);
    }
}

static void ft_soft_env_status(uint32_t **out, int sw, int cw)
{
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, sw, 13, 11);
    FT_LA_ST_W_EMIT(out, la_t3, la_s0, lsenv_offset_of_top(lsenv));
    ft_emit_li32(out, la_t3, 0x47ff);
    FT_LA_AND_EMIT(out, sw, sw, la_t3);
    FT_LA_BSTRPICK_W_EMIT(out, la_t3, sw, 7, 7);
    FT_LA_BSTRINS_W_EMIT(out, sw, la_t3, 15, 15);
    FT_LA_XORI_EMIT(out, la_t3, cw, 0x3f);
    FT_LA_AND_EMIT(out, la_t3, la_t3, sw);
    FT_LA_ANDI_EMIT(out, la_t3, la_t3, 0x3f);
    FastBranchLabel done = {0};
    FastBranchFixup f;
    ft_emit_branch_placeholder(out, &f, FT_BRANCH_BEQ, la_t3, la_zero, &done);
    ft_emit_li32(out, la_t3, 0x8080);
    FT_LA_OR_EMIT(out, sw, sw, la_t3);
    ft_bind_branch_label(&done, *out);
    ft_resolve_branch_fixup(&f);
    FT_LA_ST_H_EMIT(out, sw, la_s0, lsenv_offset_of_status_word(lsenv));
}

static void ft_soft_env_regs(uint32_t **out, bool restore, bool fx, int offset)
{
    for (int i = 0; i < 8; ++i) {
        int pos = offset + i * (fx ? 16 : 10);
        FT_LA_LD_WU_EMIT(out, la_t1, la_s0, lsenv_offset_of_top(lsenv));
        FT_LA_ADDI_D_EMIT(out, la_t1, la_t1, i);
        FT_LA_ANDI_EMIT(out, la_t1, la_t1, 7);
        FT_LA_SLLI_D_EMIT(out, la_t1, la_t1, 4);
        FT_LA_ADD_D_EMIT(out, la_t1, la_s0, la_t1);
        if (restore) {
            FT_LA_LD_D_EMIT(out, la_t2, la_t4, pos);
            FT_LA_LD_HU_EMIT(out, la_t3, la_t4, pos + 8);
            FT_LA_ST_D_EMIT(out, la_t2, la_t1, lsenv_offset_of_fpr(lsenv, 0));
            FT_LA_ST_H_EMIT(out, la_t3, la_t1, lsenv_offset_of_fpr(lsenv, 0) + 8);
        } else {
            FT_LA_LD_D_EMIT(out, la_t2, la_t1, lsenv_offset_of_fpr(lsenv, 0));
            FT_LA_LD_HU_EMIT(out, la_t3, la_t1, lsenv_offset_of_fpr(lsenv, 0) + 8);
            FT_LA_ST_D_EMIT(out, la_t2, la_t4, pos);
            FT_LA_ST_H_EMIT(out, la_t3, la_t4, pos + 8);
        }
    }
}

static void ft_soft_env_header(uint32_t **out, bool restore, bool fx, bool data32)
{
    int step = fx || !data32 ? 2 : 4;
    if (restore) {
        FT_LA_LD_HU_EMIT(out, la_t0, la_t4, 0);
        FT_LA_ST_H_EMIT(out, la_t0, la_s0, lsenv_offset_of_control_word(lsenv));
        ft_emit_x87_soft_control(out);
        FT_LA_LD_HU_EMIT(out, la_t1, la_t4, step);
        ft_soft_env_status(out, la_t1, la_t0);
        FT_LA_LD_HU_EMIT(out, la_t0, la_t4, step * 2);
        if (fx) FT_LA_XORI_EMIT(out, la_t0, la_t0, 0xff);
        for (int i = 0; i < 8; ++i) {
            FT_LA_ANDI_EMIT(out, la_t1, la_t0, fx ? 1 : 3);
            if (!fx) {
                FT_LA_XORI_EMIT(out, la_t1, la_t1, 3);
                FT_LA_SLTUI_EMIT(out, la_t1, la_t1, 1);
            }
            FT_LA_ST_B_EMIT(out, la_t1, la_s0, lsenv_offset_of_tag_word(lsenv) + i);
            FT_LA_SRLI_D_EMIT(out, la_t0, la_t0, fx ? 1 : 2);
        }
        return;
    }
    ft_soft_env_tags(out, fx);
    if (step == 4) FT_LA_ST_W_EMIT(out, la_t0, la_t4, 8);
    else FT_LA_ST_H_EMIT(out, la_t0, la_t4, 4);
    FT_LA_LD_HU_EMIT(out, la_t0, la_s0, lsenv_offset_of_control_word(lsenv));
    FT_LA_LD_HU_EMIT(out, la_t1, la_s0, lsenv_offset_of_status_word(lsenv));
    FT_LA_LD_WU_EMIT(out, la_t2, la_s0, lsenv_offset_of_top(lsenv));
    FT_LA_BSTRINS_D_EMIT(out, la_t1, la_t2, 13, 11);
    if (step == 4) {
        FT_LA_ST_W_EMIT(out, la_t0, la_t4, 0);
        FT_LA_ST_W_EMIT(out, la_t1, la_t4, 4);
    } else {
        FT_LA_ST_H_EMIT(out, la_t0, la_t4, 0);
        FT_LA_ST_H_EMIT(out, la_t1, la_t4, 2);
    }
    if (fx) {
        FT_LA_ST_D_EMIT(out, la_zero, la_t4, 8);
        FT_LA_ST_D_EMIT(out, la_zero, la_t4, 16);
    } else {
        const int offsets[] = {offsetof(CPUX86State, fpip), offsetof(CPUX86State, fpcs),
                               offsetof(CPUX86State, fpdp), offsetof(CPUX86State, fpds)};
        for (int i = 0; i < 4; ++i) {
            ft_emit_load_env(out, la_t0, offsets[i],
                             (i & 1) ? FT_LA_OPCODE_LD_HU : FT_LA_OPCODE_LD_WU);
            if (data32) FT_LA_ST_W_EMIT(out, la_t0, la_t4, 12 + 4 * i);
            else FT_LA_ST_H_EMIT(out, la_t0, la_t4, 6 + 2 * i);
        }
    }
}

/* Soft-FPU FXRSTOR synchronizes only host rounding.  Exception flags and
 * enables live in sse_status and must not be overwritten in the host FCSR. */
static void ft_emit_lats_softfpu_mxcsr(uint32_t **out, int mxcsr)
{
    FT_LA_BSTRPICK_W_EMIT(out, la_t0, mxcsr, 14, 13);
    FT_LA_ANDI_EMIT(out, la_t2, la_t0, 1);
    FT_LA_SLLI_W_EMIT(out, la_t2, la_t2, 1);
    FT_LA_XOR_EMIT(out, la_t0, la_t0, la_t2);
    FT_LA_MOVFCSR2GR_EMIT(out, la_t2, 0);
    FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t0, FCSR_OFF_RM + 1, FCSR_OFF_RM);
    FT_LA_MOVGR2FCSR_EMIT(out, 0, la_t2);
}

/* Match the software fields maintained by cpu_set_mxcsr and FXSAVE.
 * mxcsr is t1; keep the memory address in t4. */
static void ft_soft_env_sse_status(uint32_t **out, bool restore)
{
    int status = offsetof(CPUX86State, sse_status);
    if (restore) {
        if (!tcg_enabled()) return;
        FT_LA_BSTRPICK_W_EMIT(out, la_t0, la_t1, 14, 13);
        ft_emit_store_env(out, la_t0, status + offsetof(float_status, float_rounding_mode), FT_LA_OPCODE_ST_B);
        FT_LA_BSTRPICK_W_EMIT(out, la_t0, la_t1, 5, 2);
        FT_LA_SLLI_W_EMIT(out, la_t0, la_t0, 1);
        FT_LA_BSTRINS_W_EMIT(out, la_t0, la_t1, 0, 0);
        ft_emit_store_env(out, la_t0, status + offsetof(float_status, float_exception_flags), FT_LA_OPCODE_ST_H);
        FT_LA_BSTRPICK_W_EMIT(out, la_t0, la_t1, 6, 6);
        ft_emit_store_env(out, la_t0, status + offsetof(float_status, flush_inputs_to_zero), FT_LA_OPCODE_ST_B);
        FT_LA_BSTRPICK_W_EMIT(out, la_t0, la_t1, 15, 15);
        ft_emit_store_env(out, la_t0, status + offsetof(float_status, flush_to_zero), FT_LA_OPCODE_ST_B);
    } else {
        ft_emit_load_env(out, la_t0, status + offsetof(float_status, float_exception_flags), FT_LA_OPCODE_LD_BU);
        FT_LA_ANDI_EMIT(out, la_t2, la_t0, 0x1e);
        FT_LA_SLLI_W_EMIT(out, la_t2, la_t2, 1);
        FT_LA_BSTRINS_W_EMIT(out, la_t2, la_t0, 0, 0);
        FT_LA_OR_EMIT(out, la_t1, la_t1, la_t2);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, float_flag_output_denormal);
        FastBranchLabel done = {0};
        FastBranchFixup fix;
        ft_emit_branch_placeholder(out, &fix, FT_BRANCH_BEQ, la_t0, la_zero, &done);
        FT_LA_ORI_EMIT(out, la_t1, la_t1, 0x30); /* MXCSR underflow/inexact */
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&fix);
    }
}

static bool ft_emit_soft_environment(uint32_t **out, const FastTemplateFields *f,
                                     target_ulong pc, bool restore, int format,
                                     FtSoftEnv *s)
{
    if (!option_soft_fpu || !option_soft_fpu_fast) return false;
    bool fx = format == 2, data32 = f->prefix2 != dt_X86_PREFIX_OPSIZE;
    int bytes = fx ? 512 : (14 << data32) + (format == 1 ? 80 : 0);
    int addr;
    uint32_t *start = *out;
    if (!ft_emit_rip_or_mem_addr(out, f, pc, &addr)) { *out = start; return false; }
    FT_LA_ADDI_D_EMIT(out, la_t4, addr, ft_mem_access_offset(f, addr));
#ifdef CONFIG_LATX_OPT_NOFP
    FT_LA_LD_W_EMIT(out, la_t0, la_s0, lsenv_offset_of_nofp(lsenv));
    ft_soft_env_guard(out, s, FT_BRANCH_BNE, la_t0, la_zero);
#endif
    FT_LA_ANDI_EMIT(out, la_t0, la_t4, 4095);
    ft_emit_li32(out, la_t1, 4096 - bytes);
    ft_soft_env_guard(out, s, FT_BRANCH_BLTU, la_t1, la_t0);
    ft_emit_load_env(out, la_t0, ft_lsenv_offset_of_cr0(lsenv), FT_LA_OPCODE_LD_D);
    FT_LA_ANDI_EMIT(out, la_t0, la_t0, CR0_NE_MASK);
    ft_soft_env_guard(out, s, FT_BRANCH_BEQ, la_t0, la_zero);
    if (fx) {
        FT_LA_ANDI_EMIT(out, la_t0, la_t4, 15);
        ft_soft_env_guard(out, s, FT_BRANCH_BNE, la_t0, la_zero);
        ft_emit_load_env(out, la_t0, offsetof(CPUX86State, cr[4]), FT_LA_OPCODE_LD_D);
        FT_LA_ANDI_EMIT(out, la_t0, la_t0, CR4_OSFXSR_MASK);
        ft_soft_env_guard(out, s, FT_BRANCH_BEQ, la_t0, la_zero);
        ft_emit_load_env(out, la_t0, lsenv_offset_of_efer(lsenv), FT_LA_OPCODE_LD_D);
        ft_emit_li64(out, la_t1, MSR_EFER_FFXSR);
        FT_LA_AND_EMIT(out, la_t0, la_t0, la_t1);
        ft_soft_env_guard(out, s, FT_BRANCH_BNE, la_t0, la_zero);
    }
    ft_soft_env_header(out, restore, fx, data32);
    if (format) ft_soft_env_regs(out, restore, fx, fx ? 32 : 14 << data32);
    if (fx) {
        if (restore) {
            FT_LA_LD_WU_EMIT(out, la_t1, la_t4, 24);
            FT_LA_ST_W_EMIT(out, la_t1, la_s0, lsenv_offset_of_mxcsr(lsenv));
            ft_soft_env_sse_status(out, true);
            ft_emit_lats_softfpu_mxcsr(out, la_t1);
        } else {
            FT_LA_LD_WU_EMIT(out, la_t1, la_s0, lsenv_offset_of_mxcsr(lsenv));
            FT_LA_OR_EMIT(out, la_a3, la_t4, la_zero);
            ft_emit_mxcsr_flags_from_fcsr(out, la_t1);
            FT_LA_OR_EMIT(out, la_t4, la_a3, la_zero);
            ft_soft_env_sse_status(out, false);
            FT_LA_ST_W_EMIT(out, la_t1, la_s0, lsenv_offset_of_mxcsr(lsenv));
            FT_LA_ST_W_EMIT(out, la_t1, la_t4, 24);
            ft_emit_li32(out, la_t0, 0xffff);
            FT_LA_ST_W_EMIT(out, la_t0, la_t4, 28);
        }
        FastBranchLabel done = {0};
        FastBranchFixup f64;
        for (int i = 0; i < 16; ++i) {
            if (i == 8) {
                ft_emit_load_env(out, la_t0, lsenv_offset_of_hflags(lsenv), FT_LA_OPCODE_LD_WU);
                ft_emit_li32(out, la_t1, HF_CS64_MASK);
                FT_LA_AND_EMIT(out, la_t0, la_t0, la_t1);
                ft_emit_branch_placeholder(out, &f64, FT_BRANCH_BEQ, la_t0, la_zero, &done);
            }
            if (restore) FT_LA_VLD_EMIT(out, ft_xmm(i), la_t4, 160 + 16 * i);
            else FT_LA_VST_EMIT(out, ft_xmm(i), la_t4, 160 + 16 * i);
        }
        ft_bind_branch_label(&done, *out);
        ft_resolve_branch_fixup(&f64);
    } else if (format == 1 && !restore) {
        FastTemplateFields init = {0};
        init.kind = FT_FNINIT;
        *out += ft_emit_x87_state_template(&init, NULL, pc, *out);
    }
    ft_emit_branch_placeholder(out, &s->finish, FT_BRANCH_B, 0, 0, &s->done);
    ft_bind_branch_label(&s->slow, *out);
    for (unsigned i = 0; i < s->count; ++i) ft_resolve_branch_fixup(&s->guard[i]);
    s->active = true;
    return true;
}
#else
static void ft_emit_soft_memory_call(uint32_t **out, const FastTemplateFields *f,
                                     target_ulong pc, FtSoftEnv *s)
{
    (void)out; (void)f; (void)pc; (void)s;
}
static bool ft_emit_soft_environment(uint32_t **out, const FastTemplateFields *f,
                                     target_ulong pc, bool restore, int format,
                                     FtSoftEnv *s)
{
    (void)out; (void)f; (void)pc; (void)restore; (void)format; (void)s;
    return false;
}
#endif

static void ft_soft_environment_end(uint32_t **out, FtSoftEnv *s)
{
    if (s->active) {
        ft_bind_branch_label(&s->done, *out);
        ft_resolve_branch_fixup(&s->finish);
    }
}
