/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */


#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
void cpu_load_eflags(CPUX86State *env, int eflags, int update_mask);

static void ft_helper_pushf(CPUArchState *env, int width)
{
    int bytes = width / 8;
    target_ulong sp = env->regs[rsp_index] - bytes;
    target_ulong value = cpu_compute_eflags(env) & ~(VM_MASK | RF_MASK);

    if (width == 16) {
        cpu_stw_le_data(env, sp, value);
    } else if (width == 32) {
        cpu_stl_le_data(env, sp, value);
    } else {
        cpu_stq_le_data(env, sp, value);
    }
    env->regs[rsp_index] = sp;
}

static void ft_helper_popf(CPUArchState *env, int width, uint32_t update_mask)
{
    target_ulong sp = env->regs[rsp_index];
    target_ulong value;

    if (width == 16) {
        value = cpu_lduw_le_data(env, sp);
        update_mask &= 0xffff;
    } else if (width == 32) {
        value = cpu_ldl_le_data(env, sp);
    } else {
        value = cpu_ldq_le_data(env, sp);
    }
    cpu_load_eflags(env, value, update_mask);
    env->regs[rsp_index] = sp + width / 8;
}
#endif

static int ft_emit_flags_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

    (void)tb;
    (void)pc;

    switch (fields->kind) {
    case FT_CLD:
        ft_emit_set_direction_flag(&out, false);
        break;
    case FT_STD:
        ft_emit_set_direction_flag(&out, true);
        break;
    case FT_CLC:
        FT_MTFLAG(la_zero, 0x1);
        break;
    case FT_STC:
        FT_LA_ORI_EMIT(&out, la_t0, la_zero, 0xfff);
        FT_MTFLAG(la_t0, 0x1);
        break;
    case FT_CMC:
        FT_MFFLAG(la_t0, 0x1);
        FT_LA_XORI_EMIT(&out, la_t0, la_t0, 1);
        FT_MTFLAG(la_t0, 0x1);
        break;
    case FT_LAHF:
        FT_MFFLAG(la_t0, 0x1f);
        FT_LA_ORI_EMIT(&out, la_t0, la_t0, 0x2);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rax_index), la_t0, 15, 8);
        break;
    case FT_SAHF:
        FT_LA_SRLI_D_EMIT(&out, la_t0, ft_gpr(rax_index), 8);
        FT_MTFLAG(la_t0, 0x1f);
        break;
    case FT_PUSHFQ:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->alu_width);
        ft_emit_host_call(&out, (void *)ft_helper_pushf, 1u << 0);
        ft_emit_helper_epilogue(&out);
#else
        if (!ft_emit_collect_rflags(&out)) {
            return 0;
        }
        if (fields->alu_width == 16) {
            FT_LA_ST_H_EMIT(&out, la_t0, ft_gpr(rsp_index), -2);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), -2);
        } else if (fields->alu_width == 32) {
            FT_LA_ST_W_EMIT(&out, la_t0, ft_gpr(rsp_index), -4);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), -4);
        } else {
            FT_LA_ST_D_EMIT(&out, la_t0, ft_gpr(rsp_index), -8);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), -8);
        }
#endif
        break;
    case FT_POPFQ:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    {
        uint32_t update_mask = TF_MASK | AC_MASK | ID_MASK | NT_MASK;
        int cpl = tb->flags & HF_CPL_MASK;
        int iopl = (tb->flags & HF_IOPL_MASK) >> HF_IOPL_SHIFT;

        if (cpl == 0) {
            update_mask |= IF_MASK | IOPL_MASK;
        } else if (cpl <= iopl) {
            update_mask |= IF_MASK;
        }
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->alu_width);
        ft_emit_li32(&out, la_a2, update_mask);
        ft_emit_host_call(&out, (void *)ft_helper_popf, 1u << 0);
        ft_emit_helper_epilogue(&out);
        break;
    }
#else
        if (fields->alu_width == 16) {
            FT_LA_LD_HU_EMIT(&out, la_t0, ft_gpr(rsp_index), 0);
        } else if (fields->alu_width == 32) {
            FT_LA_LD_WU_EMIT(&out, la_t0, ft_gpr(rsp_index), 0);
        } else {
            FT_LA_LD_D_EMIT(&out, la_t0, ft_gpr(rsp_index), 0);
        }
        if (!fields->skip_flags && !ft_emit_apply_popfq(&out, tb)) {
            return 0;
        }
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index),
                          fields->alu_width == 16 ? 2 : fields->alu_width == 32 ? 4 : 8);
        break;
#endif
    default:
        return 0;
    }

    if (out == code && fields->skip_flags) {
        FT_LA_NOP_EMIT(&out);
    }

    return (out - code);
}
