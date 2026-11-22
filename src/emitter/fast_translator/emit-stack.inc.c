/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static void ft_helper_pusha(CPUArchState *env, int width)
{
    int step = width == 16 ? 2 : 4;
    target_ulong sp = env->regs[rsp_index];
    int regs[8] = { rax_index, rcx_index, rdx_index, rbx_index,
                    rsp_index, rbp_index, rsi_index, rdi_index };

    for (int i = 0; i < 8; i++) {
        target_ulong value = regs[i] == rsp_index ? sp : env->regs[regs[i]];
        if (width == 16) {
            cpu_stw_le_data(env, sp - (i + 1) * step, value);
        } else {
            cpu_stl_le_data(env, sp - (i + 1) * step, value);
        }
    }
    env->regs[rsp_index] = sp - 8 * step;
}

static void ft_helper_popa(CPUArchState *env, int width)
{
    int step = width == 16 ? 2 : 4;
    target_ulong sp = env->regs[rsp_index];
    int regs[8] = { rdi_index, rsi_index, rbp_index, -1,
                    rbx_index, rdx_index, rcx_index, rax_index };

    for (int i = 0; i < 8; i++) {
        target_ulong value;

        if (regs[i] < 0) {
            continue;
        }
        value = width == 16 ? cpu_lduw_le_data(env, sp + i * step) :
                              cpu_ldl_le_data(env, sp + i * step);
        if (width == 16) {
            env->regs[regs[i]] = (env->regs[regs[i]] & ~0xffffull) |
                                 (value & 0xffff);
        } else {
            env->regs[regs[i]] = value;
        }
    }
    env->regs[rsp_index] = sp + 8 * step;
}
#endif

#ifdef QUICKTRANS_LATU
static bool ft_emit_latu_pop_addr(uint32_t **out,
                                  const FastTemplateFields *fields,
                                  target_ulong pc, int bytes,
                                  int *addr, int *offset)
{
    int base;
    bool uses_sp = ft_base_from_modrm_sib_with_index(fields, &base) &&
                   base == rsp_index;
    bool segmented_rip = !fields->addr32 && fields->segment >= 0 &&
                         fields->modrm_mod == 0 && fields->modrm_rm == 5;

    if ((fields->addr32 && uses_sp) || segmented_rip) {
        FastTemplateFields unsegmented = *fields;
        int tmp = ft_addr_scratch0();
        int seg = ft_addr_scratch1();
        unsegmented.segment = -1;
        if (!ft_emit_rip_or_mem_addr(out, &unsegmented, pc, addr)) {
            return false;
        }
        /* Address-size wrapping precedes adding the segment base. */
        if (fields->addr32) {
            FT_LA_ADDI_D_EMIT(out, tmp, *addr, bytes);
            FT_LA_BSTRPICK_D_EMIT(out, tmp, tmp, 31, 0);
            *addr = tmp;
        }
        if (fields->segment >= 0) {
            ft_emit_load_env(out, seg,
                             offsetof(CPUX86State, segs[fields->segment].base),
                             FT_LA_OPCODE_LD_D);
            FT_LA_ADD_D_EMIT(out, tmp, *addr, seg);
            *addr = tmp;
        }
        *offset = 0;
        return true;
    }
    if (!ft_emit_rip_or_mem_addr(out, fields, pc, addr)) {
        return false;
    }
    *offset = ft_mem_access_offset(fields, *addr) + (uses_sp ? bytes : 0);
    return true;
}

static void ft_emit_latu_pop_sp(uint32_t **out)
{
    /* Read from old RSP, increment the full pointer, then replace low 16 bits. */
    FT_LA_LD_HU_EMIT(out, la_t0, ft_gpr(rsp_index), 0);
    FT_LA_ADDI_D_EMIT(out, ft_gpr(rsp_index), ft_gpr(rsp_index), 2);
    FT_LA_BSTRINS_D_EMIT(out, ft_gpr(rsp_index), la_t0, 15, 0);
}
#endif

static int ft_emit_push_pop_template(const FastTemplateFields *fields, TranslationBlock *tb, target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    /* Keep architectural frame registers intact until every access succeeds.
     * A signal restarts the whole x86 instruction, not an internal push. */
    if (fields->kind == FT_ENTER || fields->kind == FT_ENTER16 ||
        fields->kind == FT_ENTER_ZERO_LEVEL1) {
        bool word = fields->kind == FT_ENTER16;
        int step = word ? 2 : 8;
        unsigned level = ((unsigned)fields->imm >> 16) & 31;
        int total = step * (level ? level + 1 : 1) + (fields->imm & 0xffff);
        int sp = ft_gpr(rsp_index), bp = ft_gpr(rbp_index);
        if (word) {
            FT_LA_ST_H_EMIT(&out, bp, sp, -step);
        } else {
            FT_LA_ST_D_EMIT(&out, bp, sp, -step);
        }
        FT_LA_ADDI_D_EMIT(&out, (!word && !level) ? bp : la_t1, sp, -step);
        for (unsigned i = 1; i < level; ++i) {
            if (word) {
                FT_LA_LD_HU_EMIT(&out, la_t3, bp, -(int)(step * i));
                FT_LA_ST_H_EMIT(&out, la_t3, sp, -(int)(step * (i + 1)));
            } else {
                FT_LA_LD_D_EMIT(&out, la_t3, bp, -(int)(step * i));
                FT_LA_ST_D_EMIT(&out, la_t3, sp, -(int)(step * (i + 1)));
            }
        }
        if (level) {
            if (word) {
                FT_LA_ST_H_EMIT(&out, la_t1, sp, -(int)(step * (level + 1)));
            } else {
                FT_LA_ST_D_EMIT(&out, la_t1, sp, -(int)(step * (level + 1)));
            }
        }
        if (word) {
            FT_LA_BSTRINS_D_EMIT(&out, bp, la_t1, 15, 0);
        } else if (level) {
            FT_LA_OR_EMIT(&out, bp, la_t1, la_zero);
        }
        if (ft_fits_simm12(-total)) {
            FT_LA_ADDI_D_EMIT(&out, sp, sp, -total);
        } else {
            if (!ft_emit_li32(&out, la_t0, total)) {
                return 0;
            }
            FT_LA_SUB_D_EMIT(&out, sp, sp, la_t0);
        }
        return out - code;
    }
    if (fields->kind == FT_LEAVE && fields->alu_width != 32) {
        int sp = ft_gpr(rsp_index), bp = ft_gpr(rbp_index);
        bool word = fields->prefix2 == dt_X86_PREFIX_OPSIZE;
        if (word) {
            FT_LA_LD_HU_EMIT(&out, la_t0, bp, 0);
        } else {
            FT_LA_LD_D_EMIT(&out, la_t0, bp, 0);
        }
        FT_LA_ADDI_D_EMIT(&out, sp, bp, word ? 2 : 8);
        if (word) {
            FT_LA_BSTRINS_D_EMIT(&out, bp, la_t0, 15, 0);
        } else {
            FT_LA_OR_EMIT(&out, bp, la_t0, la_zero);
        }
        return out - code;
    }
#endif

    switch (fields->kind) {
    case FT_PUSHA:
    case FT_POPA:
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        ft_emit_helper_prologue(&out);
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->alu_width);
        ft_emit_host_call(&out,
                          fields->kind == FT_PUSHA ? (void *)ft_helper_pusha :
                                                   (void *)ft_helper_popa,
                          1u << 0);
        ft_emit_helper_epilogue(&out);
#else
        {
            int width = fields->alu_width;
            int step = width == 16 ? 2 : 4;

            if (fields->kind == FT_PUSHA) {
                int regs[8] = { rax_index, rcx_index, rdx_index, rbx_index,
                                rsp_index, rbp_index, rsi_index, rdi_index };

                /* RSP is updated only after all stores, including saved RSP. */
                for (int i = 0; i < 8; i++) {
                    int value = ft_gpr(regs[i]);
                    if (width == 16) {
                        FT_LA_ST_H_EMIT(&out, value, ft_gpr(rsp_index),
                                        -(i + 1) * step);
                    } else {
                        FT_LA_ST_W_EMIT(&out, value, ft_gpr(rsp_index),
                                        -(i + 1) * step);
                    }
                }
                FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                                   ft_gpr(rsp_index), -8 * step);
            } else {
                int regs[8] = { rdi_index, rsi_index, rbp_index, -1,
                                rbx_index, rdx_index, rcx_index, rax_index };

                for (int i = 0; i < 8; i++) {
                    if (regs[i] < 0) {
                        continue;
                    }
                    if (width == 16) {
                        FT_LA_LD_HU_EMIT(&out, la_t0,
                                         ft_gpr(rsp_index), i * step);
                        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(regs[i]), la_t0,
                                             15, 0);
                    } else {
                        FT_LA_LD_WU_EMIT(&out, ft_gpr(regs[i]),
                                         ft_gpr(rsp_index), i * step);
                    }
                }
                FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                                   ft_gpr(rsp_index), 8 * step);
            }
        }
#endif
        break;
    case FT_PUSH_IMM32:
    case FT_PUSH_IMM8:
        ft_emit_li64(&out, la_t0, (uint64_t)(int64_t)fields->imm);
#ifdef QUICKTRANS_LATU
        if (fields->alu_width == 16) {
            /* 66 6a ib sign-extends the immediate to a 16-bit stack value. */
            FT_LA_ST_H_EMIT(&out, la_t0, ft_gpr(rsp_index), -2);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), -2);
        } else
#endif
        if (fields->alu_width == 32) {
            FT_LA_ST_W_EMIT(&out, la_t0, ft_gpr(rsp_index), -4);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), -4);
        } else {
            FT_LA_ST_D_EMIT(&out, la_t0, ft_gpr(rsp_index), -8);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), -8);
        }
        break;
    case FT_PUSH_IMM16:
        ft_emit_li64(&out, la_t0, (uint16_t)fields->imm);
        FT_LA_ST_H_EMIT(&out, la_t0, ft_gpr(rsp_index), -2);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), -2);
        break;
    case FT_POP_R64:
        if (fields->reg < 0 || fields->reg >= GPR_NUM) {
            return 0;
        }
        if (fields->reg == rsp_index) {
            if (fields->alu_width == 32) {
                FT_LA_LD_WU_EMIT(&out, ft_gpr(rsp_index),
                                 ft_gpr(rsp_index), 0);
            } else {
                FT_LA_LD_D_EMIT(&out, ft_gpr(rsp_index),
                                ft_gpr(rsp_index), 0);
            }
            break;
        }
        if (fields->alu_width == 32) {
            FT_LA_LD_WU_EMIT(&out, ft_gpr(fields->reg), ft_gpr(rsp_index), 0);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), 4);
        } else {
            FT_LA_LD_D_EMIT(&out, ft_gpr(fields->reg), ft_gpr(rsp_index), 0);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), 8);
        }
        break;
    case FT_POP_R16:
#ifdef QUICKTRANS_LATU
        if (fields->reg == rsp_index) {
            ft_emit_latu_pop_sp(&out);
            break;
        }
#endif
        if (fields->reg < 0 || fields->reg >= GPR_NUM ||
            fields->reg == rsp_index) {
            return 0;
        }
        FT_LA_LD_H_EMIT(&out, la_t0, ft_gpr(rsp_index), 0);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(fields->reg), la_t0, 15, 0);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), 2);
        break;
    case FT_PUSH_R64:
        if (fields->reg < 0 || fields->reg >= GPR_NUM) {
            return 0;
        }
        if (fields->alu_width == 32) {
            FT_LA_ST_W_EMIT(&out, ft_gpr(fields->reg), ft_gpr(rsp_index), -4);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), -4);
        } else {
            FT_LA_ST_D_EMIT(&out, ft_gpr(fields->reg), ft_gpr(rsp_index), -8);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), -8);
        }
        break;
    case FT_PUSH_R16:
        if (fields->reg < 0 || fields->reg >= GPR_NUM) {
            return 0;
        }
        FT_LA_ST_H_EMIT(&out, ft_gpr(fields->reg), ft_gpr(rsp_index), -2);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), -2);
        break;
    case FT_PUSH_RM64:
    {
        int src;
        int width = fields->alu_width;

        if (fields->modrm_reg != 6 ||
            !(width == 32 ? ft_emit_load_rm32(&out, fields, pc, &src) :
                           ft_emit_load_rm64(&out, fields, pc, &src))) {
            return 0;
        }
        if (width == 32) {
            FT_LA_ST_W_EMIT(&out, src, ft_gpr(rsp_index), -4);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), -4);
        } else {
            FT_LA_ST_D_EMIT(&out, src, ft_gpr(rsp_index), -8);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), -8);
        }
        break;
    }
    case FT_POP_RM64:
    {
        int addr;
        int width = fields->alu_width;
        int bytes = width == 32 ? 4 : 8;

        if (fields->modrm_reg != 0) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

#ifdef QUICKTRANS_LATU
            if (dst == rsp_index && width != 32) {
                FT_LA_LD_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), 0);
                return out - code;
            }
#endif
            if (dst >= GPR_NUM || dst == rsp_index) {
                return 0;
            }
            if (width == 32) {
                FT_LA_LD_WU_EMIT(&out, ft_gpr(dst), ft_gpr(rsp_index), 0);
            } else {
                FT_LA_LD_D_EMIT(&out, ft_gpr(dst), ft_gpr(rsp_index), 0);
            }
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), bytes);
            return (out - code);
        }

#ifdef QUICKTRANS_LATU
        int pop_offset;
        if (!ft_emit_latu_pop_addr(&out, fields, pc, bytes, &addr, &pop_offset)) {
#else
        if (!ft_emit_mem_addr(&out, fields, &addr)) {
#endif
            return 0;
        }
        {
#ifdef QUICKTRANS_LATU
            int offset = pop_offset;
#else
            int base;
            int offset = ft_mem_access_offset(fields, addr);
            if (fields->segment < 0 &&
                ft_base_from_modrm_sib(fields, &base) &&
                base == rsp_index) {
                offset += bytes;
            }
#endif
            if (!ft_fits_simm12(offset)) {
                if (!ft_emit_li32(&out, la_t3, (uint32_t)offset)) {
                    return 0;
                }
                FT_LA_ADD_D_EMIT(&out, la_t3, addr, la_t3);
                addr = la_t3;
                offset = 0;
            }
            if (width == 32) {
                FT_LA_LD_WU_EMIT(&out, la_t4, ft_gpr(rsp_index), 0);
                FT_LA_ST_W_EMIT(&out, la_t4, addr, offset);
            } else {
                FT_LA_LD_D_EMIT(&out, la_t4, ft_gpr(rsp_index), 0);
                FT_LA_ST_D_EMIT(&out, la_t4, addr, offset);
            }
        }
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), bytes);
        break;
    }
    case FT_PUSH_RM16:
    {
        int src;

        if (fields->modrm_reg != 6 ||
            !ft_emit_load_rm16(&out, fields, pc, &src)) {
            return 0;
        }
        FT_LA_ST_H_EMIT(&out, src, ft_gpr(rsp_index), -2);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), -2);
        break;
    }
    case FT_POP_RM16:
    {
        int addr;

        if (fields->modrm_reg != 0) {
            return 0;
        }
        if (fields->modrm_mod == 3) {
            int dst = ft_modrm_rm_index(fields);

#ifdef QUICKTRANS_LATU
            if (dst == rsp_index) {
                ft_emit_latu_pop_sp(&out);
                return out - code;
            }
#endif
            if (dst >= GPR_NUM || dst == rsp_index) {
                return 0;
            }
            FT_LA_LD_H_EMIT(&out, la_t0, ft_gpr(rsp_index), 0);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(dst), la_t0, 15, 0);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), 2);
            return (out - code);
        }

#ifdef QUICKTRANS_LATU
        int pop_offset;
        if (!ft_emit_latu_pop_addr(&out, fields, pc, 2, &addr, &pop_offset)) {
#else
        if (!ft_emit_mem_addr(&out, fields, &addr)) {
#endif
            return 0;
        }
        {
#ifdef QUICKTRANS_LATU
            int offset = pop_offset;
#else
            int base;
            int offset = ft_mem_access_offset(fields, addr);
            if (fields->segment < 0 &&
                ft_base_from_modrm_sib(fields, &base) &&
                base == rsp_index) {
                offset += 2;
            }
#endif
            if (!ft_fits_simm12(offset)) {
                if (!ft_emit_li32(&out, la_t3, (uint32_t)offset)) {
                    return 0;
                }
                FT_LA_ADD_D_EMIT(&out, la_t3, addr, la_t3);
                addr = la_t3;
                offset = 0;
            }
            FT_LA_LD_H_EMIT(&out, la_t4, ft_gpr(rsp_index), 0);
            FT_LA_ST_H_EMIT(&out, la_t4, addr, offset);
        }
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), 2);
        break;
    }
    case FT_PUSH_SEG64:
    case FT_PUSH_SEG16:
    {
        int bytes = fields->kind == FT_PUSH_SEG16 ? 2 : 8;

        if (fields->reg != fs_index && fields->reg != gs_index) {
            return 0;
        }
        ft_emit_load_env(&out, la_t0,
                         offsetof(CPUX86State, segs[fields->reg].selector),
                         FT_LA_OPCODE_LD_WU);
        if (bytes == 2) {
            FT_LA_ST_H_EMIT(&out, la_t0, ft_gpr(rsp_index), -bytes);
        } else {
            FT_LA_ST_D_EMIT(&out, la_t0, ft_gpr(rsp_index), -bytes);
        }
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), -bytes);
        break;
    }
    case FT_POP_SEG64:
    case FT_POP_SEG16:
    {
        int bytes = fields->kind == FT_POP_SEG16 ? 2 : 8;
#ifndef QUICKTRANS_LATU
        bool static_context;
        bool use_static_context;
#endif

        if (fields->reg != fs_index && fields->reg != gs_index) {
            return 0;
        }
#ifndef QUICKTRANS_LATU
        /* Read the guest stack before the static prologue leaves guest ASID. */
        use_static_context = scs_enabled();
        FT_LA_LD_HU_EMIT(&out,
                         use_static_context ? la_a2 : la_a3,
                         ft_gpr(rsp_index), 0);
        static_context = ft_emit_nofp_helper_prologue(&out);
        lsassert(static_context == use_static_context);
#else
        ft_emit_helper_prologue(&out);
#endif
        ft_emit_cpu_env_ptr(&out, la_a0);
        FT_LA_ADDI_D_EMIT(&out, la_a1, la_zero, fields->reg);
#ifndef QUICKTRANS_LATU
        if (!static_context) {
            FT_LA_OR_EMIT(&out, la_a2, la_a3, la_zero);
        }
#else
        FT_LA_LD_HU_EMIT(&out, la_a2, ft_gpr(rsp_index), 0);
#endif
#ifndef QUICKTRANS_LATU
        ft_emit_default_helper_call(&out, (void *)helper_load_seg,
                                    1u << 0, static_context);
        ft_emit_nofp_helper_epilogue(&out, static_context);
#else
        ft_emit_host_call(&out, (void *)helper_load_seg, 1u << 0);
        ft_emit_helper_epilogue(&out);
#endif
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), bytes);
        break;
    }
    case FT_LEAVE:
        if (fields->alu_width == 32) {
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rsp_index),
                                  ft_gpr(rbp_index), 31, 0);
            FT_LA_LD_WU_EMIT(&out, ft_gpr(rbp_index), ft_gpr(rsp_index), 0);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), 4);
            FT_LA_BSTRPICK_D_EMIT(&out, ft_gpr(rsp_index),
                                  ft_gpr(rsp_index), 31, 0);
            break;
        }
        if (fields->prefix2 == dt_X86_PREFIX_OPSIZE) {
            FT_LA_OR_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rbp_index),
                          la_zero);
            FT_LA_LD_HU_EMIT(&out, la_t0, ft_gpr(rsp_index), 0);
            FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(rbp_index), la_t0, 15, 0);
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), 2);
            break;
        }
        FT_LA_OR_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rbp_index), la_zero);
        FT_LA_LD_D_EMIT(&out, ft_gpr(rbp_index), ft_gpr(rsp_index), 0);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), 8);
        break;
    case FT_ENTER_ZERO_LEVEL1:
        FT_LA_ST_D_EMIT(&out, ft_gpr(rbp_index), ft_gpr(rsp_index), -8);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), -8);
        FT_LA_OR_EMIT(&out, ft_gpr(rbp_index), ft_gpr(rsp_index), la_zero);
        FT_LA_ST_D_EMIT(&out, ft_gpr(rbp_index), ft_gpr(rsp_index), -8);
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), -8);
        break;
    case FT_ENTER:
    case FT_ENTER16:
    {
        bool is_16 = fields->kind == FT_ENTER16;
        int step = is_16 ? 2 : 8;
        unsigned int allocation = fields->imm & 0xffff;
        unsigned int nesting_level = (unsigned int)fields->imm >> 16;
        unsigned int i;

        if (is_16) {
            FT_LA_ST_H_EMIT(&out, ft_gpr(rbp_index), ft_gpr(rsp_index),
                            -step);
        } else {
            FT_LA_ST_D_EMIT(&out, ft_gpr(rbp_index), ft_gpr(rsp_index),
                            -step);
        }
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                          ft_gpr(rsp_index), -step);

        if (nesting_level) {
            FT_LA_OR_EMIT(&out, la_t1, ft_gpr(rsp_index), la_zero);
            for (i = 1; i < nesting_level; i++) {
                int frame_addr = la_t2;
                int frame_offset = 0;

#ifdef QUICKTRANS_LATU
                if (!is_16) {
                    /* Nesting is masked to five bits: -8*i fits simm12. */
                    frame_addr = ft_gpr(rbp_index);
                    frame_offset = -(int)(step * i);
                } else
#endif
                {
                    FT_LA_ADDI_D_EMIT(&out, la_t2, ft_gpr(rbp_index),
                                      -(int)(step * i));
                }
                if (is_16) {
                    FT_LA_LD_HU_EMIT(&out, la_t3, frame_addr, frame_offset);
                    FT_LA_ST_H_EMIT(&out, la_t3, ft_gpr(rsp_index),
                                    -step);
                } else {
                    FT_LA_LD_D_EMIT(&out, la_t3, frame_addr, frame_offset);
                    FT_LA_ST_D_EMIT(&out, la_t3, ft_gpr(rsp_index),
                                    -step);
                }
                FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                                  ft_gpr(rsp_index), -step);
            }
            if (is_16) {
                FT_LA_ST_H_EMIT(&out, la_t1, ft_gpr(rsp_index), -step);
            } else {
                FT_LA_ST_D_EMIT(&out, la_t1, ft_gpr(rsp_index), -step);
            }
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                              ft_gpr(rsp_index), -step);
            FT_LA_OR_EMIT(&out, ft_gpr(rbp_index), la_t1, la_zero);
        } else {
            FT_LA_OR_EMIT(&out, ft_gpr(rbp_index), ft_gpr(rsp_index),
                          la_zero);
        }

        if (allocation) {
            if (ft_fits_simm12(-(int)allocation)) {
                FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index),
                                  ft_gpr(rsp_index), -(int)allocation);
            } else if (!ft_emit_li32(&out, la_t0, allocation)) {
                return 0;
            } else {
                FT_LA_SUB_D_EMIT(&out, ft_gpr(rsp_index),
                                 ft_gpr(rsp_index), la_t0);
            }
        }
        break;
    }
    default:
        return 0;
    }

    return (out - code);
}

static uint32_t ft_compat_direct_target(const FastTemplateFields *fields,
                                        target_ulong next_pc)
{
    uint32_t target = next_pc + fields->imm;

    if (fields->prefix2 == dt_X86_PREFIX_OPSIZE && fields->opcode0 != 0xeb) {
        target = (uint16_t)target;
    }
    return target;
}

/* Near transfers on a flat 32-bit stack use guest return addresses. */
static int ft_try_emit_compat_near_transfer(const FastTemplateFields *fields,
                                        TranslationBlock *tb,
                                        target_ulong pc, uint32_t *code)
{
    uint32_t *out = code;
    int esp = ft_gpr(rsp_index);
    unsigned slot = fields->prefix2 == dt_X86_PREFIX_OPSIZE ? 2 : 4;
    uint32_t next = pc + fields->size;

#ifndef QUICKTRANS_LATU
    switch (fields->kind) {
    case FT_CALL_REL32:
    case FT_CALL_RM64:
    case FT_RET:
    case FT_RET_IMM16:
        /* The stack and indirect operand accesses below use flat addresses. */
        if (!(tb->flags & HF_CS32_MASK) || !(tb->flags & HF_SS32_MASK) ||
            (tb->flags & HF_ADDSEG_MASK) || tb->cs_base) {
            return 0;
        }
        break;
    default:
        return -1;
    }
#endif

    switch (fields->kind) {
    case FT_RET:
    case FT_RET_IMM16: {
        unsigned pop = slot + (uint16_t)fields->imm;

        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, esp, 31, 0);
        if (slot == 2) {
            FT_LA_LD_HU_EMIT(&out, la_r21, la_t0, 0);
        } else {
            FT_LA_LD_WU_EMIT(&out, la_r21, la_t0, 0);
        }
        if (ft_fits_simm12(pop)) {
            FT_LA_ADDI_D_EMIT(&out, esp, esp, pop);
        } else {
            ft_emit_li32(&out, la_t0, pop);
            FT_LA_ADD_D_EMIT(&out, esp, esp, la_t0);
        }
        FT_LA_BSTRPICK_D_EMIT(&out, esp, esp, 31, 0);
#ifndef QUICKTRANS_LATU
        if (!(tb->flags & HF_INHIBIT_IRQ_MASK)) {
            ft_emit_lats_soft_ras_pop(tb, &out, la_r21);
        }
#endif
        return ft_emit_helper_indirect_exit(&out, tb, code, la_r21, true);
    }
    case FT_CALL_RM64:
    case FT_JMP_RM64:
        if (!(slot == 2 ? ft_emit_load_rm16_zext(&out, fields, pc, la_r21) :
                          ft_emit_load_rm32_zext(&out, fields, pc, la_r21))) {
            return 0;
        }
        break;
    case FT_CALL_REL32:
    case FT_JMP_REL32:
        break;
    default:
        return -1;
    }

    if (fields->kind == FT_CALL_REL32 || fields->kind == FT_CALL_RM64) {
#ifndef QUICKTRANS_LATU
        ft_emit_jrra_call_metadata(tb, &out, (uintptr_t)tb->tc.ptr, next,
                                   fields->kind == FT_CALL_REL32);
#endif
        FT_LA_ADDI_D_EMIT(&out, la_t0, esp, -(int)slot);
        FT_LA_BSTRPICK_D_EMIT(&out, la_t0, la_t0, 31, 0);
        ft_emit_li32(&out, la_t1, next);
        if (slot == 2) {
            FT_LA_ST_H_EMIT(&out, la_t1, la_t0, 0);
        } else {
            FT_LA_ST_W_EMIT(&out, la_t1, la_t0, 0);
        }
        FT_LA_OR_EMIT(&out, esp, la_t0, la_zero);
#ifndef QUICKTRANS_LATU
        lsenv->tr_data->pc_next = next;
        ft_emit_lats_soft_ras_push(tb, &out, next);
#endif
    }
    if (fields->kind == FT_CALL_RM64 || fields->kind == FT_JMP_RM64) {
        return ft_emit_helper_indirect_exit(&out, tb, code, la_r21, false);
    }
    if (!ft_emit_direct_link_exit(tb, &out, 0,
                                  ft_compat_direct_target(fields, next), la_t1)) {
        return 0;
    }
    return out - code;
}
