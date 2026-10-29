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
                FT_LA_ADDI_D_EMIT(&out, la_t2, ft_gpr(rbp_index),
                                  -(int)(step * i));
                if (is_16) {
                    FT_LA_LD_HU_EMIT(&out, la_t3, la_t2, 0);
                    FT_LA_ST_H_EMIT(&out, la_t3, ft_gpr(rsp_index),
                                    -step);
                } else {
                    FT_LA_LD_D_EMIT(&out, la_t3, la_t2, 0);
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
