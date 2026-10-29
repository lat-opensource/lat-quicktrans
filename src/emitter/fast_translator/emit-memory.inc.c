/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* r/m load-store emit helpers. */

static int ft_store_preserve_src(uint32_t **out,
                                  const FastTemplateFields *fields, int src_reg)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    int base;

    /* A native-width base+small-displacement address emits no instructions.
     * Its GPR base cannot alias the temporary value register. */
    if (!fields->addr32 && fields->segment < 0 &&
        ft_fits_simm12(fields->disp) &&
        ft_base_from_modrm_sib(fields, &base)) {
        return src_reg;
    }
#else
    (void)fields;
#endif
    /* Other address forms may overwrite the temporary value. */
    if (src_reg == la_t0 || src_reg == la_t1 || src_reg == la_t4) {
        FT_LA_OR_EMIT(out, la_t3, src_reg, la_zero);
        return la_t3;
    }
    return src_reg;
}

static int ft_store_scratch_reg(int src_reg, int addr_reg)
{
    if (src_reg != la_t0 && addr_reg != la_t0) {
        return la_t0;
    }
    if (src_reg != la_t2 && addr_reg != la_t2) {
        return la_t2;
    }
    if (src_reg != la_t3 && addr_reg != la_t3) {
        return la_t3;
    }
    return la_t4;
}

static bool ft_emit_load_rm64(uint32_t **out, const FastTemplateFields *fields,
                              target_ulong pc, int *src_reg)
{
    if (fields->modrm_mod == 3) {
        int src = ft_modrm_rm_index(fields);

        if (src >= GPR_NUM) {
            return false;
        }
        *src_reg = ft_gpr(src);
        return true;
    }

    if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;

        if (!ft_emit_guest_addr(out, la_t1, target)) {
            return false;
        }
        if ((target & 7) == 0) {
            FT_LA_LD_D_EMIT(out, la_t0, la_t1, 0);
            *src_reg = la_t0;
            return true;
        }
        FT_LA_LD_BU_EMIT(out, la_t0, la_t1, 0);
        for (int i = 1; i < 8; ++i) {
            FT_LA_LD_BU_EMIT(out, la_t2, la_t1, i);
            FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, i * 8);
            FT_LA_OR_EMIT(out, la_t0, la_t0, la_t2);
        }
        *src_reg = la_t0;
        return true;
    }

    {
        int addr;

        if (!ft_emit_mem_addr(out, fields, &addr)) {
            return false;
        }
        FT_LA_LD_D_EMIT(out, la_t0, addr,
                                  ft_mem_access_offset(fields, addr));
        *src_reg = la_t0;
        return true;
    }
}

static bool ft_emit_load_rm16(uint32_t **out, const FastTemplateFields *fields,
                              target_ulong pc, int *src_reg)
{
    if (fields->modrm_mod == 3) {
        int src = ft_modrm_rm_index(fields);

        if (src >= GPR_NUM) {
            return false;
        }
        *src_reg = ft_gpr(src);
        return true;
    }

    if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;

        if (!ft_emit_guest_addr(out, la_t1, target)) {
            return false;
        }
        if (target & 1) {
            FT_LA_LD_BU_EMIT(out, la_t0, la_t1, 0);
            FT_LA_LD_BU_EMIT(out, la_t2, la_t1, 1);
            FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, 8);
            FT_LA_OR_EMIT(out, la_t0, la_t0, la_t2);
            *src_reg = la_t0;
            return true;
        }
        FT_LA_LD_H_EMIT(out, la_t0, la_t1, 0);
        *src_reg = la_t0;
        return true;
    }

    {
        int addr;

        if (!ft_emit_mem_addr(out, fields, &addr)) {
            return false;
        }
        FT_LA_LD_H_EMIT(out, la_t0, addr,
                                  ft_mem_access_offset(fields, addr));
        *src_reg = la_t0;
        return true;
    }
}

static bool ft_emit_load_rm32(uint32_t **out, const FastTemplateFields *fields,
                              target_ulong pc, int *src_reg)
{
    if (fields->modrm_mod == 3) {
        int src = ft_modrm_rm_index(fields);

        if (src >= GPR_NUM) {
            return false;
        }
        *src_reg = ft_gpr(src);
        return true;
    }

    if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;

        if (!ft_emit_guest_addr(out, la_t1, target)) {
            return false;
        }
        if (target & 3) {
            FT_LA_LD_BU_EMIT(out, la_t0, la_t1, 0);
            for (int i = 1; i < 4; ++i) {
                FT_LA_LD_BU_EMIT(out, la_t2, la_t1, i);
                FT_LA_SLLI_D_EMIT(out, la_t2, la_t2, i * 8);
                FT_LA_OR_EMIT(out, la_t0, la_t0, la_t2);
            }
            *src_reg = la_t0;
            return true;
        }
        FT_LA_LD_W_EMIT(out, la_t0, la_t1, 0);
        *src_reg = la_t0;
        return true;
    }

    {
        int addr;

        if (!ft_emit_mem_addr(out, fields, &addr)) {
            return false;
        }
        FT_LA_LD_W_EMIT(out, la_t0, addr,
                                  ft_mem_access_offset(fields, addr));
        *src_reg = la_t0;
        return true;
    }
}

static bool ft_emit_load_rm8(uint32_t **out, const FastTemplateFields *fields,
                             target_ulong pc, int *src_reg)
{
    if (fields->modrm_mod == 3) {
        int src = ft_modrm_rm_index(fields);

        if (ft_modrm_rm_is_high8(fields)) {
            src = ft_modrm_rm_high8_base_index(fields);
            FT_LA_SRLI_D_EMIT(out, la_t0, ft_gpr(src), 8);
            *src_reg = la_t0;
            return true;
        }
        if (src >= GPR_NUM) {
            return false;
        }
        *src_reg = ft_gpr(src);
        return true;
    }

    if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;

        if (!ft_emit_guest_addr(out, la_t0, target)) {
            return false;
        }
        FT_LA_LD_B_EMIT(out, la_t0, la_t0, 0);
        *src_reg = la_t0;
        return true;
    }

    {
        int addr;

        if (!ft_emit_mem_addr(out, fields, &addr)) {
            return false;
        }
        FT_LA_LD_B_EMIT(out, la_t0, addr,
                                  ft_mem_access_offset(fields, addr));
        *src_reg = la_t0;
        return true;
    }
}

static bool ft_emit_store_rm64(uint32_t **out, const FastTemplateFields *fields,
                               target_ulong pc, int src_reg)
{
    int dst_or_addr;
    int value_reg = src_reg;

    if (fields->modrm_mod == 3) {
        dst_or_addr = ft_modrm_rm_index(fields);
        if (dst_or_addr >= GPR_NUM) {
            return false;
        }
        FT_LA_OR_EMIT(out, ft_gpr(dst_or_addr), src_reg, la_zero);
        return true;
    }

    if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;
        int addr_reg = src_reg == la_t1 ? la_t3 : la_t1;
        int tmp_reg = ft_store_scratch_reg(src_reg, addr_reg);

        if (!ft_emit_guest_addr(out, addr_reg, target)) {
            return false;
        }
        if (ft_emit_data_store(out, pc, addr_reg, 0, src_reg, 8)) {
            return true;
        }
        if ((target & 7) == 0) {
            FT_LA_ST_D_EMIT(out, src_reg, addr_reg, 0);
            return true;
        }
        FT_LA_ST_B_EMIT(out, src_reg, addr_reg, 0);
        for (int i = 1; i < 8; ++i) {
            FT_LA_SRLI_D_EMIT(out, tmp_reg, src_reg, i * 8);
            FT_LA_ST_B_EMIT(out, tmp_reg, addr_reg, i);
        }
        return true;
    }

    value_reg = ft_store_preserve_src(out, fields, src_reg);
    if (!ft_emit_mem_addr(out, fields, &dst_or_addr)) {
        return false;
    }
    int offset = ft_mem_access_offset(fields, dst_or_addr);

    if (!ft_emit_data_store(out, pc, dst_or_addr, offset, value_reg, 8)) {
        FT_LA_ST_D_EMIT(out, value_reg, dst_or_addr, offset);
    }
    return true;
}

static bool ft_emit_store_rm32(uint32_t **out, const FastTemplateFields *fields,
                               target_ulong pc, int src_reg,
                               bool zero_extend_reg)
{
    int dst_or_addr;
    int value_reg = src_reg;

    if (fields->modrm_mod == 3) {
        dst_or_addr = ft_modrm_rm_index(fields);
        if (dst_or_addr >= GPR_NUM) {
            return false;
        }
#ifdef QUICKTRANS_LATU
        if (ft_gpr(dst_or_addr) != src_reg)
#endif
        FT_LA_OR_EMIT(out, ft_gpr(dst_or_addr), src_reg, la_zero);
        if (zero_extend_reg) {
            FT_LA_BSTRPICK_D_EMIT(out, ft_gpr(dst_or_addr),
                                      ft_gpr(dst_or_addr), 31, 0);
        }
        return true;
    }

    if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;
        int addr_reg = src_reg == la_t1 ? la_t3 : la_t1;
        int tmp_reg = ft_store_scratch_reg(src_reg, addr_reg);

        if (!ft_emit_guest_addr(out, addr_reg, target)) {
            return false;
        }
        if (ft_emit_data_store(out, pc, addr_reg, 0, src_reg, 4)) {
            return true;
        }
        if (target & 3) {
            for (int i = 0; i < 4; ++i) {
                if (i == 0) {
                    FT_LA_ST_B_EMIT(out, src_reg, addr_reg, 0);
                } else {
                    FT_LA_SRLI_D_EMIT(out, tmp_reg, src_reg, i * 8);
                    FT_LA_ST_B_EMIT(out, tmp_reg, addr_reg, i);
                }
            }
            return true;
        }
        FT_LA_ST_W_EMIT(out, src_reg, addr_reg, 0);
        return true;
    }

    value_reg = ft_store_preserve_src(out, fields, src_reg);
    if (!ft_emit_mem_addr(out, fields, &dst_or_addr)) {
        return false;
    }
    int offset = ft_mem_access_offset(fields, dst_or_addr);

    if (!ft_emit_data_store(out, pc, dst_or_addr, offset, value_reg, 4)) {
        FT_LA_ST_W_EMIT(out, value_reg, dst_or_addr, offset);
    }
    return true;
}

static bool ft_emit_store_rm16(uint32_t **out, const FastTemplateFields *fields,
                               target_ulong pc, int src_reg)
{
    int dst_or_addr;
    int value_reg = src_reg;

    if (fields->modrm_mod == 3) {
        dst_or_addr = ft_modrm_rm_index(fields);
        if (dst_or_addr >= GPR_NUM) {
            return false;
        }
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst_or_addr), src_reg, 15, 0);
        return true;
    }

    if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;
        int addr_reg = src_reg == la_t1 ? la_t3 : la_t1;
        int tmp_reg = ft_store_scratch_reg(src_reg, addr_reg);

        if (!ft_emit_guest_addr(out, addr_reg, target)) {
            return false;
        }
        if (ft_emit_data_store(out, pc, addr_reg, 0, src_reg, 2)) {
            return true;
        }
        if (target & 1) {
            FT_LA_ST_B_EMIT(out, src_reg, addr_reg, 0);
            FT_LA_SRLI_D_EMIT(out, tmp_reg, src_reg, 8);
            FT_LA_ST_B_EMIT(out, tmp_reg, addr_reg, 1);
            return true;
        }
        FT_LA_ST_H_EMIT(out, src_reg, addr_reg, 0);
        return true;
    }

    value_reg = ft_store_preserve_src(out, fields, src_reg);
    if (!ft_emit_mem_addr(out, fields, &dst_or_addr)) {
        return false;
    }
    int offset = ft_mem_access_offset(fields, dst_or_addr);

    if (!ft_emit_data_store(out, pc, dst_or_addr, offset, value_reg, 2)) {
        FT_LA_ST_H_EMIT(out, value_reg, dst_or_addr, offset);
    }
    return true;
}

static bool ft_emit_store_rm8(uint32_t **out, const FastTemplateFields *fields,
                              target_ulong pc, int src_reg)
{
    int dst_or_addr;
    int value_reg = src_reg;

    if (fields->modrm_mod == 3) {
        if (ft_modrm_rm_is_high8(fields)) {
            dst_or_addr = ft_modrm_rm_high8_base_index(fields);
            FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst_or_addr), src_reg, 15, 8);
            return true;
        }
        dst_or_addr = ft_modrm_rm_index(fields);
        if (dst_or_addr >= GPR_NUM) {
            return false;
        }
        FT_LA_BSTRINS_D_EMIT(out, ft_gpr(dst_or_addr), src_reg, 7, 0);
        return true;
    }

    if (ft_rip_relative_mem(fields)) {
        target_ulong target = pc + fields->size + fields->disp;
        int addr_reg = src_reg == la_t1 ? la_t3 : la_t1;

        if (!ft_emit_guest_addr(out, addr_reg, target)) {
            return false;
        }
        if (!ft_emit_data_store(out, pc, addr_reg, 0, src_reg, 1)) {
            FT_LA_ST_B_EMIT(out, src_reg, addr_reg, 0);
        }
        return true;
    }

    value_reg = ft_store_preserve_src(out, fields, src_reg);
    if (!ft_emit_mem_addr(out, fields, &dst_or_addr)) {
        return false;
    }
    int offset = ft_mem_access_offset(fields, dst_or_addr);

    if (!ft_emit_data_store(out, pc, dst_or_addr, offset, value_reg, 1)) {
        FT_LA_ST_B_EMIT(out, value_reg, dst_or_addr, offset);
    }
    return true;
}

static bool ft_emit_store_addr64_bytes(uint32_t **out, int addr_reg,
                                       int offset, int src_reg)
{
    static const int tmp_candidates[] = { la_t0, la_t1, la_t2, la_t3, la_t4 };
    int store_addr_reg = addr_reg;
    int store_offset = offset;
    int tmp_reg = -1;

    if (!ft_fits_simm12(offset)) {
        return false;
    }
    if (!ft_fits_simm12(offset + 7)) {
        for (size_t i = 0; i < ARRAY_SIZE(tmp_candidates); ++i) {
            if (tmp_candidates[i] != src_reg &&
                tmp_candidates[i] != addr_reg) {
                store_addr_reg = tmp_candidates[i];
                break;
            }
        }
        if (store_addr_reg == addr_reg) {
            return false;
        }
        FT_LA_ADDI_D_EMIT(out, store_addr_reg, addr_reg, offset);
        store_offset = 0;
    }
    for (size_t i = 0; i < ARRAY_SIZE(tmp_candidates); ++i) {
        if (tmp_candidates[i] != src_reg &&
            tmp_candidates[i] != addr_reg &&
            tmp_candidates[i] != store_addr_reg) {
            tmp_reg = tmp_candidates[i];
            break;
        }
    }
    if (tmp_reg < 0) {
        return false;
    }
    FT_LA_ST_B_EMIT(out, src_reg, store_addr_reg, store_offset);
    for (int i = 1; i < 8; ++i) {
        FT_LA_SRLI_D_EMIT(out, tmp_reg, src_reg, i * 8);
        FT_LA_ST_B_EMIT(out, tmp_reg, store_addr_reg, store_offset + i);
    }
    return true;
}

static bool ft_emit_store_addr_bytes(uint32_t **out, target_ulong guest_pc,
                                     int addr_reg, int offset, int src_reg,
                                     int bytes)
{
    static const int tmp_candidates[] = { la_t0, la_t1, la_t2, la_t3, la_t4 };
    int tmp_reg = -1;

    if (bytes <= 0 || bytes > 8) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(tmp_candidates); ++i) {
        if (tmp_candidates[i] != src_reg && tmp_candidates[i] != addr_reg) {
            tmp_reg = tmp_candidates[i];
            break;
        }
    }
    if (tmp_reg < 0) {
        return false;
    }
    if (!ft_fits_simm12(offset) || !ft_fits_simm12(offset + bytes - 1)) {
        return false;
    }
    if (ft_emit_data_store(out, guest_pc, addr_reg, offset, src_reg, bytes)) {
        return true;
    }
    FT_LA_ST_B_EMIT(out, src_reg, addr_reg, offset);
    for (int i = 1; i < bytes; ++i) {
        FT_LA_SRLI_D_EMIT(out, tmp_reg, src_reg, i * 8);
        FT_LA_ST_B_EMIT(out, tmp_reg, addr_reg, offset + i);
    }
    return true;
}

static bool ft_emit_load_addr_bytes(uint32_t **out, int addr_reg, int offset,
                                    int dst_reg, int bytes)
{
    static const int tmp_candidates[] = { la_t0, la_t1, la_t2, la_t3, la_t4 };
    int tmp_reg = -1;

    if (bytes <= 0 || bytes > 8 || dst_reg == addr_reg ||
        !ft_fits_simm12(offset) ||
        !ft_fits_simm12(offset + bytes - 1)) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(tmp_candidates); ++i) {
        if (tmp_candidates[i] != dst_reg &&
            tmp_candidates[i] != addr_reg) {
            tmp_reg = tmp_candidates[i];
            break;
        }
    }
    if (tmp_reg < 0) {
        return false;
    }

    FT_LA_LD_BU_EMIT(out, dst_reg, addr_reg, offset);
    for (int i = 1; i < bytes; ++i) {
        FT_LA_LD_BU_EMIT(out, tmp_reg, addr_reg, offset + i);
        FT_LA_SLLI_D_EMIT(out, tmp_reg, tmp_reg, i * 8);
        FT_LA_OR_EMIT(out, dst_reg, dst_reg, tmp_reg);
    }
    return true;
}

static bool ft_emit_store_xmm128_as_gpr(uint32_t **out, int src_xmm,
                                        int addr_reg, int offset)
{
    if (!ft_fits_simm12(offset)) {
        return false;
    }
    FT_LA_VST_EMIT(out, src_xmm, addr_reg, offset);
    return true;
}
