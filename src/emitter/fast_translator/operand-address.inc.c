/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* x86 operand, ModRM/SIB, and memory-address helpers. */

static inline int ft_addr_scratch0(void)
{
#ifdef CONFIG_SOFTMMU
    /* t0/t1 hold the guest r8/r9 values in the LATS system ABI. */
    return la_a4;
#else
    return la_t0;
#endif
}

static inline int ft_addr_scratch1(void)
{
#ifdef CONFIG_SOFTMMU
    return la_a5;
#else
    return la_t1;
#endif
}

static inline int ft_modrm_reg_lo3(int modrm)
{
    return modrm & 7;
}

static inline int ft_modrm_reg64_from_c0(int modrm)
{
    return ft_gpr(ft_modrm_reg_lo3(modrm));
}

static inline int ft_modrm_mod(int modrm)
{
    return (modrm >> 6) & 3;
}

static inline int ft_rex_b(const FastTemplateFields *fields)
{
    return fields->rex_bits & 1;
}

static inline int ft_rex_r(const FastTemplateFields *fields)
{
    return (fields->rex_bits >> 2) & 1;
}

static inline int ft_rex_x(const FastTemplateFields *fields)
{
    return (fields->rex_bits >> 1) & 1;
}

static inline bool ft_rex_w(const FastTemplateFields *fields)
{
    return (fields->rex_bits & 8) != 0;
}

static inline int ft_modrm_reg_index(const FastTemplateFields *fields)
{
    return fields->modrm_reg_index;
}

static inline bool ft_rip_relative_mem(const FastTemplateFields *fields)
{
    return !fields->addr32 && fields->segment < 0 &&
           fields->modrm_mod == 0 &&
           fields->modrm_rm == 5;
}

static inline bool ft_rip_mem_aligned(const FastTemplateFields *fields,
                                      unsigned align)
{
    uint64_t target;

    if (!ft_rip_relative_mem(fields)) {
        return true;
    }
    target = fields->address + fields->size + fields->disp;
    return (target & (align - 1)) == 0;
}

static inline int ft_modrm_rm_index(const FastTemplateFields *fields)
{
    return fields->modrm_rm_index;
}

static inline bool ft_modrm_rm_is_high8(const FastTemplateFields *fields)
{
    return fields->rex < 0 && fields->modrm_mod == 3 &&
           fields->modrm_rm >= 4;
}

static inline int ft_modrm_rm_high8_base_index(const FastTemplateFields *fields)
{
    return fields->modrm & 3;
}

static inline bool ft_modrm_reg_is_high8(const FastTemplateFields *fields)
{
    return fields->rex < 0 && fields->modrm_reg >= 4;
}

static inline int ft_modrm_reg_high8_base_index(const FastTemplateFields *fields)
{
    return (fields->modrm >> 3) & 3;
}

static int ft_x86_gpr_index(dt_x86_reg reg)
{
    switch (reg) {
    case dt_X86_REG_AL:
    case dt_X86_REG_AX:
    case dt_X86_REG_EAX:
    case dt_X86_REG_RAX:
        return rax_index;
    case dt_X86_REG_CL:
    case dt_X86_REG_CX:
    case dt_X86_REG_ECX:
    case dt_X86_REG_RCX:
        return rcx_index;
    case dt_X86_REG_DL:
    case dt_X86_REG_DX:
    case dt_X86_REG_EDX:
    case dt_X86_REG_RDX:
        return rdx_index;
    case dt_X86_REG_BL:
    case dt_X86_REG_BX:
    case dt_X86_REG_EBX:
    case dt_X86_REG_RBX:
        return rbx_index;
    case dt_X86_REG_SPL:
    case dt_X86_REG_SP:
    case dt_X86_REG_ESP:
    case dt_X86_REG_RSP:
        return rsp_index;
    case dt_X86_REG_BPL:
    case dt_X86_REG_BP:
    case dt_X86_REG_EBP:
    case dt_X86_REG_RBP:
        return rbp_index;
    case dt_X86_REG_SIL:
    case dt_X86_REG_SI:
    case dt_X86_REG_ESI:
    case dt_X86_REG_RSI:
        return rsi_index;
    case dt_X86_REG_DIL:
    case dt_X86_REG_DI:
    case dt_X86_REG_EDI:
    case dt_X86_REG_RDI:
        return rdi_index;
    case dt_X86_REG_R8:
    case dt_X86_REG_R8D:
    case dt_X86_REG_R8W:
    case dt_X86_REG_R8B:
        return r8_index;
    case dt_X86_REG_R9:
    case dt_X86_REG_R9D:
    case dt_X86_REG_R9W:
    case dt_X86_REG_R9B:
        return r9_index;
    case dt_X86_REG_R10:
    case dt_X86_REG_R10D:
    case dt_X86_REG_R10W:
    case dt_X86_REG_R10B:
        return r10_index;
    case dt_X86_REG_R11:
    case dt_X86_REG_R11D:
    case dt_X86_REG_R11W:
    case dt_X86_REG_R11B:
        return r11_index;
    case dt_X86_REG_R12:
    case dt_X86_REG_R12D:
    case dt_X86_REG_R12W:
    case dt_X86_REG_R12B:
        return r12_index;
    case dt_X86_REG_R13:
    case dt_X86_REG_R13D:
    case dt_X86_REG_R13W:
    case dt_X86_REG_R13B:
        return r13_index;
    case dt_X86_REG_R14:
    case dt_X86_REG_R14D:
    case dt_X86_REG_R14W:
    case dt_X86_REG_R14B:
        return r14_index;
    case dt_X86_REG_R15:
    case dt_X86_REG_R15D:
    case dt_X86_REG_R15W:
    case dt_X86_REG_R15B:
        return r15_index;
    default:
        return -1;
    }
}

static int ft_x86_xmm_index(dt_x86_reg reg)
{
    if (reg >= dt_X86_REG_XMM0 && reg <= dt_X86_REG_XMM15) {
        return reg - dt_X86_REG_XMM0;
    }
    return -1;
}

static int ft_x86_seg_index(dt_x86_reg reg)
{
    switch (reg) {
    case dt_X86_REG_ES:
        return es_index;
    case dt_X86_REG_CS:
        return cs_index;
    case dt_X86_REG_SS:
        return ss_index;
    case dt_X86_REG_DS:
        return ds_index;
    case dt_X86_REG_FS:
        return fs_index;
    case dt_X86_REG_GS:
        return gs_index;
    default:
        return -1;
    }
}

static int ft_prefix_seg_index(uint8_t prefix)
{
    switch (prefix) {
    case dt_X86_PREFIX_ES:
        return es_index;
    case dt_X86_PREFIX_CS:
        return cs_index;
    case dt_X86_PREFIX_SS:
        return ss_index;
    case dt_X86_PREFIX_DS:
        return ds_index;
    case dt_X86_PREFIX_FS:
        return fs_index;
    case dt_X86_PREFIX_GS:
        return gs_index;
    default:
        return -1;
    }
}

static bool ft_sib_has_index(const FastTemplateFields *fields)
{
    return ((fields->sib >> 3) & 7) != 4 || ft_rex_x(fields);
}

static inline int ft_sib_scale(const FastTemplateFields *fields)
{
    return (fields->sib >> 6) & 3;
}

static inline int ft_sib_index_index(const FastTemplateFields *fields)
{
    return ((fields->sib >> 3) & 7) | (ft_rex_x(fields) << 3);
}

static bool ft_base_from_modrm_sib(const FastTemplateFields *fields, int *base)
{
    if (fields->modrm_rm == 4) {
        if (ft_sib_has_index(fields)) {
            return false;
        }
        if ((fields->sib & 7) == 5 && fields->modrm_mod == 0) {
            return false;
        }
        *base = (fields->sib & 7) | (ft_rex_b(fields) << 3);
        return *base < GPR_NUM;
    }

    if (fields->modrm_rm == 5 && fields->modrm_mod == 0) {
        return false;
    }
    *base = ft_modrm_rm_index(fields);
    return *base < GPR_NUM;
}

static bool ft_base_from_modrm_sib_with_index(const FastTemplateFields *fields,
                                              int *base)
{
    if (fields->modrm_rm == 4) {
        if ((fields->sib & 7) == 5 && fields->modrm_mod == 0) {
            return false;
        }
        *base = (fields->sib & 7) | (ft_rex_b(fields) << 3);
        return *base < GPR_NUM;
    }

    if (fields->modrm_rm == 5 && fields->modrm_mod == 0) {
        return false;
    }
    *base = ft_modrm_rm_index(fields);
    return *base < GPR_NUM;
}

static bool ft_emit_mem_addr(uint32_t **out, const FastTemplateFields *fields,
                             int *addr_reg)
{
    int base;
    const int tmp0 = ft_addr_scratch0();
    const int tmp1 = ft_addr_scratch1();

    if (fields->addr32) {
        FastTemplateFields offset_fields = *fields;
        int offset_reg;

        if (fields->modrm_mod == 0 && fields->modrm_rm == 5) {
            if (!ft_emit_li32(out, tmp0, (uint32_t)fields->disp)) {
                return false;
            }
            FT_LA_BSTRPICK_D_EMIT(out, tmp0, tmp0, 31, 0);
            if (fields->segment >= 0) {
                int offset = offsetof(CPUX86State,
                                      segs[fields->segment].base);
                if (!ft_fits_simm12(offset)) {
                    return false;
                }
                ft_emit_load_env(out, tmp1, offset, FT_LA_OPCODE_LD_D);
                FT_LA_ADD_D_EMIT(out, tmp0, tmp0, tmp1);
            }
            *addr_reg = tmp0;
            return true;
        }

        /* Wrap the complete offset before adding the 64-bit segment base. */
        offset_fields.addr32 = false;
        offset_fields.segment = -1;
        if (!ft_emit_mem_addr(out, &offset_fields, &offset_reg)) {
            return false;
        }
        if (offset_reg != tmp0 && offset_reg != tmp1 && fields->disp) {
            FT_LA_ADDI_D_EMIT(out, tmp0, offset_reg, fields->disp);
            offset_reg = tmp0;
        }
        FT_LA_BSTRPICK_D_EMIT(out, tmp0, offset_reg, 31, 0);
        if (fields->segment >= 0) {
            int offset = offsetof(CPUX86State, segs[fields->segment].base);
            if (!ft_fits_simm12(offset)) {
                return false;
            }
            ft_emit_load_env(out, tmp1, offset, FT_LA_OPCODE_LD_D);
            FT_LA_ADD_D_EMIT(out, tmp0, tmp0, tmp1);
        }
        *addr_reg = tmp0;
        return true;
    }

    if (fields->segment >= 0) {
        int seg_base_offset =
            offsetof(CPUX86State, segs[fields->segment].base);

        if (!ft_fits_simm12(seg_base_offset)) {
            return false;
        }
        ft_emit_load_env(out, tmp1, seg_base_offset, FT_LA_OPCODE_LD_D);

        if (fields->modrm_rm == 4 && ft_sib_has_index(fields)) {
            int index = ft_sib_index_index(fields);
            int scale = ft_sib_scale(fields);
            bool no_base = fields->modrm_mod == 0 &&
                           (fields->sib & 7) == 5;

            if (index >= GPR_NUM) {
                return false;
            }
            if (scale) {
                if (no_base) {
                    FT_LA_SLLI_D_EMIT(out, tmp0, ft_gpr(index), scale);
                } else {
                    if (!ft_base_from_modrm_sib_with_index(fields, &base)) {
                        return false;
                    }
                    FT_LA_ALSL_D_EMIT(out, tmp0, ft_gpr(index),
                                     ft_gpr(base), scale - 1);
                }
            } else {
                if (no_base) {
                    FT_LA_OR_EMIT(out, tmp0, ft_gpr(index), la_zero);
                } else {
                    if (!ft_base_from_modrm_sib_with_index(fields, &base)) {
                        return false;
                    }
                    FT_LA_ADD_D_EMIT(out, tmp0, ft_gpr(base),
                                     ft_gpr(index));
                }
            }
            FT_LA_ADD_D_EMIT(out, tmp1, tmp1, tmp0);
        } else if (fields->modrm_rm == 4 &&
                   fields->modrm_mod == 0 &&
                   (fields->sib & 7) == 5) {
            /* Segment-relative absolute disp32, e.g. fs:[disp32]. */
        } else {
            if (!ft_base_from_modrm_sib(fields, &base)) {
                return false;
            }
            FT_LA_ADD_D_EMIT(out, tmp1, tmp1, ft_gpr(base));
        }

        if (fields->disp) {
            if (ft_fits_simm12(fields->disp)) {
                FT_LA_ADDI_D_EMIT(out, tmp1, tmp1,
                                          fields->disp);
            } else {
                if (!ft_emit_li32(out, tmp0, (uint32_t)fields->disp)) {
                    return false;
                }
                FT_LA_ADD_D_EMIT(out, tmp1, tmp1, tmp0);
            }
        }
        *addr_reg = tmp1;
        return true;
    }

    if (fields->modrm_rm == 4 && ft_sib_has_index(fields)) {
        int index = ft_sib_index_index(fields);
        int scale = ft_sib_scale(fields);
        bool no_base = fields->modrm_mod == 0 &&
                       (fields->sib & 7) == 5;

        if (index >= GPR_NUM) {
            return false;
        }
        if (scale) {
            if (no_base) {
                FT_LA_SLLI_D_EMIT(out, tmp0, ft_gpr(index), scale);
            } else {
                if (!ft_base_from_modrm_sib_with_index(fields, &base)) {
                    return false;
                }
                FT_LA_ALSL_D_EMIT(out, tmp0, ft_gpr(index),
                                 ft_gpr(base), scale - 1);
            }
        } else {
            if (no_base) {
                FT_LA_OR_EMIT(out, tmp0, ft_gpr(index), la_zero);
            } else {
                if (!ft_base_from_modrm_sib_with_index(fields, &base)) {
                    return false;
                }
                FT_LA_ADD_D_EMIT(out, tmp0, ft_gpr(base),
                                    ft_gpr(index));
            }
        }
        if (fields->disp) {
            if (ft_fits_simm12(fields->disp)) {
                FT_LA_ADDI_D_EMIT(out, tmp0, tmp0,
                                          fields->disp);
            } else {
                if (!ft_emit_li32(out, tmp1, (uint32_t)fields->disp)) {
                    return false;
                }
                FT_LA_ADD_D_EMIT(out, tmp0, tmp0, tmp1);
            }
        }
        *addr_reg = tmp0;
        return true;
    }

    if (fields->modrm_rm == 4 &&
        fields->modrm_mod == 0 &&
        (fields->sib & 7) == 5) {
        if (!ft_emit_li32(out, tmp0, (uint32_t)fields->disp)) {
            return false;
        }
        *addr_reg = tmp0;
        return true;
    }

    if (!ft_base_from_modrm_sib(fields, &base)) {
        return false;
    }
    if (fields->disp && !ft_fits_simm12(fields->disp)) {
        if (!ft_emit_li32(out, tmp0, (uint32_t)fields->disp)) {
            return false;
        }
        FT_LA_ADD_D_EMIT(out, tmp0, ft_gpr(base), tmp0);
        *addr_reg = tmp0;
        return true;
    }
    *addr_reg = ft_gpr(base);
    return true;
}

static inline int ft_mem_access_offset(const FastTemplateFields *fields,
                                       int addr_reg)
{
    return (fields->segment >= 0 ||
            addr_reg == ft_addr_scratch0() ||
            addr_reg == ft_addr_scratch1()) ?
           0 : fields->disp;
}

static bool ft_emit_rip_or_mem_addr(uint32_t **out,
                                    const FastTemplateFields *fields,
                                    target_ulong pc, int *addr_reg)
{
    if (!fields->addr32 && fields->segment < 0 &&
        fields->modrm_mod == 0 &&
        fields->modrm_rm == 5) {
        target_ulong target = pc + fields->size + fields->disp;
        const int tmp0 = ft_addr_scratch0();

        if (!ft_emit_guest_addr(out, tmp0, target)) {
            return false;
        }
        *addr_reg = tmp0;
        return true;
    }
    return ft_emit_mem_addr(out, fields, addr_reg);
}

static bool ft_supported_base_disp_addr(int rex, int modrm, int sib)
{
    int mod = ft_modrm_mod(modrm);
    int rex_x = rex >= 0 ? ((rex >> 1) & 1) : 0;

    if (mod == 3 || (mod == 0 && (modrm & 7) == 5)) {
        return false;
    }
    if ((modrm & 7) == 4) {
        if (((sib >> 3) & 7) != 4 || rex_x) {
            return false;
        }
        return mod != 0 || (sib & 7) != 5;
    }
    return true;
}

static bool ft_supported_base_disp_or_rip_addr(int rex, int modrm, int sib)
{
    int mod = ft_modrm_mod(modrm);

    if (mod == 0 && (modrm & 7) == 5) {
        return true;
    }
    return ft_supported_base_disp_addr(rex, modrm, sib);
}

static bool ft_supported_lea_addr(int rex, int modrm, int sib)
{
    int mod = ft_modrm_mod(modrm);

    if (mod == 3) {
        return false;
    }
    return true;
}

static bool ft_emit_rmw_addr(uint32_t **out, const FastTemplateFields *fields,
                             target_ulong pc, int *addr, int scratch)
{
    int offset;

    if (!ft_emit_rip_or_mem_addr(out, fields, pc, addr)) {
        return false;
    }

    offset = ft_mem_access_offset(fields, *addr);
    if (offset) {
        if (!ft_fits_simm12(offset)) {
            return false;
        }
        FT_LA_ADDI_D_EMIT(out, scratch, *addr, offset);
        *addr = scratch;
    }
    return true;
}

static void ft_preserve_cmpxchg_addr(uint32_t **out, int *addr)
{
    if (*addr == la_t1 || *addr == la_t2 || *addr == la_t3) {
        FT_LA_OR_EMIT(out, la_t4, *addr, la_zero);
        *addr = la_t4;
    }
}
