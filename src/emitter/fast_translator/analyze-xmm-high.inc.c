/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Limited SHBR for ordinary LATU TBs: keep the scalar computation, but write
 * its destination directly when the other XMM lanes are not subsequently
 * read. This is not dead-result elimination or the old pretranslation pass.
 * No cross-TB state or machine-code scan; translation cost is unmeasured.
 * AVX builds are excluded: four 32-bit lanes do not model guest YMM highs.
 */
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    !defined(CONFIG_LATX_AVX_OPT)
_Static_assert(XMM_NUM > 0 && XMM_NUM <= 16, "XMM lane demand mask width");
#define FT_XMM_LANES_ALL (UINT64_MAX >> (64 - 4 * XMM_NUM))

/* Also checked by emission, so a stale/invalid field cannot extend the
 * direct-write optimization to memory, MIN/MAX or reciprocal operations.
 */
static bool ft_scalar_direct_dst_candidate(const FastTemplateFields *f)
{
    uint32_t opcode;
    int id;

    if (f->kind != FT_SIMD_SCALAR_BIN_XMM_XMMM || f->modrm_mod != 3 ||
        f->segment >= 0 || f->vex_v >= 0 || f->opcode0 != 0x0f ||
        f->prefix2 != 0 || f->alu_op != FT_ALU_NONE ||
        ft_modrm_reg_index(f) >= XMM_NUM ||
        ft_modrm_rm_index(f) >= XMM_NUM ||
        !ft_simd_scalar_bin_opcode_info(f->prefix0, f->opcode1, &opcode,
                                        &id) || id != f->id) {
        return false;
    }
    switch (id) {
    case dt_X86_INS_ADDSS: case dt_X86_INS_ADDSD:
    case dt_X86_INS_SUBSS: case dt_X86_INS_SUBSD:
    case dt_X86_INS_MULSS: case dt_X86_INS_MULSD:
    case dt_X86_INS_DIVSS: case dt_X86_INS_DIVSD:
    case dt_X86_INS_SQRTSS: case dt_X86_INS_SQRTSD:
        return true;
    default:
        return false;
    }
}

static void ft_analyze_xmm_high_step(FastTemplateFields *f,
                                    const FastTemplateRuntimeInfo *meta,
                                    uint64_t *need_lanes, bool enabled)
{
    uint64_t dst_mask, demanded;
    unsigned lanes;
    int dst, src;

    f->scalar_direct_dst = false;
    if (!enabled || !meta || meta->terminal_exit || f->modrm_mod != 3 ||
        f->segment >= 0 || f->vex_v >= 0 || f->opcode0 != 0x0f ||
        f->prefix0 == dt_X86_PREFIX_LOCK || f->instptn_skip ||
        f->instptn_div_kind || f->direct_cmp_width ||
        f->direct_cmp_lhs_gpr >= 0 || f->direct_cmp_rhs_gpr >= 0 ||
        f->direct_bit_index_gpr >= 0 || f->direct_bit_index_imm >= 0 ||
        f->direct_branch_kind != FT_DIRECT_BRANCH_NONE ||
        f->direct_float_result || f->direct_float_xx) {
        *need_lanes = FT_XMM_LANES_ALL;
        return;
    }

    dst = ft_modrm_reg_index(f);
    src = ft_modrm_rm_index(f);
    if (ft_scalar_direct_dst_candidate(f)) {
        lanes = f->prefix0 == dt_X86_PREFIX_REPNE ? 0x3 : 0x1;
        dst_mask = (UINT64_C(0xf) & ~lanes) << (4 * dst);
        f->scalar_direct_dst = !(*need_lanes & dst_mask);
        /* Even a later FP trap can expose all guest vector registers.
         * Require complete inputs before this instruction, irrespective of
         * whether its own scalar output can be written directly.
         */
        *need_lanes = FT_XMM_LANES_ALL;
        return;
    }

    lanes = 0xf;
    switch (f->kind) {
    case FT_MOVSD_M64_XMM:
        dst = ft_modrm_rm_index(f);
        src = ft_modrm_reg_index(f);
        /* fall through */
    case FT_MOVSD_XMM_M64:
        if (f->prefix2 != 0 ||
            (f->prefix0 != dt_X86_PREFIX_REP &&
             f->prefix0 != dt_X86_PREFIX_REPNE)) {
            goto barrier;
        }
        lanes = f->prefix0 == dt_X86_PREFIX_REPNE ? 0x3 : 0x1;
        break;
    case FT_MOV128_XMMM_XMM:
        dst = ft_modrm_rm_index(f);
        src = ft_modrm_reg_index(f);
        /* fall through */
    case FT_MOV128_XMM_XMMM:
        break;
    case FT_PXOR_XMM_XMMM:
        if (dst >= XMM_NUM || src != dst) {
            goto barrier;
        }
        *need_lanes &= ~(UINT64_C(0xf) << (4 * dst));
        return;
    case FT_MOVD_R32_XMM:
        /* ModRM.reg is the XMM source; ModRM.rm is the GPR destination.
         * The register-only extraction reads low 32 bits, with no helper.
         */
        if (dst >= XMM_NUM || src >= GPR_NUM || ft_rex_w(f)) {
            goto barrier;
        }
        *need_lanes |= UINT64_C(1) << (4 * dst);
        return;
    default:
        goto barrier;
    }

    if (dst >= XMM_NUM || src >= XMM_NUM) {
        goto barrier;
    }
    dst_mask = (uint64_t)lanes << (4 * dst);
    demanded = (*need_lanes & dst_mask) >> (4 * dst);
    /* Kill first, then add source demand: also correct for dst == src.
     * Scalar moves leave the other destination lanes demanded unchanged.
     */
    *need_lanes &= ~dst_mask;
    *need_lanes |= demanded << (4 * src);
    return;

barrier:
    *need_lanes = FT_XMM_LANES_ALL;
}
#endif /* LATU user mode, no guest AVX */
