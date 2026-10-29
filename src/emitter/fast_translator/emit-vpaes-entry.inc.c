/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * LATU integration of the legacy vector AES sequences in emit-vpaes.inc.c.
 */
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    !defined(CONFIG_LATX_AVX_OPT)
#include "emit-vpaes.inc.c"

static void ft_vpaes_load_tables(uint32_t **out, const void *table,
                                  int start, int count, bool lasx)
{
    ft_emit_li64(out, la_t0, (uintptr_t)table + start * (lasx ? 32 : 16));
    for (int i = 0; i < count; ++i) {
        if (lasx) {
            FT_LA_XVLD_EMIT(out, i, la_t0, i * 32);
        } else {
            FT_LA_VLD_EMIT(out, i, la_t0, i * 16);
        }
    }
}

static void ft_vpaes_round_lsx(uint32_t **out, int dst, int key,
                                      bool enc, bool last)
{
    const void *table = enc ? ft_vpaes_enc_tables :
                              ft_vpaes_dec_tables;

    /* f0..f7 hold tables, f8..f13 are scratch, f14 holds a copied key. */
    ft_vpaes_load_tables(out, table, 0, 7, false);
    if (enc) {
        ft_vpaes_subbytes_lsx(out, dst, 13, 8, 9, 10, 11);
        FT_LA_VSHUF_B_EMIT(out, dst, dst, dst, 6);
        if (!last) {
            ft_vpaes_load_tables(out, table, 7, 2, false);
            ft_vpaes_mixcolumns_xtime_lsx(out, dst, 0, 1, 8, 9, 10, 11);
        }
    } else {
        FT_LA_VSHUF_B_EMIT(out, dst, dst, dst, 6);
        ft_vpaes_invsubbytes_lsx(out, dst, 13, 8, 9, 10, 11, 12);
        if (!last) {
            ft_vpaes_load_tables(out, table, 7, 2, false);
            ft_vpaes_invmixcolumns_xtime_lsx(out, dst, 0, 1, 8, 9, 10, 11);
        }
    }
    FT_LA_VXOR_V_EMIT(out, dst, dst, key);
}

static void ft_vpaes_round_lasx(uint32_t **out, int dst, int key,
                                      bool enc, bool last)
{
    const void *table = enc ? ft_vpaes_enc_tables_xv :
                              ft_vpaes_dec_tables_xv;

    /* f0..f7 hold tables, f8..f13 are scratch, f14 holds a copied key. */
    ft_vpaes_load_tables(out, table, 0, 7, true);
    if (enc) {
        ft_vpaes_subbytes_lasx(out, dst, 13, 8, 9, 10, 11);
        FT_LA_XVSHUF_B_EMIT(out, dst, dst, dst, 6);
        if (!last) {
            ft_vpaes_load_tables(out, table, 7, 2, true);
            ft_vpaes_mixcolumns_xtime_lasx(out, dst, 0, 1, 8, 9, 10, 11);
        }
    } else {
        FT_LA_XVSHUF_B_EMIT(out, dst, dst, dst, 6);
        ft_vpaes_invsubbytes_lasx(out, dst, 13, 8, 9, 10, 11, 12);
        if (!last) {
            ft_vpaes_load_tables(out, table, 7, 2, true);
            ft_vpaes_invmixcolumns_xtime_lasx(out, dst, 0, 1, 8, 9, 10, 11);
        }
    }
    FT_LA_XVXOR_V_EMIT(out, dst, dst, key);
}

static bool ft_emit_latu_vpaes(uint32_t **out,
                                const FastTemplateFields *fields,
                                target_ulong pc, int dst_index)
{
    int dst = ft_xmm(dst_index);
    int src;
    int addr;
    bool round = fields->id != dt_X86_INS_AESIMC &&
                 fields->id != dt_X86_INS_AESKEYGENASSIST;
    bool lasx = round && option_enable_lasx;

    /* Complete the only guest-memory access before changing FP state. */
    if (fields->modrm_mod == 3) {
        int index = ft_modrm_rm_index(fields);
        if (index >= XMM_NUM) {
            return false;
        }
        src = ft_xmm(index);
    } else {
        if (!ft_emit_rip_or_mem_addr(out, fields, pc, &addr)) {
            return false;
        }
        src = 14;
        FT_LA_VLD_EMIT(out, src, addr, ft_mem_access_offset(fields, addr));
    }
    if (round && src == dst) {
        src = 14;
        if (lasx) {
            FT_LA_XVOR_V_EMIT(out, src, dst, dst);
        } else {
            FT_LA_VOR_V_EMIT(out, src, dst, dst);
        }
    } else if (!round && src != dst) {
        FT_LA_VOR_V_EMIT(out, dst, src, src);
    }

    /* Mode 0 saves TOP and disables LBT remapping; mode 1 keeps MMX
     * aliases; mode 2 has no live guest values in the low host FPRs. */
    ft_emit_save_fprs_to_env(out);
    if (round) {
        bool enc = fields->id == dt_X86_INS_AESENC ||
                   fields->id == dt_X86_INS_AESENCLAST;
        bool last = fields->id == dt_X86_INS_AESENCLAST ||
                    fields->id == dt_X86_INS_AESDECLAST;
        if (lasx) {
            ft_vpaes_round_lasx(out, dst, src, enc, last);
        } else {
            ft_vpaes_round_lsx(out, dst, src, enc, last);
        }
    } else if (fields->id == dt_X86_INS_AESIMC) {
        ft_vpaes_load_tables(out, ft_vpaes_dec_tables, 7, 2, false);
        ft_vpaes_invmixcolumns_xtime_lsx(out, dst, 0, 1, 8, 9, 10, 11);
    } else {
        ft_vpaes_load_tables(out, ft_vpaes_keygen_tables, 0, 8, false);
        ft_vpaes_keygenassist_lsx(out, dst, 8, 9, 10, 11, 12, 13,
                                 (uint8_t)fields->imm);
    }
    ft_emit_load_fprs_from_env(out);
    return true;
}
#endif
