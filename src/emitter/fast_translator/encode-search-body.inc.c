/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 * SPDX-License-Identifier: MIT
 */

/* Included twice for LATU: compile out RSP merge work when disabled. */
static int FT_SPECIALIZED_NAME(TranslationBlock *tb,
                            const FastTemplateFields *fields_buf,
                            uint8_t *block,
                            bool check_highwater)
{
#ifdef QUICKTRANS_LATU
    uint8_t *highwater = tcg_ctx->code_gen_highwater;
#else
    uint8_t *highwater = tcg_splitwx_to_rx(tcg_ctx->code_gen_highwater);
#endif
    uint16_t *insn_end_off = tcg_ctx->gen_insn_end_off;
    uint8_t *p = block;

#ifndef QUICKTRANS_LATU
    /* PC deltas fit one byte, code deltas <=65532 fit three SLEB bytes.
     * Only the initial PC-relative address can need ten bytes. Check once,
     * before writing, rather than testing capacity for every record. */
    size_t search_bound = (size_t)tb->icount *
                         (TARGET_INSN_START_WORDS + 3) + 9;
    if (check_highwater &&
        ((uintptr_t)p > (uintptr_t)highwater ||
         search_bound > (uintptr_t)highwater - (uintptr_t)p)) {
        longjmp(ft_code_space_active->unwind, FT_CODE_REGION_FULL);
    }
#endif
    for (int i = 0, n = tb->icount; i < n; ++i) {
        if (i == 0) {
#ifdef QUICKTRANS_LATU
            *p++ = 0;
#else
            if (tb_cflags(tb) & CF_PCREL) {
                p = ft_encode_sleb128(p, fields_buf[0].address);
            } else {
                *p++ = 0;
            }
#endif
        } else {
            *p++ = fields_buf[i].address - fields_buf[i - 1].address;
        }
        for (int j = 1; j < TARGET_INSN_START_WORDS; ++j) {
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_RSP_SEARCH_ABI) && FT_WITH_RSP_MERGE
            int64_t delta = tcg_ctx->gen_insn_data[i][j] -
                (i ? tcg_ctx->gen_insn_data[i - 1][j] : 0);
            p = ft_encode_sleb128(p, delta);
#else
            *p++ = 0;
#endif
        }

        {
            int64_t end_delta = insn_end_off[i] -
                                (i == 0 ? 0 : insn_end_off[i - 1]);

            if (end_delta >= 0 && end_delta < 64) {
                *p++ = end_delta;
            } else {
                p = ft_encode_sleb128(p, end_delta);
            }
        }
#ifdef QUICKTRANS_LATU
        if (check_highwater && unlikely(p > highwater)) {
            return -1;
        }
#endif
    }

    return p - block;
}

