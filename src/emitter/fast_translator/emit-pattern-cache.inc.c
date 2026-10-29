/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Cache address-independent ALU emitter output without duplicating semantics. */

#define FT_INST_PATTERN_TABLE_BITS 10
#define FT_INST_PATTERN_TABLE_SIZE (1u << FT_INST_PATTERN_TABLE_BITS)
#define FT_INST_PATTERN_MAX_WORDS 16

typedef struct FtInstPatternTable {
    uint64_t keys[FT_INST_PATTERN_TABLE_SIZE];
    uint64_t extra_keys[FT_INST_PATTERN_TABLE_SIZE];
    uint8_t words[FT_INST_PATTERN_TABLE_SIZE];
    uint32_t code[FT_INST_PATTERN_TABLE_SIZE][FT_INST_PATTERN_MAX_WORDS];
} FtInstPatternTable;

static __thread FtInstPatternTable ft_inst_pattern_table;

#ifdef QUICKTRANS_INST_PATTERN_STATS
typedef struct FtInstPatternStats {
    uint64_t candidates;
    uint64_t hits;
    uint64_t fills;
    uint64_t replacements;
    uint64_t too_long;
} FtInstPatternStats;

static __thread FtInstPatternStats ft_inst_pattern_stats;
static bool ft_inst_pattern_stats_registered;

static void ft_inst_pattern_stats_dump(void)
{
    FtInstPatternStats *stats = &ft_inst_pattern_stats;

    fprintf(stderr,
            "[FT-INST-PATTERN] candidates=%" PRIu64
            " hits=%" PRIu64 " hit_rate=%.4f fills=%" PRIu64
            " replacements=%" PRIu64 " too_long=%" PRIu64 "\n",
            stats->candidates, stats->hits,
            stats->candidates ?
                (double)stats->hits / stats->candidates : 0.0,
            stats->fills, stats->replacements, stats->too_long);
}

static inline void ft_inst_pattern_stats_start(void)
{
    if (!ft_inst_pattern_stats_registered) {
        atexit(ft_inst_pattern_stats_dump);
        ft_inst_pattern_stats_registered = true;
    }
    ft_inst_pattern_stats.candidates++;
    if (ft_inst_pattern_stats.candidates % 5000 == 0) {
        ft_inst_pattern_stats_dump();
    }
}
#endif

static bool ft_inst_pattern_key(const FastTemplateFields *fields,
                                uint64_t *key, uint64_t *extra_key)
{
    uint64_t meta;

    if (fields->alu_op == FT_ALU_NONE || fields->segment >= 0) {
        return false;
    }
    if (fields->alu_form != FT_ALU_FORM_ACC_IMM &&
        fields->modrm_mod != 3) {
        return false;
    }

    meta = (uint64_t)fields->alu_op |
           ((uint64_t)fields->alu_form << 4) |
           ((uint64_t)fields->alu_width << 7) |
           ((uint64_t)(uint8_t)fields->modrm << 14) |
           ((uint64_t)(uint8_t)fields->rex << 22) |
           ((uint64_t)fields->skip_flags << 30);
    *key = meta | ((uint64_t)(uint32_t)fields->imm << 32);
    *extra_key = (uint64_t)(uint8_t)fields->direct_cmp_lhs_gpr |
        ((uint64_t)(uint8_t)fields->direct_cmp_rhs_gpr << 8) |
        ((uint64_t)fields->direct_cmp_width << 16) |
        ((uint64_t)fields->direct_branch_kind << 24) |
        ((uint64_t)(uint8_t)fields->direct_bit_index_gpr << 32) |
        ((uint64_t)(uint8_t)fields->direct_bit_index_imm << 40) |
        ((uint64_t)fields->instptn_div_kind << 48) |
        ((uint64_t)fields->instptn_skip << 56);
    return true;
}

static unsigned ft_inst_pattern_index(uint64_t key, uint64_t extra_key)
{
    key ^= extra_key * UINT64_C(0xd6e8feb86659fd93);
    key ^= key >> 32;
    key *= UINT64_C(0x9e3779b97f4a7c15);
    return key >> (64 - FT_INST_PATTERN_TABLE_BITS);
}

static inline void ft_inst_pattern_copy(uint32_t *dst, const uint32_t *src,
                                        unsigned words)
{
    switch (words) {
    case 16: dst[15] = src[15]; /* fall through */
    case 15: dst[14] = src[14]; /* fall through */
    case 14: dst[13] = src[13]; /* fall through */
    case 13: dst[12] = src[12]; /* fall through */
    case 12: dst[11] = src[11]; /* fall through */
    case 11: dst[10] = src[10]; /* fall through */
    case 10: dst[9] = src[9]; /* fall through */
    case 9: dst[8] = src[8]; /* fall through */
    case 8: dst[7] = src[7]; /* fall through */
    case 7: dst[6] = src[6]; /* fall through */
    case 6: dst[5] = src[5]; /* fall through */
    case 5: dst[4] = src[4]; /* fall through */
    case 4: dst[3] = src[3]; /* fall through */
    case 3: dst[2] = src[2]; /* fall through */
    case 2: dst[1] = src[1]; /* fall through */
    case 1: dst[0] = src[0];
    default: break;
    }
}

static int emit_template_fields(const FastTemplateFields *fields,
                                TranslationBlock *tb, target_ulong pc,
                                uint32_t *code)
{
    uint64_t key;
    uint64_t extra_key;
    unsigned index;
    int words;

    if (!ft_inst_pattern_key(fields, &key, &extra_key)) {
        return emit_template_fields_uncached(fields, tb, pc, code);
    }

    index = ft_inst_pattern_index(key, extra_key);
#ifdef QUICKTRANS_INST_PATTERN_STATS
    ft_inst_pattern_stats_start();
#endif
    if (ft_inst_pattern_table.keys[index] == key &&
        ft_inst_pattern_table.extra_keys[index] == extra_key) {
#ifdef QUICKTRANS_INST_PATTERN_STATS
        ft_inst_pattern_stats.hits++;
#endif
        words = ft_inst_pattern_table.words[index];
        ft_inst_pattern_copy(code, ft_inst_pattern_table.code[index], words);
        return words;
    }

    words = emit_template_fields_uncached(fields, tb, pc, code);
    if (words > 0 && words <= FT_INST_PATTERN_MAX_WORDS) {
#ifdef QUICKTRANS_INST_PATTERN_STATS
        if (ft_inst_pattern_table.keys[index]) {
            ft_inst_pattern_stats.replacements++;
        } else {
            ft_inst_pattern_stats.fills++;
        }
#endif
        ft_inst_pattern_table.keys[index] = key;
        ft_inst_pattern_table.extra_keys[index] = extra_key;
        ft_inst_pattern_table.words[index] = words;
        ft_inst_pattern_copy(ft_inst_pattern_table.code[index], code, words);
#ifdef QUICKTRANS_INST_PATTERN_STATS
    } else if (words > FT_INST_PATTERN_MAX_WORDS) {
        ft_inst_pattern_stats.too_long++;
#endif
    }
    return words;
}
