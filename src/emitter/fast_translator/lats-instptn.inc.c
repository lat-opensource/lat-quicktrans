/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 * SPDX-License-Identifier: MIT
 */

static bool ft_lats_same_reg(const FastTemplateFields *f)
{
    return (f->alu_form == FT_ALU_FORM_RM_R || f->alu_form == FT_ALU_FORM_R_RM) &&
           f->modrm_mod == 3 && f->modrm_rm_index == f->modrm_reg_index;
}

/* These are the same producer/condition pairs accepted by the outer and
 * inner legacy scanners. Signed TEST conditions also require TEST r,r. */
static bool ft_lats_cmp_cc(int cc)
{
    return cc != FT_CC_P && cc != FT_CC_NP && cc != FT_CC_O && cc != FT_CC_NO;
}

static bool ft_lats_logic_cc(int cc)
{
    return cc != FT_CC_P && cc != FT_CC_NP && cc != FT_CC_L && cc != FT_CC_GE;
}

static bool ft_lats_test_cc(const FastTemplateFields *head, int cc)
{
    if (cc == FT_CC_S || cc == FT_CC_NS || cc == FT_CC_LE || cc == FT_CC_G)
        return ft_lats_same_reg(head);
    return ft_lats_logic_cc(cc);
}

static uint64_t ft_lats_jcc_option(const FastTemplateFields *head, int cc, bool gap)
{
    bool zero = cc == FT_CC_E || cc == FT_CC_NE;
    bool sign = cc == FT_CC_S || cc == FT_CC_NS;

    if (head->prefix0 == dt_X86_PREFIX_LOCK &&
        (lsenv->tr_data->sys.cflags & CF_PARALLEL))
        return 0;
    switch (head->alu_op) {
    case FT_ALU_CMP:
        return ft_lats_cmp_cc(cc) ? (gap ? FT_INSTPTN_CMP_XX_JCC : FT_INSTPTN_CMP_JCC) : 0;
    case FT_ALU_TEST:
        return ft_lats_test_cc(head, cc) ? (gap ? FT_INSTPTN_TEST_XX_JCC : FT_INSTPTN_TEST_JCC) : 0;
    case FT_ALU_AND:
        return gap ? (zero ? FT_INSTPTN_AND_XX_JCC : 0) :
                     (ft_lats_logic_cc(cc) ? FT_INSTPTN_AND_JCC : 0);
    case FT_ALU_OR:
        return ft_lats_logic_cc(cc) ? (gap ? FT_INSTPTN_OR_XX_JCC : FT_INSTPTN_OR_JCC) : 0;
    case FT_ALU_XOR:
        return ft_lats_logic_cc(cc) ? (gap ? FT_INSTPTN_XOR_XX_JCC : FT_INSTPTN_XOR_JCC) : 0;
    case FT_ALU_ADD:
        return !gap && (zero || cc == FT_CC_NS) ? FT_INSTPTN_ADD_JCC : 0;
    case FT_ALU_SUB:
        if (gap)
            return sign && (head->alu_form == FT_ALU_FORM_ACC_IMM || head->modrm_mod == 3) ?
                   FT_INSTPTN_SUB_XX_JCC : 0;
        return zero || sign ? FT_INSTPTN_SUB_JCC : 0;
    default: break;
    }
    if (head->id == dt_X86_INS_BT && (cc == FT_CC_B || cc == FT_CC_AE))
        return gap ? FT_INSTPTN_BT_XX_JCC : FT_INSTPTN_BT_JCC;
    if (head->id == dt_X86_INS_DEC && !gap && zero && head->modrm_mod == 3 &&
        head->prefix0 != dt_X86_PREFIX_LOCK) return FT_INSTPTN_DEC_JCC;
    if ((head->kind == FT_SHIFT_RM_ONE || head->kind == FT_SHIFT_RM_IMM8) &&
        (head->kind == FT_SHIFT_RM_ONE || !ft_rotate_imm_has_zero_effective_count(head))) {
        if (head->modrm_reg == 5)
            return gap ? (cc == FT_CC_E ? FT_INSTPTN_SHR_XX_JCC : 0) :
                         (zero ? FT_INSTPTN_SHR_JCC : 0);
        if (head->modrm_reg == 7 && !gap && (zero || sign)) return FT_INSTPTN_SAR_JCC;
    }
    return 0;
}

static void ft_lats_pattern_inputs(FastTemplateFields *head, FastTemplateFields *tail)
{
    if (head->alu_op == FT_ALU_CMP || head->alu_op == FT_ALU_TEST) {
        bool cmp = head->alu_op == FT_ALU_CMP;
        head->pattern_inputs = cmp ? FT_PATTERN_SAVE_CMP : FT_PATTERN_SAVE_TEST;
        tail->pattern_inputs = cmp ? FT_PATTERN_CMP : FT_PATTERN_TEST;
        tail->direct_cmp_width = head->alu_width;
        if (tail == head + 1 && tail->kind == FT_JCC_REL) {
            head->pattern_inputs = FT_PATTERN_SAVE_REGS;
            tail->pattern_inputs = cmp ? FT_PATTERN_CMP_REGS : FT_PATTERN_TEST_REGS;
        }
    } else if (head->alu_op != FT_ALU_NONE && head->prefix0 != dt_X86_PREFIX_LOCK) {
        head->pattern_inputs = FT_PATTERN_SAVE_RESULT;
        tail->pattern_inputs = FT_PATTERN_RESULT;
        tail->direct_cmp_width = head->alu_width;
    } else {
        tail->pattern_inputs = FT_PATTERN_FLAGS;
    }
}

static void ft_lats_analyze_jcc(FastTemplateFields *fields,
                                const FastTemplateRuntimeInfo **meta, int count)
{
    FastTemplateFields *tail = &fields[count - 1];
    int i = count - 2;

    while (i >= 0 && ft_lats_pattern_gap(&fields[i])) {
        i--;
    }
    if (i < 0) return;
    FastTemplateFields *head = &fields[i];
    bool gap = i != count - 2;
    uint64_t bit = ft_lats_jcc_option(head, ft_pattern_cc(tail), gap);
    if (!bit || !ft_instptn_enabled(bit)) return;

    ft_analyze_direct_jcc_pair(head, tail, gap);
    if (tail->direct_cmp_lhs_gpr >= 0) {
        for (int j = i + 1; j < count - 1; j++) {
            if (!ft_direct_gap_is_safe(&fields[j], meta[j], tail->direct_cmp_lhs_gpr,
                                       tail->direct_cmp_rhs_gpr) ||
                (tail->direct_bit_index_gpr >= 0 &&
                 ft_gap_writes_gpr(&fields[j], tail->direct_bit_index_gpr))) {
                /* The legacy combination still applies. Capture the input
                 * at its original PC rather than rereading a modified GPR. */
                tail->direct_cmp_lhs_gpr = -1;
                tail->direct_cmp_rhs_gpr = -1;
                tail->direct_bit_index_gpr = -1;
                tail->direct_bit_index_imm = -1;
                tail->direct_branch_kind = FT_DIRECT_BRANCH_NONE;
                break;
            }
        }
    }
    if (tail->direct_cmp_lhs_gpr < 0) ft_lats_pattern_inputs(head, tail);
}

static void ft_lats_analyze_conditions(FastTemplateFields *fields, int count)
{
    for (int i = 0; i + 1 < count; i++) {
        FastTemplateFields *head = &fields[i], *next = &fields[i + 1];
        bool cmp = head->alu_op == FT_ALU_CMP;
        if (!cmp && head->alu_op != FT_ALU_TEST) continue;
        if (cmp && next->alu_op == FT_ALU_SBB && ft_lats_same_reg(next)) {
            if (next->direct_cmp_lhs_gpr < 0 && ft_instptn_enabled(FT_INSTPTN_CMP_SBB))
                ft_lats_pattern_inputs(head, next);
            continue;
        }
        if (!ft_instptn_enabled(cmp ? FT_INSTPTN_CMP_XXCC_CON : FT_INSTPTN_TEST_XXCC_CON))
            continue;
        int lhs = -1, rhs = -1;
        bool rematerialize = ft_direct_alu_reg_operands(head, &lhs, &rhs) &&
                             (cmp || lhs == rhs);
        if (!cmp) rhs = -1;
        for (int j = i + 1; j < count && j <= i + 4; j++) {
            FastTemplateFields *consumer = &fields[j];
            if (!ft_is_xxcc_consumer(consumer)) break;
            int cc = ft_pattern_cc(consumer);
            if (cmp ? (!ft_lats_cmp_cc(cc) || cc == FT_CC_S || cc == FT_CC_NS) :
                      !ft_lats_test_cc(head, cc)) break;
            FastDirectBranchKind kind;
            if (rematerialize && consumer->modrm_mod == 3 &&
                ft_direct_xxcc_kind(consumer, &kind)) {
                consumer->direct_cmp_lhs_gpr = lhs;
                consumer->direct_cmp_rhs_gpr = rhs;
                consumer->direct_cmp_width = head->alu_width;
                consumer->direct_branch_kind = kind;
                rematerialize = ft_xxcc_gap_is_safe(consumer, lhs, rhs);
            } else {
                ft_lats_pattern_inputs(head, consumer);
                rematerialize = false;
            }
        }
    }
}
