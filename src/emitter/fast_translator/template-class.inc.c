/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* Fast template class predicates used by primary translation. */

static bool ft_template_is_helper(FastTemplateKind kind);
static bool ft_template_primary_helper_allowed(FastTemplateKind kind);
static bool ft_template_uses_x87_top(FastTemplateKind kind);
static bool ft_template_uses_mmx(const FastTemplateFields *fields);
static bool ft_mmx_entry_required(bool mmx_active);
static bool ft_template_alu_info(FastTemplateKind kind, FastAluOp *op,
                                 FastAluForm *form, uint8_t *width);
static bool ft_fill_generic_alu_info(FastTemplateFields *fields);
static bool ft_primary_trace_enabled(void);
static inline bool ft_fits_simm12(int64_t value);
static bool ft_emit_li32(uint32_t **code, int rd, uint32_t value);
static bool ft_emit_guest_addr(uint32_t **code, int rd, uint64_t value);
typedef int (*FastTemplateEmitFn)(const FastTemplateFields *fields,
                                  TranslationBlock *tb, target_ulong pc,
                                  uint32_t *code);

typedef enum FastBranchKind {
    FT_BRANCH_B,
    FT_BRANCH_BEQ,
    FT_BRANCH_BNE,
    FT_BRANCH_BEQZ,
    FT_BRANCH_BNEZ,
    FT_BRANCH_BLT,
    FT_BRANCH_BGE,
    FT_BRANCH_BLTU,
    FT_BRANCH_BGEU,
} FastBranchKind;

typedef struct FastBranchLabel {
    uint32_t *code;
} FastBranchLabel;

typedef struct FastBranchFixup {
    uint32_t *branch;
    FastBranchKind kind;
    int rj;
    int rd;
    FastBranchLabel *label;
} FastBranchFixup;

static int64_t ft_branch_sign_extend(uint32_t value, int bits)
{
    return ((int64_t)value << (64 - bits)) >> (64 - bits);
}

static void ft_emit_branch_placeholder(uint32_t **out, FastBranchFixup *fixup,
                                       FastBranchKind kind, int rj, int rd,
                                       FastBranchLabel *label)
{
    fixup->branch = *out;
    fixup->kind = kind;
    fixup->rj = rj;
    fixup->rd = rd;
    fixup->label = label;

    switch (kind) {
    case FT_BRANCH_B:
        FT_LA_B_EMIT(out, 0);
        break;
    case FT_BRANCH_BEQ:
        FT_LA_BEQ_EMIT(out, rj, rd, 0);
        break;
    case FT_BRANCH_BNE:
        FT_LA_BNE_EMIT(out, rj, rd, 0);
        break;
    case FT_BRANCH_BEQZ:
        FT_LA_BEQZ_EMIT(out, rj, 0);
        break;
    case FT_BRANCH_BNEZ:
        FT_LA_BNEZ_EMIT(out, rj, 0);
        break;
    case FT_BRANCH_BLT:
        FT_LA_BLT_EMIT(out, rj, rd, 0);
        break;
    case FT_BRANCH_BGE:
        FT_LA_BGE_EMIT(out, rj, rd, 0);
        break;
    case FT_BRANCH_BLTU:
        FT_LA_BLTU_EMIT(out, rj, rd, 0);
        break;
    case FT_BRANCH_BGEU:
        FT_LA_BGEU_EMIT(out, rj, rd, 0);
        break;
    }
}

static void ft_bind_branch_label(FastBranchLabel *label, uint32_t *code)
{
    label->code = code;
}

static ptrdiff_t ft_branch_label_offset(const FastBranchFixup *fixup)
{
    /* LoongArch conditional and unconditional branches use their own PC. */
    return fixup->label->code - fixup->branch;
}

static ptrdiff_t ft_decode_branch_offset(FastBranchKind kind, uint32_t insn)
{
    uint32_t imm;

    switch (kind) {
    case FT_BRANCH_B:
        imm = ((insn >> 10) & 0xffffu) | ((insn & 0x3ffu) << 16);
        return ft_branch_sign_extend(imm, 26);
    case FT_BRANCH_BEQZ:
    case FT_BRANCH_BNEZ:
        imm = ((insn >> 10) & 0xffffu) | ((insn & 0x1fu) << 16);
        return ft_branch_sign_extend(imm, 21);
    default:
        return ft_branch_sign_extend(insn >> 10, 16);
    }
}

static void ft_resolve_branch_fixup(const FastBranchFixup *fixup)
{
    ptrdiff_t offset;

    g_assert(fixup->label->code != NULL);
    offset = ft_branch_label_offset(fixup);

    switch (fixup->kind) {
    case FT_BRANCH_B:
        *fixup->branch = FT_LA_B(offset);
        break;
    case FT_BRANCH_BEQ:
        *fixup->branch = FT_LA_BEQ(fixup->rj, fixup->rd, offset);
        break;
    case FT_BRANCH_BNE:
        *fixup->branch = FT_LA_BNE(fixup->rj, fixup->rd, offset);
        break;
    case FT_BRANCH_BEQZ:
        *fixup->branch = FT_LA_BEQZ(fixup->rj, offset);
        break;
    case FT_BRANCH_BNEZ:
        *fixup->branch = FT_LA_BNEZ(fixup->rj, offset);
        break;
    case FT_BRANCH_BLT:
        *fixup->branch = FT_LA_BLT(fixup->rj, fixup->rd, offset);
        break;
    case FT_BRANCH_BGE:
        *fixup->branch = FT_LA_BGE(fixup->rj, fixup->rd, offset);
        break;
    case FT_BRANCH_BLTU:
        *fixup->branch = FT_LA_BLTU(fixup->rj, fixup->rd, offset);
        break;
    case FT_BRANCH_BGEU:
        *fixup->branch = FT_LA_BGEU(fixup->rj, fixup->rd, offset);
        break;
    }

    g_assert(fixup->branch +
             ft_decode_branch_offset(fixup->kind, *fixup->branch) ==
             fixup->label->code);
}

static void ft_patch_branch_to(uint32_t *branch, FastBranchKind kind,
                               int rj, int rd, uint32_t *target)
{
    FastBranchLabel label = { 0 };
    FastBranchFixup fixup = {
        .branch = branch,
        .kind = kind,
        .rj = rj,
        .rd = rd,
        .label = &label,
    };

    ft_bind_branch_label(&label, target);
    ft_resolve_branch_fixup(&fixup);
}

static int ft_emit_x87_top_load(uint32_t **out);
static int ft_emit_x87_top_save(uint32_t **out);
static bool ft_emit_default_helper_prologue(uint32_t **out,
                                            bool helper_uses_fprs);
static void ft_emit_helper_prologue(uint32_t **out);
static void ft_emit_helper_epilogue(uint32_t **out);
#ifndef QUICKTRANS_LATU
static bool ft_emit_lats_nofp_helper(uint32_t **out, void *func);
static bool ft_emit_nofp_helper_prologue(uint32_t **out);
static void ft_emit_nofp_helper_epilogue(uint32_t **out,
                                         bool static_context);
static void ft_emit_default_helper_call(uint32_t **out, void *func,
                                        uint32_t pointer_args,
                                        bool static_context);
static bool ft_io_needs_permission_check(const TranslationBlock *tb);
static void ft_emit_io_port_arg(uint32_t **out,
                                const FastTemplateFields *fields);
static void ft_emit_io_check(uint32_t **out,
                             const FastTemplateFields *fields,
                             TranslationBlock *tb, int bytes,
                             bool static_context);
static void ft_emit_io_can_do(uint32_t **out, TranslationBlock *tb,
                              bool enabled);
static void ft_emit_io_breakpoint(uint32_t **out,
                                  const FastTemplateFields *fields,
                                  TranslationBlock *tb, target_ulong pc,
                                  int bytes, bool static_context);
static void *ft_io_in_helper(int bytes);
static void *ft_io_out_helper(int bytes);
#endif
static void ft_primary_debug_emit_exit_state(uint32_t **out, target_ulong pc,
                                             int condition_reg);
static void ft_emit_jump_epilogue(uint32_t **out, ADDR target,
                                  int scratch_reg);
static void ft_prepare_tu_env_dispatch_exit(TranslationBlock *tb,
                                            int succ_id);
static int ft_emit_direct_link_exit(TranslationBlock *tb, uint32_t **out,
                                    int succ_id, target_ulong target,
                                    int scratch_reg);

static bool ft_template_is_helper(FastTemplateKind kind)
{
    switch (kind) {
    case FT_LAR:
    case FT_LSL:
    case FT_VERR:
    case FT_VERW:
    case FT_HELPER_CPUID:
    case FT_IO:
    case FT_STRING_IO:
    case FT_HELPER_SYSCALL:
    case FT_HELPER_SYSENTER:
    case FT_HELPER_SYSEXIT:
    case FT_HELPER_SYSRET:
    case FT_RSM:
    case FT_HELPER_GPF:
    case FT_HELPER_INT:
    case FT_HELPER_INT3:
    case FT_HELPER_IRET:
    case FT_HELPER_IRETD:
    case FT_HELPER_IRETQ:
    case FT_HELPER_LJMP:
    case FT_HELPER_RETFQ:
    case FT_HELPER_UD0:
    case FT_HELPER_UD1:
    case FT_HELPER_UD2:
    case FT_HELPER_PCMPISTRI:
    case FT_HELPER_PCMPISTRM:
    case FT_HELPER_PCMPESTRI:
    case FT_HELPER_PCMPESTRM:
    case FT_HELPER_LDMXCSR:
    case FT_HELPER_FXSAVE:
    case FT_HELPER_FXRSTOR:
    case FT_HELPER_XSAVE:
    case FT_HELPER_XRSTOR:
    case FT_HELPER_XSAVEOPT:
    case FT_HELPER_FNSAVE:
    case FT_HELPER_FRSTOR:
    case FT_HELPER_FLDENV:
    case FT_HELPER_FNSTENV:
    case FT_POP_SEG64:
    case FT_POP_SEG16:
        return true;
    default:
        return false;
    }
}

static bool ft_template_primary_helper_allowed(FastTemplateKind kind)
{
    return kind == FT_LAR ||
           kind == FT_LSL ||
           kind == FT_VERR ||
           kind == FT_VERW ||
           kind == FT_HELPER_CPUID ||
           kind == FT_IO ||
           kind == FT_STRING_IO ||
           kind == FT_HELPER_PCMPISTRI ||
           kind == FT_HELPER_PCMPISTRM ||
           kind == FT_HELPER_PCMPESTRI ||
           kind == FT_HELPER_PCMPESTRM ||
           kind == FT_HELPER_LDMXCSR ||
           kind == FT_HELPER_FXSAVE ||
           kind == FT_HELPER_FXRSTOR ||
           kind == FT_HELPER_XSAVE ||
           kind == FT_HELPER_XRSTOR ||
           kind == FT_HELPER_XSAVEOPT ||
           kind == FT_HELPER_FNSAVE ||
           kind == FT_HELPER_FRSTOR ||
           kind == FT_HELPER_FLDENV ||
           kind == FT_HELPER_FNSTENV ||
           kind == FT_POP_SEG64 ||
           kind == FT_POP_SEG16 ||
           kind == FT_HELPER_SYSCALL ||
           kind == FT_HELPER_SYSENTER ||
           kind == FT_HELPER_SYSEXIT ||
           kind == FT_HELPER_SYSRET ||
           kind == FT_RSM ||
           kind == FT_HELPER_GPF ||
           kind == FT_HELPER_INT ||
           kind == FT_HELPER_INT3 ||
           kind == FT_HELPER_IRET ||
           kind == FT_HELPER_IRETD ||
           kind == FT_HELPER_IRETQ ||
           kind == FT_HELPER_LJMP ||
           kind == FT_HELPER_RETFQ ||
           kind == FT_HELPER_UD0 ||
           kind == FT_HELPER_UD1 ||
           kind == FT_HELPER_UD2;
}
