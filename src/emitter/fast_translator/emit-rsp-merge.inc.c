/* SPDX-License-Identifier: MIT */
/* Fold simple stack operations across selected helper-free templates. Every memory access remains
 * in order; a barrier commits the accumulated RSP before the next instruction.
 * The host search record carries the pre-instruction correction on faults.
 */
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_RSP_SEARCH_ABI)
static bool ft_rsp_merge_memory(const FastTemplateFields *f)
{
    switch (f->kind) {
    case FT_PUSH_RM64: case FT_POP_RM64:
    case FT_PUSH_RM16: case FT_POP_RM16:
        return f->modrm_mod != 3 && f->alu_width != 32;
    default: return false;
    }
}

/* The old pass absorbs ADDI after any required flag calculation. ADD/SUB
 * require dead flags; INC/DEC also have a checked live-flag prefix. */
static int ft_rsp_merge_adjustment(const FastTemplateFields *f)
{
    int64_t step;
    int base;
    if (f->instptn_skip || f->instptn_div_kind || f->direct_cmp_width ||
        f->direct_cmp_lhs_gpr >= 0 || f->direct_cmp_rhs_gpr >= 0 ||
        f->direct_branch_kind != FT_DIRECT_BRANCH_NONE ||
        f->prefix0 == dt_X86_PREFIX_LOCK) {
        return 0;
    }
    if (f->kind == FT_LEA_R64_M && !f->addr32 &&
        f->modrm_mod != 3 && ft_modrm_reg_index(f) == rsp_index &&
        ft_base_from_modrm_sib(f, &base) && base == rsp_index) {
        return ft_fits_simm12(f->disp) ? f->disp : 0;
    }
    if (f->modrm_mod != 3 || ft_modrm_rm_index(f) != rsp_index) {
        return 0;
    }
    if (f->kind == FT_INC_RM64 || f->kind == FT_DEC_RM64) {
        return f->kind == FT_INC_RM64 ? 1 : -1;
    }
    if (!f->skip_flags || f->alu_width != 64 ||
        f->alu_form != FT_ALU_FORM_RM_IMM ||
        (f->alu_op != FT_ALU_ADD && f->alu_op != FT_ALU_SUB)) {
        return 0;
    }
    step = f->alu_op == FT_ALU_ADD ? f->imm : -(int64_t)f->imm;
    return ft_fits_simm12(step) ? step : 0;
}

/* Frame instructions commit their input RSP before starting. ENTER keeps
 * it intact through all accesses; LEAVE replaces it after its load succeeds.
 * Only their final, non-faulting ADDI may join the following stack run. */
static int ft_rsp_merge_frame_step(const FastTemplateFields *f)
{
    if (f->kind == FT_LEAVE && f->alu_width != 32) {
        return f->prefix2 == dt_X86_PREFIX_OPSIZE ? 2 : 8;
    }
    if (f->kind == FT_ENTER || f->kind == FT_ENTER16 ||
        f->kind == FT_ENTER_ZERO_LEVEL1) {
        unsigned level = ((unsigned)f->imm >> 16) & 31;
        int step = f->kind == FT_ENTER16 ? 2 : 8;
        int total = step * (level ? level + 1 : 1) + (f->imm & 0xffff);
        return ft_fits_simm12(-total) ? -total : 0;
    }
    return 0;
}

static int ft_rsp_merge_step(const FastTemplateFields *f)
{
    switch (f->kind) {
    case FT_LEAVE: case FT_ENTER: case FT_ENTER16: case FT_ENTER_ZERO_LEVEL1:
        return ft_rsp_merge_frame_step(f);
    case FT_PUSH_RM16: case FT_POP_RM16:
    case FT_PUSH_RM64: case FT_POP_RM64:
        if (!ft_rsp_merge_memory(f)) {
            return 0;
        }
        switch (f->kind) {
        case FT_PUSH_RM16: return -2;
        case FT_POP_RM16: return 2;
        case FT_POP_RM64: return 8;
        default: return -8;
        }
    case FT_PUSH_R64: case FT_POP_R64:
    case FT_PUSH_R16: case FT_POP_R16:
        if (f->reg < 0 || f->reg >= GPR_NUM) {
            return 0;
        }
        break;
    case FT_PUSHFQ: case FT_PUSH_SEG64: case FT_PUSH_SEG16:
    case FT_PUSH_IMM32: case FT_PUSH_IMM8: case FT_PUSH_IMM16:
        break;
    default:
        return ft_rsp_merge_adjustment(f);
    }
    if (f->alu_width == 32 ||
        ((f->kind == FT_POP_R64 || f->kind == FT_POP_R16) && f->reg == rsp_index)) {
        return 0;
    }
    switch (f->kind) {
    case FT_PUSH_SEG64: return -8;
    case FT_POP_R64: return 8;
    case FT_POP_R16: return 2;
    case FT_PUSH_R16: case FT_PUSH_IMM16: case FT_PUSH_SEG16: return -2;
    default: return f->alu_width == 16 ? -2 : -8;
    }
}

/* Only explicit, helper-free forms may cross a deferred stack adjustment.
 * Byte register encodings 4..7 without REX mean AH..BH, not SPL..DIL. */
static bool ft_rsp_merge_reg_ok(const FastTemplateFields *f, bool reg, bool byte)
{
    int index = reg ? ft_modrm_reg_index(f) : ft_modrm_rm_index(f);
    if (byte && (reg ? ft_modrm_reg_is_high8(f) : ft_modrm_rm_is_high8(f))) {
        index = reg ? ft_modrm_reg_high8_base_index(f) :
                      ft_modrm_rm_high8_base_index(f);
    }
    return index >= 0 && index < GPR_NUM && index != rsp_index;
}

static bool ft_rsp_merge_rm_ok(const FastTemplateFields *f, int pending,
                               bool byte, bool *adjust)
{
    int base;
    if (f->modrm_mod == 3) {
        return ft_rsp_merge_reg_ok(f, false, byte);
    }
    /* SIB cannot encode RSP as an index. Other bases, including RIP and
     * absolute addresses, do not observe the deferred stack pointer. */
    if (!ft_base_from_modrm_sib_with_index(f, &base) || base != rsp_index) {
        return true;
    }
    if (ft_sib_has_index(f) ||
        !ft_fits_simm12(f->disp) || !ft_fits_simm12(f->disp + pending)) {
        return false;
    }
    *adjust = true;
    return true;
}

/* Single-load forms overwrite the full pointer only after access succeeds.
 * The per-instruction search record retains the input delta on a load fault. */
static bool ft_rsp_merge_load_overwrite(const FastTemplateFields *f)
{
    if (f->modrm_mod == 3 || ft_modrm_reg_index(f) != rsp_index) {
        return false;
    }
    switch (f->kind) {
    case FT_MOV_R64_RM64: case FT_MOV_R32_RM32:
    case FT_MOVSX_R64_RM8: case FT_MOVSX_R32_RM8:
    case FT_MOVZX_R32_RM8:
    case FT_MOVSX_R64_RM16: case FT_MOVSX_R32_RM16:
    case FT_MOVZX_R32_RM16:
    case FT_MOVSXD_R64_RM32: case FT_MOVSXD_R32_RM32:
        return true;
    default: return false;
    }
}

static bool ft_rsp_merge_overwrite(const FastTemplateFields *f)
{
    if (ft_rsp_merge_load_overwrite(f)) {
        return true;
    }
    switch (f->kind) {
    case FT_MOV_R64_IMM64: case FT_MOV_R32_IMM32:
        return f->reg == rsp_index;
    case FT_MOV_RM64_R64: case FT_MOV_RM32_R32:
        return f->modrm_mod == 3 && ft_modrm_rm_index(f) == rsp_index &&
               ft_rsp_merge_reg_ok(f, true, false);
    case FT_MOV_R64_RM64: case FT_MOV_R32_RM32:
        return f->modrm_mod == 3 && ft_modrm_reg_index(f) == rsp_index &&
               ft_rsp_merge_reg_ok(f, false, false);
    case FT_MOVSX_R64_RM8: case FT_MOVSX_R32_RM8:
    case FT_MOVZX_R32_RM8:
        return f->modrm_mod == 3 && ft_modrm_reg_index(f) == rsp_index &&
               ft_rsp_merge_reg_ok(f, false, true);
    case FT_MOVSX_R64_RM16: case FT_MOVSX_R32_RM16:
    case FT_MOVZX_R32_RM16:
    case FT_MOVSXD_R64_RM32: case FT_MOVSXD_R32_RM32:
        return f->modrm_mod == 3 && ft_modrm_reg_index(f) == rsp_index &&
               ft_rsp_merge_reg_ok(f, false, false);
    case FT_LEA_R64_M: case FT_LEA_R32_M: {
        int base;
        /* LEA has no access that can fault. Discard the old delta only if
         * neither input observes the old stack pointer. */
        return f->modrm_mod != 3 && ft_modrm_reg_index(f) == rsp_index &&
               (!ft_base_from_modrm_sib_with_index(f, &base) ||
                base != rsp_index) &&
               (!ft_sib_has_index(f) || ft_sib_index_index(f) != rsp_index);
    }
    case FT_MOVD_R32_XMM: case FT_MOVD_RM32_MMX:
    case FT_MOVQ_R64_XMM: case FT_MOVQ_RM64_MMX:
    case FT_PEXTRW_SSE41_RM16_XMM_IMM8: case FT_EXTRACTPS_RM32_XMM_IMM8:
    case FT_PEXTR_GPR_XMM_IMM8: case FT_PEXTRQ_R64_XMM_IMM8:
        return f->modrm_mod == 3 && ft_modrm_rm_index(f) == rsp_index;
    case FT_PEXTRW_R32_XMM_IMM8: case FT_PEXTRW_R32_MMX_IMM8:
    case FT_PMOVMSKB_R32_XMM: case FT_PMOVMSKB_R32_MMX:
        return f->modrm_mod == 3 && ft_modrm_reg_index(f) == rsp_index;
    default: return false;
    }
}

/* The shared address emitter applies disp before addr32 truncation and
 * before/with the segment base addition. Compensating this copied disp is
 * therefore valid for wrapped and segmented vector memory operands too.
 * Keep indexed and large-displacement cases outside this bounded change. */
static bool ft_rsp_merge_vector_rm_ok(const FastTemplateFields *f, int pending,
                                      bool *adjust)
{
    int base;
    if (f->modrm_mod == 3) {
        return ft_rsp_merge_reg_ok(f, false, false);
    }
    if (!ft_base_from_modrm_sib_with_index(f, &base) || base != rsp_index) {
        return true;
    }
    if (ft_sib_has_index(f) || !ft_fits_simm12(f->disp) ||
        !ft_fits_simm12(f->disp + pending)) {
        return false;
    }
    *adjust = true;
    return true;
}

/* These vector operands are XMM/MMX indices, not GPR indices: XMM4 is
 * not RSP. Memory forms use the same checked displacement copy as integer
 * accesses; wrapped/segmented offsets are adjusted before address generation.
 * LATU emits no SIMD FPE helper here; MMX entry only stores mode_fpu.
 * Keep branching conversions, AES/helper paths and hard-x87 TOP setup
 * as barriers. */
static bool ft_rsp_merge_vector(const FastTemplateFields *f, int pending,
                                bool *adjust_memory)
{
    switch (f->kind) {
    case FT_X87_FFREE: case FT_X87_TOP_ADJ:
        return option_soft_fpu == 2 &&
               ft_offset_fits_imm12(lsenv_offset_of_tag_word(lsenv)) &&
               (f->kind == FT_X87_FFREE ||
                f->id == dt_X86_INS_FINCSTP || f->id == dt_X86_INS_FDECSTP);
    /* In these encodings ModRM.reg is a GPR, ModRM.rm is a vector. */
    case FT_PEXTRW_R32_XMM_IMM8: case FT_PEXTRW_R32_MMX_IMM8:
    case FT_PMOVMSKB_R32_XMM: case FT_PMOVMSKB_R32_MMX:
    case FT_CVTTSS2SI_GPR_XMMM: case FT_CVTSS2SI_GPR_XMMM:
    case FT_CVTTSD2SI_GPR_XMMM: case FT_CVTSD2SI_GPR_XMMM:
        if (!ft_rsp_merge_reg_ok(f, true, false)) {
            return false;
        }
        return f->modrm_mod == 3 ||
               ft_rsp_merge_vector_rm_ok(f, pending, adjust_memory);
    /* Here ModRM.rm really is a GPR (or a memory operand). */
    case FT_MOVD_XMM_R32:
    case FT_MOVD_R32_XMM: case FT_MOVD_MMX_RM32: case FT_MOVD_RM32_MMX:
    case FT_MOVQ_MMX_RM64_GPR: case FT_MOVQ_RM64_MMX:
    case FT_PINSRW_MMX_RM16_IMM8: case FT_PEXTRW_SSE41_RM16_XMM_IMM8:
    case FT_EXTRACTPS_RM32_XMM_IMM8:
    case FT_PINSR_XMM_GPR_IMM8: case FT_PEXTR_GPR_XMM_IMM8:
    case FT_PEXTRQ_R64_XMM_IMM8: case FT_MOVQ_XMM_R64: case FT_MOVQ_R64_XMM:
    case FT_CVTSI2SS_XMM_RM: case FT_CVTSI2SD_XMM_RM:
        return ft_rsp_merge_vector_rm_ok(f, pending, adjust_memory);
    case FT_ADDPD_XMM_XMM: case FT_MULPD_XMM_XMM:
    case FT_UNPCKPD_XMM_XMMM:
    case FT_MOVAPD_XMM_M128:
    case FT_MOVQ_XMM_RM64: case FT_MOVQ_RM64_XMM: case FT_MOVQ_MMX_RM64:
    case FT_MOV128_XMM_XMMM: case FT_MOV128_XMMM_XMM:
    case FT_MOVLPS_XMM_M64: case FT_MOVLPD_XMM_M64:
    case FT_MOVHPS_XMM_M64:
    case FT_MOVSD_XMM_M64: case FT_MOVSD_M64_XMM:
    case FT_PXOR_XMM_XMMM: case FT_PADD_XMM_XMMM:
    case FT_PADDQ_XMM_XMMM: case FT_PMULUDQ_XMM_XMMM:
    case FT_PCMPEQB_XMM_XMMM: case FT_SIMD_BIN_XMM_XMMM:
    case FT_PUNPCK_XMM_XMMM: case FT_PACK_XMM_XMM:
    case FT_SIMD_MADD_XMM_XMM:
    case FT_PSRLQ_XMM_IMM8: case FT_PSLLQ_XMM_IMM8:
    case FT_PSHIFT_XMM_IMM8: case FT_PSRLDQ_XMM_IMM8:
    case FT_PSLLDQ_XMM_IMM8: case FT_SHUF_XMM_XMMM_IMM8:
    case FT_BLEND_XMM_XMMM_IMM8: case FT_BLENDV_XMM_XMMM:
    case FT_PSHUFB_XMM_XMMM: case FT_PHADD_SUB_XMM_XMMM:
    case FT_HADD_SUB_XMM_XMMM: case FT_MOVDUP_XMM_XMMM:
    case FT_PSADBW_XMM_XMMM: case FT_MPSADBW_XMM_XMMM_IMM8:
    case FT_PSHUFB_MMX_MMXM64:
    case FT_PALIGNR_MMX_MMXM64_IMM8:
    case FT_PHADD_SUB_MMX_MMXM64:
    case FT_SIMD_MADD_MMX_MMXM64:
    case FT_SIMD_BIN_MMX_MMXM64:
    case FT_PSHUFW_MMX_MMXM_IMM8:
    case FT_PSHIFT_MMX_IMM8:
    case FT_PSUBB_MMX_MMXM64:
    case FT_PSUBW_MMX_MMXM64:
    case FT_PSUBD_MMX_MMXM64:
    case FT_PSUBQ_MMX_MMXM64:
    case FT_PSUBSB_MMX_MMXM64:
    case FT_PSUBSW_MMX_MMXM64:
    case FT_PSUBUSB_MMX_MMXM64:
    case FT_PSUBUSW_MMX_MMXM64:
    case FT_PADDSB_MMX_MMXM64:
    case FT_PADDSW_MMX_MMXM64:
    case FT_PADDUSB_MMX_MMXM64:
    case FT_PADDUSW_MMX_MMXM64:
    case FT_PAVGB_MMX_MMXM64:
    case FT_PAVGW_MMX_MMXM64:
    case FT_PAND_MMX_MMXM64:
    case FT_PANDN_MMX_MMXM64:
    case FT_POR_MMX_MMXM64:
    case FT_PXOR_MMX_MMXM64:
    case FT_PSADBW_MMX_MMXM64:
    case FT_PCMPGTB_MMX_MMXM64:
    case FT_PCMPGTW_MMX_MMXM64:
    case FT_PCMPGTD_MMX_MMXM64:
    case FT_PCMPEQB_MMX_MMXM64:
    case FT_PCMPEQW_MMX_MMXM64:
    case FT_PCMPEQD_MMX_MMXM64:
    case FT_PMULLW_MMX_MMXM64:
    case FT_PMULHW_MMX_MMXM64:
    case FT_PMULHUW_MMX_MMXM64:
    case FT_PSRAW_MMX_MMXM64:
    case FT_PSRAD_MMX_MMXM64:
    case FT_PACKSSDW_MMX_MMXM64:
    case FT_PACKSSWB_MMX_MMXM64:
    case FT_PACKUSWB_MMX_MMXM64:
    case FT_PMADDWD_MMX_MMXM64:
    case FT_PMULUDQ_MMX_MMXM64:
    case FT_PMAXSW_MMX_MMXM64:
    case FT_PMINSW_MMX_MMXM64:
    case FT_PADDB_MMX_MMXM64:
    case FT_PADDW_MMX_MMXM64:
    case FT_PADDD_MMX_MMXM64:
    case FT_PADDQ_MMX_MMXM64:
    case FT_MOVDQ2Q_MMX_XMM:
    case FT_MOVQ2DQ_XMM_MMX:
    case FT_MOVQ_MMXM64_MMX:
    case FT_PALIGNR_XMM_XMMM_IMM8: case FT_INSERTPS_XMM_XMMM_IMM8:
    case FT_PHMINPOSUW_XMM_XMMM: case FT_PMOVX_XMM_XMMM:
    case FT_CVTDQ2PD_XMM_XMM: case FT_CVT_FP_XMM_XMMM:
    case FT_CVTPI2PD_XMM_MMX: case FT_CVTPI2PS_XMM_MMX:
    case FT_SIMD_SCALAR_BIN_XMM_XMMM:
        return f->modrm_mod == 3 ||
               ft_rsp_merge_vector_rm_ok(f, pending, adjust_memory);
    default:
        return false;
    }
}

/* Initialization emits branches and is a barrier. Once TOP is active these
 * hard-FPU templates only emit direct operations and environment accesses. */
static bool ft_rsp_merge_hard_x87(const FastTemplateFields *f, int pending,
                                  bool top_active, bool *adjust)
{
    if (option_soft_fpu || !top_active) {
        return false;
    }
    switch (f->kind) {
    case FT_X87_UNARY: case FT_X87_FXCH: case FT_X87_BIN_REG:
    case FT_X87_FADDP: case FT_X87_FSUBP: case FT_X87_FSUBRP:
    case FT_X87_FMULP: case FT_X87_FDIVP: case FT_X87_FDIVRP:
    case FT_X87_TOP_ADJ: case FT_X87_FST_REG: case FT_X87_FSTP_REG:
    case FT_X87_FSQRT:
    case FT_X87_FLD1: case FT_X87_FLD_CONST: case FT_X87_FLD_REG:
        return true;
    case FT_X87_FST_M32: case FT_X87_FST_M64:
    case FT_X87_FSTP_M32: case FT_X87_FSTP_M64:
        if (!ft_x87_latu_legacy_no_tag()) { return false; }
        /* fall through: tag-enabled stores contain a conditional path. */
    case FT_X87_FLD_M32: case FT_X87_FLD_M64:
    case FT_X87_FILD_M16: case FT_X87_FILD_M32: case FT_X87_FILD_M64:
    case FT_X87_BIN_M32: case FT_X87_BIN_M64:
        return ft_rsp_merge_rm_ok(f, pending, false, adjust);
    default:
        return false;
    }
}

static bool ft_rsp_merge_transparent(const FastTemplateFields *f, int pending,
                                      bool top_active, bool *adjust_memory,
                                      bool *overwrite)
{
    bool byte = f->alu_width == 8;
    *adjust_memory = false;
    if (f->instptn_skip || f->instptn_div_kind || f->direct_cmp_width ||
        f->direct_cmp_lhs_gpr >= 0 || f->direct_cmp_rhs_gpr >= 0 ||
        f->direct_bit_index_gpr >= 0 || f->direct_bit_index_imm >= 0 ||
        f->direct_branch_kind != FT_DIRECT_BRANCH_NONE ||
        f->direct_float_result || f->direct_float_xx ||
        (f->prefix0 == dt_X86_PREFIX_LOCK &&
         !(f->modrm_mod != 3 &&
           (f->kind == FT_XCHG_RM8_R8 || f->kind == FT_XCHG_RM32_R32 ||
            f->kind == FT_XCHG_RM64_R64)))) {
        return false;
    }
    /* Ordinary integer ALU fields cannot describe an overwrite, SIMD or
     * x87 template. Avoid those unrelated classifications on the hot path. */
    if (f->alu_op != FT_ALU_NONE) {
        switch (f->alu_op) {
        case FT_ALU_ADD: case FT_ALU_SUB: case FT_ALU_ADC: case FT_ALU_SBB:
        case FT_ALU_AND: case FT_ALU_OR: case FT_ALU_XOR:
        case FT_ALU_CMP: case FT_ALU_TEST: break;
        default: return false;
        }
        /* Non-LOCK ADC/SBB commit flags only after the successful store.
         * Other memory ALU forms are safe here only with dead output flags;
         * their live flag calculation still precedes the faulting store. */
        if (f->modrm_mod != 3 && f->alu_form != FT_ALU_FORM_R_RM &&
            f->alu_form != FT_ALU_FORM_ACC_IMM &&
            f->alu_op != FT_ALU_CMP && f->alu_op != FT_ALU_TEST &&
            !f->skip_flags && !ft_alu_uses_cf(f->alu_op)) {
            return false;
        }
        switch (f->alu_form) {
        case FT_ALU_FORM_ACC_IMM: return true;
        case FT_ALU_FORM_RM_R: case FT_ALU_FORM_R_RM:
            if (!ft_rsp_merge_reg_ok(f, true, byte)) { return false; }
            /* fall through */
        case FT_ALU_FORM_RM_IMM:
            return ft_rsp_merge_rm_ok(f, pending, byte, adjust_memory);
        default: return false;
        }
    }
    if (f->modrm_mod == 3) {
        switch (f->kind) {
        case FT_MOV_RM8_R8: case FT_MOV_R8_RM8:
            byte = true; /* fall through */
        case FT_MOV_RM16_R16: case FT_MOV_R16_RM16:
        case FT_MOV_RM32_R32: case FT_MOV_R32_RM32:
        case FT_MOV_RM64_R64: case FT_MOV_R64_RM64:
            if (ft_rsp_merge_reg_ok(f, true, byte) &&
                ft_rsp_merge_reg_ok(f, false, byte)) {
                return true;
            }
            /* A full RSP overwrite still needs its existing handling. */
            break;
        default: break;
        }
    }
    if (ft_rsp_merge_load_overwrite(f)) {
        *overwrite = true;
        return ft_rsp_merge_rm_ok(f, pending, false, adjust_memory);
    }
    if (ft_rsp_merge_overwrite(f)) {
        *overwrite = true;
        return true;
    }
    if (ft_rsp_merge_vector(f, pending, adjust_memory) ||
        ft_rsp_merge_hard_x87(f, pending, top_active, adjust_memory)) {
        return true;
    }
    switch (f->kind) {
    case FT_NOP_MULTI: return true;
    case FT_CLC: case FT_STC: case FT_CMC:
    case FT_CLD: case FT_STD: case FT_LAHF: case FT_SAHF:
        /* Direct flag/env or AH updates, with no RSP input or branch. */
        return true;
    case FT_CRC32_R_RM8:
        return ft_rsp_merge_reg_ok(f, true, false) &&
               ft_rsp_merge_rm_ok(f, pending, true, adjust_memory);
    case FT_CRC32_R_RM16: case FT_CRC32_R_RM32: case FT_CRC32_R_RM64:
    case FT_IMUL_R16_RM16: case FT_IMUL_R32_RM32: case FT_IMUL_R64_RM64:
    case FT_IMUL_R16_RM16_IMM8: case FT_IMUL_R16_RM16_IMM16:
    case FT_IMUL_R32_RM32_IMM8: case FT_IMUL_R32_RM32_IMM32:
    case FT_IMUL_R64_RM64_IMM8: case FT_IMUL_R64_RM64_IMM32:
        return ft_rsp_merge_reg_ok(f, true, false) &&
               ft_rsp_merge_rm_ok(f, pending, false, adjust_memory);
    case FT_IMUL_RM8:
        return ft_rsp_merge_rm_ok(f, pending, true, adjust_memory);
    case FT_IMUL_RM16: case FT_IMUL_RM32: case FT_IMUL_RM64:
        return ft_rsp_merge_rm_ok(f, pending, false, adjust_memory);
    case FT_RORX_R32_RM32_IMM8: case FT_RORX_R64_RM64_IMM8:
        return f->reg >= 0 && f->reg < GPR_NUM && f->reg != rsp_index &&
               ft_rsp_merge_rm_ok(f, pending, false, adjust_memory);
    case FT_MOVBE_R16_M16: case FT_MOVBE_M16_R16:
    case FT_MOVBE_R32_M32: case FT_MOVBE_M32_R32:
    case FT_MOVBE_R64_M64: case FT_MOVBE_M64_R64:
        return ft_rsp_merge_reg_ok(f, true, false) &&
               ft_rsp_merge_rm_ok(f, pending, false, adjust_memory);
    case FT_XCHG_RM8_R8:
        byte = true;
        /* fall through */
    case FT_XCHG_RM32_R32: case FT_XCHG_RM64_R64:
        /* Memory XCHG is a single atomic swap followed by register update;
         * no retry branch or helper, and no register change on access fault. */
        return ft_rsp_merge_reg_ok(f, true, byte) &&
               ft_rsp_merge_rm_ok(f, pending, byte, adjust_memory);
    case FT_XCHG_R16_AX: case FT_XCHG_R32_EAX: case FT_XCHG_R64_RAX: {
        int reg = ft_rex_base_from_opcode(f->rex, f->opcode0);
        return reg > 0 && reg < GPR_NUM && reg != rsp_index;
    }
    case FT_LZCNT_R16_RM16: case FT_LZCNT_R32_RM32: case FT_LZCNT_R64_RM64:
    case FT_POPCNT_R16_RM16: case FT_POPCNT_R32_RM32: case FT_POPCNT_R64_RM64:
    case FT_TZCNT_R64_RM64:
        /* Live flag materialization branches. Narrow TZCNT also branches
         * for a zero input, even with dead flags. */
        return f->skip_flags && ft_rsp_merge_reg_ok(f, true, false) &&
               ft_rsp_merge_rm_ok(f, pending, false, adjust_memory);
    case FT_BLS_R32_RM: case FT_BLS_R64_RM:
        /* BLS destination is VEX.vvvv (fields->reg), not ModRM.reg. */
        return f->skip_flags && f->reg >= 0 && f->reg < GPR_NUM &&
               f->reg != rsp_index &&
               ft_rsp_merge_rm_ok(f, pending, false, adjust_memory);
    case FT_BEXTR_R32_RM_R: case FT_BEXTR_R64_RM_R:
    case FT_BZHI_R32_RM_R: case FT_BZHI_R64_RM_R:
    case FT_ANDN_R32_R_RM: case FT_ANDN_R64_R_RM:
        if (!f->skip_flags) { return false; }
        /* fall through: reg/imm encode the two explicit GPR operands. */
    case FT_SHLX_R32_RM_R: case FT_SHLX_R64_RM_R:
    case FT_SHRX_R32_RM_R: case FT_SHRX_R64_RM_R:
    case FT_SARX_R32_RM_R: case FT_SARX_R64_RM_R:
    case FT_MULX_R32_R_RM: case FT_MULX_R64_R_RM:
        return f->reg >= 0 && f->reg < GPR_NUM && f->reg != rsp_index &&
               f->imm >= 0 && f->imm < GPR_NUM && f->imm != rsp_index &&
               ft_rsp_merge_rm_ok(f, pending, false, adjust_memory);
    case FT_SETCC_RM8:
        return ft_rsp_merge_rm_ok(f, pending, true, adjust_memory);
    case FT_MOV_R8_IMM8:
        if (f->rex < 0 && f->reg >= 4 && f->reg < 8) { return true; }
        /* fall through */
    case FT_MOV_R16_IMM16: case FT_MOV_R32_IMM32: case FT_MOV_R64_IMM64:
    case FT_BSWAP_R32: case FT_BSWAP_R64:
        return f->reg >= 0 && f->reg < GPR_NUM && f->reg != rsp_index;
    case FT_MOV_RM8_R8: case FT_MOV_R8_RM8:
        byte = true;
        /* fall through */
    case FT_MOV_RM16_R16: case FT_MOV_R16_RM16:
    case FT_MOV_RM32_R32: case FT_MOV_R32_RM32:
    case FT_MOV_RM64_R64: case FT_MOV_R64_RM64:
        return ft_rsp_merge_reg_ok(f, true, byte) &&
               ft_rsp_merge_rm_ok(f, pending, byte, adjust_memory);
    case FT_MOVSX_R64_RM8: case FT_MOVSX_R32_RM8: case FT_MOVSX_R16_RM8:
    case FT_MOVZX_R16_RM8: case FT_MOVZX_R32_RM8:
        byte = true;
        /* fall through */
    case FT_MOVSX_R64_RM16: case FT_MOVSX_R32_RM16: case FT_MOVSX_R16_RM16:
    case FT_MOVZX_R32_RM16: case FT_MOVSXD_R64_RM32:
    case FT_LEA_R64_M: case FT_LEA_R32_M: case FT_LEA_R16_M:
        return ft_rsp_merge_reg_ok(f, true, false) &&
               ft_rsp_merge_rm_ok(f, pending, byte, adjust_memory);
    case FT_MOV_RM8_IMM8: byte = true; /* fall through */
    case FT_MOV_RM32_IMM32: case FT_MOV_RM64_IMM32:
        return ft_rsp_merge_rm_ok(f, pending, byte, adjust_memory);
    case FT_NOT_RM8: byte = true; /* fall through */
    case FT_NOT_RM16: case FT_NOT_RM32: case FT_NOT_RM64:
        /* NOT never writes flags; the non-LOCK store is its only mutation. */
        return ft_rsp_merge_rm_ok(f, pending, byte, adjust_memory);
    case FT_NEG_RM8: case FT_INC_RM8: case FT_DEC_RM8:
        byte = true; /* fall through */
    case FT_NEG_RM16: case FT_NEG_RM32: case FT_NEG_RM64:
    case FT_INC_RM16: case FT_INC_RM32: case FT_INC_RM64:
    case FT_DEC_RM16: case FT_DEC_RM32: case FT_DEC_RM64:
        /* Non-LOCK memory forms store before committing flags. */
        return ft_rsp_merge_rm_ok(f, pending, byte, adjust_memory);
    case FT_BTX_RM_R:
        if (!ft_rsp_merge_reg_ok(f, true, false)) { return false; }
        /* fall through */
    case FT_BTX_RM32_IMM8:
        return f->modrm_mod == 3 && ft_rsp_merge_reg_ok(f, false, false);
    case FT_SHIFT_RM_IMM8: case FT_SHIFT_RM_ONE:
        byte = f->opcode0 == 0xc0 || f->opcode0 == 0xd0;
        return f->modrm_mod == 3 && f->modrm_reg != 2 && f->modrm_reg != 3 &&
               ft_rsp_merge_reg_ok(f, false, byte);
    default: return false;
    }
}

/* Complex address formation and live flags read the architectural RSP.
 * Commit before that read, as the old IR2 pass does; the trailing stack
 * adjustment may still start a new run after all faults in this instruction. */
static bool ft_rsp_merge_requires_committed(const FastTemplateFields *f)
{
    int base;
    if (ft_rsp_merge_frame_step(f) ||
        ((f->kind == FT_PUSH_R64 || f->kind == FT_PUSH_R16) && f->reg == rsp_index)) {
        return true;
    }
    if ((f->kind == FT_INC_RM64 || f->kind == FT_DEC_RM64) && !f->skip_flags) {
        return true;
    }
    return ft_rsp_merge_memory(f) && (f->addr32 || f->segment >= 0) &&
           ft_base_from_modrm_sib_with_index(f, &base) && base == rsp_index;
}

static bool ft_rsp_merge_can_continue(const FastTemplateFields *f, int pending,
                                      bool top_active, int step, bool *adjust,
                                      bool *overwrite)
{
    *adjust = false;
    *overwrite = false;
    if (step) {
        int base;
        if (pending && ft_rsp_merge_requires_committed(f)) {
            return false;
        }
        if (ft_rsp_merge_memory(f) &&
            ft_base_from_modrm_sib_with_index(f, &base) && base == rsp_index &&
            ((int64_t)f->disp + pending < INT32_MIN ||
             (int64_t)f->disp + pending > INT32_MAX)) {
            return false;
        }
        *adjust = ft_rsp_merge_memory(f) &&
                  ft_base_from_modrm_sib_with_index(f, &base) && base == rsp_index;
        return ft_fits_simm12(pending + step);
    }
    return ft_rsp_merge_transparent(f, pending, top_active, adjust, overwrite);
}

/* Emit the memory operation directly with the deferred stack displacement.
 * The caller appends an RSP commit only when the run ends. No intermediate
 * ADDI or expected instruction words need to be generated for these forms. */
static int ft_rsp_merge_emit_register(const FastTemplateFields *f,
                                       uint32_t *code, int before, int step)
{
    uint32_t *out = code;
    if (!step) {
        return 0;
    }
    switch (f->kind) {
    case FT_PUSH_R64:
        FT_LA_ST_D_EMIT(&out, ft_gpr(f->reg), ft_gpr(rsp_index), before + step);
        break;
    case FT_PUSH_R16:
        FT_LA_ST_H_EMIT(&out, ft_gpr(f->reg), ft_gpr(rsp_index), before + step);
        break;
    case FT_POP_R64:
        FT_LA_LD_D_EMIT(&out, ft_gpr(f->reg), ft_gpr(rsp_index), before);
        break;
    case FT_POP_R16:
        FT_LA_LD_H_EMIT(&out, la_t0, ft_gpr(rsp_index), before);
        FT_LA_BSTRINS_D_EMIT(&out, ft_gpr(f->reg), la_t0, 15, 0);
        break;
    default:
        return 0;
    }
    return out - code;
}

static int ft_rsp_merge_apply(const FastTemplateFields *f, uint32_t *code,
                              int words, int before, int after, bool last,
                              int step)
{
    bool memory = ft_rsp_merge_memory(f);
    int mem_index = step < 0 ? words - 2 : (memory ? words - 3 : 0);
    uint32_t expected, *out = &expected;
    if (f->kind == FT_LEAVE && step) {
        uint32_t sequence[3], *check = sequence;
        bool word = step == 2;
        if (word) {
            FT_LA_LD_HU_EMIT(&check, la_t0, ft_gpr(rbp_index), 0);
        } else {
            FT_LA_LD_D_EMIT(&check, la_t0, ft_gpr(rbp_index), 0);
        }
        FT_LA_ADDI_D_EMIT(&check, ft_gpr(rsp_index), ft_gpr(rbp_index), step);
        if (word) {
            FT_LA_BSTRINS_D_EMIT(&check, ft_gpr(rbp_index), la_t0, 15, 0);
        } else {
            FT_LA_OR_EMIT(&check, ft_gpr(rbp_index), la_t0, la_zero);
        }
        if (before || words != 3 || code[0] != sequence[0] ||
            code[1] != sequence[1] || code[2] != sequence[2]) {
            return -1;
        }
        out = code + 1;
        if (last) {
            FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rbp_index), after);
        } else {
            FT_LA_OR_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rbp_index), la_zero);
        }
        return words;
    }
    if (ft_rsp_merge_frame_step(f)) {
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), step);
        if (before || words < 3 || code[words - 1] != expected ||
            !ft_fits_simm12(after)) {
            return -1;
        }
        if (!last || !after) {
            return words - 1;
        }
        out = code + words - 1;
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), after);
        return words;
    }
    if (ft_rsp_merge_adjustment(f)) {
        bool live_incdec = !f->skip_flags &&
            (f->kind == FT_INC_RM64 || f->kind == FT_DEC_RM64);
        int prefix = live_incdec ? 1 : 0;
        if (live_incdec) {
            uint32_t flag = ft_gpr2(f->kind == FT_INC_RM64 ?
                                    FT_LA_OPCODE_X86INC_D : FT_LA_OPCODE_X86DEC_D,
                                    ft_gpr(rsp_index), la_zero);
            if (before || words != 2 || code[0] != flag) {
                return -1;
            }
        }
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), step);
        if (words != prefix + 1 || code[prefix] != expected ||
            !ft_fits_simm12(after)) {
            return -1;
        }
        if (!last || !after) {
            return prefix;
        }
        out = code + prefix;
        FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), after);
        return prefix + 1;
    }
    if (!step || words < (memory ? 3 : 2) || !ft_fits_simm12(after) ||
        !ft_fits_simm12(before + (step < 0 ? step : 0))) {
        return -1;
    }
    FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), step);
    if (code[words - 1] != expected) {
        return -1;
    }
    /* Match the full memory word, not just a presumed immediate field. */
    out = &expected;
    if (step < 0) {
        int src = (f->kind == FT_PUSH_R64 || f->kind == FT_PUSH_R16) ?
                  ft_gpr(f->reg) : la_t0;
        if (step == -2) {
            FT_LA_ST_H_EMIT(&out, src, ft_gpr(rsp_index), step);
        } else {
            FT_LA_ST_D_EMIT(&out, src, ft_gpr(rsp_index), step);
        }
    } else if (step == 2) {
        FT_LA_LD_H_EMIT(&out, memory ? la_t4 : la_t0, ft_gpr(rsp_index), 0);
    } else {
        FT_LA_LD_D_EMIT(&out, memory ? la_t4 : ft_gpr(f->reg),
                         ft_gpr(rsp_index), 0);
    }
    if (code[mem_index] != expected) {
        return -1;
    }
    code[mem_index] = (expected & ~(0xfffu << 10)) |
        (((unsigned)(before + (step < 0 ? step : 0)) & 0xfffu) << 10);
    if (!last || !after) {
        return words - 1;
    }
    out = code + words - 1;
    FT_LA_ADDI_D_EMIT(&out, ft_gpr(rsp_index), ft_gpr(rsp_index), after);
    return words;
}
#endif
